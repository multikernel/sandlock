//! Supervisor process — drives the OCI container lifecycle via sandlock-core.
//!
//! `run_supervisor` converts the OCI policy into a `sandlock_core::Sandbox` and
//! drives the two-phase OCI lifecycle:
//!
//! 1. `sandbox.create_interactive(cmd)` — forks the child, installs the full
//!    sandlock policy (Landlock + seccomp-notify + resource limits + network
//!    ACL), and parks the child before execve.
//! 2. The supervisor writes the child PID to the caller's pipe and then waits
//!    on its Unix socket for a `Start` command.
//! 3. On `Start`: `sandbox.start()` releases the parked child to execve.
//! 4. `sandbox.wait()` collects the exit status and persists it to state.json.
//!
//! Communication with the CLI is newline-delimited JSON over a Unix socket in
//! the sandbox's state directory.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::oneshot;

use crate::init::{Req, Resp, CONTROL_FD};

use crate::policy::OciPolicy;
use crate::state::SandboxState;

/// Demultiplexer for the single control channel to `sandlock-init`.
///
/// All replies (`Started`, `Exited`, `Err`) arrive on one socket and must be
/// routed: a `Started`/`Err` is the immediate reply to the request just sent
/// (requests are serialized by holding the writer lock across the await, so the
/// correlation is unambiguous), while an `Exited{pid}` is routed to the waiter
/// registered for that pid (an exec, or the main workload). An `Exited` that
/// arrives before its waiter registers is buffered in `early_exits`.
struct LinkState {
    /// Sender for the reply to the in-flight request (a `Started` or `Err`).
    pending: Option<oneshot::Sender<Resp>>,
    /// Per-pid exit waiters (main workload + attached execs).
    exit_waiters: HashMap<i32, oneshot::Sender<Resp>>,
    /// Exits that arrived before a waiter registered.
    early_exits: HashMap<i32, Resp>,
}

struct InitLink {
    /// Write half (a dup of the control socket) used for blocking `sendmsg`.
    writer: tokio::sync::Mutex<std::os::unix::net::UnixStream>,
    state: StdMutex<LinkState>,
}

impl InitLink {
    /// Build the link and spawn the background reader that routes replies.
    fn new(
        writer: std::os::unix::net::UnixStream,
        reader: tokio::net::UnixStream,
    ) -> Arc<Self> {
        let link = Arc::new(InitLink {
            writer: tokio::sync::Mutex::new(writer),
            state: StdMutex::new(LinkState {
                pending: None,
                exit_waiters: HashMap::new(),
                early_exits: HashMap::new(),
            }),
        });
        let weak = link.clone();
        tokio::spawn(async move { reader_task(weak, reader).await });
        link
    }

    /// Send a request (optionally with SCM_RIGHTS `fds`) and return its
    /// immediate `Started`/`Err` reply. The writer lock is held across the
    /// await so requests are serialized and each reply pairs with its request.
    async fn request(&self, req: &Req, fds: &[RawFd]) -> std::io::Result<Resp> {
        let mut bytes = serde_json::to_vec(req)?;
        bytes.push(b'\n');
        let writer = self.writer.lock().await;
        let (tx, rx) = oneshot::channel();
        {
            let mut st = self.state.lock().unwrap();
            st.pending = Some(tx);
        }
        crate::fdpass::send_with_fds(&writer, &bytes, fds)?;
        // Hold the writer lock until the reply lands so a concurrent request
        // cannot overwrite `pending` before this one is answered.
        let resp = rx.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sandlock-init closed control channel")
        })?;
        drop(writer);
        Ok(resp)
    }

    /// Register interest in the exit of `pid`. If the exit was already reported
    /// (buffered), the receiver resolves immediately.
    fn register_exit(&self, pid: i32) -> oneshot::Receiver<Resp> {
        let (tx, rx) = oneshot::channel();
        let mut st = self.state.lock().unwrap();
        if let Some(resp) = st.early_exits.remove(&pid) {
            let _ = tx.send(resp);
        } else {
            st.exit_waiters.insert(pid, tx);
        }
        rx
    }

    /// Send `Shutdown` to init. No reply is expected (init exits).
    async fn shutdown(&self) {
        if let Ok(mut bytes) = serde_json::to_vec(&Req::Shutdown) {
            bytes.push(b'\n');
            let writer = self.writer.lock().await;
            let _ = crate::fdpass::send_with_fds(&writer, &bytes, &[]);
        }
    }
}

/// Background reader: parse newline-delimited `Resp` from init and route each.
/// init never sends fds to the daemon, so a plain line reader is sufficient.
async fn reader_task(link: Arc<InitLink>, reader: tokio::net::UnixStream) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp: Resp = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut st = link.state.lock().unwrap();
        match resp {
            Resp::Started { .. } | Resp::Err { .. } => {
                if let Some(tx) = st.pending.take() {
                    let _ = tx.send(resp);
                }
            }
            Resp::Exited { pid, .. } => {
                if let Some(tx) = st.exit_waiters.remove(&pid) {
                    let _ = tx.send(resp);
                } else {
                    st.early_exits.insert(pid, resp);
                }
            }
        }
    }
    // Channel closed: drop senders so any pending request/waiter unblocks with a
    // RecvError rather than hanging forever.
    let mut st = link.state.lock().unwrap();
    st.pending.take();
    st.exit_waiters.clear();
}

/// Map an init `Resp::Exited` (if any) to the on-disk `ExitInfo`.
fn exit_info_from_resp(resp: Option<Resp>) -> Option<crate::state::ExitInfo> {
    match resp {
        Some(Resp::Exited { code, signal, .. }) => {
            Some(crate::state::ExitInfo { code, signal })
        }
        _ => None,
    }
}

/// Commands the CLI sends to the Supervisor over the Unix socket.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum SupervisorCmd {
    /// Release the parked child to execve.
    Start,
    /// Query the child PID.
    Ping,
    /// Terminate the supervisor without starting the child (used by `delete`
    /// when the sandbox was never started).  The sandbox `Drop` kills the
    /// parked child.
    Shutdown,
    /// Capture a checkpoint of the running child into `dir`.
    Checkpoint { dir: String },
    /// Run an additional process inside the running container. Carries 3
    /// ancillary fds (stdin, stdout, stderr) over SCM_RIGHTS alongside this
    /// JSON. `detach` means the CLI will not wait for an `Exit` reply.
    Exec {
        args: Vec<String>,
        env: Vec<(String, String)>,
        cwd: Option<String>,
        detach: bool,
    },
    /// Deliver `signum` to the container's entire process group (the group
    /// whose leader is sandlock-init). Used by `kill --all` and `delete
    /// --force` so the CLI does not need to know the pgid directly.
    Signal { signum: i32 },
}

/// Responses from the Supervisor.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum SupervisorReply {
    Ok,
    Pid { pid: i32 },
    Err { msg: String },
    /// Final status of an exec'd process (attached exec only).
    Exit { code: Option<i32>, signal: Option<i32> },
}

/// Deterministic 64-bit FNV-1a hash of `id` as 16 lowercase hex chars.
///
/// Keeps the supervisor socket path short enough for `sockaddr_un.sun_path`
/// (108 bytes incl. NUL) even when the runtime root and container id are long
/// (containerd passes a 64-char id under /run/containerd/runc/<ns>). Only needs
/// to be stable within a single binary: bind and connect run the same build.
fn fnv1a_hex(id: &str) -> String {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for b in id.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    format!("{:016x}", h)
}

/// Returns the path to the supervisor socket for the given sandbox ID.
///
/// Lives directly under the state dir as `<fnv16(id)>.sock` (not under the
/// per-id state subdir) so the path stays well under the `sun_path` limit.
pub fn socket_path(id: &str) -> PathBuf {
    PathBuf::from(crate::state::state_dir()).join(format!("{}.sock", fnv1a_hex(id)))
}

/// Send a command to a running supervisor and return its reply (blocking).
///
/// The protocol is newline-delimited JSON over a Unix socket.
pub fn send_command(id: &str, cmd: SupervisorCmd) -> Result<SupervisorReply> {
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixStream;

    let path = socket_path(id);
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("connect to supervisor socket {:?}", path))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let msg = serde_json::to_string(&cmd)?;
    stream.write_all(msg.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = std::io::BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    serde_json::from_str(line.trim()).context("parse supervisor reply")
}

/// Run the supervisor in the **current process**.
///
/// Builds a `Sandbox` from the OCI policy, drives the full create/start/wait
/// lifecycle using `sandlock_core`, and communicates the child PID back to the
/// CLI via `pid_write_fd`.
pub fn run_supervisor(
    id: &str,
    cmd: &[String],
    policy: OciPolicy,
    pid_write_fd: i32,
) -> Result<Option<crate::state::ExitInfo>> {
    if cmd.is_empty() {
        anyhow::bail!("OCI spec error: process.args is empty");
    }

    // Create backing dirs for emulated tmpfs mounts before building the
    // sandbox so each bind redirect has a target on disk.  They live under the
    // sandbox state dir and are removed with it on `delete`.
    for dir in &policy.scratch_dirs {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create tmpfs backing dir {:?}", dir))?;
    }

    // Build the Sandbox from the OCI policy — this carries chroot, env, fs
    // rules, resource limits, and network policy into sandlock-core.
    let mut sandbox = policy.to_sandbox().context("build Sandbox from OCI policy")?;
    sandbox.set_name(id);

    let sock_path = socket_path(id);
    if sock_path.exists() {
        std::fs::remove_file(&sock_path).ok();
    }

    // A multi-threaded runtime is required: sandlock-core spawns tokio tasks
    // for the seccomp-notify supervisor, CPU throttle, and load-avg tracking.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    rt.block_on(supervisor_main(id, cmd, sandbox, sock_path, pid_write_fd))
}

/// Write a line to the notification pipe and close it.  Used for both the
/// success case (`OK <pid>`) and the failure case (`ERR <message>`).
fn pipe_write(fd: i32, line: &str) {
    let s = format!("{}\n", line);
    unsafe {
        libc::write(fd, s.as_ptr() as *const libc::c_void, s.len());
        libc::close(fd);
    }
}

/// Async body of `run_supervisor`.
///
/// Instead of running the workload directly, this launches a confined
/// `sandlock-init` (PID-1) that runs in-process in the forked child (no exec)
/// and relays OCI verbs to it over a control socket: the workload and any
/// exec'd processes are forked by `sandlock-init` and so share the one sandbox
/// (seccomp filter + Landlock ruleset + notify supervisor).
async fn supervisor_main(
    id: &str,
    cmd: &[String],
    mut sandbox: sandlock_core::Sandbox,
    sock_path: PathBuf,
    pid_write_fd: i32,
) -> Result<Option<crate::state::ExitInfo>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    // Bind the socket BEFORE create() so the CLI can call `start` the moment
    // `create` returns without a race on socket availability.
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR bind socket: {}", e));
            anyhow::bail!("bind supervisor socket {:?}: {}", sock_path, e);
        }
    };

    // Restrict connects to the owner (root, same as the runtime). Best-effort:
    // the path-length fix is what matters; a chmod failure must not abort create.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o700));
    }

    // Set up the control channel. The child end is mapped onto CONTROL_FD inside
    // the confined process; the daemon keeps the other end to drive
    // RunMain/RunExec/Shutdown.
    let (daemon_ctl, child_ctl) = match std::os::unix::net::UnixStream::pair() {
        Ok(p) => p,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR control socketpair: {}", e));
            anyhow::bail!("control socketpair: {}", e);
        }
    };
    let extra_fds = vec![(CONTROL_FD, child_ctl.as_raw_fd())];

    // OCI `create` of the CONFINED sandlock-init: forks the child, installs the
    // full sandlock policy, maps CONTROL_FD, and parks. The child runs the
    // in-process `run_init` control loop instead of exec'ing a separate binary:
    // it is already a fork of this supervisor, so the init code is mapped, and
    // because nothing is exec'd there is no execve for Landlock to authorize.
    if let Err(e) = sandbox
        .create_with_in_child_main("sandlock-init", extra_fds, crate::init::run_init)
        .await
    {
        pipe_write(pid_write_fd, &format!("ERR create: {}", e));
        return Err(anyhow::anyhow!("sandbox create_with_in_child_main: {}", e));
    }
    // The child inherited child_ctl at fork and dup'd it onto CONTROL_FD; drop
    // the daemon's copy so it holds only daemon_ctl (and so EOF on daemon_ctl
    // tracks init exiting).
    drop(child_ctl);

    // Release sandlock-init to run its control loop. It then blocks reading
    // CONTROL_FD for the first request. This happens at create/supervisor time
    // (not OCI start) so init is alive to receive RunMain when the OCI `start`
    // arrives.
    if let Err(e) = sandbox.start() {
        pipe_write(pid_write_fd, &format!("ERR start init: {}", e));
        return Err(anyhow::anyhow!("start sandlock-init: {}", e));
    }

    let init_pid = sandbox.pid().unwrap_or(0) as i32;

    // Build the demuxing control link to sandlock-init. `daemon_ctl` is a std
    // socket; a dup serves the blocking fd-passing writer while the original is
    // converted to a nonblocking tokio socket for the async reader. set_nonblocking
    // sets O_NONBLOCK on the shared open file description, but the writer only
    // sends tiny control messages, so a nonblocking `sendmsg` never short-writes.
    let writer = match daemon_ctl.try_clone() {
        Ok(w) => w,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR dup control: {}", e));
            anyhow::bail!("dup control socket: {}", e);
        }
    };
    if let Err(e) = daemon_ctl.set_nonblocking(true) {
        pipe_write(pid_write_fd, &format!("ERR control nonblock: {}", e));
        anyhow::bail!("set control nonblocking: {}", e);
    }
    let reader = match tokio::net::UnixStream::from_std(daemon_ctl) {
        Ok(r) => r,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR control tokio: {}", e));
            anyhow::bail!("convert control socket to tokio: {}", e);
        }
    };
    let link = InitLink::new(writer, reader);

    // Notify the CLI: `OK <pid>` on success. Before OCI `start` there is no
    // workload yet, so the reported/recorded PID is sandlock-init's (the
    // container PID-1); OCI `start` updates state.pid to the workload PID.
    // Report two pids: the supervisor daemon's own pid (this process, which is
    // the containerd shim's child and what the shim reaps to detect exit) and
    // sandlock-init's pid (the OCI container init, recorded as state.pid).
    pipe_write(pid_write_fd, &format!("OK {} {}", std::process::id(), init_pid));

    {
        let mut state = SandboxState::load(id)
            .unwrap_or_else(|_| SandboxState::new(id, Path::new("/"), "1.0.2"));
        state.set_created(init_pid);
        state.save().ok();
    }

    // PRE-START accept-loop: serve CLI commands until `Start` (transition to the
    // running-serve loop) or `Shutdown`/error (return so the Sandbox Drop kills
    // and reaps init, which collapses the whole group).
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return Ok(None),
        };

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            continue;
        }

        let incoming: SupervisorCmd = match serde_json::from_slice(&buf[..n]) {
            Ok(c) => c,
            Err(e) => {
                let reply = serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                    .unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
                continue;
            }
        };

        match incoming {
            SupervisorCmd::Ping => {
                let reply =
                    serde_json::to_vec(&SupervisorReply::Pid { pid: init_pid }).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
            SupervisorCmd::Start => {
                // OCI `start`: tell init to fork the workload. The reply pid is
                // the workload PID (not init), which becomes state.pid.
                let req = Req::RunMain {
                    argv: cmd.to_vec(),
                    env: vec![],
                    cwd: None,
                };
                match link.request(&req, &[]).await {
                    Ok(Resp::Started { pid }) => {
                        let main_exit = link.register_exit(pid);
                        if let Ok(mut s) = SandboxState::load(id) {
                            s.set_created(pid);
                            s.set_running();
                            s.save().ok();
                        }
                        let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                        // Workload is running: keep serving the control socket
                        // (Ping/Exec/Checkpoint) until it exits or Shutdown.
                        let exit_info =
                            serve_running_init(id, &link, &mut sandbox, &listener, pid, main_exit)
                                .await;
                        if let Ok(mut s) = SandboxState::load(id) {
                            s.set_stopped(exit_info.clone());
                            s.save().ok();
                        }
                        return Ok(exit_info);
                    }
                    Ok(Resp::Err { msg }) => {
                        let reply = serde_json::to_vec(&SupervisorReply::Err { msg })
                            .unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                        return Ok(None);
                    }
                    other => {
                        let msg = format!("unexpected init reply to RunMain: {:?}", other);
                        let reply = serde_json::to_vec(&SupervisorReply::Err { msg })
                            .unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                        return Ok(None);
                    }
                }
            }
            SupervisorCmd::Shutdown => {
                // `delete` before `start`: tell init to exit, then return so
                // the Sandbox Drop reaps it.
                link.shutdown().await;
                let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
                return Ok(None);
            }
            SupervisorCmd::Checkpoint { dir } => {
                let reply = match sandbox.checkpoint().await {
                    Ok(mut cp) => {
                        cp.name = id.to_string();
                        match cp.save(std::path::Path::new(&dir)) {
                            Ok(()) => serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default(),
                            Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() }).unwrap_or_default(),
                        }
                    }
                    Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() }).unwrap_or_default(),
                };
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
            SupervisorCmd::Exec { .. } => {
                let reply = serde_json::to_vec(&SupervisorReply::Err {
                    msg: "container is not running; start it before exec".into(),
                })
                .unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
            SupervisorCmd::Signal { .. } => {
                let reply = serde_json::to_vec(&SupervisorReply::Err {
                    msg: "container not running".into(),
                })
                .unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
        }
    }
}

/// Serve the control socket while the workload (forked by sandlock-init) runs,
/// returning its recorded exit info once it exits or a Shutdown is received.
///
/// Exit is detected via the init control channel (`main_exit` resolves when init
/// reports the workload's `Exited`), not a pidfd: init owns the workload and
/// reports its status authoritatively. `sandbox` is kept alive (and is used for
/// `checkpoint`) so the shared seccomp-notify supervisor keeps servicing the
/// workload and any exec'd processes.
async fn serve_running_init(
    id: &str,
    link: &Arc<InitLink>,
    sandbox: &mut sandlock_core::Sandbox,
    listener: &tokio::net::UnixListener,
    workload_pid: i32,
    mut main_exit: oneshot::Receiver<Resp>,
) -> Option<crate::state::ExitInfo> {
    loop {
        tokio::select! {
            res = &mut main_exit => {
                // Workload exited; init kills the group and exits too. The
                // Sandbox Drop reaps init.
                return exit_info_from_resp(res.ok());
            }
            conn = listener.accept() => {
                match conn {
                    Ok((stream, _)) => {
                        match serve_one_running_init(stream, link, sandbox, id, workload_pid).await {
                            RunningCmd::Continue => {}
                            RunningCmd::Shutdown => {
                                link.shutdown().await;
                                return None;
                            }
                        }
                    }
                    Err(_) => {
                        // Listener broke: fall back to waiting for the workload
                        // exit so we still record a final state.
                        return exit_info_from_resp((&mut main_exit).await.ok());
                    }
                }
            }
        }
    }
}

/// Handle one accepted connection while the container is RUNNING (init path).
/// Reads the command via recvmsg so exec stdio fds arrive with the bytes.
async fn serve_one_running_init(
    mut stream: tokio::net::UnixStream,
    link: &Arc<InitLink>,
    sandbox: &mut sandlock_core::Sandbox,
    id: &str,
    workload_pid: i32,
) -> RunningCmd {
    use tokio::io::AsyncWriteExt;

    let (buf, fds) = match crate::fdpass::recv_with_fds_async(&stream, 3).await {
        Ok(pair) => pair,
        Err(_) => return RunningCmd::Continue,
    };
    if buf.is_empty() {
        return RunningCmd::Continue;
    }
    let incoming: SupervisorCmd = match serde_json::from_slice(&buf) {
        Ok(c) => c,
        Err(e) => {
            let reply = serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                .unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            return RunningCmd::Continue;
        }
    };
    match incoming {
        SupervisorCmd::Ping => {
            let reply =
                serde_json::to_vec(&SupervisorReply::Pid { pid: workload_pid }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Start => {
            // Already running: idempotent no-op.
            let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Exec { args, env, cwd, detach } => {
            handle_exec(stream, link.clone(), args, env, cwd, detach, fds).await;
            RunningCmd::Continue
        }
        SupervisorCmd::Checkpoint { dir } => {
            // Capture the WORKLOAD, not sandlock-init (which is the sandbox's
            // direct child and would only snapshot the init process blocked in
            // recvmsg).
            let reply = match sandbox.checkpoint_pid(workload_pid).await {
                Ok(mut cp) => {
                    cp.name = id.to_string();
                    match cp.save(std::path::Path::new(&dir)) {
                        Ok(()) => serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default(),
                        Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                            .unwrap_or_default(),
                    }
                }
                Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                    .unwrap_or_default(),
            };
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Signal { signum } => {
            // killpg targets the process GROUP, whose leader is sandlock-init.
            // sandbox.pid() is that group-leader pid (set by setpgid(0,0) in core).
            let init_pgid = sandbox.pid().unwrap_or(0) as i32;
            if init_pgid > 0 {
                unsafe { libc::killpg(init_pgid, signum) };
                let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            } else {
                let reply = serde_json::to_vec(&SupervisorReply::Err { msg: "no container process group".into() }).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
            RunningCmd::Continue
        }
        SupervisorCmd::Shutdown => {
            let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Shutdown
        }
    }
}

/// Forward an exec to sandlock-init: send `RunExec` + the 3 stdio fds, relay the
/// `Started` pid back to the CLI as `Pid`, then (attached only) wait for the
/// init `Exited` and relay it as `Exit`. The daemon's fd copies are dropped once
/// init has dup'd them via SCM_RIGHTS.
#[allow(clippy::too_many_arguments)]
async fn handle_exec(
    mut stream: tokio::net::UnixStream,
    link: Arc<InitLink>,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<String>,
    detach: bool,
    fds: Vec<std::os::unix::io::OwnedFd>,
) {
    use tokio::io::AsyncWriteExt;

    if fds.len() < 3 {
        let reply = serde_json::to_vec(&SupervisorReply::Err {
            msg: "exec requires 3 stdio fds".into(),
        })
        .unwrap_or_default();
        let _ = stream.write_all(&reply).await;
        let _ = stream.write_all(b"\n").await;
        return;
    }
    if args.is_empty() {
        let reply = serde_json::to_vec(&SupervisorReply::Err { msg: "exec: empty command".into() })
            .unwrap_or_default();
        let _ = stream.write_all(&reply).await;
        let _ = stream.write_all(b"\n").await;
        return;
    }

    let raw: Vec<RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
    let req = Req::RunExec { argv: args, env, cwd, detach };
    let started = link.request(&req, &raw).await;
    // init has now dup'd the fds (SCM_RIGHTS); drop the daemon's copies.
    drop(fds);

    match started {
        Ok(Resp::Started { pid }) => {
            let reply = serde_json::to_vec(&SupervisorReply::Pid { pid }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            if !detach {
                // Register the waiter before yielding so a fast Exited is not
                // missed, then relay it on a background task to keep the serve
                // loop responsive.
                let rx = link.register_exit(pid);
                tokio::spawn(async move {
                    if let Ok(Resp::Exited { code, signal, .. }) = rx.await {
                        let reply = serde_json::to_vec(&SupervisorReply::Exit { code, signal })
                            .unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                    }
                });
            }
        }
        Ok(Resp::Err { msg }) => {
            let reply = serde_json::to_vec(&SupervisorReply::Err { msg }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
        }
        other => {
            let msg = format!("unexpected init reply to RunExec: {:?}", other);
            let reply = serde_json::to_vec(&SupervisorReply::Err { msg }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
        }
    }
}

/// Convert a `RunResult` (or wait error) into the on-disk `ExitInfo`.
fn exit_info_from(
    res: Result<sandlock_core::RunResult, sandlock_core::SandlockError>,
) -> Option<crate::state::ExitInfo> {
    use crate::state::ExitInfo;
    use sandlock_core::ExitStatus;
    match res {
        Ok(r) => match r.exit_status {
            ExitStatus::Code(code) => Some(ExitInfo { code: Some(code), signal: None }),
            ExitStatus::Signal(sig) => Some(ExitInfo { code: None, signal: Some(sig) }),
            ExitStatus::Killed => Some(ExitInfo { code: None, signal: Some(libc::SIGKILL) }),
            ExitStatus::Timeout => Some(ExitInfo { code: Some(124), signal: None }),
        },
        Err(_) => None,
    }
}

/// Open an independent pidfd for `pid` as an AsyncFd readiness source for child
/// exit, WITHOUT consuming the sandbox's own pidfd. A pidfd becomes readable
/// when the process exits. Returns None if pidfd_open is unavailable or the
/// child is already gone (caller then falls back to a plain wait()).
fn exit_watcher(pid: i32) -> Option<tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>> {
    use std::os::unix::io::{FromRawFd, OwnedFd};
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return None;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    tokio::io::unix::AsyncFd::with_interest(fd, tokio::io::Interest::READABLE).ok()
}

/// Outcome of handling one running-container control command.
enum RunningCmd {
    Continue,
    Shutdown,
}

/// Handle a single accepted connection while the container is RUNNING. Serves
/// Ping, Checkpoint, Start (idempotent no-op since already running), and
/// Shutdown. Returns whether to keep serving or shut down.
async fn serve_one_running(
    stream: &mut tokio::net::UnixStream,
    sandbox: &mut sandlock_core::Sandbox,
    id: &str,
    child_pid: i32,
) -> RunningCmd {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 {
        return RunningCmd::Continue;
    }
    let incoming: SupervisorCmd = match serde_json::from_slice(&buf[..n]) {
        Ok(c) => c,
        Err(e) => {
            let reply = serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                .unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            return RunningCmd::Continue;
        }
    };
    match incoming {
        SupervisorCmd::Ping => {
            let reply =
                serde_json::to_vec(&SupervisorReply::Pid { pid: child_pid }).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Start => {
            // Already running: idempotent no-op.
            let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Checkpoint { dir } => {
            let reply = match sandbox.checkpoint().await {
                Ok(mut cp) => {
                    cp.name = id.to_string();
                    match cp.save(std::path::Path::new(&dir)) {
                        Ok(()) => serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default(),
                        Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                            .unwrap_or_default(),
                    }
                }
                Err(e) => serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                    .unwrap_or_default(),
            };
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Exec { .. } => {
            // exec inside a restored container is not supported (restore has no
            // sandlock-init relay). Reject so the CLI surfaces a clear error.
            let reply = serde_json::to_vec(&SupervisorReply::Err {
                msg: "exec is not supported on a restored container".into(),
            })
            .unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
        }
        SupervisorCmd::Signal { signum } => {
            // child_pid is the group leader's pid (== pgid) in the restore path.
            if child_pid > 0 {
                unsafe { libc::killpg(child_pid, signum) };
                let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            } else {
                let reply = serde_json::to_vec(&SupervisorReply::Err { msg: "no container process group".into() }).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
            RunningCmd::Continue
        }
        SupervisorCmd::Shutdown => {
            let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Shutdown
        }
    }
}

/// Serve the control socket while the (already-running) child executes,
/// returning the recorded exit info once the child exits or a Shutdown is
/// received. Uses an independent pidfd watcher so the sandbox's own pidfd is
/// consumed only by the final `wait()`, after exit. `AsyncFd::readable()` is
/// cancel-safe and borrows only the watcher, so accepted commands can use
/// `sandbox` freely.
async fn serve_running(
    id: &str,
    sandbox: &mut sandlock_core::Sandbox,
    listener: &tokio::net::UnixListener,
    child_pid: i32,
) -> Option<crate::state::ExitInfo> {
    let watcher = match exit_watcher(child_pid) {
        Some(w) => w,
        None => {
            // Cannot watch concurrently: just wait for exit (no serving).
            return reap_and_collapse(sandbox, child_pid).await;
        }
    };
    loop {
        tokio::select! {
            ready = watcher.readable() => {
                // Child exited (pidfd readable), or the watcher errored: either
                // way collect the status via the sandbox's own pidfd. We return
                // immediately, so there is no need to clear readiness.
                let _ = ready;
                return reap_and_collapse(sandbox, child_pid).await;
            }
            conn = listener.accept() => {
                match conn {
                    Ok((mut stream, _)) => {
                        match serve_one_running(&mut stream, sandbox, id, child_pid).await {
                            RunningCmd::Continue => {}
                            RunningCmd::Shutdown => {
                                let _ = sandbox.kill();
                                return exit_info_from(sandbox.wait().await);
                            }
                        }
                    }
                    Err(_) => return reap_and_collapse(sandbox, child_pid).await,
                }
            }
        }
    }
}

/// Collect the main process's exit status, then collapse its process group.
///
/// sandlock uses no PID namespace, so when the container's main process exits
/// the kernel does not tear down the processes it spawned (background children,
/// and exec'd siblings sharing the group). Send SIGKILL to the whole group so
/// nothing outlives the container with a now-dead supervisor. `child_pid` is the
/// group's pgid (core does `setpgid(0, 0)` in the child); `killpg` reaches any
/// remaining members and is a harmless `ESRCH` when the group is already empty.
/// The `Shutdown` path does not call this because `sandbox.kill()` already
/// SIGKILLs the same process group.
async fn reap_and_collapse(
    sandbox: &mut sandlock_core::Sandbox,
    child_pid: i32,
) -> Option<crate::state::ExitInfo> {
    let info = exit_info_from(sandbox.wait().await);
    if child_pid > 0 {
        unsafe { libc::killpg(child_pid, libc::SIGKILL) };
    }
    info
}

/// Run the supervisor in the **current process** for an OCI `restore`.
///
/// Unlike [`run_supervisor`], the policy comes from the checkpoint image (the
/// saved `Sandbox`), not from an `OciPolicy`, and there is no separate `start`:
/// `restore_interactive` both creates the child and resumes it, so the sandbox
/// is `Running` the moment restore returns.
pub fn run_supervisor_restore(id: &str, image_dir: &str, pid_write_fd: i32) -> Result<()> {
    // Load the checkpoint image. On failure report back through the pid pipe so
    // the CLI surfaces a clear error rather than a bare EOF.
    let cp = match sandlock_core::Checkpoint::load(std::path::Path::new(image_dir)) {
        Ok(c) => c,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR load checkpoint: {}", e));
            return Err(anyhow::anyhow!("load checkpoint from {:?}: {}", image_dir, e));
        }
    };

    // Build the Sandbox from the SAVED policy (cp.policy is a Sandbox with a
    // manual Clone), not from an OciPolicy.
    let mut sandbox = cp.policy.clone();
    sandbox.set_name(id);

    let sock_path = socket_path(id);
    if sock_path.exists() {
        std::fs::remove_file(&sock_path).ok();
    }

    // Same multi-threaded runtime requirement as run_supervisor.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    rt.block_on(supervisor_restore_main(id, sandbox, cp, sock_path, pid_write_fd))
}

/// Async body of [`run_supervisor_restore`].
async fn supervisor_restore_main(
    id: &str,
    mut sandbox: sandlock_core::Sandbox,
    cp: sandlock_core::Checkpoint,
    sock_path: PathBuf,
    pid_write_fd: i32,
) -> Result<()> {
    use tokio::net::UnixListener;

    // Bind the control socket BEFORE restore (mirrors create binding before
    // create) so the CLI never races on socket availability.
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR bind socket: {}", e));
            anyhow::bail!("bind supervisor socket {:?}: {}", sock_path, e);
        }
    };

    // Restrict connects to the owner (root, same as the runtime). Best-effort:
    // the path-length fix is what matters; a chmod failure must not abort restore.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o700));
    }

    // Restore: forks the child under the saved policy, injects the checkpoint,
    // and RESUMES it. The child is already running on return — there is no
    // separate start step.
    if let Err(e) = sandbox.restore_interactive(&cp).await {
        pipe_write(pid_write_fd, &format!("ERR restore: {}", e));
        return Err(anyhow::anyhow!("sandbox restore_interactive: {}", e));
    }
    for f in sandbox.restore_skipped() {
        eprintln!("sandlock: fd {} not transparently restored: {}", f.fd, f.path);
    }

    let child_pid = sandbox.pid().unwrap_or(0);

    // Notify the CLI: `OK <pid>` on success.
    pipe_write(pid_write_fd, &format!("OK {}", child_pid));

    // Restore resumes the child immediately, so persist RUNNING right away
    // (set_created records the PID, set_running flips the status).
    {
        let mut state = SandboxState::load(id)
            .unwrap_or_else(|_| SandboxState::new(id, Path::new("/"), "1.0.2"));
        state.set_created(child_pid);
        state.set_running();
        state.save().ok();
    }

    // Serve the control socket while the resumed child runs (shared with the
    // create+start path). There is no `Start` (the child is already running): a
    // stray `Start` is an idempotent no-op. An independent pidfd watcher detects
    // exit so the sandbox's own pidfd is consumed exactly once, by the final
    // `wait()`, avoiding the cancellation hazard of re-creating `wait()` per
    // select iteration.
    let exit_info = serve_running(id, &mut sandbox, &listener, child_pid).await;

    if let Ok(mut s) = SandboxState::load(id) {
        s.set_stopped(exit_info);
        s.save().ok();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_uses_short_hashed_name_under_state_dir() {
        let p = socket_path("my-sandbox");
        let s = p.to_str().unwrap();
        assert!(s.starts_with(&crate::state::state_dir()));
        assert!(s.ends_with(".sock"));
        // file name is 16 hex chars + ".sock" = 21 bytes, never the raw id.
        assert_eq!(p.file_name().unwrap().to_str().unwrap().len(), 21);
        assert!(!s.contains("my-sandbox"));
    }

    #[test]
    fn socket_filename_keeps_path_under_sun_len_for_cri_root() {
        // containerd's runc-v2 shim passes this root plus a 64-char id.
        let cri_root = "/run/containerd/runc/k8s.io";
        let id = "a".repeat(64);
        let full = format!("{}/{}.sock", cri_root, fnv1a_hex(&id));
        assert!(full.len() < 108, "socket path too long: {} bytes", full.len());
    }

    #[test]
    fn fnv1a_hex_is_deterministic_and_distinct() {
        assert_eq!(fnv1a_hex("abc"), fnv1a_hex("abc"));
        assert_ne!(fnv1a_hex("abc"), fnv1a_hex("abd"));
        assert_eq!(fnv1a_hex("abc").len(), 16);
        assert!(fnv1a_hex("abc").chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn supervisor_cmd_start_serde() {
        let cmd = SupervisorCmd::Start;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("start"));
    }

    #[test]
    fn supervisor_cmd_ping_serde() {
        let cmd = SupervisorCmd::Ping;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("ping"));
    }

    #[test]
    fn supervisor_cmd_shutdown_serde() {
        let cmd = SupervisorCmd::Shutdown;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("shutdown"));
    }

    #[test]
    fn supervisor_reply_ok_serde() {
        let reply = SupervisorReply::Ok;
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("ok"));
    }

    #[test]
    fn supervisor_reply_pid_serde() {
        let reply = SupervisorReply::Pid { pid: 42 };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("42"));
    }

    #[test]
    fn supervisor_reply_err_serde() {
        let reply = SupervisorReply::Err { msg: "test error".into() };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("err"));
        assert!(json.contains("test error"));
    }

    #[test]
    fn supervisor_cmd_checkpoint_serde() {
        let cmd = SupervisorCmd::Checkpoint { dir: "/tmp/img".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("checkpoint"));
        assert!(json.contains("/tmp/img"));
        let back: SupervisorCmd = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, SupervisorCmd::Checkpoint { .. }));
    }

    #[test]
    fn supervisor_cmd_signal_serde() {
        let cmd = SupervisorCmd::Signal { signum: libc::SIGKILL };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("signal"));
        let back: SupervisorCmd = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, SupervisorCmd::Signal { signum: 9 }));
    }
}
