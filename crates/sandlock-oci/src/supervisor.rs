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
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::policy::OciPolicy;
use crate::state::SandboxState;

/// Filename of the supervisor control socket inside the sandbox state dir.
pub const SUPERVISOR_SOCKET: &str = "supervisor.sock";

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

/// Returns the path to the supervisor socket for the given sandbox ID.
pub fn socket_path(id: &str) -> PathBuf {
    PathBuf::from(crate::state::state_dir())
        .join(id)
        .join(SUPERVISOR_SOCKET)
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
) -> Result<()> {
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
async fn supervisor_main(
    id: &str,
    cmd: &[String],
    mut sandbox: sandlock_core::Sandbox,
    sock_path: PathBuf,
    pid_write_fd: i32,
) -> Result<()> {
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

    // OCI `create` — forks the child, installs the full sandlock policy
    // (seccomp-notify + Landlock + resource limits + network ACL), and parks
    // the child before execve using a pipe rather than SIGSTOP.
    let cmd_refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
    if let Err(e) = sandbox.create_interactive(&cmd_refs).await {
        pipe_write(pid_write_fd, &format!("ERR create: {}", e));
        return Err(anyhow::anyhow!("sandbox create_interactive: {}", e));
    }

    let child_pid = sandbox.pid().unwrap_or(0) as i32;

    // Notify the CLI: `OK <pid>` on success.  The CLI treats any non-OK
    // response (or EOF) as a create failure, so this is the only success path.
    pipe_write(pid_write_fd, &format!("OK {}", child_pid));

    // Persist Created state with the real child PID.
    {
        let mut state = SandboxState::load(id).unwrap_or_else(|_| {
            SandboxState::new(id, Path::new("/"), "1.0.2")
        });
        state.set_created(child_pid);
        state.save().ok();
    }

    // PRE-START accept-loop: serve CLI commands until `Start` (transition to
    // the running-serve loop) or `Shutdown`/error (return so the Sandbox Drop
    // kills and reaps the parked child).
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return Ok(()),
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
                    serde_json::to_vec(&SupervisorReply::Pid { pid: child_pid }).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
            }
            SupervisorCmd::Start => {
                // OCI `start` — release the parked child to execve with the
                // full sandlock policy already in place.
                match sandbox.start() {
                    Ok(()) => {
                        if let Ok(mut s) = SandboxState::load(id) {
                            s.set_running();
                            s.save().ok();
                        }
                        let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                        // Child is now running: keep serving the control socket
                        // (so `checkpoint` works) until it exits or Shutdown.
                        let exit_info =
                            serve_running(id, &mut sandbox, &listener, child_pid).await;
                        if let Ok(mut s) = SandboxState::load(id) {
                            s.set_stopped(exit_info);
                            s.save().ok();
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        let reply = serde_json::to_vec(&SupervisorReply::Err { msg: e.to_string() })
                            .unwrap_or_default();
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.write_all(b"\n").await;
                        // start() failed with the child still parked: do NOT
                        // wait() (it would block forever on a child that never
                        // execve's).  Return so the Sandbox Drop kills and reaps
                        // the parked child.
                        return Ok(());
                    }
                }
            }
            SupervisorCmd::Shutdown => {
                // `delete` before `start` — acknowledge and exit.  The sandbox
                // Drop will kill and reap the parked child.
                let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
                let _ = stream.write_all(&reply).await;
                let _ = stream.write_all(b"\n").await;
                return Ok(());
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
        SupervisorCmd::Shutdown => {
            let reply = serde_json::to_vec(&SupervisorReply::Ok).unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Shutdown
        }
        // Temporary: Task 4 replaces this with the real exec handler.
        SupervisorCmd::Exec { .. } => {
            let reply = serde_json::to_vec(&SupervisorReply::Err {
                msg: "exec not wired yet".into(),
            })
            .unwrap_or_default();
            let _ = stream.write_all(&reply).await;
            let _ = stream.write_all(b"\n").await;
            RunningCmd::Continue
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

    // Restore: forks the child under the saved policy, injects the checkpoint,
    // and RESUMES it. The child is already running on return — there is no
    // separate start step.
    let skipped = match sandbox.restore_interactive(&cp).await {
        Ok(s) => s,
        Err(e) => {
            pipe_write(pid_write_fd, &format!("ERR restore: {}", e));
            return Err(anyhow::anyhow!("sandbox restore_interactive: {}", e));
        }
    };
    for path in &skipped {
        eprintln!("sandlock: not transparently restored: {}", path);
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
    fn socket_path_is_under_state_dir() {
        let p = socket_path("my-sandbox");
        assert!(p.to_str().unwrap().contains("my-sandbox"));
        assert!(p.to_str().unwrap().contains("supervisor.sock"));
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
    fn supervisor_cmd_exec_serde() {
        let cmd = SupervisorCmd::Exec {
            args: vec!["sh".into(), "-c".into(), "echo hi".into()],
            env: vec![("FOO".into(), "bar".into())],
            cwd: Some("/work".into()),
            detach: false,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("exec"));
        let back: SupervisorCmd = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, SupervisorCmd::Exec { .. }));
    }

    #[test]
    fn supervisor_reply_exit_serde() {
        let reply = SupervisorReply::Exit { code: Some(3), signal: None };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("exit"));
        assert!(json.contains('3'));
        let back: SupervisorReply = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, SupervisorReply::Exit { code: Some(3), .. }));
    }
}
