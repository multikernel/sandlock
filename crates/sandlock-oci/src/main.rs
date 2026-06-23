//! `sandlock-oci` — OCI runtime shim for the sandlock sandbox.
//!
//! Implements the OCI Runtime Specification command interface so that
//! container runtimes (containerd, CRI-O, Kubernetes) can use sandlock
//! as a drop-in low-level runtime without kernel namespaces.
//!
//! ## Lifecycle
//!
//! ```text
//!   create <id> -b <bundle>  →  spawn Supervisor, sandbox.create(), park Child, save state
//!   start  <id>              →  Supervisor.Start → sandbox.start() → Child execve
//!   state  <id>              →  print state.json (reconciled against liveness)
//!   kill   <id> <signal>     →  forward signal to Child PID
//!   delete <id>              →  send Shutdown to Supervisor, cleanup state dir
//!   exec   <id> <cmd>        →  daemon relays to sandlock-init, which fork-execs a sibling in the same sandbox
//! ```
//!
//! ## Known limitations
//!
//! - The workload and all exec'd processes share one sandbox (one seccomp supervisor)
//!   via an in-sandbox sandlock-init PID-1.
//! - `exec` runs non-TTY only: `-t` / `--console-socket` are accepted for runc
//!   compatibility but ignored (no PTY yet).

mod fdpass;
mod init;
mod policy;
mod spec;
mod state;
mod supervisor;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use state::{SandboxState, Status};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sandlock-oci",
    about = "OCI-compliant runtime for the sandlock sandbox (namespace-less, Landlock-based)",
    version
)]
struct Cli {
    /// Root directory for sandbox state (one subdir per sandbox).
    ///
    /// The OCI-standard knob that containerd/CRI-O pass. When omitted,
    /// defaults to `$XDG_RUNTIME_DIR/sandlock-oci` for unprivileged users
    /// and `/run/sandlock-oci` for root.
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a sandbox. Spawns the Supervisor and forks the child in a
    /// paused state. Saves state to /run/sandlock-oci/<id>/state.json.
    Create {
        /// Unique sandbox identifier.
        id: String,
        /// Path to the OCI bundle directory.
        #[arg(short = 'b', long)]
        bundle: PathBuf,
        /// File descriptor to write the sandbox PID to (optional, for CRI).
        #[arg(long = "pid-file")]
        pid_file: Option<PathBuf>,
        /// Console socket path (ignored — sandlock doesn't use PTYs by default).
        #[arg(long = "console-socket")]
        console_socket: Option<PathBuf>,
    },

    /// Start a previously created sandbox.
    Start {
        /// Sandbox identifier.
        id: String,
    },

    /// Output the state of a sandbox as JSON.
    State {
        /// Sandbox identifier.
        id: String,
    },

    /// Send a signal to a sandbox's init process.
    Kill {
        /// Sandbox identifier.
        id: String,
        /// Signal name or number (e.g. SIGTERM or 15).
        #[arg(default_value = "SIGTERM")]
        signal: String,
        /// Send signal to all processes in the sandbox (not just init).
        #[arg(short, long)]
        all: bool,
    },

    /// Delete a sandbox and its state.
    Delete {
        /// Sandbox identifier.
        id: String,
        /// Force deletion even if the sandbox is still running.
        #[arg(short, long)]
        force: bool,
    },

    /// List all sandboxes managed by sandlock-oci.
    List,

    /// Check kernel feature support (delegates to sandlock-core checks).
    Check,

    /// Execute a process inside a running container (non-TTY).
    ///
    /// Supports inline args (`exec <id> <cmd> [args...]`) and the process-spec
    /// form (`exec --process spec.json <id>`). The exec'd process is fork-exec'd
    /// by the container's in-sandbox `sandlock-init`, so it shares the one
    /// sandbox (and seccomp supervisor) with the container's main process. `-t` /
    /// `--console-socket` are accepted for runc compatibility but ignored (no
    /// PTY yet).
    Exec {
        /// Container identifier.
        id: String,
        /// Path to a process-spec JSON file (OCI `Process`). Takes precedence
        /// over inline command args when provided.
        #[arg(short = 'p', long = "process", value_name = "FILE")]
        process: Option<PathBuf>,
        /// Write the exec process PID to this file.
        #[arg(long = "pid-file", value_name = "PATH")]
        pid_file: Option<PathBuf>,
        /// Detach: return after the process starts without waiting for exit.
        #[arg(short = 'd', long)]
        detach: bool,
        /// Console socket for PTY exec (accepted, ignored: no PTY yet).
        #[arg(long = "console-socket", value_name = "PATH")]
        console_socket: Option<PathBuf>,
        /// Allocate a pseudo-TTY (accepted, ignored: no PTY yet).
        #[arg(short = 't', long)]
        tty: bool,
        /// Environment variable to set (KEY=VALUE). Repeatable.
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Working directory inside the container.
        #[arg(long, value_name = "PATH")]
        cwd: Option<PathBuf>,
        /// Command and arguments to execute inside the container.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Capture a checkpoint of a running sandbox to an image directory.
    Checkpoint {
        /// Sandbox/container ID.
        id: String,
        /// Directory to write the checkpoint image into.
        #[arg(long = "image-path")]
        image_path: String,
    },

    /// Restore a sandbox from a checkpoint image directory (resumes it running).
    Restore {
        /// Sandbox/container ID to create.
        id: String,
        /// Directory containing the checkpoint image.
        #[arg(long = "image-path")]
        image_path: String,
        /// OCI bundle path (accepted for runc compatibility; may be unused).
        #[arg(long = "bundle")]
        bundle: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Resolve the state-dir root once, before any state I/O or fork, so the
    // supervisor child inherits the same location.
    state::init_state_dir(cli.root.as_deref().and_then(|p| p.to_str()));

    match cli.command {
        Command::Create { id, bundle, pid_file, console_socket: _ } => {
            cmd_create(&id, &bundle, pid_file.as_deref())?;
        }
        Command::Start { id } => {
            cmd_start(&id)?;
        }
        Command::State { id } => {
            let mut state = SandboxState::load(&id)
                .with_context(|| format!("no such sandbox: {}", id))?;
            // Reconcile: if we believe the sandbox is running but the process
            // is gone (killed out-of-band), transition to stopped so callers
            // see the current truth rather than stale state.
            if state.status == Status::Running && !state.is_alive() {
                state.set_stopped(None);
                state.save().ok();
            }
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Command::Kill { id, signal, all } => {
            cmd_kill(&id, &signal, all)?;
        }
        Command::Delete { id, force } => {
            cmd_delete(&id, force)?;
        }
        Command::List => {
            let ids = state::list_sandboxes()?;
            if ids.is_empty() {
                println!("No sandlock-oci sandboxes.");
            } else {
                println!("{:<40} {:<10} {}", "ID", "STATUS", "PID");
                for id in ids {
                    if let Ok(s) = SandboxState::load(&id) {
                        println!("{:<40} {:<10} {}", s.id, s.status, s.pid);
                    }
                }
            }
        }
        Command::Exec {
            id,
            process,
            pid_file,
            detach,
            console_socket: _,
            tty: _,
            env,
            cwd,
            command,
        } => {
            cmd_exec(
                &id,
                process.as_deref(),
                pid_file.as_deref(),
                detach,
                &env,
                cwd.as_deref(),
                &command,
            )?;
        }
        Command::Check => {
            match sandlock_core::landlock_abi_version() {
                Ok(v) => {
                    println!("Landlock ABI: v{}", v);
                    println!(
                        "Status: {}",
                        if v >= sandlock_core::MIN_LANDLOCK_ABI {
                            "OK"
                        } else {
                            "UNSUPPORTED"
                        }
                    );
                }
                Err(e) => {
                    eprintln!("Landlock unavailable: {}", e);
                    std::process::exit(1);
                }
            }
            println!("Platform: {}", std::env::consts::ARCH);
        }
        Command::Checkpoint { id, image_path } => {
            cmd_checkpoint(&id, &image_path)?;
        }
        Command::Restore { id, image_path, bundle: _ } => {
            cmd_restore(&id, &image_path)?;
        }
    }

    Ok(())
}

/// `sandlock-oci create <id> -b <bundle>`
///
/// 1. Parse OCI config.json from the bundle.
/// 2. Map spec to an OciPolicy.
/// 3. Save initial `Created` state.
/// 4. Fork a Supervisor (double-fork daemon) which forks the Child.
/// 5. Child is SIGSTOP'd; supervisor writes PID to CLI via pipe (no sleep/race).
fn cmd_create(id: &str, bundle: &PathBuf, pid_file: Option<&std::path::Path>) -> Result<()> {
    // OCI requires the sandbox ID to be unique within the runtime root.
    // Reject a re-used ID up front rather than overwriting the existing
    // sandbox's state and orphaning its supervisor + parked child.  The
    // caller must `delete` the old sandbox first.
    if SandboxState::load(id).is_ok() {
        bail!("sandbox {} already exists", id);
    }

    let bundle = bundle
        .canonicalize()
        .with_context(|| format!("bundle path {:?} does not exist", bundle))?;

    // Load and validate spec
    let spec = spec::load_spec(&bundle)?;
    let policy = spec::spec_to_policy(&spec, &bundle, id)?;

    // Extract the command from the spec — OCI requires non-empty args
    let cmd_args: Vec<String> = spec
        .process()
        .as_ref()
        .and_then(|p| p.args().clone())
        .filter(|args| !args.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "OCI spec process.args is empty; cannot create sandbox without a command"
            )
        })?;

    // Create initial state
    let state = SandboxState::new(id, &bundle, spec.version());
    state.save().with_context(|| format!("save state for sandbox {}", id))?;

    // ── Pipe for synchronous PID notification ────────────────────────────────
    // Supervisor writes the child PID here immediately after forking, so the
    // parent can read it without sleeping or racing.
    let mut pid_pipe: [i32; 2] = [0; 2];
    unsafe {
        if libc::pipe2(pid_pipe.as_mut_ptr(), libc::O_CLOEXEC) < 0 {
            bail!("pipe2 failed: {}", std::io::Error::last_os_error());
        }
    }
    let read_fd = pid_pipe[0];
    let write_fd = pid_pipe[1];

    // ── Double-fork daemonization ────────────────────────────────────────────
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        bail!("fork failed: {}", std::io::Error::last_os_error());
    }

    if pid == 0 {
        // ===== INTERMEDIATE CHILD (becomes daemon, then forks supervisor) =====

        // Close read end — parent reads the PID
        unsafe { libc::close(read_fd); }

        // Detach from the parent's session so we survive the parent exiting.
        unsafe { libc::setsid() };

        // Second fork to fully orphan the supervisor.
        let pid2 = unsafe { libc::fork() };
        if pid2 < 0 {
            unsafe {
                libc::close(write_fd);
                libc::_exit(1);
            }
        }
        if pid2 != 0 {
            // Intermediate child — close write end and exit immediately.
            unsafe {
                libc::close(write_fd);
                libc::_exit(0);
            }
        }

        // ===== SUPERVISOR PROCESS (grandchild) =====

        // Close the read end (inherited from intermediate, not needed here)
        unsafe { libc::close(read_fd); }

        // Detach the daemon's working directory from the caller's so we don't
        // pin a filesystem the caller may later want to unmount.  The
        // sandbox's own cwd comes from the OCI spec via the sandbox policy,
        // independent of the supervisor's cwd.
        unsafe { libc::chdir(b"/\0".as_ptr() as *const libc::c_char); }

        // Redirect only stdin to /dev/null — the supervisor daemon doesn't
        // need input.  stdout/stderr are intentionally *not* redirected:
        // containerd/CRI-O wire the runtime's stdio to the sandbox's log
        // FIFOs, so fds 1 and 2 must be passed through to the child process
        // so that sandbox output reaches `kubectl logs`.
        unsafe {
            let devnull = libc::open(
                b"/dev/null\0".as_ptr() as *const libc::c_char,
                libc::O_RDONLY,
            );
            if devnull >= 0 {
                libc::dup2(devnull, 0);
                if devnull > 0 {
                    libc::close(devnull);
                }
            }
        }

        let _ = supervisor::run_supervisor(id, &cmd_args, policy, write_fd);
        unsafe {
            libc::close(write_fd);
            libc::_exit(0);
        }
    }

    // ===== ORIGINAL PROCESS (caller) =====

    // Close unused write end — only the supervisor writes
    unsafe { libc::close(write_fd) };

    // Wait for the intermediate child so we don't leave a zombie.
    let mut wstatus = 0i32;
    unsafe { libc::waitpid(pid, &mut wstatus, 0) };

    // Read the supervisor's response from the pipe.
    //
    // Protocol: supervisor writes one of:
    //   `OK <pid>\n`   — sandbox created, <pid> is the sandbox's init PID
    //   `ERR <msg>\n`  — setup failed; the sandbox was never created
    //   (EOF)          — supervisor crashed before writing; treated as error
    let child_pid = {
        let mut buf = [0u8; 512];
        let n = unsafe {
            libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        unsafe { libc::close(read_fd) };
        if n <= 0 {
            bail!("supervisor exited without reporting status (check system logs)");
        }
        let response = String::from_utf8_lossy(&buf[..n as usize]);
        let response = response.trim();
        if let Some(rest) = response.strip_prefix("OK ") {
            rest.parse::<i32>()
                .with_context(|| format!("invalid PID in supervisor response: {:?}", response))?
        } else if let Some(msg) = response.strip_prefix("ERR ") {
            bail!("sandbox create failed: {}", msg);
        } else {
            bail!("unexpected supervisor response: {:?}", response);
        }
    };

    // Update the state file with the actual PID.
    {
        let mut state = SandboxState::load(id)?;
        state.set_created(child_pid);
        state.save()?;
    }

    // Write pid-file if requested (CRI-O / containerd expect this).
    if let Some(pf) = pid_file {
        std::fs::write(pf, child_pid.to_string())
            .with_context(|| format!("write pid file {:?}", pf))?;
    }

    Ok(())
}

/// `sandlock-oci restore <id> --image-path <dir>`
///
/// Mirrors [`cmd_create`]'s supervisor-spawn + pid-pipe handshake, but the
/// policy and command come from the checkpoint image (not an OCI bundle), and
/// there is no separate `start`: `run_supervisor_restore` both creates and
/// resumes the child, so the sandbox is `Running` once the handshake succeeds.
fn cmd_restore(id: &str, image_path: &str) -> Result<()> {
    // Reject a re-used ID up front, exactly like `create`.
    if SandboxState::load(id).is_ok() {
        bail!("sandbox {} already exists", id);
    }

    // Persist an initial state so `state`/`delete` work even if the supervisor
    // dies before it can write its own Running state. The supervisor overwrites
    // this with Running once the child is resumed.
    let state = SandboxState::new(id, std::path::Path::new("/"), "1.0.2");
    state.save().with_context(|| format!("save state for sandbox {}", id))?;

    // ── Pipe for synchronous PID notification ────────────────────────────────
    let mut pid_pipe: [i32; 2] = [0; 2];
    unsafe {
        if libc::pipe2(pid_pipe.as_mut_ptr(), libc::O_CLOEXEC) < 0 {
            bail!("pipe2 failed: {}", std::io::Error::last_os_error());
        }
    }
    let read_fd = pid_pipe[0];
    let write_fd = pid_pipe[1];

    let image_path = image_path.to_string();

    // ── Double-fork daemonization (identical to cmd_create) ──────────────────
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        bail!("fork failed: {}", std::io::Error::last_os_error());
    }

    if pid == 0 {
        // ===== INTERMEDIATE CHILD =====
        unsafe { libc::close(read_fd); }
        unsafe { libc::setsid() };

        let pid2 = unsafe { libc::fork() };
        if pid2 < 0 {
            unsafe {
                libc::close(write_fd);
                libc::_exit(1);
            }
        }
        if pid2 != 0 {
            unsafe {
                libc::close(write_fd);
                libc::_exit(0);
            }
        }

        // ===== SUPERVISOR PROCESS (grandchild) =====
        unsafe { libc::close(read_fd); }
        unsafe { libc::chdir(b"/\0".as_ptr() as *const libc::c_char); }
        unsafe {
            let devnull = libc::open(
                b"/dev/null\0".as_ptr() as *const libc::c_char,
                libc::O_RDONLY,
            );
            if devnull >= 0 {
                libc::dup2(devnull, 0);
                if devnull > 0 {
                    libc::close(devnull);
                }
            }
        }

        let _ = supervisor::run_supervisor_restore(id, &image_path, write_fd);
        unsafe {
            libc::close(write_fd);
            libc::_exit(0);
        }
    }

    // ===== ORIGINAL PROCESS (caller) =====
    unsafe { libc::close(write_fd) };

    let mut wstatus = 0i32;
    unsafe { libc::waitpid(pid, &mut wstatus, 0) };

    let child_pid = {
        let mut buf = [0u8; 512];
        let n = unsafe {
            libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        unsafe { libc::close(read_fd) };
        if n <= 0 {
            bail!("supervisor exited without reporting status (check system logs)");
        }
        let response = String::from_utf8_lossy(&buf[..n as usize]);
        let response = response.trim();
        if let Some(rest) = response.strip_prefix("OK ") {
            rest.parse::<i32>()
                .with_context(|| format!("invalid PID in supervisor response: {:?}", response))?
        } else if let Some(msg) = response.strip_prefix("ERR ") {
            bail!("sandbox restore failed: {}", msg);
        } else {
            bail!("unexpected supervisor response: {:?}", response);
        }
    };

    // Restore resumes immediately: record Running with the real PID. This is
    // authoritative regardless of how the supervisor's own state write races.
    {
        let mut state = SandboxState::load(id)?;
        state.set_created(child_pid);
        state.set_running();
        state.save()?;
    }

    Ok(())
}

/// `sandlock-oci start <id>`
///
/// Signals the Supervisor to release the paused child (SIGCONT → execve).
fn cmd_start(id: &str) -> Result<()> {
    // Verify the sandbox exists and is in Created state.
    let state = SandboxState::load(id)
        .with_context(|| format!("no such sandbox: {}", id))?;

    match state.status {
        Status::Created => {} // expected
        Status::Creating => bail!("sandbox {} is still being created", id),
        Status::Running => bail!("sandbox {} is already running", id),
        Status::Stopped => bail!("sandbox {} has already stopped", id),
    }

    // Send Start command to supervisor.
    match supervisor::send_command(id, supervisor::SupervisorCmd::Start)? {
        supervisor::SupervisorReply::Ok => Ok(()),
        supervisor::SupervisorReply::Err { msg } => bail!("supervisor error: {}", msg),
        other => bail!("unexpected supervisor reply: {:?}", other),
    }
}

/// `sandlock-oci kill <id> <signal>`
///
/// Forwards a signal to the sandbox's init process.
fn cmd_kill(id: &str, signal: &str, all: bool) -> Result<()> {
    let state = SandboxState::load(id)
        .with_context(|| format!("no such sandbox: {}", id))?;

    if state.pid <= 0 {
        bail!(
            "sandbox {} has no PID (status: {})",
            id,
            state.status
        );
    }

    let signum = parse_signal(signal)?;

    if all {
        // For group-wide signals, ask the daemon to killpg so it uses the
        // correct pgid (sandlock-init's pid, not the workload's). Fall back
        // to a direct killpg if the daemon is unreachable (already exited).
        let sent = supervisor::send_command(
            id,
            supervisor::SupervisorCmd::Signal { signum },
        );
        if sent.is_err() {
            // Daemon gone: best-effort direct killpg on the recorded pid.
            unsafe { libc::killpg(state.pid, signum) };
        }
    } else {
        let ret = unsafe { libc::kill(state.pid, signum) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // ESRCH means the process is already gone -- not an error.
            if err.raw_os_error() != Some(libc::ESRCH) {
                bail!("kill({}, {}): {}", state.pid, signal, err);
            }
        }
    }
    Ok(())
}

/// `sandlock-oci delete <id>`
///
/// Kills the sandbox (if running) and removes the state directory.
fn cmd_delete(id: &str, force: bool) -> Result<()> {
    let state = match SandboxState::load(id) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    if state.status == Status::Running && !force {
        bail!("sandbox {} is still running; use --force or kill it first", id);
    }

    // If the supervisor is blocked waiting for `start`, send Shutdown so it
    // exits cleanly rather than leaking a process.  Ignore send errors: the
    // supervisor may have already exited or the socket may not exist yet.
    if matches!(state.status, Status::Creating | Status::Created) {
        let _ = supervisor::send_command(id, supervisor::SupervisorCmd::Shutdown);
    }

    // If running with --force, ask the daemon to shutdown (it sends Shutdown to
    // sandlock-init, which killpg's its group and exits). This correctly targets
    // the process group even when state.pid is the workload (not the pgid).
    // Fall back to a direct killpg if the daemon is already gone.
    if state.status == Status::Running && state.pid > 0 && state.is_alive() {
        let sent = supervisor::send_command(id, supervisor::SupervisorCmd::Shutdown);
        if sent.is_err() {
            // Daemon already gone: kill whatever we can reach.
            unsafe { libc::killpg(state.pid, libc::SIGKILL) };
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Remove supervisor socket.
    let sock = supervisor::socket_path(id);
    std::fs::remove_file(&sock).ok();

    // Remove state directory.
    state.delete()?;
    Ok(())
}

/// `sandlock-oci checkpoint <id> --image-path <dir>`
///
/// Asks the Supervisor to snapshot the running sandbox into an image directory.
fn cmd_checkpoint(id: &str, image_path: &str) -> Result<()> {
    match supervisor::send_command(id, supervisor::SupervisorCmd::Checkpoint { dir: image_path.to_string() })? {
        supervisor::SupervisorReply::Ok => Ok(()),
        supervisor::SupervisorReply::Err { msg } => bail!("checkpoint failed: {}", msg),
        other => bail!("unexpected supervisor reply: {:?}", other),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Resolved request for an exec'd process: command, environment overrides, and
/// optional working directory. Built from either a `--process` spec JSON or
/// inline args, with `--env`/`--cwd` flags merged on top.
#[derive(Debug)]
struct ExecRequest {
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<String>,
}

/// Resolve the exec command/env/cwd from a process-spec file or inline args.
/// `--env` entries merge over (and override) the spec's env; `--cwd` overrides
/// the spec's cwd.
fn resolve_exec_request(
    process_file: Option<&std::path::Path>,
    inline_args: &[String],
    extra_env: &[String],
    extra_cwd: Option<&std::path::Path>,
) -> Result<ExecRequest> {
    use std::collections::BTreeMap;

    let (args, mut env_map, mut cwd): (Vec<String>, BTreeMap<String, String>, Option<String>) =
        if let Some(pf) = process_file {
            let raw = std::fs::read_to_string(pf)
                .with_context(|| format!("read process spec {:?}", pf))?;
            let proc: oci_spec::runtime::Process =
                serde_json::from_str(&raw).context("parse process spec JSON")?;
            let args = proc.args().as_ref().cloned().unwrap_or_default();
            let env: BTreeMap<String, String> = proc
                .env()
                .as_ref()
                .map(|e| {
                    e.iter()
                        .filter_map(|v| v.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            let c = proc.cwd().to_string_lossy().to_string();
            let cwd = if c.is_empty() { None } else { Some(c) };
            (args, env, cwd)
        } else {
            (inline_args.to_vec(), BTreeMap::new(), None)
        };

    for kv in extra_env {
        if let Some((k, v)) = kv.split_once('=') {
            env_map.insert(k.to_string(), v.to_string());
        }
    }
    if let Some(c) = extra_cwd {
        cwd = Some(c.to_string_lossy().to_string());
    }

    if args.is_empty() {
        bail!("exec requires a command; pass it after the container ID or use --process");
    }

    Ok(ExecRequest {
        args,
        env: env_map.into_iter().collect(),
        cwd,
    })
}

/// `sandlock-oci exec <id> [--process spec.json] [-- <cmd> [args...]]`
///
/// Connects to the container's supervisor, passes this process's stdio fds via
/// SCM_RIGHTS, and asks the supervisor to spawn the command under a clone of the
/// container policy. Attached (default): block until the exec'd process exits
/// and exit with its status. `--detach`: return after it starts.
fn cmd_exec(
    id: &str,
    process_file: Option<&std::path::Path>,
    pid_file: Option<&std::path::Path>,
    detach: bool,
    extra_env: &[String],
    extra_cwd: Option<&std::path::Path>,
    inline_args: &[String],
) -> Result<()> {
    use std::io::BufRead;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    let state = SandboxState::load(id).with_context(|| format!("no such container: {}", id))?;
    if state.status != Status::Running {
        bail!("container {} is not running (status: {})", id, state.status);
    }

    let req = resolve_exec_request(process_file, inline_args, extra_env, extra_cwd)?;

    let cmd = supervisor::SupervisorCmd::Exec {
        args: req.args,
        env: req.env,
        cwd: req.cwd,
        detach,
    };
    let payload = serde_json::to_vec(&cmd).context("serialize exec command")?;

    let sock = supervisor::socket_path(id);
    let stream = UnixStream::connect(&sock)
        .with_context(|| format!("connect to supervisor socket {:?}", sock))?;

    // Pass our stdin/stdout/stderr to the supervisor alongside the command.
    fdpass::send_with_fds(
        &stream,
        &payload,
        &[
            std::io::stdin().as_raw_fd(),
            std::io::stdout().as_raw_fd(),
            std::io::stderr().as_raw_fd(),
        ],
    )
    .context("send exec command + stdio fds")?;

    let mut reader = std::io::BufReader::new(&stream);

    // First reply: Pid (or Err).
    let mut line = String::new();
    reader.read_line(&mut line).context("read exec pid reply")?;
    let pid_reply: supervisor::SupervisorReply =
        serde_json::from_str(line.trim()).context("parse exec pid reply")?;
    let exec_pid = match pid_reply {
        supervisor::SupervisorReply::Pid { pid } => pid,
        supervisor::SupervisorReply::Err { msg } => bail!("exec failed: {}", msg),
        other => bail!("unexpected exec reply: {:?}", other),
    };

    if let Some(pf) = pid_file {
        std::fs::write(pf, exec_pid.to_string())
            .with_context(|| format!("write pid file {:?}", pf))?;
    }

    if detach {
        return Ok(());
    }

    // Second reply: Exit. Exit this CLI with the same status.
    let mut line2 = String::new();
    reader.read_line(&mut line2).context("read exec exit reply")?;
    let exit_reply: supervisor::SupervisorReply =
        serde_json::from_str(line2.trim()).context("parse exec exit reply")?;
    match exit_reply {
        supervisor::SupervisorReply::Exit { code, signal } => {
            if let Some(c) = code {
                std::process::exit(c);
            }
            if let Some(s) = signal {
                std::process::exit(128 + s);
            }
            std::process::exit(0);
        }
        supervisor::SupervisorReply::Err { msg } => bail!("exec failed: {}", msg),
        other => bail!("unexpected exec exit reply: {:?}", other),
    }
    // Every arm above diverges (process::exit or bail!), so the match types as
    // `!` and is the function's tail expression: no trailing Ok(()) needed.
}

/// Parse a signal name (e.g. "SIGTERM", "TERM", "15") into a libc signal number.
fn parse_signal(s: &str) -> Result<i32> {
    // Try numeric first.
    if let Ok(n) = s.parse::<i32>() {
        return Ok(n);
    }
    // Strip "SIG" prefix for named signals.
    let s_up = s.to_uppercase();
    let name = s_up.strip_prefix("SIG").unwrap_or(&s_up);
    let sig = match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "KILL" => libc::SIGKILL,
        "TERM" => libc::SIGTERM,
        "STOP" => libc::SIGSTOP,
        "CONT" => libc::SIGCONT,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        other => bail!("unknown signal: {}", other),
    };
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_signal_numeric() {
        assert_eq!(parse_signal("15").unwrap(), libc::SIGTERM);
        assert_eq!(parse_signal("9").unwrap(), libc::SIGKILL);
    }

    #[test]
    fn parse_signal_name() {
        assert_eq!(parse_signal("SIGTERM").unwrap(), libc::SIGTERM);
        assert_eq!(parse_signal("TERM").unwrap(), libc::SIGTERM);
        assert_eq!(parse_signal("sigkill").unwrap(), libc::SIGKILL);
    }

    #[test]
    fn parse_signal_unknown_errors() {
        assert!(parse_signal("SIGNOTREAL").is_err());
    }

    #[test]
    fn resolve_inline_args_with_env_and_cwd() {
        let req = resolve_exec_request(
            None,
            &["sh".to_string(), "-c".to_string(), "echo hi".to_string()],
            &["FOO=bar".to_string(), "BAZ=qux".to_string()],
            Some(std::path::Path::new("/work")),
        )
        .unwrap();
        assert_eq!(req.args, vec!["sh", "-c", "echo hi"]);
        assert!(req.env.contains(&("FOO".to_string(), "bar".to_string())));
        assert!(req.env.contains(&("BAZ".to_string(), "qux".to_string())));
        assert_eq!(req.cwd.as_deref(), Some("/work"));
    }

    #[test]
    fn resolve_empty_command_errors() {
        let err = resolve_exec_request(None, &[], &[], None).unwrap_err();
        assert!(err.to_string().contains("requires a command"));
    }

    #[test]
    fn resolve_process_spec_json() {
        let dir = std::env::temp_dir().join(format!("sl-exec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spec = dir.join("process.json");
        std::fs::write(
            &spec,
            r#"{"user":{"uid":0,"gid":0},"args":["/bin/true"],"env":["A=1"],"cwd":"/srv"}"#,
        )
        .unwrap();
        let req = resolve_exec_request(Some(&spec), &[], &["B=2".to_string()], None).unwrap();
        assert_eq!(req.args, vec!["/bin/true"]);
        // --env merges on top of the spec env.
        assert!(req.env.contains(&("A".to_string(), "1".to_string())));
        assert!(req.env.contains(&("B".to_string(), "2".to_string())));
        assert_eq!(req.cwd.as_deref(), Some("/srv"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
