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
//! ```
//!
//! ## Known limitations
//!
//! - `exec` is not implemented (required for `kubectl exec` / exec probes).

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

    /// Execute a process inside a running sandbox.
    ///
    /// **Not yet implemented.** Required for `kubectl exec` and exec-based
    /// liveness/readiness probes.  Tracked as a known limitation.
    ///
    /// All arguments are accepted without validation so that containerd/CRI-O
    /// invocations (which pass flags like `--process`, `--detach`, `--pid-file`
    /// *before* the sandbox-id) parse cleanly and receive a clear error.
    Exec {
        /// All exec arguments captured as-is (id, flags, command).
        /// `allow_hyphen_values` + `trailing_var_arg` ensure that runc-style
        /// flags preceding the sandbox-id do not trigger an "unexpected
        /// argument" error.
        #[arg(num_args = 0.., trailing_var_arg = true, allow_hyphen_values = true)]
        _args: Vec<String>,
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
        Command::Exec { _args: _ } => {
            bail!(
                "`exec` is not implemented in sandlock-oci. \
                 It is required for kubectl exec and exec-based probes but has not \
                 yet been built (tracked as a known limitation)."
            );
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

    let ret = if all {
        // Kill the entire process group.
        unsafe { libc::killpg(state.pid, signum) }
    } else {
        unsafe { libc::kill(state.pid, signum) }
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // ESRCH means the process is already gone — not an error.
        if err.raw_os_error() != Some(libc::ESRCH) {
            bail!("kill({}, {}): {}", state.pid, signal, err);
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
    // exits cleanly rather than leaking a process.  Ignore send errors — the
    // supervisor may have already exited or the socket may not exist yet.
    if matches!(state.status, Status::Creating | Status::Created) {
        let _ = supervisor::send_command(id, supervisor::SupervisorCmd::Shutdown);
    }

    // Kill the sandbox process if it's still alive (Running + force, or any
    // state where the child is alive).
    if state.pid > 0 && state.is_alive() {
        unsafe { libc::killpg(state.pid, libc::SIGKILL) };
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
}