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

/// Format for the runc-compatible `--log` file. runc defaults to `text`; the
/// containerd shim passes `json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

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

    /// Path to append fatal errors to (runc-compatible; read by the
    /// containerd shim to surface the failure reason).
    #[arg(long, global = true)]
    log: Option<PathBuf>,

    /// Format for the --log file. runc defaults to "text"; the containerd
    /// shim passes "json".
    #[arg(long = "log-format", global = true, value_enum, default_value = "text")]
    log_format: LogFormat,

    /// Accepted for runc compatibility; no-op (no logging framework yet).
    #[arg(long, global = true)]
    debug: bool,

    /// Accepted for runc compatibility; ignored (sandlock is cgroup-less).
    #[arg(long = "systemd-cgroup", global = true)]
    systemd_cgroup: bool,

    /// Accepted for runc compatibility; ignored. Both `--rootless` and
    /// `--rootless=true|false` are allowed.
    #[arg(long, global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    rootless: Option<bool>,

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
        /// Accepted for runc compatibility; ignored (sandlock does not pivot_root).
        #[arg(long = "no-pivot")]
        no_pivot: bool,
        /// Accepted for runc compatibility; ignored (no session keyring).
        #[arg(long = "no-new-keyring")]
        no_new_keyring: bool,
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
        /// Accepted for runc compatibility; ignored (sandlock does not pivot_root).
        #[arg(long = "no-pivot")]
        no_pivot: bool,
        /// Accepted for runc compatibility; ignored (no session keyring).
        #[arg(long = "no-new-keyring")]
        no_new_keyring: bool,
    },
}

/// Append a fatal error to the runc-compatible `--log` file so containerd can
/// surface the real failure reason. Never panics: if the file cannot be opened
/// the error is dropped here (it is still printed to stderr by the caller).
fn write_error_log(path: &std::path::Path, format: LogFormat, err: &anyhow::Error) {
    use std::io::Write;
    // `{:#}` renders the full anyhow context chain on one line.
    let msg = format!("{:#}", err);
    let line = match format {
        // serde_json handles correct escaping of arbitrary message text.
        LogFormat::Json => serde_json::json!({ "level": "error", "msg": msg }).to_string(),
        LogFormat::Text => msg,
    };
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}", line);
    }
}

fn main() {
    let cli = Cli::parse();
    // Capture the log destination before `cli.command` is consumed by `run`.
    let log = cli.log.clone();
    let log_format = cli.log_format;
    if let Err(err) = run(cli) {
        if let Some(path) = log.as_deref() {
            write_error_log(path, log_format, &err);
        }
        eprintln!("Error: {:#}", err);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    // Resolve the state-dir root once, before any state I/O or fork, so the
    // supervisor child inherits the same location.
    state::init_state_dir(cli.root.as_deref().and_then(|p| p.to_str()));

    match cli.command {
        Command::Create { id, bundle, pid_file, console_socket: _, no_pivot: _, no_new_keyring: _ } => {
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
        Command::Restore { id, image_path, bundle: _, no_pivot: _, no_new_keyring: _ } => {
            cmd_restore(&id, &image_path)?;
        }
    }

    Ok(())
}

/// How the supervisor daemon should terminate so a reaping containerd shim sees
/// a wait-status that mirrors the workload.
#[derive(Debug, PartialEq, Eq)]
enum ExitAction {
    /// Exit with this code (workload exited normally).
    Code(i32),
    /// Re-raise this signal on self (workload was killed by it) so the shim sees
    /// WIFSIGNALED and reports 128+signal, matching runc.
    Raise(i32),
}

fn supervisor_exit_action(info: Option<state::ExitInfo>) -> ExitAction {
    match info {
        Some(state::ExitInfo { code: Some(c), .. }) => ExitAction::Code(c),
        Some(state::ExitInfo { signal: Some(s), .. }) => ExitAction::Raise(s),
        _ => ExitAction::Code(0),
    }
}

/// Terminate the supervisor daemon with the workload's status. Diverges.
fn supervisor_exit(info: Option<state::ExitInfo>) -> ! {
    match supervisor_exit_action(info) {
        ExitAction::Code(c) => unsafe { libc::_exit(c) },
        ExitAction::Raise(s) => unsafe {
            libc::signal(s as libc::c_int, libc::SIG_DFL);
            libc::raise(s as libc::c_int);
            // raise should not return for a default-action signal; fall back.
            libc::_exit(128 + s)
        },
    }
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

        let exit_info = supervisor::run_supervisor(id, &cmd_args, policy, write_fd)
            .ok()
            .flatten();
        unsafe { libc::close(write_fd) };
        // Exit with the workload's status so a reaping containerd shim reports
        // the right container exit code/signal.
        supervisor_exit(exit_info);
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
    let (supervisor_pid, init_pid) = {
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
            let mut parts = rest.split_whitespace();
            let sup = parts.next().and_then(|s| s.parse::<i32>().ok());
            let init = parts.next().and_then(|s| s.parse::<i32>().ok());
            match (sup, init) {
                (Some(sup), Some(init)) => (sup, init),
                _ => bail!("invalid PIDs in supervisor response: {:?}", response),
            }
        } else if let Some(msg) = response.strip_prefix("ERR ") {
            bail!("sandbox create failed: {}", msg);
        } else {
            bail!("unexpected supervisor response: {:?}", response);
        }
    };

    // state.pid is the OCI container init (sandlock-init); `start` later updates
    // it to the workload pid.
    {
        let mut state = SandboxState::load(id)?;
        state.set_created(init_pid);
        state.save()?;
    }

    // The pid-file gets the SUPERVISOR pid: that is the process the containerd
    // shim reaps to detect container exit (the supervisor is the shim's child
    // and exits with the workload's status).
    if let Some(pf) = pid_file {
        std::fs::write(pf, supervisor_pid.to_string())
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
        // Always ask the supervisor to report the exec'd process's exit. The
        // caller's `--detach` (set by the containerd shim) is handled locally
        // by the exec proxy below, which still needs that exit status.
        detach: false,
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

    if detach {
        // Detached exec (containerd: `exec --detach --pid-file`). The shim
        // expects this CLI to return promptly and reaps the pid-file pid for
        // exit. The exec'd process is sandlock-init's child, which the shim
        // cannot reap; so fork a proxy whose pid goes in the pid-file. When this
        // CLI returns, the proxy reparents to the shim (the subreaper), and the
        // proxy exits with the exec'd process's status, so the shim reaps a
        // matching wait-status. This is the exec-path analog of the create-path
        // supervisor that the shim already reaps.
        let mut rdy = [0i32; 2];
        if unsafe { libc::pipe2(rdy.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            bail!("pipe2 for exec proxy failed: {}", std::io::Error::last_os_error());
        }
        let (rdy_r, rdy_w) = (rdy[0], rdy[1]);
        let kid = unsafe { libc::fork() };
        if kid < 0 {
            bail!("fork exec proxy failed: {}", std::io::Error::last_os_error());
        }
        if kid == 0 {
            // ===== EXEC PROXY =====
            unsafe { libc::close(rdy_r) };
            // Drop the shim's exec stdio so we do not pin those streams open;
            // the exec'd process holds its own dup'd copies (via SCM_RIGHTS), so
            // the shim still sees EOF when that process exits.
            unsafe {
                let n = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
                if n >= 0 {
                    libc::dup2(n, 0);
                    libc::dup2(n, 1);
                    libc::dup2(n, 2);
                    if n > 2 {
                        libc::close(n);
                    }
                }
            }
            // The pid the shim will reap is THIS proxy.
            if let Some(pf) = pid_file {
                let _ = std::fs::write(pf, std::process::id().to_string());
            }
            // Tell the parent the pid-file is written; it can now return.
            unsafe {
                libc::write(rdy_w, b"x".as_ptr() as *const libc::c_void, 1);
                libc::close(rdy_w);
            }
            // Block until the exec'd process exits, then exit with its status.
            let mut line2 = String::new();
            if reader.read_line(&mut line2).is_ok() {
                if let Ok(supervisor::SupervisorReply::Exit { code, signal }) =
                    serde_json::from_str::<supervisor::SupervisorReply>(line2.trim())
                {
                    supervisor_exit(Some(state::ExitInfo { code, signal }));
                }
            }
            // Lost the channel before an Exit arrived: report a generic failure
            // so the shim does not hang.
            unsafe { libc::_exit(255) };
        }
        // ===== PARENT: wait until the proxy has written the pid-file, return =====
        unsafe { libc::close(rdy_w) };
        let mut b = [0u8; 1];
        unsafe {
            libc::read(rdy_r, b.as_mut_ptr() as *mut libc::c_void, 1);
            libc::close(rdy_r);
        }
        return Ok(());
    }

    // Attached: this CLI is the handle the caller waits on. Record the exec'd
    // pid and block until it exits.
    if let Some(pf) = pid_file {
        std::fs::write(pf, exec_pid.to_string())
            .with_context(|| format!("write pid file {:?}", pf))?;
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
    use clap::Parser;

    #[test]
    fn accepts_runc_create_globals() {
        let cli = Cli::try_parse_from([
            "sandlock-oci", "--root", "/r", "--log", "/l", "--log-format", "json",
            "--systemd-cgroup", "--debug",
            "create", "--bundle", "/b", "--pid-file", "/p",
            "--no-pivot", "--no-new-keyring", "id",
        ])
        .expect("should parse runc-style create invocation");
        assert!(matches!(cli.command, Command::Create { .. }));
        assert_eq!(cli.log.as_deref(), Some(std::path::Path::new("/l")));
        assert_eq!(cli.log_format, LogFormat::Json);
    }

    #[test]
    fn accepts_globals_on_other_subcommands() {
        let subs: [&[&str]; 4] = [
            &["state", "id"],
            &["start", "id"],
            &["kill", "id", "SIGKILL"],
            &["delete", "--force", "id"],
        ];
        for sub in subs {
            let mut argv = vec![
                "sandlock-oci", "--root", "/r", "--log", "/l",
                "--log-format", "json", "--systemd-cgroup",
            ];
            argv.extend_from_slice(sub);
            Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("failed to parse {:?}: {e}", argv));
        }
    }

    #[test]
    fn rootless_both_forms_parse() {
        let bare = Cli::try_parse_from(["sandlock-oci", "--rootless", "list"]).unwrap();
        assert_eq!(bare.rootless, Some(true));
        let explicit =
            Cli::try_parse_from(["sandlock-oci", "--rootless=false", "list"]).unwrap();
        assert_eq!(explicit.rootless, Some(false));
    }

    #[test]
    fn supervisor_exit_action_maps_status() {
        assert_eq!(
            supervisor_exit_action(Some(state::ExitInfo { code: Some(7), signal: None })),
            ExitAction::Code(7)
        );
        assert_eq!(
            supervisor_exit_action(Some(state::ExitInfo { code: None, signal: Some(libc::SIGSEGV) })),
            ExitAction::Raise(libc::SIGSEGV)
        );
        assert_eq!(supervisor_exit_action(None), ExitAction::Code(0));
    }

    #[test]
    fn error_log_json_is_parseable_with_msg() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.json");
        let err = anyhow::anyhow!("boom").context("creating sandbox");
        write_error_log(&path, LogFormat::Json, &err);
        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(v["level"], "error");
        let msg = v["msg"].as_str().unwrap();
        assert!(msg.contains("creating sandbox"), "msg was: {msg}");
        assert!(msg.contains("boom"), "msg was: {msg}");
    }

    #[test]
    fn error_log_text_is_plain_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.txt");
        write_error_log(&path, LogFormat::Text, &anyhow::anyhow!("plain failure"));
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.trim(), "plain failure");
    }

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
