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
//! ## exec
//!
//! `exec` re-applies the container's Landlock policy to the calling process
//! and then execvp's the requested command.  Because sandlock does not use
//! Linux namespaces, exec simply confines the new process with the same
//! filesystem rules as the original container.

mod policy;
mod spec;
mod state;
mod supervisor;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use state::{ContainerState, Status};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sandlock-oci",
    about = "OCI-compliant runtime for the sandlock sandbox (namespace-less, Landlock-based)",
    version
)]
struct Cli {
    /// Enable debug logging to stderr.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a container. Spawns the Supervisor and forks the child in a
    /// paused state. Saves state to /run/sandlock-oci/<id>/state.json.
    Create {
        /// Unique container identifier.
        id: String,
        /// Path to the OCI bundle directory.
        #[arg(short = 'b', long)]
        bundle: PathBuf,
        /// File descriptor to write the container PID to (optional, for CRI).
        #[arg(long = "pid-file")]
        pid_file: Option<PathBuf>,
        /// Console socket path (ignored — sandlock doesn't use PTYs by default).
        #[arg(long = "console-socket")]
        console_socket: Option<PathBuf>,
    },

    /// Start a previously created container.
    Start {
        /// Container identifier.
        id: String,
    },

    /// Output the state of a container as JSON.
    State {
        /// Container identifier.
        id: String,
    },

    /// Send a signal to a container's init process.
    Kill {
        /// Container identifier.
        id: String,
        /// Signal name or number (e.g. SIGTERM or 15).
        #[arg(default_value = "SIGTERM")]
        signal: String,
        /// Send signal to all processes in the container (not just init).
        #[arg(short, long)]
        all: bool,
    },

    /// Delete a container and its state.
    Delete {
        /// Container identifier.
        id: String,
        /// Force deletion even if the container is still running.
        #[arg(short, long)]
        force: bool,
    },

    /// List all containers managed by sandlock-oci.
    List,

    /// Check kernel feature support (delegates to sandlock-core checks).
    Check,

    /// Execute a process inside a running container.
    ///
    /// Re-applies the container's Landlock policy to the current process then
    /// execvp's the requested command.  Supports both the inline-args form
    /// (`exec <id> <cmd> [args...]`) and the process-spec form
    /// (`exec --process spec.json <id>`).
    Exec {
        /// Container identifier.
        id: String,

        /// Path to a process spec JSON file (OCI `Process` object).
        /// Takes precedence over inline command args when provided.
        #[arg(short = 'p', long = "process", value_name = "FILE")]
        process: Option<PathBuf>,

        /// Write the exec process PID to this file.
        #[arg(long = "pid-file", value_name = "PATH")]
        pid_file: Option<PathBuf>,

        /// Detach: run the exec process in the background without waiting.
        #[arg(short = 'd', long)]
        detach: bool,

        /// Console socket for PTY-based exec (parsed but not used).
        #[arg(long = "console-socket", value_name = "PATH")]
        console_socket: Option<PathBuf>,

        /// Environment variable to set (KEY=VALUE). Repeatable.
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Working directory inside the container.
        #[arg(long, value_name = "PATH")]
        cwd: Option<PathBuf>,

        /// Allocate a pseudo-TTY (flag accepted; TTY handling not yet wired).
        #[arg(short = 't', long)]
        tty: bool,

        /// Command and arguments to execute inside the container.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Create { id, bundle, pid_file, console_socket: _ } => {
            cmd_create(&id, &bundle, pid_file.as_deref())?;
        }
        Command::Start { id } => {
            cmd_start(&id)?;
        }
        Command::State { id } => {
            let mut state = ContainerState::load(&id)
                .with_context(|| format!("no such container: {}", id))?;
            // Reconcile: if we believe the container is running but the process
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
            let ids = state::list_containers()?;
            if ids.is_empty() {
                println!("No sandlock-oci containers.");
            } else {
                println!("{:<40} {:<10} {}", "ID", "STATUS", "PID");
                for id in ids {
                    if let Ok(s) = ContainerState::load(&id) {
                        println!("{:<40} {:<10} {}", s.id, s.status, s.pid);
                    }
                }
            }
        }
        Command::Exec { id, process, pid_file, detach, console_socket: _, tty: _, env, cwd, command } => {
            cmd_exec(&id, process.as_deref(), pid_file.as_deref(), detach, &env, cwd.as_deref(), &command)?;
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
    let bundle = bundle
        .canonicalize()
        .with_context(|| format!("bundle path {:?} does not exist", bundle))?;

    // Load and validate spec
    let spec = spec::load_spec(&bundle)?;
    let policy = spec::spec_to_policy(&spec, &bundle)?;

    // Extract the command from the spec — OCI requires non-empty args
    let cmd_args: Vec<String> = spec
        .process()
        .as_ref()
        .and_then(|p| p.args().clone())
        .filter(|args| !args.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "OCI spec process.args is empty; cannot create container without a command"
            )
        })?;

    // Create initial state
    let state = ContainerState::new(id, &bundle, spec.version());
    state.save().with_context(|| format!("save state for container {}", id))?;

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

        // Redirect only stdin to /dev/null — the supervisor daemon doesn't
        // need input.  stdout/stderr are intentionally *not* redirected:
        // containerd/CRI-O wire the runtime's stdio to the container's log
        // FIFOs, so fds 1 and 2 must be passed through to the child process
        // so that container output reaches `kubectl logs`.
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
    //   `OK <pid>\n`   — sandbox created, <pid> is the container's init PID
    //   `ERR <msg>\n`  — setup failed; the container was never created
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
            bail!("container create failed: {}", msg);
        } else {
            bail!("unexpected supervisor response: {:?}", response);
        }
    };

    // Update the state file with the actual PID.
    {
        let mut state = ContainerState::load(id)?;
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

/// `sandlock-oci start <id>`
///
/// Signals the Supervisor to release the paused child (SIGCONT → execve).
fn cmd_start(id: &str) -> Result<()> {
    // Verify the container exists and is in Created state.
    let state = ContainerState::load(id)
        .with_context(|| format!("no such container: {}", id))?;

    match state.status {
        Status::Created => {} // expected
        Status::Creating => bail!("container {} is still being created", id),
        Status::Running => bail!("container {} is already running", id),
        Status::Stopped => bail!("container {} has already stopped", id),
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
/// Forwards a signal to the container's init process.
fn cmd_kill(id: &str, signal: &str, all: bool) -> Result<()> {
    let state = ContainerState::load(id)
        .with_context(|| format!("no such container: {}", id))?;

    if state.pid <= 0 {
        bail!(
            "container {} has no PID (status: {})",
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
/// Kills the container (if running) and removes the state directory.
fn cmd_delete(id: &str, force: bool) -> Result<()> {
    let state = match ContainerState::load(id) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    if state.status == Status::Running && !force {
        bail!("container {} is still running; use --force or kill it first", id);
    }

    // If the supervisor is blocked waiting for `start`, send Shutdown so it
    // exits cleanly rather than leaking a process.  Ignore send errors — the
    // supervisor may have already exited or the socket may not exist yet.
    if matches!(state.status, Status::Creating | Status::Created) {
        let _ = supervisor::send_command(id, supervisor::SupervisorCmd::Shutdown);
    }

    // Kill the container process if it's still alive (Running + force, or any
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

/// `sandlock-oci exec <id> [--process spec.json] [-- <cmd> [args...]]`
///
/// Re-applies the container's Landlock policy to the current process, then
/// execvp's the requested command.  Because sandlock does not use Linux
/// namespaces the exec simply runs with the same filesystem confinement as the
/// original container — no `setns` / `nsenter` is required.
fn cmd_exec(
    id: &str,
    process_file: Option<&std::path::Path>,
    pid_file: Option<&std::path::Path>,
    detach: bool,
    extra_env: &[String],
    extra_cwd: Option<&std::path::Path>,
    inline_args: &[String],
) -> Result<()> {
    use std::ffi::CString;
    use std::collections::HashMap;

    let state = ContainerState::load(id)
        .with_context(|| format!("no such container: {}", id))?;

    if state.status != Status::Running {
        bail!("container {} is not running (status: {})", id, state.status);
    }

    // ── Resolve the command, env, and cwd ─────────────────────────────────
    let (cmd, mut env_map, resolved_cwd) = if let Some(pf) = process_file {
        let raw = std::fs::read_to_string(pf)
            .with_context(|| format!("read process spec {:?}", pf))?;
        let proc: oci_spec::runtime::Process = serde_json::from_str(&raw)
            .context("parse process spec JSON")?;

        let cmd: Vec<String> = proc.args().as_ref().cloned()
            .filter(|a| !a.is_empty())
            .unwrap_or_default();

        let env: HashMap<String, String> = proc.env().as_ref()
            .map(|env| env.iter()
                .filter_map(|v| v.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
                .collect())
            .unwrap_or_default();

        let cwd = Some(proc.cwd().clone());
        (cmd, env, cwd)
    } else {
        if inline_args.is_empty() {
            bail!("exec requires a command; pass it after the container ID or use --process");
        }
        (inline_args.to_vec(), HashMap::new(), extra_cwd.map(|p| p.to_path_buf()))
    };

    if cmd.is_empty() {
        bail!("exec: command is empty");
    }

    // Merge any extra --env flags
    for kv in extra_env {
        if let Some((k, v)) = kv.split_once('=') {
            env_map.insert(k.to_string(), v.to_string());
        }
    }

    // ── Re-derive the OCI policy from the original bundle ─────────────────
    let spec = spec::load_spec(&state.bundle)?;
    let policy = spec::spec_to_policy(&spec, &state.bundle)?;

    // ── If detach, fork and let the parent return immediately ─────────────
    if detach {
        let child = unsafe { libc::fork() };
        if child < 0 {
            bail!("fork for detach failed: {}", std::io::Error::last_os_error());
        }
        if child != 0 {
            // Parent returns immediately; child continues below.
            if let Some(pf) = pid_file {
                std::fs::write(pf, child.to_string())
                    .with_context(|| format!("write pid file {:?}", pf))?;
            }
            return Ok(());
        }
        // Detached child: redirect stdin/stdout/stderr to /dev/null
        unsafe {
            let devnull = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
            if devnull >= 0 {
                libc::dup2(devnull, 0);
                libc::dup2(devnull, 1);
                libc::dup2(devnull, 2);
                if devnull > 2 { libc::close(devnull); }
            }
        }
    }

    // ── Apply Landlock confinement from the original policy ────────────────
    let mut cb = sandlock_core::ConfinementBuilder::default();
    for p in &policy.fs_read  { cb = cb.fs_read(p); }
    for p in &policy.fs_write { cb = cb.fs_write(p); }
    sandlock_core::confine(&cb.build()).map_err(|e| anyhow::anyhow!("{}", e))?;

    // ── Apply chroot (if the container had a rootfs) ───────────────────────
    if let Some(ref rootfs) = policy.rootfs {
        let c = CString::new(rootfs.to_string_lossy().as_ref())
            .context("rootfs path contains NUL")?;
        if unsafe { libc::chroot(c.as_ptr()) } != 0 {
            bail!("chroot({:?}) failed: {}", rootfs, std::io::Error::last_os_error());
        }
        if unsafe { libc::chdir(b"/\0".as_ptr() as *const libc::c_char) } != 0 {
            bail!("chdir(/) after chroot failed: {}", std::io::Error::last_os_error());
        }
    }

    // ── Apply working directory ────────────────────────────────────────────
    let cwd_to_use = resolved_cwd.as_deref().or(extra_cwd).or(policy.cwd.as_deref());
    if let Some(cwd) = cwd_to_use {
        let c = CString::new(cwd.to_string_lossy().as_ref())
            .context("cwd path contains NUL")?;
        if unsafe { libc::chdir(c.as_ptr()) } != 0 {
            bail!("chdir({:?}) failed: {}", cwd, std::io::Error::last_os_error());
        }
    }

    // ── Apply environment ─────────────────────────────────────────────────
    for (k, v) in &env_map {
        std::env::set_var(k, v);
    }

    // ── Write pid file (non-detach path) ──────────────────────────────────
    if !detach {
        if let Some(pf) = pid_file {
            let pid = unsafe { libc::getpid() };
            std::fs::write(pf, pid.to_string())
                .with_context(|| format!("write pid file {:?}", pf))?;
        }
    }

    // ── execvp ────────────────────────────────────────────────────────────
    let prog = CString::new(cmd[0].as_str()).context("invalid command")?;
    let c_args: Vec<CString> = cmd.iter()
        .map(|a| CString::new(a.as_str()).unwrap_or_else(|_| CString::new("?").unwrap()))
        .collect();
    let mut ptrs: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()) };
    bail!("execvp({:?}) failed: {}", cmd[0], std::io::Error::last_os_error())
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