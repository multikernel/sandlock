//! `sandlock-oci` — OCI runtime shim for the sandlock sandbox.
//!
//! Implements the OCI Runtime Specification command interface so that
//! container runtimes (containerd, CRI-O, Kubernetes) can use sandlock
//! as a drop-in low-level runtime without kernel namespaces.
//!
//! ## Lifecycle
//!
//! ```text
//!   create <id> -b <bundle>  →  spawn Supervisor, fork Child (SIGSTOP'd), save state
//!   start  <id>              →  signal Supervisor → Child execve
//!   state  <id>              →  print state.json
//!   kill   <id> <signal>     →  forward signal to Child PID
//!   delete <id>              →  cleanup state dir, kill Supervisor/Child
//! ```

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // ── create ───────────────────────────────────────────────────────────
        Command::Create { id, bundle, pid_file, console_socket: _ } => {
            cmd_create(&id, &bundle, pid_file.as_deref())?;
        }

        // ── start ────────────────────────────────────────────────────────────
        Command::Start { id } => {
            cmd_start(&id)?;
        }

        // ── state ────────────────────────────────────────────────────────────
        Command::State { id } => {
            let state = ContainerState::load(&id)
                .with_context(|| format!("no such container: {}", id))?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }

        // ── kill ─────────────────────────────────────────────────────────────
        Command::Kill { id, signal, all } => {
            cmd_kill(&id, &signal, all)?;
        }

        // ── delete ───────────────────────────────────────────────────────────
        Command::Delete { id, force } => {
            cmd_delete(&id, force)?;
        }

        // ── list ─────────────────────────────────────────────────────────────
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

        // ── check ────────────────────────────────────────────────────────────
        Command::Check => {
            match sandlock_core::landlock_abi_version() {
                Ok(v) => {
                    println!("Landlock ABI: v{}", v);
                    println!(
                        "Status: {}",
                        if v >= sandlock_core::MIN_LANDLOCK_ABI { "OK" } else { "UNSUPPORTED" }
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

// ── Command implementations ──────────────────────────────────────────────────

/// `sandlock-oci create <id> -b <bundle>`
///
/// 1. Parse OCI config.json from the bundle.
/// 2. Map spec to sandlock Policy.
/// 3. Save initial `Created` state.
/// 4. Fork a Supervisor process (daemonized) which in turn forks the Child
///    and parks it with SIGSTOP.
fn cmd_create(id: &str, bundle: &PathBuf, pid_file: Option<&std::path::Path>) -> Result<()> {
    let bundle = bundle
        .canonicalize()
        .with_context(|| format!("bundle path {:?} does not exist", bundle))?;

    // Load and validate spec
    let spec = spec::load_spec(&bundle)?;
    let _builder = spec::spec_to_policy(&spec, &bundle)?;

    // Extract the command from the spec
    let cmd_args: Vec<String> = spec
        .process()
        .as_ref()
        .and_then(|p| p.args().clone())
        .unwrap_or_else(|| vec!["sh".to_string()]);

    // Create initial state
    let state = ContainerState::new(id, &bundle, spec.version());
    state.save().with_context(|| format!("save state for container {}", id))?;

    // Daemonize the supervisor into a background process.
    // We double-fork so the supervisor is fully detached from the caller's
    // process group (containerd / nerdctl don't want to wait for it).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork failed: {}", std::io::Error::last_os_error());
    }

    if pid == 0 {
        // ===== INTERMEDIATE CHILD (will become supervisor) =====

        // Detach from the parent's session so we survive the parent exiting.
        unsafe { libc::setsid() };

        // Second fork to fully orphan the supervisor.
        let pid2 = unsafe { libc::fork() };
        if pid2 < 0 {
            unsafe { libc::_exit(1) };
        }
        if pid2 != 0 {
            // Intermediate child exits immediately.
            unsafe { libc::_exit(0) };
        }

        // ===== SUPERVISOR PROCESS =====

        // Redirect stdout/stderr to /dev/null to avoid polluting the caller.
        unsafe {
            let devnull = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
            if devnull >= 0 {
                libc::dup2(devnull, 0);
                libc::dup2(devnull, 1);
                libc::dup2(devnull, 2);
                if devnull > 2 { libc::close(devnull); }
            }
        }

        // Build a minimal policy for the supervisor-managed child.
        // The full policy mapping is applied when sandlock runs the actual process.
        let policy = sandlock_core::Policy::builder()
            .build()
            .unwrap_or_else(|_| {
                sandlock_core::Policy::builder().build().expect("minimal policy")
            });

        let _ = supervisor::run_supervisor(id, &cmd_args, policy);
        unsafe { libc::_exit(0) };
    }

    // ===== ORIGINAL PROCESS (caller) =====
    // Wait for the intermediate child so we don't leave a zombie.
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    // Give the supervisor a moment to start and update the state.
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Write pid-file if requested (CRI-O / containerd expect this)
    if let Some(pf) = pid_file {
        let state = ContainerState::load(id)?;
        std::fs::write(pf, state.pid.to_string())
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
        bail!("container {} has no PID (status: {})", id, state.status);
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
        Err(_) => {
            // Already gone — that's OK.
            return Ok(());
        }
    };

    if state.status == Status::Running && !force {
        bail!(
            "container {} is still running; use --force or kill it first",
            id
        );
    }

    // Kill if still alive.
    if state.pid > 0 && state.is_alive() {
        unsafe { libc::killpg(state.pid, libc::SIGKILL) };
        // Give the kernel a moment to reap.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Remove supervisor socket.
    let sock = supervisor::socket_path(id);
    std::fs::remove_file(&sock).ok();

    // Remove state directory.
    state.delete()?;
    Ok(())
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
        "HUP"  => libc::SIGHUP,
        "INT"  => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "KILL" => libc::SIGKILL,
        "TERM" => libc::SIGTERM,
        "STOP" => libc::SIGSTOP,
        "CONT" => libc::SIGCONT,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        other  => bail!("unknown signal: {}", other),
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
