//! Supervisor process — manages the child lifecycle via signal synchronization.
//!
//! Implements Phase 2 of the plan: the Supervisor forks the child (User
//! Application), parks it in a wait state, then on `start` triggers `execve`.
//!
//! Communication with the CLI is via a Unix socket written to the state dir.

use anyhow::{bail, Context, Result};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::state::ContainerState;

/// Filename of the supervisor's control socket inside the state dir.
pub const SUPERVISOR_SOCKET: &str = "supervisor.sock";

/// Commands the CLI sends to the Supervisor over the Unix socket.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum SupervisorCmd {
    /// Tell the supervisor to release the child (trigger execve).
    Start,
    /// Request the current PID.
    Ping,
}

/// Response from the Supervisor.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum SupervisorReply {
    Ok,
    Pid { pid: i32 },
    Err { msg: String },
}

/// Returns the path to the supervisor socket for the given container ID.
pub fn socket_path(id: &str) -> PathBuf {
    Path::new(crate::state::STATE_DIR)
        .join(id)
        .join(SUPERVISOR_SOCKET)
}

/// Send a command to an already-running supervisor and return its reply.
pub fn send_command(id: &str, cmd: SupervisorCmd) -> Result<SupervisorReply> {
    use std::os::unix::net::UnixStream;
    use std::io::{Read, Write};

    let path = socket_path(id);
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("connect to supervisor socket {:?}", path))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let msg = serde_json::to_string(&cmd)?;
    stream.write_all(msg.as_bytes())?;
    stream.write_all(b"\n")?;

    let mut buf = String::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 { break; }
        buf.push_str(&String::from_utf8_lossy(&tmp[..n]));
        if buf.contains('\n') { break; }
    }

    let reply: SupervisorReply = serde_json::from_str(buf.trim())
        .context("parse supervisor reply")?;
    Ok(reply)
}

/// Run the supervisor event loop in the **current process**.
///
/// This is called by the `create` subcommand after forking. It:
/// 1. Forks the child process and suspends it with SIGSTOP.
/// 2. Writes the PID to the state file.
/// 3. Listens on a Unix socket for `start` / `ping` commands.
/// 4. On `start`: sends SIGCONT to the child, then monitors until it exits.
pub fn run_supervisor(
    id: &str,
    cmd: &[String],
    policy: sandlock_core::Policy,
) -> Result<()> {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    let sock_path = socket_path(id);

    // Create the listener before forking so it's ready before the CLI calls start.
    if sock_path.exists() {
        std::fs::remove_file(&sock_path).ok();
    }
    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("bind supervisor socket {:?}", sock_path))?;

    // ── Fork child and immediately SIGSTOP it ────────────────────────────────
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        bail!("fork failed: {}", std::io::Error::last_os_error());
    }

    if child_pid == 0 {
        // ===== CHILD =====
        // Stop ourselves and wait for SIGCONT from the supervisor.
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            libc::raise(libc::SIGSTOP);
        }

        // After SIGCONT, apply sandlock confinement and exec.
        // We use the core's confine_current_process to apply Landlock.
        if let Err(e) = sandlock_core::confine_current_process(&policy) {
            eprintln!("sandlock-oci: failed to confine process: {}", e);
            unsafe { libc::_exit(1) };
        }

        let prog = std::ffi::CString::new(cmd[0].as_str()).unwrap();
        let c_args: Vec<std::ffi::CString> = cmd
            .iter()
            .map(|a| std::ffi::CString::new(a.as_str()).unwrap())
            .collect();
        let mut ptrs: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()) };
        unsafe { libc::_exit(127) };
    }

    // ===== PARENT (Supervisor) =====

    // Update state with the child PID. Status is Created because it's SIGSTOP'd.
    let mut state = ContainerState::load(id).unwrap_or_else(|_| {
        ContainerState::new(id, Path::new("/"), "1.0.2")
    });
    state.set_created(child_pid);
    state.save().ok();

    // ── Event loop ───────────────────────────────────────────────────────────
    listener.set_nonblocking(false).ok();
    'outer: loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() { continue; }
                let cmd: SupervisorCmd = match serde_json::from_str(line.trim()) {
                    Ok(c) => c,
                    Err(e) => {
                        let reply = SupervisorReply::Err { msg: e.to_string() };
                        let _ = serde_json::to_writer(&stream, &reply);
                        continue;
                    }
                };
                match cmd {
                    SupervisorCmd::Ping => {
                        let _ = serde_json::to_writer(
                            &stream,
                            &SupervisorReply::Pid { pid: child_pid },
                        );
                    }
                    SupervisorCmd::Start => {
                        // Send SIGCONT to release the SIGSTOP'd child.
                        unsafe { libc::kill(child_pid, libc::SIGCONT) };
                        
                        // Update state to Running.
                        if let Ok(mut s) = ContainerState::load(id) {
                            s.set_running();
                            s.save().ok();
                        }

                        let _ = serde_json::to_writer(&stream, &SupervisorReply::Ok);
                        break 'outer;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }

    // Monitor the child until it exits.
    loop {
        let mut status = 0i32;
        let ret = unsafe { libc::waitpid(child_pid, &mut status, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) { continue; }
            break;
        }
        break;
    }

    // Update state to stopped.
    if let Ok(mut s) = ContainerState::load(id) {
        s.set_stopped();
        s.save().ok();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_is_under_state_dir() {
        let p = socket_path("my-container");
        assert!(p.to_str().unwrap().contains("my-container"));
        assert!(p.to_str().unwrap().contains("supervisor.sock"));
    }

    #[test]
    fn supervisor_cmd_serde() {
        let cmd = SupervisorCmd::Start;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("start"));
    }
}
