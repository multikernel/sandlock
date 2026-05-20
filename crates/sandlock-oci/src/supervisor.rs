//! Supervisor process — manages the child lifecycle via signal synchronization.
//!
//! Implements Phase 2 of the plan: the Supervisor forks the child (User
//! Application), parks it in a wait state, then on `start` triggers `execve`.
//!
//! Communication with the CLI is via a Unix socket written to the state dir.
//!
//! Lifecycle:
//!
//! 1. Supervisor creates a Unix socket and forks the child.
//! 2. The child SIGSTOPs itself immediately.
//! 3. The supervisor writes child PID to the pipe (for the CLI to read
//!    synchronously, no sleep/race), then enters an accept loop.
//! 4. On `start`: supervisor sends SIGCONT to the child.  The child wakes
//!    up, applies Landlock confinement + chroot + cwd + env, then execs.
//! 5. On `ping`: supervisor replies with the child PID.
//! 6. After the child exits, the supervisor updates state to Stopped and
//!    returns.

use anyhow::{bail, Context, Result};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::policy::OciPolicy;
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
    Path::new(crate::state::state_dir())
        .join(id)
        .join(SUPERVISOR_SOCKET)
}

/// Send a command to an already-running supervisor and return its reply.
///
/// The protocol is newline-delimited JSON over a Unix socket.
/// Each request and response is a single JSON line terminated with '\n'.
pub fn send_command(id: &str, cmd: SupervisorCmd) -> Result<SupervisorReply> {
    use std::io::{BufRead, Read, Write};
    use std::os::unix::net::UnixStream;

    let path = socket_path(id);
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("connect to supervisor socket {:?}", path))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    // Write the command as a newline-terminated JSON line.
    let msg = serde_json::to_string(&cmd)?;
    stream.write_all(msg.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    // Read a single newline-delimited response line, which avoids ambiguity
    // if the stream stays open for future commands.
    let mut reader = std::io::BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let reply: SupervisorReply = serde_json::from_str(line.trim())
        .context("parse supervisor reply")?;
    Ok(reply)
}

/// Run the supervisor event loop in the **current process**.
///
/// # Arguments
///
/// * `id` — container identifier
/// * `cmd` — the command the child should exec after SIGCONT
/// * `policy` — the OCI policy to apply to the child (chroot, env, resources)
/// * `pid_write_fd` — raw fd to write the child PID to (owned by caller)
///
/// The child applies confinement itself after being released via SIGCONT.
/// This function never returns except on fatal error.
pub fn run_supervisor(
    id: &str,
    cmd: &[String],
    policy: OciPolicy,
    pid_write_fd: i32,
) -> Result<()> {
    use std::io::{Read, Write};

    // Validate the command is non-empty (OCI spec requirement).
    if cmd.is_empty() {
        bail!("OCI spec error: process.args is empty; cannot run a container with no command");
    }

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
        // ===== CHILD PROCESS =====

        // Close the parent's copy of the pid pipe — child doesn't use it.
        unsafe { libc::close(pid_write_fd) };

        // Stop ourselves and wait for SIGCONT from the supervisor.
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            libc::raise(libc::SIGSTOP);
        }

        // After SIGCONT, the child is now running.
        // Apply confinement, chdir, env, then exec.
        // These are all applied in the child process — the supervisor never
        // chroots or changes its own environment.

        // 1. Apply chroot if the policy has a rootfs.
        if let Some(ref rootfs) = policy.rootfs {
            if unsafe { libc::chroot(rootfs.as_ptr() as *const libc::c_char) } != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("sandlock-oci: chroot({:?}) failed: {}", rootfs, err);
                unsafe { libc::_exit(127) };
            }
            if unsafe { libc::chdir(b"/\0".as_ptr() as *const libc::c_char) } != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("sandlock-oci: chdir(/) after chroot failed: {}", err);
                unsafe { libc::_exit(127) };
            }
        }

        // 2. Change working directory.
        if let Some(ref cwd) = policy.cwd {
            let cwd_str = cwd.to_string_lossy();
            if unsafe { libc::chdir(cwd_str.as_ptr() as *const libc::c_char) } != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("sandlock-oci: chdir({:?}) failed: {}", cwd, err);
                unsafe { libc::_exit(127) };
            }
        }

        // 3. Set environment variables from the spec.
        // Clear all existing env vars if the spec provides any.
        if !policy.env.is_empty() {
            for (key, _) in std::env::vars_os() {
                // Keep PATH as a fallback if the spec doesn't override it.
                if key == "PATH" && !policy.env.contains_key("PATH") {
                    continue;
                }
                std::env::remove_var(&key);
            }
        }
        for (key, value) in &policy.env {
            std::env::set_var(key, value);
        }

        // 4. Apply Landlock filesystem confinement (irreversible).
        if let Err(e) = policy.confine() {
            eprintln!("sandlock-oci: failed to apply Landlock confinement: {}", e);
            unsafe { libc::_exit(127) };
        }

        // 5. execvp — the child is now fully confined.
        let prog = match std::ffi::CString::new(cmd[0].as_str()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("sandlock-oci: invalid command string: {}", e);
                unsafe { libc::_exit(127) };
            }
        };
        let c_args: Vec<std::ffi::CString> = cmd
            .iter()
            .map(|a| {
                std::ffi::CString::new(a.as_str()).unwrap_or_else(|_| {
                    eprintln!("sandlock-oci: invalid argument string");
                    unsafe { libc::_exit(127) };
                })
            })
            .collect();
        let mut ptrs: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
        ptrs.push(std::ptr::null());

        unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()) };

        // execvp failed
        let err = std::io::Error::last_os_error();
        eprintln!("sandlock-oci: execvp({:?}) failed: {}", cmd[0], err);
        unsafe { libc::_exit(127) };
    }

    // ===== PARENT (Supervisor) =====

    // Write the child PID to the pipe immediately so the CLI can read it
    // synchronously without sleeping or racing.
    let pid_str = format!("{}\n", child_pid);
    unsafe {
        libc::write(
            pid_write_fd,
            pid_str.as_ptr() as *const libc::c_void,
            pid_str.len(),
        );
        libc::close(pid_write_fd);
    }

    // Update state with the child PID. Status is Created because it's SIGSTOP'd.
    let mut state = ContainerState::load(id).unwrap_or_else(|_| {
        ContainerState::new(id, Path::new("/"), "1.0.2")
    });
    state.set_created(child_pid);
    state.save().ok();

    // ── Event loop: serve CLI commands over the Unix socket ────────────────
    // Use blocking mode.  WasBlock can appear transiently in some cases;
    // handle it as a retry, not a dead code branch.
    listener
        .set_nonblocking(false)
        .expect("set_nonblocking call failed");

    'outer: loop {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                // Read the request (newline-delimited JSON).
                let mut buf = [0u8; 4096];
                let mut request = Vec::new();

                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.iter().rposition(|&b| b == b'\n').is_some() {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Transient in blocking mode — retry read.
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        Err(_) => break,
                    }
                }

                if request.is_empty() {
                    continue;
                }

                let cmd: SupervisorCmd = match serde_json::from_slice(&request) {
                    Ok(c) => c,
                    Err(e) => {
                        let reply = SupervisorReply::Err { msg: e.to_string() };
                        let _ = serde_json::to_writer(&stream, &reply);
                        let _ = stream.write_all(b"\n");
                        let _ = stream.flush();
                        continue;
                    }
                };

                match cmd {
                    SupervisorCmd::Ping => {
                        let reply = SupervisorReply::Pid { pid: child_pid };
                        let _ = serde_json::to_writer(&stream, &reply);
                        let _ = stream.write_all(b"\n");
                        let _ = stream.flush();
                    }
                    SupervisorCmd::Start => {
                        // Release the child by sending SIGCONT.
                        unsafe { libc::kill(child_pid, libc::SIGCONT) };

                        // Update state to Running.
                        if let Ok(mut s) = ContainerState::load(id) {
                            s.set_running();
                            s.save().ok();
                        }

                        let _ = serde_json::to_writer(&stream, &SupervisorReply::Ok);
                        let _ = stream.write_all(b"\n");
                        let _ = stream.flush();

                        // Break out of the accept loop — the child is now running
                        // and we just need to wait for it to exit.
                        break 'outer;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Avoid spinning: sleep briefly before retrying accept.
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                // Fatal accept error.
                break;
            }
        }
    }

    // Monitor the child until it exits.
    loop {
        let mut status = 0i32;
        let ret = unsafe { libc::waitpid(child_pid, &mut status, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        break;
    }

    // Update state to stopped, capturing exit info.
    if let Ok(mut s) = ContainerState::load(id) {
        s.set_stopped(None);
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
        let reply = SupervisorReply::Err {
            msg: "test error".into(),
        };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("err"));
        assert!(json.contains("test error"));
    }
}