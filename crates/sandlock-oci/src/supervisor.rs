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
//! the container's state directory.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::policy::OciPolicy;
use crate::state::ContainerState;

/// Filename of the supervisor control socket inside the container state dir.
pub const SUPERVISOR_SOCKET: &str = "supervisor.sock";

/// Commands the CLI sends to the Supervisor over the Unix socket.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum SupervisorCmd {
    /// Release the parked child to execve.
    Start,
    /// Query the child PID.
    Ping,
}

/// Responses from the Supervisor.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum SupervisorReply {
    Ok,
    Pid { pid: i32 },
    Err { msg: String },
}

/// Returns the path to the supervisor socket for the given container ID.
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

/// Async body of `run_supervisor`.
async fn supervisor_main(
    id: &str,
    cmd: &[String],
    mut sandbox: sandlock_core::Sandbox,
    sock_path: PathBuf,
    pid_write_fd: i32,
) -> Result<()> {
    use sandlock_core::ExitStatus;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    use crate::state::ExitInfo;

    // Bind the socket BEFORE create() so the CLI can call `start` the moment
    // `create` returns without a race on socket availability.
    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("bind supervisor socket {:?}", sock_path))?;

    // OCI `create` — forks the child, installs the full sandlock policy
    // (seccomp-notify + Landlock + resource limits + network ACL), and parks
    // the child before execve using a pipe rather than SIGSTOP.
    let cmd_refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
    sandbox
        .create_interactive(&cmd_refs)
        .await
        .context("sandbox create_interactive")?;

    let child_pid = sandbox.pid().unwrap_or(0) as i32;

    // Notify the CLI of the child PID so it can write the pid-file and update
    // state without racing. This fd is write-once then closed.
    {
        let s = format!("{}\n", child_pid);
        unsafe {
            libc::write(pid_write_fd, s.as_ptr() as *const libc::c_void, s.len());
            libc::close(pid_write_fd);
        }
    }

    // Persist Created state with the real child PID.
    {
        let mut state = ContainerState::load(id).unwrap_or_else(|_| {
            ContainerState::new(id, Path::new("/"), "1.0.2")
        });
        state.set_created(child_pid);
        state.save().ok();
    }

    // Accept-loop: serve CLI commands until `Start` is received.
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => break,
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
                // OCI `start` — write to the ready pipe so the parked child
                // proceeds to execve with the full sandlock policy already in
                // place.
                let reply = match sandbox.start() {
                    Ok(()) => {
                        if let Ok(mut s) = ContainerState::load(id) {
                            s.set_running();
                            s.save().ok();
                        }
                        SupervisorReply::Ok
                    }
                    Err(e) => SupervisorReply::Err { msg: e.to_string() },
                };
                let reply_bytes = serde_json::to_vec(&reply).unwrap_or_default();
                let _ = stream.write_all(&reply_bytes).await;
                let _ = stream.write_all(b"\n").await;
                break;
            }
        }
    }

    // Wait for the child to exit and record the exit status.
    let exit_info = match sandbox.wait().await {
        Ok(result) => match result.exit_status {
            ExitStatus::Code(code) => Some(ExitInfo { code: Some(code), signal: None }),
            ExitStatus::Signal(sig) => Some(ExitInfo { code: None, signal: Some(sig) }),
            ExitStatus::Killed => Some(ExitInfo { code: None, signal: Some(libc::SIGKILL) }),
            ExitStatus::Timeout => Some(ExitInfo { code: Some(124), signal: None }),
        },
        Err(_) => None,
    };

    if let Ok(mut s) = ContainerState::load(id) {
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
        let reply = SupervisorReply::Err { msg: "test error".into() };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("err"));
        assert!(json.contains("test error"));
    }
}
