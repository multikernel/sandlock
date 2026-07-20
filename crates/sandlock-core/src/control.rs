//! Per-sandbox Unix control socket for introspection.
//!
//! Every sandbox (CLI, Python SDK, embedded) gets a runtime directory under
//! `/dev/shm/sandlock-$UID/<name>/` containing:
//!
//! * `pid` — single-line pid file; lets `sandlock ps` list and prune dead
//!   sandboxes without opening the socket.
//! * `control.sock` — Unix stream socket bound by the supervisor before the
//!   child is forked.  Serves the introspection wire protocol.
//!
//! ## Wire protocol
//!
//! 4-byte big-endian length prefix, then UTF-8 JSON.  One client at a time per
//! socket.
//!
//! Request:
//! ```json
//! {"v": 1, "verb": "config", "args": {}}
//! ```
//!
//! Response:
//! ```json
//! {"v": 1, "ok": true, "data": { ...effective Sandbox policy... }}
//! ```
//! or
//! ```json
//! {"v": 1, "ok": false, "err": "..."}
//! ```

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::sandbox::Sandbox;
use crate::seccomp::ctx::SupervisorCtx;

// ============================================================
// Public API — runtime dir helpers (used by core + CLI)
// ============================================================

/// Return the per-user runtime directory root.
pub fn runtime_dir_uid(uid: u32) -> PathBuf {
    PathBuf::from(format!("/dev/shm/sandlock-{}", uid))
}

/// Return the per-sandbox runtime directory for a given name.
pub fn sandbox_dir(name: &str) -> PathBuf {
    let uid = unsafe { libc::getuid() };
    runtime_dir_uid(uid).join(name)
}

/// Return the pid file path inside a sandbox runtime dir.
pub fn pid_path(dir: &Path) -> PathBuf {
    dir.join("pid")
}

/// Return the control socket path inside a sandbox runtime dir.
pub fn sock_path(dir: &Path) -> PathBuf {
    dir.join("control.sock")
}

// ============================================================
// Runtime dir lifecycle — called from sandbox-core
// ============================================================

/// Create the per-sandbox runtime directory, write the pid file, and bind the
/// control socket.  Returns the `UnixListener` (to be passed to
/// `spawn_control_loop`) and the dir path.
///
/// Must be called after the child is forked (so `pid` is known) but before
/// `do_start` releases the child to execve.
pub fn setup_runtime_dir(name: &str, pid: i32) -> Result<(UnixListener, PathBuf), std::io::Error> {
    let dir = sandbox_dir(name);

    // Remove any stale dir from a previous run with the same name.
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;

    // Restrict to owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }

    // Write pid file.
    std::fs::write(pid_path(&dir), format!("{}\n", pid))?;

    // Bind control socket.
    let sp = sock_path(&dir);
    let listener = UnixListener::bind(&sp)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sp, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok((listener, dir))
}

/// Remove the per-sandbox runtime directory. Best-effort: failures are logged
/// but never propagated (called from Drop paths).
pub fn cleanup_runtime_dir(dir: &Path) {
    let pid_file = pid_path(dir);
    if pid_file.exists() {
        let _ = std::fs::remove_file(&pid_file);
    }
    let sp = sock_path(dir);
    if sp.exists() {
        let _ = std::fs::remove_file(&sp);
    }
    if dir.exists() {
        let _ = std::fs::remove_dir(dir);
    }
}

// ============================================================
// Control loop — spawned as a dedicated tokio task
// ============================================================

/// Spawn the control-loop task.  Returns immediately after spawning; the task
/// runs until the listener is closed or the supervisor shuts down.
///
/// Takes ownership of `sandbox` (moved into the task) so the config snapshot
/// lives for the lifetime of the control loop.  The sandbox clone has
/// `init_fn = None` (FnOnce can't be cloned), so the value is `Send`.
pub fn spawn_control_loop(
    listener: UnixListener,
    ctx: Arc<SupervisorCtx>,
    sandbox: Sandbox,
    dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    // Use a Mutex to satisfy Sync (Sandbox is not Sync due to the type-level
    // presence of Box<dyn FnOnce>, even though our clone has init_fn=None).
    // The control loop only reads, so a Mutex is fine.
    let sandbox = Arc::new(tokio::sync::Mutex::new(sandbox));
    tokio::spawn(async move {
        control_loop(listener, ctx, sandbox, dir).await;
    })
}

/// Accept connections on the control socket and serve one request per
/// connection (single-client-at-a-time, no concurrency).
async fn control_loop(
    listener: UnixListener,
    ctx: Arc<SupervisorCtx>,
    sandbox: Arc<tokio::sync::Mutex<Sandbox>>,
    _dir: PathBuf,
) {
    // Convert std listener to tokio.
    listener.set_nonblocking(true).ok();
    let listener = match tokio::net::UnixListener::from_std(listener) {
        Ok(l) => l,
        Err(_) => return,
    };

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };

        // Optional: audit peer credentials (same-UID trust boundary).
        // SO_PEERCRED is cheap and surfaces unexpected mismatches.
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let raw = stream.as_raw_fd();
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            } == 0
            {
                let my_uid = unsafe { libc::getuid() };
                if cred.uid != my_uid {
                    eprintln!(
                        "sandlock: control socket: peer uid {} != my uid {} — \
                         unexpected; dir 0700 should prevent this",
                        cred.uid, my_uid
                    );
                }
            }
        }

        // Serve one request; close after.
        serve_one(stream, &ctx, &sandbox).await;
    }
}

// ============================================================
// Request handling
// ============================================================

#[derive(serde::Deserialize)]
struct ControlRequest {
    v: u32,
    verb: String,
    #[serde(default)]
    #[allow(dead_code)]
    args: serde_json::Value,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ControlResponse {
    pub v: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

async fn serve_one(
    stream: tokio::net::UnixStream,
    ctx: &Arc<SupervisorCtx>,
    sandbox: &Arc<tokio::sync::Mutex<Sandbox>>,
) {
    use tokio::io::AsyncReadExt;

    let mut stream = stream;
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let body_len = u32::from_be_bytes(len_buf) as usize;
    // Reject unreasonable sizes.
    if body_len > 65536 {
        return;
    }
    let mut body = vec![0u8; body_len];
    if stream.read_exact(&mut body).await.is_err() {
        return;
    }

    let req: ControlRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("parse error: {}", e)),
            };
            let _ = write_response(&mut stream, &resp).await;
            return;
        }
    };

    if req.v != 1 {
        let resp = ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!("unsupported protocol version: {}", req.v)),
        };
        let _ = write_response(&mut stream, &resp).await;
        return;
    }

    match req.verb.as_str() {
        "config" => handle_config(&mut stream, ctx, sandbox).await,
        _ => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("unknown verb: {}", req.verb)),
            };
            let _ = write_response(&mut stream, &resp).await;
        }
    }
}

async fn handle_config(
    stream: &mut tokio::net::UnixStream,
    ctx: &Arc<SupervisorCtx>,
    sandbox: &Arc<tokio::sync::Mutex<Sandbox>>,
) {
    // Collect dynamic policy_fn denies.
    let dynamic_denied: Vec<String> = {
        let pfn = ctx.policy_fn.lock().await;
        pfn.denied.denied_paths()
    };

    // Build the effective profile.
    let sb = sandbox.lock().await;
    let profile = crate::profile::sandbox_to_profile(&sb, &dynamic_denied);

    // Emit JSON.  Wrap in a "policy" key so the top-level response is
    // structured; the data field is the full ProfileInput.
    let data = match serde_json::to_value(&profile) {
        Ok(v) => v,
        Err(e) => {
            let resp = ControlResponse {
                v: 1,
                ok: false,
                data: None,
                err: Some(format!("serialize error: {}", e)),
            };
            let _ = write_response(stream, &resp).await;
            return;
        }
    };

    let resp = ControlResponse {
        v: 1,
        ok: true,
        data: Some(data),
        err: None,
    };
    let _ = write_response(stream, &resp).await;
}

/// Write a length-prefixed JSON response.
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    resp: &ControlResponse,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let body = serde_json::to_vec(resp).unwrap_or_else(|_| {
        serde_json::to_vec(&ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some("internal error".to_string()),
        })
        .unwrap_or_default()
    });
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&body).await?;
    Ok(())
}

// ============================================================
// Pruning — called by sandlock ps to clean up stale dirs
// ============================================================

/// Walk `/dev/shm/sandlock-$UID/` and return entries for every live sandbox.
/// Dead sandboxes (pid file exists but process is gone) are pruned.
///
/// Returns `(name, pid)` pairs for live sandboxes.
pub fn list_live_sandboxes() -> Result<Vec<(String, i32)>, std::io::Error> {
    let uid = unsafe { libc::getuid() };
    let root = runtime_dir_uid(uid);
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut live = Vec::new();
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(_) => return Ok(Vec::new()),
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }

        let pid_file = pid_path(&dir);
        let pid_str = match std::fs::read_to_string(&pid_file) {
            Ok(s) => s,
            Err(_) => {
                // No pid file — stale/incomplete dir, remove it.
                let _ = std::fs::remove_dir_all(&dir);
                continue;
            }
        };

        let pid: i32 = match pid_str.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                let _ = std::fs::remove_dir_all(&dir);
                continue;
            }
        };

        // Liveness check: kill(pid, 0) returns 0 if the process exists.
        if unsafe { libc::kill(pid, 0) } == 0 {
            let name = match dir.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            live.push((name, pid));
        } else {
            // Dead: prune.
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    // Sort by name for deterministic output.
    live.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(live)
}

// ============================================================
// Client helpers — used by sandlock-cli to talk to the socket
// ============================================================

/// Send a request to a sandbox's control socket and return the JSON response
/// body (the `data` field, or error).
pub fn send_control_request(
    name: &str,
    verb: &str,
    args: serde_json::Value,
) -> Result<ControlResponse, String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let dir = sandbox_dir(name);
    let sp = sock_path(&dir);
    let mut stream = UnixStream::connect(&sp)
        .map_err(|e| format!("connect to {:?}: {}", sp, e))?;

    let req = serde_json::json!({
        "v": 1,
        "verb": verb,
        "args": args,
    });
    let body = serde_json::to_vec(&req)
        .map_err(|e| format!("serialize request: {}", e))?;

    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(|e| format!("write len: {}", e))?;
    stream.write_all(&body).map_err(|e| format!("write body: {}", e))?;

    // Read response.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| format!("read len: {}", e))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 65536 {
        return Err("response too large".to_string());
    }
    let mut resp_body = vec![0u8; resp_len];
    stream.read_exact(&mut resp_body).map_err(|e| format!("read body: {}", e))?;

    serde_json::from_slice(&resp_body)
        .map_err(|e| format!("parse response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_dir_paths() {
        let dir = sandbox_dir("test-sandbox");
        assert!(dir.to_string_lossy().contains("test-sandbox"));
        assert!(dir.to_string_lossy().contains("sandlock-"));
    }

    #[test]
    fn test_list_live_sandboxes_empty() {
        // When no sandboxes are running, returns empty.
        let result = list_live_sandboxes().unwrap();
        // May or may not be empty depending on test environment; just ensure
        // it doesn't error.
        assert!(result.iter().all(|(_, pid)| *pid > 0));
    }
}
