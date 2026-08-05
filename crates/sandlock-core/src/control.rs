//! Per-sandbox Unix control socket for introspection.
//!
//! Every sandbox (CLI, Python SDK, embedded) gets a runtime directory under
//! `/dev/shm/sandlock-$UID/<name>/` containing:
//!
//! * `pid` — two-line pid file (`child_pid\nsupervisor_pid\n`); lets
//!   `sandlock ps` list and prune dead sandboxes without opening the
//!   socket. The child PID is used for `/proc` introspection (UPTIME,
//!   CMD); the supervisor PID owns the control socket and is used for
//!   liveness checks.
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
pub(crate) fn runtime_dir_uid(uid: u32) -> PathBuf {
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

/// Read a sandbox's operating-mode marker (e.g. "learn") from its runtime
/// dir. `None` for ordinary runs, which write no mode file.
pub fn sandbox_mode(name: &str) -> Option<String> {
    let s = std::fs::read_to_string(sandbox_dir(name).join("mode")).ok()?;
    let s = s.trim();
    if s.is_empty() { None } else { Some(s.to_string()) }
}

/// Read the supervisor PID from a runtime dir's pid file.
/// Returns `None` if the file is missing, unparseable, or does not
/// contain two lines (child_pid\nsupervisor_pid\n).
fn read_supervisor_pid(dir: &Path) -> Option<i32> {
    let content = std::fs::read_to_string(pid_path(dir)).ok()?;
    // Line 2 is the supervisor PID.
    content.lines().nth(1)?.trim().parse().ok()
}

// ============================================================
// Runtime dir lifecycle — called from sandbox-core
// ============================================================

/// Create the per-sandbox runtime directory and write the pid file — shared
/// by the supervisor and no_supervisor paths.  Returns the dir path.
///
/// # Name collision
///
/// If a runtime directory already exists for `name` and its supervisor is
/// still alive, this returns `ErrorKind::AlreadyExists`.  Stale dirs (dead
/// supervisor) are removed and recreated.
///
/// # no_supervisor callers
///
/// The `no_supervisor` path in `do_spawn` calls this directly (without the
/// socket) instead of duplicating a bare `remove_dir_all` + `create_dir_all`
/// that had no liveness check and would wipe a live sandbox's pid file on a
/// name collision.
pub(crate) fn setup_runtime_dir(
    name: &str,
    child_pid: i32,
    supervisor_pid: i32,
    mode: Option<&str>,
) -> Result<(UnixListener, PathBuf), std::io::Error> {
    let dir = setup_runtime_dir_no_socket(name, child_pid, supervisor_pid, mode)?;

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

/// Create the per-sandbox runtime directory and write the pid file, without
/// binding a control socket.  Used by the `no_supervisor` path (no socket
/// exists) and as the common prefix of `setup_runtime_dir` for the supervisor
/// path.
pub(crate) fn setup_runtime_dir_no_socket(
    name: &str,
    child_pid: i32,
    supervisor_pid: i32,
    mode: Option<&str>,
) -> Result<PathBuf, std::io::Error> {
    let dir = sandbox_dir(name);

    // Check for name collision: if the dir exists and the sandbox is still
    // alive, refuse to overwrite it.
    if dir.exists() {
        if let Some(pid) = read_supervisor_pid(&dir) {
            if unsafe { libc::kill(pid, 0) } == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("sandbox '{}' is already running (PID {})", name, pid),
                ));
            }
        }
        // Dead or unparseable — safe to remove.
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;

    // Restrict to owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }

    // Write pid file atomically via temp + rename so list_live_sandboxes
    // never sees a partially-written or empty pid file.
    // Operating-mode marker for the `sandlock ps` STATUS column. Written
    // before the pid file so a listing never sees the sandbox without it.
    if let Some(m) = mode {
        std::fs::write(dir.join("mode"), m)?;
    }

    let pid_path = pid_path(&dir);
    let tmp_path = dir.join(".pid.tmp");
    std::fs::write(&tmp_path, format!("{}\n{}\n", child_pid, supervisor_pid))?;
    std::fs::rename(&tmp_path, &pid_path)?;

    Ok(dir)
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
pub(crate) fn spawn_control_loop(
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
        "ports" => handle_ports(&mut stream, ctx).await,
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

async fn handle_ports(
    stream: &mut tokio::net::UnixStream,
    ctx: &Arc<SupervisorCtx>,
) {
    // Read the current virtual→real port map from the supervisor's
    // NetworkState.  This is the live mapping at request-time — more
    // accurate than a static registry that only refreshes on bind and
    // goes stale on SIGKILL.
    let ports: std::collections::HashMap<u16, u16> = {
        let ns = ctx.network.lock().await;
        ns.port_map.virtual_to_real.clone()
    };

    let data = match serde_json::to_value(&ports) {
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

/// Write a length-prefixed JSON response.  Rejects bodies over 64 KB
/// (mirrors the client-side cap in `send_control_request`).
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    resp: &ControlResponse,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    const MAX_RESPONSE_BYTES: usize = 65536;

    let body = serde_json::to_vec(resp).unwrap_or_else(|_| {
        serde_json::to_vec(&ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some("internal error".to_string()),
        })
        .unwrap_or_default()
    });

    // Cap oversized responses on the server side too.
    let body = if body.len() > MAX_RESPONSE_BYTES {
        serde_json::to_vec(&ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!(
                "response too large ({} bytes, max {})",
                body.len(),
                MAX_RESPONSE_BYTES
            )),
        })
        .unwrap_or_default()
    } else {
        body
    };

    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&body).await?;
    Ok(())
}

// ============================================================
// Pruning — called by sandlock ps to clean up stale dirs
// ============================================================

/// Walk `/dev/shm/sandlock-$UID/` and return entries for every live sandbox.
/// Dead sandboxes (supervisor process is gone) are pruned.
///
/// Returns `(name, child_pid)` pairs for live sandboxes.  The child PID is
/// used by `sandlock ps` for `/proc/<pid>/stat` and `/proc/<pid>/cmdline`.
///
/// Directories younger than 2 seconds are never pruned, even if the pid
/// file is missing or unparseable — this avoids a race with `setup_runtime_dir`
/// which creates the dir before writing the pid file.
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

    let now = std::time::SystemTime::now();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }

        // Parse the pid file.  Format: child_pid\nsupervisor_pid\n
        let pid_file = pid_path(&dir);
        let pid_str = match std::fs::read_to_string(&pid_file) {
            Ok(s) => s,
            Err(_) => {
                // No pid file — could be a dir being set up concurrently.
                // Don't prune if the dir was modified less than 2 seconds ago.
                if !dir_is_recent(&dir, &now) {
                    let _ = std::fs::remove_dir_all(&dir);
                }
                continue;
            }
        };

        let mut lines = pid_str.lines();
        let child_pid: i32 = match lines.next().and_then(|l| l.trim().parse().ok()) {
            Some(p) => p,
            None => {
                if !dir_is_recent(&dir, &now) {
                    let _ = std::fs::remove_dir_all(&dir);
                }
                continue;
            }
        };
        let supervisor_pid: i32 = match lines.next().and_then(|l| l.trim().parse().ok()) {
            Some(p) => p,
            None => {
                if !dir_is_recent(&dir, &now) {
                    let _ = std::fs::remove_dir_all(&dir);
                }
                continue;
            }
        };

        // Liveness check: use supervisor PID since the supervisor owns
        // the control socket.  If the supervisor is dead, the sandbox is
        // effectively dead even if the child still runs.
        if unsafe { libc::kill(supervisor_pid, 0) } == 0 {
            let name = match dir.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            live.push((name, child_pid));
        } else {
            // Dead: prune.
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    // Sort by name for deterministic output.
    live.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(live)
}

/// Return true if `dir` was modified less than 2 seconds ago.
fn dir_is_recent(dir: &Path, now: &std::time::SystemTime) -> bool {
    if let Ok(meta) = std::fs::metadata(dir) {
        if let Ok(mtime) = meta.modified() {
            if let Ok(elapsed) = now.duration_since(mtime) {
                return elapsed.as_secs() < 2;
            }
        }
    }
    false
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

    // Check supervisor liveness before attempting connect.  If the
    // supervisor is dead the socket is stale and connect() would fail
    // with a confusing "No such file" — give a clearer message.
    if let Some(pid) = read_supervisor_pid(&dir) {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return Err(format!(
                "sandbox '{}' supervisor (PID {}) is not running",
                name, pid
            ));
        }
    }

    let sp = sock_path(&dir);
    let mut stream = UnixStream::connect(&sp)
        .map_err(|e| format!("connect to {:?}: {}", sp, e))?;

    // Set a 2-second timeout on reads so a wedged supervisor does not
    // block the CLI forever.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| format!("set_write_timeout: {}", e))?;

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
    fn test_runtime_dir_mode_file_roundtrip() {
        // Unique name: sandbox names are uid-wide, never reuse a fixed one.
        let name = format!("test-mode-{}", std::process::id());
        let pid = std::process::id() as i32;

        let dir = setup_runtime_dir_no_socket(&name, pid, pid, Some("learn")).unwrap();
        assert_eq!(sandbox_mode(&name).as_deref(), Some("learn"));
        cleanup_runtime_dir(&dir);

        let dir = setup_runtime_dir_no_socket(&name, pid, pid, None).unwrap();
        assert_eq!(sandbox_mode(&name), None);
        cleanup_runtime_dir(&dir);
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
