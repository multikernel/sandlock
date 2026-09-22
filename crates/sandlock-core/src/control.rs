//! Per-sandbox control sockets for introspection and kill.
//!
//! Names are owned by process-associated SEM_UNDO claims in a per-user
//! SysV semaphore registry. Ordinary host forks cannot retain those claims.
//! Each claim has a random instance token used for two abstract Unix sockets:
//! the supervisor's request listener and the child's process-group listener.
//! Socket copies can outlive a claim without reserving its human-readable name.
//! Both peers authenticate SO_PEERCRED; the child calls listen() after setpgid().
//!
//! ## Wire protocol
//!
//! 4-byte big-endian length prefix, then UTF-8 JSON.  One request per
//! connection.
//!
//! Request:
//! ```json
//! {"v": 1, "verb": "info", "args": {}}
//! ```
//!
//! Response:
//! ```json
//! {"v": 1, "ok": true, "data": {"mode": null}}
//! ```
//! or
//! ```json
//! {"v": 1, "ok": false, "err": "..."}
//! ```
//!
//! Verbs: `info` (mode), `config` (effective policy as
//! `ProfileInput`), `ports` (virtual to real port map), `kill` (SIGKILL
//! every process group the supervisor has recorded).

pub(crate) mod ownership;

use std::os::linux::net::SocketAddrExt;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;

use crate::sandbox::Sandbox;
use crate::seccomp::ctx::SupervisorCtx;

// ============================================================
// Socket address
// ============================================================

fn instance_addr(token: &str, pgrp: bool) -> std::io::Result<SocketAddr> {
    let uid = unsafe { libc::getuid() };
    let suffix = if pgrp { "/pgrp" } else { "" };
    SocketAddr::from_abstract_name(format!("sandlock/{uid}/v2/{token}{suffix}"))
}

#[cfg(test)]
fn socket_addr(name: &str) -> std::io::Result<SocketAddr> {
    instance_addr(&ownership::lookup(name)?.token, false)
}

// ============================================================
// Live control fds
// ============================================================

/// Every control fd this process holds, so a forked child can close them
/// without reading /proc. Bind, close, and fork() all take the lock, so a
/// child never sees an fd that is half registered.
static LIVE: Mutex<Vec<RawFd>> = Mutex::new(Vec::new());

fn live() -> std::sync::MutexGuard<'static, Vec<RawFd>> {
    LIVE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A socket fd that stays on the live list until it closes.
#[derive(Debug)]
pub(crate) struct ControlFd(RawFd);

impl ControlFd {
    fn register(fd: OwnedFd) -> Self {
        let fd = fd.into_raw_fd();
        live().push(fd);
        ControlFd(fd)
    }

    fn set_nonblocking(&self) -> std::io::Result<()> {
        let flags = unsafe { libc::fcntl(self.0, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(self.0, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn accept(&self) -> std::io::Result<ControlFd> {
        let fd = unsafe {
            libc::accept4(
                self.0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ControlFd::register(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.0, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl AsRawFd for ControlFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for ControlFd {
    fn drop(&mut self) {
        let mut live = live();
        live.retain(|&fd| fd != self.0);
        unsafe { libc::close(self.0) };
    }
}

/// fork() with the live list locked. The child closes every control fd but
/// `keep` before anything else runs, so the sandbox never holds one; `keep`
/// is the child's own pgrp socket, which it still has to listen on.
pub(crate) fn fork_without_control_fds(keep: Option<RawFd>) -> libc::pid_t {
    let live = live();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        for &fd in live.iter() {
            if Some(fd) != keep {
                unsafe { libc::close(fd) };
            }
        }
    }
    pid
}

/// Both sockets of one sandbox, bound before it forks. `control` already
/// listens, from the supervisor. `pgrp` is bound only: the child calls
/// listen() on it after setpgid(), so its peer pid is the group leader.
#[derive(Debug)]
pub(crate) struct ControlSockets {
    pub control: ControlFd,
    pub pgrp: ControlFd,
    pub claim: Option<ownership::Claim>,
}

/// `AddrInUse` means a live sandbox of this uid already owns the name.
pub(crate) fn bind_control_sockets(name: &str) -> std::io::Result<ControlSockets> {
    let claim = ownership::Claim::new(name)?;
    let control = ControlFd::register(UnixListener::bind_addr(&instance_addr(&claim.entry.token, false)?)?.into());
    let pgrp = ControlFd::register(bind_only(&instance_addr(&claim.entry.token, true)?)?);
    Ok(ControlSockets { control, pgrp, claim: Some(claim) })
}

/// std has no bind-without-listen, and listen() must be the child's call.
fn bind_only(addr: &SocketAddr) -> std::io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let name = addr.as_abstract_name().expect("abstract address");
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, &src) in sun.sun_path[1..].iter_mut().zip(name) {
        *dst = src as libc::c_char;
    }
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len();
    let rc = unsafe {
        libc::bind(fd.as_raw_fd(), &sun as *const _ as *const libc::sockaddr, len as libc::socklen_t)
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// In the child, after setpgid(). listen() records this pid as the
/// socket's peer credential; the supervisor keeps the socket alive.
pub(crate) fn publish_pgrp(fd: RawFd) {
    unsafe {
        libc::listen(fd, libc::SOMAXCONN);
        libc::close(fd);
    }
}

// ============================================================
// Control loop, spawned as a dedicated tokio task
// ============================================================

/// What the `info` verb reports. Pids are not here: the sockets carry them.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SandboxInfo {
    pub mode: Option<String>,
}

/// Spawn the control-loop task. `ctx` is `None` for sandboxes without a
/// seccomp-notify supervisor (`--no-supervisor`, nested); those still
/// answer `info` and the static `config`, and report no ports.
pub(crate) fn spawn_control_loop(
    sockets: ControlSockets,
    ctx: Option<Arc<SupervisorCtx>>,
    sandbox: Sandbox,
    info: SandboxInfo,
) -> tokio::task::JoinHandle<()> {
    // Mutex only to satisfy Sync: Sandbox carries a Box<dyn FnOnce> slot
    // even though this clone's is None.
    let sandbox = Arc::new(tokio::sync::Mutex::new(sandbox));
    tokio::spawn(async move {
        let ControlSockets { control, pgrp, claim: _claim } = sockets;
        control_loop(control, Some(pgrp), ctx, sandbox, info, unsafe { libc::getuid() }).await;
    })
}

fn peer_cred(fd: RawFd) -> Option<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred)
}

fn into_async(fd: ControlFd) -> Option<AsyncFd<ControlFd>> {
    fd.set_nonblocking().ok()?;
    AsyncFd::new(fd).ok()
}

async fn accept(listener: &AsyncFd<ControlFd>) -> std::io::Result<ControlFd> {
    loop {
        let mut guard = listener.readable().await?;
        match guard.try_io(|inner| inner.get_ref().accept()) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

/// One accepted connection, driven through the reactor while its fd stays
/// on the live list.
struct ControlStream(AsyncFd<ControlFd>);

impl tokio::io::AsyncRead for ControlStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let mut guard = std::task::ready!(self.0.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| inner.get_ref().read(unfilled)) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl tokio::io::AsyncWrite for ControlStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        loop {
            let mut guard = std::task::ready!(self.0.poll_write_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Accept one connection at a time and serve one request per connection.
/// `my_uid` is a parameter so a test can prove the refusal path without a
/// second uid. The timeout keeps one stalled client from wedging
/// introspection. Clients only connect to the pgrp socket for its peer
/// credential and never speak, so those connections are accepted and
/// dropped to keep its backlog empty; a child that never called listen()
/// makes accept() fail with EINVAL, after which the socket is left alone.
async fn control_loop(
    listener: ControlFd,
    pgrp: Option<ControlFd>,
    ctx: Option<Arc<SupervisorCtx>>,
    sandbox: Arc<tokio::sync::Mutex<Sandbox>>,
    info: SandboxInfo,
    my_uid: u32,
) {
    let Some(listener) = into_async(listener) else { return };
    let mut pgrp = pgrp.and_then(into_async);

    loop {
        let drain = async {
            match &pgrp {
                Some(l) => accept(l).await,
                None => std::future::pending().await,
            }
        };
        let stream = tokio::select! {
            accepted = accept(&listener) => match accepted {
                Ok(stream) => stream,
                Err(_) => return,
            },
            drained = drain => {
                if drained.is_err() {
                    pgrp = None;
                }
                continue;
            }
        };
        // Abstract names have no permission bits, so this is the only gate.
        if peer_cred(stream.as_raw_fd()).map(|c| c.uid) != Some(my_uid) {
            continue;
        }
        let Ok(stream) = AsyncFd::new(stream).map(ControlStream) else { continue };
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            serve_one(stream, ctx.as_ref(), &sandbox, &info),
        )
        .await;
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
    stream: ControlStream,
    ctx: Option<&Arc<SupervisorCtx>>,
    sandbox: &Arc<tokio::sync::Mutex<Sandbox>>,
    info: &SandboxInfo,
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
        "info" => handle_info(&mut stream, info).await,
        "config" => handle_config(&mut stream, ctx, sandbox).await,
        "ports" => handle_ports(&mut stream, ctx).await,
        "kill" => handle_kill(&mut stream, ctx).await,
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

async fn handle_info(stream: &mut ControlStream, info: &SandboxInfo) {
    let resp = match serde_json::to_value(info) {
        Ok(data) => ControlResponse { v: 1, ok: true, data: Some(data), err: None },
        Err(e) => ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!("serialize error: {}", e)),
        },
    };
    let _ = write_response(stream, &resp).await;
}

async fn handle_config(
    stream: &mut ControlStream,
    ctx: Option<&Arc<SupervisorCtx>>,
    sandbox: &Arc<tokio::sync::Mutex<Sandbox>>,
) {
    let dynamic_denied: Vec<String> = match ctx {
        Some(ctx) => ctx.policy_fn.lock().await.denied.denied_paths(),
        None => Vec::new(),
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

/// Only the supervisor knows the groups a process has moved into, so
/// `sandlock kill` asks here before it signals the child's own group.
async fn handle_kill(stream: &mut ControlStream, ctx: Option<&Arc<SupervisorCtx>>) {
    let resp = match ctx.map(|ctx| ctx.groups.signal(libc::SIGKILL)) {
        Some(Ok(groups)) => ControlResponse {
            v: 1,
            ok: true,
            data: Some(serde_json::json!({ "groups": groups })),
            err: None,
        },
        Some(Err(e)) => ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some(format!("signal process groups: {}", e)),
        },
        None => ControlResponse {
            v: 1,
            ok: false,
            data: None,
            err: Some("no supervisor".into()),
        },
    };
    let _ = write_response(stream, &resp).await;
}

async fn handle_ports(
    stream: &mut ControlStream,
    ctx: Option<&Arc<SupervisorCtx>>,
) {
    let ports: std::collections::HashMap<u16, u16> = match ctx {
        Some(ctx) => ctx.network.lock().await.port_map.virtual_to_real.clone(),
        None => Default::default(),
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
    stream: &mut ControlStream,
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
// Discovery
// ============================================================

/// Names owned by live supervisors in the caller's IPC namespace.
pub fn list_sandboxes() -> std::io::Result<Vec<String>> {
    let mut names: Vec<_> = ownership::list()?.into_iter().map(|entry| entry.name).collect();
    names.sort();
    Ok(names)
}

// ============================================================
// Client helpers — used by sandlock-cli to talk to the socket
// ============================================================

fn unresponsive(name: &str, e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            format!("sandbox '{}' is unresponsive", name)
        }
        _ => format!("read from sandbox '{}': {}", name, e),
    }
}

fn connect_socket(addr: &SocketAddr) -> std::io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sun.sun_family = libc::AF_UNIX as _;
    let name = addr.as_abstract_name().expect("abstract control address");
    for (dst, &src) in sun.sun_path[1..].iter_mut().zip(name) { *dst = src as _; }
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len();
    if unsafe { libc::connect(fd.as_raw_fd(), (&sun as *const libc::sockaddr_un).cast(), len as _) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// Connect to one of a sandbox's sockets and return the stream with the
/// listener's credentials. `my_uid` is a parameter so a test can prove the
/// refusal without a second uid. SO_PEERCRED on a connected stream reports
/// the process that called listen(), so a name squatted by another user is
/// rejected here, and the pid is that process as seen from this pid
/// namespace.
fn connect_as(addr: &SocketAddr, my_uid: u32) -> Result<(UnixStream, libc::ucred), std::io::Error> {
    let fd = connect_socket(addr)?;
    let stream = UnixStream::from(fd);
    match peer_cred(stream.as_raw_fd()) {
        Some(cred) if cred.uid == my_uid => Ok((stream, cred)),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "owned by another user",
        )),
    }
}

fn connect_control(name: &str, my_uid: u32) -> Result<(UnixStream, libc::ucred), String> {
    let entry = ownership::lookup(name).map_err(|e| e.to_string())?;
    connect_entry(name, &entry, my_uid)
}

fn connect_entry(name: &str, entry: &ownership::Entry, my_uid: u32) -> Result<(UnixStream, libc::ucred), String> {
    let addr = instance_addr(&entry.token, false).map_err(|e| e.to_string())?;
    let (stream, cred) = connect_as(&addr, my_uid).map_err(|e| match e.kind() {
        std::io::ErrorKind::ConnectionRefused => format!("sandbox '{name}' is still starting"),
        std::io::ErrorKind::PermissionDenied => format!("socket for '{name}' is owned by another user"),
        _ => format!("connect to sandbox '{name}': {e}"),
    })?;
    if cred.pid != entry.supervisor {
        return Err(format!("sandbox '{name}' changed owner"));
    }
    Ok((stream, cred))
}

/// The two pids `kill` needs, both stamped by the kernel at listen() time.
#[derive(Debug, Clone, Copy)]
pub struct SandboxPids {
    /// The child, which leads its own process group.
    pub child: i32,
    pub supervisor: i32,
}

/// Needs no cooperation from the supervisor, so it works on one that is
/// stopped or wedged.
pub fn sandbox_pids(name: &str) -> Result<SandboxPids, String> {
    sandbox_pids_as(name, unsafe { libc::getuid() })
}

fn sandbox_pids_as(name: &str, my_uid: u32) -> Result<SandboxPids, String> {
    let entry = ownership::lookup(name).map_err(|e| e.to_string())?;
    let (_, supervisor) = connect_entry(name, &entry, my_uid)?;
    let addr = instance_addr(&entry.token, true).map_err(|e| e.to_string())?;
    // The name exists, so the supervisor is up; the child has not reached
    // listen() yet if this is refused.
    let (_, child) = connect_as(&addr, my_uid).map_err(|e| match e.kind() {
        std::io::ErrorKind::ConnectionRefused => format!("sandbox '{}' is still starting", name),
        std::io::ErrorKind::PermissionDenied => {
            format!("socket for '{}' is owned by another user", name)
        }
        _ => format!("connect to sandbox '{}': {}", name, e),
    })?;
    Ok(SandboxPids { child: child.pid, supervisor: supervisor.pid })
}

/// Send a request to a sandbox's control socket and return the response.
pub fn send_control_request(
    name: &str,
    verb: &str,
    args: serde_json::Value,
) -> Result<ControlResponse, String> {
    send_control_request_as(name, verb, args, unsafe { libc::getuid() })
}

fn send_control_request_as(
    name: &str,
    verb: &str,
    args: serde_json::Value,
    my_uid: u32,
) -> Result<ControlResponse, String> {
    use std::io::{Read, Write};

    let (mut stream, _) = connect_control(name, my_uid)?;

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
    stream.read_exact(&mut len_buf).map_err(|e| unresponsive(name, e))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 65536 {
        return Err("response too large".to_string());
    }
    let mut resp_body = vec![0u8; resp_len];
    stream.read_exact(&mut resp_body).map_err(|e| unresponsive(name, e))?;

    serde_json::from_slice(&resp_body)
        .map_err(|e| format!("parse response: {}", e))
}

/// Ask a sandbox for its mode.
pub fn sandbox_info(name: &str) -> Result<SandboxInfo, String> {
    let resp = send_control_request(name, "info", serde_json::Value::Object(Default::default()))?;
    if !resp.ok {
        return Err(resp.err.unwrap_or_else(|| "info failed".into()));
    }
    let data = resp.data.ok_or_else(|| "empty info response".to_string())?;
    serde_json::from_value(data).map_err(|e| format!("parse info response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_fork_cannot_reserve_a_released_name() {
        let name = format!("test-control-host-fork-{}", std::process::id());
        let sockets = bind_control_sockets(&name).unwrap();
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                libc::close(pipe[1]);
                let mut byte = 0u8;
                libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(pipe[0]); }
        drop(sockets);
        let reused = bind_control_sockets(&name);
        unsafe {
            libc::close(pipe[1]);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        assert!(reused.is_ok(), "name still reserved: {:?}", reused.err());
    }

    #[test]
    fn bind_is_the_name_mutex_and_listing_follows_the_listener() {
        // Unique name: sandbox names are uid-wide, never reuse a fixed one.
        let name = format!("test-ctrl-unit-{}", std::process::id());
        let sockets = bind_control_sockets(&name).unwrap();
        assert!(list_sandboxes().unwrap().contains(&name));
        let err = bind_control_sockets(&name).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        drop(sockets);
        assert!(!list_sandboxes().unwrap().contains(&name));
    }

    /// The live list is exactly what a forked child closes, so it has to
    /// follow every bind and every drop.
    #[test]
    fn live_list_follows_bind_and_drop() {
        let name = format!("test-ctrl-live-{}", std::process::id());
        let sockets = bind_control_sockets(&name).unwrap();
        let (control, pgrp) = (sockets.control.as_raw_fd(), sockets.pgrp.as_raw_fd());
        assert!(live().contains(&control) && live().contains(&pgrp));
        drop(sockets);
        assert!(!live().contains(&control) && !live().contains(&pgrp));
    }

    /// A forked child keeps only the pgrp socket it was told to, with no
    /// help from /proc.
    #[test]
    fn forked_child_keeps_only_its_pgrp_socket() {
        let pid = std::process::id();
        let mine = bind_control_sockets(&format!("test-ctrl-fork-mine-{pid}")).unwrap();
        let sibling = bind_control_sockets(&format!("test-ctrl-fork-sibling-{pid}")).unwrap();
        let keep = mine.pgrp.as_raw_fd();
        let closed = [mine.control.as_raw_fd(), sibling.control.as_raw_fd(), sibling.pgrp.as_raw_fd()];

        let child = fork_without_control_fds(Some(keep));
        assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
        if child == 0 {
            let is_open = |fd: RawFd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
            let ok = is_open(keep) && closed.iter().all(|&fd| !is_open(fd));
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "child status {status:#x}");
    }

    /// The pids come from the kernel's record of who called listen(), not
    /// from anything the sandbox says; nobody serves these sockets here.
    #[test]
    fn client_learns_both_pids_from_the_kernel() {
        let name = format!("test-ctrl-pids-{}", std::process::id());
        let sockets = bind_control_sockets(&name).unwrap();
        let me = std::process::id() as i32;

        let err = sandbox_pids(&name).unwrap_err();
        assert!(err.contains("still starting"), "before listen: {err}");

        assert_eq!(unsafe { libc::listen(sockets.pgrp.as_raw_fd(), 1) }, 0);
        let pids = sandbox_pids(&name).unwrap();
        assert_eq!((pids.child, pids.supervisor), (me, me));

        let expect = unsafe { libc::getuid() }.wrapping_add(1);
        let err = sandbox_pids_as(&name, expect).unwrap_err();
        assert!(err.contains("owned by another user"), "got: {err}");
    }

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    fn test_sandbox() -> Sandbox {
        Sandbox::builder().fs_read("/usr").build().unwrap()
    }

    fn info() -> SandboxInfo {
        SandboxInfo { mode: Some("test".into()) }
    }

    /// Bind a listener for `name`, run the control loop on it with
    /// `expected_uid`, and return the task handle.
    fn serve(name: &str, expected_uid: u32) -> tokio::task::JoinHandle<()> {
        let sockets = bind_control_sockets(name).unwrap();
        let sandbox = Arc::new(tokio::sync::Mutex::new(test_sandbox()));
        tokio::spawn(async move {
            let _claim = sockets.claim;
            control_loop(sockets.control, None, None, sandbox, info(), expected_uid).await;
        })
    }

    /// Connect as ourselves, send an info request, and return what the
    /// server sent back (empty on a silent close).
    fn raw_info_request(name: &str) -> Vec<u8> {
        let mut s = UnixStream::connect_addr(&socket_addr(name).unwrap()).unwrap();
        let body = br#"{"v":1,"verb":"info","args":{}}"#;
        s.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        s.write_all(body).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_answers_its_own_uid() {
        let name = format!("test-ctrl-own-{}", std::process::id());
        let task = serve(&name, unsafe { libc::getuid() });
        let out = tokio::task::spawn_blocking(move || raw_info_request(&name)).await.unwrap();
        task.abort();
        assert!(out.len() > 4, "expected a response, got {} bytes", out.len());
        let resp: ControlResponse = serde_json::from_slice(&out[4..]).unwrap();
        assert!(resp.ok);
        let got: SandboxInfo = serde_json::from_value(resp.data.unwrap()).unwrap();
        assert_eq!(got.mode.as_deref(), Some("test"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_closes_on_another_uid_without_answering() {
        let name = format!("test-ctrl-foreign-{}", std::process::id());
        let task = serve(&name, unsafe { libc::getuid() }.wrapping_add(1));
        let out = tokio::task::spawn_blocking(move || raw_info_request(&name)).await.unwrap();
        task.abort();
        assert!(out.is_empty(), "another uid must get no bytes, got {:?}", out);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_refuses_a_listener_owned_by_another_uid() {
        let name = format!("test-ctrl-squat-{}", std::process::id());
        let task = serve(&name, unsafe { libc::getuid() });
        let expect = unsafe { libc::getuid() }.wrapping_add(1);
        let n = name.clone();
        let err = tokio::task::spawn_blocking(move || {
            send_control_request_as(&n, "info", serde_json::Value::Object(Default::default()), expect)
                .unwrap_err()
        })
        .await
        .unwrap();
        task.abort();
        assert!(err.contains("owned by another user"), "got: {err}");
    }

    #[test]
    fn listing_survives_a_foreign_non_utf8_name() {
        let addr = SocketAddr::from_abstract_name(b"sandlock-probe-\xff\xfe").unwrap();
        let _foreign = UnixListener::bind_addr(&addr).unwrap();
        let name = format!("test-ctrl-utf8-{}", std::process::id());
        let _ours = bind_control_sockets(&name).unwrap();
        assert!(list_sandboxes().unwrap().contains(&name));
    }
}
