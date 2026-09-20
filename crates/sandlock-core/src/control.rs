//! Per-sandbox control sockets for introspection and kill.
//!
//! Every sandbox (CLI, Python SDK, embedded) owns two abstract Unix
//! stream sockets. `\0sandlock/<uid>/<name>` is the name: the child binds
//! it and calls listen() on it right after setpgid(), and nobody ever
//! accepts on it. `\0sandlock/<uid>/<name>/<child pid>` takes the requests;
//! the supervisor binds it and calls listen() on it once the fork has
//! given the child a pid.
//! Abstract names live in the kernel, not the filesystem: bind on a taken
//! name fails, so the first name is the UID-wide sandbox mutex; both names
//! vanish with the supervisor, so nothing is ever stale; `/proc/net/unix`
//! lists them, so `sandlock ps` needs no registry on disk; and a nested
//! sandlock needs no writable directory from the outer policy, only
//! permission to create a socket.
//!
//! A name stays bound while any fd refers to its socket, and a fork copies
//! every fd. The name socket is therefore held with no fd at all (see
//! [`NameVault`]), so that no fork of the host, not even a child that never
//! execs, can keep a finished sandbox's name taken. The request socket
//! does sit in the fd table, since it has to be accepted on, but its name
//! is never asked for twice.
//!
//! listen() stamps the caller's pid into the socket and SO_PEERCRED hands
//! that stamp to whoever connects, so a client learns the child's pid,
//! which is its process group, from the name socket, and the supervisor's
//! from the request socket, which the child's pid leads it to, without the
//! supervisor answering anything. That is what `sandlock kill` uses, so it
//! works on a supervisor that is stopped or wedged. Nobody accepts on the
//! name socket, so each lookup stays in its backlog for the life of the
//! sandbox. Abstract names carry no permission bits, so both sides check
//! the SO_PEERCRED uid: the server closes any connection from another uid
//! and the client refuses a listener owned by one.
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
//! `ProfileInput`), `ports` (virtual to real port map).

use std::os::linux::net::SocketAddrExt;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;

use crate::sandbox::Sandbox;
use crate::seccomp::ctx::SupervisorCtx;

// ============================================================
// Socket address
// ============================================================

/// Bytes after the leading NUL of the abstract name.
pub(crate) fn socket_name(uid: u32, name: &str) -> Vec<u8> {
    format!("sandlock/{uid}/{name}").into_bytes()
}

/// Sandbox names reject `/`, so the suffix cannot collide with a name.
fn request_socket_name(uid: u32, name: &str, child: i32) -> Vec<u8> {
    format!("sandlock/{uid}/{name}/{child}").into_bytes()
}

fn socket_addr(name: &str) -> std::io::Result<SocketAddr> {
    let uid = unsafe { libc::getuid() };
    SocketAddr::from_abstract_name(socket_name(uid, name))
}

fn request_socket_addr(name: &str, child: i32) -> std::io::Result<SocketAddr> {
    let uid = unsafe { libc::getuid() };
    SocketAddr::from_abstract_name(request_socket_name(uid, name, child))
}

// ============================================================
// The name, parked in flight
// ============================================================

/// A sockaddr the forked child can use: it must not allocate.
type RawAddr = (libc::sockaddr_un, libc::socklen_t);

fn raw_addr(name: &[u8]) -> RawAddr {
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, &src) in sun.sun_path[1..].iter_mut().zip(name) {
        *dst = src as libc::c_char;
    }
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len();
    (sun, len as libc::socklen_t)
}

/// Holds a sandbox's name socket without holding an fd to it.
///
/// An abstract name stays bound while any fd refers to its socket, and
/// every fork of this process copies every fd, including forks the host
/// makes on its own and children that never exec. So the name socket never
/// enters this process's fd table. The child creates it and sends it here
/// with SCM_RIGHTS, and the message is left unreceived: a file in flight is
/// one reference, which fork does not multiply. Receiving the message with
/// no room for the fd makes the kernel drop that reference, which frees the
/// name at once, whoever holds a copy of this socketpair.
pub(crate) struct NameVault {
    vault: OwnedFd,
    child_end: Option<OwnedFd>,
    addr: RawAddr,
}

/// What the child needs to publish the name. Plain data, built before the
/// fork.
#[derive(Clone, Copy)]
pub(crate) struct NamePublisher {
    to_vault: RawFd,
    vault: RawFd,
    addr: RawAddr,
}

impl NameVault {
    pub(crate) fn new(name: &str) -> std::io::Result<Self> {
        let mut pair = [0 as RawFd; 2];
        let kind = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
        if unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, pair.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let (vault, child_end) = unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
        let addr = raw_addr(&socket_name(unsafe { libc::getuid() }, name));
        Ok(NameVault { vault, child_end: Some(child_end), addr })
    }

    pub(crate) fn publisher(&self) -> Option<NamePublisher> {
        let to_vault = self.child_end.as_ref()?.as_raw_fd();
        Some(NamePublisher { to_vault, vault: self.vault.as_raw_fd(), addr: self.addr })
    }

    /// In the parent, after the fork: wait for the child's verdict without
    /// taking the socket out of flight. `AddrInUse` means a live sandbox of
    /// this uid already owns the name. `child` is the child's pidfd, so a
    /// child that died before publishing cannot hang this.
    pub(crate) fn published(&mut self, child: Option<RawFd>) -> std::io::Result<()> {
        self.child_end = None;
        let mut fds = [
            libc::pollfd { fd: self.vault.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: child.unwrap_or(-1), events: libc::POLLIN, revents: 0 },
        ];
        loop {
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
            if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            break;
        }
        if fds[0].revents & libc::POLLIN == 0 {
            return Err(std::io::Error::other("child exited before publishing its name"));
        }
        // No control buffer: a peek must not install the fd here either.
        let mut status = [0u8; 4];
        match recv_without_fd(self.vault.as_raw_fd(), &mut status, libc::MSG_PEEK) {
            Ok(4) if status == [0; 4] => Ok(()),
            Ok(4) => Err(std::io::Error::from_raw_os_error(i32::from_ne_bytes(status))),
            Ok(_) => Err(std::io::Error::other("child exited before publishing its name")),
            Err(e) => Err(e),
        }
    }
}

impl Drop for NameVault {
    fn drop(&mut self) {
        let mut status = [0u8; 4];
        while matches!(recv_without_fd(self.vault.as_raw_fd(), &mut status, libc::MSG_DONTWAIT), Ok(n) if n > 0) {}
    }
}

/// Receive data only. The kernel closes any fd the message carries.
fn recv_without_fd(sock: RawFd, buf: &mut [u8], flags: libc::c_int) -> std::io::Result<usize> {
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    match unsafe { libc::recvmsg(sock, &mut msg, flags) } {
        n if n < 0 => Err(std::io::Error::last_os_error()),
        n => Ok(n as usize),
    }
}

impl NamePublisher {
    /// In the child, after setpgid(). listen() records this pid, which is
    /// also its process group, as the socket's peer credential. The status
    /// goes to the parent either way; the socket goes with it on success.
    pub(crate) fn publish(&self) {
        unsafe {
            let sock = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            let addr = &self.addr.0 as *const _ as *const libc::sockaddr;
            let ok = sock >= 0
                && libc::bind(sock, addr, self.addr.1) == 0
                && libc::listen(sock, libc::SOMAXCONN) == 0;
            let status: i32 = if ok { 0 } else { *libc::__errno_location() };

            let mut data = status.to_ne_bytes();
            let mut iov = libc::iovec { iov_base: data.as_mut_ptr() as *mut libc::c_void, iov_len: data.len() };
            let mut cmsg = [0u64; 4];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if ok {
                msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
                msg.msg_controllen = libc::CMSG_SPACE(4) as _;
                let hdr = libc::CMSG_FIRSTHDR(&msg);
                (*hdr).cmsg_level = libc::SOL_SOCKET;
                (*hdr).cmsg_type = libc::SCM_RIGHTS;
                (*hdr).cmsg_len = libc::CMSG_LEN(4) as _;
                std::ptr::write_unaligned(libc::CMSG_DATA(hdr) as *mut RawFd, sock);
            }
            libc::sendmsg(self.to_vault, &msg, libc::MSG_NOSIGNAL);
            libc::close(sock);
            libc::close(self.to_vault);
            libc::close(self.vault);
        }
    }
}

// ============================================================
// The request socket
// ============================================================

/// A socket fd that refuses connections from the moment we let go of it.
/// Its name is never reused, so a copy in some forked child does no harm
/// by lingering, but it must not look alive.
#[derive(Debug)]
pub(crate) struct ControlFd(OwnedFd);

impl ControlFd {
    fn set_nonblocking(&self) -> std::io::Result<()> {
        let fd = self.0.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn accept(&self) -> std::io::Result<ControlFd> {
        let fd = unsafe {
            libc::accept4(
                self.0.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ControlFd(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(self.0.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.0.as_raw_fd(), buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl AsRawFd for ControlFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl Drop for ControlFd {
    fn drop(&mut self) {
        unsafe { libc::shutdown(self.0.as_raw_fd(), libc::SHUT_RDWR) };
    }
}

/// Bind and listen on this instance's request socket. The child's pid is
/// part of the name: clients learn it from the name socket, and it keeps
/// the name from ever being asked for twice.
pub(crate) fn bind_request_socket(name: &str, child: i32) -> std::io::Result<ControlFd> {
    Ok(ControlFd(UnixListener::bind_addr(&request_socket_addr(name, child)?)?.into()))
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
    listener: ControlFd,
    ctx: Option<Arc<SupervisorCtx>>,
    sandbox: Sandbox,
    info: SandboxInfo,
) -> tokio::task::JoinHandle<()> {
    // Mutex only to satisfy Sync: Sandbox carries a Box<dyn FnOnce> slot
    // even though this clone's is None.
    let sandbox = Arc::new(tokio::sync::Mutex::new(sandbox));
    tokio::spawn(control_loop(listener, ctx, sandbox, info, unsafe { libc::getuid() }))
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

/// One accepted connection, driven through the reactor.
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
/// introspection.
async fn control_loop(
    listener: ControlFd,
    ctx: Option<Arc<SupervisorCtx>>,
    sandbox: Arc<tokio::sync::Mutex<Sandbox>>,
    info: SandboxInfo,
    my_uid: u32,
) {
    let Some(listener) = into_async(listener) else { return };

    loop {
        let Ok(stream) = accept(&listener).await else { return };
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

/// Names of every listening control socket belonging to `uid`, parsed
/// from `/proc/net/unix` text. Columns: Num RefCount Protocol Flags Type
/// St Inode Path; Flags 00010000 is __SO_ACCEPTCON, a listening socket.
pub(crate) fn parse_proc_net_unix(text: &str, uid: u32) -> Vec<String> {
    let prefix = format!("@sandlock/{uid}/");
    let mut names: Vec<String> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let flags = fields.nth(3)?;
            let path = fields.nth(3)?;
            if flags != "00010000" {
                return None;
            }
            let name = path.strip_prefix(&prefix)?;
            (!name.contains('/')).then(|| name.to_string())
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Names of the caller's live sandboxes, sorted.
pub fn list_sandboxes() -> std::io::Result<Vec<String>> {
    // Any process can bind an abstract name that is not UTF-8; ours are
    // ASCII, so a mangled foreign name just fails the prefix match.
    let text = String::from_utf8_lossy(&std::fs::read("/proc/net/unix")?).into_owned();
    Ok(parse_proc_net_unix(&text, unsafe { libc::getuid() }))
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

/// Connect to one of a sandbox's sockets and return the stream with the
/// listener's credentials. `my_uid` is a parameter so a test can prove the
/// refusal without a second uid. SO_PEERCRED on a connected stream reports
/// the process that called listen(), so a name squatted by another user is
/// rejected here, and the pid is that process as seen from this pid
/// namespace.
fn connect_as(addr: &SocketAddr, my_uid: u32) -> Result<(UnixStream, libc::ucred), std::io::Error> {
    let stream = UnixStream::connect_addr(addr)?;
    match peer_cred(stream.as_raw_fd()) {
        Some(cred) if cred.uid == my_uid => Ok((stream, cred)),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "owned by another user",
        )),
    }
}

fn connect_control(name: &str, my_uid: u32) -> Result<(UnixStream, libc::ucred), String> {
    let addr = socket_addr(name).map_err(|e| format!("socket address for '{}': {}", name, e))?;
    connect_as(&addr, my_uid).map_err(|e| match e.kind() {
        std::io::ErrorKind::ConnectionRefused => format!("no sandbox named '{}'", name),
        std::io::ErrorKind::PermissionDenied => {
            format!("socket for '{}' is owned by another user", name)
        }
        _ => format!("connect to sandbox '{}': {}", name, e),
    })
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
    let (stream, pids) = connect_request(name, my_uid)?;
    drop(stream);
    Ok(pids)
}

/// Connect to a sandbox's request socket, by way of its name socket.
fn connect_request(name: &str, my_uid: u32) -> Result<(UnixStream, SandboxPids), String> {
    let (_, child) = connect_control(name, my_uid)?;
    let addr = request_socket_addr(name, child.pid)
        .map_err(|e| format!("socket address for '{}': {}", name, e))?;
    // The name exists, so the child is up; the supervisor has not bound
    // its side yet if this is refused.
    let (stream, supervisor) = connect_as(&addr, my_uid).map_err(|e| match e.kind() {
        std::io::ErrorKind::ConnectionRefused => format!("sandbox '{}' is still starting", name),
        std::io::ErrorKind::PermissionDenied => {
            format!("socket for '{}' is owned by another user", name)
        }
        _ => format!("connect to sandbox '{}': {}", name, e),
    })?;
    Ok((stream, SandboxPids { child: child.pid, supervisor: supervisor.pid }))
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

    let (mut stream, _) = connect_request(name, my_uid)?;

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
    fn longest_name_fits_sun_path() {
        let name = "x".repeat(64);
        // Leading NUL plus the name must fit the kernel's 108-byte sun_path.
        assert!(request_socket_name(u32::MAX, &name, i32::MAX).len() < 108);
    }

    #[test]
    fn parses_listening_sockets_for_uid_only() {
        let text = "Num RefCount Protocol Flags Type St Inode Path\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 11628860 @sandlock/1000/alpha\n\
            0000000000000000: 00000003 00000000 00000000 0001 03 11628861 @sandlock/1000/alpha\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 11628862 @sandlock/1001/other\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 11628863 /run/user/1000/bus\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 11628864 @sandlock/1000/beta\n\
            0000000000000000: 00000002 00000000 00010000 0001 01 11628865 @sandlock/1000/beta/pgrp\n";
        assert_eq!(parse_proc_net_unix(text, 1000), vec!["alpha", "beta"]);
        assert_eq!(parse_proc_net_unix(text, 1001), vec!["other"]);
    }

    /// Claim `name` the way a sandbox does: a forked child publishes it.
    /// Returns the vault and that child's pid, which the name is stamped
    /// with.
    fn claim(name: &str) -> std::io::Result<(NameVault, i32)> {
        let mut vault = NameVault::new(name)?;
        let publisher = vault.publisher().unwrap();
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
        if child == 0 {
            publisher.publish();
            unsafe { libc::_exit(0) };
        }
        let published = vault.published(None);
        unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
        published.map(|()| (vault, child))
    }

    #[test]
    fn the_name_is_a_mutex_and_listing_follows_it() {
        // Unique name: sandbox names are uid-wide, never reuse a fixed one.
        let name = format!("test-ctrl-unit-{}", std::process::id());
        let (vault, _) = claim(&name).unwrap();
        assert!(list_sandboxes().unwrap().contains(&name));
        let err = claim(&name).err().expect("second claim must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        drop(vault);
        assert!(!list_sandboxes().unwrap().contains(&name));
    }

    /// The host can fork at any time, in ways no libc hook sees, and such a
    /// child may never exec. It copies every fd of this process, and the
    /// name must still be free the moment its vault is dropped.
    #[test]
    fn a_fork_made_by_the_host_cannot_hold_the_name() {
        let name = format!("test-ctrl-host-fork-{}", std::process::id());
        let (vault, _) = claim(&name).unwrap();

        let mut gate = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe2(gate.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let lingering = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) } as libc::pid_t;
        assert!(lingering >= 0, "clone: {}", std::io::Error::last_os_error());
        if lingering == 0 {
            let mut byte = 0u8;
            unsafe {
                libc::close(gate[1]);
                libc::read(gate[0], &mut byte as *mut u8 as *mut libc::c_void, 1);
                libc::_exit(0);
            }
        }

        drop(vault);
        let again = claim(&name);
        unsafe {
            libc::close(gate[1]);
            libc::close(gate[0]);
            libc::waitpid(lingering, std::ptr::null_mut(), 0);
        }
        again.expect("the name must be free while the host's child lives");
    }

    /// The pids come from the kernel's record of who called listen(), not
    /// from anything the sandbox says; nobody serves these sockets here.
    #[test]
    fn client_learns_both_pids_from_the_kernel() {
        let name = format!("test-ctrl-pids-{}", std::process::id());
        let (_vault, child) = claim(&name).unwrap();
        let me = std::process::id() as i32;

        let err = sandbox_pids(&name).unwrap_err();
        assert!(err.contains("still starting"), "before the request socket: {err}");

        let _requests = bind_request_socket(&name, child).unwrap();
        let pids = sandbox_pids(&name).unwrap();
        assert_eq!((pids.child, pids.supervisor), (child, me));

        let expect = unsafe { libc::getuid() }.wrapping_add(1);
        let err = sandbox_pids_as(&name, expect).unwrap_err();
        assert!(err.contains("owned by another user"), "got: {err}");
    }

    /// A request socket we let go of must refuse connections at once, even
    /// while a copy of its fd lingers in some forked child.
    #[test]
    fn a_released_request_socket_refuses_connections() {
        let name = format!("test-ctrl-refuse-{}", std::process::id());
        let (_vault, child) = claim(&name).unwrap();
        let requests = bind_request_socket(&name, child).unwrap();
        let copy = unsafe { libc::dup(requests.as_raw_fd()) };
        drop(requests);
        let err = sandbox_pids(&name).unwrap_err();
        unsafe { libc::close(copy) };
        assert!(err.contains("still starting"), "got: {err}");
    }

    use std::io::{Read, Write};

    fn test_sandbox() -> Sandbox {
        Sandbox::builder().fs_read("/usr").build().unwrap()
    }

    fn info() -> SandboxInfo {
        SandboxInfo { mode: Some("test".into()) }
    }

    /// Claim `name` and run the control loop for it as `expected_uid`. The
    /// name lasts as long as the returned vault.
    fn serve(name: &str, expected_uid: u32) -> (NameVault, tokio::task::JoinHandle<()>) {
        let (vault, child) = claim(name).unwrap();
        let listener = bind_request_socket(name, child).unwrap();
        let sandbox = Arc::new(tokio::sync::Mutex::new(test_sandbox()));
        (vault, tokio::spawn(control_loop(listener, None, sandbox, info(), expected_uid)))
    }

    /// Connect as ourselves, send an info request, and return what the
    /// server sent back (empty on a silent close).
    fn raw_info_request(name: &str) -> Vec<u8> {
        let (mut s, _) = connect_request(name, unsafe { libc::getuid() }).unwrap();
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
        let (_vault, task) = serve(&name, unsafe { libc::getuid() });
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
        let (_vault, task) = serve(&name, unsafe { libc::getuid() }.wrapping_add(1));
        let out = tokio::task::spawn_blocking(move || raw_info_request(&name)).await.unwrap();
        task.abort();
        assert!(out.is_empty(), "another uid must get no bytes, got {:?}", out);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_refuses_a_listener_owned_by_another_uid() {
        let name = format!("test-ctrl-squat-{}", std::process::id());
        let (_vault, task) = serve(&name, unsafe { libc::getuid() });
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
        let _ours = claim(&name).unwrap();
        assert!(list_sandboxes().unwrap().contains(&name));
    }
}
