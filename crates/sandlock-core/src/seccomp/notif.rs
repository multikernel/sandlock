// Seccomp user notification supervisor — async event loop that receives
// notifications from the kernel, dispatches them to handler functions, and
// sends responses.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;

use crate::error::NotifError;
use crate::arch;
use crate::sys::structs::{
    SeccompNotif, SeccompNotifAddfd, SeccompNotifResp,
    SECCOMP_ADDFD_FLAG_SEND, SECCOMP_IOCTL_NOTIF_ADDFD, SECCOMP_IOCTL_NOTIF_ID_VALID, SECCOMP_IOCTL_NOTIF_RECV,
    SECCOMP_IOCTL_NOTIF_SEND, SECCOMP_IOCTL_NOTIF_SET_FLAGS,
    SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP, SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    ENOMEM,
};

// ============================================================
// NotifAction — how the supervisor should respond
// ============================================================

/// A one-shot callback invoked with the child-side fd number returned by
/// `SECCOMP_IOCTL_NOTIF_ADDFD` after a successful `InjectFdSendTracked`.
/// Wraps a boxed closure with a manual `Debug` impl so that `NotifAction`
/// can keep deriving `Debug`.  The closure is both `Send` and `Sync` so
/// that `&NotifAction` remains `Send` (required because `NotifAction` is
/// borrowed across `.await` points in the notifier loop).
pub struct OnInjectSuccess(pub Box<dyn FnOnce(i32) + Send + Sync>);

impl std::fmt::Debug for OnInjectSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnInjectSuccess(<callback>)")
    }
}

impl OnInjectSuccess {
    pub fn new<F: FnOnce(i32) + Send + Sync + 'static>(f: F) -> Self {
        Self(Box::new(f))
    }
}

/// A deferred decision: an owned, `'static` future that produces the real
/// [`NotifAction`] off the supervisor's notification loop.
///
/// A handler returns [`NotifAction::Defer`] when computing the response is
/// slow (a network round-trip, a blocking syscall) and must not stall the
/// single supervisor task that gates every other trapped syscall.  The
/// supervisor moves the future onto a worker, lets the loop proceed, and
/// sends the response (via the still-valid `notif.id`) when the future
/// resolves.  The future is `'static` because it outlives the borrowed
/// `HandlerCtx` — capture what you need (`notif` is `Copy`, `notif_fd` is a
/// `RawFd`) by value rather than borrowing `&self`.
///
/// The deferred future need only be `Send` (not `Sync`): the supervisor
/// moves it onto a worker task and never shares it by reference.  Requiring
/// `Sync` of user futures would be a leaky bound (it would reject a future
/// capturing, say, a `Cell`), so it is not required.
pub struct Deferred(Pin<Box<dyn Future<Output = NotifAction> + Send + 'static>>);

// Safety: `NotifAction` must stay `Sync` so it can live in `Sync` contexts
// (handler `&self` state, etc.; the `Handler` trait is `Send + Sync`), which
// requires `Deferred: Sync`.  A `Send`-only future is not `Sync`, but the
// boxed future is unreachable through a shared `&Deferred`: the field is
// private, `Debug` touches only a static string, and `run(self)` consumes
// the value (it is never callable through `&self`).  With no path to poll or
// read the future via a shared reference, sharing `&Deferred` across threads
// cannot race, so asserting `Sync` is sound while keeping user futures
// `Send`-only.
unsafe impl Sync for Deferred {}

impl std::fmt::Debug for Deferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Deferred(<future>)")
    }
}

impl Deferred {
    pub fn new<F: Future<Output = NotifAction> + Send + 'static>(f: F) -> Self {
        Self(Box::pin(f))
    }

    /// Drive the deferred future to its terminal action.  Consumes `self`
    /// because the future is run exactly once, on a worker task.
    pub async fn run(self) -> NotifAction {
        self.0.await
    }
}

/// How the supervisor should respond to a notification.
#[derive(Debug)]
pub enum NotifAction {
    /// SECCOMP_USER_NOTIF_FLAG_CONTINUE — let the syscall proceed.
    Continue,
    /// Return -1 with the given errno.
    Errno(i32),
    /// Inject a file descriptor into the child, then continue.
    InjectFd { srcfd: RawFd, targetfd: i32 },
    /// Inject a file descriptor using SECCOMP_ADDFD_FLAG_SEND (atomically responds).
    /// The child sees the injected fd as the return value of the syscall.
    /// The `OwnedFd` is closed automatically after the ioctl completes.
    /// `newfd_flags` controls flags on the injected fd (e.g. O_CLOEXEC).
    InjectFdSend { srcfd: OwnedFd, newfd_flags: u32 },
    /// Like `InjectFdSend`, but also invokes `on_success` with the
    /// child-side fd number that `SECCOMP_IOCTL_NOTIF_ADDFD` returned.
    /// Used when the caller needs to track the exact fd number allocated
    /// in the child (e.g. to key per-fd state without TOCTOU).
    InjectFdSendTracked {
        srcfd: OwnedFd,
        newfd_flags: u32,
        on_success: OnInjectSuccess,
    },
    /// Synthetic return value (the child sees this as the syscall result).
    ReturnValue(i64),
    /// Don't respond — used for checkpoint/freeze.
    Hold,
    /// Kill the child process group (OOM-kill semantics).
    /// Fields: signal, process group leader pid.
    Kill { sig: i32, pgid: i32 },
    /// Defer the response: run the carried future on a worker task and
    /// send its terminal action later, keyed by `notif.id`.  Non-`Continue`,
    /// so it short-circuits the handler chain — a deferring handler makes a
    /// terminal decision.  See [`Deferred`].
    Defer(Deferred),
}

impl NotifAction {
    /// Construct a [`NotifAction::Defer`] from a `'static` future.  Ergonomic
    /// shorthand for `NotifAction::Defer(Deferred::new(fut))`.
    pub fn defer<F: Future<Output = NotifAction> + Send + 'static>(fut: F) -> Self {
        NotifAction::Defer(Deferred::new(fut))
    }

    /// Inject `content` into the child as the syscall's returned fd, backed by
    /// a sealed (read-only, fixed-size), `O_CLOEXEC` in-memory file.
    ///
    /// The fd is created, populated, sealed, and owned end to end by sandlock;
    /// the caller never sees or closes it. On allocation failure this collapses
    /// to `Errno(EIO)`, so a handler can return it directly:
    ///
    /// ```ignore
    /// return NotifAction::inject_bytes(&secret);
    /// ```
    ///
    /// For a *writable* injected fd, build one with
    /// [`content_memfd(content, false)`](content_memfd) and pass it to
    /// [`NotifAction::InjectFdSend`] yourself.
    pub fn inject_bytes(content: &[u8]) -> NotifAction {
        match content_memfd(content, true) {
            Ok(fd) => NotifAction::InjectFdSend {
                srcfd: fd,
                newfd_flags: libc::O_CLOEXEC as u32,
            },
            Err(_) => NotifAction::Errno(libc::EIO),
        }
    }
}

/// Create an anonymous in-memory file ("memfd") populated with `content` and
/// rewound to offset 0, ready to inject as a syscall's returned fd via
/// [`NotifAction::InjectFdSend`].
///
/// When `seal` is true the fd is sealed read-only and fixed-size
/// (`F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK`) so the guest
/// cannot modify or resize the content it is handed. Sealing is best-effort:
/// on a kernel without sealing support the fd is still returned, bounded by
/// the rest of the policy. Pass `false` only when the guest genuinely needs a
/// writable injected fd.
///
/// Most callers want [`NotifAction::inject_bytes`], which wraps this in the
/// common sealed + `O_CLOEXEC` configuration.
pub fn content_memfd(content: &[u8], seal: bool) -> io::Result<OwnedFd> {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::io::FromRawFd;

    let flags = if seal {
        (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as u32
    } else {
        libc::MFD_CLOEXEC as u32
    };
    let memfd = crate::sys::syscall::memfd_create("sandlock-content", flags)?;

    // Write the content and rewind. Borrow the raw fd for File I/O without
    // transferring ownership: `memfd` (the OwnedFd) keeps owning it.
    {
        let raw = memfd.as_raw_fd();
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        let res = file
            .write_all(content)
            .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()));
        std::mem::forget(file); // don't close `raw`; `memfd` still owns it
        res?;
    }

    if seal {
        // Best-effort: ignore failure on kernels lacking sealing support.
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
        unsafe { libc::fcntl(memfd.as_raw_fd(), libc::F_ADD_SEALS, seals) };
    }

    Ok(memfd)
}

/// Collapse a deferred future's resolved action into a sendable terminal
/// action.  A deferred future that itself resolves to `Defer` is a bug
/// (no nested deferral); collapse it to `EIO` so the trapped child gets a
/// definite response instead of wedging forever waiting for one.
fn finalize_deferred(action: NotifAction) -> NotifAction {
    match action {
        NotifAction::Defer(_) => NotifAction::Errno(libc::EIO),
        other => other,
    }
}

// ============================================================
// NetworkPolicy — network access policy enum
// ============================================================

/// Per-IP port allowlist. `Any` is used by `policy_fn` IP-only
/// overrides (legacy `restrict_network(ips)` API where the user
/// restricts the destination IP set but not ports).
#[derive(Debug, Clone)]
pub enum PortAllow {
    /// Any port permitted to this IP.
    Any,
    /// Only these ports permitted to this IP.
    Specific(HashSet<u16>),
}

/// Global network policy for the sandbox.
#[derive(Debug, Clone)]
pub enum NetworkPolicy {
    /// No IP-level restriction for this protocol. On the on-behalf path this
    /// is only ever reached *with* a destination policy active (e.g. a `*:*` /
    /// `:*` allow-all-ports rule), so here it means "allow any destination."
    /// The empty-`net_allow` deny-all case never reaches this arm: with no
    /// destination policy the connect is returned to the kernel and Landlock's
    /// `CONNECT_TCP` deny-all governs it.
    Unrestricted,
    /// Endpoint-level allowlist: a connection is permitted iff the
    /// destination IP and port match at least one entry below.
    AllowList {
        /// Per-IP port rules. From `--net-allow host:ports` after
        /// hostname resolution, or from `policy_fn` overrides.
        per_ip: HashMap<IpAddr, PortAllow>,
        /// (network, allowed-ports) rules from `--net-allow` IP/CIDR
        /// targets, matched by containment with no DNS. `PortAllow::Any`
        /// permits every port to the range.
        cidrs: Vec<(crate::network::IpCidr, PortAllow)>,
        /// Ports permitted for any IP (from `--net-allow :port` /
        /// `*:port`).
        any_ip_ports: HashSet<u16>,
    },
    /// Default-allow denylist: a connection is permitted unless the
    /// destination IP/port matches a deny rule. From `--net-deny`.
    DenyList {
        /// (network, denied-ports) rules. `PortAllow::Any` denies every
        /// port to the network; `Specific` denies only those ports.
        cidrs: Vec<(crate::network::IpCidr, PortAllow)>,
        /// Ports denied for any IP (the `:port` form).
        any_ip_ports: HashSet<u16>,
        /// Deny everything (the `:*` / `*:*` form). Rare; here for
        /// completeness so the form is not silently a no-op.
        deny_all: bool,
    },
}

impl NetworkPolicy {
    /// True iff a connection to (ip, port) should be permitted.
    pub fn allows(&self, ip: IpAddr, port: u16) -> bool {
        match self {
            NetworkPolicy::Unrestricted => true,
            NetworkPolicy::AllowList { per_ip, cidrs, any_ip_ports } => {
                if any_ip_ports.contains(&port) {
                    return true;
                }
                match per_ip.get(&ip) {
                    Some(PortAllow::Any) => return true,
                    Some(PortAllow::Specific(s)) if s.contains(&port) => return true,
                    _ => {}
                }
                for (net, allowed) in cidrs {
                    if net.contains(ip) {
                        match allowed {
                            PortAllow::Any => return true,
                            PortAllow::Specific(s) => {
                                if s.contains(&port) {
                                    return true;
                                }
                            }
                        }
                    }
                }
                false
            }
            NetworkPolicy::DenyList { cidrs, any_ip_ports, deny_all } => {
                if *deny_all {
                    return false;
                }
                if any_ip_ports.contains(&port) {
                    return false;
                }
                for (net, denied) in cidrs {
                    if net.contains(ip) {
                        match denied {
                            PortAllow::Any => return false,
                            PortAllow::Specific(s) => {
                                if s.contains(&port) {
                                    return false;
                                }
                            }
                        }
                    }
                }
                true
            }
        }
    }
}

/// Check if a path-bearing notification targets a denied path.
///
/// For two-path syscalls (renameat2, linkat), checks both source and
/// destination paths — a denied file must not be linked, renamed, or
/// overwritten.
///
/// Each resolved path is checked both as-is (lexical normalization) and
/// after following symlinks via `canonicalize`.  This prevents bypass via
/// pre-existing symlinks, relative symlinks, or symlink chains that
/// ultimately resolve to a denied path.
pub(crate) fn is_path_denied_for_notif(
    policy_fn_state: &super::state::PolicyFnState,
    notif: &SeccompNotif,
    notif_fd: RawFd,
) -> bool {
    if let Some(path) = resolve_path_for_notif(notif, notif_fd) {
        if is_denied_with_symlink_resolve(policy_fn_state, &path) {
            return true;
        }
    }
    // For two-path syscalls, also check the second (destination) path.
    if let Some(path) = resolve_second_path_for_notif(notif, notif_fd) {
        if is_denied_with_symlink_resolve(policy_fn_state, &path) {
            return true;
        }
    }
    false
}

/// Check a path against denied entries, also resolving symlinks.
///
/// First checks the lexical path, then `canonicalize`s to follow symlinks
/// and checks the real path.  This catches pre-existing symlinks, relative
/// symlinks, and symlink chains that resolve to a denied file.
fn is_denied_with_symlink_resolve(
    policy_fn_state: &super::state::PolicyFnState,
    path: &str,
) -> bool {
    // Check the literal (lexically normalized) path first.
    if policy_fn_state.is_path_denied(path) {
        return true;
    }
    // Follow symlinks and re-check against denied entries.
    if let Ok(real) = std::fs::canonicalize(path) {
        if policy_fn_state.is_path_denied(&real.to_string_lossy()) {
            return true;
        }
    }
    false
}

/// Read the thread-group leader (Tgid) of a thread from `/proc/<tid>/status`.
fn tgid_of(tid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", tid)).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:").and_then(|r| r.trim().parse().ok()))
}

/// Duplicate a file descriptor from an arbitrary process (by PID/TID) into the supervisor.
///
/// `pidfd_getfd` (Linux 5.6+) needs a pidfd for the owning *process*. All threads
/// of a process share one fd table, so the process's pidfd dups any thread's fd:
/// `pidfd_open(pid, 0)` gives it directly when `pid` is a thread-group leader,
/// otherwise we resolve the leader via `Tgid` in `/proc/<pid>/status` and open
/// that. The triggering thread is frozen on the seccomp notification, so its
/// Tgid cannot race with pid reuse. Works on any kernel with `pidfd_getfd`.
pub(crate) fn dup_fd_from_pid(pid: u32, target_fd: i32) -> io::Result<OwnedFd> {
    use crate::sys::syscall::{pidfd_getfd, pidfd_open};
    let pidfd = pidfd_open(pid, 0).or_else(|e| match tgid_of(pid) {
        Some(tgid) if tgid != pid => pidfd_open(tgid, 0),
        _ => Err(e),
    })?;
    pidfd_getfd(&pidfd, target_fd, 0)
}

// ============================================================
// NotifPolicy — policy for the notification supervisor
// ============================================================

/// Policy for the notification supervisor.
pub struct NotifPolicy {
    pub max_memory_bytes: u64,
    pub max_processes: u32,
    pub has_memory_limit: bool,
    /// A **network destination policy** is active: a `net_allow` allowlist, a
    /// `net_deny` denylist, an HTTP ACL, or a live `policy_fn` (i.e.
    /// `network_destination_policy`). Despite the historical singular framing
    /// this is *not* only an allowlist. When set, the on-behalf path is the
    /// IP-level enforcer for connect/sendto/sendmsg and those handlers must
    /// never `Continue`; when clear, the syscalls are trapped only to gate
    /// named `AF_UNIX` sockets and IP destinations are returned to the kernel
    /// so Landlock/BPF govern them.
    pub has_net_destination_policy: bool,
    /// `--net-deny-bind` is active: trap `bind()` and register the on-behalf
    /// handler so denied TCP ports can be refused (independent of the
    /// connect-side `has_net_destination_policy`).
    pub has_bind_denylist: bool,
    /// Named (pathname) `AF_UNIX` connect gate. When true, `connect()` to a
    /// named unix socket whose path is not covered by an fs-write grant is
    /// denied with EACCES. Landlock has no access right for unix-socket
    /// connect, so the seccomp layer closes the escape; abstract sockets are
    /// handled by `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` instead.
    pub has_unix_fs_gate: bool,
    pub has_random_seed: bool,
    pub has_time_start: bool,
    /// Argv-safety gate: the supervisor must freeze every task that
    /// could mutate argv before any consumer reads it. True when
    /// `policy_fn` is active or when a handler is bound to
    /// execve/execveat (such handlers can call `read_child_mem`).
    /// Also gates ptrace fork-event tracking so `ProcessIndex` is
    /// complete when the freeze enumerates it.
    pub argv_safety_required: bool,
    pub time_offset: i64,
    pub num_cpus: Option<u32>,
    pub port_remap: bool,
    pub cow_enabled: bool,
    pub chroot_root: Option<std::path::PathBuf>,
    /// Virtual paths allowed for reading under chroot (original user-specified paths).
    pub chroot_readable: Vec<std::path::PathBuf>,
    /// Virtual paths allowed for writing under chroot (original user-specified paths).
    pub chroot_writable: Vec<std::path::PathBuf>,
    /// Virtual paths explicitly denied under chroot.
    pub chroot_denied: Vec<std::path::PathBuf>,
    /// Mount mappings: (virtual_path, host_path) pairs.
    pub chroot_mounts: Vec<(std::path::PathBuf, std::path::PathBuf)>,
    pub deterministic_dirs: bool,
    pub virtual_hostname: Option<String>,
    pub has_http_acl: bool,
    /// Synthetic `/etc/hosts` served to the sandbox. Always populated:
    /// `openat("/etc/hosts")` returns a memfd with this content so the
    /// host's on-disk `/etc/hosts` never leaks in. The content is the
    /// loopback base plus any concrete hostnames resolved from `net_allow`.
    pub virtual_etc_hosts: String,
    /// User-declared trust-bundle paths to splice the MITM CA into.
    pub ca_inject_paths: Vec<std::path::PathBuf>,
    /// Active MITM CA public cert (PEM bytes) to inject. `Some` only when
    /// HTTPS MITM is active (BYO or generated).
    pub ca_inject_pem: Option<std::sync::Arc<Vec<u8>>>,
}

impl NotifPolicy {
    /// Whether an IP-family `connect()` must be handled on-behalf by the
    /// supervisor, given the destination's loopback-ness.
    ///
    /// This is the connect-side form of the invariant the `sendto`/`sendmsg`
    /// handlers already follow: with [`Self::has_net_destination_policy`] the
    /// on-behalf path is the IP-level enforcer and must never `Continue`;
    /// without it there is nothing to enforce and the syscall is returned to
    /// the kernel. `connect()` adds one wrinkle over datagram sends —
    /// `port_remap` rewrites the destination, but only for **loopback** — so
    /// that is the sole extra reason to supervise an otherwise-unpoliced IP
    /// connect. When this returns `false`, the connect was trapped purely to
    /// gate named `AF_UNIX` sockets, and deferring to the kernel lets the
    /// child's own Landlock `CONNECT_TCP` rules govern it (deny-all for an
    /// empty `net_allow`); handling it on-behalf would run it in the
    /// unconfined supervisor and bypass that decision.
    pub(crate) fn ip_connect_supervised(&self, dest_is_loopback: bool) -> bool {
        self.has_net_destination_policy || (self.port_remap && dest_is_loopback)
    }
}

// ============================================================
// Low-level ioctl helpers
// ============================================================

/// Receive a seccomp notification from the kernel.
/// ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &notif)
fn recv_notif(fd: RawFd) -> io::Result<SeccompNotif> {
    let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV as libc::c_ulong, &mut notif as *mut _)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(notif)
    }
}

/// Result of a non-blocking probe on the seccomp notif fd.
enum NotifFdState {
    /// At least one INIT-state notification is queued. `recv_notif`
    /// will return without blocking.
    Pending,
    /// No notifications and no terminal flags. Wait for the next
    /// epoll edge before probing again.
    Empty,
    /// `POLLHUP`/`POLLERR`/`POLLNVAL` set, or `poll(2)` itself failed:
    /// filter has been released or the fd is invalid. The supervisor
    /// should exit; subsequent waits would busy-spin because epoll
    /// keeps reporting the fd ready.
    Terminal,
}

/// Non-blocking probe of the seccomp notif fd.
///
/// `SECCOMP_IOCTL_NOTIF_RECV` ignores `O_NONBLOCK` and calls
/// `wait_event_interruptible` unconditionally (kernel/seccomp.c
/// `seccomp_notify_recv`). So `recv_notif` cannot be invoked
/// speculatively to detect an empty queue. This helper uses
/// `poll(timeout=0)` as a non-blocking predictor: if POLLIN is set
/// the kernel will hand us a notification without blocking; if a
/// terminal flag is set the fd will keep waking AsyncFd until the
/// supervisor exits.
fn probe_notif_fd(fd: RawFd) -> NotifFdState {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let r = unsafe { libc::poll(&mut pfd, 1, 0) };
    if r > 0 && (pfd.revents & libc::POLLIN) != 0 {
        return NotifFdState::Pending;
    }
    if r < 0 || (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
        return NotifFdState::Terminal;
    }
    NotifFdState::Empty
}

/// Send a response with SECCOMP_USER_NOTIF_FLAG_CONTINUE.
fn respond_continue(fd: RawFd, id: u64) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    send_resp_raw(fd, &resp)
}

/// Send a response that returns -1 with the given errno.
fn respond_errno(fd: RawFd, id: u64, errno: i32) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    send_resp_raw(fd, &resp)
}

/// Send a response with a synthetic return value.
fn respond_value(fd: RawFd, id: u64, val: i64) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val,
        error: 0,
        flags: 0,
    };
    send_resp_raw(fd, &resp)
}

/// Fail-closed response used when fd injection fails.
///
/// Denies the syscall with `EACCES` rather than letting it continue: a
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` here would let the child's original
/// syscall run unmediated against the host path, silently bypassing
/// chroot/file confinement. (Regression guard: this must never be a CONTINUE
/// response.)
fn inject_failure_resp(id: u64) -> SeccompNotifResp {
    SeccompNotifResp {
        id,
        val: 0,
        error: -libc::EACCES,
        flags: 0,
    }
}

/// Inject a file descriptor into the child process using SECCOMP_ADDFD_FLAG_SEND.
///
/// Uses the SEND flag to atomically inject the fd and respond to the syscall.
/// The ioctl return value is the fd number assigned in the child process.
/// After this call, no additional SECCOMP_IOCTL_NOTIF_SEND is needed.
fn inject_fd_and_send(fd: RawFd, id: u64, srcfd: RawFd, newfd_flags: u32) -> io::Result<i32> {
    let addfd = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: srcfd as u32,
        newfd: 0,   // ignored when SECCOMP_ADDFD_FLAG_SETFD is not set
        newfd_flags,
    };
    let ret = unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong, &addfd as *const _)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as i32)
    }
}

/// Inject a file descriptor into the child process (without responding).
/// ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd)
fn inject_fd(fd: RawFd, id: u64, srcfd: RawFd, targetfd: i32) -> io::Result<()> {
    let addfd = SeccompNotifAddfd {
        id,
        flags: 0,
        srcfd: srcfd as u32,
        newfd: targetfd as u32,
        newfd_flags: 0,
    };
    let ret = unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong, &addfd as *const _)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Raw ioctl to send a notification response.
fn send_resp_raw(fd: RawFd, resp: &SeccompNotifResp) -> io::Result<()> {
    let ret = unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND as libc::c_ulong, resp as *const _)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Check whether a notification ID is still valid (TOCTOU guard).
/// ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id)
pub(crate) fn id_valid(fd: RawFd, id: u64) -> io::Result<()> {
    let ret = unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID as libc::c_ulong, &id as *const _)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Try to enable sync wakeup (Linux 6.7+). Ignores errors.
fn try_set_sync_wakeup(fd: RawFd) {
    let flags: u64 = SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP as u64;
    unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SET_FLAGS as libc::c_ulong, &flags as *const _);
    }
}

// ============================================================
// Child memory access helpers
// ============================================================

/// Read bytes from a child process via process_vm_readv (single syscall).
fn read_child_mem_vm(pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, NotifError> {
    let mut buf = vec![0u8; len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    let ret = unsafe {
        libc::process_vm_readv(pid as i32, &local_iov, 1, &remote_iov, 1, 0)
    };
    if ret < 0 {
        Err(NotifError::ChildMemoryRead(io::Error::last_os_error()))
    } else {
        buf.truncate(ret as usize);
        Ok(buf)
    }
}

/// Write bytes to a child process via process_vm_writev (single syscall).
fn write_child_mem_vm(pid: u32, addr: u64, data: &[u8]) -> Result<(), NotifError> {
    let local_iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: data.len(),
    };
    let ret = unsafe {
        libc::process_vm_writev(pid as i32, &local_iov, 1, &remote_iov, 1, 0)
    };
    if ret < 0 {
        Err(NotifError::ChildMemoryRead(io::Error::last_os_error()))
    } else if (ret as usize) < data.len() {
        Err(NotifError::ChildMemoryRead(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short write: {} of {} bytes", ret, data.len()),
        )))
    } else {
        Ok(())
    }
}

/// Read bytes from a child process via `process_vm_readv` with TOCTOU validation.
///
/// Calls `id_valid` before and after the read to ensure the notification is
/// still live (kernel did not abort or release the trapped syscall while the
/// supervisor was reading guest memory).
///
/// Public — used by downstream `Handler` implementations to read syscall
/// arguments that the kernel passes by pointer (paths in `openat`, buffers
/// in `write`/`writev`, etc.).
pub fn read_child_mem(
    notif_fd: RawFd,
    id: u64,
    pid: u32,
    addr: u64,
    len: usize,
) -> Result<Vec<u8>, NotifError> {
    id_valid(notif_fd, id).map_err(NotifError::Ioctl)?;
    let result = read_child_mem_vm(pid, addr, len)?;
    id_valid(notif_fd, id).map_err(NotifError::Ioctl)?;
    Ok(result)
}

/// Read a NUL-terminated string from child memory without crossing unmapped
/// page boundaries in a single `process_vm_readv` call.
///
/// TOCTOU-safe — internally calls [`read_child_mem`], inheriting the
/// `id_valid` checks bracketing each `process_vm_readv` call.
///
/// Page-aware: reads up to a page boundary at a time and stops at the
/// first NUL byte, never crossing into unmapped memory.  Returns
/// `None` for `addr == 0`, `max_len == 0`, a read failure, or a string
/// that exceeds `max_len` without a NUL.
///
/// Public — used by downstream `Handler` implementations that read
/// path arguments from notifications (`openat`, `unlinkat`, `statx`,
/// `newfstatat`, etc.).
pub fn read_child_cstr(
    notif_fd: RawFd,
    id: u64,
    pid: u32,
    addr: u64,
    max_len: usize,
) -> Option<String> {
    if addr == 0 || max_len == 0 {
        return None;
    }

    const PAGE_SIZE: u64 = 4096;
    let mut result = Vec::with_capacity(max_len.min(256));
    let mut cur = addr;
    while result.len() < max_len {
        let page_remaining = PAGE_SIZE - (cur % PAGE_SIZE);
        let remaining = max_len - result.len();
        let to_read = page_remaining.min(remaining as u64) as usize;
        let bytes = read_child_mem(notif_fd, id, pid, cur, to_read).ok()?;
        if let Some(nul) = bytes.iter().position(|&b| b == 0) {
            result.extend_from_slice(&bytes[..nul]);
            return String::from_utf8(result).ok();
        }
        result.extend_from_slice(&bytes);
        cur += to_read as u64;
    }

    String::from_utf8(result).ok()
}

/// Write bytes to a child process via `process_vm_writev` with TOCTOU validation.
///
/// Same TOCTOU contract as [`read_child_mem`].  Public for downstream
/// `Handler` implementations that synthesise syscall results into
/// guest memory (e.g. fake `getdents64` listings populated from a
/// virtual directory index, or synthesised `stat` buffers).
pub fn write_child_mem(
    notif_fd: RawFd,
    id: u64,
    pid: u32,
    addr: u64,
    data: &[u8],
) -> Result<(), NotifError> {
    id_valid(notif_fd, id).map_err(NotifError::Ioctl)?;
    write_child_mem_vm(pid, addr, data)?;
    id_valid(notif_fd, id).map_err(NotifError::Ioctl)?;
    Ok(())
}

// ============================================================
// Response dispatch
// ============================================================

/// Dispatch a `NotifAction` to the appropriate low-level response function.
fn send_response(fd: RawFd, id: u64, action: NotifAction) -> io::Result<()> {
    match action {
        NotifAction::Continue => respond_continue(fd, id),
        NotifAction::Errno(errno) => respond_errno(fd, id, errno),
        NotifAction::InjectFd { srcfd, targetfd } => {
            inject_fd(fd, id, srcfd, targetfd)?;
            respond_continue(fd, id)
        }
        NotifAction::InjectFdSend { srcfd, newfd_flags } => {
            // SECCOMP_ADDFD_FLAG_SEND atomically injects the fd and responds.
            // No separate NOTIF_SEND needed after this.
            // On failure, deny (fail closed) rather than letting the original
            // syscall continue unmediated against the host path.
            // srcfd (OwnedFd) is dropped at end of this arm, closing the fd.
            match inject_fd_and_send(fd, id, srcfd.as_raw_fd(), newfd_flags) {
                Ok(_new_fd) => Ok(()),
                Err(_) => send_resp_raw(fd, &inject_failure_resp(id)),
            }
        }
        NotifAction::InjectFdSendTracked { srcfd, newfd_flags, on_success } => {
            match inject_fd_and_send(fd, id, srcfd.as_raw_fd(), newfd_flags) {
                Ok(new_fd) => {
                    (on_success.0)(new_fd);
                    Ok(())
                }
                Err(_) => send_resp_raw(fd, &inject_failure_resp(id)),
            }
        }
        NotifAction::ReturnValue(val) => respond_value(fd, id, val),
        NotifAction::Hold => Ok(()), // Don't send a response.
        NotifAction::Defer(_) => {
            // Defer is intercepted in `handle_notification` and never reaches
            // here on the normal path. If it ever does, fail closed with EIO
            // rather than dropping the future and wedging the child.
            debug_assert!(false, "Defer reached send_response; should be intercepted earlier");
            respond_errno(fd, id, libc::EIO)
        }
        NotifAction::Kill { sig, pgid } => {
            // Kill the entire process group, then return ENOMEM so the
            // seccomp notification is resolved (avoids a kernel warning).
            unsafe { libc::killpg(pgid, sig) };
            respond_errno(fd, id, ENOMEM)
        }
    }
}

// ============================================================
// vDSO re-patching after exec
// ============================================================

/// Re-patch the vDSO if the base address changed (e.g. after exec replaces it).
fn maybe_patch_vdso(pid: i32, procfs: &mut super::state::ProcfsState, policy: &NotifPolicy) {
    let base = match crate::vdso::find_vdso_base(pid) {
        Ok(addr) => addr,
        Err(_) => return,
    };
    if base == procfs.vdso_patched_addr {
        return; // already patched this vDSO
    }
    let time_offset = if policy.has_time_start { Some(policy.time_offset) } else { None };
    if crate::vdso::patch(pid, time_offset, policy.has_random_seed).is_ok() {
        procfs.vdso_patched_addr = base;
    }
}

// ============================================================
// Policy event emission
// ============================================================

/// Map a syscall number to a human-readable name for the policy callback.
fn syscall_name(nr: i64) -> &'static str {
    match nr {
        n if n == libc::SYS_openat => "openat",
        n if n == libc::SYS_connect => "connect",
        n if n == libc::SYS_sendto => "sendto",
        n if n == libc::SYS_sendmsg => "sendmsg",
        n if n == libc::SYS_sendmmsg => "sendmmsg",
        n if n == libc::SYS_bind => "bind",
        n if n == libc::SYS_clone => "clone",
        n if n == libc::SYS_clone3 => "clone3",
        n if Some(n) == arch::sys_vfork() => "vfork",
        n if Some(n) == arch::sys_fork() => "fork",
        n if n == libc::SYS_execve => "execve",
        n if n == libc::SYS_execveat => "execveat",
        n if n == libc::SYS_mmap => "mmap",
        n if n == libc::SYS_munmap => "munmap",
        n if n == libc::SYS_brk => "brk",
        n if n == libc::SYS_getrandom => "getrandom",
        n if n == libc::SYS_unlinkat => "unlinkat",
        n if n == libc::SYS_mkdirat => "mkdirat",
        _ => "unknown",
    }
}

/// Map a syscall number to a high-level category.
fn syscall_category(nr: i64) -> crate::policy_fn::SyscallCategory {
    use crate::policy_fn::SyscallCategory;
    match nr {
        n if n == libc::SYS_openat || n == libc::SYS_unlinkat
            || n == libc::SYS_mkdirat || n == libc::SYS_renameat2
            || n == libc::SYS_symlinkat || n == libc::SYS_linkat
            || n == libc::SYS_fchmodat || n == libc::SYS_fchownat
            || n == libc::SYS_truncate || n == libc::SYS_readlinkat
            || n == libc::SYS_newfstatat || n == libc::SYS_statx
            || n == libc::SYS_faccessat || n == libc::SYS_getdents64
            || Some(n) == arch::sys_getdents() => SyscallCategory::File,
        n if n == libc::SYS_connect || n == libc::SYS_sendto
            || n == libc::SYS_sendmsg || n == libc::SYS_sendmmsg
            || n == libc::SYS_bind
            || n == libc::SYS_getsockname => SyscallCategory::Network,
        n if n == libc::SYS_clone || n == libc::SYS_clone3
            || Some(n) == arch::sys_vfork() || Some(n) == arch::sys_fork()
            || n == libc::SYS_execve || n == libc::SYS_execveat => SyscallCategory::Process,
        n if n == libc::SYS_mmap || n == libc::SYS_munmap
            || n == libc::SYS_brk || n == libc::SYS_mremap
            => SyscallCategory::Memory,
        _ => SyscallCategory::File, // default
    }
}

/// Read the parent PID from /proc/{pid}/stat.
fn read_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Format: "pid (comm) state ppid ..."
    // Find the closing ')' then split the rest
    let close_paren = stat.rfind(')')?;
    let rest = &stat[close_paren + 2..]; // skip ") "
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] = state, fields[1] = ppid
    fields.get(1)?.parse().ok()
}

/// Read a NUL-terminated path from child memory (up to 256 bytes).
fn read_path_for_event(notif: &SeccompNotif, addr: u64, notif_fd: RawFd) -> Option<String> {
    if addr == 0 { return None; }
    let bytes = read_child_mem(notif_fd, notif.id, notif.pid, addr, 256).ok()?;
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..nul].to_vec()).ok()
}

fn normalize_path(path: &std::path::Path) -> String {
    use std::path::{Component, PathBuf};

    let mut normalized = PathBuf::new();
    let absolute = path.is_absolute();
    if absolute {
        normalized.push("/");
    }

    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(_) => {}
        }
    }

    if normalized.as_os_str().is_empty() {
        if absolute { "/".into() } else { ".".into() }
    } else {
        normalized.to_string_lossy().into_owned()
    }
}

fn resolve_at_path_for_event(notif: &SeccompNotif, dirfd: i64, path: &str) -> Option<String> {
    use std::path::Path;

    if Path::new(path).is_absolute() {
        return Some(normalize_path(Path::new(path)));
    }

    let dirfd32 = dirfd as i32;
    let base = if dirfd32 == libc::AT_FDCWD {
        std::fs::read_link(format!("/proc/{}/cwd", notif.pid)).ok()?
    } else {
        std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd32)).ok()?
    };

    Some(normalize_path(&base.join(path)))
}

fn resolve_path_for_notif(notif: &SeccompNotif, notif_fd: RawFd) -> Option<String> {
    let nr = notif.data.nr as i64;
    match nr {
        n if n == libc::SYS_openat => {
            // openat(dirfd, pathname, flags, mode)
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[0] as i64, &path)
        }
        n if Some(n) == arch::sys_open() || n == libc::SYS_execve => {
            let path = read_path_for_event(notif, notif.data.args[0], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &path)
        }
        n if n == libc::SYS_execveat => {
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[0] as i64, &path)
        }
        // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        // Check the source (old) path — deny if it's a denied file being linked away.
        n if n == libc::SYS_linkat => {
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[0] as i64, &path)
        }
        // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        // Check the source (old) path — deny if a denied file is being renamed away.
        n if n == libc::SYS_renameat2 => {
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[0] as i64, &path)
        }
        // symlinkat(target, newdirfd, linkpath)
        // The target string is what the symlink points to; deny if it names a denied path.
        n if n == libc::SYS_symlinkat => {
            let target = read_path_for_event(notif, notif.data.args[0], notif_fd)?;
            // target may be absolute or relative to the process cwd
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &target)
        }
        // link(oldpath, newpath) — legacy, AT_FDCWD implied for both
        n if Some(n) == arch::sys_link() => {
            let path = read_path_for_event(notif, notif.data.args[0], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &path)
        }
        // rename(oldpath, newpath) — legacy, AT_FDCWD implied for both
        n if Some(n) == arch::sys_rename() => {
            let path = read_path_for_event(notif, notif.data.args[0], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &path)
        }
        // symlink(target, linkpath) — legacy
        n if Some(n) == arch::sys_symlink() => {
            let target = read_path_for_event(notif, notif.data.args[0], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &target)
        }
        _ => None,
    }
}

/// Resolve the second (destination) path for two-path syscalls.
///
/// Returns `None` for syscalls that only have a single path argument.
fn resolve_second_path_for_notif(notif: &SeccompNotif, notif_fd: RawFd) -> Option<String> {
    let nr = notif.data.nr as i64;
    match nr {
        // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        n if n == libc::SYS_renameat2 => {
            let path = read_path_for_event(notif, notif.data.args[3], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[2] as i64, &path)
        }
        // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        // Destination of a hardlink to a denied file should also be denied
        // (prevents overwriting a denied file via linkat).
        n if n == libc::SYS_linkat => {
            let path = read_path_for_event(notif, notif.data.args[3], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[2] as i64, &path)
        }
        // rename(oldpath, newpath) — legacy
        n if Some(n) == arch::sys_rename() => {
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &path)
        }
        // link(oldpath, newpath) — legacy
        n if Some(n) == arch::sys_link() => {
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &path)
        }
        _ => None,
    }
}

/// Extract IP and port from a sockaddr in child memory.
fn read_sockaddr_for_event(notif: &SeccompNotif, addr: u64, len: usize, notif_fd: RawFd)
    -> (Option<std::net::IpAddr>, Option<u16>)
{
    if addr == 0 || len < 4 { return (None, None); }
    let bytes = match read_child_mem(notif_fd, notif.id, notif.pid, addr, len.min(128)) {
        Ok(b) => b,
        Err(_) => return (None, None),
    };
    if bytes.len() < 4 { return (None, None); }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let ip = match family as u32 {
        f if f == crate::sys::structs::AF_INET && bytes.len() >= 8 => {
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[4], bytes[5], bytes[6], bytes[7],
            )))
        }
        f if f == crate::sys::structs::AF_INET6 && bytes.len() >= 24 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[8..24]);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)))
        }
        _ => None,
    };
    (ip, if port > 0 { Some(port) } else { None })
}

/// Read argv (NULL-terminated array of char* in child memory) for execve.
/// Capped at 64 entries × 256 bytes/entry as a safety bound.
fn read_argv_for_event(notif: &SeccompNotif, argv_ptr: u64, notif_fd: RawFd) -> Option<Vec<String>> {
    if argv_ptr == 0 { return None; }
    let mut args = Vec::new();
    let ptr_size = std::mem::size_of::<u64>();

    for i in 0..64u64 {
        let ptr_addr = argv_ptr + i * ptr_size as u64;
        let ptr_bytes = read_child_mem(notif_fd, notif.id, notif.pid, ptr_addr, ptr_size).ok()?;
        let str_ptr = u64::from_ne_bytes(ptr_bytes[..8].try_into().ok()?);
        if str_ptr == 0 { break; } // NULL terminator

        if let Some(s) = read_path_for_event(notif, str_ptr, notif_fd) {
            args.push(s);
        } else {
            break;
        }
    }

    if args.is_empty() { None } else { Some(args) }
}

/// Resolve a held syscall's policy_fn gate outcome into a verdict.
///
/// `received` is the verdict the callback sent, or `None` if the gate timed
/// out or its channel closed before a decision arrived. A held syscall is one
/// whose verdict matters (execve, connect, openat, ...); when no decision
/// arrives we fail closed and deny rather than letting the syscall proceed.
fn resolve_held_gate(
    received: Option<crate::policy_fn::Verdict>,
) -> Option<crate::policy_fn::Verdict> {
    match received {
        Some(v) => Some(v),
        None => Some(crate::policy_fn::Verdict::Deny),
    }
}

/// Emit a syscall event to the policy_fn callback thread (if active).
/// Returns the callback's verdict for held syscalls.
async fn emit_policy_event(
    notif: &SeccompNotif,
    action: &NotifAction,
    policy_fn_state: &Arc<tokio::sync::Mutex<super::state::PolicyFnState>>,
    notif_fd: RawFd,
) -> Option<crate::policy_fn::Verdict> {
    let pfs = policy_fn_state.lock().await;
    let tx = match pfs.event_tx.as_ref() {
        Some(tx) => tx.clone(),
        None => return None,
    };
    drop(pfs);

    let nr = notif.data.nr as i64;
    let denied = matches!(action, NotifAction::Errno(_));
    let name = syscall_name(nr);
    let category = syscall_category(nr);
    let parent_pid = read_ppid(notif.pid);

    // Extract metadata based on syscall type.
    //
    // Path strings are deliberately NOT extracted: the kernel re-reads
    // user-memory pointers after Continue, so any path-string-based
    // decision is racy (issue #27). Path-based access control belongs
    // in static Landlock rules.
    //
    // argv IS extracted for allowed execve/execveat notifications:
    // the supervisor freezes every task in the sandbox (siblings +
    // peers) before this callback reads argv and keeps that freeze
    // through Continue, so the post-Continue re-read sees the same
    // memory we read here.
    //
    // Network fields are TOCTOU-safe because connect/sendto/bind are
    // performed on-behalf via pidfd_getfd; the kernel never re-reads
    // child memory for those syscalls.
    let mut host = None;
    let mut port = None;
    let mut size = None;
    let mut argv = None;

    if !denied && (nr == libc::SYS_execve || nr == libc::SYS_execveat) {
        // execve(pathname, argv, envp):       args[1] = argv ptr
        // execveat(dirfd, pathname, argv, ..): args[2] = argv ptr
        let argv_ptr = if nr == libc::SYS_execveat {
            notif.data.args[2]
        } else {
            notif.data.args[1]
        };
        argv = read_argv_for_event(notif, argv_ptr, notif_fd);
    }

    if nr == libc::SYS_connect || nr == libc::SYS_sendto || nr == libc::SYS_bind {
        // connect(fd, addr, addrlen): args[1]=addr, args[2]=len
        let addr_ptr = notif.data.args[1];
        let addr_len = notif.data.args[2] as usize;
        let (h, p) = read_sockaddr_for_event(notif, addr_ptr, addr_len, notif_fd);
        host = h;
        port = p;
    }

    if nr == libc::SYS_mmap {
        // mmap(addr, length, ...): args[1] = length
        size = Some(notif.data.args[1]);
    }

    let event = crate::policy_fn::SyscallEvent {
        syscall: name.to_string(),
        category,
        pid: notif.pid,
        parent_pid,
        host,
        port,
        size,
        argv,
        denied,
    };

    // Hold syscalls where the callback's verdict matters.
    // The child is blocked until the callback returns.
    let is_held = nr == libc::SYS_execve || nr == libc::SYS_execveat
        || nr == libc::SYS_connect || nr == libc::SYS_sendto
        || nr == libc::SYS_bind || nr == libc::SYS_openat;

    if is_held {
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel();
        let _ = tx.send(crate::policy_fn::PolicyEvent {
            event,
            gate: Some(gate_tx),
        });
        let received = match tokio::time::timeout(std::time::Duration::from_secs(5), gate_rx).await {
            Ok(Ok(verdict)) => Some(verdict),
            _ => None, // timeout or channel closed
        };
        resolve_held_gate(received)
    } else {
        let _ = tx.send(crate::policy_fn::PolicyEvent {
            event,
            gate: None,
        });
        None
    }
}

// ============================================================
// Per-notification handler (runs in a spawned task)
// ============================================================

/// Process a single seccomp notification: vDSO re-patch, path denial check,
/// dispatch, policy event emission, and response.
/// Maximum number of deferred handler futures running concurrently. Caps
/// the worker fan-out (and any resources those workers hold, e.g. memfds or
/// sockets) so a burst of deferrals cannot exhaust the supervisor process.
const DEFER_MAX_INFLIGHT: usize = 64;

/// Maximum time a deferred handler future may run before the supervisor gives
/// up and fails the trapped syscall closed. Bounds the worst case so a hung
/// future (e.g. a stalled network fetch in a token-injection handler) cannot
/// park the child forever or permanently leak its `DEFER_MAX_INFLIGHT` slot.
const DEFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Drive a deferred future to its terminal action, bounded by `limit`.
///
/// On timeout, fail closed with `EIO` so the trapped child gets a definite
/// response instead of parking forever; `finalize_deferred` still guards a
/// future that resolves to a nested `Defer`.
async fn run_deferred_within(deferred: Deferred, limit: std::time::Duration) -> NotifAction {
    match tokio::time::timeout(limit, deferred.run()).await {
        Ok(action) => finalize_deferred(action),
        Err(_) => {
            eprintln!(
                "sandlock: deferred handler exceeded {:?}; failing syscall with EIO",
                limit
            );
            NotifAction::Errno(libc::EIO)
        }
    }
}

/// Spawn a worker task that drives a deferred handler future to its terminal
/// action and sends the seccomp response, keyed by `id`. The `permit` is
/// held for the worker's lifetime, releasing its `DEFER_MAX_INFLIGHT` slot on
/// completion. A stale `id` (child exited mid-defer) makes `send_response`
/// a no-op, matching the inline path's "child may have exited" tolerance.
fn spawn_deferred(
    fd: RawFd,
    id: u64,
    deferred: Deferred,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    tokio::spawn(async move {
        let _permit = permit; // released when the worker finishes
        let action = run_deferred_within(deferred, DEFER_TIMEOUT).await;
        let _ = send_response(fd, id, action);
    });
}

async fn handle_notification(
    notif: SeccompNotif,
    ctx: &Arc<super::ctx::SupervisorCtx>,
    dispatch_table: &super::dispatch::DispatchTable,
    fd: RawFd,
    defer_sem: &Arc<tokio::sync::Semaphore>,
) {
    let policy = &ctx.policy;

    // Ensure every pid that produces a notification has per-process
    // supervisor state and an exit watcher. The fork handler runs on
    // the *parent* pid (the child doesn't exist yet at clone-time), so
    // the child gets registered the first time it issues a notified
    // syscall.
    crate::resource::register_child_if_new(ctx, notif.pid as i32).await;

    // Re-patch vDSO if needed (exec replaces it with a fresh copy).
    if policy.has_time_start || policy.has_random_seed {
        let mut pfs = ctx.procfs.lock().await;
        maybe_patch_vdso(notif.pid as i32, &mut pfs, policy);
    }

    // Check dynamic path denials before dispatch
    let mut action = {
        let nr = notif.data.nr as i64;
        let mut path_check_nrs = vec![
            libc::SYS_openat, libc::SYS_execve, libc::SYS_execveat,
            libc::SYS_linkat, libc::SYS_renameat2, libc::SYS_symlinkat,
        ];
        path_check_nrs.extend([
            arch::sys_open(), arch::sys_link(), arch::sys_rename(), arch::sys_symlink(),
        ].into_iter().flatten());
        let should_precheck_denied = policy.chroot_root.is_none()
            && path_check_nrs.contains(&nr);
        if should_precheck_denied {
            let pfs = ctx.policy_fn.lock().await;
            if is_path_denied_for_notif(&pfs, &notif, fd) {
                NotifAction::Errno(libc::EACCES)
            } else {
                drop(pfs);
                dispatch_table.dispatch(notif, fd).await
            }
        } else {
            dispatch_table.dispatch(notif, fd).await
        }
    };

    let nr = notif.data.nr as i64;
    let fork_counted = matches!(action, NotifAction::Continue)
        && crate::resource::fork_counted_on_continue(&notif, fd);

    // TOCTOU-close for execve (issue #27): freeze every sandbox task
    // that could mutate argv before policy_fn reads argv and before the
    // kernel re-reads it after Continue. This covers two writer classes:
    //   1. Sibling threads of the calling tid (same TGID, share mm).
    //   2. Peer processes in other TGIDs that alias argv pages via
    //      MAP_SHARED mappings or share mm via clone(CLONE_VM).
    //
    // The freeze enumerates ProcessIndex. With policy_fn active, that
    // index is complete: fork-like syscalls are traced at creation time
    // below, before new children can run user code.
    //
    // Strict on failure: if we cannot establish the freeze, we cannot
    // safely expose argv or allow execve, so we deny with EPERM.
    let mut exec_freeze = None;
    if matches!(action, NotifAction::Continue)
        && policy.argv_safety_required
        && crate::freeze::requires_freeze_on_continue(nr)
    {
        match crate::freeze::freeze_sandbox_for_execve(
            &ctx.processes,
            notif.pid as i32,
        ) {
            Ok(outcome) => {
                exec_freeze = Some(outcome);
            }
            Err(e) => {
                eprintln!(
                    "sandlock: argv-safety freeze failed for pid {}: {} \
                     — denying execve to preserve TOCTOU invariant",
                    notif.pid, e
                );
                action = NotifAction::Errno(libc::EPERM);
            }
        }
    }

    // Emit event to policy_fn callback if active. For execve, argv is
    // only populated after `exec_freeze` has stopped every possible
    // writer, and those tasks stay stopped until after NOTIF_SEND.
    if let Some(verdict) = emit_policy_event(&notif, &action, &ctx.policy_fn, fd).await {
        use crate::policy_fn::Verdict;
        match verdict {
            Verdict::Deny => { action = NotifAction::Errno(libc::EPERM); }
            Verdict::DenyWith(errno) => { action = NotifAction::Errno(errno); }
            Verdict::Audit => { /* allow, but could log here */ }
            Verdict::Allow => {}
        }
    }

    if fork_counted && !matches!(action, NotifAction::Continue) {
        crate::resource::rollback_fork_count(&ctx.resource).await;
    }

    // With policy_fn active, fork-like syscalls are traced for exactly
    // one ptrace event so ProcessIndex becomes complete before the new
    // child can run user code. That closes the race where a peer
    // process could exist without ever having produced a notification.
    let mut creation_trace = None;
    if matches!(action, NotifAction::Continue)
        && crate::resource::requires_process_creation_tracking(&notif, fd, policy)
    {
        match crate::resource::prepare_process_creation_tracking(ctx, notif.pid as i32).await {
            Ok(trace) => {
                creation_trace = Some(trace);
            }
            Err(e) => {
                eprintln!(
                    "sandlock: process-creation tracking failed for pid {}: {} \
                     — denying fork-like syscall to preserve argv TOCTOU invariant",
                    notif.pid, e
                );
                if fork_counted {
                    crate::resource::rollback_fork_count(&ctx.resource).await;
                }
                action = NotifAction::Errno(libc::EPERM);
            }
        }
    }

    // Deferred response: run the handler's future on a worker task so the
    // single supervisor loop is not blocked waiting for slow work (a network
    // round-trip, a blocking syscall). The trapped child stays parked in the
    // syscall; the worker sends the real response later, keyed by notif.id.
    //
    // Deferral is refused on syscalls whose Continue path requires the
    // execve argv-safety freeze or fork creation-tracking: sending the
    // response off-loop would skip that TOCTOU-closing work. (When `action`
    // is Defer it is not Continue, so `exec_freeze`/`creation_trace` above
    // are already None — there is nothing to unwind here.)
    if let NotifAction::Defer(deferred) = action {
        if crate::freeze::requires_freeze_on_continue(nr)
            || crate::resource::requires_process_creation_tracking(&notif, fd, policy)
        {
            let _ = send_response(fd, notif.id, NotifAction::Errno(libc::EPERM));
            return;
        }
        match Arc::clone(defer_sem).try_acquire_owned() {
            Ok(permit) => spawn_deferred(fd, notif.id, deferred, permit),
            // Too many deferrals in flight: fail fast with EAGAIN rather than
            // blocking the loop or letting unbounded workers accrete.
            Err(_) => {
                let _ = send_response(fd, notif.id, NotifAction::Errno(libc::EAGAIN));
            }
        }
        return;
    }

    // Ignore error — child may have exited between recv and response.
    let exec_continued = exec_freeze.is_some() && matches!(action, NotifAction::Continue);
    let send_result = send_response(fd, notif.id, action);

    if let Some(trace) = creation_trace {
        if send_result.is_ok() {
            match crate::resource::finish_process_creation_tracking(trace).await {
                Ok(true) => {}
                Ok(false) => {
                    crate::resource::rollback_fork_count(&ctx.resource).await;
                }
                Err(e) => {
                    crate::resource::rollback_fork_count(&ctx.resource).await;
                    eprintln!(
                        "sandlock: process-creation tracking completion failed for pid {}: {}",
                        notif.pid, e
                    );
                }
            }
        } else {
            crate::resource::rollback_fork_count(&ctx.resource).await;
            crate::resource::abort_process_creation_tracking(trace).await;
        }
    }

    if let Some(freeze) = exec_freeze {
        if exec_continued && send_result.is_ok() {
            crate::freeze::detach_peers(&freeze.peer_tids);
        } else {
            crate::freeze::detach_all(&freeze);
        }
    }
}

// ============================================================
// Main supervisor loop
// ============================================================

/// Async event loop that processes seccomp notifications.
///
/// Runs until the notification fd is closed (child exits or filter is removed).
///
/// `pending_handlers` are user-supplied syscall handlers registered after all
/// builtin handlers.  For the default behaviour without any custom handlers
/// pass an empty `Vec`.
pub async fn supervisor(
    notif_fd: OwnedFd,
    ctx: Arc<super::ctx::SupervisorCtx>,
    pending_handlers: Vec<(i64, std::sync::Arc<dyn super::dispatch::Handler>)>,
    startup: tokio::sync::oneshot::Sender<io::Result<()>>,
) {
    // Register the notif fd with the Tokio IO driver so we can wait for
    // readiness via epoll instead of a dedicated blocking thread.
    let async_fd = match tokio::io::unix::AsyncFd::with_interest(
        notif_fd,
        tokio::io::Interest::READABLE,
    ) {
        Ok(fd) => fd,
        Err(err) => {
            let _ = startup.send(Err(err));
            return;
        }
    };
    let fd = async_fd.get_ref().as_raw_fd();

    // Build the dispatch table once at startup.
    let dispatch_table = Arc::new(super::dispatch::build_dispatch_table(
        &ctx.policy,
        &ctx.resource,
        &ctx,
        pending_handlers,
    ));

    // Try to enable sync wakeup (Linux 6.7+, ignore error on older kernels).
    try_set_sync_wakeup(fd);

    // The IO driver has the fd registered; subsequent block_on cycles
    // can resume this task and pick up readiness events. Tell the
    // caller it is safe to release the child.
    let _ = startup.send(Ok(()));

    // Periodic sweep as a defensive backstop in case pidfd-based
    // lifecycle cleanup misses an entry (e.g. pidfd_open failed for a
    // child on an old kernel, or its watcher panicked). At 5 minutes
    // this is cheap enough to leave on; the primary cleanup path is
    // still per-child pidfd readiness in `spawn_pid_watcher`.
    let gc = tokio::spawn(process_index_gc(Arc::clone(&ctx.processes)));

    // Bounds the number of in-flight deferred handler futures (see
    // `DEFER_MAX_INFLIGHT`). Shared across all notifications this supervisor
    // processes.
    let defer_sem = Arc::new(tokio::sync::Semaphore::new(DEFER_MAX_INFLIGHT));

    // Edge-triggered drain: each `readable().await` returns once per
    // epoll edge, then we drain the kernel queue via `probe_notif_fd`
    // until empty. The drain is necessary because tokio's AsyncFd is
    // edge-triggered and `recv_notif` does not signal "would block",
    // so a burst of arrivals between two `readable().await` calls
    // would coalesce into a single wake event.
    //
    // Notifications are processed sequentially (not spawned) to avoid
    // mutex contention between concurrent handlers.
    'outer: loop {
        let mut ready = match async_fd.readable().await {
            Ok(r) => r,
            Err(_) => break 'outer,
        };
        ready.clear_ready();
        drop(ready);

        loop {
            match probe_notif_fd(fd) {
                NotifFdState::Pending => {
                    let notif = match recv_notif(fd) {
                        Ok(n) => n,
                        Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                        Err(_) => break 'outer,
                    };
                    handle_notification(notif, &ctx, &dispatch_table, fd, &defer_sem).await;
                }
                NotifFdState::Empty => break,
                NotifFdState::Terminal => break 'outer,
            }
        }
    }

    gc.abort();
}

/// Periodic sweep that drops `ProcessIndex` entries for exited PIDs.
/// Per-process state hangs off these entries via `Arc`, so dropping
/// them releases everything in one step.
async fn process_index_gc(processes: Arc<super::state::ProcessIndex>) {
    let interval = std::time::Duration::from_secs(300);
    loop {
        tokio::time::sleep(interval).await;
        if processes.len() == 0 {
            continue;
        }
        processes.prune_dead();
    }
}

/// Spawn a per-child task that awaits the pidfd becoming readable
/// (process exit) and then runs unified cleanup across every
/// per-process supervisor map.
///
/// The watcher *owns* the pidfd via `AsyncFd<OwnedFd>` — the kernel
/// fd stays alive for as long as tokio's IO driver has it registered,
/// and is closed exactly once when the watcher task ends. This avoids
/// a TOCTOU where dropping the fd from a separate map could let a
/// recycled fd be deregistered from epoll.
pub(crate) fn spawn_pid_watcher(
    ctx: Arc<super::ctx::SupervisorCtx>,
    key: super::state::PidKey,
    pidfd: std::os::unix::io::OwnedFd,
) {
    tokio::spawn(async move {
        let async_fd = match tokio::io::unix::AsyncFd::with_interest(
            pidfd,
            tokio::io::Interest::READABLE,
        ) {
            Ok(f) => f,
            Err(_) => {
                // AsyncFd registration failed (extremely unusual);
                // fall back to immediate cleanup so we don't leak the
                // index entry. The OwnedFd we passed in is consumed
                // by `with_interest`'s Err return and will close on
                // drop here.
                cleanup_pid(&ctx, key).await;
                return;
            }
        };
        // pidfd becomes readable when the process exits; we don't
        // read any data, so `readable()` is just an await point.
        let _ = async_fd.readable().await;
        cleanup_pid(&ctx, key).await;
        // async_fd drops here, closing the pidfd.
    });
}

/// Drop the supervisor's per-process state for `key`. With every
/// per-process map living inside `PerProcessState` (owned by
/// `ProcessIndex`), this is a single unregister — the entry's `Arc`
/// drops here, and remaining clones held by in-flight handlers will
/// drop with their tasks, freeing `PerProcessState` automatically.
pub(crate) async fn cleanup_pid(ctx: &super::ctx::SupervisorCtx, key: super::state::PidKey) {
    ctx.processes.unregister(key);
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::FromRawFd;

    fn gettid() -> u32 {
        (unsafe { libc::syscall(libc::SYS_gettid) }) as u32
    }

    #[test]
    fn inject_failure_response_denies_not_continues() {
        // When fd injection fails, the supervisor must fail closed: deny the
        // syscall instead of letting it continue unmediated against the host
        // path (which would silently bypass chroot/file confinement).
        let resp = inject_failure_resp(123);
        assert_eq!(resp.id, 123);
        assert_eq!(
            resp.flags & SECCOMP_USER_NOTIF_FLAG_CONTINUE,
            0,
            "fd-injection failure must not respond with CONTINUE"
        );
        assert_ne!(resp.error, 0, "fd-injection failure must be a denial");
        assert_eq!(resp.error, -libc::EACCES);
    }

    #[test]
    fn held_gate_no_decision_denies() {
        use crate::policy_fn::Verdict;
        // A held syscall whose policy_fn gate times out or whose channel closes
        // (received == None) must fail closed: deny, not allow the syscall.
        assert!(matches!(resolve_held_gate(None), Some(Verdict::Deny)));
    }

    #[test]
    fn held_gate_passes_through_callback_verdict() {
        use crate::policy_fn::Verdict;
        // A real verdict from the callback is forwarded unchanged.
        assert!(matches!(
            resolve_held_gate(Some(Verdict::Allow)),
            Some(Verdict::Allow)
        ));
        assert!(matches!(
            resolve_held_gate(Some(Verdict::Deny)),
            Some(Verdict::Deny)
        ));
        assert!(matches!(
            resolve_held_gate(Some(Verdict::DenyWith(13))),
            Some(Verdict::DenyWith(13))
        ));
    }

    #[test]
    fn tgid_of_main_thread_is_own_pid() {
        // The main thread's tid equals the process pid, and its Tgid is the pid.
        assert_eq!(tgid_of(gettid()), Some(std::process::id()));
    }

    #[test]
    fn tgid_of_worker_thread_resolves_to_process() {
        // A non-leader thread's Tgid is the process pid, not its own tid.
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            tid_tx.send(gettid()).unwrap();
            done_rx.recv().ok(); // stay alive until the test has read /proc
        });
        let worker_tid = tid_rx.recv().unwrap();
        let pid = std::process::id();
        assert_ne!(worker_tid, pid, "worker tid must differ from pid");
        assert_eq!(tgid_of(worker_tid), Some(pid));
        done_tx.send(()).ok();
        h.join().unwrap();
    }

    #[test]
    fn dup_fd_from_pid_handles_worker_thread_fd() {
        use std::os::unix::io::AsRawFd;
        // Open an fd in a non-leader worker thread, then duplicate it by that
        // thread's tid. Exercises the tid->process pidfd resolution end to end
        // (PIDFD_THREAD on >=6.9, the /proc Tgid fallback on older kernels).
        let (info_tx, info_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            let f = std::fs::File::open("/dev/null").unwrap();
            info_tx.send((gettid(), f.as_raw_fd())).unwrap();
            done_rx.recv().ok();
            drop(f);
        });
        let (worker_tid, fd) = info_rx.recv().unwrap();
        let dup = dup_fd_from_pid(worker_tid, fd);
        done_tx.send(()).ok();
        h.join().unwrap();
        assert!(dup.is_ok(), "dup_fd_from_pid for a worker-thread fd failed: {:?}", dup.err());
    }

    #[test]
    fn read_child_cstr_returns_none_for_null_addr_or_zero_max_len() {
        // Smoke: addr == 0 short-circuits without touching the child.
        assert!(read_child_cstr(-1, 0, 0, 0, 4096).is_none());
        // max_len == 0 also short-circuits.
        assert!(read_child_cstr(-1, 0, 0, 0xdeadbeef, 0).is_none());
    }

    #[test]
    fn test_notif_action_debug() {
        // Ensure all variants implement Debug.
        let _ = format!("{:?}", NotifAction::Continue);
        let _ = format!("{:?}", NotifAction::Errno(1));
        let _ = format!("{:?}", NotifAction::InjectFd { srcfd: 3, targetfd: 4 });
        // Use a real fd (dup'd from stderr) so OwnedFd can safely close it.
        let test_fd = unsafe { OwnedFd::from_raw_fd(libc::dup(2)) };
        let _ = format!("{:?}", NotifAction::InjectFdSend { srcfd: test_fd, newfd_flags: 0 });
        let _ = format!("{:?}", NotifAction::ReturnValue(42));
        let _ = format!("{:?}", NotifAction::Hold);
        let _ = format!("{:?}", NotifAction::Kill { sig: 9, pgid: 1 });
        let _ = format!("{:?}", NotifAction::defer(async { NotifAction::Continue }));
    }

    #[tokio::test]
    async fn deferred_future_need_not_be_sync() {
        // A deferred future may capture Send-but-not-Sync state across an
        // await. `Cell` is Send but never Sync; holding it across `.await`
        // makes the future !Sync. Only `Send` is required (the supervisor
        // moves the future to a worker, never shares it by reference).
        use std::cell::Cell;
        let action = NotifAction::defer(async move {
            let counter = Cell::new(0);
            counter.set(counter.get() + 41);
            tokio::task::yield_now().await; // hold the !Sync Cell across await
            NotifAction::ReturnValue(counter.get() + 1)
        });
        let NotifAction::Defer(d) = action else { panic!("expected Defer") };
        assert!(matches!(d.run().await, NotifAction::ReturnValue(42)));
    }

    #[tokio::test]
    async fn deferred_runs_to_its_terminal_action() {
        // A Defer carries a future; running it yields the deferred decision.
        let action = NotifAction::defer(async { NotifAction::ReturnValue(7) });
        let NotifAction::Defer(deferred) = action else {
            panic!("defer() must construct a NotifAction::Defer");
        };
        assert!(matches!(deferred.run().await, NotifAction::ReturnValue(7)));
    }

    #[tokio::test(start_paused = true)]
    async fn deferred_times_out_to_eio() {
        // A deferred future that exceeds its limit must fail closed (EIO) so
        // the trapped child gets a definite response instead of parking
        // forever (and leaking its DEFER_MAX_INFLIGHT slot).
        let slow = Deferred::new(async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            NotifAction::ReturnValue(7)
        });
        let action = run_deferred_within(slow, std::time::Duration::from_secs(1)).await;
        assert!(matches!(action, NotifAction::Errno(e) if e == libc::EIO));
    }

    #[tokio::test(start_paused = true)]
    async fn deferred_within_limit_passes_through() {
        // A future that resolves within the limit returns its terminal action.
        let fast = Deferred::new(async { NotifAction::ReturnValue(7) });
        let action = run_deferred_within(fast, std::time::Duration::from_secs(1)).await;
        assert!(matches!(action, NotifAction::ReturnValue(7)));
    }

    #[test]
    fn finalize_deferred_collapses_nested_defer_to_eio() {
        // A deferred future that itself resolves to Defer is a bug: collapse
        // to EIO so the trapped child is never wedged waiting for a response.
        let nested = NotifAction::defer(async { NotifAction::Continue });
        assert!(matches!(finalize_deferred(nested), NotifAction::Errno(e) if e == libc::EIO));
        // Non-nested terminal actions pass through unchanged.
        assert!(matches!(finalize_deferred(NotifAction::Continue), NotifAction::Continue));
        assert!(matches!(
            finalize_deferred(NotifAction::ReturnValue(3)),
            NotifAction::ReturnValue(3)
        ));
    }

    #[test]
    fn content_memfd_roundtrips_content() {
        use std::io::Read;
        let fd = content_memfd(b"hello world", true).expect("content_memfd");
        // The fd is rewound to offset 0, so a plain read returns the content.
        let mut f = std::fs::File::from(fd);
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello world");
    }

    #[test]
    fn content_memfd_sealed_applies_write_seal() {
        let fd = content_memfd(b"data", true).expect("content_memfd");
        let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
        assert!(seals >= 0, "F_GET_SEALS failed");
        assert!(
            seals & libc::F_SEAL_WRITE != 0,
            "expected F_SEAL_WRITE on a sealed memfd, got {seals:#x}"
        );
    }

    #[test]
    fn content_memfd_unsealed_has_no_write_seal() {
        let fd = content_memfd(b"data", false).expect("content_memfd");
        let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
        assert!(seals >= 0, "F_GET_SEALS failed");
        assert_eq!(
            seals & libc::F_SEAL_WRITE,
            0,
            "unsealed memfd must not carry a write seal, got {seals:#x}"
        );
    }

    #[test]
    fn inject_bytes_produces_sealed_cloexec_injectfdsend() {
        use std::io::Read;
        match NotifAction::inject_bytes(b"payload") {
            NotifAction::InjectFdSend { srcfd, newfd_flags } => {
                assert_eq!(newfd_flags, libc::O_CLOEXEC as u32);
                let seals = unsafe { libc::fcntl(srcfd.as_raw_fd(), libc::F_GET_SEALS) };
                assert!(seals & libc::F_SEAL_WRITE != 0, "inject_bytes must seal");
                let mut f = std::fs::File::from(srcfd);
                let mut buf = String::new();
                f.read_to_string(&mut buf).unwrap();
                assert_eq!(buf, "payload");
            }
            other => panic!("expected InjectFdSend, got {other:?}"),
        }
    }

    #[test]
    fn test_network_state_new() {
        let ns = super::super::state::NetworkState::new();
        assert!(matches!(ns.tcp_policy, NetworkPolicy::Unrestricted));
        assert!(matches!(ns.udp_policy, NetworkPolicy::Unrestricted));
        assert!(matches!(ns.icmp_policy, NetworkPolicy::Unrestricted));
        assert!(ns.port_map.bound_ports.is_empty());
    }

    #[test]
    fn test_time_random_state_new() {
        let tr = super::super::state::TimeRandomState::new(None, None);
        assert!(tr.time_offset.is_none());
        assert!(tr.random_state.is_none());
    }

    #[test]
    fn test_resource_state_new() {
        let rs = super::super::state::ResourceState::new(1024 * 1024, 10);
        assert_eq!(rs.mem_used, 0);
        assert_eq!(rs.max_memory_bytes, 1024 * 1024);
        assert_eq!(rs.max_processes, 10);
        assert!(!rs.hold_forks);
        assert!(rs.held_notif_ids.is_empty());
    }

    #[test]
    fn test_process_vm_readv_self() {
        let data: u64 = 0xDEADBEEF_CAFEBABE;
        let addr = &data as *const u64 as u64;
        let pid = std::process::id();
        let result = read_child_mem_vm(pid, addr, 8);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        let read_val = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(read_val, 0xDEADBEEF_CAFEBABE);
    }

    #[test]
    fn test_process_vm_writev_self() {
        let mut data: u64 = 0;
        let addr = &mut data as *mut u64 as u64;
        let pid = std::process::id();
        let payload = 0x1234567890ABCDEFu64.to_ne_bytes();
        let result = write_child_mem_vm(pid, addr, &payload);
        assert!(result.is_ok());
        assert_eq!(data, 0x1234567890ABCDEF);
    }

    #[test]
    fn denylist_blocks_matching_cidr_allows_rest() {
        use crate::network::IpCidr;
        let policy = NetworkPolicy::DenyList {
            cidrs: vec![(IpCidr::parse("10.0.0.0/8").unwrap(), PortAllow::Any)],
            any_ip_ports: HashSet::new(),
            deny_all: false,
        };
        assert!(!policy.allows("10.1.2.3".parse().unwrap(), 443)); // denied
        assert!(policy.allows("8.8.8.8".parse().unwrap(), 443));   // allowed
    }

    #[test]
    fn denylist_blocks_any_ip_port() {
        let mut ports = HashSet::new();
        ports.insert(25u16);
        let policy = NetworkPolicy::DenyList {
            cidrs: Vec::new(),
            any_ip_ports: ports,
            deny_all: false,
        };
        assert!(!policy.allows("8.8.8.8".parse().unwrap(), 25)); // denied
        assert!(policy.allows("8.8.8.8".parse().unwrap(), 80));  // allowed
    }

    #[test]
    fn denylist_specific_ports_on_cidr() {
        use crate::network::IpCidr;
        let mut ports = HashSet::new();
        ports.insert(443u16);
        let policy = NetworkPolicy::DenyList {
            cidrs: vec![(IpCidr::parse("1.2.3.4/32").unwrap(), PortAllow::Specific(ports))],
            any_ip_ports: HashSet::new(),
            deny_all: false,
        };
        assert!(!policy.allows("1.2.3.4".parse().unwrap(), 443)); // denied
        assert!(policy.allows("1.2.3.4".parse().unwrap(), 80));   // allowed
    }

    #[test]
    fn allowlist_permits_matching_cidr_only() {
        use crate::network::IpCidr;
        let mut ports = HashSet::new();
        ports.insert(80u16);
        let policy = NetworkPolicy::AllowList {
            per_ip: HashMap::new(),
            cidrs: vec![(IpCidr::parse("10.0.0.0/8").unwrap(), PortAllow::Specific(ports))],
            any_ip_ports: HashSet::new(),
        };
        assert!(policy.allows("10.1.2.3".parse().unwrap(), 80));   // in range, port ok
        assert!(!policy.allows("10.1.2.3".parse().unwrap(), 443)); // in range, wrong port
        assert!(!policy.allows("8.8.8.8".parse().unwrap(), 80));   // out of range
    }

    #[test]
    fn allowlist_cidr_all_ports() {
        use crate::network::IpCidr;
        let policy = NetworkPolicy::AllowList {
            per_ip: HashMap::new(),
            cidrs: vec![(IpCidr::parse("192.168.0.0/16").unwrap(), PortAllow::Any)],
            any_ip_ports: HashSet::new(),
        };
        assert!(policy.allows("192.168.5.5".parse().unwrap(), 9999)); // any port in range
        assert!(!policy.allows("10.0.0.1".parse().unwrap(), 9999));   // out of range
    }
}
