//! Netlink virtualization handlers — interpose AF_NETLINK sockets as
//! unix socketpairs driven by a synthesized NETLINK_ROUTE responder.
//!
//! Continue safety (issue #27): every Continue here is dispatch routing
//! based on register args (socket domain, fd number) or a fall-through
//! after harmless cosmetic adjustments (recvmsg pre-zeroing). Decisions
//! that require security enforcement (non-NETLINK_ROUTE protocol) return
//! Errno; substitution returns InjectFdSendTracked. The fd-cookie check
//! (`state.is_cookie(tgid, fd)`) examines a register arg, not user memory,
//! so the seccomp_unotify TOCTOU class doesn't apply: a racing thread
//! cannot change the fd number stored in another thread's syscall
//! registers.

use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use crate::netlink::{proxy, state::NetlinkState};
use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction, OnInjectSuccess};
use crate::sys::structs::SeccompNotif;

const AF_NETLINK: u64 = 16;
const NETLINK_ROUTE: u64 = 0;

/// Resolve `notif.pid` (which is a TID per the kernel's `task_pid_vnr`) to
/// the enclosing thread group id.  fds are shared across all threads of a
/// process, so cookie entries must be keyed by TGID — otherwise a cookie
/// created by thread A is invisible to thread B in the same process.
fn tgid_of(tid: i32) -> i32 {
    let path = format!("/proc/{}/status", tid);
    if let Ok(s) = std::fs::read_to_string(&path) {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Tgid:") {
                if let Ok(v) = rest.trim().parse::<i32>() {
                    return v;
                }
            }
        }
    }
    // Fallback: if we can't read status, treat the tid as the tgid.
    tid
}

/// Read a POD struct `T` from child memory via `process_vm_readv`, with the
/// shared `notif::read_child_mem` helper that ID-validates the notification
/// before and after the read.
fn read_struct<T: Copy>(
    notif_fd: RawFd,
    id: u64,
    pid: u32,
    addr: usize,
) -> Option<T> {
    let bytes = read_child_mem(notif_fd, id, pid, addr as u64, std::mem::size_of::<T>()).ok()?;
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}

/// Intercept `socket(AF_NETLINK, *, NETLINK_ROUTE)` and substitute one end
/// of a `socketpair(AF_UNIX, SOCK_SEQPACKET)`. A tokio task takes the
/// supervisor-side end and speaks synthesized NETLINK_ROUTE replies.
/// Other domains pass through; other netlink protocols are denied.
pub async fn handle_socket(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
) -> NotifAction {
    let domain   = notif.data.args[0];
    let protocol = notif.data.args[2];

    if domain != AF_NETLINK {
        return NotifAction::Continue;
    }
    if protocol != NETLINK_ROUTE {
        return NotifAction::Errno(libc::EAFNOSUPPORT);
    }

    let mut fds = [0i32; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return NotifAction::Errno(libc::ENOMEM);
    }
    // fds[0] → supervisor side (responder owns)
    // fds[1] → child side (injected)
    //
    // The supervisor end is driven by a tokio task via AsyncFd, so it
    // must be non-blocking. The child end stays blocking (glibc's
    // netlink code expects blocking semantics).
    let flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return NotifAction::Errno(libc::ENOMEM);
    }
    let responder_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    // tgid, not tid: fds are process-scoped, so the cookie set must be
    // keyed per-process to be visible across threads of the same app.
    // The responder also uses tgid as `nlmsg_pid` in its replies so the
    // value is consistent with what `handle_getsockname` writes for the
    // same process (glibc compares incoming nlmsg_pid against the value
    // it read back from getsockname — they must agree).
    let tgid = tgid_of(notif.pid as i32);
    proxy::spawn_responder(responder_fd, tgid as u32);

    // Record the (tgid, fd) once the kernel's ADDFD ioctl returns the
    // child-side fd number.  Doing it from the on-success callback
    // (rather than guessing via inode matching afterwards) closes the
    // TOCTOU gap: the entry lands in the state map *before* the child's
    // syscall unblocks, and the key is the exact fd slot the kernel
    // allocated — not derivable by racing the child.
    let state = Arc::clone(state);
    NotifAction::InjectFdSendTracked {
        srcfd: child_fd,
        newfd_flags: libc::O_CLOEXEC as u32,
        on_success: OnInjectSuccess::new(move |child_fd_num| {
            state.register(tgid, child_fd_num);
        }),
    }
}

/// Zero out the `msg_name` region of a recvmsg/recvfrom before the kernel
/// runs the syscall, so that the source address glibc sees has
/// `nl_pid == 0` (the kernel only writes `sun_family` = AF_UNIX = 2 bytes
/// into a unix-socketpair recvmsg's source address; bytes 2..end remain as
/// whatever we pre-filled).
///
/// glibc's netlink receive loop rejects messages where
/// `source_addr.nl_pid != 0` with a silent `continue`, interpreting them as
/// coming from a non-kernel peer.  Without this zeroing the `nl_pid` bits
/// are uninitialized stack and the check is flaky.
pub async fn handle_netlink_recvmsg(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
    notif_fd: RawFd,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let tgid = tgid_of(notif.pid as i32);
    if !state.is_cookie(tgid, fd) {
        return NotifAction::Continue;
    }

    let nr = notif.data.nr as i64;
    let sockaddr_nl_len: usize = 12;
    let zeros = [0u8; 12];
    let pid = notif.pid;
    let id = notif.id;

    if nr == libc::SYS_recvmsg {
        // args: (fd, msghdr*, flags)
        let msghdr_ptr = notif.data.args[1] as usize;
        if let Some(hdr) = read_struct::<libc::msghdr>(notif_fd, id, pid, msghdr_ptr) {
            if !hdr.msg_name.is_null() && (hdr.msg_namelen as usize) >= sockaddr_nl_len {
                let _ = write_child_mem(notif_fd, id, pid, hdr.msg_name as u64, &zeros);
            }
        }
    } else if nr == libc::SYS_recvfrom {
        // args: (fd, buf, len, flags, src_addr*, addrlen_ptr)
        let src_addr = notif.data.args[4] as u64;
        let addrlen_ptr = notif.data.args[5] as u64;
        if src_addr != 0 && addrlen_ptr != 0 {
            if let Ok(b) = read_child_mem(notif_fd, id, pid, addrlen_ptr, 4) {
                let cap = u32::from_ne_bytes(b.try_into().unwrap_or([0; 4])) as usize;
                if cap >= sockaddr_nl_len {
                    let _ = write_child_mem(notif_fd, id, pid, src_addr, &zeros);
                }
            }
        }
    }

    NotifAction::Continue
}

pub async fn handle_bind(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let tgid = tgid_of(notif.pid as i32);
    if state.is_cookie(tgid, fd) {
        return NotifAction::ReturnValue(0);
    }
    NotifAction::Continue
}

/// Remove `(tgid, fd)` from the cookie set when the child closes a
/// tracked netlink socket.  Lets the kernel actually close the fd too.
pub async fn handle_close(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let tgid = tgid_of(notif.pid as i32);
    if state.is_cookie(tgid, fd) {
        state.unregister(tgid, fd);
    }
    NotifAction::Continue
}

pub async fn handle_getsockname(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
    notif_fd: RawFd,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let tgid = tgid_of(notif.pid as i32);
    if !state.is_cookie(tgid, fd) {
        return NotifAction::Continue;
    }

    // struct sockaddr_nl { u16 nl_family; u16 _pad; u32 nl_pid; u32 nl_groups; }
    //
    // We use the tgid as the synthesized nl_pid so it's stable across
    // threads of the same process — matching the real kernel's netlink
    // auto-bind behavior which assigns one nl_pid per netlink socket.
    let mut addr = [0u8; 12];
    let nl_family = libc::AF_NETLINK as u16;
    addr[0..2].copy_from_slice(&nl_family.to_ne_bytes());
    addr[4..8].copy_from_slice(&(tgid as u32).to_ne_bytes());

    let addr_ptr = notif.data.args[1] as u64;
    let addrlen_ptr = notif.data.args[2] as u64;
    let pid = notif.pid;
    let id = notif.id;

    let cur = match read_child_mem(notif_fd, id, pid, addrlen_ptr, 4) {
        Ok(b) => u32::from_ne_bytes(b.try_into().unwrap_or([0; 4])) as usize,
        Err(_) => return NotifAction::Errno(libc::EFAULT),
    };
    let to_write = cur.min(addr.len());
    if write_child_mem(notif_fd, id, pid, addr_ptr, &addr[..to_write]).is_err() {
        return NotifAction::Errno(libc::EFAULT);
    }
    let actual = (addr.len() as u32).to_ne_bytes();
    let _ = write_child_mem(notif_fd, id, pid, addrlen_ptr, &actual);
    NotifAction::ReturnValue(0)
}
