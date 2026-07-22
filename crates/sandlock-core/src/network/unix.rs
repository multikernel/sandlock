// Named AF_UNIX gate subsystem, shared by the connect and send handlers.
//
// Landlock has no access right for unix-socket connect, so a named
// (pathname) target is gated on the fs-write grants: the path is resolved
// to its real inode in the child's root view, pinned with an O_PATH fd,
// and the syscall runs on-behalf against `/proc/self/fd/<pin>` so the
// checked inode is the one acted on (TOCTOU- and symlink-safe).

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_mem, NotifAction};
use crate::sys::structs::{SeccompNotif, ECONNREFUSED};

use super::materialize::{
    materialize_msg, mmsg_entry_ptr, mmsg_msglen_addr, named_unix_socket_path, ChildMsghdr,
    MaterializedMsg,
};
use super::send_engine::{batch_send_step, resolve_send, wants_blocking, BatchStep};
use super::verdict::{path_under_any, real_path_under_any};

/// Render the supervisor-side path that addresses `sun_path` **in the child's
/// root view**, i.e. `/proc/<pid>/root` + the child's absolute `sun_path`.
/// Pure: builds a string, touches nothing. Single source of truth for the
/// resolution context, so a change to it is visible in one unit test rather
/// than only in a live sandbox.
///
/// Returns `None` for a relative `sun_path`, which is refused instead of
/// resolved: the supervisor cannot reproduce the child's cwd, so resolving one
/// here would silently address a different socket — whichever one sits at that
/// name under the *supervisor's* cwd. Concatenating a relative input onto the
/// prefix would also produce a path that merely happens to be bogus today
/// (`/proc/42/rootsvc.dgram`); the explicit check makes the fail-closed
/// property intentional rather than incidental, and keeps it under a refactor
/// to `Path::join`, which would silently drop the prefix.
fn child_root_path(child_pid: u32, sun_path: &std::path::Path) -> Option<String> {
    if !sun_path.is_absolute() {
        return None;
    }
    Some(format!("/proc/{}/root{}", child_pid, sun_path.display()))
}

/// Pin the inode a named unix socket `sun_path` resolves to **in the child's
/// root view** (see [`child_root_path`]), following the child's symlinks rather
/// than the supervisor's. Returns an `O_PATH` fd to that exact inode; callers
/// address it through `/proc/self/fd` so the resolved inode is the one acted on,
/// immune to a path swap after the check (TOCTOU- and symlink-safe).
///
/// A `sun_path` [`child_root_path`] refuses gets `ECONNREFUSED`, which matches
/// the errno an unreachable target already returns, so no caller observes a new
/// failure mode.
fn pin_child_unix_target(
    child_pid: u32,
    sun_path: &std::path::Path,
) -> Result<OwnedFd, NotifAction> {
    let proc_path = match child_root_path(child_pid, sun_path) {
        Some(p) => p,
        None => return Err(NotifAction::Errno(ECONNREFUSED)),
    };
    // `O_PATH` follows symlinks to the real socket inode and pins it without
    // performing any I/O on the socket.
    let c_proc = std::ffi::CString::new(proc_path)
        .map_err(|_| NotifAction::Errno(libc::EACCES))?;
    let pinned_raw = unsafe { libc::open(c_proc.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if pinned_raw < 0 {
        // Target missing or unreachable: refuse without leaking the reason.
        return Err(NotifAction::Errno(ECONNREFUSED));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(pinned_raw) })
}

/// Resolve a named unix socket `sun_path` to its real, symlink-followed inode
/// in the child's root view (see [`pin_child_unix_target`]) and verify that
/// inode is under an fs-write grant. On success returns the pinned `O_PATH` fd;
/// on failure returns the deny/refuse `NotifAction`.
fn resolve_named_unix_target(
    child_pid: u32,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> Result<OwnedFd, NotifAction> {
    let pinned = pin_child_unix_target(child_pid, sun_path)?;

    // Canonical path of the pinned inode in our mount namespace.
    let real = std::fs::read_link(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .map_err(|_| NotifAction::Errno(libc::EACCES))?;
    if real_path_under_any(&real, writable) {
        Ok(pinned)
    } else {
        Err(NotifAction::Errno(libc::EACCES))
    }
}

/// Build a `sockaddr_un` addressing `/proc/self/fd/<fd>`. The kernel resolves
/// it to the exact pinned inode, so connecting/sending to it targets the inode
/// we validated rather than re-resolving a path string. Returns `None` only if
/// the rendered path would overflow `sun_path` (never, in practice).
fn proc_self_fd_sockaddr(fd: RawFd) -> Option<(libc::sockaddr_un, libc::socklen_t)> {
    let path = format!("/proc/self/fd/{}", fd);
    let bytes = path.as_bytes();
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= sun.sun_path.len() {
        return None;
    }
    sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, &b) in bytes.iter().enumerate() {
        sun.sun_path[i] = b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    Some((sun, len))
}

/// Flatten a `sockaddr_un` into the owned byte form [`MaterializedMsg::addr`]
/// carries. Single place so every on-behalf send encodes the destination the
/// same way.
fn sockaddr_un_bytes(sun: &libc::sockaddr_un, len: libc::socklen_t) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(sun as *const libc::sockaddr_un as *const u8, len as usize) }
        .to_vec()
}

/// On-behalf `connect()` for a NAMED `AF_UNIX` socket in non-chroot mode:
/// resolve+verify the target, then connect the child's socket to the pinned
/// inode through `/proc/self/fd`.
pub(super) fn connect_named_unix_on_behalf(
    child_pid: u32,
    sockfd: i32,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> NotifAction {
    let pinned = match resolve_named_unix_target(child_pid, sun_path, writable) {
        Ok(fd) => fd,
        Err(action) => return action,
    };
    let (sun, len) = match proc_self_fd_sockaddr(pinned.as_raw_fd()) {
        Some(s) => s,
        None => return NotifAction::Errno(libc::ENAMETOOLONG),
    };
    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(child_pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let ret = unsafe {
        libc::connect(
            dup_fd.as_raw_fd(),
            &sun as *const libc::sockaddr_un as *const libc::sockaddr,
            len,
        )
    };
    if ret == 0 {
        NotifAction::ReturnValue(0)
    } else {
        NotifAction::Errno(unsafe { *libc::__errno_location() })
    }
}

/// On-behalf `sendto()` for a NAMED `AF_UNIX` datagram in non-chroot mode:
/// resolve+verify the target, copy the child's data, then send to the pinned
/// inode through `/proc/self/fd`.
pub(super) fn sendto_named_unix_on_behalf(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    sockfd: i32,
    buf_ptr: u64,
    buf_len: usize,
    flags: i32,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> NotifAction {
    let pinned = match resolve_named_unix_target(notif.pid, sun_path, writable) {
        Ok(fd) => fd,
        Err(action) => return action,
    };
    let (sun, len) = match proc_self_fd_sockaddr(pinned.as_raw_fd()) {
        Some(s) => s,
        None => return NotifAction::Errno(libc::ENAMETOOLONG),
    };
    let data = match read_child_mem(notif_fd, notif.id, notif.pid, buf_ptr, buf_len) {
        Ok(b) => b,
        Err(_) => return NotifAction::Errno(libc::EIO),
    };
    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    // Route through resolve_send like the sendmsg path instead of an inline
    // blocking sendto: the dup shares the child's blocking mode, so an inline
    // send on the notification loop wedges the whole loop when a child fills a
    // datagram queue it never drains — the same DoS this change fixes elsewhere.
    // The first attempt is non-blocking on the loop; a blocking child's would-
    // block is completed off-loop.
    let addr = sockaddr_un_bytes(&sun, len);
    let m = MaterializedMsg {
        data,
        control: None,
        addr,
        _scm_fds: Vec::new(),
        _pinned: Some(pinned),
    };
    let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
    resolve_send(dup_fd, m, flags, blocking)
}

/// On-behalf `sendto()` for a NAMED `AF_UNIX` datagram on a sandbox that
/// declares NO filesystem grants (`has_unix_fs_gate == false`), so there is no
/// fs-write grant list to check the target against — [`resolve_named_unix_target`]
/// would refuse every target against an empty list. The destination must still be
/// resolved in the CHILD's context: this pins the inode via `/proc/<pid>/root`
/// and sends to `/proc/self/fd/<pin>`, so a relative (or otherwise
/// child-relative) `sun_path` can never be resolved against the supervisor's
/// cwd/root, and the socket that was resolved is the socket written to.
///
/// Takes the caller's already-dup'd socket — the caller pinned it to read its
/// stable `SO_DOMAIN` — so the child's `sockfd` is sampled exactly once and
/// cannot be swapped between the domain check and the send.
///
/// REACHABILITY: no configuration that can execute code reaches this today, so
/// it carries no integration test and is defence in depth rather than a live
/// path. `has_unix_fs_gate == false` means the sandbox declares no fs grant at
/// all, and Landlock then denies `execve` of anything (verified: a sandbox with
/// only `net_allow` fails with `EACCES` on exec), while `Sandbox::fork` — the
/// one way into an already-running process — installs a deny-only seccomp
/// filter and no notification supervisor, so no send handler runs there. The
/// arm exists because the pre-existing alternative was to hand the child's raw
/// `sun_path` to the supervisor's own `sendto`, which resolves against the
/// SUPERVISOR's cwd/root; if either gap closes (an fs opt-out, or `fork` gaining
/// notify supervision) that would become a live confused-deputy write.
pub(super) fn sendto_pinned_unix_on_behalf(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    dup_fd: OwnedFd,
    buf_ptr: u64,
    buf_len: usize,
    flags: i32,
    sun_path: &std::path::Path,
) -> NotifAction {
    let pinned = match pin_child_unix_target(notif.pid, sun_path) {
        Ok(fd) => fd,
        Err(action) => return action,
    };
    let (sun, len) = match proc_self_fd_sockaddr(pinned.as_raw_fd()) {
        Some(s) => s,
        None => return NotifAction::Errno(libc::ENAMETOOLONG),
    };
    let data = match read_child_mem(notif_fd, notif.id, notif.pid, buf_ptr, buf_len) {
        Ok(b) => b,
        Err(_) => return NotifAction::Errno(libc::EIO),
    };
    // `pinned` must stay open (and at the same fd number) for the
    // `/proc/self/fd/<pin>` destination to resolve, so the message owns it.
    let m = MaterializedMsg {
        data,
        control: None,
        addr: sockaddr_un_bytes(&sun, len),
        _scm_fds: Vec::new(),
        _pinned: Some(pinned),
    };
    let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
    resolve_send(dup_fd, m, flags, blocking)
}

/// Apply the named-unix fs gate to a `sendmsg()` whose `msg_name` may address a
/// unix socket. Returns `Some(action)` when the target is a named `AF_UNIX`
/// socket (handled here), or `None` to fall through to the IP path (connected
/// socket, IP family, abstract socket, or an unreadable header).
pub(super) fn unix_sendmsg_gate(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
    sockfd: i32,
    msghdr_ptr: u64,
    flags: i32,
) -> Option<NotifAction> {
    let hdr = ChildMsghdr::read(notif, notif_fd, msghdr_ptr).ok()?;
    if hdr.connected() {
        return None; // connected socket: no address to gate
    }
    let addr_bytes =
        super::read_sockaddr(notif_fd, notif.id, notif.pid, hdr.name_ptr, hdr.namelen as usize).ok()?;
    // None unless this is a NAMED AF_UNIX target; IP/abstract fall through.
    let path = named_unix_socket_path(&addr_bytes)?;

    if ctx.policy.chroot_root.is_some() {
        return Some(if path_under_any(&path, &ctx.policy.chroot_writable) {
            NotifAction::Continue
        } else {
            NotifAction::Errno(libc::EACCES)
        });
    }
    Some(sendmsg_named_unix_on_behalf(
        notif,
        notif_fd,
        sockfd,
        msghdr_ptr,
        flags,
        &path,
        &ctx.policy.chroot_writable,
    ))
}

/// On-behalf `sendmsg()` for a NAMED `AF_UNIX` datagram in non-chroot mode:
/// resolve+verify the target, copy the message's iovecs and control data, then
/// send to the pinned inode through `/proc/self/fd`.
fn sendmsg_named_unix_on_behalf(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    sockfd: i32,
    msghdr_ptr: u64,
    flags: i32,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> NotifAction {
    match send_named_unix_msghdr(notif, notif_fd, sockfd, msghdr_ptr, sun_path, writable) {
        Ok((dup_fd, m)) => {
            let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
            resolve_send(dup_fd, m, flags, blocking)
        }
        Err(errno) => NotifAction::Errno(errno),
    }
}

/// Core of the named-unix on-behalf `sendmsg`: resolve+verify `sun_path` and
/// copy the message's iovecs/control from the child, addressed to the pinned
/// inode via `/proc/self/fd`. Returns the dup'd socket and a [`MaterializedMsg`]
/// (which keeps the inode pin alive) for the caller to send — inline, and
/// deferred if it would block. Shared by the single-message `sendmsg` path and
/// the per-entry `sendmmsg` path.
fn send_named_unix_msghdr(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    sockfd: i32,
    msghdr_ptr: u64,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> Result<(OwnedFd, MaterializedMsg), i32> {
    let pinned = match resolve_named_unix_target(notif.pid, sun_path, writable) {
        Ok(fd) => fd,
        Err(NotifAction::Errno(e)) => return Err(e),
        Err(_) => return Err(libc::EACCES),
    };
    let (sun, sun_len) = proc_self_fd_sockaddr(pinned.as_raw_fd()).ok_or(libc::ENAMETOOLONG)?;

    let hdr = ChildMsghdr::read(notif, notif_fd, msghdr_ptr)?;

    // The destination is the `/proc/self/fd/<pinned>` sockaddr; `pinned` must
    // stay open (and at the same fd number) for that path to resolve, so the
    // message keeps it alive. Copy the sockaddr bytes it currently encodes.
    let addr = sockaddr_un_bytes(&sun, sun_len);

    // Named target is always AF_UNIX, so translate SCM_RIGHTS / reject creds.
    let m = materialize_msg(notif, notif_fd, &hdr, addr, true, Some(pinned))?;

    let dup_fd = crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd)
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF))?;

    Ok((dup_fd, m))
}

/// Read a `sendmmsg` entry's `msg_name` and return its NAMED `AF_UNIX` path, or
/// `None` for a connected (null-name), IP, or abstract entry. The entry's
/// `msghdr` is the first field of `struct mmsghdr`, so it begins at `entry_ptr`.
pub(super) fn mmsg_entry_named_unix_path(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    entry_ptr: u64,
) -> Option<std::path::PathBuf> {
    let hdr = ChildMsghdr::read(notif, notif_fd, entry_ptr).ok()?;
    if hdr.connected() {
        return None;
    }
    let addr_bytes =
        super::read_sockaddr(notif_fd, notif.id, notif.pid, hdr.name_ptr, hdr.namelen as usize).ok()?;
    named_unix_socket_path(&addr_bytes)
}

/// On-behalf `sendmmsg` for a batch containing NAMED `AF_UNIX` entries
/// (non-chroot). Each named-unix entry is resolved, verified, and sent to its
/// pinned inode; the loop stops at the first entry it cannot gate on-behalf
/// (connected/abstract) or that is denied, returning the count sent so far
/// (standard short-`sendmmsg` semantics). Never returns `Continue`, so a unix
/// entry cannot ride out via the binary whole-call passthrough.
pub(super) fn sendmmsg_named_unix_on_behalf(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    sockfd: i32,
    msgvec_ptr: u64,
    vlen: usize,
    flags: i32,
    writable: &[std::path::PathBuf],
) -> NotifAction {
    let mut sent: usize = 0;
    let mut first_errno: Option<i32> = None;
    for i in 0..vlen {
        let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
        let path = match mmsg_entry_named_unix_path(notif, notif_fd, entry_ptr) {
            Some(p) => p,
            // Connected/abstract/unreadable entry: cannot gate on-behalf, so
            // stop here and report a short send rather than passing it through.
            None => break,
        };
        let (dup_fd, m) = match send_named_unix_msghdr(notif, notif_fd, sockfd, entry_ptr, &path, writable) {
            Ok(pair) => pair,
            Err(errno) => {
                first_errno = Some(errno);
                break;
            }
        };
        match batch_send_step(
            &dup_fd, m, flags, notif_fd, notif.id, notif.pid,
            mmsg_msglen_addr(entry_ptr), sent,
        ) {
            BatchStep::Sent => sent += 1,
            BatchStep::Done(action) => return action,
            BatchStep::Stop(errno) => {
                if sent == 0 {
                    first_errno = Some(errno);
                }
                break;
            }
        }
    }
    if sent > 0 {
        NotifAction::ReturnValue(sent as i64)
    } else {
        NotifAction::Errno(first_errno.unwrap_or(libc::EACCES))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resolution context is the CHILD's root view, not the supervisor's.
    /// Asserting on the rendered string is the only way to see that: without a
    /// mount namespace the supervisor's `/` and `/proc/<pid>/root` name the same
    /// inodes, so dropping the prefix is invisible to any live-sandbox test but
    /// is exactly the bug (a chrooted or differently-mounted child would be
    /// addressed against the supervisor's root).
    #[test]
    fn child_root_path_resolves_in_the_childs_root_view() {
        assert_eq!(
            child_root_path(4242, std::path::Path::new("/run/svc.dgram")).as_deref(),
            Some("/proc/4242/root/run/svc.dgram")
        );
    }

    /// A relative `sun_path` must be refused outright, never resolved: the
    /// supervisor's cwd is not the child's, so resolving it would address
    /// whatever socket happens to sit at that name next to the supervisor.
    /// Asserted on the builder rather than on `pin_child_unix_target`, whose
    /// `ECONNREFUSED` is indistinguishable from "target missing" — dropping the
    /// guard there still yields `ECONNREFUSED` because the concatenation
    /// (`/proc/<pid>/rootsvc.dgram`) fails to open anyway, so such a test would
    /// pass with the guard deleted.
    #[test]
    fn child_root_path_refuses_relative_sun_path() {
        assert_eq!(
            child_root_path(4242, std::path::Path::new("svc.dgram")),
            None,
            "a relative sun_path must be refused, not concatenated"
        );
    }

    /// End-to-end control for the two assertions above: the builder's output is
    /// actually what gets opened and pinned. Uses our own pid, whose root view
    /// is the test process's own root, so the pin is deterministic.
    #[test]
    fn pin_child_unix_target_pins_absolute_path() {
        let pinned = pin_child_unix_target(std::process::id(), std::path::Path::new("/dev/null"));
        assert!(pinned.is_ok(), "absolute path must pin, got {:?}", pinned.err());
    }
}
