// IP send handlers (sendto / sendmsg / sendmmsg): parse the message from
// child memory into owned values, decide via the destination verdict, and
// execute through the send engine. Named AF_UNIX targets are delegated to
// `unix`; connected sends carry no destination and skip the verdict (the
// connect was gated when it happened).

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_mem, NotifAction};
use crate::sys::structs::{SeccompNotif, ECONNREFUSED};

use super::materialize::{
    materialize_msg, mmsg_entry_ptr, mmsg_msglen_addr, named_unix_socket_path,
    parse_ip_from_sockaddr, parse_port_from_sockaddr, ChildMsghdr, MaterializedMsg,
    MAX_SEND_BUF,
};
use super::send_engine::{batch_send_step, resolve_send, wants_blocking, BatchStep};
use super::unix::{
    mmsg_entry_named_unix_path, sendmmsg_named_unix_on_behalf, sendto_named_unix_on_behalf,
    unix_sendmsg_gate,
};
use super::verdict::{check_ip_destination, path_under_any};
use super::{query_socket_protocol, socket_is_unix, Protocol};

// ============================================================
// sendto_on_behalf / sendmsg_on_behalf — on-behalf (TOCTOU-safe)
// ============================================================

/// Perform sendto() on behalf of the child process (TOCTOU-safe).
///
/// 1. Copy sockaddr from child memory (our copy — immune to TOCTOU)
/// 2. Check IP against allowlist on our copy
/// 3. Copy data buffer from child memory
/// 4. Duplicate child's socket fd via pidfd_getfd
/// 5. sendto() in supervisor with validated sockaddr + copied data
/// 6. Return byte count or errno
///
/// Only triggers for unconnected sends (addr_ptr != NULL), which is
/// primarily UDP. Connected sockets (addr_ptr == NULL) use CONTINUE.
pub(super) async fn sendto_on_behalf(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let args = &notif.data.args;
    let sockfd = args[0] as i32;
    let buf_ptr = args[1];
    let buf_len = args[2] as usize;
    if buf_len > MAX_SEND_BUF {
        return NotifAction::Errno(libc::EMSGSIZE);
    }
    let flags = args[3] as i32;
    let addr_ptr = args[4];
    let addr_len = args[5] as u32;

    if addr_ptr == 0 {
        return NotifAction::Continue; // connected socket, no addr to check
    }

    // 1. Copy sockaddr from child memory (small: 16-28 bytes)
    let addr_bytes =
        match read_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, addr_len as usize) {
            Ok(b) => b,
            Err(_) => return NotifAction::Errno(libc::EIO),
        };

    // 2. Check (ip, port) against the per-protocol endpoint allowlist.
    // One pidfd_getfd serves both the SO_PROTOCOL probe and the
    // on-behalf sendto.
    if let Some(ip) = parse_ip_from_sockaddr(&addr_bytes) {
        let dest_port = parse_port_from_sockaddr(&addr_bytes);
        let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
            Ok(fd) => fd,
            Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
        };
        let protocol = match query_socket_protocol(dup_fd.as_raw_fd()) {
            Some(p) => p,
            None => return NotifAction::Errno(ECONNREFUSED),
        };
        if let Err(e) = check_ip_destination(ctx, notif.pid, protocol, ip, dest_port).await {
            return NotifAction::Errno(e);
        }

        // 3. Copy data buffer from child memory
        let data = match read_child_mem(notif_fd, notif.id, notif.pid, buf_ptr, buf_len) {
            Ok(b) => b,
            Err(_) => return NotifAction::Errno(libc::EIO),
        };

        // 4. Send on-behalf (deferred if it would block), like sendmsg — a
        // sendto is a sendmsg with a single iovec and an explicit destination.
        // The first attempt is non-blocking on the loop; a blocking child whose
        // send buffer is full defers off the loop instead of wedging it.
        let m = MaterializedMsg {
            data,
            control: None,
            addr: addr_bytes,
            _scm_fds: Vec::new(),
            _pinned: None,
        };
        let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
        resolve_send(dup_fd, m, flags, blocking)
    } else {
        // Non-IP family. Gate a NAMED AF_UNIX datagram the same way as connect:
        // sendto to a named socket is a WRITE on its inode, so deny unless the
        // resolved real target is under an fs-write grant.
        match named_unix_socket_path(&addr_bytes) {
            Some(path) if ctx.policy.has_unix_fs_gate => {
                if ctx.policy.chroot_root.is_some() {
                    if path_under_any(&path, &ctx.policy.chroot_writable) {
                        NotifAction::Continue
                    } else {
                        NotifAction::Errno(libc::EACCES)
                    }
                } else {
                    sendto_named_unix_on_behalf(
                        notif,
                        notif_fd,
                        sockfd,
                        buf_ptr,
                        buf_len,
                        flags,
                        &path,
                        &ctx.policy.chroot_writable,
                    )
                }
            }
            _ => NotifAction::Continue,
        }
    }
}

/// Perform sendmsg() on behalf of the child process (TOCTOU-safe).
///
/// 1. Copy full msghdr from child memory
/// 2. Copy sockaddr from msg_name (our copy — immune to TOCTOU)
/// 3. Check IP against allowlist on our copy
/// 4. Copy iovec data buffers from child memory
/// 5. Copy control message buffer from child memory
/// 6. Duplicate child's socket fd via pidfd_getfd
/// 7. sendmsg() in supervisor with validated sockaddr + copied data
/// 8. Return byte count or errno
pub(super) async fn sendmsg_on_behalf(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let args = &notif.data.args;
    let sockfd = args[0] as i32;
    let msghdr_ptr = args[1];
    let flags = args[2] as i32;

    // Named-unix datagram gate. A named AF_UNIX `msg_name` is handled here; the
    // IP path below only covers AF_INET/AF_INET6, and would pass a unix target
    // straight through.
    if ctx.policy.has_unix_fs_gate {
        if let Some(action) = unix_sendmsg_gate(notif, ctx, notif_fd, sockfd, msghdr_ptr, flags) {
            return action;
        }
    }

    // With a destination policy active, never Continue: the kernel would
    // re-read `msg_name` from child memory, where a racing thread could swap a
    // connected (NULL) name for a denied address. Send on-behalf (including
    // connected sends) so the verdict is made on the immune copy. Without a
    // policy there is nothing to bypass, so the Continue fast path below stands.
    let dest_policy = ctx.policy.has_net_destination_policy;
    if !dest_policy {
        // Pre-scan for Continue cases (connected socket / non-IP family).
        // EFAULT on unreadable msghdr (vs. Continue, which would let the kernel
        // re-read child memory and bypass our check).
        match prescan_msghdr(notif, notif_fd, msghdr_ptr) {
            PrescanResult::ContinueWholeCall => return NotifAction::Continue,
            PrescanResult::Errno(e) => return NotifAction::Errno(e),
            PrescanResult::OnBehalf => {}
        }
    }

    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    // Resolve the protocol as `Option`: it is only consumed to validate a
    // non-connected IP destination. `query_socket_protocol` returns `None` for
    // an AF_UNIX socket (no IP protocol), and a connected send (every AF_UNIX
    // send that reaches here — its connection was gated at connect time) never
    // consumes it, so the send goes through the TOCTOU-safe on-behalf path on
    // our immune `dup_fd` rather than being refused. A non-connected send with
    // no resolvable protocol fails closed inside `send_msghdr_on_behalf`.
    //
    // On-behalf (not Continue) is load-bearing under a destination policy: a
    // Continue would let the kernel re-resolve `sockfd`/`msg_name` against the
    // live child, so a racing `dup2(inet_sock, sockfd)` after a domain check
    // could redirect the send onto an IP socket to a denied destination.
    let protocol = query_socket_protocol(dup_fd.as_raw_fd());

    match send_msghdr_on_behalf(notif, ctx, notif_fd, &dup_fd, protocol, msghdr_ptr).await {
        Ok(m) => {
            let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
            resolve_send(dup_fd, m, flags, blocking)
        }
        Err(errno) => NotifAction::Errno(errno),
    }
}

// ============================================================
// prescan_msghdr / send_msghdr_on_behalf — shared per-message work
// ============================================================

#[derive(Clone, Copy)]
enum PrescanResult {
    /// All fields present, IP-family destination — caller can take the
    /// on-behalf path with `send_msghdr_on_behalf`.
    OnBehalf,
    /// `msg_name == NULL` (connected socket) or non-IP family
    /// (AF_UNIX etc.). Caller should return `NotifAction::Continue` so
    /// the kernel handles the syscall in the child's namespace —
    /// AF_UNIX path resolution is the canonical reason we don't take
    /// these messages on behalf.
    ContinueWholeCall,
    /// Memory read failure. Caller maps to the appropriate errno
    /// (EFAULT for unreadable msghdr, EIO for the sockaddr).
    Errno(i32),
}

/// Probe one `struct msghdr` to decide whether the on-behalf path
/// applies. Used by both `sendmsg_on_behalf` (one msghdr) and
/// `sendmmsg_on_behalf` (one per `mmsghdr` entry, before doing any
/// sends — Continue is a whole-syscall decision).
fn prescan_msghdr(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    msghdr_ptr: u64,
) -> PrescanResult {
    let hdr = match ChildMsghdr::read(notif, notif_fd, msghdr_ptr) {
        Ok(h) => h,
        Err(e) => return PrescanResult::Errno(e),
    };
    if hdr.connected() {
        return PrescanResult::ContinueWholeCall;
    }
    let addr_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, hdr.name_ptr, hdr.namelen as usize) {
        Ok(b) => b,
        Err(_) => return PrescanResult::Errno(libc::EIO),
    };
    if parse_ip_from_sockaddr(&addr_bytes).is_none() {
        return PrescanResult::ContinueWholeCall;
    }
    PrescanResult::OnBehalf
}

/// Validate, materialize, and send one `struct msghdr` on behalf of
/// the child. Caller is responsible for:
///   - dup'ing the child fd (`dup_fd`),
///   - resolving the socket protocol (`protocol`) via
///     `query_socket_protocol` on that dup.
///
/// `protocol` is `Option` because it is only consumed to validate a
/// *non-connected* IP destination against the allowlist. A connected send
/// (`msg_name == NULL`) — which is every send that reaches here on an AF_UNIX
/// socket, since its connection was already gated at connect time — carries no
/// destination and needs no protocol, so `None` is passed through unused. When
/// the message *is* non-connected, a missing protocol fails closed
/// (`ECONNREFUSED`), so an IP send whose protocol can't be resolved is refused
/// rather than escaping the allowlist.
///
/// Returns a [`MaterializedMsg`] the caller sends (inline and, if it would
/// block, deferred) via [`resolve_send`] / [`send_materialized`]; or an errno.
/// ECONNREFUSED is used both for "destination blocked by policy" and for
/// "couldn't parse a port from the sockaddr"; EIO for sub-buffer read failures.
async fn send_msghdr_on_behalf(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
    dup_fd: &std::os::unix::io::OwnedFd,
    protocol: Option<Protocol>,
    msghdr_ptr: u64,
) -> Result<MaterializedMsg, i32> {
    let hdr = ChildMsghdr::read(notif, notif_fd, msghdr_ptr)?;

    // A connected socket carries no per-message address (`msg_name == NULL` or
    // zero length). There is nothing to check against the destination
    // allowlist (the connection was gated at connect time), but we must still
    // send it on-behalf rather than Continue: Continue lets the kernel re-read
    // the msghdr from child memory, where a racing thread could have swapped a
    // null `msg_name` for a denied address. A non-connected entry has its IP
    // destination validated on the immune copy before the send.
    let connected = hdr.connected();
    let addr_bytes = if connected {
        Vec::new()
    } else {
        match read_child_mem(notif_fd, notif.id, notif.pid, hdr.name_ptr, hdr.namelen as usize) {
            Ok(b) => b,
            Err(_) => return Err(libc::EIO),
        }
    };
    if !connected {
        let ip = match parse_ip_from_sockaddr(&addr_bytes) {
            Some(ip) => ip,
            // A non-IP, non-connected address on an IP send path (e.g. the
            // sockaddr changed under us). Fail closed.
            None => return Err(libc::EAFNOSUPPORT),
        };
        let dest_port = parse_port_from_sockaddr(&addr_bytes);
        // A non-connected IP send must have a resolved protocol to key the
        // per-protocol allowlist. If it couldn't be resolved, fail closed.
        let protocol = protocol.ok_or(ECONNREFUSED)?;
        check_ip_destination(ctx, notif.pid, protocol, ip, dest_port).await?;
    }

    // Translate SCM_RIGHTS / reject creds only for a unix socket; an IP socket's
    // control carries no fds or credentials and passes through untouched.
    // (`addr_bytes` is already empty for a connected send.)
    materialize_msg(
        notif,
        notif_fd,
        &hdr,
        addr_bytes,
        socket_is_unix(dup_fd.as_raw_fd()),
        None,
    )
}

// ============================================================
// sendmmsg_on_behalf — multi-message variant
// ============================================================

/// Cap on the number of messages we'll process per sendmmsg call.
/// Linux's UIO_MAXIOV is 1024; lower here to bound supervisor work
/// per syscall (each entry costs at minimum a few read_child_mem
/// hops + one sendmsg).
const MAX_MMSGHDR_ENTRIES: usize = 256;

/// Perform `sendmmsg()` on behalf of the child. Pre-scans every entry
/// for Continue cases (NULL `msg_name` or non-IP family) — if any
/// entry would Continue, we Continue the whole syscall to match
/// `sendmsg_on_behalf`'s coarse-grained behavior. Otherwise dup the
/// child fd once, query SO_PROTOCOL once, then loop:
/// validate → send → write `msg_len` back to the child's mmsghdr.
///
/// On partial failure (entry K denied or send fails), returns
/// `ReturnValue(K)` matching the kernel's "messages successfully
/// transmitted" semantics. Returns the errno only when the very first
/// entry fails — otherwise the child sees a positive count and reads
/// per-entry `msg_len` to learn the per-message status.
pub(super) async fn sendmmsg_on_behalf(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let args = &notif.data.args;
    let sockfd = args[0] as i32;
    let msgvec_ptr = args[1];
    let vlen = (args[2] as u32 as usize).min(MAX_MMSGHDR_ENTRIES);
    let flags = args[3] as i32;

    if vlen == 0 {
        return NotifAction::ReturnValue(0);
    }

    // Named-unix gate. If any entry targets a named AF_UNIX socket, handle the
    // whole batch here: the existing prescan below would Continue the entire
    // call on the first non-IP entry, which would let a unix entry bypass the
    // gate.
    if ctx.policy.has_unix_fs_gate {
        let mut named_unix = false;
        for i in 0..vlen {
            let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
            if mmsg_entry_named_unix_path(notif, notif_fd, entry_ptr).is_some() {
                named_unix = true;
                break;
            }
        }
        if named_unix {
            if ctx.policy.chroot_root.is_some() {
                // Chroot: lexical check; deny the whole call if any named-unix
                // entry is outside the (virtual) write grants.
                for i in 0..vlen {
                    let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
                    if let Some(path) = mmsg_entry_named_unix_path(notif, notif_fd, entry_ptr) {
                        if !path_under_any(&path, &ctx.policy.chroot_writable) {
                            return NotifAction::Errno(libc::EACCES);
                        }
                    }
                }
                // All granted: fall through to the existing path.
            } else {
                return sendmmsg_named_unix_on_behalf(
                    notif,
                    notif_fd,
                    sockfd,
                    msgvec_ptr,
                    vlen,
                    flags,
                    &ctx.policy.chroot_writable,
                );
            }
        }
    }

    // Destination policy active: handle the whole batch on-behalf and never
    // Continue. Continue would let the kernel re-read each `msghdr` from child
    // memory, where a racing thread could swap a connected (NULL `msg_name`)
    // entry for a denied address after our prescan, bypassing the allowlist on
    // an unconnected datagram socket. On-behalf sends use the immune copy and
    // validate every IP destination, so the verdict is TOCTOU-free.
    if ctx.policy.has_net_destination_policy {
        let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
            Ok(fd) => fd,
            Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
        };
        // Protocol is resolved as `Option` and consumed only by a non-connected
        // IP entry (see `send_msghdr_on_behalf`). It is `None` for an AF_UNIX
        // socket — whose connected entries send through the immune `dup_fd`
        // without a destination check — so the batch is handled on-behalf here
        // rather than refused with ECONNREFUSED. On-behalf (not Continue) keeps
        // it TOCTOU-safe against a racing fd swap.
        let protocol = query_socket_protocol(dup_fd.as_raw_fd());
        let mut sent: usize = 0;
        let mut first_errno: Option<i32> = None;
        for i in 0..vlen {
            let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
            let m = match send_msghdr_on_behalf(notif, ctx, notif_fd, &dup_fd, protocol, entry_ptr)
                .await
            {
                Ok(m) => m,
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
        return if sent > 0 {
            NotifAction::ReturnValue(sent as i64)
        } else {
            NotifAction::Errno(first_errno.unwrap_or(ECONNREFUSED))
        };
    }

    // No destination policy: the connected fast path is safe (nothing to
    // bypass), so Continue is acceptable. Pre-scan every entry; if any has a
    // Continue-eligible shape (NULL msg_name or non-IP family), Continue the
    // whole sendmmsg. Mixed-shape calls aren't supported because Continue is
    // binary at the syscall level.
    for i in 0..vlen {
        let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
        match prescan_msghdr(notif, notif_fd, entry_ptr) {
            PrescanResult::OnBehalf => continue,
            PrescanResult::ContinueWholeCall => return NotifAction::Continue,
            PrescanResult::Errno(e) => return NotifAction::Errno(e),
        }
    }

    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let protocol = match query_socket_protocol(dup_fd.as_raw_fd()) {
        Some(p) => p,
        None => return NotifAction::Errno(ECONNREFUSED),
    };

    let mut sent: usize = 0;
    let mut first_errno: Option<i32> = None;

    for i in 0..vlen {
        let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
        // Every entry is OnBehalf (IP, non-connected) per the prescan above, so
        // the resolved protocol is always required and present here.
        let m = match send_msghdr_on_behalf(notif, ctx, notif_fd, &dup_fd, Some(protocol), entry_ptr).await {
            Ok(m) => m,
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
        // Defensive: vlen > 0 + no successes means at least one attempt
        // failed, so first_errno is set. Fall back to ECONNREFUSED
        // rather than panicking on the unwrap if invariants ever drift.
        NotifAction::Errno(first_errno.unwrap_or(ECONNREFUSED))
    }
}
