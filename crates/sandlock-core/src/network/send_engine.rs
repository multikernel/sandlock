// Execute phase: the only code that performs on-behalf sends.
//
// Consumes MaterializedMsg values (already parsed, validated, and owned)
// and resolves them to a terminal NotifAction, deferring off the
// notification loop when a blocking child's send cannot complete on the
// first non-blocking attempt.

use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

use crate::seccomp::notif::{write_child_mem, NotifAction};

use super::materialize::MaterializedMsg;

/// True iff this send should block until it completes: the socket is in blocking
/// mode (`O_NONBLOCK` clear — the dup shares the child's file description, so it
/// reflects the child's own mode) *and* the per-call `send_flags` did not request
/// non-blocking with `MSG_DONTWAIT`. A child that passes `MSG_DONTWAIT` on a
/// blocking socket wants the immediate short-count/`EAGAIN`, not a deferred
/// block-to-completion, so it must not be deferred.
pub(crate) fn wants_blocking(fd: RawFd, send_flags: i32) -> bool {
    if send_flags & libc::MSG_DONTWAIT != 0 {
        return false;
    }
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    fl >= 0 && (fl & libc::O_NONBLOCK) == 0
}

/// One `sendmsg` of `m` starting at byte `offset`. The destination address and
/// control ancillary are attached only at `offset == 0`: `SCM_RIGHTS` transmits
/// exactly once, and a stream continuation carries no new address. Returns the
/// kernel result (>= 0 bytes, or -1 with errno in `*__errno_location`).
fn send_materialized_at(fd: RawFd, m: &MaterializedMsg, offset: usize, flags: i32) -> isize {
    let iov = libc::iovec {
        iov_base: unsafe { m.data.as_ptr().add(offset) } as *mut libc::c_void,
        iov_len: m.data.len() - offset,
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    if offset == 0 {
        if !m.addr.is_empty() {
            msg.msg_name = m.addr.as_ptr() as *mut libc::c_void;
            msg.msg_namelen = m.addr.len() as u32;
        }
        if let Some(ref c) = m.control {
            msg.msg_control = c.as_ptr() as *mut libc::c_void;
            msg.msg_controllen = c.len();
        }
    }
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    unsafe { libc::sendmsg(fd, &msg, flags) }
}

/// Resolve a materialized send to a terminal action. The first attempt is
/// non-blocking (`MSG_DONTWAIT`) on the seccomp loop, so it never blocks there.
/// A non-blocking child gets whatever that one attempt returns (short count or
/// `EAGAIN`), exactly as the kernel would give it. A blocking child whose whole
/// message didn't fit is completed off the loop (`defer_send`), preserving the
/// kernel's "a blocking send of N returns N" contract without occupying the
/// loop or a worker thread — a stream send that partially fit continues from
/// the sent offset; a full send buffer defers from offset 0.
pub(crate) fn resolve_send(dup_fd: OwnedFd, m: MaterializedMsg, flags: i32, child_blocking: bool) -> NotifAction {
    let ret = send_materialized_at(dup_fd.as_raw_fd(), &m, 0, flags | libc::MSG_DONTWAIT);
    if ret >= 0 {
        let sent = ret as usize;
        if !child_blocking || sent >= m.data.len() {
            return NotifAction::ReturnValue(ret as i64);
        }
        // Blocking stream socket, partial fit: finish the remainder off the loop.
        return NotifAction::defer(defer_send(dup_fd, m, flags, sent));
    }
    let err = unsafe { *libc::__errno_location() };
    if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
        if child_blocking {
            return NotifAction::defer(defer_send(dup_fd, m, flags, 0));
        }
        return NotifAction::Errno(libc::EAGAIN);
    }
    NotifAction::Errno(err)
}

/// Byte-level completion core: await writability on the dup'd fd through the
/// Tokio IO driver's epoll (never blocking a worker thread) and push the rest of
/// the message, advancing `offset` past each partial send, until the whole
/// message is delivered or a real error occurs. Bounded by the supervisor's
/// deferred-work timeout, so a peer that never drains can wedge only this one
/// send for that bound — never the notification loop.
///
/// `Ok(n)` is the total bytes sent: the full length on success, or the bytes
/// queued before a hard error interrupted a partially-sent stream. `Err(e)` is
/// returned only when nothing at all was sent. Shared by the single-message
/// deferral ([`defer_send`]) and the batch tail ([`complete_batch_entry`]).
async fn push_until_done(
    dup_fd: OwnedFd,
    m: MaterializedMsg,
    flags: i32,
    mut offset: usize,
) -> Result<usize, i32> {
    let afd = tokio::io::unix::AsyncFd::with_interest(dup_fd, tokio::io::Interest::WRITABLE)
        .map_err(|_| libc::EIO)?;
    loop {
        let mut guard = afd.writable().await.map_err(|_| libc::EIO)?;
        let ret = send_materialized_at(afd.get_ref().as_raw_fd(), &m, offset, flags | libc::MSG_DONTWAIT);
        if ret >= 0 {
            offset += ret as usize;
            if offset >= m.data.len() {
                return Ok(m.data.len());
            }
            // More to send; the next writability edge (or an EAGAIN below) gates it.
            continue;
        }
        let err = unsafe { *libc::__errno_location() };
        if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
            guard.clear_ready();
            continue;
        }
        return if offset > 0 { Ok(offset) } else { Err(err) };
    }
}

/// Deferred tail of [`resolve_send`] for a single message: complete the send and
/// return the byte count (matching a blocking send of N returning N; a partial
/// stream then error returns the partial count).
async fn defer_send(dup_fd: OwnedFd, m: MaterializedMsg, flags: i32, offset: usize) -> NotifAction {
    match push_until_done(dup_fd, m, flags, offset).await {
        Ok(n) => NotifAction::ReturnValue(n as i64),
        Err(e) => NotifAction::Errno(e),
    }
}

/// Deferred tail shared by the three `sendmmsg` batch loops. Completes entry
/// `prior_count` (which either would-block entirely, offset 0, or partially sent
/// a stream, offset > 0) off the loop, then reports the *message* count — not a
/// byte count — as `sendmmsg` requires.
///
/// Aligns with the kernel's blocking-stream semantics: a `sendmsg` that makes
/// any progress returns that byte count and is a completed message; a hard error
/// after partial progress surfaces on the child's *next* call. So for any
/// `Ok(n)` (n is the full length on success, or the bytes queued before a hard
/// error) we write `n` back as this entry's `msg_len` and count it as
/// `prior_count + 1`. This never returns 0 for `vlen > 0`, and — crucially —
/// never leaves an already-queued entry uncounted, which would make the child
/// re-send bytes the kernel already accepted (duplicate data) or spin forever on
/// a zero-progress retry. `Err(e)` (nothing sent at all) reports the errno only
/// when nothing has been sent yet (`prior_count == 0`), else the prior count.
/// Entries beyond this one are left for the child to retry, so the batch is
/// never materialized whole.
fn complete_batch_entry(
    dup_fd: OwnedFd,
    m: MaterializedMsg,
    flags: i32,
    offset: usize,
    notif_fd: RawFd,
    notif_id: u64,
    notif_pid: u32,
    msglen_addr: u64,
    prior_count: usize,
) -> NotifAction {
    NotifAction::defer(async move {
        match push_until_done(dup_fd, m, flags, offset).await {
            Ok(n) => {
                let bytes = (n as u32).to_ne_bytes();
                let _ = write_child_mem(notif_fd, notif_id, notif_pid, msglen_addr, &bytes);
                NotifAction::ReturnValue((prior_count + 1) as i64)
            }
            Err(e) => {
                if prior_count == 0 {
                    NotifAction::Errno(e)
                } else {
                    NotifAction::ReturnValue(prior_count as i64)
                }
            }
        }
    })
}

/// Outcome of one `sendmmsg` batch entry.
pub(crate) enum BatchStep {
    /// Entry completed inline; its `msg_len` was written back. Count it and
    /// move to the next entry.
    Sent,
    /// Entry left the loop (entry 0 fully blocked, or a blocking stream entry
    /// that partially sent); the whole syscall resolves to this action.
    Done(NotifAction),
    /// Batch stops at this entry; the errno to report when nothing was sent.
    Stop(i32),
}

/// Execute phase for one batch entry, shared by the three `sendmmsg` loops:
/// one `MSG_DONTWAIT` attempt on the notification loop, then the only two
/// cases that may leave it (entry 0 fully blocked, or a blocking stream entry
/// that partially sent) are completed off the loop via `complete_batch_entry`,
/// so a caller ignoring per-entry `msg_len` is never silently truncated and a
/// blocking child never sees a spurious `EAGAIN`. A would-block at a later
/// entry, or at entry 0 of a non-blocking child, is a contract-legal
/// `Stop(EAGAIN)`; a hard error is `Stop(err)`.
///
/// `dup_fd` is borrowed; the two deferred cases `try_clone` it (a `dup(2)` of
/// the same file description, so semantics match handing over the original).
pub(crate) fn batch_send_step(
    dup_fd: &OwnedFd,
    m: MaterializedMsg,
    flags: i32,
    notif_fd: RawFd,
    notif_id: u64,
    notif_pid: u32,
    msglen_addr: u64,
    prior_count: usize,
) -> BatchStep {
    let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
    let ret = send_materialized_at(dup_fd.as_raw_fd(), &m, 0, flags | libc::MSG_DONTWAIT);
    if ret >= 0 {
        if blocking && (ret as usize) < m.data.len() {
            // Partial stream on a blocking socket: finish this entry off the
            // loop and report it as completed with its full byte count.
            let dup = match dup_fd.try_clone() {
                Ok(d) => d,
                Err(_) => return BatchStep::Stop(libc::EIO),
            };
            return BatchStep::Done(complete_batch_entry(
                dup, m, flags, ret as usize, notif_fd, notif_id, notif_pid, msglen_addr,
                prior_count,
            ));
        }
        let bytes = (ret as u32).to_ne_bytes();
        let _ = write_child_mem(notif_fd, notif_id, notif_pid, msglen_addr, &bytes);
        return BatchStep::Sent;
    }
    let err = unsafe { *libc::__errno_location() };
    if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
        if prior_count == 0 && blocking {
            // Entry 0 would block entirely: a blocking socket never returns
            // EAGAIN, so complete it off the loop.
            let dup = match dup_fd.try_clone() {
                Ok(d) => d,
                Err(_) => return BatchStep::Stop(libc::EIO),
            };
            return BatchStep::Done(complete_batch_entry(
                dup, m, flags, 0, notif_fd, notif_id, notif_pid, msglen_addr, 0,
            ));
        }
        return BatchStep::Stop(libc::EAGAIN);
    }
    BatchStep::Stop(err)
}
