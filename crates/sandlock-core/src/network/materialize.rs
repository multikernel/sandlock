// Parse phase: every byte-level reader of child-controlled memory.
//
// This module owns the sockaddr/msghdr/cmsg/iovec parsers and produces
// owned, validated values (MaterializedMsg) with no references to child
// state. Once a value leaves this module, TOCTOU is over: later phases
// never re-read child memory.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

use crate::seccomp::notif::read_child_mem;
use crate::sys::structs::{SeccompNotif, AF_INET, AF_INET6};

/// Maximum buffer size for sendto/sendmsg on-behalf operations (64 MiB).
/// Prevents a sandboxed process from triggering OOM in the supervisor.
pub(crate) const MAX_SEND_BUF: usize = 64 << 20;

/// Maximum ancillary (control) buffer we copy for an on-behalf `sendmsg`.
/// A control buffer larger than this fails closed with `EMSGSIZE` rather than
/// being silently truncated into a partial cmsg chain (`SCM_MAX_FD` is 253 fds
/// ≈ 1 KiB, so 16 KiB is far above any legitimate use while bounding supervisor
/// memory per trapped send).
const MAX_CONTROL_BUF: usize = 16 << 10;

// ============================================================
// parse_ip_from_sockaddr — parse IP from a sockaddr byte buffer
// ============================================================

/// Parse IP address from a sockaddr byte buffer.
/// Returns None for non-IP families (AF_UNIX etc.) — always allowed.
pub(crate) fn parse_ip_from_sockaddr(bytes: &[u8]) -> Option<IpAddr> {
    if bytes.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as u32;
    match family {
        f if f == AF_INET => {
            if bytes.len() < 8 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                bytes[4], bytes[5], bytes[6], bytes[7],
            )))
        }
        f if f == AF_INET6 => {
            if bytes.len() < 24 {
                return None;
            }
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&bytes[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(addr_bytes)))
        }
        _ => None,
    }
}

// ============================================================
// parse_port_from_sockaddr — parse TCP port from sockaddr bytes
// ============================================================

/// Parse TCP port from a sockaddr byte buffer.
/// Returns None for non-IP families (AF_UNIX etc.).
pub(crate) fn parse_port_from_sockaddr(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as u32;
    match family {
        f if f == AF_INET || f == AF_INET6 => {
            Some(u16::from_be_bytes([bytes[2], bytes[3]]))
        }
        _ => None,
    }
}

pub(crate) fn set_port_in_sockaddr(bytes: &mut [u8], port: u16) {
    if bytes.len() >= 4 {
        let port_bytes = port.to_be_bytes();
        bytes[2] = port_bytes[0];
        bytes[3] = port_bytes[1];
    }
}

/// Rewrite the `SCM_RIGHTS` file descriptors in a copied control buffer from
/// the child's fd numbers to supervisor fd numbers, rejecting identity cmsgs.
///
/// On-behalf sends run in the supervisor, so a control buffer copied verbatim
/// from the child carries fd numbers that are meaningless (or, worse, alias
/// unrelated files) in the supervisor. For every `SOL_SOCKET`/`SCM_RIGHTS`
/// message we `pidfd_getfd` each child fd into the supervisor and patch its
/// number in place. The returned `OwnedFd`s must stay alive until after
/// `sendmsg` (the kernel installs its own copies into the socket buffer during
/// the send), then drop to close the supervisor's copies.
///
/// `SCM_CREDENTIALS` is rejected with `EPERM`: on the on-behalf path the
/// *supervisor* is the syscall's sender, so forwarding the child's crafted
/// `pid/uid/gid` would either fail `EPERM` anyway (an unprivileged supervisor
/// can't assert them) or, for a privileged supervisor, let the child forge
/// credentials it could never send itself. Failing closed is the safe choice.
///
/// Errors: `EBADF` if a child fd can't be fetched (matching the kernel's own
/// error for a bad fd), `EPERM` for a credential cmsg, `EINVAL` for a malformed
/// cmsg header (too short or extending past the buffer) — all fail closed, none
/// sends a partial or forged control chain.
fn translate_scm_rights(child_pid: u32, control: &[u8]) -> Result<(Vec<u8>, Vec<OwnedFd>), i32> {
    // sizeof(struct cmsghdr) on LP64: cmsg_len(8) + cmsg_level(4) + cmsg_type(4).
    // CMSG_ALIGN(16) == 16, so cmsg data begins right after the header.
    const CMSG_HDR: usize = 16;
    const FD: usize = std::mem::size_of::<i32>();
    let mut out = control.to_vec();
    let mut held: Vec<OwnedFd> = Vec::new();
    let mut off = 0usize;
    while off + CMSG_HDR <= out.len() {
        let cmsg_len = usize::from_ne_bytes(out[off..off + 8].try_into().unwrap());
        let level = i32::from_ne_bytes(out[off + 8..off + 12].try_into().unwrap());
        let ctype = i32::from_ne_bytes(out[off + 12..off + 16].try_into().unwrap());
        // `cmsg_len` is child-controlled. Compare against the *remaining* space
        // (never `off + cmsg_len`, which could overflow `usize`). A header that
        // is too short or claims to run past the buffer is malformed — fail
        // closed, as the kernel would `EINVAL` it. `off <= out.len() - CMSG_HDR`
        // holds from the loop guard, so `out.len() - off` cannot underflow.
        if cmsg_len < CMSG_HDR || cmsg_len > out.len() - off {
            return Err(libc::EINVAL);
        }
        if level == libc::SOL_SOCKET {
            if ctype == libc::SCM_RIGHTS {
                let data_off = off + CMSG_HDR;
                let nfds = (cmsg_len - CMSG_HDR) / FD;
                for i in 0..nfds {
                    let p = data_off + i * FD;
                    let child_fd = i32::from_ne_bytes(out[p..p + FD].try_into().unwrap());
                    let sup_fd = crate::seccomp::notif::dup_fd_from_pid(child_pid, child_fd)
                        .map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF))?;
                    out[p..p + FD].copy_from_slice(&sup_fd.as_raw_fd().to_ne_bytes());
                    held.push(sup_fd);
                }
            } else if ctype == libc::SCM_CREDENTIALS {
                return Err(libc::EPERM);
            }
        }
        // Advance to CMSG_ALIGN(cmsg_len). `cmsg_len <= out.len() - off` bounds
        // the aligned add well under `usize::MAX`; each step is >= CMSG_HDR so
        // the loop always makes progress.
        off += (cmsg_len + 7) & !7;
    }
    Ok((out, held))
}

/// Copy (and, for a unix socket, translate) the control buffer of an on-behalf
/// send. Both sendmsg paths reach it through [`materialize_msg`].
///
/// Returns `(control_bytes, held_fds)` — the fds keep the translated
/// `SCM_RIGHTS` files open across the send. Fails closed: oversized control →
/// `EMSGSIZE`; unreadable control → `EIO` (never a silent send that drops the
/// caller's cmsgs). For a unix socket, `SCM_RIGHTS` fds are translated and
/// `SCM_CREDENTIALS` is rejected; a non-unix socket's control passes through
/// verbatim.
fn materialize_control(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    msg_control_ptr: u64,
    msg_controllen: u64,
    is_unix: bool,
) -> Result<(Option<Vec<u8>>, Vec<OwnedFd>), i32> {
    if msg_control_ptr == 0 || msg_controllen == 0 {
        return Ok((None, Vec::new()));
    }
    // Fail closed on an oversized control buffer instead of silently truncating
    // (which could drop SCM_RIGHTS fds or send a malformed tail).
    if msg_controllen as usize > MAX_CONTROL_BUF {
        return Err(libc::EMSGSIZE);
    }
    let raw = read_child_mem(notif_fd, notif.id, notif.pid, msg_control_ptr, msg_controllen as usize)
        .map_err(|_| libc::EIO)?;
    if is_unix {
        let (buf, fds) = translate_scm_rights(notif.pid, &raw)?;
        Ok((Some(buf), fds))
    } else {
        Ok((Some(raw), Vec::new()))
    }
}

/// Extract the filesystem path of a NAMED `AF_UNIX` connect target from a raw
/// `sockaddr`. Returns `None` for abstract sockets (`sun_path[0] == 0`),
/// unnamed sockets, or any non-`AF_UNIX` family (none of which the fs gate
/// applies to).
pub(crate) fn named_unix_socket_path(addr_bytes: &[u8]) -> Option<std::path::PathBuf> {
    // sockaddr_un layout: u16 sun_family, then sun_path. Need the family plus
    // at least one path byte.
    if addr_bytes.len() < 3 {
        return None;
    }
    let family = u16::from_ne_bytes([addr_bytes[0], addr_bytes[1]]);
    if family != libc::AF_UNIX as u16 {
        return None;
    }
    let sun_path = &addr_bytes[2..];
    if sun_path[0] == 0 {
        return None; // abstract namespace (Landlock scope handles it)
    }
    let end = sun_path.iter().position(|&b| b == 0).unwrap_or(sun_path.len());
    let raw = &sun_path[..end];
    if raw.is_empty() {
        return None;
    }
    std::str::from_utf8(raw).ok().map(std::path::PathBuf::from)
}

/// `struct msghdr` size on LP64 Linux (x86_64 / aarch64 / riscv64): four
/// 8-byte pointer/length fields, one (u32 + pad) `msg_namelen`, and the
/// trailing (i32 + pad) `msg_flags` = 56 bytes.
pub(crate) const MSGHDR_SIZE: usize = 56;

/// One `struct msghdr` copied out of child memory. The single place the LP64
/// field offsets are known; every consumer of a child msghdr goes through
/// [`ChildMsghdr::read`] instead of hand-indexing raw bytes. (`msg_flags` is
/// output-only on the send side, so it is not carried.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChildMsghdr {
    pub(crate) name_ptr: u64,
    pub(crate) namelen: u32,
    pub(crate) iov_ptr: u64,
    pub(crate) iovlen: u64,
    pub(crate) control_ptr: u64,
    pub(crate) controllen: u64,
}

impl ChildMsghdr {
    /// Parse a raw msghdr image. `None` if the buffer is short.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MSGHDR_SIZE {
            return None;
        }
        Some(ChildMsghdr {
            name_ptr: u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
            namelen: u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
            iov_ptr: u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
            iovlen: u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
            control_ptr: u64::from_ne_bytes(bytes[32..40].try_into().unwrap()),
            controllen: u64::from_ne_bytes(bytes[40..48].try_into().unwrap()),
        })
    }

    /// Copy one msghdr out of child memory. `EFAULT` on an unreadable or
    /// short read, matching the kernel's errno for a bad `msghdr` pointer.
    pub(crate) fn read(notif: &SeccompNotif, notif_fd: RawFd, ptr: u64) -> Result<Self, i32> {
        match read_child_mem(notif_fd, notif.id, notif.pid, ptr, MSGHDR_SIZE) {
            Ok(b) => Self::parse(&b).ok_or(libc::EFAULT),
            Err(_) => Err(libc::EFAULT),
        }
    }

    /// True when the message carries no destination (connected-socket send):
    /// a null or zero-length `msg_name`.
    pub(crate) fn connected(&self) -> bool {
        self.name_ptr == 0 || self.namelen == 0
    }
}

/// `struct mmsghdr` on LP64: the 56-byte msghdr + 4-byte `msg_len` result +
/// 4 bytes tail padding = 64 bytes, `msg_len` at offset 56.
const MMSGHDR_SIZE: usize = 64;
const MSG_LEN_OFFSET: usize = 56;

/// Address of `sendmmsg` entry `i` in the child's `msgvec` array. The entry's
/// `msghdr` is the first field of `struct mmsghdr`, so this address is also
/// what [`ChildMsghdr::read`] takes for the entry.
pub(crate) fn mmsg_entry_ptr(msgvec_ptr: u64, i: usize) -> u64 {
    msgvec_ptr + (i * MMSGHDR_SIZE) as u64
}

/// Address of the `msg_len` result field inside the entry at `entry_ptr`.
pub(crate) fn mmsg_msglen_addr(entry_ptr: u64) -> u64 {
    entry_ptr + MSG_LEN_OFFSET as u64
}

/// Materialize phase for one msghdr: flatten the iovec payload and copy (and,
/// for a unix socket, translate) the control buffer, producing an owned
/// [`MaterializedMsg`] with no references to child state. `addr` is the
/// already-validated destination bytes (empty = connected send); `pinned`
/// keeps a named-unix target inode alive for the send's lifetime.
pub(crate) fn materialize_msg(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    hdr: &ChildMsghdr,
    addr: Vec<u8>,
    translate_unix_control: bool,
    pinned: Option<OwnedFd>,
) -> Result<MaterializedMsg, i32> {
    let iovlen = (hdr.iovlen as usize).min(1024);
    let iov_bytes = read_child_mem(notif_fd, notif.id, notif.pid, hdr.iov_ptr, iovlen * 16)
        .map_err(|_| libc::EIO)?;
    let data = flatten_iovecs(notif, notif_fd, &iov_bytes, iovlen)?;
    let (control, scm_fds) = materialize_control(
        notif,
        notif_fd,
        hdr.control_ptr,
        hdr.controllen,
        translate_unix_control,
    )?;
    Ok(MaterializedMsg {
        data,
        control,
        addr,
        _scm_fds: scm_fds,
        _pinned: pinned,
    })
}

/// A fully-materialized on-behalf send. Owns the (flattened) iovec payload, the
/// translated control buffer (with its `SCM_RIGHTS` fds and any named-unix inode
/// pin kept alive), and the destination sockaddr (empty = connected). Owning
/// everything lets the send be retried — from a byte offset, on a deferred
/// worker — without borrowing supervisor state, so a blocked send can leave the
/// sequential notification loop while still delivering the whole message.
pub(crate) struct MaterializedMsg {
    pub(crate) data: Vec<u8>,
    pub(crate) control: Option<Vec<u8>>,
    pub(crate) addr: Vec<u8>,
    pub(crate) _scm_fds: Vec<OwnedFd>,
    pub(crate) _pinned: Option<OwnedFd>,
}

/// Read a child's iovec array (`iov_bytes` = the raw `struct iovec[]`) and
/// concatenate the referenced buffers into one owned payload, capped at
/// `MAX_SEND_BUF` total so a hostile child can't OOM the supervisor. A null
/// base or zero length contributes nothing (matching the prior per-iovec copy).
fn flatten_iovecs(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    iov_bytes: &[u8],
    iovlen: usize,
) -> Result<Vec<u8>, i32> {
    let mut data: Vec<u8> = Vec::new();
    for i in 0..iovlen {
        let off = i * 16;
        if off + 16 > iov_bytes.len() {
            break;
        }
        let base = u64::from_ne_bytes(iov_bytes[off..off + 8].try_into().unwrap());
        let len = u64::from_ne_bytes(iov_bytes[off + 8..off + 16].try_into().unwrap()) as usize;
        if base == 0 || len == 0 {
            continue;
        }
        if len > MAX_SEND_BUF || data.len().saturating_add(len) > MAX_SEND_BUF {
            return Err(libc::EMSGSIZE);
        }
        data.extend_from_slice(
            &read_child_mem(notif_fd, notif.id, notif.pid, base, len).map_err(|_| libc::EIO)?,
        );
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- translate_scm_rights tests (control-buffer parsing, child-controlled) ---

    fn cmsg_hdr(cmsg_len: usize, level: i32, ctype: i32) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[0..8].copy_from_slice(&cmsg_len.to_ne_bytes());
        b[8..12].copy_from_slice(&level.to_ne_bytes());
        b[12..16].copy_from_slice(&ctype.to_ne_bytes());
        b
    }

    #[test]
    fn scm_rights_rejects_overflowing_cmsg_len() {
        // A child-crafted cmsg_len near usize::MAX must fail closed (EINVAL),
        // never overflow-panic (debug) or wrap past the bounds check (release).
        let buf = cmsg_hdr(usize::MAX - 7, libc::SOL_SOCKET, libc::SCM_RIGHTS);
        assert_eq!(translate_scm_rights(0, &buf).map(drop), Err(libc::EINVAL));
    }

    #[test]
    fn scm_rights_rejects_short_header() {
        let buf = cmsg_hdr(8, libc::SOL_SOCKET, libc::SCM_RIGHTS); // < CMSG_HDR (16)
        assert_eq!(translate_scm_rights(0, &buf).map(drop), Err(libc::EINVAL));
    }

    #[test]
    fn scm_rights_rejects_cmsg_running_past_buffer() {
        let buf = cmsg_hdr(17, libc::SOL_SOCKET, libc::SCM_RIGHTS); // claims 17, has 16
        assert_eq!(translate_scm_rights(0, &buf).map(drop), Err(libc::EINVAL));
    }

    #[test]
    fn scm_rights_rejects_credentials() {
        // Identity ancillary data on the on-behalf path must fail closed, not be
        // forwarded with the child's crafted pid/uid/gid.
        let buf = cmsg_hdr(16, libc::SOL_SOCKET, libc::SCM_CREDENTIALS);
        assert_eq!(translate_scm_rights(0, &buf).map(drop), Err(libc::EPERM));
    }

    #[test]
    fn scm_rights_passes_through_empty_and_non_socket_cmsg() {
        // Empty control → no-op. A non-SOL_SOCKET cmsg (e.g. an IP-level control)
        // passes through byte-for-byte with no fetched fds.
        let (out, fds) = translate_scm_rights(0, &[]).unwrap();
        assert!(out.is_empty() && fds.is_empty());

        let buf = cmsg_hdr(16, libc::IPPROTO_IP, 2 /* IP_TTL-ish */);
        let (out, fds) = translate_scm_rights(0, &buf).unwrap();
        assert_eq!(out, buf);
        assert!(fds.is_empty());
    }

    // --- ChildMsghdr tests (LP64 msghdr layout, child-controlled) ---

    #[test]
    fn child_msghdr_parses_lp64_fields() {
        let mut b = vec![0u8; MSGHDR_SIZE];
        b[0..8].copy_from_slice(&0x1111u64.to_ne_bytes());
        b[8..12].copy_from_slice(&7u32.to_ne_bytes());
        b[16..24].copy_from_slice(&0x2222u64.to_ne_bytes());
        b[24..32].copy_from_slice(&3u64.to_ne_bytes());
        b[32..40].copy_from_slice(&0x3333u64.to_ne_bytes());
        b[40..48].copy_from_slice(&64u64.to_ne_bytes());
        let h = ChildMsghdr::parse(&b).unwrap();
        assert_eq!(
            (h.name_ptr, h.namelen, h.iov_ptr, h.iovlen, h.control_ptr, h.controllen),
            (0x1111, 7, 0x2222, 3, 0x3333, 64)
        );
        assert!(!h.connected());
    }

    #[test]
    fn child_msghdr_rejects_short_buffer() {
        assert!(ChildMsghdr::parse(&[0u8; MSGHDR_SIZE - 1]).is_none());
    }

    #[test]
    fn child_msghdr_connected_on_null_or_empty_name() {
        // Null msg_name.
        let b = vec![0u8; MSGHDR_SIZE];
        assert!(ChildMsghdr::parse(&b).unwrap().connected());
        // Non-null msg_name with zero msg_namelen.
        let mut b2 = vec![0u8; MSGHDR_SIZE];
        b2[0..8].copy_from_slice(&0x1111u64.to_ne_bytes());
        assert!(ChildMsghdr::parse(&b2).unwrap().connected());
    }

    #[test]
    fn mmsg_addressing_helpers() {
        assert_eq!(mmsg_entry_ptr(0x1000, 0), 0x1000);
        assert_eq!(mmsg_entry_ptr(0x1000, 2), 0x1000 + 2 * MMSGHDR_SIZE as u64);
        assert_eq!(mmsg_msglen_addr(0x1000), 0x1000 + MSG_LEN_OFFSET as u64);
    }
}
