// Network policy enforcement via seccomp notification: connect/sendto/
// sendmsg/sendmmsg are intercepted and either passed through, denied, or
// performed on-behalf against a copy of the child's arguments.
//
// The module is organized around three phases, each enforced by a boundary:
//
//   materialize  parse phase: every byte-level reader of child-controlled
//                memory; produces owned values (ChildMsghdr, MaterializedMsg)
//                so later phases never re-read child state (TOCTOU-safe).
//   verdict      decide phase: pure policy verdicts over materialized values;
//                no I/O, no locks, unit-testable.
//   send_engine  execute phase: the only code that performs sends, including
//                the blocking/defer state machine for the notification loop.
//
// The per-syscall handlers chain those phases:
//
//   connect      IP connect (verdict + HTTP-ACL redirect / port-remap plan).
//   send         IP sendto/sendmsg/sendmmsg.
//   unix         the named AF_UNIX gate shared by connect and send.
//   rules        --net-allow/--net-deny parsing, DNS resolution, /etc/hosts.
//
// This file keeps the socket probes and the handle_net dispatch.

use std::os::unix::io::RawFd;
use std::sync::Arc;

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;

mod connect;
pub(crate) mod materialize;
mod rules;
mod send;
mod send_engine;
mod unix;
mod verdict;

// `network` is pub(crate), so this re-export is the crate-internal path for
// the rule types. The two resolved-set types are named only in re-exported
// signatures (callers bind them by inference), which trips unused_imports.
#[allow(unused_imports)]
pub use rules::{
    compose_virtual_etc_hosts, resolve_net_allow, resolve_net_deny, IpCidr, NetAllow, NetDeny,
    NetRule, NetTarget, Protocol, ResolvedNetAllow, ResolvedNetAllowSet, ResolvedNetDenySet,
};

use connect::connect_on_behalf;
use send::{sendmmsg_on_behalf, sendmsg_on_behalf, sendto_on_behalf};

/// Largest sockaddr length we copy from the child when gating a `connect`/
/// `sendto`/`sendmsg` destination. The seccomp-notify trap fires at syscall
/// entry, *before* the kernel's own `addrlen > sizeof(sockaddr_storage)`
/// (`EINVAL`) check, so a child can pass `addr_len`/`msg_namelen` up to
/// `u32::MAX`. Reading that verbatim into `vec![0u8; len]` would let the child
/// force a multi-GiB supervisor allocation (OOM / alloc-abort of the monitor)
/// for an address that is at most this many bytes. Every legitimate sockaddr
/// fits in `sizeof(sockaddr_storage)`, so a larger length is rejected before the
/// read (see [`read_sockaddr`]).
const MAX_SOCKADDR_LEN: usize = std::mem::size_of::<libc::sockaddr_storage>();

/// Copy a sockaddr from child memory, rejecting an oversized length *before* the
/// allocation. `len` is child-controlled (`addr_len` / `msg_namelen`, a `u32`),
/// and the trap fires before the kernel's `addrlen > sizeof(sockaddr_storage)`
/// check, so an uncapped read would let the child force a multi-GiB supervisor
/// allocation. A length larger than a `sockaddr_storage` cannot address a valid
/// sockaddr, so it fails closed with `EINVAL` (matching what the kernel would
/// return) rather than being silently truncated; a read fault maps to `EIO`.
pub(super) fn read_sockaddr(
    notif_fd: RawFd,
    id: u64,
    pid: u32,
    ptr: u64,
    len: usize,
) -> Result<Vec<u8>, i32> {
    if len > MAX_SOCKADDR_LEN {
        return Err(libc::EINVAL);
    }
    read_child_mem(notif_fd, id, pid, ptr, len).map_err(|_| libc::EIO)
}

// ============================================================
// query_socket_protocol — derive the rule Protocol from a fd via getsockopt
// ============================================================

/// Query `SO_PROTOCOL` on a dup'd socket fd to learn whether to route
/// the on-behalf check through the TCP, UDP, or ICMP policy.
///
/// Returns `None` for protocols sandlock does not gate via `net_allow`
/// (raw, SCTP, etc.) — the handler treats those as "no rule applies"
/// which collapses to the default-deny path.
pub(crate) fn query_socket_protocol(fd: RawFd) -> Option<Protocol> {
    let mut proto: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PROTOCOL,
            &mut proto as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    match proto {
        libc::IPPROTO_TCP => Some(Protocol::Tcp),
        libc::IPPROTO_UDP => Some(Protocol::Udp),
        // IPPROTO_ICMP and IPPROTO_ICMPV6 both route to the ICMP policy
        // (the policy doesn't distinguish IP versions; the rule's
        // resolved IP set already covers both via DNS).
        libc::IPPROTO_ICMP | libc::IPPROTO_ICMPV6 => Some(Protocol::Icmp),
        _ => None,
    }
}

/// True iff `fd` is an `AF_UNIX` socket, probed via `SO_DOMAIN`. `SCM_RIGHTS`
/// and `SCM_CREDENTIALS` are unix-only, so control rewriting/gating is applied
/// only to unix sockets — an IP socket's control (e.g. `IP_PKTINFO`) carries no
/// fds or credentials and passes through untouched.
fn socket_is_unix(fd: RawFd) -> bool {
    let mut domain: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            &mut domain as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    rc == 0 && domain == libc::AF_UNIX
}

// ============================================================
// handle_net — main handler for connect/sendto/sendmsg
// ============================================================

/// Handle network-related notifications (connect, sendto, sendmsg).
///
/// All three are handled on-behalf (TOCTOU-safe): the supervisor copies data
/// from child memory, validates the destination, duplicates the socket via
/// pidfd_getfd, and performs the syscall itself. The child's memory is never
/// re-read by the kernel after validation.
///
/// Continue safety (issue #27): the on-behalf paths don't return Continue
/// at all (they return ReturnValue/Errno after performing the syscall in
/// the supervisor). The Continue cases in this module are:
///   1. Non-IP families (AF_UNIX etc.) — the IP allowlist doesn't apply;
///      Landlock IPC scoping is the enforcement boundary.
///   2. Connected sockets with addr_ptr == 0 — the address was already
///      validated at connect time, so the kernel re-read of (nothing) is
///      moot.
///   3. The fall-through case below — only reachable if the BPF filter
///      mis-routes a syscall; the kernel handles it normally.
/// In sendmsg_on_behalf, the msghdr read failure path returns
/// Errno(EFAULT) rather than Continue: a racing thread that briefly
/// unmaps the msghdr could otherwise force a fall-through that lets the
/// kernel execute sendmsg without the allowlist check. Sub-buffer read
/// failures (sockaddr/iovec/control) already return Errno(EIO) and so
/// don't bypass the check either.
pub(crate) async fn handle_net(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    if nr == libc::SYS_connect {
        connect_on_behalf(notif, ctx, notif_fd).await
    } else if nr == libc::SYS_sendto {
        sendto_on_behalf(notif, ctx, notif_fd).await
    } else if nr == libc::SYS_sendmsg {
        sendmsg_on_behalf(notif, ctx, notif_fd).await
    } else if nr == libc::SYS_sendmmsg {
        sendmmsg_on_behalf(notif, ctx, notif_fd).await
    } else {
        NotifAction::Continue
    }
}

