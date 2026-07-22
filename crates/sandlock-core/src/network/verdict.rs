// Decide phase: policy verdicts over already-materialized values.
//
// Nothing in this module reads child memory: inputs are values the parse
// phase produced (destination IP/port, resolved socket paths) plus
// supervisor-owned policy state. That makes each decision unit-testable and
// structurally incapable of re-reading child state after validation.

use std::net::IpAddr;
use std::sync::Arc;

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::NetworkPolicy;
use crate::sys::structs::ECONNREFUSED;

use super::Protocol;

/// Verdict for one validated IP destination against the effective policy.
/// Pure: no I/O, no locks.
///
/// `ECONNREFUSED` covers both a policy deny and an unparseable port (fail
/// closed), matching the errno contract of the connect and send handlers.
/// For ICMP rules every per-IP entry is `PortAllow::Any`, so the port arg
/// (typically 0 or the ICMP id) is functionally ignored: IP is what matters.
pub(crate) fn destination_verdict(
    effective: &NetworkPolicy,
    ip: IpAddr,
    port: Option<u16>,
) -> Result<(), i32> {
    if matches!(effective, NetworkPolicy::Unrestricted) {
        // No rules for this protocol's wildcard: Landlock (TCP only) or the
        // protocol's wildcard rule covers it; no additional check here.
        return Ok(());
    }
    match port {
        Some(p) if effective.allows(ip, p) => Ok(()),
        _ => Err(ECONNREFUSED),
    }
}

/// Resolve the effective per-protocol policy for `pid` and apply
/// [`destination_verdict`]. Shared by the sendto and sendmsg handlers;
/// connect keeps its own `ns` borrow alive for HTTP-ACL and port-remap
/// reads, so it calls [`destination_verdict`] directly.
pub(crate) async fn check_ip_destination(
    ctx: &Arc<SupervisorCtx>,
    pid: u32,
    protocol: Protocol,
    ip: IpAddr,
    port: Option<u16>,
) -> Result<(), i32> {
    let ns = ctx.network.lock().await;
    let live_policy = {
        let pfs = ctx.policy_fn.lock().await;
        pfs.live_policy.clone()
    };
    let effective = ns.effective_network_policy(pid, protocol, live_policy.as_ref());
    drop(ns);
    destination_verdict(&effective, ip, port)
}

/// True if `real` (an already-canonical path) is at or under any of `prefixes`,
/// canonicalizing each prefix so a symlinked grant path still matches. Touches
/// only the supervisor's own view of the grant paths, never child state.
pub(crate) fn real_path_under_any(real: &std::path::Path, prefixes: &[std::path::PathBuf]) -> bool {
    prefixes.iter().any(|p| {
        let canon = std::fs::canonicalize(p);
        real.starts_with(canon.as_deref().unwrap_or(p))
    })
}

/// True if `path`, lexically normalized (`.`/`..` resolved without touching the
/// filesystem), is at or under any of the granted `prefixes`. Mirrors the
/// prefix matching the chroot fs enforcement uses.
pub(crate) fn path_under_any(path: &std::path::Path, prefixes: &[std::path::PathBuf]) -> bool {
    let norm = crate::chroot::resolve::confine(&path.to_string_lossy());
    prefixes.iter().any(|p| norm.starts_with(p))
}

/// The shape of a non-IP destination sockaddr, keyed on its ADDRESS FAMILY
/// first. Produced by `materialize::classify_dest_shape` from the copied
/// address bytes.
///
/// The family is the load-bearing distinction. An abstract `AF_UNIX` address
/// and an `AF_NETLINK` address both yield no pathname, but they are not the
/// same case and must not share an arm: the first has to fail closed (see
/// [`SendPath::Reject`]), the second is a legitimate message on a unix socket
/// (see [`SendPath::RawDestOnBehalf`]).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DestShape {
    /// `sa_family == AF_UNIX` with a pathname `sun_path` the supervisor can
    /// re-resolve in the child's root view.
    UnixNamed(std::path::PathBuf),
    /// `sa_family == AF_UNIX` with no usable pathname: an ABSTRACT address
    /// (`sun_path[0] == 0`), an unnamed one, a non-UTF-8 `sun_path`, or a
    /// buffer too short to carry a family at all.
    UnixNoPath,
    /// `sa_family != AF_UNIX`. Reached here only for families
    /// `parse_ip_from_sockaddr` does not handle: `AF_NETLINK`, `AF_PACKET`,
    /// `AF_VSOCK`, ...
    NotUnix,
}

/// The send path selected for one message, from the already-parsed destination
/// shape and the *stable* socket domain. Pure: the caller supplies whether the
/// message is connected, the parsed IP (if any), whether the pinned socket is
/// `AF_UNIX`, and the destination's [`DestShape`], so the decision is
/// unit-testable and cannot re-read child state.
///
/// Every non-`Reject` arm sends on-behalf on the pinned fd rather than returning
/// `Continue`: gating on the transient address family and Continuing would let a
/// racing `dup2(inet_sock, sockfd)` + `msg_name` swap ride out on the kernel's
/// re-read and reach a denied IP. Sending on the pinned fd we already checked
/// closes that window.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SendPath {
    /// Connected socket: no per-message destination; send on-behalf, no check.
    ConnectedOnBehalf,
    /// IP destination: validate `ip` against the allowlist, then send on-behalf.
    IpChecked(IpAddr),
    /// Named (pathname) unix destination on a unix-domain socket: resolve the
    /// target in the CHILD's root view, pin its inode, and send on-behalf to
    /// `/proc/self/fd/<pin>` with no IP check (the kernel constrains a unix
    /// socket to unix peers, and we never Continue).
    NamedUnixOnBehalf,
    /// A non-`AF_UNIX` destination address on a unix-domain socket: send
    /// on-behalf on the pinned fd with the child's address bytes verbatim.
    ///
    /// This is the shape sandlock's own `NETLINK_ROUTE` virtualization
    /// produces: the child's "netlink socket" is one end of a
    /// `socketpair(AF_UNIX, SOCK_SEQPACKET)`, and glibc addresses it with a
    /// `sockaddr_nl`. There is no pathname to pin and none is needed — the
    /// socket is connected, so the kernel ignores `msg_name` entirely, and the
    /// fd was pinned before the domain was read, so no `dup2` can redirect the
    /// send. Refusing this shape instead would take every netlink query
    /// (`if_nameindex`, `getaddrinfo`'s `AI_ADDRCONFIG` probe, ...) offline for
    /// any sandbox that declares a destination policy.
    ///
    /// For any other non-unix family on a unix socket the kernel itself
    /// rejects the mismatch, so passing the bytes through is not a widening.
    RawDestOnBehalf,
    /// Everything else, failed closed with `EAFNOSUPPORT`:
    ///   - a non-IP address on a non-unix socket — the address-family-swap shape;
    ///   - an `AF_UNIX` destination we cannot pin in the child's context: an
    ///     ABSTRACT address, an empty one, or a non-UTF-8 `sun_path`.
    ///
    /// Abstract addresses fail closed because an on-behalf send is executed by
    /// the supervisor, which carries no Landlock domain, and
    /// `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` is enforced against the credentials
    /// of the process performing the send. Sending an abstract datagram
    /// on-behalf would therefore hand the child every abstract socket on the
    /// host, turning the child's scope boundary off whenever a destination
    /// policy is active. Continuing instead (so the child runs the send inside
    /// its own scoped domain) is not an option here — that is exactly the TOCTOU
    /// this path closes — so the send is refused.
    Reject,
}

/// Classify a send destination into the [`SendPath`] the handler should take.
///
/// `dest` is the destination's [`DestShape`] — attacker-controlled per message.
/// It is deliberately separate from `is_unix_socket` (the socket's stable
/// `SO_DOMAIN`), which cannot be swapped once the fd is pinned. Only a
/// unix-domain socket may take an on-behalf non-IP arm at all; what the
/// destination family then selects is *which* on-behalf arm.
pub(crate) fn classify_send_path(
    connected: bool,
    ip: Option<IpAddr>,
    is_unix_socket: bool,
    dest: &DestShape,
) -> SendPath {
    if connected {
        return SendPath::ConnectedOnBehalf;
    }
    match ip {
        Some(ip) => SendPath::IpChecked(ip),
        // A non-IP address on a non-unix socket is the address-family-swap
        // shape, whatever the address claims to be.
        None if !is_unix_socket => SendPath::Reject,
        None => match dest {
            DestShape::UnixNamed(_) => SendPath::NamedUnixOnBehalf,
            DestShape::UnixNoPath => SendPath::Reject,
            DestShape::NotUnix => SendPath::RawDestOnBehalf,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::notif::PortAllow;
    use std::collections::{HashMap, HashSet};

    fn allowlist_for(ip: &str, port: u16) -> NetworkPolicy {
        let mut per_ip = HashMap::new();
        per_ip.insert(
            ip.parse::<IpAddr>().unwrap(),
            PortAllow::Specific(HashSet::from([port])),
        );
        NetworkPolicy::AllowList {
            per_ip,
            cidrs: Vec::new(),
            any_ip_ports: HashSet::new(),
        }
    }

    #[test]
    fn verdict_unrestricted_allows_everything() {
        let p = NetworkPolicy::Unrestricted;
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(destination_verdict(&p, ip, Some(80)), Ok(()));
        // Even an unparseable port is fine when nothing restricts the protocol.
        assert_eq!(destination_verdict(&p, ip, None), Ok(()));
    }

    #[test]
    fn verdict_allowlist_matches_ip_and_port() {
        let p = allowlist_for("10.0.0.1", 443);
        let allowed: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        assert_eq!(destination_verdict(&p, allowed, Some(443)), Ok(()));
        assert_eq!(destination_verdict(&p, allowed, Some(80)), Err(ECONNREFUSED));
        assert_eq!(destination_verdict(&p, other, Some(443)), Err(ECONNREFUSED));
    }

    #[test]
    fn verdict_fails_closed_on_unparseable_port() {
        let p = allowlist_for("10.0.0.1", 443);
        let allowed: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(destination_verdict(&p, allowed, None), Err(ECONNREFUSED));
    }

    fn named(p: &str) -> DestShape {
        DestShape::UnixNamed(std::path::PathBuf::from(p))
    }

    #[test]
    fn send_path_connected_never_checks_address() {
        // A connected socket carries no per-message destination; the parsed
        // address and socket domain are irrelevant.
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            classify_send_path(true, Some(ip), false, &DestShape::NotUnix),
            SendPath::ConnectedOnBehalf
        );
        assert_eq!(
            classify_send_path(true, None, true, &DestShape::UnixNoPath),
            SendPath::ConnectedOnBehalf
        );
    }

    #[test]
    fn send_path_ip_destination_is_checked() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            classify_send_path(false, Some(ip), false, &DestShape::NotUnix),
            SendPath::IpChecked(ip)
        );
        // Socket domain does not override a parsed IP destination.
        assert_eq!(
            classify_send_path(false, Some(ip), true, &DestShape::NotUnix),
            SendPath::IpChecked(ip)
        );
    }

    #[test]
    fn send_path_named_unix_destination_goes_on_behalf() {
        // A NAMED (pathname) address on a unix-domain socket is the one unix
        // datagram the supervisor can re-resolve in the child's root view: send
        // it on-behalf on the pinned fd (never Continue), so a raced fd/addr swap
        // cannot redirect it to a denied IP.
        assert_eq!(
            classify_send_path(false, None, true, &named("/run/svc.dgram")),
            SendPath::NamedUnixOnBehalf
        );
    }

    #[test]
    fn send_path_abstract_unix_destination_is_rejected() {
        // An abstract (or empty, or non-UTF-8) AF_UNIX address has no pathname
        // to pin. It must fail closed rather than be sent on-behalf — the
        // supervisor carries no Landlock domain, so an on-behalf abstract send
        // would escape the child's LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET.
        assert_eq!(
            classify_send_path(false, None, true, &DestShape::UnixNoPath),
            SendPath::Reject
        );
    }

    #[test]
    fn send_path_non_unix_destination_on_unix_socket_goes_on_behalf() {
        // A non-AF_UNIX address on a unix-domain socket is NOT the abstract
        // case and must not share its arm: it is what sandlock's own
        // NETLINK_ROUTE virtualization produces (child fd = one end of a
        // socketpair(AF_UNIX, SOCK_SEQPACKET), addressed with a sockaddr_nl).
        // Collapsing it into Reject takes every netlink query offline under a
        // destination policy, so this assertion is the deterministic witness
        // that the two no-pathname shapes stay apart.
        assert_eq!(
            classify_send_path(false, None, true, &DestShape::NotUnix),
            SendPath::RawDestOnBehalf
        );
    }

    #[test]
    fn send_path_non_ip_on_non_unix_socket_is_rejected() {
        // A non-IP address on a non-unix (IP) socket is the address-family-swap
        // shape; fail closed. Pre-fix logic returned Continue for this input, so
        // this assertion is the deterministic fail-without-fix witness. The
        // stable socket domain decides first: no destination shape rescues it.
        assert_eq!(
            classify_send_path(false, None, false, &DestShape::NotUnix),
            SendPath::Reject
        );
        assert_eq!(
            classify_send_path(false, None, false, &DestShape::UnixNoPath),
            SendPath::Reject
        );
        assert_eq!(
            classify_send_path(false, None, false, &named("/run/svc.dgram")),
            SendPath::Reject
        );
    }
}
