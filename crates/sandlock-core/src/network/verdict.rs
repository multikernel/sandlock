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

/// The send path selected for one message, from the already-parsed destination
/// shape and the *stable* socket domain. Pure: the caller supplies whether the
/// message is connected, the parsed IP (if any), whether the pinned socket is
/// `AF_UNIX`, and whether the destination is a NAMED (pathname) unix address, so
/// the decision is unit-testable and cannot re-read child state.
///
/// The named-unix arm sends on-behalf on the pinned fd rather than returning
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
    /// Everything else, failed closed with `EAFNOSUPPORT`:
    ///   - a non-IP address on a non-unix socket — the address-family-swap shape;
    ///   - a unix destination we cannot pin in the child's context: an ABSTRACT
    ///     address, an empty one, or a non-UTF-8 `sun_path`.
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
/// `named_unix_dest` is "the destination sockaddr is a pathname `AF_UNIX`
/// address" (i.e. `named_unix_socket_path` returned `Some`), which is precisely
/// the set of unix destinations the supervisor can re-resolve in the child's
/// root view and pin. It is deliberately separate from `is_unix_socket` (the
/// socket's stable `SO_DOMAIN`): the address is attacker-controlled per message,
/// the domain is not, and both must hold to send on-behalf.
pub(crate) fn classify_send_path(
    connected: bool,
    ip: Option<IpAddr>,
    is_unix_socket: bool,
    named_unix_dest: bool,
) -> SendPath {
    if connected {
        return SendPath::ConnectedOnBehalf;
    }
    match ip {
        Some(ip) => SendPath::IpChecked(ip),
        None if is_unix_socket && named_unix_dest => SendPath::NamedUnixOnBehalf,
        None => SendPath::Reject,
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

    #[test]
    fn send_path_connected_never_checks_address() {
        // A connected socket carries no per-message destination; the parsed
        // address and socket domain are irrelevant.
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            classify_send_path(true, Some(ip), false, false),
            SendPath::ConnectedOnBehalf
        );
        assert_eq!(
            classify_send_path(true, None, true, false),
            SendPath::ConnectedOnBehalf
        );
    }

    #[test]
    fn send_path_ip_destination_is_checked() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            classify_send_path(false, Some(ip), false, false),
            SendPath::IpChecked(ip)
        );
        // Socket domain does not override a parsed IP destination.
        assert_eq!(
            classify_send_path(false, Some(ip), true, false),
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
            classify_send_path(false, None, true, true),
            SendPath::NamedUnixOnBehalf
        );
    }

    #[test]
    fn send_path_abstract_unix_destination_is_rejected() {
        // An abstract (or empty, or non-UTF-8) unix address has no pathname to
        // pin: `named_unix_socket_path` returns None, so `named_unix_dest` is
        // false. It must fail closed rather than be sent on-behalf — the
        // supervisor carries no Landlock domain, so an on-behalf abstract send
        // would escape the child's LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET.
        assert_eq!(classify_send_path(false, None, true, false), SendPath::Reject);
    }

    #[test]
    fn send_path_non_ip_on_non_unix_socket_is_rejected() {
        // A non-IP address on a non-unix (IP) socket is the address-family-swap
        // shape; fail closed. Pre-fix logic returned Continue for this input, so
        // this assertion is the deterministic fail-without-fix witness.
        assert_eq!(classify_send_path(false, None, false, false), SendPath::Reject);
        // A pathname address does not rescue a non-unix socket: the stable
        // domain decides, and only both together take the on-behalf arm.
        assert_eq!(classify_send_path(false, None, false, true), SendPath::Reject);
    }
}
