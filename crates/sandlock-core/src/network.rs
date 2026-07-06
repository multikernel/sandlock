// Network policy and control handlers — IP allowlist enforcement via seccomp notification.
//
// Intercepts connect/sendto/sendmsg syscalls, extracts the destination IP from
// the child's memory, and checks it against an allowlist of resolved IPs.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::SandboxError;
use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction};
use crate::sys::structs::{SeccompNotif, AF_INET, AF_INET6, ECONNREFUSED};

/// Maximum buffer size for sendto/sendmsg on-behalf operations (64 MiB).
/// Prevents a sandboxed process from triggering OOM in the supervisor.
const MAX_SEND_BUF: usize = 64 << 20;

/// Maximum ancillary (control) buffer we copy for an on-behalf `sendmsg`.
/// A control buffer larger than this fails closed with `EMSGSIZE` rather than
/// being silently truncated into a partial cmsg chain (`SCM_MAX_FD` is 253 fds
/// ≈ 1 KiB, so 16 KiB is far above any legitimate use while bounding supervisor
/// memory per trapped send).
const MAX_CONTROL_BUF: usize = 16 << 10;

/// An IPv4 or IPv6 address with a prefix length, used by `--net-deny`
/// to match destination IPs by exact address (`/32`, `/128`) or by range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpCidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl IpCidr {
    /// Parse `addr` or `addr/prefix`. A bare address becomes a host route
    /// (`/32` for IPv4, `/128` for IPv6). Hostnames are rejected: the
    /// address part must parse as a literal IP.
    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        let (addr_str, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let len: u8 = p.parse().map_err(|_| {
                    SandboxError::Invalid(format!("invalid prefix length in `{}`", s))
                })?;
                (a, Some(len))
            }
            None => (s, None),
        };
        let addr: IpAddr = addr_str.parse().map_err(|_| {
            SandboxError::Invalid(format!("`{}` is not a valid IP address", s))
        })?;
        let max = match addr {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        let prefix_len = prefix.unwrap_or(max);
        if prefix_len > max {
            return Err(SandboxError::Invalid(format!(
                "prefix /{} too large for {} in `{}`",
                prefix_len,
                if max == 32 { "IPv4" } else { "IPv6" },
                s
            )));
        }
        Ok(IpCidr { addr, prefix_len })
    }

    /// True iff this CIDR is a single host (`/32` IPv4 or `/128` IPv6),
    /// i.e. it came from a bare IP literal rather than a range.
    pub fn is_single_host(&self) -> bool {
        match self.addr {
            IpAddr::V4(_) => self.prefix_len == 32,
            IpAddr::V6(_) => self.prefix_len == 128,
        }
    }

    /// True iff `ip` falls within this network. Different address
    /// families never match.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix_len);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix_len);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpCidr {
    /// A single host renders as the bare address (`1.2.3.4`, `::1`); a
    /// range keeps its prefix (`10.0.0.0/8`). Inverse of [`IpCidr::parse`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_single_host() {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix_len)
        }
    }
}

/// What a `--net-allow` / `--net-deny` rule targets at the IP layer.
///
/// `Cidr` covers both a bare IP literal (stored as a `/32` or `/128`) and
/// an explicit CIDR range. `Host` is a hostname resolved via DNS at sandbox
/// start; it is only produced for `--net-allow` (deny rejects hostnames).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetTarget {
    /// Any destination IP (the `:port` / `*:port` / `*` form).
    AnyIp,
    /// A literal IP or CIDR range. Matched by containment, no DNS.
    Cidr(IpCidr),
    /// A hostname, resolved to IPs at sandbox start (allow-only).
    Host(String),
}

/// A single `--net-allow` / `--net-deny` rule. Both flags share this
/// representation and the same grammar; they differ only in whether
/// hostnames are accepted (`--net-deny` rejects them) and in how the
/// resolved rule is enforced (allowlist vs denylist).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetRule {
    /// L4 protocol this rule applies to.
    #[serde(default = "default_protocol_tcp")]
    pub protocol: Protocol,
    /// What the rule targets at the IP layer.
    pub target: NetTarget,
    /// Permitted/denied ports. Empty when `all_ports` is true and always
    /// empty for `Protocol::Icmp`.
    pub ports: Vec<u16>,
    /// "Any port" (bare target with no `:port`, or the `*` port token).
    #[serde(default)]
    pub all_ports: bool,
}

/// `--net-allow` and `--net-deny` rules are the same shape; the aliases
/// document intent at call sites and field declarations.
pub type NetAllow = NetRule;
pub type NetDeny = NetRule;

fn default_protocol_tcp() -> Protocol {
    Protocol::Tcp
}

impl NetRule {
    /// Parse a `--net-allow` spec into a rule. Hostnames are accepted and
    /// resolved to IPs at sandbox start. Grammar (shared with `--net-deny`):
    ///
    /// - `host` / `<ip>` / `<cidr>` / `*` -- all ports (port optional; `*`
    ///   targets any IP). TCP is the default scheme.
    /// - `host:<port[,port,...]>` / `<ip>:<port>` / `<cidr>:*` / `:port`.
    /// - `[<ipv6|ipv6cidr>]:<port>` -- bracketed IPv6 with a port (a bare
    ///   `addr:port` string is itself a valid IPv6 address, so the port
    ///   form needs brackets).
    /// - `tcp://...` / `udp://...` / `icmp://...` schemes (icmp: no port).
    pub fn parse_allow(spec: &str) -> Result<NetRule, SandboxError> {
        Self::parse_spec(spec, "--net-allow", true)
    }

    /// Parse a `--net-deny` spec into a rule. Identical grammar to
    /// [`parse_allow`](Self::parse_allow), except hostnames are rejected
    /// (the target must be a literal IP/CIDR or `*`); use `--http-deny`
    /// for domain blocking.
    pub fn parse_deny(spec: &str) -> Result<NetDeny, SandboxError> {
        Self::parse_spec(spec, "--net-deny", false)
    }

    /// Shared grammar for both flags. `label` selects the error prefix and
    /// `allow_hosts` whether non-IP targets are accepted (allow) or
    /// rejected (deny).
    fn parse_spec(spec: &str, label: &str, allow_hosts: bool) -> Result<NetRule, SandboxError> {
        let (protocol, rest) = match spec.split_once("://") {
            Some((scheme, body)) => {
                let proto = Protocol::parse(scheme).ok_or_else(|| {
                    SandboxError::Invalid(format!(
                        "{}: unknown scheme `{}://` in `{}` (expected tcp, udp, icmp)",
                        label, scheme, spec
                    ))
                })?;
                (proto, body)
            }
            None => (Protocol::Tcp, spec),
        };

        // ICMP carries no port: the whole body is the target.
        if protocol == Protocol::Icmp {
            if rest.is_empty() {
                return Err(SandboxError::Invalid(format!(
                    "{}: icmp rule needs a host/IP or `*`, got `{}`",
                    label, spec
                )));
            }
            // Reject an explicit port. IPv6 literals/CIDRs also contain
            // `:`, so only flag a `:` that isn't part of a valid IP/CIDR.
            if rest != "*" && IpCidr::parse(rest).is_err() && rest.contains(':') {
                return Err(SandboxError::Invalid(format!(
                    "{}: icmp rule takes no port, got `{}`",
                    label, spec
                )));
            }
            return Ok(NetRule {
                protocol,
                target: parse_target(rest, label, allow_hosts)?,
                ports: Vec::new(),
                all_ports: true,
            });
        }

        // 1. Bracketed IPv6 with a port: `[addr]:ports`.
        if let Some(stripped) = rest.strip_prefix('[') {
            let (inside, port_part) = stripped.rsplit_once("]:").ok_or_else(|| {
                SandboxError::Invalid(format!("{}: malformed bracketed address in `{}`", label, spec))
            })?;
            let (ports, all_ports) = parse_ports(port_part, label, spec)?;
            return Ok(NetRule {
                protocol,
                target: NetTarget::Cidr(IpCidr::parse(inside)?),
                ports,
                all_ports,
            });
        }

        // An empty body must not silently mean "everything"; require an
        // explicit `*` for the any-IP target.
        if rest.is_empty() {
            return Err(SandboxError::Invalid(format!(
                "{}: empty rule in `{}` (use `*` for any host)",
                label, spec
            )));
        }

        // 2. Whole body is an IP/CIDR with no port -> all ports. Trying
        //    `IpCidr::parse` first is what makes bare IPv6 (`::1`) and IPv6
        //    CIDRs (`fc00::/7`) work despite containing colons.
        if let Ok(cidr) = IpCidr::parse(rest) {
            return Ok(NetRule {
                protocol,
                target: NetTarget::Cidr(cidr),
                ports: Vec::new(),
                all_ports: true,
            });
        }

        // 3. `target[:ports]` where target is an IP/CIDR, hostname, `*`, or
        //    empty. The port suffix is optional: a target with no `:port`
        //    covers all ports, mirroring the bare-target form above.
        let (host_part, port_part) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        let target = parse_target(host_part, label, allow_hosts)?;
        let (ports, all_ports) = match port_part {
            Some(p) => parse_ports(p, label, spec)?,
            None => (Vec::new(), true),
        };
        Ok(NetRule {
            protocol,
            target,
            ports,
            all_ports,
        })
    }
}

/// Parse a rule target: `*` / empty -> any IP, an IP/CIDR literal ->
/// `Cidr`, otherwise a hostname (`Host`) when `allow_hosts`, else an error.
fn parse_target(s: &str, label: &str, allow_hosts: bool) -> Result<NetTarget, SandboxError> {
    match s {
        "" | "*" => Ok(NetTarget::AnyIp),
        // A `/` signals CIDR intent: parse strictly so a bad prefix is a
        // clear error rather than being misread as a hostname.
        _ if s.contains('/') => Ok(NetTarget::Cidr(
            IpCidr::parse(s).map_err(|e| SandboxError::Invalid(format!("{}: {}", label, e)))?,
        )),
        _ => {
            if let Ok(cidr) = IpCidr::parse(s) {
                Ok(NetTarget::Cidr(cidr))
            } else if allow_hosts {
                Ok(NetTarget::Host(s.to_string()))
            } else {
                Err(SandboxError::Invalid(format!(
                    "{}: `{}` is not an IP or CIDR (hostnames are not allowed; \
                     use --http-deny for domains)",
                    label, s
                )))
            }
        }
    }
}

/// Parse a port suffix. `*` means all ports; mixing `*` with concrete
/// ports, port 0, and an empty list are all rejected.
fn parse_ports(s: &str, label: &str, full: &str) -> Result<(Vec<u16>, bool), SandboxError> {
    let mut ports = Vec::new();
    let mut saw_wildcard = false;
    for p in s.split(',') {
        let p = p.trim();
        if p == "*" {
            saw_wildcard = true;
            continue;
        }
        let n: u16 = p.parse().map_err(|_| {
            SandboxError::Invalid(format!("{}: invalid port `{}` in `{}`", label, p, full))
        })?;
        if n == 0 {
            return Err(SandboxError::Invalid(format!(
                "{}: port 0 is not valid in `{}`",
                label, full
            )));
        }
        ports.push(n);
    }
    if saw_wildcard && !ports.is_empty() {
        return Err(SandboxError::Invalid(format!(
            "{}: cannot mix `*` with concrete ports in `{}`",
            label, full
        )));
    }
    if !saw_wildcard && ports.is_empty() {
        return Err(SandboxError::Invalid(format!(
            "{}: at least one port required in `{}`",
            label, full
        )));
    }
    Ok((ports, saw_wildcard))
}

/// L4 protocol that a `NetAllow` rule applies to.
///
/// `Tcp` is the default if a rule has no scheme (the bare `host:port`
/// form). `Udp` and `Icmp` require an explicit scheme.
///
/// `Icmp` is the kernel's unprivileged ping socket
/// (`SOCK_DGRAM + IPPROTO_ICMP{,V6}`), gated by `ping_group_range` —
/// destinations are filterable per host. Sandlock does not expose raw
/// ICMP (`SOCK_RAW + IPPROTO_ICMP`): destination filtering at `sendto`
/// would lie because raw sockets let the agent craft the IP header,
/// and packet-crafting capabilities aren't part of the XOA threat
/// model. Workloads that genuinely need raw ICMP should run outside
/// sandlock or rely on the host's `ping_group_range` for the dgram
/// path instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Protocol {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            _ => None,
        }
    }
}

// ============================================================
// parse_ip_from_sockaddr — parse IP from a sockaddr byte buffer
// ============================================================

/// Parse IP address from a sockaddr byte buffer.
/// Returns None for non-IP families (AF_UNIX etc.) — always allowed.
fn parse_ip_from_sockaddr(bytes: &[u8]) -> Option<IpAddr> {
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
fn parse_port_from_sockaddr(bytes: &[u8]) -> Option<u16> {
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

fn set_port_in_sockaddr(bytes: &mut [u8], port: u16) {
    if bytes.len() >= 4 {
        let port_bytes = port.to_be_bytes();
        bytes[2] = port_bytes[0];
        bytes[3] = port_bytes[1];
    }
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

/// Copy (and, for a unix socket, translate) the control buffer of an on-behalf
/// send. Shared by `send_msghdr_on_behalf` and `send_named_unix_msghdr`.
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

// ============================================================
// connect_on_behalf — perform connect() on behalf of the child (TOCTOU-safe)
// ============================================================

/// Perform connect() on behalf of the child process (TOCTOU-safe).
///
/// 1. Copy sockaddr from child memory (our copy — immune to TOCTOU)
/// 2. Check IP against allowlist on our copy
/// 3. Duplicate child's socket fd via pidfd_getfd
/// 4. connect() in supervisor with our validated sockaddr
/// 5. Return result to child
async fn connect_on_behalf(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let args = &notif.data.args;
    let sockfd = args[0] as i32;
    let addr_ptr = args[1];
    let addr_len = args[2] as u32;

    // 1. Copy sockaddr from child memory
    let addr_bytes =
        match read_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, addr_len as usize) {
            Ok(b) => b,
            Err(_) => return NotifAction::Errno(libc::EIO),
        };

    // 2. Check destination against the per-protocol endpoint allowlist.
    // The dup we'd need anyway for the on-behalf connect doubles as
    // our SO_PROTOCOL probe — one pidfd_getfd, one getsockopt. The
    // per-protocol policy is keyed on whether the socket is TCP / UDP
    // / kernel ping (ICMP). Unknown protocol (raw, SCTP, etc.) fails
    // closed: the BPF should have prevented socket creation, so
    // reaching here with one is an unexpected case worth refusing.
    if let Some(ip) = parse_ip_from_sockaddr(&addr_bytes) {
        // Same invariant as the sendto/sendmsg handlers above: `connect()` is
        // trapped whenever the named-`AF_UNIX` gate is on (any fs grant), for
        // every address family, but with no network destination policy there
        // is nothing to enforce on an IP destination. Return it to the kernel
        // so the child's own Landlock `CONNECT_TCP` rules govern it — handling
        // it on-behalf in the unconfined supervisor would bypass that decision
        // (an empty `net_allow` deny-all would silently permit egress). See
        // `NotifPolicy::ip_connect_supervised`.
        if !ctx.policy.ip_connect_supervised(ip.is_loopback()) {
            return NotifAction::Continue;
        }
        let dest_port = parse_port_from_sockaddr(&addr_bytes);
        let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
            Ok(fd) => fd,
            Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
        };
        let protocol = match query_socket_protocol(dup_fd.as_raw_fd()) {
            Some(p) => p,
            None => return NotifAction::Errno(ECONNREFUSED),
        };
        let ns = ctx.network.lock().await;
        let live_policy = {
            let pfs = ctx.policy_fn.lock().await;
            pfs.live_policy.clone()
        };
        let effective = ns.effective_network_policy(notif.pid, protocol, live_policy.as_ref());
        match (effective, dest_port) {
            (crate::seccomp::notif::NetworkPolicy::Unrestricted, _) => {
                // No rules for this protocol's wildcard — Landlock (TCP
                // only) or the protocol's wildcard rule covers it; no
                // additional check here.
            }
            (policy, Some(p)) => {
                // For ICMP rules every per-IP entry is `PortAllow::Any`,
                // so the port arg from the sockaddr (typically 0 or the
                // ICMP id) is functionally ignored — IP is what matters.
                if !policy.allows(ip, p) {
                    return NotifAction::Errno(ECONNREFUSED);
                }
            }
            (_, None) => {
                // Couldn't parse port from sockaddr — fail closed.
                return NotifAction::Errno(ECONNREFUSED);
            }
        }
        // Check for HTTP ACL redirect
        let http_acl_addr = ns.http_acl_addr;
        let http_acl_intercept = dest_port.map_or(false, |p| ns.http_acl_ports.contains(&p));
        let http_acl_orig_dest = ns.http_acl_orig_dest.clone();
        let remapped_loopback_port = if ctx.policy.port_remap && ip.is_loopback() {
            dest_port.and_then(|p| ns.port_map.get_real(p))
        } else {
            None
        };

        drop(ns);

        // Determine the actual connect target (redirect HTTP/HTTPS to proxy)
        let mut redirected = false;
        let is_ipv6 = parse_ip_from_sockaddr(&addr_bytes)
            .map_or(false, |ip| ip.is_ipv6());
        let (mut connect_addr, connect_len) = if let Some(proxy_addr) = http_acl_addr {
            if http_acl_intercept {
                redirected = true;
                if is_ipv6 {
                    // IPv6 socket: redirect via IPv4-mapped IPv6 address
                    // (::ffff:127.0.0.1) so it connects to the IPv4 proxy.
                    let mut sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                    sa6.sin6_family = libc::AF_INET6 as u16;
                    sa6.sin6_port = proxy_addr.port().to_be();
                    // Build ::ffff:127.0.0.1
                    let mapped = std::net::Ipv6Addr::from(
                        match proxy_addr {
                            std::net::SocketAddr::V4(v4) => v4.ip().to_ipv6_mapped(),
                            std::net::SocketAddr::V6(v6) => *v6.ip(),
                        }
                    );
                    sa6.sin6_addr.s6_addr = mapped.octets();
                    let bytes = unsafe {
                        std::slice::from_raw_parts(
                            &sa6 as *const _ as *const u8,
                            std::mem::size_of::<libc::sockaddr_in6>(),
                        )
                    }
                    .to_vec();
                    (bytes, std::mem::size_of::<libc::sockaddr_in6>() as u32)
                } else {
                    // IPv4 socket: redirect directly.
                    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                    sa.sin_family = libc::AF_INET as u16;
                    sa.sin_port = proxy_addr.port().to_be();
                    match proxy_addr {
                        std::net::SocketAddr::V4(v4) => {
                            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                        }
                        std::net::SocketAddr::V6(_) => {
                            // Proxy always binds to 127.0.0.1
                            return NotifAction::Errno(libc::EAFNOSUPPORT);
                        }
                    }
                    let bytes = unsafe {
                        std::slice::from_raw_parts(
                            &sa as *const _ as *const u8,
                            std::mem::size_of::<libc::sockaddr_in>(),
                        )
                    }
                    .to_vec();
                    (bytes, std::mem::size_of::<libc::sockaddr_in>() as u32)
                }
            } else {
                (addr_bytes.clone(), addr_len)
            }
        } else {
            (addr_bytes.clone(), addr_len)
        };
        if !redirected {
            if let Some(real_port) = remapped_loopback_port {
                // The child sees virtual ports via getsockname(); connect
                // still has to target the real bound loopback port.
                set_port_in_sockaddr(&mut connect_addr, real_port);
            }
        }

        // (The supervisor-side dup is the same fd we already created
        // for the SO_PROTOCOL probe above — reuse it rather than
        // pidfd_getfd-ing a second time.)

        // 4. Record original dest IP *before* connect to prevent TOCTOU race:
        //    the proxy may receive the request before we write the mapping if
        //    we do it after connect(). We already have the original IP from
        //    addr_bytes (our immune copy).
        if redirected {
            if let Some(ref orig_dest_map) = http_acl_orig_dest {
                if let Some(orig_ip) = parse_ip_from_sockaddr(&addr_bytes) {
                    // Bind the socket so getsockname() returns the local addr
                    // the proxy will see as client_addr.
                    if is_ipv6 {
                        let mut bind_sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                        bind_sa6.sin6_family = libc::AF_INET6 as u16;
                        // port 0 + IN6ADDR_ANY = kernel picks ephemeral port
                        unsafe {
                            libc::bind(
                                dup_fd.as_raw_fd(),
                                &bind_sa6 as *const _ as *const libc::sockaddr,
                                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                            );
                        }
                        let mut local_sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                        let mut local_len: libc::socklen_t =
                            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
                        let gs_ret = unsafe {
                            libc::getsockname(
                                dup_fd.as_raw_fd(),
                                &mut local_sa6 as *mut _ as *mut libc::sockaddr,
                                &mut local_len,
                            )
                        };
                        if gs_ret == 0 {
                            let local_port = u16::from_be(local_sa6.sin6_port);
                            let local_ip = Ipv6Addr::from(local_sa6.sin6_addr.s6_addr);
                            let local_addr = std::net::SocketAddr::V6(
                                std::net::SocketAddrV6::new(local_ip, local_port, 0, 0),
                            );
                            if let Ok(mut map) = orig_dest_map.write() {
                                map.insert(local_addr, orig_ip);
                            }
                        }
                    } else {
                        let mut bind_sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                        bind_sa.sin_family = libc::AF_INET as u16;
                        // port 0 + INADDR_ANY = kernel picks ephemeral port
                        unsafe {
                            libc::bind(
                                dup_fd.as_raw_fd(),
                                &bind_sa as *const _ as *const libc::sockaddr,
                                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                            );
                        }
                        let mut local_sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                        let mut local_len: libc::socklen_t =
                            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                        let gs_ret = unsafe {
                            libc::getsockname(
                                dup_fd.as_raw_fd(),
                                &mut local_sa as *mut _ as *mut libc::sockaddr,
                                &mut local_len,
                            )
                        };
                        if gs_ret == 0 {
                            let local_port = u16::from_be(local_sa.sin_port);
                            let local_ip = Ipv4Addr::from(u32::from_be(local_sa.sin_addr.s_addr));
                            let local_addr = std::net::SocketAddr::V4(
                                std::net::SocketAddrV4::new(local_ip, local_port),
                            );
                            if let Ok(mut map) = orig_dest_map.write() {
                                map.insert(local_addr, orig_ip);
                            }
                        }
                    }
                }
            }
        }

        // 5. Perform connect in supervisor with our validated sockaddr
        let ret = unsafe {
            libc::connect(
                dup_fd.as_raw_fd(),
                connect_addr.as_ptr() as *const libc::sockaddr,
                connect_len as libc::socklen_t,
            )
        };

        // 6. Return result.
        // On failure, the stale orig_dest entry is harmless: the proxy never
        // sees this connection, and the entry will be cleaned up on the next
        // successful request from the same local address (or on shutdown).
        if ret == 0 {
            NotifAction::ReturnValue(0)
        } else {
            let errno = unsafe { *libc::__errno_location() };
            NotifAction::Errno(errno)
        }
        // dup_fd dropped here, closing supervisor's copy
    } else {
        // Non-IP family. A NAMED (pathname) AF_UNIX connect is a gap Landlock
        // cannot close (it has no access right for unix-socket connect), so a
        // netns-less sandbox could reach a host service socket and escape.
        // Connecting is a WRITE on the socket inode (kernel: unix_find_other ->
        // path_permission(MAY_WRITE)), so require the path to be covered by an
        // fs-write grant, mirroring the kernel's own DAC; otherwise deny with
        // EACCES. The decision is made on `addr_bytes` (our immune copy) and we
        // never return Continue on the deny path, so it is TOCTOU-safe.
        // Abstract sockets (no path) are handled by the Landlock abstract scope.
        match named_unix_socket_path(&addr_bytes) {
            Some(path) if ctx.policy.has_unix_fs_gate => {
                if ctx.policy.chroot_root.is_some() {
                    // Chroot mode: the child's paths are virtual, so a lexical
                    // check against the (virtual) write grants is consistent,
                    // and host socket paths are absent from the chroot view
                    // anyway. Deny unless under a write grant.
                    if path_under_any(&path, &ctx.policy.chroot_writable) {
                        NotifAction::Continue
                    } else {
                        NotifAction::Errno(libc::EACCES)
                    }
                } else {
                    // Non-chroot: resolve the symlink-followed real target and
                    // connect on-behalf to the pinned inode, so a symlink inside
                    // a granted dir cannot redirect to an ungranted socket.
                    connect_named_unix_on_behalf(
                        notif.pid,
                        sockfd,
                        &path,
                        &ctx.policy.chroot_writable,
                    )
                }
            }
            // Abstract/unnamed socket, non-AF_UNIX family, or gate disabled.
            _ => NotifAction::Continue,
        }
    }
}

/// Resolve a named unix socket `sun_path` to its real, symlink-followed inode
/// in the child's root view (`/proc/<pid>/root`) and verify that inode is under
/// an fs-write grant. On success returns a pinned `O_PATH` fd to that exact
/// inode; on failure returns the deny/refuse `NotifAction`. Callers must
/// operate on the pinned fd via `/proc/self/fd` so the checked inode is the one
/// acted on, immune to a path swap after the check (TOCTOU- and symlink-safe).
fn resolve_named_unix_target(
    child_pid: u32,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> Result<OwnedFd, NotifAction> {
    // Resolve in the child's mount/root view so its symlinks (not ours) decide
    // the target. `O_PATH` follows symlinks to the real socket inode and pins
    // it without performing any I/O on the socket.
    let proc_path = format!("/proc/{}/root{}", child_pid, sun_path.display());
    let c_proc = std::ffi::CString::new(proc_path)
        .map_err(|_| NotifAction::Errno(libc::EACCES))?;
    let pinned_raw = unsafe { libc::open(c_proc.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if pinned_raw < 0 {
        // Target missing or unreachable: refuse without leaking the reason.
        return Err(NotifAction::Errno(ECONNREFUSED));
    }
    let pinned = unsafe { OwnedFd::from_raw_fd(pinned_raw) };

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

/// On-behalf `connect()` for a NAMED `AF_UNIX` socket in non-chroot mode:
/// resolve+verify the target, then connect the child's socket to the pinned
/// inode through `/proc/self/fd`.
fn connect_named_unix_on_behalf(
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
fn sendto_named_unix_on_behalf(
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
    let addr = unsafe {
        std::slice::from_raw_parts(&sun as *const libc::sockaddr_un as *const u8, len as usize)
    }
    .to_vec();
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

/// True if `real` (an already-canonical path) is at or under any of `prefixes`,
/// canonicalizing each prefix so a symlinked grant path still matches.
fn real_path_under_any(real: &std::path::Path, prefixes: &[std::path::PathBuf]) -> bool {
    prefixes.iter().any(|p| {
        let canon = std::fs::canonicalize(p);
        real.starts_with(canon.as_deref().unwrap_or(p))
    })
}

/// Apply the named-unix fs gate to a `sendmsg()` whose `msg_name` may address a
/// unix socket. Returns `Some(action)` when the target is a named `AF_UNIX`
/// socket (handled here), or `None` to fall through to the IP path (connected
/// socket, IP family, abstract socket, or an unreadable header).
fn unix_sendmsg_gate(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
    sockfd: i32,
    msghdr_ptr: u64,
    flags: i32,
) -> Option<NotifAction> {
    let msghdr_bytes = read_child_mem(notif_fd, notif.id, notif.pid, msghdr_ptr, 56).ok()?;
    if msghdr_bytes.len() < 56 {
        return None;
    }
    let msg_name_ptr = u64::from_ne_bytes(msghdr_bytes[0..8].try_into().unwrap());
    if msg_name_ptr == 0 {
        return None; // connected socket: no address to gate
    }
    let msg_namelen = u32::from_ne_bytes(msghdr_bytes[8..12].try_into().unwrap());
    let addr_bytes =
        read_child_mem(notif_fd, notif.id, notif.pid, msg_name_ptr, msg_namelen as usize).ok()?;
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

    let msghdr_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, msghdr_ptr, 56) {
        Ok(b) if b.len() >= 56 => b,
        _ => return Err(libc::EFAULT),
    };
    let msg_iov_ptr = u64::from_ne_bytes(msghdr_bytes[16..24].try_into().unwrap());
    let msg_iovlen = u64::from_ne_bytes(msghdr_bytes[24..32].try_into().unwrap());
    let msg_control_ptr = u64::from_ne_bytes(msghdr_bytes[32..40].try_into().unwrap());
    let msg_controllen = u64::from_ne_bytes(msghdr_bytes[40..48].try_into().unwrap());

    let iovlen = (msg_iovlen as usize).min(1024);
    let iov_bytes = read_child_mem(notif_fd, notif.id, notif.pid, msg_iov_ptr, iovlen * 16)
        .map_err(|_| libc::EIO)?;
    let data = flatten_iovecs(notif, notif_fd, &iov_bytes, iovlen)?;
    // Named target is always AF_UNIX, so translate SCM_RIGHTS / reject creds.
    let (control_buf, scm_fds) =
        materialize_control(notif, notif_fd, msg_control_ptr, msg_controllen, true)?;

    let dup_fd = crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd)
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF))?;

    // The destination is the `/proc/self/fd/<pinned>` sockaddr; `pinned` must
    // stay open (and at the same fd number) for that path to resolve, so the
    // message keeps it alive. Copy the sockaddr bytes it currently encodes.
    let addr = unsafe {
        std::slice::from_raw_parts(&sun as *const libc::sockaddr_un as *const u8, sun_len as usize)
    }
    .to_vec();

    Ok((
        dup_fd,
        MaterializedMsg {
            data,
            control: control_buf,
            addr,
            _scm_fds: scm_fds,
            _pinned: Some(pinned),
        },
    ))
}

/// Read a `sendmmsg` entry's `msg_name` and return its NAMED `AF_UNIX` path, or
/// `None` for a connected (null-name), IP, or abstract entry. The entry's
/// `msghdr` is the first field of `struct mmsghdr`, so it begins at `entry_ptr`.
fn mmsg_entry_named_unix_path(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    entry_ptr: u64,
) -> Option<std::path::PathBuf> {
    let hdr = read_child_mem(notif_fd, notif.id, notif.pid, entry_ptr, 12).ok()?;
    if hdr.len() < 12 {
        return None;
    }
    let msg_name_ptr = u64::from_ne_bytes(hdr[0..8].try_into().unwrap());
    if msg_name_ptr == 0 {
        return None;
    }
    let msg_namelen = u32::from_ne_bytes(hdr[8..12].try_into().unwrap());
    let addr_bytes =
        read_child_mem(notif_fd, notif.id, notif.pid, msg_name_ptr, msg_namelen as usize).ok()?;
    named_unix_socket_path(&addr_bytes)
}

/// On-behalf `sendmmsg` for a batch containing NAMED `AF_UNIX` entries
/// (non-chroot). Each named-unix entry is resolved, verified, and sent to its
/// pinned inode; the loop stops at the first entry it cannot gate on-behalf
/// (connected/abstract) or that is denied, returning the count sent so far
/// (standard short-`sendmmsg` semantics). Never returns `Continue`, so a unix
/// entry cannot ride out via the binary whole-call passthrough.
fn sendmmsg_named_unix_on_behalf(
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
        let entry_ptr = msgvec_ptr + (i * MMSGHDR_SIZE) as u64;
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
        // Non-blocking per entry so a batch never occupies the notification loop;
        // the two cases that must leave the loop are deferred (see below).
        let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
        let ret = send_materialized_at(dup_fd.as_raw_fd(), &m, 0, flags | libc::MSG_DONTWAIT);
        if ret >= 0 {
            if blocking && (ret as usize) < m.data.len() {
                // Partial stream on a blocking socket: complete this entry off the
                // loop and report it, so a caller ignoring per-entry msg_len isn't
                // silently truncated.
                return complete_batch_entry(
                    dup_fd, m, flags, ret as usize, notif_fd, notif.id, notif.pid,
                    entry_ptr + MSG_LEN_OFFSET as u64, sent,
                );
            }
            let bytes = (ret as u32).to_ne_bytes();
            let _ = write_child_mem(
                notif_fd, notif.id, notif.pid, entry_ptr + MSG_LEN_OFFSET as u64, &bytes,
            );
            sent += 1;
        } else {
            let err = unsafe { *libc::__errno_location() };
            if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                if sent == 0 && blocking {
                    // Entry 0 would block entirely: a blocking socket never returns
                    // EAGAIN, so complete it off the loop.
                    return complete_batch_entry(
                        dup_fd, m, flags, 0, notif_fd, notif.id, notif.pid,
                        entry_ptr + MSG_LEN_OFFSET as u64, 0,
                    );
                }
                // i>0 with nothing sent is a contract-legal short count; a
                // non-blocking child at entry 0 gets EAGAIN.
                if sent == 0 {
                    first_errno = Some(libc::EAGAIN);
                }
                break;
            }
            first_errno = Some(err);
            break;
        }
    }
    if sent > 0 {
        NotifAction::ReturnValue(sent as i64)
    } else {
        NotifAction::Errno(first_errno.unwrap_or(libc::EACCES))
    }
}

/// Extract the filesystem path of a NAMED `AF_UNIX` connect target from a raw
/// `sockaddr`. Returns `None` for abstract sockets (`sun_path[0] == 0`),
/// unnamed sockets, or any non-`AF_UNIX` family (none of which the fs gate
/// applies to).
fn named_unix_socket_path(addr_bytes: &[u8]) -> Option<std::path::PathBuf> {
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

/// True if `path`, lexically normalized (`.`/`..` resolved without touching the
/// filesystem), is at or under any of the granted `prefixes`. Mirrors the
/// prefix matching the chroot fs enforcement uses.
fn path_under_any(path: &std::path::Path, prefixes: &[std::path::PathBuf]) -> bool {
    let norm = crate::chroot::resolve::confine(&path.to_string_lossy());
    prefixes.iter().any(|p| norm.starts_with(p))
}

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
async fn sendto_on_behalf(
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
        let ns = ctx.network.lock().await;
        let live_policy = {
            let pfs = ctx.policy_fn.lock().await;
            pfs.live_policy.clone()
        };
        let effective = ns.effective_network_policy(notif.pid, protocol, live_policy.as_ref());
        if !matches!(effective, crate::seccomp::notif::NetworkPolicy::Unrestricted) {
            match dest_port {
                Some(p) if !effective.allows(ip, p) => {
                    return NotifAction::Errno(ECONNREFUSED);
                }
                None => return NotifAction::Errno(ECONNREFUSED),
                Some(_) => {}
            }
        }
        drop(ns);

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
async fn sendmsg_on_behalf(
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
    let msghdr_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, msghdr_ptr, 56) {
        Ok(b) if b.len() >= 56 => b,
        _ => return PrescanResult::Errno(libc::EFAULT),
    };
    let msg_name_ptr = u64::from_ne_bytes(msghdr_bytes[0..8].try_into().unwrap());
    if msg_name_ptr == 0 {
        return PrescanResult::ContinueWholeCall;
    }
    let msg_namelen = u32::from_ne_bytes(msghdr_bytes[8..12].try_into().unwrap());
    let addr_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, msg_name_ptr, msg_namelen as usize) {
        Ok(b) => b,
        Err(_) => return PrescanResult::Errno(libc::EIO),
    };
    if parse_ip_from_sockaddr(&addr_bytes).is_none() {
        return PrescanResult::ContinueWholeCall;
    }
    PrescanResult::OnBehalf
}

/// A fully-materialized on-behalf send. Owns the (flattened) iovec payload, the
/// translated control buffer (with its `SCM_RIGHTS` fds and any named-unix inode
/// pin kept alive), and the destination sockaddr (empty = connected). Owning
/// everything lets the send be retried — from a byte offset, on a deferred
/// worker — without borrowing supervisor state, so a blocked send can leave the
/// sequential notification loop while still delivering the whole message.
struct MaterializedMsg {
    data: Vec<u8>,
    control: Option<Vec<u8>>,
    addr: Vec<u8>,
    _scm_fds: Vec<OwnedFd>,
    _pinned: Option<OwnedFd>,
}

/// True iff this send should block until it completes: the socket is in blocking
/// mode (`O_NONBLOCK` clear — the dup shares the child's file description, so it
/// reflects the child's own mode) *and* the per-call `send_flags` did not request
/// non-blocking with `MSG_DONTWAIT`. A child that passes `MSG_DONTWAIT` on a
/// blocking socket wants the immediate short-count/`EAGAIN`, not a deferred
/// block-to-completion, so it must not be deferred.
fn wants_blocking(fd: RawFd, send_flags: i32) -> bool {
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

/// Resolve a materialized send to a terminal action. The first attempt is
/// non-blocking (`MSG_DONTWAIT`) on the seccomp loop, so it never blocks there.
/// A non-blocking child gets whatever that one attempt returns (short count or
/// `EAGAIN`), exactly as the kernel would give it. A blocking child whose whole
/// message didn't fit is completed off the loop (`defer_send`), preserving the
/// kernel's "a blocking send of N returns N" contract without occupying the
/// loop or a worker thread — a stream send that partially fit continues from
/// the sent offset; a full send buffer defers from offset 0.
fn resolve_send(dup_fd: OwnedFd, m: MaterializedMsg, flags: i32, child_blocking: bool) -> NotifAction {
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
    let msghdr_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, msghdr_ptr, 56) {
        Ok(b) if b.len() >= 56 => b,
        _ => return Err(libc::EFAULT),
    };
    let msg_name_ptr = u64::from_ne_bytes(msghdr_bytes[0..8].try_into().unwrap());
    let msg_namelen = u32::from_ne_bytes(msghdr_bytes[8..12].try_into().unwrap());
    let msg_iov_ptr = u64::from_ne_bytes(msghdr_bytes[16..24].try_into().unwrap());
    let msg_iovlen = u64::from_ne_bytes(msghdr_bytes[24..32].try_into().unwrap());
    let msg_control_ptr = u64::from_ne_bytes(msghdr_bytes[32..40].try_into().unwrap());
    let msg_controllen = u64::from_ne_bytes(msghdr_bytes[40..48].try_into().unwrap());

    // A connected socket carries no per-message address (`msg_name == NULL` or
    // zero length). There is nothing to check against the destination
    // allowlist (the connection was gated at connect time), but we must still
    // send it on-behalf rather than Continue: Continue lets the kernel re-read
    // the msghdr from child memory, where a racing thread could have swapped a
    // null `msg_name` for a denied address. A non-connected entry has its IP
    // destination validated on the immune copy before the send.
    let connected = msg_name_ptr == 0 || msg_namelen == 0;
    let addr_bytes = if connected {
        Vec::new()
    } else {
        match read_child_mem(notif_fd, notif.id, notif.pid, msg_name_ptr, msg_namelen as usize) {
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

        let ns = ctx.network.lock().await;
        let live_policy = {
            let pfs = ctx.policy_fn.lock().await;
            pfs.live_policy.clone()
        };
        let effective = ns.effective_network_policy(notif.pid, protocol, live_policy.as_ref());
        if !matches!(effective, crate::seccomp::notif::NetworkPolicy::Unrestricted) {
            match dest_port {
                Some(p) if !effective.allows(ip, p) => return Err(ECONNREFUSED),
                None => return Err(ECONNREFUSED),
                Some(_) => {}
            }
        }
        drop(ns);
    }

    let iovlen = (msg_iovlen as usize).min(1024);
    let iov_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, msg_iov_ptr, iovlen * 16) {
        Ok(b) => b,
        Err(_) => return Err(libc::EIO),
    };
    let data = flatten_iovecs(notif, notif_fd, &iov_bytes, iovlen)?;

    // Translate SCM_RIGHTS / reject creds only for a unix socket; an IP socket's
    // control carries no fds or credentials and passes through untouched.
    let (control_buf, scm_fds) = materialize_control(
        notif,
        notif_fd,
        msg_control_ptr,
        msg_controllen,
        socket_is_unix(dup_fd.as_raw_fd()),
    )?;

    Ok(MaterializedMsg {
        data,
        control: control_buf,
        addr: if connected { Vec::new() } else { addr_bytes },
        _scm_fds: scm_fds,
        _pinned: None,
    })
}

// ============================================================
// sendmmsg_on_behalf — multi-message variant
// ============================================================

/// `struct mmsghdr` size on Linux x86_64 / aarch64: 56-byte msghdr +
/// 4-byte msg_len + 4-byte tail padding = 64 bytes. msg_len lives at
/// offset 56.
const MMSGHDR_SIZE: usize = 64;
const MSG_LEN_OFFSET: usize = 56;
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
async fn sendmmsg_on_behalf(
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
            let entry_ptr = msgvec_ptr + (i * MMSGHDR_SIZE) as u64;
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
                    let entry_ptr = msgvec_ptr + (i * MMSGHDR_SIZE) as u64;
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
            let entry_ptr = msgvec_ptr + (i * MMSGHDR_SIZE) as u64;
            let m = match send_msghdr_on_behalf(notif, ctx, notif_fd, &dup_fd, protocol, entry_ptr)
                .await
            {
                Ok(m) => m,
                Err(errno) => {
                    first_errno = Some(errno);
                    break;
                }
            };
            // A batch sends each entry non-blocking so it never occupies the loop;
            // the two cases that must not (entry 0 fully blocked, or a partial
            // stream entry) are completed off the loop instead of the child
            // seeing a spurious EAGAIN or a silently-truncated msg_len.
            let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
            let ret = send_materialized_at(dup_fd.as_raw_fd(), &m, 0, flags | libc::MSG_DONTWAIT);
            if ret >= 0 {
                if blocking && (ret as usize) < m.data.len() {
                    return complete_batch_entry(
                        dup_fd, m, flags, ret as usize, notif_fd, notif.id, notif.pid,
                        entry_ptr + MSG_LEN_OFFSET as u64, sent,
                    );
                }
                let bytes = (ret as u32).to_ne_bytes();
                let _ = write_child_mem(
                    notif_fd, notif.id, notif.pid, entry_ptr + MSG_LEN_OFFSET as u64, &bytes,
                );
                sent += 1;
            } else {
                let err = unsafe { *libc::__errno_location() };
                if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                    if sent == 0 && blocking {
                        return complete_batch_entry(
                            dup_fd, m, flags, 0, notif_fd, notif.id, notif.pid,
                            entry_ptr + MSG_LEN_OFFSET as u64, 0,
                        );
                    }
                    if sent == 0 {
                        first_errno = Some(libc::EAGAIN);
                    }
                    break;
                }
                first_errno = Some(err);
                break;
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
        let entry_ptr = msgvec_ptr + (i * MMSGHDR_SIZE) as u64;
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
        let entry_ptr = msgvec_ptr + (i * MMSGHDR_SIZE) as u64;
        // Every entry is OnBehalf (IP, non-connected) per the prescan above, so
        // the resolved protocol is always required and present here.
        let m = match send_msghdr_on_behalf(notif, ctx, notif_fd, &dup_fd, Some(protocol), entry_ptr).await {
            Ok(m) => m,
            Err(errno) => {
                first_errno = Some(errno);
                break;
            }
        };
        // Non-blocking per entry (see the destination-policy batch above); the
        // entry-0-fully-blocked and partial-stream cases complete off the loop.
        let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
        let ret = send_materialized_at(dup_fd.as_raw_fd(), &m, 0, flags | libc::MSG_DONTWAIT);
        if ret >= 0 {
            if blocking && (ret as usize) < m.data.len() {
                return complete_batch_entry(
                    dup_fd, m, flags, ret as usize, notif_fd, notif.id, notif.pid,
                    entry_ptr + MSG_LEN_OFFSET as u64, sent,
                );
            }
            let bytes = (ret as u32).to_ne_bytes();
            let _ = write_child_mem(
                notif_fd, notif.id, notif.pid, entry_ptr + MSG_LEN_OFFSET as u64, &bytes,
            );
            sent += 1;
        } else {
            let err = unsafe { *libc::__errno_location() };
            if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                if sent == 0 && blocking {
                    return complete_batch_entry(
                        dup_fd, m, flags, 0, notif_fd, notif.id, notif.pid,
                        entry_ptr + MSG_LEN_OFFSET as u64, 0,
                    );
                }
                if sent == 0 {
                    first_errno = Some(libc::EAGAIN);
                }
                break;
            }
            first_errno = Some(err);
            break;
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

// ============================================================
// resolve_net_allow — resolve --net-allow rules to runtime allowlist
// ============================================================

/// Resolved form of `Policy::net_allow`, ready for the on-behalf path.
pub struct ResolvedNetAllow {
    /// Per-IP port rules (each concrete-host entry resolves to one or
    /// more IPs). An IP appearing here with an empty port set means
    /// "all ports for this IP" (from a `host:*` rule).
    pub per_ip: HashMap<IpAddr, HashSet<u16>>,
    /// IPs permitted on every port (from `host:*` rules after host
    /// resolution). The on-behalf path treats these the same as
    /// `PortAllow::Any` — the entry in `per_ip` is kept as a
    /// placeholder for diagnostic / `/etc/hosts` purposes.
    pub per_ip_all_ports: HashSet<IpAddr>,
    /// IP/CIDR-literal targets, matched by containment with no DNS (an
    /// exact IP literal is a `/32` or `/128`). Each carries the ports
    /// permitted to that range (`PortAllow::Any` for all-ports rules).
    pub cidrs: Vec<(IpCidr, crate::seccomp::notif::PortAllow)>,
    /// Ports permitted to any IP (the `:port` form).
    pub any_ip_ports: HashSet<u16>,
    /// Any-host any-port wildcard (`:*` / `*:*`, or `icmp://*`). When
    /// true, the per-protocol policy becomes `Unrestricted` and the
    /// on-behalf check is bypassed for that protocol.
    pub any_ip_all_ports: bool,
}

/// Per-protocol resolved allowlists. Each protocol gets its own
/// `ResolvedNetAllow`; the on-behalf path picks the right one based on
/// the dup'd fd's `SO_PROTOCOL`. `etc_hosts` is shared across all
/// protocols (the synthetic file maps every concrete host that appears
/// in any rule).
pub struct ResolvedNetAllowSet {
    pub tcp: ResolvedNetAllow,
    pub udp: ResolvedNetAllow,
    pub icmp: ResolvedNetAllow,
    /// `<ip> <hostname>\n` lines from every concrete-host rule across
    /// every protocol, in resolution order. Empty when no concrete-host
    /// rules are present. Combined with the loopback base (or, in chroot
    /// mode, the image's `/etc/hosts`) by [`compose_virtual_etc_hosts`]
    /// to build the synthetic file served to the sandbox.
    pub concrete_host_entries: String,
}

/// Resolve `--net-allow` rules into per-protocol runtime allowlists.
///
/// Rules are grouped by `Protocol` and each group is resolved
/// independently. ICMP rules carry no ports, so the resulting ICMP
/// `ResolvedNetAllow` always has empty `any_ip_ports` / per-IP port
/// sets — the on-behalf check routes ICMP through the IP-only path
/// (PortAllow::Any). A `*` host on ICMP becomes `any_ip_all_ports`,
/// which the handler reads as "no destination check."
pub async fn resolve_net_allow(
    rules: &[NetAllow],
) -> io::Result<ResolvedNetAllowSet> {
    use crate::seccomp::notif::PortAllow;
    let per_proto = |target: Protocol| async move {
        let mut per_ip: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
        let mut per_ip_all_ports: HashSet<IpAddr> = HashSet::new();
        let mut cidrs: Vec<(IpCidr, PortAllow)> = Vec::new();
        let mut any_ip_ports: HashSet<u16> = HashSet::new();
        let mut any_ip_all_ports = false;
        let mut local_etc_hosts = String::new();

        for rule in rules.iter().filter(|r| r.protocol == target) {
            match &rule.target {
                NetTarget::AnyIp => {
                    if rule.all_ports || target == Protocol::Icmp {
                        // ICMP rules never carry ports, so a wildcard-host
                        // ICMP rule (`icmp://*`) means "any destination."
                        any_ip_all_ports = true;
                    } else {
                        for &p in &rule.ports {
                            any_ip_ports.insert(p);
                        }
                    }
                }
                NetTarget::Cidr(c) => {
                    // IP/CIDR literals are matched by containment with no
                    // DNS, exactly like `--net-deny` targets.
                    let pa = if rule.all_ports || target == Protocol::Icmp {
                        PortAllow::Any
                    } else {
                        PortAllow::Specific(rule.ports.iter().copied().collect())
                    };
                    cidrs.push((*c, pa));
                }
                NetTarget::Host(host) => {
                    let addr = format!("{}:0", host);
                    let resolved = tokio::net::lookup_host(addr.as_str()).await.map_err(|e| {
                        io::Error::new(
                            e.kind(),
                            format!("failed to resolve host '{}': {}", host, e),
                        )
                    })?;
                    for socket_addr in resolved {
                        let ip = socket_addr.ip();
                        if rule.all_ports || target == Protocol::Icmp {
                            per_ip_all_ports.insert(ip);
                            per_ip.entry(ip).or_default();
                        } else {
                            let entry = per_ip.entry(ip).or_default();
                            for &p in &rule.ports {
                                entry.insert(p);
                            }
                        }
                        local_etc_hosts.push_str(&format!("{} {}\n", ip, host));
                    }
                }
            }
        }

        Ok::<_, io::Error>((
            ResolvedNetAllow {
                per_ip,
                per_ip_all_ports,
                cidrs,
                any_ip_ports,
                any_ip_all_ports,
            },
            local_etc_hosts,
        ))
    };

    let (tcp, tcp_eh) = per_proto(Protocol::Tcp).await?;
    let (udp, udp_eh) = per_proto(Protocol::Udp).await?;
    let (icmp, icmp_eh) = per_proto(Protocol::Icmp).await?;

    let mut concrete_host_entries = String::new();
    for chunk in [tcp_eh, udp_eh, icmp_eh] {
        concrete_host_entries.push_str(&chunk);
    }

    Ok(ResolvedNetAllowSet {
        tcp,
        udp,
        icmp,
        concrete_host_entries,
    })
}

/// Per-protocol resolved deny policies, ready for `NetworkState`.
pub struct ResolvedNetDenySet {
    pub tcp: crate::seccomp::notif::NetworkPolicy,
    pub udp: crate::seccomp::notif::NetworkPolicy,
    pub icmp: crate::seccomp::notif::NetworkPolicy,
}

/// Resolve `--net-deny` rules into per-protocol `DenyList` policies.
/// A protocol with no deny rules stays `Unrestricted` (allow-all).
pub fn resolve_net_deny(rules: &[NetDeny]) -> ResolvedNetDenySet {
    use crate::seccomp::notif::{NetworkPolicy, PortAllow};

    let per_proto = |target: Protocol| -> NetworkPolicy {
        let mut cidrs: Vec<(IpCidr, PortAllow)> = Vec::new();
        let mut any_ip_ports: HashSet<u16> = HashSet::new();
        let mut deny_all = false;
        let mut saw_rule = false;

        for rule in rules.iter().filter(|r| r.protocol == target) {
            saw_rule = true;
            match &rule.target {
                NetTarget::AnyIp => {
                    if rule.all_ports || target == Protocol::Icmp {
                        deny_all = true;
                    } else {
                        for &p in &rule.ports {
                            any_ip_ports.insert(p);
                        }
                    }
                }
                NetTarget::Cidr(c) => {
                    let pa = if rule.all_ports || target == Protocol::Icmp {
                        PortAllow::Any
                    } else {
                        PortAllow::Specific(rule.ports.iter().copied().collect())
                    };
                    cidrs.push((*c, pa));
                }
                // `--net-deny` rejects hostnames at parse time, so a deny
                // rule never carries a `Host` target.
                NetTarget::Host(_) => unreachable!("net-deny rejects hostnames"),
            }
        }

        if !saw_rule {
            NetworkPolicy::Unrestricted
        } else {
            NetworkPolicy::DenyList {
                cidrs,
                any_ip_ports,
                deny_all,
            }
        }
    };

    ResolvedNetDenySet {
        tcp: per_proto(Protocol::Tcp),
        udp: per_proto(Protocol::Udp),
        icmp: per_proto(Protocol::Icmp),
    }
}

/// Compose the synthetic `/etc/hosts` served to the sandbox.
///
/// - **No chroot**: emit the fixed loopback base
///   (`127.0.0.1 localhost\n::1 localhost\n`) followed by the
///   concrete-host entries from [`resolve_net_allow`]. The sandbox sees
///   the same baseline regardless of what the host's on-disk file says.
/// - **With chroot**: read `<chroot>/etc/hosts` and use it as the base
///   (an image that bakes in private-registry entries or similar keeps
///   them). Inject loopback entries only for any localhost family the
///   image doesn't already cover — never both, so we don't duplicate
///   what the image already has. Concrete-host entries are still
///   appended on top.
///
/// If a chroot is set but `<chroot>/etc/hosts` is unreadable (absent,
/// permission denied, etc.), fall back to the bare loopback base — the
/// sandbox always sees a usable hosts file.
pub fn compose_virtual_etc_hosts(
    chroot_root: Option<&std::path::Path>,
    concrete_host_entries: &str,
) -> String {
    let mut out = String::new();
    let mut has_v4_localhost = false;
    let mut has_v6_localhost = false;

    if let Some(root) = chroot_root {
        if let Ok(image) = std::fs::read_to_string(root.join("etc").join("hosts")) {
            for line in image.lines() {
                // Strip an inline `#` comment before tokenizing — the
                // hosts(5) format treats everything after `#` as a comment.
                let stripped = line.split('#').next().unwrap_or("");
                let mut parts = stripped.split_whitespace();
                let Some(ip) = parts.next() else { continue };
                for name in parts {
                    if name == "localhost" {
                        if ip == "127.0.0.1" {
                            has_v4_localhost = true;
                        } else if ip == "::1" {
                            has_v6_localhost = true;
                        }
                    }
                }
            }
            out.push_str(&image);
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
        }
    }

    if !has_v4_localhost {
        out.push_str("127.0.0.1 localhost\n");
    }
    if !has_v6_localhost {
        out.push_str("::1 localhost\n");
    }
    out.push_str(concrete_host_entries);
    out
}

// ============================================================
// Tests
// ============================================================

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

    // --- NetAllow::parse tests ---

    #[test]
    fn netallow_parse_concrete_host_port() {
        let r = NetRule::parse_allow("example.com:443").unwrap();
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "example.com"));
        assert_eq!(r.ports, vec![443]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_parse_any_host_port() {
        let r = NetRule::parse_allow(":8080").unwrap();
        assert_eq!(r.target, NetTarget::AnyIp);
        assert_eq!(r.ports, vec![8080]);
        assert!(!r.all_ports);

        let r = NetRule::parse_allow("*:8080").unwrap();
        assert_eq!(r.target, NetTarget::AnyIp);
        assert_eq!(r.ports, vec![8080]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_parse_multiple_ports() {
        let r = NetRule::parse_allow("github.com:22,80,443").unwrap();
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "github.com"));
        assert_eq!(r.ports, vec![22, 80, 443]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_parse_wildcard_any_host_any_port_colon() {
        let r = NetRule::parse_allow(":*").unwrap();
        assert_eq!(r.target, NetTarget::AnyIp);
        assert!(r.ports.is_empty());
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_parse_wildcard_any_host_any_port_star() {
        let r = NetRule::parse_allow("*:*").unwrap();
        assert_eq!(r.target, NetTarget::AnyIp);
        assert!(r.ports.is_empty());
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_parse_wildcard_concrete_host_any_port() {
        let r = NetRule::parse_allow("example.com:*").unwrap();
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "example.com"));
        assert!(r.ports.is_empty());
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_parse_rejects_mixed_wildcard_and_concrete() {
        // `host:80,*` and `host:*,80` are both ambiguous: the user
        // either meant "any port" (wildcard wins) or "ports 80 plus
        // some weird placeholder". Refuse and force a clean spec.
        let err = NetRule::parse_allow("example.com:80,*").unwrap_err();
        assert!(format!("{}", err).contains("cannot mix"));
        let err = NetRule::parse_allow("example.com:*,80").unwrap_err();
        assert!(format!("{}", err).contains("cannot mix"));
    }

    #[test]
    fn netallow_parse_rejects_port_zero() {
        let err = NetRule::parse_allow("example.com:0").unwrap_err();
        assert!(format!("{}", err).contains("port 0"));
    }

    #[test]
    fn netallow_parse_rejects_empty_port() {
        let err = NetRule::parse_allow("example.com:").unwrap_err();
        assert!(format!("{}", err).contains("invalid port"));
    }

    #[test]
    fn netallow_bare_host_is_all_ports() {
        // No port suffix means "all ports" (port optional), symmetric
        // with the `host:*` form.
        let r = NetRule::parse_allow("example.com").unwrap();
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "example.com"));
        assert!(r.all_ports);
        assert!(r.ports.is_empty());
    }

    #[test]
    fn netallow_bare_star_is_any_host_all_ports() {
        let r = NetRule::parse_allow("*").unwrap();
        assert_eq!(r.target, NetTarget::AnyIp);
        assert!(r.all_ports);
        assert!(r.ports.is_empty());
    }

    #[test]
    fn netallow_empty_spec_rejected() {
        assert!(NetRule::parse_allow("").is_err());
        assert!(NetRule::parse_allow("tcp://").is_err());
    }

    #[test]
    fn netallow_cidr_target_with_port() {
        // CIDR ranges are now first-class in --net-allow (matched by
        // containment, no DNS), symmetric with --net-deny.
        let r = NetRule::parse_allow("10.0.0.0/8:80").unwrap();
        assert!(matches!(&r.target, NetTarget::Cidr(c) if !c.is_single_host()));
        assert_eq!(r.ports, vec![80]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_ipv6_literal_and_bracket() {
        let lo: std::net::IpAddr = "::1".parse().unwrap();
        // Bare IPv6 literal (previously mis-split on its colons).
        let r = NetRule::parse_allow("::1").unwrap();
        assert!(matches!(&r.target, NetTarget::Cidr(c) if c.addr == lo && c.is_single_host()));
        assert!(r.all_ports);
        // Bracketed IPv6 with a port.
        let r = NetRule::parse_allow("[::1]:443").unwrap();
        assert!(matches!(&r.target, NetTarget::Cidr(c) if c.addr == lo && c.is_single_host()));
        assert_eq!(r.ports, vec![443]);
        // IPv6 CIDR.
        let r = NetRule::parse_allow("fc00::/7").unwrap();
        assert!(matches!(&r.target, NetTarget::Cidr(c) if !c.is_single_host()));
        assert!(r.all_ports);
    }

    #[tokio::test]
    async fn test_resolve_net_allow_cidr_no_dns() {
        // A CIDR / IP-literal target resolves into `cidrs` directly, with
        // no DNS lookup and no `per_ip` / `/etc/hosts` entry.
        let rules = vec![
            NetAllow { protocol: Protocol::Tcp, target: NetTarget::Cidr(IpCidr::parse("10.0.0.0/8").unwrap()), ports: vec![80], all_ports: false },
            NetAllow { protocol: Protocol::Tcp, target: NetTarget::Cidr(IpCidr::parse("1.2.3.4").unwrap()), ports: vec![], all_ports: true },
        ];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert_eq!(resolved.tcp.cidrs.len(), 2);
        assert!(resolved.tcp.per_ip.is_empty());
        assert!(resolved.concrete_host_entries.is_empty());
    }

    #[test]
    fn netallow_parse_repeated_wildcard_is_idempotent() {
        // `*,*` collapses to a single wildcard — neither token contributes
        // a concrete port, so the rule remains "any port".
        let r = NetRule::parse_allow(":*,*").unwrap();
        assert!(r.all_ports);
        assert!(r.ports.is_empty());
    }

    // --- Protocol scheme prefix tests ---

    #[test]
    fn netallow_bare_form_defaults_to_tcp() {
        let r = NetRule::parse_allow("example.com:443").unwrap();
        assert_eq!(r.protocol, Protocol::Tcp);
    }

    #[test]
    fn netallow_explicit_tcp_scheme() {
        let r = NetRule::parse_allow("tcp://example.com:443").unwrap();
        assert_eq!(r.protocol, Protocol::Tcp);
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "example.com"));
        assert_eq!(r.ports, vec![443]);
    }

    #[test]
    fn netallow_udp_scheme_with_host_port() {
        let r = NetRule::parse_allow("udp://1.1.1.1:53").unwrap();
        assert_eq!(r.protocol, Protocol::Udp);
        // An IP literal becomes a single-host CIDR target (no DNS).
        let one: std::net::IpAddr = "1.1.1.1".parse().unwrap();
        assert!(matches!(&r.target, NetTarget::Cidr(c) if c.addr == one && c.is_single_host()));
        assert_eq!(r.ports, vec![53]);
    }

    #[test]
    fn netallow_udp_wildcard_any_anywhere() {
        // The "any UDP" gate, equivalent to the old `allow_udp = true`.
        let r = NetRule::parse_allow("udp://*:*").unwrap();
        assert_eq!(r.protocol, Protocol::Udp);
        assert_eq!(r.target, NetTarget::AnyIp);
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_icmp_scheme_with_host() {
        let r = NetRule::parse_allow("icmp://github.com").unwrap();
        assert_eq!(r.protocol, Protocol::Icmp);
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "github.com"));
        assert!(r.ports.is_empty());
        // ICMP carries no ports, so the rule is "all ports" by convention.
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_icmp_wildcard() {
        // The "any ICMP echo" gate, equivalent to the old
        // `allow_icmp = true` for the SOCK_DGRAM path.
        let r = NetRule::parse_allow("icmp://*").unwrap();
        assert_eq!(r.protocol, Protocol::Icmp);
        assert_eq!(r.target, NetTarget::AnyIp);
    }

    #[test]
    fn netallow_icmp_rejects_port() {
        // ICMP has no port — `:port` is meaningless and refused
        // explicitly so users can't write a rule that doesn't do what
        // they think.
        let err = NetRule::parse_allow("icmp://github.com:80").unwrap_err();
        assert!(format!("{}", err).contains("icmp rule takes no port"));
    }

    #[test]
    fn netallow_icmp_rejects_empty_body() {
        let err = NetRule::parse_allow("icmp://").unwrap_err();
        assert!(format!("{}", err).contains("needs a host/IP or `*`"));
    }

    #[test]
    fn netallow_unknown_scheme_rejected() {
        // Including `icmp-raw` — sandlock does not expose raw ICMP, so
        // the scheme is unknown rather than a special-case error.
        for spec in ["sctp://host:1234", "icmp-raw://*"] {
            let err = NetRule::parse_allow(spec).unwrap_err();
            assert!(format!("{}", err).contains("unknown scheme"), "spec: {}", spec);
        }
    }

    #[tokio::test]
    async fn test_resolve_net_allow_empty() {
        let resolved = resolve_net_allow(&[]).await.unwrap();
        assert!(resolved.tcp.per_ip.is_empty());
        assert!(resolved.tcp.any_ip_ports.is_empty());
        assert!(resolved.udp.per_ip.is_empty());
        assert!(resolved.icmp.per_ip.is_empty());
        // No concrete-host rules → no resolved-entry lines.
        assert!(resolved.concrete_host_entries.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_net_allow_concrete_host() {
        let rules = vec![NetAllow {
            protocol: Protocol::Tcp,
            target: NetTarget::Host("localhost".to_string()),
            ports: vec![80, 443],
            all_ports: false,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        // localhost should resolve to at least one loopback addr; only
        // the TCP set has entries.
        assert!(!resolved.tcp.per_ip.is_empty());
        for ports in resolved.tcp.per_ip.values() {
            assert!(ports.contains(&80));
            assert!(ports.contains(&443));
        }
        assert!(resolved.udp.per_ip.is_empty());
        assert!(resolved.icmp.per_ip.is_empty());
        // The resolved entry (`<ip> localhost`) surfaces in concrete_host_entries.
        assert!(resolved.concrete_host_entries.contains("127.0.0.1 localhost"));
    }

    #[tokio::test]
    async fn test_resolve_net_allow_any_ip() {
        let rules = vec![NetAllow {
            protocol: Protocol::Tcp,
            target: NetTarget::AnyIp,
            ports: vec![8080],
            all_ports: false,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(resolved.tcp.per_ip.is_empty());
        assert!(resolved.tcp.any_ip_ports.contains(&8080));
        assert!(!resolved.tcp.any_ip_all_ports);
        // Any-IP rule has no concrete host, so no resolved-entry line.
        assert!(resolved.concrete_host_entries.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_net_allow_any_ip_all_ports() {
        // `:*` — fully unrestricted egress, TCP-only.
        let rules = vec![NetAllow {
            protocol: Protocol::Tcp,
            target: NetTarget::AnyIp,
            ports: vec![],
            all_ports: true,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(resolved.tcp.any_ip_all_ports);
        assert!(resolved.tcp.per_ip.is_empty());
        assert!(resolved.tcp.per_ip_all_ports.is_empty());
        assert!(resolved.tcp.any_ip_ports.is_empty());
        // UDP/ICMP unaffected by a TCP rule.
        assert!(!resolved.udp.any_ip_all_ports);
        assert!(!resolved.icmp.any_ip_all_ports);
    }

    #[tokio::test]
    async fn test_resolve_net_allow_concrete_host_all_ports() {
        // `localhost:*` — every port to localhost only, TCP.
        let rules = vec![NetAllow {
            protocol: Protocol::Tcp,
            target: NetTarget::Host("localhost".to_string()),
            ports: vec![],
            all_ports: true,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(!resolved.tcp.any_ip_all_ports);
        assert!(
            !resolved.tcp.per_ip_all_ports.is_empty(),
            "localhost should resolve to at least one IP marked as any-port"
        );
        for ip in resolved.tcp.per_ip_all_ports.iter() {
            assert!(resolved.tcp.per_ip.contains_key(ip));
        }
        assert!(resolved.concrete_host_entries.contains("localhost"));
    }

    #[tokio::test]
    async fn test_resolve_net_allow_mixed_wildcard_and_concrete() {
        // Wildcard rule alongside concrete: wildcard sets the global
        // any-host any-port flag for TCP; concrete rule still resolves
        // into per_ip (the runtime layer chooses Unrestricted, ignoring
        // the concrete entries).
        let rules = vec![
            NetAllow {
                protocol: Protocol::Tcp,
                target: NetTarget::AnyIp,
                ports: vec![],
                all_ports: true,
            },
            NetAllow {
                protocol: Protocol::Tcp,
                target: NetTarget::Host("localhost".to_string()),
                ports: vec![22],
                all_ports: false,
            },
        ];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(resolved.tcp.any_ip_all_ports);
        assert!(!resolved.tcp.per_ip.is_empty());
    }

    // ============================================================
    // Per-protocol resolution — UDP / ICMP slices stay isolated
    // ============================================================

    #[tokio::test]
    async fn test_resolve_per_protocol_isolation() {
        // A UDP rule should not appear in the TCP set, and vice versa.
        // This is the property Phase 2 relies on for protocol routing.
        let rules = vec![
            NetAllow {
                protocol: Protocol::Tcp,
                target: NetTarget::Host("localhost".to_string()),
                ports: vec![443],
                all_ports: false,
            },
            NetAllow {
                protocol: Protocol::Udp,
                target: NetTarget::AnyIp,
                ports: vec![53],
                all_ports: false,
            },
        ];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(
            !resolved.tcp.per_ip.is_empty(),
            "TCP rule should populate tcp set"
        );
        assert!(
            resolved.udp.any_ip_ports.contains(&53),
            "UDP rule should populate udp set"
        );
        // Cross-contamination check: TCP per_ip ports must not contain 53;
        // UDP must not contain 443.
        for ports in resolved.tcp.per_ip.values() {
            assert!(!ports.contains(&53), "UDP port leaked into TCP set");
        }
        assert!(!resolved.udp.any_ip_ports.contains(&443), "TCP port leaked into UDP set");
    }

    #[tokio::test]
    async fn test_resolve_icmp_no_ports() {
        // ICMP rules carry no ports; concrete hosts go into per_ip with
        // PortAllow::Any-style empty port set, plus per_ip_all_ports.
        let rules = vec![NetAllow {
            protocol: Protocol::Icmp,
            target: NetTarget::Host("localhost".to_string()),
            ports: vec![],
            all_ports: false,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(
            !resolved.icmp.per_ip.is_empty(),
            "icmp host should populate per_ip"
        );
        assert!(
            !resolved.icmp.per_ip_all_ports.is_empty(),
            "icmp host should mark per_ip_all_ports (no port check)"
        );
        assert!(resolved.icmp.any_ip_ports.is_empty());
        // TCP/UDP unaffected.
        assert!(resolved.tcp.per_ip.is_empty());
        assert!(resolved.udp.per_ip.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_icmp_wildcard() {
        // `icmp://*` — any ICMP destination.
        let rules = vec![NetAllow {
            protocol: Protocol::Icmp,
            target: NetTarget::AnyIp,
            ports: vec![],
            all_ports: false,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(resolved.icmp.any_ip_all_ports);
        assert!(!resolved.tcp.any_ip_all_ports);
    }

    // ============================================================
    // compose_virtual_etc_hosts — synthetic /etc/hosts assembly
    // ============================================================

    use std::io::Write;

    fn temp_rootfs_with_hosts(name: &str, hosts_content: Option<&str>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sandlock-test-compose-hosts-{}-{}",
            name, std::process::id()
        ));
        let _ = std::fs::create_dir_all(dir.join("etc"));
        if let Some(content) = hosts_content {
            let mut f = std::fs::File::create(dir.join("etc").join("hosts")).unwrap();
            f.write_all(content.as_bytes()).unwrap();
        }
        dir
    }

    #[test]
    fn compose_no_chroot_emits_loopback_base() {
        // Default path — no chroot, no concrete-host rules → the same
        // fixed loopback view we promise every sandbox.
        let out = compose_virtual_etc_hosts(None, "");
        assert_eq!(out, "127.0.0.1 localhost\n::1 localhost\n");
    }

    #[test]
    fn compose_no_chroot_appends_concrete_entries() {
        let out = compose_virtual_etc_hosts(None, "10.0.0.1 api\n");
        assert_eq!(out, "127.0.0.1 localhost\n::1 localhost\n10.0.0.1 api\n");
    }

    #[test]
    fn compose_chroot_seeds_from_image_and_injects_missing_loopback() {
        // Image ships an entry of its own but no localhost mapping; the
        // shim must keep the image's content and inject both loopback
        // entries on top so the always-on guarantee still holds.
        let rootfs = temp_rootfs_with_hosts(
            "no-localhost",
            Some("10.0.0.5 myimage.local\n"),
        );
        let out = compose_virtual_etc_hosts(Some(&rootfs), "");
        assert!(out.contains("10.0.0.5 myimage.local"), "image entry missing: {out}");
        assert!(out.contains("127.0.0.1 localhost"), "v4 loopback missing: {out}");
        assert!(out.contains("::1 localhost"), "v6 loopback missing: {out}");
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn compose_chroot_does_not_duplicate_existing_loopback() {
        // Image already has both loopback entries — don't append duplicates.
        let rootfs = temp_rootfs_with_hosts(
            "both-localhost",
            Some("127.0.0.1 localhost\n::1 localhost\n10.0.0.5 myimage.local\n"),
        );
        let out = compose_virtual_etc_hosts(Some(&rootfs), "");
        assert_eq!(out.matches("127.0.0.1 localhost").count(), 1, "v4 dup'd: {out}");
        assert_eq!(out.matches("::1 localhost").count(), 1, "v6 dup'd: {out}");
        assert!(out.contains("10.0.0.5 myimage.local"));
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn compose_chroot_injects_only_missing_family() {
        // Image has v4 but no v6 localhost — inject only v6, leave v4 alone.
        let rootfs = temp_rootfs_with_hosts(
            "only-v4-localhost",
            Some("127.0.0.1 localhost myimage\n"),
        );
        let out = compose_virtual_etc_hosts(Some(&rootfs), "");
        assert_eq!(out.matches("127.0.0.1 localhost").count(), 1);
        assert!(out.contains("::1 localhost"), "v6 loopback should be injected: {out}");
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn compose_chroot_missing_file_falls_back_to_loopback() {
        // Chroot exists but has no /etc/hosts — fall back to the bare
        // loopback base so the sandbox always sees a usable file.
        let rootfs = temp_rootfs_with_hosts("no-file", None);
        let out = compose_virtual_etc_hosts(Some(&rootfs), "10.0.0.1 api\n");
        assert_eq!(out, "127.0.0.1 localhost\n::1 localhost\n10.0.0.1 api\n");
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn compose_chroot_strips_inline_comments_when_detecting_loopback() {
        // hosts(5) treats `#` as a comment-start; the loopback-presence
        // check must respect it (otherwise an image line like
        // `127.0.0.1 # localhost` would be falsely treated as covering v4).
        let rootfs = temp_rootfs_with_hosts(
            "with-comments",
            Some("127.0.0.1 # localhost is a comment here\n"),
        );
        let out = compose_virtual_etc_hosts(Some(&rootfs), "");
        // Real `127.0.0.1 localhost` line must still be injected.
        assert!(
            out.lines().any(|l| l.trim() == "127.0.0.1 localhost"),
            "v4 loopback should still be injected: {out}"
        );
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    // --- IpCidr tests ---

    #[test]
    fn ipcidr_parse_bare_ipv4_is_host_route() {
        let c = IpCidr::parse("1.2.3.4").unwrap();
        assert_eq!(c.prefix_len, 32);
        assert!(c.contains("1.2.3.4".parse().unwrap()));
        assert!(!c.contains("1.2.3.5".parse().unwrap()));
    }

    #[test]
    fn ipcidr_parse_ipv4_range_contains() {
        let c = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.3.7.9".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipcidr_parse_ipv6_range_contains() {
        let c = IpCidr::parse("fc00::/7").unwrap();
        assert!(c.contains("fd00::1".parse().unwrap()));
        assert!(!c.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn ipcidr_zero_prefix_matches_all_same_family() {
        let c = IpCidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains("8.8.8.8".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap())); // family mismatch
    }

    #[test]
    fn ipcidr_rejects_hostname() {
        assert!(IpCidr::parse("example.com").is_err());
    }

    #[test]
    fn ipcidr_rejects_oversized_prefix() {
        assert!(IpCidr::parse("10.0.0.0/33").is_err());
        assert!(IpCidr::parse("fc00::/129").is_err());
    }

    // --- NetDeny::parse tests ---

    #[test]
    fn netdeny_bare_cidr_is_all_ports_tcp() {
        let rule = NetRule::parse_deny("10.0.0.0/8").unwrap();
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert!(matches!(rule.target, NetTarget::Cidr(_)));
        assert!(rule.all_ports);
    }

    #[test]
    fn netdeny_bare_ip_is_host_route_all_ports() {
        let rule = NetRule::parse_deny("169.254.169.254").unwrap();
        match &rule.target {
            NetTarget::Cidr(c) => assert_eq!(c.prefix_len, 32),
            _ => panic!("expected cidr"),
        }
        assert!(rule.all_ports);
    }

    #[test]
    fn netdeny_cidr_with_port() {
        let rule = NetRule::parse_deny("10.0.0.0/8:443").unwrap();
        assert_eq!(rule.ports, vec![443]);
        assert!(!rule.all_ports);
    }

    #[test]
    fn netdeny_any_ip_port() {
        let rule = NetRule::parse_deny(":25").unwrap();
        assert!(matches!(rule.target, NetTarget::AnyIp));
        assert_eq!(rule.ports, vec![25]);
    }

    #[test]
    fn netdeny_udp_scheme() {
        let rule = NetRule::parse_deny("udp://192.168.0.0/16:53").unwrap();
        assert_eq!(rule.protocol, Protocol::Udp);
        assert_eq!(rule.ports, vec![53]);
    }

    #[test]
    fn netdeny_ipv6_bracket_port() {
        let rule = NetRule::parse_deny("[::1]:443").unwrap();
        assert_eq!(rule.ports, vec![443]);
        match &rule.target {
            NetTarget::Cidr(c) => assert_eq!(c.prefix_len, 128),
            _ => panic!("expected cidr"),
        }
    }

    #[test]
    fn netdeny_rejects_hostname() {
        assert!(NetRule::parse_deny("evil.com:443").is_err());
        assert!(NetRule::parse_deny("evil.com").is_err());
    }

    #[test]
    fn netdeny_bare_ipv6_address_all_ports() {
        let rule = NetRule::parse_deny("::1").unwrap();
        assert!(rule.all_ports);
        match &rule.target {
            NetTarget::Cidr(c) => assert_eq!(c.prefix_len, 128),
            _ => panic!("expected cidr"),
        }
    }

    #[test]
    fn netdeny_bare_ipv6_cidr_all_ports() {
        let rule = NetRule::parse_deny("fc00::/7").unwrap();
        assert!(rule.all_ports);
        let ula: std::net::IpAddr = "fd00::1".parse().unwrap();
        assert!(matches!(&rule.target, NetTarget::Cidr(c) if c.contains(ula)));
    }

    #[test]
    fn netdeny_empty_icmp_body_is_rejected() {
        assert!(NetRule::parse_deny("icmp://").is_err());
    }

    #[test]
    fn netdeny_bare_star_is_any_ip_all_ports() {
        // `*` with no port is the any-IP, all-ports form (port optional,
        // symmetric with a bare IP/CIDR).
        let rule = NetRule::parse_deny("*").unwrap();
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert!(matches!(rule.target, NetTarget::AnyIp));
        assert!(rule.all_ports);
        assert!(rule.ports.is_empty());
    }

    #[test]
    fn netdeny_udp_bare_star_all_ports() {
        let rule = NetRule::parse_deny("udp://*").unwrap();
        assert_eq!(rule.protocol, Protocol::Udp);
        assert!(matches!(rule.target, NetTarget::AnyIp));
        assert!(rule.all_ports);
    }

    #[test]
    fn netdeny_empty_spec_rejected() {
        // An empty body must not silently mean "deny everything".
        assert!(NetRule::parse_deny("").is_err());
        assert!(NetRule::parse_deny("udp://").is_err());
    }

    // --- resolve_net_deny tests ---

    #[test]
    fn resolve_net_deny_groups_per_protocol() {
        let rule = NetRule::parse_deny("10.0.0.0/8").unwrap();
        let set = resolve_net_deny(std::slice::from_ref(&rule));
        // TCP policy denies 10.x, UDP/ICMP unaffected (still allow-all).
        assert!(!set.tcp.allows("10.0.0.1".parse().unwrap(), 443));
        assert!(set.udp.allows("10.0.0.1".parse().unwrap(), 443));
    }

    #[test]
    fn resolve_net_deny_any_ip_port() {
        let rule = NetRule::parse_deny(":25").unwrap();
        let set = resolve_net_deny(std::slice::from_ref(&rule));
        assert!(!set.tcp.allows("8.8.8.8".parse().unwrap(), 25));
        assert!(set.tcp.allows("8.8.8.8".parse().unwrap(), 80));
    }
}
