// IP connect handler: parse the destination from child memory, decide
// (policy verdict plus a ConnectPlan computed as data: redirect to the
// HTTP ACL proxy, remap a loopback port, or pass through), then execute
// on the dup'd socket. Named AF_UNIX connects are delegated to `unix`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_mem, NotifAction};
use crate::sys::structs::{SeccompNotif, ECONNREFUSED};

use super::materialize::{
    named_unix_socket_path, parse_ip_from_sockaddr, parse_port_from_sockaddr,
    set_port_in_sockaddr,
};
use super::unix::connect_named_unix_on_behalf;
use super::verdict::{destination_verdict, path_under_any};
use super::query_socket_protocol;

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
pub(super) async fn connect_on_behalf(
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
        // Decide: verdict on the immune copy, then compute the connect plan
        // (redirect / remap / passthrough) as data while the policy state is
        // locked. Everything after the lock drops is execute-only.
        let ns = ctx.network.lock().await;
        let live_policy = {
            let pfs = ctx.policy_fn.lock().await;
            pfs.live_policy.clone()
        };
        let effective = ns.effective_network_policy(notif.pid, protocol, live_policy.as_ref());
        if let Err(e) = destination_verdict(&effective, ip, dest_port) {
            return NotifAction::Errno(e);
        }
        let proxy = ns
            .http_acl_addr
            .filter(|_| dest_port.map_or(false, |p| ns.http_acl_ports.contains(&p)));
        let remap_port = if ctx.policy.port_remap && ip.is_loopback() {
            dest_port.and_then(|p| ns.port_map.get_real(p))
        } else {
            None
        };
        let orig_dest_map = ns.http_acl_orig_dest.clone();
        drop(ns);

        let plan = match plan_connect_target(&addr_bytes, proxy, remap_port) {
            Ok(p) => p,
            Err(e) => return NotifAction::Errno(e),
        };

        // Execute. Record the original destination *before* connect to prevent
        // a TOCTOU race: the proxy may receive the request before we write the
        // mapping if we did it after connect(). The IP comes from `addr_bytes`
        // (our immune copy). The dup from the SO_PROTOCOL probe above is
        // reused rather than pidfd_getfd-ing a second time.
        if plan.record_orig_dest {
            if let Some(ref map) = orig_dest_map {
                record_orig_dest(map, dup_fd.as_raw_fd(), ip.is_ipv6(), ip);
            }
        }
        connect_dup(dup_fd.as_raw_fd(), &plan.addr)
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

/// Execute-phase plan for one IP connect, computed as data by the decide
/// phase: where to actually connect and whether the original destination
/// must be recorded for the HTTP ACL proxy before connecting.
struct ConnectPlan {
    /// Sockaddr bytes to connect to: the child's original destination, the
    /// HTTP ACL proxy, or the original with a remapped loopback port.
    addr: Vec<u8>,
    /// Record (local addr, original dest IP) before connecting so the proxy
    /// can resolve the intended destination (redirect only).
    record_orig_dest: bool,
}

/// Decide phase: pick the connect target from the validated destination and
/// the redirect/remap policy. Pure: no I/O, no locks.
///
/// `proxy` is `Some` when the HTTP ACL intercepts this destination port; the
/// connect is redirected to the proxy and the original destination must be
/// recorded first. `remap_port` is the real bound port when loopback port
/// remap applies; the child sees virtual ports via getsockname(), so the
/// connect targets the real one. Remap never applies to a redirected
/// connect.
fn plan_connect_target(
    addr_bytes: &[u8],
    proxy: Option<std::net::SocketAddr>,
    remap_port: Option<u16>,
) -> Result<ConnectPlan, i32> {
    let is_ipv6 = parse_ip_from_sockaddr(addr_bytes).map_or(false, |ip| ip.is_ipv6());
    if let Some(proxy_addr) = proxy {
        let addr = if is_ipv6 {
            // IPv6 socket: redirect via the IPv4-mapped IPv6 address
            // (::ffff:127.0.0.1) so it connects to the IPv4 proxy.
            let mut sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa6.sin6_family = libc::AF_INET6 as u16;
            sa6.sin6_port = proxy_addr.port().to_be();
            let mapped = match proxy_addr {
                std::net::SocketAddr::V4(v4) => v4.ip().to_ipv6_mapped(),
                std::net::SocketAddr::V6(v6) => *v6.ip(),
            };
            sa6.sin6_addr.s6_addr = mapped.octets();
            unsafe {
                std::slice::from_raw_parts(
                    &sa6 as *const _ as *const u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                )
            }
            .to_vec()
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
                    // Proxy always binds to 127.0.0.1.
                    return Err(libc::EAFNOSUPPORT);
                }
            }
            unsafe {
                std::slice::from_raw_parts(
                    &sa as *const _ as *const u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                )
            }
            .to_vec()
        };
        return Ok(ConnectPlan {
            addr,
            record_orig_dest: true,
        });
    }
    let mut addr = addr_bytes.to_vec();
    if let Some(real_port) = remap_port {
        set_port_in_sockaddr(&mut addr, real_port);
    }
    Ok(ConnectPlan {
        addr,
        record_orig_dest: false,
    })
}

/// Execute-phase helper for a proxy redirect: bind an ephemeral local address
/// on `fd` (port 0, any address) and read it back with getsockname(), then
/// record (local addr, original destination IP) so the proxy can resolve the
/// intended destination of the connection it is about to receive. Failures
/// are silent, matching the prior behavior: a missed mapping degrades the
/// proxy's view of one connection, it does not block the connect.
fn record_orig_dest(
    map: &crate::transparent_proxy::OrigDestMap,
    fd: RawFd,
    is_ipv6: bool,
    orig_ip: IpAddr,
) {
    let local_addr = if is_ipv6 {
        let mut bind_sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        // port 0 + IN6ADDR_ANY = kernel picks the ephemeral port.
        bind_sa6.sin6_family = libc::AF_INET6 as u16;
        unsafe {
            libc::bind(
                fd,
                &bind_sa6 as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            );
        }
        let mut local_sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut local_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let gs_ret = unsafe {
            libc::getsockname(
                fd,
                &mut local_sa6 as *mut _ as *mut libc::sockaddr,
                &mut local_len,
            )
        };
        if gs_ret != 0 {
            return;
        }
        let local_port = u16::from_be(local_sa6.sin6_port);
        let local_ip = Ipv6Addr::from(local_sa6.sin6_addr.s6_addr);
        std::net::SocketAddr::V6(std::net::SocketAddrV6::new(local_ip, local_port, 0, 0))
    } else {
        let mut bind_sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        // port 0 + INADDR_ANY = kernel picks the ephemeral port.
        bind_sa.sin_family = libc::AF_INET as u16;
        unsafe {
            libc::bind(
                fd,
                &bind_sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
        }
        let mut local_sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut local_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let gs_ret = unsafe {
            libc::getsockname(
                fd,
                &mut local_sa as *mut _ as *mut libc::sockaddr,
                &mut local_len,
            )
        };
        if gs_ret != 0 {
            return;
        }
        let local_port = u16::from_be(local_sa.sin_port);
        let local_ip = Ipv4Addr::from(u32::from_be(local_sa.sin_addr.s_addr));
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(local_ip, local_port))
    };
    if let Ok(mut m) = map.write() {
        m.insert(local_addr, orig_ip);
    }
}

/// Execute-phase tail: connect(2) on the dup'd socket to the planned target.
/// On failure, a stale orig_dest entry is harmless: the proxy never sees this
/// connection, and the entry is overwritten by the next successful request
/// from the same local address (or dropped on shutdown).
fn connect_dup(fd: RawFd, addr: &[u8]) -> NotifAction {
    let ret = unsafe {
        libc::connect(
            fd,
            addr.as_ptr() as *const libc::sockaddr,
            addr.len() as libc::socklen_t,
        )
    };
    if ret == 0 {
        NotifAction::ReturnValue(0)
    } else {
        NotifAction::Errno(unsafe { *libc::__errno_location() })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- plan_connect_target tests (connect decide phase) ---

    fn v4_sockaddr(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as u16;
        sa.sin_port = port.to_be();
        sa.sin_addr.s_addr = u32::from_ne_bytes(ip);
        unsafe {
            std::slice::from_raw_parts(
                &sa as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            )
        }
        .to_vec()
    }

    fn v6_sockaddr(port: u16) -> Vec<u8> {
        let mut sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sa6.sin6_family = libc::AF_INET6 as u16;
        sa6.sin6_port = port.to_be();
        sa6.sin6_addr.s6_addr = std::net::Ipv6Addr::LOCALHOST.octets();
        unsafe {
            std::slice::from_raw_parts(
                &sa6 as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_in6>(),
            )
        }
        .to_vec()
    }

    #[test]
    fn plan_passthrough_keeps_original_bytes() {
        let a = v4_sockaddr([10, 0, 0, 1], 443);
        let plan = plan_connect_target(&a, None, None).unwrap();
        assert_eq!(plan.addr, a);
        assert!(!plan.record_orig_dest);
    }

    #[test]
    fn plan_remap_rewrites_only_the_port() {
        let a = v4_sockaddr([127, 0, 0, 1], 8080);
        let plan = plan_connect_target(&a, None, Some(41234)).unwrap();
        assert_eq!(parse_port_from_sockaddr(&plan.addr), Some(41234));
        assert_eq!(
            parse_ip_from_sockaddr(&plan.addr),
            parse_ip_from_sockaddr(&a)
        );
        assert!(!plan.record_orig_dest);
    }

    #[test]
    fn plan_v4_proxy_redirects_v4_destination() {
        let a = v4_sockaddr([93, 184, 216, 34], 80);
        let proxy: std::net::SocketAddr = "127.0.0.1:3128".parse().unwrap();
        let plan = plan_connect_target(&a, Some(proxy), None).unwrap();
        assert_eq!(
            parse_ip_from_sockaddr(&plan.addr),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(parse_port_from_sockaddr(&plan.addr), Some(3128));
        assert!(plan.record_orig_dest);
    }

    #[test]
    fn plan_proxy_on_v6_destination_uses_mapped_address() {
        let a = v6_sockaddr(80);
        let proxy: std::net::SocketAddr = "127.0.0.1:3128".parse().unwrap();
        let plan = plan_connect_target(&a, Some(proxy), None).unwrap();
        assert_eq!(
            parse_ip_from_sockaddr(&plan.addr),
            Some("::ffff:127.0.0.1".parse().unwrap())
        );
        assert_eq!(parse_port_from_sockaddr(&plan.addr), Some(3128));
        assert!(plan.record_orig_dest);
    }

    #[test]
    fn plan_v6_proxy_on_v4_destination_fails_closed() {
        let a = v4_sockaddr([93, 184, 216, 34], 80);
        let proxy: std::net::SocketAddr = "[::1]:3128".parse().unwrap();
        assert_eq!(
            plan_connect_target(&a, Some(proxy), None).map(|p| p.addr),
            Err(libc::EAFNOSUPPORT)
        );
    }

    #[test]
    fn plan_remap_does_not_apply_to_redirect() {
        let a = v4_sockaddr([127, 0, 0, 1], 8080);
        let proxy: std::net::SocketAddr = "127.0.0.1:3128".parse().unwrap();
        let plan = plan_connect_target(&a, Some(proxy), Some(41234)).unwrap();
        assert_eq!(parse_port_from_sockaddr(&plan.addr), Some(3128));
        assert!(plan.record_orig_dest);
    }

}

