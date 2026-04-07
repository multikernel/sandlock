// Network control handlers — IP allowlist enforcement via seccomp notification.
//
// Intercepts connect/sendto/sendmsg syscalls, extracts the destination IP from
// the child's memory, and checks it against an allowlist of resolved IPs.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_mem, NotifAction};
use crate::sys::structs::{SeccompNotif, AF_INET, AF_INET6, ECONNREFUSED};

/// Maximum buffer size for sendto/sendmsg on-behalf operations (64 MiB).
/// Prevents a sandboxed process from triggering OOM in the supervisor.
const MAX_SEND_BUF: usize = 64 << 20;

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

    // 2. Check IP against allowlist
    if let Some(ip) = parse_ip_from_sockaddr(&addr_bytes) {
        let ns = ctx.network.lock().await;
        let live_policy = {
            let pfs = ctx.policy_fn.lock().await;
            pfs.live_policy.clone()
        };
        if let crate::seccomp::notif::NetworkPolicy::AllowList(ref allowed) =
            ns.effective_network_policy(notif.pid, live_policy.as_ref())
        {
            if !allowed.contains(&ip) {
                return NotifAction::Errno(ECONNREFUSED);
            }
        }
        // Check for HTTP ACL redirect
        let dest_port = parse_port_from_sockaddr(&addr_bytes);
        let http_acl_addr = ns.http_acl_addr;
        let http_acl_intercept = dest_port.map_or(false, |p| ns.http_acl_ports.contains(&p));
        let http_acl_orig_dest = ns.http_acl_orig_dest.clone();

        drop(ns);

        // Determine the actual connect target (redirect HTTP/HTTPS to proxy)
        let mut redirected = false;
        let is_ipv6 = parse_ip_from_sockaddr(&addr_bytes)
            .map_or(false, |ip| ip.is_ipv6());
        let (connect_addr, connect_len) = if let Some(proxy_addr) = http_acl_addr {
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

        // 3. Duplicate child's socket into supervisor (use notif.pid for grandchild support)
        let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
            Ok(fd) => fd,
            Err(_) => return NotifAction::Errno(libc::ENOSYS),
        };

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
        // Non-IP family (AF_UNIX etc.) — allow through
        NotifAction::Continue
    }
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

    // 2. Check IP against allowlist
    if let Some(ip) = parse_ip_from_sockaddr(&addr_bytes) {
        let ns = ctx.network.lock().await;
        let live_policy = {
            let pfs = ctx.policy_fn.lock().await;
            pfs.live_policy.clone()
        };
        if let crate::seccomp::notif::NetworkPolicy::AllowList(ref allowed) =
            ns.effective_network_policy(notif.pid, live_policy.as_ref())
        {
            if !allowed.contains(&ip) {
                return NotifAction::Errno(ECONNREFUSED);
            }
        }
        drop(ns);

        // 3. Copy data buffer from child memory
        let data = match read_child_mem(notif_fd, notif.id, notif.pid, buf_ptr, buf_len) {
            Ok(b) => b,
            Err(_) => return NotifAction::Errno(libc::EIO),
        };

        // 4. Duplicate child's socket into supervisor (use notif.pid for grandchild support)
        let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
            Ok(fd) => fd,
            Err(_) => return NotifAction::Errno(libc::ENOSYS),
        };

        // 5. Perform sendto in supervisor with validated sockaddr + copied data
        let ret = unsafe {
            libc::sendto(
                dup_fd.as_raw_fd(),
                data.as_ptr() as *const libc::c_void,
                data.len(),
                flags,
                addr_bytes.as_ptr() as *const libc::sockaddr,
                addr_len as libc::socklen_t,
            )
        };

        // 6. Return result
        if ret >= 0 {
            NotifAction::ReturnValue(ret as i64)
        } else {
            let errno = unsafe { *libc::__errno_location() };
            NotifAction::Errno(errno)
        }
    } else {
        // Non-IP family (AF_UNIX etc.) — allow through
        NotifAction::Continue
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

    // 1. Read full msghdr struct (56 bytes on x86_64):
    //   msg_name(8) + msg_namelen(4) + pad(4) + msg_iov(8) + msg_iovlen(8)
    //   + msg_control(8) + msg_controllen(8) + msg_flags(4) + pad(4)
    let msghdr_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, msghdr_ptr, 56) {
        Ok(b) if b.len() >= 56 => b,
        _ => return NotifAction::Continue,
    };

    let msg_name_ptr = u64::from_ne_bytes(msghdr_bytes[0..8].try_into().unwrap());
    let msg_namelen = u32::from_ne_bytes(msghdr_bytes[8..12].try_into().unwrap());
    let msg_iov_ptr = u64::from_ne_bytes(msghdr_bytes[16..24].try_into().unwrap());
    let msg_iovlen = u64::from_ne_bytes(msghdr_bytes[24..32].try_into().unwrap());
    let msg_control_ptr = u64::from_ne_bytes(msghdr_bytes[32..40].try_into().unwrap());
    let msg_controllen = u64::from_ne_bytes(msghdr_bytes[40..48].try_into().unwrap());

    if msg_name_ptr == 0 {
        return NotifAction::Continue; // no address — connected socket
    }

    // 2. Copy sockaddr from msg_name
    let addr_bytes = match read_child_mem(
        notif_fd, notif.id, notif.pid, msg_name_ptr, msg_namelen as usize,
    ) {
        Ok(b) => b,
        Err(_) => return NotifAction::Errno(libc::EIO),
    };

    // 3. Check IP against allowlist
    let ip = match parse_ip_from_sockaddr(&addr_bytes) {
        Some(ip) => ip,
        None => return NotifAction::Continue, // Non-IP family — allow through
    };

    let ns = ctx.network.lock().await;
    let live_policy = {
        let pfs = ctx.policy_fn.lock().await;
        pfs.live_policy.clone()
    };
    if let crate::seccomp::notif::NetworkPolicy::AllowList(ref allowed) =
        ns.effective_network_policy(notif.pid, live_policy.as_ref())
    {
        if !allowed.contains(&ip) {
            return NotifAction::Errno(ECONNREFUSED);
        }
    }
    drop(ns);

    // 4. Copy iovec entries and their data buffers from child memory
    // Safety: cap iovlen to prevent excessive allocation
    let iovlen = (msg_iovlen as usize).min(1024);
    let iov_size = iovlen * 16; // each iovec is 16 bytes (ptr + len)
    let iov_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, msg_iov_ptr, iov_size) {
        Ok(b) => b,
        Err(_) => return NotifAction::Errno(libc::EIO),
    };

    let mut data_bufs: Vec<Vec<u8>> = Vec::with_capacity(iovlen);
    let mut local_iovs: Vec<libc::iovec> = Vec::with_capacity(iovlen);

    for i in 0..iovlen {
        let off = i * 16;
        if off + 16 > iov_bytes.len() { break; }
        let iov_base = u64::from_ne_bytes(iov_bytes[off..off + 8].try_into().unwrap());
        let iov_len = u64::from_ne_bytes(iov_bytes[off + 8..off + 16].try_into().unwrap()) as usize;

        if iov_len > MAX_SEND_BUF {
            return NotifAction::Errno(libc::EMSGSIZE);
        }

        if iov_base == 0 || iov_len == 0 {
            data_bufs.push(Vec::new());
            continue;
        }

        let buf = match read_child_mem(notif_fd, notif.id, notif.pid, iov_base, iov_len) {
            Ok(b) => b,
            Err(_) => return NotifAction::Errno(libc::EIO),
        };
        data_bufs.push(buf);
    }

    // Build local iovec array pointing to our copied data
    for buf in &data_bufs {
        local_iovs.push(libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        });
    }

    // 5. Copy control message buffer (ancillary data)
    let control_buf = if msg_control_ptr != 0 && msg_controllen > 0 {
        let len = (msg_controllen as usize).min(4096);
        read_child_mem(notif_fd, notif.id, notif.pid, msg_control_ptr, len).ok()
    } else {
        None
    };

    // 6. Duplicate child's socket into supervisor (use notif.pid for grandchild support)
    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(_) => return NotifAction::Errno(libc::ENOSYS),
    };

    // 7. Build msghdr and perform sendmsg in supervisor
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = addr_bytes.as_ptr() as *mut libc::c_void;
    msg.msg_namelen = addr_bytes.len() as u32;
    msg.msg_iov = local_iovs.as_mut_ptr();
    msg.msg_iovlen = local_iovs.len();
    if let Some(ref ctrl) = control_buf {
        msg.msg_control = ctrl.as_ptr() as *mut libc::c_void;
        msg.msg_controllen = ctrl.len();
    }

    let ret = unsafe { libc::sendmsg(dup_fd.as_raw_fd(), &msg, flags) };

    // 8. Return result
    if ret >= 0 {
        NotifAction::ReturnValue(ret as i64)
    } else {
        let errno = unsafe { *libc::__errno_location() };
        NotifAction::Errno(errno)
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
    } else {
        NotifAction::Continue
    }
}

// ============================================================
// resolve_hosts — resolve domain names to IPs
// ============================================================

/// Resolve a list of domain names to IP addresses.
///
/// Always includes loopback addresses (127.0.0.1 and ::1).
/// Uses tokio's async DNS resolver.
pub async fn resolve_hosts(hosts: &[String]) -> io::Result<HashSet<IpAddr>> {
    let mut ips = HashSet::new();

    // Always allow loopback
    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));

    for host in hosts {
        // Append a dummy port for lookup_host
        let addr = format!("{}:0", host);
        let result = tokio::net::lookup_host(addr.as_str()).await;
        match result {
            Ok(resolved) => {
                for socket_addr in resolved {
                    ips.insert(socket_addr.ip());
                }
            }
            Err(e) => {
                // Return error on DNS failure to avoid silently skipping hosts
                return Err(io::Error::new(
                    e.kind(),
                    format!("failed to resolve host '{}': {}", host, e),
                ));
            }
        }
    }

    Ok(ips)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_hosts_loopback() {
        let ips = resolve_hosts(&[]).await.unwrap();
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[tokio::test]
    async fn test_resolve_hosts_with_domain() {
        let hosts = vec!["localhost".to_string()];
        let ips = resolve_hosts(&hosts).await.unwrap();
        // localhost should resolve to loopback
        assert!(
            ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST))
                || ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }
}
