// Network control handlers — IP allowlist enforcement via seccomp notification.
//
// Intercepts connect/sendto/sendmsg syscalls, extracts the destination IP from
// the child's memory, and checks it against an allowlist of resolved IPs.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;
use std::sync::Arc;

use tokio::sync::Mutex;

use std::os::unix::io::AsRawFd;

use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction, SupervisorState};
use crate::sys::structs::{SeccompNotif, AF_INET, AF_INET6, ECONNREFUSED};

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
    state: &Arc<Mutex<SupervisorState>>,
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
        let st = state.lock().await;
        if let crate::seccomp::notif::NetworkPolicy::AllowList(ref allowed) =
            st.effective_network_policy(notif.pid)
        {
            if !allowed.contains(&ip) {
                return NotifAction::Errno(ECONNREFUSED);
            }
        }
        let child_pidfd = match st.child_pidfd {
            Some(fd) => fd,
            None => return NotifAction::Errno(libc::ENOSYS),
        };
        drop(st);

        // 3. Duplicate child's socket into supervisor
        let dup_fd = match crate::seccomp::notif::dup_child_fd(child_pidfd, sockfd) {
            Ok(fd) => fd,
            Err(_) => return NotifAction::Errno(libc::ENOSYS),
        };

        // 4. Perform connect in supervisor with our validated sockaddr
        let ret = unsafe {
            libc::connect(
                dup_fd.as_raw_fd(),
                addr_bytes.as_ptr() as *const libc::sockaddr,
                addr_len as libc::socklen_t,
            )
        };

        // 5. Return result
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
// sendto_validate_overwrite / sendmsg_validate_overwrite — validate-and-overwrite
// ============================================================

/// Validate sendto's sockaddr and overwrite in child memory (near-zero TOCTOU).
///
/// 1. Copy sockaddr from child memory (our copy)
/// 2. Check IP against allowlist on our copy
/// 3. Write our validated copy back to child memory
/// 4. CONTINUE (kernel sends with child's data buffer + our validated sockaddr)
async fn sendto_validate_overwrite(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
) -> NotifAction {
    let addr_ptr = notif.data.args[4];
    if addr_ptr == 0 {
        return NotifAction::Continue; // connected socket, no addr to check
    }
    let addr_len = notif.data.args[5] as u32;

    // 1. Copy sockaddr
    let addr_bytes =
        match read_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, addr_len as usize) {
            Ok(b) => b,
            Err(_) => return NotifAction::Errno(libc::EIO),
        };

    // 2. Check IP
    if let Some(ip) = parse_ip_from_sockaddr(&addr_bytes) {
        let st = state.lock().await;
        if let crate::seccomp::notif::NetworkPolicy::AllowList(ref allowed) =
            st.effective_network_policy(notif.pid)
        {
            if !allowed.contains(&ip) {
                return NotifAction::Errno(ECONNREFUSED);
            }
        }
        drop(st);

        // 3. Write validated copy back (shrinks TOCTOU window to nanoseconds)
        let _ = write_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, &addr_bytes);
    }

    // 4. CONTINUE — kernel uses child's data buffer with our validated sockaddr
    NotifAction::Continue
}

/// Validate sendmsg's sockaddr and overwrite in child memory (near-zero TOCTOU).
///
/// 1. Copy sockaddr from msg_name in msghdr
/// 2. Check IP against allowlist on our copy
/// 3. Write our validated copy back to child memory
/// 4. CONTINUE
async fn sendmsg_validate_overwrite(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
) -> NotifAction {
    let msghdr_ptr = notif.data.args[1];

    // Read msghdr: msg_name(8) + msg_namelen(4)
    let msghdr_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, msghdr_ptr, 16) {
        Ok(b) if b.len() >= 12 => b,
        _ => return NotifAction::Continue,
    };

    let msg_name_ptr = u64::from_ne_bytes(msghdr_bytes[0..8].try_into().unwrap());
    if msg_name_ptr == 0 {
        return NotifAction::Continue; // no address — connected socket
    }
    let msg_namelen = u32::from_ne_bytes(msghdr_bytes[8..12].try_into().unwrap());

    // 1. Copy sockaddr from msg_name
    let addr_bytes = match read_child_mem(
        notif_fd,
        notif.id,
        notif.pid,
        msg_name_ptr,
        msg_namelen as usize,
    ) {
        Ok(b) => b,
        Err(_) => return NotifAction::Errno(libc::EIO),
    };

    // 2. Check IP
    if let Some(ip) = parse_ip_from_sockaddr(&addr_bytes) {
        let st = state.lock().await;
        if let crate::seccomp::notif::NetworkPolicy::AllowList(ref allowed) =
            st.effective_network_policy(notif.pid)
        {
            if !allowed.contains(&ip) {
                return NotifAction::Errno(ECONNREFUSED);
            }
        }
        drop(st);

        // 3. Write validated copy back
        let _ = write_child_mem(notif_fd, notif.id, notif.pid, msg_name_ptr, &addr_bytes);
    }

    // 4. CONTINUE
    NotifAction::Continue
}

// ============================================================
// handle_net — main handler for connect/sendto/sendmsg
// ============================================================

/// Handle network-related notifications (connect, sendto, sendmsg).
///
/// connect is handled on-behalf (TOCTOU-safe). sendto/sendmsg use
/// validate-and-overwrite to shrink the TOCTOU window to nanoseconds.
pub(crate) async fn handle_net(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    if nr == libc::SYS_connect {
        connect_on_behalf(notif, state, notif_fd).await
    } else if nr == libc::SYS_sendto {
        sendto_validate_overwrite(notif, state, notif_fd).await
    } else if nr == libc::SYS_sendmsg {
        sendmsg_validate_overwrite(notif, state, notif_fd).await
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
