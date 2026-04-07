// Port remapping for multi-sandbox isolation via seccomp notification.
//
// Intercepts bind and getsockname syscalls to track and remap ports.
// When a sandbox binds to a port that conflicts with another sandbox,
// the supervisor can transparently remap it to an available port.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction};
use crate::seccomp::state::NetworkState;
use crate::sys::structs::{SeccompNotif, AF_INET, AF_INET6};

// ============================================================
// PortMap — tracks virtual-to-real port mappings
// ============================================================

/// Tracks port bindings for a sandbox.
///
/// `virtual_to_real` maps the port the child thinks it bound to the actual
/// port on the host. `real_to_virtual` is the reverse mapping, used to
/// translate getsockname results back to the virtual port.
#[derive(Debug, Default)]
pub struct PortMap {
    /// virtual port -> real port
    pub virtual_to_real: HashMap<u16, u16>,
    /// real port -> virtual port
    pub real_to_virtual: HashMap<u16, u16>,
    /// Set of ports actually bound on the host by this sandbox.
    pub bound_ports: std::collections::HashSet<u16>,
}

impl PortMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a port binding. If the port was remapped, records both directions.
    pub fn record_bind(&mut self, virtual_port: u16, real_port: u16) {
        self.bound_ports.insert(real_port);
        if virtual_port != real_port {
            self.virtual_to_real.insert(virtual_port, real_port);
            self.real_to_virtual.insert(real_port, virtual_port);
        }
    }

    /// Look up the real port for a virtual port.
    pub fn get_real(&self, virtual_port: u16) -> Option<u16> {
        self.virtual_to_real.get(&virtual_port).copied()
    }

    /// Look up the virtual port for a real port.
    pub fn get_virtual(&self, real_port: u16) -> Option<u16> {
        self.real_to_virtual.get(&real_port).copied()
    }

    /// Return a real port for `virtual_port`, allocating one if needed.
    ///
    /// Fast path: try to use the virtual port itself. If that port is already
    /// taken on the host, fall back to asking the kernel for any free ephemeral
    /// port. Once a mapping is established it is cached and returned unchanged
    /// on subsequent calls.
    pub fn allocate_or_reserve(&mut self, virtual_port: u16, family: u32) -> Option<u16> {
        // Already mapped?
        if let Some(real) = self.virtual_to_real.get(&virtual_port) {
            return Some(*real);
        }
        // Fast path: try the virtual port itself
        if let Some(port) = try_reserve_port(virtual_port, family) {
            self.record_bind(virtual_port, port);
            return Some(port);
        }
        // Slow path: allocate different port
        let real = allocate_real_port(family)?;
        self.record_bind(virtual_port, real);
        Some(real)
    }
}

// ============================================================
// Port extraction from sockaddr
// ============================================================

/// Extract the port number from a sockaddr buffer (AF_INET or AF_INET6).
/// Returns None for non-IP address families.
fn extract_port(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as u32;
    match family {
        f if f == AF_INET || f == AF_INET6 => {
            // Port is bytes 2-3 in network byte order (big endian)
            Some(u16::from_be_bytes([bytes[2], bytes[3]]))
        }
        _ => None,
    }
}

/// Write a modified port back into a sockaddr buffer at the port offset.
fn set_port_in_sockaddr(bytes: &mut [u8], port: u16) {
    if bytes.len() >= 4 {
        let port_bytes = port.to_be_bytes();
        bytes[2] = port_bytes[0];
        bytes[3] = port_bytes[1];
    }
}

// ============================================================
// Port allocation helpers
// ============================================================

/// Check if a port is available by probe-and-close.
fn try_reserve_port(port: u16, family: u32) -> Option<u16> {
    if port == 0 {
        return None;
    }
    let addr: SocketAddr = if family == AF_INET6 {
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)
    } else {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    };
    TcpListener::bind(addr).ok().map(|_| port)
}

/// Allocate a free ephemeral port from the kernel via bind(0).
fn allocate_real_port(family: u32) -> Option<u16> {
    let addr: SocketAddr = if family == AF_INET6 {
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0)
    } else {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)
    };
    let listener = TcpListener::bind(addr).ok()?;
    Some(listener.local_addr().ok()?.port())
}

// ============================================================
// handle_bind — intercept bind to track/remap ports
// ============================================================

/// Handle bind syscalls on behalf of the child process (TOCTOU-safe).
///
/// Performs bind() in the supervisor using a duplicated copy of the child's
/// socket fd (via pidfd_getfd). This avoids TOCTOU races and allows port
/// remapping to be applied transparently.
///
/// bind(sockfd, addr, addrlen): args[0]=fd, args[1]=addr_ptr, args[2]=addrlen
pub(crate) async fn handle_bind(
    notif: &SeccompNotif,
    network: &Arc<Mutex<NetworkState>>,
    notif_fd: RawFd,
) -> NotifAction {
    let sockfd = notif.data.args[0] as i32;
    let addr_ptr = notif.data.args[1];
    let addr_len = notif.data.args[2] as usize;

    if addr_ptr == 0 || addr_len < 4 {
        return NotifAction::Continue;
    }

    let read_len = addr_len.min(128);
    let mut bytes = match read_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, read_len) {
        Ok(b) => b,
        Err(_) => return NotifAction::Errno(libc::EIO),
    };

    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as u32;

    if let Some(virtual_port) = extract_port(&bytes) {
        if virtual_port == 0 {
            // Ephemeral port — still do on-behalf for TOCTOU safety
            let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
                Ok(fd) => fd,
                Err(_) => return NotifAction::Errno(libc::ENOSYS),
            };
            let ret = unsafe {
                libc::bind(dup_fd.as_raw_fd(), bytes.as_ptr() as *const libc::sockaddr, addr_len as libc::socklen_t)
            };
            return if ret == 0 {
                NotifAction::ReturnValue(0)
            } else {
                NotifAction::Errno(unsafe { *libc::__errno_location() })
            };
        }

        let mut ns = network.lock().await;
        // Apply port remapping on our copy
        if let Some(real_port) = ns.port_map.allocate_or_reserve(virtual_port, family) {
            if real_port != virtual_port {
                set_port_in_sockaddr(&mut bytes, real_port);
            }
        }

        drop(ns);

        // Duplicate child's socket and bind in supervisor
        let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
            Ok(fd) => fd,
            Err(_) => return NotifAction::Errno(libc::ENOSYS),
        };

        let ret = unsafe {
            libc::bind(dup_fd.as_raw_fd(), bytes.as_ptr() as *const libc::sockaddr, addr_len as libc::socklen_t)
        };

        if ret == 0 {
            NotifAction::ReturnValue(0)
        } else {
            NotifAction::Errno(unsafe { *libc::__errno_location() })
        }
    } else {
        // Non-IP family — still do on-behalf for consistency
        let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
            Ok(fd) => fd,
            Err(_) => return NotifAction::Errno(libc::ENOSYS),
        };
        let ret = unsafe {
            libc::bind(dup_fd.as_raw_fd(), bytes.as_ptr() as *const libc::sockaddr, addr_len as libc::socklen_t)
        };
        if ret == 0 {
            NotifAction::ReturnValue(0)
        } else {
            NotifAction::Errno(unsafe { *libc::__errno_location() })
        }
    }
}

// ============================================================
// handle_getsockname — translate real port back to virtual port
// ============================================================

/// Handle getsockname to translate real ports back to virtual ports.
///
/// After getsockname executes, reads the returned sockaddr and replaces
/// the real port with the virtual port if a mapping exists.
///
/// For Phase 5, this is a framework — since we only do identity mappings
/// in handle_bind, getsockname will always see the correct port. When
/// actual remapping is added, this will rewrite the port in the result.
///
/// getsockname(sockfd, addr, addrlen): args[0]=fd, args[1]=addr_ptr, args[2]=addrlen_ptr
pub(crate) async fn handle_getsockname(
    notif: &SeccompNotif,
    network: &Arc<Mutex<NetworkState>>,
    notif_fd: RawFd,
) -> NotifAction {
    let addr_ptr = notif.data.args[1];
    let addrlen_ptr = notif.data.args[2];

    if addr_ptr == 0 || addrlen_ptr == 0 {
        return NotifAction::Continue;
    }

    // Read the addrlen value to know how many bytes to read.
    let addrlen_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, addrlen_ptr, 4) {
        Ok(b) if b.len() >= 4 => b,
        _ => return NotifAction::Continue,
    };
    let addr_len = u32::from_ne_bytes(addrlen_bytes[..4].try_into().unwrap()) as usize;

    if addr_len < 4 {
        return NotifAction::Continue;
    }

    let read_len = addr_len.min(128);
    let mut bytes = match read_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, read_len) {
        Ok(b) => b,
        Err(_) => return NotifAction::Continue,
    };

    if let Some(real_port) = extract_port(&bytes) {
        let ns = network.lock().await;
        if let Some(virtual_port) = ns.port_map.get_virtual(real_port) {
            // Rewrite the port in the sockaddr buffer.
            set_port_in_sockaddr(&mut bytes, virtual_port);
            drop(ns);
            // Write the modified sockaddr back to child memory.
            let _ = write_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, &bytes);
        }
    }

    NotifAction::Continue
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_map_identity() {
        let mut pm = PortMap::new();
        pm.record_bind(8080, 8080);
        assert!(pm.bound_ports.contains(&8080));
        assert_eq!(pm.get_real(8080), None); // identity — not stored in remap tables
        assert_eq!(pm.get_virtual(8080), None);
    }

    #[test]
    fn test_port_map_remap() {
        let mut pm = PortMap::new();
        pm.record_bind(8080, 9090);
        assert!(pm.bound_ports.contains(&9090));
        assert_eq!(pm.get_real(8080), Some(9090));
        assert_eq!(pm.get_virtual(9090), Some(8080));
    }

    #[test]
    fn test_extract_port_ipv4() {
        // AF_INET = 2, port 8080 (0x1F90) in network byte order
        let mut buf = vec![0u8; 16];
        let family = (AF_INET as u16).to_ne_bytes();
        buf[0] = family[0];
        buf[1] = family[1];
        buf[2] = 0x1F; // port high byte
        buf[3] = 0x90; // port low byte
        assert_eq!(extract_port(&buf), Some(8080));
    }

    #[test]
    fn test_extract_port_ipv6() {
        let mut buf = vec![0u8; 28];
        let family = (AF_INET6 as u16).to_ne_bytes();
        buf[0] = family[0];
        buf[1] = family[1];
        buf[2] = 0x00;
        buf[3] = 0x50; // port 80
        assert_eq!(extract_port(&buf), Some(80));
    }

    #[test]
    fn test_extract_port_unix() {
        // AF_UNIX = 1
        let buf = vec![1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(extract_port(&buf), None);
    }

    #[test]
    fn test_extract_port_too_short() {
        let buf = vec![2, 0];
        assert_eq!(extract_port(&buf), None);
    }

    #[test]
    fn test_set_port_in_sockaddr() {
        let mut buf = vec![0u8; 16];
        set_port_in_sockaddr(&mut buf, 443);
        assert_eq!(buf[2], 0x01);
        assert_eq!(buf[3], 0xBB);
    }

    #[test]
    fn test_try_reserve_port_zero() {
        assert!(try_reserve_port(0, AF_INET).is_none());
    }

    #[test]
    fn test_allocate_real_port() {
        let port = allocate_real_port(AF_INET);
        assert!(port.is_some());
        assert!(port.unwrap() > 0);
    }

    #[test]
    fn test_port_map_allocate_or_reserve() {
        let mut pm = PortMap::new();
        let real = pm.allocate_or_reserve(18080, AF_INET); // use high port unlikely to conflict
        assert!(real.is_some());
        let real = real.unwrap();
        assert!(pm.bound_ports.contains(&real));
    }

    #[test]
    fn test_port_map_allocate_or_reserve_cached() {
        let mut pm = PortMap::new();
        let first = pm.allocate_or_reserve(18081, AF_INET).unwrap();
        let second = pm.allocate_or_reserve(18081, AF_INET).unwrap();
        assert_eq!(first, second); // should return cached mapping
    }
}
