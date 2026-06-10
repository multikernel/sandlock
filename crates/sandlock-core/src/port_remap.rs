// Port remapping for multi-sandbox isolation via seccomp notification.
//
// Intercepts bind and getsockname syscalls to track and remap ports.
// When a sandbox binds to a port that conflicts with another sandbox,
// the supervisor can transparently remap it to an available port.
//
// Continue safety (issue #27):
//   - handle_bind performs the bind on-behalf via pidfd_getfd (kernel
//     object, not racy user-memory string) and returns ReturnValue/Errno.
//     No security decision returns Continue.
//   - handle_getsockname performs the getsockname on-behalf and writes
//     the translated sockaddr back to the child, so remapped real ports
//     never leak through the virtual interface.

use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
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
#[derive(Default)]
pub struct PortMap {
    /// virtual port -> real port
    pub virtual_to_real: HashMap<u16, u16>,
    /// real port -> virtual port
    pub real_to_virtual: HashMap<u16, u16>,
    /// Set of ports actually bound on the host by this sandbox.
    pub bound_ports: std::collections::HashSet<u16>,
    /// Optional callback invoked after each port bind with the current virtual_to_real map.
    #[allow(clippy::type_complexity)]
    pub on_bind: Option<Box<dyn Fn(&HashMap<u16, u16>) + Send + Sync>>,
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
        if let Some(ref cb) = self.on_bind {
            // Report all bound ports: identity + remapped
            let mut all: HashMap<u16, u16> = self.bound_ports.iter()
                .map(|&p| (self.real_to_virtual.get(&p).copied().unwrap_or(p), p))
                .collect();
            all.extend(self.virtual_to_real.iter().map(|(&v, &r)| (v, r)));
            cb(&all);
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
// handle_bind — intercept bind to track/remap ports
// ============================================================

/// Handle bind syscalls on behalf of the child process (TOCTOU-safe).
///
/// Performs bind() in the supervisor using a duplicated copy of the child's
/// socket fd (via pidfd_getfd). For AF_INET/AF_INET6 with a non-zero port:
///
///   1. Pick a first-attempt port: the cached real port if `port_map` has
///      one for this virtual port, else the virtual port itself.
///   2. Bind the child's socket to that port. On `EADDRINUSE`, retry with
///      port 0 so the kernel picks a fresh real port. The retry covers
///      both the first-time host conflict and the stale-cache case where
///      our previously-allocated real port was reclaimed by another
///      process after the prior socket was closed.
///   3. `record_bind` runs only after the bind succeeds, and only when
///      the mapping actually changed — failed binds leave no stale
///      forward-map entry.
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

    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };

    // Non-IP family or ephemeral (port == 0): bind verbatim — nothing to
    // track or remap. extract_port returns None for non-IP families and
    // for truncated buffers; in both cases the kernel will validate.
    let virtual_port = match extract_port(&bytes) {
        Some(p) if p != 0 => p,
        _ => return bind_verbatim(&dup_fd, &bytes, addr_len),
    };

    // --net-deny-bind: reject binding a denied TCP port. Only TCP is gated
    // (mirroring --net-allow-bind); UDP/other binds are unaffected. The
    // SO_PROTOCOL probe is skipped entirely when the denylist is empty.
    let denied = {
        let ns = network.lock().await;
        !ns.bind_deny_ports.is_empty() && ns.bind_deny_ports.contains(&virtual_port)
    };
    if denied
        && crate::network::query_socket_protocol(dup_fd.as_raw_fd())
            == Some(crate::network::Protocol::Tcp)
    {
        return NotifAction::Errno(libc::EACCES);
    }

    // Pick a first-attempt port: cached real port if known, else the
    // virtual port itself. The cached real port keeps repeat binds of
    // the same virtual port consistent across the sandbox; the virtual
    // port itself is the natural identity-bind target.
    let cached_real = {
        let ns = network.lock().await;
        ns.port_map.get_real(virtual_port)
    };
    let attempt_port = cached_real.unwrap_or(virtual_port);
    set_port_in_sockaddr(&mut bytes, attempt_port);

    let ret = unsafe {
        libc::bind(
            dup_fd.as_raw_fd(),
            bytes.as_ptr() as *const libc::sockaddr,
            addr_len as libc::socklen_t,
        )
    };
    if ret == 0 {
        // The cached mapping (if any) is already correct. Record only
        // when this is a first-time identity bind.
        if cached_real.is_none() {
            network.lock().await.port_map.record_bind(virtual_port, virtual_port);
        }
        return NotifAction::ReturnValue(0);
    }
    let err = unsafe { *libc::__errno_location() };
    if err != libc::EADDRINUSE {
        return NotifAction::Errno(err);
    }

    // EADDRINUSE on the chosen real port. Two cases:
    //   - First-time bind: another process owns the virtual port on the
    //     host.
    //   - Cached bind: our previously-allocated real port was reclaimed
    //     while the sandbox's earlier socket was closed.
    // In both cases let the kernel pick a fresh real port via bind(0).
    set_port_in_sockaddr(&mut bytes, 0);
    let ret = unsafe {
        libc::bind(
            dup_fd.as_raw_fd(),
            bytes.as_ptr() as *const libc::sockaddr,
            addr_len as libc::socklen_t,
        )
    };
    if ret != 0 {
        return NotifAction::Errno(unsafe { *libc::__errno_location() });
    }
    let real_port = match query_local_port(&dup_fd) {
        Some(p) => p,
        None => return NotifAction::Errno(libc::EIO),
    };
    network.lock().await.port_map.record_bind(virtual_port, real_port);
    NotifAction::ReturnValue(0)
}

/// Run `bind(2)` on a duplicated child fd, propagating success or errno.
fn bind_verbatim(fd: &OwnedFd, addr: &[u8], len: usize) -> NotifAction {
    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            addr.as_ptr() as *const libc::sockaddr,
            len as libc::socklen_t,
        )
    };
    if ret == 0 {
        NotifAction::ReturnValue(0)
    } else {
        NotifAction::Errno(unsafe { *libc::__errno_location() })
    }
}

/// Read the local port from a bound socket via `getsockname(2)`.
fn query_local_port(fd: &OwnedFd) -> Option<u16> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            &mut storage as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret != 0 {
        return None;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(&storage as *const _ as *const u8, len as usize)
    };
    extract_port(bytes)
}

// ============================================================
// handle_getsockname — translate real port back to virtual port
// ============================================================

/// Handle getsockname to translate real ports back to virtual ports.
///
/// Performs getsockname() in the supervisor using a duplicated copy of the
/// child's socket fd, rewrites the returned real port to the virtual port
/// when a mapping exists, and copies the result back to child memory.
///
/// getsockname(sockfd, addr, addrlen): args[0]=fd, args[1]=addr_ptr, args[2]=addrlen_ptr
pub(crate) async fn handle_getsockname(
    notif: &SeccompNotif,
    network: &Arc<Mutex<NetworkState>>,
    notif_fd: RawFd,
) -> NotifAction {
    let sockfd = notif.data.args[0] as i32;
    let addr_ptr = notif.data.args[1];
    let addrlen_ptr = notif.data.args[2];

    if addr_ptr == 0 || addrlen_ptr == 0 {
        return NotifAction::Errno(libc::EFAULT);
    }

    // Read the caller-provided buffer length.
    let addrlen_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, addrlen_ptr, 4) {
        Ok(b) if b.len() >= 4 => b,
        _ => return NotifAction::Errno(libc::EFAULT),
    };
    let addr_len = u32::from_ne_bytes(addrlen_bytes[..4].try_into().unwrap()) as usize;

    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let storage_len = std::mem::size_of::<libc::sockaddr_storage>();
    let mut actual_len = addr_len.min(storage_len) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            dup_fd.as_raw_fd(),
            &mut storage as *mut _ as *mut libc::sockaddr,
            &mut actual_len,
        )
    };
    if ret != 0 {
        return NotifAction::Errno(unsafe { *libc::__errno_location() });
    }

    let actual_len_usize = actual_len as usize;
    let to_write = addr_len.min(actual_len_usize).min(storage_len);
    let mut bytes = if to_write == 0 {
        Vec::new()
    } else {
        let storage_bytes = unsafe {
            std::slice::from_raw_parts(
                &storage as *const _ as *const u8,
                storage_len,
            )
        };
        storage_bytes[..to_write].to_vec()
    };

    if let Some(real_port) = extract_port(&bytes) {
        let ns = network.lock().await;
        if let Some(virtual_port) = ns.port_map.get_virtual(real_port) {
            set_port_in_sockaddr(&mut bytes, virtual_port);
        }
    }

    if !bytes.is_empty()
        && write_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, &bytes).is_err()
    {
        return NotifAction::Errno(libc::EFAULT);
    }

    let actual = (actual_len as u32).to_ne_bytes();
    if write_child_mem(notif_fd, notif.id, notif.pid, addrlen_ptr, &actual).is_err() {
        return NotifAction::Errno(libc::EFAULT);
    }

    NotifAction::ReturnValue(0)
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

}
