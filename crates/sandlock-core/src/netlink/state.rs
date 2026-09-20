use std::collections::HashMap;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;

use crate::sys::syscall::{pidfd_getfd, pidfd_open};

/// The kernel's id for a socket (`SO_COOKIE`): 64 bits, never reused.
///
/// Not the inode number: those come from a 32-bit counter shared with pipes,
/// which wraps without checking for live collisions, so a sandboxed process
/// can steer a new socket onto a number of its choosing.
pub(crate) fn socket_cookie(fd: RawFd) -> io::Result<u64> {
    let mut cookie: u64 = 0;
    let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            &mut cookie as *mut u64 as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 { Ok(cookie) } else { Err(io::Error::last_os_error()) }
}

/// Per-sandbox registry of virtualized netlink cookie fds.
///
/// Keyed by `(pid, fd)`, the exact fd number allocated in the child when our
/// `socket(AF_NETLINK, ..., NETLINK_ROUTE)` handler returned
/// `InjectFdSendTracked`, and holding the id of the socket injected there.
///
/// The id is what keeps an entry honest. A slot can be emptied or refilled
/// without any syscall we could watch (`dup2`, `close_range`, `O_CLOEXEC` on
/// exec), and watching `close` itself costs more than it buys: a trapped
/// `close` that a signal interrupts never runs, and callers do not retry it
/// (issue #235). So nothing tracks the slot, and every lookup checks that it
/// still holds our socket.
#[derive(Default)]
pub struct NetlinkState {
    cookies: Mutex<HashMap<(i32, i32), u64>>,
}

impl NetlinkState {
    pub fn new() -> Self {
        Self { cookies: Mutex::new(HashMap::new()) }
    }

    /// Register a new cookie fd injected into the child.
    pub fn register(&self, pid: i32, fd: i32, socket_cookie: u64) {
        self.cookies.lock().unwrap().insert((pid, fd), socket_cookie);
    }

    /// Is this (pid, fd) still one of our injected netlink cookies?
    pub fn is_cookie(&self, pid: i32, fd: i32) -> bool {
        let mut cookies = self.cookies.lock().unwrap();
        let Some(&ours) = cookies.get(&(pid, fd)) else {
            return false;
        };
        if socket_cookie_in(pid, fd).ok() == Some(ours) {
            return true;
        }
        cookies.remove(&(pid, fd));
        false
    }

    /// Drop every entry of a process that has exited.
    pub fn forget_process(&self, pid: i32) {
        self.cookies.lock().unwrap().retain(|&(owner, _), _| owner != pid);
    }
}

fn socket_cookie_in(pid: i32, fd: i32) -> io::Result<u64> {
    let process = pidfd_open(pid as u32, 0)?;
    let socket = pidfd_getfd(&process, fd, 0)?;
    socket_cookie(socket.as_raw_fd())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_reused_fd_slot_is_no_longer_a_cookie() {
        let pid = std::process::id() as i32;
        let (ours, _peer) = UnixStream::pair().unwrap();
        let fd = ours.as_raw_fd();

        let state = NetlinkState::new();
        state.register(pid, fd, socket_cookie(fd).unwrap());
        assert!(state.is_cookie(pid, fd));

        // No close() is seen here, as with dup2 or close_range in a child.
        let other = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(unsafe { libc::dup2(other.as_raw_fd(), fd) }, fd);
        assert!(!state.is_cookie(pid, fd));
    }

    #[test]
    fn another_socket_in_the_slot_is_not_ours() {
        let pid = std::process::id() as i32;
        let (ours, _peer) = UnixStream::pair().unwrap();
        let fd = ours.as_raw_fd();

        let state = NetlinkState::new();
        state.register(pid, fd, socket_cookie(fd).unwrap());

        let (later, _peer2) = UnixStream::pair().unwrap();
        assert_eq!(unsafe { libc::dup2(later.as_raw_fd(), fd) }, fd);
        assert!(!state.is_cookie(pid, fd));
    }

    #[test]
    fn forget_process_drops_only_that_process() {
        let state = NetlinkState::new();
        state.register(10, 3, 1);
        state.register(11, 3, 2);
        state.forget_process(10);
        let cookies = state.cookies.lock().unwrap();
        assert!(!cookies.contains_key(&(10, 3)) && cookies.contains_key(&(11, 3)));
    }
}
