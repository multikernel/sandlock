use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::sync::Mutex;

/// Per-sandbox registry of virtualized netlink cookie fds.
///
/// Keyed by `(tgid, fd)`, the slot the kernel allocated when the
/// `socket(AF_NETLINK, ..., NETLINK_ROUTE)` handler injected one end of a
/// socketpair. The slot alone does not identify the cookie: dup2, close_range
/// and exec all replace an fd without a close() the supervisor could trap,
/// so each entry also holds the socket cookie of the injected end, and a
/// lookup checks the fd currently in the slot against it.
#[derive(Default)]
pub struct NetlinkState {
    cookies: Mutex<HashMap<(i32, i32), u64>>,
}

/// The kernel's per-socket cookie: 64 bits, assigned once, never reused
/// while the system is up, unlike an inode number.
pub(crate) fn socket_cookie(fd: &impl AsRawFd) -> Option<u64> {
    let mut cookie: u64 = 0;
    let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(cookie)
}

impl NetlinkState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the cookie fd injected into the child at `(tgid, fd)`.
    pub fn register(&self, tgid: i32, fd: i32, cookie: u64) {
        self.cookies.lock().unwrap().insert((tgid, fd), cookie);
    }

    /// Whether the fd now in slot `(tgid, fd)` is the injected cookie. A
    /// slot the child reused for something else is forgotten on the spot.
    pub fn is_cookie(&self, tgid: i32, fd: i32) -> bool {
        let Some(expected) = self.cookies.lock().unwrap().get(&(tgid, fd)).copied() else {
            return false;
        };
        let current = crate::seccomp::notif::dup_fd_from_pid(tgid as u32, fd)
            .ok()
            .and_then(|dup| socket_cookie(&dup));
        if current == Some(expected) {
            return true;
        }
        self.cookies.lock().unwrap().remove(&(tgid, fd));
        false
    }
}
