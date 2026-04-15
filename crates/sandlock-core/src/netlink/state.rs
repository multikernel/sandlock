use std::collections::HashSet;
use std::sync::Mutex;

/// Per-sandbox registry of virtualized netlink cookie fds.
///
/// Keyed by `(pid, fd)` — the exact fd number allocated in the child
/// when our `socket(AF_NETLINK, ..., NETLINK_ROUTE)` handler returned
/// `InjectFdSendTracked`.  Using the fd number directly (instead of
/// comparing `/proc/<pid>/fd/<fd>` inodes against a set of injected
/// inodes) avoids TOCTOU: once we record `(pid, fd)`, no other thread
/// can redirect that fd slot without our `close` handler observing it
/// and removing the entry first.
#[derive(Default)]
pub struct NetlinkState {
    cookies: Mutex<HashSet<(i32, i32)>>,
}

impl NetlinkState {
    pub fn new() -> Self {
        Self { cookies: Mutex::new(HashSet::new()) }
    }

    /// Register a new cookie fd injected into the child.
    pub fn register(&self, pid: i32, fd: i32) {
        self.cookies.lock().unwrap().insert((pid, fd));
    }

    /// Remove a cookie entry.  Called from the close handler when the
    /// child closes a tracked fd.
    pub fn unregister(&self, pid: i32, fd: i32) {
        self.cookies.lock().unwrap().remove(&(pid, fd));
    }

    /// Is this (pid, fd) one of our injected netlink cookies?
    pub fn is_cookie(&self, pid: i32, fd: i32) -> bool {
        self.cookies.lock().unwrap().contains(&(pid, fd))
    }
}
