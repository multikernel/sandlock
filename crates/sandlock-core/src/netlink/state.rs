use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

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

/// Keeps a cookie registered until its responder exits or is cancelled.
#[must_use]
pub struct Registration {
    state: Arc<NetlinkState>,
    slot: (i32, i32),
    cookie: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.state.unregister_if_matches(self.slot, self.cookie);
    }
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

    /// Register the injected fd for the lifetime of its responder.
    pub fn register(self: &Arc<Self>, tgid: i32, fd: i32, cookie: u64) -> Registration {
        self.cookies.lock().unwrap().insert((tgid, fd), cookie);
        Registration { state: Arc::clone(self), slot: (tgid, fd), cookie }
    }

    fn unregister_if_matches(&self, slot: (i32, i32), cookie: u64) {
        let mut cookies = self.cookies.lock().unwrap();
        // A previous responder may finish after its slot has been reused.
        if cookies.get(&slot) == Some(&cookie) {
            cookies.remove(&slot);
        }
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
        self.unregister_if_matches((tgid, fd), expected);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_lifetime_reclaims_entries_during_churn() {
        let state = Arc::new(NetlinkState::new());
        for tgid in 1..1000 {
            let registration = state.register(tgid, 3, tgid as u64);
            assert_eq!(state.cookies.lock().unwrap().len(), 1);
            drop(registration);
            assert!(state.cookies.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn old_registration_does_not_remove_reused_slot() {
        let state = Arc::new(NetlinkState::new());
        let old = state.register(1, 3, 10);
        let new = state.register(1, 3, 20);
        drop(old);
        assert_eq!(state.cookies.lock().unwrap().get(&(1, 3)), Some(&20));
        drop(new);
        assert!(state.cookies.lock().unwrap().is_empty());
    }

    fn socketpair() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        use std::os::fd::FromRawFd;
        let mut fds = [-1; 2];
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
        unsafe { (std::os::fd::OwnedFd::from_raw_fd(fds[0]), std::os::fd::OwnedFd::from_raw_fd(fds[1])) }
    }

    #[tokio::test]
    async fn peer_closure_reclaims_entries_without_cookie_lookups() {
        let state = Arc::new(NetlinkState::new());
        for tgid in 1..100 {
            let (server, client) = socketpair();
            let registration = state.register(tgid, 3, tgid as u64);
            let task = crate::netlink::proxy::spawn_responder(server, tgid as u32, registration);
            drop(client);
            tokio::time::timeout(std::time::Duration::from_secs(2), task).await.unwrap().unwrap();
            assert!(state.cookies.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn responder_cancellation_reclaims_entry_before_first_poll() {
        let state = Arc::new(NetlinkState::new());
        let (server, _client) = socketpair();
        let registration = state.register(1, 3, 10);
        let task = crate::netlink::proxy::spawn_responder(server, 1, registration);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(state.cookies.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn duplicated_peer_keeps_registration_until_last_close() {
        let state = Arc::new(NetlinkState::new());
        let (server, client) = socketpair();
        let duplicate = client.try_clone().unwrap();
        let registration = state.register(1, 3, 10);
        let task = crate::netlink::proxy::spawn_responder(server, 1, registration);
        drop(client);
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert_eq!(state.cookies.lock().unwrap().len(), 1);
        drop(duplicate);
        tokio::time::timeout(std::time::Duration::from_secs(2), task).await.unwrap().unwrap();
        assert!(state.cookies.lock().unwrap().is_empty());
    }
}
