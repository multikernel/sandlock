use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

/// Maps socket identities to virtual netlink port IDs, shared by all fd aliases.
#[derive(Default)]
pub struct NetlinkState {
    cookies: Mutex<HashMap<u64, u32>>,
}

/// Keeps a cookie registered until its responder exits or is cancelled.
#[must_use]
pub struct Registration {
    state: Arc<NetlinkState>,
    cookie: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.state.cookies.lock().unwrap().remove(&self.cookie);
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

    /// Register the socket for the lifetime of its responder.
    pub fn register(self: &Arc<Self>, cookie: u64, port_id: u32) -> Registration {
        self.cookies.lock().unwrap().insert(cookie, port_id);
        Registration { state: Arc::clone(self), cookie }
    }

    pub(crate) fn contains_cookie(&self, cookie: u64) -> bool {
        self.cookies.lock().map(|cookies| cookies.contains_key(&cookie)).unwrap_or(true)
    }

    pub fn port_id(&self, pid: u32, fd: i32) -> Option<u32> {
        let socket = crate::seccomp::notif::dup_fd_from_pid(pid, fd).ok()?;
        let cookie = socket_cookie(&socket)?;
        self.cookies.lock().unwrap().get(&cookie).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_lifetime_reclaims_entries_during_churn() {
        let state = Arc::new(NetlinkState::new());
        for tgid in 1..1000 {
            let registration = state.register(tgid as u64, tgid as u32);
            assert_eq!(state.cookies.lock().unwrap().len(), 1);
            drop(registration);
            assert!(state.cookies.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn dropping_one_registration_preserves_other_sockets() {
        let state = Arc::new(NetlinkState::new());
        let old = state.register(10, 1);
        let new = state.register(20, 1);
        drop(old);
        assert_eq!(state.cookies.lock().unwrap().get(&20), Some(&1));
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
            let registration = state.register(tgid as u64, tgid as u32);
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
        let registration = state.register(10, 1);
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
        let registration = state.register(10, 1);
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
