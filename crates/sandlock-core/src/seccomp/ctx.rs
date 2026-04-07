use std::os::unix::io::RawFd;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::notif::{NotifPolicy, SupervisorState};

/// Holds all supervisor state and policy. Passed to every handler.
/// Currently wraps the monolithic SupervisorState; domain states will
/// be extracted incrementally.
pub struct SupervisorCtx {
    /// Legacy monolithic state — fields will be extracted into domain structs.
    pub state: Arc<Mutex<SupervisorState>>,
    /// Immutable policy — no lock needed.
    pub policy: Arc<NotifPolicy>,
    /// pidfd for the child process (immutable after spawn).
    pub child_pidfd: Option<RawFd>,
    /// Seccomp notification fd (for on-behalf operations).
    pub notif_fd: RawFd,
}
