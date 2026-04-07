use std::os::unix::io::RawFd;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::notif::{NotifPolicy, SupervisorState};
use super::state::{CowState, ResourceState};

/// Holds all supervisor state and policy. Passed to every handler.
/// Currently wraps the monolithic SupervisorState; domain states will
/// be extracted incrementally.
pub struct SupervisorCtx {
    /// Legacy monolithic state — fields will be extracted into domain structs.
    pub state: Arc<Mutex<SupervisorState>>,
    /// Resource-limit state (memory, processes, checkpoint).
    pub resource: Arc<Mutex<ResourceState>>,
    /// Copy-on-write filesystem state.
    pub cow: Arc<Mutex<CowState>>,
    /// Immutable policy — no lock needed.
    pub policy: Arc<NotifPolicy>,
    /// pidfd for the child process (immutable after spawn).
    pub child_pidfd: Option<RawFd>,
    /// Seccomp notification fd (for on-behalf operations).
    pub notif_fd: RawFd,
}
