// Resource-limit state — memory, process, and checkpoint tracking.
//
// Extracted from the monolithic `SupervisorState` so that resource-limit
// handlers can lock this independently from other domain states.

use std::collections::HashMap;

/// Resource-limit runtime state shared across notification handlers.
pub struct ResourceState {
    /// Live concurrent process count — incremented on fork, decremented on wait.
    pub proc_count: u32,
    /// Maximum allowed concurrent processes.
    pub max_processes: u32,
    /// Estimated anonymous memory usage (bytes).
    pub mem_used: u64,
    /// Maximum allowed anonymous memory (bytes).
    pub max_memory_bytes: u64,
    /// Per-PID brk base addresses for memory tracking.
    pub brk_bases: HashMap<i32, u64>,
    /// Whether fork notifications should be held (checkpoint/freeze).
    pub hold_forks: bool,
    /// Notification IDs held during a checkpoint freeze.
    pub held_notif_ids: Vec<u64>,
    /// Exponentially-weighted load average.
    pub load_avg: crate::procfs::LoadAvg,
    /// Instant when the supervisor started (for uptime reporting).
    pub start_instant: std::time::Instant,
}

impl ResourceState {
    /// Create a new resource state with the given limits.
    pub fn new(max_memory_bytes: u64, max_processes: u32) -> Self {
        Self {
            proc_count: 0,
            max_processes,
            mem_used: 0,
            max_memory_bytes,
            brk_bases: HashMap::new(),
            hold_forks: false,
            held_notif_ids: Vec::new(),
            load_avg: crate::procfs::LoadAvg::new(),
            start_instant: std::time::Instant::now(),
        }
    }
}

// ============================================================
// CowState — copy-on-write filesystem state
// ============================================================

/// Copy-on-write filesystem state.
///
/// Extracted from `SupervisorState` so that COW handlers can lock this
/// independently from other domain states.
pub struct CowState {
    /// Seccomp-based COW branch (None if COW disabled).
    pub branch: Option<crate::cow::seccomp::SeccompCowBranch>,
    /// Getdents cache for COW directories.
    /// Value is (host_path, entries) to detect fd reuse and invalidate stale entries.
    pub dir_cache: HashMap<(i32, u32), (String, Vec<Vec<u8>>)>,
}

impl CowState {
    pub fn new() -> Self {
        Self {
            branch: None,
            dir_cache: HashMap::new(),
        }
    }
}
