// Domain-specific state structs — each domain is locked independently so
// handlers only contend on the state they actually need.

use std::collections::{HashMap, HashSet};

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
// ProcfsState — /proc virtualization state
// ============================================================

/// /proc virtualization runtime state.
pub struct ProcfsState {
    /// PIDs belonging to the sandbox (for /proc PID filtering).
    pub proc_pids: HashSet<i32>,
    /// Cache of filtered dirent entries keyed by (pid, fd, directory target).
    /// Populated on first getdents64 call for a /proc directory, drained on subsequent calls.
    pub getdents_cache: HashMap<(i32, u32, String), Vec<Vec<u8>>>,
    /// Base address of the last vDSO we patched (0 = not yet patched).
    pub vdso_patched_addr: u64,
}

impl ProcfsState {
    pub fn new() -> Self {
        Self {
            proc_pids: HashSet::new(),
            getdents_cache: HashMap::new(),
            vdso_patched_addr: 0,
        }
    }
}

// ============================================================
// CowState — copy-on-write filesystem state
// ============================================================

/// Stable process identity for per-process COW state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PidKey {
    /// Numeric PID observed by seccomp notification.
    pub pid: i32,
    /// Process start time from /proc/<pid>/stat field 22.
    pub start_time: u64,
}

/// Copy-on-write filesystem state.
pub struct CowState {
    /// Seccomp-based COW branch (None if COW disabled).
    pub branch: Option<crate::cow::seccomp::SeccompCowBranch>,
    /// Getdents cache for COW directories.
    /// Value is (host_path, entries) to detect fd reuse and invalidate stale entries.
    pub dir_cache: HashMap<(PidKey, u32), (String, Vec<Vec<u8>>)>,
    /// Logical cwd for processes that chdir into COW-only directories.
    pub virtual_cwds: HashMap<PidKey, String>,
}

impl CowState {
    pub fn new() -> Self {
        Self {
            branch: None,
            dir_cache: HashMap::new(),
            virtual_cwds: HashMap::new(),
        }
    }

    /// Drop COW per-process entries for an older process that used the same numeric PID.
    pub(crate) fn prune_reused_pid(&mut self, current: PidKey) {
        self.virtual_cwds
            .retain(|key, _| key.pid != current.pid || *key == current);
        self.dir_cache
            .retain(|(key, _), _| key.pid != current.pid || *key == current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cow_state_prunes_entries_for_reused_pid() {
        let old = PidKey { pid: 42, start_time: 1 };
        let current = PidKey { pid: 42, start_time: 2 };
        let other = PidKey { pid: 43, start_time: 1 };
        let mut state = CowState::new();

        state.virtual_cwds.insert(old, "/old".to_string());
        state.virtual_cwds.insert(other, "/other".to_string());
        state.dir_cache.insert((old, 7), ("/old".to_string(), Vec::new()));
        state.dir_cache.insert((other, 7), ("/other".to_string(), Vec::new()));

        state.prune_reused_pid(current);

        assert!(!state.virtual_cwds.contains_key(&old));
        assert!(!state.dir_cache.contains_key(&(old, 7)));
        assert_eq!(state.virtual_cwds.get(&other), Some(&"/other".to_string()));
        assert!(state.dir_cache.contains_key(&(other, 7)));
    }
}

// ============================================================
// NetworkState — network policy and port remapping state
// ============================================================

/// Network policy and port-remapping state.
pub struct NetworkState {
    /// Global network policy: unrestricted or limited to a set of IPs.
    pub network_policy: crate::seccomp::notif::NetworkPolicy,
    /// Port binding and remapping tracker.
    pub port_map: crate::port_remap::PortMap,
    /// Per-PID network overrides from policy_fn.
    pub pid_ip_overrides: std::sync::Arc<std::sync::RwLock<HashMap<u32, HashSet<std::net::IpAddr>>>>,
    /// HTTP ACL proxy address (None if HTTP ACL not active).
    pub http_acl_addr: Option<std::net::SocketAddr>,
    /// TCP ports to intercept and redirect to the HTTP ACL proxy.
    pub http_acl_ports: HashSet<u16>,
    /// Shared map for recording original destination IPs on proxy redirect.
    pub http_acl_orig_dest: Option<crate::http_acl::OrigDestMap>,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            network_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            port_map: crate::port_remap::PortMap::new(),
            pid_ip_overrides: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            http_acl_addr: None,
            http_acl_ports: HashSet::new(),
            http_acl_orig_dest: None,
        }
    }

    /// Get the effective network policy for a PID.
    ///
    /// Priority: per-PID override > live policy (from PolicyFnState) > global network_policy.
    /// The `live_policy` parameter allows checking the live policy without needing
    /// to lock the PolicyFnState mutex.
    pub fn effective_network_policy(
        &self,
        pid: u32,
        live_policy: Option<&std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    ) -> crate::seccomp::notif::NetworkPolicy {
        // Per-PID override takes priority
        if let Ok(overrides) = self.pid_ip_overrides.read() {
            if let Some(ips) = overrides.get(&pid) {
                return crate::seccomp::notif::NetworkPolicy::AllowList(ips.clone());
            }
        }
        // Live policy (dynamic updates from policy_fn)
        if let Some(lp) = live_policy {
            if let Ok(live) = lp.read() {
                if !live.allowed_ips.is_empty() {
                    return crate::seccomp::notif::NetworkPolicy::AllowList(live.allowed_ips.clone());
                }
            }
        }
        // Global policy
        self.network_policy.clone()
    }
}

// ============================================================
// TimeRandomState — deterministic time/random state
// ============================================================

/// Time offset and deterministic random state.
pub struct TimeRandomState {
    /// Clock offset for time virtualization.
    pub time_offset: Option<i64>,
    /// Deterministic PRNG state (seeded from policy).
    pub random_state: Option<rand_chacha::ChaCha8Rng>,
}

impl TimeRandomState {
    pub fn new(time_offset: Option<i64>, random_state: Option<rand_chacha::ChaCha8Rng>) -> Self {
        Self { time_offset, random_state }
    }
}

// ============================================================
// PolicyFnState — dynamic policy callback state
// ============================================================

/// Dynamic policy callback state.
pub struct PolicyFnState {
    /// Event sender for dynamic policy callback (None if no policy_fn).
    pub event_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::policy_fn::PolicyEvent>>,
    /// Shared live policy for dynamic updates (None if no policy_fn).
    pub live_policy: Option<std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    /// Dynamically denied paths from policy_fn.
    pub denied_paths: std::sync::Arc<std::sync::RwLock<HashSet<String>>>,
}

impl PolicyFnState {
    pub fn new() -> Self {
        Self {
            event_tx: None,
            live_policy: None,
            denied_paths: std::sync::Arc::new(std::sync::RwLock::new(HashSet::new())),
        }
    }

    /// Check if a path is dynamically denied.
    pub fn is_path_denied(&self, path: &str) -> bool {
        if let Ok(denied) = self.denied_paths.read() {
            let path = std::path::Path::new(path);
            denied.iter().any(|d| path.starts_with(std::path::Path::new(d)))
        } else {
            false
        }
    }
}

// ============================================================
// ChrootState — chroot-specific runtime state
// ============================================================

/// Chroot-specific runtime state.
pub struct ChrootState {
    /// Virtual exe path for chroot (set by handle_chroot_exec when memfd patching
    /// rewrites PT_INTERP, since /proc/self/exe would otherwise show the memfd path).
    pub chroot_exe: Option<std::path::PathBuf>,
}

impl ChrootState {
    pub fn new() -> Self {
        Self { chroot_exe: None }
    }
}
