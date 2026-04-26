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
    /// Per-process brk base addresses for memory tracking. Keyed by
    /// PidKey so a recycled numeric pid never inherits the previous
    /// process's brk base.
    pub brk_bases: HashMap<PidKey, u64>,
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
///
/// Sandbox membership (the set of "our" pids) lives in
/// `ProcessIndex`, not here — there used to be a denormalized mirror
/// here that had to be hand-synced. /proc handlers query
/// `ctx.processes` directly.
pub struct ProcfsState {
    /// Cache of filtered dirent entries keyed by (pid, fd, directory target).
    /// Populated on first getdents64 call for a /proc directory, drained on subsequent calls.
    pub getdents_cache: HashMap<(i32, u32, String), Vec<Vec<u8>>>,
    /// Base address of the last vDSO we patched (0 = not yet patched).
    pub vdso_patched_addr: u64,
}

impl ProcfsState {
    pub fn new() -> Self {
        Self {
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

/// Read the process start time (field 22 of /proc/<pid>/stat) for `pid`.
/// Returns None if the process is gone or /proc is not readable.
pub(crate) fn read_pid_start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Skip past "pid (comm)" — comm may contain spaces and parens, but the
    // last ") " in the line ends the comm field.
    let rest = stat.rsplit_once(") ")?.1;
    // The first token after "(comm) " is field 3; field 22 is therefore nth(19).
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Source-of-truth registry for processes inside the sandbox.
///
/// Holds the canonical `pid → PidKey` mapping plus everything any
/// handler needs to ask about sandbox membership. Kept behind an
/// internal `std::sync::RwLock` so the read-mostly hot paths
/// (`key_for`, `contains`, `/proc` virtualization) don't have to take
/// an async mutex on every notification — and so ProcessIndex doesn't
/// need its own `Mutex` wrapper in `SupervisorCtx`. Lock guards are
/// `!Send` and the compiler will reject holding one across an
/// `.await`, which keeps callers honest.
///
/// Ownership of each child's pidfd lives with the per-child watcher
/// task, not with this index. That keeps the kernel fd alive for as
/// long as the `AsyncFd` registration in the tokio IO driver does,
/// and avoids a race where dropping the fd from the index could
/// deregister a recycled fd from epoll.
pub struct ProcessIndex {
    inner: std::sync::RwLock<HashMap<i32, PidKey>>,
}

impl ProcessIndex {
    pub fn new() -> Self {
        Self {
            inner: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Register a process by reading its start_time once and
    /// inserting the canonical PidKey. Returns the key, or None if
    /// the process is already gone. The caller is responsible for
    /// keeping the pidfd alive — the per-child watcher task does
    /// this via `AsyncFd<OwnedFd>`.
    pub fn register(&self, pid: i32) -> Option<PidKey> {
        let start_time = read_pid_start_time(pid)?;
        let key = PidKey { pid, start_time };
        self.inner.write().ok()?.insert(pid, key);
        Some(key)
    }

    /// Look up the canonical PidKey for a notification's raw pid.
    /// Returns None if this pid was never registered (e.g. pidfd_open
    /// failed at fork) — callers should fall back to a no-op.
    pub fn key_for(&self, pid: i32) -> Option<PidKey> {
        self.inner.read().ok()?.get(&pid).copied()
    }

    /// Cheap membership test — used by /proc virtualization to gate
    /// access to `/proc/<pid>/...` paths and by getdents filtering.
    pub fn contains(&self, pid: i32) -> bool {
        self.inner
            .read()
            .map(|g| g.contains_key(&pid))
            .unwrap_or(false)
    }

    /// Number of tracked processes (for /proc/loadavg total).
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Largest tracked pid (for /proc/loadavg last_pid).
    pub fn max_pid(&self) -> Option<i32> {
        self.inner.read().ok()?.keys().copied().max()
    }

    /// Snapshot the set of tracked pids. Used by getdents filtering
    /// where the caller needs O(1) lookups inside a loop and would
    /// otherwise have to re-acquire the read lock per entry.
    pub fn pids_snapshot(&self) -> HashSet<i32> {
        self.inner
            .read()
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Remove a process from the index. Called from the per-child
    /// watcher task once the process has exited.
    pub fn unregister(&self, key: PidKey) {
        if let Ok(mut g) = self.inner.write() {
            // Only clear if the entry still points at this key. A PID
            // recycled with a fresh start_time may already have
            // overwritten the entry via register(); we must not stomp it.
            if g.get(&key.pid) == Some(&key) {
                g.remove(&key.pid);
            }
        }
    }
}

impl Default for ProcessIndex {
    fn default() -> Self {
        Self::new()
    }
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

    /// Drop COW per-process entries for processes that have exited.
    ///
    /// Walks the unique PIDs in `virtual_cwds` and `dir_cache`, reading
    /// each PID's start_time from /proc/<pid>/stat once. Entries for PIDs
    /// whose process is gone, or whose start_time no longer matches the
    /// stored PidKey, are removed. Intended to be called periodically by
    /// a supervisor-side GC task; runs in O(unique_pids) per sweep.
    pub fn prune_dead_pids(&mut self) {
        let mut pids: HashSet<i32> = HashSet::new();
        pids.extend(self.virtual_cwds.keys().map(|k| k.pid));
        pids.extend(self.dir_cache.keys().map(|(k, _)| k.pid));

        let mut alive_keys: HashSet<PidKey> = HashSet::with_capacity(pids.len());
        for pid in pids {
            if let Some(start_time) = read_pid_start_time(pid) {
                alive_keys.insert(PidKey { pid, start_time });
            }
        }

        self.virtual_cwds.retain(|key, _| alive_keys.contains(key));
        self.dir_cache
            .retain(|(key, _), _| alive_keys.contains(key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cow_state_prunes_entries_for_exited_pids() {
        // Spawn /bin/true and wait for it to exit so we know its PID is gone.
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("failed to spawn /bin/true");
        let dead_pid = child.id() as i32;
        let dead_start = read_pid_start_time(dead_pid)
            .expect("failed to read start_time before child exits");
        let _ = child.wait();
        // Wait until /proc/<pid> actually disappears.  Reaping can lag
        // on some kernels even after wait() returns.
        for _ in 0..100 {
            if read_pid_start_time(dead_pid).is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Self is definitely alive.
        let live_pid = unsafe { libc::getpid() };
        let live_start = read_pid_start_time(live_pid)
            .expect("self should have a readable start_time");

        let dead = PidKey { pid: dead_pid, start_time: dead_start };
        let live = PidKey { pid: live_pid, start_time: live_start };

        let mut state = CowState::new();
        state.virtual_cwds.insert(dead, "/dead".to_string());
        state.virtual_cwds.insert(live, "/live".to_string());
        state.dir_cache.insert((dead, 3), ("/dead".to_string(), Vec::new()));
        state.dir_cache.insert((live, 3), ("/live".to_string(), Vec::new()));

        state.prune_dead_pids();

        assert!(!state.virtual_cwds.contains_key(&dead));
        assert!(!state.dir_cache.contains_key(&(dead, 3)));
        assert_eq!(state.virtual_cwds.get(&live), Some(&"/live".to_string()));
        assert!(state.dir_cache.contains_key(&(live, 3)));
    }

    #[test]
    fn cow_state_prunes_entries_for_recycled_pid() {
        // Same numeric PID with a different start_time means the original
        // process has gone and a new one took its slot.  Stale entries
        // must be dropped even if a process at that PID currently exists.
        let live_pid = unsafe { libc::getpid() };
        let live_start = read_pid_start_time(live_pid).unwrap();
        let stale = PidKey { pid: live_pid, start_time: live_start.wrapping_sub(1) };

        let mut state = CowState::new();
        state.virtual_cwds.insert(stale, "/stale".to_string());
        state.dir_cache.insert((stale, 5), ("/stale".to_string(), Vec::new()));

        state.prune_dead_pids();

        assert!(!state.virtual_cwds.contains_key(&stale));
        assert!(!state.dir_cache.contains_key(&(stale, 5)));
    }

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

    #[test]
    fn process_index_register_lookup_unregister() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx
            .register(self_pid)
            .expect("register should succeed for live pid");
        assert_eq!(key.pid, self_pid);

        assert_eq!(idx.key_for(self_pid), Some(key));
        assert!(idx.contains(self_pid));
        assert_eq!(idx.key_for(self_pid + 999_999), None);
        assert!(!idx.contains(self_pid + 999_999));
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.max_pid(), Some(self_pid));

        idx.unregister(key);
        assert_eq!(idx.key_for(self_pid), None);
        assert!(!idx.contains(self_pid));
        assert_eq!(idx.len(), 0);
        assert_eq!(idx.max_pid(), None);
    }

    #[test]
    fn process_index_register_overwrites_stale_entry_for_recycled_pid() {
        // Forge a stale entry via the public register() path, then
        // simulate recycle by re-registering — start_time will differ
        // because pid/comm gets a fresh stat read.
        let self_pid = unsafe { libc::getpid() };
        let stale_key = PidKey { pid: self_pid, start_time: 0 };
        let idx = ProcessIndex::new();
        idx.inner.write().unwrap().insert(self_pid, stale_key);

        let new_key = idx.register(self_pid).unwrap();
        assert_ne!(new_key, stale_key);
        assert_eq!(idx.key_for(self_pid), Some(new_key));

        // Unregistering by the stale key must NOT clobber the fresh
        // registration; only an exact-match unregister wins.
        idx.unregister(stale_key);
        assert_eq!(idx.key_for(self_pid), Some(new_key));
    }

    #[test]
    fn process_index_pids_snapshot_is_independent() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx.register(self_pid).unwrap();
        let snap = idx.pids_snapshot();
        idx.unregister(key);
        // The snapshot is a copy — unregister doesn't mutate it.
        assert!(snap.contains(&self_pid));
        assert!(!idx.contains(self_pid));
    }

    #[test]
    fn brk_bases_keyed_by_pidkey_distinguishes_recycled_pids() {
        // ResourceState::brk_bases is keyed by PidKey, so a recycled
        // numeric pid with a different start_time is treated as a
        // different process and doesn't inherit the previous brk base.
        let mut rs = ResourceState::new(0, 0);
        let pid = 100i32;
        let original = PidKey { pid, start_time: 1000 };
        let recycled = PidKey { pid, start_time: 2000 };
        rs.brk_bases.insert(original, 0xdead_beef);

        assert_eq!(rs.brk_bases.get(&original), Some(&0xdead_beef));
        assert_eq!(rs.brk_bases.get(&recycled), None);
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
