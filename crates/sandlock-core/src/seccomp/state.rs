// Domain-specific state structs — each domain is locked independently so
// handlers only contend on the state they actually need. Per-process
// state is bundled into a single `PerProcessState` owned by
// `ProcessIndex`; cleanup on exit is just dropping the entry's `Arc`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

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

/// /proc virtualization runtime state. Sandbox membership lives in
/// `ProcessIndex`; per-process getdents caches live in
/// `PerProcessState::procfs_dir_cache`. This struct only holds
/// truly global virtualization state.
pub struct ProcfsState {
    /// Base address of the last vDSO we patched (0 = not yet patched).
    pub vdso_patched_addr: u64,
}

impl ProcfsState {
    pub fn new() -> Self {
        Self {
            vdso_patched_addr: 0,
        }
    }
}

// ============================================================
// PidKey — stable per-process identity
// ============================================================

/// Stable process identity. Numeric pid plus the start_time that
/// distinguishes a specific process instance from any future recycle
/// of the same pid slot.
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

// ============================================================
// PerProcessState — bundled per-process supervisor state
// ============================================================

/// All per-process supervisor state for one tracked child. One
/// instance lives per `PidKey`, owned by `ProcessIndex` behind an
/// `Arc<AsyncMutex<…>>`. Cleanup on process exit is one operation:
/// `ProcessIndex::unregister` drops the index's `Arc`, and the
/// supervisor's per-handler clones drop along with their tasks.
#[derive(Default)]
pub struct PerProcessState {
    /// Logical cwd while the process is chdir'd into a COW-only
    /// directory. None means "use kernel-reported cwd".
    pub virtual_cwd: Option<String>,
    /// Recorded brk base for memory accounting. None until first brk.
    pub brk_base: Option<u64>,
    /// COW directory dirent cache. Keyed by child's fd; value is
    /// (host target path, sorted dirent bytes left to return).
    /// Entries are invalidated when the fd is reused for a different
    /// directory.
    pub cow_dir_cache: HashMap<u32, (String, Vec<Vec<u8>>)>,
    /// /proc directory dirent cache. Keyed by (child fd, target
    /// path); same drain-on-EOF semantics as cow_dir_cache.
    pub procfs_dir_cache: HashMap<(u32, String), Vec<Vec<u8>>>,
}

// ============================================================
// ProcessIndex — sandbox membership + per-process state
// ============================================================

/// Source-of-truth registry for processes inside the sandbox.
///
/// Maps the kernel's numeric `pid` (the value that arrives in seccomp
/// notifications) to the canonical `PidKey` plus an
/// `Arc<AsyncMutex<PerProcessState>>` holding everything per-process.
/// Held behind an internal `std::sync::RwLock` so the read-mostly hot
/// paths (`key_for`, `contains`, `entry_for`, `/proc` virtualization)
/// avoid an async mutex on every notification, and so `ProcessIndex`
/// doesn't need its own outer wrapper in `SupervisorCtx`. Lock guards
/// are `!Send` and the compiler will reject holding one across an
/// `.await`, which keeps callers honest.
///
/// Ownership of each child's pidfd lives with the per-child watcher
/// task, not with this index. That keeps the kernel fd alive for as
/// long as the `AsyncFd` registration in the tokio IO driver does,
/// and avoids a race where dropping the fd from the index could
/// deregister a recycled fd from epoll.
pub struct ProcessIndex {
    inner: std::sync::RwLock<HashMap<i32, ProcessEntry>>,
}

#[derive(Clone)]
struct ProcessEntry {
    key: PidKey,
    state: Arc<AsyncMutex<PerProcessState>>,
}

impl ProcessIndex {
    pub fn new() -> Self {
        Self {
            inner: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Register a process by reading its start_time once and
    /// allocating its `PerProcessState`. Returns the canonical key,
    /// or None if the process is already gone. The caller is
    /// responsible for keeping the pidfd alive — the per-child
    /// watcher task does this via `AsyncFd<OwnedFd>`.
    pub fn register(&self, pid: i32) -> Option<PidKey> {
        let start_time = read_pid_start_time(pid)?;
        let key = PidKey { pid, start_time };
        let entry = ProcessEntry {
            key,
            state: Arc::new(AsyncMutex::new(PerProcessState::default())),
        };
        self.inner.write().ok()?.insert(pid, entry);
        Some(key)
    }

    /// Look up the canonical PidKey for a notification's raw pid.
    /// Returns None if this pid was never registered (e.g. pidfd_open
    /// failed at fork) — callers should fall back to a no-op.
    pub fn key_for(&self, pid: i32) -> Option<PidKey> {
        self.inner.read().ok()?.get(&pid).map(|e| e.key)
    }

    /// Look up both the PidKey and the per-process state handle for
    /// `pid`. Returns None if the pid isn't tracked. The caller locks
    /// the returned `Arc<AsyncMutex<…>>` to read or mutate.
    pub fn entry_for(&self, pid: i32) -> Option<(PidKey, Arc<AsyncMutex<PerProcessState>>)> {
        self.inner
            .read()
            .ok()?
            .get(&pid)
            .map(|e| (e.key, Arc::clone(&e.state)))
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

    /// Remove a process from the index. The per-process state's
    /// `Arc` reference held by the index drops here; remaining clones
    /// (e.g. a handler that's mid-execution for that pid) will drop
    /// when they go out of scope, and the inner `PerProcessState`
    /// frees automatically.
    pub fn unregister(&self, key: PidKey) {
        if let Ok(mut g) = self.inner.write() {
            // Only clear if the entry still points at this key. A PID
            // recycled with a fresh start_time may already have
            // overwritten the entry via register(); we must not stomp it.
            if g.get(&key.pid).map(|e| e.key) == Some(key) {
                g.remove(&key.pid);
            }
        }
    }

    /// Defensive sweep: drop entries whose process is gone (or whose
    /// start_time has changed). Called from a low-frequency backstop
    /// task in case a pidfd watcher failed to spawn or the kernel
    /// didn't deliver the readability event.
    pub fn prune_dead(&self) {
        let candidates: Vec<(i32, PidKey)> = match self.inner.read() {
            Ok(g) => g.iter().map(|(p, e)| (*p, e.key)).collect(),
            Err(_) => return,
        };
        let mut dead = Vec::new();
        for (pid, key) in candidates {
            match read_pid_start_time(pid) {
                Some(st) if st == key.start_time => continue,
                _ => dead.push(key),
            }
        }
        if dead.is_empty() {
            return;
        }
        if let Ok(mut g) = self.inner.write() {
            for key in dead {
                if g.get(&key.pid).map(|e| e.key) == Some(key) {
                    g.remove(&key.pid);
                }
            }
        }
    }
}

impl Default for ProcessIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// CowState — copy-on-write filesystem state (global only)
// ============================================================

/// Global COW state. Per-process COW state (virtual cwd, dir cache)
/// lives in `PerProcessState`.
pub struct CowState {
    /// Seccomp-based COW branch (None if COW disabled).
    pub branch: Option<crate::cow::seccomp::SeccompCowBranch>,
}

impl CowState {
    pub fn new() -> Self {
        Self { branch: None }
    }
}

// ============================================================
// NetworkState — network policy and port remapping state
// ============================================================

/// Network policy and port-remapping state.
pub struct NetworkState {
    /// Global network policy: endpoint-level allowlist or unrestricted.
    pub network_policy: crate::seccomp::notif::NetworkPolicy,
    /// Port binding and remapping tracker.
    pub port_map: crate::port_remap::PortMap,
    /// Per-PID network overrides from policy_fn (IP-only via the legacy
    /// `restrict_network(ips)` API; any port is permitted to listed IPs).
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
    /// PID/live overrides are IP-only — any port is permitted to listed
    /// IPs (legacy `policy_fn` semantics).
    pub fn effective_network_policy(
        &self,
        pid: u32,
        live_policy: Option<&std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    ) -> crate::seccomp::notif::NetworkPolicy {
        use crate::seccomp::notif::{NetworkPolicy, PortAllow};
        let ip_only_allow = |ips: &HashSet<std::net::IpAddr>| {
            let per_ip = ips.iter().map(|&ip| (ip, PortAllow::Any)).collect();
            NetworkPolicy::AllowList {
                per_ip,
                any_ip_ports: HashSet::new(),
            }
        };
        if let Ok(overrides) = self.pid_ip_overrides.read() {
            if let Some(ips) = overrides.get(&pid) {
                return ip_only_allow(ips);
            }
        }
        if let Some(lp) = live_policy {
            if let Ok(live) = lp.read() {
                if !live.allowed_ips.is_empty() {
                    return ip_only_allow(&live.allowed_ips);
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        // Forge a stale entry by direct insertion under the lock.
        {
            let stale_key = PidKey { pid: self_pid, start_time: 0 };
            let stale = ProcessEntry {
                key: stale_key,
                state: Arc::new(AsyncMutex::new(PerProcessState::default())),
            };
            idx.inner.write().unwrap().insert(self_pid, stale);
        }

        let new_key = idx.register(self_pid).unwrap();
        assert_ne!(new_key.start_time, 0);
        assert_eq!(idx.key_for(self_pid), Some(new_key));

        // Unregistering by the stale key must NOT clobber the fresh
        // registration; only an exact-match unregister wins.
        let stale_key = PidKey { pid: self_pid, start_time: 0 };
        idx.unregister(stale_key);
        assert_eq!(idx.key_for(self_pid), Some(new_key));
    }

    #[tokio::test]
    async fn process_index_entry_for_returns_shared_handle() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx.register(self_pid).unwrap();

        let (k1, s1) = idx.entry_for(self_pid).unwrap();
        let (k2, s2) = idx.entry_for(self_pid).unwrap();
        assert_eq!(k1, key);
        assert_eq!(k2, key);

        // Two clones of the same Arc — writes through one are visible
        // through the other.
        s1.lock().await.brk_base = Some(0xdead_beef);
        assert_eq!(s2.lock().await.brk_base, Some(0xdead_beef));

        // After unregister, entry_for returns None but existing Arc
        // clones stay valid (kept alive by callers).
        idx.unregister(key);
        assert!(idx.entry_for(self_pid).is_none());
        assert_eq!(s1.lock().await.brk_base, Some(0xdead_beef));
    }

    #[test]
    fn process_index_pids_snapshot_is_independent() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx.register(self_pid).unwrap();
        let snap = idx.pids_snapshot();
        idx.unregister(key);
        assert!(snap.contains(&self_pid));
        assert!(!idx.contains(self_pid));
    }

    #[test]
    fn process_index_prune_dead_drops_recycled_entries() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        // Insert a stale entry for self with a wrong start_time.
        let stale_key = PidKey { pid: self_pid, start_time: 0 };
        let stale = ProcessEntry {
            key: stale_key,
            state: Arc::new(AsyncMutex::new(PerProcessState::default())),
        };
        idx.inner.write().unwrap().insert(self_pid, stale);

        idx.prune_dead();
        assert!(!idx.contains(self_pid));
    }

    #[test]
    fn process_index_prune_dead_keeps_live_entries() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx.register(self_pid).unwrap();
        idx.prune_dead();
        assert_eq!(idx.key_for(self_pid), Some(key));
    }
}
