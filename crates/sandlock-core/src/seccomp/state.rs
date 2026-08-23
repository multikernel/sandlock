// Domain-specific state structs — each domain is locked independently so
// handlers only contend on the state they actually need. Per-process
// state is bundled into a single `PerProcessState` owned by
// `ProcessIndex`; cleanup on exit is just dropping the entry's `Arc`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

/// Resource-limit runtime state shared across notification handlers.
pub struct ResourceState {
    /// Live concurrent process count — incremented on fork, decremented on wait.
    pub proc_count: u32,
    /// Peak concurrent process count observed since sandbox start.
    pub peak_proc_count: u32,
    /// Maximum allowed concurrent processes.
    pub max_processes: u32,
    /// Estimated anonymous memory usage (bytes).
    pub mem_used: u64,
    /// Peak anonymous memory usage observed since sandbox start (bytes).
    pub peak_mem_used: u64,
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
            peak_proc_count: 1, // root process always exists; handle_fork counts children only
            max_processes,
            mem_used: 0,
            peak_mem_used: 0,
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

/// /proc virtualization runtime state. Per-notification process state
/// lives in `ProcessIndex`; per-process getdents caches live in
/// `PerProcessState::procfs_dir_cache`. This struct only holds truly
/// global virtualization state.
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

/// Read the thread-group leader pid (TGID) containing `tid` from
/// `/proc/<tid>/status`. `None` when the task is gone or /proc is
/// unreadable; callers decide what that means for them.
pub(crate) fn read_tgid_of_tid(tid: i32) -> Option<i32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", tid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Read the parent pid (field 4 of `/proc/<pid>/stat`) for `pid`.
/// `None` when the task is gone or /proc is unreadable.
pub(crate) fn read_ppid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Skip past "pid (comm)": comm may contain spaces and parens, but the
    // last ") " in the line ends it. The first token after it is the state,
    // and the parent pid follows.
    let rest = stat.rsplit_once(") ")?.1;
    rest.split_whitespace().nth(1)?.parse().ok()
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
    /// Anonymous memory (bytes) charged to this address space and not
    /// yet credited back. Only the thread-group leader's entry carries a
    /// charge: threads share one address space, so all accounting for a
    /// task is routed to its leader via [`ProcessIndex::addr_space_state`].
    /// Credited back to the global total when the address space goes away
    /// (exec replaces it, or the process exits).
    pub mem_charged: u64,
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
// ProcessIndex — tracked processes + per-process state
// ============================================================

/// Registry for tracked sandbox processes plus their per-process
/// supervisor state.
///
/// In the default supervisor this is populated lazily from seccomp
/// notifications. When `policy_fn` is active, fork-like syscalls are
/// additionally traced for one ptrace creation event so children are
/// inserted here before they can run user code; this makes the index
/// complete for argv-safety freezes.
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

/// A task's current directory as the sandbox believes it to be: the
/// path `getcwd` should report, in whatever namespace the child sees
/// (the virtual path under chroot, the real path otherwise).
///
/// `None` means the task has never moved, so the kernel's own cwd is
/// still authoritative. Shared behind an `Arc` the way the kernel
/// shares `fs_struct`, so a chdir in one thread is seen by its
/// siblings. Kept outside `PerProcessState` (and behind a std mutex)
/// because path resolution reads it from synchronous helpers.
pub type SharedCwd = Arc<std::sync::Mutex<Option<PathBuf>>>;

#[derive(Clone)]
struct ProcessEntry {
    key: PidKey,
    /// Thread-group leader of this task; equals `key.pid` for a
    /// single-threaded process. Read once at registration and kept
    /// outside the async mutex so address-space lookups need only the
    /// index's read lock.
    tgid: i32,
    state: Arc<AsyncMutex<PerProcessState>>,
    cwd: SharedCwd,
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
        // Unreadable /proc means the task is its own address space as far
        // as accounting is concerned: better local than misrouted.
        let tgid = read_tgid_of_tid(pid).unwrap_or(pid);
        let entry = ProcessEntry {
            key,
            tgid,
            state: Arc::new(AsyncMutex::new(PerProcessState::default())),
            cwd: self.inherited_cwd(pid, tgid),
        };
        self.inner.write().ok()?.insert(pid, entry);
        Some(key)
    }

    /// The cwd cell a task starts life with.
    ///
    /// A thread joins its leader's cell, because the kernel hands
    /// pthreads a shared `fs_struct` and one thread's chdir moves its
    /// siblings. Anything else copies the parent's current value, which
    /// is what `fork(2)` does. Thread-group membership stands in for
    /// `CLONE_FS` here, the same approximation `addr_space_state` makes
    /// for `CLONE_VM`: a bare `clone(CLONE_FS)` without `CLONE_THREAD`
    /// gets a private copy instead of sharing. An untracked parent
    /// leaves the child at None, which falls back to the kernel's cwd.
    fn inherited_cwd(&self, pid: i32, tgid: i32) -> SharedCwd {
        let ppid = if tgid == pid { read_ppid(pid) } else { None };
        let Ok(guard) = self.inner.read() else {
            return SharedCwd::default();
        };
        if tgid != pid {
            if let Some(leader) = guard.get(&tgid) {
                return Arc::clone(&leader.cwd);
            }
        }
        let parent_cwd = ppid
            .and_then(|p| guard.get(&p))
            .and_then(|e| e.cwd.lock().ok().and_then(|c| c.clone()));
        Arc::new(std::sync::Mutex::new(parent_cwd))
    }

    /// The cwd cell to read or write for `pid`.
    ///
    /// A task without an entry of its own falls back to its
    /// thread-group leader: `pidfd_open` on a non-leader tid needs
    /// `PIDFD_THREAD` (Linux 6.9), so `register_pid_if_new` can leave a
    /// thread unregistered. Since threads share one `fs_struct`, the
    /// leader's cell is the correct answer for them, not an
    /// approximation. Only that miss pays for the extra /proc read.
    fn cwd_cell(&self, pid: i32) -> Option<SharedCwd> {
        if let Ok(guard) = self.inner.read() {
            if let Some(entry) = guard.get(&pid) {
                return Some(Arc::clone(&entry.cwd));
            }
        }
        let tgid = read_tgid_of_tid(pid)?;
        if tgid == pid {
            return None;
        }
        let guard = self.inner.read().ok()?;
        guard.get(&tgid).map(|e| Arc::clone(&e.cwd))
    }

    /// The cwd this task believes it is in, or None when the task is
    /// untracked or has never moved.
    pub fn virtual_cwd(&self, pid: i32) -> Option<PathBuf> {
        let cell = self.cwd_cell(pid)?;
        let cwd = cell.lock().ok()?.clone();
        cwd
    }

    /// Record where this task now believes it is. Silently does nothing
    /// for an untracked pid: the fallback is the kernel's own cwd.
    pub fn set_virtual_cwd(&self, pid: i32, cwd: PathBuf) {
        if let Some(cell) = self.cwd_cell(pid) {
            if let Ok(mut slot) = cell.lock() {
                *slot = Some(cwd);
            }
        }
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

    /// Per-address-space state for `pid`: the thread-group leader's
    /// entry when `pid` is a thread, otherwise its own. Memory
    /// accounting keys off this because threads share one address
    /// space — charging each thread separately would let every thread's
    /// first brk go free and would credit a live heap back when one
    /// thread exits. Falls back to the task's own entry when the leader
    /// is untracked.
    pub fn addr_space_state(&self, pid: i32) -> Option<Arc<AsyncMutex<PerProcessState>>> {
        let guard = self.inner.read().ok()?;
        let entry = guard.get(&pid)?;
        if entry.tgid != pid {
            if let Some(leader) = guard.get(&entry.tgid) {
                return Some(Arc::clone(&leader.state));
            }
        }
        Some(Arc::clone(&entry.state))
    }

    /// Cheap tracked-process test — used by /proc virtualization to
    /// gate access to `/proc/<pid>/...` paths and by getdents filtering.
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

/// Network policy and port-remapping state. Holds one
/// `NetworkPolicy` per L4 protocol — the on-behalf handler picks the
/// matching one based on the dup'd fd's `SO_PROTOCOL`.
pub struct NetworkState {
    /// Allowlist for TCP destinations (`tcp://...` and bare-form rules;
    /// bare specs expand to a TCP + UDP pair at parse time).
    pub tcp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Allowlist for UDP destinations (`udp://...` and bare-form rules).
    pub udp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Allowlist for ICMP destinations (`icmp://...` rules). ICMP rules
    /// carry no ports, so every entry uses `PortAllow::Any` and the
    /// effective check is IP-only.
    pub icmp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Port binding and remapping tracker.
    pub port_map: crate::port_remap::PortMap,
    /// `--net-deny-bind`: TCP ports the sandbox may NOT bind (default-allow
    /// denylist). The on-behalf `bind()` handler rejects a TCP bind to any
    /// port in this set with `EACCES`; empty = no bind denylist.
    pub bind_deny_ports: HashSet<u16>,
    /// Per-PID network overrides from policy_fn (IP-only via the legacy
    /// `restrict_network(ips)` API; any port is permitted to listed IPs).
    pub pid_ip_overrides: std::sync::Arc<std::sync::RwLock<HashMap<u32, HashSet<std::net::IpAddr>>>>,
    /// HTTP ACL proxy address (None if HTTP ACL not active).
    pub http_acl_addr: Option<std::net::SocketAddr>,
    /// TCP ports to intercept and redirect to the HTTP ACL proxy.
    pub http_acl_ports: HashSet<u16>,
    /// Shared map for recording original destination IPs on proxy redirect.
    pub http_acl_orig_dest: Option<crate::transparent_proxy::OrigDestMap>,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            tcp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            udp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            icmp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            port_map: crate::port_remap::PortMap::new(),
            bind_deny_ports: HashSet::new(),
            pid_ip_overrides: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            http_acl_addr: None,
            http_acl_ports: HashSet::new(),
            http_acl_orig_dest: None,
        }
    }

    /// Get the effective network policy for a PID and protocol.
    ///
    /// Priority: per-PID override > live policy (from PolicyFnState) >
    /// the per-protocol allowlist for `protocol`.
    /// PID/live overrides are IP-only — any port is permitted to listed
    /// IPs (legacy `policy_fn` semantics) — and they apply across all
    /// protocols, since the legacy API didn't distinguish them.
    pub fn effective_network_policy(
        &self,
        pid: u32,
        protocol: crate::sandbox::Protocol,
        live_policy: Option<&std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    ) -> crate::seccomp::notif::NetworkPolicy {
        use crate::sandbox::Protocol;
        use crate::seccomp::notif::{NetworkPolicy, PortAllow};
        let ip_only_allow = |ips: &HashSet<std::net::IpAddr>| {
            let per_ip = ips.iter().map(|&ip| (ip, PortAllow::Any)).collect();
            NetworkPolicy::AllowList {
                per_ip,
                cidrs: Vec::new(),
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
        match protocol {
            Protocol::Tcp => self.tcp_policy.clone(),
            Protocol::Udp => self.udp_policy.clone(),
            Protocol::Icmp => self.icmp_policy.clone(),
        }
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
// DeniedSet — denied paths plus captured file identities
// ============================================================

/// The filesystem deny set: path prefixes plus the file-handle identities
/// captured when each path was denied.
///
/// The path set is the primary, race-free boundary enforced at `open`. The
/// identity set makes the deny robust against namespace games (hardlinks,
/// renames, and pre-existing aliases): a [`FileId`] is the kernel file handle,
/// which encodes the inode and a generation number, so it travels with the
/// file's identity rather than the name used to reach it and is immune to
/// inode reuse. An open is denied if the opened file's identity matches, no
/// matter which path led to it. With `AT_HANDLE_FID` the kernel encodes an
/// identity FID for essentially every filesystem (generic inode FID where
/// NFS-export ops are absent); the rare path that still fails captures no
/// identity and relies on the always-on path prefix.
#[derive(Default)]
pub struct DeniedSet {
    paths: std::sync::RwLock<HashSet<String>>,
    ids: std::sync::RwLock<HashSet<FileId>>,
}

/// A file's stable identity: its kernel file handle, keyed by the superblock
/// device so identical handles from different filesystems cannot collide.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct FileId {
    dev: u64,
    handle_type: i32,
    handle: Vec<u8>,
}

/// Identity of a path, following symlinks (the open will resolve to the same
/// target). `None` if it cannot be resolved or no handle can be encoded. The
/// `(handle_type, handle)` FID comes from [`crate::sys::fs::file_handle`]; it is
/// keyed by the superblock `dev` so handles from different filesystems cannot
/// collide.
pub(crate) fn file_id_of_path(path: &str) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    let dev = std::fs::metadata(path).ok()?.dev();
    let c = std::ffi::CString::new(path).ok()?;
    let (handle_type, handle) =
        crate::sys::fs::file_handle(libc::AT_FDCWD, &c, libc::AT_SYMLINK_FOLLOW)?;
    Some(FileId { dev, handle_type, handle })
}

/// Identity of an open fd.
pub(crate) fn file_id_of_fd(fd: std::os::unix::io::RawFd) -> Option<FileId> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    let empty = std::ffi::CString::new("").ok()?;
    let (handle_type, handle) = crate::sys::fs::file_handle(fd, &empty, libc::AT_EMPTY_PATH)?;
    Some(FileId { dev: st.st_dev as u64, handle_type, handle })
}

impl DeniedSet {
    /// Deny `path` (and its subtree, by prefix). Also captures the file's
    /// handle identity if it exists now, so the deny still applies after the
    /// file is hardlinked or renamed to a non-denied name.
    pub fn deny(&self, path: &str) {
        if let Ok(mut p) = self.paths.write() {
            p.insert(path.to_string());
        }
        if let Some(id) = file_id_of_path(path) {
            if let Ok(mut i) = self.ids.write() {
                i.insert(id);
            }
        }
    }

    /// Stop denying `path`, dropping its captured identity too (best-effort:
    /// only if the path still resolves). A leftover identity would only ever
    /// over-deny, which is fail-safe.
    pub fn allow(&self, path: &str) {
        if let Ok(mut p) = self.paths.write() {
            p.remove(path);
        }
        if let Some(id) = file_id_of_path(path) {
            if let Ok(mut i) = self.ids.write() {
                i.remove(&id);
            }
        }
    }

    /// True if `path` is at or beneath a denied path (lexical prefix).
    pub fn is_path_denied(&self, path: &str) -> bool {
        self.paths.read().map_or(false, |denied| {
            let path = std::path::Path::new(path);
            denied
                .iter()
                .any(|d| path.starts_with(std::path::Path::new(d)))
        })
    }

    /// True if `id` is a denied file identity (catches hardlinks, renames, and
    /// pre-existing aliases regardless of the path used).
    pub(crate) fn is_id_denied(&self, id: &FileId) -> bool {
        self.ids.read().map_or(false, |s| s.contains(id))
    }

    /// Whether any deny rule is in effect.
    pub fn is_empty(&self) -> bool {
        self.paths.read().map_or(true, |p| p.is_empty())
            && self.ids.read().map_or(true, |i| i.is_empty())
    }

    /// Snapshot of the currently-denied path prefixes (sorted, deduped).
    /// Used by the control-socket `config` verb to reflect dynamic
    /// `policy_fn`-issued `deny_path()` calls in the effective policy.
    pub fn denied_paths(&self) -> Vec<String> {
        self.paths.read().map_or(Vec::new(), |p| {
            let mut v: Vec<String> = p.iter().cloned().collect();
            v.sort();
            v.dedup();
            v
        })
    }
}

// ============================================================
// PolicyFnState — dynamic policy callback state
// ============================================================

/// Dynamic policy callback state.
pub struct PolicyFnState {
    /// Event sender for dynamic policy callback (None if no policy_fn).
    pub event_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::policy_fn::PolicyMsg>>,
    /// Shared live policy for dynamic updates (None if no policy_fn).
    pub live_policy: Option<std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    /// Dynamically denied paths and inode identities from policy_fn / fs_deny.
    pub denied: std::sync::Arc<DeniedSet>,
}

impl PolicyFnState {
    pub fn new() -> Self {
        Self {
            event_tx: None,
            live_policy: None,
            denied: std::sync::Arc::new(DeniedSet::default()),
        }
    }

    /// Check if a path is at or beneath a denied path.
    pub fn is_path_denied(&self, path: &str) -> bool {
        self.denied.is_path_denied(path)
    }

    /// Check if an opened file's handle identity is denied.
    pub(crate) fn is_id_denied(&self, id: &FileId) -> bool {
        self.denied.is_id_denied(id)
    }

    /// Whether any deny rule is currently in effect. Cheap gate for the
    /// race-free on-behalf open path: with no denies there is no carve-out
    /// to protect and opens are left to the kernel and Landlock.
    pub fn has_denied_paths(&self) -> bool {
        !self.denied.is_empty()
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
    fn threads_of_one_process_share_one_cwd() {
        // The kernel gives pthreads a shared fs_struct, so a chdir in one
        // thread moves its siblings. Registering a tid must join the leader's
        // cwd rather than start a private one.
        let leader = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        idx.register(leader).expect("leader registers");

        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            tid_tx.send(tid).unwrap();
            // Stay alive: register() reads /proc/<tid>/stat.
            let _ = stop_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        idx.register(tid).expect("thread registers");

        idx.set_virtual_cwd(tid, PathBuf::from("/workspace"));
        assert_eq!(idx.virtual_cwd(leader), Some(PathBuf::from("/workspace")));

        let _ = stop_tx.send(());
        thread.join().unwrap();
    }

    #[test]
    fn an_unregistered_thread_uses_its_leader_cwd() {
        // pidfd_open on a non-leader tid needs PIDFD_THREAD (Linux 6.9), so
        // register_pid_if_new can leave a thread without an entry of its own.
        // It still shares the leader's fs_struct, so its chdir must land in
        // the leader's cell rather than vanish.
        let leader = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        idx.register(leader).expect("leader registers");

        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            tid_tx.send(tid).unwrap();
            let _ = stop_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        // Deliberately not registered.
        assert!(!idx.contains(tid));

        idx.set_virtual_cwd(tid, PathBuf::from("/workspace"));
        assert_eq!(idx.virtual_cwd(tid), Some(PathBuf::from("/workspace")));
        assert_eq!(idx.virtual_cwd(leader), Some(PathBuf::from("/workspace")));

        let _ = stop_tx.send(());
        thread.join().unwrap();
    }

    #[test]
    fn a_child_copies_the_parent_cwd_instead_of_sharing_it() {
        // fork(2) copies fs_struct: the child starts where the parent stood,
        // and its later chdir must not move the parent.
        let parent = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        idx.register(parent).expect("parent registers");
        idx.set_virtual_cwd(parent, PathBuf::from("/workspace"));

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            // Async-signal-safe only: sleep, then leave without unwinding.
            let ts = libc::timespec { tv_sec: 30, tv_nsec: 0 };
            unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
            unsafe { libc::_exit(0) };
        }

        idx.register(child).expect("child registers");
        assert_eq!(idx.virtual_cwd(child), Some(PathBuf::from("/workspace")));

        idx.set_virtual_cwd(child, PathBuf::from("/tmp"));
        assert_eq!(idx.virtual_cwd(parent), Some(PathBuf::from("/workspace")));

        unsafe { libc::kill(child, libc::SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0) };
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
                tgid: self_pid,
                state: Arc::new(AsyncMutex::new(PerProcessState::default())),
                cwd: SharedCwd::default(),
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
            tgid: self_pid,
            state: Arc::new(AsyncMutex::new(PerProcessState::default())),
            cwd: SharedCwd::default(),
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
