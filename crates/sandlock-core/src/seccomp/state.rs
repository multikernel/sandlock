// Domain-specific state structs — each domain is locked independently so
// handlers only contend on the state they actually need. Per-process
// state is bundled into a single `PerProcessState` owned by
// `ProcessIndex`; cleanup on exit is just dropping the entry's `Arc`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
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

    /// Distinct thread groups in the index. Entries are keyed by the
    /// notifying task's tid, so one group can appear under several keys.
    pub fn tgids_snapshot(&self) -> HashSet<i32> {
        self.inner
            .read()
            .map(|g| g.values().map(|e| e.tgid).collect())
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

/// The static policy stages and optional dynamic IP restriction applied to one
/// destination. Keeping allow and deny separate means an arbitrary
/// allowlist/denylist intersection does not need a lossy merged
/// representation.
#[derive(Debug, Clone)]
pub(crate) struct NetworkPolicyLayers {
    /// The default-deny allow layer, or unrestricted when no allowlist is
    /// active for this protocol.
    pub allow: crate::seccomp::notif::NetworkPolicy,
    /// The default-allow deny layer, or unrestricted when no denylist is
    /// active for this protocol.
    pub deny: crate::seccomp::notif::NetworkPolicy,
    /// An optional dynamic IP-only restriction from `policy_fn`. This stays
    /// separate from the static layer so it cannot widen static port, CIDR,
    /// or protocol restrictions.
    pub dynamic_ips: Option<HashSet<std::net::IpAddr>>,
}

impl NetworkPolicyLayers {
    /// True when no destination can pass either layer.
    pub(crate) fn denies_everything(&self) -> bool {
        self.dynamic_ips.as_ref().map_or(false, |ips| ips.is_empty())
            || self.allow.denies_everything()
            || self.deny.denies_everything()
            || !network_layers_allow_any(&self.allow, &self.deny, self.dynamic_ips.as_ref())
    }
}

#[derive(Clone, Copy)]
enum IpRegion {
    Any,
    Exact(std::net::IpAddr),
    Cidr(crate::network::IpCidr),
}

enum PortRegion<'a> {
    Any,
    Specific(&'a HashSet<u16>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

#[derive(Clone, Copy)]
struct IpRange {
    family: IpFamily,
    start: u128,
    end: u128,
}

fn network_layers_allow_any(
    allow: &crate::seccomp::notif::NetworkPolicy,
    deny: &crate::seccomp::notif::NetworkPolicy,
    dynamic_ips: Option<&HashSet<std::net::IpAddr>>,
) -> bool {
    if let Some(ips) = dynamic_ips {
        return ips
            .iter()
            .any(|&ip| static_policy_allows_any_for_ip(allow, deny, ip));
    }

    match allow {
        crate::seccomp::notif::NetworkPolicy::Unrestricted => {
            region_allows_any(deny, IpRegion::Any, PortRegion::Any)
        }
        crate::seccomp::notif::NetworkPolicy::AllowList {
            per_ip,
            cidrs,
            any_ip_ports,
        } => {
            per_ip.iter().any(|(&ip, ports)| {
                region_allows_any(deny, IpRegion::Exact(ip), port_region(ports))
            }) || cidrs.iter().any(|(net, ports)| {
                region_allows_any(deny, IpRegion::Cidr(*net), port_region(ports))
            }) || any_ip_ports
                .iter()
                .any(|&port| region_has_ip_survivor(deny, IpRegion::Any, port))
        }
        // The allow layer is never a denylist in a resolved sandbox. Keep an
        // unexpected direct construction fail-open here rather than claiming
        // that two unrelated denylists have no possible survivor.
        crate::seccomp::notif::NetworkPolicy::DenyList { .. } => true,
    }
}

fn static_policy_allows_any_for_ip(
    allow: &crate::seccomp::notif::NetworkPolicy,
    deny: &crate::seccomp::notif::NetworkPolicy,
    ip: std::net::IpAddr,
) -> bool {
    let ip = ip.to_canonical();
    match allow {
        crate::seccomp::notif::NetworkPolicy::Unrestricted => {
            region_allows_any(deny, IpRegion::Exact(ip), PortRegion::Any)
        }
        crate::seccomp::notif::NetworkPolicy::AllowList {
            per_ip,
            cidrs,
            any_ip_ports,
        } => {
            per_ip.get(&ip).is_some_and(|ports| {
                region_allows_any(deny, IpRegion::Exact(ip), port_region(ports))
            }) || cidrs.iter().any(|(net, ports)| {
                net.contains(ip)
                    && region_allows_any(deny, IpRegion::Exact(ip), port_region(ports))
            }) || (!any_ip_ports.is_empty()
                && any_ip_ports
                    .iter()
                    .any(|&port| region_has_ip_survivor(deny, IpRegion::Exact(ip), port)))
        }
        crate::seccomp::notif::NetworkPolicy::DenyList { .. } => true,
    }
}

fn port_region(ports: &crate::seccomp::notif::PortAllow) -> PortRegion<'_> {
    match ports {
        crate::seccomp::notif::PortAllow::Any => PortRegion::Any,
        crate::seccomp::notif::PortAllow::Specific(ports) => PortRegion::Specific(ports),
    }
}

fn region_allows_any(
    deny: &crate::seccomp::notif::NetworkPolicy,
    region: IpRegion,
    ports: PortRegion<'_>,
) -> bool {
    match ports {
        PortRegion::Specific(ports) => ports
            .iter()
            .any(|&port| region_has_ip_survivor(deny, region, port)),
        PortRegion::Any => candidate_ports(deny)
            .into_iter()
            .any(|port| region_has_ip_survivor(deny, region, port)),
    }
}

fn candidate_ports(deny: &crate::seccomp::notif::NetworkPolicy) -> Vec<u16> {
    match deny {
        crate::seccomp::notif::NetworkPolicy::Unrestricted => vec![0],
        crate::seccomp::notif::NetworkPolicy::AllowList { .. } => vec![0],
        crate::seccomp::notif::NetworkPolicy::DenyList {
            cidrs,
            any_ip_ports,
            deny_all,
        } => {
            if *deny_all {
                return Vec::new();
            }
            let mut specific_ports = HashSet::new();
            for (_, denied) in cidrs {
                if let crate::seccomp::notif::PortAllow::Specific(ports) = denied {
                    specific_ports.extend(ports.iter().copied());
                }
            }
            let mut candidates = specific_ports.clone();
            candidates.insert(0);
            if let Some(port) = (0..=u16::MAX)
                .find(|&port| !specific_ports.contains(&port) && !any_ip_ports.contains(&port))
            {
                candidates.insert(port);
            }
            candidates.into_iter().collect()
        }
    }
}

fn region_has_ip_survivor(
    deny: &crate::seccomp::notif::NetworkPolicy,
    region: IpRegion,
    port: u16,
) -> bool {
    match deny {
        crate::seccomp::notif::NetworkPolicy::Unrestricted
        | crate::seccomp::notif::NetworkPolicy::AllowList { .. } => true,
        crate::seccomp::notif::NetworkPolicy::DenyList {
            cidrs,
            any_ip_ports,
            deny_all,
        } => {
            if *deny_all || any_ip_ports.contains(&port) {
                return false;
            }
            match region {
                IpRegion::Exact(ip) => !cidrs.iter().any(|(net, denied)| {
                    net.contains(ip) && port_is_denied(denied, port)
                }),
                IpRegion::Any | IpRegion::Cidr(_) => ip_region_has_survivor(region, cidrs, port),
            }
        }
    }
}

fn port_is_denied(denied: &crate::seccomp::notif::PortAllow, port: u16) -> bool {
    match denied {
        crate::seccomp::notif::PortAllow::Any => true,
        crate::seccomp::notif::PortAllow::Specific(ports) => ports.contains(&port),
    }
}

fn ip_region_has_survivor(
    region: IpRegion,
    cidrs: &[(crate::network::IpCidr, crate::seccomp::notif::PortAllow)],
    port: u16,
) -> bool {
    region_ranges(region).into_iter().any(|target| {
        let covered = cidrs
            .iter()
            .filter(|(_, denied)| port_is_denied(denied, port))
            .filter_map(|(net, _)| {
                let range = cidr_range(net);
                (range.family == target.family).then_some(range)
            })
            .collect();
        !range_fully_covered(target, covered)
    })
}

fn region_ranges(region: IpRegion) -> Vec<IpRange> {
    match region {
        IpRegion::Any => vec![
            IpRange {
                family: IpFamily::V4,
                start: 0,
                end: u32::MAX as u128,
            },
            IpRange {
                family: IpFamily::V6,
                start: 0,
                end: u128::MAX,
            },
        ],
        IpRegion::Exact(ip) => vec![match ip {
            std::net::IpAddr::V4(ip) => IpRange {
                family: IpFamily::V4,
                start: u32::from(ip) as u128,
                end: u32::from(ip) as u128,
            },
            std::net::IpAddr::V6(ip) => IpRange {
                family: IpFamily::V6,
                start: u128::from(ip),
                end: u128::from(ip),
            },
        }],
        IpRegion::Cidr(net) => vec![cidr_range(&net)],
    }
}

fn cidr_range(net: &crate::network::IpCidr) -> IpRange {
    match net.addr {
        std::net::IpAddr::V4(ip) => {
            let bits = u32::from(ip);
            let mask = if net.prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - net.prefix_len)
            };
            let start = bits & mask;
            IpRange {
                family: IpFamily::V4,
                start: start as u128,
                end: (start | !mask) as u128,
            }
        }
        std::net::IpAddr::V6(ip) => {
            let bits = u128::from(ip);
            let mask = if net.prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - net.prefix_len)
            };
            let start = bits & mask;
            IpRange {
                family: IpFamily::V6,
                start,
                end: start | !mask,
            }
        }
    }
}

fn range_fully_covered(target: IpRange, mut covered: Vec<IpRange>) -> bool {
    covered.sort_by_key(|range| range.start);
    let mut next = target.start;
    for range in covered {
        if range.end < next {
            continue;
        }
        if range.start > next {
            return false;
        }
        if range.end >= target.end {
            return true;
        }
        next = range.end + 1;
    }
    false
}

/// Network policy and port-remapping state. Holds separate allow and deny
/// `NetworkPolicy` layers per L4 protocol — the on-behalf handler picks the
/// matching pair based on the dup'd fd's `SO_PROTOCOL`.
pub struct NetworkState {
    /// Allow layer for TCP destinations (`tcp://...` and bare-form rules;
    /// bare specs expand to a TCP + UDP pair at parse time).
    pub tcp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Static deny layer for TCP destinations.
    pub tcp_deny_policy: crate::seccomp::notif::NetworkPolicy,
    /// Allow layer for UDP destinations (`udp://...` and bare-form rules).
    pub udp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Static deny layer for UDP destinations.
    pub udp_deny_policy: crate::seccomp::notif::NetworkPolicy,
    /// Allow layer for ICMP destinations (`icmp://...` rules). ICMP rules
    /// carry no ports, so every entry uses `PortAllow::Any` and the
    /// effective check is IP-only.
    pub icmp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Static deny layer for ICMP destinations.
    pub icmp_deny_policy: crate::seccomp::notif::NetworkPolicy,
    /// Port binding and remapping tracker.
    pub port_map: crate::port_remap::PortMap,
    /// Whether `policy_fn` has activated a global dynamic network layer. Kept
    /// separately from `LivePolicy` so an empty IP set remains distinguishable
    /// from an unrestricted initial policy.
    pub(crate) network_policy_active: Arc<RwLock<bool>>,
    /// Bind allow layer. `None` means bind is in deny-only mode; `Some` may
    /// contain an empty `Ports` list for the default-deny allow-only mode.
    pub bind_allow_ports: Option<crate::sandbox::BindPorts>,
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
            tcp_deny_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            udp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            udp_deny_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            icmp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            icmp_deny_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            port_map: crate::port_remap::PortMap::new(),
            network_policy_active: Arc::new(RwLock::new(false)),
            bind_allow_ports: Some(crate::sandbox::BindPorts::default()),
            bind_deny_ports: HashSet::new(),
            pid_ip_overrides: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            http_acl_addr: None,
            http_acl_ports: HashSet::new(),
            http_acl_orig_dest: None,
        }
    }

    /// Get the effective allow and deny policy layers for the task `tid` and
    /// protocol.
    ///
    /// Static deny remains independent of dynamic policy. A dynamic
    /// restriction is returned as an IP-only layer, so it narrows rather than
    /// replaces the per-protocol static allow layer. Otherwise, a per-PID
    /// restriction takes precedence over the live global restriction.
    /// PID/live restrictions are IP-only — any port is permitted to listed
    /// IPs (legacy `policy_fn` semantics) — and they apply across all
    /// protocols, since the legacy API didn't distinguish them. When both
    /// dynamic restrictions are active, their IP sets are intersected.
    pub(crate) fn effective_network_policy(
        &self,
        tid: u32,
        protocol: crate::sandbox::Protocol,
        live_policy: Option<&std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    ) -> NetworkPolicyLayers {
        use crate::sandbox::Protocol;
        let deny = match protocol {
            Protocol::Tcp => self.tcp_deny_policy.clone(),
            Protocol::Udp => self.udp_deny_policy.clone(),
            Protocol::Icmp => self.icmp_deny_policy.clone(),
        };
        // Hold the mode lock while taking the live-policy snapshot. The
        // callback updates both under the same lock, so an empty set cannot be
        // observed with the old "unrestricted" mode.
        let network_policy_active_guard = self.network_policy_active.read().ok();
        let network_policy_active = network_policy_active_guard
            .as_ref()
            .map(|r| **r)
            .unwrap_or(true);
        let live = live_policy.and_then(|lp| lp.read().ok().map(|policy| policy.clone()));
        drop(network_policy_active_guard);
        // Overrides are keyed by process; the notification names a thread.
        let pid_ips = self.pid_ip_overrides.read().ok().and_then(|overrides| {
            if overrides.is_empty() {
                return None;
            }
            let tgid = read_tgid_of_tid(tid as i32).map_or(tid, |t| t as u32);
            overrides.get(&tgid).cloned()
        });

        let canonicalize_ips = |ips: &HashSet<std::net::IpAddr>| {
            ips.iter().map(|ip| ip.to_canonical()).collect::<HashSet<_>>()
        };
        let static_allow = match protocol {
            Protocol::Tcp => self.tcp_policy.clone(),
            Protocol::Udp => self.udp_policy.clone(),
            Protocol::Icmp => self.icmp_policy.clone(),
        };

        if network_policy_active {
            let mut allowed_ips = live
                .as_ref()
                .map(|policy| canonicalize_ips(&policy.allowed_ips))
                .unwrap_or_default();
            if let Some(pid_ips) = pid_ips {
                let pid_ips = canonicalize_ips(&pid_ips);
                allowed_ips.retain(|ip| pid_ips.contains(ip));
            }
            return NetworkPolicyLayers {
                allow: static_allow,
                deny,
                dynamic_ips: Some(allowed_ips),
            };
        }
        if let Some(pid_ips) = pid_ips {
            return NetworkPolicyLayers {
                allow: static_allow,
                deny,
                dynamic_ips: Some(canonicalize_ips(&pid_ips)),
            };
        }
        NetworkPolicyLayers {
            allow: static_allow,
            deny,
            dynamic_ips: None,
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

    /// The override is set from a policy event's pid and consulted on every
    /// thread's syscalls, so it must be keyed by process, not by task.
    #[test]
    fn pid_override_applies_to_every_thread_of_the_process() {
        let ns = NetworkState::new();
        let tgid = std::process::id();
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        ns.pid_ip_overrides
            .write()
            .unwrap()
            .insert(tgid, HashSet::from([ip]));

        let policy = std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
            assert_ne!(tid, tgid);
            ns.effective_network_policy(tid, crate::sandbox::Protocol::Tcp, None)
        })
        .join()
        .unwrap();

        assert_eq!(policy.dynamic_ips, Some(HashSet::from([ip])));
        assert!(matches!(
            policy.allow,
            crate::seccomp::notif::NetworkPolicy::Unrestricted
        ));
        assert!(matches!(
            policy.deny,
            crate::seccomp::notif::NetworkPolicy::Unrestricted
        ));
    }

    #[test]
    fn pid_override_cannot_erase_static_network_deny() {
        use crate::network::IpCidr;
        use crate::seccomp::notif::{NetworkPolicy, PortAllow};

        let mut ns = NetworkState::new();
        ns.tcp_deny_policy = NetworkPolicy::DenyList {
            cidrs: vec![(IpCidr::parse("10.0.0.0/8").unwrap(), PortAllow::Any)],
            any_ip_ports: HashSet::new(),
            deny_all: false,
        };
        let allowed_by_override: std::net::IpAddr = "10.1.2.3".parse().unwrap();
        ns.pid_ip_overrides
            .write()
            .unwrap()
            .insert(std::process::id(), HashSet::from([allowed_by_override]));

        let layers =
            ns.effective_network_policy(std::process::id(), crate::sandbox::Protocol::Tcp, None);
        assert!(matches!(
            layers.dynamic_ips,
            Some(ref ips) if ips.contains(&allowed_by_override)
        ));
        assert!(!layers.deny.allows(allowed_by_override, 443));
    }

    #[test]
    fn empty_global_network_restriction_is_an_active_deny_all() {
        let ns = NetworkState::new();
        *ns.network_policy_active.write().unwrap() = true;
        ns.pid_ip_overrides.write().unwrap().insert(
            std::process::id(),
            HashSet::from(["8.8.8.8".parse().unwrap()]),
        );
        let layers =
            ns.effective_network_policy(std::process::id(), crate::sandbox::Protocol::Tcp, None);
        assert!(matches!(
            layers.dynamic_ips,
            Some(ref ips) if ips.is_empty()
        ));
    }

    #[test]
    fn an_initial_live_policy_does_not_replace_static_port_rules() {
        use crate::seccomp::notif::{NetworkPolicy, PortAllow};

        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let mut ns = NetworkState::new();
        ns.tcp_policy = NetworkPolicy::AllowList {
            per_ip: HashMap::from([(ip, PortAllow::Specific(HashSet::from([443])))]),
            cidrs: Vec::new(),
            any_ip_ports: HashSet::new(),
        };
        let live = Arc::new(RwLock::new(crate::policy_fn::LivePolicy {
            allowed_ips: HashSet::from([ip]),
            max_memory_bytes: 0,
            max_processes: 0,
        }));

        let layers = ns.effective_network_policy(
            std::process::id(),
            crate::sandbox::Protocol::Tcp,
            Some(&live),
        );
        assert!(layers.dynamic_ips.is_none());
        assert!(layers.allow.allows(ip, 443));
        assert!(!layers.allow.allows(ip, 80));
    }

    #[test]
    fn static_protocol_boundary_survives_an_initial_live_policy() {
        use crate::seccomp::notif::NetworkPolicy;

        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let mut ns = NetworkState::new();
        ns.tcp_policy = NetworkPolicy::AllowList {
            per_ip: HashMap::from([(ip, crate::seccomp::notif::PortAllow::Any)]),
            cidrs: Vec::new(),
            any_ip_ports: HashSet::new(),
        };
        // This is the resolved shape of an explicit tcp-only allow rule for
        // UDP: the protocol has an active but empty allowlist.
        ns.udp_policy = NetworkPolicy::AllowList {
            per_ip: HashMap::new(),
            cidrs: Vec::new(),
            any_ip_ports: HashSet::new(),
        };
        let live = Arc::new(RwLock::new(crate::policy_fn::LivePolicy {
            allowed_ips: HashSet::from([ip]),
            max_memory_bytes: 0,
            max_processes: 0,
        }));

        let layers = ns.effective_network_policy(
            std::process::id(),
            crate::sandbox::Protocol::Udp,
            Some(&live),
        );
        assert!(layers.dynamic_ips.is_none());
        assert!(layers.allow.denies_everything());
    }

    #[test]
    fn pid_override_cannot_widen_static_allowlist() {
        use crate::seccomp::notif::{NetworkPolicy, PortAllow};

        let static_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let foreign_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        let mut ns = NetworkState::new();
        ns.tcp_policy = NetworkPolicy::AllowList {
            per_ip: HashMap::from([(
                static_ip,
                PortAllow::Specific(HashSet::from([443])),
            )]),
            cidrs: Vec::new(),
            any_ip_ports: HashSet::new(),
        };
        ns.pid_ip_overrides
            .write()
            .unwrap()
            .insert(std::process::id(), HashSet::from([foreign_ip]));

        let layers = ns.effective_network_policy(
            std::process::id(),
            crate::sandbox::Protocol::Tcp,
            None,
        );
        assert!(matches!(
            layers.dynamic_ips,
            Some(ref ips) if ips.contains(&foreign_ip)
        ));
        assert!(!layers.allow.allows(foreign_ip, 443));
        assert!(layers.allow.allows(static_ip, 443));
    }

    #[test]
    fn grant_activates_the_dynamic_network_layer() {
        let granted_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let ns = NetworkState::new();
        let live = Arc::new(RwLock::new(crate::policy_fn::LivePolicy {
            allowed_ips: HashSet::new(),
            max_memory_bytes: 0,
            max_processes: 0,
        }));
        let active = ns.network_policy_active.clone();
        let mut ctx = crate::policy_fn::PolicyContext::new(
            live.clone(),
            crate::policy_fn::LivePolicy {
                allowed_ips: HashSet::from([granted_ip]),
                max_memory_bytes: 0,
                max_processes: 0,
            },
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(DeniedSet::default()),
            active,
        );

        ctx.grant_network(&[granted_ip]).unwrap();
        let layers = ns.effective_network_policy(
            std::process::id(),
            crate::sandbox::Protocol::Tcp,
            Some(&live),
        );
        assert_eq!(layers.dynamic_ips, Some(HashSet::from([granted_ip])));
    }

    #[test]
    fn fully_overlapping_allow_and_deny_layers_deny_everything() {
        use crate::network::IpCidr;
        use crate::seccomp::notif::{NetworkPolicy, PortAllow};

        let cidr = IpCidr::parse("10.0.0.0/8").unwrap();
        let mut ns = NetworkState::new();
        ns.udp_policy = NetworkPolicy::AllowList {
            per_ip: HashMap::new(),
            cidrs: vec![(cidr, PortAllow::Any)],
            any_ip_ports: HashSet::new(),
        };
        ns.udp_deny_policy = NetworkPolicy::DenyList {
            cidrs: vec![(cidr, PortAllow::Any)],
            any_ip_ports: HashSet::new(),
            deny_all: false,
        };

        let layers = ns.effective_network_policy(
            std::process::id(),
            crate::sandbox::Protocol::Udp,
            None,
        );
        assert!(layers.denies_everything());
    }

    #[test]
    fn partially_overlapping_allow_and_deny_layers_leave_a_survivor() {
        use crate::network::IpCidr;
        use crate::seccomp::notif::{NetworkPolicy, PortAllow};

        let allow_cidr = IpCidr::parse("10.0.0.0/8").unwrap();
        let deny_cidr = IpCidr::parse("10.0.0.0/9").unwrap();
        let mut ns = NetworkState::new();
        ns.udp_policy = NetworkPolicy::AllowList {
            per_ip: HashMap::new(),
            cidrs: vec![(allow_cidr, PortAllow::Any)],
            any_ip_ports: HashSet::new(),
        };
        ns.udp_deny_policy = NetworkPolicy::DenyList {
            cidrs: vec![(deny_cidr, PortAllow::Any)],
            any_ip_ports: HashSet::new(),
            deny_all: false,
        };

        let layers = ns.effective_network_policy(
            std::process::id(),
            crate::sandbox::Protocol::Udp,
            None,
        );
        assert!(!layers.denies_everything());
    }
}
