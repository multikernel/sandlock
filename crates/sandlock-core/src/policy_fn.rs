//! Dynamic policy — live policy modification via syscall event callbacks.
//!
//! Allows a user-provided callback to inspect syscall events and adjust
//! sandbox permissions at runtime (grant, restrict, per-PID overrides).
//!
//! ```ignore
//! let policy = Policy::builder()
//!     .fs_read("/usr").fs_read("/lib")
//!     .net_allow_host("127.0.0.1")
//!     .policy_fn(|event, ctx| {
//!         if event.syscall == "connect" && event.host == Some("10.0.0.5".parse().unwrap()) {
//!             return Verdict::Deny;
//!         }
//!         Verdict::Allow
//!     })
//!     .build()?;
//! ```
//!
//! # TOCTOU and string-typed fields
//!
//! Path and argv strings the kernel will re-read after a `Continue`
//! response (per `seccomp_unotify(2)`) are not exposed on this event.
//! Path-based access control belongs in static Landlock rules
//! (`fs_read`/`fs_write`/`fs_deny`), which the kernel enforces directly
//! and which are not subject to user-memory races. Network fields
//! (`host`, `port`) are TOCTOU-safe because the supervisor performs
//! `connect`/`sendto`/`bind` on-behalf via `pidfd_getfd` and the kernel
//! never re-reads child memory for those syscalls.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

// ============================================================
// SyscallCategory
// ============================================================

/// High-level category of a syscall event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallCategory {
    /// Filesystem operations (openat, unlinkat, mkdirat, etc.)
    File,
    /// Network operations (connect, sendto, bind, etc.)
    Network,
    /// Process lifecycle (clone, execve, vfork, etc.)
    Process,
    /// Memory management (mmap, munmap, brk, etc.)
    Memory,
}

// ============================================================
// SyscallEvent
// ============================================================

/// An intercepted syscall event observed by the seccomp supervisor.
///
/// # TOCTOU and string-typed fields
///
/// Path strings are deliberately absent. Per `seccomp_unotify(2)`, the
/// kernel re-reads user-memory pointers after a `Continue` response, so
/// any path-string-based decision is racy in a multi-threaded child.
/// Path-based access control belongs in static Landlock rules
/// (`fs_read` / `fs_write` / `fs_deny`); see issue #27.
///
/// `argv` *is* exposed for `execve`/`execveat` and is TOCTOU-safe by
/// construction: with `policy_fn` active, fork-like syscalls are traced
/// for one ptrace creation event, so children are registered in
/// `ProcessIndex` before they can run user code. Before the supervisor
/// exposes `argv` to `policy_fn` or returns `Continue` for an execve, it
/// then `PTRACE_SEIZE`+`PTRACE_INTERRUPT`s every task that could write
/// the memory — both sibling threads of the calling tid (same TGID, share
/// `mm_struct`) and peer threads in other TGIDs that may alias argv
/// pages via `MAP_SHARED` mappings or share `mm_struct` via
/// `clone(CLONE_VM)`. The kernel's post-Continue re-read therefore
/// sees the same memory the supervisor inspected. Siblings are killed
/// by the kernel during execve's `de_thread` step; peer threads are
/// detached after `NOTIF_SEND` and resume normally. See
/// `crate::sandbox_freeze`.
///
/// Network fields (`host`, `port`) are TOCTOU-safe because the
/// supervisor performs `connect`/`sendto`/`bind` on-behalf via
/// `pidfd_getfd` and the kernel never re-reads child memory for those.
#[derive(Debug, Clone)]
pub struct SyscallEvent {
    /// Syscall name (e.g., "connect", "openat", "execve", "clone").
    pub syscall: String,
    /// High-level category.
    pub category: SyscallCategory,
    /// PID of the process that made the syscall.
    pub pid: u32,
    /// Parent PID (read from /proc/{pid}/stat).
    pub parent_pid: Option<u32>,
    /// Destination IP address (for connect, sendto). TOCTOU-safe.
    pub host: Option<IpAddr>,
    /// Destination port (for connect, sendto, bind). TOCTOU-safe.
    pub port: Option<u16>,
    /// Size argument (for mmap, brk).
    pub size: Option<u64>,
    /// Command arguments for execve/execveat. TOCTOU-safe: every task
    /// in `ProcessIndex` (caller's siblings and peer processes) is
    /// frozen before argv is read for this event and before the kernel
    /// re-reads argv from child memory; fork-like syscalls register
    /// children before they can run user code while `policy_fn` is
    /// active.
    pub argv: Option<Vec<String>>,
    /// Whether the supervisor denied this syscall.
    pub denied: bool,
}

impl SyscallEvent {
    /// Returns true if any argv element contains the given substring.
    /// Only meaningful for execve/execveat events (where argv is populated).
    pub fn argv_contains(&self, s: &str) -> bool {
        self.argv.as_ref().map_or(false, |args| args.iter().any(|a| a.contains(s)))
    }
}

// ============================================================
// LivePolicy — atomically swappable runtime policy
// ============================================================

/// Runtime policy state that can be modified by the policy callback.
///
/// This is separate from the static `Policy` — it holds only the fields
/// that can be dynamically adjusted at runtime.
#[derive(Debug, Clone)]
pub struct LivePolicy {
    /// Allowed destination IPs for outbound connections.
    pub allowed_ips: HashSet<IpAddr>,
    /// Maximum memory in bytes (0 = unlimited).
    pub max_memory_bytes: u64,
    /// Maximum number of forks.
    pub max_processes: u32,
}

// ============================================================
// PolicyContext
// ============================================================

/// Context passed to the policy callback for inspecting and modifying policy.
///
/// - `grant()`: expand permissions up to the ceiling (reversible)
/// - `restrict()`: permanently shrink permissions (irreversible)
/// - `restrict_pid()`: apply per-PID network overrides
pub struct PolicyContext {
    live: Arc<RwLock<LivePolicy>>,
    ceiling: LivePolicy,
    restricted: HashSet<&'static str>,
    pid_overrides: Arc<RwLock<HashMap<u32, HashSet<IpAddr>>>>,
    denied_paths: Arc<RwLock<HashSet<String>>>,
}

impl PolicyContext {
    pub(crate) fn new(
        live: Arc<RwLock<LivePolicy>>,
        ceiling: LivePolicy,
        pid_overrides: Arc<RwLock<HashMap<u32, HashSet<IpAddr>>>>,
        denied_paths: Arc<RwLock<HashSet<String>>>,
    ) -> Self {
        Self {
            live,
            ceiling,
            restricted: HashSet::new(),
            pid_overrides,
            denied_paths,
        }
    }

    /// Current effective policy (snapshot).
    pub fn current(&self) -> LivePolicy {
        self.live.read().unwrap().clone()
    }

    /// Maximum permissions (immutable ceiling).
    pub fn ceiling(&self) -> &LivePolicy {
        &self.ceiling
    }

    // ---- Grant (expand within ceiling) ----

    /// Expand allowed IPs. Cannot exceed ceiling. Fails if restricted.
    pub fn grant_network(&mut self, ips: &[IpAddr]) -> Result<(), PolicyFnError> {
        self.check_not_restricted("allowed_ips")?;
        let mut live = self.live.write().unwrap();
        for ip in ips {
            if self.ceiling.allowed_ips.contains(ip) {
                live.allowed_ips.insert(*ip);
            }
        }
        Ok(())
    }

    /// Expand max memory. Cannot exceed ceiling. Fails if restricted.
    pub fn grant_max_memory(&mut self, bytes: u64) -> Result<(), PolicyFnError> {
        self.check_not_restricted("max_memory_bytes")?;
        let mut live = self.live.write().unwrap();
        live.max_memory_bytes = bytes.min(self.ceiling.max_memory_bytes);
        Ok(())
    }

    /// Expand max processes. Cannot exceed ceiling. Fails if restricted.
    pub fn grant_max_processes(&mut self, n: u32) -> Result<(), PolicyFnError> {
        self.check_not_restricted("max_processes")?;
        let mut live = self.live.write().unwrap();
        live.max_processes = n.min(self.ceiling.max_processes);
        Ok(())
    }

    // ---- Restrict (permanent shrink) ----

    /// Permanently restrict allowed IPs. Cannot be granted back.
    pub fn restrict_network(&mut self, ips: &[IpAddr]) {
        self.restricted.insert("allowed_ips");
        let mut live = self.live.write().unwrap();
        live.allowed_ips = ips.iter().copied().collect();
    }

    /// Permanently restrict max memory. Cannot be granted back.
    pub fn restrict_max_memory(&mut self, bytes: u64) {
        self.restricted.insert("max_memory_bytes");
        let mut live = self.live.write().unwrap();
        live.max_memory_bytes = bytes;
    }

    /// Permanently restrict max processes. Cannot be granted back.
    pub fn restrict_max_processes(&mut self, n: u32) {
        self.restricted.insert("max_processes");
        let mut live = self.live.write().unwrap();
        live.max_processes = n;
    }

    // ---- Per-PID overrides ----

    /// Restrict network for a specific PID (tighter than global policy).
    pub fn restrict_pid_network(&self, pid: u32, ips: &[IpAddr]) {
        let mut overrides = self.pid_overrides.write().unwrap();
        overrides.insert(pid, ips.iter().copied().collect());
    }

    /// Remove per-PID override, falling back to global policy.
    pub fn clear_pid_override(&self, pid: u32) {
        let mut overrides = self.pid_overrides.write().unwrap();
        overrides.remove(&pid);
    }

    // ---- Filesystem restriction ----

    /// Deny access to a path (and all children). Checked by the supervisor
    /// on openat/stat/access syscalls. Takes effect immediately.
    pub fn deny_path(&self, path: &str) {
        let mut denied = self.denied_paths.write().unwrap();
        denied.insert(path.to_string());
    }

    /// Remove a previously denied path.
    pub fn allow_path(&self, path: &str) {
        let mut denied = self.denied_paths.write().unwrap();
        denied.remove(path);
    }

    // ---- Internal ----

    fn check_not_restricted(&self, field: &str) -> Result<(), PolicyFnError> {
        if self.restricted.contains(field) {
            Err(PolicyFnError::FieldRestricted(field.to_string()))
        } else {
            Ok(())
        }
    }
}

// ============================================================
// Error type
// ============================================================

/// Errors from policy callback operations.
#[derive(Debug, thiserror::Error)]
pub enum PolicyFnError {
    #[error("cannot grant restricted field: {0}")]
    FieldRestricted(String),
}

// ============================================================
// PolicyCallback type
// ============================================================

/// Verdict returned by the policy callback for the current syscall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Allow the syscall to proceed (default).
    Allow,
    /// Allow but flag for audit logging.
    Audit,
    /// Deny the syscall with EPERM.
    Deny,
    /// Deny the syscall with a specific errno.
    DenyWith(i32),
}

impl Default for Verdict {
    fn default() -> Self { Verdict::Allow }
}

/// A callback function invoked for each intercepted syscall.
///
/// Called synchronously on a dedicated thread. For `execve` syscalls,
/// the child process is held until the callback returns.
///
/// Return `Verdict::Deny` to block the current syscall. Only effective
/// for held syscalls (execve/execveat) and network syscalls (connect/sendto).
///
/// Wrapped in `Arc` so that `Policy` remains `Clone`.
pub type PolicyCallback = Arc<dyn Fn(SyscallEvent, &mut PolicyContext) -> Verdict + Send + Sync + 'static>;

// ============================================================
// Event channel types (used by supervisor integration)
// ============================================================

/// An event sent from the supervisor to the policy callback thread.
pub struct PolicyEvent {
    pub event: SyscallEvent,
    /// If Some, the supervisor blocks until this is signaled.
    /// Used for execve to allow pre-execution policy changes.
    /// The Verdict is sent back to control allow/deny.
    pub gate: Option<tokio::sync::oneshot::Sender<Verdict>>,
}

// ============================================================
// Policy callback runner
// ============================================================

/// Spawn a thread that receives syscall events and calls the policy callback.
///
/// Returns a sender for the supervisor to push events into.
pub(crate) fn spawn_policy_fn(
    callback: PolicyCallback,
    live: Arc<RwLock<LivePolicy>>,
    ceiling: LivePolicy,
    pid_overrides: Arc<RwLock<HashMap<u32, HashSet<IpAddr>>>>,
    denied_paths: Arc<RwLock<HashSet<String>>>,
) -> tokio::sync::mpsc::UnboundedSender<PolicyEvent> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PolicyEvent>();

    std::thread::Builder::new()
        .name("sandlock-policy-fn".to_string())
        .spawn(move || {
            let mut ctx = PolicyContext::new(live, ceiling, pid_overrides, denied_paths);

            while let Some(pe) = rx.blocking_recv() {
                let verdict = callback(pe.event, &mut ctx);

                // Signal the supervisor with the verdict.
                // For execve, this unblocks the child.
                if let Some(gate) = pe.gate {
                    let _ = gate.send(verdict);
                }
            }
        })
        .expect("failed to spawn policy-fn thread");

    tx
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_live() -> LivePolicy {
        LivePolicy {
            allowed_ips: ["127.0.0.1", "10.0.0.1"]
                .iter()
                .map(|s| s.parse().unwrap())
                .collect(),
            max_memory_bytes: 1024 * 1024 * 1024,
            max_processes: 64,
        }
    }

    #[test]
    fn test_grant_within_ceiling() {
        let live = Arc::new(RwLock::new(LivePolicy {
            allowed_ips: HashSet::new(),
            max_memory_bytes: 0,
            max_processes: 0,
        }));
        let ceiling = test_live();
        let pid_overrides = Arc::new(RwLock::new(HashMap::new()));
        let denied_paths = Arc::new(RwLock::new(HashSet::new()));
        let mut ctx = PolicyContext::new(live.clone(), ceiling, pid_overrides, denied_paths);

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        ctx.grant_network(&[ip]).unwrap();
        assert!(live.read().unwrap().allowed_ips.contains(&ip));
    }

    #[test]
    fn test_grant_capped_to_ceiling() {
        let live = Arc::new(RwLock::new(LivePolicy {
            allowed_ips: HashSet::new(),
            max_memory_bytes: 0,
            max_processes: 0,
        }));
        let ceiling = test_live();
        let pid_overrides = Arc::new(RwLock::new(HashMap::new()));
        let denied_paths = Arc::new(RwLock::new(HashSet::new()));
        let mut ctx = PolicyContext::new(live.clone(), ceiling, pid_overrides, denied_paths);

        // Try to grant an IP not in ceiling — should be silently ignored
        let foreign: IpAddr = "8.8.8.8".parse().unwrap();
        ctx.grant_network(&[foreign]).unwrap();
        assert!(!live.read().unwrap().allowed_ips.contains(&foreign));
    }

    #[test]
    fn test_restrict_then_grant_fails() {
        let live = Arc::new(RwLock::new(test_live()));
        let ceiling = test_live();
        let pid_overrides = Arc::new(RwLock::new(HashMap::new()));
        let denied_paths = Arc::new(RwLock::new(HashSet::new()));
        let mut ctx = PolicyContext::new(live, ceiling, pid_overrides, denied_paths);

        ctx.restrict_network(&[]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(ctx.grant_network(&[ip]).is_err());
    }

    #[test]
    fn test_restrict_max_memory() {
        let live = Arc::new(RwLock::new(test_live()));
        let ceiling = test_live();
        let pid_overrides = Arc::new(RwLock::new(HashMap::new()));
        let denied_paths = Arc::new(RwLock::new(HashSet::new()));
        let mut ctx = PolicyContext::new(live.clone(), ceiling, pid_overrides, denied_paths);

        ctx.restrict_max_memory(256 * 1024 * 1024);
        assert_eq!(live.read().unwrap().max_memory_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn test_pid_override() {
        let live = Arc::new(RwLock::new(test_live()));
        let ceiling = test_live();
        let pid_overrides = Arc::new(RwLock::new(HashMap::new()));
        let denied_paths = Arc::new(RwLock::new(HashSet::new()));
        let ctx = PolicyContext::new(live, ceiling, pid_overrides.clone(), denied_paths);

        let localhost: IpAddr = "127.0.0.1".parse().unwrap();
        ctx.restrict_pid_network(1234, &[localhost]);

        let overrides = pid_overrides.read().unwrap();
        let pid_ips = overrides.get(&1234).unwrap();
        assert!(pid_ips.contains(&localhost));
        assert_eq!(pid_ips.len(), 1);
    }

    #[test]
    fn test_clear_pid_override() {
        let live = Arc::new(RwLock::new(test_live()));
        let ceiling = test_live();
        let pid_overrides = Arc::new(RwLock::new(HashMap::new()));
        let denied_paths = Arc::new(RwLock::new(HashSet::new()));
        let ctx = PolicyContext::new(live, ceiling, pid_overrides.clone(), denied_paths);

        let localhost: IpAddr = "127.0.0.1".parse().unwrap();
        ctx.restrict_pid_network(1234, &[localhost]);
        ctx.clear_pid_override(1234);
        assert!(!pid_overrides.read().unwrap().contains_key(&1234));
    }

    #[test]
    fn test_event_argv_contains() {
        let event = SyscallEvent {
            syscall: "execve".to_string(),
            category: SyscallCategory::Process,
            pid: 1,
            parent_pid: Some(0),
            host: None,
            port: None,
            size: None,
            argv: Some(vec!["python3".into(), "-c".into(), "print(1)".into()]),
            denied: false,
        };
        assert!(event.argv_contains("python3"));
        assert!(event.argv_contains("-c"));
        assert!(!event.argv_contains("ruby"));
        assert_eq!(event.category, SyscallCategory::Process);
    }

    #[test]
    fn test_event_argv_contains_none() {
        let event = SyscallEvent {
            syscall: "openat".to_string(),
            category: SyscallCategory::File,
            pid: 1,
            parent_pid: None,
            host: None,
            port: None,
            size: None,
            argv: None,
            denied: false,
        };
        assert!(!event.argv_contains("anything"));
    }
}
