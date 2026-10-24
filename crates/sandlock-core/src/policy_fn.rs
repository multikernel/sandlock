//! Dynamic policy — live policy modification via syscall event callbacks.
//!
//! Allows a user-provided callback to inspect syscall events and adjust
//! sandbox permissions at runtime: narrow them through the context, or grant
//! network rules within `PolicyFn::approvable` when answering an approval.
//!
//! ```
//! use sandlock_core::{Sandbox, PolicyFn, policy_fn::Verdict};
//!
//! let blocked_host = "10.0.0.5".parse()?;
//! let policy = Sandbox::builder()
//!     .net_allow("tcp://10.0.0.0/24:443")
//!     .policy_fn(PolicyFn::new(move |event, _ctx| {
//!         if event.syscall == "connect" && event.host == Some(blocked_host) {
//!             return Verdict::Deny;
//!         }
//!         Verdict::Allow
//!     }))
//!     .build()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
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
use std::time::Duration;
use tokio_util::sync::CancellationToken;

// ============================================================
// SyscallCategory
// ============================================================

/// High-level category of a syscall event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallCategory {
    /// Filesystem operations (openat, unlinkat, mkdirat, etc.)
    Filesystem,
    /// Network operations (connect, sendto, bind, etc.)
    Network,
    /// Process lifecycle (clone, execve, vfork, etc.)
    Process,
}

/// The event categories a policy callback subscribes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CategorySet(u8);

impl CategorySet {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const ALL: Self = Self(0b111);

    pub(crate) fn of(categories: &[SyscallCategory]) -> Self {
        Self(categories.iter().fold(0, |bits, &c| bits | 1 << c as u8))
    }

    pub(crate) fn contains(self, category: SyscallCategory) -> bool {
        self.0 & 1 << category as u8 != 0
    }
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
/// `crate::freeze`.
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
    /// PID of the process that made the syscall. Notifications name the
    /// calling thread; this is its thread-group id.
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
    /// Resolved absolute path for file syscalls (openat, execve/execveat,
    /// mkdirat, unlinkat, symlinkat, truncate, renameat2 src, linkat src).
    /// Read from child user memory, not TOCTOU-safe for enforcement but
    /// sufficient for learn-mode observation.
    /// `None` for non-file syscalls or when resolution fails.
    pub path: Option<std::path::PathBuf>,
    /// Second resolved path for two-path syscalls (renameat2 dst, linkat dst).
    /// `None` for single-path syscalls.
    pub path2: Option<std::path::PathBuf>,
    /// Open flags for openat (the `flags` argument, e.g. `O_RDONLY`,
    /// `O_WRONLY`, `O_CREAT`). `None` for non-openat syscalls.
    pub flags: Option<u64>,
    /// Socket protocol for network syscalls (connect, sendto, sendmsg, sendmmsg).
    /// One of "tcp", "udp", "icmp". `None` for non-network syscalls or when
    /// protocol resolution fails.
    pub protocol: Option<String>,
    /// Socket file descriptor for network syscalls (connect, send*, bind).
    /// `None` for non-network syscalls.
    pub fd: Option<i64>,
}

impl SyscallEvent {
    /// Returns true if any argv element contains the given substring.
    /// Only meaningful for execve/execveat events (where argv is populated).
    pub fn argv_contains(&self, s: &str) -> bool {
        self.argv
            .as_ref()
            .map_or(false, |args| args.iter().any(|a| a.contains(s)))
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
    /// Destinations outbound connections and sends may reach now.
    pub net_allow: NetRuleSet,
    /// Destinations an approval may still open; always covers `net_allow`.
    pub net_approvable: NetRuleSet,
    /// Maximum memory in bytes (0 = unlimited).
    pub max_memory_bytes: u64,
    /// Maximum concurrent processes (`u32::MAX` = unlimited).
    pub max_processes: u32,
}

pub use crate::network::NetRuleSet;

/// Permissions in the `Sandbox` vocabulary, used to narrow live policy or to
/// bound what approvals may open.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permissions {
    net_allow: Option<Vec<String>>,
}

impl Permissions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a `net_allow` spec, in the same syntax as
    /// [`SandboxBuilder::net_allow`](crate::SandboxBuilder::net_allow).
    pub fn net_allow(mut self, spec: impl Into<String>) -> Self {
        self.net_allow
            .get_or_insert_with(Vec::new)
            .push(spec.into());
        self
    }

    /// Name `net_allow` with no specs, which means no destination.
    pub fn net_allow_none(mut self) -> Self {
        self.net_allow.get_or_insert_with(Vec::new);
        self
    }

    pub(crate) fn net_allow_specs(&self) -> Option<&[String]> {
        self.net_allow.as_deref()
    }

    pub(crate) fn net_rules(&self) -> Result<NetRuleSet, PolicyFnError> {
        let specs = self
            .net_allow_specs()
            .ok_or_else(|| PolicyFnError::Invalid("no permissions given".into()))?;
        NetRuleSet::parse_literal(specs)
    }
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
    cancellation: CancellationToken,
    live: Arc<RwLock<LivePolicy>>,
    ceiling: LivePolicy,
    restricted: HashSet<&'static str>,
    pid_overrides: Arc<RwLock<HashMap<u32, NetRuleSet>>>,
    denied: Arc<crate::seccomp::state::DeniedSet>,
    events: CategorySet,
}

impl PolicyContext {
    pub(crate) fn new(
        live: Arc<RwLock<LivePolicy>>,
        ceiling: LivePolicy,
        pid_overrides: Arc<RwLock<HashMap<u32, NetRuleSet>>>,
        denied: Arc<crate::seccomp::state::DeniedSet>,
    ) -> Self {
        Self {
            cancellation: CancellationToken::new(),
            live,
            ceiling,
            restricted: HashSet::new(),
            pid_overrides,
            denied,
            events: CategorySet::ALL,
        }
    }

    /// Whether sandbox shutdown has cancelled this callback.
    ///
    /// Interactive approval loops must check this between bounded waits and
    /// return promptly when true. Shutdown joins the callback thread; it cannot
    /// interrupt arbitrary user code.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Current effective policy (snapshot).
    pub fn current(&self) -> LivePolicy {
        self.live.read().unwrap().clone()
    }

    // ---- Grant (expand within ceiling) ----

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

    /// Permanently narrow live and approvable network rules to `p`.
    pub fn restrict(&mut self, p: &Permissions) -> Result<(), PolicyFnError> {
        let rules = p.net_rules()?;
        let mut live = self.live.write().unwrap();
        live.net_allow = live.net_allow.intersect(&rules);
        live.net_approvable = live.net_approvable.intersect(&rules);
        Ok(())
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

    /// Narrow one process's network below the live policy.
    pub fn restrict_pid(&self, pid: u32, p: &Permissions) -> Result<(), PolicyFnError> {
        let rules = p.net_rules()?;
        self.pid_overrides.write().unwrap().insert(pid, rules);
        Ok(())
    }

    /// Remove per-PID override, falling back to global policy.
    pub fn clear_pid_override(&self, pid: u32) {
        let mut overrides = self.pid_overrides.write().unwrap();
        overrides.remove(&pid);
    }

    // ---- Filesystem restriction ----

    /// Deny access to a path (and all children). Checked by the supervisor
    /// on openat/stat/access syscalls. Takes effect immediately. The file's
    /// inode identity is captured too, so the deny survives hardlinks and
    /// renames to a non-denied name. Fails unless filesystem events
    /// are subscribed, since only then are path syscalls intercepted.
    pub fn deny_path(&self, path: &str) -> Result<(), PolicyFnError> {
        if !self.events.contains(SyscallCategory::Filesystem) {
            return Err(PolicyFnError::NotSubscribed(SyscallCategory::Filesystem));
        }
        self.denied.deny(path);
        Ok(())
    }

    /// Remove a previously denied path.
    pub fn allow_path(&self, path: &str) {
        self.denied.allow(path);
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
    #[error("{0:?} events are not subscribed")]
    NotSubscribed(SyscallCategory),
    #[error("invalid network rule: {0}")]
    Invalid(String),
    #[error("not approvable: {0}")]
    NotApprovable(String),
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
    /// Widen the live rules to `Permissions` for good, within
    /// [`PolicyFn::approvable`], then allow. A grant outside it denies.
    Grant(Permissions),
}

impl Default for Verdict {
    fn default() -> Self {
        Verdict::Allow
    }
}

/// A callback function invoked for each intercepted syscall.
///
/// Called on a dedicated thread, one event at a time. Held syscalls come with
/// an [`Approval`]; the child stays blocked until it is resolved, the verdict
/// timeout expires, or the sandbox shuts down. Shutdown waits for a running
/// callback to return.
///
/// Only held syscalls can be denied: exec (execve/execveat), open
/// (open/openat/openat2), and network (connect/bind/sendto/sendmsg/sendmmsg).
/// Filesystem-mutation events (mkdir/unlink/symlink/link/rename/truncate) are
/// observation-only. Use `fs_deny` to block paths.
///
/// Wrapped in `Arc` so that `Policy` remains `Clone`.
pub type PolicyCallback =
    Arc<dyn Fn(SyscallEvent, &mut PolicyContext, Option<Approval>) + Send + Sync + 'static>;

/// The pending verdict of one held syscall, answerable from any thread.
///
/// Dropping it unresolved denies the syscall with `EPERM`.
#[derive(Debug)]
pub struct Approval {
    gate: tokio::sync::oneshot::Sender<Verdict>,
    cancellation: CancellationToken,
    live: Option<Arc<RwLock<LivePolicy>>>,
}

impl Approval {
    /// Answer the held syscall. A refused [`Verdict::Grant`] denies it and
    /// is logged; use [`Approval::try_resolve`] to see why.
    pub fn resolve(self, verdict: Verdict) {
        if let Err(e) = self.try_resolve(verdict) {
            log::warn!("policy_fn grant refused, operation denied: {e}");
        }
    }

    /// Like [`Approval::resolve`], but reports a refused grant. The syscall
    /// is answered either way.
    pub fn try_resolve(self, verdict: Verdict) -> Result<(), PolicyFnError> {
        let (verdict, result) = match verdict {
            Verdict::Grant(p) => match self.grant(&p) {
                Ok(()) => (Verdict::Allow, Ok(())),
                Err(e) => (Verdict::Deny, Err(e)),
            },
            verdict => (verdict, Ok(())),
        };
        let _ = self.gate.send(verdict);
        result
    }

    pub fn allow(self) {
        self.resolve(Verdict::Allow);
    }

    pub fn deny(self) {
        self.resolve(Verdict::Deny);
    }

    fn grant(&self, p: &Permissions) -> Result<(), PolicyFnError> {
        let rules = p.net_rules()?;
        let live = self
            .live
            .as_ref()
            .ok_or_else(|| PolicyFnError::NotApprovable("no live policy".into()))?;
        let mut live = live.write().unwrap();
        if !live.net_approvable.covers(&rules) {
            return Err(PolicyFnError::NotApprovable(
                p.net_allow_specs().unwrap_or_default().join(", "),
            ));
        }
        live.net_allow.union(&rules);
        Ok(())
    }

    /// Whether shutdown or the verdict timeout already decided the syscall,
    /// so resolving no longer matters.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled() || self.gate.is_closed()
    }
}

/// A dynamic policy callback and the settings for its held verdicts.
#[derive(Clone)]
pub struct PolicyFn {
    pub(crate) callback: PolicyCallback,
    pub(crate) verdict_timeout: Option<Duration>,
    pub(crate) events: CategorySet,
    pub(crate) approvable: Permissions,
    /// `approvable` parsed at sandbox build.
    pub(crate) approvable_net_allow: Vec<crate::network::NetAllow>,
}

impl PolicyFn {
    /// Configure a callback that returns each verdict, with a five-second
    /// verdict timeout. Approval loops must check
    /// [`PolicyContext::is_cancelled`] between bounded waits.
    pub fn new(
        callback: impl Fn(SyscallEvent, &mut PolicyContext) -> Verdict + Send + Sync + 'static,
    ) -> Self {
        Self::deferred(move |event, ctx, approval| {
            let verdict = callback(event, ctx);
            if let Some(approval) = approval {
                approval.resolve(if ctx.is_cancelled() {
                    Verdict::Deny
                } else {
                    verdict
                });
            }
        })
    }

    /// Configure a callback that may keep a held syscall's [`Approval`] and
    /// resolve it later, so the next event is delivered without waiting for
    /// a decision. `approval` is `None` for observation-only events.
    pub fn deferred(
        callback: impl Fn(SyscallEvent, &mut PolicyContext, Option<Approval>) + Send + Sync + 'static,
    ) -> Self {
        Self {
            callback: Arc::new(callback),
            verdict_timeout: Some(Duration::from_secs(5)),
            events: CategorySet::ALL,
            approvable: Permissions::new(),
            approvable_net_allow: Vec::new(),
        }
    }

    /// Maximum wait for a held verdict, including queue time. `None` waits
    /// until a decision or shutdown; zero denies immediately. Expiry denies
    /// the syscall without interrupting a callback already running.
    pub fn verdict_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.verdict_timeout = timeout;
        self
    }

    /// Deliver only events in these categories (default: all). Syscalls
    /// outside them are not intercepted for the callback, so a network-only
    /// callback skips file traps and execve freezing.
    pub fn events(mut self, categories: &[SyscallCategory]) -> Self {
        self.events = CategorySet::of(categories);
        self
    }

    /// The most an approval may open beyond `net_allow`. Destinations here
    /// but not yet allowed are held for the callback instead of refused.
    pub fn approvable(mut self, permissions: Permissions) -> Self {
        self.approvable = permissions;
        self
    }
}

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

/// What the supervisor pushes to the policy thread.
pub enum PolicyMsg {
    Event(PolicyEvent),
    Shutdown,
}

pub(crate) async fn wait_for_verdict(
    gate: tokio::sync::oneshot::Receiver<Verdict>,
    timeout: Option<Duration>,
    cancellation: &CancellationToken,
) -> Verdict {
    if timeout == Some(Duration::ZERO) {
        return Verdict::Deny;
    }
    let deadline = async {
        match timeout {
            Some(duration) => tokio::time::sleep(duration).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Verdict::Deny,
        _ = deadline => Verdict::Deny,
        verdict = gate => verdict.unwrap_or(Verdict::Deny),
    }
}

/// Cancels pending approvals and joins the callback thread on drop.
pub(crate) struct PolicyFnWorker {
    cancellation: CancellationToken,
    tx: tokio::sync::mpsc::UnboundedSender<PolicyMsg>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PolicyFnWorker {
    pub(crate) fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(crate) fn sender(&self) -> tokio::sync::mpsc::UnboundedSender<PolicyMsg> {
        self.tx.clone()
    }
}

impl Drop for PolicyFnWorker {
    fn drop(&mut self) {
        self.cancel();
        let _ = self.tx.send(PolicyMsg::Shutdown);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Spawn a thread that receives syscall events and calls the policy callback.
pub(crate) fn spawn_policy_fn(
    callback: PolicyCallback,
    live: Arc<RwLock<LivePolicy>>,
    ceiling: LivePolicy,
    pid_overrides: Arc<RwLock<HashMap<u32, NetRuleSet>>>,
    denied: Arc<crate::seccomp::state::DeniedSet>,
    events: CategorySet,
) -> PolicyFnWorker {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PolicyMsg>();

    let cancellation = CancellationToken::new();
    let worker_cancellation = cancellation.clone();
    let thread = std::thread::Builder::new()
        .name("sandlock-policy-fn".to_string())
        .spawn(move || {
            let mut ctx = PolicyContext::new(live, ceiling, pid_overrides, denied);
            ctx.cancellation = worker_cancellation;
            ctx.events = events;

            while let Some(PolicyMsg::Event(pe)) = rx.blocking_recv() {
                if ctx.is_cancelled() {
                    break;
                }
                if pe.gate.as_ref().is_some_and(|gate| gate.is_closed()) {
                    continue;
                }
                let approval = pe.gate.map(|gate| Approval {
                    gate,
                    cancellation: ctx.cancellation.clone(),
                    live: Some(ctx.live.clone()),
                });
                callback(pe.event, &mut ctx, approval);
            }
        })
        .expect("failed to spawn policy-fn thread");

    PolicyFnWorker {
        cancellation,
        tx,
        thread: Some(thread),
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_event() -> SyscallEvent {
        SyscallEvent {
            syscall: "openat".into(),
            category: SyscallCategory::Filesystem,
            pid: 1,
            parent_pid: None,
            host: None,
            port: None,
            size: None,
            argv: None,
            denied: false,
            path: None,
            path2: None,
            fd: None,
            flags: None,
            protocol: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn verdict_timeout_denies_and_closes_gate() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cancellation = CancellationToken::new();
        let start = tokio::time::Instant::now();
        assert_eq!(
            wait_for_verdict(rx, Some(std::time::Duration::from_secs(30)), &cancellation).await,
            Verdict::Deny
        );
        assert_eq!(start.elapsed(), std::time::Duration::from_secs(30));
        assert!(tx.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn unlimited_approval_accepts_late_verdict() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cancellation = CancellationToken::new();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            tx.send(Verdict::DenyWith(13)).unwrap();
        });
        assert_eq!(
            wait_for_verdict(rx, None, &cancellation).await,
            Verdict::DenyWith(13)
        );
    }

    #[tokio::test]
    async fn shutdown_cancels_pending_approval() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        let waiter = tokio::spawn(async move { wait_for_verdict(rx, None, &signal).await });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap(),
            Verdict::Deny
        );
        assert!(tx.is_closed());
    }

    #[tokio::test]
    async fn shutdown_wins_over_ready_approval() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tx.send(Verdict::Allow).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            wait_for_verdict(rx, None, &cancellation).await,
            Verdict::Deny
        );
    }

    #[tokio::test]
    async fn zero_verdict_timeout_denies_ready_verdict() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tx.send(Verdict::Allow).unwrap();
        assert_eq!(
            wait_for_verdict(rx, Some(Duration::ZERO), &CancellationToken::new()).await,
            Verdict::Deny
        );
    }

    #[tokio::test]
    async fn closed_approval_channel_denies() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        drop(tx);
        assert_eq!(
            wait_for_verdict(rx, None, &CancellationToken::new()).await,
            Verdict::Deny
        );
    }

    #[test]
    fn worker_skips_expired_queued_approval() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = std::sync::Mutex::new(release_rx);
        let callback = PolicyFn::new(move |_e, _ctx| {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                started_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
            }
            Verdict::Allow
        })
        .callback;
        let worker = spawn_policy_fn(
            callback,
            Arc::new(RwLock::new(test_live())),
            test_live(),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(crate::seccomp::state::DeniedSet::default()),
            CategorySet::ALL,
        );
        let tx = worker.sender();
        tx.send(PolicyMsg::Event(PolicyEvent {
            event: test_event(),
            gate: None,
        }))
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let (expired_tx, expired_rx) = tokio::sync::oneshot::channel();
        tx.send(PolicyMsg::Event(PolicyEvent {
            event: test_event(),
            gate: Some(expired_tx),
        }))
        .unwrap();
        drop(expired_rx);
        let (last_tx, last_rx) = tokio::sync::oneshot::channel();
        tx.send(PolicyMsg::Event(PolicyEvent {
            event: test_event(),
            gate: Some(last_tx),
        }))
        .unwrap();
        release_tx.send(()).unwrap();
        assert_eq!(last_rx.blocking_recv(), Ok(Verdict::Allow));
        drop(worker);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn worker_shutdown_cancels_callback_and_discards_queue() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let callback = PolicyFn::new(move |_e, ctx| {
            seen.fetch_add(1, Ordering::SeqCst);
            started_tx.send(()).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !ctx.is_cancelled() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert!(
                ctx.is_cancelled(),
                "shutdown did not cancel the running callback"
            );
            Verdict::Allow
        })
        .callback;
        let worker = spawn_policy_fn(
            callback,
            Arc::new(RwLock::new(test_live())),
            test_live(),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(crate::seccomp::state::DeniedSet::default()),
            CategorySet::ALL,
        );
        let tx = worker.sender();
        let (gate_tx, mut gate_rx) = tokio::sync::oneshot::channel();
        tx.send(PolicyMsg::Event(PolicyEvent {
            event: test_event(),
            gate: Some(gate_tx),
        }))
        .unwrap();
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let (queued_tx, mut queued_rx) = tokio::sync::oneshot::channel();
        tx.send(PolicyMsg::Event(PolicyEvent {
            event: test_event(),
            gate: Some(queued_tx),
        }))
        .unwrap();
        drop(worker);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(gate_rx.try_recv(), Ok(Verdict::Deny));
        assert_eq!(
            queued_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        );
    }

    #[tokio::test]
    async fn dropped_approval_denies() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        drop(Approval {
            gate: tx,
            cancellation: CancellationToken::new(),
            live: None,
        });
        assert_eq!(
            wait_for_verdict(rx, None, &CancellationToken::new()).await,
            Verdict::Deny
        );
    }

    #[test]
    fn approval_reports_timeout_and_shutdown() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Verdict>();
        let cancellation = CancellationToken::new();
        let approval = Approval {
            gate: tx,
            cancellation: cancellation.clone(),
            live: None,
        };
        assert!(!approval.is_cancelled());
        cancellation.cancel();
        assert!(approval.is_cancelled());

        let (tx, rx2) = tokio::sync::oneshot::channel::<Verdict>();
        let approval = Approval {
            gate: tx,
            cancellation: CancellationToken::new(),
            live: None,
        };
        drop(rx2);
        assert!(approval.is_cancelled());
        drop(rx);
    }

    #[test]
    fn worker_delivers_next_event_while_approval_pending() {
        let (approvals_tx, approvals_rx) = std::sync::mpsc::channel();
        let approvals_tx = std::sync::Mutex::new(approvals_tx);
        let callback = PolicyFn::deferred(move |_e, _ctx, approval| {
            approvals_tx
                .lock()
                .unwrap()
                .send(approval.unwrap())
                .unwrap();
        })
        .callback;
        let worker = spawn_policy_fn(
            callback,
            Arc::new(RwLock::new(test_live())),
            test_live(),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(crate::seccomp::state::DeniedSet::default()),
            CategorySet::ALL,
        );
        let (first_tx, first_rx) = tokio::sync::oneshot::channel();
        let (second_tx, second_rx) = tokio::sync::oneshot::channel();
        for gate in [first_tx, second_tx] {
            worker
                .sender()
                .send(PolicyMsg::Event(PolicyEvent {
                    event: test_event(),
                    gate: Some(gate),
                }))
                .unwrap();
        }
        let first = approvals_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let second = approvals_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        std::thread::spawn(move || second.resolve(Verdict::DenyWith(13)))
            .join()
            .unwrap();
        first.allow();
        assert_eq!(second_rx.blocking_recv(), Ok(Verdict::DenyWith(13)));
        assert_eq!(first_rx.blocking_recv(), Ok(Verdict::Allow));
    }

    fn rules(specs: &[&str]) -> NetRuleSet {
        NetRuleSet::parse_literal(specs).unwrap()
    }

    fn test_live() -> LivePolicy {
        LivePolicy {
            net_allow: rules(&["127.0.0.1:*", "10.0.0.1:*"]),
            net_approvable: rules(&["*:*"]),
            max_memory_bytes: 1024 * 1024 * 1024,
            max_processes: 64,
        }
    }

    fn test_ctx(live: &Arc<RwLock<LivePolicy>>) -> PolicyContext {
        PolicyContext::new(
            live.clone(),
            test_live(),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(crate::seccomp::state::DeniedSet::default()),
        )
    }

    #[test]
    fn restrict_narrows_live_and_approvable() {
        let live = Arc::new(RwLock::new(test_live()));
        let mut ctx = test_ctx(&live);
        ctx.restrict(&Permissions::new().net_allow("127.0.0.1:443"))
            .unwrap();
        let live = live.read().unwrap();
        assert_eq!(live.net_allow, rules(&["127.0.0.1:443"]));
        assert_eq!(live.net_approvable, rules(&["127.0.0.1:443"]));
    }

    #[test]
    fn restrict_to_none_denies_everything() {
        let live = Arc::new(RwLock::new(test_live()));
        let mut ctx = test_ctx(&live);
        ctx.restrict(&Permissions::new().net_allow_none()).unwrap();
        assert!(live.read().unwrap().net_allow.is_empty());
        assert!(live.read().unwrap().net_approvable.is_empty());
    }

    #[test]
    fn restrict_rejects_hostname() {
        let live = Arc::new(RwLock::new(test_live()));
        let mut ctx = test_ctx(&live);
        assert!(matches!(
            ctx.restrict(&Permissions::new().net_allow("example.com:443")),
            Err(PolicyFnError::Invalid(_))
        ));
        assert_eq!(live.read().unwrap().net_allow, test_live().net_allow);
    }

    #[test]
    fn restrict_rejects_empty() {
        let live = Arc::new(RwLock::new(test_live()));
        let mut ctx = test_ctx(&live);
        assert!(matches!(
            ctx.restrict(&Permissions::new()),
            Err(PolicyFnError::Invalid(_))
        ));
    }

    #[test]
    fn test_restrict_max_memory() {
        let live = Arc::new(RwLock::new(test_live()));
        let mut ctx = test_ctx(&live);
        ctx.restrict_max_memory(256 * 1024 * 1024);
        assert_eq!(live.read().unwrap().max_memory_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn restrict_pid_records_override() {
        let live = Arc::new(RwLock::new(test_live()));
        let pid_overrides = Arc::new(RwLock::new(HashMap::new()));
        let ctx = PolicyContext::new(
            live,
            test_live(),
            pid_overrides.clone(),
            Arc::new(crate::seccomp::state::DeniedSet::default()),
        );
        ctx.restrict_pid(1234, &Permissions::new().net_allow("127.0.0.1:*"))
            .unwrap();
        assert_eq!(
            pid_overrides.read().unwrap().get(&1234),
            Some(&rules(&["127.0.0.1:*"]))
        );
        ctx.clear_pid_override(1234);
        assert!(!pid_overrides.read().unwrap().contains_key(&1234));
    }

    #[test]
    fn test_category_set() {
        let net = CategorySet::of(&[SyscallCategory::Network]);
        assert!(net.contains(SyscallCategory::Network));
        assert!(!net.contains(SyscallCategory::Filesystem));
        assert!(!net.contains(SyscallCategory::Process));
        assert!(!CategorySet::NONE.contains(SyscallCategory::Filesystem));
        assert_eq!(
            CategorySet::of(&[
                SyscallCategory::Filesystem,
                SyscallCategory::Network,
                SyscallCategory::Process,
            ]),
            CategorySet::ALL
        );
    }

    #[test]
    fn test_deny_path_requires_file_events() {
        let denied = Arc::new(crate::seccomp::state::DeniedSet::default());
        let mut ctx = PolicyContext::new(
            Arc::new(RwLock::new(test_live())),
            test_live(),
            Arc::new(RwLock::new(HashMap::new())),
            denied.clone(),
        );
        ctx.events = CategorySet::of(&[SyscallCategory::Network]);
        assert!(matches!(
            ctx.deny_path("/etc/hostname"),
            Err(PolicyFnError::NotSubscribed(SyscallCategory::Filesystem))
        ));
        assert!(!denied.is_path_denied("/etc/hostname"));

        ctx.events = CategorySet::ALL;
        ctx.deny_path("/etc/hostname").unwrap();
        assert!(denied.is_path_denied("/etc/hostname"));
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
            path: None,
            path2: None,
            flags: None,
            protocol: None,
            fd: None,
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
            category: SyscallCategory::Filesystem,
            pid: 1,
            parent_pid: None,
            host: None,
            port: None,
            size: None,
            argv: None,
            denied: false,
            path: None,
            path2: None,
            flags: None,
            protocol: None,
            fd: None,
        };
        assert!(!event.argv_contains("anything"));
    }
}
