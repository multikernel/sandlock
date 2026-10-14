//! Dynamic policy — live policy modification via syscall event callbacks.
//!
//! Allows a user-provided callback to inspect syscall events and adjust
//! sandbox permissions at runtime (grant, restrict, per-PID overrides).
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
/// returns `Continue` for an execve, it `PTRACE_SEIZE`+`PTRACE_INTERRUPT`s
/// every task that could write
/// the memory — both sibling threads of the calling tid (same TGID, share
/// `mm_struct`) and peer threads in other TGIDs that may alias argv
/// pages via `MAP_SHARED` mappings or share `mm_struct` via
/// `clone(CLONE_VM)`, then re-reads argv and denies the exec unless it
/// matches what `policy_fn` saw. The kernel's post-Continue re-read
/// therefore sees the argv the callback approved. Siblings are killed
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
    /// Maximum concurrent processes (`u32::MAX` = unlimited).
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
    cancellation: CancellationToken,
    live: Arc<RwLock<LivePolicy>>,
    ceiling: LivePolicy,
    restricted: HashSet<&'static str>,
    pid_overrides: Arc<RwLock<HashMap<u32, HashSet<IpAddr>>>>,
    denied: Arc<crate::seccomp::state::DeniedSet>,
}

impl PolicyContext {
    pub(crate) fn new(
        live: Arc<RwLock<LivePolicy>>,
        ceiling: LivePolicy,
        pid_overrides: Arc<RwLock<HashMap<u32, HashSet<IpAddr>>>>,
        denied: Arc<crate::seccomp::state::DeniedSet>,
    ) -> Self {
        Self {
            cancellation: CancellationToken::new(),
            live,
            ceiling,
            restricted: HashSet::new(),
            pid_overrides,
            denied,
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
    /// on openat/stat/access syscalls. Takes effect immediately. The file's
    /// inode identity is captured too, so the deny survives hardlinks and
    /// renames to a non-denied name.
    pub fn deny_path(&self, path: &str) {
        self.denied.deny(path);
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
/// Called synchronously on a dedicated thread. For held syscalls the child
/// process is blocked until a verdict, the approval timeout, or shutdown.
/// Approval loops must check [`PolicyContext::is_cancelled`] between bounded
/// waits. Shutdown waits for running callbacks to return.
///
/// Return `Verdict::Deny` to block the current syscall. Only effective for
/// held syscalls: exec (execve/execveat), open (open/openat/openat2), and
/// network (connect/bind/sendto/sendmsg/sendmmsg). Filesystem-mutation
/// events (mkdir/unlink/symlink/link/rename/truncate) are observation-only;
/// their verdicts are ignored. Use `fs_deny` to block paths.
///
/// Wrapped in `Arc` so that `Policy` remains `Clone`.
pub type PolicyCallback = Arc<dyn Fn(SyscallEvent, &mut PolicyContext) -> Verdict + Send + Sync + 'static>;

/// An owned decision for a held syscall. Dropping it unanswered denies the syscall.
pub struct Approval {
    gate: Option<tokio::sync::oneshot::Sender<Verdict>>,
    cancellation: CancellationToken,
}

/// The approval was already answered, expired, or cancelled.
#[derive(Debug, thiserror::Error)]
#[error("approval is no longer pending")]
pub struct ApprovalClosed;

impl Approval {
    fn new(gate: tokio::sync::oneshot::Sender<Verdict>, cancellation: CancellationToken) -> Self {
        Self { gate: Some(gate), cancellation }
    }

    /// Resolve once. A late answer cannot revive a cancelled syscall.
    pub fn resolve(&mut self, verdict: Verdict) -> Result<(), ApprovalClosed> {
        let gate = self.gate.take().ok_or(ApprovalClosed)?;
        if self.cancellation.is_cancelled() {
            let _ = gate.send(Verdict::Deny);
            return Err(ApprovalClosed);
        }
        gate.send(verdict).map_err(|_| ApprovalClosed)
    }

    /// Whether no further decision can be accepted.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
            || self.gate.as_ref().map_or(true, |gate| gate.is_closed())
    }
}

type DeferredPolicyCallback = Arc<
    dyn Fn(SyscallEvent, &mut PolicyContext, Option<Approval>) + Send + Sync + 'static,
>;

/// A dynamic policy callback and the settings for its held verdicts.
#[derive(Clone)]
pub struct PolicyFn {
    pub(crate) callback: DeferredPolicyCallback,
    pub(crate) verdict_timeout: Option<Duration>,
}

impl PolicyFn {
    /// Configure a callback with a five-second verdict timeout.
    pub fn new(
        callback: impl Fn(SyscallEvent, &mut PolicyContext) -> Verdict + Send + Sync + 'static,
    ) -> Self {
        Self::deferred(move |event, ctx, approval| {
            let verdict = callback(event, ctx);
            if let Some(mut approval) = approval {
                let _ = approval.resolve(verdict);
            }
        })
    }

    /// Deliver owned approvals that may be answered after the callback returns.
    /// Observation-only events receive `None`. The context is callback-scoped;
    /// only the approval may be retained. Callbacks should return promptly.
    pub fn deferred(
        callback: impl Fn(SyscallEvent, &mut PolicyContext, Option<Approval>) + Send + Sync + 'static,
    ) -> Self {
        Self {
            callback: Arc::new(callback),
            verdict_timeout: Some(Duration::from_secs(5)),
        }
    }

    /// Maximum wait for a held verdict, including queue time. `None` waits
    /// until a decision or shutdown; zero denies immediately. Expiry denies
    /// the syscall without interrupting a callback already running.
    pub fn verdict_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.verdict_timeout = timeout;
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

pub(crate) fn wait_for_verdict(
    gate: tokio::sync::oneshot::Receiver<Verdict>,
    timeout: Option<Duration>,
    cancellation: CancellationToken,
) -> impl std::future::Future<Output = Verdict> + Send {
    let deadline = timeout.map(|duration| tokio::time::Instant::now() + duration);
    async move {
        if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
            return Verdict::Deny;
        }
        let deadline = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
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
    callback: DeferredPolicyCallback,
    live: Arc<RwLock<LivePolicy>>,
    ceiling: LivePolicy,
    pid_overrides: Arc<RwLock<HashMap<u32, HashSet<IpAddr>>>>,
    denied: Arc<crate::seccomp::state::DeniedSet>,
) -> PolicyFnWorker {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PolicyMsg>();

    let cancellation = CancellationToken::new();
    let worker_cancellation = cancellation.clone();
    let thread = std::thread::Builder::new()
        .name("sandlock-policy-fn".to_string())
        .spawn(move || {
            let mut ctx = PolicyContext::new(live, ceiling, pid_overrides, denied);
            ctx.cancellation = worker_cancellation;
            let _cancel_on_exit = ctx.cancellation.clone().drop_guard();

            while let Some(PolicyMsg::Event(pe)) = rx.blocking_recv() {
                if ctx.is_cancelled() {
                    break;
                }
                if pe.gate.as_ref().is_some_and(|gate| gate.is_closed()) {
                    continue;
                }
                let approval = pe.gate.map(|gate| Approval::new(gate, ctx.cancellation.clone()));
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
            category: SyscallCategory::File,
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
            wait_for_verdict(rx, Some(std::time::Duration::from_secs(30)), cancellation.clone()).await,
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
            wait_for_verdict(rx, None, cancellation.clone()).await,
            Verdict::DenyWith(13)
        );
    }

    #[tokio::test]
    async fn shutdown_cancels_pending_approval() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        let waiter = tokio::spawn(async move { wait_for_verdict(rx, None, signal).await });
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
            wait_for_verdict(rx, None, cancellation.clone()).await,
            Verdict::Deny
        );
    }

    #[tokio::test]
    async fn zero_verdict_timeout_denies_ready_verdict() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tx.send(Verdict::Allow).unwrap();
        assert_eq!(
            wait_for_verdict(rx, Some(Duration::ZERO), CancellationToken::new()).await,
            Verdict::Deny
        );
    }

    #[tokio::test]
    async fn closed_approval_channel_denies() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        drop(tx);
        assert_eq!(
            wait_for_verdict(rx, None, CancellationToken::new()).await,
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
        let callback: PolicyCallback = Arc::new(move |_e, _ctx| {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                started_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
            }
            Verdict::Allow
        });
        let worker = spawn_policy_fn(
            PolicyFn::new(move |event, ctx| callback(event, ctx)).callback,
            Arc::new(RwLock::new(test_live())),
            test_live(),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(crate::seccomp::state::DeniedSet::default()),
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
        let callback: PolicyCallback = Arc::new(move |_e, ctx| {
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
        });
        let worker = spawn_policy_fn(
            PolicyFn::new(move |event, ctx| callback(event, ctx)).callback,
            Arc::new(RwLock::new(test_live())),
            test_live(),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(crate::seccomp::state::DeniedSet::default()),
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

    #[tokio::test(start_paused = true)]
    async fn deferred_deadline_starts_before_first_poll() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let wait = wait_for_verdict(rx, Some(Duration::from_secs(1)), CancellationToken::new());
        tokio::time::advance(Duration::from_secs(2)).await;
        tx.send(Verdict::Allow).unwrap();
        assert_eq!(wait.await, Verdict::Deny);
    }

    #[tokio::test]
    async fn deferred_approval_lifecycle() {
        let cancellation = CancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut approval = Approval::new(tx, cancellation.clone());
        approval.resolve(Verdict::Allow).unwrap();
        assert!(approval.resolve(Verdict::Deny).is_err());
        assert_eq!(rx.await.unwrap(), Verdict::Allow);

        let (tx, rx) = tokio::sync::oneshot::channel();
        drop(Approval::new(tx, cancellation.clone()));
        assert_eq!(wait_for_verdict(rx, None, cancellation.clone()).await, Verdict::Deny);

        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut approval = Approval::new(tx, cancellation.clone());
        drop(rx);
        assert!(approval.is_cancelled());
        assert!(approval.resolve(Verdict::Allow).is_err());

        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut approval = Approval::new(tx, cancellation.clone());
        cancellation.cancel();
        assert!(approval.is_cancelled());
        assert!(approval.resolve(Verdict::Allow).is_err());
        assert_eq!(wait_for_verdict(rx, None, cancellation.clone()).await, Verdict::Deny);
    }

    #[test]
    fn deferred_callback_delivers_multiple_outstanding_approvals() {
        let (tx, rx) = std::sync::mpsc::channel();
        let policy = PolicyFn::deferred(move |_, _, approval| {
            tx.send(approval).unwrap();
        });
        let worker = spawn_policy_fn(
            policy.callback,
            Arc::new(RwLock::new(test_live())),
            test_live(),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(crate::seccomp::state::DeniedSet::default()),
        );
        let mut responses = Vec::new();
        for _ in 0..2 {
            let (gate, response) = tokio::sync::oneshot::channel();
            worker.sender().send(PolicyMsg::Event(PolicyEvent {
                event: test_event(), gate: Some(gate),
            })).unwrap();
            responses.push(response);
        }
        let mut first = rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
        let mut second = rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
        second.resolve(Verdict::Allow).unwrap();
        assert_eq!(responses.pop().unwrap().blocking_recv().unwrap(), Verdict::Allow);
        drop(worker);
        assert!(first.is_cancelled());
        assert!(first.resolve(Verdict::Allow).is_err());
    }

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
        let denied = Arc::new(crate::seccomp::state::DeniedSet::default());
        let mut ctx = PolicyContext::new(live.clone(), ceiling, pid_overrides, denied);

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
        let denied = Arc::new(crate::seccomp::state::DeniedSet::default());
        let mut ctx = PolicyContext::new(live.clone(), ceiling, pid_overrides, denied);

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
        let denied = Arc::new(crate::seccomp::state::DeniedSet::default());
        let mut ctx = PolicyContext::new(live, ceiling, pid_overrides, denied);

        ctx.restrict_network(&[]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(ctx.grant_network(&[ip]).is_err());
    }

    #[test]
    fn test_restrict_max_memory() {
        let live = Arc::new(RwLock::new(test_live()));
        let ceiling = test_live();
        let pid_overrides = Arc::new(RwLock::new(HashMap::new()));
        let denied = Arc::new(crate::seccomp::state::DeniedSet::default());
        let mut ctx = PolicyContext::new(live.clone(), ceiling, pid_overrides, denied);

        ctx.restrict_max_memory(256 * 1024 * 1024);
        assert_eq!(live.read().unwrap().max_memory_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn test_pid_override() {
        let live = Arc::new(RwLock::new(test_live()));
        let ceiling = test_live();
        let pid_overrides = Arc::new(RwLock::new(HashMap::new()));
        let denied = Arc::new(crate::seccomp::state::DeniedSet::default());
        let ctx = PolicyContext::new(live, ceiling, pid_overrides.clone(), denied);

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
        let denied = Arc::new(crate::seccomp::state::DeniedSet::default());
        let ctx = PolicyContext::new(live, ceiling, pid_overrides.clone(), denied);

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
            category: SyscallCategory::File,
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
