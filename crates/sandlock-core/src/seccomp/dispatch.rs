// Table-driven syscall dispatch — routes seccomp notifications to handler chains.
//
// Each syscall number maps to an ordered chain of handlers.  The chain is walked
// until a handler returns a non-Continue action (or the chain is exhausted, in
// which case Continue is returned).
//
// Continue safety (issue #27):
//   - The chain walker treats Continue as "this handler did not intervene,
//     try the next one." A final Continue (no handler intervened, or chain
//     exhausted) means the syscall passes through to the kernel as-issued.
//     The kernel still enforces Landlock and the BPF filter on the
//     untouched syscall, so dispatch-level Continue is not a security
//     decision — it's the absence of one.
//   - The conditional shim closures (random/hostname/etc_hosts opens) that
//     wrap an Option-returning helper translate `None` into Continue,
//     which is the same "not my path, next handler" semantics. None of
//     them approve a syscall based on user-memory contents.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::Arc;

use super::ctx::SupervisorCtx;
use super::notif::{NotifAction, NotifPolicy};
use super::state::ResourceState;
use super::syscall::SyscallError;
use crate::arch;
use crate::sys::structs::SeccompNotif;

use thiserror::Error;
use tokio::sync::Mutex;

// ============================================================
// Types
// ============================================================

// ============================================================
// Handler trait — the new public extension API.
// ============================================================

/// Public extension trait for sandlock seccomp-notif handlers.
///
/// Each implementor is registered against a [`crate::seccomp::syscall::Syscall`]
/// through [`crate::Sandbox::run_with_extra_handlers`] /
/// [`crate::Sandbox::run_interactive_with_extra_handlers`].  Receives
/// `&HandlerCtx` borrowed for the call; cannot outlive the dispatch
/// invocation.
///
/// State lives on the implementor — no `Arc::clone` ladders, no
/// closure ceremony at registration time.
///
/// `handle` returns a boxed `Future` so the trait stays dyn-compatible
/// (the supervisor stores user handlers as `Vec<Arc<dyn Handler>>`,
/// keyed by syscall number).  Returning `impl Future` directly via
/// RPITIT would be more efficient but is not object-safe, and changing
/// the storage to a non-erased shape would force a generic dispatch
/// chain incompatible with arbitrary user handler types.
pub trait Handler: Send + Sync + 'static {
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NotifAction> + Send + 'a>>;
}

/// Context passed to `Handler::handle`.
///
/// `notif` is the kernel notification (owned by value — it's a small
/// `repr(C)` struct, cheap to copy).  `notif_fd` is the supervisor's
/// seccomp listener fd, used by helpers like `read_child_mem` /
/// `write_child_mem` / `read_child_cstr` for TOCTOU-safe child memory
/// access.
///
/// Handler state lives on the implementor (`&self`).  Supervisor-internal
/// state is intentionally not exposed here so the `SupervisorCtx`
/// internal fields are not part of the downstream extension contract.
pub struct HandlerCtx {
    pub notif: SeccompNotif,
    pub notif_fd: RawFd,
}

// Blanket impl: any Fn(&HandlerCtx) -> Future is a Handler.
//
// Lets lightweight closure-style handlers work without ceremony at the
// call site.  Handlers that need state should use `struct + explicit
// impl Handler` instead.
impl<F, Fut> Handler for F
where
    F: Fn(&HandlerCtx) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = NotifAction> + Send + 'static,
{
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NotifAction> + Send + 'a>> {
        Box::pin((self)(cx))
    }
}

// Concrete impls for `Box<dyn Handler>` and `Arc<dyn Handler>` so callers
// can erase concrete handler types behind a smart pointer when mixing
// different handler shapes in one `IntoIterator` passed to
// `run_with_extra_handlers` — e.g. `Vec<(i64, Box<dyn Handler>)>` lets a
// downstream register handlers of different concrete types without
// writing a per-crate wrapper enum.
//
// These are concrete `Box<dyn Handler>` / `Arc<dyn Handler>` rather than
// `<H: Handler + ?Sized>` blankets to avoid coherence overlap with the
// `impl<F, Fut> Handler for F where F: Fn(&HandlerCtx) -> Fut` blanket
// above.
impl Handler for Box<dyn Handler> {
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NotifAction> + Send + 'a>> {
        (**self).handle(cx)
    }
}

impl Handler for std::sync::Arc<dyn Handler> {
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NotifAction> + Send + 'a>> {
        (**self).handle(cx)
    }
}

/// Errors raised when registering user handlers via
/// [`crate::Sandbox::run_with_extra_handlers`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandlerError {
    #[error("invalid syscall in handler registration: {0}")]
    InvalidSyscall(#[from] SyscallError),

    #[error(
        "handler on syscall {syscall_nr} conflicts with the deny list \
         (DEFAULT_DENY_SYSCALLS or policy.deny_syscalls) and would let \
         user code bypass it via SECCOMP_USER_NOTIF_FLAG_CONTINUE"
    )]
    OnDenySyscall { syscall_nr: i64 },
}

/// Reject handler registrations that would weaken sandlock's confinement
/// guarantees.
///
/// The cBPF program emits notif JEQs *before* deny JEQs, so a syscall
/// present in both lists hits `SECCOMP_RET_USER_NOTIF` first.  A handler
/// registered on a syscall that is on the deny list would therefore
/// convert a kernel-deny into a user-supervised path: a handler returning
/// `NotifAction::Continue` becomes `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and
/// the kernel actually runs the syscall — silently bypassing deny.
///
/// The deny list is whatever [`crate::context::deny_syscall_numbers`]
/// resolves from the policy's explicit [`crate::policy::SyscallPolicy`].
///
/// **No syscall policy** (`SyscallPolicy::None`): the resolved deny list is
/// empty, so this function returns `Ok(())` for any syscall. There is no BPF
/// deny block in this mode, so there is no notif/deny overlap to bypass.
///
/// Takes only the syscall numbers because that's all it needs to check.
/// Called from the `run_with_extra_handlers` entry points before any
/// handler is registered against the dispatch table.
///
/// Returns the offending syscall number on rejection so the caller can
/// surface it to the end user.
pub(crate) fn validate_handler_syscalls_against_policy(
    syscall_nrs: &[i64],
    policy: &crate::policy::Policy,
) -> Result<(), i64> {
    let deny: std::collections::HashSet<u32> =
        crate::context::deny_syscall_numbers(policy).into_iter().collect();
    for &nr in syscall_nrs {
        if deny.contains(&(nr as u32)) {
            return Err(nr);
        }
    }
    Ok(())
}


/// Ordered chain of handlers for a single syscall number.
struct HandlerChain {
    handlers: Vec<std::sync::Arc<dyn Handler>>,
}

/// Maps syscall numbers to handler chains.
pub struct DispatchTable {
    chains: HashMap<i64, HandlerChain>,
}

impl DispatchTable {
    /// Create an empty dispatch table.
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
        }
    }

    /// Register a handler for the given syscall number.  Handlers are
    /// called in registration order; the first non-Continue result wins.
    ///
    /// Generic over `H: Handler` — accepts either a struct with explicit
    /// `impl Handler for ...` or a closure (via blanket impl).
    pub fn register<H: Handler>(&mut self, syscall_nr: i64, handler: H) {
        self.register_arc(syscall_nr, std::sync::Arc::new(handler));
    }

    /// Register a pre-`Arc`'d handler.  Used both by builtin chunks
    /// that share state via `Arc::clone` (one `ForkHandler` instance
    /// registers against `SYS_clone`/`SYS_clone3`/`SYS_vfork`) and by
    /// `run_with_extra_handlers` when each item already arrives as
    /// `Arc<dyn Handler>`.
    pub(crate) fn register_arc(
        &mut self,
        syscall_nr: i64,
        handler: std::sync::Arc<dyn Handler>,
    ) {
        self.chains
            .entry(syscall_nr)
            .or_insert_with(|| HandlerChain { handlers: Vec::new() })
            .handlers
            .push(handler);
    }

    /// Dispatch a notification through the handler chain for its syscall number.
    pub(crate) async fn dispatch(
        &self,
        notif: SeccompNotif,
        notif_fd: RawFd,
    ) -> NotifAction {
        let nr = notif.data.nr as i64;
        if let Some(chain) = self.chains.get(&nr) {
            let handler_ctx = HandlerCtx { notif, notif_fd };
            for handler in &chain.handlers {
                let action = handler.handle(&handler_ctx).await;
                if !matches!(action, NotifAction::Continue) {
                    return action;
                }
            }
        }
        NotifAction::Continue
    }
}

// ============================================================
// Table builder — mechanical translation of old dispatch()
// ============================================================

/// Build the dispatch table from a `NotifPolicy`.  Every branch from the old
/// monolithic `dispatch()` function is translated into a `table.register()` call.
/// Priority is preserved by registration order.
///
/// `pending_handlers` are appended **after** all builtin handlers, so they
/// observe the post-builtin view (e.g. `chroot`-normalized paths on
/// `openat`).  Builtins cannot be overridden or removed — this is the
/// security boundary for downstream crates.
pub(crate) fn build_dispatch_table(
    policy: &Arc<NotifPolicy>,
    resource: &Arc<Mutex<ResourceState>>,
    ctx: &Arc<SupervisorCtx>,
    pending_handlers: Vec<(i64, std::sync::Arc<dyn Handler>)>,
) -> DispatchTable {
    let mut table = DispatchTable::new();

    // ------------------------------------------------------------------
    // Fork/clone family (always on)
    // ------------------------------------------------------------------
    for &nr in arch::FORK_LIKE_SYSCALLS {
        let policy_for_fork = Arc::clone(policy);
        let resource_for_fork = Arc::clone(resource);
        table.register(nr, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let notif_fd = cx.notif_fd;
            let policy = Arc::clone(&policy_for_fork);
            let resource = Arc::clone(&resource_for_fork);
            async move {
                crate::resource::handle_fork(&notif, notif_fd, &resource, &policy).await
            }
        });
    }

    // ------------------------------------------------------------------
    // Wait family (always on)
    // ------------------------------------------------------------------
    for &nr in &[libc::SYS_wait4, libc::SYS_waitid] {
        let resource_for_wait = Arc::clone(resource);
        table.register(nr, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let resource = Arc::clone(&resource_for_wait);
            async move {
                crate::resource::handle_wait(&notif, &resource).await
            }
        });
    }

    // ------------------------------------------------------------------
    // Memory management (conditional on has_memory_limit)
    // ------------------------------------------------------------------
    if policy.has_memory_limit {
        for &nr in &[
            libc::SYS_mmap, libc::SYS_munmap, libc::SYS_brk,
            libc::SYS_mremap, libc::SYS_shmget,
        ] {
            let policy_for_mem = Arc::clone(policy);
            let __sup = Arc::clone(ctx);
            table.register(nr, move |cx: &HandlerCtx| {
                let notif = cx.notif;
                let sup = Arc::clone(&__sup);
                let policy = Arc::clone(&policy_for_mem);
                async move {
                    crate::resource::handle_memory(&notif, &sup, &policy).await
                }
            });
        }
    }

    // ------------------------------------------------------------------
    // Network (conditional on has_net_allowlist || has_http_acl)
    // ------------------------------------------------------------------
    if policy.has_net_allowlist || policy.has_http_acl {
        for &nr in &[libc::SYS_connect, libc::SYS_sendto, libc::SYS_sendmsg] {
            let __sup = Arc::clone(ctx);
            table.register(nr, move |cx: &HandlerCtx| {
                let notif = cx.notif;
                let sup = Arc::clone(&__sup);
                let notif_fd = cx.notif_fd;
                async move {
                    crate::network::handle_net(&notif, &sup, notif_fd).await
                }
            });
        }
    }

    // ------------------------------------------------------------------
    // Deterministic random — getrandom()
    // ------------------------------------------------------------------
    if policy.has_random_seed {
        let __sup = Arc::clone(ctx);
        table.register(libc::SYS_getrandom, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            let notif_fd = cx.notif_fd;
            async move {
                let mut tr = sup.time_random.lock().await;
                if let Some(ref mut rng) = tr.random_state {
                    crate::random::handle_getrandom(&notif, rng, notif_fd)
                } else {
                    NotifAction::Continue
                }
            }
        });
    }

    // ------------------------------------------------------------------
    // Deterministic random — /dev/urandom opens (openat)
    // ------------------------------------------------------------------
    if policy.has_random_seed {
        let __sup = Arc::clone(ctx);
        table.register(libc::SYS_openat, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            let notif_fd = cx.notif_fd;
            async move {
                let mut tr = sup.time_random.lock().await;
                if let Some(ref mut rng) = tr.random_state {
                    if let Some(action) = crate::random::handle_random_open(&notif, rng, notif_fd) {
                        return action;
                    }
                }
                NotifAction::Continue
            }
        });
    }

    // ------------------------------------------------------------------
    // Timer adjustment (conditional on has_time_start)
    // ------------------------------------------------------------------
    if policy.has_time_start {
        let time_offset = policy.time_offset;
        for &nr in &[
            libc::SYS_clock_nanosleep as i64,
            libc::SYS_timerfd_settime as i64,
            libc::SYS_timer_settime as i64,
        ] {
            table.register(nr, move |cx: &HandlerCtx| {
                let notif = cx.notif;
                let notif_fd = cx.notif_fd;
                async move {
                    crate::time::handle_timer(&notif, time_offset, notif_fd)
                }
            });
        }
    }

    // ------------------------------------------------------------------
    // Chroot path interception (before COW)
    // ------------------------------------------------------------------
    if policy.chroot_root.is_some() {
        register_chroot_handlers(&mut table, policy, ctx);
    }

    // ------------------------------------------------------------------
    // COW filesystem interception
    // ------------------------------------------------------------------
    if policy.cow_enabled {
        register_cow_handlers(&mut table, ctx);
    }

    // ------------------------------------------------------------------
    // /proc virtualization (always on)
    // ------------------------------------------------------------------
    {
        let policy_for_proc_open = Arc::clone(policy);
        let resource_for_proc_open = Arc::clone(resource);
        let __sup = Arc::clone(ctx);
        table.register(libc::SYS_openat, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            let notif_fd = cx.notif_fd;
            let policy = Arc::clone(&policy_for_proc_open);
            let resource = Arc::clone(&resource_for_proc_open);
            async move {
                let processes = Arc::clone(&sup.processes);
                let network = Arc::clone(&sup.network);
                crate::procfs::handle_proc_open(&notif, &processes, &resource, &network, &policy, notif_fd).await
            }
        });
    }
    let mut getdents_nrs = vec![libc::SYS_getdents64];
    if let Some(getdents) = arch::SYS_GETDENTS {
        getdents_nrs.push(getdents);
    }
    for nr in getdents_nrs {
        let policy_for_getdents = Arc::clone(policy);
        let __sup = Arc::clone(ctx);
        table.register(nr, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            let notif_fd = cx.notif_fd;
            let policy = Arc::clone(&policy_for_getdents);
            async move {
                let processes = Arc::clone(&sup.processes);
                crate::procfs::handle_getdents(&notif, &processes, &policy, notif_fd).await
            }
        });
    }

    // ------------------------------------------------------------------
    // Virtual CPU count
    // ------------------------------------------------------------------
    if let Some(n) = policy.num_cpus {
        table.register(libc::SYS_sched_getaffinity, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let notif_fd = cx.notif_fd;
            async move {
                crate::procfs::handle_sched_getaffinity(&notif, n, notif_fd)
            }
        });
    }

    // ------------------------------------------------------------------
    // Hostname virtualization
    // ------------------------------------------------------------------
    if let Some(ref hostname) = policy.virtual_hostname {
        let hostname_for_uname = hostname.clone();
        let hostname_for_open = hostname.clone();
        table.register(libc::SYS_uname, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let notif_fd = cx.notif_fd;
            let hostname = hostname_for_uname.clone();
            async move {
                crate::procfs::handle_uname(&notif, &hostname, notif_fd)
            }
        });
        table.register(libc::SYS_openat, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let notif_fd = cx.notif_fd;
            let hostname = hostname_for_open.clone();
            async move {
                if let Some(action) = crate::procfs::handle_hostname_open(&notif, &hostname, notif_fd) {
                    action
                } else {
                    NotifAction::Continue
                }
            }
        });
    }

    // ------------------------------------------------------------------
    // /etc/hosts virtualization (for net_allow_hosts)
    // ------------------------------------------------------------------
    if let Some(ref etc_hosts) = policy.virtual_etc_hosts {
        let etc_hosts_for_open = etc_hosts.clone();
        table.register(libc::SYS_openat, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let notif_fd = cx.notif_fd;
            let etc_hosts = etc_hosts_for_open.clone();
            async move {
                if let Some(action) = crate::procfs::handle_etc_hosts_open(&notif, &etc_hosts, notif_fd) {
                    action
                } else {
                    NotifAction::Continue
                }
            }
        });
    }

    // ------------------------------------------------------------------
    // Deterministic directory listing
    // ------------------------------------------------------------------
    if policy.deterministic_dirs {
        let mut getdents_nrs = vec![libc::SYS_getdents64];
        if let Some(getdents) = arch::SYS_GETDENTS {
            getdents_nrs.push(getdents);
        }
        for nr in getdents_nrs {
            let __sup = Arc::clone(ctx);
            table.register(nr, move |cx: &HandlerCtx| {
                let notif = cx.notif;
                let sup = Arc::clone(&__sup);
                let notif_fd = cx.notif_fd;
                async move {
                    let processes = Arc::clone(&sup.processes);
                    crate::procfs::handle_sorted_getdents(&notif, &processes, notif_fd).await
                }
            });
        }
    }

    // ------------------------------------------------------------------
    // NETLINK_ROUTE virtualization (always on).
    //
    // Send/recv traffic flows through a `socketpair(AF_UNIX,
    // SOCK_SEQPACKET)` whose supervisor-side end is driven by a tokio
    // task spawned in `handle_socket`.  Only `socket`, `bind`,
    // `getsockname`, `recvmsg`/`recvfrom`, and `close` need supervisor
    // intercepts; send uses the kernel directly.
    //
    // Must register before `port_remap` so the netlink `bind` handler
    // runs first and returns `Continue` for non-cookie fds.
    // ------------------------------------------------------------------
    {
        let __sup = Arc::clone(ctx);
        table.register(libc::SYS_socket, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            async move {
                let state = Arc::clone(&sup.netlink);
                crate::netlink::handlers::handle_socket(&notif, &state).await
            }
        });
        let __sup = Arc::clone(ctx);
        table.register(libc::SYS_bind, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            async move {
                let state = Arc::clone(&sup.netlink);
                crate::netlink::handlers::handle_bind(&notif, &state).await
            }
        });
        let __sup = Arc::clone(ctx);
        table.register(libc::SYS_getsockname, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            let notif_fd = cx.notif_fd;
            async move {
                let state = Arc::clone(&sup.netlink);
                crate::netlink::handlers::handle_getsockname(&notif, &state, notif_fd).await
            }
        });
        // Zero the msg_name region on recv so glibc sees nl_pid=0
        // (the kernel only writes sun_family on unix socketpair recvmsg,
        //  leaving the rest of the buffer as stack garbage otherwise).
        for &nr in &[libc::SYS_recvfrom, libc::SYS_recvmsg] {
            let __sup = Arc::clone(ctx);
            table.register(nr, move |cx: &HandlerCtx| {
                let notif = cx.notif;
                let sup = Arc::clone(&__sup);
                let notif_fd = cx.notif_fd;
                async move {
                    let state = Arc::clone(&sup.netlink);
                    crate::netlink::handlers::handle_netlink_recvmsg(&notif, &state, notif_fd).await
                }
            });
        }
        // Unregister on close so the (pid, fd) slot isn't left in the
        // cookie set once the child reuses the fd for something else.
        let __sup = Arc::clone(ctx);
        table.register(libc::SYS_close, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            async move {
                let state = Arc::clone(&sup.netlink);
                crate::netlink::handlers::handle_close(&notif, &state).await
            }
        });
    }

    // ------------------------------------------------------------------
    // Bind — on-behalf
    // ------------------------------------------------------------------
    if policy.port_remap || policy.has_net_allowlist {
        let __sup = Arc::clone(ctx);
        table.register(libc::SYS_bind, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            let notif_fd = cx.notif_fd;
            async move {
                crate::port_remap::handle_bind(&notif, &sup.network, notif_fd).await
            }
        });
    }

    // ------------------------------------------------------------------
    // getsockname — port remap
    // ------------------------------------------------------------------
    if policy.port_remap {
        let __sup = Arc::clone(ctx);
        table.register(libc::SYS_getsockname, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            let notif_fd = cx.notif_fd;
            async move {
                crate::port_remap::handle_getsockname(&notif, &sup.network, notif_fd).await
            }
        });
    }

    // ------------------------------------------------------------------
    // Pending user handlers — appended after builtins so builtin handlers
    // keep their security-critical priority (chroot path normalization,
    // COW writes, resource accounting).
    // ------------------------------------------------------------------
    for (nr, h) in pending_handlers {
        table.register_arc(nr, h);
    }

    table
}

// ============================================================
// Chroot handler registration
// ============================================================

fn register_chroot_handlers(
    table: &mut DispatchTable,
    policy: &Arc<NotifPolicy>,
    ctx: &Arc<SupervisorCtx>,
) {
    use crate::chroot::dispatch::ChrootCtx;

    // Helper macro — produces a closure satisfying Handler via blanket impl.
    // The closure clones `policy` (Arc) before the async block; inside the
    // async block it borrows fields of that cloned Arc to build `ChrootCtx`.
    macro_rules! chroot_handler {
        ($policy:expr, $handler:expr) => {{
            let policy = Arc::clone($policy);
            let chroot_state = Arc::clone(&ctx.chroot);
            let cow_state = Arc::clone(&ctx.cow);
            move |cx: &HandlerCtx| {
                let notif = cx.notif;
                let chroot_state = Arc::clone(&chroot_state);
                let cow_state = Arc::clone(&cow_state);
                let notif_fd = cx.notif_fd;
                let policy = Arc::clone(&policy);
                async move {
                    let chroot_ctx = ChrootCtx {
                        root: policy.chroot_root.as_ref().unwrap(),
                        readable: &policy.chroot_readable,
                        writable: &policy.chroot_writable,
                        denied: &policy.chroot_denied,
                        mounts: &policy.chroot_mounts,
                    };
                    $handler(&notif, &chroot_state, &cow_state, notif_fd, &chroot_ctx).await
                }
            }
        }};
    }

    // Same shape for fall-through variants (semantically identical here;
    // kept separate for symmetry with the old code).
    macro_rules! chroot_handler_fallthrough {
        ($policy:expr, $handler:expr) => {{
            let policy = Arc::clone($policy);
            let chroot_state = Arc::clone(&ctx.chroot);
            let cow_state = Arc::clone(&ctx.cow);
            move |cx: &HandlerCtx| {
                let notif = cx.notif;
                let chroot_state = Arc::clone(&chroot_state);
                let cow_state = Arc::clone(&cow_state);
                let notif_fd = cx.notif_fd;
                let policy = Arc::clone(&policy);
                async move {
                    let chroot_ctx = ChrootCtx {
                        root: policy.chroot_root.as_ref().unwrap(),
                        readable: &policy.chroot_readable,
                        writable: &policy.chroot_writable,
                        denied: &policy.chroot_denied,
                        mounts: &policy.chroot_mounts,
                    };
                    $handler(&notif, &chroot_state, &cow_state, notif_fd, &chroot_ctx).await
                }
            }
        }};
    }

    // openat — fallthrough if Continue
    table.register(libc::SYS_openat, chroot_handler_fallthrough!(policy,
        crate::chroot::dispatch::handle_chroot_open));

    // open (legacy) — fallthrough if Continue
    if let Some(open) = arch::SYS_OPEN {
        table.register(open, chroot_handler_fallthrough!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_open));
    }

    // execve, execveat — unconditional return
    for &nr in &[libc::SYS_execve, libc::SYS_execveat] {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_exec));
    }

    // Modern write syscalls
    for &nr in &[
        libc::SYS_unlinkat, libc::SYS_mkdirat, libc::SYS_renameat2,
        libc::SYS_symlinkat, libc::SYS_linkat, libc::SYS_fchmodat,
        libc::SYS_fchownat, libc::SYS_truncate,
    ] {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_write));
    }

    // Legacy write syscalls
    if let Some(nr) = arch::SYS_UNLINK {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_unlink));
    }
    if let Some(nr) = arch::SYS_RMDIR {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_rmdir));
    }
    if let Some(nr) = arch::SYS_MKDIR {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_mkdir));
    }
    if let Some(nr) = arch::SYS_RENAME {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_rename));
    }
    if let Some(nr) = arch::SYS_SYMLINK {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_symlink));
    }
    if let Some(nr) = arch::SYS_LINK {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_link));
    }
    if let Some(nr) = arch::SYS_CHMOD {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_chmod));
    }

    // chown — non-follow
    if let Some(chown) = arch::SYS_CHOWN {
        let policy_for_chown = Arc::clone(policy);
        let __sup = Arc::clone(ctx);
        table.register(chown, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            let notif_fd = cx.notif_fd;
            let policy = Arc::clone(&policy_for_chown);
            async move {
                let chroot_ctx = ChrootCtx {
                    root: policy.chroot_root.as_ref().unwrap(),
                    readable: &policy.chroot_readable,
                    writable: &policy.chroot_writable,
                    denied: &policy.chroot_denied,
                    mounts: &policy.chroot_mounts,
                };
                crate::chroot::dispatch::handle_chroot_legacy_chown(&notif, &sup.chroot, &sup.cow, notif_fd, &chroot_ctx, false).await
            }
        });
    }

    // lchown — follow
    if let Some(lchown) = arch::SYS_LCHOWN {
        let policy_for_lchown = Arc::clone(policy);
        let __sup = Arc::clone(ctx);
        table.register(lchown, move |cx: &HandlerCtx| {
            let notif = cx.notif;
            let sup = Arc::clone(&__sup);
            let notif_fd = cx.notif_fd;
            let policy = Arc::clone(&policy_for_lchown);
            async move {
                let chroot_ctx = ChrootCtx {
                    root: policy.chroot_root.as_ref().unwrap(),
                    readable: &policy.chroot_readable,
                    writable: &policy.chroot_writable,
                    denied: &policy.chroot_denied,
                    mounts: &policy.chroot_mounts,
                };
                crate::chroot::dispatch::handle_chroot_legacy_chown(&notif, &sup.chroot, &sup.cow, notif_fd, &chroot_ctx, true).await
            }
        });
    }

    // stat family
    for &nr in &[
        libc::SYS_newfstatat,
        libc::SYS_faccessat,
        crate::chroot::dispatch::SYS_FACCESSAT2,
    ] {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_stat));
    }

    // Legacy stat
    if let Some(nr) = arch::SYS_STAT {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_stat));
    }
    if let Some(nr) = arch::SYS_LSTAT {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_lstat));
    }
    if let Some(nr) = arch::SYS_ACCESS {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_access));
    }

    // statx
    table.register(libc::SYS_statx, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_statx));

    // readlink
    table.register(libc::SYS_readlinkat, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_readlink));
    if let Some(nr) = arch::SYS_READLINK {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_legacy_readlink));
    }

    // getdents
    let mut getdents_nrs = vec![libc::SYS_getdents64];
    if let Some(getdents) = arch::SYS_GETDENTS {
        getdents_nrs.push(getdents);
    }
    for nr in getdents_nrs {
        table.register(nr, chroot_handler!(policy,
            crate::chroot::dispatch::handle_chroot_getdents));
    }

    // chdir, getcwd, statfs, utimensat
    table.register(libc::SYS_chdir as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_chdir));
    table.register(libc::SYS_getcwd as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_getcwd));
    table.register(libc::SYS_statfs as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_statfs));
    table.register(libc::SYS_utimensat as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_utimensat));
}

// ============================================================
// COW handler registration
// ============================================================

fn register_cow_handlers(table: &mut DispatchTable, ctx: &Arc<SupervisorCtx>) {
    // Helper that captures `ctx.cow` and `ctx.processes` once at table-build
    // time, then re-clones the per-handler `Arc`s on each invocation.
    macro_rules! cow_call {
        ($handler:expr) => {{
            let cow_state = Arc::clone(&ctx.cow);
            let processes_state = Arc::clone(&ctx.processes);
            move |cx: &HandlerCtx| {
                let notif = cx.notif;
                let cow_state = Arc::clone(&cow_state);
                let processes_state = Arc::clone(&processes_state);
                let notif_fd = cx.notif_fd;
                async move {
                    $handler(&notif, &cow_state, &processes_state, notif_fd).await
                }
            }
        }};
    }

    // Write syscalls (*at variants + legacy)
    let mut write_nrs = vec![
        libc::SYS_unlinkat, libc::SYS_mkdirat, libc::SYS_renameat2,
        libc::SYS_symlinkat, libc::SYS_linkat, libc::SYS_fchmodat,
        libc::SYS_fchownat, libc::SYS_truncate,
    ];
    write_nrs.extend([
        arch::SYS_UNLINK, arch::SYS_RMDIR, arch::SYS_MKDIR, arch::SYS_RENAME,
        arch::SYS_SYMLINK, arch::SYS_LINK, arch::SYS_CHMOD, arch::SYS_CHOWN,
        arch::SYS_LCHOWN,
    ].into_iter().flatten());
    for nr in write_nrs {
        table.register(nr, cow_call!(crate::cow::dispatch::handle_cow_write));
    }

    table.register(libc::SYS_utimensat, cow_call!(crate::cow::dispatch::handle_cow_utimensat));

    let mut access_nrs = vec![libc::SYS_faccessat, crate::cow::dispatch::SYS_FACCESSAT2];
    access_nrs.extend(arch::SYS_ACCESS);
    for nr in access_nrs {
        table.register(nr, cow_call!(crate::cow::dispatch::handle_cow_access));
    }

    let mut open_nrs = vec![libc::SYS_openat];
    open_nrs.extend(arch::SYS_OPEN);
    for nr in open_nrs {
        table.register(nr, cow_call!(crate::cow::dispatch::handle_cow_open));
    }

    let mut stat_nrs = vec![libc::SYS_newfstatat, libc::SYS_faccessat];
    stat_nrs.extend([arch::SYS_STAT, arch::SYS_LSTAT, arch::SYS_ACCESS].into_iter().flatten());
    for nr in stat_nrs {
        table.register(nr, cow_call!(crate::cow::dispatch::handle_cow_stat));
    }

    table.register(libc::SYS_statx, cow_call!(crate::cow::dispatch::handle_cow_statx));

    let mut readlink_nrs = vec![libc::SYS_readlinkat];
    readlink_nrs.extend(arch::SYS_READLINK);
    for nr in readlink_nrs {
        table.register(nr, cow_call!(crate::cow::dispatch::handle_cow_readlink));
    }

    let mut getdents_nrs = vec![libc::SYS_getdents64];
    getdents_nrs.extend(arch::SYS_GETDENTS);
    for nr in getdents_nrs {
        table.register(nr, cow_call!(crate::cow::dispatch::handle_cow_getdents));
    }

    table.register(libc::SYS_chdir, cow_call!(crate::cow::dispatch::handle_cow_chdir));
    table.register(libc::SYS_getcwd, cow_call!(crate::cow::dispatch::handle_cow_getcwd));
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod extra_handler_tests {
    //! Unit tests for the user-supplied handler extension API.
    //!
    //! Drive the actual `DispatchTable::dispatch` walker against a minimal
    //! `SupervisorCtx` constructed from default-state pieces.  Handler
    //! closures here ignore the context (no notif fd, no real child), so
    //! the dispatch invariants under test (registration order, chain
    //! short-circuit on first non-`Continue`, append-after-builtin
    //! placement) are exercised end-to-end without needing a live
    //! Landlock+seccomp sandbox — those scenarios live under
    //! `crates/sandlock-core/tests/integration/test_extra_handlers.rs`.
    use super::*;
    use crate::netlink::NetlinkState;
    use crate::seccomp::ctx::SupervisorCtx;
    use crate::seccomp::notif::NotifPolicy;
    use crate::seccomp::state::{
        ChrootState, CowState, NetworkState, PolicyFnState, ProcessIndex, ProcfsState,
        ResourceState, TimeRandomState,
    };
    use crate::sys::structs::{SeccompData, SeccompNotif};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fake_notif(nr: i32) -> SeccompNotif {
        SeccompNotif {
            id: 0,
            pid: 1,
            flags: 0,
            data: SeccompData {
                nr,
                arch: 0,
                instruction_pointer: 0,
                args: [0; 6],
            },
        }
    }

    /// Minimal `SupervisorCtx` for unit tests.  Every field is built from
    /// the corresponding state's `new()`/default constructor — no syscalls,
    /// no fds, no spawned children.  Handlers in these tests do not
    /// actually inspect the context, so the values do not need to match
    /// any real run; they only need to satisfy the type signature so we
    /// can call `dispatch()`.
    fn fake_supervisor_ctx() -> Arc<SupervisorCtx> {
        Arc::new(SupervisorCtx {
            resource: Arc::new(Mutex::new(ResourceState::new(0, 0))),
            cow: Arc::new(Mutex::new(CowState::new())),
            procfs: Arc::new(Mutex::new(ProcfsState::new())),
            network: Arc::new(Mutex::new(NetworkState::new())),
            time_random: Arc::new(Mutex::new(TimeRandomState::new(None, None))),
            policy_fn: Arc::new(Mutex::new(PolicyFnState::new())),
            chroot: Arc::new(Mutex::new(ChrootState::new())),
            netlink: Arc::new(NetlinkState::new()),
            processes: Arc::new(ProcessIndex::new()),
            policy: Arc::new(NotifPolicy {
                max_memory_bytes: 0,
                max_processes: 0,
                has_memory_limit: false,
                has_net_allowlist: false,
                has_random_seed: false,
                has_time_start: false,
                time_offset: 0,
                num_cpus: None,
                argv_safety_required: false,
                port_remap: false,
                cow_enabled: false,
                chroot_root: None,
                chroot_readable: Vec::new(),
                chroot_writable: Vec::new(),
                chroot_denied: Vec::new(),
                chroot_mounts: Vec::new(),
                deterministic_dirs: false,
                virtual_hostname: None,
                has_http_acl: false,
                virtual_etc_hosts: None,
            }),
            child_pidfd: None,
            notif_fd: -1,
        })
    }

    /// All registered handlers run, in registration order, when each
    /// returns `Continue`.  Verifies that `register` appends to the
    /// underlying `Vec` and that `dispatch` walks it front-to-back.
    #[tokio::test]
    async fn dispatch_walks_chain_in_registration_order() {
        let mut table = DispatchTable::new();
        let order = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));

        for tag in [1u8, 2u8, 3u8] {
            let order_clone = Arc::clone(&order);
            table.register(
                libc::SYS_openat,
                move |_cx: &HandlerCtx| {
                    let order = Arc::clone(&order_clone);
                    async move {
                        order.lock().unwrap().push(tag);
                        NotifAction::Continue
                    }
                },
            );
        }

        let _ctx = fake_supervisor_ctx();
        let action = table
            .dispatch(fake_notif(libc::SYS_openat as i32), -1)
            .await;

        assert!(matches!(action, NotifAction::Continue));
        let recorded = order.lock().unwrap();
        assert_eq!(
            *recorded,
            [1u8, 2u8, 3u8],
            "every handler must run, in the order it was registered"
        );
    }

    /// Append-after-builtin contract: when a user handler is registered
    /// after a builtin, dispatch invokes the builtin first and the
    /// user handler second.  This is the security-load-bearing invariant —
    /// a builtin returning a non-`Continue` `NotifAction` must short-circuit
    /// before the user handler runs (covered by
    /// `dispatch_stops_at_first_non_continue`); when the builtin returns
    /// `Continue`, the user handler observes the post-builtin view.
    #[tokio::test]
    async fn dispatch_runs_builtin_before_extra() {
        let mut table = DispatchTable::new();
        let order = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));

        // Builtin first, tagged 'B'.
        let order_builtin = Arc::clone(&order);
        table.register(
            libc::SYS_openat,
            move |_cx: &HandlerCtx| {
                let order = Arc::clone(&order_builtin);
                async move {
                    order.lock().unwrap().push(b'B');
                    NotifAction::Continue
                }
            },
        );

        // Extra after, tagged 'E'.  Registered after builtin to mirror
        // append-after-builtin placement from `build_dispatch_table`.
        let order_extra = Arc::clone(&order);
        table.register(
            libc::SYS_openat,
            move |_cx: &HandlerCtx| {
                let order = Arc::clone(&order_extra);
                async move {
                    order.lock().unwrap().push(b'E');
                    NotifAction::Continue
                }
            },
        );

        let _ctx = fake_supervisor_ctx();
        let action = table
            .dispatch(fake_notif(libc::SYS_openat as i32), -1)
            .await;

        assert!(matches!(action, NotifAction::Continue));
        let recorded = order.lock().unwrap();
        assert_eq!(
            *recorded,
            [b'B', b'E'],
            "builtin must run before extra (insertion order preserved)"
        );
    }

    /// First non-`Continue` wins: a handler returning `Errno` short-circuits
    /// the chain, and subsequent handlers must not run.  This is the
    /// invariant that prevents a user-supplied extra from being observed
    /// (or, in the inverse direction, prevents an extra's `Errno` from
    /// being silently overridden by a later handler that happens to also
    /// be registered for the same syscall).
    #[tokio::test]
    async fn dispatch_stops_at_first_non_continue() {
        let mut table = DispatchTable::new();
        let calls = Arc::new(AtomicUsize::new(0));

        // First handler — returns Errno, must terminate the chain.
        let calls_first = Arc::clone(&calls);
        table.register(
            libc::SYS_openat,
            move |_cx: &HandlerCtx| {
                let calls = Arc::clone(&calls_first);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    NotifAction::Errno(libc::EACCES)
                }
            },
        );

        // Second handler — must NOT be called.
        let calls_second = Arc::clone(&calls);
        table.register(
            libc::SYS_openat,
            move |_cx: &HandlerCtx| {
                let calls = Arc::clone(&calls_second);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    NotifAction::Continue
                }
            },
        );

        let _ctx = fake_supervisor_ctx();
        let action = table
            .dispatch(fake_notif(libc::SYS_openat as i32), -1)
            .await;

        match action {
            NotifAction::Errno(e) => assert_eq!(e, libc::EACCES),
            other => panic!("expected Errno(EACCES), got {:?}", other),
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second handler must not run after first returned non-Continue"
        );
    }

    /// `validate_handler_syscalls_against_policy` must reject handlers whose
    /// syscall is in the policy's user-specified deny list, with the same
    /// rationale as DEFAULT_DENY: the BPF program emits notif JEQs before
    /// deny JEQs, so a user handler returning `Continue` would translate into
    /// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and silently bypass the kernel-level
    /// deny.
    ///
    /// Uses `mremap` because it is in `syscall_name_to_nr` but not in
    /// `DEFAULT_DENY_SYSCALLS` — putting it into `SyscallPolicy::Deny` is the only
    /// way it ends up on the deny list, so the test isolates the user-supplied
    /// path of `deny_syscall_numbers` from the default branch covered by
    /// `extra_handler_on_default_deny_syscall_is_rejected`.
    ///
    /// Pure-logic counterpart to the integration test of the same name —
    /// runs without a live sandbox so the contract is enforced even on
    /// hosts where seccomp integration tests are skipped.
    #[test]
    fn validate_extras_rejects_user_specified_deny() {
        let policy = crate::policy::Policy::builder()
            .deny_syscalls(vec!["mremap".into()])
            .build()
            .expect("policy builds");

        let result = validate_handler_syscalls_against_policy(&[libc::SYS_mremap], &policy);
        assert_eq!(
            result,
            Err(libc::SYS_mremap),
            "handler on user-specified deny must be rejected, naming the offending syscall"
        );
    }

    // ---- Handler trait tests --------------------------------------

    #[tokio::test]
    async fn handler_via_blanket_impl_dispatches_closures() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = Arc::clone(&counter);

        let h = move |cx: &HandlerCtx| {
            let counter = Arc::clone(&counter_clone);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = cx.notif.pid; // touch ctx so it's exercised
                NotifAction::Continue
            }
        };

        let _sup = fake_supervisor_ctx();
        let notif = fake_notif(libc::SYS_openat as i32);
        let cx = HandlerCtx { notif, notif_fd: -1 };

        let action = h.handle(&cx).await;
        assert!(matches!(action, NotifAction::Continue));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// Struct-based `Handler` registered through `DispatchTable::register`
    /// MUST be invoked when `dispatch()` walks the chain — and `&self`
    /// state MUST persist across notifications.  Bridges the gap between
    /// the trait-shape unit tests above (which call `.handle()` directly)
    /// and the dispatch ordering tests (which use closures via blanket
    /// impl).  Without this test, a regression where the dispatch walker
    /// dropped `Arc<dyn Handler>` calls but kept closures working would
    /// not be caught at the unit layer.
    #[tokio::test]
    async fn dispatch_invokes_struct_handler_with_persistent_self_state() {
        use std::sync::atomic::{AtomicU64, Ordering};

        struct StructHandler {
            calls: AtomicU64,
        }

        impl Handler for StructHandler {
            fn handle<'a>(
                &'a self,
                _cx: &'a HandlerCtx,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NotifAction> + Send + 'a>> {
                Box::pin(async move {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    NotifAction::Continue
                })
            }
        }

        let mut table = DispatchTable::new();
        let handler = std::sync::Arc::new(StructHandler {
            calls: AtomicU64::new(0),
        });
        table.register_arc(libc::SYS_openat, handler.clone() as std::sync::Arc<dyn Handler>);

        let _sup = fake_supervisor_ctx();
        let notif = fake_notif(libc::SYS_openat as i32);

        // Three independent dispatches against the same registered handler.
        // Walker MUST hit the struct's handle() each time, accumulating
        // state on &self.calls.
        for _ in 0..3 {
            let action = table.dispatch(notif, -1).await;
            assert!(matches!(action, NotifAction::Continue));
        }

        assert_eq!(
            handler.calls.load(Ordering::SeqCst),
            3,
            "dispatch must invoke the struct-based handler on every walk"
        );
    }
}
