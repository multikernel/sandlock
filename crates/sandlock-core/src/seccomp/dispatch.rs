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
use std::future::Future;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::sync::Arc;

use super::ctx::SupervisorCtx;
use super::notif::{NotifAction, NotifPolicy};
use super::state::ResourceState;
use crate::arch;
use crate::sys::structs::SeccompNotif;

use tokio::sync::Mutex;

// ============================================================
// Types
// ============================================================

/// An async handler function.  Receives the notification, the supervisor
/// context, and the notif fd.  Returns a `NotifAction`.
pub type HandlerFn = Box<
    dyn Fn(SeccompNotif, Arc<SupervisorCtx>, RawFd) -> Pin<Box<dyn Future<Output = NotifAction> + Send>>
        + Send
        + Sync,
>;

/// A user-supplied handler bound to a specific syscall number.
///
/// Passed to [`crate::Sandbox::run_with_extra_handlers`]; appended to the
/// dispatch table **after** all builtin handlers for the same syscall.
///
/// # Ordering and security boundary
///
/// Within a syscall's chain, handlers run in registration order and the
/// first non-[`NotifAction::Continue`] result wins.  Builtin handlers are
/// registered first (for example `chroot` path-normalization on `openat`),
/// so an `ExtraHandler` observes the post-builtin view of each syscall.
/// This ordering is fixed and cannot be changed by downstream crates —
/// it is the security boundary that prevents user handlers from bypassing
/// sandlock confinement.
///
/// # Example
///
/// ```ignore
/// use sandlock_core::seccomp::dispatch::{ExtraHandler, HandlerFn};
/// use sandlock_core::seccomp::notif::NotifAction;
///
/// let audit: HandlerFn = Box::new(|notif, _ctx, _fd| {
///     Box::pin(async move {
///         eprintln!("openat from pid {}", notif.data.pid);
///         NotifAction::Continue
///     })
/// });
///
/// let extras = vec![ExtraHandler::new(libc::SYS_openat, audit)];
/// ```
pub struct ExtraHandler {
    pub syscall_nr: i64,
    pub handler: HandlerFn,
}

impl ExtraHandler {
    pub fn new(syscall_nr: i64, handler: HandlerFn) -> Self {
        Self { syscall_nr, handler }
    }
}

/// Reject extras that would weaken sandlock's confinement guarantees.
///
/// The cBPF program emits notif JEQs *before* deny JEQs, so a syscall
/// present in both lists hits `SECCOMP_RET_USER_NOTIF` first.  An extra
/// registered on a syscall that is on the deny list would therefore
/// convert a kernel-deny into a user-supervised path: a handler returning
/// `NotifAction::Continue` becomes `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and
/// the kernel actually runs the syscall — silently bypassing deny.
///
/// The deny list is whatever [`crate::context::deny_syscall_numbers`]
/// resolves: `policy.deny_syscalls` if set, otherwise
/// `DEFAULT_DENY_SYSCALLS` when neither `deny_syscalls` nor
/// `allow_syscalls` is set; both branches are guarded by this function.
///
/// **Allowlist mode** (`policy.allow_syscalls = Some(_)`): the resolved
/// deny list is empty, so this function returns `Ok(())` for any extra.
/// That is sound because the BPF deny block is empty in this mode too —
/// confinement comes from the allowlist enforced at the kernel level,
/// and there is no notif/deny overlap for an extra to bypass.
///
/// Returns the offending syscall number on rejection so the caller can
/// surface it to the end user.
///
/// Visibility: kept `pub(crate)` because the only safe consumption path
/// is via [`crate::Sandbox::run_with_extra_handlers`], which calls this
/// function before fork.  Downstream crates that pre-build their own
/// `Vec<ExtraHandler>` get the same enforcement transparently through
/// that entry point — there is no `ExtraHandler::register_into` API
/// that would let a user bypass it.
pub(crate) fn validate_extras_against_policy(
    extras: &[ExtraHandler],
    policy: &crate::policy::Policy,
) -> Result<(), u32> {
    let deny: std::collections::HashSet<u32> =
        crate::context::deny_syscall_numbers(policy).into_iter().collect();
    for extra in extras {
        let nr = extra.syscall_nr as u32;
        if deny.contains(&nr) {
            return Err(nr);
        }
    }
    Ok(())
}

/// Ordered chain of handlers for a single syscall number.
struct HandlerChain {
    handlers: Vec<HandlerFn>,
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

    /// Register a handler for the given syscall number.  Handlers are called in
    /// registration order; the first non-Continue result wins.
    pub fn register(&mut self, syscall_nr: i64, handler: HandlerFn) {
        self.chains
            .entry(syscall_nr)
            .or_insert_with(|| HandlerChain {
                handlers: Vec::new(),
            })
            .handlers
            .push(handler);
    }

    /// Dispatch a notification through the handler chain for its syscall number.
    pub async fn dispatch(
        &self,
        notif: SeccompNotif,
        ctx: &Arc<SupervisorCtx>,
        notif_fd: RawFd,
    ) -> NotifAction {
        let nr = notif.data.nr as i64;
        if let Some(chain) = self.chains.get(&nr) {
            for handler in &chain.handlers {
                let action = handler(notif, Arc::clone(ctx), notif_fd).await;
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
/// `extra_handlers` are appended **after** all builtin handlers, so they
/// observe the post-builtin view (e.g. `chroot`-normalized paths on
/// `openat`).  Builtins cannot be overridden or removed — this is the
/// security boundary for downstream crates.
pub fn build_dispatch_table(
    policy: &Arc<NotifPolicy>,
    resource: &Arc<Mutex<ResourceState>>,
    extra_handlers: Vec<ExtraHandler>,
) -> DispatchTable {
    let mut table = DispatchTable::new();

    // ------------------------------------------------------------------
    // Fork/clone family (always on)
    // ------------------------------------------------------------------
    let mut fork_nrs = vec![libc::SYS_clone, libc::SYS_clone3];
    if let Some(vfork) = arch::SYS_VFORK {
        fork_nrs.push(vfork);
    }
    for nr in fork_nrs {
        let policy = Arc::clone(policy);
        let resource = Arc::clone(resource);
        table.register(nr, Box::new(move |notif, _ctx, _notif_fd| {
            let policy = Arc::clone(&policy);
            let resource = Arc::clone(&resource);
            Box::pin(async move {
                crate::resource::handle_fork(&notif, &resource, &policy).await
            })
        }));
    }

    // ------------------------------------------------------------------
    // Wait family (always on)
    // ------------------------------------------------------------------
    for &nr in &[libc::SYS_wait4, libc::SYS_waitid] {
        let resource = Arc::clone(resource);
        table.register(nr, Box::new(move |notif, _ctx, _notif_fd| {
            let resource = Arc::clone(&resource);
            Box::pin(async move {
                crate::resource::handle_wait(&notif, &resource).await
            })
        }));
    }

    // ------------------------------------------------------------------
    // Memory management (conditional on has_memory_limit)
    // ------------------------------------------------------------------
    if policy.has_memory_limit {
        for &nr in &[
            libc::SYS_mmap, libc::SYS_munmap, libc::SYS_brk,
            libc::SYS_mremap, libc::SYS_shmget,
        ] {
            let policy = Arc::clone(policy);
            table.register(nr, Box::new(move |notif, ctx, _notif_fd| {
                let policy = Arc::clone(&policy);
                Box::pin(async move {
                    crate::resource::handle_memory(&notif, &ctx, &policy).await
                })
            }));
        }
    }

    // ------------------------------------------------------------------
    // Network (conditional on has_net_allowlist || has_http_acl)
    // ------------------------------------------------------------------
    if policy.has_net_allowlist || policy.has_http_acl {
        for &nr in &[libc::SYS_connect, libc::SYS_sendto, libc::SYS_sendmsg] {
            table.register(nr, Box::new(|notif, ctx, notif_fd| {
                Box::pin(async move {
                    crate::network::handle_net(&notif, &ctx, notif_fd).await
                })
            }));
        }
    }

    // ------------------------------------------------------------------
    // Deterministic random — getrandom()
    // ------------------------------------------------------------------
    if policy.has_random_seed {
        table.register(libc::SYS_getrandom, Box::new(|notif, ctx, notif_fd| {
            Box::pin(async move {
                let mut tr = ctx.time_random.lock().await;
                if let Some(ref mut rng) = tr.random_state {
                    crate::random::handle_getrandom(&notif, rng, notif_fd)
                } else {
                    NotifAction::Continue
                }
            })
        }));
    }

    // ------------------------------------------------------------------
    // Deterministic random — /dev/urandom opens (openat)
    // ------------------------------------------------------------------
    if policy.has_random_seed {
        table.register(libc::SYS_openat, Box::new(|notif, ctx, notif_fd| {
            Box::pin(async move {
                let mut tr = ctx.time_random.lock().await;
                if let Some(ref mut rng) = tr.random_state {
                    if let Some(action) = crate::random::handle_random_open(&notif, rng, notif_fd) {
                        return action;
                    }
                }
                NotifAction::Continue
            })
        }));
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
            table.register(nr, Box::new(move |notif, _ctx, notif_fd| {
                Box::pin(async move {
                    crate::time::handle_timer(&notif, time_offset, notif_fd)
                })
            }));
        }
    }

    // ------------------------------------------------------------------
    // Chroot path interception (before COW)
    // ------------------------------------------------------------------
    if policy.chroot_root.is_some() {
        register_chroot_handlers(&mut table, policy);
    }

    // ------------------------------------------------------------------
    // COW filesystem interception
    // ------------------------------------------------------------------
    if policy.cow_enabled {
        register_cow_handlers(&mut table);
    }

    // ------------------------------------------------------------------
    // /proc virtualization (always on)
    // ------------------------------------------------------------------
    {
        let policy = Arc::clone(policy);
        let resource = Arc::clone(resource);
        table.register(libc::SYS_openat, Box::new(move |notif, ctx, notif_fd| {
            let policy = Arc::clone(&policy);
            let resource = Arc::clone(&resource);
            let processes = Arc::clone(&ctx.processes);
            let network = Arc::clone(&ctx.network);
            Box::pin(async move {
                crate::procfs::handle_proc_open(&notif, &processes, &resource, &network, &policy, notif_fd).await
            })
        }));
    }
    let mut getdents_nrs = vec![libc::SYS_getdents64];
    if let Some(getdents) = arch::SYS_GETDENTS {
        getdents_nrs.push(getdents);
    }
    for nr in getdents_nrs {
        let policy = Arc::clone(policy);
        table.register(nr, Box::new(move |notif, ctx, notif_fd| {
            let policy = Arc::clone(&policy);
            let processes = Arc::clone(&ctx.processes);
            Box::pin(async move {
                crate::procfs::handle_getdents(&notif, &processes, &policy, notif_fd).await
            })
        }));
    }

    // ------------------------------------------------------------------
    // Virtual CPU count
    // ------------------------------------------------------------------
    if let Some(n) = policy.num_cpus {
        table.register(libc::SYS_sched_getaffinity, Box::new(move |notif, _ctx, notif_fd| {
            Box::pin(async move {
                crate::procfs::handle_sched_getaffinity(&notif, n, notif_fd)
            })
        }));
    }

    // ------------------------------------------------------------------
    // Hostname virtualization
    // ------------------------------------------------------------------
    if let Some(ref hostname) = policy.hostname {
        let hostname = hostname.clone();
        let hostname2 = hostname.clone();
        table.register(libc::SYS_uname, Box::new(move |notif, _ctx, notif_fd| {
            let hostname = hostname.clone();
            Box::pin(async move {
                crate::procfs::handle_uname(&notif, &hostname, notif_fd)
            })
        }));
        table.register(libc::SYS_openat, Box::new(move |notif, _ctx, notif_fd| {
            let hostname = hostname2.clone();
            Box::pin(async move {
                if let Some(action) = crate::procfs::handle_hostname_open(&notif, &hostname, notif_fd) {
                    action
                } else {
                    NotifAction::Continue
                }
            })
        }));
    }

    // ------------------------------------------------------------------
    // /etc/hosts virtualization (for net_allow_hosts)
    // ------------------------------------------------------------------
    if let Some(ref etc_hosts) = policy.virtual_etc_hosts {
        let etc_hosts = etc_hosts.clone();
        table.register(libc::SYS_openat, Box::new(move |notif, _ctx, notif_fd| {
            let etc_hosts = etc_hosts.clone();
            Box::pin(async move {
                if let Some(action) = crate::procfs::handle_etc_hosts_open(&notif, &etc_hosts, notif_fd) {
                    action
                } else {
                    NotifAction::Continue
                }
            })
        }));
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
            table.register(nr, Box::new(|notif, ctx, notif_fd| {
                let processes = Arc::clone(&ctx.processes);
                Box::pin(async move {
                    crate::procfs::handle_sorted_getdents(&notif, &processes, notif_fd).await
                })
            }));
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
        table.register(libc::SYS_socket, Box::new(|notif, ctx, _fd| {
            let state = Arc::clone(&ctx.netlink);
            Box::pin(async move {
                crate::netlink::handlers::handle_socket(&notif, &state).await
            })
        }));
        table.register(libc::SYS_bind, Box::new(|notif, ctx, _fd| {
            let state = Arc::clone(&ctx.netlink);
            Box::pin(async move {
                crate::netlink::handlers::handle_bind(&notif, &state).await
            })
        }));
        table.register(libc::SYS_getsockname, Box::new(|notif, ctx, notif_fd| {
            let state = Arc::clone(&ctx.netlink);
            Box::pin(async move {
                crate::netlink::handlers::handle_getsockname(&notif, &state, notif_fd).await
            })
        }));
        // Zero the msg_name region on recv so glibc sees nl_pid=0
        // (the kernel only writes sun_family on unix socketpair recvmsg,
        //  leaving the rest of the buffer as stack garbage otherwise).
        for &nr in &[libc::SYS_recvfrom, libc::SYS_recvmsg] {
            table.register(nr, Box::new(|notif, ctx, notif_fd| {
                let state = Arc::clone(&ctx.netlink);
                Box::pin(async move {
                    crate::netlink::handlers::handle_netlink_recvmsg(&notif, &state, notif_fd).await
                })
            }));
        }
        // Unregister on close so the (pid, fd) slot isn't left in the
        // cookie set once the child reuses the fd for something else.
        table.register(libc::SYS_close, Box::new(|notif, ctx, _fd| {
            let state = Arc::clone(&ctx.netlink);
            Box::pin(async move {
                crate::netlink::handlers::handle_close(&notif, &state).await
            })
        }));
    }

    // ------------------------------------------------------------------
    // Bind — on-behalf
    // ------------------------------------------------------------------
    if policy.port_remap || policy.has_net_allowlist {
        table.register(libc::SYS_bind, Box::new(|notif, ctx, notif_fd| {
            Box::pin(async move {
                crate::port_remap::handle_bind(&notif, &ctx.network, notif_fd).await
            })
        }));
    }

    // ------------------------------------------------------------------
    // getsockname — port remap
    // ------------------------------------------------------------------
    if policy.port_remap {
        table.register(libc::SYS_getsockname, Box::new(|notif, ctx, notif_fd| {
            Box::pin(async move {
                crate::port_remap::handle_getsockname(&notif, &ctx.network, notif_fd).await
            })
        }));
    }

    // ------------------------------------------------------------------
    // Extra handlers supplied by the caller of `Sandbox::run_with_extra_handlers`.
    // Appended last so builtin handlers keep their security-critical priority
    // (chroot path normalization, COW writes, resource accounting).
    // ------------------------------------------------------------------
    for extra in extra_handlers {
        table.register(extra.syscall_nr, extra.handler);
    }

    table
}

// ============================================================
// Chroot handler registration
// ============================================================

fn register_chroot_handlers(table: &mut DispatchTable, policy: &Arc<NotifPolicy>) {
    use crate::chroot::dispatch::ChrootCtx;

    // Helper macro to reduce boilerplate for chroot handlers that unconditionally
    // return (non-fallthrough).
    macro_rules! chroot_handler {
        ($policy:expr, $handler:expr) => {{
            let policy = Arc::clone($policy);
            let handler_fn: HandlerFn = Box::new(move |notif, ctx, notif_fd| {
                let policy = Arc::clone(&policy);
                Box::pin(async move {
                    let chroot_ctx = ChrootCtx {
                        root: policy.chroot_root.as_ref().unwrap(),
                        readable: &policy.chroot_readable,
                        writable: &policy.chroot_writable,
                        denied: &policy.chroot_denied,
                        mounts: &policy.chroot_mounts,
                    };
                    $handler(&notif, &ctx.chroot, &ctx.cow, notif_fd, &chroot_ctx).await
                })
            });
            handler_fn
        }};
    }

    // Helper for chroot handlers that may fall through (return Continue).
    macro_rules! chroot_handler_fallthrough {
        ($policy:expr, $handler:expr) => {{
            let policy = Arc::clone($policy);
            let handler_fn: HandlerFn = Box::new(move |notif, ctx, notif_fd| {
                let policy = Arc::clone(&policy);
                Box::pin(async move {
                    let chroot_ctx = ChrootCtx {
                        root: policy.chroot_root.as_ref().unwrap(),
                        readable: &policy.chroot_readable,
                        writable: &policy.chroot_writable,
                        denied: &policy.chroot_denied,
                        mounts: &policy.chroot_mounts,
                    };
                    $handler(&notif, &ctx.chroot, &ctx.cow, notif_fd, &chroot_ctx).await
                })
            });
            handler_fn
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
        let policy = Arc::clone(policy);
        table.register(chown, Box::new(move |notif, ctx, notif_fd| {
            let policy = Arc::clone(&policy);
            Box::pin(async move {
                let chroot_ctx = ChrootCtx {
                    root: policy.chroot_root.as_ref().unwrap(),
                    readable: &policy.chroot_readable,
                    writable: &policy.chroot_writable,
                    denied: &policy.chroot_denied,
                    mounts: &policy.chroot_mounts,
                };
                crate::chroot::dispatch::handle_chroot_legacy_chown(&notif, &ctx.chroot, &ctx.cow, notif_fd, &chroot_ctx, false).await
            })
        }));
    }

    // lchown — follow
    if let Some(lchown) = arch::SYS_LCHOWN {
        let policy = Arc::clone(policy);
        table.register(lchown, Box::new(move |notif, ctx, notif_fd| {
            let policy = Arc::clone(&policy);
            Box::pin(async move {
                let chroot_ctx = ChrootCtx {
                    root: policy.chroot_root.as_ref().unwrap(),
                    readable: &policy.chroot_readable,
                    writable: &policy.chroot_writable,
                    denied: &policy.chroot_denied,
                    mounts: &policy.chroot_mounts,
                };
                crate::chroot::dispatch::handle_chroot_legacy_chown(&notif, &ctx.chroot, &ctx.cow, notif_fd, &chroot_ctx, true).await
            })
        }));
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

fn register_cow_handlers(table: &mut DispatchTable) {
    // Helper to grab cow + processes from ctx in one place.
    macro_rules! cow_call {
        ($handler:expr) => {
            Box::new(|notif, ctx, notif_fd| {
                let cow = Arc::clone(&ctx.cow);
                let processes = Arc::clone(&ctx.processes);
                Box::pin(async move { $handler(&notif, &cow, &processes, notif_fd).await })
            })
        };
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
                port_remap: false,
                cow_enabled: false,
                chroot_root: None,
                chroot_readable: Vec::new(),
                chroot_writable: Vec::new(),
                chroot_denied: Vec::new(),
                chroot_mounts: Vec::new(),
                deterministic_dirs: false,
                hostname: None,
                has_http_acl: false,
                virtual_etc_hosts: None,
            }),
            child_pidfd: None,
            notif_fd: -1,
        })
    }

    #[test]
    fn extra_handler_ctor_preserves_fields() {
        let h: HandlerFn = Box::new(|_notif, _ctx, _fd| {
            Box::pin(async { NotifAction::Continue })
        });
        let eh = ExtraHandler::new(libc::SYS_openat, h);
        assert_eq!(eh.syscall_nr, libc::SYS_openat);
    }

    /// All registered handlers run, in registration order, when each
    /// returns `Continue`.  Verifies that `register` appends to the
    /// underlying `Vec` and that `dispatch` walks it front-to-back.
    #[tokio::test]
    async fn dispatch_walks_chain_in_registration_order() {
        let mut table = DispatchTable::new();
        let order = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));

        for tag in [1u8, 2u8, 3u8] {
            let order = Arc::clone(&order);
            table.register(
                libc::SYS_openat,
                Box::new(move |_notif, _ctx, _fd| {
                    let order = Arc::clone(&order);
                    Box::pin(async move {
                        order.lock().unwrap().push(tag);
                        NotifAction::Continue
                    })
                }),
            );
        }

        let ctx = fake_supervisor_ctx();
        let action = table
            .dispatch(fake_notif(libc::SYS_openat as i32), &ctx, -1)
            .await;

        assert!(matches!(action, NotifAction::Continue));
        let recorded = order.lock().unwrap();
        assert_eq!(
            *recorded,
            [1u8, 2u8, 3u8],
            "every handler must run, in the order it was registered"
        );
    }

    /// Append-after-builtin contract: when an `ExtraHandler` is registered
    /// after a builtin-like handler, dispatch invokes the builtin first
    /// and the extra second.  This is the security-load-bearing invariant —
    /// a builtin returning a non-`Continue` `NotifAction` must short-circuit
    /// before the extra runs (covered by
    /// `dispatch_stops_at_first_non_continue`); when the builtin returns
    /// `Continue`, the extra observes the post-builtin view.
    #[tokio::test]
    async fn dispatch_runs_builtin_before_extra() {
        let mut table = DispatchTable::new();
        let order = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));

        // Builtin first, tagged 'B'.
        let order_builtin = Arc::clone(&order);
        table.register(
            libc::SYS_openat,
            Box::new(move |_notif, _ctx, _fd| {
                let order = Arc::clone(&order_builtin);
                Box::pin(async move {
                    order.lock().unwrap().push(b'B');
                    NotifAction::Continue
                })
            }),
        );

        // Extra after, tagged 'E'.  Routed through `ExtraHandler` to mirror
        // how `build_dispatch_table` consumes user-supplied handlers.
        let order_extra = Arc::clone(&order);
        let extra = ExtraHandler::new(
            libc::SYS_openat,
            Box::new(move |_notif, _ctx, _fd| {
                let order = Arc::clone(&order_extra);
                Box::pin(async move {
                    order.lock().unwrap().push(b'E');
                    NotifAction::Continue
                })
            }),
        );
        table.register(extra.syscall_nr, extra.handler);

        let ctx = fake_supervisor_ctx();
        let action = table
            .dispatch(fake_notif(libc::SYS_openat as i32), &ctx, -1)
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
            Box::new(move |_notif, _ctx, _fd| {
                let calls = Arc::clone(&calls_first);
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    NotifAction::Errno(libc::EACCES)
                })
            }),
        );

        // Second handler — must NOT be called.
        let calls_second = Arc::clone(&calls);
        table.register(
            libc::SYS_openat,
            Box::new(move |_notif, _ctx, _fd| {
                let calls = Arc::clone(&calls_second);
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    NotifAction::Continue
                })
            }),
        );

        let ctx = fake_supervisor_ctx();
        let action = table
            .dispatch(fake_notif(libc::SYS_openat as i32), &ctx, -1)
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

    #[test]
    fn extras_vec_empty_leaves_table_without_change() {
        // build_dispatch_table with empty extras should not add any entries.
        // We verify the for-loop degenerates to nop.
        let extras: Vec<ExtraHandler> = Vec::new();
        let mut handler_count = 0usize;
        for _ in extras {
            handler_count += 1;
        }
        assert_eq!(handler_count, 0, "empty extras registers zero handlers");
    }

    /// `validate_extras_against_policy` must reject extras whose syscall is in
    /// the policy's user-specified `deny_syscalls` list, with the same
    /// rationale as DEFAULT_DENY: the BPF program emits notif JEQs before
    /// deny JEQs, so a user handler returning `Continue` would translate into
    /// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and silently bypass the kernel-level
    /// deny.
    ///
    /// Uses `mremap` because it is in `syscall_name_to_nr` but not in
    /// `DEFAULT_DENY_SYSCALLS` — putting it into `deny_syscalls` is the only
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
        let handler: HandlerFn =
            Box::new(|_notif, _ctx, _fd| Box::pin(async { NotifAction::Continue }));
        let extras = vec![ExtraHandler::new(libc::SYS_mremap, handler)];

        let result = validate_extras_against_policy(&extras, &policy);
        assert_eq!(
            result,
            Err(libc::SYS_mremap as u32),
            "extras on user-specified deny must be rejected, naming the offending syscall"
        );
    }
}
