// Table-driven syscall dispatch — routes seccomp notifications to handler chains.
//
// Each syscall number maps to an ordered chain of handlers.  The chain is walked
// until a handler returns a non-Continue action (or the chain is exhausted, in
// which case Continue is returned).

use std::collections::HashMap;
use std::future::Future;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::Mutex;

use super::notif::{NotifAction, NotifPolicy, SupervisorState};
use super::state::{CowState, ProcfsState, ResourceState};
use crate::sys::structs::SeccompNotif;

// ============================================================
// Types
// ============================================================

/// An async handler function.  Receives the notification, shared state,
/// COW state, and the notif fd.  Returns a `NotifAction`.
pub type HandlerFn = Box<
    dyn Fn(SeccompNotif, Arc<Mutex<SupervisorState>>, Arc<Mutex<CowState>>, Arc<Mutex<ProcfsState>>, RawFd) -> Pin<Box<dyn Future<Output = NotifAction> + Send>>
        + Send
        + Sync,
>;

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
        state: &Arc<Mutex<SupervisorState>>,
        cow: &Arc<Mutex<CowState>>,
        procfs: &Arc<Mutex<ProcfsState>>,
        notif_fd: RawFd,
    ) -> NotifAction {
        let nr = notif.data.nr as i64;
        if let Some(chain) = self.chains.get(&nr) {
            for handler in &chain.handlers {
                let action = handler(notif, Arc::clone(state), Arc::clone(cow), Arc::clone(procfs), notif_fd).await;
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
pub fn build_dispatch_table(
    policy: &Arc<NotifPolicy>,
    resource: &Arc<Mutex<ResourceState>>,
    procfs: &Arc<Mutex<ProcfsState>>,
) -> DispatchTable {
    let mut table = DispatchTable::new();

    // ------------------------------------------------------------------
    // Fork/clone family (always on)
    // ------------------------------------------------------------------
    for &nr in &[libc::SYS_clone, libc::SYS_clone3, libc::SYS_vfork] {
        let policy = Arc::clone(policy);
        let resource = Arc::clone(resource);
        let procfs = Arc::clone(procfs);
        table.register(nr, Box::new(move |notif, _state, _cow, _procfs_inner, _notif_fd| {
            let policy = Arc::clone(&policy);
            let resource = Arc::clone(&resource);
            let procfs_inner = Arc::clone(&procfs);
            Box::pin(async move {
                crate::resource::handle_fork(&notif, &resource, &procfs_inner, &policy).await
            })
        }));
    }

    // ------------------------------------------------------------------
    // Wait family (always on)
    // ------------------------------------------------------------------
    for &nr in &[libc::SYS_wait4, libc::SYS_waitid] {
        let resource = Arc::clone(resource);
        table.register(nr, Box::new(move |notif, _state, _cow, _procfs, _notif_fd| {
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
            let resource = Arc::clone(resource);
            table.register(nr, Box::new(move |notif, _state, _cow, _procfs, _notif_fd| {
                let policy = Arc::clone(&policy);
                let resource = Arc::clone(&resource);
                Box::pin(async move {
                    crate::resource::handle_memory(&notif, &resource, &policy).await
                })
            }));
        }
    }

    // ------------------------------------------------------------------
    // Network (conditional on has_net_allowlist || has_http_acl)
    // ------------------------------------------------------------------
    if policy.has_net_allowlist || policy.has_http_acl {
        for &nr in &[libc::SYS_connect, libc::SYS_sendto, libc::SYS_sendmsg] {
            table.register(nr, Box::new(|notif, state, _cow, _procfs, notif_fd| {
                Box::pin(async move {
                    crate::network::handle_net(&notif, &state, notif_fd).await
                })
            }));
        }
    }

    // ------------------------------------------------------------------
    // Deterministic random — getrandom()
    // ------------------------------------------------------------------
    if policy.has_random_seed {
        table.register(libc::SYS_getrandom, Box::new(|notif, state, _cow, _procfs, notif_fd| {
            Box::pin(async move {
                let mut st = state.lock().await;
                if let Some(ref mut rng) = st.random_state {
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
        table.register(libc::SYS_openat, Box::new(|notif, state, _cow, _procfs, notif_fd| {
            Box::pin(async move {
                let mut st = state.lock().await;
                if let Some(ref mut rng) = st.random_state {
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
            table.register(nr, Box::new(move |notif, _state, _cow, _procfs, notif_fd| {
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
        table.register(libc::SYS_openat, Box::new(move |notif, state, _cow, procfs_inner, notif_fd| {
            let policy = Arc::clone(&policy);
            let resource = Arc::clone(&resource);
            let procfs_inner = Arc::clone(&procfs_inner);
            Box::pin(async move {
                crate::procfs::handle_proc_open(&notif, &procfs_inner, &resource, &state, &policy, notif_fd).await
            })
        }));
    }
    for &nr in &[libc::SYS_getdents64, libc::SYS_getdents as i64] {
        let policy = Arc::clone(policy);
        table.register(nr, Box::new(move |notif, _state, _cow, procfs_inner, notif_fd| {
            let policy = Arc::clone(&policy);
            let procfs_inner = Arc::clone(&procfs_inner);
            Box::pin(async move {
                crate::procfs::handle_getdents(&notif, &procfs_inner, &policy, notif_fd).await
            })
        }));
    }

    // ------------------------------------------------------------------
    // Virtual CPU count
    // ------------------------------------------------------------------
    if let Some(n) = policy.num_cpus {
        table.register(libc::SYS_sched_getaffinity, Box::new(move |notif, _state, _cow, _procfs, notif_fd| {
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
        table.register(libc::SYS_uname, Box::new(move |notif, _state, _cow, _procfs, notif_fd| {
            let hostname = hostname.clone();
            Box::pin(async move {
                crate::procfs::handle_uname(&notif, &hostname, notif_fd)
            })
        }));
        table.register(libc::SYS_openat, Box::new(move |notif, _state, _cow, _procfs, notif_fd| {
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
    // Deterministic directory listing
    // ------------------------------------------------------------------
    if policy.deterministic_dirs {
        for &nr in &[libc::SYS_getdents64, libc::SYS_getdents as i64] {
            table.register(nr, Box::new(|notif, _state, _cow, procfs_inner, notif_fd| {
                Box::pin(async move {
                    crate::procfs::handle_sorted_getdents(&notif, &procfs_inner, notif_fd).await
                })
            }));
        }
    }

    // ------------------------------------------------------------------
    // Bind — on-behalf
    // ------------------------------------------------------------------
    if policy.port_remap || policy.has_net_allowlist {
        table.register(libc::SYS_bind, Box::new(|notif, state, _cow, _procfs, notif_fd| {
            Box::pin(async move {
                crate::port_remap::handle_bind(&notif, &state, notif_fd).await
            })
        }));
    }

    // ------------------------------------------------------------------
    // getsockname — port remap
    // ------------------------------------------------------------------
    if policy.port_remap {
        table.register(libc::SYS_getsockname, Box::new(|notif, state, _cow, _procfs, notif_fd| {
            Box::pin(async move {
                crate::port_remap::handle_getsockname(&notif, &state, notif_fd).await
            })
        }));
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
            let handler_fn: HandlerFn = Box::new(move |notif, state, cow, _procfs, notif_fd| {
                let policy = Arc::clone(&policy);
                Box::pin(async move {
                    let ctx = ChrootCtx {
                        root: policy.chroot_root.as_ref().unwrap(),
                        readable: &policy.chroot_readable,
                        writable: &policy.chroot_writable,
                        denied: &policy.chroot_denied,
                        mounts: &policy.chroot_mounts,
                    };
                    $handler(&notif, &state, &cow, notif_fd, &ctx).await
                })
            });
            handler_fn
        }};
    }

    // Helper for chroot handlers that may fall through (return Continue).
    macro_rules! chroot_handler_fallthrough {
        ($policy:expr, $handler:expr) => {{
            let policy = Arc::clone($policy);
            let handler_fn: HandlerFn = Box::new(move |notif, state, cow, _procfs, notif_fd| {
                let policy = Arc::clone(&policy);
                Box::pin(async move {
                    let ctx = ChrootCtx {
                        root: policy.chroot_root.as_ref().unwrap(),
                        readable: &policy.chroot_readable,
                        writable: &policy.chroot_writable,
                        denied: &policy.chroot_denied,
                        mounts: &policy.chroot_mounts,
                    };
                    $handler(&notif, &state, &cow, notif_fd, &ctx).await
                })
            });
            handler_fn
        }};
    }

    // openat — fallthrough if Continue
    table.register(libc::SYS_openat, chroot_handler_fallthrough!(policy,
        crate::chroot::dispatch::handle_chroot_open));

    // open (legacy) — fallthrough if Continue
    table.register(libc::SYS_open as i64, chroot_handler_fallthrough!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_open));

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
    table.register(libc::SYS_unlink as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_unlink));
    table.register(libc::SYS_rmdir as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_rmdir));
    table.register(libc::SYS_mkdir as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_mkdir));
    table.register(libc::SYS_rename as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_rename));
    table.register(libc::SYS_symlink as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_symlink));
    table.register(libc::SYS_link as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_link));
    table.register(libc::SYS_chmod as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_chmod));

    // chown — non-follow
    {
        let policy = Arc::clone(policy);
        table.register(libc::SYS_chown as i64, Box::new(move |notif, state, cow, _procfs, notif_fd| {
            let policy = Arc::clone(&policy);
            Box::pin(async move {
                let ctx = ChrootCtx {
                    root: policy.chroot_root.as_ref().unwrap(),
                    readable: &policy.chroot_readable,
                    writable: &policy.chroot_writable,
                    denied: &policy.chroot_denied,
                    mounts: &policy.chroot_mounts,
                };
                crate::chroot::dispatch::handle_chroot_legacy_chown(&notif, &state, &cow, notif_fd, &ctx, false).await
            })
        }));
    }

    // lchown — follow
    {
        let policy = Arc::clone(policy);
        table.register(libc::SYS_lchown as i64, Box::new(move |notif, state, cow, _procfs, notif_fd| {
            let policy = Arc::clone(&policy);
            Box::pin(async move {
                let ctx = ChrootCtx {
                    root: policy.chroot_root.as_ref().unwrap(),
                    readable: &policy.chroot_readable,
                    writable: &policy.chroot_writable,
                    denied: &policy.chroot_denied,
                    mounts: &policy.chroot_mounts,
                };
                crate::chroot::dispatch::handle_chroot_legacy_chown(&notif, &state, &cow, notif_fd, &ctx, true).await
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
    table.register(libc::SYS_stat as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_stat));
    table.register(libc::SYS_lstat as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_lstat));
    table.register(libc::SYS_access as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_access));

    // statx
    table.register(libc::SYS_statx, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_statx));

    // readlink
    table.register(libc::SYS_readlinkat, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_readlink));
    table.register(libc::SYS_readlink as i64, chroot_handler!(policy,
        crate::chroot::dispatch::handle_chroot_legacy_readlink));

    // getdents
    for &nr in &[libc::SYS_getdents64, libc::SYS_getdents as i64] {
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
    // Write syscalls — unconditional return
    for &nr in &[
        libc::SYS_unlinkat, libc::SYS_mkdirat, libc::SYS_renameat2,
        libc::SYS_symlinkat, libc::SYS_linkat, libc::SYS_fchmodat,
        libc::SYS_fchownat, libc::SYS_truncate,
    ] {
        table.register(nr, Box::new(|notif, _state, cow, _procfs, notif_fd| {
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_write(&notif, &cow, notif_fd).await
            })
        }));
    }

    // Legacy write syscalls
    for &nr in &[
        libc::SYS_unlink as i64, libc::SYS_rmdir as i64,
        libc::SYS_mkdir as i64, libc::SYS_rename as i64,
        libc::SYS_symlink as i64, libc::SYS_link as i64,
        libc::SYS_chmod as i64, libc::SYS_chown as i64,
        libc::SYS_lchown as i64,
    ] {
        table.register(nr, Box::new(|notif, _state, cow, _procfs, notif_fd| {
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_legacy_write(&notif, &cow, notif_fd).await
            })
        }));
    }

    // faccessat/access — fallthrough
    for &nr in &[
        libc::SYS_faccessat,
        crate::cow::dispatch::SYS_FACCESSAT2,
        libc::SYS_access as i64,
    ] {
        table.register(nr, Box::new(|notif, _state, cow, _procfs, notif_fd| {
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_access(&notif, &cow, notif_fd).await
            })
        }));
    }

    // openat/open — fallthrough
    for &nr in &[libc::SYS_openat, libc::SYS_open as i64] {
        table.register(nr, Box::new(|notif, _state, cow, _procfs, notif_fd| {
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_open(&notif, &cow, notif_fd).await
            })
        }));
    }

    // stat family — fallthrough
    for &nr in &[
        libc::SYS_newfstatat, libc::SYS_faccessat,
        libc::SYS_stat as i64, libc::SYS_lstat as i64,
        libc::SYS_access as i64,
    ] {
        table.register(nr, Box::new(|notif, _state, cow, _procfs, notif_fd| {
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_stat(&notif, &cow, notif_fd).await
            })
        }));
    }

    // statx — fallthrough
    table.register(libc::SYS_statx, Box::new(|notif, _state, cow, _procfs, notif_fd| {
        Box::pin(async move {
            crate::cow::dispatch::handle_cow_statx(&notif, &cow, notif_fd).await
        })
    }));

    // readlink — fallthrough
    for &nr in &[libc::SYS_readlinkat, libc::SYS_readlink as i64] {
        table.register(nr, Box::new(|notif, _state, cow, _procfs, notif_fd| {
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_readlink(&notif, &cow, notif_fd).await
            })
        }));
    }

    // getdents — fallthrough
    for &nr in &[libc::SYS_getdents64, libc::SYS_getdents as i64] {
        table.register(nr, Box::new(|notif, _state, cow, _procfs, notif_fd| {
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_getdents(&notif, &cow, notif_fd).await
            })
        }));
    }
}
