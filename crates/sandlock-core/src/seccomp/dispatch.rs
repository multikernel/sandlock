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
pub fn build_dispatch_table(
    policy: &Arc<NotifPolicy>,
    resource: &Arc<Mutex<ResourceState>>,
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
        table.register(nr, Box::new(move |notif, ctx, _notif_fd| {
            let policy = Arc::clone(&policy);
            let resource = Arc::clone(&resource);
            let procfs_inner = Arc::clone(&ctx.procfs);
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
            let resource = Arc::clone(resource);
            table.register(nr, Box::new(move |notif, _ctx, _notif_fd| {
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
            let procfs_inner = Arc::clone(&ctx.procfs);
            let network = Arc::clone(&ctx.network);
            Box::pin(async move {
                crate::procfs::handle_proc_open(&notif, &procfs_inner, &resource, &network, &policy, notif_fd).await
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
            let procfs_inner = Arc::clone(&ctx.procfs);
            Box::pin(async move {
                crate::procfs::handle_getdents(&notif, &procfs_inner, &policy, notif_fd).await
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
                let procfs_inner = Arc::clone(&ctx.procfs);
                Box::pin(async move {
                    crate::procfs::handle_sorted_getdents(&notif, &procfs_inner, notif_fd).await
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
        table.register(nr, Box::new(|notif, ctx, notif_fd| {
            let cow = Arc::clone(&ctx.cow);
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_write(&notif, &cow, notif_fd).await
            })
        }));
    }

    // utimensat — unconditional return
    table.register(libc::SYS_utimensat, Box::new(|notif, ctx, notif_fd| {
        let cow = Arc::clone(&ctx.cow);
        Box::pin(async move {
            crate::cow::dispatch::handle_cow_utimensat(&notif, &cow, notif_fd).await
        })
    }));

    // faccessat/access — fallthrough
    let mut access_nrs = vec![
        libc::SYS_faccessat,
        crate::cow::dispatch::SYS_FACCESSAT2,
    ];
    access_nrs.extend(arch::SYS_ACCESS);
    for nr in access_nrs {
        table.register(nr, Box::new(|notif, ctx, notif_fd| {
            let cow = Arc::clone(&ctx.cow);
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_access(&notif, &cow, notif_fd).await
            })
        }));
    }

    // openat/open — fallthrough
    let mut open_nrs = vec![libc::SYS_openat];
    open_nrs.extend(arch::SYS_OPEN);
    for nr in open_nrs {
        table.register(nr, Box::new(|notif, ctx, notif_fd| {
            let cow = Arc::clone(&ctx.cow);
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_open(&notif, &cow, notif_fd).await
            })
        }));
    }

    // stat family — fallthrough
    let mut stat_nrs = vec![
        libc::SYS_newfstatat, libc::SYS_faccessat,
    ];
    stat_nrs.extend([arch::SYS_STAT, arch::SYS_LSTAT, arch::SYS_ACCESS].into_iter().flatten());
    for nr in stat_nrs {
        table.register(nr, Box::new(|notif, ctx, notif_fd| {
            let cow = Arc::clone(&ctx.cow);
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_stat(&notif, &cow, notif_fd).await
            })
        }));
    }

    // statx — fallthrough
    table.register(libc::SYS_statx, Box::new(|notif, ctx, notif_fd| {
        let cow = Arc::clone(&ctx.cow);
        Box::pin(async move {
            crate::cow::dispatch::handle_cow_statx(&notif, &cow, notif_fd).await
        })
    }));

    // readlink — fallthrough
    let mut readlink_nrs = vec![libc::SYS_readlinkat];
    readlink_nrs.extend(arch::SYS_READLINK);
    for nr in readlink_nrs {
        table.register(nr, Box::new(|notif, ctx, notif_fd| {
            let cow = Arc::clone(&ctx.cow);
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_readlink(&notif, &cow, notif_fd).await
            })
        }));
    }

    // getdents — fallthrough
    let mut getdents_nrs = vec![libc::SYS_getdents64];
    getdents_nrs.extend(arch::SYS_GETDENTS);
    for nr in getdents_nrs {
        table.register(nr, Box::new(|notif, ctx, notif_fd| {
            let cow = Arc::clone(&ctx.cow);
            Box::pin(async move {
                crate::cow::dispatch::handle_cow_getdents(&notif, &cow, notif_fd).await
            })
        }));
    }

    // chdir — redirect to upper dir if target was created by COW
    table.register(libc::SYS_chdir, Box::new(|notif, ctx, notif_fd| {
        let cow = Arc::clone(&ctx.cow);
        Box::pin(async move {
            crate::cow::dispatch::handle_cow_chdir(&notif, &cow, notif_fd).await
        })
    }));
}
