// Resource limit handlers — memory and process limit enforcement.
//
// Continue safety (issue #27): every `Continue` in this module is safe.
// Most decisions here are on scalar register args (clone flags, mmap
// len, brk address, etc.) which are copied into the seccomp_notif
// struct at notification time — they are *not* pointers into racy user
// memory. The one exception is `clone3`, whose flags live in a
// `clone_args` struct that the supervisor reads from child memory; see
// `clone_flags` for the TOCTOU rationale. The reader is used only for
// resource accounting, not for any kernel-enforced security boundary.
// The kernel's re-read of the syscall args after Continue comes from
// the suspended calling thread's saved registers, which a sibling
// thread cannot mutate.

use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_mem, spawn_pid_watcher, NotifAction, NotifPolicy};
use crate::seccomp::state::ResourceState;
use crate::sys::structs::{
    SeccompNotif, CLONE_NS_FLAGS, EAGAIN, EPERM,
};

/// CLONE_THREAD flag — threads don't count toward process limit.
const CLONE_THREAD: u64 = 0x0001_0000;

/// MAP_ANONYMOUS flag — only anonymous mappings count toward memory limit.
const MAP_ANONYMOUS: u64 = 0x20;

/// Effective clone flags for a fork-like notification.
///
/// `clone(2)` exposes flags directly in `args[0]`. `clone3(2)` instead
/// passes a pointer to a `clone_args` struct in `args[0]` (size in
/// `args[1]`); its `flags` field is the first u64. `fork`/`vfork`
/// have no flags. Anything else returns `None`.
///
/// TOCTOU note: the `clone3` read is from racy user memory — a sibling
/// thread could mutate the struct between this read and the kernel's
/// re-read after `Continue`. Callers use this only for resource
/// accounting (`proc_count`, fork-event tracking gate), never as a
/// security boundary, so a misread can throttle incorrectly but cannot
/// bypass any kernel-enforced deny.
fn clone_flags(notif: &SeccompNotif, notif_fd: RawFd) -> Option<u64> {
    let args = &notif.data.args;
    let nr = notif.data.nr as i64;
    if nr == libc::SYS_clone {
        return Some(args[0]);
    }
    if nr == libc::SYS_clone3 {
        let ptr = args[0];
        let size = args[1] as usize;
        if ptr == 0 || size < 8 {
            return None;
        }
        let buf = read_child_mem(notif_fd, notif.id, notif.pid, ptr, 8).ok()?;
        let arr: [u8; 8] = buf.as_slice().try_into().ok()?;
        return Some(u64::from_ne_bytes(arr));
    }
    if Some(nr) == crate::arch::sys_vfork() || Some(nr) == crate::arch::sys_fork() {
        return Some(0);
    }
    None
}

/// True when the fork-like notification creates a thread (CLONE_THREAD
/// set), i.e. it should not bump the process count. Returns false for
/// non-fork notifs and for clone3 calls whose `clone_args` cannot be
/// read (fail-safe: count as a process rather than silently uncount).
fn is_thread_create(notif: &SeccompNotif, notif_fd: RawFd) -> bool {
    matches!(clone_flags(notif, notif_fd), Some(f) if f & CLONE_THREAD != 0)
}

/// Handle fork/clone/vfork notifications.
///
/// Enforces namespace creation ban and process limits.
///
/// Note: `notif.pid` here is the *parent* (the task issuing
/// fork/clone/vfork). The kernel hasn't run the syscall yet, so we don't
/// know the child's pid yet. When `policy_fn` is active, the supervisor
/// wraps the eventual `Continue` in one-shot ptrace fork-event tracking
/// and registers the new child before it can run user code.
pub(crate) async fn handle_fork(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    ctx: &Arc<SupervisorCtx>,
    _policy: &NotifPolicy,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;

    // Namespace flags are denied for clone (clone3's are caught by the
    // BPF arg filter; vfork takes no flags).
    if nr == libc::SYS_clone && (args[0] & CLONE_NS_FLAGS) != 0 {
        return NotifAction::Errno(EPERM);
    }

    // Threads share their parent's process slot — don't count, allow.
    if is_thread_create(notif, notif_fd) {
        return NotifAction::Continue;
    }

    // Effective process limit. A policy_fn can tighten the static limit at
    // runtime (`restrict_max_processes`), so read the live value when a
    // callback is active; otherwise use the static one. (Lock policy_fn before
    // the resource lock to keep a consistent order.)
    let live_max = {
        let pfs = ctx.policy_fn.lock().await;
        pfs.live_policy
            .as_ref()
            .and_then(|lp| lp.read().ok().map(|l| l.max_processes))
    };

    let mut rs = ctx.resource.lock().await;

    // Checkpoint/freeze: hold the fork notification.
    if rs.hold_forks {
        rs.held_notif_ids.push(notif.id);
        return NotifAction::Hold;
    }

    // Enforce concurrent process limit.
    let limit = live_max.unwrap_or(rs.max_processes);
    if rs.proc_count >= limit {
        return NotifAction::Errno(EAGAIN);
    }

    rs.proc_count += 1;
    NotifAction::Continue
}

/// If `notif.pid` is not yet tracked in the ProcessIndex, register
/// per-process supervisor state for it: open a pidfd, record the
/// canonical PidKey, and spawn the exit watcher. Called from the
/// supervisor's notification dispatcher before per-syscall handlers
/// run, so handlers can rely on `ProcessIndex::key_for(notif.pid)`
/// returning a fresh PidKey.
///
/// With `policy_fn` active, fork-like syscalls additionally register
/// new child processes at creation time via ptrace fork events, before
/// the child can run user code. Without `policy_fn`, lazy registration
/// is enough because no argv-based security decision is exposed.
///
/// The fast path is a single `RwLock` read: if the pid is already
/// tracked, we trust the entry. PID-identity correctness comes from
/// the per-child pidfd watcher — a process can't issue notifications
/// after it has exited, and the kernel won't recycle a PID until the
/// parent has waited (which we observe), so a stale entry has no
/// window in which to be hit. We deliberately do *not* re-stat
/// /proc/<pid>/stat on every notification.
pub(crate) fn register_pid_if_new(ctx: &Arc<SupervisorCtx>, pid: i32) -> bool {
    if ctx.processes.contains(pid) {
        return true;
    }

    let pidfd = match crate::sys::syscall::pidfd_open(pid as u32, 0) {
        Ok(fd) => fd,
        Err(_) => {
            // clone3 can create CLONE_THREAD tasks. Linux 6.9 added
            // PIDFD_THREAD so pidfd_open works for non-leader TIDs too.
            const PIDFD_THREAD: u32 = libc::O_EXCL as u32;
            match crate::sys::syscall::pidfd_open(pid as u32, PIDFD_THREAD) {
                Ok(fd) => fd,
                Err(_) => {
                    if matches!(read_tgid_of_tid(pid), Some(tgid) if ctx.processes.contains(tgid)) {
                        return true;
                    }
                    return false; // old kernel or process gone
                }
            }
        }
    };

    let key = match ctx.processes.register(pid) {
        Some(k) => k,
        None => return false, // process exited between pidfd_open and stat read
    };

    // Hand the pidfd to the watcher; it owns the fd's lifetime now.
    spawn_pid_watcher(Arc::clone(ctx), key, pidfd);
    true
}

fn read_tgid_of_tid(tid: i32) -> Option<i32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", tid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

pub(crate) async fn register_child_if_new(ctx: &Arc<SupervisorCtx>, pid: i32) {
    let _ = register_pid_if_new(ctx, pid);
}

/// Command sent to the per-trace ptrace worker after `prepare` returns.
enum TraceCmd {
    /// The seccomp `Continue` has been sent; resume and capture the fork event.
    Proceed,
    /// Tear down without proceeding (e.g. `send_response` failed).
    Abort,
}

/// Handle to a one-shot ptrace fork-tracking session.
///
/// ptrace *commands* (`PTRACE_SEIZE`, `GETEVENTMSG`, `DETACH`, …) are
/// per-tracer-thread — issuing one from a thread other than the one that
/// `SEIZE`d fails with `ESRCH`. (Only `waitpid` may be called cross-thread.)
/// So the whole command sequence — SEIZE, the post-`Continue` event wait, and
/// the final `PTRACE_DETACH` — runs inside one `spawn_blocking` worker
/// (`process_creation_worker`) pinned to a single thread. This handle only
/// carries the channels driving that worker plus the tracee tid (used by
/// `finish` to wake the worker's blocking wait on the failed-fork path); it
/// owns no ptrace state, so dropping it never issues a cross-thread ptrace op.
pub(crate) struct ProcessCreationTrace {
    cmd_tx: std::sync::mpsc::SyncSender<TraceCmd>,
    join: Option<tokio::task::JoinHandle<io::Result<bool>>>,
    /// The traced (forking) task's tid — `finish`'s watchdog signals it.
    caller_tid: i32,
    /// True once `finish`/`abort` has sent a command; gates the Drop fallback.
    signaled: bool,
}

impl Drop for ProcessCreationTrace {
    fn drop(&mut self) {
        // If neither `finish` nor `abort` ran (early return / panic between
        // `prepare` and `finish`), the worker is blocked waiting for a command.
        // Tell it to abort so it detaches the tracee on its own thread and
        // exits, rather than leaking a blocked blocking-pool thread.
        if !self.signaled {
            let _ = self.cmd_tx.send(TraceCmd::Abort);
        }
        // The dropped `join` handle detaches the worker task; it runs to
        // completion (performing the ptrace detach on its owning thread).
    }
}

fn is_process_creation_notif(notif: &SeccompNotif) -> bool {
    crate::arch::fork_like_syscalls().contains(&(notif.data.nr as i64))
}

/// True when `handle_fork` would have incremented the concurrent
/// process count for this notification if it returned `Continue`.
///
/// Mirrors the thread-vs-process decision in `handle_fork`: a clone or
/// clone3 with `CLONE_THREAD` does not bump the count, so a later
/// rollback would be wrong. The clone3 flag check involves a racy read
/// from child memory — see `clone_flags`.
pub(crate) fn fork_counted_on_continue(notif: &SeccompNotif, notif_fd: RawFd) -> bool {
    is_process_creation_notif(notif) && !is_thread_create(notif, notif_fd)
}

/// True when this notification can create a new task that must be in
/// `ProcessIndex` before it can race a later execve argv decision.
pub(crate) fn requires_process_creation_tracking(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    policy: &NotifPolicy,
) -> bool {
    policy.argv_safety_required && fork_counted_on_continue(notif, notif_fd)
}

/// Arm ptrace fork-event tracking on the syscall's calling task.
///
/// The caller is parked in the seccomp user-notification wait when this
/// runs. Crucially, the tracee **cannot reach a ptrace-stop until the
/// supervisor sends `Continue`** — so we must not `PTRACE_INTERRUPT`+wait
/// here (that deadlocks). Instead `prepare` only performs `PTRACE_SEIZE`
/// (which does not stop the tracee) on a dedicated worker thread, then
/// returns once SEIZE is confirmed. The worker parks until `finish` (called
/// after `Continue`) tells it to proceed, at which point it does the
/// `INTERRUPT` + event loop + detach — all on that same thread, as ptrace
/// requires.
pub(crate) async fn prepare_process_creation_tracking(
    ctx: &Arc<SupervisorCtx>,
    caller_tid: i32,
) -> io::Result<ProcessCreationTrace> {
    let ctx = Arc::clone(ctx);
    // SEIZE result, reported back as an errno so `io::Error` need not cross
    // the channel (it is not `Clone`/`Send`-friendly to reconstruct).
    let (attached_tx, attached_rx) = tokio::sync::oneshot::channel::<Result<(), i32>>();
    // Capacity 1: `finish`/`abort`/Drop send exactly one command; the send is
    // non-blocking and the worker is always waiting to receive it.
    let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel::<TraceCmd>(1);

    let join = tokio::task::spawn_blocking(move || {
        process_creation_worker(caller_tid, ctx, attached_tx, cmd_rx)
    });

    match attached_rx.await {
        Ok(Ok(())) => Ok(ProcessCreationTrace { cmd_tx, join: Some(join), caller_tid, signaled: false }),
        Ok(Err(errno)) => {
            let _ = join.await;
            Err(io::Error::from_raw_os_error(errno))
        }
        Err(_) => {
            // Worker dropped the sender without reporting (panic). Reap it.
            let _ = join.await;
            Err(io::Error::new(
                io::ErrorKind::Other,
                "process-creation worker exited before SEIZE",
            ))
        }
    }
}

/// Owns the entire ptrace lifecycle for one fork-tracking session on a single
/// thread. SEIZE happens before `Continue`; the `INTERRUPT` + event loop +
/// detach happen after, once `cmd_rx` delivers `Proceed`.
fn process_creation_worker(
    caller_tid: i32,
    ctx: Arc<SupervisorCtx>,
    attached_tx: tokio::sync::oneshot::Sender<Result<(), i32>>,
    cmd_rx: std::sync::mpsc::Receiver<TraceCmd>,
) -> io::Result<bool> {
    // SEIZE (does NOT stop the tracee) before `Continue`, so the child is born
    // traced/stopped once the fork runs. Because SEIZE itself never blocks on
    // a stop, it is safe against the seccomp-notify wait the tracee sits in.
    let opts = (libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACESYSGOOD) as libc::c_ulong;
    let ret = unsafe { libc::ptrace(libc::PTRACE_SEIZE as libc::c_uint, caller_tid, 0, opts) };
    if ret < 0 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EPERM);
        let _ = attached_tx.send(Err(errno));
        return Err(io::Error::from_raw_os_error(errno));
    }
    let _ = attached_tx.send(Ok(()));

    // Park until the orchestration confirms `Continue` was sent (Proceed) or
    // asks us to tear down (Abort).
    match cmd_rx.recv() {
        Ok(TraceCmd::Proceed) => {}
        Ok(TraceCmd::Abort) | Err(_) => {
            detach_traced(caller_tid);
            return Ok(false);
        }
    }

    // After `Continue`, watch for the fork-creation event (no INTERRUPT — see
    // `run_creation_event_loop`).
    let result = run_creation_event_loop(caller_tid, &ctx);
    detach_traced(caller_tid);
    result
}

fn detach_traced(tid: i32) {
    let _ = unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, 0, 0) };
}

fn wait_for_ptrace_stop(tid: i32) -> io::Result<libc::c_int> {
    let mut status: libc::c_int = 0;
    loop {
        let ret = unsafe { libc::waitpid(tid, &mut status, libc::__WALL) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        break;
    }

    if !libc::WIFSTOPPED(status) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected ptrace wait status: {status:#x}"),
        ));
    }
    Ok(status)
}


#[cfg(test)]
static CHILD_REGISTERED_HOOK: std::sync::Mutex<
    Option<Box<dyn Fn(i32) + Send + 'static>>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
fn child_registered_for_test(child_pid: i32) {
    if let Ok(guard) = CHILD_REGISTERED_HOOK.lock() {
        if let Some(hook) = guard.as_ref() {
            hook(child_pid);
        }
    }
}

/// Signal `finish`'s watchdog sends to the tracee to wake this blocking wait
/// when a fork created no child (a failed fork emits no ptrace event). SIGURG
/// is effectively unused by normal programs and ignored by default, so it is a
/// safe wake poke that we recognise and swallow.
const FORK_WATCHDOG_SIGNAL: libc::c_int = libc::SIGURG;

/// Watch the SEIZE'd parent for the fork-creation event after `Continue`.
///
/// Resolves to `Ok(true)` when the fork created a child (registered before it
/// can run user code) or `Ok(false)` when the fork-like syscall created none.
/// The caller (`process_creation_worker`) detaches the tracee afterward.
///
/// We request only fork events (PTRACE_O_TRACEFORK family), not syscall
/// tracing. A *successful* fork therefore stops the parent at
/// `PTRACE_EVENT_{FORK,VFORK,CLONE}` synchronously with the fork — with both
/// parent and child born stopped, so the child cannot run user code while we
/// register it. A *failed* fork produces no ptrace stop at all, so this would
/// block forever; `finish` bounds it by sending [`FORK_WATCHDOG_SIGNAL`] to the
/// tracee after a deadline, which we observe here as a signal-delivery-stop and
/// treat as "no child". (We do **not** `PTRACE_INTERRUPT` to force a stop —
/// that races the fork and is unreliable; and we do not busy-poll.)
fn run_creation_event_loop(caller_tid: i32, ctx: &Arc<SupervisorCtx>) -> io::Result<bool> {
    loop {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(caller_tid, &mut status, libc::__WALL) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            // Tracee exited / was killed out from under us: no child to track.
            return Ok(false);
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }

        let event = (status >> 16) & 0xffff;
        if event == libc::PTRACE_EVENT_FORK
            || event == libc::PTRACE_EVENT_VFORK
            || event == libc::PTRACE_EVENT_CLONE
        {
            return handle_fork_event(caller_tid, ctx);
        }

        let stopsig = libc::WSTOPSIG(status);
        if stopsig == FORK_WATCHDOG_SIGNAL {
            // `finish`'s watchdog fired: the fork-like syscall created no child
            // (it returned without a fork event, e.g. EAGAIN/ENOMEM). Swallow
            // the wake signal — the worker detaches the tracee next.
            return Ok(false);
        }

        // Some other signal-delivery-stop in the window: forward the pending
        // signal and keep waiting for the fork event.
        let inject = if stopsig == libc::SIGTRAP { 0 } else { stopsig as libc::c_ulong };
        ptrace_resume(caller_tid, libc::PTRACE_CONT, inject)?;
    }
}

/// `ptrace(request, tid, 0, data)` returning an error on failure.
fn ptrace_resume(tid: i32, request: libc::c_uint, data: libc::c_ulong) -> io::Result<()> {
    let ret = unsafe { libc::ptrace(request, tid, 0, data) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// On a `PTRACE_EVENT_{FORK,VFORK,CLONE}`: read the new child's pid, register
/// it in `ProcessIndex` (so the execve argv-freeze can enumerate it), then
/// detach the child so it can run. Runs on the worker thread.
fn handle_fork_event(caller_tid: i32, ctx: &Arc<SupervisorCtx>) -> io::Result<bool> {
    let mut child_pid: libc::c_ulong = 0;
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG as libc::c_uint,
            caller_tid,
            0,
            &mut child_pid,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let child_pid = child_pid as i32;
    if !register_pid_if_new(ctx, child_pid) {
        let _ = unsafe { libc::kill(child_pid, libc::SIGKILL) };
        detach_traced(child_pid);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("failed to register new child pid {child_pid}"),
        ));
    }
    #[cfg(test)]
    child_registered_for_test(child_pid);

    // The child is born stopped under PTRACE_O_TRACEFORK; wait for its
    // birth-stop, then detach so it can run. Result ignored: a racing exit is
    // possible and detach is harmless either way. The caller (parent) is
    // detached by `process_creation_worker`.
    let _ = wait_for_ptrace_stop(child_pid);
    detach_traced(child_pid);
    Ok(true)
}

/// Complete one-shot process-creation tracking after `Continue`.
///
/// Signals the worker (started in `prepare`) to proceed, then awaits its
/// result. All ptrace work happens on the worker's single thread; this only
/// drives it and bounds the failed-fork case.
pub(crate) async fn finish_process_creation_tracking(
    mut trace: ProcessCreationTrace,
) -> io::Result<bool> {
    /// Upper bound on how long to wait for the fork event. The event is
    /// delivered synchronously with the fork (sub-millisecond), so this only
    /// elapses for a fork that created no child (e.g. EAGAIN/ENOMEM).
    const FORK_EVENT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

    trace.signaled = true;
    let caller_tid = trace.caller_tid;
    // Send is non-blocking (capacity-1 channel, single sender) — the worker is
    // parked waiting to receive, then blocks in `waitpid` for the fork event.
    let _ = trace.cmd_tx.send(TraceCmd::Proceed);
    let mut join = trace.join.take().expect("join handle present until finish/abort");

    let join_err =
        |e| io::Error::new(io::ErrorKind::Other, format!("spawn_blocking join: {e}"));

    // Race the worker against a watchdog. The worker's `waitpid` is blocking, so
    // a *failed* fork (no ptrace event) would hang it forever; on the deadline
    // we poke the tracee so its `waitpid` returns and the worker reports "no
    // child". `kill` does not need the tracer thread, so this is safe from here.
    tokio::select! {
        res = &mut join => res.map_err(join_err)?,
        _ = tokio::time::sleep(FORK_EVENT_DEADLINE) => {
            unsafe { libc::kill(caller_tid, FORK_WATCHDOG_SIGNAL); }
            join.await.map_err(join_err)?
        }
    }
}

/// Tear down a tracking session whose `Continue` was never sent (e.g.
/// `send_response` failed). Signals the worker to abort; it detaches the
/// tracee on its own thread.
pub(crate) async fn abort_process_creation_tracking(mut trace: ProcessCreationTrace) {
    trace.signaled = true;
    let _ = trace.cmd_tx.send(TraceCmd::Abort);
    if let Some(join) = trace.join.take() {
        let _ = join.await;
    }
}

/// Handle wait4/waitid notifications — decrement the concurrent process count.
///
/// Only blocking waits reach the supervisor (WNOHANG/WNOWAIT calls are
/// filtered out by BPF and allowed without notification).  A blocking wait
/// will definitely reap a child, so we decrement before the kernel executes it.
pub(crate) async fn handle_wait(
    _notif: &SeccompNotif,
    resource: &Arc<Mutex<ResourceState>>,
) -> NotifAction {
    let mut rs = resource.lock().await;
    rs.proc_count = rs.proc_count.saturating_sub(1);
    NotifAction::Continue
}

/// Undo the optimistic process-count increment if a fork-like syscall
/// is denied after `handle_fork` allowed it.
pub(crate) async fn rollback_fork_count(resource: &Arc<Mutex<ResourceState>>) {
    let mut rs = resource.lock().await;
    rs.proc_count = rs.proc_count.saturating_sub(1);
}

/// Handle memory-related notifications (mmap, munmap, brk, mremap, shmget).
///
/// Tracks anonymous memory usage and enforces the configured memory limit.
pub(crate) async fn handle_memory(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    policy: &NotifPolicy,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;
    // Effective limit. A policy_fn can tighten the static ceiling at runtime
    // (`restrict_max_memory`), so read the live value when a callback is
    // active; otherwise use the static limit. The live value is seeded from
    // the static `max_memory` ceiling, and this handler is only registered
    // when that ceiling exists, so it is never the 0/unlimited sentinel.
    let limit = {
        let pfs = ctx.policy_fn.lock().await;
        pfs.live_policy
            .as_ref()
            .and_then(|lp| lp.read().ok().map(|l| l.max_memory_bytes))
            .unwrap_or(policy.max_memory_bytes)
    };

    let mut st = ctx.resource.lock().await;

    let kill = NotifAction::Kill { sig: libc::SIGKILL, pgid: notif.pid as i32 };

    if nr == libc::SYS_mmap {
        // args[1] = len, args[3] = flags
        let len = args[1];
        let flags = args[3];
        if (flags & MAP_ANONYMOUS) != 0 {
            if st.mem_used.saturating_add(len) > limit {
                return kill;
            }
            st.mem_used += len;
        }
    } else if nr == libc::SYS_munmap {
        // args[1] = len
        let len = args[1];
        st.mem_used = st.mem_used.saturating_sub(len);
    } else if nr == libc::SYS_brk {
        // args[0] = new_brk
        let new_brk = args[0];

        if new_brk == 0 {
            // Query: return Continue, kernel handles it.
            return NotifAction::Continue;
        }

        // Per-process brk base is in PerProcessState. Drop the global
        // ResourceState lock first to avoid lock ordering issues with
        // the per-process lock acquired below (per-process first,
        // then global, when both are needed).
        drop(st);
        let entry = match ctx.processes.entry_for(notif.pid as i32) {
            Some(e) => e,
            None => return NotifAction::Continue,
        };
        let mut perproc = entry.1.lock().await;
        let mut st = ctx.resource.lock().await;

        let base = *perproc.brk_base.get_or_insert(new_brk);
        if new_brk > base {
            let delta = new_brk - base;
            if st.mem_used.saturating_add(delta) > limit {
                return kill;
            }
            st.mem_used += delta;
            perproc.brk_base = Some(new_brk);
        } else if new_brk < base {
            let delta = base - new_brk;
            st.mem_used = st.mem_used.saturating_sub(delta);
            perproc.brk_base = Some(new_brk);
        }
    } else if nr == libc::SYS_mremap {
        // args[1] = old_len, args[2] = new_len
        let old_len = args[1];
        let new_len = args[2];

        if new_len > old_len {
            let growth = new_len - old_len;
            if st.mem_used.saturating_add(growth) > limit {
                return kill;
            }
            st.mem_used += growth;
        } else if new_len < old_len {
            let shrink = old_len - new_len;
            st.mem_used = st.mem_used.saturating_sub(shrink);
        }
    } else if nr == libc::SYS_shmget {
        // shmget(key, size, shmflg) — args[1] = size
        let size = args[1];
        if size > 0 && st.mem_used.saturating_add(size) > limit {
            return kill;
        }
        st.mem_used += size;
    }

    NotifAction::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::NetlinkState;
    use crate::seccomp::state::{
        ChrootState, CowState, NetworkState, PolicyFnState, ProcessIndex, ProcfsState,
        TimeRandomState,
    };
    use crate::sys::structs::{SeccompData, SeccompNotif};
    use std::ptr;

    const GO: isize = 0;
    const CHILD_RAN: isize = 1;
    const REGISTERED_BEFORE_RUN: isize = 2;
    const REGISTERED_PID: isize = 3;
    const DONE: isize = 4;
    const FORK_FAILED: isize = 5;
    const FLAGS_LEN: usize = 4096;

    fn fake_notif(nr: i64, arg0: u64) -> SeccompNotif {
        SeccompNotif {
            id: 0,
            pid: 1,
            flags: 0,
            data: SeccompData {
                nr: nr as i32,
                arch: 0,
                instruction_pointer: 0,
                args: [arg0, 0, 0, 0, 0, 0],
            },
        }
    }

    fn fake_policy(argv_safety_required: bool) -> NotifPolicy {
        NotifPolicy {
            max_memory_bytes: 0,
            max_processes: 0,
            has_memory_limit: false,
            has_net_destination_policy: false,
            has_bind_denylist: false,
            has_unix_fs_gate: false,
            has_random_seed: false,
            has_time_start: false,
            argv_safety_required,
            time_offset: 0,
            num_cpus: None,
            port_remap: false,
            cow_enabled: false,
            chroot_root: None,
            chroot_readable: Vec::new(),
            chroot_writable: Vec::new(),
            chroot_denied: Vec::new(),
            chroot_mounts: Vec::new(),
            chroot_mount_ro: Vec::new(),
            deterministic_dirs: false,
            virtual_hostname: None,
            has_http_acl: false,
            virtual_etc_hosts: String::new(),
            ca_inject_paths: Vec::new(),
            ca_inject_pem: None,
        }
    }

    fn fake_supervisor_ctx(argv_safety_required: bool) -> Arc<SupervisorCtx> {
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
            policy: Arc::new(fake_policy(argv_safety_required)),
            child_pidfd: None,
            notif_fd: -1,
        })
    }

    #[test]
    fn process_creation_tracking_predicates_follow_argv_safety_gate() {
        let no_argv_safety = fake_policy(false);
        let argv_safety = fake_policy(true);
        let clone_proc = fake_notif(libc::SYS_clone, 0);
        let clone_thread = fake_notif(libc::SYS_clone, CLONE_THREAD);
        let clone3 = fake_notif(libc::SYS_clone3, 0);
        let openat = fake_notif(libc::SYS_openat, 0);

        // notif_fd = -1: clone3's user-memory read fails (id_valid),
        // which fail-safes to "not a thread" → counted as process.
        // Matches the synthetic clone3 notif's expected accounting.
        let fd = -1;

        assert!(fork_counted_on_continue(&clone_proc, fd));
        assert!(!fork_counted_on_continue(&clone_thread, fd));
        assert!(fork_counted_on_continue(&clone3, fd));
        assert!(!fork_counted_on_continue(&openat, fd));

        assert!(!requires_process_creation_tracking(&clone_proc, fd, &no_argv_safety));
        assert!(requires_process_creation_tracking(&clone_proc, fd, &argv_safety));
        assert!(!requires_process_creation_tracking(&clone_thread, fd, &argv_safety));
        assert!(requires_process_creation_tracking(&clone3, fd, &argv_safety));
        assert!(!requires_process_creation_tracking(&openat, fd, &argv_safety));

        if let Some(fork_nr) = crate::arch::sys_fork() {
            let fork = fake_notif(fork_nr, 0);
            assert!(fork_counted_on_continue(&fork, fd));
            assert!(requires_process_creation_tracking(&fork, fd, &argv_safety));
        }
        if let Some(vfork_nr) = crate::arch::sys_vfork() {
            let vfork = fake_notif(vfork_nr, 0);
            assert!(fork_counted_on_continue(&vfork, fd));
            assert!(requires_process_creation_tracking(&vfork, fd, &argv_safety));
        }
    }

    struct SharedFlags {
        ptr: *mut i32,
    }

    impl SharedFlags {
        fn new() -> Self {
            let ptr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    FLAGS_LEN,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(ptr, libc::MAP_FAILED, "mmap shared flags");
            Self {
                ptr: ptr.cast::<i32>(),
            }
        }

        fn read(&self, slot: isize) -> i32 {
            unsafe { ptr::read_volatile(self.ptr.offset(slot)) }
        }

        fn write(&self, slot: isize, value: i32) {
            unsafe { ptr::write_volatile(self.ptr.offset(slot), value) };
        }

        fn addr(&self) -> usize {
            self.ptr as usize
        }
    }

    impl Drop for SharedFlags {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.ptr.cast(), FLAGS_LEN);
            }
        }
    }

    struct HookReset;

    impl Drop for HookReset {
        fn drop(&mut self) {
            if let Ok(mut hook) = CHILD_REGISTERED_HOOK.lock() {
                *hook = None;
            }
        }
    }

    struct CallerGuard {
        pid: i32,
        flags_addr: usize,
    }

    impl CallerGuard {
        fn new(pid: i32, flags: &SharedFlags) -> Self {
            Self {
                pid,
                flags_addr: flags.addr(),
            }
        }

        fn disarm(&mut self) {
            self.pid = 0;
        }
    }

    impl Drop for CallerGuard {
        fn drop(&mut self) {
            if self.pid <= 0 {
                return;
            }
            let flags = self.flags_addr as *mut i32;
            unsafe {
                ptr::write_volatile(flags.offset(GO), 1);
                ptr::write_volatile(flags.offset(DONE), 1);
                libc::kill(self.pid, libc::SIGKILL);
                let mut status = 0;
                let _ = libc::waitpid(self.pid, &mut status, 0);
            }
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
    unsafe fn caller_wait_then_fork(flags: *mut i32) -> ! {
        while ptr::read_volatile(flags.offset(GO)) == 0 {
            core::hint::spin_loop();
        }

        // x86_64 has a real fork(2) syscall; generic-ABI arches (aarch64, riscv64)
        // have none, so glibc fork() emulates it via clone(SIGCHLD). Either way the
        // kernel reports a PTRACE_EVENT_{FORK,CLONE}, which is what we track.
        #[cfg(target_arch = "x86_64")]
        let pid = libc::syscall(libc::SYS_fork) as i32;
        #[cfg(not(target_arch = "x86_64"))]
        let pid = libc::fork();
        if pid == 0 {
            ptr::write_volatile(flags.offset(CHILD_RAN), 1);
            while ptr::read_volatile(flags.offset(DONE)) == 0 {
                core::hint::spin_loop();
            }
            libc::_exit(0);
        }
        if pid > 0 {
            let mut status = 0;
            let _ = libc::waitpid(pid, &mut status, 0);
            libc::_exit(0);
        }

        ptr::write_volatile(flags.offset(FORK_FAILED), 1);
        libc::_exit(1);
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
    #[test]
    fn process_creation_tracking_registers_child_before_user_code_runs() {
        let flags = SharedFlags::new();
        let flags_addr = flags.addr();

        let caller = unsafe { libc::fork() };
        assert!(caller >= 0, "fork caller");
        if caller == 0 {
            unsafe { caller_wait_then_fork(flags.ptr) };
        }
        let mut caller_guard = CallerGuard::new(caller, &flags);

        let _hook_reset = HookReset;
        {
            let mut hook = CHILD_REGISTERED_HOOK.lock().expect("hook lock");
            *hook = Some(Box::new(move |child_pid| {
                let flags = flags_addr as *mut i32;
                unsafe {
                    let child_ran = ptr::read_volatile(flags.offset(CHILD_RAN));
                    ptr::write_volatile(flags.offset(REGISTERED_PID), child_pid);
                    ptr::write_volatile(
                        flags.offset(REGISTERED_BEFORE_RUN),
                        if child_ran == 0 { 1 } else { -1 },
                    );
                }
            }));
        }

        let ctx = fake_supervisor_ctx(true);
        let rt = tokio::runtime::Builder::new_current_thread()
            // `enable_all` (not just io): `finish_process_creation_tracking`
            // arms a `tokio::time` watchdog, which needs the time driver.
            .enable_all()
            .build()
            .expect("tokio runtime");
        let trace = match rt.block_on(prepare_process_creation_tracking(&ctx, caller)) {
            Ok(trace) => trace,
            Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
                eprintln!("skipping ptrace fork-event test: ptrace denied: {e}");
                return;
            }
            Err(e) => panic!("prepare process-creation tracking: {e}"),
        };

        flags.write(GO, 1);
        let created = rt
            .block_on(finish_process_creation_tracking(trace))
            .expect("finish process-creation tracking");
        assert!(created, "fork/clone should produce a ptrace process-creation event");

        let registered_pid = flags.read(REGISTERED_PID);
        assert!(registered_pid > 0, "child pid should be captured by hook");
        assert!(
            ctx.processes.contains(registered_pid),
            "child should be registered in ProcessIndex"
        );
        assert_eq!(
            flags.read(REGISTERED_BEFORE_RUN),
            1,
            "child should still be ptrace-stopped when registered"
        );

        flags.write(DONE, 1);
        let mut status = 0;
        let waited = unsafe { libc::waitpid(caller, &mut status, 0) };
        assert_eq!(waited, caller, "wait caller");
        assert_eq!(flags.read(FORK_FAILED), 0, "fork in caller failed");
        caller_guard.disarm();
    }
}
