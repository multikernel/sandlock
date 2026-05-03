// Resource limit handlers — memory and process limit enforcement.
//
// Continue safety (issue #27): every `Continue` in this module is safe.
// All decisions here are on scalar register args (clone flags, mmap len,
// brk address, etc.) which are copied into the seccomp_notif struct at
// notification time — they are *not* pointers into racy user memory.
// The kernel's re-read of the syscall args after Continue comes from the
// suspended calling thread's saved registers, which a sibling thread
// cannot mutate. So even though we return Continue after taking a
// security-relevant action (e.g., counting an allocation against the
// memory limit), there is no TOCTOU substitution window for the values
// we examined.

use std::io;
use std::mem;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{spawn_pid_watcher, NotifAction, NotifPolicy};
use crate::seccomp::state::ResourceState;
use crate::sys::structs::{
    SeccompNotif, CLONE_NS_FLAGS, EAGAIN, EPERM,
};

/// CLONE_THREAD flag — threads don't count toward process limit.
const CLONE_THREAD: u64 = 0x0001_0000;

/// MAP_ANONYMOUS flag — only anonymous mappings count toward memory limit.
const MAP_ANONYMOUS: u64 = 0x20;

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
    resource: &Arc<Mutex<ResourceState>>,
    _policy: &NotifPolicy,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;

    // For clone/vfork: check namespace flags in args[0].
    if nr == libc::SYS_clone || Some(nr) == crate::arch::SYS_VFORK {
        if nr == libc::SYS_clone && (args[0] & CLONE_NS_FLAGS) != 0 {
            return NotifAction::Errno(EPERM);
        }
        // For clone: if CLONE_THREAD is set, it's a thread — don't count, allow.
        if nr == libc::SYS_clone && (args[0] & CLONE_THREAD) != 0 {
            return NotifAction::Continue;
        }
    }
    // For clone3: BPF arg filter handles dangerous cases; proceed to limit check.

    let mut rs = resource.lock().await;

    // Checkpoint/freeze: hold the fork notification.
    if rs.hold_forks {
        rs.held_notif_ids.push(notif.id);
        return NotifAction::Hold;
    }

    // Enforce concurrent process limit.
    if rs.proc_count >= rs.max_processes {
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

/// One-shot ptrace attachment around a fork-like syscall. RAII guard:
/// on drop, detaches the caller so the supervisor cannot leak a ptrace
/// relationship if a code path between `prepare_*` and `finish_*`
/// panics or returns early. Functions that complete the tracking and
/// detach explicitly should still hand the trace to a consuming
/// function (or let it fall out of scope) — duplicate `PTRACE_DETACH`
/// is harmless (returns ESRCH and is ignored).
pub(crate) struct ProcessCreationTrace {
    caller_tid: i32,
}

impl Drop for ProcessCreationTrace {
    fn drop(&mut self) {
        detach_traced(self.caller_tid);
    }
}

fn is_process_creation_notif(notif: &SeccompNotif) -> bool {
    let nr = notif.data.nr as i64;
    nr == libc::SYS_clone
        || nr == libc::SYS_clone3
        || Some(nr) == crate::arch::SYS_VFORK
        || Some(nr) == crate::arch::SYS_FORK
}

/// True when `handle_fork` would have incremented the concurrent
/// process count for this notification if it returned `Continue`.
pub(crate) fn fork_counted_on_continue(notif: &SeccompNotif) -> bool {
    if !is_process_creation_notif(notif) {
        return false;
    }
    let nr = notif.data.nr as i64;
    !(nr == libc::SYS_clone && (notif.data.args[0] & CLONE_THREAD) != 0)
}

/// True when this notification can create a new task that must be in
/// `ProcessIndex` before it can race a later execve argv decision.
pub(crate) fn requires_process_creation_tracking(
    notif: &SeccompNotif,
    policy: &NotifPolicy,
) -> bool {
    policy.argv_safety_required && fork_counted_on_continue(notif)
}

/// Arm ptrace fork-event tracking on the syscall's calling task.
///
/// The caller is stopped in seccomp user notification when this runs.
/// After the supervisor sends `Continue`, the kernel executes the
/// fork-like syscall and reports `PTRACE_EVENT_{FORK,VFORK,CLONE}`;
/// the new child is born traced/stopped, so we can register it before
/// detaching either task.
///
/// Runs the blocking `waitpid` on a tokio blocking-pool thread so the
/// notification handler's worker is not stalled if the wait stretches.
pub(crate) async fn prepare_process_creation_tracking(
    caller_tid: i32,
) -> io::Result<ProcessCreationTrace> {
    tokio::task::spawn_blocking(move || prepare_process_creation_tracking_blocking(caller_tid))
        .await
        .map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("spawn_blocking join: {e}"))
        })?
}

fn prepare_process_creation_tracking_blocking(
    caller_tid: i32,
) -> io::Result<ProcessCreationTrace> {
    let opts = (libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACESYSGOOD) as libc::c_ulong;
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SEIZE as libc::c_uint,
            caller_tid,
            0,
            opts,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Arm the RAII guard the moment SEIZE succeeds: any early return
    // from here to the end of this function detaches via Drop.
    let trace = ProcessCreationTrace { caller_tid };

    let ret = unsafe {
        libc::ptrace(libc::PTRACE_INTERRUPT as libc::c_uint, caller_tid, 0, 0)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    wait_for_ptrace_stop(caller_tid)?;

    // Arm a syscall-exit stop as a fallback. A successful fork-like
    // syscall reports PTRACE_EVENT_{FORK,VFORK,CLONE}; a failed one has
    // no child event, but it still reaches syscall-exit so the
    // supervisor will not block forever waiting for a child that was
    // never created.
    let ret = unsafe {
        libc::ptrace(libc::PTRACE_SYSCALL as libc::c_uint, caller_tid, 0, 0)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(trace)
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

fn syscall_stop_kind(tid: i32) -> io::Result<u8> {
    let mut info: libc::ptrace_syscall_info = unsafe { mem::zeroed() };
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO as libc::c_uint,
            tid,
            mem::size_of::<libc::ptrace_syscall_info>(),
            &mut info,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.op)
}

/// Complete one-shot process-creation tracking after `Continue`.
///
/// Runs the blocking `waitpid` on a tokio blocking-pool thread so the
/// notification handler's worker is not stalled.
pub(crate) async fn finish_process_creation_tracking(
    ctx: &Arc<SupervisorCtx>,
    trace: ProcessCreationTrace,
) -> io::Result<bool> {
    let ctx = Arc::clone(ctx);
    tokio::task::spawn_blocking(move || finish_process_creation_tracking_blocking(&ctx, trace))
        .await
        .map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("spawn_blocking join: {e}"))
        })?
}

fn finish_process_creation_tracking_blocking(
    ctx: &Arc<SupervisorCtx>,
    trace: ProcessCreationTrace,
) -> io::Result<bool> {
    // Every early return below relies on `trace`'s Drop to detach the
    // caller. The success path hands `trace` off to
    // `finish_process_creation_event`, which keeps the same guarantee.
    loop {
        let status = wait_for_ptrace_stop(trace.caller_tid)?;

        let event = (status >> 16) & 0xffff;
        let is_fork_event = event == libc::PTRACE_EVENT_FORK
            || event == libc::PTRACE_EVENT_VFORK
            || event == libc::PTRACE_EVENT_CLONE;
        if is_fork_event {
            return finish_process_creation_event(ctx, trace);
        }

        let stopsig = libc::WSTOPSIG(status);
        if event == 0 && stopsig == (libc::SIGTRAP | 0x80) {
            let op = syscall_stop_kind(trace.caller_tid)?;
            match op {
                libc::PTRACE_SYSCALL_INFO_ENTRY => {
                    let ret = unsafe {
                        libc::ptrace(
                            libc::PTRACE_SYSCALL as libc::c_uint,
                            trace.caller_tid,
                            0,
                            0,
                        )
                    };
                    if ret < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    continue;
                }
                libc::PTRACE_SYSCALL_INFO_EXIT => {
                    return Ok(false);
                }
                op => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("unexpected ptrace syscall stop kind: {op}"),
                    ));
                }
            }
        }

        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected ptrace event: {event}"),
        ));
    }
}

fn finish_process_creation_event(
    ctx: &Arc<SupervisorCtx>,
    trace: ProcessCreationTrace,
) -> io::Result<bool> {
    // `trace` detaches the caller on drop; the explicit child-side
    // detaches stay manual since the child is not held by the guard.
    let mut child_pid: libc::c_ulong = 0;
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG as libc::c_uint,
            trace.caller_tid,
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

    // Wait for the child's birth-traced ptrace-stop, then detach so it
    // can run. Result ignored: the child may have already proceeded
    // (PTRACE_O_TRACEFORK leaves it stopped, but a racing exit is
    // possible) — detach is harmless either way.
    let _ = wait_for_ptrace_stop(child_pid);
    detach_traced(child_pid);
    drop(trace);
    Ok(true)
}

/// Tear down a tracking session whose `Continue` was never sent
/// (e.g., `send_response` failed). Runs the blocking `waitpid` on the
/// tokio blocking pool.
pub(crate) async fn abort_process_creation_tracking(trace: ProcessCreationTrace) {
    let _ = tokio::task::spawn_blocking(move || abort_process_creation_tracking_blocking(trace))
        .await;
}

fn abort_process_creation_tracking_blocking(trace: ProcessCreationTrace) {
    // INTERRUPT + wait so we can detach cleanly from a known state;
    // the actual detach happens via `trace`'s Drop on scope exit.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_INTERRUPT as libc::c_uint,
            trace.caller_tid,
            0,
            0,
        )
    };
    if ret == 0 {
        let _ = wait_for_ptrace_stop(trace.caller_tid);
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
    let limit = policy.max_memory_bytes;

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
