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
use std::mem;
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
    if Some(nr) == crate::arch::SYS_VFORK || Some(nr) == crate::arch::SYS_FORK {
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
    resource: &Arc<Mutex<ResourceState>>,
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
    crate::arch::FORK_LIKE_SYSCALLS.contains(&(notif.data.nr as i64))
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
    #[cfg(test)]
    child_registered_for_test(child_pid);

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
            has_net_allowlist: false,
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
            deterministic_dirs: false,
            hostname: None,
            has_http_acl: false,
            virtual_etc_hosts: None,
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

        if let Some(fork_nr) = crate::arch::SYS_FORK {
            let fork = fake_notif(fork_nr, 0);
            assert!(fork_counted_on_continue(&fork, fd));
            assert!(requires_process_creation_tracking(&fork, fd, &argv_safety));
        }
        if let Some(vfork_nr) = crate::arch::SYS_VFORK {
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

    #[cfg(target_arch = "x86_64")]
    unsafe fn caller_wait_then_raw_fork(flags: *mut i32) -> ! {
        while ptr::read_volatile(flags.offset(GO)) == 0 {
            core::hint::spin_loop();
        }

        let pid = libc::syscall(libc::SYS_fork) as i32;
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn process_creation_tracking_registers_child_before_user_code_runs() {
        let flags = SharedFlags::new();
        let flags_addr = flags.addr();

        let caller = unsafe { libc::fork() };
        assert!(caller >= 0, "fork caller");
        if caller == 0 {
            unsafe { caller_wait_then_raw_fork(flags.ptr) };
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
            .enable_io()
            .build()
            .expect("tokio runtime");
        let trace = match rt.block_on(prepare_process_creation_tracking(caller)) {
            Ok(trace) => trace,
            Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
                eprintln!("skipping ptrace fork-event test: ptrace denied: {e}");
                return;
            }
            Err(e) => panic!("prepare process-creation tracking: {e}"),
        };

        flags.write(GO, 1);
        let created = rt
            .block_on(finish_process_creation_tracking(&ctx, trace))
            .expect("finish process-creation tracking");
        assert!(created, "raw fork should produce a ptrace fork event");

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
        assert_eq!(flags.read(FORK_FAILED), 0, "raw fork failed in caller");
        caller_guard.disarm();
    }
}
