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
/// Enforces namespace creation ban and process limits, registers the
/// new child in `ProcessIndex` (with an owned pidfd), and spawns a
/// per-child pidfd watcher that runs unified cleanup on exit.
///
/// Note: `notif.pid` here is the *parent* (the task issuing
/// clone/fork). The kernel hasn't run the syscall yet, so we don't
/// know the child's pid. The child is discovered and registered later,
/// on its first own seccomp notification, via `register_child_if_new`.
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
/// it: open a pidfd, record the canonical PidKey, and spawn the exit
/// watcher. Called from the supervisor's notification dispatcher
/// before per-syscall handlers run, so handlers can rely on
/// `ProcessIndex::key_for(notif.pid)` returning a fresh PidKey.
///
/// The fast path is a single `RwLock` read: if the pid is already
/// tracked, we trust the entry. PID-identity correctness comes from
/// the per-child pidfd watcher — a process can't issue notifications
/// after it has exited, and the kernel won't recycle a PID until the
/// parent has waited (which we observe), so a stale entry has no
/// window in which to be hit. We deliberately do *not* re-stat
/// /proc/<pid>/stat on every notification.
pub(crate) async fn register_child_if_new(ctx: &Arc<SupervisorCtx>, pid: i32) {
    if ctx.processes.contains(pid) {
        return;
    }

    let pidfd = match crate::sys::syscall::pidfd_open(pid as u32, 0) {
        Ok(fd) => fd,
        Err(_) => return, // old kernel or process gone — GC backstop will clean up
    };

    let key = match ctx.processes.register(pid) {
        Some(k) => k,
        None => return, // process exited between pidfd_open and stat read
    };

    // Hand the pidfd to the watcher; it owns the fd's lifetime now.
    spawn_pid_watcher(Arc::clone(ctx), key, pidfd);
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
