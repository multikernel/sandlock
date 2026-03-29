// Resource limit handlers — memory and process limit enforcement.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::seccomp::notif::{NotifAction, NotifPolicy, SupervisorState};
use crate::sys::structs::{
    SeccompNotif, CLONE_NS_FLAGS, EAGAIN, ENOMEM, EPERM,
};

/// CLONE_THREAD flag — threads don't count toward process limit.
const CLONE_THREAD: u64 = 0x0001_0000;

/// MAP_ANONYMOUS flag — only anonymous mappings count toward memory limit.
const MAP_ANONYMOUS: u64 = 0x20;

/// Handle fork/clone/vfork notifications.
///
/// Enforces namespace creation ban, process limits, and checkpoint hold.
pub(crate) async fn handle_fork(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    _policy: &NotifPolicy,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;

    // For clone/vfork: check namespace flags in args[0].
    if nr == libc::SYS_clone || nr == libc::SYS_vfork {
        if nr == libc::SYS_clone && (args[0] & CLONE_NS_FLAGS) != 0 {
            return NotifAction::Errno(EPERM);
        }
        // For clone: if CLONE_THREAD is set, it's a thread — don't count, allow.
        if nr == libc::SYS_clone && (args[0] & CLONE_THREAD) != 0 {
            return NotifAction::Continue;
        }
    }
    // For clone3: BPF arg filter handles dangerous cases; proceed to limit check.

    let mut st = state.lock().await;

    // Checkpoint/freeze: hold the fork notification.
    if st.hold_forks {
        st.held_notif_ids.push(notif.id);
        return NotifAction::Hold;
    }

    // Enforce process limit.
    if st.proc_count >= st.max_processes {
        return NotifAction::Errno(EAGAIN);
    }

    st.proc_count += 1;
    st.proc_pids.insert(notif.pid as i32);

    NotifAction::Continue
}

/// Handle memory-related notifications (mmap, munmap, brk, mremap).
///
/// Tracks anonymous memory usage and enforces the configured memory limit.
pub(crate) async fn handle_memory(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    policy: &NotifPolicy,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;
    let limit = policy.max_memory_bytes;

    let mut st = state.lock().await;

    if nr == libc::SYS_mmap {
        // args[1] = len, args[3] = flags
        let len = args[1];
        let flags = args[3];
        if (flags & MAP_ANONYMOUS) != 0 {
            if st.mem_used.saturating_add(len) > limit {
                return NotifAction::Errno(ENOMEM);
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
        let pid = notif.pid as i32;

        if new_brk == 0 {
            // Query: return Continue, kernel handles it.
            return NotifAction::Continue;
        }

        let base = *st.brk_bases.entry(pid).or_insert(new_brk);

        if new_brk > base {
            let delta = new_brk - base;
            if st.mem_used.saturating_add(delta) > limit {
                return NotifAction::Errno(ENOMEM);
            }
            st.mem_used += delta;
            st.brk_bases.insert(pid, new_brk);
        } else if new_brk < base {
            let delta = base - new_brk;
            st.mem_used = st.mem_used.saturating_sub(delta);
            st.brk_bases.insert(pid, new_brk);
        }
    } else if nr == libc::SYS_mremap {
        // args[1] = old_len, args[2] = new_len
        let old_len = args[1];
        let new_len = args[2];

        if new_len > old_len {
            let growth = new_len - old_len;
            if st.mem_used.saturating_add(growth) > limit {
                return NotifAction::Errno(ENOMEM);
            }
            st.mem_used += growth;
        } else if new_len < old_len {
            let shrink = old_len - new_len;
            st.mem_used = st.mem_used.saturating_sub(shrink);
        }
    }

    NotifAction::Continue
}
