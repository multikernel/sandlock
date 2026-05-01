//! Freeze sandbox threads of an execve caller before returning Continue.
//!
//! # Why
//!
//! Per `seccomp_unotify(2)`, after the supervisor responds with
//! `Continue`, the kernel re-reads the syscall's user-memory pointers
//! before executing the syscall. For execve, that means the kernel
//! re-reads `pathname` and the argv array from child memory. Any task
//! that can write to that memory in the window between the supervisor's
//! inspection and the kernel's re-read can defeat the decision
//! `policy_fn` made on the values it saw.
//!
//! Two distinct task classes can write that memory:
//! 1. Sibling threads of the calling tid (same TGID; share `mm_struct`
//!    by definition).
//! 2. Peer processes in other TGIDs that alias the same pages via
//!    `MAP_SHARED` mappings (memfd, SysV shm, shared file mmap), or
//!    that share the calling task's `mm_struct` via
//!    `clone(CLONE_VM)` without `CLONE_THREAD`.
//!
//! `freeze_sandbox_for_execve` closes both classes. It enumerates every
//! TGID tracked in `ProcessIndex` (the canonical sandbox membership
//! set), walks `/proc/<tgid>/task` per TGID, and `PTRACE_SEIZE` +
//! `PTRACE_INTERRUPT` every TID. Together with the supervisor's
//! sequential notification dispatch (which prevents new clone/fork
//! notifications from being processed while the freeze is in flight),
//! every entity that could mutate argv is paused before the kernel
//! re-reads.
//!
//! # Sibling vs peer cleanup
//!
//! Sibling threads (same TGID as the caller) are killed by the kernel
//! during execve's `de_thread` step, so the supervisor never has to
//! detach them — their ptrace state is reaped along with the threads.
//!
//! Peer threads (different TGID) survive execve. The supervisor must
//! `PTRACE_DETACH` them after `NOTIF_SEND` so they can resume normal
//! execution. The freeze function returns the peer TID list for that
//! purpose; siblings are not returned because they need no follow-up.
//!
//! # Failure modes (strict)
//!
//! The freeze is an invariant: if the supervisor exposed argv to
//! `policy_fn` and the callback returned Allow, the kernel must re-read
//! the same memory the supervisor inspected. We refuse to silently
//! degrade — if the freeze cannot be established, the supervisor
//! denies the execve with `EPERM` rather than letting it proceed
//! without TOCTOU protection.
//!
//! - `PTRACE_SEIZE` returns `ESRCH` for a sibling that exited between
//!   enumeration and seize. Treated as success: there is no thread to
//!   race.
//! - Any other ptrace failure (YAMA `ptrace_scope` >= 2 outside the
//!   parent chain, another tracer attached, kernel resource limits)
//!   produces an error; siblings already frozen during the partial
//!   attempt are detached so they resume normally; the caller fails
//!   the syscall closed.

use std::collections::HashSet;
use std::fs;
use std::io;

/// Read the `State:` field from `/proc/<tid>/status`. Returns the
/// single-character state code (`R`, `S`, `D`, `T`, `t`, `Z`, `X`)
/// or `None` if the file or line is unreadable.
fn read_task_state(tid: i32) -> Option<char> {
    let status = fs::read_to_string(format!("/proc/{}/status", tid)).ok()?;
    let line = status.lines().find(|l| l.starts_with("State:"))?;
    // Format is "State:\t<char> (<word>)" — find the first non-space
    // character after the colon.
    line.split_whitespace().nth(1).and_then(|s| s.chars().next())
}

/// `PTRACE_SEIZE` + `PTRACE_INTERRUPT` a single tid and wait for the
/// confirmed ptrace-stop. Returns `Ok(true)` if the tid is now
/// ptrace-stopped (and must be detached later), `Ok(false)` if the
/// tid does not need to be ptrace-attached (already exited, or held
/// in an uninterruptible kernel wait where it cannot mutate user
/// memory), or an error if ptrace refused.
///
/// # Why we read `/proc/<tid>/status` first
///
/// A task in `TASK_UNINTERRUPTIBLE` (`State: D`) — most commonly the
/// vfork parent of the execve caller, suspended in `kernel_clone`
/// until its child execs — cannot enter ptrace-stop until its
/// kernel wait clears. For vfork specifically, the wait won't clear
/// until we send Continue, but we can't send Continue while we're
/// blocked in `waitpid` for that exact task. Naively waitpid'ing
/// would deadlock the supervisor.
///
/// Such tasks also don't *need* to be ptrace-attached: they can't
/// run user code while in uninterruptible wait, and therefore can't
/// mutate argv. The kernel is already holding them for us. We skip
/// the seize entirely and return `Ok(false)` so the caller does not
/// add them to the detach list.
///
/// On a partial-progress failure (PTRACE_SEIZE succeeded but
/// PTRACE_INTERRUPT did not), the function detaches itself before
/// returning so the caller doesn't have to track partial state.
fn seize_and_interrupt(tid: i32) -> io::Result<bool> {
    // Skip tasks the kernel is already holding for us. See doc above.
    if read_task_state(tid) == Some('D') {
        return Ok(false);
    }

    let ret = unsafe {
        libc::ptrace(libc::PTRACE_SEIZE as libc::c_uint, tid, 0, 0)
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(false); // already exited — nothing to freeze
        }
        return Err(err);
    }
    // PTRACE_SEIZE succeeded; from here, any error path must DETACH
    // before returning so we don't leave the task traced-but-running.

    let ret = unsafe {
        libc::ptrace(libc::PTRACE_INTERRUPT as libc::c_uint, tid, 0, 0)
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        let _ = unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, 0, 0) };
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(false);
        }
        return Err(err);
    }

    // Wait for the confirmed ptrace-stop. The task was not in
    // uninterruptible wait when we checked, so PTRACE_INTERRUPT
    // delivers within microseconds. `__WALL` is needed because
    // siblings are threads (not children of the supervisor in the
    // traditional fork sense) and waitpid(2) by default ignores them.
    let mut status: i32 = 0;
    let _ = unsafe { libc::waitpid(tid, &mut status, libc::__WALL) };
    Ok(true)
}

/// Detach a previously-frozen task. Used to roll back partial
/// progress when a later task refuses to be frozen, and to release
/// peer tasks after the kernel has re-read execve argv.
fn detach(tid: i32) {
    let _ = unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, 0, 0) };
}

/// Enumerate every TID in a TGID via `/proc/<tgid>/task/`. Linux
/// resolves `/proc/<any_tid>/task` to the same directory, so this
/// works whether `tgid` is the leader's PID or any TID in the group.
fn list_threads_of_tgid(tgid: i32) -> io::Result<Vec<i32>> {
    let dir = fs::read_dir(format!("/proc/{}/task", tgid))?;
    let mut tids = Vec::new();
    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        if let Ok(tid) = name_str.parse::<i32>() {
            tids.push(tid);
        }
    }
    Ok(tids)
}

/// Read the TGID containing `tid` from `/proc/<tid>/status`.
fn read_tgid_of_tid(tid: i32) -> io::Result<i32> {
    let status = fs::read_to_string(format!("/proc/{}/status", tid))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse Tgid: {}", e),
                )
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no Tgid: line in /proc/<tid>/status",
    ))
}

/// Outcome of a sandbox-wide freeze. The supervisor must call
/// `detach_peers(&outcome.peer_tids)` after `NOTIF_SEND` to let the
/// peer processes resume.
#[derive(Debug, Default)]
pub(crate) struct SandboxFreeze {
    /// TIDs in *other* TGIDs that were ptrace-stopped. These survive
    /// execve and must be detached so they can resume normal
    /// execution. Siblings of `caller_tid` are deliberately not in
    /// this list — execve's `de_thread` kills them and the kernel
    /// reaps their ptrace state automatically.
    pub peer_tids: Vec<i32>,
}

/// Freeze every sandbox thread that could mutate execve argv before
/// the kernel re-reads it.
///
/// Walks every TGID in `processes` (and defensively the caller's own
/// TGID), enumerates each TGID's threads via `/proc/<tgid>/task/`,
/// and `PTRACE_SEIZE` + `PTRACE_INTERRUPT` every TID except
/// `caller_tid`. Sibling threads of `caller_tid` and peer threads in
/// other TGIDs are both covered.
///
/// Strict semantics: if any task refuses to be frozen, every
/// already-frozen task is detached and the error is propagated. The
/// caller is expected to deny the execve with `EPERM`, preserving the
/// invariant that exposed argv is always TOCTOU-safe.
///
/// On success, returns the list of *peer* TIDs that survive execve and
/// must be detached after `NOTIF_SEND`. Sibling TIDs are not returned
/// because they die in `de_thread`.
pub(crate) fn freeze_sandbox_for_execve(
    processes: &crate::seccomp::state::ProcessIndex,
    caller_tid: i32,
) -> io::Result<SandboxFreeze> {
    let caller_tgid = read_tgid_of_tid(caller_tid)?;

    // ProcessIndex is the canonical sandbox membership set. The
    // supervisor's `register_child_if_new` runs before per-syscall
    // handlers, so the caller's TGID is guaranteed to be present.
    let tgids: HashSet<i32> = processes.pids_snapshot();

    let mut sibling_tids: Vec<i32> = Vec::new();
    let mut peer_tids: Vec<i32> = Vec::new();

    for tgid in &tgids {
        // /proc/<tgid>/task may disappear if the TGID exited between
        // snapshot and walk — that's fine, no threads to freeze.
        let tids = match list_threads_of_tgid(*tgid) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for tid in tids {
            if tid == caller_tid {
                continue;
            }
            match seize_and_interrupt(tid) {
                Ok(true) => {
                    if *tgid == caller_tgid {
                        sibling_tids.push(tid);
                    } else {
                        peer_tids.push(tid);
                    }
                }
                Ok(false) => continue, // already exited — fine
                Err(e) => {
                    // Roll back: detach every task we already froze
                    // (siblings + peers) so they resume normally.
                    for t in &sibling_tids {
                        detach(*t);
                    }
                    for t in &peer_tids {
                        detach(*t);
                    }
                    return Err(e);
                }
            }
        }
    }

    Ok(SandboxFreeze { peer_tids })
}

/// Detach peer TIDs after the kernel has re-read execve argv. Errors
/// are ignored: a peer that already exited returns ESRCH, which is
/// harmless.
pub(crate) fn detach_peers(peer_tids: &[i32]) {
    for tid in peer_tids {
        detach(*tid);
    }
}

/// Helper called from the dispatch hot path. Returns true if the
/// notification is for an execve-class syscall whose Continue response
/// requires freezing siblings.
pub(crate) fn requires_freeze_on_continue(syscall_nr: i64) -> bool {
    syscall_nr == libc::SYS_execve || syscall_nr == libc::SYS_execveat
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::state::ProcessIndex;

    #[test]
    fn list_threads_of_tgid_includes_self() {
        // Our own /proc/self/task always exists and always contains
        // at least our own tid.
        let our_tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
        let tids = list_threads_of_tgid(our_tid).unwrap();
        assert!(tids.contains(&our_tid));
    }

    #[test]
    fn requires_freeze_only_for_exec() {
        assert!(requires_freeze_on_continue(libc::SYS_execve));
        assert!(requires_freeze_on_continue(libc::SYS_execveat));
        assert!(!requires_freeze_on_continue(libc::SYS_openat));
        assert!(!requires_freeze_on_continue(libc::SYS_connect));
    }

    /// Regression test for the cross-process TOCTOU concern raised on
    /// issue #27 (Changaco): a peer process in the sandbox — different
    /// TGID, possibly aliasing argv pages via shared memory — must also
    /// be frozen before the kernel re-reads execve argv. Sibling-thread
    /// freeze alone (`freeze_siblings_for_execve`) does not cover this.
    ///
    /// This test registers a peer process in `ProcessIndex` and verifies
    /// that `freeze_sandbox_for_execve` puts it in ptrace-stop, the same
    /// way `freeze_siblings_for_execve` does for siblings.
    #[test]
    fn freeze_sandbox_includes_peer_process() {
        use std::process::{Command, Stdio};

        let mut peer = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn peer sleep");
        let peer_pid = peer.id() as i32;

        // Give the peer a moment to actually be running.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Register the peer in a fresh ProcessIndex (mirrors what the
        // supervisor's clone/fork notification handler would do).
        let processes = ProcessIndex::new();
        processes
            .register(peer_pid)
            .expect("register peer in ProcessIndex");

        let our_tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;

        let outcome = freeze_sandbox_for_execve(&processes, our_tid)
            .expect("freeze_sandbox_for_execve");

        // Peer's TID is its own TGID (single-threaded sleep), and it's
        // a different TGID from ours, so it should be in peer_tids.
        assert!(
            outcome.peer_tids.contains(&peer_pid),
            "peer pid {} should be in peer_tids: {:?}",
            peer_pid,
            outcome.peer_tids
        );

        // Verify the peer is actually ptrace-stopped via /proc.
        let status = std::fs::read_to_string(format!("/proc/{}/status", peer_pid))
            .expect("read peer status");
        let state_line = status
            .lines()
            .find(|l| l.starts_with("State:"))
            .expect("State: line");
        assert!(
            state_line.contains("t (tracing stop)") || state_line.contains("T (stopped)"),
            "peer should be ptrace-stopped, got: {}",
            state_line
        );

        // Cleanup: detach the peer so it can resume and be killed.
        detach_peers(&outcome.peer_tids);
        let _ = peer.kill();
        let _ = peer.wait();
    }
}
