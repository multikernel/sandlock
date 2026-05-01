//! Freeze sibling threads of an execve caller before returning Continue.
//!
//! # Why
//!
//! Per `seccomp_unotify(2)`, after the supervisor responds with
//! `Continue`, the kernel re-reads the syscall's user-memory pointers
//! before executing the syscall. For execve, that means the kernel
//! re-reads `pathname` and the argv array from child memory. A racing
//! sibling thread of the calling tid can mutate that memory in the
//! window between the supervisor's response and the kernel's re-read,
//! defeating any decision policy_fn made on the values it inspected.
//!
//! This module closes the window for execve specifically. Before the
//! supervisor returns Continue, every sibling tid is `PTRACE_SEIZE`d
//! and `PTRACE_INTERRUPT`ed (which puts it in group-stop). The kernel
//! re-reads while no sibling is running. Then the supervisor releases
//! its hold on the seccomp notification.
//!
//! # Why this is essentially free for execve
//!
//! `execve(2)` already terminates all sibling threads as part of
//! `de_thread`. Freezing them moments earlier doesn't change observable
//! behavior — the kernel kills them anyway. We don't need to detach
//! explicitly; the siblings die with the rest of the thread group
//! during execve, and ptrace records associated with them are reaped
//! by the kernel.
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

use std::fs;
use std::io;

/// Enumerate sibling tids of `caller_tid` from `/proc/<caller_pid>/task/`.
/// `caller_tid` is excluded from the result.
fn list_siblings(caller_tid: i32) -> io::Result<Vec<i32>> {
    let dir = fs::read_dir(format!("/proc/{}/task", caller_tid))?;
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
        let tid: i32 = match name_str.parse() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if tid != caller_tid {
            tids.push(tid);
        }
    }
    Ok(tids)
}

/// `PTRACE_SEIZE` + `PTRACE_INTERRUPT` a single tid and wait for the
/// resulting group-stop. Returns `Ok(true)` if the tid is now stopped,
/// `Ok(false)` if the tid had already exited (ESRCH; nothing to do),
/// or an error if ptrace refused.
///
/// On a partial-progress failure (PTRACE_SEIZE succeeded but
/// PTRACE_INTERRUPT did not), the function detaches itself before
/// returning so the caller doesn't have to track partial state.
fn seize_and_interrupt(tid: i32) -> io::Result<bool> {
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
    // before returning so we don't leave the sibling traced-but-running.

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

    // Wait for the ptrace-stop. WNOHANG would race; we want to block
    // until the sibling is genuinely stopped. __WALL is needed because
    // siblings are threads (not children of the supervisor in the
    // traditional fork sense) and waitpid(2) by default ignores them.
    let mut status: i32 = 0;
    let _ = unsafe { libc::waitpid(tid, &mut status, libc::__WALL) };
    Ok(true)
}

/// Detach a previously-frozen sibling. Used to roll back partial
/// progress when a later sibling refuses to be frozen.
fn detach(tid: i32) {
    let _ = unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, 0, 0) };
}

/// Freeze all sibling threads of `caller_tid`.
///
/// Strict semantics: if any sibling refuses to be frozen, all
/// successfully-frozen siblings are detached (so they resume normally)
/// and the error is propagated. The caller is expected to deny the
/// execve with EPERM, preserving the invariant that exposed argv is
/// always TOCTOU-safe.
///
/// On success, returns the number of siblings frozen. The supervisor
/// does not actively detach on the success path — siblings die during
/// execve's `de_thread`, and the kernel reaps the ptrace state.
pub(crate) fn freeze_siblings_for_execve(caller_tid: i32) -> io::Result<usize> {
    let siblings = list_siblings(caller_tid)?;
    let mut frozen: Vec<i32> = Vec::with_capacity(siblings.len());
    for tid in siblings {
        match seize_and_interrupt(tid) {
            Ok(true) => frozen.push(tid),
            Ok(false) => continue, // already exited — fine
            Err(e) => {
                // Roll back: detach everything we already froze so they
                // resume normally, then fail.
                for ftid in &frozen {
                    detach(*ftid);
                }
                return Err(e);
            }
        }
    }
    Ok(frozen.len())
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

    #[test]
    fn list_siblings_excludes_self() {
        // Our own /proc/self/task always exists; just check we don't
        // see our own tid in the list.
        let our_tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
        let siblings = list_siblings(our_tid).unwrap();
        assert!(!siblings.contains(&our_tid));
    }

    #[test]
    fn requires_freeze_only_for_exec() {
        assert!(requires_freeze_on_continue(libc::SYS_execve));
        assert!(requires_freeze_on_continue(libc::SYS_execveat));
        assert!(!requires_freeze_on_continue(libc::SYS_openat));
        assert!(!requires_freeze_on_continue(libc::SYS_connect));
    }
}
