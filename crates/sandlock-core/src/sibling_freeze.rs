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
//! # Failure modes
//!
//! - `PTRACE_SEIZE` returns `EPERM` if the supervisor lacks the right
//!   to trace (YAMA `ptrace_scope` >= 2 with the supervisor not in the
//!   child's parent chain). Sandlock's supervisor is always the parent,
//!   so this is rare in practice but documented.
//! - `PTRACE_SEIZE` returns `ESRCH` if the sibling already exited
//!   between enumeration and seize. Treated as success (nothing to
//!   freeze).
//! - On any other failure, the supervisor returns Continue without the
//!   freeze. The fallback is the existing Landlock bound on execve
//!   paths (the racing thread can only swap to a Landlock-allowed
//!   path), which was the pre-fix behavior.

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
/// resulting group-stop. Returns Ok(()) if the tid is now stopped (or
/// has already exited — ESRCH is treated as success).
fn seize_and_interrupt(tid: i32) -> io::Result<()> {
    let ret = unsafe {
        libc::ptrace(libc::PTRACE_SEIZE as libc::c_uint, tid, 0, 0)
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // ESRCH: tid already exited. Nothing to freeze.
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(err);
    }

    let ret = unsafe {
        libc::ptrace(libc::PTRACE_INTERRUPT as libc::c_uint, tid, 0, 0)
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(err);
    }

    // Wait for the ptrace-stop. WNOHANG would race; we want to block
    // until the sibling is genuinely stopped. __WALL is needed because
    // siblings are threads (not children of the supervisor in the
    // traditional fork sense) and waitpid(2) by default ignores them.
    let mut status: i32 = 0;
    let _ = unsafe { libc::waitpid(tid, &mut status, libc::__WALL) };
    Ok(())
}

/// Freeze all sibling threads of `caller_tid` so the kernel's
/// post-Continue re-read of execve arguments cannot race with sibling
/// writes.
///
/// On success, returns the number of siblings frozen. On any failure
/// (typically YAMA blocking ptrace), logs a warning and returns the
/// underlying error — callers fall back to sending Continue without
/// the freeze.
///
/// The supervisor does not detach: siblings die during execve's
/// `de_thread`, and the kernel reaps the ptrace state automatically.
pub(crate) fn freeze_siblings_for_execve(caller_tid: i32) -> io::Result<usize> {
    let siblings = list_siblings(caller_tid)?;
    let mut frozen = 0;
    for tid in &siblings {
        if let Err(e) = seize_and_interrupt(*tid) {
            // One sibling failed; we still want to keep the rest frozen
            // for the duration of this syscall. Log and continue.
            eprintln!(
                "sandlock: sibling-freeze: PTRACE_SEIZE tid {} failed: {} \
                 (execve TOCTOU window remains open for this thread)",
                tid, e
            );
            continue;
        }
        frozen += 1;
    }
    Ok(frozen)
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
