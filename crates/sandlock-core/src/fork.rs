//! COW fork — create lightweight clones of a sandboxed process.
//!
//! The template process runs `init_cmd` to load expensive state, then
//! enters a fork-ready loop. The parent calls `fork(N)` to create N
//! COW clones that share memory pages with the template. Each clone
//! receives `CLONE_ID=0..N-1` and execs `work_cmd`.
//!
//! Uses raw `fork()` syscall (NR 57 on x86_64). The supervisor
//! intercepts fork-like syscalls for process accounting and, when
//! `policy_fn` is active, child registration before user code runs.

use std::os::unix::io::RawFd;

// ============================================================
// Raw fork
// ============================================================

/// Raw fork() syscall — NR 57 on x86_64.
fn raw_fork() -> std::io::Result<i32> {
    #[cfg(target_arch = "x86_64")]
    const NR_FORK: i64 = 57;

    #[cfg(target_arch = "x86_64")]
    {
        let pid = unsafe { libc::syscall(NR_FORK) };
        if pid < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(pid as i32)
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 doesn't have fork(2), use clone with SIGCHLD only
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(pid)
        }
    }
}

// ============================================================
// Child side: fork-ready loop
// ============================================================

/// Fork N clones with per-clone stdout pipes.
///
/// `stdout_write_fds` contains the write ends of pipes created by the parent.
/// Each clone's stdout is dup2'd to its corresponding write fd.
///
/// Wire protocol on ctrl_fd:
///   N × 4 bytes: clone PIDs
///   (after clones finish) N × 4 bytes: exit codes
pub(crate) fn fork_ready_loop_fn(
    ctrl_fd: RawFd,
    n: u32,
    work_fn: &dyn Fn(u32),
    stdout_write_fds: &[RawFd],
) {
    let _ = unsafe { libc::fflush(std::ptr::null_mut()) };

    let mut pids = Vec::with_capacity(n as usize);

    for i in 0..n {
        match raw_fork() {
            Ok(0) => {
                // === Clone child ===
                unsafe { libc::close(ctrl_fd) };
                // Redirect stdout to this clone's pipe
                if (i as usize) < stdout_write_fds.len() && stdout_write_fds[i as usize] >= 0 {
                    unsafe { libc::dup2(stdout_write_fds[i as usize], 1) };
                }
                // Close all write fds (belong to other clones)
                for &wfd in stdout_write_fds {
                    if wfd >= 0 { unsafe { libc::close(wfd) }; }
                }
                unsafe { libc::setpgid(0, 0) };
                std::env::set_var("CLONE_ID", i.to_string());

                work_fn(i);
                unsafe { libc::fflush(std::ptr::null_mut()) };
                unsafe { libc::_exit(0) };
            }
            Ok(pid) => {
                pids.push(pid as u32);
            }
            Err(_) => {
                pids.push(0);
            }
        }
    }

    // Close all write ends in template (parent has the read ends)
    for &wfd in stdout_write_fds {
        if wfd >= 0 { unsafe { libc::close(wfd) }; }
    }

    // Send PIDs
    let pid_bytes: Vec<u8> = pids.iter().flat_map(|p| p.to_be_bytes()).collect();
    unsafe { libc::write(ctrl_fd, pid_bytes.as_ptr() as *const _, pid_bytes.len()) };

    // Wait for all clones and send exit codes
    let mut exit_codes = Vec::with_capacity(pids.len());
    for &pid in &pids {
        if pid > 0 {
            let mut status: i32 = 0;
            unsafe { libc::waitpid(pid as i32, &mut status, 0) };
            let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 };
            exit_codes.push(code as i32);
        } else {
            exit_codes.push(-1);
        }
    }
    let code_bytes: Vec<u8> = exit_codes.iter().flat_map(|c| c.to_be_bytes()).collect();
    unsafe { libc::write(ctrl_fd, code_bytes.as_ptr() as *const _, code_bytes.len()) };
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_fork() {
        let pid = raw_fork().unwrap();
        if pid == 0 {
            // child
            unsafe { libc::_exit(42) };
        }
        // parent
        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 42);
    }
}
