//! COW fork — create lightweight clones of a sandboxed process.
//!
//! The template process runs `init_cmd` to load expensive state, then
//! enters a fork-ready loop. The parent calls `fork(N)` to create N
//! COW clones that share memory pages with the template. Each clone
//! receives `CLONE_ID=0..N-1` and execs `work_cmd`.
//!
//! Uses raw `fork()` syscall (NR 57 on x86_64) to bypass seccomp
//! notification — the BPF filter only intercepts `clone`/`clone3`.

use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// ============================================================
// Control protocol
// ============================================================

const TRIGGER_FORK_BATCH: u8 = 0x04;

/// Send a length-prefixed message on the control fd.
fn send_bytes(fd: RawFd, data: &[u8]) {
    let len = (data.len() as u32).to_be_bytes();
    unsafe { libc::write(fd, len.as_ptr() as *const _, 4) };
    if !data.is_empty() {
        unsafe { libc::write(fd, data.as_ptr() as *const _, data.len()) };
    }
}

/// Receive a length-prefixed message from the control fd.
fn recv_bytes(fd: RawFd) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    let r = unsafe { libc::read(fd, len_buf.as_mut_ptr() as *mut _, 4) };
    if r < 4 {
        return None;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; len];
    let mut read = 0;
    while read < len {
        let n = unsafe { libc::read(fd, buf[read..].as_mut_ptr() as *mut _, len - read) };
        let n = if n <= 0 { return None; } else { n as usize };
        if n == 0 { return None; }
        read += n;
    }
    Some(buf)
}

// ============================================================
// Simple env batch serialization (no serde_json dependency)
// ============================================================

/// Format: "K=V\nK=V\n---\nK=V\n---\n..."  (--- separates entries)
fn serialize_env_batch(envs: &[HashMap<String, String>]) -> Vec<u8> {
    let mut buf = String::new();
    for (i, env) in envs.iter().enumerate() {
        if i > 0 { buf.push_str("---\n"); }
        for (k, v) in env {
            buf.push_str(k);
            buf.push('=');
            buf.push_str(v);
            buf.push('\n');
        }
    }
    buf.into_bytes()
}

fn parse_env_batch(data: &[u8]) -> Vec<HashMap<String, String>> {
    let text = String::from_utf8_lossy(data);
    text.split("---\n")
        .map(|section| {
            section.lines()
                .filter_map(|line| {
                    let (k, v) = line.split_once('=')?;
                    Some((k.to_string(), v.to_string()))
                })
                .collect()
        })
        .collect()
}

// ============================================================
// Raw fork (bypasses seccomp clone interception)
// ============================================================

/// Raw fork() syscall — NR 57 on x86_64.
/// Unlike clone/clone3, this is NOT intercepted by the seccomp notif filter.
fn raw_fork() -> std::io::Result<i32> {
    #[cfg(target_arch = "x86_64")]
    const NR_FORK: i64 = 57;
    #[cfg(target_arch = "aarch64")]
    const NR_FORK: i64 = -1; // aarch64 has no fork — use clone with minimal flags

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

/// Fork-ready loop (command-based) — runs in the sandbox child.
///
/// Blocks on the control fd waiting for fork commands. When a batch
/// fork command arrives, forks N times using raw fork(), sets CLONE_ID,
/// execs the work command, and sends PIDs back to the parent.
pub(crate) fn fork_ready_loop(ctrl_fd: RawFd, work_cmd: &[std::ffi::CString]) -> ! {
    loop {
        let mut trigger = [0u8; 1];
        let r = unsafe { libc::read(ctrl_fd, trigger.as_mut_ptr() as *mut _, 1) };
        match r {
            0 | -1 => break,
            _ => {}
        }

        if trigger[0] != TRIGGER_FORK_BATCH {
            continue;
        }

        // Read batch: JSON array of env maps
        let batch_json = match recv_bytes(ctrl_fd) {
            Some(b) => b,
            None => break,
        };

        // Parse: simple format "K=V\nK=V\n---\nK=V\n..." (--- separates envs)
        let env_list = parse_env_batch(&batch_json);
        let n = env_list.len();

        // Flush before forking
        let _ = unsafe { libc::fflush(std::ptr::null_mut()) };

        let mut pids = Vec::with_capacity(n);

        for env in &env_list {
            match raw_fork() {
                Ok(0) => {
                    // === Clone child ===
                    unsafe { libc::close(ctrl_fd) };
                    unsafe { libc::setpgid(0, 0) };

                    // Set environment
                    for (k, v) in env {
                        std::env::set_var(k, v);
                    }

                    // Exec work command
                    let argv_ptrs: Vec<*const libc::c_char> = work_cmd
                        .iter()
                        .map(|s| s.as_ptr())
                        .chain(std::iter::once(std::ptr::null()))
                        .collect();
                    unsafe { libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr()) };
                    unsafe { libc::_exit(127) };
                }
                Ok(pid) => {
                    pids.push(pid as u32);
                }
                Err(_) => {
                    pids.push(0); // fork failed
                }
            }
        }

        // Send all PIDs back in one write
        let pid_bytes: Vec<u8> = pids.iter().flat_map(|p| p.to_be_bytes()).collect();
        unsafe { libc::write(ctrl_fd, pid_bytes.as_ptr() as *const _, pid_bytes.len()) };
    }

    unsafe { libc::_exit(0) };
}

// ============================================================
// Parent side: request fork batch
// ============================================================

/// Request N forks from the template process.
///
/// Sends a batch fork command via the control fd and reads back N PIDs.
pub(crate) fn request_fork_batch(
    ctrl_fd: RawFd,
    n: usize,
    extra_env: &HashMap<String, String>,
) -> std::io::Result<Vec<i32>> {
    // Build env list: [{...extra, "CLONE_ID": "0"}, {..."CLONE_ID": "1"}, ...]
    let env_list: Vec<HashMap<String, String>> = (0..n)
        .map(|i| {
            let mut env = extra_env.clone();
            env.insert("CLONE_ID".into(), i.to_string());
            env
        })
        .collect();

    let batch_json = serialize_env_batch(&env_list);

    // Send trigger + payload
    let trigger = [TRIGGER_FORK_BATCH];
    if unsafe { libc::write(ctrl_fd, trigger.as_ptr() as *const _, 1) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    send_bytes(ctrl_fd, &batch_json);

    // Read N PIDs (4 bytes each, big-endian u32)
    let mut pid_buf = vec![0u8; n * 4];
    let mut read = 0;
    while read < pid_buf.len() {
        let r = unsafe { libc::read(ctrl_fd, pid_buf[read..].as_mut_ptr() as *mut _, pid_buf.len() - read) };
        let r = if r < 0 { return Err(std::io::Error::last_os_error()); } else { r as usize };
        if r == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "control fd closed during fork batch",
            ));
        }
        read += r;
    }

    let pids: Vec<i32> = pid_buf
        .chunks(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()) as i32)
        .collect();

    Ok(pids)
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
