//! The confined in-sandbox PID-1 (`sandlock-init`) control loop and its wire
//! protocol.
//!
//! [`run_init`] is the loop: it reads [`Req`] messages on [`CONTROL_FD`] and
//! fork-execs the workload (`RunMain`) and additional `exec`'d commands
//! (`RunExec`). Every child inherits this process's seccomp filter and Landlock
//! ruleset, so they share the one supervisor. When the main workload exits, the
//! container is done: the loop kills the process group and exits.
//!
//! It runs **in-process** in the confined fork (see
//! `Sandbox::create_with_in_child_main`), not as a separately-exec'd binary:
//! the child is already a fork of the supervisor, so this code is mapped, and
//! nothing is exec'd for init itself, which sidesteps Landlock having to
//! authorize an execve of a path-less image.

pub mod proto;
mod fdrecv;

pub use proto::{Req, Resp, CONTROL_FD};

use std::ffi::CString;
use std::os::unix::io::RawFd;

fn send(fd: RawFd, resp: &Resp) {
    if let Ok(mut v) = serde_json::to_vec(resp) {
        v.push(b'\n');
        unsafe {
            libc::write(fd, v.as_ptr() as *const _, v.len());
        }
    }
}

/// fork+exec `argv` with optional cwd/env and optional stdio fds (0,1,2).
/// Returns the child pid, or -1 on fork failure.
fn spawn(
    argv: &[String],
    env: &[(String, String)],
    cwd: &Option<String>,
    stdio: Option<[RawFd; 3]>,
) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid != 0 {
        return pid;
    }
    // child
    if let Some(fds) = stdio {
        for (i, &fd) in fds.iter().enumerate() {
            unsafe {
                libc::dup2(fd, i as i32);
            }
        }
        for &fd in &fds {
            if fd > 2 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
    if let Some(c) = cwd {
        if let Ok(cs) = CString::new(c.as_str()) {
            unsafe {
                libc::chdir(cs.as_ptr());
            }
        }
    }
    for (k, v) in env {
        std::env::set_var(k, v);
    }
    let cargv: Vec<CString> = argv.iter().filter_map(|a| CString::new(a.as_str()).ok()).collect();
    let mut ptrs: Vec<*const libc::c_char> = cargv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // Under chroot the sandlock seccomp exec handler rewrites the pathname in
    // place (to /proc/self/fd/N for the injected binary fd). Pass a separate
    // PATH_MAX buffer as the `file` argument so that rewrite cannot clobber
    // argv[0], which busybox-style binaries use for applet detection. execvp
    // still does PATH lookup for bare command names against this buffer.
    if let Some(first) = cargv.first() {
        let orig = first.as_bytes_with_nul();
        let mut exec_path = vec![0u8; libc::PATH_MAX as usize];
        exec_path[..orig.len()].copy_from_slice(orig);
        unsafe {
            libc::execvp(exec_path.as_ptr() as *const libc::c_char, ptrs.as_ptr());
        }
    }
    unsafe { libc::_exit(127) };
}

fn wait_exit(pid: i32) -> (Option<i32>, Option<i32>) {
    let mut status = 0i32;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return (None, None); // genuine waitpid error: do not fabricate an exit
        }
        break;
    }
    if libc::WIFEXITED(status) {
        (Some(libc::WEXITSTATUS(status)), None)
    } else if libc::WIFSIGNALED(status) {
        (None, Some(libc::WTERMSIG(status)))
    } else {
        (None, None)
    }
}

/// Run the confined PID-1 control loop on [`CONTROL_FD`]. Returns when the
/// daemon closes the channel or sends `Shutdown`; the main-workload reaper may
/// `_exit` the process first when the workload exits.
///
/// This runs in the confined fork created by
/// `Sandbox::create_with_in_child_main`; it uses only `libc` + `serde_json`
/// (heap allocation only, which glibc makes fork-safe via its atfork handler)
/// and never touches the supervisor's async runtime.
pub fn run_init() {
    let ctl = CONTROL_FD;
    let mut main_pid: i32 = -1;
    loop {
        let (bytes, fds) = match fdrecv::recv(ctl, 3) {
            Ok(p) => p,
            Err(_) => break,
        };
        if bytes.is_empty() {
            break;
        } // daemon closed the channel
          // Trim trailing ASCII whitespace before parsing.
        let trimmed = &bytes[..bytes.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(0, |i| i + 1)];
        let req: Req = match serde_json::from_slice(trimmed) {
            Ok(r) => r,
            Err(e) => {
                send(ctl, &Resp::Err { msg: e.to_string() });
                continue;
            }
        };
        match req {
            Req::RunMain { argv, env, cwd } => {
                let pid = spawn(&argv, &env, &cwd, None);
                if pid < 0 {
                    send(ctl, &Resp::Err { msg: "fork failed".into() });
                    continue;
                }
                main_pid = pid;
                // main shares the process group already (init is the leader).
                send(ctl, &Resp::Started { pid });
                // Reap the workload in a dedicated thread so the loop keeps
                // serving exec; on its exit, tear the container down.
                let ctl2 = ctl;
                std::thread::spawn(move || {
                    let (code, signal) = wait_exit(pid);
                    if code.is_some() || signal.is_some() {
                        send(ctl2, &Resp::Exited { pid, code, signal });
                        unsafe {
                            libc::killpg(libc::getpgrp(), libc::SIGKILL);
                            // _exit rather than std::process::exit: this is a
                            // fork of the supervisor, so atexit handlers would
                            // run inherited (tokio/glibc) cleanup.
                            libc::_exit(0);
                        }
                    }
                });
            }
            Req::RunExec { argv, env, cwd, detach } => {
                if fds.len() < 3 {
                    for &fd in &fds {
                        unsafe {
                            libc::close(fd);
                        }
                    }
                    send(ctl, &Resp::Err { msg: "exec needs 3 fds".into() });
                    continue;
                }
                let stdio = [fds[0], fds[1], fds[2]];
                let pid = spawn(&argv, &env, &cwd, Some(stdio));
                for &fd in &fds {
                    unsafe {
                        libc::close(fd);
                    }
                } // parent drops its copies
                if pid < 0 {
                    send(ctl, &Resp::Err { msg: "fork failed".into() });
                    continue;
                }
                send(ctl, &Resp::Started { pid });
                if !detach {
                    let ctl2 = ctl;
                    std::thread::spawn(move || {
                        let (code, signal) = wait_exit(pid);
                        send(ctl2, &Resp::Exited { pid, code, signal });
                    });
                } else {
                    std::thread::spawn(move || {
                        let _ = wait_exit(pid);
                    });
                }
            }
            Req::Shutdown => {
                if main_pid > 0 {
                    unsafe {
                        libc::killpg(libc::getpgrp(), libc::SIGKILL);
                    }
                }
                break;
            }
        }
    }
}
