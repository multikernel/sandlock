use sandlock_core::Sandbox;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// Exit codes for the pty-session helper child, so a failure names its cause.
const EXIT_OK: i32 = 0;
const EXIT_NOT_FOREGROUND_AT_START: i32 = 10;
const EXIT_RUN_FAILED: i32 = 11;
const EXIT_FOREGROUND_STOLEN: i32 = 12;
const EXIT_FOREGROUND_NOT_TAKEN: i32 = 13;
const EXIT_FOREGROUND_NOT_RESTORED: i32 = 14;
const EXIT_BACKGROUND_RUN_FAILED: i32 = 15;

const PTY_SESSION: &str = "SANDLOCK_TEST_TTY_SESSION";
const SHELL_PGRP: &str = "SANDLOCK_TEST_TTY_SHELL_PGRP";

fn rerun_self(test: &str) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([test, "--exact", "--nocapture"])
        .stdout(Stdio::null());
    cmd
}

/// Exit code of `child`, or `None` if it was signalled or outlived the deadline.
fn wait_exit_code(mut child: Child) -> Option<i32> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Re-run `test` in a fresh session whose controlling terminal is a new pty
/// (slave on stdin); there `f` runs and its return value is the exit code.
///
/// The tty-foreground behavior under test only manifests when stdin is the
/// controlling terminal of the sandbox parent's session: `tcsetpgrp` from
/// the sandboxed child is a no-op otherwise. The helper is exec'd rather than
/// forked: a forked copy of the threaded test harness inherits locks held by
/// threads it does not have, and hung on one.
fn run_in_pty_session(test: &str, f: fn() -> i32) -> i32 {
    if std::env::var_os(PTY_SESSION).is_some() {
        if unsafe { libc::tcgetpgrp(0) != libc::getpgrp() } {
            std::process::exit(EXIT_NOT_FOREGROUND_AT_START);
        }
        std::process::exit(f());
    }

    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let ret = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        ret,
        0,
        "openpty failed: {}",
        std::io::Error::last_os_error()
    );
    // Held until the helper exits, so the slave side stays a live terminal
    // for the whole run.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };

    let mut cmd = rerun_self(test);
    cmd.env(PTY_SESSION, "1").stdin(Stdio::from(slave));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let helper = cmd.spawn().expect("failed to start the pty-session helper");
    let code = wait_exit_code(helper);
    drop(master);
    code.expect("pty-session helper was signalled or hung")
}

fn test_policy() -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .build()
        .unwrap()
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

/// A captured (non-interactive) `run` must leave the terminal's foreground
/// process group with the caller. Stealing it demotes the caller to a
/// background job: its next stdin read raises SIGTTIN and a job-control
/// shell reports it "Stopped" (issue #164, problem 2).
#[test]
fn captured_run_leaves_tty_foreground_with_caller() {
    let code = run_in_pty_session(
        "test_tty::captured_run_leaves_tty_foreground_with_caller",
        || {
            let result = block_on(test_policy().with_name("tty-captured").run(&["true"]));
            match result {
                Ok(r) if r.success() => {}
                _ => return EXIT_RUN_FAILED,
            }
            if unsafe { libc::tcgetpgrp(0) != libc::getpgrp() } {
                return EXIT_FOREGROUND_STOLEN;
            }
            EXIT_OK
        },
    );
    assert_eq!(
        code, EXIT_OK,
        "helper exit {code} (10=no tty foreground at start, 11=run failed, \
         12=captured run stole the tty foreground group)"
    );
}

/// After an interactive run completes, the terminal foreground group must
/// be back with the caller. The CLI's parent shell restores itself when the
/// whole process exits, but an API user embedding an interactive run keeps
/// living on the same terminal afterward.
#[test]
fn interactive_run_returns_tty_foreground_after_exit() {
    let code = run_in_pty_session(
        "test_tty::interactive_run_returns_tty_foreground_after_exit",
        || {
            let mut policy = test_policy().with_name("tty-interactive");
            let result = block_on(policy.run_interactive(&["true"]));
            match result {
                Ok(r) if r.success() => {}
                _ => return EXIT_RUN_FAILED,
            }
            if unsafe { libc::tcgetpgrp(0) != libc::getpgrp() } {
                return EXIT_FOREGROUND_NOT_RESTORED;
            }
            EXIT_OK
        },
    );
    assert_eq!(
        code, EXIT_OK,
        "helper exit {code} (10=no tty foreground at start, 11=run failed, \
         14=tty foreground not returned to the caller after the run)"
    );
}

/// Interactive runs hand the terminal to the sandboxed child while it is
/// alive (so shells can read from the tty), and return it to the caller
/// once the child is reaped, including the kill path.
#[test]
fn interactive_run_hands_tty_foreground_to_child_while_alive() {
    let code = run_in_pty_session(
        "test_tty::interactive_run_hands_tty_foreground_to_child_while_alive",
        || {
            block_on(async {
                let mut policy = test_policy().with_name("tty-handover");
                if policy.spawn_interactive(&["sleep", "30"]).await.is_err() {
                    return EXIT_RUN_FAILED;
                }
                let child = match policy.pid() {
                    Some(p) => p,
                    None => return EXIT_RUN_FAILED,
                };
                // The child runs in its reaper's group, not one it leads.
                if unsafe { libc::tcgetpgrp(0) != libc::getpgid(child) } {
                    return EXIT_FOREGROUND_NOT_TAKEN;
                }
                if policy.kill().is_err() {
                    return EXIT_RUN_FAILED;
                }
                if policy.wait().await.is_err() {
                    return EXIT_RUN_FAILED;
                }
                if unsafe { libc::tcgetpgrp(0) != libc::getpgrp() } {
                    return EXIT_FOREGROUND_NOT_RESTORED;
                }
                EXIT_OK
            })
        },
    );
    assert_eq!(
        code, EXIT_OK,
        "helper exit {code} (10=no tty foreground at start, 11=spawn/kill/wait failed, \
         13=child never got the tty foreground, 14=tty foreground not returned after reap)"
    );
}

/// A job that outlives main can take the terminal back after wait() returned
/// it; shutdown() kills that job and must not leave the caller in the
/// background.
#[test]
fn shutdown_returns_tty_foreground_taken_by_a_job() {
    if !std::path::Path::new("/usr/bin/python3").exists() {
        return;
    }
    let code = run_in_pty_session(
        "test_tty::shutdown_returns_tty_foreground_taken_by_a_job",
        || {
            block_on(async {
                let name = format!("tty-job-steal-{}", std::process::id());
                let mut policy = test_policy().with_name(&name);
                let script = "import os, signal, time\n\
                          signal.signal(signal.SIGTTOU, signal.SIG_IGN)\n\
                          if os.fork() == 0:\n    \
                              time.sleep(0.3)\n    \
                              os.tcsetpgrp(0, os.getpgrp())\n    \
                              time.sleep(60)\n";
                if policy
                    .spawn_interactive(&["python3", "-c", script])
                    .await
                    .is_err()
                {
                    return EXIT_RUN_FAILED;
                }
                if policy.wait().await.is_err() {
                    return EXIT_RUN_FAILED;
                }
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while unsafe { libc::tcgetpgrp(0) == libc::getpgrp() } {
                    if std::time::Instant::now() > deadline {
                        return EXIT_FOREGROUND_NOT_TAKEN;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                if policy.shutdown().await.is_err() {
                    return EXIT_RUN_FAILED;
                }
                if unsafe { libc::tcgetpgrp(0) != libc::getpgrp() } {
                    return EXIT_FOREGROUND_NOT_RESTORED;
                }
                EXIT_OK
            })
        },
    );
    assert_eq!(
        code, EXIT_OK,
        "helper exit {code} (10=no tty foreground at start, 11=spawn/wait/shutdown failed, \
         13=the job never took the tty foreground, 14=tty foreground not returned after shutdown)"
    );
}

/// A run started from a background job (`sandlock run ... &`) must leave the
/// terminal with the foreground group. Taking it makes the login shell read
/// EIO from its tty, which it treats as EOF, so it exits and ends the ssh
/// session.
#[test]
fn background_run_leaves_tty_foreground_with_shell() {
    const TEST: &str = "test_tty::background_run_leaves_tty_foreground_with_shell";
    if let Ok(shell_pgrp) = std::env::var(SHELL_PGRP) {
        std::process::exit(background_job(shell_pgrp.parse().unwrap()));
    }
    let code = run_in_pty_session(TEST, || {
        let shell_pgrp = unsafe { libc::getpgrp() };
        let job = rerun_self(TEST)
            .env(SHELL_PGRP, shell_pgrp.to_string())
            .process_group(0)
            .spawn();
        let Ok(job) = job else {
            return EXIT_RUN_FAILED;
        };
        match wait_exit_code(job) {
            Some(EXIT_OK) => {}
            Some(code) => return code,
            None => return EXIT_BACKGROUND_RUN_FAILED,
        }
        if unsafe { libc::tcgetpgrp(0) != shell_pgrp } {
            return EXIT_FOREGROUND_STOLEN;
        }
        EXIT_OK
    });
    assert_eq!(
        code, EXIT_OK,
        "helper exit {code} (10=no tty foreground at start, 11=background job did not start, \
         12=background run took the tty foreground from the shell, \
         15=background spawn/kill/wait failed)"
    );
}

fn background_job(shell_pgrp: libc::pid_t) -> i32 {
    block_on(async {
        let name = format!("tty-background-{}", std::process::id());
        let mut policy = test_policy().with_name(&name);
        if policy.spawn_interactive(&["sleep", "30"]).await.is_err() {
            return EXIT_BACKGROUND_RUN_FAILED;
        }
        let stolen = unsafe { libc::tcgetpgrp(0) != shell_pgrp };
        if policy.kill().is_err() || policy.wait().await.is_err() {
            return EXIT_BACKGROUND_RUN_FAILED;
        }
        if stolen {
            EXIT_FOREGROUND_STOLEN
        } else {
            EXIT_OK
        }
    })
}
