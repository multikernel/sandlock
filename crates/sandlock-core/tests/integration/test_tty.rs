use sandlock_core::Sandbox;

// Exit codes for the pty-session helper child, so a failure names its cause.
const EXIT_OK: i32 = 0;
const EXIT_NOT_FOREGROUND_AT_START: i32 = 10;
const EXIT_RUN_FAILED: i32 = 11;
const EXIT_FOREGROUND_STOLEN: i32 = 12;
const EXIT_FOREGROUND_NOT_TAKEN: i32 = 13;

/// Fork a child into a fresh session whose controlling terminal is a new
/// pty (slave on stdin), then run `f` there and return its exit code.
///
/// The tty-foreground behavior under test only manifests when stdin is the
/// controlling terminal of the sandbox parent's session: `tcsetpgrp` from
/// the sandboxed child is a no-op otherwise. The test binary has no
/// controlling tty of its own to give up, so each test gets one this way.
fn run_in_pty_session(f: fn() -> i32) -> i32 {
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
    assert_eq!(ret, 0, "openpty failed: {}", std::io::Error::last_os_error());

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

    if pid == 0 {
        unsafe {
            libc::close(master);
            if libc::setsid() < 0 {
                libc::_exit(100);
            }
            if libc::ioctl(slave, libc::TIOCSCTTY, 0) != 0 {
                libc::_exit(101);
            }
            if libc::dup2(slave, 0) < 0 {
                libc::_exit(102);
            }
            if slave != 0 {
                libc::close(slave);
            }
            if libc::tcgetpgrp(0) != libc::getpgrp() {
                libc::_exit(EXIT_NOT_FOREGROUND_AT_START);
            }
            libc::_exit(f());
        }
    }

    unsafe { libc::close(slave) };
    let mut status: i32 = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    // Close the master only after the child exits, so the slave side stays
    // a live terminal for the whole run.
    unsafe { libc::close(master) };
    assert_eq!(ret, pid, "waitpid failed: {}", std::io::Error::last_os_error());
    assert!(libc::WIFEXITED(status), "helper child did not exit normally: status {status}");
    libc::WEXITSTATUS(status)
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
    let code = run_in_pty_session(|| {
        let result = block_on(test_policy().with_name("tty-captured").run(&["true"]));
        match result {
            Ok(r) if r.success() => {}
            _ => return EXIT_RUN_FAILED,
        }
        if unsafe { libc::tcgetpgrp(0) != libc::getpgrp() } {
            return EXIT_FOREGROUND_STOLEN;
        }
        EXIT_OK
    });
    assert_eq!(
        code, EXIT_OK,
        "helper exit {code} (10=no tty foreground at start, 11=run failed, \
         12=captured run stole the tty foreground group)"
    );
}

/// Interactive runs hand the terminal to the sandboxed child so shells can
/// read from the tty. The foreground group observed after the run is the
/// child's, not the caller's.
#[test]
fn interactive_run_hands_tty_foreground_to_child() {
    let code = run_in_pty_session(|| {
        let mut policy = test_policy().with_name("tty-interactive");
        let result = block_on(policy.run_interactive(&["true"]));
        match result {
            Ok(r) if r.success() => {}
            _ => return EXIT_RUN_FAILED,
        }
        if unsafe { libc::tcgetpgrp(0) == libc::getpgrp() } {
            return EXIT_FOREGROUND_NOT_TAKEN;
        }
        EXIT_OK
    });
    assert_eq!(
        code, EXIT_OK,
        "helper exit {code} (10=no tty foreground at start, 11=run failed, \
         13=interactive run did not hand the tty foreground to the child)"
    );
}
