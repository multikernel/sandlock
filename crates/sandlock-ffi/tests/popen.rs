//! Integration tests for the C ABI streaming-stdio `sandlock_popen` (RFC #67).
//!
//! These drive the FFI symbols directly (no C compilation step) and read the
//! returned pipe fds. The handle uses a multi-threaded runtime, so blocking
//! reads on the test thread do not starve the supervisor.

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;

use sandlock_ffi::{
    sandlock_handle_free, sandlock_handle_kill, sandlock_handle_wait, sandlock_popen,
    sandlock_result_exit_code, sandlock_result_free, sandlock_result_success,
    sandlock_sandbox_build, sandlock_sandbox_builder_fs_read, sandlock_sandbox_builder_new,
    sandlock_sandbox_free, sandlock_sandbox_t,
};

const INHERIT: u32 = 0;
const PIPED: u32 = 1;
const NULL: u32 = 2;

/// Build a policy that can exec the usual coreutils in a minimal rootfs.
fn build_policy() -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    for p in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"] {
        // `/lib64` is absent on RISC-V glibc / musl; fs_read is mandatory.
        if p == "/lib64" && !std::path::Path::new("/lib64").exists() { continue; }
        let c = CString::new(p).unwrap();
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    let mut err: c_int = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert_eq!(err, 0, "policy build failed");
    assert!(!policy.is_null());
    policy
}

fn argv(cmd: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
    let owned: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    (owned, ptrs)
}

#[test]
fn popen_streams_stdout_and_collects_exit() {
    let policy = build_policy();
    let (_owned, av) = argv(&["echo", "ffi-hi"]);

    let mut fd_in: c_int = -1;
    let mut fd_out: c_int = -1;
    let mut fd_err: c_int = -1;
    let h = unsafe {
        sandlock_popen(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as c_uint,
            INHERIT,
            PIPED,
            INHERIT,
            &mut fd_in,
            &mut fd_out,
            &mut fd_err,
        )
    };
    assert!(!h.is_null(), "sandlock_popen returned null");
    assert_eq!(fd_in, -1, "stdin was inherit → no fd");
    assert!(fd_out >= 0, "stdout was piped → expected an fd");
    assert_eq!(fd_err, -1, "stderr was inherit → no fd");

    let mut out = String::new();
    unsafe { std::fs::File::from_raw_fd(fd_out) }
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(out, "ffi-hi\n");

    let res = unsafe { sandlock_handle_wait(h) };
    assert!(!res.is_null());
    assert_eq!(unsafe { sandlock_result_exit_code(res) }, 0);
    unsafe {
        sandlock_result_free(res);
        sandlock_handle_free(h);
        sandlock_sandbox_free(policy);
    }
}

#[test]
fn popen_stdin_stdout_roundtrip() {
    let policy = build_policy();
    let (_owned, av) = argv(&["cat"]);

    let mut fd_in: c_int = -1;
    let mut fd_out: c_int = -1;
    let mut fd_err: c_int = -1;
    let h = unsafe {
        sandlock_popen(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as c_uint,
            PIPED,
            PIPED,
            INHERIT,
            &mut fd_in,
            &mut fd_out,
            &mut fd_err,
        )
    };
    assert!(!h.is_null());
    assert!(fd_in >= 0 && fd_out >= 0);

    let mut stdin = unsafe { std::fs::File::from_raw_fd(fd_in) };
    let mut stdout = unsafe { std::fs::File::from_raw_fd(fd_out) };
    stdin.write_all(b"ping\n").unwrap();
    drop(stdin); // EOF → cat exits

    let mut out = String::new();
    stdout.read_to_string(&mut out).unwrap();
    assert_eq!(out, "ping\n");

    let res = unsafe { sandlock_handle_wait(h) };
    assert_eq!(unsafe { sandlock_result_exit_code(res) }, 0);
    unsafe {
        sandlock_result_free(res);
        sandlock_handle_free(h);
        sandlock_sandbox_free(policy);
    }
}

#[test]
fn popen_null_mode_yields_no_fd() {
    let policy = build_policy();
    let (_owned, av) = argv(&["echo", "discarded"]);

    let mut fd_in: c_int = -1;
    let mut fd_out: c_int = -1;
    let mut fd_err: c_int = -1;
    let h = unsafe {
        sandlock_popen(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as c_uint,
            INHERIT,
            NULL,
            INHERIT,
            &mut fd_in,
            &mut fd_out,
            &mut fd_err,
        )
    };
    assert!(!h.is_null());
    assert_eq!(fd_out, -1, "Null stdout yields no caller fd");
    let res = unsafe { sandlock_handle_wait(h) };
    assert_eq!(unsafe { sandlock_result_exit_code(res) }, 0);
    unsafe {
        sandlock_result_free(res);
        sandlock_handle_free(h);
        sandlock_sandbox_free(policy);
    }
}

#[test]
fn popen_stderr_piped_through_ffi() {
    let policy = build_policy();
    let (_owned, av) = argv(&["sh", "-c", "echo err 1>&2"]);

    let mut fd_in: c_int = -1;
    let mut fd_out: c_int = -1;
    let mut fd_err: c_int = -1;
    let h = unsafe {
        sandlock_popen(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as c_uint,
            INHERIT,
            INHERIT,
            PIPED,
            &mut fd_in,
            &mut fd_out,
            &mut fd_err,
        )
    };
    assert!(!h.is_null());
    assert_eq!(fd_out, -1, "stdout was inherit");
    assert!(fd_err >= 0, "stderr was piped → expected an fd");

    let mut out = String::new();
    unsafe { std::fs::File::from_raw_fd(fd_err) }
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(out, "err\n");

    let res = unsafe { sandlock_handle_wait(h) };
    assert_eq!(unsafe { sandlock_result_exit_code(res) }, 0);
    unsafe {
        sandlock_result_free(res);
        sandlock_handle_free(h);
        sandlock_sandbox_free(policy);
    }
}

/// kill → wait → free: kill terminates the group, wait still collects the
/// (non-success) exit status, free releases cleanly.
#[test]
fn popen_kill_then_wait_then_free() {
    let policy = build_policy();
    let (_owned, av) = argv(&["sleep", "100"]);

    let mut a: c_int = -1;
    let mut b: c_int = -1;
    let mut c: c_int = -1;
    let h = unsafe {
        sandlock_popen(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as c_uint,
            INHERIT,
            INHERIT,
            INHERIT,
            &mut a,
            &mut b,
            &mut c,
        )
    };
    assert!(!h.is_null());

    assert_eq!(unsafe { sandlock_handle_kill(h) }, 0, "kill should succeed");
    let res = unsafe { sandlock_handle_wait(h) };
    assert!(!res.is_null(), "wait must still return after kill");
    assert!(
        !unsafe { sandlock_result_success(res) },
        "a killed process is not success"
    );
    unsafe {
        sandlock_result_free(res);
        sandlock_handle_free(h);
        sandlock_sandbox_free(policy);
    }
}

/// kill → free without wait must not hang: free's Sandbox::drop reaps the
/// still-Running process.
#[test]
fn popen_kill_then_free_without_wait() {
    let policy = build_policy();
    let (_owned, av) = argv(&["sleep", "100"]);

    let mut a: c_int = -1;
    let mut b: c_int = -1;
    let mut c: c_int = -1;
    let h = unsafe {
        sandlock_popen(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as c_uint,
            INHERIT,
            INHERIT,
            INHERIT,
            &mut a,
            &mut b,
            &mut c,
        )
    };
    assert!(!h.is_null());
    assert_eq!(unsafe { sandlock_handle_kill(h) }, 0);
    // No wait — free must reap, not hang.
    unsafe {
        sandlock_handle_free(h);
        sandlock_sandbox_free(policy);
    }
}

/// kill is idempotent: a second kill (process already dying/exited) still
/// returns 0 (ESRCH is swallowed).
#[test]
fn popen_kill_is_idempotent() {
    let policy = build_policy();
    let (_owned, av) = argv(&["sleep", "100"]);

    let mut a: c_int = -1;
    let mut b: c_int = -1;
    let mut c: c_int = -1;
    let h = unsafe {
        sandlock_popen(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as c_uint,
            INHERIT,
            INHERIT,
            INHERIT,
            &mut a,
            &mut b,
            &mut c,
        )
    };
    assert!(!h.is_null());
    assert_eq!(unsafe { sandlock_handle_kill(h) }, 0);
    assert_eq!(
        unsafe { sandlock_handle_kill(h) },
        0,
        "second kill must be idempotent"
    );
    let res = unsafe { sandlock_handle_wait(h) };
    unsafe {
        sandlock_result_free(res);
        sandlock_handle_free(h);
        sandlock_sandbox_free(policy);
    }
}

#[test]
fn popen_rejects_unknown_stdio_mode() {
    let policy = build_policy();
    let (_owned, av) = argv(&["echo", "x"]);

    let mut fd_in: c_int = 7; // pre-set non-sentinel to prove it is reset
    let mut fd_out: c_int = 7;
    let mut fd_err: c_int = 7;
    let h = unsafe {
        sandlock_popen(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as c_uint,
            INHERIT,
            99,
            INHERIT, // 99 is not a valid StdioMode
            &mut fd_in,
            &mut fd_out,
            &mut fd_err,
        )
    };
    assert!(
        h.is_null(),
        "unknown stdio mode must fail loudly (null handle)"
    );
    assert_eq!(
        (fd_in, fd_out, fd_err),
        (-1, -1, -1),
        "out fds reset to -1 on error"
    );
    unsafe { sandlock_sandbox_free(policy) };
}

/// A PIPED stream whose out-pointer is null must have its pipe fd *closed*, not
/// leaked (the advertised no-leak invariant of `write_or_close_fd`). Run enough
/// iterations that a per-call fd leak would blow the process fd count, and
/// assert it stays bounded. If the null-out-ptr close branch regressed into a
/// leak, this fails; the other tests (all passing real `&mut fd`) would not.
#[test]
fn popen_piped_stream_with_null_out_ptr_is_closed_not_leaked() {
    fn fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    let policy = build_policy();
    let (_owned, av) = argv(&["echo", "leak-check"]);

    let mut samples = Vec::new();
    for i in 0..40 {
        let mut fd_in: c_int = -1;
        let mut fd_err: c_int = -1;
        // stdout is PIPED but its out pointer is null → the pipe read-end must be
        // closed inside sandlock_popen, never handed out and never leaked.
        let h = unsafe {
            sandlock_popen(
                policy,
                ptr::null(),
                av.as_ptr(),
                av.len() as c_uint,
                INHERIT,
                PIPED,
                INHERIT,
                &mut fd_in,
                ptr::null_mut(), // discard the piped stdout fd
                &mut fd_err,
            )
        };
        assert!(
            !h.is_null(),
            "popen with a null out-pointer should still succeed"
        );
        assert_eq!(fd_in, -1, "stdin inherited → no fd");
        assert_eq!(fd_err, -1, "stderr inherited → no fd");
        let res = unsafe { sandlock_handle_wait(h) };
        unsafe {
            sandlock_result_free(res);
            sandlock_handle_free(h);
        }
        // Skip the first few iterations: the runtime lazily opens fds that stay
        // open and would skew a raw before/after diff.
        if i >= 5 {
            samples.push(fd_count());
        }
    }
    unsafe { sandlock_sandbox_free(policy) };

    let min = *samples.iter().min().unwrap();
    let max = *samples.iter().max().unwrap();
    assert!(
        max - min <= 2,
        "process fd count grew across iterations (min={min}, max={max}) — a PIPED \
         stream with a null out-pointer is leaking its fd instead of being closed"
    );
}
