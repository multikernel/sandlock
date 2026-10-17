//! Session lifetime through the C ABI: a wait that keeps the session, and
//! signals from another thread while that wait is blocked.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;

use sandlock_ffi::{
    sandlock_handle_free, sandlock_handle_kill, sandlock_handle_process_groups,
    sandlock_handle_shutdown, sandlock_handle_t, sandlock_handle_wait, sandlock_popen,
    sandlock_result_free, sandlock_result_success, sandlock_sandbox_build,
    sandlock_sandbox_builder_fs_read, sandlock_sandbox_builder_new, sandlock_sandbox_free,
    sandlock_sandbox_t, sandlock_string_free,
};

const INHERIT: u32 = 0;

fn build_policy() -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    for p in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"] {
        if p == "/lib64" && !std::path::Path::new("/lib64").exists() {
            continue;
        }
        let c = CString::new(p).unwrap();
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    let mut err: c_int = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert_eq!(err, 0, "policy build failed");
    policy
}

fn popen(policy: *mut sandlock_sandbox_t, cmd: &[&str]) -> *mut sandlock_handle_t {
    let owned: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();
    let av: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    let (mut fd_in, mut fd_out, mut fd_err): (c_int, c_int, c_int) = (-1, -1, -1);
    let h = unsafe {
        sandlock_popen(
            policy,
            ptr::null(),
            av.as_ptr(),
            av.len() as c_uint,
            INHERIT,
            INHERIT,
            INHERIT,
            &mut fd_in,
            &mut fd_out,
            &mut fd_err,
        )
    };
    assert!(!h.is_null(), "sandlock_popen returned null");
    h
}

#[test]
fn kill_reaches_a_blocked_wait() {
    let policy = build_policy();
    let h = popen(policy, &["sleep", "60"]);
    let addr = h as usize;
    let killer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        unsafe { sandlock_handle_kill(addr as *mut sandlock_handle_t) }
    });
    let mut status = ptr::null_mut();
    assert_eq!(unsafe { sandlock_handle_wait(h, 5000, &mut status) }, 0);
    assert_eq!(killer.join().unwrap(), 0);
    assert_eq!(unsafe { sandlock_result_success(status) }, false);
    unsafe {
        sandlock_result_free(status);
        sandlock_result_free(sandlock_handle_shutdown(h));
        sandlock_handle_free(h);
        sandlock_sandbox_free(policy);
    }
}

#[test]
fn wait_timeout_leaves_the_session_alive() {
    let policy = build_policy();
    let h = popen(policy, &["sleep", "60"]);
    let mut status = ptr::null_mut();
    assert_eq!(unsafe { sandlock_handle_wait(h, 50, &mut status) }, 1);
    assert!(status.is_null());
    let groups = unsafe { sandlock_handle_process_groups(h) };
    assert!(!groups.is_null());
    let listed = unsafe { CStr::from_ptr(groups) }
        .to_string_lossy()
        .into_owned();
    assert_ne!(listed, "[]", "the session is still running");
    unsafe {
        sandlock_string_free(groups);
        sandlock_result_free(sandlock_handle_shutdown(h));
        sandlock_handle_free(h);
        sandlock_sandbox_free(policy);
    }
}
