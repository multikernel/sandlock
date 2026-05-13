//! Integration smoke tests for the FFI handler ABI.

use sandlock_ffi::notif_repr::sandlock_notif_data_t;

#[test]
fn notif_data_layout_matches_documented_size() {
    // 8 + 4 + 4 + 4 + 4 + 8 + 6*8 = 80 bytes. If this changes, the C header
    // and any external consumers need to be updated together.
    assert_eq!(std::mem::size_of::<sandlock_notif_data_t>(), 80);
    assert_eq!(std::mem::align_of::<sandlock_notif_data_t>(), 8);
}

#[test]
fn notif_data_from_seccomp_notif_copies_all_fields() {
    use sandlock_core::{SeccompData, SeccompNotif};

    let notif = SeccompNotif {
        id: 0xDEAD_BEEF_CAFE_F00D,
        pid: 4242,
        flags: 7,
        data: SeccompData {
            nr: 21, // SYS_access on x86_64
            arch: 0xC000_003E,
            instruction_pointer: 0x7FFF_FFFF_AAAA,
            args: [1, 2, 3, 4, 5, 6],
        },
    };
    let snap = sandlock_notif_data_t::from(&notif);
    assert_eq!(snap.id, 0xDEAD_BEEF_CAFE_F00D);
    assert_eq!(snap.pid, 4242);
    assert_eq!(snap.flags, 7);
    assert_eq!(snap.syscall_nr, 21);
    assert_eq!(snap.arch, 0xC000_003E);
    assert_eq!(snap.instruction_pointer, 0x7FFF_FFFF_AAAA);
    assert_eq!(snap.args, [1, 2, 3, 4, 5, 6]);
}

use sandlock_ffi::handler::{
    sandlock_mem_read, sandlock_mem_read_cstr, sandlock_mem_write,
};

#[test]
fn mem_accessors_reject_null_arguments() {
    // Verifies the null-pointer guards in each accessor. Happy-path
    // coverage with a live notif_fd is exercised by the end-to-end
    // tests further down this file.
    let mut buf = [0u8; 4];
    let mut out_len: usize = 0;
    let p = std::ptr::null();
    unsafe {
        assert_eq!(
            sandlock_mem_read_cstr(p, 0, buf.as_mut_ptr(), buf.len(), &mut out_len),
            -1,
            "read_cstr should reject null handle",
        );
        assert_eq!(
            sandlock_mem_read(p, 0, buf.as_mut_ptr(), buf.len(), &mut out_len),
            -1,
            "read should reject null handle",
        );
        assert_eq!(
            sandlock_mem_write(p, 0, buf.as_ptr(), buf.len()),
            -1,
            "write should reject null handle",
        );
    }
}

use sandlock_ffi::handler::{
    sandlock_action_kind_t, sandlock_action_out_t, sandlock_action_set_continue,
    sandlock_action_set_errno, sandlock_action_set_hold, sandlock_action_set_kill,
    sandlock_action_set_return_value,
};

#[test]
fn action_setters_record_kind_and_payload() {
    let mut a = sandlock_action_out_t::zeroed();
    unsafe { sandlock_action_set_continue(&mut a) };
    assert_eq!(a.kind, sandlock_action_kind_t::Continue as u32);

    unsafe { sandlock_action_set_errno(&mut a, 13) };
    assert_eq!(a.kind, sandlock_action_kind_t::Errno as u32);
    assert_eq!(unsafe { a.payload.errno }, 13);

    unsafe { sandlock_action_set_return_value(&mut a, -1) };
    assert_eq!(a.kind, sandlock_action_kind_t::ReturnValue as u32);
    assert_eq!(unsafe { a.payload.return_value }, -1);

    unsafe { sandlock_action_set_hold(&mut a) };
    assert_eq!(a.kind, sandlock_action_kind_t::Hold as u32);

    unsafe { sandlock_action_set_kill(&mut a, libc::SIGKILL, 4321) };
    assert_eq!(a.kind, sandlock_action_kind_t::Kill as u32);
    assert_eq!(unsafe { a.payload.kill.sig }, libc::SIGKILL);
    assert_eq!(unsafe { a.payload.kill.pgid }, 4321);
}

#[test]
fn action_out_layout_is_stable() {
    // kind(4) + pad(4) + payload(16) = 24 bytes; alignment driven by the
    // u64 inside the union. Layout drift between Rust and the C header
    // would corrupt caller-allocated buffers.
    assert_eq!(std::mem::size_of::<sandlock_action_out_t>(), 24);
    assert_eq!(std::mem::align_of::<sandlock_action_out_t>(), 8);
}

use sandlock_ffi::handler::{
    sandlock_exception_policy_t, sandlock_handler_free, sandlock_handler_fn_t,
    sandlock_handler_new, sandlock_handler_t,
};

extern "C-unwind" fn test_handler(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_continue(out) };
    0
}

static ROUND_TRIP_DROPPER_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

extern "C-unwind" fn round_trip_dropper(ud: *mut std::ffi::c_void) {
    // Reclaim the leaked Box so its destructor runs (real drop path).
    unsafe { drop(Box::from_raw(ud as *mut u32)); }
    ROUND_TRIP_DROPPER_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

#[test]
fn handler_new_and_free_round_trip() {
    // Reset in case another test in the binary touched this counter.
    ROUND_TRIP_DROPPER_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);

    let ud = Box::into_raw(Box::new(0xABCDu32)) as *mut std::ffi::c_void;
    let on_ex = sandlock_exception_policy_t::Kill as u32;
    let h: *mut sandlock_handler_t = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            ud,
            Some(round_trip_dropper),
            on_ex,
        )
    };
    assert!(!h.is_null());
    assert_eq!(
        ROUND_TRIP_DROPPER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "dropper must not fire before sandlock_handler_free",
    );

    unsafe { sandlock_handler_free(h) };

    assert_eq!(
        ROUND_TRIP_DROPPER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "dropper must fire exactly once during Drop",
    );
}

#[test]
fn handler_new_rejects_invalid_exception_policy() {
    let h = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            std::ptr::null_mut(),
            None,
            99u32, // out of range
        )
    };
    assert!(h.is_null(), "expected null handle on invalid on_exception");
}

use sandlock_core::seccomp::dispatch::{Handler, HandlerCtx};
use sandlock_core::seccomp::notif::NotifAction;
use sandlock_core::{SeccompData, SeccompNotif};
use sandlock_ffi::handler::FfiHandler;

fn fake_ctx() -> HandlerCtx {
    HandlerCtx {
        notif: SeccompNotif {
            id: 1, pid: std::process::id(), flags: 0,
            data: SeccompData { nr: 39, arch: 0xC000003E,
                                instruction_pointer: 0, args: [0; 6] },
        },
        notif_fd: -1,
    }
}

extern "C-unwind" fn return_value_42(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_return_value(out, 42) };
    0
}

extern "C-unwind" fn returns_error_with_unset_action(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    _out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    -1
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_translates_return_value() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(return_value_42),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    let h = unsafe { FfiHandler::from_raw(raw) };
    let cx = fake_ctx();
    let action = h.handle(&cx).await;
    assert!(matches!(action, NotifAction::ReturnValue(42)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_applies_exception_policy_on_failure() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(returns_error_with_unset_action),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::DenyEperm as u32,
        )
    };
    let h = unsafe { FfiHandler::from_raw(raw) };
    let cx = fake_ctx();
    let action = h.handle(&cx).await;
    assert!(matches!(action, NotifAction::Errno(e) if e == libc::EPERM));
}

use std::ffi::CString;
use sandlock_ffi::handler::{
    sandlock_handler_registration_t, sandlock_run_with_handlers,
};

extern "C-unwind" fn force_getpid_to_777(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_return_value(out, 777) };
    0
}

#[test]
fn run_with_handlers_intercepts_getpid() {
    use sandlock_ffi::*; // bring in builder + result symbols

    let builder = sandlock_sandbox_builder_new();
    // Allow the runtime bits the child needs. The exact mounts mirror
    // sandlock's own integration tests — read-only access to the system
    // libraries and the python interpreter, plus a writable /tmp.
    let builder = unsafe {
        let p = CString::new("/usr").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/bin").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/lib").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/lib64").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/etc").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/tmp").unwrap();
        sandlock_sandbox_builder_fs_write(builder, p.as_ptr())
    };

    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    let handler = unsafe {
        handler::sandlock_handler_new(
            Some(force_getpid_to_777),
            std::ptr::null_mut(),
            None,
            handler::sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(!handler.is_null(), "handler_new returned null");
    let registrations = [sandlock_handler_registration_t {
        syscall_nr: libc::SYS_getpid,
        handler,
    }];

    let script = CString::new(
        "import os, sys; sys.stdout.write(str(os.getpid()))",
    ).unwrap();
    // Use the system python3 directly. Running through `/usr/bin/env
    // python3` would pick up any venv shim in $PATH whose pyvenv.cfg
    // sits outside the sandbox's read allowlist and fail before our
    // handler ever gets a chance to fire.
    let arg0 = CString::new("/usr/bin/python3").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let argv = [
        arg0.as_ptr(),
        arg1.as_ptr(),
        script.as_ptr(),
    ];

    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            std::ptr::null(), // name: auto-generate `sandbox-{pid}`
            argv.as_ptr(),
            argv.len() as u32,
            registrations.as_ptr(),
            registrations.len(),
        )
    };
    assert!(!rr.is_null(), "sandlock_run_with_handlers returned null");
    let stdout = unsafe {
        let mut len: usize = 0;
        let p = sandlock_result_stdout_bytes(rr, &mut len);
        if p.is_null() { Vec::new() } else { std::slice::from_raw_parts(p, len).to_vec() }
    };
    let stderr = unsafe {
        let mut len: usize = 0;
        let p = sandlock_result_stderr_bytes(rr, &mut len);
        if p.is_null() { Vec::new() } else { std::slice::from_raw_parts(p, len).to_vec() }
    };
    let stdout_str = String::from_utf8_lossy(&stdout);
    let stderr_str = String::from_utf8_lossy(&stderr);
    let exit_code = unsafe { sandlock_result_exit_code(rr) };
    assert!(stdout_str.contains("777"),
            "expected getpid to be intercepted; exit={} stdout={:?} stderr={:?}",
            exit_code, stdout_str, stderr_str);

    unsafe { sandlock_result_free(rr); }
    unsafe { sandlock_sandbox_free(policy); }
}

// ---------------------------------------------------------------------------
// Expanded coverage
// ---------------------------------------------------------------------------
//
// The tests below probe each remaining branch of the handler ABI surface:
//
//   * Group A: setters for the inject-fd variants and null-pointer safety.
//   * Group B: every `NotifAction` translation the dispatcher must produce.
//   * Group C: exception-policy fallbacks beyond the default `DenyEperm`.
//   * Group D: panic recovery across the FFI boundary.
//   * Group E: `Unset` action when the callback returns 0 but never sets one.
//   * Group F: `sandlock_handler_new` edge cases (null fn / null ud + dropper).
//   * Group G: `sandlock_run_with_handlers` failure paths and ownership.
//   * Group H: multiple handlers each firing for their own syscall.
//   * Group I: live-fd `sandlock_mem_read_cstr` via an intercepted `openat`.
//
// Style mirrors the existing end-to-end test: explicit `extern "C-unwind"`
// handler fns, no helper macros, `assert!(matches!(...))` for action
// variants.

use sandlock_ffi::handler::sandlock_action_set_inject_fd_send;

// ---- Group A: action setters --------------------------------------------

#[test]
fn action_inject_fd_send_setter_records_payload() {
    let mut a = sandlock_action_out_t::zeroed();
    // O_CLOEXEC is the canonical flag a handler would pass through.
    unsafe { sandlock_action_set_inject_fd_send(&mut a, 42, 0o2000000) };
    assert_eq!(a.kind, sandlock_action_kind_t::InjectFdSend as u32);
    // Safety: kind == InjectFdSend selects the `inject_send` union arm
    // (matches the ABI contract documented on the setter).
    assert_eq!(unsafe { a.payload.inject_send.srcfd }, 42);
    assert_eq!(unsafe { a.payload.inject_send.newfd_flags }, 0o2000000);
}

#[test]
fn action_setters_are_null_safe() {
    // Safety: each setter documents null as a no-op; this test is the
    // executable form of that contract. If any setter dereferences null
    // the process aborts and the test reports failure.
    unsafe {
        sandlock_action_set_continue(std::ptr::null_mut());
        sandlock_action_set_errno(std::ptr::null_mut(), 13);
        sandlock_action_set_return_value(std::ptr::null_mut(), -1);
        sandlock_action_set_hold(std::ptr::null_mut());
        sandlock_action_set_kill(std::ptr::null_mut(), libc::SIGKILL, 0);
        sandlock_action_set_inject_fd_send(std::ptr::null_mut(), 0, 0);
    }
}

// ---- Group B: FfiHandler translation ------------------------------------
//
// Each variant gets its own explicit `extern "C-unwind"` handler so the
// test retains the line-by-line transparency of the existing tests rather
// than hiding setup behind a macro.

extern "C-unwind" fn handler_set_continue(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_continue(out) };
    0
}

extern "C-unwind" fn handler_set_errno_eacces(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_errno(out, 13) };
    0
}

extern "C-unwind" fn handler_set_hold(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_hold(out) };
    0
}

extern "C-unwind" fn handler_set_kill_sigterm_1234(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_kill(out, libc::SIGTERM, 1234) };
    0
}

extern "C-unwind" fn handler_set_kill_sigkill_zero_pgid(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_kill(out, libc::SIGKILL, 0) };
    0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_translates_continue() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(handler_set_continue),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    // Safety: `raw` was just produced by `sandlock_handler_new` and is
    // non-null; ownership transfers into the adapter.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let action = h.handle(&fake_ctx()).await;
    assert!(matches!(action, NotifAction::Continue));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_translates_errno() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(handler_set_errno_eacces),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    // Safety: see `ffi_handler_translates_continue`.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let action = h.handle(&fake_ctx()).await;
    assert!(matches!(action, NotifAction::Errno(e) if e == 13));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_translates_hold() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(handler_set_hold),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    // Safety: see `ffi_handler_translates_continue`.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let action = h.handle(&fake_ctx()).await;
    assert!(matches!(action, NotifAction::Hold));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_translates_kill_with_explicit_pgid() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(handler_set_kill_sigterm_1234),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    // Safety: see `ffi_handler_translates_continue`.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let action = h.handle(&fake_ctx()).await;
    assert!(matches!(
        action,
        NotifAction::Kill { sig, pgid } if sig == libc::SIGTERM && pgid == 1234
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_translates_kill_zero_pgid_substitutes_child_pgid() {
    // Spawn a real child so that getpgid(child.pid) is the test runner's
    // pgid — distinct from child.pid (a fresh pid). This makes the test a
    // genuine regression hook for the substitution: buggy production code
    // that returns notif.pid would yield child.pid, but the production
    // formula (getpgid(notif.pid)) yields the test runner's pgid. The
    // mismatch causes the assertion to fail under the bug.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep child");
    let child_pid = child.id() as i32;
    // Compute the expected pgid the same way production does. If `sleep`
    // exited or was reaped between spawn and this call, fall back to the
    // pid to mirror production's ESRCH branch.
    let expected_pgid = {
        // SAFETY: same as the production call — no preconditions.
        let q = unsafe { libc::getpgid(child_pid) };
        if q < 0 { child_pid } else { q }
    };
    // Sanity-check that this host actually exposes a meaningful pgid !=
    // pid for the spawned child. Otherwise the assertion below is
    // satisfied by both the buggy and fixed implementations, making the
    // test useless on this host.
    assert_ne!(
        expected_pgid, child_pid,
        "test precondition: getpgid(child_pid) must differ from child_pid for this test to catch regressions; \
         got pgid={expected_pgid}, pid={child_pid}",
    );

    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(handler_set_kill_sigkill_zero_pgid),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    // Safety: see `ffi_handler_translates_continue`.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let cx = HandlerCtx {
        notif: SeccompNotif {
            id: 1,
            pid: child_pid as u32,
            flags: 0,
            data: SeccompData {
                nr: 39,
                arch: 0xC000_003E,
                instruction_pointer: 0,
                args: [0; 6],
            },
        },
        notif_fd: -1,
    };
    let action = h.handle(&cx).await;

    // Reap the child regardless of assertion outcome.
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        matches!(
            action,
            NotifAction::Kill { sig, pgid }
                if sig == libc::SIGKILL && pgid == expected_pgid
        ),
        "expected Kill {{ sig: SIGKILL, pgid: {expected_pgid} }}, got {action:?}",
    );
}

// ---- Group C: exception policy fallbacks --------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_kill_policy_on_callback_rc_nonzero() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(returns_error_with_unset_action),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    // Safety: see `ffi_handler_translates_continue`.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let action = h.handle(&fake_ctx()).await;
    assert!(matches!(action, NotifAction::Kill { sig, .. } if sig == libc::SIGKILL));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_continue_policy_on_callback_rc_nonzero() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(returns_error_with_unset_action),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Continue as u32,
        )
    };
    // Safety: see `ffi_handler_translates_continue`.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let action = h.handle(&fake_ctx()).await;
    assert!(matches!(action, NotifAction::Continue));
}

// ---- Group D: panic recovery --------------------------------------------

extern "C-unwind" fn panicking_handler(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    _out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    panic!("test panic from extern C handler");
}

// `sandlock_handler_fn_t` is `extern "C-unwind" fn`, so a panic raised
// inside the Rust handler unwinds across the C ABI boundary and is
// caught by the `std::panic::catch_unwind` in `FfiHandler::handle`. The
// dispatcher then falls back to the configured exception policy — here
// `Kill` — which the assertion below verifies. Pure-C callers cannot
// panic, so this stability claim is exclusively for Rust handlers
// exposed through the C ABI (the integration-test pattern here).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_recovers_from_callback_panic() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(panicking_handler),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    // Safety: see `ffi_handler_translates_continue`.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let action = h.handle(&fake_ctx()).await;
    // The `catch_unwind` inside `spawn_blocking` swallows the panic and
    // the dispatcher falls back to the configured exception policy.
    assert!(matches!(action, NotifAction::Kill { sig, .. } if sig == libc::SIGKILL));
}

// ---- Group E: Unset action with zero rc ---------------------------------

extern "C-unwind" fn never_sets_action(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    _out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_callback_returns_zero_but_never_sets_action_triggers_fallback() {
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(never_sets_action),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::DenyEperm as u32,
        )
    };
    // Safety: see `ffi_handler_translates_continue`.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let action = h.handle(&fake_ctx()).await;
    // `translate_action` returns `None` for `Unset`, which routes the
    // dispatcher onto the exception policy fallback.
    assert!(matches!(action, NotifAction::Errno(e) if e == libc::EPERM));
}

// ---- Group F: handler_new edge cases ------------------------------------

extern "C-unwind" fn panicking_dropper(_ud: *mut std::ffi::c_void) {
    panic!("dropper invoked when it should not have been");
}

#[test]
fn handler_new_with_null_handler_fn_returns_null() {
    let h = unsafe {
        sandlock_handler_new(
            None,
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(h.is_null(), "expected null handle when handler_fn is None");
}

#[test]
fn handler_new_with_null_ud_and_dropper_does_not_invoke_dropper() {
    // Allocates a container with a destructor but null ud; the `Drop`
    // impl on `sandlock_handler_t` must skip the destructor in that case
    // because there is nothing to free.
    let h = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            std::ptr::null_mut(),
            Some(panicking_dropper),
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(!h.is_null(), "expected a valid handler container");
    // Safety: `h` was just produced and not yet freed. If the guard in
    // `Drop` were missing the dropper would panic and abort the test.
    unsafe { sandlock_handler_free(h) };
}

// ---- Group G: run_with_handlers failure paths ---------------------------

#[test]
fn run_with_handlers_null_policy_returns_null() {
    let arg0 = CString::new("/bin/true").unwrap();
    let argv = [arg0.as_ptr()];
    let rr = unsafe {
        sandlock_run_with_handlers(
            std::ptr::null(),
            std::ptr::null(), // name: auto-generate `sandbox-{pid}`
            argv.as_ptr(),
            argv.len() as u32,
            std::ptr::null(),
            0,
        )
    };
    assert!(rr.is_null(), "expected null result for null policy");
}

#[test]
fn run_with_handlers_null_argv_returns_null() {
    use sandlock_ffi::*;
    let builder = sandlock_sandbox_builder_new();
    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            std::ptr::null(), // name: auto-generate `sandbox-{pid}`
            std::ptr::null(),
            3, // argc > 0 with null argv must fail validation
            std::ptr::null(),
            0,
        )
    };
    assert!(rr.is_null(), "expected null result for null argv with argc > 0");

    unsafe { sandlock_sandbox_free(policy); }
}

#[test]
fn run_with_handlers_zero_argc_returns_null() {
    // argc == 0 means "no command to execute" — the sandbox cannot
    // exec an empty argv, so the FFI must reject it at the boundary
    // before consuming handler containers.
    use sandlock_ffi::*;
    let builder = sandlock_sandbox_builder_new();
    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    let arg0 = CString::new("/bin/true").unwrap();
    let argv = [arg0.as_ptr()];
    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            std::ptr::null(), // name: auto-generate `sandbox-{pid}`
            argv.as_ptr(),
            0, // zero argc must reject
            std::ptr::null(),
            0,
        )
    };
    assert!(rr.is_null(), "expected null result for argc == 0");

    unsafe { sandlock_sandbox_free(policy); }
}

#[test]
fn run_with_handlers_null_registrations_with_nonzero_count_returns_null() {
    use sandlock_ffi::*;
    let builder = sandlock_sandbox_builder_new();
    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    let arg0 = CString::new("/bin/true").unwrap();
    let argv = [arg0.as_ptr()];
    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            std::ptr::null(), // name: auto-generate `sandbox-{pid}`
            argv.as_ptr(),
            argv.len() as u32,
            std::ptr::null(), // null registrations with nregistrations > 0
            1,
        )
    };
    assert!(rr.is_null(), "expected null result for null registrations + count > 0");

    unsafe { sandlock_sandbox_free(policy); }
}

#[test]
fn run_with_handlers_empty_registrations_runs_normally() {
    use sandlock_ffi::*;

    let builder = sandlock_sandbox_builder_new();
    // Same allowlist as the existing end-to-end test — /bin/true links
    // against libc and ld.so so it still needs /lib + /lib64 + /usr.
    let builder = unsafe {
        let p = CString::new("/usr").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/bin").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/lib").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/lib64").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/etc").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/tmp").unwrap();
        sandlock_sandbox_builder_fs_write(builder, p.as_ptr())
    };

    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    let arg0 = CString::new("/bin/true").unwrap();
    let argv = [arg0.as_ptr()];

    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            std::ptr::null(), // name: auto-generate `sandbox-{pid}`
            argv.as_ptr(),
            argv.len() as u32,
            std::ptr::null(),
            0,
        )
    };
    assert!(!rr.is_null(), "empty registrations should still run /bin/true");
    let success = unsafe { sandlock_result_success(rr) };
    let exit_code = unsafe { sandlock_result_exit_code(rr) };
    assert!(success, "/bin/true should exit successfully; exit={}", exit_code);

    unsafe { sandlock_result_free(rr); }
    unsafe { sandlock_sandbox_free(policy); }
}

static ONE_SHOT_DROPPER_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

extern "C-unwind" fn one_shot_dropper(ud: *mut std::ffi::c_void) {
    ONE_SHOT_DROPPER_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if !ud.is_null() {
        // Reclaim the leaked Box so leak-sanitizer builds stay clean.
        unsafe { drop(Box::from_raw(ud as *mut u32)); }
    }
}

#[test]
fn run_with_handlers_null_handler_in_array_returns_null() {
    use sandlock_ffi::*;

    let builder = sandlock_sandbox_builder_new();
    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    // The validating handler must NOT be consumed by `sandlock_run_with_handlers`
    // when validation fails — the call should be transactional. We assert this
    // by registering `one_shot_dropper` and verifying it fires exactly once
    // (from our explicit `sandlock_handler_free` call below, not from
    // `sandlock_run_with_handlers`).
    ONE_SHOT_DROPPER_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
    let ud = Box::into_raw(Box::new(0xAAu32)) as *mut std::ffi::c_void;
    let valid = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            ud,
            Some(one_shot_dropper),
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(!valid.is_null());

    let regs = [
        sandlock_handler_registration_t {
            syscall_nr: libc::SYS_getpid,
            handler: valid,
        },
        sandlock_handler_registration_t {
            syscall_nr: libc::SYS_getppid,
            handler: std::ptr::null_mut(), // forces validation failure
        },
    ];

    let arg0 = CString::new("/bin/true").unwrap();
    let argv = [arg0.as_ptr()];

    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            std::ptr::null(), // name: auto-generate `sandbox-{pid}`
            argv.as_ptr(),
            argv.len() as u32,
            regs.as_ptr(),
            regs.len(),
        )
    };
    assert!(rr.is_null(), "expected null result when an array entry is null");
    // The valid handler must still be ours to free — proving it was not
    // consumed by the failed call.
    unsafe { sandlock_handler_free(valid) };
    assert_eq!(
        ONE_SHOT_DROPPER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "dropper must fire exactly once (from our explicit free)",
    );

    unsafe { sandlock_sandbox_free(policy); }
}

// ---- Group H: multiple handlers -----------------------------------------

extern "C-unwind" fn force_getpid_to_111(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_return_value(out, 111) };
    0
}

extern "C-unwind" fn force_getppid_to_222(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_return_value(out, 222) };
    0
}

#[test]
fn run_with_handlers_two_handlers_each_fires_for_own_syscall() {
    use sandlock_ffi::*;

    let builder = sandlock_sandbox_builder_new();
    let builder = unsafe {
        let p = CString::new("/usr").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/bin").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/lib").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/lib64").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/etc").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/tmp").unwrap();
        sandlock_sandbox_builder_fs_write(builder, p.as_ptr())
    };

    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    let h_pid = unsafe {
        handler::sandlock_handler_new(
            Some(force_getpid_to_111),
            std::ptr::null_mut(),
            None,
            handler::sandlock_exception_policy_t::Kill as u32,
        )
    };
    let h_ppid = unsafe {
        handler::sandlock_handler_new(
            Some(force_getppid_to_222),
            std::ptr::null_mut(),
            None,
            handler::sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(!h_pid.is_null() && !h_ppid.is_null());

    let registrations = [
        sandlock_handler_registration_t {
            syscall_nr: libc::SYS_getpid,
            handler: h_pid,
        },
        sandlock_handler_registration_t {
            syscall_nr: libc::SYS_getppid,
            handler: h_ppid,
        },
    ];

    let script = CString::new(
        "import os, sys; sys.stdout.write(str(os.getpid())+'|'+str(os.getppid()))",
    ).unwrap();
    let arg0 = CString::new("/usr/bin/python3").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let argv = [
        arg0.as_ptr(),
        arg1.as_ptr(),
        script.as_ptr(),
    ];

    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            std::ptr::null(), // name: auto-generate `sandbox-{pid}`
            argv.as_ptr(),
            argv.len() as u32,
            registrations.as_ptr(),
            registrations.len(),
        )
    };
    assert!(!rr.is_null(), "sandlock_run_with_handlers returned null");
    let stdout = unsafe {
        let mut len: usize = 0;
        let p = sandlock_result_stdout_bytes(rr, &mut len);
        if p.is_null() { Vec::new() } else { std::slice::from_raw_parts(p, len).to_vec() }
    };
    let stderr = unsafe {
        let mut len: usize = 0;
        let p = sandlock_result_stderr_bytes(rr, &mut len);
        if p.is_null() { Vec::new() } else { std::slice::from_raw_parts(p, len).to_vec() }
    };
    let stdout_str = String::from_utf8_lossy(&stdout);
    let stderr_str = String::from_utf8_lossy(&stderr);
    let exit_code = unsafe { sandlock_result_exit_code(rr) };
    assert!(
        stdout_str.contains("111") && stdout_str.contains("222"),
        "expected both handlers to fire; exit={} stdout={:?} stderr={:?}",
        exit_code, stdout_str, stderr_str,
    );

    unsafe { sandlock_result_free(rr); }
    unsafe { sandlock_sandbox_free(policy); }
}

// ---- Group I: live-fd mem_read_cstr -------------------------------------

extern "C-unwind" fn deny_magic_marker_path(
    _ud: *mut std::ffi::c_void,
    notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    // openat(dirfd, pathname, flags, ...) — pathname is args[1].
    // Safety: `notif` and `mem` are valid pointers supplied by the
    // dispatcher for the duration of this callback; `out` is the
    // caller-allocated action-out buffer.
    let addr = unsafe { (*notif).args[1] };
    let mut buf = [0u8; 256];
    let mut n: usize = 0;
    let rc = unsafe {
        sandlock_ffi::handler::sandlock_mem_read_cstr(
            mem, addr, buf.as_mut_ptr(), buf.len(), &mut n,
        )
    };
    if rc != 0 {
        // Read failed — fall back to letting the syscall through so the
        // test runner sees a clean ENOENT rather than a fabricated EACCES.
        unsafe { sandlock_ffi::handler::sandlock_action_set_continue(out) };
        return 0;
    }
    let path = std::str::from_utf8(&buf[..n]).unwrap_or("");
    if path == "/sandlock-test-magic-marker" {
        unsafe { sandlock_ffi::handler::sandlock_action_set_errno(out, libc::EACCES) };
    } else {
        unsafe { sandlock_ffi::handler::sandlock_action_set_continue(out) };
    }
    0
}

#[test]
fn mem_read_cstr_reads_path_from_intercepted_openat() {
    use sandlock_ffi::*;

    let builder = sandlock_sandbox_builder_new();
    let builder = unsafe {
        let p = CString::new("/usr").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/bin").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/lib").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/lib64").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/etc").unwrap();
        sandlock_sandbox_builder_fs_read(builder, p.as_ptr())
    };
    let builder = unsafe {
        let p = CString::new("/tmp").unwrap();
        sandlock_sandbox_builder_fs_write(builder, p.as_ptr())
    };

    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    let handler = unsafe {
        handler::sandlock_handler_new(
            Some(deny_magic_marker_path),
            std::ptr::null_mut(),
            None,
            handler::sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(!handler.is_null());
    let registrations = [sandlock_handler_registration_t {
        syscall_nr: libc::SYS_openat,
        handler,
    }];

    // Child opens the magic path and prints the errno on failure.
    let script = CString::new(
        "import os, sys\n\
         try:\n\
         \x20   os.open('/sandlock-test-magic-marker', os.O_RDONLY)\n\
         \x20   sys.exit(0)\n\
         except OSError as e:\n\
         \x20   sys.stderr.write('errno=' + str(e.errno) + '\\n')\n\
         \x20   sys.exit(1)\n",
    ).unwrap();
    let arg0 = CString::new("/usr/bin/python3").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let argv = [
        arg0.as_ptr(),
        arg1.as_ptr(),
        script.as_ptr(),
    ];

    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            std::ptr::null(), // name: auto-generate `sandbox-{pid}`
            argv.as_ptr(),
            argv.len() as u32,
            registrations.as_ptr(),
            registrations.len(),
        )
    };
    assert!(!rr.is_null(), "sandlock_run_with_handlers returned null");
    let stderr = unsafe {
        let mut len: usize = 0;
        let p = sandlock_result_stderr_bytes(rr, &mut len);
        if p.is_null() { Vec::new() } else { std::slice::from_raw_parts(p, len).to_vec() }
    };
    let stdout = unsafe {
        let mut len: usize = 0;
        let p = sandlock_result_stdout_bytes(rr, &mut len);
        if p.is_null() { Vec::new() } else { std::slice::from_raw_parts(p, len).to_vec() }
    };
    let stderr_str = String::from_utf8_lossy(&stderr);
    let stdout_str = String::from_utf8_lossy(&stdout);
    let exit_code = unsafe { sandlock_result_exit_code(rr) };
    // EACCES is 13; if the path-read worked the child saw errno=13. If a
    // different errno appears the handler ran but `mem_read_cstr` failed
    // and we fell through — fail with a diagnostic message rather than
    // silently masking.
    assert!(
        stderr_str.contains("errno=13"),
        "expected handler to inject EACCES via mem_read_cstr; \
         exit={} stdout={:?} stderr={:?}",
        exit_code, stdout_str, stderr_str,
    );

    unsafe { sandlock_result_free(rr); }
    unsafe { sandlock_sandbox_free(policy); }
}
