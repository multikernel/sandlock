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

    // Plant a sentinel covering the first 8 bytes of the union (the
    // largest scalar variant) before each tag-only setter. A setter
    // documented as "kind only" that accidentally stomps the payload
    // would clobber the sentinel.
    const SENTINEL: u64 = 0xDEAD_BEEF_CAFE_F00D;

    // Writing through a union field is safe; reading is unsafe (we
    // might be looking at bytes deposited by a different variant). The
    // sentinel writes therefore need no `unsafe`, the post-condition
    // reads do.
    a.payload.none = SENTINEL;
    unsafe { sandlock_action_set_continue(&mut a) };
    assert_eq!(a.kind, sandlock_action_kind_t::Continue as u32);
    assert_eq!(unsafe { a.payload.none }, SENTINEL,
               "set_continue must be tag-only and leave payload untouched");

    unsafe { sandlock_action_set_errno(&mut a, 13) };
    assert_eq!(a.kind, sandlock_action_kind_t::Errno as u32);
    assert_eq!(unsafe { a.payload.errno_value }, 13);

    unsafe { sandlock_action_set_return_value(&mut a, -1) };
    assert_eq!(a.kind, sandlock_action_kind_t::ReturnValue as u32);
    assert_eq!(unsafe { a.payload.return_value }, -1);

    a.payload.none = SENTINEL;
    unsafe { sandlock_action_set_hold(&mut a) };
    assert_eq!(a.kind, sandlock_action_kind_t::Hold as u32);
    assert_eq!(unsafe { a.payload.none }, SENTINEL,
               "set_hold must be tag-only and leave payload untouched");

    unsafe { sandlock_action_set_kill(&mut a, libc::SIGKILL, 4321) };
    assert_eq!(a.kind, sandlock_action_kind_t::Kill as u32);
    assert_eq!(unsafe { a.payload.kill.sig }, libc::SIGKILL);
    assert_eq!(unsafe { a.payload.kill.pgid }, 4321);
}

#[test]
fn action_out_layout_is_stable() {
    // Size + align are gross guards; pin down field offsets so a
    // field reorder that preserves size still gets caught.
    use std::mem::{align_of, size_of, MaybeUninit};
    use sandlock_ffi::handler::sandlock_action_out_t;

    assert_eq!(size_of::<sandlock_action_out_t>(), 24,
               "size drift breaks the C ABI layout");
    assert_eq!(align_of::<sandlock_action_out_t>(), 8,
               "align drift breaks the C ABI layout");

    // Hand-roll offset_of through MaybeUninit — works on stable Rust
    // without an extra crate. The C header has kind at offset 0 and
    // payload at offset 8 (4 bytes implicit padding after kind).
    let mut probe = MaybeUninit::<sandlock_action_out_t>::uninit();
    let base = probe.as_mut_ptr() as usize;
    let kind_offset = unsafe { std::ptr::addr_of_mut!((*probe.as_mut_ptr()).kind) as usize - base };
    let payload_offset = unsafe { std::ptr::addr_of_mut!((*probe.as_mut_ptr()).payload) as usize - base };
    assert_eq!(kind_offset, 0, "kind must be at offset 0");
    assert_eq!(payload_offset, 8, "payload must be at offset 8 (kind+4 bytes padding)");
}

#[test]
fn notif_data_field_offsets_are_stable() {
    use std::mem::MaybeUninit;
    use sandlock_ffi::notif_repr::sandlock_notif_data_t;

    let probe = MaybeUninit::<sandlock_notif_data_t>::uninit();
    let base = probe.as_ptr() as usize;

    // C header order: id(u64), pid(u32), flags(u32), syscall_nr(i32),
    // arch(u32), instruction_pointer(u64), args([u64;6]). Each
    // `addr_of!` is cast to `*const u8` so the closure-free subtraction
    // works uniformly across the heterogeneous field types.
    assert_eq!(
        unsafe { std::ptr::addr_of!((*probe.as_ptr()).id) as *const u8 as usize - base },
        0,
        "id must be at offset 0",
    );
    assert_eq!(
        unsafe { std::ptr::addr_of!((*probe.as_ptr()).pid) as *const u8 as usize - base },
        8,
        "pid must be at offset 8",
    );
    assert_eq!(
        unsafe { std::ptr::addr_of!((*probe.as_ptr()).flags) as *const u8 as usize - base },
        12,
        "flags must be at offset 12",
    );
    assert_eq!(
        unsafe { std::ptr::addr_of!((*probe.as_ptr()).syscall_nr) as *const u8 as usize - base },
        16,
        "syscall_nr must be at offset 16",
    );
    assert_eq!(
        unsafe { std::ptr::addr_of!((*probe.as_ptr()).arch) as *const u8 as usize - base },
        20,
        "arch must be at offset 20",
    );
    assert_eq!(
        unsafe { std::ptr::addr_of!((*probe.as_ptr()).instruction_pointer) as *const u8 as usize - base },
        24,
        "instruction_pointer must be at offset 24",
    );
    assert_eq!(
        unsafe { std::ptr::addr_of!((*probe.as_ptr()).args) as *const u8 as usize - base },
        32,
        "args must be at offset 32",
    );
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
    // Cover the boundary (one past the highest valid DenyEio=3),
    // a mid-range value, and the extreme u32::MAX. A mutation that
    // rejects only specific values would fail at least one of these.
    for bad in [4u32, 5u32, 99u32, u32::MAX] {
        let h = unsafe {
            sandlock_handler_new(
                Some(test_handler as sandlock_handler_fn_t),
                std::ptr::null_mut(),
                None,
                bad,
            )
        };
        assert!(h.is_null(), "expected null for on_exception={bad}");
    }
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

/// Spawn a `sleep 30` child that immediately calls `setpgid(0, 0)` so
/// it becomes its own pgid leader (distinct from the supervisor's
/// pgid). Returns a `HandlerCtx` carrying the child's pid plus the
/// `Child` handle so the caller can reap it.
///
/// Use this in tests that need `FfiHandler::handle` to produce
/// `child_pgid != UNSAFE_PGID` — i.e., where the exception policy's
/// `Kill` arm must remain observable. `fake_ctx()` cannot satisfy
/// that requirement because the test process IS the supervisor, so
/// `getpgid(std::process::id()) == getpgid(0)` and the
/// `pgid == supervisor_pgid` guard would trip, yielding `UNSAFE_PGID`
/// and degrading the policy to `Errno(EPERM)`.
fn fake_ctx_with_isolated_child() -> (HandlerCtx, std::process::Child) {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("30");
    // SAFETY: `setpgid` is async-signal-safe; pid=0 acts on the
    // calling process; pgid=0 creates a new group whose leader is the
    // calling process.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn sleep child");
    let child_pid = child.id() as i32;
    // pre_exec runs after fork; poll briefly for the kernel to
    // observe the pgid change.
    let supervisor_pgid = unsafe { libc::getpgid(0) };
    for _ in 0..50 {
        // SAFETY: signal-safe; positive pid.
        let resolved = unsafe { libc::getpgid(child_pid) };
        if resolved == child_pid && resolved != supervisor_pgid {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let resolved = unsafe { libc::getpgid(child_pid) };
    assert_eq!(
        resolved, child_pid,
        "precondition: pre_exec setpgid(0,0) did not take effect (resolved={resolved})",
    );
    assert_ne!(
        resolved, supervisor_pgid,
        "precondition: child's pgid must differ from supervisor's",
    );
    let ctx = HandlerCtx {
        notif: SeccompNotif {
            id: 1, pid: child_pid as u32, flags: 0,
            data: SeccompData { nr: 39, arch: 0xC000003E,
                                instruction_pointer: 0, args: [0; 6] },
        },
        notif_fd: -1,
    };
    (ctx, child)
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
async fn deferred_ffi_handler_returns_defer_that_resolves_to_callback() {
    // A handler flagged deferred must return NotifAction::Defer (so the
    // supervisor runs it off-loop), and driving that future must yield the
    // same action the C callback would have produced inline.
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(return_value_42),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    unsafe { sandlock_ffi::handler::sandlock_handler_set_deferred(raw, true) };
    let h = unsafe { FfiHandler::from_raw(raw) };
    let cx = fake_ctx();
    let action = h.handle(&cx).await;
    let deferred = match action {
        NotifAction::Defer(d) => d,
        other => panic!("deferred handler must return Defer, got {other:?}"),
    };
    assert!(matches!(deferred.run().await, NotifAction::ReturnValue(42)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_deferred_ffi_handler_stays_inline() {
    // Without the flag, handle() resolves the action inline (no Defer).
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
    assert!(matches!(h.handle(&cx).await, NotifAction::ReturnValue(42)));
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
    // The child script writes exactly `str(os.getpid())` with
    // `sys.stdout.write`, so no trailing newline is expected. Match
    // the full stdout — a substring check would silently pass on a
    // mutation that broke dispatch when the real pid happened to
    // contain "777" (pids 7770-7779, 17770-17779, ...).
    assert_eq!(stdout_str.trim_end_matches('\n'), "777",
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
    // Spawn a child that places itself into a fresh process group via
    // `setpgid(0, 0)` in pre_exec. The child therefore becomes its own
    // pgid leader: `getpgid(child_pid) == child_pid`, and crucially
    // `getpgid(child_pid) != getpgid(0)` (the supervisor's pgid).
    //
    // The supervisor_pgid guard added in the defense-in-depth pass would
    // otherwise refuse the substitution and fall back to the bare pid.
    // By breaking the child away into its own group we keep this test
    // exercising the happy path: zero pgid in a Kill action is replaced
    // with the resolved pgid (here `== child_pid`, but reached through
    // the substitution branch — not the supervisor-guard fallback).
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("30");
    unsafe {
        cmd.pre_exec(|| {
            // SAFETY: `setpgid` is async-signal-safe; pid=0 acts on the
            // calling process; pgid=0 creates a new group whose leader
            // is the calling process.
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn sleep child");
    let child_pid = child.id() as i32;
    let supervisor_pgid = unsafe { libc::getpgid(0) };
    // Poll briefly because pre_exec runs after fork but the parent may
    // observe the pgid change asynchronously.
    let mut resolved_pgid = unsafe { libc::getpgid(child_pid) };
    for _ in 0..50 {
        if resolved_pgid == child_pid {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        resolved_pgid = unsafe { libc::getpgid(child_pid) };
    }
    // The child is its own pgid leader; supervisor's pgid is distinct.
    assert_eq!(
        resolved_pgid, child_pid,
        "precondition: pre_exec setpgid(0,0) should leave child as its own pgid leader",
    );
    assert_ne!(
        resolved_pgid, supervisor_pgid,
        "precondition: child's pgid must differ from supervisor's pgid for the substitution branch to fire",
    );
    let expected_pgid = child_pid;

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

// ---- Group K: defense-in-depth guards for child pgid resolution ----------
//
// These tests verify the three guard rails in `FfiHandler::handle` that
// protect against the supervisor-suicide vector when resolving the
// fallback pgid for `Kill { pgid: 0 }` actions.

fn fake_ctx_with_pid(pid: u32) -> HandlerCtx {
    HandlerCtx {
        notif: SeccompNotif {
            id: 1,
            pid,
            flags: 0,
            data: SeccompData {
                nr: 39,
                arch: 0xC000_003E,
                instruction_pointer: 0,
                args: [0; 6],
            },
        },
        notif_fd: -1,
    }
}

extern "C-unwind" fn k_handler_set_kill_sigkill_zero_pgid(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_kill(out, libc::SIGKILL, 0) };
    0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k1_pgid_resolution_rejects_pid_zero() {
    // notif.pid == 0 can occur in nested PID namespaces (Kubernetes
    // pod-in-pod, KubeVirt, DinD). The earlier resolution fell back to
    // the bare pid (`0`) here, and `translate_action`'s `Kill` arm then
    // produced `Kill { pgid: 0 }`. POSIX `killpg(0, sig)` is "signal
    // the caller's process group" — supervisor suicide, the very
    // vector this resolution exists to close.
    //
    // The new resolution flags this case via `UNSAFE_PGID`.
    // `translate_action`'s `Kill` arm refuses substitution and returns
    // `None`, which routes the dispatcher onto the configured
    // exception policy (here `Continue`).
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(k_handler_set_kill_sigkill_zero_pgid),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Continue as u32,
        )
    };
    let handler = unsafe { FfiHandler::from_raw(raw) };
    let cx = fake_ctx_with_pid(0);
    let action = handler.handle(&cx).await;
    assert!(
        matches!(action, NotifAction::Continue),
        "expected exception-policy fallback (Continue) when no safe pgid available, got {action:?}",
    );
}

// Defence-in-depth: in addition to the unit-level assertion above,
// verify directly that the supervisor's process group is NOT signalled
// when the lethal-pgid path triggers. We register a SIGURG handler on
// the test process (a signal not used by tokio or by the test runtime),
// run a callback that arms a `Kill { sig: SIGURG, pgid: 0 }` action
// through the FFI handler dispatch, and assert the counter never
// increments. If the old behaviour (substitute pgid=0 and dispatch)
// regressed, the supervisor's group would receive SIGURG and the
// assertion would fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k1_no_supervisor_signal_on_pid_zero_kill() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SIGURG_COUNT: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn sigurg_handler(_: libc::c_int) {
        SIGURG_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    // SAFETY: installing a signal handler is signal-safe; the handler
    // itself touches only an AtomicUsize (lock-free, async-signal-safe
    // on Linux).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigurg_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGURG, &sa, std::ptr::null_mut());
    }
    SIGURG_COUNT.store(0, Ordering::SeqCst);

    extern "C-unwind" fn arm_lethal_kill(
        _ud: *mut std::ffi::c_void,
        _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
        _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
        out: *mut sandlock_ffi::handler::sandlock_action_out_t,
    ) -> i32 {
        unsafe { sandlock_ffi::handler::sandlock_action_set_kill(out, libc::SIGURG, 0) };
        0
    }
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(arm_lethal_kill),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Continue as u32,
        )
    };
    let handler = unsafe { FfiHandler::from_raw(raw) };
    let cx = fake_ctx_with_pid(0); // pid=0 -> UNSAFE_PGID
    let action = handler.handle(&cx).await;

    // The action must be Continue (exception-policy fallback), NOT a
    // Kill that send_response would forward to killpg(0).
    assert!(
        matches!(action, NotifAction::Continue),
        "action must not be Kill when no safe pgid is available; got {action:?}",
    );

    // Give the OS a moment in case SIGURG was actually delivered.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        SIGURG_COUNT.load(Ordering::SeqCst),
        0,
        "supervisor's process group must NOT receive the signal",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k2_pgid_resolution_rejects_supervisor_pgid_match() {
    // Spawn a child WITHOUT pre_exec setpgid, so it inherits the
    // supervisor's process group. `getpgid(child_pid) == getpgid(0) ==
    // supervisor_pgid`. Earlier versions fell back to the bare pid here
    // (Kill { pgid: child_pid }), but that left the substitution
    // semantics under-defined: `killpg(child_pid)` succeeds only if
    // child_pid happens to also be a pgid. With the new resolution
    // we flag the case via `UNSAFE_PGID`, and `translate_action`'s
    // `Kill` arm refuses substitution — routing the dispatcher onto
    // the exception policy (here `Continue`).
    let supervisor_pgid = unsafe { libc::getpgid(0) };
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep child");
    let child_pid = child.id() as i32;

    // The child inherits the supervisor's pgid by default. Confirm the
    // precondition holds; otherwise this test cannot discriminate.
    let resolved_pgid = unsafe { libc::getpgid(child_pid) };
    assert_eq!(
        resolved_pgid, supervisor_pgid,
        "precondition: child should inherit supervisor's pgid; got {resolved_pgid}, supervisor={supervisor_pgid}",
    );

    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(k_handler_set_kill_sigkill_zero_pgid),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Continue as u32,
        )
    };
    let handler = unsafe { FfiHandler::from_raw(raw) };
    let cx = fake_ctx_with_pid(child_pid as u32);
    let action = handler.handle(&cx).await;

    // Reap the child regardless of assertion outcome.
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        matches!(action, NotifAction::Continue),
        "expected exception-policy fallback (Continue) when child's pgid matches supervisor's (supervisor_pgid={supervisor_pgid}), got {action:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn k3_pgid_resolution_falls_back_on_esrch() {
    // Use a clearly-dead pid that will never exist on this host.
    // `getpgid(i32::MAX)` returns -1 with ESRCH on Linux. Earlier
    // versions fell back to the bare pid here, producing
    // `Kill { pgid: i32::MAX }` — which the kernel would reject with
    // ESRCH in the response path, but only after `translate_action`
    // had emitted a Kill action. The new resolution flags the case
    // via `UNSAFE_PGID`; `translate_action`'s `Kill` arm refuses
    // substitution and routes through the exception policy
    // (here `Continue`).
    let dead_pid: u32 = i32::MAX as u32;

    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(k_handler_set_kill_sigkill_zero_pgid),
            std::ptr::null_mut(),
            None,
            sandlock_exception_policy_t::Continue as u32,
        )
    };
    let handler = unsafe { FfiHandler::from_raw(raw) };
    let cx = fake_ctx_with_pid(dead_pid);
    let action = handler.handle(&cx).await;
    assert!(
        matches!(action, NotifAction::Continue),
        "expected exception-policy fallback (Continue) on ESRCH, got {action:?}",
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
    // Use an isolated child so the resolved child_pgid is not
    // UNSAFE_PGID — otherwise the exception policy's Kill arm
    // (correctly) degrades to Errno(EPERM) to avoid supervisor
    // suicide, and the assertion below would not exercise the
    // Kill-path the test exists to cover.
    let (cx, mut child) = fake_ctx_with_isolated_child();
    let action = h.handle(&cx).await;
    let _ = child.kill();
    let _ = child.wait();
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
    // Use an isolated child so the Kill exception policy is observable
    // (rationale identical to `ffi_handler_kill_policy_on_callback_rc_nonzero`).
    let (cx, mut child) = fake_ctx_with_isolated_child();
    let action = h.handle(&cx).await;
    let _ = child.kill();
    let _ = child.wait();
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

static NULL_UD_DROP_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

extern "C-unwind" fn counting_null_ud_dropper(ud: *mut std::ffi::c_void) {
    // Sanity: confirm the dropper sees the null ud we passed in.
    assert!(ud.is_null(), "dropper invoked with non-null ud unexpectedly");
    NULL_UD_DROP_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
fn handler_new_with_null_ud_still_invokes_dropper() {
    // C header guarantees ud_drop fires exactly once on free, regardless
    // of whether ud is null. C-side droppers can mirror free(NULL)
    // semantics themselves; the Rust container does not gate on ud.

    NULL_UD_DROP_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
    let h = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            std::ptr::null_mut(), // <-- null ud
            Some(counting_null_ud_dropper),
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(!h.is_null());
    assert_eq!(
        NULL_UD_DROP_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "dropper must not fire before sandlock_handler_free",
    );
    unsafe { sandlock_handler_free(h) };
    assert_eq!(
        NULL_UD_DROP_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "dropper must fire exactly once during Drop",
    );
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
fn run_with_handlers_rejects_oversize_argc() {
    // Defence-in-depth: `argc` is a `u32` from C, so a malicious or
    // buggy caller could pass e.g. `u32::MAX` with a small backing
    // array. Without an upper bound, `argv_from_c` would dereference
    // four billion pointer slots before returning. We cap at 4096
    // (vastly larger than any plausible argv) and reject anything
    // above.
    use sandlock_ffi::*;
    let builder = sandlock_sandbox_builder_new();
    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    let arg0 = CString::new("/bin/true").unwrap();
    // Backing argv has only one real entry; we lie about argc to
    // exercise the bound check. The FFI must reject before reading
    // past the first slot.
    let argv = [arg0.as_ptr()];
    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            std::ptr::null(),
            argv.as_ptr(),
            5000, // > MAX_ARGV (4096)
            std::ptr::null(),
            0,
        )
    };
    assert!(rr.is_null(), "expected null result for argc > MAX_ARGV");

    unsafe { sandlock_sandbox_free(policy); }
}

#[test]
fn run_with_handlers_rejects_oversize_nregistrations() {
    // Mirror of `..._oversize_argc` for the registration count.
    // A `nregistrations = usize::MAX` with a small backing array
    // would hand `slice::from_raw_parts` a length larger than the
    // allocation — UB. The FFI must refuse before that point.
    use sandlock_ffi::*;
    let builder = sandlock_sandbox_builder_new();
    let policy = {
        let mut err: i32 = 0;
        unsafe { sandlock_sandbox_build(builder, &mut err, std::ptr::null_mut()) }
    };
    assert!(!policy.is_null(), "policy build failed");

    let arg0 = CString::new("/bin/true").unwrap();
    let argv = [arg0.as_ptr()];
    // Single real registration slot; we lie about the count.
    // `handler` is null so even if the bound check were bypassed the
    // validation pass would still fail — that is fine because the
    // bound check must trip first (a missing check would have us
    // walk 5000 invalid slots before noticing).
    let regs = [sandlock_handler_registration_t {
        syscall_nr: libc::SYS_getpid,
        handler: std::ptr::null_mut(),
    }];
    let rr = unsafe {
        sandlock_run_with_handlers(
            policy,
            std::ptr::null(),
            argv.as_ptr(),
            argv.len() as u32,
            regs.as_ptr(),
            5000, // > MAX_REGISTRATIONS (4096)
        )
    };
    assert!(rr.is_null(), "expected null result for nregistrations > MAX_REGISTRATIONS");

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

    // The supervisor owns and frees the valid handler even when the
    // call rejects the array because of a null entry. We assert this
    // by registering `one_shot_dropper` and verifying it fires
    // exactly once — from the supervisor's `release_registrations`,
    // not from a manual `sandlock_handler_free` (which would now be
    // a double-free per the always-consume contract documented in
    // sandlock.h).
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
    assert_eq!(
        ONE_SHOT_DROPPER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "dropper must fire exactly once (from the supervisor's release_registrations)",
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
    // The child writes exactly `getpid|getppid` with `sys.stdout.write`
    // — no trailing newline. Exact-match catches mutations where one
    // handler silently fails but the real pid/ppid still contains the
    // sentinel substring.
    assert_eq!(
        stdout_str.trim_end_matches('\n'),
        "111|222",
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

// ---------------------------------------------------------------------------
// Ownership regression tests (A1, A2, A3, A5)
// ---------------------------------------------------------------------------
//
// These exercise the four ownership/leak gaps that adversarial review
// surfaced after the initial handler ABI landed:
//
//   * A1: a callback that arms `InjectFdSend` then panics or returns
//     non-zero must NOT leak the supervisor-side srcfd.
//   * A2: a callback that writes the `InjectFdSendTracked` discriminant
//     by hand (no setter is exposed but the value is public in the C
//     header) must NOT leak the supervisor-side srcfd.
//   * A3: `sandlock_run_with_handlers` early-return paths (null policy,
//     invalid argv, invalid name) must still consume the registered
//     handler containers — the documented contract is "ownership
//     transfers on entry, regardless of return value".
//   * A5: `sandlock_handler_free` was `extern "C"`, so a panicking
//     `ud_drop` would abort. Switched to `extern "C-unwind"`; verify a
//     panic propagates back instead of aborting the process.

// A small pipe helper used by the inject-fd drain tests below. Returns
// `(read_end, write_end)`. The write end is what the handler hands to
// the supervisor as the "inject" srcfd; the read end stays in this
// test and observes EOF once the drain path closes the write end.
fn make_pipe() -> (i32, i32) {
    // Use `pipe2` with `O_CLOEXEC` so concurrent tests that spawn
    // children (via std::process::Command, including
    // `fake_ctx_with_isolated_child`) do not inherit a copy of the
    // write end. Without this, an inherited duplicate keeps the read
    // end from observing EOF even after the supervisor's drain path
    // closes its own copy — the EOF-drain assertion would then hang
    // on EAGAIN instead of returning 0.
    //
    // SAFETY: `libc::pipe2` writes exactly two fds into the array on
    // success and returns 0; we assert success below.
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "pipe2() failed: errno={}", std::io::Error::last_os_error());
    (fds[0], fds[1])
}

// Waits up to ~2 seconds for `fd` to reach EOF, returning 0 on EOF,
// the byte count if any data was written (shouldn't happen in the
// drain tests), or -1 on timeout / poll error. Uses `poll(2)` watching
// POLLHUP rather than a single nonblocking `read` because the
// `pipe2(O_CLOEXEC)` defense in `make_pipe` is incomplete: CLOEXEC
// closes the inherited duplicate only at `exec(2)`, so a sibling test
// that's mid-fork-exec can transiently hold our write end open and
// suppress EOF on the first read. Polling for POLLHUP lets the kernel
// notify us once the last writer (including any short-lived inherited
// copy) is gone.
fn wait_for_eof(fd: i32) -> isize {
    const TIMEOUT_MS: i32 = 2000;
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: `pfd` is a stack-local with a single valid fd; `poll`
    // reads/writes only the supplied entry.
    let pret = unsafe { libc::poll(&mut pfd, 1, TIMEOUT_MS) };
    if pret <= 0 {
        return -1;
    }
    // POLLHUP is reported in `revents` unconditionally when every
    // writer has closed; readers then return 0 from `read`.
    if pfd.revents & libc::POLLHUP != 0 {
        return 0;
    }
    // Readable but not hung up: data was written. Surface the count so
    // the caller's assertion includes informative output.
    // SAFETY: `read` writes at most one byte into the on-stack buffer.
    unsafe {
        let mut buf = [0u8; 1];
        libc::read(fd, buf.as_mut_ptr() as *mut std::ffi::c_void, 1)
    }
}

extern "C-unwind" fn arm_inject_fd_then_panic(
    ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    // The test stashes the write-end fd in a heap-allocated i32 and
    // passes its pointer as `ud`. Read the fd, arm the inject action,
    // then panic — the dispatcher must still drain the fd.
    // SAFETY: `ud` points to a live `i32` for the duration of this call
    // (owned by the test).
    let fd = unsafe { *(ud as *const i32) };
    unsafe { sandlock_ffi::handler::sandlock_action_set_inject_fd_send(out, fd, 0) };
    panic!("test panic after arming InjectFdSend");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a1_ffi_handler_drains_inject_fd_on_panic() {
    // Bug A1 regression hook: a C handler that calls
    // `sandlock_action_set_inject_fd_send` and then panics used to leak
    // the supervisor-side srcfd. After the fix, the dispatcher's
    // catch-unwind path drains the pending payload, closing the fd.
    //
    // The exception policy below is `Kill`. With `fake_ctx()` (test
    // process's own pid), the pgid resolution sees
    // `pgid == supervisor_pgid` and yields `UNSAFE_PGID`. The Kill
    // exception arm then degrades to `Errno(EPERM)` (D-new-1: avoid
    // supervisor suicide via killpg(0)). The drain assertion below is
    // the load-bearing one for this regression hook — the exception
    // action just demonstrates that the dispatcher routed onto the
    // policy fallback at all.
    let (read_fd, write_fd) = make_pipe();
    // Heap-allocated so the pointer stays valid across spawn_blocking.
    let fd_holder: Box<i32> = Box::new(write_fd);
    let fd_ptr = Box::into_raw(fd_holder) as *mut std::ffi::c_void;

    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(arm_inject_fd_then_panic),
            fd_ptr,
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    // SAFETY: `raw` was just produced and is non-null.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let action = h.handle(&fake_ctx()).await;
    assert!(
        matches!(action, NotifAction::Errno(e) if e == libc::EPERM),
        "panic must route to the exception-policy fallback (Kill degraded to EPERM under UNSAFE_PGID), got {action:?}",
    );

    // After `handle` returns, the drain path should have closed
    // `write_fd`. Poll for EOF via POLLHUP with a timeout; if the leak
    // were still present, no writer would ever close and the poll
    // would time out (-1).
    let n = wait_for_eof(read_fd);
    assert_eq!(
        n, 0,
        "expected EOF on read end (write end closed by drain); got n={n}",
    );

    // Reclaim the heap allocation for the fd holder so the test is
    // leak-clean. `write_fd` itself is owned by the drain path; do NOT
    // close it here.
    // SAFETY: `fd_ptr` came from `Box::into_raw` on a `Box<i32>`.
    unsafe { drop(Box::from_raw(fd_ptr as *mut i32)); }
    // SAFETY: `read_fd` is still open; close it.
    unsafe { libc::close(read_fd); }
}

extern "C-unwind" fn arm_inject_fd_send_tracked_discriminant(
    ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    // Write the InjectFdSendTracked discriminant by hand. The setter
    // is not exposed in this release, but the discriminant value is
    // public in the C header, so a C caller could do exactly this.
    // SAFETY: `ud` and `out` are valid for the duration of this call.
    let fd = unsafe { *(ud as *const i32) };
    unsafe {
        (*out).kind = sandlock_ffi::handler::sandlock_action_kind_t::InjectFdSendTracked as u32;
        (*out).payload.inject_send_tracked =
            sandlock_ffi::handler::sandlock_action_inject_tracked_t {
                srcfd: fd,
                newfd_flags: 0,
                tracker: 0,
            };
    }
    0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a2_ffi_handler_drains_inject_fd_tracked_discriminant() {
    // Bug A2 regression hook: a C handler that writes the
    // `InjectFdSendTracked` discriminant directly used to leak the
    // srcfd because `translate_action`'s `K::InjectFdSendTracked` arm
    // returned None and dropped the value without reclaiming the fd.
    //
    // See `a1_ffi_handler_drains_inject_fd_on_panic` for why the
    // exception action below is `Errno(EPERM)` rather than `Kill`.
    let (read_fd, write_fd) = make_pipe();
    let fd_holder: Box<i32> = Box::new(write_fd);
    let fd_ptr = Box::into_raw(fd_holder) as *mut std::ffi::c_void;

    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(arm_inject_fd_send_tracked_discriminant),
            fd_ptr,
            None,
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    // SAFETY: `raw` was just produced and is non-null.
    let h = unsafe { FfiHandler::from_raw(raw) };
    let action = h.handle(&fake_ctx()).await;
    assert!(
        matches!(action, NotifAction::Errno(e) if e == libc::EPERM),
        "unsupported tracked discriminant must route to the exception-policy fallback (Kill degraded to EPERM under UNSAFE_PGID), got {action:?}",
    );

    let n = wait_for_eof(read_fd);
    assert_eq!(
        n, 0,
        "expected EOF on read end (write end closed by drain); got n={n}",
    );

    // SAFETY: `fd_ptr` came from `Box::into_raw` on a `Box<i32>`.
    unsafe { drop(Box::from_raw(fd_ptr as *mut i32)); }
    // SAFETY: `read_fd` is still open; close it.
    unsafe { libc::close(read_fd); }
}

static A3_UD_DROPPER_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

extern "C-unwind" fn a3_counter_dropper(_ud: *mut std::ffi::c_void) {
    A3_UD_DROPPER_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

#[test]
fn a3_run_with_handlers_releases_registrations_on_null_policy() {
    // Bug A3 regression hook: the null-policy early-return path used to
    // abandon the registration array. After the fix, the supervisor
    // consumes every non-null handler pointer on entry, regardless of
    // return value.
    A3_UD_DROPPER_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
    // Non-null ud — the dropper itself ignores the value, so any
    // non-null bit pattern works. (Null ud would also fire the
    // dropper per the C header contract; we just pick a non-null
    // sentinel here for clarity of intent.)
    let h = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            0xFEED_FACEusize as *mut std::ffi::c_void,
            Some(a3_counter_dropper),
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(!h.is_null(), "handler_new must produce a valid container");
    let regs = [sandlock_handler_registration_t {
        syscall_nr: libc::SYS_getpid,
        handler: h,
    }];
    let rr = unsafe {
        sandlock_run_with_handlers(
            std::ptr::null(), // null policy triggers the early-return path
            std::ptr::null(), // name
            std::ptr::null(), // argv
            0,                // argc
            regs.as_ptr(),
            regs.len(),
        )
    };
    assert!(rr.is_null(), "expected null result for null policy");
    assert_eq!(
        A3_UD_DROPPER_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "ud_drop must fire on the early-return path (handler consumed by supervisor)",
    );
}

extern "C-unwind" fn a5_panicking_dropper(_ud: *mut std::ffi::c_void) {
    panic!("test panic from dropper");
}

static C_NEW_1_DROPPER_A: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static C_NEW_1_DROPPER_B: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

extern "C-unwind" fn c_new_1_dropper_a(_ud: *mut std::ffi::c_void) {
    C_NEW_1_DROPPER_A.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    panic!("c_new_1 dropper_a panic");
}

extern "C-unwind" fn c_new_1_dropper_b(_ud: *mut std::ffi::c_void) {
    C_NEW_1_DROPPER_B.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

#[test]
fn release_registrations_continues_after_mid_loop_panic() {
    // Bug C-new-1 regression hook: `release_registrations` used to
    // drop each container in a bare loop. A mid-loop panic from a
    // user-supplied `ud_drop` would unwind past the remaining slots,
    // leaving handler containers leaked (partial-consume — violates
    // the "array consumed as a whole" C-ABI contract). After the fix,
    // each drop runs inside `catch_unwind`, the first panic is
    // captured, the loop completes, and the panic is then re-raised
    // through the `extern "C-unwind"` entry point.
    C_NEW_1_DROPPER_A.store(0, std::sync::atomic::Ordering::SeqCst);
    C_NEW_1_DROPPER_B.store(0, std::sync::atomic::Ordering::SeqCst);

    let h1 = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            // Non-null ud sentinel; the dropper does not read the
            // pointer. Null ud would also fire the dropper per the
            // C header contract.
            0xDEAD_BEEFusize as *mut std::ffi::c_void,
            Some(c_new_1_dropper_a),
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    let h2 = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            0xCAFE_F00Dusize as *mut std::ffi::c_void,
            Some(c_new_1_dropper_b),
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(!h1.is_null() && !h2.is_null(), "handler_new must succeed");
    let regs = [
        sandlock_handler_registration_t { syscall_nr: libc::SYS_getpid, handler: h1 },
        sandlock_handler_registration_t { syscall_nr: libc::SYS_getppid, handler: h2 },
    ];
    // Null policy triggers `release_registrations` on the
    // early-return path. With the fix, `sandlock_run_with_handlers`
    // unwinds (extern "C-unwind") because dropper_a panics;
    // `catch_unwind` here captures it.
    let result = std::panic::catch_unwind(|| {
        unsafe {
            sandlock_run_with_handlers(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                regs.as_ptr(),
                regs.len(),
            )
        }
    });
    assert!(
        result.is_err(),
        "expected sandlock_run_with_handlers to propagate the captured panic out of release_registrations",
    );
    assert_eq!(
        C_NEW_1_DROPPER_A.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "dropper_a must have fired exactly once",
    );
    assert_eq!(
        C_NEW_1_DROPPER_B.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "dropper_b must have fired despite dropper_a panicking (no partial-consume leak)",
    );
}

#[test]
fn a5_handler_free_unwinds_on_panicking_dropper() {
    // Bug A5 regression hook: `sandlock_handler_free` used to be
    // `extern "C"`, which aborts on unwind. After the fix it is
    // `extern "C-unwind"` and a panicking `ud_drop` propagates back to
    // the caller's `catch_unwind`.
    //
    // Note: with the bug still present, the process aborts here and
    // the test binary dies — `catch_unwind` cannot recover from an
    // abort. So we write the test against the FIXED code; the
    // destructive sanity check (manually flipping the ABI back to
    // `extern "C"`) is a one-shot manual confirmation.
    let h = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            // Any non-null bit pattern works because the dropper
            // itself never reads through the pointer — it just panics.
            // Null ud would also fire the dropper per the C header
            // contract.
            0xDEAD_BEEFusize as *mut std::ffi::c_void,
            Some(a5_panicking_dropper),
            sandlock_exception_policy_t::Kill as u32,
        )
    };
    assert!(!h.is_null(), "handler_new must produce a valid container");
    let result = std::panic::catch_unwind(|| {
        // SAFETY: `h` is a valid, unregistered container; we
        // intentionally trigger the panicking dropper by freeing it.
        unsafe { sandlock_handler_free(h) };
    });
    assert!(
        result.is_err(),
        "expected sandlock_handler_free to unwind a panicking dropper instead of aborting",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ffi_handler_deny_eio_policy_on_callback_rc_nonzero() {
    extern "C-unwind" fn returns_error(
        _ud: *mut std::ffi::c_void,
        _n: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
        _m: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
        _out: *mut sandlock_ffi::handler::sandlock_action_out_t,
    ) -> i32 {
        -1
    }
    let raw = unsafe {
        sandlock_ffi::handler::sandlock_handler_new(
            Some(returns_error),
            std::ptr::null_mut(),
            None,
            sandlock_ffi::handler::sandlock_exception_policy_t::DenyEio as u32,
        )
    };
    let h = unsafe { sandlock_ffi::handler::FfiHandler::from_raw(raw) };
    let cx = fake_ctx();
    let action = h.handle(&cx).await;
    assert!(matches!(action, NotifAction::Errno(e) if e == libc::EIO),
            "expected Errno(EIO), got {:?}", action);
}

// ----------------------------------------------------------------
// sandlock_syscall_nr — syscall-name -> number resolution.
// ----------------------------------------------------------------

#[test]
fn syscall_nr_resolves_a_known_name() {
    let name = std::ffi::CString::new("openat").unwrap();
    let nr = unsafe { sandlock_ffi::sandlock_syscall_nr(name.as_ptr()) };
    assert_eq!(
        nr, libc::SYS_openat,
        "\"openat\" must resolve to the host-arch SYS_openat",
    );
}

#[test]
fn syscall_nr_rejects_an_unknown_name() {
    // A syscall sandlock does not filter is absent from the resolver
    // table; the function must say so (-1), not guess a number.
    let name = std::ffi::CString::new("definitely_not_a_syscall").unwrap();
    let nr = unsafe { sandlock_ffi::sandlock_syscall_nr(name.as_ptr()) };
    assert_eq!(nr, -1, "an unknown name must resolve to -1");
}

#[test]
fn syscall_nr_rejects_null() {
    let nr = unsafe { sandlock_ffi::sandlock_syscall_nr(std::ptr::null()) };
    assert_eq!(nr, -1, "a NULL name must resolve to -1, not dereference");
}
