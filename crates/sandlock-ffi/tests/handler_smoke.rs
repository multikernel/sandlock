//! Integration smoke test for the FFI handler ABI introduced in PR 1.
//! Subsequent tasks expand this file as the surface is built up.

#[test]
fn handler_module_is_exposed() {
    // This forces the `handler` module to be referenced from the cdylib
    // public surface. Replaced by real tests in later tasks.
    let _ = sandlock_ffi::handler::SANDLOCK_HANDLER_MODULE_BUILT;
}

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
    // coverage comes in Task 7 with a live notif_fd.
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

extern "C" fn test_handler(
    _ud: *mut std::ffi::c_void,
    _notif: *const sandlock_ffi::notif_repr::sandlock_notif_data_t,
    _mem: *mut sandlock_ffi::handler::sandlock_mem_handle_t,
    out: *mut sandlock_ffi::handler::sandlock_action_out_t,
) -> i32 {
    unsafe { sandlock_ffi::handler::sandlock_action_set_continue(out) };
    0
}

extern "C" fn dropper(ud: *mut std::ffi::c_void) {
    // Reconstitute the Box we leaked in the test below.
    unsafe { drop(Box::from_raw(ud as *mut u32)); }
}

#[test]
fn handler_new_and_free_round_trip() {
    let ud = Box::into_raw(Box::new(0xABCDu32)) as *mut std::ffi::c_void;
    let on_ex = sandlock_exception_policy_t::Kill as u32;
    let h: *mut sandlock_handler_t = unsafe {
        sandlock_handler_new(
            Some(test_handler as sandlock_handler_fn_t),
            ud,
            Some(dropper),
            on_ex,
        )
    };
    assert!(!h.is_null());
    unsafe { sandlock_handler_free(h) };
    // `dropper` runs and frees the Box; if it does not, leak-sanitizer
    // (when enabled) will flag this test.
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
