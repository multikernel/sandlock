//! C ABI size and time setters forward text to the core grammar, and a value
//! the core refuses comes back from the build with the core's reason.

use std::ffi::{CStr, CString};
use std::ptr;

use sandlock_core::sandbox::{ByteSize, SandboxBuilder};
use sandlock_ffi::{
    sandlock_sandbox_build, sandlock_sandbox_builder_max_disk, sandlock_sandbox_builder_max_memory,
    sandlock_sandbox_builder_new, sandlock_sandbox_builder_time_start, sandlock_string_free,
};

type Setter = unsafe extern "C" fn(*mut SandboxBuilder, *const libc::c_char) -> *mut SandboxBuilder;

fn build_err(setter: Setter, value: &str) -> String {
    let value = CString::new(value).unwrap();
    let b = unsafe { setter(sandlock_sandbox_builder_new(), value.as_ptr()) };
    assert!(!b.is_null());
    let mut err = 0;
    let mut msg = ptr::null_mut();
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, &mut msg) };
    assert!(policy.is_null(), "{value:?} built");
    assert_eq!(err, -1);
    let text = unsafe { CStr::from_ptr(msg) }.to_string_lossy().into_owned();
    unsafe { sandlock_string_free(msg) };
    text
}

#[test]
fn setters_take_the_core_spellings() {
    let mem = CString::new("512M").unwrap();
    let disk = CString::new("1G").unwrap();
    let start = CString::new("1969-07-20T20:17:00.5Z").unwrap();
    let b = unsafe {
        let b = sandlock_sandbox_builder_max_memory(sandlock_sandbox_builder_new(), mem.as_ptr());
        let b = sandlock_sandbox_builder_max_disk(b, disk.as_ptr());
        sandlock_sandbox_builder_time_start(b, start.as_ptr())
    };
    let sb = unsafe { *Box::from_raw(b) }.build().expect("build failed");
    assert_eq!(sb.max_memory, Some(ByteSize::mib(512)));
    assert_eq!(sb.max_disk, Some(ByteSize::gib(1)));
    let moon = std::time::UNIX_EPOCH - std::time::Duration::from_millis(14_182_979_500);
    assert_eq!(sb.time_start, Some(moon));
}

#[test]
fn refused_values_report_the_core_reason() {
    let cases: [(Setter, &str, &str); 4] = [
        (sandlock_sandbox_builder_max_memory, "1.5G", "max_memory"),
        (sandlock_sandbox_builder_max_memory, "1T", "max_memory"),
        (sandlock_sandbox_builder_max_disk, "lots", "max_disk"),
        (sandlock_sandbox_builder_time_start, "1767225600", "time_start"),
    ];
    for (setter, value, knob) in cases {
        let msg = build_err(setter, value);
        assert!(msg.contains(knob), "{value:?}: {msg}");
    }
}

#[test]
fn null_value_fails_the_build() {
    let setters: [Setter; 3] = [
        sandlock_sandbox_builder_max_memory,
        sandlock_sandbox_builder_max_disk,
        sandlock_sandbox_builder_time_start,
    ];
    for setter in setters {
        let b = unsafe { setter(sandlock_sandbox_builder_new(), ptr::null()) };
        assert!(b.is_null());
    }
}
