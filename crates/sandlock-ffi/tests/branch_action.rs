//! C ABI `BranchAction` setters: discriminants map onto the Rust enum, and
//! any other value fails the build instead of picking an action.

use std::ptr;

use sandlock_core::sandbox::{BranchAction, SandboxBuilder};
use sandlock_core::Sandbox;
use sandlock_ffi::{
    sandlock_sandbox_build, sandlock_sandbox_builder_new, sandlock_sandbox_builder_on_error,
    sandlock_sandbox_builder_on_exit,
};

type Setter = unsafe extern "C" fn(*mut SandboxBuilder, u8) -> *mut SandboxBuilder;

const DISCRIMINANTS: [(u8, BranchAction); 4] = [
    (0, BranchAction::Commit),
    (1, BranchAction::Abort),
    (2, BranchAction::Keep),
    (3, BranchAction::Defer),
];

fn build_with(setter: Setter, raw: u8) -> Sandbox {
    let b = unsafe { setter(sandlock_sandbox_builder_new(), raw) };
    assert!(!b.is_null(), "valid discriminant {raw} rejected");
    unsafe { *Box::from_raw(b) }.build().expect("build failed")
}

#[test]
fn on_exit_discriminants_match_rust_enum() {
    for (raw, action) in DISCRIMINANTS {
        assert_eq!(build_with(sandlock_sandbox_builder_on_exit, raw).on_exit, action);
    }
}

#[test]
fn on_error_discriminants_match_rust_enum() {
    for (raw, action) in DISCRIMINANTS {
        assert_eq!(build_with(sandlock_sandbox_builder_on_error, raw).on_error, action);
    }
}

#[test]
fn unrecognized_discriminant_fails_the_build() {
    let setters: [Setter; 2] = [sandlock_sandbox_builder_on_exit, sandlock_sandbox_builder_on_error];
    for setter in setters {
        for raw in [4u8, 99, u8::MAX] {
            let b = unsafe { setter(sandlock_sandbox_builder_new(), raw) };
            assert!(b.is_null(), "discriminant {raw} accepted");

            let mut err = 0;
            let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
            assert!(policy.is_null());
            assert_eq!(err, -1);
        }
    }
}
