//! Integration tests for the C ABI `Protection` setters.
//!
//! These tests drive the FFI symbols directly (no C compilation step)
//! and read back state through the public Rust `Sandbox` API to verify
//! the setters mutate the underlying `ProtectionPolicy`.
//!
//! Protection discriminants are passed as raw `u32` (matching the C ABI
//! and Python ctypes signatures). The `PROT_*` constants below mirror
//! the values defined in `crates/sandlock-ffi/include/sandlock.h`.

use sandlock_core::{Protection, ProtectionState, Sandbox};
use sandlock_ffi::{
    sandlock_protection_min_abi, sandlock_sandbox_builder_allow_degraded,
    sandlock_sandbox_builder_disable, sandlock_sandbox_builder_new,
};

const PROT_FS_REFER: u32 = 0;
const PROT_FS_TRUNCATE: u32 = 1;
const PROT_NET_TCP: u32 = 2;
const PROT_FS_IOCTL_DEV: u32 = 3;
const PROT_SIGNAL_SCOPE: u32 = 4;
const PROT_ABSTRACT_UNIX_SOCKET_SCOPE: u32 = 5;

#[test]
fn protection_min_abi_returns_kernel_documented_floors() {
    // Discriminants in the C ABI must agree with Landlock's
    // documented per-feature ABI floor. Drifting these numbers is a
    // contract break with every external binding.
    assert_eq!(
        sandlock_protection_min_abi(PROT_FS_REFER),
        2,
        "FsRefer requires Landlock ABI v2",
    );
    assert_eq!(
        sandlock_protection_min_abi(PROT_FS_TRUNCATE),
        3,
        "FsTruncate requires Landlock ABI v3",
    );
    assert_eq!(
        sandlock_protection_min_abi(PROT_NET_TCP),
        4,
        "NetTcp requires Landlock ABI v4",
    );
    assert_eq!(
        sandlock_protection_min_abi(PROT_FS_IOCTL_DEV),
        5,
        "FsIoctlDev requires Landlock ABI v5",
    );
    assert_eq!(
        sandlock_protection_min_abi(PROT_SIGNAL_SCOPE),
        6,
        "SignalScope requires Landlock ABI v6",
    );
    assert_eq!(
        sandlock_protection_min_abi(PROT_ABSTRACT_UNIX_SOCKET_SCOPE),
        6,
        "AbstractUnixSocketScope requires Landlock ABI v6",
    );
}

#[test]
fn protection_discriminants_cover_rust_enum_in_order() {
    // The C ABI discriminants MUST mirror `Protection::all()` iteration
    // order so external callers (Python ctypes, hand-written C) can
    // index via the raw integer.
    let rust_order: Vec<Protection> = Protection::all().collect();
    assert_eq!(rust_order.len(), 6, "if a new protection lands, extend the FFI discriminants and the PROT_* constants");
    assert_eq!(rust_order[PROT_FS_REFER as usize], Protection::FsRefer);
    assert_eq!(rust_order[PROT_FS_TRUNCATE as usize], Protection::FsTruncate);
    assert_eq!(rust_order[PROT_NET_TCP as usize], Protection::NetTcp);
    assert_eq!(rust_order[PROT_FS_IOCTL_DEV as usize], Protection::FsIoctlDev);
    assert_eq!(rust_order[PROT_SIGNAL_SCOPE as usize], Protection::SignalScope);
    assert_eq!(
        rust_order[PROT_ABSTRACT_UNIX_SOCKET_SCOPE as usize],
        Protection::AbstractUnixSocketScope,
    );
}

/// Run a build sequence through the FFI: builder_new + the supplied
/// closure (typically chaining `allow_degraded` / `disable` setters)
/// + `build()`. Returns the resulting Sandbox so the caller can
/// inspect `protection_policy`.
fn build_via_ffi<F>(configure: F) -> Sandbox
where
    F: FnOnce(*mut sandlock_core::sandbox::SandboxBuilder) -> *mut sandlock_core::sandbox::SandboxBuilder,
{
    let b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");
    let b = configure(b);
    assert!(!b.is_null(), "configure returned null builder");
    // SAFETY: `b` is a valid Box pointer produced by builder_new and
    // possibly relocated through builder setters.
    let builder = unsafe { *Box::from_raw(b) };
    builder.build().expect("build failed")
}

#[test]
fn builder_allow_degraded_marks_protection_degradable() {
    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_allow_degraded(b, PROT_SIGNAL_SCOPE)
    });
    assert_eq!(
        sandbox.protection_policy.state(Protection::SignalScope),
        ProtectionState::Degradable,
    );
    // Other protections stay strict (default).
    assert_eq!(
        sandbox.protection_policy.state(Protection::FsRefer),
        ProtectionState::Strict,
    );
}

#[test]
fn builder_disable_marks_protection_disabled() {
    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_disable(b, PROT_ABSTRACT_UNIX_SOCKET_SCOPE)
    });
    assert_eq!(
        sandbox.protection_policy.state(Protection::AbstractUnixSocketScope),
        ProtectionState::Disabled,
    );
    assert_eq!(
        sandbox.protection_policy.state(Protection::FsRefer),
        ProtectionState::Strict,
    );
}

#[test]
fn builder_setters_chain_and_last_call_wins() {
    // disable after allow_degraded must end in Disabled (last writer
    // wins, mirroring `ProtectionPolicy::set` semantics).
    let sandbox = build_via_ffi(|b| unsafe {
        let b = sandlock_sandbox_builder_allow_degraded(b, PROT_SIGNAL_SCOPE);
        let b = sandlock_sandbox_builder_disable(b, PROT_SIGNAL_SCOPE);
        // And opt-out two more protections in one chain.
        let b = sandlock_sandbox_builder_allow_degraded(b, PROT_FS_TRUNCATE);
        sandlock_sandbox_builder_disable(b, PROT_NET_TCP)
    });

    assert_eq!(
        sandbox.protection_policy.state(Protection::SignalScope),
        ProtectionState::Disabled,
        "last-writer-wins: disable after allow_degraded",
    );
    assert_eq!(
        sandbox.protection_policy.state(Protection::FsTruncate),
        ProtectionState::Degradable,
    );
    assert_eq!(
        sandbox.protection_policy.state(Protection::NetTcp),
        ProtectionState::Disabled,
    );
    // Untouched protection stays Strict.
    assert_eq!(
        sandbox.protection_policy.state(Protection::FsIoctlDev),
        ProtectionState::Strict,
    );
}

#[test]
fn builder_setters_tolerate_null_builder() {
    // Null in, null out — no panic. Matches the convention of every
    // other `sandlock_sandbox_builder_*` setter.
    let out = unsafe {
        sandlock_sandbox_builder_allow_degraded(std::ptr::null_mut(), PROT_SIGNAL_SCOPE)
    };
    assert!(out.is_null(), "allow_degraded(null, _) must return null");

    let out = unsafe {
        sandlock_sandbox_builder_disable(std::ptr::null_mut(), PROT_FS_REFER)
    };
    assert!(out.is_null(), "disable(null, _) must return null");
}

// ----------------------------------------------------------------
// Out-of-range discriminant guards. The Rust entry-points must reject
// unknown values at the boundary; reaching a Rust `match` over a
// `#[repr(C)]` enum with an out-of-range integer was undefined
// behaviour in the original implementation. These tests pin the new
// validating behaviour: setters become no-ops, `min_abi` returns the
// 0 sentinel.
// ----------------------------------------------------------------

const INVALID_DISCRIMINANTS: &[u32] = &[6, 7, 42, 99, 1_000, u32::MAX];

#[test]
fn protection_min_abi_returns_zero_sentinel_for_unknown_discriminant() {
    for &raw in INVALID_DISCRIMINANTS {
        assert_eq!(
            sandlock_protection_min_abi(raw),
            0,
            "min_abi({}) must return the 0 sentinel for an unknown discriminant",
            raw,
        );
    }
}

#[test]
fn allow_degraded_with_unknown_discriminant_is_a_noop() {
    // The builder pointer must be returned untouched, and the
    // resulting Sandbox must have no `Degradable` state set.
    for &raw in INVALID_DISCRIMINANTS {
        let sandbox = build_via_ffi(|b| unsafe {
            sandlock_sandbox_builder_allow_degraded(b, raw)
        });
        for p in Protection::all() {
            assert_eq!(
                sandbox.protection_policy.state(p),
                ProtectionState::Strict,
                "raw discriminant {} must leave {:?} at the default Strict state",
                raw, p,
            );
        }
    }
}

#[test]
fn disable_with_unknown_discriminant_is_a_noop() {
    for &raw in INVALID_DISCRIMINANTS {
        let sandbox = build_via_ffi(|b| unsafe {
            sandlock_sandbox_builder_disable(b, raw)
        });
        for p in Protection::all() {
            assert_eq!(
                sandbox.protection_policy.state(p),
                ProtectionState::Strict,
                "raw discriminant {} must leave {:?} at the default Strict state",
                raw, p,
            );
        }
    }
}

#[test]
fn unknown_discriminant_does_not_corrupt_subsequent_valid_calls() {
    // A bad call must not poison the builder — a following valid call
    // must succeed normally. Catches a class of bug where the bad path
    // leaks/double-frees the builder allocation.
    let sandbox = build_via_ffi(|b| unsafe {
        let b = sandlock_sandbox_builder_allow_degraded(b, 9999);
        let b = sandlock_sandbox_builder_disable(b, u32::MAX);
        sandlock_sandbox_builder_disable(b, PROT_SIGNAL_SCOPE)
    });
    assert_eq!(
        sandbox.protection_policy.state(Protection::SignalScope),
        ProtectionState::Disabled,
        "valid call after two invalid ones must still take effect",
    );
}
