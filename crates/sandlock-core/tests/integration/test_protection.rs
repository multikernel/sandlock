//! Integration tests for the per-protection availability resolution
//! in `landlock::confine_inner`.
//!
//! These tests exercise the policy-driven resolution path directly via
//! the `ProtectionStatus::resolve()` helper with synthetic ABI values,
//! so they are independent of the host kernel's actual Landlock ABI.

use sandlock_core::landlock::compute_fs_mask;
use sandlock_core::{Protection, ProtectionPolicy, ProtectionState, ProtectionStatus};

// Landlock FS access constants (kernel ABI, stable). Kept local to the
// test so we don't need to expose `crate::sys::structs`. These are bit
// positions defined by `linux/landlock.h`.
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

// ----------------------------------------------------------------------
// ProtectionStatus::resolve() — Strict
// ----------------------------------------------------------------------

#[test]
fn strict_on_supporting_host_resolves_to_active() {
    // SignalScope needs ABI v6; host claims v6.
    let pol = ProtectionPolicy::strict_all();
    assert_eq!(
        ProtectionStatus::resolve(Protection::SignalScope, 6, &pol),
        ProtectionStatus::Active,
        "Strict + available host must resolve to Active"
    );
}

#[test]
fn strictly_unavailable_returns_protection_unavailable() {
    // SignalScope needs ABI v6; host only has v5.
    let pol = ProtectionPolicy::strict_all();
    let r = ProtectionStatus::resolve(Protection::SignalScope, 5, &pol);
    assert_eq!(
        r,
        ProtectionStatus::Unavailable,
        "Strict + unavailable host must resolve to StrictlyUnavailable"
    );
}

#[test]
fn strict_all_on_v6_host_resolves_every_protection_active() {
    // Default strict_all() policy on a kernel meeting the highest floor
    // (v6) yields Active for every protection — this is the load-bearing
    // invariant that preserves pre-refactor confine_inner behaviour.
    let pol = ProtectionPolicy::strict_all();
    for p in Protection::all() {
        assert_eq!(
            ProtectionStatus::resolve(p, 6, &pol),
            ProtectionStatus::Active,
            "{:?} under strict_all on v6 host must be Active",
            p
        );
    }
}

// ----------------------------------------------------------------------
// ProtectionStatus::resolve() — Degradable
// ----------------------------------------------------------------------

#[test]
fn degradable_on_unavailable_host_resolves_to_degraded() {
    let mut pol = ProtectionPolicy::strict_all();
    pol.set(Protection::SignalScope, ProtectionState::Degradable);
    let r = ProtectionStatus::resolve(Protection::SignalScope, 5, &pol);
    assert_eq!(
        r,
        ProtectionStatus::Degraded,
        "Degradable + unavailable host must resolve to Degraded (silent skip)"
    );
}

#[test]
fn degradable_on_supporting_host_resolves_to_active() {
    let mut pol = ProtectionPolicy::strict_all();
    pol.set(Protection::FsTruncate, ProtectionState::Degradable);
    // FsTruncate needs v3.
    assert_eq!(
        ProtectionStatus::resolve(Protection::FsTruncate, 6, &pol),
        ProtectionStatus::Active,
        "Degradable + available host must enforce (Active)"
    );
}

// ----------------------------------------------------------------------
// ProtectionStatus::resolve() — Disabled
// ----------------------------------------------------------------------

#[test]
fn disabled_on_supporting_host_resolves_to_disabled() {
    let mut pol = ProtectionPolicy::strict_all();
    pol.set(Protection::SignalScope, ProtectionState::Disabled);
    let r = ProtectionStatus::resolve(Protection::SignalScope, 6, &pol);
    assert_eq!(
        r,
        ProtectionStatus::Disabled,
        "Disabled must resolve to Disabled regardless of host support"
    );
}

#[test]
fn disabled_on_unavailable_host_resolves_to_disabled() {
    let mut pol = ProtectionPolicy::strict_all();
    pol.set(Protection::SignalScope, ProtectionState::Disabled);
    let r = ProtectionStatus::resolve(Protection::SignalScope, 5, &pol);
    assert_eq!(
        r,
        ProtectionStatus::Disabled,
        "Disabled wins over host availability — never StrictlyUnavailable"
    );
}

// ----------------------------------------------------------------------
// Per-protection ABI floor matrix
// ----------------------------------------------------------------------

#[test]
fn strict_all_on_v4_host_fails_only_for_v5_plus_protections() {
    // Host with ABI v4 supports FsRefer (v2), FsTruncate (v3), NetTcp
    // (v4); fails on FsIoctlDev (v5), SignalScope (v6),
    // AbstractUnixSocketScope (v6).
    let pol = ProtectionPolicy::strict_all();
    assert_eq!(ProtectionStatus::resolve(Protection::FsRefer, 4, &pol), ProtectionStatus::Active);
    assert_eq!(ProtectionStatus::resolve(Protection::FsTruncate, 4, &pol), ProtectionStatus::Active);
    assert_eq!(ProtectionStatus::resolve(Protection::NetTcp, 4, &pol), ProtectionStatus::Active);
    assert_eq!(
        ProtectionStatus::resolve(Protection::FsIoctlDev, 4, &pol),
        ProtectionStatus::Unavailable
    );
    assert_eq!(
        ProtectionStatus::resolve(Protection::SignalScope, 4, &pol),
        ProtectionStatus::Unavailable
    );
    assert_eq!(
        ProtectionStatus::resolve(Protection::AbstractUnixSocketScope, 4, &pol),
        ProtectionStatus::Unavailable
    );
}

#[test]
fn fully_degradable_policy_never_returns_strictly_unavailable_even_on_v1() {
    // A policy that marks every protection Degradable must never
    // produce StrictlyUnavailable, even on a host so old it only
    // supports the v1 base set (no fs-extension protections).
    let mut pol = ProtectionPolicy::strict_all();
    for p in Protection::all() {
        pol.set(p, ProtectionState::Degradable);
    }
    for p in Protection::all() {
        let r = ProtectionStatus::resolve(p, 1, &pol);
        assert!(
            matches!(r, ProtectionStatus::Active | ProtectionStatus::Degraded),
            "{:?} on v1 host with Degradable must not be StrictlyUnavailable, got {:?}",
            p,
            r
        );
    }
}

// ----------------------------------------------------------------------
// compute_fs_mask() — Degraded protections must be masked off
//
// Regression guards for the bug where `compute_fs_mask` only masked
// off `ProtectionStatus::Disabled` bits, leaving a `Degraded` bit in the
// handled-fs mask. The kernel then rejects `landlock_create_ruleset`
// with EINVAL — breaking the `Degradable` silent-skip contract.
//
// Each test pins one extension protection to `Degradable` and feeds
// `compute_fs_mask` a synthetic host ABI below that protection's
// floor, asserting the bit is NOT in the returned mask.
// ----------------------------------------------------------------------

#[test]
fn degradable_fs_truncate_on_v1_host_masks_off_truncate_bit() {
    // FsTruncate needs ABI v3; host claims v1. Marking it Degradable
    // must drop LANDLOCK_ACCESS_FS_TRUNCATE from the handled-fs mask
    // (it shouldn't be there from base_fs_access(1) either, but we
    // assert the post-mask invariant directly).
    let mut pol = ProtectionPolicy::strict_all();
    pol.set(Protection::FsTruncate, ProtectionState::Degradable);
    // Sanity: the protection resolves Degraded on this host.
    assert_eq!(
        ProtectionStatus::resolve(Protection::FsTruncate, 1, &pol),
        ProtectionStatus::Degraded
    );
    let mask = compute_fs_mask(1, &pol);
    assert_eq!(
        mask & LANDLOCK_ACCESS_FS_TRUNCATE,
        0,
        "Degraded FsTruncate must not leave its bit in handled_access_fs (mask=0x{:x})",
        mask
    );
}

#[test]
fn degradable_fs_refer_on_v1_host_masks_off_refer_bit() {
    // FsRefer needs ABI v2; host claims v1. Marking it Degradable
    // must drop LANDLOCK_ACCESS_FS_REFER from the handled-fs mask.
    let mut pol = ProtectionPolicy::strict_all();
    pol.set(Protection::FsRefer, ProtectionState::Degradable);
    assert_eq!(ProtectionStatus::resolve(Protection::FsRefer, 1, &pol), ProtectionStatus::Degraded);
    let mask = compute_fs_mask(1, &pol);
    assert_eq!(
        mask & LANDLOCK_ACCESS_FS_REFER,
        0,
        "Degraded FsRefer must not leave its bit in handled_access_fs (mask=0x{:x})",
        mask
    );
}

#[test]
fn degradable_fs_ioctl_dev_on_v4_host_masks_off_ioctl_dev_bit() {
    // FsIoctlDev needs ABI v5; host claims v4. Marking it Degradable
    // must drop LANDLOCK_ACCESS_FS_IOCTL_DEV from the handled-fs mask.
    let mut pol = ProtectionPolicy::strict_all();
    pol.set(Protection::FsIoctlDev, ProtectionState::Degradable);
    assert_eq!(
        ProtectionStatus::resolve(Protection::FsIoctlDev, 4, &pol),
        ProtectionStatus::Degraded
    );
    let mask = compute_fs_mask(4, &pol);
    assert_eq!(
        mask & LANDLOCK_ACCESS_FS_IOCTL_DEV,
        0,
        "Degraded FsIoctlDev must not leave its bit in handled_access_fs (mask=0x{:x})",
        mask
    );
}

// ----------------------------------------------------------------------
// Sandbox::active_protections() runtime accessor
// ----------------------------------------------------------------------

#[test]
fn active_protections_returns_six_entries() {
    // Construct a default Sandbox; we don't actually run it — just
    // call the accessor. The dev host has Landlock available, so
    // abi_version() should succeed.
    let sb = sandlock_core::Sandbox::builder().build_unchecked().expect("build");
    let result = sb.active_protections().expect("ABI detect");
    assert_eq!(result.len(), 6);
}

#[test]
fn active_protections_reports_disabled_for_explicitly_off() {
    let mut sb = sandlock_core::Sandbox::builder().build_unchecked().expect("build");
    sb.protection_policy.set(Protection::SignalScope, ProtectionState::Disabled);
    let result = sb.active_protections().expect("ABI detect");
    let signal = result.iter().find(|(p, _)| *p == Protection::SignalScope).unwrap();
    assert_eq!(signal.1, ProtectionStatus::Disabled);
}

// ----------------------------------------------------------------------
// SandboxBuilder::allow_degraded / ::disable polarity-out methods
// ----------------------------------------------------------------------

#[test]
fn builder_allow_degraded_sets_state_to_degradable() {
    let sb = sandlock_core::Sandbox::builder()
        .allow_degraded(Protection::SignalScope)
        .build_unchecked()
        .expect("build");
    assert_eq!(
        sb.protection_policy.state(Protection::SignalScope),
        ProtectionState::Degradable
    );
}

#[test]
fn builder_disable_sets_state_to_disabled() {
    let sb = sandlock_core::Sandbox::builder()
        .disable(Protection::AbstractUnixSocketScope)
        .build_unchecked()
        .expect("build");
    assert_eq!(
        sb.protection_policy.state(Protection::AbstractUnixSocketScope),
        ProtectionState::Disabled
    );
}

#[test]
fn builder_methods_are_idempotent_last_wins() {
    let sb = sandlock_core::Sandbox::builder()
        .allow_degraded(Protection::SignalScope)
        .disable(Protection::SignalScope)
        .build_unchecked()
        .expect("build");
    assert_eq!(
        sb.protection_policy.state(Protection::SignalScope),
        ProtectionState::Disabled
    );
}

#[test]
fn builder_methods_fluent_chain() {
    let sb = sandlock_core::Sandbox::builder()
        .allow_degraded(Protection::SignalScope)
        .allow_degraded(Protection::AbstractUnixSocketScope)
        .disable(Protection::FsTruncate)
        .build_unchecked()
        .expect("build");
    assert_eq!(
        sb.protection_policy.state(Protection::SignalScope),
        ProtectionState::Degradable
    );
    assert_eq!(
        sb.protection_policy.state(Protection::AbstractUnixSocketScope),
        ProtectionState::Degradable
    );
    assert_eq!(
        sb.protection_policy.state(Protection::FsTruncate),
        ProtectionState::Disabled
    );
    assert_eq!(
        sb.protection_policy.state(Protection::FsRefer),
        ProtectionState::Strict
    );
}

// ----------------------------------------------------------------------
// Checkpoint round-trip: protection_policy must survive serialization
//
// `Checkpoint::save`/`load` bincode-serialize the whole `Sandbox`. A
// sandbox built with a `disable()` opt-out must restore with that exact
// posture — otherwise restore silently resets to `strict_all()` and, on
// a host that required the opt-out (e.g. a v5 kernel that cannot provide
// a v6 scope), `confine` then fails with ProtectionUnavailable.
//
// This test fails if `protection_policy` is `#[serde(skip)]` (it would
// deserialize back to `Strict`); it passes only when the field and the
// protection enums actually serialize.
// ----------------------------------------------------------------------

#[test]
fn protection_policy_survives_bincode_round_trip() {
    let sb = sandlock_core::Sandbox::builder()
        .disable(Protection::SignalScope)
        .build_unchecked()
        .expect("build");

    let bytes = bincode::serialize(&sb).expect("serialize sandbox");
    let restored: sandlock_core::Sandbox =
        bincode::deserialize(&bytes).expect("deserialize sandbox");

    assert_eq!(
        restored.protection_policy.state(Protection::SignalScope),
        ProtectionState::Disabled,
        "a disabled protection must survive the checkpoint round-trip, \
         not reset to strict_all() on load"
    );
}

// ----------------------------------------------------------------------
// Regression: disable() of an FS protection must not cause confine to
// fail with EINVAL when the sandbox has a writable path.
//
// `compute_fs_mask` drops the disabled bit (REFER/TRUNCATE/IOCTL_DEV)
// from `handled_access_fs`, but the per-path write mask is derived from
// `write_access(abi)` alone. If the two are not intersected, the
// writable-path rule still requests the dropped bit, which is no longer
// a subset of the ruleset's handled accesses, and `landlock_add_rule`
// rejects it with EINVAL, breaking every real sandbox (one that has at
// least one writable path) under `disable(FsRefer/FsTruncate/FsIoctlDev)`.
//
// This must run a real `confine_filesystem` against the host kernel, so
// it forks: confinement is irreversible. NO_NEW_PRIVS is set in the
// child so `restrict_self` succeeds; the child then exits 0 only if
// every `add_path_rule` (including the writable-path rule) was accepted.
// ----------------------------------------------------------------------

/// Run `confine_filesystem(sandbox)` in a forked child and return true
/// iff it succeeds end-to-end (child exits 0). Exit codes: 0 = Ok,
/// 1 = confine_filesystem returned Err (the EINVAL bug), 2 = NO_NEW_PRIVS
/// prctl failed (harness problem, not the code under test).
fn confine_filesystem_succeeds_in_child(sandbox: &sandlock_core::Sandbox) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            unsafe { libc::_exit(2) };
        }
        let code = match sandlock_core::landlock::confine_filesystem(sandbox) {
            Ok(()) => 0,
            Err(_) => 1,
        };
        unsafe { libc::_exit(code) };
    }
    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status), "child did not exit normally");
    libc::WEXITSTATUS(status)
}

#[test]
fn disable_fs_protection_with_writable_path_does_not_einval() {
    // Needs a real v6+ host: the default policy keeps the v6 scope
    // protections Strict, so confine_filesystem would otherwise abort
    // with ProtectionUnavailable before reaching the FS rules.
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    // A writable path is the trigger: without one, no write rule is
    // installed and the handled-vs-rule inconsistency never surfaces.
    // (FsRefer is excluded: disabling it is rejected at build time; see
    // `disable_fsrefer_is_rejected_at_build` below.)
    for p in [Protection::FsTruncate, Protection::FsIoctlDev] {
        let sandbox = sandlock_core::Sandbox::builder()
            .disable(p)
            .fs_write("/tmp")
            .build()
            .expect("build sandbox");

        assert_eq!(
            confine_filesystem_succeeds_in_child(&sandbox),
            0,
            "disable({:?}) + fs_write(\"/tmp\") must confine cleanly, \
             not fail with EINVAL when installing the writable-path rule",
            p
        );
    }
}

// ----------------------------------------------------------------------
// disable(FsRefer) is a footgun: Landlock denies REFER by default even
// when unhandled, so disabling it can only tighten the sandbox, never
// loosen it (contrary to what `disable()` promises). It is rejected at
// build time. `allow_degraded(FsRefer)` stays meaningful and is allowed.
// ----------------------------------------------------------------------

#[test]
fn disable_fsrefer_is_rejected_at_build() {
    let err = sandlock_core::Sandbox::builder()
        .disable(Protection::FsRefer)
        .build()
        .expect_err("disable(FsRefer) must be rejected at build");
    let msg = err.to_string();
    assert!(
        msg.contains("FsRefer"),
        "rejection message should name FsRefer, got: {msg}"
    );

    // The unchecked path must reject it too.
    assert!(
        sandlock_core::Sandbox::builder()
            .disable(Protection::FsRefer)
            .build_unchecked()
            .is_err(),
        "build_unchecked must also reject disable(FsRefer)"
    );

    // allow_degraded(FsRefer) is still meaningful and must build cleanly.
    sandlock_core::Sandbox::builder()
        .allow_degraded(Protection::FsRefer)
        .build()
        .expect("allow_degraded(FsRefer) must remain allowed");
}
