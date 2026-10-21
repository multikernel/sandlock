//! Integration tests for the per-protection availability resolution
//! in `landlock::confine_inner`.
//!
//! Most of these tests exercise the policy-driven resolution path
//! directly via the `ProtectionStatus::resolve()` helper with synthetic
//! ABI values, so they are independent of the host kernel's actual
//! Landlock ABI. The one exception is
//! `degraded_policy_confines_and_runs_below_v6`, which builds and runs a
//! genuinely confined child to cover the end-to-end degrade path on a
//! real low-ABI kernel; it self-skips where Landlock is unavailable.

use landlock::AccessFs;
use sandlock_core::landlock_policy::compute_fs_mask;
use sandlock_core::{Protection, ProtectionPolicy, ProtectionState, ProtectionStatus};

// ----------------------------------------------------------------------
// ProtectionStatus::resolve() — Strict
// ----------------------------------------------------------------------

#[test]
fn strict_on_supporting_host_resolves_to_active() {
    // SignalScope needs ABI v6; host claims v6.
    let pol = ProtectionPolicy::strict_all();
    assert_eq!(
        ProtectionStatus::resolve(Protection::SignalScope, landlock::ABI::V6, &pol),
        ProtectionStatus::Active,
        "Strict + available host must resolve to Active"
    );
}

#[test]
fn strictly_unavailable_returns_protection_unavailable() {
    // SignalScope needs ABI v6; host only has v5.
    let pol = ProtectionPolicy::strict_all();
    let r = ProtectionStatus::resolve(Protection::SignalScope, landlock::ABI::V5, &pol);
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
            ProtectionStatus::resolve(p, landlock::ABI::V6, &pol),
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
    let r = ProtectionStatus::resolve(Protection::SignalScope, landlock::ABI::V5, &pol);
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
        ProtectionStatus::resolve(Protection::FsTruncate, landlock::ABI::V6, &pol),
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
    let r = ProtectionStatus::resolve(Protection::SignalScope, landlock::ABI::V6, &pol);
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
    let r = ProtectionStatus::resolve(Protection::SignalScope, landlock::ABI::V5, &pol);
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
    assert_eq!(
        ProtectionStatus::resolve(Protection::FsRefer, landlock::ABI::V4, &pol),
        ProtectionStatus::Active
    );
    assert_eq!(
        ProtectionStatus::resolve(Protection::FsTruncate, landlock::ABI::V4, &pol),
        ProtectionStatus::Active
    );
    assert_eq!(
        ProtectionStatus::resolve(Protection::NetTcp, landlock::ABI::V4, &pol),
        ProtectionStatus::Active
    );
    assert_eq!(
        ProtectionStatus::resolve(Protection::FsIoctlDev, landlock::ABI::V4, &pol),
        ProtectionStatus::Unavailable
    );
    assert_eq!(
        ProtectionStatus::resolve(Protection::SignalScope, landlock::ABI::V4, &pol),
        ProtectionStatus::Unavailable
    );
    assert_eq!(
        ProtectionStatus::resolve(Protection::AbstractUnixSocketScope, landlock::ABI::V4, &pol),
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
        let r = ProtectionStatus::resolve(p, landlock::ABI::V1, &pol);
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
    // must drop AccessFs::Truncate from the handled-fs mask
    // (it shouldn't be there from base_fs_access(landlock::ABI::V1) either, but we
    // assert the post-mask invariant directly).
    let mut pol = ProtectionPolicy::strict_all();
    pol.set(Protection::FsTruncate, ProtectionState::Degradable);
    // Sanity: the protection resolves Degraded on this host.
    assert_eq!(
        ProtectionStatus::resolve(Protection::FsTruncate, landlock::ABI::V1, &pol),
        ProtectionStatus::Degraded
    );
    let mask = compute_fs_mask(landlock::ABI::V1, &pol);
    assert!(
        !mask.contains(AccessFs::Truncate),
        "Degraded FsTruncate must not leave its bit in handled_access_fs (mask={:?})",
        mask
    );
}

#[test]
fn degradable_fs_refer_on_v1_host_masks_off_refer_bit() {
    // FsRefer needs ABI v2; host claims v1. Marking it Degradable
    // must drop AccessFs::Refer from the handled-fs mask.
    let mut pol = ProtectionPolicy::strict_all();
    pol.set(Protection::FsRefer, ProtectionState::Degradable);
    assert_eq!(
        ProtectionStatus::resolve(Protection::FsRefer, landlock::ABI::V1, &pol),
        ProtectionStatus::Degraded
    );
    let mask = compute_fs_mask(landlock::ABI::V1, &pol);
    assert!(
        !mask.contains(AccessFs::Refer),
        "Degraded FsRefer must not leave its bit in handled_access_fs (mask={:?})",
        mask
    );
}

#[test]
fn degradable_fs_ioctl_dev_on_v4_host_masks_off_ioctl_dev_bit() {
    // FsIoctlDev needs ABI v5; host claims v4. Marking it Degradable
    // must drop AccessFs::IoctlDev from the handled-fs mask.
    let mut pol = ProtectionPolicy::strict_all();
    pol.set(Protection::FsIoctlDev, ProtectionState::Degradable);
    assert_eq!(
        ProtectionStatus::resolve(Protection::FsIoctlDev, landlock::ABI::V4, &pol),
        ProtectionStatus::Degraded
    );
    let mask = compute_fs_mask(landlock::ABI::V4, &pol);
    assert!(
        !mask.contains(AccessFs::IoctlDev),
        "Degraded FsIoctlDev must not leave its bit in handled_access_fs (mask={:?})",
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
    let sb = sandlock_core::Sandbox::builder()
        .build_unchecked()
        .expect("build");
    let result = sb.active_protections().expect("ABI detect");
    assert_eq!(result.len(), 6);
}

#[test]
fn active_protections_reports_disabled_for_explicitly_off() {
    let mut sb = sandlock_core::Sandbox::builder()
        .build_unchecked()
        .expect("build");
    sb.protection_policy
        .set(Protection::SignalScope, ProtectionState::Disabled);
    let result = sb.active_protections().expect("ABI detect");
    let signal = result
        .iter()
        .find(|(p, _)| *p == Protection::SignalScope)
        .unwrap();
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
        sb.protection_policy
            .state(Protection::AbstractUnixSocketScope),
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
        sb.protection_policy
            .state(Protection::AbstractUnixSocketScope),
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
#[cfg(feature = "checkpoint")]
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
        let code = match sandlock_core::landlock_policy::confine_filesystem(sandbox) {
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
    if sandlock_core::landlock_abi_version().unwrap_or(0) < landlock::ABI::V6 as u32 {
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

// ----------------------------------------------------------------------
// End-to-end degrade path: real confinement on a low-ABI host
//
// Unlike the synthetic resolve() tests above, this one builds and runs a
// genuinely confined child. A *fully degradable* policy must build on
// any Landlock-capable kernel and confine with whatever the host
// supports, degrading (silently skipping) the scopes it lacks instead of
// hard-failing the way the default `strict_all()` does below ABI 6.
//
// This is the test that gives the ubuntu-22.04 CI runner (a 6.8 Azure
// kernel, Landlock ABI v4) its purpose: there, SignalScope /
// AbstractUnixSocketScope (v6) and FsIoctlDev (v5) resolve to Degraded,
// exercising the opt-out path end-to-end. On a v6 host the same scopes
// resolve Active and the degrade assertion is skipped. Where Landlock is
// unavailable entirely, the test self-skips rather than failing.
// ----------------------------------------------------------------------

#[tokio::test]
async fn degraded_policy_confines_and_runs_below_v6() {
    let abi = match sandlock_core::landlock_abi_version() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Skipping: Landlock unavailable ({e})");
            return;
        }
    };

    let mut builder = sandlock_core::Sandbox::builder();
    for p in Protection::all() {
        builder = builder.allow_degraded(p);
    }
    let sandbox = builder
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .build()
        .expect("a fully-degradable policy must build on any Landlock host");

    // Below ABI 6, every scope the host cannot provide must resolve to
    // Degraded — not Unavailable, which is what makes `confine` refuse.
    if abi < landlock::ABI::V6 as u32 {
        let states = sandbox
            .active_protections()
            .expect("resolve protections against host ABI");
        for (p, status) in &states {
            if p.min_abi() as u32 > abi {
                assert_eq!(
                    *status,
                    ProtectionStatus::Degraded,
                    "{p:?} (needs v{}) on a v{abi} host must degrade, not fail",
                    p.min_abi()
                );
            }
        }
    }

    let result = sandbox
        .with_name("degraded")
        .run(&["echo", "ok"])
        .await
        .expect("a confined child must run under a degraded policy");
    assert!(
        result.success(),
        "degraded-mode confinement must still execute the child"
    );
}

/// Kernels before 6.9 reject PIDFD_SIGNAL_PROCESS_GROUP. Re-run this test in
/// a child that emulates one, so the filter never touches the test process.
#[test]
fn shutdown_without_pidfd_group_signals() {
    const CHILD: &str = "SANDLOCK_TEST_NO_PIDFD_GROUP_SIGNALS";
    if std::env::var_os(CHILD).is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "test_protection::shutdown_without_pidfd_group_signals",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("shutdown hung without pidfd group signals");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    let filter = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 3,
            k: libc::SYS_pidfd_send_signal as u32,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 16 + 3 * 8,
        },
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: 1 << 2,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EINVAL as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
            0
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display().to_string();
    let mut builder = sandlock_core::Sandbox::builder();
    for protection in Protection::all() {
        builder = builder.allow_degraded(protection);
    }
    let policy = builder
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(dir.path())
        .build()
        .unwrap();
    let job = |name: &str| -> i32 {
        std::fs::read_to_string(dir.path().join(name))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    };
    let publish = |name: &str| {
        format!("open('{d}/{name}.tmp','w').write(str(os.getpid())); os.rename('{d}/{name}.tmp','{d}/{name}'); signal.pause()")
    };
    let wait_for = |name: &str| format!("while not os.path.exists('{d}/{name}'): time.sleep(0.01)");
    let gone = |pid: i32| unsafe { libc::kill(pid, 0) } != 0;

    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        // `cmd &` stays in main's group, which the live reaper pins.
        let mut sb = policy.clone();
        sb.spawn(&["sh", "-c", &format!("sleep 60 & echo $! > {d}/r; exit 7")]).await.unwrap();
        assert_eq!(sb.wait().await.unwrap(), sandlock_core::ExitStatus::Code(7));
        let background = job("r");
        assert_eq!(sb.shutdown().await.unwrap().exit_status, sandlock_core::ExitStatus::Code(7));
        assert!(gone(background));

        // A setsid job whose leader lives is reached by number.
        let mut sb = policy.clone();
        let script = format!("import os,signal,time\nif os.fork()==0:\n os.setsid(); {}\n{}", publish("s"), wait_for("s"));
        sb.spawn(&["python3", "-c", &script]).await.unwrap();
        sb.wait().await.unwrap();
        let leader = job("s");
        sb.shutdown().await.unwrap();
        assert!(gone(leader));

        // A double-fork daemon outlived its leader: unreachable, so reported.
        let mut sb = policy.clone();
        let script = format!("import os,signal,time\nif os.fork()==0:\n os.setsid()\n if os.fork()==0:\n  {}\n os._exit(0)\n{}", publish("d"), wait_for("d"));
        sb.spawn(&["python3", "-c", &script]).await.unwrap();
        sb.wait().await.unwrap();
        let daemon = job("d");
        assert!(tokio::time::timeout(std::time::Duration::from_secs(5), sb.shutdown()).await.unwrap().is_err());
        drop(sb);
        assert_eq!(unsafe { libc::kill(daemon, libc::SIGKILL) }, 0);
    });
}
