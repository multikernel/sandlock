//! Integration tests for the user-supplied `ExtraHandler` API.
//!
//! These tests exercise the full plumbing through the kernel: the guest
//! issues a syscall, the BPF filter raises a `USER_NOTIF`, the supervisor
//! walks the dispatch chain (builtins first, extras last) and the kernel
//! applies the `NotifAction` returned by the extra handler.  Any of the
//! following regressions would break them:
//!
//! * extra-handler syscalls not added to the BPF filter → kernel never
//!   raises a notification, the handler silently never fires;
//! * extras registered before builtins → handler observes pre-builtin
//!   arguments (e.g. unnormalized chroot paths) or short-circuits a
//!   security-critical builtin;
//! * `Continue` not translated to `SECCOMP_USER_NOTIF_FLAG_CONTINUE` →
//!   observe-only handlers wedge the guest.
//!
//! Each test uses `SYS_uname` because under the default policy it is
//! **not** intercepted by any builtin (`uname` is added only when the
//! policy sets a `hostname`).  This isolates the behaviour under test
//! to the extras path.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sandlock_core::seccomp::dispatch::{ExtraHandler, HandlerFn};
use sandlock_core::seccomp::notif::NotifAction;
use sandlock_core::{Policy, Sandbox};

/// Read a NUL-terminated path from the sandboxed child's address space.
///
/// Used by tests that need to inspect which `openat`s actually reached
/// their extra handler.  Works without `CAP_SYS_PTRACE` because the test
/// process and the sandboxed child share the same UID, which is the
/// permission `process_vm_readv(2)` actually checks.
fn read_path_from_child(pid: u32, addr: u64) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mut buf = vec![0u8; 4096];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let n = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    let nul = buf.iter().position(|&b| b == 0)?;
    String::from_utf8(buf[..nul].to_vec()).ok()
}

fn base_policy() -> sandlock_core::PolicyBuilder {
    // `fs_read_if_exists` for `/lib64` because aarch64 hosts (Ubuntu CI
    // arm64 runner) do not have it — the dynamic linker lives under
    // `/lib/aarch64-linux-gnu/`.  A strict `fs_read` here makes Landlock
    // refuse to add the rule and the child exits before completing
    // confinement, surfacing as `pipe closed before 4 bytes read`
    // in the parent.  Mirrors the convention used in upstream
    // `test_dry_run`, `test_fork`, `test_netlink_virt`, `test_landlock`.
    Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
}

fn temp_out(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sandlock-test-extras-{}-{}",
        name,
        std::process::id(),
    ))
}

/// An extra handler registered on a syscall that the default policy
/// does not intercept (`SYS_uname`) MUST receive notifications and its
/// `NotifAction::Errno` MUST surface in the guest as the corresponding
/// errno.  This is the security contract: without BPF plumbing the
/// kernel would never raise USER_NOTIF for `uname` and the handler
/// would silently never fire — the maintainer-cited footgun.
#[tokio::test]
async fn extra_handler_intercepts_syscall_outside_builtin_set() {
    let policy = base_policy().build().unwrap();
    let out = temp_out("uname-eacces");
    let cmd = format!("uname -a; echo $? > {}", out.display());

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_handler = Arc::clone(&calls);
    let handler: HandlerFn = Box::new(move |_notif, _ctx, _fd| {
        let calls = Arc::clone(&calls_in_handler);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            NotifAction::Errno(libc::EACCES)
        })
    });

    let extras = vec![ExtraHandler::new(libc::SYS_uname, handler)];

    let result = Sandbox::run_with_extra_handlers(&policy, &["sh", "-c", &cmd], extras)
        .await
        .expect("sandbox spawn failed");

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let code: i32 = contents.trim().parse().unwrap_or(-1);

    assert!(result.success(), "shell wrapper should exit 0");
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "extra handler must have fired at least once for SYS_uname"
    );
    assert_ne!(
        code, 0,
        "uname must observe the errno injected by the extra handler"
    );
}

/// `Continue` must translate into `SECCOMP_USER_NOTIF_FLAG_CONTINUE` so
/// the guest receives the kernel's natural outcome.  This guards an
/// observe-only audit handler from accidentally wedging the guest.
#[tokio::test]
async fn extra_handler_continue_lets_syscall_proceed() {
    let policy = base_policy().build().unwrap();
    let out = temp_out("uname-continue");
    let cmd = format!("uname -a; echo $? > {}", out.display());

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_handler = Arc::clone(&calls);
    let handler: HandlerFn = Box::new(move |_notif, _ctx, _fd| {
        let calls = Arc::clone(&calls_in_handler);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            NotifAction::Continue
        })
    });

    let extras = vec![ExtraHandler::new(libc::SYS_uname, handler)];

    let result = Sandbox::run_with_extra_handlers(&policy, &["sh", "-c", &cmd], extras)
        .await
        .expect("sandbox spawn failed");

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let code: i32 = contents.trim().parse().unwrap_or(-1);

    assert!(result.success());
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "observe-only handler must have seen at least one SYS_uname"
    );
    assert_eq!(
        code, 0,
        "Continue must let the kernel execute uname normally"
    );
}

/// `Sandbox::run_with_extra_handlers(_, _, vec![])` must be observably
/// identical to `Sandbox::run(_, _)`.  Guards the documented backwards
/// compatibility contract.
#[tokio::test]
async fn empty_extras_preserves_default_behaviour() {
    let policy = base_policy().build().unwrap();

    let baseline = Sandbox::run(&policy, &["uname", "-a"]).await.unwrap();
    let with_extras = Sandbox::run_with_extra_handlers(&policy, &["uname", "-a"], Vec::new())
        .await
        .unwrap();

    assert!(baseline.success());
    assert!(with_extras.success());
    assert_eq!(baseline.code(), with_extras.code());
}

/// Cross-handler ordering: an extra registered on a syscall that already
/// has builtin handlers must run *after* them, observing the post-builtin
/// `NotifAction::Continue` state.  `SYS_openat` is intercepted by the
/// always-on /proc-virtualization builtin which returns `Continue` for
/// non-`/proc` paths; the extra must therefore see those `openat`s.
///
/// Verifies the ordering contract end-to-end through the kernel — the
/// unit tests only check `Vec` index ordering inside the dispatch table.
#[tokio::test]
async fn extra_handler_runs_after_builtin_returns_continue() {
    let policy = base_policy().build().unwrap();
    let out = temp_out("openat-cross");
    let cmd = format!("cat /etc/hostname; echo $? > {}", out.display());

    let openat_calls = Arc::new(AtomicUsize::new(0));
    let openat_in_handler = Arc::clone(&openat_calls);
    let handler: HandlerFn = Box::new(move |_notif, _ctx, _fd| {
        let openat_calls = Arc::clone(&openat_in_handler);
        Box::pin(async move {
            openat_calls.fetch_add(1, Ordering::SeqCst);
            // Continue lets the kernel resume the syscall — the builtin
            // already returned Continue for non-/proc paths and this
            // handler must not break the chain.
            NotifAction::Continue
        })
    });

    let extras = vec![ExtraHandler::new(libc::SYS_openat, handler)];

    let result = Sandbox::run_with_extra_handlers(&policy, &["sh", "-c", &cmd], extras)
        .await
        .expect("sandbox spawn failed");

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let code: i32 = contents.trim().parse().unwrap_or(-1);

    assert!(result.success());
    assert!(
        openat_calls.load(Ordering::SeqCst) >= 1,
        "extra on SYS_openat must observe at least one openat after builtins return Continue"
    );
    assert_eq!(
        code, 0,
        "the cat must succeed — Continue from the extra must let the kernel resume"
    );
}

/// Negative half of the security boundary: when a builtin returns a
/// non-`Continue` action, the extra **must not** fire for that
/// notification.  Verified end-to-end through the kernel by relying on
/// the always-on `/proc`-virtualization builtin, which returns `Errno`
/// for `openat` on `/proc/$pid/...` for any pid not in the sandbox set
/// (here: pid 1) and `Continue` for paths outside `/proc`.
///
/// The handler records the resolved path of every `openat` it observes,
/// so the assertion is structural rather than counter-based: the blocked
/// path must be absent from the observed list, while a peer non-blocked
/// path must be present (proving the extra is wired up, not just silent).
#[tokio::test]
async fn builtin_non_continue_blocks_extra() {
    let policy = base_policy().build().unwrap();
    let out = temp_out("openat-blocked-by-builtin");
    let cmd = format!(
        "cat /proc/1/cmdline; cat /etc/hostname; echo $? > {}",
        out.display()
    );

    let observed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_in_handler = Arc::clone(&observed);
    let handler: HandlerFn = Box::new(move |notif, _ctx, _fd| {
        let observed = Arc::clone(&observed_in_handler);
        Box::pin(async move {
            // openat(dirfd, pathname, flags, mode) → args[1] is the path
            let path_addr = notif.data.args[1];
            if let Some(p) = read_path_from_child(notif.pid, path_addr) {
                observed.lock().unwrap().push(p);
            }
            NotifAction::Continue
        })
    });

    let extras = vec![ExtraHandler::new(libc::SYS_openat, handler)];

    let _ = Sandbox::run_with_extra_handlers(&policy, &["sh", "-c", &cmd], extras)
        .await
        .expect("sandbox spawn failed");

    let _ = std::fs::remove_file(&out);
    let paths = observed.lock().unwrap();

    let saw_etc_hostname = paths.iter().any(|p| p == "/etc/hostname");
    let saw_proc_pid = paths.iter().any(|p| p.starts_with("/proc/1/"));

    assert!(
        saw_etc_hostname,
        "extra must observe non-blocked openats, got paths: {:?}",
        *paths,
    );
    assert!(
        !saw_proc_pid,
        "extra must NOT observe openats that the procfs builtin blocked with Errno; got paths: {:?}",
        *paths,
    );
}

/// Multiple extras on the same syscall must run in `Vec` order and the
/// chain stops at the first non-`Continue`.  Verified end-to-end:
/// `extra1` returns `Continue` and increments `c1`; `extra2` returns
/// `Errno(EACCES)` and increments `c2`.  Each guest invocation of
/// `SYS_uname` must produce exactly one increment in each counter
/// (`c1 == c2`), and the guest must observe the `EACCES` from `extra2`.
///
/// If insertion order were not preserved (`extra2` before `extra1`),
/// `c1` would stay at 0 because the `Errno` from `extra2` would
/// short-circuit the chain before `extra1` ran.
#[tokio::test]
async fn chain_of_extras_runs_in_insertion_order() {
    let policy = base_policy().build().unwrap();
    let out = temp_out("chain-order");
    let cmd = format!("uname -a; echo $? > {}", out.display());

    let c1 = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::new(AtomicUsize::new(0));

    let c1_in_h = Arc::clone(&c1);
    let h1: HandlerFn = Box::new(move |_n, _c, _f| {
        let c = Arc::clone(&c1_in_h);
        Box::pin(async move {
            c.fetch_add(1, Ordering::SeqCst);
            NotifAction::Continue
        })
    });

    let c2_in_h = Arc::clone(&c2);
    let h2: HandlerFn = Box::new(move |_n, _c, _f| {
        let c = Arc::clone(&c2_in_h);
        Box::pin(async move {
            c.fetch_add(1, Ordering::SeqCst);
            NotifAction::Errno(libc::EACCES)
        })
    });

    let extras = vec![
        ExtraHandler::new(libc::SYS_uname, h1),
        ExtraHandler::new(libc::SYS_uname, h2),
    ];

    let result = Sandbox::run_with_extra_handlers(&policy, &["sh", "-c", &cmd], extras)
        .await
        .expect("sandbox spawn failed");

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let code: i32 = contents.trim().parse().unwrap_or(-1);

    let v1 = c1.load(Ordering::SeqCst);
    let v2 = c2.load(Ordering::SeqCst);

    assert!(result.success(), "shell wrapper should still exit 0");
    assert!(v1 >= 1, "first handler must have fired");
    assert_eq!(
        v1, v2,
        "every Continue from extra1 must reach extra2 — got c1={} c2={}",
        v1, v2,
    );
    assert_ne!(
        code, 0,
        "uname must observe the EACCES injected by the second handler"
    );
}

/// Default-deny bypass guard: registering an extra on a syscall in
/// `DEFAULT_DENY_SYSCALLS` (e.g. `mount`) MUST be rejected at registration
/// time.  Without this check the extra-syscall ends up in the BPF notif
/// block, which is matched *before* the deny block, so a user handler
/// returning `Continue` would translate into
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and the kernel would actually run
/// `mount` — silently bypassing default deny.
#[tokio::test]
async fn extra_handler_on_default_deny_syscall_is_rejected() {
    let policy = base_policy().build().unwrap();
    let handler: HandlerFn = Box::new(|_notif, _ctx, _fd| {
        Box::pin(async { NotifAction::Continue })
    });
    let extras = vec![ExtraHandler::new(libc::SYS_mount, handler)];

    let result = Sandbox::run_with_extra_handlers(&policy, &["true"], extras).await;

    assert!(
        result.is_err(),
        "extras on a default-deny syscall must be rejected up-front"
    );
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("default-deny") || msg.contains("bypass"),
        "error must explain why the registration is rejected, got: {}",
        msg
    );
}

/// User-supplied `policy.deny_syscalls` must be honoured by the same guard
/// that protects DEFAULT_DENY: an extra registered on a syscall the caller
/// explicitly asked to deny would otherwise let a `Continue` from the
/// handler reach the deny-JEQ via the notif path and bypass the kernel
/// rejection at user-space discretion.
///
/// Counterpart to `extra_handler_on_default_deny_syscall_is_rejected`,
/// driving the user-list branch of `deny_syscall_numbers` (see
/// `crates/sandlock-core/src/context.rs`).  Uses `SYS_mremap` because it is
/// in `syscall_name_to_nr` but **not** in DEFAULT_DENY — putting it into
/// `deny_syscalls` is the only way it lands on the deny list, isolating the
/// user-supplied branch under test from the default-deny branch.
#[tokio::test]
async fn extra_handler_on_user_specified_deny_is_rejected() {
    let policy = base_policy()
        .deny_syscalls(vec!["mremap".into()])
        .build()
        .unwrap();
    let handler: HandlerFn = Box::new(|_notif, _ctx, _fd| {
        Box::pin(async { NotifAction::Continue })
    });
    let extras = vec![ExtraHandler::new(libc::SYS_mremap, handler)];

    let result = Sandbox::run_with_extra_handlers(&policy, &["true"], extras).await;

    assert!(
        result.is_err(),
        "extras on a user-specified deny syscall must be rejected up-front"
    );
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("bypass"),
        "error must explain why the registration is rejected, got: {}",
        msg
    );
    assert!(
        msg.contains(&libc::SYS_mremap.to_string()),
        "error must surface the offending syscall number ({}), got: {}",
        libc::SYS_mremap,
        msg
    );
}
