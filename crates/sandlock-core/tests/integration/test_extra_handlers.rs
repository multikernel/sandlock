//! Integration tests for the user-supplied `Handler` extension API
//! (`Sandbox::run_with_extra_handlers`).
//!
//! These tests exercise the full plumbing through the kernel: the guest
//! issues a syscall, the BPF filter raises a `USER_NOTIF`, the supervisor
//! walks the dispatch chain (builtins first, user handlers last) and the
//! kernel applies the `NotifAction` returned by the handler.  Any of the
//! following regressions would break them:
//!
//! * user-handler syscalls not added to the BPF filter → kernel never
//!   raises a notification, the handler silently never fires;
//! * user handlers registered before builtins → handler observes
//!   pre-builtin arguments (e.g. unnormalized chroot paths) or
//!   short-circuits a security-critical builtin;
//! * `Continue` not translated to `SECCOMP_USER_NOTIF_FLAG_CONTINUE` →
//!   observe-only handlers wedge the guest.
//!
//! Each test uses `SYS_getcwd` because under the default policy no builtin
//! registers against it (`getcwd` is intercepted only when chroot or COW
//! path virtualization is enabled).  This isolates the behaviour under
//! test to the user-handler path.  The guest must run `/bin/pwd` (the
//! binary), not `pwd` (the shell builtin which reads `$PWD` and never
//! issues the syscall) — otherwise any errno injected by a user handler
//! can't reach the user-visible exit code.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sandlock_core::seccomp::notif::NotifAction;
use sandlock_core::{
    Handler, HandlerCtx, HandlerError, Policy, Sandbox, SandlockError, SyscallError,
};

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
/// does not intercept (`SYS_getcwd`) MUST receive notifications and its
/// `NotifAction::Errno` MUST surface in the guest as the corresponding
/// errno.  This is the security contract: without BPF plumbing the
/// kernel would never raise USER_NOTIF for `getcwd` and the handler
/// would silently never fire — the maintainer-cited footgun.
#[tokio::test]
async fn extra_handler_intercepts_syscall_outside_builtin_set() {
    let policy = base_policy().build().unwrap();
    let out = temp_out("getcwd-eacces");
    let cmd = format!("/bin/pwd; echo $? > {}", out.display());

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_handler = Arc::clone(&calls);
    let handler = move |_cx: &HandlerCtx| {
        let calls = Arc::clone(&calls_in_handler);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            NotifAction::Errno(libc::EACCES)
        }
    };

    let result = Sandbox::run_with_extra_handlers(
        &policy,
        None,
        &["sh", "-c", &cmd],
        [(libc::SYS_getcwd, handler)],
    )
    .await
    .expect("sandbox spawn failed");

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let code: i32 = contents.trim().parse().unwrap_or(-1);

    assert!(result.success(), "shell wrapper should exit 0");
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "extra handler must have fired at least once for SYS_getcwd"
    );
    assert_ne!(
        code, 0,
        "getcwd must observe the errno injected by the extra handler"
    );
}

/// `Continue` must translate into `SECCOMP_USER_NOTIF_FLAG_CONTINUE` so
/// the guest receives the kernel's natural outcome.  This guards an
/// observe-only audit handler from accidentally wedging the guest.
#[tokio::test]
async fn extra_handler_continue_lets_syscall_proceed() {
    let policy = base_policy().build().unwrap();
    let out = temp_out("getcwd-continue");
    let cmd = format!("/bin/pwd; echo $? > {}", out.display());

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_handler = Arc::clone(&calls);
    let handler = move |_cx: &HandlerCtx| {
        let calls = Arc::clone(&calls_in_handler);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            NotifAction::Continue
        }
    };

    let result = Sandbox::run_with_extra_handlers(
        &policy,
        None,
        &["sh", "-c", &cmd],
        [(libc::SYS_getcwd, handler)],
    )
    .await
    .expect("sandbox spawn failed");

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let code: i32 = contents.trim().parse().unwrap_or(-1);

    assert!(result.success());
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "observe-only handler must have seen at least one SYS_getcwd"
    );
    assert_eq!(
        code, 0,
        "Continue must let the kernel execute getcwd normally"
    );
}

/// `Sandbox::run_with_extra_handlers(_, _, vec![])` must be observably
/// identical to `Sandbox::run(_, _)`.  Guards the documented backwards
/// compatibility contract.
#[tokio::test]
async fn empty_extras_preserves_default_behaviour() {
    let policy = base_policy().build().unwrap();

    let baseline = Sandbox::run(&policy, None, &["/bin/pwd"]).await.unwrap();
    let no_handlers: [(i64, fn(&HandlerCtx) -> std::future::Ready<NotifAction>); 0] = [];
    let with_extras = Sandbox::run_with_extra_handlers(&policy, None, &["/bin/pwd"], no_handlers)
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
    let cmd = format!("cat /etc/passwd; echo $? > {}", out.display());

    let openat_calls = Arc::new(AtomicUsize::new(0));
    let openat_in_handler = Arc::clone(&openat_calls);
    let handler = move |_cx: &HandlerCtx| {
        let openat_calls = Arc::clone(&openat_in_handler);
        async move {
            openat_calls.fetch_add(1, Ordering::SeqCst);
            // Continue lets the kernel resume the syscall — the builtin
            // already returned Continue for non-/proc paths and this
            // handler must not break the chain.
            NotifAction::Continue
        }
    };

    let result = Sandbox::run_with_extra_handlers(
        &policy,
        None,
        &["sh", "-c", &cmd],
        [(libc::SYS_openat, handler)],
    )
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
        "cat /proc/1/cmdline; cat /etc/passwd; echo $? > {}",
        out.display()
    );

    let observed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_in_handler = Arc::clone(&observed);
    let handler = move |cx: &HandlerCtx| {
        let observed = Arc::clone(&observed_in_handler);
        let notif = cx.notif;
        async move {
            // openat(dirfd, pathname, flags, mode) → args[1] is the path
            let path_addr = notif.data.args[1];
            if let Some(p) = read_path_from_child(notif.pid, path_addr) {
                observed.lock().unwrap().push(p);
            }
            NotifAction::Continue
        }
    };

    let _ = Sandbox::run_with_extra_handlers(
        &policy,
        None,
        &["sh", "-c", &cmd],
        [(libc::SYS_openat, handler)],
    )
    .await
    .expect("sandbox spawn failed");

    let _ = std::fs::remove_file(&out);
    let paths = observed.lock().unwrap();

    let saw_etc_passwd = paths.iter().any(|p| p == "/etc/passwd");
    let saw_proc_pid = paths.iter().any(|p| p.starts_with("/proc/1/"));

    assert!(
        saw_etc_passwd,
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
/// `SYS_getcwd` must produce exactly one increment in each counter
/// (`c1 == c2`), and the guest must observe the `EACCES` from `extra2`.
///
/// If insertion order were not preserved (`extra2` before `extra1`),
/// `c1` would stay at 0 because the `Errno` from `extra2` would
/// short-circuit the chain before `extra1` ran.
#[tokio::test]
async fn chain_of_extras_runs_in_insertion_order() {
    // Two struct instances with the same concrete type keep the iterator's
    // `H` parameter homogeneous; an `id` field plus a configurable action
    // distinguishes their behaviour.
    struct Counter {
        c: Arc<AtomicUsize>,
        action: NotifAction,
    }

    impl Handler for Counter {
        fn handle<'a>(
            &'a self,
            _cx: &'a HandlerCtx,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NotifAction> + Send + 'a>> {
            Box::pin(async move {
                self.c.fetch_add(1, Ordering::SeqCst);
                match self.action {
                    NotifAction::Continue => NotifAction::Continue,
                    NotifAction::Errno(e) => NotifAction::Errno(e),
                    _ => unreachable!("test only uses Continue / Errno"),
                }
            })
        }
    }

    let policy = base_policy().build().unwrap();
    let out = temp_out("chain-order");
    let cmd = format!("/bin/pwd; echo $? > {}", out.display());

    let c1 = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::new(AtomicUsize::new(0));

    let h1 = Counter {
        c: Arc::clone(&c1),
        action: NotifAction::Continue,
    };
    let h2 = Counter {
        c: Arc::clone(&c2),
        action: NotifAction::Errno(libc::EACCES),
    };

    let result = Sandbox::run_with_extra_handlers(
        &policy,
        None,
        &["sh", "-c", &cmd],
        [(libc::SYS_getcwd, h1), (libc::SYS_getcwd, h2)],
    )
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
        "getcwd must observe the EACCES injected by the second handler"
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
    let handler = |_cx: &HandlerCtx| async { NotifAction::Continue };

    let result = Sandbox::run_with_extra_handlers(
        &policy,
        None,
        &["true"],
        [(libc::SYS_mount, handler)],
    )
    .await;

    assert!(
        result.is_err(),
        "extras on a default-deny syscall must be rejected up-front"
    );
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("deny") || msg.contains("bypass"),
        "error must explain why the registration is rejected, got: {}",
        msg
    );
}

/// User-supplied `SyscallPolicy::Deny` entries must be honoured by the same guard
/// that protects DEFAULT_DENY: an extra registered on a syscall the caller
/// explicitly asked to deny would otherwise let a `Continue` from the
/// handler reach the deny-JEQ via the notif path and bypass the kernel
/// rejection at user-space discretion.
///
/// Counterpart to `extra_handler_on_default_deny_syscall_is_rejected`,
/// driving the user-list branch of `deny_syscall_numbers` (see
/// `crates/sandlock-core/src/context.rs`).  Uses `SYS_mremap` because it is
/// in `syscall_name_to_nr` but **not** in DEFAULT_DENY — putting it into
/// `SyscallPolicy::Deny` is the only way it lands on the deny list, isolating the
/// user-supplied branch under test from the default-deny branch.
#[tokio::test]
async fn extra_handler_on_user_specified_deny_is_rejected() {
    let policy = base_policy()
        .deny_syscalls(vec!["mremap".into()])
        .build()
        .unwrap();
    let handler = |_cx: &HandlerCtx| async { NotifAction::Continue };

    let result = Sandbox::run_with_extra_handlers(
        &policy,
        None,
        &["true"],
        [(libc::SYS_mremap, handler)],
    )
    .await;

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

// ============================================================
// New Handler trait API — integration tests
// ============================================================

/// A closure-shaped handler (via the blanket `impl<F, Fut> Handler for F`)
/// passed to `run_with_extra_handlers` MUST observe notifications and the
/// guest MUST see the handler's `Errno`.  This verifies the parameter-type
/// rework on `run_with_extra_handlers` doesn't drop notifications.
#[tokio::test]
async fn handler_via_blanket_impl_dispatches_in_sandbox() {
    let policy = base_policy().build().unwrap();
    let out = temp_out("blanket-impl-eacces");
    let cmd = format!("/bin/pwd; echo $? > {}", out.display());

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_handler = Arc::clone(&calls);
    let handler = move |_cx: &HandlerCtx| {
        let calls = Arc::clone(&calls_in_handler);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            NotifAction::Errno(libc::EACCES)
        }
    };

    let _result = Sandbox::run_with_extra_handlers(
        &policy,
        None,
        &["sh", "-c", &cmd],
        [(libc::SYS_getcwd, handler)],
    )
    .await
    .expect("run_with_extra_handlers");

    assert!(
        calls.load(Ordering::SeqCst) > 0,
        "handler must have fired through BPF -> notif -> dispatch"
    );

    let exit_code = std::fs::read_to_string(&out)
        .map(|s| s.trim().parse::<i32>().unwrap_or(-1))
        .unwrap_or(-1);
    let _ = std::fs::remove_file(&out);
    assert_ne!(
        exit_code, 0,
        "/bin/pwd must have failed because EACCES was returned"
    );
}

/// A struct-based `Handler` (with state on `&self`, not captured `Arc`)
/// MUST be invocable through `run_with_extra_handlers` and accumulate
/// state across multiple notifications within one sandbox run.
///
/// This exercises the full struct-impl-Handler shape end-to-end: the
/// handler owns its own `Arc<AtomicUsize>` field, gets registered
/// against `SYS_getcwd`, and the dispatch walker invokes
/// `GetcwdCounter::handle` on every notification.  Returning `Errno(EPERM)`
/// serialises the notification cycle (kernel waits for the response before
/// letting the child proceed), so the counter is guaranteed observable
/// after `run_with_extra_handlers` returns.
///
/// Without this test, a regression where dispatch dropped the
/// struct-`Arc<dyn Handler>` path but kept closures-via-blanket-impl
/// working would not be caught at the integration layer.
#[tokio::test]
async fn struct_handler_state_persists_across_sandbox_calls() {
    struct GetcwdCounter {
        calls: Arc<AtomicUsize>,
    }

    impl Handler for GetcwdCounter {
        fn handle<'a>(
            &'a self,
            _cx: &'a HandlerCtx,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NotifAction> + Send + 'a>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                NotifAction::Errno(libc::EPERM)
            })
        }
    }

    let policy = base_policy().build().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = GetcwdCounter {
        calls: Arc::clone(&calls),
    };

    let out = temp_out("struct-handler-counter");
    let cmd = format!("/bin/pwd; /bin/pwd; echo done > {}", out.display());

    Sandbox::run_with_extra_handlers(
        &policy,
        None,
        &["sh", "-c", &cmd],
        [(libc::SYS_getcwd, handler)],
    )
    .await
    .expect("run_with_extra_handlers");
    let _ = std::fs::remove_file(&out);

    assert!(
        calls.load(Ordering::SeqCst) >= 2,
        "struct-based handler MUST have observed at least 2 getcwd calls \
         (state persists across notifications via &self), got {}",
        calls.load(Ordering::SeqCst)
    );
}

/// `run_with_extra_handlers` with a negative syscall number MUST return
/// `HandlerError::InvalidSyscall(SyscallError::Negative)` up-front, before
/// fork.  Closes the silent-never-fires footgun.
#[tokio::test]
async fn run_with_extra_handlers_rejects_negative_syscall() {
    let policy = base_policy().build().unwrap();
    let handler = |_cx: &HandlerCtx| async { NotifAction::Continue };

    let result =
        Sandbox::run_with_extra_handlers(&policy, None, &["true"], [(-5i64, handler)]).await;

    match result {
        Err(SandlockError::Handler(HandlerError::InvalidSyscall(SyscallError::Negative(-5)))) => {}
        other => panic!(
            "expected Handler(InvalidSyscall(Negative(-5))), got {:?}",
            other.err()
        ),
    }
}

/// Same as above but for an arch-unknown syscall number.
#[tokio::test]
async fn run_with_extra_handlers_rejects_arch_unknown_syscall() {
    let policy = base_policy().build().unwrap();
    let handler = |_cx: &HandlerCtx| async { NotifAction::Continue };

    let result =
        Sandbox::run_with_extra_handlers(&policy, None, &["true"], [(99_999i64, handler)]).await;

    match result {
        Err(SandlockError::Handler(HandlerError::InvalidSyscall(
            SyscallError::UnknownForArch(99_999),
        ))) => {}
        other => panic!(
            "expected Handler(InvalidSyscall(UnknownForArch(99_999))), got {:?}",
            other.err()
        ),
    }
}

/// Two handlers passed in one `IntoIterator` on the same syscall MUST
/// fire in iteration order, with the chain short-circuiting on the
/// first non-Continue.  Mirror of `chain_of_extras_runs_in_insertion_order`
/// — that test already covers chain ordering through the dispatch path,
/// this one covers ordering specifically through the new
/// `IntoIterator<Item = (S, H)>` parameter shape.  Two instances of the
/// same struct keep the iterator's `H` type homogeneous.
#[tokio::test]
async fn run_with_extra_handlers_preserves_insertion_order_in_sandbox_chain() {
    struct OrderTracker {
        id: u8,
        order: Arc<Mutex<Vec<u8>>>,
        action: NotifAction,
    }

    impl Handler for OrderTracker {
        fn handle<'a>(
            &'a self,
            _cx: &'a HandlerCtx,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NotifAction> + Send + 'a>> {
            Box::pin(async move {
                self.order.lock().unwrap().push(self.id);
                match self.action {
                    NotifAction::Continue => NotifAction::Continue,
                    NotifAction::Errno(e) => NotifAction::Errno(e),
                    _ => unreachable!("test only uses Continue / Errno"),
                }
            })
        }
    }

    let policy = base_policy().build().unwrap();
    let out = temp_out("run-with-extras-order");
    let cmd = format!("/bin/pwd; echo $? > {}", out.display());

    let order = Arc::new(Mutex::new(Vec::<u8>::new()));
    let h1 = OrderTracker {
        id: 1,
        order: Arc::clone(&order),
        action: NotifAction::Continue,
    };
    let h2 = OrderTracker {
        id: 2,
        order: Arc::clone(&order),
        action: NotifAction::Errno(libc::EACCES),
    };

    Sandbox::run_with_extra_handlers(
        &policy,
        None,
        &["sh", "-c", &cmd],
        [(libc::SYS_getcwd, h1), (libc::SYS_getcwd, h2)],
    )
    .await
    .expect("run_with_extra_handlers");

    let order = order.lock().unwrap();
    assert!(order.len() >= 2, "expected at least 2 dispatches, got {:?}", *order);
    assert_eq!(order[0], 1, "h1 must run before h2; order: {:?}", *order);
    assert_eq!(order[1], 2, "h2 must run after h1; order: {:?}", *order);

    let _ = std::fs::remove_file(&out);
}

/// `run_with_extra_handlers` on a default-deny syscall MUST return
/// `HandlerError::OnDenySyscall` up-front (before fork) — closes the
/// kernel-deny -> NOTIF_FLAG_CONTINUE bypass attack.
#[tokio::test]
async fn run_with_extra_handlers_rejects_handler_on_default_deny_syscall() {
    let policy = base_policy().build().unwrap();
    let handler = |_cx: &HandlerCtx| async { NotifAction::Continue };

    // SYS_mount is in DEFAULT_DENY_SYSCALLS.
    let result =
        Sandbox::run_with_extra_handlers(&policy, None, &["true"], [(libc::SYS_mount, handler)]).await;

    match result {
        Err(SandlockError::Handler(HandlerError::OnDenySyscall { syscall_nr })) => {
            assert_eq!(syscall_nr, libc::SYS_mount);
        }
        other => panic!("expected Handler(OnDenySyscall), got {:?}", other.err()),
    }
}
