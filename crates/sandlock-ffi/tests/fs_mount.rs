//! Integration tests for the C ABI filesystem-mount setters.
//!
//! `builder_*` tests drive the FFI symbols directly (no C compilation
//! step) and read back state through the public Rust `Sandbox` API.
//!
//! The `read_only_mount_*` test goes the whole way through the C ABI
//! (builder setters, `sandlock_sandbox_build`, `sandlock_run`) and runs a
//! real guest inside a chroot to check what the mount actually enforces:
//! reads succeed, writes are refused. A read-only mount is a policy
//! decision in the seccomp-notify chroot handlers (writes get EACCES),
//! not a kernel `MS_RDONLY` mount, and it only exists under `chroot`.

use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::{c_char, c_int, c_uint};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::ptr;

use sandlock_core::Sandbox;
use sandlock_ffi::{
    sandlock_result_exit_code, sandlock_result_free, sandlock_result_stderr,
    sandlock_result_stdout, sandlock_result_success, sandlock_run, sandlock_sandbox_build,
    sandlock_sandbox_builder_chroot, sandlock_sandbox_builder_fs_mount,
    sandlock_sandbox_builder_fs_mount_ro, sandlock_sandbox_builder_fs_read,
    sandlock_sandbox_builder_fs_write, sandlock_sandbox_builder_fs_read_write, sandlock_sandbox_builder_new, sandlock_sandbox_free,
    sandlock_sandbox_t, sandlock_string_free,
};

// ----------------------------------------------------------------
// Builder-level: what the setters record on the built Sandbox
// ----------------------------------------------------------------

/// Run `builder_new` + the supplied setter chain + `build()`, returning
/// the Sandbox so the caller can inspect `fs_mount` / `fs_mount_ro`.
fn build_via_ffi<F>(configure: F) -> Sandbox
where
    F: FnOnce(
        *mut sandlock_core::sandbox::SandboxBuilder,
    ) -> *mut sandlock_core::sandbox::SandboxBuilder,
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

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn builder_fs_mount_ro_registers_the_mount_and_marks_it_read_only() {
    let (vp, hp) = (cstr("/work"), cstr("/host/work"));
    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, vp.as_ptr(), hp.as_ptr())
    });

    // A read-only mount is still a mount: the pair must be in fs_mount,
    // otherwise nothing is visible at the virtual path at all.
    assert_eq!(
        sandbox.fs_mount,
        vec![(PathBuf::from("/work"), PathBuf::from("/host/work"))],
        "fs_mount_ro must also register the mount mapping",
    );
    // And the virtual path must be on the read-only side list, which is
    // what makes writes fail.
    assert_eq!(
        sandbox.fs_mount_ro,
        vec![PathBuf::from("/work")],
        "fs_mount_ro must mark the virtual path read-only",
    );
}

#[test]
fn builder_fs_mount_leaves_the_mount_writable() {
    let (vp, hp) = (cstr("/work"), cstr("/host/work"));
    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount(b, vp.as_ptr(), hp.as_ptr())
    });

    assert_eq!(
        sandbox.fs_mount,
        vec![(PathBuf::from("/work"), PathBuf::from("/host/work"))],
    );
    assert!(
        sandbox.fs_mount_ro.is_empty(),
        "plain fs_mount must not mark anything read-only, got {:?}",
        sandbox.fs_mount_ro,
    );
}

#[test]
fn builder_mount_setters_chain_and_stay_distinguishable() {
    let (ro_v, ro_h) = (cstr("/ro"), cstr("/host/ro"));
    let (rw_v, rw_h) = (cstr("/rw"), cstr("/host/rw"));
    let sandbox = build_via_ffi(|b| unsafe {
        let b = sandlock_sandbox_builder_fs_mount_ro(b, ro_v.as_ptr(), ro_h.as_ptr());
        sandlock_sandbox_builder_fs_mount(b, rw_v.as_ptr(), rw_h.as_ptr())
    });

    assert_eq!(
        sandbox.fs_mount,
        vec![
            (PathBuf::from("/ro"), PathBuf::from("/host/ro")),
            (PathBuf::from("/rw"), PathBuf::from("/host/rw")),
        ],
        "both mounts must survive the moved builder pointer",
    );
    assert_eq!(
        sandbox.fs_mount_ro,
        vec![PathBuf::from("/ro")],
        "only the read-only mount's virtual path may be marked read-only",
    );
}

#[test]
fn builder_fs_mount_ro_tolerates_null_arguments() {
    let (vp, hp) = (cstr("/work"), cstr("/host/work"));

    // Null in, builder out unchanged: the convention every other
    // `sandlock_sandbox_builder_*` setter follows.
    let out =
        unsafe { sandlock_sandbox_builder_fs_mount_ro(ptr::null_mut(), vp.as_ptr(), hp.as_ptr()) };
    assert!(out.is_null(), "fs_mount_ro(null, _, _) must return null");

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, ptr::null(), hp.as_ptr())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "a null virtual_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, vp.as_ptr(), ptr::null())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "a null host_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );
}

#[test]
fn builder_fs_mount_ro_refuses_empty_paths() {
    // An empty virtual path is a prefix of *every* path, so recording it
    // would mount the whole tree and make ChrootCtx::can_read return true
    // everywhere, and the read allowlist would be gone. Core's
    // parse_mount_spec rejects empty components for the same reason, so
    // the C ABI must not be the one door that accepts them.
    let (vp, hp) = (cstr("/work"), cstr("/host/work"));
    let empty = cstr("");

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, empty.as_ptr(), hp.as_ptr())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "an empty virtual_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, vp.as_ptr(), empty.as_ptr())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "an empty host_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );
}

#[test]
fn builder_fs_mount_ro_refuses_non_utf8_paths() {
    // A lossy conversion would have collapsed these to "", i.e. to the
    // tree-wide mount above; dropping the mount is the fail-closed choice
    // for a setter with no error channel.
    let (vp, hp) = (cstr("/work"), cstr("/host/work"));
    let bad = CString::new(vec![b'/', 0xff, b'x']).unwrap();

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, bad.as_ptr(), hp.as_ptr())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "a non-UTF-8 virtual_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );

    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_mount_ro(b, vp.as_ptr(), bad.as_ptr())
    });
    assert!(
        sandbox.fs_mount.is_empty() && sandbox.fs_mount_ro.is_empty(),
        "a non-UTF-8 host_path must add no mount, got {:?} / {:?}",
        sandbox.fs_mount,
        sandbox.fs_mount_ro,
    );
}

#[test]
fn builder_fs_mount_refuses_unusable_paths_exactly_like_fs_mount_ro() {
    // The plain setter is the *more* dangerous door for the same input:
    // an empty virtual path there voids the write allowlist as well as the
    // read one (`ChrootCtx::can_write` short-circuits on `is_mounted`),
    // with no read-only marking left to hold writes closed. Both setters
    // must therefore drop the mount rather than degrade the path to "".
    // `sandlock_sandbox_builder_fs_mount` is what the Go binding
    // (go/sandlock_linux.go) and the Python `Sandbox` dataclass
    // (python/src/sandlock/_sdk.py) call, so this is the reachable one.
    let good = cstr("/work");
    let bad_utf8 = CString::new(vec![b'/', 0xff, b'x']).unwrap();
    let empty = cstr("");

    let cases: [(&str, &CString, &CString); 4] = [
        ("empty virtual_path", &empty, &good),
        ("empty host_path", &good, &empty),
        ("non-UTF-8 virtual_path", &bad_utf8, &good),
        ("non-UTF-8 host_path", &good, &bad_utf8),
    ];

    for (label, vp, hp) in cases {
        let sandbox = build_via_ffi(|b| unsafe {
            sandlock_sandbox_builder_fs_mount(b, vp.as_ptr(), hp.as_ptr())
        });
        assert!(
            sandbox.fs_mount.is_empty(),
            "fs_mount with {label} must add no mount, got {:?}",
            sandbox.fs_mount,
        );
        // Nothing marks it read-only either, so a recorded mount here would
        // be a tree-wide read-write mapping.
        assert!(sandbox.fs_mount_ro.is_empty());
    }
}

// ----------------------------------------------------------------
// End-to-end: what a read-only mount enforces on a real guest
// ----------------------------------------------------------------

/// Path to the static rootfs-helper binary (compiled by sandlock-core's
/// build.rs, which has already run because this crate depends on it).
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found; sandlock-core's build.rs should have compiled it")
}

fn temp_dir(name: &str) -> PathBuf {
    // Prefer cargo's per-test-binary tmp dir (same filesystem as the
    // compiled helper) so the rootfs can hard-link it instead of copying:
    // a copy's writable fd can leak into a concurrent fork+exec and make
    // the execve fail with ETXTBSY.
    let base = option_env!("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!(
        "sandlock-ffi-mount-{}-{}",
        name,
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("failed to create temp dir");
    dir
}

/// Minimal self-contained rootfs with the busybox-style rootfs-helper.
fn build_test_rootfs(name: &str) -> PathBuf {
    let rootfs = temp_dir(name);
    let helper = helper_binary();

    for dir in &["usr/bin", "etc", "proc", "dev", "tmp"] {
        fs::create_dir_all(rootfs.join(dir)).expect("failed to create rootfs dir");
    }
    let _ = fs::set_permissions(rootfs.join("tmp"), fs::Permissions::from_mode(0o1777));

    let dest = rootfs.join("usr/bin/rootfs-helper");
    fs::hard_link(&helper, &dest)
        .or_else(|_| fs::copy(&helper, &dest).map(|_| ()))
        .expect("failed to install rootfs-helper into rootfs");
    for cmd in &["cat", "write", "ls"] {
        let link = rootfs.join(format!("usr/bin/{}", cmd));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink("rootfs-helper", &link)
            .expect("failed to create busybox symlink");
    }
    let _ = std::os::unix::fs::symlink("usr/bin", rootfs.join("bin"));

    rootfs
}

/// Captured outcome of one guest command.
struct Run {
    success: bool,
    code: c_int,
    stdout: String,
    stderr: String,
}

/// Run `argv` under `policy` through the C ABI and collect the result.
fn run_in_sandbox(policy: *mut sandlock_sandbox_t, argv: &[&str]) -> Run {
    let owned: Vec<CString> = argv.iter().map(|s| cstr(s)).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    let r = unsafe { sandlock_run(policy, ptr::null(), ptrs.as_ptr(), ptrs.len() as c_uint) };
    assert!(!r.is_null(), "sandlock_run({:?}) returned null", argv);

    let read = |p: *mut c_char| -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: `p` is a malloc'd NUL-terminated string owned by us.
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        unsafe { sandlock_string_free(p) };
        s
    };
    let out = Run {
        success: unsafe { sandlock_result_success(r) },
        code: unsafe { sandlock_result_exit_code(r) },
        stdout: read(unsafe { sandlock_result_stdout(r) }),
        stderr: read(unsafe { sandlock_result_stderr(r) }),
    };
    unsafe { sandlock_result_free(r) };
    out
}

/// Build a chroot policy through the C ABI with one read-only mount at
/// `/ro` and one read-write mount at `/rw`.
fn build_mount_policy(rootfs: &Path, ro_host: &Path, rw_host: &Path) -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");

    let root = cstr(rootfs.to_str().unwrap());
    b = unsafe { sandlock_sandbox_builder_chroot(b, root.as_ptr()) };
    for p in ["/usr", "/bin", "/proc", "/dev"] {
        let c = cstr(p);
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    // Grant /ro read AND write explicitly: the read-only mount must win
    // over an explicit writable rule, which is the whole point of
    // checking mount_ro before the writable prefixes.
    for p in ["/ro", "/rw"] {
        let c = cstr(p);
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
        b = unsafe { sandlock_sandbox_builder_fs_write(b, c.as_ptr()) };
    }

    let (ro_v, ro_h) = (cstr("/ro"), cstr(ro_host.to_str().unwrap()));
    b = unsafe { sandlock_sandbox_builder_fs_mount_ro(b, ro_v.as_ptr(), ro_h.as_ptr()) };
    let (rw_v, rw_h) = (cstr("/rw"), cstr(rw_host.to_str().unwrap()));
    b = unsafe { sandlock_sandbox_builder_fs_mount(b, rw_v.as_ptr(), rw_h.as_ptr()) };

    let mut err: c_int = 0;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, &mut err_msg) };
    if err != 0 {
        let msg = if err_msg.is_null() {
            String::new()
        } else {
            let m = unsafe { CStr::from_ptr(err_msg) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandlock_string_free(err_msg) };
            m
        };
        panic!("sandbox_build failed: {}", msg);
    }
    assert!(!policy.is_null(), "sandbox_build returned null policy");
    policy
}

#[test]
fn read_only_mount_allows_reads_and_denies_writes() {
    let rootfs = build_test_rootfs("ro-enforced");
    fs::create_dir_all(rootfs.join("ro")).unwrap();
    fs::create_dir_all(rootfs.join("rw")).unwrap();

    let ro_host = temp_dir("ro-host");
    let rw_host = temp_dir("rw-host");
    fs::write(ro_host.join("input.txt"), "hello read-only mount\n").unwrap();
    fs::write(rw_host.join("input.txt"), "hello writable mount\n").unwrap();

    let policy = build_mount_policy(&rootfs, &ro_host, &rw_host);

    // 1. Reads go through the read-only mount, and they reach the host
    //    directory (not an empty rootfs dir of the same name).
    let r = run_in_sandbox(policy, &["rootfs-helper", "cat", "/ro/input.txt"]);
    assert!(
        r.success,
        "cat /ro/input.txt must succeed under a read-only mount: exit={} stderr={}",
        r.code, r.stderr,
    );
    assert_eq!(
        r.stdout.trim(),
        "hello read-only mount",
        "read-only mount must expose the host directory's content",
    );

    // 2. Creating a file under the read-only mount is refused, even
    //    though /ro was granted fs_write.
    let r = run_in_sandbox(
        policy,
        &["rootfs-helper", "write", "/ro/created.txt", "nope"],
    );
    assert!(
        !r.success,
        "creating /ro/created.txt must fail under a read-only mount: stdout={} stderr={}",
        r.stdout, r.stderr,
    );
    assert!(
        r.stderr.contains("Permission denied"),
        "write to a read-only mount must be denied with EACCES, got stderr={:?}",
        r.stderr,
    );
    assert!(
        !ro_host.join("created.txt").exists(),
        "the denied write must not have reached the host directory",
    );

    // 3. Overwriting an existing file under the read-only mount is
    //    refused too, and the host content is untouched.
    let r = run_in_sandbox(
        policy,
        &["rootfs-helper", "write", "/ro/input.txt", "clobbered"],
    );
    assert!(
        !r.success,
        "overwriting /ro/input.txt must fail: stdout={} stderr={}",
        r.stdout, r.stderr,
    );
    assert_eq!(
        fs::read_to_string(ro_host.join("input.txt")).unwrap(),
        "hello read-only mount\n",
        "the host file must be byte-identical after the denied write",
    );

    // 4. Control: the very same policy, the very same guest command, on
    //    a mount registered with `fs_mount` instead: writes land. This
    //    is what pins the denial on the read-only marking rather than on
    //    a broken mount setup.
    let r = run_in_sandbox(
        policy,
        &["rootfs-helper", "write", "/rw/created.txt", "yes"],
    );
    assert!(
        r.success,
        "write to a read-write mount must succeed: exit={} stderr={}",
        r.code, r.stderr,
    );
    assert_eq!(
        fs::read_to_string(rw_host.join("created.txt")).unwrap(),
        "yes\n",
        "the allowed write must reach the host directory",
    );

    unsafe { sandlock_sandbox_free(policy) };
    let _ = fs::remove_dir_all(&rootfs);
    let _ = fs::remove_dir_all(&ro_host);
    let _ = fs::remove_dir_all(&rw_host);
}

#[test]
fn builder_explicit_read_write_grants_both_authorities() {
    let path = cstr("/tmp");
    let sandbox = build_via_ffi(|b| unsafe {
        sandlock_sandbox_builder_fs_read_write(b, path.as_ptr())
    });
    assert_eq!(sandbox.fs_readable, vec![PathBuf::from("/tmp")]);
    assert_eq!(sandbox.fs_writable, vec![PathBuf::from("/tmp")]);
}
