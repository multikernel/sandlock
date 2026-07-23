use sandlock_core::{Sandbox, SandboxBuilder};
use sandlock_core::sandbox::BranchAction;
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandlock-test-cow-{}-{}", name, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Path to the static rootfs-helper binary (compiled by build.rs).
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found — build.rs should have compiled it")
}

// ============================================================
// Seccomp-based COW tests (workdir set)
// ============================================================

/// Test that seccomp COW creates files in upper, committed on exit.
#[tokio::test]
async fn test_seccomp_cow_create_file() {
    let workdir = temp_dir("seccomp-create");
    fs::write(workdir.join("existing.txt"), "hello").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)  // workdir set → seccomp COW
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let new_file = workdir.join("new.txt");
    let cmd = format!("touch {}", new_file.display());
    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "touch should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            // After commit, new file should exist in workdir
            assert!(new_file.exists(), "new.txt should exist after commit");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that seccomp COW abort discards changes.
#[tokio::test]
async fn test_seccomp_cow_abort() {
    let workdir = temp_dir("seccomp-abort");
    fs::write(workdir.join("existing.txt"), "original").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let new_file = workdir.join("aborted.txt");
    let cmd = format!("touch {}", new_file.display());
    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(_) => {
            // After abort, new file should NOT exist
            assert!(!new_file.exists(), "aborted.txt should not exist after abort");
            // Original file should be unchanged
            let content = fs::read_to_string(workdir.join("existing.txt")).unwrap();
            assert_eq!(content, "original");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test seccomp COW with relative paths (AT_FDCWD).
///
/// Regression test: resolve_at_path must truncate dirfd to i32 before
/// comparing with AT_FDCWD (-100). The kernel stores AT_FDCWD as
/// 0x00000000FFFFFF9C in the 64-bit seccomp_data.args field, not
/// 0xFFFFFFFFFFFFFF9C.
#[tokio::test]
async fn test_seccomp_cow_relative_path_abort() {
    let workdir = temp_dir("seccomp-relpath");
    fs::write(workdir.join("orig.txt"), "original\n").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Use relative paths (triggers AT_FDCWD in openat) — the child's cwd is set via .cwd().
    let result = policy.clone().with_name("test").run(&[
        "sh", "-c", "echo MUTATED >> orig.txt; echo leak > leaked.txt"
    ]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "sh should succeed");
            // With abort, original file must be unchanged
            let content = fs::read_to_string(workdir.join("orig.txt")).unwrap();
            assert_eq!(content, "original\n", "orig.txt should be unchanged after abort");
            // New file must not exist
            assert!(!workdir.join("leaked.txt").exists(), "leaked.txt should not exist after abort");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test seccomp COW commit with relative paths (AT_FDCWD).
#[tokio::test]
async fn test_seccomp_cow_relative_path_commit() {
    let workdir = temp_dir("seccomp-relpath-commit");
    fs::write(workdir.join("orig.txt"), "original\n").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run(&[
        "sh", "-c", "echo APPENDED >> orig.txt; echo new > created.txt"
    ]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "sh should succeed");
            // With commit, changes should be merged back
            let content = fs::read_to_string(workdir.join("orig.txt")).unwrap();
            assert!(content.contains("APPENDED"), "orig.txt should have appended content after commit");
            assert!(content.starts_with("original\n"), "orig.txt should preserve original content");
            // New file should exist
            let new_content = fs::read_to_string(workdir.join("created.txt")).unwrap();
            assert_eq!(new_content.trim(), "new", "created.txt should exist after commit");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that openat with O_DIRECTORY works for COW-created directories.
///
/// When a directory is created via COW (only in upper layer), openat with
/// O_DIRECTORY must resolve to the upper path.  Without this fix,
/// prepare_open skipped O_DIRECTORY opens and the kernel returned ENOENT.
#[tokio::test]
async fn test_seccomp_cow_open_directory() {
    let workdir = temp_dir("seccomp-opendir");
    let out_file = workdir.join("opendir_ok.txt");

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    // mkdir creates the dir in COW upper; python opens it with O_DIRECTORY.
    let script = format!(
        concat!(
            "mkdir -p subdir && python3 -c \"",
            "import os; ",
            "fd = os.open('subdir', os.O_RDONLY | os.O_DIRECTORY); ",
            "os.close(fd); ",
            "open('{}', 'w').write('ok')\"",
        ),
        out_file.display()
    );
    let result = policy.clone().with_name("test").run(&["sh", "-c", &script]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "script should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            let content = fs::read_to_string(&out_file).unwrap();
            assert_eq!(content, "ok");
        }
        Err(e) => eprintln!("Seccomp COW opendir test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that chdir works for directories created inside COW.
///
/// When a directory is created via COW (only exists in the upper layer),
/// chdir must be intercepted and redirected to the upper path.  Without
/// this, the kernel returns ENOENT because it doesn't see the COW directory.
#[tokio::test]
async fn test_seccomp_cow_chdir_to_created_dir() {
    let workdir = temp_dir("seccomp-chdir");
    let out_file = workdir.join("chdir_ok.txt");

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    // Create a nested directory through a dirfd so the COW handler must map the
    // upper-layer fd target back to the logical workdir before mkdirat.
    // Use physical pwd so the assertion covers getcwd virtualization.
    let script = format!(
        concat!(
            "mkdir -p subdir && python3 -c \"",
            "import os; ",
            "fd = os.open('subdir', os.O_RDONLY | os.O_DIRECTORY); ",
            "os.mkdir('deep', dir_fd=fd); ",
            "os.close(fd)\" && ",
            "cd subdir/deep && pwd -P > {}"
        ),
        out_file.display()
    );
    let result = policy.clone().with_name("test").run(&["sh", "-c", &script]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "script should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            let content = fs::read_to_string(&out_file).unwrap();
            assert!(
                content.trim().ends_with("subdir/deep"),
                "pwd should end with subdir/deep, got: {}",
                content.trim()
            );
        }
        Err(e) => eprintln!("Seccomp COW chdir test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Test that the raw open syscall ABI works correctly with COW.
///
/// Regression test: handle_cow_open always read args in openat() layout
/// (dirfd=args[0], path=args[1], flags=args[2]), but open() uses
/// (path=args[0], flags=args[1], mode=args[2]). This caused COW to miss
/// all legacy open() calls on x86_64, falling through to the kernel. ARM64
/// and riscv64 do not provide SYS_open, so they use the equivalent raw
/// openat ABI.
#[tokio::test]
async fn test_seccomp_cow_legacy_open_syscall() {
    let workdir = temp_dir("seccomp-legacy-open");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-legacy-open-{}", std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Use raw syscall ABI to create a file, then verify it's visible during
    // the run but discarded on abort. x86_64 uses legacy SYS_open; ARM64 and
    // riscv64 use the equivalent openat(AT_FDCWD, ...) ABI.
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "O_WRONLY = 1; O_CREAT = 64; O_TRUNC = 512\n",
        "path = b'{wd}/newfile.txt'\n",
        "if platform.machine() in ('aarch64', 'riscv64'):\n",
        "    fd = libc.syscall(56, -100, path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)\n",
        "else:\n",
        "    fd = libc.syscall(2, path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)\n",
        "err = ctypes.get_errno()\n",
        "if fd >= 0:\n",
        "    os.write(fd, b'created via raw open')\n",
        "    os.close(fd)\n",
        "    content = open('{wd}/newfile.txt').read()\n",
        "    open('{out}', 'w').write(content)\n",
        "else:\n",
        "    open('{out}', 'w').write(f'FAILED:errno={{err}}')\n",
    ), wd = workdir.display(), out = out_file.display());

    let result = policy.clone().with_name("test").run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "created via raw open", "raw open ABI should work with COW");
    // After abort, the file should not exist on the real filesystem
    assert!(!workdir.join("newfile.txt").exists(), "newfile.txt should not exist after abort");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// Test that O_CREAT|O_EXCL succeeds after unlink in COW mode.
///
/// Regression test: after unlink marked a file as deleted, the subsequent
/// O_CREAT|O_EXCL open correctly identified the file as deleted and prepared
/// a COW copy, but the supervisor's open() still had O_EXCL in the flags.
/// Since the file was just copied to upper, the kernel's open() returned
/// EEXIST. The fix strips O_EXCL from the supervisor's open flags.
#[tokio::test]
async fn test_seccomp_cow_excl_after_unlink() {
    let workdir = temp_dir("seccomp-excl-unlink");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-excl-unlink-{}", std::process::id()
    ));
    fs::write(workdir.join("target.txt"), "original").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    // Unlink the file, then recreate it with O_CREAT|O_EXCL via raw open ABI.
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "path = b'{wd}/target.txt'\n",
        "ret = libc.unlink(path)\n",
        "if ret != 0:\n",
        "    open('{out}', 'w').write(f'UNLINK_FAILED:{{ctypes.get_errno()}}')\n",
        "    raise SystemExit(1)\n",
        "O_WRONLY = 1; O_CREAT = 64; O_EXCL = 128\n",
        "if platform.machine() in ('aarch64', 'riscv64'):\n",
        "    fd = libc.syscall(56, -100, path, O_WRONLY | O_CREAT | O_EXCL, 0o644)\n",
        "else:\n",
        "    fd = libc.syscall(2, path, O_WRONLY | O_CREAT | O_EXCL, 0o644)\n",
        "err = ctypes.get_errno()\n",
        "if fd >= 0:\n",
        "    os.write(fd, b'recreated')\n",
        "    os.close(fd)\n",
        "    open('{out}', 'w').write('OK')\n",
        "else:\n",
        "    open('{out}', 'w').write(f'OPEN_FAILED:{{err}}')\n",
    ), wd = workdir.display(), out = out_file.display());

    let result = policy.clone().with_name("test").run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "OK", "O_EXCL after unlink should succeed, got: {}", content);
    // After commit, the file should contain the new content
    let target = fs::read_to_string(workdir.join("target.txt")).unwrap_or_default();
    assert_eq!(target, "recreated", "target.txt should have new content after commit");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// Test that seccomp COW read isolation works (reads original before any writes).
#[tokio::test]
async fn test_seccomp_cow_read_existing() {
    let workdir = temp_dir("seccomp-read");
    fs::write(workdir.join("data.txt"), "hello world").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let out_file = workdir.join("out.txt");
    let cmd = format!(
        "cat {} > {}",
        workdir.join("data.txt").display(),
        out_file.display()
    );
    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "cat should succeed");
            let content = fs::read_to_string(&out_file).unwrap_or_default();
            assert_eq!(content.trim(), "hello world");
        }
        Err(e) => eprintln!("Seccomp COW test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

/// Regression test: a file deleted inside the COW workdir must read back as
/// ENOENT, not its pre-delete content. The read/open path returned
/// `Skip -> Continue` for a whiteout, so the kernel opened the untouched lower
/// file and leaked the original bytes — while stat/access already returned
/// ENOENT, so the two paths disagreed and a deletion was invisible to a reader.
#[tokio::test]
async fn test_seccomp_cow_read_deleted_file_is_enoent() {
    let workdir = temp_dir("seccomp-read-deleted");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-read-deleted-{}", std::process::id()
    ));
    fs::write(workdir.join("secret.txt"), "PREDELETE").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Delete the file, then read it back with `dd`, which issues a bare
    // open(O_RDONLY) with no preceding path stat — unlike `cat FILE` or a shell
    // redirect, which stat first and would short-circuit on the (correct) stat
    // ENOENT without ever exercising the open path this fix targets. `dd`
    // succeeding means the open was honored and the untouched lower bytes leaked;
    // `dd` failing means the whiteout was honored (ENOENT). Both the copied bytes
    // and the marker land in /tmp (not the COW workdir), so they are real writes.
    let secret = workdir.join("secret.txt");
    let leak_file = std::env::temp_dir().join(format!(
        "sandlock-test-read-deleted-leak-{}", std::process::id()
    ));
    let cmd = format!(
        "rm -f {secret}; if dd if={secret} of={leak} status=none; then printf 'OPENED' > {marker}; else printf 'DENIED' > {marker}; fi",
        secret = secret.display(),
        leak = leak_file.display(),
        marker = out_file.display(),
    );

    let result = policy.clone().with_name("test").run(&["sh", "-c", &cmd]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let marker = fs::read_to_string(&out_file).unwrap_or_default();
    let leaked = fs::read_to_string(&leak_file).unwrap_or_default();
    assert_eq!(
        marker, "DENIED",
        "open of a deleted COW file must be denied (ENOENT), not read lower content (leaked: {:?})", leaked
    );
    assert!(
        leaked.is_empty(),
        "no pre-delete bytes may leak through the read path, got: {:?}", leaked
    );

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
    let _ = fs::remove_file(&leak_file);
}

/// Regression test: statx on a COW-created file must succeed.
///
/// statx is what `ls`, `stat`, and most modern coreutils use. The COW
/// statx handler returned Continue when the file existed in the upper
/// layer, so the kernel re-ran statx against the un-redirected lower path
/// and returned ENOENT for files that live only in upper.
#[tokio::test]
async fn test_seccomp_cow_statx_created_file() {
    let workdir = temp_dir("seccomp-statx");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-statx-{}", std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Create a file that lives only in the COW upper layer, then statx it
    // via the raw syscall (the path coreutils `stat`/`ls` take).
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "libc.syscall.restype = ctypes.c_long\n",
        "open('created.txt', 'w').write('hi')\n",
        "buf = ctypes.create_string_buffer(256)\n",
        "AT_FDCWD = -100\n",
        "STATX_BASIC_STATS = 0x7ff\n",
        "nr = 291 if platform.machine() in ('aarch64', 'riscv64') else 332\n",
        "ret = libc.syscall(nr, AT_FDCWD, b'created.txt', 0, STATX_BASIC_STATS, buf)\n",
        "err = ctypes.get_errno()\n",
        "open('{out}', 'w').write('OK' if ret == 0 else f'FAIL:errno={{err}}')\n",
    ), out = out_file.display());

    let result = policy.clone().with_name("test").run(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}, stderr={}", result.code(), result.stderr_str().unwrap_or(""));
    let content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(content, "OK", "statx on COW-created file should succeed, got: {}", content);

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_file(&out_file);
}

/// Regression test: a binary created inside the COW workdir must
/// be executable. execve had no COW redirect, so the kernel resolved the
/// un-redirected lower path and returned ENOENT for binaries that live
/// only in the upper layer.
#[tokio::test]
async fn test_seccomp_cow_exec_created_file() {
    let workdir = temp_dir("seccomp-exec");
    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_read(&helper_dir)
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Copy our own static rootfs-helper into the COW workdir (lands in
    // upper), then exec it. The helper (not a system binary like /bin/echo,
    // whose behavior varies across hosts: Ubuntu rust-coreutils ships a
    // multicall binary) is itself busybox-style: invoked as `./echo` it
    // dispatches on basename(argv[0]). That also catches the exec redirect
    // clobbering argv[0]: shells pass the same buffer as execve path and
    // argv[0], so rewriting the path to /proc/self/fd/N must relocate
    // argv[0], or the helper sees basename "N" and exits 127.
    let cmd = format!("cp {} echo && ./echo EXEC_OK", helper.display());
    let result = policy.clone().with_name("test").run(&[
        "sh", "-c", &cmd,
    ]).await.unwrap();

    assert!(
        result.success(),
        "exec of COW-created binary should succeed (argv[0] preserved), exit={:?}, stderr={}",
        result.code(), result.stderr_str().unwrap_or("")
    );
    assert!(
        result.stdout_str().unwrap_or("").contains("EXEC_OK"),
        "exec'd binary should print EXEC_OK, stdout={:?}",
        result.stdout_str()
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// Exec a COW-created binary with the path and argv strings tightly packed
/// in one buffer: the /proc/self/fd/N rewrite window covers argv[1] too, so
/// the supervisor must relocate every clobbered string, not only argv[0].
/// Shell-driven layouts happen to keep argv[1] out of the window; this
/// crafts the packed layout directly with execve(2) via ctypes.
#[tokio::test]
async fn test_seccomp_cow_exec_packed_argv_relocation() {
    let workdir = temp_dir("seccomp-exec-packed");
    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_read(&helper_dir)
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let script = format!(concat!(
        "import ctypes, shutil, os\n",
        "shutil.copy('{helper}', 'echo')\n",
        "os.chmod('echo', 0o755)\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "buf = ctypes.create_string_buffer(b'./echo\\0EXEC_OK_PACKED\\0')\n",
        "base = ctypes.addressof(buf)\n",
        "argv = (ctypes.c_void_p * 3)(base, base + 7, None)\n",
        "envp = (ctypes.c_void_p * 1)(None)\n",
        "libc.execve(ctypes.c_void_p(base), argv, envp)\n",
        "raise SystemExit('execve failed errno=%d' % ctypes.get_errno())\n",
    ), helper = helper.display());

    let result = policy.clone().with_name("test").run(&["python3", "-c", &script]).await.unwrap();

    assert!(
        result.success(),
        "packed-argv exec should succeed, exit={:?}, stderr={}",
        result.code(), result.stderr_str().unwrap_or("")
    );
    assert!(
        result.stdout_str().unwrap_or("").contains("EXEC_OK_PACKED"),
        "argv[1] must survive the path rewrite, stdout={:?}",
        result.stdout_str()
    );

    let _ = fs::remove_dir_all(&workdir);
}

// ============================================================
// Branch disposition on an abandoned sandbox
// ============================================================

/// Number of branch subdirectories under a `fs_storage` dir.
fn branch_count(storage: &std::path::Path) -> usize {
    fs::read_dir(storage).map(|rd| rd.count()).unwrap_or(0)
}

/// `BranchAction::Keep` means "preserve the changes for later inspection", and a
/// sandbox that is abandoned without `wait()` IS the case worth inspecting.
///
/// A branch only reaches `Sandbox`'s own disposition after a completed `wait()`,
/// so on this path the branch's `Drop` backstop is what decides. It must honour
/// an explicit `Keep` — and must still reclaim under the default action, which
/// is the leak the backstop exists to close.
///
/// `Keep` is honoured from EITHER action. An abandoned run has no exit status,
/// so there is no choosing between `on_exit` and `on_error`: a caller who asked
/// to keep the changes in either case asked to keep them here.
#[tokio::test]
async fn test_abandoned_sandbox_honours_keep_and_still_reclaims_by_default() {
    let workdir = temp_dir("abandon-wd");
    let keep_store = temp_dir("abandon-keep-st");
    let on_error_store = temp_dir("abandon-onerror-st");
    let default_store = temp_dir("abandon-default-st");
    for d in [&keep_store, &on_error_store, &default_store] {
        let _ = fs::remove_dir_all(d);
        let _ = fs::create_dir_all(d);
    }

    let base = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir).workdir(&workdir).cwd(&workdir);

    {
        let mut sb = base.clone()
            .fs_storage(&keep_store)
            .on_exit(BranchAction::Keep)
            .build()
            .unwrap();
        sb.create(&["sh", "-c", "echo kept > k.txt"]).await.unwrap();
        sb.start().unwrap();
        // Dropped here, with no wait(): the caller walked away from the run.
    }
    {
        let mut sb = base.clone()
            .fs_storage(&on_error_store)
            .on_error(BranchAction::Keep)
            .build()
            .unwrap();
        sb.create(&["sh", "-c", "echo kept > k.txt"]).await.unwrap();
        sb.start().unwrap();
    }
    {
        let mut sb = base.clone()
            .fs_storage(&default_store)
            .build()
            .unwrap();
        sb.create(&["sh", "-c", "echo gone > g.txt"]).await.unwrap();
        sb.start().unwrap();
    }

    // Dropping the sandbox does not itself drop the branch: the shared COW state
    // is also held by the aborted supervisor task, so the branch is dropped when
    // the runtime reaps it. Wait for the default store to empty — that reclaim IS
    // the proof that the branch drops have run, without which the Keep assertion
    // below would pass on a branch that simply had not been dropped yet.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while branch_count(&default_store) != 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        branch_count(&default_store), 0,
        "an abandoned sandbox with the default action must still reclaim its upper",
    );
    assert_eq!(
        branch_count(&keep_store), 1,
        "an abandoned sandbox configured on_exit(Keep) must still preserve its upper",
    );
    assert_eq!(
        branch_count(&on_error_store), 1,
        "an abandoned sandbox configured on_error(Keep) must still preserve its upper",
    );

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&keep_store);
    let _ = fs::remove_dir_all(&on_error_store);
    let _ = fs::remove_dir_all(&default_store);
}

// ============================================================
// Branch disposition on a completed run
// ============================================================

/// Build a COW sandbox over `workdir` with the two dispositions under test.
fn disposition_sandbox(
    workdir: &std::path::Path,
    on_exit: BranchAction,
    on_error: BranchAction,
) -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(workdir).workdir(workdir).cwd(workdir)
        .on_exit(on_exit)
        .on_error(on_error)
        .build()
        .unwrap()
}

/// Run `script` in a fresh COW workdir under the two dispositions and report
/// the child's exit code together with whether its write reached the workdir.
async fn run_and_report_landing(
    tag: &str,
    script: &str,
    on_exit: BranchAction,
    on_error: BranchAction,
) -> (Option<i32>, bool) {
    let workdir = temp_dir(tag);
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::create_dir_all(&workdir);

    let code = {
        let mut sb = disposition_sandbox(&workdir, on_exit, on_error);
        let result = sb.run(&["sh", "-c", script]).await.unwrap();
        result.code()
        // Dropped here: the disposition runs in `Sandbox`'s Drop.
    };
    let landed = workdir.join("f.txt").exists();
    let _ = fs::remove_dir_all(&workdir);
    (code, landed)
}

/// Which branch action a completed run applies is selected by the child's exit
/// status: `on_exit` for exit code 0, `on_error` for a non-zero one.
///
/// The two failing runs differ only in which way round the actions are wired,
/// so an implementation that always took `on_exit` and one that always took
/// `on_error` each contradict one of them; the succeeding run pins which of the
/// two names goes with which status.
#[tokio::test]
async fn test_branch_action_is_selected_by_the_child_exit_status() {
    let script_fail = "echo written > f.txt; exit 3";
    let script_ok = "echo written > f.txt";

    let (code, landed) = run_and_report_landing(
        "disp-fail-abort", script_fail, BranchAction::Commit, BranchAction::Abort,
    ).await;
    assert_eq!(code, Some(3), "the failing script must actually have failed");
    assert!(
        !landed,
        "a non-zero exit must apply on_error (Abort), so the write must not reach the workdir",
    );

    let (code, landed) = run_and_report_landing(
        "disp-fail-commit", script_fail, BranchAction::Abort, BranchAction::Commit,
    ).await;
    assert_eq!(code, Some(3), "the failing script must actually have failed");
    assert!(
        landed,
        "a non-zero exit must apply on_error (Commit), so the write must reach the workdir",
    );

    let (code, landed) = run_and_report_landing(
        "disp-ok-commit", script_ok, BranchAction::Commit, BranchAction::Abort,
    ).await;
    assert_eq!(code, Some(0), "the succeeding script must actually have succeeded");
    assert!(
        landed,
        "exit code 0 must apply on_exit (Commit), so the write must reach the workdir",
    );

    let (code, landed) = run_and_report_landing(
        "disp-ok-abort", script_ok, BranchAction::Abort, BranchAction::Commit,
    ).await;
    assert_eq!(code, Some(0), "the succeeding script must actually have succeeded");
    assert!(
        !landed,
        "exit code 0 must apply on_exit (Abort), so the write must not reach the workdir",
    );
}

/// A run kept with `BranchAction::Keep` leaves a marker that records the
/// deletions alongside the upper, so an out-of-band recovery restores the
/// change set instead of resurrecting the files the run deleted.
///
/// The deletion here is the child's own `rm`, so this covers the marker written
/// from the real supervisor path: the COW layer holds that deletion in RAM only
/// and nothing in the upper represents it, which is why copying the upper back
/// over the workdir is not by itself a recovery.
#[tokio::test]
async fn test_kept_branch_marker_records_the_runs_deletion_not_only_its_upper() {
    let workdir = temp_dir("keep-marker-wd");
    let storage = temp_dir("keep-marker-st");
    for d in [&workdir, &storage] {
        let _ = fs::remove_dir_all(d);
        let _ = fs::create_dir_all(d);
    }
    fs::write(workdir.join("victim.txt"), "ORIGINAL").unwrap();

    {
        let mut sb = Sandbox::builder()
            .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
            .fs_read("/proc")
            .fs_write(&workdir).workdir(&workdir).cwd(&workdir)
            .fs_storage(&storage)
            .on_exit(BranchAction::Keep)
            .build()
            .unwrap();
        let result = sb.run(&["sh", "-c", "rm victim.txt && echo NEW > added.txt"]).await.unwrap();
        assert!(
            result.success(),
            "the child must have deleted and written, exit={:?}, stderr={}",
            result.code(), result.stderr_str().unwrap_or(""),
        );
    }

    let preserved = sandlock_core::list_preserved(&storage);
    assert_eq!(preserved.len(), 1, "the kept branch must be findable by a sweep");
    let branch = &preserved[0];
    assert_eq!(branch.reason, sandlock_core::PreserveReason::Kept);
    assert_eq!(
        branch.workdir,
        workdir.canonicalize().unwrap(),
        "the marker must name the workdir the change set belongs to",
    );
    assert_eq!(
        branch.deleted,
        vec![PathBuf::from("victim.txt")],
        "the marker must record the file the run deleted",
    );
    assert_eq!(
        fs::read_to_string(branch.upper.join("added.txt")).unwrap(),
        "NEW\n",
        "the upper must hold the file the run added",
    );

    // Keep does not merge: the workdir still holds the pre-run state, so the
    // marker's deletion is the only record that the file was removed.
    assert_eq!(fs::read_to_string(workdir.join("victim.txt")).unwrap(), "ORIGINAL");
    assert!(!workdir.join("added.txt").exists(), "Keep must not merge the upper");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

// ============================================================
// Merge failure, storage layout, and the syscall error contract
// ============================================================

/// Build a COW sandbox over `workdir` that reads enough of the host to run a
/// shell or python, and writes only inside the workdir.
fn cow_sandbox(workdir: &std::path::Path, on_exit: BranchAction) -> SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(workdir).workdir(workdir).cwd(workdir)
        .on_exit(on_exit)
}

/// A merge that fails leaves the change set on disk under a `MergeInterrupted`
/// marker, which on the plain-`Sandbox` path is the ONLY record that the
/// workdir was never updated: the disposition runs in `Drop` and discards the
/// `commit()` error, so the caller — who already has its `RunResult` in hand,
/// reporting a successful run — is never told.
///
/// The merge is made to fail by removing the workdir between the run and the
/// disposition, so the first copy has no root to open under.
#[tokio::test]
async fn test_failed_merge_on_the_drop_path_leaves_the_upper_recoverable() {
    let workdir = temp_dir("merge-fail-wd");
    let storage = temp_dir("merge-fail-st");
    for d in [&workdir, &storage] {
        let _ = fs::remove_dir_all(d);
        let _ = fs::create_dir_all(d);
    }

    {
        let mut sb = cow_sandbox(&workdir, BranchAction::Commit)
            .fs_storage(&storage)
            .build()
            .unwrap();
        let result = sb.run(&["sh", "-c", "echo NEW > added.txt"]).await.unwrap();
        assert!(
            result.success(),
            "the child must have written, exit={:?}, stderr={}",
            result.code(), result.stderr_str().unwrap_or(""),
        );
        // Out of band, as an unmount or another process would: the workdir the
        // merge is about to copy into is gone.
        fs::remove_dir_all(&workdir).unwrap();
        // Dropped here: `Drop` commits, the merge fails, and the error is lost.
    }

    let preserved = sandlock_core::list_preserved(&storage);
    assert_eq!(
        preserved.len(), 1,
        "a merge that could not run must leave exactly one branch for a sweep, got {:?}",
        preserved,
    );
    let branch = &preserved[0];
    assert_eq!(
        branch.reason,
        sandlock_core::PreserveReason::MergeInterrupted,
        "the reason must say the workdir may have been touched, not that the caller kept the branch",
    );
    assert_eq!(
        fs::read_to_string(branch.upper.join("added.txt")).unwrap(),
        "NEW\n",
        "the unpublished change must still be readable from the preserved upper",
    );

    let _ = fs::remove_dir_all(&storage);
    let _ = fs::remove_dir_all(&workdir);
}

/// With no `fs_storage`, branch storage goes to the per-process default base
/// `$TMPDIR/sandlock-cow-<pid>`, and `list_preserved` reads exactly one level:
/// a sweep of `$TMPDIR` itself does not reach a branch under that base.
///
/// The two halves are the documented limitation of the default layout — a sweep
/// across process lifetimes has to enumerate the per-process bases itself — and
/// the reason a caller who wants one recoverable root must pass `fs_storage`.
#[tokio::test]
async fn test_default_storage_base_is_per_process_and_the_sweep_does_not_recurse() {
    let workdir = temp_dir("default-base-wd");
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::create_dir_all(&workdir);

    {
        let mut sb = cow_sandbox(&workdir, BranchAction::Keep).build().unwrap();
        let result = sb
            .run(&["sh", "-c", "echo x > default-base-marker.txt"])
            .await
            .unwrap();
        assert!(
            result.success(),
            "the child must have written, exit={:?}, stderr={}",
            result.code(), result.stderr_str().unwrap_or(""),
        );
    }

    let base = std::env::temp_dir().join(format!("sandlock-cow-{}", std::process::id()));
    let ours: Vec<_> = sandlock_core::list_preserved(&base)
        .into_iter()
        .filter(|p| p.upper.join("default-base-marker.txt").exists())
        .collect();
    assert_eq!(
        ours.len(), 1,
        "the kept branch must be under the per-process default base {}",
        base.display(),
    );
    assert_eq!(
        ours[0].branch_dir.parent(),
        Some(base.as_path()),
        "the branch must sit directly under the base, one level down",
    );

    let from_tmp = sandlock_core::list_preserved(&std::env::temp_dir());
    assert!(
        !from_tmp.iter().any(|p| p.branch_dir == ours[0].branch_dir),
        "the sweep must not descend from $TMPDIR into the per-process base, but it reached {}",
        ours[0].branch_dir.display(),
    );

    let _ = fs::remove_dir_all(&ours[0].branch_dir);
    let _ = fs::remove_dir_all(&workdir);
}

/// `O_CREAT|O_EXCL` reports EEXIST for a file that exists only in the workdir
/// as well as for one this run created in the upper, and still creates a file
/// whose name neither layer holds.
///
/// The existence check has to span both layers: against the upper alone a
/// lock-file idiom would silently clobber a pre-existing workdir file, and
/// against the workdir alone it would clobber one the same run had just made.
#[tokio::test]
async fn test_o_excl_sees_both_the_workdir_and_the_upper() {
    let workdir = temp_dir("excl-layers");
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::create_dir_all(&workdir);
    fs::write(workdir.join("lower.txt"), "LOWER").unwrap();

    let script = concat!(
        "import os, errno\n",
        "def e(*a):\n",
        "    try:\n",
        "        os.close(os.open(*a)); return 'CREATED'\n",
        "    except OSError as ex: return errno.errorcode.get(ex.errno, str(ex.errno))\n",
        "flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY\n",
        "open('upper.txt', 'w').write('UPPER')\n",
        "print('lower', e('lower.txt', flags))\n",
        "print('upper', e('upper.txt', flags))\n",
        "print('fresh', e('fresh.txt', flags))\n",
    );

    let mut sb = cow_sandbox(&workdir, BranchAction::Abort).build().unwrap();
    let result = sb.run(&["python3", "-c", script]).await.unwrap();
    assert!(
        result.success(),
        "the probe must have run, exit={:?}, stderr={}",
        result.code(), result.stderr_str().unwrap_or(""),
    );
    let out = result.stdout_str().unwrap_or("").to_string();
    assert!(out.contains("lower EEXIST"), "O_EXCL must see the workdir file, stdout={:?}", out);
    assert!(out.contains("upper EEXIST"), "O_EXCL must see the file this run created, stdout={:?}", out);
    assert!(
        out.contains("fresh CREATED"),
        "O_EXCL must still create a name neither layer holds, stdout={:?}", out,
    );

    // Abort: the pre-existing file must be untouched by the probe.
    drop(sb);
    assert_eq!(fs::read_to_string(workdir.join("lower.txt")).unwrap(), "LOWER");

    let _ = fs::remove_dir_all(&workdir);
}

/// `unlink` on a directory reaches the child as EISDIR and `rmdir` on a regular
/// file as ENOTDIR, whether the path exists only in the workdir or was created
/// by this run in the upper.
///
/// The COW layer answers both from the merged view rather than letting the
/// kernel decide, so each layer is a separate arm of the type check and each
/// needs its own case.
#[tokio::test]
async fn test_unlink_type_mismatches_reach_the_child_as_eisdir_and_enotdir() {
    let workdir = temp_dir("unlink-errno");
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::create_dir_all(&workdir);
    fs::create_dir_all(workdir.join("lower_dir")).unwrap();
    fs::write(workdir.join("lower_file.txt"), "x").unwrap();

    let script = concat!(
        "import os, errno\n",
        "def e(fn, *a):\n",
        "    try:\n",
        "        fn(*a); return 'OK'\n",
        "    except OSError as ex: return errno.errorcode.get(ex.errno, str(ex.errno))\n",
        "os.mkdir('upper_dir')\n",
        "open('upper_file.txt', 'w').write('x')\n",
        "print('unlink_lower_dir', e(os.unlink, 'lower_dir'))\n",
        "print('rmdir_lower_file', e(os.rmdir, 'lower_file.txt'))\n",
        "print('unlink_upper_dir', e(os.unlink, 'upper_dir'))\n",
        "print('rmdir_upper_file', e(os.rmdir, 'upper_file.txt'))\n",
    );

    let mut sb = cow_sandbox(&workdir, BranchAction::Abort).build().unwrap();
    let result = sb.run(&["python3", "-c", script]).await.unwrap();
    assert!(
        result.success(),
        "the probe must have run, exit={:?}, stderr={}",
        result.code(), result.stderr_str().unwrap_or(""),
    );
    let out = result.stdout_str().unwrap_or("").to_string();
    for expected in [
        "unlink_lower_dir EISDIR",
        "rmdir_lower_file ENOTDIR",
        "unlink_upper_dir EISDIR",
        "rmdir_upper_file ENOTDIR",
    ] {
        assert!(out.contains(expected), "expected {:?} in stdout={:?}", expected, out);
    }

    // Abort: nothing the probe touched may reach the workdir.
    drop(sb);
    assert!(workdir.join("lower_dir").is_dir(), "a refused unlink must not have deleted the directory");
    assert!(!workdir.join("upper_dir").exists(), "an aborted run must not publish its directory");

    let _ = fs::remove_dir_all(&workdir);
}
