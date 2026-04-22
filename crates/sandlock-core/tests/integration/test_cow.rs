use sandlock_core::{Policy, Sandbox};
use sandlock_core::policy::{FsIsolation, BranchAction};
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandlock-test-cow-{}-{}", name, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Test that basic commands still work with OverlayFS enabled.
#[tokio::test]
async fn test_overlayfs_basic_commands() {
    let workdir = temp_dir("basic");
    let storage = temp_dir("basic-storage");
    fs::write(workdir.join("hello.txt"), "original").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .fs_isolation(FsIsolation::OverlayFs)
        .workdir(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["cat", "hello.txt"]).await;
    // May fail on systems without unprivileged overlayfs support
    match result {
        Ok(r) => assert!(r.success(), "cat should succeed"),
        Err(e) => eprintln!("OverlayFS test skipped (not supported): {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// Test that writes in the sandbox don't affect the original directory (abort).
#[tokio::test]
async fn test_overlayfs_write_isolation() {
    let workdir = temp_dir("isolation");
    let storage = temp_dir("isolation-storage");
    fs::write(workdir.join("data.txt"), "original").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .fs_isolation(FsIsolation::OverlayFs)
        .workdir(&workdir)
        .fs_storage(&storage)
        .on_exit(BranchAction::Abort)
        .on_error(BranchAction::Abort)
        .build()
        .unwrap();

    // Write to a file inside the sandbox
    let result = Sandbox::run(&policy, &["sh", "-c", "echo modified > data.txt"]).await;
    match result {
        Ok(_r) => {
            // Original file should still say "original" (COW aborted)
            let content = fs::read_to_string(workdir.join("data.txt")).unwrap();
            assert_eq!(content.trim(), "original", "Original should be unchanged after abort");
        }
        Err(e) => eprintln!("OverlayFS test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// Test that COW commit merges writes back.
#[tokio::test]
async fn test_overlayfs_commit() {
    let workdir = temp_dir("commit");
    let storage = temp_dir("commit-storage");
    fs::write(workdir.join("data.txt"), "original").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .fs_isolation(FsIsolation::OverlayFs)
        .workdir(&workdir)
        .fs_storage(&storage)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["sh", "-c", "echo committed > data.txt"]).await;
    match result {
        Ok(r) => {
            if r.success() {
                let content = fs::read_to_string(workdir.join("data.txt")).unwrap();
                assert_eq!(content.trim(), "committed", "File should be updated after commit");
            }
        }
        Err(e) => eprintln!("OverlayFS test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// Test that policy validation catches missing workdir.
#[tokio::test]
async fn test_cow_requires_workdir() {
    let result = Policy::builder()
        .fs_isolation(FsIsolation::OverlayFs)
        .build();
    assert!(result.is_err(), "Should fail without workdir");
}

// ============================================================
// Seccomp-based COW tests (FsIsolation::None + workdir)
// ============================================================

/// Test that seccomp COW creates files in upper, committed on exit.
#[tokio::test]
async fn test_seccomp_cow_create_file() {
    let workdir = temp_dir("seccomp-create");
    fs::write(workdir.join("existing.txt"), "hello").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)  // FsIsolation::None is default → seccomp COW
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let new_file = workdir.join("new.txt");
    let cmd = format!("touch {}", new_file.display());
    let result = Sandbox::run(&policy, &["sh", "-c", &cmd]).await;
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

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let new_file = workdir.join("aborted.txt");
    let cmd = format!("touch {}", new_file.display());
    let result = Sandbox::run(&policy, &["sh", "-c", &cmd]).await;
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

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Use relative paths (triggers AT_FDCWD in openat) — the child's cwd is set via .cwd().
    let result = Sandbox::run(&policy, &[
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

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &[
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

    let policy = Policy::builder()
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
    let result = Sandbox::run(&policy, &["sh", "-c", &script]).await;
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

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Commit)
        .build()
        .unwrap();

    // mkdir creates the dir in COW upper only; cd must see it via interception.
    // Use physical pwd so the assertion covers getcwd virtualization.
    let script = format!(
        "mkdir -p subdir/deep && cd subdir/deep && pwd -P > {}",
        out_file.display()
    );
    let result = Sandbox::run(&policy, &["sh", "-c", &script]).await;
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
/// does not provide SYS_open, so it uses the equivalent raw openat ABI.
#[tokio::test]
async fn test_seccomp_cow_legacy_open_syscall() {
    let workdir = temp_dir("seccomp-legacy-open");
    let out_file = std::env::temp_dir().join(format!(
        "sandlock-test-legacy-open-{}", std::process::id()
    ));

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir).fs_write("/tmp")
        .workdir(&workdir)
        .cwd(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Use raw syscall ABI to create a file, then verify it's visible during
    // the run but discarded on abort. x86_64 uses legacy SYS_open; ARM64 uses
    // the equivalent openat(AT_FDCWD, ...) ABI.
    let script = format!(concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "O_WRONLY = 1; O_CREAT = 64; O_TRUNC = 512\n",
        "path = b'{wd}/newfile.txt'\n",
        "if platform.machine() == 'aarch64':\n",
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

    let result = Sandbox::run(&policy, &["python3", "-c", &script]).await.unwrap();
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

    let policy = Policy::builder()
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
        "if platform.machine() == 'aarch64':\n",
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

    let result = Sandbox::run(&policy, &["python3", "-c", &script]).await.unwrap();
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

    let policy = Policy::builder()
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
    let result = Sandbox::run(&policy, &["sh", "-c", &cmd]).await;
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
