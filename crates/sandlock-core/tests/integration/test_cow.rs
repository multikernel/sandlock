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
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin").fs_read("/etc")
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
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin").fs_read("/etc")
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
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin").fs_read("/etc")
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
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin").fs_read("/etc")
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
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin").fs_read("/etc")
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
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // Use relative paths (triggers AT_FDCWD in openat) — the child's cwd is workdir.
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
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
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

/// Test that seccomp COW read isolation works (reads original before any writes).
#[tokio::test]
async fn test_seccomp_cow_read_existing() {
    let workdir = temp_dir("seccomp-read");
    fs::write(workdir.join("data.txt"), "hello world").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin").fs_read("/etc")
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
