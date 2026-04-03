use sandlock_core::policy::BranchAction;
#[allow(unused_imports)]
use sandlock_core::{Policy, Sandbox};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Path to the static musl rootfs-helper binary.
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found — run: musl-gcc -static -O2 -o tests/rootfs-helper tests/rootfs-helper.c")
}

/// Minimal fs_readable set needed to run rootfs-helper under chroot.
fn minimal_exec_policy(rootfs: &PathBuf) -> sandlock_core::PolicyBuilder {
    Policy::builder()
        .chroot(rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/proc")
        .fs_read("/dev")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("sandlock-test-chroot-{}-{}", name, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Build a self-contained rootfs with the static rootfs-helper binary.
///
/// Layout:
///   usr/bin/rootfs-helper   — the real binary
///   usr/bin/sh              — symlink -> rootfs-helper
///   usr/bin/cat             — symlink -> rootfs-helper
///   usr/bin/echo            — symlink -> rootfs-helper
///   usr/bin/ls              — symlink -> rootfs-helper
///   usr/bin/pwd             — symlink -> rootfs-helper
///   usr/bin/readlink        — symlink -> rootfs-helper
///   usr/bin/true            — symlink -> rootfs-helper
///   usr/bin/write           — symlink -> rootfs-helper
///   bin                     — symlink -> usr/bin  (merged /usr)
///   sbin                    — symlink -> usr/sbin (merged /usr)
///   etc/
///   proc/
///   dev/
///   tmp/                    — mode 1777
fn build_test_rootfs(name: &str) -> PathBuf {
    let rootfs = temp_dir(name);
    let helper = helper_binary();

    // Create real directories
    for dir in &["usr/bin", "usr/sbin", "etc", "proc", "dev", "tmp"] {
        let _ = fs::create_dir_all(rootfs.join(dir));
    }

    // Set /tmp sticky
    let _ = fs::set_permissions(rootfs.join("tmp"), fs::Permissions::from_mode(0o1777));

    // Copy the helper binary
    let dest = rootfs.join("usr/bin/rootfs-helper");
    fs::copy(&helper, &dest).expect("failed to copy rootfs-helper into rootfs");
    let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o755));

    // Create busybox-style symlinks (relative, within rootfs)
    for cmd in &["sh", "cat", "echo", "ls", "pwd", "readlink", "true", "write"] {
        let link = rootfs.join(format!("usr/bin/{}", cmd));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink("rootfs-helper", &link)
            .expect("failed to create busybox symlink");
    }

    // Merged /usr symlinks (like real distros)
    let _ = std::os::unix::fs::symlink("usr/bin", rootfs.join("bin"));
    let _ = std::os::unix::fs::symlink("usr/sbin", rootfs.join("sbin"));

    rootfs
}

fn cleanup_rootfs(rootfs: &PathBuf) {
    let _ = fs::remove_dir_all(rootfs);
}

/// List / inside chroot shows rootfs contents (should see "usr", "tmp", "bin", "etc")
#[tokio::test]
async fn test_chroot_ls_root() {
    let rootfs = build_test_rootfs("ls-root");

    let policy = Policy::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/tmp")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["rootfs-helper", "ls", "/"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "ls / should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert!(stdout.contains("usr"), "should list usr, got: {}", stdout);
            assert!(stdout.contains("tmp"), "should list tmp, got: {}", stdout);
            assert!(stdout.contains("bin"), "should list bin, got: {}", stdout);
            assert!(stdout.contains("etc"), "should list etc, got: {}", stdout);
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Path traversal via /../../ stays confined — reads a file unique to the chroot.
#[tokio::test]
async fn test_chroot_no_escape() {
    let rootfs = build_test_rootfs("no-escape");

    // Write a sentinel file only inside the chroot's /etc
    let sentinel = "sandlock-chroot-sentinel";
    fs::write(rootfs.join("etc/sentinel"), sentinel).unwrap();

    let policy = Policy::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    // Path traversal: /../../etc/sentinel should resolve to /etc/sentinel inside
    // the chroot (the sentinel file we created), not escape to the host.
    let result = Sandbox::run(&policy, &["rootfs-helper", "cat", "/../../etc/sentinel"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "cat should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert_eq!(
                stdout.trim(),
                sentinel,
                "should read chroot sentinel, got: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// pwd returns / inside chroot
#[tokio::test]
async fn test_chroot_getcwd() {
    let rootfs = build_test_rootfs("getcwd");

    let policy = Policy::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["rootfs-helper", "pwd"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "pwd should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert_eq!(stdout, "/", "pwd should return /, got: {}", stdout);
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// echo hello > /tmp/test.txt && cat /tmp/test.txt works, file appears in rootfs/tmp
#[tokio::test]
async fn test_chroot_write_file() {
    let rootfs = build_test_rootfs("write-file");

    let policy = Policy::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let result = Sandbox::run(
        &policy,
        &["rootfs-helper", "sh", "-c", "echo hello > /tmp/test.txt && cat /tmp/test.txt"],
    )
    .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert_eq!(stdout, "hello", "cat should output hello, got: {}", stdout);
            // File should appear in rootfs/tmp (since /tmp inside chroot maps to rootfs/tmp)
            let real_path = rootfs.join("tmp/test.txt");
            assert!(
                real_path.exists(),
                "test.txt should exist at {}",
                real_path.display()
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// chroot + COW with BranchAction::Abort discards writes
#[tokio::test]
async fn test_chroot_with_cow() {
    let rootfs = build_test_rootfs("cow");
    let tmp_dir = rootfs.join("tmp");

    let policy = Policy::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = Sandbox::run(
        &policy,
        &["rootfs-helper", "sh", "-c", "echo cow-test > /tmp/cow.txt"],
    )
    .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            // With abort, file should NOT exist
            let cow_file = tmp_dir.join("cow.txt");
            assert!(
                !cow_file.exists(),
                "cow.txt should not exist after abort, but found at {}",
                cow_file.display()
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// readlink /proc/self/root returns /
#[tokio::test]
async fn test_chroot_proc_self_root() {
    let rootfs = build_test_rootfs("proc-self-root");

    let policy = Policy::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["rootfs-helper", "readlink", "/proc/self/root"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "readlink should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert_eq!(
                stdout, "/",
                "readlink /proc/self/root should return /, got: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Writing to /tmp should fail when only fs_read is granted (no fs_write("/tmp"))
#[tokio::test]
async fn test_chroot_write_denied_without_fs_write() {
    let rootfs = build_test_rootfs("write-denied");

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .fs_read("/tmp")
        // Deliberately NO fs_write("/tmp")
        .build()
        .unwrap();

    let result = Sandbox::run(
        &policy,
        &["rootfs-helper", "sh", "-c", "echo denied > /tmp/should-fail.txt"],
    )
    .await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "write should fail without fs_write, but got exit=0"
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// execve inside chroot with fs_readable=["/"] should work — regression test
/// for a bug where the seccomp path rewrite truncated /proc/self/fd/N when
/// the original path buffer was shorter than the replacement string.
#[tokio::test]
async fn test_chroot_exec_with_root_readable() {
    let rootfs = build_test_rootfs("exec-root-readable");

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .fs_read("/")
        .build()
        .unwrap();

    // Use /bin/rootfs-helper which goes through the bin -> usr/bin symlink
    let result = Sandbox::run(&policy, &["/bin/rootfs-helper", "echo", "chroot-exec-ok"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "/bin/rootfs-helper should succeed with fs_read(\"/\"), exit={:?} stderr: {} stdout: {}",
                r.code(), r.stderr_str().unwrap_or(""), r.stdout_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert!(
                stdout.contains("chroot-exec-ok"),
                "should print chroot-exec-ok, got: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Reading /etc/hostname should fail when /etc is not in fs_readable
#[tokio::test]
async fn test_chroot_read_denied_without_fs_read() {
    let rootfs = build_test_rootfs("read-denied");

    // Create a hostname file in the rootfs
    fs::write(rootfs.join("etc/hostname"), "sandlock-test-host").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        // Deliberately NO fs_read("/etc")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["rootfs-helper", "cat", "/etc/hostname"]).await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "cat /etc/hostname should fail without fs_read(\"/etc\"), exit={:?} stdout={}",
                r.code(),
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}
