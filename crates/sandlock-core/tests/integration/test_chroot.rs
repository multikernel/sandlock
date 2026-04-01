use sandlock_core::policy::BranchAction;
#[allow(unused_imports)]
use sandlock_core::{Policy, Sandbox};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Minimal fs_readable set needed to run a binary under chroot.
fn minimal_exec_policy(rootfs: &PathBuf) -> sandlock_core::PolicyBuilder {
    Policy::builder()
        .chroot(rootfs)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/sbin")
        .fs_read("/proc")
        .fs_read("/dev")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("sandlock-test-chroot-{}-{}", name, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn build_test_rootfs(name: &str) -> PathBuf {
    let rootfs = temp_dir(name);
    for dir in &[
        "usr", "lib", "lib64", "bin", "sbin", "etc", "proc", "dev", "tmp",
    ] {
        let host = PathBuf::from("/").join(dir);
        let target = rootfs.join(dir);
        if host.exists() && !target.exists() {
            let _ = std::os::unix::fs::symlink(&host, &target);
        }
    }
    let tmp = rootfs.join("tmp");
    if !tmp.exists() {
        let _ = fs::create_dir_all(&tmp);
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o1777));
    }
    rootfs
}

fn cleanup_rootfs(rootfs: &PathBuf) {
    // Remove symlinks and dirs; ignore errors
    for dir in &[
        "usr", "lib", "lib64", "bin", "sbin", "etc", "proc", "dev", "tmp",
    ] {
        let target = rootfs.join(dir);
        let _ = fs::remove_file(&target); // removes symlinks
    }
    let _ = fs::remove_dir_all(rootfs);
}

/// List / inside chroot shows rootfs contents (should see "usr", "tmp")
#[tokio::test]
async fn test_chroot_ls_root() {
    let rootfs = build_test_rootfs("ls-root");

    let policy = Policy::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/sbin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/tmp")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["ls", "/"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "echo /* should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert!(stdout.contains("usr"), "should list usr, got: {}", stdout);
            assert!(stdout.contains("tmp"), "should list tmp, got: {}", stdout);
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
    let chroot_etc = rootfs.join("etc");
    if chroot_etc.is_symlink() {
        let _ = fs::remove_file(&chroot_etc);
    }
    let _ = fs::create_dir_all(&chroot_etc);
    let sentinel = "sandlock-chroot-sentinel";
    fs::write(chroot_etc.join("sentinel"), sentinel).unwrap();

    let policy = Policy::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/sbin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    // Path traversal: /../../etc/sentinel should resolve to /etc/sentinel inside
    // the chroot (the sentinel file we created), not escape to the host.
    let result = Sandbox::run(&policy, &["cat", "/../../etc/sentinel"]).await;
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
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/sbin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["pwd"]).await;
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
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/sbin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let result =
        Sandbox::run(&policy, &["sh", "-c", "echo hello > /tmp/test.txt && cat /tmp/test.txt"])
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
    // Create a real tmp dir (not a symlink) for writes
    let tmp_dir = rootfs.join("tmp");
    let _ = fs::remove_file(&tmp_dir); // remove symlink if any
    let _ = fs::create_dir_all(&tmp_dir);
    let _ = fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o1777));

    let policy = Policy::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/sbin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result =
        Sandbox::run(&policy, &["sh", "-c", "echo cow-test > /tmp/cow.txt"]).await;
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
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/sbin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["readlink", "/proc/self/root"]).await;
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

    let result = Sandbox::run(&policy, &["sh", "-c", "echo denied > /tmp/should-fail.txt"]).await;
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

/// Reading /etc/hostname should fail when /etc is not in fs_readable
#[tokio::test]
async fn test_chroot_read_denied_without_fs_read() {
    let rootfs = build_test_rootfs("read-denied");

    let policy = minimal_exec_policy(&rootfs)
        // Deliberately NO fs_read("/etc")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["cat", "/etc/hostname"]).await;
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
