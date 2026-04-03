use sandlock_core::{Policy, Sandbox};

/// Check if user namespaces with uid mapping actually work in this environment.
/// Some CI environments (containers, restricted kernels) allow unshare but block
/// writing to /proc/self/uid_map.
fn userns_available() -> bool {
    // Fork a child that tries unshare(CLONE_NEWUSER) + uid_map write.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        // Child: try unshare + write uid_map
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            unsafe { libc::_exit(1) };
        }
        let uid = unsafe { libc::getuid() };
        let map = format!("0 {} 1\n", uid);
        let ok = std::fs::write("/proc/self/setgroups", "deny\n").is_ok()
            && std::fs::write("/proc/self/uid_map", &map).is_ok()
            && std::fs::write("/proc/self/gid_map", &map).is_ok()
            && unsafe { libc::getuid() } == 0;
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    // Parent: wait and check exit status
    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// Test that --uid 0 makes the child appear as uid 0.
#[tokio::test]
async fn test_uid_zero() {
    if !userns_available() {
        eprintln!("Skipping: user namespaces not available in this environment");
        return;
    }

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .uid(0)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["id", "-u"]).await.unwrap();
    assert!(result.success(), "id -u failed: {:?}", result.exit_status);
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "0", "Expected uid 0, got: {:?}", stdout.trim());
}

/// Test that --uid 0 makes the child appear as gid 0.
#[tokio::test]
async fn test_uid_zero_gid_zero() {
    if !userns_available() {
        eprintln!("Skipping: user namespaces not available in this environment");
        return;
    }

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .uid(0)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["id", "-g"]).await.unwrap();
    assert!(result.success(), "id -g failed: {:?}", result.exit_status);
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "0", "Expected gid 0, got: {:?}", stdout.trim());
}

/// Test that without --uid, uid is NOT 0 (assuming tests don't run as root).
#[tokio::test]
async fn test_no_uid_keeps_real_uid() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["id", "-u"]).await.unwrap();
    assert!(result.success());
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // If running as root already, skip this check
    if unsafe { libc::getuid() } != 0 {
        assert_ne!(stdout.trim(), "0", "Without --uid, uid should not be 0");
    }
}

/// Test that --uid 0 doesn't break basic command execution.
#[tokio::test]
async fn test_uid_zero_echo() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .uid(0)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["echo", "hello"]).await.unwrap();
    assert!(result.success());
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "hello");
}

/// Test that --uid 1000 maps to the expected UID inside the namespace.
#[tokio::test]
async fn test_uid_custom() {
    if !userns_available() {
        eprintln!("Skipping: user namespaces not available in this environment");
        return;
    }

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .uid(1000)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["id", "-u"]).await.unwrap();
    assert!(result.success(), "id -u failed: {:?}", result.exit_status);
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "1000", "Expected uid 1000, got: {:?}", stdout.trim());
}
