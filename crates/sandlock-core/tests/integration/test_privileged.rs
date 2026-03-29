use sandlock_core::{Policy, Sandbox};

/// Test that privileged mode makes the child appear as uid 0.
#[tokio::test]
async fn test_privileged_uid_zero() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .privileged(true)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["id", "-u"]).await.unwrap();
    assert!(result.success(), "id -u failed: {:?}", result.exit_status);
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "0", "Expected uid 0, got: {:?}", stdout.trim());
}

/// Test that privileged mode makes the child appear as gid 0.
#[tokio::test]
async fn test_privileged_gid_zero() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .privileged(true)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["id", "-g"]).await.unwrap();
    assert!(result.success(), "id -g failed: {:?}", result.exit_status);
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "0", "Expected gid 0, got: {:?}", stdout.trim());
}

/// Test that without privileged, uid is NOT 0 (assuming tests don't run as root).
#[tokio::test]
async fn test_unprivileged_uid_nonzero() {
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
        assert_ne!(stdout.trim(), "0", "Without privileged, uid should not be 0");
    }
}

/// Test that privileged mode doesn't break basic command execution.
#[tokio::test]
async fn test_privileged_echo() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .privileged(true)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["echo", "hello"]).await.unwrap();
    assert!(result.success());
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "hello");
}
