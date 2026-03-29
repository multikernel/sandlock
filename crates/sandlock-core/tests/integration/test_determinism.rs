use sandlock_core::{Policy, Sandbox};
use std::time::{Duration, SystemTime};

/// Test that random_seed produces deterministic output.
/// Run the same command twice with the same seed — getrandom results should match.
#[tokio::test]
async fn test_random_seed_deterministic() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .random_seed(42)
        .build()
        .unwrap();

    // Use sh + od on /dev/urandom to exercise getrandom syscall path
    let r1 = Sandbox::run(&policy, &["sh", "-c", "od -A n -N 16 -t x1 /dev/urandom"])
        .await
        .unwrap();
    let r2 = Sandbox::run(&policy, &["sh", "-c", "od -A n -N 16 -t x1 /dev/urandom"])
        .await
        .unwrap();

    assert!(r1.success(), "First run failed");
    assert!(r2.success(), "Second run failed");
    // Note: stdout capture isn't implemented yet, so we can't compare outputs.
    // For now, just verify both runs succeed with the random_seed policy.
}

/// Test that different seeds produce different processes (both succeed).
#[tokio::test]
async fn test_random_seed_different_seeds() {
    let p1 = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .random_seed(1)
        .build()
        .unwrap();
    let p2 = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .random_seed(999)
        .build()
        .unwrap();

    let r1 = Sandbox::run(&p1, &["true"]).await.unwrap();
    let r2 = Sandbox::run(&p2, &["true"]).await.unwrap();
    assert!(r1.success());
    assert!(r2.success());
}

/// Test that time_start sets frozen time.
/// The date command should show a year matching the frozen time.
#[tokio::test]
async fn test_time_start_frozen() {
    // Freeze to 2000-01-01T00:00:00Z
    let y2k = SystemTime::UNIX_EPOCH + Duration::from_secs(946684800);
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .time_start(y2k)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["date", "+%Y"]).await.unwrap();
    assert!(result.success(), "date command failed");
    // Note: Without stdout capture, we can't verify the year is 2000.
    // But the command should at least succeed with vDSO patching active.
}

/// Test that time_start doesn't break basic command execution.
#[tokio::test]
async fn test_time_start_basic_commands_work() {
    let past = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000); // 2001-09-09
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .time_start(past)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["echo", "hello"]).await.unwrap();
    assert!(result.success());
}

/// Test combining random_seed and time_start.
#[tokio::test]
async fn test_combined_determinism() {
    let past = SystemTime::UNIX_EPOCH + Duration::from_secs(946684800);
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .time_start(past)
        .random_seed(42)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["echo", "deterministic"]).await.unwrap();
    assert!(result.success());
}
