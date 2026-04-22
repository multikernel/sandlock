use sandlock_core::{Policy, Sandbox};
use std::time::{Duration, SystemTime};

/// Test that random_seed produces deterministic output from /dev/urandom.
/// Run the same command twice with the same seed — reads should match.
#[tokio::test]
async fn test_random_seed_deterministic() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .random_seed(42)
        .build()
        .unwrap();

    // Read 16 bytes from /dev/urandom via od — exercises the openat interception path.
    let r1 = Sandbox::run(&policy, &["sh", "-c", "od -A n -N 16 -t x1 /dev/urandom"])
        .await
        .unwrap();
    let r2 = Sandbox::run(&policy, &["sh", "-c", "od -A n -N 16 -t x1 /dev/urandom"])
        .await
        .unwrap();

    assert!(r1.success(), "First run failed");
    assert!(r2.success(), "Second run failed");

    let out1 = String::from_utf8_lossy(r1.stdout.as_deref().unwrap_or_default());
    let out2 = String::from_utf8_lossy(r2.stdout.as_deref().unwrap_or_default());
    assert!(
        !out1.trim().is_empty(),
        "Expected non-empty output from /dev/urandom read"
    );
    assert_eq!(
        out1.trim(),
        out2.trim(),
        "Two runs with same seed should produce identical /dev/urandom output"
    );
}

/// Test that different seeds produce different /dev/urandom output.
#[tokio::test]
async fn test_random_seed_different_seeds() {
    let p1 = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/dev")
        .random_seed(1)
        .build()
        .unwrap();
    let p2 = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/dev")
        .random_seed(999)
        .build()
        .unwrap();

    let cmd = &["sh", "-c", "od -A n -N 16 -t x1 /dev/urandom"];
    let r1 = Sandbox::run(&p1, cmd).await.unwrap();
    let r2 = Sandbox::run(&p2, cmd).await.unwrap();
    assert!(r1.success());
    assert!(r2.success());

    let out1 = String::from_utf8_lossy(r1.stdout.as_deref().unwrap_or_default());
    let out2 = String::from_utf8_lossy(r2.stdout.as_deref().unwrap_or_default());
    assert!(
        !out1.trim().is_empty(),
        "Expected non-empty output"
    );
    assert_ne!(
        out1.trim(),
        out2.trim(),
        "Different seeds should produce different /dev/urandom output"
    );
}

/// Test that time_start sets frozen time.
/// The date command should show a year matching the frozen time.
#[tokio::test]
#[cfg_attr(target_arch = "aarch64", ignore = "ARM64 vDSO time patching is planned for stage 4")]
async fn test_time_start_frozen() {
    // Freeze to 2000-06-15T00:00:00Z (mid-year avoids timezone boundary issues)
    let y2k = SystemTime::UNIX_EPOCH + Duration::from_secs(961027200);
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .time_start(y2k)
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["date", "+%Y"]).await.unwrap();
    assert!(result.success(), "date command failed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "2000", "Expected year 2000, got: {:?}", stdout.trim());
}

/// Test that time_start doesn't break basic command execution.
#[tokio::test]
async fn test_time_start_basic_commands_work() {
    let past = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000); // 2001-09-09
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
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
        .fs_read_if_exists("/lib64")
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

/// Test that deterministic_dirs produces sorted directory listings.
/// Run ls twice — output should match and be sorted.
#[tokio::test]
#[cfg_attr(target_arch = "aarch64", ignore = "ARM64 deterministic getdents virtualization needs follow-up")]
async fn test_deterministic_dirs() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .deterministic_dirs(true)
        .build()
        .unwrap();

    // Use ls -f -1 to preserve raw getdents order (no re-sorting by ls).
    let r1 = Sandbox::run(&policy, &["ls", "-f", "-1", "/etc"]).await.unwrap();
    let r2 = Sandbox::run(&policy, &["ls", "-f", "-1", "/etc"]).await.unwrap();
    assert!(r1.success(), "First ls failed");
    assert!(r2.success(), "Second ls failed");

    let out1 = String::from_utf8_lossy(r1.stdout.as_deref().unwrap_or_default());
    let out2 = String::from_utf8_lossy(r2.stdout.as_deref().unwrap_or_default());
    assert!(
        !out1.trim().is_empty(),
        "Expected non-empty ls output"
    );
    assert_eq!(
        out1, out2,
        "Two ls -f runs should produce identical output with deterministic_dirs"
    );

    // Verify the output is actually sorted (skip . and .. entries from ls -f).
    let lines: Vec<&str> = out1.lines()
        .filter(|l| *l != "." && *l != "..")
        .collect();
    let mut sorted = lines.clone();
    sorted.sort();
    assert_eq!(lines, sorted, "getdents output should be lexicographically sorted");
}

/// Test that hostname virtualizes both uname() and /etc/hostname.
#[tokio::test]
async fn test_hostname_virtualization() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .hostname("mybox")
        .build()
        .unwrap();

    // Verify uname() returns the virtual hostname.
    let result = Sandbox::run(&policy, &["hostname"]).await.unwrap();
    assert!(result.success(), "hostname command failed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "mybox", "Expected hostname 'mybox', got: {:?}", stdout.trim());

    // Verify /etc/hostname also returns the virtual hostname.
    let result = Sandbox::run(&policy, &["cat", "/etc/hostname"]).await.unwrap();
    assert!(result.success(), "cat /etc/hostname failed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "mybox", "Expected /etc/hostname 'mybox', got: {:?}", stdout.trim());
}
