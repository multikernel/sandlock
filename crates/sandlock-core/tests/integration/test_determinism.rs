use sandlock_core::{Sandbox};
use std::time::{Duration, SystemTime};

/// Test that random_seed produces deterministic output from /dev/urandom.
/// Run the same command twice with the same seed — reads should match.
#[tokio::test]
async fn test_random_seed_deterministic() {
    let policy = Sandbox::builder()
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
    let r1 = policy.clone().with_name("test").run(&["sh", "-c", "od -A n -N 16 -t x1 /dev/urandom"])
        .await
        .unwrap();
    let r2 = policy.clone().with_name("test").run(&["sh", "-c", "od -A n -N 16 -t x1 /dev/urandom"])
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
    let p1 = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/dev")
        .random_seed(1)
        .build()
        .unwrap();
    let p2 = Sandbox::builder()
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
    let r1 = p1.clone().with_name("test").run(cmd).await.unwrap();
    let r2 = p2.clone().with_name("test").run(cmd).await.unwrap();
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
async fn test_time_start_frozen() {
    // Freeze to 2000-06-15T00:00:00Z (mid-year avoids timezone boundary issues)
    let y2k = SystemTime::UNIX_EPOCH + Duration::from_secs(961027200);
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .time_start(y2k)
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run(&["date", "+%Y"]).await.unwrap();
    assert!(result.success(), "date command failed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "2000", "Expected year 2000, got: {:?}", stdout.trim());
}

/// Test that time_start doesn't break basic command execution.
#[tokio::test]
async fn test_time_start_basic_commands_work() {
    let past = SystemTime::UNIX_EPOCH + Duration::from_secs(1000000000); // 2001-09-09
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .time_start(past)
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run(&["echo", "hello"]).await.unwrap();
    assert!(result.success());
}

/// Test combining random_seed and time_start.
#[tokio::test]
async fn test_combined_determinism() {
    let past = SystemTime::UNIX_EPOCH + Duration::from_secs(946684800);
    let policy = Sandbox::builder()
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

    let result = policy.clone().with_name("test").run(&["echo", "deterministic"]).await.unwrap();
    assert!(result.success());
}

/// Test that deterministic_dirs produces sorted directory listings.
/// Run directory iteration twice — output should match and be sorted.
#[tokio::test]
async fn test_deterministic_dirs() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .deterministic_dirs(true)
        .build()
        .unwrap();

    // Read directory entries without userland sorting so the assertion covers
    // the sandbox's getdents virtualization. Some minimal ls implementations
    // do not support `-f`, so avoid depending on ls option support here.
    let scan = "python3 - <<'PY'\nimport os\nprint('\\n'.join(e.name for e in os.scandir('/etc')))\nPY";
    let r1 = policy.clone().with_name("test").run(&["sh", "-c", scan]).await.unwrap();
    let r2 = policy.clone().with_name("test").run(&["sh", "-c", scan]).await.unwrap();
    assert!(
        r1.success(),
        "First directory scan failed: {}",
        String::from_utf8_lossy(r1.stderr.as_deref().unwrap_or_default())
    );
    assert!(
        r2.success(),
        "Second directory scan failed: {}",
        String::from_utf8_lossy(r2.stderr.as_deref().unwrap_or_default())
    );

    let out1 = String::from_utf8_lossy(r1.stdout.as_deref().unwrap_or_default());
    let out2 = String::from_utf8_lossy(r2.stdout.as_deref().unwrap_or_default());
    assert!(
        !out1.trim().is_empty(),
        "Expected non-empty ls output"
    );
    assert_eq!(
        out1, out2,
        "Two directory scans should produce identical output with deterministic_dirs"
    );

    // Verify the output is actually sorted (skip dot entries when the runtime
    // exposes them).
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
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .build()
        .unwrap();

    // Verify uname() returns the virtual hostname.
    let result = policy.clone().with_name("mybox").run(&["hostname"]).await.unwrap();
    assert!(result.success(), "hostname command failed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "mybox", "Expected hostname 'mybox', got: {:?}", stdout.trim());

    // Verify /etc/hostname also returns the virtual hostname.
    let result = policy.clone().with_name("mybox").run(&["cat", "/etc/hostname"]).await.unwrap();
    assert!(result.success(), "cat /etc/hostname failed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "mybox", "Expected /etc/hostname 'mybox', got: {:?}", stdout.trim());
}

/// The /etc/hostname shim used to do a literal `path == "/etc/hostname"`
/// match, so dirfd-relative and non-canonical spellings leaked the host's
/// real hostname. Exercise each bypass shape and assert the virtual
/// hostname comes back.
#[tokio::test]
async fn test_hostname_virtualization_resists_path_bypasses() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .build()
        .unwrap();

    let script = concat!(
        "import os\n",
        "results = {}\n",
        "etcfd = os.open('/etc', os.O_DIRECTORY | os.O_RDONLY)\n",
        "fd = os.open('hostname', os.O_RDONLY, dir_fd=etcfd)\n",
        "results['dirfd']  = os.read(fd, 4096).decode().strip()\n",
        "os.close(fd); os.close(etcfd)\n",
        "results['dotdot'] = open('/etc/../etc/hostname').read().strip()\n",
        "results['curdir'] = open('/etc/./hostname').read().strip()\n",
        "results['slash2'] = open('//etc/hostname').read().strip()\n",
        "print(results)\n",
    );

    let result = policy.clone().with_name("mybox").run(&["python3", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    for label in ["dirfd", "dotdot", "curdir", "slash2"] {
        let needle = format!("'{label}': 'mybox'");
        assert!(
            stdout.contains(&needle),
            "{label}: host /etc/hostname leaked. stdout: {stdout}"
        );
    }
}
