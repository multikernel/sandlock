use std::time::{Duration, Instant};

use sandlock_core::policy::ByteSize;
use sandlock_core::{ExitStatus, Policy, Sandbox};

use libc;

/// Helper: build a base policy that allows Python3 and basic filesystem access.
fn base_policy() -> sandlock_core::policy::PolicyBuilder {
    Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
}

/// Helper: generate a temp file path for test output.
fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "sandlock-test-resource-{}-{}",
        name,
        std::process::id()
    ))
}

#[tokio::test]
async fn test_cpu_throttle_slows_execution() {
    let out = temp_path("cpu-throttle");

    // Run CPU-bound workload without throttle
    let policy_fast = base_policy().build().unwrap();
    let start_fast = Instant::now();
    Sandbox::run_interactive(&policy_fast, &[
        "python3",
        "-c",
        "s = 0\nfor i in range(2_000_000): s += i\n",
    ])
    .await
    .unwrap();
    let fast_elapsed = start_fast.elapsed();

    // Run the same workload with max_cpu(25)
    let script = format!(
        concat!(
            "s = 0\n",
            "for i in range(2_000_000): s += i\n",
            "open('{}', 'w').write(str(s))\n",
        ),
        out.display()
    );
    let policy_slow = base_policy().max_cpu(25).build().unwrap();
    let start_slow = Instant::now();
    Sandbox::run_interactive(&policy_slow, &["python3", "-c", &script])
        .await
        .unwrap();
    let slow_elapsed = start_slow.elapsed();

    // Verify output was written correctly
    let content = std::fs::read_to_string(&out).expect("temp file should exist");
    assert!(!content.is_empty(), "output file should have content");

    // Throttled version should take noticeably longer (>1.5x)
    assert!(
        slow_elapsed > fast_elapsed.mul_f64(1.5),
        "throttled ({:?}) should be >1.5x slower than unthrottled ({:?})",
        slow_elapsed,
        fast_elapsed,
    );

    let _ = std::fs::remove_file(&out);
}

#[tokio::test]
async fn test_cpu_throttle_100_no_slowdown() {
    // Run without throttle
    let policy_base = base_policy().build().unwrap();
    let start_base = Instant::now();
    Sandbox::run_interactive(&policy_base, &[
        "python3",
        "-c",
        "s = 0\nfor i in range(2_000_000): s += i\n",
    ])
    .await
    .unwrap();
    let base_elapsed = start_base.elapsed();

    // Run with max_cpu(100) — should not slow down
    let policy_full = base_policy().max_cpu(100).build().unwrap();
    let start_full = Instant::now();
    Sandbox::run_interactive(&policy_full, &[
        "python3",
        "-c",
        "s = 0\nfor i in range(2_000_000): s += i\n",
    ])
    .await
    .unwrap();
    let full_elapsed = start_full.elapsed();

    // max_cpu(100) should complete in roughly the same time (within 3x to
    // account for CI variance)
    assert!(
        full_elapsed < base_elapsed.mul_f64(3.0),
        "max_cpu(100) ({:?}) should not be dramatically slower than unthrottled ({:?})",
        full_elapsed,
        base_elapsed,
    );
}

#[tokio::test]
async fn test_timeout_kills_process() {
    let policy = base_policy().build().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        Sandbox::run_interactive(&policy, &["sleep", "300"]),
    )
    .await;

    // tokio::time::timeout should return Err(Elapsed) because the process
    // would run for 300 seconds
    assert!(
        result.is_err(),
        "expected timeout error, but process completed: {:?}",
        result,
    );
}

#[tokio::test]
async fn test_process_limit_enforced() {
    let out = temp_path("proc-limit");

    let script = format!(concat!(
        "import os\n",
        "count = 0\n",
        "for i in range(20):\n",
        "  try:\n",
        "    pid = os.fork()\n",
        "    if pid == 0:\n",
        "      os._exit(0)\n",
        "    else:\n",
        "      os.waitpid(pid, 0)\n",
        "      count += 1\n",
        "  except OSError:\n",
        "    break\n",
        "open('{out}', 'w').write(str(count))\n",
    ), out = out.display());

    let policy = base_policy().max_processes(3).build().unwrap();
    Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();

    let content = std::fs::read_to_string(&out).expect("temp file should exist");
    let count: u32 = content.trim().parse().expect("should be a number");
    assert!(
        count < 20,
        "expected some forks to fail with process limit, but all {} succeeded",
        count,
    );

    let _ = std::fs::remove_file(&out);
}

#[tokio::test]
async fn test_memory_limit_enforced() {
    let out = temp_path("mem-limit");

    let script = format!(concat!(
        "import sys\n",
        "try:\n",
        "  data = bytearray(200 * 1024 * 1024)\n",
        "  open('{out}', 'w').write('allocated')\n",
        "except MemoryError:\n",
        "  open('{out}', 'w').write('oom')\n",
        "except Exception as e:\n",
        "  open('{out}', 'w').write('error:' + str(e))\n",
    ), out = out.display());

    let policy = base_policy()
        .max_memory(ByteSize(64 * 1024 * 1024))
        .build()
        .unwrap();

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script]).await;

    // Process must be killed with SIGKILL when exceeding memory limit
    let run_result = result.expect("sandbox should return a result");
    assert!(
        matches!(run_result.exit_status, ExitStatus::Signal(libc::SIGKILL) | ExitStatus::Killed),
        "expected SIGKILL, got {:?}",
        run_result.exit_status,
    );
    // The output file should not exist — process was killed before writing
    if let Ok(content) = std::fs::read_to_string(&out) {
        assert_ne!(content.trim(), "allocated", "should not have allocated 200MB under 64MB limit");
    }

    let _ = std::fs::remove_file(&out);
}

#[tokio::test]
async fn test_spawn_and_kill() {
    let policy = base_policy().build().unwrap();
    let mut sb = Sandbox::new(&policy).unwrap();

    sb.spawn(&["sleep", "300"]).await.unwrap();
    sb.kill().unwrap();

    let result = sb.wait().await.unwrap();
    assert!(
        matches!(result.exit_status, ExitStatus::Signal(_) | ExitStatus::Killed),
        "expected Signal or Killed, got {:?}",
        result.exit_status,
    );
}

#[tokio::test]
async fn test_cpu_cores_affinity() {
    let out = temp_path("cpu-cores");

    // Bind to CPU 0 only
    let script = format!(concat!(
        "import os\n",
        "mask = os.sched_getaffinity(0)\n",
        "open('{}', 'w').write(','.join(str(c) for c in sorted(mask)))\n",
    ), out.display());

    let policy = base_policy()
        .cpu_cores(vec![0])
        .build()
        .unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script]).await.unwrap();
    assert_eq!(result.code(), Some(0));

    let content = std::fs::read_to_string(&out).expect("temp file should exist");
    assert_eq!(content.trim(), "0", "sandbox should be pinned to CPU 0 only");

    let _ = std::fs::remove_file(&out);
}

#[tokio::test]
async fn test_pause_resume() {
    let policy = base_policy().build().unwrap();
    let mut sb = Sandbox::new(&policy).unwrap();

    sb.spawn(&["sleep", "300"]).await.unwrap();

    sb.pause().expect("pause should succeed");
    sb.resume().expect("resume should succeed");

    sb.kill().unwrap();
    let result = sb.wait().await.unwrap();

    // Process should have been killed cleanly after pause/resume cycle
    assert!(
        matches!(
            result.exit_status,
            ExitStatus::Signal(_) | ExitStatus::Killed
        ),
        "expected Signal or Killed after pause/resume/kill, got {:?}",
        result.exit_status,
    );
}
