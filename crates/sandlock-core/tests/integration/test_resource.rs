use std::time::{Duration, Instant};

use sandlock_core::sandbox::ByteSize;
use sandlock_core::{Sandbox, ExitStatus};

use libc;

/// Helper: build a base policy that allows Python3 and basic filesystem access.
fn base_policy() -> sandlock_core::sandbox::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
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
    policy_fast.clone().run_interactive(&[
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
    policy_slow.clone().run_interactive(&["python3", "-c", &script])
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
    policy_base.clone().run_interactive(&[
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
    policy_full.clone().run_interactive(&[
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
        policy.clone().run_interactive(&["sleep", "300"]),
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

    // Fork children that stay alive (sleep) so they count toward the concurrent
    // process limit.  With max_processes=3, the parent counts as 1, so only 2
    // additional children can be alive at once.
    let script = format!(concat!(
        "import os, time\n",
        "count = 0\n",
        "for i in range(10):\n",
        "  try:\n",
        "    pid = os.fork()\n",
        "    if pid == 0:\n",
        "      time.sleep(60)\n",
        "      os._exit(0)\n",
        "    else:\n",
        "      count += 1\n",
        "  except OSError:\n",
        "    break\n",
        "open('{out}', 'w').write(str(count))\n",
    ), out = out.display());

    let policy = base_policy().max_processes(3).build().unwrap();
    policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let content = std::fs::read_to_string(&out).expect("temp file should exist");
    let count: u32 = content.trim().parse().expect("should be a number");
    assert!(
        count < 10,
        "expected some forks to fail with process limit, but all {} succeeded",
        count,
    );

    let _ = std::fs::remove_file(&out);
}

#[tokio::test]
async fn test_process_limit_allows_sequential_reuse() {
    let out = temp_path("proc-reuse");

    // Fork+wait sequentially: each child exits before the next fork, so peak
    // concurrent processes never exceeds 2 (parent + 1 child), which is
    // exactly what max_processes=2 allows.
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

    let policy = base_policy().max_processes(2).build().unwrap();
    policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let content = std::fs::read_to_string(&out).expect("temp file should exist");
    let count: u32 = content.trim().parse().expect("should be a number");
    assert_eq!(
        count, 20,
        "all 20 sequential forks should succeed (peak concurrent = 2), but only {} did",
        count,
    );

    let _ = std::fs::remove_file(&out);
}

#[tokio::test]
async fn test_process_limit_unset_is_unlimited() {
    // 100 live children is past the 64 that used to be the default.
    let out = temp_path("no-process-limit");
    let script = format!(concat!(
        "import os, signal\n",
        "pids = []\n",
        "try:\n",
        "  for i in range(100):\n",
        "    pid = os.fork()\n",
        "    if pid == 0:\n",
        "      signal.pause()\n",
        "      os._exit(0)\n",
        "    pids.append(pid)\n",
        "except OSError:\n",
        "  pass\n",
        "open('{}', 'w').write(str(len(pids)))\n",
        "for pid in pids:\n",
        "  os.kill(pid, signal.SIGKILL)\n",
        "  os.waitpid(pid, 0)\n",
    ), out.display());
    let policy = base_policy().build().unwrap();
    policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    let count: u32 = std::fs::read_to_string(&out)
        .expect("temp file should exist")
        .parse()
        .unwrap();
    let _ = std::fs::remove_file(&out);
    assert_eq!(count, 100, "no limit set, all 100 forks should succeed, got {}", count);
}

/// Run `script` under `max_processes` and return what it wrote to `{out}`.
async fn run_under_process_limit(name: &str, max_processes: u32, script: &str) -> String {
    let out = temp_path(name);
    let script = script.replace("{out}", &out.display().to_string());
    let policy = base_policy().max_processes(max_processes).build().unwrap();
    policy.clone().run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    let content = std::fs::read_to_string(&out).expect("temp file should exist");
    let _ = std::fs::remove_file(&out);
    content
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn test_process_limit_counts_bare_fork() {
    // glibc's fork() is clone(2) underneath, so only a raw fork(2) exercises
    // the legacy syscall number.
    let script = concat!(
        "import ctypes, os, time\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "count = 0\n",
        "for i in range(10):\n",
        "  pid = libc.syscall(57)\n",
        "  if pid == 0:\n",
        "    time.sleep(60)\n",
        "    os._exit(0)\n",
        "  if pid < 0:\n",
        "    break\n",
        "  count += 1\n",
        "open('{out}', 'w').write(str(count))\n",
    );
    let count: u32 = run_under_process_limit("bare-fork", 3, script)
        .await
        .parse()
        .unwrap();
    assert_eq!(count, 2, "limit 3 leaves room for 2 children, got {}", count);
}

// A slot belongs to a process until it dies, however it is reaped. Each test
// below forks more children in sequence than the limit allows at once, under
// a limit with no headroom beyond the children alive at that moment.

#[tokio::test]
async fn test_process_limit_releases_slot_on_wnohang_reap() {
    let script = concat!(
        "import os, time\n",
        "count = 0\n",
        "try:\n",
        "  for i in range(20):\n",
        "    pid = os.fork()\n",
        "    if pid == 0:\n",
        "      os._exit(0)\n",
        "    while os.waitpid(pid, os.WNOHANG)[0] == 0:\n",
        "      time.sleep(0.001)\n",
        "    count += 1\n",
        "except OSError:\n",
        "  pass\n",
        "open('{out}', 'w').write(str(count))\n",
    );
    let count = run_under_process_limit("wnohang-reap", 2, script).await;
    assert_eq!(count, "20", "every WNOHANG-reaped child should free its slot");
}

#[tokio::test]
async fn test_process_limit_releases_slot_on_auto_reap() {
    // SIGCHLD ignored: the kernel reaps the child, no wait call ever happens.
    let script = concat!(
        "import os, signal, time\n",
        "signal.signal(signal.SIGCHLD, signal.SIG_IGN)\n",
        "count = 0\n",
        "try:\n",
        "  for i in range(20):\n",
        "    pid = os.fork()\n",
        "    if pid == 0:\n",
        "      os._exit(0)\n",
        "    try:\n",
        "      while True:\n",
        "        os.kill(pid, 0)\n",
        "        time.sleep(0.001)\n",
        "    except ProcessLookupError:\n",
        "      pass\n",
        "    count += 1\n",
        "except OSError:\n",
        "  pass\n",
        "open('{out}', 'w').write(str(count))\n",
    );
    let count = run_under_process_limit("auto-reap", 2, script).await;
    assert_eq!(count, "20", "every auto-reaped child should free its slot");
}

#[tokio::test]
async fn test_process_limit_releases_slot_of_orphan() {
    // Double fork: the grandchild is reaped by init, never by a sandbox wait.
    // Its death is not observable from here, so a refused fork is retried
    // until the grandchild of the previous round is gone.
    let script = concat!(
        "import os, time\n",
        "def fork_retrying():\n",
        "  for attempt in range(2000):\n",
        "    try:\n",
        "      return os.fork()\n",
        "    except OSError:\n",
        "      time.sleep(0.001)\n",
        "  raise SystemExit(1)\n",
        "count = 0\n",
        "for i in range(20):\n",
        "  pid = fork_retrying()\n",
        "  if pid == 0:\n",
        "    if fork_retrying() == 0:\n",
        "      os._exit(0)\n",
        "    os._exit(0)\n",
        "  os.waitpid(pid, 0)\n",
        "  count += 1\n",
        "  open('{out}', 'w').write(str(count))\n",
    );
    let count = run_under_process_limit("orphan", 3, script).await;
    assert_eq!(count, "20", "every orphaned grandchild should free its slot");
}

#[tokio::test]
async fn test_process_limit_not_lowered_by_failed_wait() {
    // A blocking wait that reaps nothing (ECHILD) must not free a slot.
    let script = concat!(
        "import os, time\n",
        "count = 0\n",
        "for i in range(10):\n",
        "  try:\n",
        "    os.waitpid(1, 0)\n",
        "  except ChildProcessError:\n",
        "    pass\n",
        "  try:\n",
        "    pid = os.fork()\n",
        "  except OSError:\n",
        "    break\n",
        "  if pid == 0:\n",
        "    time.sleep(60)\n",
        "    os._exit(0)\n",
        "  count += 1\n",
        "open('{out}', 'w').write(str(count))\n",
    );
    let count = run_under_process_limit("failed-wait", 3, script).await;
    assert_eq!(count, "2", "limit 3 leaves room for exactly 2 live children");
}

#[tokio::test]
async fn test_process_limit_releases_slots_of_concurrent_children() {
    let script = concat!(
        "import os\n",
        "count = 0\n",
        "try:\n",
        "  for round in range(10):\n",
        "    pids = []\n",
        "    for i in range(4):\n",
        "      pid = os.fork()\n",
        "      if pid == 0:\n",
        "        os._exit(0)\n",
        "      pids.append(pid)\n",
        "    for pid in pids:\n",
        "      os.waitpid(pid, 0)\n",
        "    count += 1\n",
        "except OSError:\n",
        "  pass\n",
        "open('{out}', 'w').write(str(count))\n",
    );
    let count = run_under_process_limit("concurrent", 5, script).await;
    assert_eq!(count, "10", "each round of 4 children should free all 4 slots");
}

#[tokio::test]
async fn test_threads_do_not_count_toward_process_limit_clone3() {
    // Regression: handle_fork only checked CLONE_THREAD on SYS_clone, not
    // SYS_clone3 (whose flags live in a clone_args struct in user memory).
    // glibc 2.34+ implements pthread_create via clone3, so spawning many
    // Python threads under a tight max_processes would over-count and the
    // thread creations would fail with EAGAIN once the limit was hit.
    let out = temp_path("clone3-threads");

    let script = format!(concat!(
        "import threading, time\n",
        "barrier = threading.Barrier(11)\n",  // 10 threads + main
        "def worker():\n",
        "  barrier.wait()\n",
        "ts = [threading.Thread(target=worker) for _ in range(10)]\n",
        "for t in ts: t.start()\n",
        "barrier.wait()\n",  // every thread reached this point => all 10 alive together
        "for t in ts: t.join()\n",
        "open('{out}', 'w').write('ok')\n",
    ), out = out.display());

    // max_processes=2 leaves zero headroom for child *processes*, so any
    // pre-fix bug that counted threads as processes would block thread
    // creation immediately.
    let policy = base_policy().max_processes(2).build().unwrap();
    let result = policy.clone().run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(
        matches!(result.exit_status, ExitStatus::Code(0)),
        "python should exit 0; got {:?}",
        result.exit_status,
    );
    let content = std::fs::read_to_string(&out).expect("temp file should exist");
    assert_eq!(content, "ok", "all 10 threads should have started concurrently");

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

    let result = policy.clone().run_interactive(&["python3", "-c", &script]).await;

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
    let mut sb = policy.clone();

    sb.create_interactive(&["sleep", "300"]).await.unwrap();
    sb.start().unwrap();
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
    let result = policy.clone().run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert_eq!(result.code(), Some(0));

    let content = std::fs::read_to_string(&out).expect("temp file should exist");
    assert_eq!(content.trim(), "0", "sandbox should be pinned to CPU 0 only");

    let _ = std::fs::remove_file(&out);
}

/// A probe that reports the descriptor limit it sees, whether it can raise it
/// back, and how far it gets opening descriptors. Shared by the restricted and
/// the baseline arm so the two runs differ only by `max_open_files`.
const NOFILE_PROBE: &str = concat!(
    "import os, resource\n",
    "print('STARTED', flush=True)\n",
    "soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)\n",
    "print('RLIM', soft, hard)\n",
    "try:\n",
    "    resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096)); print('RAISE_OK')\n",
    "except (ValueError, OSError): print('RAISE_DENIED')\n",
    "fds = []\n",
    "try:\n",
    "    for _ in range(200): fds.append(os.open('/dev/null', os.O_RDONLY))\n",
    "    print('OPEN_OK', len(fds))\n",
    "except OSError as e: print('OPEN_DENIED', e.errno, len(fds))\n",
);

/// `max_open_files` is enforced via RLIMIT_NOFILE in the child: the guest sees
/// the lowered limit, cannot raise it back, and hits EMFILE past it. The
/// control run (same probe, no limit) opens every descriptor; without the
/// setrlimit call the two runs are indistinguishable and this test fails.
#[tokio::test]
async fn test_max_open_files_enforced() {
    let restricted = base_policy()
        .max_open_files(64)
        .build()
        .unwrap()
        .run(&["python3", "-c", NOFILE_PROBE])
        .await
        .unwrap();
    let out = String::from_utf8_lossy(restricted.stdout.as_deref().unwrap_or(b"")).into_owned();
    assert!(out.contains("STARTED"), "guest should start, got: {}", out);
    // Both bounds lowered: a soft-only cap would be advisory, since the guest
    // may call setrlimit itself.
    assert!(out.contains("RLIM 64 64"), "guest should see soft=hard=64, got: {}", out);
    // Lowering the hard limit is one-way only for an *unprivileged* sandlock.
    // Nothing drops CAP_SYS_RESOURCE, so a child of a root supervisor raises the
    // cap right back, and then opens all 200 descriptors. Asserting the
    // unprivileged behaviour unconditionally would fail every run under `sudo`
    // on a correct build, so the guest-side assertions are split by euid; the
    // cap itself (RLIM above) is checked in both modes.
    if unsafe { libc::geteuid() } == 0 {
        assert!(
            out.contains("RAISE_OK"),
            "a privileged sandlock keeps CAP_SYS_RESOURCE, so the guest may raise the cap back \
             (documented caveat on max_open_files); got: {}",
            out
        );
    } else {
        assert!(out.contains("RAISE_DENIED"), "lowering the hard limit must be one-way, got: {}", out);
        assert!(!out.contains("OPEN_OK"), "200 descriptors must exceed the limit of 64, got: {}", out);
        assert!(out.contains("OPEN_DENIED 24"), "excess open() should fail with EMFILE, got: {}", out);
    }
    assert_eq!(restricted.code(), Some(0));

    let baseline = base_policy()
        .build()
        .unwrap()
        .run(&["python3", "-c", NOFILE_PROBE])
        .await
        .unwrap();
    let out = String::from_utf8_lossy(baseline.stdout.as_deref().unwrap_or(b"")).into_owned();
    assert!(!out.contains("RLIM 64 64"), "unset max_open_files must inherit, got: {}", out);
    assert!(out.contains("OPEN_OK 200"), "no limit means 200 descriptors open fine, got: {}", out);
    assert_eq!(baseline.code(), Some(0));
}

/// The cap never *widens* the guest's descriptor budget: a request above the
/// limit sandlock itself runs under is clamped to the inherited soft limit, not
/// granted. Clamping against the hard limit alone is not enough: the common
/// host layout is a soft/hard split (1024 / 1048576), where every request in
/// between would otherwise hand the sandboxed process more descriptors than the
/// same command gets unsandboxed.
#[tokio::test]
async fn test_max_open_files_does_not_raise_inherited_limit() {
    let mut orig = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut orig) }, 0);

    // The test needs a soft < hard split to ask for "more than we have but less
    // than the kernel would refuse". Create one if the host has none, keeping
    // the soft limit high enough for the rest of the suite (the change is
    // process-wide and restored right after the run).
    let soft = orig.rlim_cur.min(4096);
    if soft >= orig.rlim_max {
        eprintln!("skipped: no soft<hard RLIMIT_NOFILE split available on this host");
        return;
    }
    let lowered = libc::rlimit { rlim_cur: soft, rlim_max: orig.rlim_max };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);

    // Request well above the inherited soft limit but still below the hard one,
    // so a hard-limit-only clamp would let it through unchanged.
    let requested = (soft + 1024) as u32;
    let result = base_policy()
        .max_open_files(requested)
        .build()
        .unwrap()
        .run(&["python3", "-c", NOFILE_PROBE])
        .await;

    // Restore before asserting: a panic here must not leave the whole test
    // binary running under the lowered limit.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &orig) }, 0);

    let result = result.unwrap();
    let out = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or(b"")).into_owned();
    assert_eq!(result.code(), Some(0), "the run must succeed, got: {}", out);
    assert!(
        out.contains(&format!("RLIM {} {}", soft, soft)),
        "requesting {} with an inherited soft limit of {} must clamp to {}, not widen the guest's \
         budget; got: {}",
        requested,
        soft,
        soft,
        out
    );
}

/// The setrlimit must stay the *last* confinement step. A cap this small is
/// below what Landlock (one O_PATH fd per rule path plus the ruleset fd) and
/// the seccomp notify listener need, so applying it any earlier makes the child
/// die with "landlock: create ruleset: Too many open files" instead of running.
/// With the correct placement those descriptors are already spent and closed,
/// and the cap only has to cover stdio plus the loader.
#[tokio::test]
async fn test_max_open_files_applied_after_landlock_and_seccomp() {
    let result = base_policy()
        .max_open_files(12)
        .build()
        .unwrap()
        .run(&["/bin/true"])
        .await
        .expect(
            "the child must survive confinement setup under a small cap; an early setrlimit \
             starves Landlock/seccomp and kills the child before it reports back",
        );
    assert_eq!(
        result.code(),
        Some(0),
        "a cap smaller than the confinement setup needs must still run, stderr: {}",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or(b""))
    );
}

#[tokio::test]
async fn test_pause_resume() {
    let policy = base_policy().build().unwrap();
    let mut sb = policy.clone();

    sb.create_interactive(&["sleep", "300"]).await.unwrap();
    sb.start().unwrap();

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
