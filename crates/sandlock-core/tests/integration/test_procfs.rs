use sandlock_core::policy::ByteSize;
use sandlock_core::{Policy, Sandbox};

/// Test that num_cpus virtualizes both /proc/cpuinfo and sched_getaffinity.
#[tokio::test]
async fn test_num_cpus_virtualization() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(2)
        .build()
        .unwrap();

    // Verify /proc/cpuinfo shows 2 processors.
    let result = Sandbox::run(&policy, Some("test"), &["sh", "-c", "grep -c ^processor /proc/cpuinfo"]).await.unwrap();
    assert!(result.success(), "grep /proc/cpuinfo should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "2", "/proc/cpuinfo should show 2 processors, got: {:?}", stdout.trim());

    // Verify nproc (sched_getaffinity) also reports 2.
    let result = Sandbox::run(&policy, Some("test"), &["nproc"]).await.unwrap();
    assert!(result.success(), "nproc should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "2", "nproc should report 2 CPUs, got: {:?}", stdout.trim());
}

/// Test that max_memory virtualizes /proc/meminfo.
#[tokio::test]
async fn test_meminfo_virtualization() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .max_memory(ByteSize::mib(256))
        .build()
        .unwrap();

    // Read meminfo — should show virtualized values
    let result = Sandbox::run(&policy, Some("test"), &["cat", "/proc/meminfo"]).await.unwrap();
    assert!(result.success(), "cat /proc/meminfo should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // 256 MiB = 262144 kB
    assert!(
        stdout.contains("MemTotal:       262144 kB"),
        "Expected MemTotal of 262144 kB (256 MiB), got: {:?}", stdout
    );
}

/// Test that sensitive /proc paths are blocked.
#[tokio::test]
async fn test_sensitive_proc_blocked() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(1) // activate proc virtualization
        .build()
        .unwrap();

    // /proc/kcore should be denied
    let result = Sandbox::run(&policy, Some("test"), &["cat", "/proc/kcore"]).await.unwrap();
    assert!(!result.success(), "/proc/kcore should be denied");
}

/// Test basic sandbox still works without /proc virtualization.
#[tokio::test]
async fn test_no_proc_virt_still_works() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, Some("test"), &["cat", "/proc/version"]).await.unwrap();
    assert!(result.success(), "Should work without proc virtualization");
}

/// Test that /proc/net/tcp is filtered with port_remap — only shows sandbox's own ports.
#[tokio::test]
async fn test_proc_net_tcp_filtered() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procnet-{}",
        std::process::id()
    ));

    // Pick a free port to avoid conflicts with parallel tests.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .net_bind_port(port)
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "s.bind(('127.0.0.1', {port}))\n",
        "s.listen(1)\n",
        "with open('/proc/net/tcp') as f:\n",
        "  lines = f.readlines()\n",
        "s.close()\n",
        "ports = []\n",
        "for line in lines[1:]:\n",
        "  parts = line.split()\n",
        "  if len(parts) >= 2:\n",
        "    port_hex = parts[1].split(':')[1]\n",
        "    ports.append(int(port_hex, 16))\n",
        "open('{out}', 'w').write(str(len(ports)))\n",
    ), port = port, out = out.display());

    let result = Sandbox::run_interactive(&policy, Some("test"), &["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let count: usize = content.parse().unwrap_or(999);
    assert!(count <= 2, "/proc/net/tcp should be filtered, got {} entries", count);

    let _ = std::fs::remove_file(&out);
}

/// Test that /proc/mounts is virtualized and only shows sandbox mounts.
#[tokio::test]
async fn test_proc_mounts_virtualized() {
    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, Some("test"), &["cat", "/proc/mounts"]).await.unwrap();
    assert!(result.success(), "cat /proc/mounts should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // Should contain the root entry (no chroot → rootfs)
    assert!(stdout.contains("rootfs / rootfs rw 0 0"), "Should show root mount, got: {}", stdout);
    // Should NOT leak host mounts (e.g. /home, /boot, real device paths)
    assert!(!stdout.contains("/home"), "Should not leak host /home mount");
    assert!(!stdout.contains("nvme"), "Should not leak host disk device names");
}

/// Test that /proc/self/mountinfo is virtualized.
#[tokio::test]
async fn test_proc_self_mountinfo_virtualized() {
    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, Some("test"), &["cat", "/proc/self/mountinfo"]).await.unwrap();
    assert!(result.success(), "cat /proc/self/mountinfo should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // Should contain root entry in mountinfo format
    assert!(stdout.contains("/ / rw - rootfs rootfs rw"), "Should show root in mountinfo, got: {}", stdout);
    assert!(!stdout.contains("/home"), "Should not leak host /home mount in mountinfo");
}

/// Test that /proc/{ppid}/ is blocked (non-sandbox PID isolation).
#[tokio::test]
async fn test_proc_parent_pid_blocked() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procparent-{}",
        std::process::id()
    ));

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let script = format!(concat!(
        "import os\n",
        "ppid = os.getppid()\n",
        "results = []\n",
        "for entry in ['cmdline', 'status']:\n",
        "  try:\n",
        "    open(f'/proc/{{ppid}}/{{entry}}').read()\n",
        "    results.append('LEAKED')\n",
        "  except PermissionError:\n",
        "    results.append('BLOCKED')\n",
        "  except Exception as e:\n",
        "    results.append(f'ERR:{{e}}')\n",
        "# Verify /proc/self still works\n",
        "try:\n",
        "  open('/proc/self/status').read()\n",
        "  results.append('SELF_OK')\n",
        "except Exception:\n",
        "  results.append('SELF_FAIL')\n",
        "open('{out}', 'w').write(','.join(results))\n",
    ), out = out.display());

    let result = Sandbox::run_interactive(&policy, Some("test"), &["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "script should exit 0");
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let parts: Vec<&str> = content.split(',').collect();
    assert_eq!(parts.get(0), Some(&"BLOCKED"), "/proc/ppid/cmdline should be blocked, got: {}", content);
    assert_eq!(parts.get(1), Some(&"BLOCKED"), "/proc/ppid/status should be blocked, got: {}", content);
    assert_eq!(parts.get(2), Some(&"SELF_OK"), "/proc/self/status should still work, got: {}", content);
}

/// Test that /proc/net/tcp hides host ports when sandbox has no bindings.
#[tokio::test]
async fn test_proc_net_tcp_hides_host_ports() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procnet-hide-{}",
        std::process::id()
    ));

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(concat!(
        "with open('/proc/net/tcp') as f:\n",
        "  lines = f.readlines()\n",
        "ports = []\n",
        "for line in lines[1:]:\n",
        "  parts = line.split()\n",
        "  if len(parts) >= 2:\n",
        "    port_hex = parts[1].split(':')[1]\n",
        "    ports.append(int(port_hex, 16))\n",
        "open('{out}', 'w').write(str(len(ports)))\n",
    ), out = out.display());

    let result = Sandbox::run_interactive(&policy, Some("test"), &["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let count: usize = content.parse().unwrap_or(999);
    assert_eq!(count, 0, "/proc/net/tcp should show 0 entries when sandbox has no bindings");

    let _ = std::fs::remove_file(&out);
}
