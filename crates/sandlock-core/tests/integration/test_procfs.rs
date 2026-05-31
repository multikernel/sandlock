use sandlock_core::sandbox::ByteSize;
use sandlock_core::{Sandbox};

/// Test that num_cpus virtualizes both /proc/cpuinfo and sched_getaffinity.
#[tokio::test]
async fn test_num_cpus_virtualization() {
    let policy = Sandbox::builder()
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
    let result = policy.clone().with_name("test").run(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"]).await.unwrap();
    assert!(result.success(), "grep /proc/cpuinfo should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "2", "/proc/cpuinfo should show 2 processors, got: {:?}", stdout.trim());

    // Verify nproc (sched_getaffinity) also reports 2.
    let result = policy.clone().with_name("test").run(&["nproc"]).await.unwrap();
    assert!(result.success(), "nproc should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "2", "nproc should report 2 CPUs, got: {:?}", stdout.trim());
}

/// Test that max_memory virtualizes /proc/meminfo.
#[tokio::test]
async fn test_meminfo_virtualization() {
    let policy = Sandbox::builder()
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
    let result = policy.clone().with_name("test").run(&["cat", "/proc/meminfo"]).await.unwrap();
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
    let policy = Sandbox::builder()
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
    let result = policy.clone().with_name("test").run(&["cat", "/proc/kcore"]).await.unwrap();
    assert!(!result.success(), "/proc/kcore should be denied");
}

/// The sensitive-path deny used to do a literal `path == "/proc/kcore"`
/// (and `starts_with("/proc/kcore/")`) match, which any non-canonical or
/// dirfd-relative spelling sidestepped. Exercise each known bypass shape
/// and assert the deny still fires.
#[tokio::test]
async fn test_sensitive_proc_resists_bypasses() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(1)
        .build()
        .unwrap();

    // EACCES (errno 13) is what the handler returns for sensitive paths.
    // Each branch prints OK if the open was denied, FAIL otherwise.
    let script = concat!(
        "import os, errno\n",
        "results = []\n",
        "def must_deny(label, fn):\n",
        "  try:\n",
        "    fd = fn()\n",
        "    os.close(fd)\n",
        "    results.append(f'{label}:LEAKED')\n",
        "  except OSError as e:\n",
        "    results.append(f'{label}:DENIED' if e.errno == errno.EACCES else f'{label}:errno={e.errno}')\n",
        // 1. dirfd-relative: open(/proc), then open 'kcore' relative to it
        "procfd = os.open('/proc', os.O_DIRECTORY | os.O_RDONLY)\n",
        "must_deny('dirfd', lambda: os.open('kcore', os.O_RDONLY, dir_fd=procfd))\n",
        "os.close(procfd)\n",
        // 2. non-canonical absolutes
        "must_deny('dotdot', lambda: os.open('/proc/../proc/kcore', os.O_RDONLY))\n",
        "must_deny('curdir', lambda: os.open('/proc/./kcore', os.O_RDONLY))\n",
        "must_deny('slash2', lambda: os.open('//proc/kcore', os.O_RDONLY))\n",
        "print('|'.join(results))\n",
    );

    let result = policy.clone().with_name("test").run(&["python3", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    for label in ["dirfd", "dotdot", "curdir", "slash2"] {
        let needle = format!("{label}:DENIED");
        assert!(
            stdout.contains(&needle),
            "{label}: /proc/kcore leaked via this spelling. stdout: {stdout}"
        );
    }
}

/// The /proc/cpuinfo virtualization used to do a literal
/// `path == "/proc/cpuinfo"` match, so non-canonical and dirfd-relative
/// spellings fell through to the host's real cpuinfo and leaked the host's
/// real CPU count.
#[tokio::test]
async fn test_proc_virt_resists_bypasses() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(2)
        .build()
        .unwrap();

    // Every spelling must see exactly 2 `^processor` lines, matching the
    // synthetic cpuinfo. A leak to the host file would show this host's
    // real CPU count (almost certainly != 2).
    let script = concat!(
        "import os\n",
        "results = {}\n",
        "procfd = os.open('/proc', os.O_DIRECTORY | os.O_RDONLY)\n",
        "fd = os.open('cpuinfo', os.O_RDONLY, dir_fd=procfd)\n",
        "results['dirfd']  = os.read(fd, 4096).decode().count('processor\\t')\n",
        "os.close(fd); os.close(procfd)\n",
        "results['dotdot'] = open('/proc/../proc/cpuinfo').read().count('processor\\t')\n",
        "results['curdir'] = open('/proc/./cpuinfo').read().count('processor\\t')\n",
        "results['slash2'] = open('//proc/cpuinfo').read().count('processor\\t')\n",
        "print(results)\n",
    );

    let result = policy.clone().with_name("test").run(&["python3", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    for label in ["dirfd", "dotdot", "curdir", "slash2"] {
        let needle = format!("'{label}': 2");
        assert!(
            stdout.contains(&needle),
            "{label}: host cpuinfo leaked (expected 2 processors, virtualized). stdout: {stdout}"
        );
    }
}

/// Test basic sandbox still works without /proc virtualization.
#[tokio::test]
async fn test_no_proc_virt_still_works() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run(&["cat", "/proc/version"]).await.unwrap();
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

    let policy = Sandbox::builder()
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

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let count: usize = content.parse().unwrap_or(999);
    assert!(count <= 2, "/proc/net/tcp should be filtered, got {} entries", count);

    let _ = std::fs::remove_file(&out);
}

/// Test that /proc/mounts is virtualized and only shows sandbox mounts.
#[tokio::test]
async fn test_proc_mounts_virtualized() {
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run(&["cat", "/proc/mounts"]).await.unwrap();
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
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run(&["cat", "/proc/self/mountinfo"]).await.unwrap();
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

    let policy = Sandbox::builder()
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

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
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

    let policy = Sandbox::builder()
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

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let count: usize = content.parse().unwrap_or(999);
    assert_eq!(count, 0, "/proc/net/tcp should show 0 entries when sandbox has no bindings");

    let _ = std::fs::remove_file(&out);
}
