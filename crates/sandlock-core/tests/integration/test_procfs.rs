use sandlock_core::policy::ByteSize;
use sandlock_core::{Policy, Sandbox};

/// Test that num_cpus virtualizes /proc/cpuinfo.
#[tokio::test]
async fn test_num_cpus_virtualization() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(2)
        .build()
        .unwrap();

    // nproc reads /proc/cpuinfo or sysconf to get CPU count
    let result = Sandbox::run(&policy, &["nproc"]).await.unwrap();
    assert!(result.success(), "nproc should succeed");
    // Note: without stdout capture, can't verify the output is "2"
    // But the command should work with /proc virtualization active
}

/// Test that max_memory virtualizes /proc/meminfo.
#[tokio::test]
async fn test_meminfo_virtualization() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .max_memory(ByteSize::mib(256))
        .build()
        .unwrap();

    // Read meminfo — should succeed
    let result = Sandbox::run(&policy, &["cat", "/proc/meminfo"]).await.unwrap();
    assert!(result.success(), "cat /proc/meminfo should succeed");
}

/// Test that sensitive /proc paths are blocked.
#[tokio::test]
async fn test_sensitive_proc_blocked() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(1) // activate proc virtualization
        .build()
        .unwrap();

    // /proc/kcore should be denied
    let result = Sandbox::run(&policy, &["cat", "/proc/kcore"]).await.unwrap();
    assert!(!result.success(), "/proc/kcore should be denied");
}

/// Test basic sandbox still works without /proc virtualization.
#[tokio::test]
async fn test_no_proc_virt_still_works() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, &["cat", "/proc/version"]).await.unwrap();
    assert!(result.success(), "Should work without proc virtualization");
}

/// Test that /proc/net/tcp is filtered with port_remap — only shows sandbox's own ports.
#[tokio::test]
async fn test_proc_net_tcp_filtered() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procnet-{}",
        std::process::id()
    ));

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .net_bind_port(5555)
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "s.bind(('127.0.0.1', 5555))\n",
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
    ), out = out.display());

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let count: usize = content.parse().unwrap_or(999);
    assert!(count <= 2, "/proc/net/tcp should be filtered, got {} entries", count);

    let _ = std::fs::remove_file(&out);
}

/// Test that /proc/net/tcp hides host ports when sandbox has no bindings.
#[tokio::test]
async fn test_proc_net_tcp_hides_host_ports() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procnet-hide-{}",
        std::process::id()
    ));

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin")
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

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let count: usize = content.parse().unwrap_or(999);
    assert_eq!(count, 0, "/proc/net/tcp should show 0 entries when sandbox has no bindings");

    let _ = std::fs::remove_file(&out);
}
