use sandlock_core::{Policy, Sandbox};
use std::path::PathBuf;

fn temp_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sandlock-test-net-{}-{}", name, std::process::id()))
}

fn base_policy() -> sandlock_core::PolicyBuilder {
    Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
}

/// Test that net_allow_host blocks connections to non-allowed hosts.
#[tokio::test]
async fn test_net_allow_host_blocks_disallowed() {
    let out = temp_file("block");

    let policy = base_policy()
        .net_allow_host("127.0.0.1")  // only localhost allowed
        .build()
        .unwrap();

    // Try to connect to 1.1.1.1:80 — should be blocked
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "  s.settimeout(2)\n",
        "  s.connect(('1.1.1.1', 80))\n",
        "  s.close()\n",
        "  open('{out}', 'w').write('ALLOWED')\n",
        "except (OSError, socket.timeout):\n",
        "  open('{out}', 'w').write('BLOCKED')\n",
    ), out = out.display());

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(content, "BLOCKED", "connection to 1.1.1.1 should be blocked");

    let _ = std::fs::remove_file(&out);
}

/// Test that net_allow_host permits connections to allowed hosts.
#[tokio::test]
async fn test_net_allow_host_permits_allowed() {
    let out = temp_file("allow");

    let policy = base_policy()
        .net_allow_host("127.0.0.1")
        .net_bind_port(0)
        .port_remap(true)
        .build()
        .unwrap();

    // Create a local TCP server and connect to it — should be allowed
    let script = format!(concat!(
        "import socket, threading\n",
        "srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "srv.bind(('127.0.0.1', 0))\n",
        "srv.listen(1)\n",
        "port = srv.getsockname()[1]\n",
        "def accept():\n",
        "  conn, _ = srv.accept()\n",
        "  conn.close()\n",
        "t = threading.Thread(target=accept, daemon=True)\n",
        "t.start()\n",
        "c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "c.connect(('127.0.0.1', port))\n",
        "c.close()\n",
        "t.join(timeout=2)\n",
        "srv.close()\n",
        "open('{out}', 'w').write('CONNECTED')\n",
    ), out = out.display());

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(content, "CONNECTED");

    let _ = std::fs::remove_file(&out);
}

/// Test that without net_allow_host, connections are unrestricted.
#[tokio::test]
async fn test_no_net_allow_host_unrestricted() {
    let out = temp_file("unrestricted");

    // No net_allow_host — all connections allowed
    let policy = base_policy().build().unwrap();

    // Connect to localhost on a port that doesn't exist — should get ECONNREFUSED (not EPERM)
    let script = format!(concat!(
        "import socket, errno\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.settimeout(1)\n",
        "try:\n",
        "  s.connect(('127.0.0.1', 1))\n",
        "  open('{out}', 'w').write('CONNECTED')\n",
        "except ConnectionRefusedError:\n",
        "  open('{out}', 'w').write('REFUSED')\n",
        "except PermissionError:\n",
        "  open('{out}', 'w').write('BLOCKED')\n",
        "finally:\n",
        "  s.close()\n",
    ), out = out.display());

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    // Without allowlist, should get REFUSED (not BLOCKED)
    assert_eq!(content, "REFUSED", "without net_allow_host, connect should not be blocked by seccomp");

    let _ = std::fs::remove_file(&out);
}
