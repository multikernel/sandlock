use sandlock_core::{Policy, Sandbox};
use std::net::TcpListener;
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

    // Use a fixed port so we can add it to net_connect.
    let test_port: u16 = 19753;
    let policy = base_policy()
        .net_allow_host("127.0.0.1")
        .net_bind_port(test_port)
        .net_connect_port(test_port)
        .port_remap(true)
        .build()
        .unwrap();

    // Create a local TCP server and connect to it — should be allowed
    let script = format!(concat!(
        "import socket, threading\n",
        "srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "srv.bind(('127.0.0.1', {port}))\n",
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
    ), out = out.display(), port = test_port);

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(content, "CONNECTED");

    let _ = std::fs::remove_file(&out);
}

/// Test that without net_allow_host, connections are unrestricted
/// (provided the port is in net_connect).
#[tokio::test]
async fn test_no_net_allow_host_unrestricted() {
    let out = temp_file("unrestricted");

    // No net_allow_host — connections allowed on permitted ports
    let policy = base_policy().net_connect_port(1).build().unwrap();

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

/// Test that a grandchild process (forked from the sandboxed child) can
/// perform network operations. Before the fix in f9eeda3, the supervisor
/// used a stored pidfd for the original child, so pidfd_getfd failed when
/// the socket belonged to a grandchild's fd table.
#[tokio::test]
async fn test_grandchild_network_connect() {
    let out = temp_file("grandchild");

    // Spawn a local TCP server outside the sandbox for the grandchild to connect to.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let _ = std::io::Write::write_all(&mut conn, b"hello");
    });

    let policy = base_policy()
        .net_allow_host("127.0.0.1")
        .net_connect_port(port)
        .build()
        .unwrap();

    // The sandboxed process spawns a subprocess (grandchild) that does the
    // actual TCP connect. This exercises dup_fd_from_pid(notif.pid, ...).
    let script = format!(concat!(
        "import subprocess, sys\n",
        "child = subprocess.run([sys.executable, '-c', ",
        "\"import socket\\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\\n",
        "s.settimeout(5)\\n",
        "s.connect(('127.0.0.1', {port}))\\n",
        "data = s.recv(16)\\n",
        "s.close()\\n",
        "open('{out}', 'w').write(data.decode())\\n",
        "\"])\n",
        "sys.exit(child.returncode)\n",
    ), out = out.display(), port = port);

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(content, "hello", "grandchild should connect and read data");

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out);
}
