use sandlock_core::{Policy, Sandbox};
use std::net::TcpListener;
use std::path::PathBuf;

fn temp_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sandlock-test-net-{}-{}", name, std::process::id()))
}

fn base_policy() -> sandlock_core::PolicyBuilder {
    Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
}

/// Test that --net-allow blocks connections to non-allowed hosts.
#[tokio::test]
async fn test_net_allow_blocks_disallowed_host() {
    let out = temp_file("block");

    let policy = base_policy()
        .net_allow("127.0.0.1:80")  // only localhost:80
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

/// Test that --net-allow permits connections to the listed (host, port).
#[tokio::test]
async fn test_net_allow_permits_listed_endpoint() {
    let out = temp_file("allow");

    let test_port: u16 = 19753;
    let policy = base_policy()
        .net_allow(format!("127.0.0.1:{}", test_port))
        .net_bind_port(test_port)
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

/// `--net-allow :port` (any IP, specific port) permits the kernel-level
/// connect — Landlock allows the port and the on-behalf path's any-IP
/// match accepts. Connecting to a port without a listener still returns
/// ECONNREFUSED from the kernel (not EACCES from sandlock).
#[tokio::test]
async fn test_net_allow_any_ip_port() {
    let out = temp_file("any-ip");

    let policy = base_policy().net_allow(":1").build().unwrap();

    let script = format!(concat!(
        "import socket\n",
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
    assert_eq!(content, "REFUSED", "connect to permitted port should reach kernel; got: {}", content);

    let _ = std::fs::remove_file(&out);
}

/// `--net-allow host:portA` rejects connections to (host, portB) — the
/// (ip, port) pair must match an endpoint rule. A real server bound on
/// the blocked port distinguishes sandbox-rejection (ECONNREFUSED from
/// sandlock) from kernel-refused (also ECONNREFUSED) — it ensures the
/// connect would have succeeded if sandlock allowed it.
#[tokio::test]
async fn test_net_allow_endpoint_rejects_other_ports() {
    let out = temp_file("port-blocked");

    let blocked_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let blocked_port = blocked_listener.local_addr().unwrap().port();
    let blocked_listener = std::sync::Arc::new(blocked_listener);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = stop.clone();
    let l_clone = blocked_listener.clone();
    let acceptor = std::thread::spawn(move || {
        l_clone.set_nonblocking(true).unwrap();
        while !stop_clone.load(std::sync::atomic::Ordering::SeqCst) {
            match l_clone.accept() {
                Ok((mut conn, _)) => { let _ = std::io::Write::write_all(&mut conn, b"hi"); }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    });

    let allowed_port: u16 = if blocked_port == u16::MAX { 1024 } else { blocked_port + 1 };

    let policy = base_policy()
        .net_allow(format!("127.0.0.1:{}", allowed_port))
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.settimeout(2)\n",
        "try:\n",
        "  s.connect(('127.0.0.1', {port}))\n",
        "  open('{out}', 'w').write('CONNECTED')\n",
        "except ConnectionRefusedError:\n",
        "  open('{out}', 'w').write('REFUSED')\n",
        "except (OSError, socket.timeout) as e:\n",
        "  open('{out}', 'w').write('OTHER:' + e.__class__.__name__)\n",
        "finally:\n",
        "  s.close()\n",
    ), out = out.display(), port = blocked_port);

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script]).await.unwrap();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = acceptor.join();

    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(
        content, "REFUSED",
        "port {} not in net_allow must be rejected even when listener is bound (got: {})",
        blocked_port, content
    );

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
        .net_allow(format!("127.0.0.1:{}", port))
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
