use sandlock_core::{Sandbox};
use std::path::PathBuf;

/// Helper to find a free port.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn temp_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sandlock-test-remap-{}-{}", name, std::process::id()))
}

fn base_policy() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
}

/// Test that a sandboxed process can bind on an allowed port with port remapping.
#[tokio::test]
async fn test_port_remap_bind() {
    let port = free_port();
    let out = temp_file("bind");

    let policy = base_policy()
        .net_bind_port(port)
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(
        "import socket\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         s.bind(('127.0.0.1', {port}))\n\
         s.listen(1)\n\
         s.close()\n\
         open('{out}', 'w').write('OK')\n",
        out = out.display()
    );

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(content, "OK");
    let _ = std::fs::remove_file(&out);
}

/// Test loopback: bind + connect + echo within one sandbox.
#[tokio::test]
async fn test_port_remap_loopback() {
    let port = free_port();
    let out = temp_file("loopback");

    let policy = base_policy()
        .net_bind_port(port)
        .net_allow(format!("127.0.0.1:{}", port))
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(
        concat!(
            "import socket, threading, time\n",
            "PORT = {port}\n",
            "def server():\n",
            "  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
            "  s.bind(('127.0.0.1', PORT))\n",
            "  s.listen(1)\n",
            "  conn, _ = s.accept()\n",
            "  data = conn.recv(64)\n",
            "  conn.sendall(data)\n",
            "  conn.close()\n",
            "  s.close()\n",
            "t = threading.Thread(target=server, daemon=True)\n",
            "t.start()\n",
            "time.sleep(0.1)\n",
            "c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "c.connect(('127.0.0.1', PORT))\n",
            "c.sendall(b'ECHO')\n",
            "resp = c.recv(64)\n",
            "c.close()\n",
            "t.join(timeout=2)\n",
            "open('{out}', 'w').write('PASS' if resp == b'ECHO' else 'FAIL')\n",
        ),
        port = port,
        out = out.display()
    );

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(content, "PASS");
    let _ = std::fs::remove_file(&out);
}

/// Test that getsockname returns the bound port.
#[tokio::test]
async fn test_port_remap_getsockname() {
    let port = free_port();
    let out = temp_file("getsockname");

    let policy = base_policy()
        .net_bind_port(port)
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(
        "import socket\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         s.bind(('127.0.0.1', {port}))\n\
         addr = s.getsockname()\n\
         s.close()\n\
         open('{out}', 'w').write(str(addr[1]))\n",
        out = out.display()
    );

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(content, port.to_string(), "getsockname should return bound port");
    let _ = std::fs::remove_file(&out);
}

/// Test port remapping under conflict (port already occupied on host).
#[tokio::test]
async fn test_port_remap_conflict() {
    // Occupy a port on the host
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_port = listener.local_addr().unwrap().port();
    let out = temp_file("conflict");

    let policy = base_policy()
        .net_bind_port(occupied_port)
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(
        concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
            "try:\n",
            "  s.bind(('127.0.0.1', {occupied_port}))\n",
            "  addr = s.getsockname()\n",
            "  open('{out}', 'w').write(f'BOUND:{{addr[1]}}')\n",
            "except OSError as e:\n",
            "  open('{out}', 'w').write(f'ERROR:{{e}}')\n",
            "finally:\n",
            "  s.close()\n",
        ),
        occupied_port = occupied_port,
        out = out.display()
    );

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    // Remap must be transparent: child asked for occupied_port and must
    // see it back from getsockname, even though the kernel-side bind
    // landed on a different real port.
    assert_eq!(
        content,
        format!("BOUND:{}", occupied_port),
        "getsockname must return the virtual port the child asked for"
    );

    // Keep listener alive so the port stays occupied during the test
    drop(listener);
    let _ = std::fs::remove_file(&out);
}

/// Test loopback under forced remap: the host pre-binds the port so the
/// supervisor must allocate a different real port, then the sandbox does
/// bind/listen/connect against the *virtual* port. Exercises both halves
/// of the port-remap transparency: handle_getsockname returning the
/// virtual port and connect_on_behalf translating it back to the real
/// port for the loopback dial.
#[tokio::test]
async fn test_port_remap_loopback_under_conflict() {
    // Occupy a port on the host to force the supervisor to remap.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_port = listener.local_addr().unwrap().port();
    let out = temp_file("loopback-conflict");

    let policy = base_policy()
        .net_bind_port(occupied_port)
        .net_allow(format!("127.0.0.1:{}", occupied_port))
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(
        concat!(
            "import socket, threading, time\n",
            "PORT = {port}\n",
            "errs = []\n",
            "def server():\n",
            "  try:\n",
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
            "    s.bind(('127.0.0.1', PORT))\n",
            "    # getsockname must return the virtual port (PORT),\n",
            "    # not the real port the supervisor allocated.\n",
            "    bound = s.getsockname()[1]\n",
            "    if bound != PORT:\n",
            "      errs.append(f'getsockname={{bound}} want={{PORT}}')\n",
            "    s.listen(1)\n",
            "    conn, _ = s.accept()\n",
            "    data = conn.recv(64)\n",
            "    conn.sendall(data)\n",
            "    conn.close()\n",
            "    s.close()\n",
            "  except Exception as e:\n",
            "    errs.append(f'server:{{e}}')\n",
            "t = threading.Thread(target=server, daemon=True)\n",
            "t.start()\n",
            "time.sleep(0.2)\n",
            "try:\n",
            "  c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "  c.connect(('127.0.0.1', PORT))\n",
            "  c.sendall(b'ECHO')\n",
            "  resp = c.recv(64)\n",
            "  c.close()\n",
            "except Exception as e:\n",
            "  resp = b''\n",
            "  errs.append(f'client:{{e}}')\n",
            "t.join(timeout=3)\n",
            "if errs:\n",
            "  open('{out}', 'w').write('FAIL:' + ';'.join(errs))\n",
            "else:\n",
            "  open('{out}', 'w').write('PASS' if resp == b'ECHO' else 'FAIL:resp')\n",
        ),
        port = occupied_port,
        out = out.display()
    );

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(content, "PASS", "loopback under conflict failed: {}", content);

    drop(listener);
    let _ = std::fs::remove_file(&out);
}
