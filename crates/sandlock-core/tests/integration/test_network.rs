use sandlock_core::{Sandbox};
use std::net::TcpListener;
use std::path::PathBuf;

fn temp_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sandlock-test-net-{}-{}", name, std::process::id()))
}

fn base_policy() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
}

// ============================================================
// Phase 2: per-protocol destination scoping
// ============================================================

/// `udp://127.0.0.1:53` rule scopes UDP sends to 127.0.0.1:53. A
/// `sendto(1.1.1.1, 53)` on the same UDP socket must be denied because
/// the rule's host filters destinations, not just protocol creation.
#[tokio::test]
async fn test_udp_rule_scopes_destination_by_host() {
    let out_allowed = temp_file("udp-allowed");
    let out_blocked = temp_file("udp-blocked");

    let policy = base_policy()
        .net_allow("udp://127.0.0.1:53")
        .build()
        .unwrap();

    // Two sendto calls on the same socket: one to the allowed host, one
    // to a different host on the same port. The on-behalf handler must
    // accept the first and deny the second with ECONNREFUSED (errno 111).
    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "try:\n",
        "  s.sendto(b'x', ('127.0.0.1', 53))\n",
        "  open('{ok}', 'w').write('ALLOWED')\n",
        "except OSError as e:\n",
        "  open('{ok}', 'w').write(f'ERR:{{e.errno}}')\n",
        "try:\n",
        "  s.sendto(b'x', ('1.1.1.1', 53))\n",
        "  open('{deny}', 'w').write('ALLOWED')\n",
        "except OSError as e:\n",
        "  open('{deny}', 'w').write(f'ERR:{{e.errno}}')\n",
        "s.close()\n",
    ), ok = out_allowed.display(), deny = out_blocked.display());

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let allowed = std::fs::read_to_string(&out_allowed).unwrap_or_default();
    let blocked = std::fs::read_to_string(&out_blocked).unwrap_or_default();
    let _ = std::fs::remove_file(&out_allowed);
    let _ = std::fs::remove_file(&out_blocked);

    assert_eq!(allowed, "ALLOWED", "sendto to allowed host should succeed");
    assert_eq!(blocked, "ERR:111", "sendto to disallowed host should ECONNREFUSED");
}

/// `udp://*:*` is the "any UDP destination" gate — it should not regress
/// after Phase 2's per-protocol routing. Both sendtos succeed.
#[tokio::test]
async fn test_udp_wildcard_allows_any_destination() {
    let out_a = temp_file("udp-wild-a");
    let out_b = temp_file("udp-wild-b");

    let policy = base_policy().net_allow("udp://*:*").build().unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "try:\n",
        "  s.sendto(b'x', ('127.0.0.1', 53))\n",
        "  open('{a}', 'w').write('ALLOWED')\n",
        "except OSError as e:\n",
        "  open('{a}', 'w').write(f'ERR:{{e.errno}}')\n",
        "try:\n",
        "  s.sendto(b'x', ('1.1.1.1', 53))\n",
        "  open('{b}', 'w').write('ALLOWED')\n",
        "except OSError as e:\n",
        "  open('{b}', 'w').write(f'ERR:{{e.errno}}')\n",
        "s.close()\n",
    ), a = out_a.display(), b = out_b.display());

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let a = std::fs::read_to_string(&out_a).unwrap_or_default();
    let b = std::fs::read_to_string(&out_b).unwrap_or_default();
    let _ = std::fs::remove_file(&out_a);
    let _ = std::fs::remove_file(&out_b);

    assert_eq!(a, "ALLOWED");
    assert_eq!(b, "ALLOWED");
}

/// A UDP rule must not authorize TCP destinations. Phase 1 closed off
/// UDP socket creation under a TCP-only policy; Phase 2 must also stop
/// UDP rules from leaking into the TCP destination check. Here we have
/// a UDP-only rule for 1.1.1.1:53 and try a TCP connect to that
/// (host, port) — which should still be denied because the TCP policy
/// has no rules.
#[tokio::test]
async fn test_udp_rule_does_not_authorize_tcp() {
    let out = temp_file("udp-no-leak-tcp");

    let policy = base_policy().net_allow("udp://1.1.1.1:53").build().unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.settimeout(2)\n",
        "try:\n",
        "  s.connect(('1.1.1.1', 53))\n",
        "  open('{out}', 'w').write('ALLOWED')\n",
        "except (OSError, socket.timeout) as e:\n",
        "  errno = getattr(e, 'errno', 0)\n",
        "  open('{out}', 'w').write(f'BLOCKED:{{errno}}')\n",
        "s.close()\n",
    ), out = out.display());

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert!(
        content.starts_with("BLOCKED:"),
        "TCP connect must not piggyback on a UDP rule, got: {}", content
    );
}

/// `sendmmsg` is the most common UDP escape hatch — agents that want to
/// bypass per-message destination filtering can batch sends with it.
/// This test calls `libc.sendmmsg` directly via ctypes (Python's
/// `socket` module doesn't expose it) with two messages: the first to
/// an allowed host, the second to a disallowed one. The on-behalf
/// handler must let the first through and stop at the second, returning
/// 1 to match the kernel's "messages successfully transmitted" semantics
/// on partial failure.
#[tokio::test]
async fn test_sendmmsg_partial_failure_on_blocked_destination() {
    let out = temp_file("sendmmsg-partial");

    let policy = base_policy()
        .net_allow("udp://127.0.0.1:53")
        .build()
        .unwrap();

    let script = format!(concat!(
        "import ctypes, socket, struct\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "libc.sendmmsg.restype = ctypes.c_int\n",
        "\n",
        "class iovec(ctypes.Structure):\n",
        "    _fields_ = [('iov_base', ctypes.c_void_p), ('iov_len', ctypes.c_size_t)]\n",
        "\n",
        "class msghdr(ctypes.Structure):\n",
        "    _fields_ = [\n",
        "        ('msg_name', ctypes.c_void_p),\n",
        "        ('msg_namelen', ctypes.c_uint),\n",
        "        ('_p1', ctypes.c_uint),\n",
        "        ('msg_iov', ctypes.c_void_p),\n",
        "        ('msg_iovlen', ctypes.c_size_t),\n",
        "        ('msg_control', ctypes.c_void_p),\n",
        "        ('msg_controllen', ctypes.c_size_t),\n",
        "        ('msg_flags', ctypes.c_int),\n",
        "        ('_p2', ctypes.c_uint),\n",
        "    ]\n",
        "\n",
        "class mmsghdr(ctypes.Structure):\n",
        "    _fields_ = [('msg_hdr', msghdr), ('msg_len', ctypes.c_uint), ('_p', ctypes.c_uint)]\n",
        "\n",
        "def sai(ip, port):\n",
        "    return struct.pack('=HH4s8x', socket.AF_INET, socket.htons(port), socket.inet_aton(ip))\n",
        "\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "\n",
        "addr_ok = ctypes.create_string_buffer(sai('127.0.0.1', 53))\n",
        "addr_blk = ctypes.create_string_buffer(sai('1.1.1.1', 53))\n",
        "data = ctypes.create_string_buffer(b'x')\n",
        "\n",
        "iovs = (iovec * 2)()\n",
        "iovs[0].iov_base = ctypes.cast(data, ctypes.c_void_p).value\n",
        "iovs[0].iov_len = 1\n",
        "iovs[1].iov_base = ctypes.cast(data, ctypes.c_void_p).value\n",
        "iovs[1].iov_len = 1\n",
        "\n",
        "vec = (mmsghdr * 2)()\n",
        "vec[0].msg_hdr.msg_name = ctypes.cast(addr_ok, ctypes.c_void_p).value\n",
        "vec[0].msg_hdr.msg_namelen = 16\n",
        "vec[0].msg_hdr.msg_iov = ctypes.cast(ctypes.pointer(iovs[0]), ctypes.c_void_p).value\n",
        "vec[0].msg_hdr.msg_iovlen = 1\n",
        "vec[1].msg_hdr.msg_name = ctypes.cast(addr_blk, ctypes.c_void_p).value\n",
        "vec[1].msg_hdr.msg_namelen = 16\n",
        "vec[1].msg_hdr.msg_iov = ctypes.cast(ctypes.pointer(iovs[1]), ctypes.c_void_p).value\n",
        "vec[1].msg_hdr.msg_iovlen = 1\n",
        "\n",
        "ret = libc.sendmmsg(s.fileno(), vec, 2, 0)\n",
        "errno = ctypes.get_errno()\n",
        "msg0_len = vec[0].msg_len\n",
        "open('{out}', 'w').write(f'ret={{ret}} errno={{errno}} msg0_len={{msg0_len}}')\n",
        "s.close()\n",
    ), out = out.display());

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);

    // ret=1 — first message sent, second blocked. msg0_len=1 — one byte
    // delivered for the first message. errno is whatever the kernel left
    // it as (sendmmsg sets errno only on full failure ret<0).
    assert!(
        content.starts_with("ret=1 ") && content.contains("msg0_len=1"),
        "expected partial success ret=1 msg0_len=1, got: {}", content
    );
}

/// Defense-in-depth check that `sendmmsg` doesn't silently bypass the
/// per-protocol routing. With a UDP-only rule, a TCP socket using
/// `sendmsg`/`sendto` already fails (Phase 2 covered that). We verify
/// the same property holds when the agent uses `sendmmsg` to a UDP
/// destination outside the allowlist with vlen=1: ret should be -1
/// because no entries succeeded.
#[tokio::test]
async fn test_sendmmsg_single_blocked_returns_econnrefused() {
    let out = temp_file("sendmmsg-blocked");

    let policy = base_policy()
        .net_allow("udp://127.0.0.1:53")
        .build()
        .unwrap();

    let script = format!(concat!(
        "import ctypes, socket, struct\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "libc.sendmmsg.restype = ctypes.c_int\n",
        "\n",
        "class iovec(ctypes.Structure):\n",
        "    _fields_ = [('iov_base', ctypes.c_void_p), ('iov_len', ctypes.c_size_t)]\n",
        "\n",
        "class msghdr(ctypes.Structure):\n",
        "    _fields_ = [\n",
        "        ('msg_name', ctypes.c_void_p), ('msg_namelen', ctypes.c_uint), ('_p1', ctypes.c_uint),\n",
        "        ('msg_iov', ctypes.c_void_p), ('msg_iovlen', ctypes.c_size_t),\n",
        "        ('msg_control', ctypes.c_void_p), ('msg_controllen', ctypes.c_size_t),\n",
        "        ('msg_flags', ctypes.c_int), ('_p2', ctypes.c_uint),\n",
        "    ]\n",
        "\n",
        "class mmsghdr(ctypes.Structure):\n",
        "    _fields_ = [('msg_hdr', msghdr), ('msg_len', ctypes.c_uint), ('_p', ctypes.c_uint)]\n",
        "\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "addr = ctypes.create_string_buffer(\n",
        "    struct.pack('=HH4s8x', socket.AF_INET, socket.htons(53), socket.inet_aton('1.1.1.1'))\n",
        ")\n",
        "data = ctypes.create_string_buffer(b'x')\n",
        "iov = iovec()\n",
        "iov.iov_base = ctypes.cast(data, ctypes.c_void_p).value\n",
        "iov.iov_len = 1\n",
        "vec = (mmsghdr * 1)()\n",
        "vec[0].msg_hdr.msg_name = ctypes.cast(addr, ctypes.c_void_p).value\n",
        "vec[0].msg_hdr.msg_namelen = 16\n",
        "vec[0].msg_hdr.msg_iov = ctypes.cast(ctypes.pointer(iov), ctypes.c_void_p).value\n",
        "vec[0].msg_hdr.msg_iovlen = 1\n",
        "ret = libc.sendmmsg(s.fileno(), vec, 1, 0)\n",
        "errno = ctypes.get_errno()\n",
        "open('{out}', 'w').write(f'ret={{ret}} errno={{errno}}')\n",
        "s.close()\n",
    ), out = out.display());

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);

    assert_eq!(
        content, "ret=-1 errno=111",
        "blocked sendmmsg should return -1 with ECONNREFUSED, got: {}", content
    );
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

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
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
        .net_allow_bind_port(test_port)
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

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
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

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
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

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
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

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(content, "hello", "grandchild should connect and read data");

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out);
}

/// `--net-allow :*` opens egress to every host and port. Verifies
/// that both the Landlock side (CONNECT_TCP unhandled) and the
/// on-behalf side (NetworkPolicy::Unrestricted) cooperate to allow a
/// connection to a port that no concrete rule mentions. Issue #32.
#[tokio::test]
async fn test_net_allow_wildcard_any_host_any_port() {
    let out = temp_file("wildcard-any");

    // Stand up a server on a port nothing else mentions.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let _ = std::io::Write::write_all(&mut conn, b"ok");
    });

    let policy = base_policy().net_allow(":*").build().unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.settimeout(5)\n",
        "s.connect(('127.0.0.1', {port}))\n",
        "data = s.recv(16)\n",
        "s.close()\n",
        "open('{out}', 'w').write(data.decode())\n",
    ), out = out.display(), port = port);

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(content, "ok", "wildcard :* should permit arbitrary egress");

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out);
}

/// `--net-allow host:*` permits every port to the host but still
/// blocks other hosts. Verifies the Landlock-unhandled + on-behalf
/// per_ip_all_ports path keeps the IP allowlist intact.
#[tokio::test]
async fn test_net_allow_wildcard_host_only() {
    let out = temp_file("wildcard-host");

    // Server on localhost; a non-localhost connect must still be blocked.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let _ = std::io::Write::write_all(&mut conn, b"ok");
    });

    let policy = base_policy().net_allow("localhost:*").build().unwrap();

    let script = format!(concat!(
        "import socket\n",
        "results = []\n",
        // localhost any port — should connect
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.settimeout(5)\n",
        "try:\n",
        "  s.connect(('127.0.0.1', {port}))\n",
        "  results.append('local:ok')\n",
        "  s.close()\n",
        "except OSError as e:\n",
        "  results.append(f'local:err{{e.errno}}')\n",
        // non-localhost — should be blocked
        "s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s2.settimeout(2)\n",
        "try:\n",
        "  s2.connect(('1.1.1.1', 80))\n",
        "  results.append('remote:ALLOWED')\n",
        "  s2.close()\n",
        "except (OSError, socket.timeout):\n",
        "  results.append('remote:blocked')\n",
        "open('{out}', 'w').write(','.join(results))\n",
    ), out = out.display(), port = port);

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(content.contains("local:ok"), "localhost should connect; got: {}", content);
    assert!(content.contains("remote:blocked"),
        "remote host must remain blocked under host:* wildcard; got: {}", content);

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out);
}

/// `--net-deny-bind` is default-allow: a denied TCP port fails to bind with
/// EACCES, other TCP ports bind fine, and UDP on the denied port is
/// unaffected (the deny is TCP-only, mirroring --net-allow-bind).
#[tokio::test]
async fn test_net_deny_bind_blocks_tcp_only() {
    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }
    let denied = free_port();
    let mut allowed = free_port();
    while allowed == denied {
        allowed = free_port();
    }
    let out = temp_file("denybind");

    // A `udp://*` egress rule lets the child create UDP sockets, so the
    // TCP-only nature of the bind denylist can be observed below. (net_allow
    // is egress-only and orthogonal to the bind denylist.)
    let policy = base_policy()
        .net_allow("udp://*")
        .net_deny_bind_port(denied)
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket, json\n",
        "res = {{}}\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "try:\n",
        "  s.bind(('127.0.0.1', {denied}))\n",
        "  res['tcp_denied'] = 'bound'\n",
        "except PermissionError:\n",
        "  res['tcp_denied'] = 'eacces'\n",
        "s.close()\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "try:\n",
        "  s.bind(('127.0.0.1', {allowed}))\n",
        "  res['tcp_allowed'] = 'ok'\n",
        "except OSError as e:\n",
        "  res['tcp_allowed'] = 'err:%d' % e.errno\n",
        "s.close()\n",
        "u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "try:\n",
        "  u.bind(('127.0.0.1', {denied}))\n",
        "  res['udp_denied'] = 'ok'\n",
        "except OSError as e:\n",
        "  res['udp_denied'] = 'err:%d' % e.errno\n",
        "u.close()\n",
        "open('{out}', 'w').write(json.dumps(res))\n",
    ), denied = denied, allowed = allowed, out = out.display());

    let result = policy.clone().with_name("test")
        .run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert!(content.contains("\"tcp_denied\": \"eacces\""), "denied TCP bind must fail with EACCES; got: {content}");
    assert!(content.contains("\"tcp_allowed\": \"ok\""), "non-denied TCP bind must succeed; got: {content}");
    assert!(content.contains("\"udp_denied\": \"ok\""), "UDP on the denied port must be allowed (TCP-only); got: {content}");
}
