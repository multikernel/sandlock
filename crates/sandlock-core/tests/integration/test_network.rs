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

/// Regression for the uncapped-sockaddr-length DoS: a child can pass
/// `addr_len = 0xFFFFFFFF` to `sendto`. The seccomp-notify trap fires before the
/// kernel's `addrlen > sizeof(sockaddr_storage) -> EINVAL` check, so without the
/// `read_sockaddr` guard the supervisor did `vec![0u8; 0xFFFFFFFF]` (~4 GiB) and
/// could OOM/abort, taking down every sandbox. The child sends with a bogus 4 GiB
/// `addr_len` via raw `libc.sendto`. The supervisor must (a) survive — the whole
/// run completes — and (b) reject the oversized length with `EINVAL` (22),
/// matching the kernel, rather than reading it (or silently truncating). The
/// destination gate never runs, so both the allowed and blocked host fail the
/// same way.
#[tokio::test]
async fn test_sendto_huge_addrlen_rejected_with_einval() {
    let out = temp_file("huge-addrlen");

    let policy = base_policy()
        .net_allow("udp://127.0.0.1:53")
        .build()
        .unwrap();

    let script = format!(concat!(
        "import ctypes, socket, struct, os\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "libc.sendto.restype = ctypes.c_ssize_t\n",
        "def sai(ip, port):\n",
        "    return struct.pack('<H', socket.AF_INET) + struct.pack('!H', port) + socket.inet_aton(ip) + b'\\x00'*8\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "buf = ctypes.create_string_buffer(b'x')\n",
        "def send(ip):\n",
        "    a = ctypes.create_string_buffer(sai(ip, 53))\n",
        // addrlen = 0xFFFFFFFF: without the clamp this forces a ~4 GiB supervisor alloc.
        "    ctypes.set_errno(0)\n",
        "    r = libc.sendto(s.fileno(), buf, 1, 0, a, 0xFFFFFFFF)\n",
        "    return 'OK' if r >= 0 else f'ERR:{{ctypes.get_errno()}}'\n",
        "allowed = send('127.0.0.1')\n",
        "blocked = send('1.1.1.1')\n",
        "open('{out}', 'w').write(allowed + '|' + blocked)\n",
        "s.close()\n",
    ), out = out.display());

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();
    // The run completing at all is the core assertion: an OOM-aborted supervisor
    // would kill the child instead of letting it finish.
    assert!(result.success(), "supervisor should survive a 4 GiB addr_len; exit={:?}", result.code());

    let got = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    // EINVAL (22) for both: the oversized addr_len is rejected before the
    // destination gate, so allowed vs blocked is never reached.
    assert_eq!(got, "ERR:22|ERR:22",
        "a bogus 4 GiB addr_len must be rejected with EINVAL, matching the kernel");
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

/// Functional check that a `sendmmsg` on a CONNECTED socket (each entry has
/// `msg_name == NULL`) is handled correctly while a destination policy is
/// active: the connected-send on-behalf path must forward both datagrams to
/// the allowed loopback listener rather than blocking or dropping them.
///
/// This does not attempt to reproduce the msg_name TOCTOU that motivated the
/// on-behalf path (that race is not deterministically reproducible); it only
/// asserts the path delivers correctly. Delivery is verified synchronously
/// after the run: the send completes before `run_interactive` returns, so both
/// datagrams are already buffered in the listener and can be drained without
/// any background thread or timing race.
#[tokio::test]
async fn test_connected_sendmmsg_delivers_on_behalf() {
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // Bounded timeout so a regression that drops datagrams fails the recv
    // below instead of hanging; on success the datagrams are already queued.
    listener
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    let out = temp_file("connected-sendmmsg");
    let policy = base_policy()
        .net_allow(&format!("udp://127.0.0.1:{}", port))
        .build()
        .unwrap();

    let script = format!(concat!(
        "import ctypes, socket\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "libc.sendmmsg.restype = ctypes.c_int\n",
        "class iovec(ctypes.Structure):\n",
        "    _fields_ = [('iov_base', ctypes.c_void_p), ('iov_len', ctypes.c_size_t)]\n",
        "class msghdr(ctypes.Structure):\n",
        "    _fields_ = [('msg_name', ctypes.c_void_p), ('msg_namelen', ctypes.c_uint),\n",
        "        ('_p1', ctypes.c_uint), ('msg_iov', ctypes.c_void_p),\n",
        "        ('msg_iovlen', ctypes.c_size_t), ('msg_control', ctypes.c_void_p),\n",
        "        ('msg_controllen', ctypes.c_size_t), ('msg_flags', ctypes.c_int), ('_p2', ctypes.c_uint)]\n",
        "class mmsghdr(ctypes.Structure):\n",
        "    _fields_ = [('msg_hdr', msghdr), ('msg_len', ctypes.c_uint), ('_p', ctypes.c_uint)]\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "s.connect(('127.0.0.1', {port}))\n",
        "data = ctypes.create_string_buffer(b'hi')\n",
        "iovs = (iovec * 2)()\n",
        "vec = (mmsghdr * 2)()\n",
        "for k in range(2):\n",
        "    iovs[k].iov_base = ctypes.cast(data, ctypes.c_void_p).value\n",
        "    iovs[k].iov_len = 2\n",
        "    vec[k].msg_hdr.msg_name = None\n",
        "    vec[k].msg_hdr.msg_namelen = 0\n",
        "    vec[k].msg_hdr.msg_iov = ctypes.cast(ctypes.pointer(iovs[k]), ctypes.c_void_p).value\n",
        "    vec[k].msg_hdr.msg_iovlen = 1\n",
        "ret = libc.sendmmsg(s.fileno(), vec, 2, 0)\n",
        "open('{out}', 'w').write('ret=%d' % ret)\n",
        "s.close()\n",
    ), port = port, out = out.display());

    let result = policy
        .clone()
        .with_name("test")
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        content, "ret=2",
        "connected sendmmsg must send both messages on-behalf, got: {content}"
    );

    // Drain the buffered datagrams synchronously: both were sent before the
    // child exited, so recv_from returns the queued packets without blocking.
    let mut buf = [0u8; 64];
    let mut delivered = 0;
    while delivered < 2 && listener.recv_from(&mut buf).is_ok() {
        delivered += 1;
    }
    assert_eq!(
        delivered, 2,
        "both datagrams must be delivered to the allowed listener"
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

/// `--net-allow-bind '*'` leaves Landlock's BIND_TCP hook unhandled: any
/// TCP port may be bound, including an ephemeral port-0 bind that a port
/// enumeration cannot express. The control run pins the default: with no
/// allow-bind list, a TCP bind is denied with EACCES.
#[tokio::test]
async fn test_net_allow_bind_wildcard_permits_any_bind() {
    let out = temp_file("bindall");

    let script = format!(concat!(
        "import socket, json\n",
        "res = {{}}\n",
        "for key, port in (('fixed', 18461), ('ephemeral', 0)):\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "  try:\n",
        "    s.bind(('127.0.0.1', port))\n",
        "    res[key] = 'ok'\n",
        "  except OSError as e:\n",
        "    res[key] = 'err:%d' % e.errno\n",
        "  s.close()\n",
        "open('{out}', 'w').write(json.dumps(res))\n",
    ), out = out.display());

    // Control: no allow-bind list means default-deny for TCP bind.
    let policy = base_policy().build().unwrap();
    let result = policy.clone().with_name("test")
        .run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.contains("\"fixed\": \"err:13\""),
        "default must deny TCP bind with EACCES; got: {content}"
    );

    // Wildcard: every bind succeeds.
    let policy = base_policy().net_allow_bind("*").build().unwrap();
    let result = policy.clone().with_name("test")
        .run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert!(
        content.contains("\"fixed\": \"ok\""),
        "wildcard must allow a fixed-port bind; got: {content}"
    );
    assert!(
        content.contains("\"ephemeral\": \"ok\""),
        "wildcard must allow an ephemeral port-0 bind; got: {content}"
    );
}

/// `--net-allow-bind '*'` must loosen bind only: connect enforcement stays
/// fully active. Exercised at runtime against a live loopback listener (so a
/// wrongly-permitted connect would SUCCEED, not merely ECONNREFUSED a dead
/// port), under both connect enforcers:
///
/// 1. Wildcard bind alone (empty `net_allow` = deny-all): Landlock's
///    `CONNECT_TCP` deny-all must survive `BIND_TCP` being dropped from the
///    handled set — connect fails with `EACCES` at the kernel.
/// 2. Wildcard bind plus a bounded `net_allow`: the destination policy is
///    enforced on-behalf, which refuses a disallowed endpoint with
///    `ECONNREFUSED`.
///
/// In both, a fixed-port bind succeeds alongside the failing connect.
#[tokio::test]
async fn test_net_allow_bind_wildcard_keeps_connect_enforcement() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let out = temp_file("bindall-connect");

    let script = format!(concat!(
        "import socket, json\n",
        "res = {{}}\n",
        "b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "try:\n",
        "  b.bind(('127.0.0.1', 18517))\n",
        "  res['bind'] = 'ok'\n",
        "except OSError as e:\n",
        "  res['bind'] = 'err:%d' % e.errno\n",
        "b.close()\n",
        "c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "c.settimeout(3)\n",
        "try:\n",
        "  c.connect(('127.0.0.1', {port}))\n",
        "  res['connect'] = 'ok'\n",
        "except OSError as e:\n",
        "  res['connect'] = 'err:%d' % e.errno\n",
        "c.close()\n",
        "open('{out}', 'w').write(json.dumps(res))\n",
    ), port = port, out = out.display());

    // 1. Wildcard bind, empty net_allow: Landlock CONNECT_TCP deny-all.
    let policy = base_policy().net_allow_bind("*").build().unwrap();
    let result = policy.with_name("test")
        .run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.contains("\"bind\": \"ok\""),
        "wildcard must allow the bind (deny-all connect case); got: {content}"
    );
    assert!(
        content.contains("\"connect\": \"err:13\""),
        "empty net_allow must still deny connect via Landlock (EACCES); got: {content}"
    );

    // 2. Wildcard bind + bounded net_allow that does not cover `port`: the
    //    on-behalf destination policy refuses the endpoint.
    let policy = base_policy()
        .net_allow_bind("*")
        .net_allow("127.0.0.1:80")
        .build()
        .unwrap();
    let result = policy.with_name("test")
        .run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    drop(listener);
    assert!(
        content.contains("\"bind\": \"ok\""),
        "wildcard must allow the bind (bounded net_allow case); got: {content}"
    );
    assert!(
        content.contains("\"connect\": \"err:111\""),
        "bounded net_allow must refuse a disallowed connect on-behalf (ECONNREFUSED); got: {content}"
    );
}

/// Regression (deny-all bypass via the unix-socket connect gate): an empty
/// `net_allow` must DENY outbound TCP even when filesystem grants are present.
///
/// Any fs grant turns on the named-`AF_UNIX` connect gate
/// (`has_unix_fs_gate`), which traps `connect()` for *all* address families.
/// A bug let the supervisor perform IP connects on-behalf in that case —
/// running them in the (unconfined) supervisor and bypassing the child's
/// Landlock `CONNECT_TCP` deny-all. With deny-all in force the child's
/// `connect()` must fail with `EACCES` (errno 13) at the kernel, never reach
/// the listener.
///
/// A live loopback listener is used so that IF the connect were wrongly
/// allowed it would *succeed* (ALLOWED) rather than merely `ECONNREFUSED` to a
/// dead port — making the assertion discriminate a true Landlock deny from an
/// on-behalf connect that happened to fail.
#[tokio::test]
async fn test_empty_net_allow_denies_tcp_despite_fs_grants() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let out = temp_file("empty-deny-tcp");

    // base_policy() grants fs reads -> has_unix_fs_gate is on. No `.net_allow`
    // call: an empty allowlist means "deny all outbound".
    let policy = base_policy().build().unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.settimeout(3)\n",
        "try:\n",
        "  s.connect(('127.0.0.1', {port}))\n",
        "  open('{out}', 'w').write('ALLOWED')\n",
        "except OSError as e:\n",
        "  open('{out}', 'w').write('ERR:%d' % e.errno)\n",
        "s.close()\n",
    ), port = port, out = out.display());

    let result = policy.with_name("test")
        .run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let got = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    drop(listener);

    assert_eq!(
        got, "ERR:13",
        "empty net_allow must deny TCP connect via Landlock (EACCES); got {got:?}"
    );
}

/// Regression: a `sendmsg()` on a *connected* `AF_UNIX` stream socket must pass
/// through when a `net_allow` destination policy is active. The IP destination
/// policy governs IP sockets only; a bug routed every connected send through
/// the IP on-behalf path, where `query_socket_protocol` returns `None` for a
/// unix socket and the send was refused with `ECONNREFUSED`. That broke every
/// connected-socket `sendmsg` user (Wayland, D-Bus — they use `sendmsg` for its
/// fd-passing capability) the moment any `--net-allow` rule was set, even
/// though the send targets no network destination. `send()`/`sendto` were
/// unaffected (they Continue connected sockets), so only `sendmsg` regressed.
///
/// A live `AF_UNIX` listener is used so the child's `connect()` succeeds and the
/// `sendmsg()` reaches a real peer: the send must return the byte count, not an
/// errno.
#[tokio::test]
async fn test_connected_unix_sendmsg_passes_through_under_net_policy() {
    use std::io::Read;
    use std::os::unix::net::UnixListener;

    let sock_path = temp_file("unix-sendmsg.sock");
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).unwrap();

    // Accept + drain in a background thread so the child's send has a peer.
    let accepter = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let mut buf = [0u8; 16];
            let _ = conn.read(&mut buf);
        }
    });

    let out = temp_file("unix-sendmsg-out");

    // `net_allow` activates `has_net_destination_policy`; `fs_write("/tmp")`
    // covers the socket path so `has_unix_fs_gate` is on too — the realistic
    // shape of the report (a `--net-allow` rule plus fs grants).
    let policy = base_policy().net_allow("127.0.0.1:80").build().unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
        "s.connect('{sock}')\n",
        "try:\n",
        "  n = s.sendmsg([b'hello'])\n",
        "  open('{out}', 'w').write('SENT:%d' % n)\n",
        "except OSError as e:\n",
        "  open('{out}', 'w').write('ERR:%d' % e.errno)\n",
        "s.close()\n",
    ), sock = sock_path.display(), out = out.display());

    let result = policy.with_name("test")
        .run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let got = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let _ = accepter.join();
    let _ = std::fs::remove_file(&sock_path);

    assert_eq!(
        got, "SENT:5",
        "connected AF_UNIX sendmsg under net_allow must pass through (got {got:?})"
    );
}

/// Regression: a `sendmsg()` that passes a file descriptor via `SCM_RIGHTS` on a
/// connected `AF_UNIX` socket must deliver a *working* fd when a `net_allow`
/// policy routes the send on-behalf. The on-behalf path copies the control
/// buffer, so without translation the child's fd numbers reach the supervisor's
/// `sendmsg` verbatim — passing the wrong file or failing `EBADF`. The fix
/// `pidfd_getfd`s each `SCM_RIGHTS` fd into the supervisor before the send.
///
/// The child opens a payload file and passes its fd; the receiver reads the
/// passed fd back and must see the payload's exact bytes — which only holds if
/// the fd was translated to the real open file, not an unrelated supervisor fd.
#[tokio::test]
async fn test_connected_unix_sendmsg_translates_scm_rights_under_net_policy() {
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

    let payload = temp_file("scm-payload");
    std::fs::write(&payload, b"SCMOK").unwrap();

    let sock_path = temp_file("scm-sendmsg.sock");
    let _ = std::fs::remove_file(&sock_path);
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

    // Accept, recvmsg the SCM_RIGHTS fd, read it, and report the bytes.
    let received = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let received_w = received.clone();
    let accepter = std::thread::spawn(move || {
        let (conn, _) = match listener.accept() { Ok(c) => c, Err(_) => return };
        let cfd = conn.as_raw_fd();
        let mut databuf = [0u8; 8];
        let mut cmsgbuf = [0u8; 64];
        let mut iov = libc::iovec {
            iov_base: databuf.as_mut_ptr() as *mut libc::c_void,
            iov_len: databuf.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsgbuf.len() as _;
        let n = unsafe { libc::recvmsg(cfd, &mut msg, 0) };
        if n < 0 { return; }
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null() { return; }
        let c = unsafe { &*cmsg };
        if c.cmsg_level == libc::SOL_SOCKET && c.cmsg_type == libc::SCM_RIGHTS {
            let data = unsafe { libc::CMSG_DATA(cmsg) } as *const RawFd;
            let passed = unsafe { std::ptr::read_unaligned(data) };
            let f = unsafe { std::fs::File::from_raw_fd(passed) };
            use std::io::Read;
            let mut s = String::new();
            let _ = (&f).take(16).read_to_string(&mut s);
            *received_w.lock().unwrap() = s;
        }
    });

    let out = temp_file("scm-out");
    // fs_read("/tmp") lets the child open the payload O_RDONLY; net_allow forces
    // the on-behalf path where the SCM_RIGHTS translation matters.
    let policy = base_policy().fs_read("/tmp").net_allow("127.0.0.1:80").build().unwrap();

    let script = format!(concat!(
        "import socket, array, os\n",
        "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
        "s.connect('{sock}')\n",
        "fd = os.open('{payload}', os.O_RDONLY)\n",
        "try:\n",
        "  n = s.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])\n",
        "  open('{out}', 'w').write('SENT:%d' % n)\n",
        "except OSError as e:\n",
        "  open('{out}', 'w').write('ERR:%d' % e.errno)\n",
        "s.close()\n",
    ), sock = sock_path.display(), payload = payload.display(), out = out.display());

    let result = policy.with_name("test")
        .run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let sent = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = accepter.join();
    let got_fd = received.lock().unwrap().clone();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&payload);

    assert_eq!(sent, "SENT:1", "SCM_RIGHTS sendmsg under net_allow must succeed (got {sent:?})");
    assert_eq!(
        got_fd, "SCMOK",
        "receiver must read the passed fd's file — SCM_RIGHTS translated to the real open file (got {got_fd:?})"
    );
}

/// A large blocking on-behalf send to a peer that stalls before draining must
/// fill the socket buffer, would-block, and *defer* off the notification loop —
/// then resume on writability and deliver every byte. This exercises the
/// `MSG_DONTWAIT` + `AsyncFd` deferred path; a regression would either truncate
/// the transfer, spuriously fail with `EAGAIN`, or (before the fix) block the
/// whole supervisor loop on the send.
#[tokio::test]
async fn test_large_blocking_send_defers_and_delivers_under_net_policy() {
    use std::io::Read;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const N: usize = 4 * 1024 * 1024; // well past any socket send buffer

    let sock_path = temp_file("defer-send.sock");
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).unwrap();

    // Accept, stall briefly (so the sender's buffer fills and the on-behalf send
    // must defer), then drain everything and count the bytes.
    let total = std::sync::Arc::new(AtomicUsize::new(0));
    let total_w = total.clone();
    let accepter = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let mut buf = [0u8; 65536];
            loop {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        total_w.fetch_add(n, Ordering::Relaxed);
                    }
                }
            }
        }
    });

    let out = temp_file("defer-send-out");
    let policy = base_policy().net_allow("127.0.0.1:80").build().unwrap();
    // A SINGLE blocking send() of N bytes must return N — the kernel's contract
    // for a blocking stream socket. A regression that returned on the first
    // partial (one SO_SNDBUF worth) would write a short count here.
    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
        "s.connect('{sock}')\n",
        "n = s.send(b'z' * {n})\n",   // one syscall; blocking → must return all N
        "s.close()\n",
        "open('{out}', 'w').write('SENT:%d' % n)\n",
    ), sock = sock_path.display(), n = N, out = out.display());

    let result = policy.with_name("test")
        .run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let sent = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = accepter.join();
    let got = total.load(Ordering::Relaxed);
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&sock_path);

    assert_eq!(
        sent, format!("SENT:{N}"),
        "one blocking send() must return the full {N} bytes (deferred to completion, not truncated)"
    );
    assert_eq!(got, N, "peer must receive all {N} bytes — no truncation on the deferred path");
}

/// `sendmmsg` of one large message on a blocking connected stream socket, to a
/// peer that stalls before draining: the entry can't complete on the first
/// non-blocking attempt, so it must be finished off the loop (not reported as a
/// spurious EAGAIN or a short `msg_len`). The child must see `ret == 1` with the
/// entry's `msg_len == N`, and the peer must receive all `N` bytes.
#[tokio::test]
async fn test_sendmmsg_blocking_entry_defers_and_delivers_under_net_policy() {
    use std::io::Read;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const N: usize = 4 * 1024 * 1024;

    let sock_path = temp_file("mmsg-defer.sock");
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).unwrap();

    let total = std::sync::Arc::new(AtomicUsize::new(0));
    let total_w = total.clone();
    let accepter = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let mut buf = [0u8; 65536];
            loop {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        total_w.fetch_add(n, Ordering::Relaxed);
                    }
                }
            }
        }
    });

    let out = temp_file("mmsg-defer-out");
    let policy = base_policy().net_allow("127.0.0.1:80").build().unwrap();
    let script = format!(concat!(
        "import ctypes, socket\n",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n",
        "libc.sendmmsg.restype = ctypes.c_int\n",
        "class iovec(ctypes.Structure):\n",
        "    _fields_ = [('iov_base', ctypes.c_void_p), ('iov_len', ctypes.c_size_t)]\n",
        "class msghdr(ctypes.Structure):\n",
        "    _fields_ = [('msg_name', ctypes.c_void_p), ('msg_namelen', ctypes.c_uint),\n",
        "        ('_p1', ctypes.c_uint), ('msg_iov', ctypes.c_void_p), ('msg_iovlen', ctypes.c_size_t),\n",
        "        ('msg_control', ctypes.c_void_p), ('msg_controllen', ctypes.c_size_t),\n",
        "        ('msg_flags', ctypes.c_int), ('_p2', ctypes.c_uint)]\n",
        "class mmsghdr(ctypes.Structure):\n",
        "    _fields_ = [('msg_hdr', msghdr), ('msg_len', ctypes.c_uint), ('_p', ctypes.c_uint)]\n",
        "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",   // blocking, connected
        "s.connect('{sock}')\n",
        "data = ctypes.create_string_buffer(b'z' * {n}, {n})\n",
        "iov = iovec(); iov.iov_base = ctypes.cast(data, ctypes.c_void_p).value; iov.iov_len = {n}\n",
        "vec = (mmsghdr * 1)()\n",
        "vec[0].msg_hdr.msg_iov = ctypes.cast(ctypes.pointer(iov), ctypes.c_void_p).value\n",
        "vec[0].msg_hdr.msg_iovlen = 1\n",   // msg_name NULL => connected
        "ret = libc.sendmmsg(s.fileno(), vec, 1, 0)\n",
        "open('{out}', 'w').write('ret=%d msg_len=%d' % (ret, vec[0].msg_len))\n",
        "s.close()\n",
    ), sock = sock_path.display(), n = N, out = out.display());

    let result = policy.with_name("test")
        .run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = accepter.join();
    let got = total.load(Ordering::Relaxed);
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&sock_path);

    assert_eq!(
        content, format!("ret=1 msg_len={N}"),
        "blocking sendmmsg entry must complete off-loop: ret=1 with full msg_len (got {content:?})"
    );
    assert_eq!(got, N, "peer must receive all {N} bytes of the deferred batch entry");
}
