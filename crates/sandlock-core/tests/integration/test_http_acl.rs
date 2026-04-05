use sandlock_core::{Policy, Sandbox};
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;

fn temp_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sandlock-test-http-{}-{}",
        name,
        std::process::id()
    ))
}

fn base_policy() -> sandlock_core::PolicyBuilder {
    Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/tmp")
        .fs_write("/tmp")
}

/// Spawn a minimal HTTP server on 127.0.0.1:0 that accepts `n` requests.
/// Returns (port, join_handle). The server responds 200 with body "ok" to
/// every request regardless of method/path — ACL enforcement happens in
/// the proxy, not the origin server.
fn spawn_http_server(n: usize) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        for _ in 0..n {
            if let Ok(mut stream) = listener.accept().map(|(s, _)| s) {
                handle_http_conn(&mut stream);
            }
        }
    });
    (port, handle)
}

/// Spawn a minimal HTTP server on [::1]:0 (IPv6 loopback).
fn spawn_http_server_v6(n: usize) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        for _ in 0..n {
            if let Ok(mut stream) = listener.accept().map(|(s, _)| s) {
                handle_http_conn(&mut stream);
            }
        }
    });
    (port, handle)
}

/// Read one HTTP request and write a 200 OK response.
fn handle_http_conn(stream: &mut TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    // Read request line + headers until blank line.
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if line.to_lowercase().starts_with("content-length:") {
            content_length = line.split(':').nth(1)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    // Drain request body if any.
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        let _ = reader.read_exact(&mut body);
    }
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn http_script(url: &str, out: &std::path::Path) -> String {
    format!(
        concat!(
            "import urllib.request, urllib.error\n",
            "try:\n",
            "    resp = urllib.request.urlopen('{url}')\n",
            "    open('{out}', 'w').write('OK:' + str(resp.status))\n",
            "except urllib.error.HTTPError as e:\n",
            "    open('{out}', 'w').write('HTTP:' + str(e.code))\n",
            "except Exception as e:\n",
            "    open('{out}', 'w').write('ERR:' + str(e))\n",
        ),
        url = url,
        out = out.display(),
    )
}

fn post_script(url: &str, out: &std::path::Path) -> String {
    format!(
        concat!(
            "import urllib.request, urllib.error\n",
            "try:\n",
            "    req = urllib.request.Request('{url}', method='POST', data=b'test')\n",
            "    resp = urllib.request.urlopen(req)\n",
            "    open('{out}', 'w').write('OK:' + str(resp.status))\n",
            "except urllib.error.HTTPError as e:\n",
            "    open('{out}', 'w').write('HTTP:' + str(e.code))\n",
            "except Exception as e:\n",
            "    open('{out}', 'w').write('ERR:' + str(e))\n",
        ),
        url = url,
        out = out.display(),
    )
}

// ============================================================
// Tests using local HTTP server — no external network required
// ============================================================

/// Allowed GET request passes through the ACL proxy to local server.
#[tokio::test]
async fn test_http_allow_get() {
    let out = temp_file("allow-get");
    let (port, srv) = spawn_http_server(1);

    let policy = base_policy()
        .http_allow(&format!("GET 127.0.0.1/*"))
        .http_port(port)
        .build()
        .unwrap();

    let script = http_script(&format!("http://127.0.0.1:{}/get", port), &out);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(content.starts_with("OK:200"), "expected OK:200, got: {}", content);

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out);
}

/// GET to a non-matching path should be blocked (403) by the proxy.
#[tokio::test]
async fn test_http_deny_non_matching() {
    let out = temp_file("deny-nonmatch");
    // Server won't receive a connection (blocked by proxy), so don't wait.
    let (port, _srv) = spawn_http_server(1);

    let policy = base_policy()
        .http_allow(&format!("GET 127.0.0.1/allowed"))
        .http_port(port)
        .build()
        .unwrap();

    let script = http_script(&format!("http://127.0.0.1:{}/denied", port), &out);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(content.starts_with("HTTP:403"), "expected HTTP:403, got: {}", content);

    let _ = std::fs::remove_file(&out);
}

/// Deny rules take precedence over allow rules.
#[tokio::test]
async fn test_http_deny_precedence() {
    let out_allowed = temp_file("deny-prec-allowed");
    let out_denied = temp_file("deny-prec-denied");
    let (port, srv) = spawn_http_server(1); // only 1 request gets through

    let policy = base_policy()
        .http_allow(&format!("* 127.0.0.1/*"))
        .http_deny(&format!("* 127.0.0.1/secret"))
        .http_port(port)
        .build()
        .unwrap();

    // GET /public — should succeed
    let script = http_script(&format!("http://127.0.0.1:{}/public", port), &out_allowed);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_allowed).unwrap_or_default();
    assert!(content.starts_with("OK:200"), "expected OK:200 for /public, got: {}", content);

    // GET /secret — should be denied
    let script = http_script(&format!("http://127.0.0.1:{}/secret", port), &out_denied);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_denied).unwrap_or_default();
    assert!(content.starts_with("HTTP:403"), "expected HTTP:403 for /secret, got: {}", content);

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out_allowed);
    let _ = std::fs::remove_file(&out_denied);
}

/// Without any HTTP ACL rules, traffic passes through normally
/// (provided the port is in net_connect).
#[tokio::test]
async fn test_http_no_acl_unrestricted() {
    let out = temp_file("no-acl");
    let (port, srv) = spawn_http_server(1);

    let policy = base_policy().net_connect_port(port).build().unwrap();

    let script = http_script(&format!("http://127.0.0.1:{}/get", port), &out);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(content.starts_with("OK:200"), "expected OK:200 (unrestricted), got: {}", content);

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out);
}

/// Allow GET but not POST to the same endpoint — verifies method-level ACL.
#[tokio::test]
async fn test_http_method_filtering() {
    let out_get = temp_file("method-get");
    let out_post = temp_file("method-post");
    let (port, srv) = spawn_http_server(1); // only GET goes through

    let policy = base_policy()
        .http_allow(&format!("GET 127.0.0.1/anything"))
        .http_port(port)
        .build()
        .unwrap();

    // GET should succeed
    let script = http_script(&format!("http://127.0.0.1:{}/anything", port), &out_get);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(content.starts_with("OK:200"), "expected OK:200 for GET, got: {}", content);

    // POST should be denied
    let script = post_script(&format!("http://127.0.0.1:{}/anything", port), &out_post);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_post).unwrap_or_default();
    assert!(content.starts_with("HTTP:403"), "expected HTTP:403 for POST, got: {}", content);

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out_get);
    let _ = std::fs::remove_file(&out_post);
}

/// Multiple allow rules — only matching ones pass.
#[tokio::test]
async fn test_http_multiple_allow_rules() {
    let out_get = temp_file("multi-get");
    let out_other = temp_file("multi-other");
    let (port, srv) = spawn_http_server(1);

    let policy = base_policy()
        .http_allow(&format!("GET 127.0.0.1/get"))
        .http_allow(&format!("POST 127.0.0.1/post"))
        .http_port(port)
        .build()
        .unwrap();

    // GET /get — should succeed (matches first rule)
    let script = http_script(&format!("http://127.0.0.1:{}/get", port), &out_get);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(content.starts_with("OK:200"), "expected OK:200 for /get, got: {}", content);

    // GET /anything — should be denied (not in allow list)
    let script = http_script(&format!("http://127.0.0.1:{}/anything", port), &out_other);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_other).unwrap_or_default();
    assert!(content.starts_with("HTTP:403"), "expected HTTP:403 for /anything, got: {}", content);

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out_get);
    let _ = std::fs::remove_file(&out_other);
}

/// Wildcard host allow with a specific deny — deny takes precedence.
#[tokio::test]
async fn test_http_wildcard_host() {
    let out_get = temp_file("wildcard-get");
    let out_denied = temp_file("wildcard-denied");
    let (port, srv) = spawn_http_server(1);

    let policy = base_policy()
        .http_allow(&format!("* 127.0.0.1/*"))
        .http_deny("* */admin/*")
        .http_port(port)
        .build()
        .unwrap();

    // GET /get — should succeed
    let script = http_script(&format!("http://127.0.0.1:{}/get", port), &out_get);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(content.starts_with("OK:200"), "expected OK:200 for /get, got: {}", content);

    // GET /admin/settings — should be denied
    let script = http_script(&format!("http://127.0.0.1:{}/admin/settings", port), &out_denied);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_denied).unwrap_or_default();
    assert!(content.starts_with("HTTP:403"), "expected HTTP:403 for /admin/settings, got: {}", content);

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out_get);
    let _ = std::fs::remove_file(&out_denied);
}

/// Non-intercepted port traffic should NOT go through the proxy.
#[tokio::test]
async fn test_http_non_intercepted_port() {
    let out = temp_file("non-intercept");

    // ACL intercepts port 80 by default, not random ports
    let policy = base_policy()
        .http_allow("GET example.com/get")
        .build()
        .unwrap();

    let script = format!(
        concat!(
            "import socket, threading\n",
            "try:\n",
            "    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "    srv.bind(('127.0.0.1', 0))\n",
            "    port = srv.getsockname()[1]\n",
            "    srv.listen(1)\n",
            "    def accept_one():\n",
            "        conn, _ = srv.accept()\n",
            "        conn.send(b'HELLO')\n",
            "        conn.close()\n",
            "    t = threading.Thread(target=accept_one, daemon=True)\n",
            "    t.start()\n",
            "    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "    c.settimeout(2)\n",
            "    c.connect(('127.0.0.1', port))\n",
            "    data = c.recv(10)\n",
            "    c.close()\n",
            "    srv.close()\n",
            "    open('{out}', 'w').write('OK:' + data.decode())\n",
            "except Exception as e:\n",
            "    open('{out}', 'w').write('ERR:' + str(e))\n",
        ),
        out = out.display(),
    );

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(content.starts_with("OK:HELLO"), "expected OK:HELLO, got: {}", content);

    let _ = std::fs::remove_file(&out);
}

// ============================================================
// IPv6 tests
// ============================================================

/// IPv6 loopback: allowed GET via [::1] passes through the ACL proxy.
#[tokio::test]
async fn test_http_acl_ipv6_allow() {
    let out = temp_file("ipv6-allow");
    let (port, srv) = spawn_http_server_v6(1);

    let policy = base_policy()
        .http_allow("GET */*")
        .http_port(port)
        .build()
        .unwrap();

    let script = http_script(&format!("http://[::1]:{}/get", port), &out);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(content.starts_with("OK:200"), "expected OK:200 for IPv6 allow, got: {}", content);

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out);
}

/// IPv6 loopback: non-matching path denied by ACL proxy.
#[tokio::test]
async fn test_http_acl_ipv6_deny() {
    let out = temp_file("ipv6-deny");
    let (port, _srv) = spawn_http_server_v6(1);

    let policy = base_policy()
        .http_allow("GET */allowed")
        .http_port(port)
        .build()
        .unwrap();

    let script = http_script(&format!("http://[::1]:{}/denied", port), &out);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(content.starts_with("HTTP:403"), "expected HTTP:403 for IPv6 deny, got: {}", content);

    let _ = std::fs::remove_file(&out);
}

/// IPv6 non-intercepted port should pass through without proxy interference.
#[tokio::test]
async fn test_http_ipv6_non_intercepted_port() {
    let out = temp_file("ipv6-non-intercept");

    let policy = base_policy()
        .http_allow("GET example.com/get")
        .build()
        .unwrap();

    let script = format!(
        concat!(
            "import socket, threading\n",
            "try:\n",
            "    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n",
            "    srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)\n",
            "    srv.bind(('::1', 0))\n",
            "    port = srv.getsockname()[1]\n",
            "    srv.listen(1)\n",
            "    def accept_one():\n",
            "        conn, _ = srv.accept()\n",
            "        conn.send(b'HELLO6')\n",
            "        conn.close()\n",
            "    t = threading.Thread(target=accept_one, daemon=True)\n",
            "    t.start()\n",
            "    c = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n",
            "    c.settimeout(2)\n",
            "    c.connect(('::1', port))\n",
            "    data = c.recv(10)\n",
            "    c.close()\n",
            "    srv.close()\n",
            "    open('{out}', 'w').write('OK:' + data.decode())\n",
            "except Exception as e:\n",
            "    open('{out}', 'w').write('ERR:' + str(e))\n",
        ),
        out = out.display(),
    );

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(content.starts_with("OK:HELLO6"), "expected OK:HELLO6, got: {}", content);

    let _ = std::fs::remove_file(&out);
}

/// IPv6 method filtering: allow GET but deny POST via [::1].
#[tokio::test]
async fn test_http_acl_ipv6_method_filtering() {
    let out_get = temp_file("ipv6-method-get");
    let out_post = temp_file("ipv6-method-post");
    let (port, srv) = spawn_http_server_v6(1); // only GET goes through

    let policy = base_policy()
        .http_allow("GET */*")
        .http_port(port)
        .build()
        .unwrap();

    // GET should succeed
    let script = http_script(&format!("http://[::1]:{}/anything", port), &out_get);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(content.starts_with("OK:200"), "expected OK:200 for IPv6 GET, got: {}", content);

    // POST should be denied
    let script = post_script(&format!("http://[::1]:{}/anything", port), &out_post);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_post).unwrap_or_default();
    assert!(content.starts_with("HTTP:403"), "expected HTTP:403 for IPv6 POST, got: {}", content);

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out_get);
    let _ = std::fs::remove_file(&out_post);
}
