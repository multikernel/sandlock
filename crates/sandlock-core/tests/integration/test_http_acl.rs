use sandlock_core::Sandbox;
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

fn base_policy() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
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
            content_length = line
                .split(':')
                .nth(1)
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
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200, got: {}",
        content
    );

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
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("HTTP:403"),
        "expected HTTP:403, got: {}",
        content
    );

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
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_allowed).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 for /public, got: {}",
        content
    );

    // GET /secret — should be denied
    let script = http_script(&format!("http://127.0.0.1:{}/secret", port), &out_denied);
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_denied).unwrap_or_default();
    assert!(
        content.starts_with("HTTP:403"),
        "expected HTTP:403 for /secret, got: {}",
        content
    );

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

    let policy = base_policy()
        .net_allow(format!(":{}", port))
        .build()
        .unwrap();

    let script = http_script(&format!("http://127.0.0.1:{}/get", port), &out);
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 (unrestricted), got: {}",
        content
    );

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
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 for GET, got: {}",
        content
    );

    // POST should be denied
    let script = post_script(&format!("http://127.0.0.1:{}/anything", port), &out_post);
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_post).unwrap_or_default();
    assert!(
        content.starts_with("HTTP:403"),
        "expected HTTP:403 for POST, got: {}",
        content
    );

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
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 for /get, got: {}",
        content
    );

    // GET /anything — should be denied (not in allow list)
    let script = http_script(&format!("http://127.0.0.1:{}/anything", port), &out_other);
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_other).unwrap_or_default();
    assert!(
        content.starts_with("HTTP:403"),
        "expected HTTP:403 for /anything, got: {}",
        content
    );

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
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 for /get, got: {}",
        content
    );

    // GET /admin/settings — should be denied
    let script = http_script(
        &format!("http://127.0.0.1:{}/admin/settings", port),
        &out_denied,
    );
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_denied).unwrap_or_default();
    assert!(
        content.starts_with("HTTP:403"),
        "expected HTTP:403 for /admin/settings, got: {}",
        content
    );

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out_get);
    let _ = std::fs::remove_file(&out_denied);
}

/// Non-intercepted port traffic should NOT go through the proxy.
/// The port must be in `net_connect` (per AND semantics — see Network
/// Model in README); the proxy still leaves it alone because it is not
/// in `http_ports`.
#[tokio::test]
async fn test_http_non_intercepted_port() {
    let out = temp_file("non-intercept");

    // Bind the listener in the test process so we know the port up
    // front and can plumb it through `--net-allow`.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let _ = std::io::Write::write_all(&mut conn, b"HELLO");
        }
    });

    let policy = base_policy()
        .http_allow("GET example.com/get")
        .net_allow(format!(":{}", port))
        .build()
        .unwrap();

    let script = format!(
        concat!(
            "import socket\n",
            "try:\n",
            "    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
            "    c.settimeout(2)\n",
            "    c.connect(('127.0.0.1', {port}))\n",
            "    data = c.recv(10)\n",
            "    c.close()\n",
            "    open('{out}', 'w').write('OK:' + data.decode())\n",
            "except Exception as e:\n",
            "    open('{out}', 'w').write('ERR:' + str(e))\n",
        ),
        out = out.display(),
        port = port,
    );

    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    srv.join().unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:HELLO"),
        "expected OK:HELLO, got: {}",
        content
    );

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
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 for IPv6 allow, got: {}",
        content
    );

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
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("HTTP:403"),
        "expected HTTP:403 for IPv6 deny, got: {}",
        content
    );

    let _ = std::fs::remove_file(&out);
}

/// IPv6 non-intercepted port should pass through without proxy interference.
/// (Same AND-semantics requirement as the IPv4 sibling test.)
#[tokio::test]
async fn test_http_ipv6_non_intercepted_port() {
    let out = temp_file("ipv6-non-intercept");

    let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let _ = std::io::Write::write_all(&mut conn, b"HELLO6");
        }
    });

    let policy = base_policy()
        .http_allow("GET example.com/get")
        .net_allow(format!(":{}", port))
        .build()
        .unwrap();

    let script = format!(
        concat!(
            "import socket\n",
            "try:\n",
            "    c = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n",
            "    c.settimeout(2)\n",
            "    c.connect(('::1', {port}))\n",
            "    data = c.recv(10)\n",
            "    c.close()\n",
            "    open('{out}', 'w').write('OK:' + data.decode())\n",
            "except Exception as e:\n",
            "    open('{out}', 'w').write('ERR:' + str(e))\n",
        ),
        out = out.display(),
        port = port,
    );

    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    srv.join().unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:HELLO6"),
        "expected OK:HELLO6, got: {}",
        content
    );

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
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 for IPv6 GET, got: {}",
        content
    );

    // POST should be denied
    let script = post_script(&format!("http://[::1]:{}/anything", port), &out_post);
    let result = policy
        .clone()
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success());
    let content = std::fs::read_to_string(&out_post).unwrap_or_default();
    assert!(
        content.starts_with("HTTP:403"),
        "expected HTTP:403 for IPv6 POST, got: {}",
        content
    );

    srv.join().unwrap();
    let _ = std::fs::remove_file(&out_get);
    let _ = std::fs::remove_file(&out_post);
}

/// Spawn a server that records the `Authorization` header of the one request it
/// receives, for credential-injection tests.
fn spawn_capturing_http_server() -> (
    u16,
    thread::JoinHandle<()>,
    std::sync::Arc<std::sync::Mutex<Option<String>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cap = captured.clone();
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if line.to_lowercase().starts_with("authorization:") {
                    *cap.lock().unwrap() = Some(line.split_once(':').unwrap().1.trim().to_string());
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
            }
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    (port, handle, captured)
}

/// A credential declared in the supervisor is injected into the outbound request
/// inside the proxy — the child never carries it in env/argv/headers — and
/// reaches the upstream, after the ACL check.
#[tokio::test]
async fn test_credential_injected_into_upstream() {
    let out = temp_file("cred-inject");
    let secret_file = temp_file("cred-secret");
    std::fs::write(&secret_file, "sk-phase1-secret\n").unwrap();
    let (port, srv, captured) = spawn_capturing_http_server();

    let mut policy = base_policy()
        .http_allow("GET 127.0.0.1/*")
        .http_port(port)
        .credential("api", &format!("file:{}", secret_file.display()))
        .http_auth("GET 127.0.0.1/* bearer api")
        .build()
        .unwrap();

    let script = http_script(&format!("http://127.0.0.1:{}/data", port), &out);
    let result = policy
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "child request should succeed, got: {}",
        content
    );

    srv.join().unwrap();
    let got = captured.lock().unwrap().clone();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&secret_file);

    // The child sent no Authorization header; the proxy injected the credential
    // by value while the child only ever knew its name.
    assert_eq!(
        got.as_deref(),
        Some("Bearer sk-phase1-secret"),
        "upstream must receive the injected credential (got {got:?})"
    );
}

/// Deny-path invariant: a request that matches an inject rule but is denied by
/// the ACL must be blocked (403) and the credential must never be rendered — the
/// upstream sees no connection at all. Proves injection sits strictly after the
/// ACL check.
#[tokio::test]
async fn test_denied_request_does_not_inject_credential() {
    let out = temp_file("cred-deny");
    let secret_file = temp_file("cred-deny-secret");
    std::fs::write(&secret_file, "sk-must-not-leak\n").unwrap();
    let (port, _srv, captured) = spawn_capturing_http_server();

    // ACL allows only /allowed; the inject rule matches every path. A GET to
    // /secret is denied by the ACL, so injection must not run.
    let mut policy = base_policy()
        .http_allow("GET 127.0.0.1/allowed")
        .http_port(port)
        .credential("api", &format!("file:{}", secret_file.display()))
        .http_auth("GET 127.0.0.1/* bearer api")
        .build()
        .unwrap();

    let script = http_script(&format!("http://127.0.0.1:{}/secret", port), &out);
    let result = policy
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    // Give the (never-reached) upstream a moment; it must not have been contacted.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let got = captured.lock().unwrap().clone();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&secret_file);

    assert!(
        content.starts_with("HTTP:403"),
        "denied request should be 403, got: {}",
        content
    );
    assert_eq!(
        got, None,
        "credential must not reach the upstream on a denied request"
    );
}

/// An `env:`-sourced credential must be scrubbed from the child's environment,
/// otherwise the agent could read the real secret straight out of its own env
/// instead of relying on proxy-side injection. The child does no network here —
/// it just reports whether it can still see the variable.
#[tokio::test]
async fn test_env_sourced_credential_stripped_from_child() {
    std::env::set_var("SANDLOCK_TEST_SECRET_ENV", "sk-env-secret");
    let out = temp_file("cred-envstrip");
    let (port, _srv) = spawn_http_server(0); // just to obtain a valid intercept port
    let mut policy = base_policy()
        .http_allow("GET 127.0.0.1/*")
        .http_port(port)
        .credential("api", "env:SANDLOCK_TEST_SECRET_ENV")
        .http_auth("GET 127.0.0.1/* bearer api")
        .build()
        .unwrap();

    let script = format!(
        "import os; open('{}', 'w').write(os.environ.get('SANDLOCK_TEST_SECRET_ENV', 'ABSENT'))",
        out.display()
    );
    let result = policy
        .run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    std::env::remove_var("SANDLOCK_TEST_SECRET_ENV");
    assert_eq!(
        content, "ABSENT",
        "env-sourced credential must be stripped from the child's environment, got {content:?}"
    );
}

// NOTE (RFC #66 follow-up): injection over the HTTPS/MITM path is not covered
// here — this suite has no TLS upstream or ephemeral-CA harness. The rendering
// code is scheme-agnostic (service.rs runs the same `apply` after the ACL on the
// "https" path), and the plaintext tests above exercise it; a TLS end-to-end
// test needs a CA-trust harness and is tracked as a separate follow-up.
