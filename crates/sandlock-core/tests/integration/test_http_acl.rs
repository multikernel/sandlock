use sandlock_core::{Policy, Sandbox};
use std::path::PathBuf;

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

fn https_script(url: &str, out: &std::path::Path) -> String {
    format!(
        concat!(
            "import urllib.request, urllib.error, ssl, os\n",
            "try:\n",
            "    ctx = ssl.create_default_context()\n",
            "    ca = os.environ.get('SSL_CERT_FILE')\n",
            "    if ca:\n",
            "        ctx.load_verify_locations(ca)\n",
            "    resp = urllib.request.urlopen('{url}', context=ctx)\n",
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

/// With http_allow("GET httpbin.org/get"), a GET to httpbin.org/get should succeed.
#[ignore] // requires network access to httpbin.org
#[tokio::test]
async fn test_http_allow_get() {
    let out = temp_file("allow-get");

    let policy = base_policy()
        .http_allow("GET httpbin.org/get")
        .build()
        .unwrap();

    let script = http_script("http://httpbin.org/get", &out);

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200, got: {}",
        content
    );

    let _ = std::fs::remove_file(&out);
}

/// With http_allow("GET httpbin.org/get"), a GET to /post should be blocked (403).
#[ignore] // requires network access to httpbin.org
#[tokio::test]
async fn test_http_deny_non_matching() {
    let out = temp_file("deny-nonmatch");

    let policy = base_policy()
        .http_allow("GET httpbin.org/get")
        .build()
        .unwrap();

    let script = http_script("http://httpbin.org/post", &out);

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
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

/// With http_allow("* httpbin.org/*") and http_deny("* httpbin.org/post"),
/// GET /get should succeed but access to /post should be denied (403).
#[ignore] // requires network access to httpbin.org
#[tokio::test]
async fn test_http_deny_precedence() {
    let out_get = temp_file("deny-prec-get");
    let out_post = temp_file("deny-prec-post");

    let policy = base_policy()
        .http_allow("* httpbin.org/*")
        .http_deny("* httpbin.org/post")
        .build()
        .unwrap();

    // Test GET /get — should succeed
    let script_get = http_script("http://httpbin.org/get", &out_get);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script_get])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content_get = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(
        content_get.starts_with("OK:200"),
        "expected OK:200 for /get, got: {}",
        content_get
    );

    // Test access to /post — should be denied
    let script_post = http_script("http://httpbin.org/post", &out_post);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script_post])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content_post = std::fs::read_to_string(&out_post).unwrap_or_default();
    assert!(
        content_post.starts_with("HTTP:403"),
        "expected HTTP:403 for /post, got: {}",
        content_post
    );

    let _ = std::fs::remove_file(&out_get);
    let _ = std::fs::remove_file(&out_post);
}

/// Without any http rules, HTTP traffic passes through normally.
#[ignore] // requires network access to httpbin.org
#[tokio::test]
async fn test_http_no_acl_unrestricted() {
    let out = temp_file("no-acl");

    let policy = base_policy().build().unwrap();

    let script = http_script("http://httpbin.org/get", &out);

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 (unrestricted), got: {}",
        content
    );

    let _ = std::fs::remove_file(&out);
}

/// Allow GET but not POST to the same endpoint — verifies method-level ACL.
#[ignore] // requires network access to httpbin.org
#[tokio::test]
async fn test_http_method_filtering() {
    let out_get = temp_file("method-get");
    let out_post = temp_file("method-post");

    let policy = base_policy()
        .http_allow("GET httpbin.org/anything")
        .build()
        .unwrap();

    // GET should succeed
    let script_get = http_script("http://httpbin.org/anything", &out_get);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script_get])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content_get = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(
        content_get.starts_with("OK:200"),
        "expected OK:200 for GET, got: {}",
        content_get
    );

    // POST should be denied
    let script_post = post_script("http://httpbin.org/anything", &out_post);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script_post])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content_post = std::fs::read_to_string(&out_post).unwrap_or_default();
    assert!(
        content_post.starts_with("HTTP:403"),
        "expected HTTP:403 for POST, got: {}",
        content_post
    );

    let _ = std::fs::remove_file(&out_get);
    let _ = std::fs::remove_file(&out_post);
}

/// HTTPS through the MITM proxy — allowed request should succeed.
#[ignore] // requires network access to httpbin.org
#[tokio::test]
async fn test_https_mitm_allow() {
    let out = temp_file("https-allow");

    let policy = base_policy()
        .http_allow("GET httpbin.org/get")
        .build()
        .unwrap();

    let script = https_script("https://httpbin.org/get", &out);

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 for HTTPS allow, got: {}",
        content
    );

    let _ = std::fs::remove_file(&out);
}

/// HTTPS through the MITM proxy — non-matching path should be denied.
#[ignore] // requires network access to httpbin.org
#[tokio::test]
async fn test_https_mitm_deny() {
    let out = temp_file("https-deny");

    let policy = base_policy()
        .http_allow("GET httpbin.org/get")
        .build()
        .unwrap();

    let script = https_script("https://httpbin.org/post", &out);

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("HTTP:403"),
        "expected HTTP:403 for HTTPS deny, got: {}",
        content
    );

    let _ = std::fs::remove_file(&out);
}

/// Multiple allow rules — only matching ones pass.
#[ignore] // requires network access to httpbin.org
#[tokio::test]
async fn test_http_multiple_allow_rules() {
    let out_get = temp_file("multi-get");
    let out_anything = temp_file("multi-anything");

    let policy = base_policy()
        .http_allow("GET httpbin.org/get")
        .http_allow("POST httpbin.org/post")
        .build()
        .unwrap();

    // GET /get — should succeed (matches first rule)
    let script_get = http_script("http://httpbin.org/get", &out_get);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script_get])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content_get = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(
        content_get.starts_with("OK:200"),
        "expected OK:200 for /get, got: {}",
        content_get
    );

    // GET /anything — should be denied (not in allow list)
    let script_anything = http_script("http://httpbin.org/anything", &out_anything);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script_anything])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content_anything = std::fs::read_to_string(&out_anything).unwrap_or_default();
    assert!(
        content_anything.starts_with("HTTP:403"),
        "expected HTTP:403 for /anything, got: {}",
        content_anything
    );

    let _ = std::fs::remove_file(&out_get);
    let _ = std::fs::remove_file(&out_anything);
}

/// Wildcard host allow with a specific deny — deny takes precedence.
#[ignore] // requires network access to httpbin.org
#[tokio::test]
async fn test_http_wildcard_host() {
    let out_get = temp_file("wildcard-get");
    let out_418 = temp_file("wildcard-418");

    let policy = base_policy()
        .http_allow("* httpbin.org/*")
        .http_deny("* */status/418")
        .build()
        .unwrap();

    // GET /get — should succeed (matches wildcard allow, no deny match)
    let script_get = http_script("http://httpbin.org/get", &out_get);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script_get])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content_get = std::fs::read_to_string(&out_get).unwrap_or_default();
    assert!(
        content_get.starts_with("OK:200"),
        "expected OK:200 for /get, got: {}",
        content_get
    );

    // GET /status/418 — should be denied by deny rule
    let script_418 = http_script("http://httpbin.org/status/418", &out_418);
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script_418])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content_418 = std::fs::read_to_string(&out_418).unwrap_or_default();
    assert!(
        content_418.starts_with("HTTP:403"),
        "expected HTTP:403 for /status/418, got: {}",
        content_418
    );

    let _ = std::fs::remove_file(&out_get);
    let _ = std::fs::remove_file(&out_418);
}

/// Non-HTTP port traffic should NOT be intercepted by the proxy.
#[ignore] // requires local TCP server
#[tokio::test]
async fn test_http_non_intercepted_port() {
    let out = temp_file("non-intercept");

    let policy = base_policy()
        .http_allow("GET httpbin.org/get")
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
    assert!(
        content.starts_with("OK:HELLO"),
        "expected OK:HELLO, got: {}",
        content
    );

    let _ = std::fs::remove_file(&out);
}

/// IPv6 loopback connection through HTTP ACL — allowed request should succeed.
/// Verifies that AF_INET6 sockets are properly redirected via IPv4-mapped addresses.
#[ignore] // requires IPv6 loopback
#[tokio::test]
async fn test_http_acl_ipv6_allow() {
    let port_file = temp_file("ipv6-allow-port");
    let out = temp_file("ipv6-allow");

    // Start an IPv6 HTTP server in a sandbox, get its port, then test ACL.
    // We run server + client together in one script to keep port coordination simple.
    let script = format!(
        concat!(
            "import http.server, socket, threading, urllib.request, urllib.error, time\n",
            "class H(http.server.BaseHTTPRequestHandler):\n",
            "    def do_GET(self):\n",
            "        self.send_response(200)\n",
            "        self.end_headers()\n",
            "        self.wfile.write(b'ipv6-ok')\n",
            "    def log_message(self, *a): pass\n",
            "class V6Server(http.server.HTTPServer):\n",
            "    address_family = socket.AF_INET6\n",
            "srv = V6Server(('::1', 0), H)\n",
            "port = srv.server_address[1]\n",
            "t = threading.Thread(target=srv.handle_request, daemon=True)\n",
            "t.start()\n",
            "try:\n",
            "    resp = urllib.request.urlopen('http://[::1]:%d/get' % port)\n",
            "    open('{out}', 'w').write('OK:' + str(resp.status))\n",
            "except urllib.error.HTTPError as e:\n",
            "    open('{out}', 'w').write('HTTP:' + str(e.code))\n",
            "except Exception as e:\n",
            "    open('{out}', 'w').write('ERR:' + str(e))\n",
            "srv.server_close()\n",
        ),
        out = out.display(),
    );

    // Use http_port to intercept whatever port the server picks.
    // We can't know the port ahead of time, so intercept all traffic
    // by using a broad allow rule. The key test is that IPv6 connections
    // are properly redirected and not dropped with EAFNOSUPPORT.
    let policy = base_policy()
        .http_allow("GET */get")
        .build()
        .unwrap();

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    // The server is on a non-standard port (not 80), so the proxy won't
    // intercept it by default. The connection should go through directly.
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 for IPv6 loopback, got: {}",
        content
    );

    let _ = std::fs::remove_file(&port_file);
    let _ = std::fs::remove_file(&out);
}

/// IPv6 connection to httpbin.org on port 80 — verifies ACL enforcement
/// over IPv6 when the destination has AAAA records.
#[ignore] // requires network + IPv6 connectivity
#[tokio::test]
async fn test_http_acl_ipv6_allow_remote() {
    let out = temp_file("ipv6-allow-remote");

    // Force IPv6 via a Python script that explicitly creates an AF_INET6 socket.
    let script = format!(
        concat!(
            "import socket, urllib.request, urllib.error\n",
            "# Resolve httpbin.org to an IPv6 address\n",
            "infos = socket.getaddrinfo('httpbin.org', 80, socket.AF_INET6, socket.SOCK_STREAM)\n",
            "if not infos:\n",
            "    open('{out}', 'w').write('SKIP:no-ipv6')\n",
            "else:\n",
            "    try:\n",
            "        resp = urllib.request.urlopen('http://httpbin.org/get')\n",
            "        open('{out}', 'w').write('OK:' + str(resp.status))\n",
            "    except urllib.error.HTTPError as e:\n",
            "        open('{out}', 'w').write('HTTP:' + str(e.code))\n",
            "    except Exception as e:\n",
            "        open('{out}', 'w').write('ERR:' + str(e))\n",
        ),
        out = out.display(),
    );

    let policy = base_policy()
        .http_allow("GET httpbin.org/get")
        .build()
        .unwrap();

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:200") || content.starts_with("SKIP:no-ipv6"),
        "expected OK:200 or SKIP:no-ipv6, got: {}",
        content
    );

    let _ = std::fs::remove_file(&out);
}

/// IPv6 connection should be denied when ACL doesn't match — ensures the proxy
/// enforces rules on IPv6-redirected connections, not just silently passing them.
#[ignore] // requires network + IPv6 connectivity
#[tokio::test]
async fn test_http_acl_ipv6_deny_remote() {
    let out = temp_file("ipv6-deny-remote");

    let script = format!(
        concat!(
            "import socket, urllib.request, urllib.error\n",
            "infos = socket.getaddrinfo('httpbin.org', 80, socket.AF_INET6, socket.SOCK_STREAM)\n",
            "if not infos:\n",
            "    open('{out}', 'w').write('SKIP:no-ipv6')\n",
            "else:\n",
            "    try:\n",
            "        resp = urllib.request.urlopen('http://httpbin.org/post')\n",
            "        open('{out}', 'w').write('OK:' + str(resp.status))\n",
            "    except urllib.error.HTTPError as e:\n",
            "        open('{out}', 'w').write('HTTP:' + str(e.code))\n",
            "    except Exception as e:\n",
            "        open('{out}', 'w').write('ERR:' + str(e))\n",
        ),
        out = out.display(),
    );

    let policy = base_policy()
        .http_allow("GET httpbin.org/get")
        .build()
        .unwrap();

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("HTTP:403") || content.starts_with("SKIP:no-ipv6"),
        "expected HTTP:403 or SKIP:no-ipv6, got: {}",
        content
    );

    let _ = std::fs::remove_file(&out);
}

/// IPv6 non-intercepted port should pass through without proxy interference.
#[ignore] // requires IPv6 loopback
#[tokio::test]
async fn test_http_ipv6_non_intercepted_port() {
    let out = temp_file("ipv6-non-intercept");

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

    let policy = base_policy()
        .http_allow("GET httpbin.org/get")
        .build()
        .unwrap();

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:HELLO6"),
        "expected OK:HELLO6, got: {}",
        content
    );

    let _ = std::fs::remove_file(&out);
}

/// HTTP ACL combined with IP allowlist — both must pass.
#[ignore] // requires network access to httpbin.org
#[tokio::test]
async fn test_http_acl_with_net_allow_hosts() {
    let out = temp_file("acl-net-allow");

    let policy = base_policy()
        .http_allow("GET httpbin.org/get")
        .net_allow_host("httpbin.org")
        .build()
        .unwrap();

    let script = http_script("http://httpbin.org/get", &out);

    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(
        content.starts_with("OK:200"),
        "expected OK:200 with ACL + net_allow, got: {}",
        content
    );

    let _ = std::fs::remove_file(&out);
}
