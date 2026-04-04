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
