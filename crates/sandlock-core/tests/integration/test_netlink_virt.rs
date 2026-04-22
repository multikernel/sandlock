use std::path::PathBuf;
use sandlock_core::{Policy, Sandbox};

fn base_policy() -> sandlock_core::PolicyBuilder {
    Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64")
        .fs_read("/bin").fs_read("/etc").fs_read("/proc")
        .fs_read("/dev").fs_write("/tmp")
}

fn temp_out(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sandlock-test-nlvirt-{}-{}", name, std::process::id()
    ))
}

#[tokio::test]
async fn if_nameindex_returns_only_lo() {
    let out = temp_out("if-nameindex");
    let script = format!(concat!(
        "import socket\n",
        "ifs = socket.if_nameindex()\n",
        "open('{out}', 'w').write(repr(ifs))\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert!(
        contents.contains("'lo'") && !contents.contains("'eth"),
        "expected only lo, got: {}", contents
    );
    assert!(result.success());
}

#[tokio::test]
async fn loopback_bind_succeeds() {
    let out = temp_out("loopback-bind");
    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "try:\n",
        "  s.bind(('127.0.0.1', 0))\n",
        "  result = 'OK'\n",
        "except OSError as e:\n",
        "  result = f'FAIL:{{e}}'\n",
        "finally:\n",
        "  s.close()\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    // port 0 in Landlock net rules means "allow any port"
    let policy = base_policy().net_bind_port(0).build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(contents.trim(), "OK", "loopback bind failed: {}", contents);
    assert!(result.success());
}

/// Exercises `RTM_GETADDR` via glibc's `__check_pf`.  With `AI_ADDRCONFIG`,
/// glibc opens a NETLINK_ROUTE socket and dumps addresses to decide which
/// families (v4/v6) the host supports.  Our synthesized dump advertises
/// both 127.0.0.1 and ::1, so getaddrinfo must return entries for both
/// families for `localhost`.
#[tokio::test]
async fn getaddrinfo_ai_addrconfig_returns_v4_and_v6() {
    let out = temp_out("getaddrinfo");
    let script = format!(concat!(
        "import socket\n",
        "fams = sorted({{i[0].name for i in socket.getaddrinfo(",
        "'localhost', 443, type=socket.SOCK_STREAM, flags=socket.AI_ADDRCONFIG)}})\n",
        "open('{out}', 'w').write(','.join(fams))\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "AF_INET,AF_INET6",
        "AI_ADDRCONFIG should return both families for localhost, got: {}",
        contents
    );
    assert!(result.success());
}

#[tokio::test]
async fn non_route_netlink_still_blocked() {
    let out = temp_out("netlink-audit-blocked");
    let script = format!(concat!(
        "import socket\n",
        "NETLINK_AUDIT = 9\n",
        "try:\n",
        "  s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except OSError as e:\n",
        "  result = f'BLOCKED:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert!(
        contents.starts_with("BLOCKED:"),
        "NETLINK_AUDIT should be blocked, got: {}", contents
    );
    assert!(result.success());
}
