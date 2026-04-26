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

/// /proc/net/dev should be virtualized to show only loopback.
#[tokio::test]
async fn proc_net_dev_shows_only_lo() {
    let out = temp_out("proc-net-dev");
    let script = format!(concat!(
        "lines = open('/proc/net/dev').readlines()\n",
        "ifaces = [l.split(':')[0].strip() for l in lines[2:]]\n",
        "open('{out}', 'w').write(','.join(ifaces))\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(contents.trim(), "lo", "expected only lo in /proc/net/dev, got: {}", contents);
    assert!(result.success());
}

/// /proc/net/if_inet6 should be virtualized to show only loopback.
#[tokio::test]
async fn proc_net_if_inet6_shows_only_lo() {
    let out = temp_out("proc-net-if-inet6");
    let script = format!(concat!(
        "lines = open('/proc/net/if_inet6').readlines()\n",
        "ifaces = [l.split()[-1] for l in lines if l.strip()]\n",
        "open('{out}', 'w').write(','.join(ifaces))\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(contents.trim(), "lo", "expected only lo in /proc/net/if_inet6, got: {}", contents);
    assert!(result.success());
}

/// SIOCGIFCONF ioctl should be blocked by the BPF arg filter, returning EPERM.
#[tokio::test]
async fn ioctl_siocgifconf_blocked() {
    let out = temp_out("ioctl-siocgifconf");
    let script = format!(concat!(
        "import fcntl, struct, socket, errno\n",
        "SIOCGIFCONF = 0x8912\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "buf = b'\\x00' * 4096\n",
        "ifc = struct.pack('iP', len(buf), 0)\n",
        "try:\n",
        "  fcntl.ioctl(s.fileno(), SIOCGIFCONF, ifc)\n",
        "  result = 'ALLOWED'\n",
        "except OSError as e:\n",
        "  result = f'BLOCKED:{{e.errno}}'\n",
        "finally:\n",
        "  s.close()\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        &format!("BLOCKED:{}", libc::EPERM),
        "SIOCGIFCONF should be blocked with EPERM, got: {}", contents
    );
    assert!(result.success());
}

/// SIOCETHTOOL ioctl should be blocked by the BPF arg filter.
#[tokio::test]
async fn ioctl_siocethtool_blocked() {
    let out = temp_out("ioctl-siocethtool");
    let script = format!(concat!(
        "import fcntl, struct, socket\n",
        "SIOCETHTOOL = 0x8946\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "ifr = struct.pack('16sP', b'eth0', 0)\n",
        "try:\n",
        "  fcntl.ioctl(s.fileno(), SIOCETHTOOL, ifr)\n",
        "  result = 'ALLOWED'\n",
        "except OSError as e:\n",
        "  result = f'BLOCKED:{{e.errno}}'\n",
        "finally:\n",
        "  s.close()\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        &format!("BLOCKED:{}", libc::EPERM),
        "SIOCETHTOOL should be blocked with EPERM, got: {}", contents
    );
    assert!(result.success());
}

/// /sys/class/net should be blocked as a sensitive path.
#[tokio::test]
async fn sys_class_net_blocked() {
    let out = temp_out("sys-class-net");
    let script = format!(concat!(
        "import os\n",
        "try:\n",
        "  entries = os.listdir('/sys/class/net')\n",
        "  result = 'ALLOWED:' + ','.join(entries)\n",
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
        "/sys/class/net should be blocked, got: {}", contents
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
