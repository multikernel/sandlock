use std::path::PathBuf;
use sandlock_core::{Sandbox};

fn base_policy() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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
    let policy = base_policy().net_allow_bind_port(0).build().unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(contents.trim(), "OK", "loopback bind failed: {}", contents);
    assert!(result.success());
}

/// Exercises `RTM_GETADDR` via glibc's `__check_pf`.  With `AI_ADDRCONFIG`,
/// glibc opens a NETLINK_ROUTE socket and dumps addresses to decide which
/// families (v4/v6) the host supports.  Our synthesized dump advertises
/// both 127.0.0.1 and ::1, so AI_ADDRCONFIG must accept both families.
///
/// We use `getaddrinfo(None, port, AI_PASSIVE | AI_ADDRCONFIG)` instead of
/// looking up "localhost". glibc fast-paths "localhost" through a
/// hard-coded check that uses `__check_pf` directly and filters out v6
/// when no non-loopback IPv6 address is configured (loopback-only is
/// exactly what our sandbox shows), so a localhost lookup never returns
/// v6 inside the sandbox regardless of `/etc/hosts`. AI_PASSIVE with a
/// null node name returns the wildcard address for every family that
/// `__check_pf` says is configured, so it exercises the netlink dump
/// path directly.
#[tokio::test]
async fn getaddrinfo_ai_addrconfig_returns_v4_and_v6() {
    let out = temp_out("getaddrinfo");
    let script = format!(concat!(
        "import socket\n",
        "fams = sorted({{i[0].name for i in socket.getaddrinfo(",
        "None, 443, type=socket.SOCK_STREAM, ",
        "flags=socket.AI_PASSIVE | socket.AI_ADDRCONFIG)}})\n",
        "open('{out}', 'w').write(','.join(fams))\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "AF_INET,AF_INET6",
        "AI_ADDRCONFIG should consider both families configured, got: {}",
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert!(
        contents.starts_with("BLOCKED:"),
        "/sys/class/net should be blocked, got: {}", contents
    );
    assert!(result.success());
}

/// Regression for Copy Fail (CVE-2026-31431). The exploit's first step is
/// `socket(AF_ALG, SOCK_SEQPACKET, 0)`, then `bind()` to a sockaddr_alg
/// naming "authencesn(hmac(sha256),cbc(aes))". If `socket()` is denied
/// with EAFNOSUPPORT the page-cache corruption primitive is unreachable.
#[tokio::test]
async fn af_alg_socket_blocked() {
    let out = temp_out("af-alg-blocked");
    let script = format!(concat!(
        "import socket, errno\n",
        "AF_ALG = 38\n",
        "try:\n",
        "  s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except OSError as e:\n",
        "  result = f'BLOCKED:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    // EAFNOSUPPORT == 97 on Linux. We assert the exact errno so a future
    // accidental switch to EPERM/EACCES (which would surface differently
    // to callers) is caught.
    assert_eq!(
        contents, "BLOCKED:97",
        "AF_ALG socket() must return EAFNOSUPPORT, got: {contents}"
    );
    assert!(result.success());
}

/// Other niche socket families — same threat model as AF_ALG (kernel LPE
/// surface that XOA agents have no business reaching). AF_ALG has its own
/// dedicated test above; this one guards the broader class.
#[tokio::test]
async fn niche_socket_families_blocked() {
    // (name, AF_* numeric value)
    let families: &[(&str, i32)] = &[
        ("AF_PACKET", 17),    // PACKET_MMAP has had UAFs
        ("AF_VSOCK", 40),     // recurring use-after-frees
        ("AF_XDP", 44),
        ("AF_TIPC", 30),
    ];

    for (name, af) in families {
        let out = temp_out(&format!("family-blocked-{}", name));
        let script = format!(concat!(
            "import socket\n",
            "try:\n",
            "  s = socket.socket({af}, socket.SOCK_RAW, 0)\n",
            "  s.close()\n",
            "  result = 'ALLOWED'\n",
            "except OSError as e:\n",
            "  result = f'BLOCKED:{{e.errno}}'\n",
            "open('{out}', 'w').write(result)\n",
        ), af = af, out = out.display());

        let policy = base_policy().build().unwrap();
        let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
            .await.unwrap();

        let contents = std::fs::read_to_string(&out).unwrap_or_default();
        let _ = std::fs::remove_file(&out);
        assert!(
            contents.starts_with("BLOCKED:"),
            "{name} should be blocked, got: {contents}"
        );
        assert!(result.success());
    }
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert!(
        contents.starts_with("BLOCKED:"),
        "NETLINK_AUDIT should be blocked, got: {}", contents
    );
    assert!(result.success());
}

/// `/etc/hosts` is always virtualized, independent of whatever the host's
/// on-disk file says: the sandbox sees a fixed loopback-only view. The
/// loopback base (`127.0.0.1 localhost` / `::1 localhost`) is always
/// present, and concrete-host entries from `net_allow` get appended to
/// the same synthetic file.
#[tokio::test]
async fn etc_hosts_virtualized_with_loopback_base() {
    let out = temp_out("etc-hosts");
    let script = format!(
        "open('{out}', 'w').write(open('/etc/hosts').read())\n",
        out = out.display(),
    );

    let policy = base_policy().build().unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    // With no `net_allow` rules the sandbox sees exactly the loopback
    // base; any deviation means the on-disk `/etc/hosts` leaked through.
    assert_eq!(
        contents,
        "127.0.0.1 localhost\n::1 localhost\n",
        "virtual /etc/hosts content mismatch"
    );
    assert!(result.success());
}

/// The literal-path match used to be the only check, so any spelling
/// other than `"/etc/hosts"` reached the host's on-disk file. Hit each
/// known bypass and assert we see the synthetic content instead.
#[tokio::test]
async fn etc_hosts_virtualization_resists_path_bypasses() {
    let out = temp_out("etc-hosts-bypass");
    // Python's builtin `open` goes through libc → `openat(AT_FDCWD, ...)`,
    // so we cover the dirfd-relative case via os.open + os.openat-style
    // file-descriptor reuse, and the non-canonical case directly.
    let script = format!(concat!(
        "import os\n",
        "results = {{}}\n",
        // 1. Dirfd-relative: open /etc, then read 'hosts' relative to it.
        "etcfd = os.open('/etc', os.O_DIRECTORY | os.O_RDONLY)\n",
        "fd = os.open('hosts', os.O_RDONLY, dir_fd=etcfd)\n",
        "results['dirfd_relative'] = os.read(fd, 4096).decode()\n",
        "os.close(fd); os.close(etcfd)\n",
        // 2. Non-canonical absolute via redundant components.
        "results['dotdot']  = open('/etc/../etc/hosts').read()\n",
        "results['slash2']  = open('//etc/hosts').read()\n",
        "results['curdir']  = open('/etc/./hosts').read()\n",
        "open('{out}', 'w').write(repr(results))\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    // Every spelling must hit the synthetic memfd, not the host file.
    let expected = "127.0.0.1 localhost\\n::1 localhost\\n";
    for label in ["dirfd_relative", "dotdot", "slash2", "curdir"] {
        let needle = format!("'{label}': '{expected}'");
        assert!(
            contents.contains(&needle),
            "{label}: host /etc/hosts leaked. got: {contents}"
        );
    }
    assert!(result.success());
}

/// Regression guard for the netlink virtualization under a DESTINATION POLICY.
///
/// A non-empty `net_allow` sets `has_net_destination_policy`, which stops
/// `sendto` from Continuing on a non-IP destination and routes it through the
/// supervisor's on-behalf arm instead. The virtualized "netlink socket" the
/// child holds is one end of a `socketpair(AF_UNIX, SOCK_SEQPACKET)`
/// (`netlink::handlers::handle_socket`), and glibc addresses it with a
/// `sockaddr_nl` — a NON-`AF_UNIX` destination on a unix-domain socket. That
/// shape carries no pathname, exactly like an abstract unix address; a handler
/// that keys on "did a pathname come out of it" instead of on the address
/// family collapses the two and fails the send closed with `EAFNOSUPPORT`,
/// taking every netlink query offline for any sandbox with a destination
/// policy — `if_nameindex`, `getaddrinfo`'s `AI_ADDRCONFIG` probe, and so on.
///
/// `if_nameindex()` is the shortest observable consumer: glibc opens a
/// NETLINK_ROUTE socket, `sendto`s an `RTM_GETLINK` dump request, and reads the
/// reply. The assertion is the same one `if_nameindex_returns_only_lo` makes
/// without a policy, so the two differ only in the switch under test.
#[tokio::test]
async fn if_nameindex_works_under_destination_policy() {
    let out = temp_out("if-nameindex-netpolicy");
    let _ = std::fs::remove_file(&out);
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  result = repr(socket.if_nameindex())\n",
        "except OSError as e:\n",
        "  result = 'ERRNO:%d' % e.errno\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    // Any rule at all flips has_net_destination_policy on; the rule itself is
    // irrelevant to a unix/netlink send.
    let policy = base_policy().net_allow("127.0.0.1:9").build().unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await.unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert!(
        contents.contains("'lo'") && !contents.contains("'eth"),
        "netlink must keep working under a destination policy; expected only lo, got: {}",
        contents
    );
    assert!(result.success());
}
