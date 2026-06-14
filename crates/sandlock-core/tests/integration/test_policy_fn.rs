use sandlock_core::{Sandbox};
use sandlock_core::policy_fn::{Verdict, SyscallCategory};
use sandlock_core::sandbox::ByteSize;
use std::net::{IpAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn temp_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sandlock-test-policyfn-{}-{}", name, std::process::id()))
}

/// A live TCP listener on `host:ephemeral`. Connecting to it *succeeds* when
/// allowed, so a deny-test can tell a real block from a connection that would
/// have failed anyway (e.g. ECONNREFUSED to a dead port).
fn loopback_listener(host: &str) -> (TcpListener, u16) {
    let l = TcpListener::bind((host, 0)).expect("bind loopback listener");
    let port = l.local_addr().unwrap().port();
    (l, port)
}

fn base_policy() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
}

/// Test that the policy callback receives events with metadata.
#[tokio::test]
async fn test_policy_fn_receives_events_with_metadata() {
    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();

    let policy = base_policy()
        .policy_fn(move |event, _ctx| {
            events_clone.lock().unwrap().push(event.syscall.clone());
            Verdict::Allow
        })
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", "print('hello')"],
    ).await.unwrap();
    assert!(result.success());

    let captured = events.lock().unwrap();
    assert!(!captured.is_empty(), "should receive events");

    // Should have at least one openat (file syscall) and one execve.
    assert!(captured.iter().any(|n| n == "openat"),
        "should include openat, got: {:?}", &captured[..captured.len().min(5)]);
    assert!(captured.iter().any(|n| n == "execve"),
        "should include execve, got: {:?}", &captured[..captured.len().min(5)]);
}

/// Verdict::Deny blocks a connect syscall (with EPERM), attributable to the
/// callback. The previous version connected to a dead port (127.0.0.1:1) and
/// accepted any error as "blocked", so it passed even if the deny did nothing.
/// Target a live listener on an allowlisted port: Landlock permits it and the
/// listener would accept it, so the EPERM can only come from the policy_fn.
#[tokio::test]
async fn test_policy_fn_deny_connect() {
    let out = temp_file("deny-connect");
    let (_listener, port) = loopback_listener("127.0.0.1");

    let policy = base_policy()
        .net_allow(format!("127.0.0.1:{port}"))
        .policy_fn(move |event, _ctx| {
            if event.syscall == "connect" {
                return Verdict::Deny; // EPERM
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.settimeout(3)\n",
        "try:\n",
        "  s.connect(('127.0.0.1', {port}))\n",
        "  open('{out}', 'w').write('CONNECTED')\n",
        "except OSError as e:\n",
        "  open('{out}', 'w').write('BLOCKED:%d' % e.errno)\n",
    ), port = port, out = out.display());

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    // EPERM (1) from the policy_fn deny — not a dead-port ECONNREFUSED.
    assert_eq!(content, "BLOCKED:1", "connect should be denied by policy_fn (EPERM)");
}

/// restrict_network narrows outbound to the listed IPs and is enforced. The
/// previous version called `restrict_network(&[])` — an empty list is a no-op —
/// and connected to a dead port, so it verified nothing. Use two live loopback
/// listeners (127.0.0.1 and 127.0.0.2), both allowlisted up front so either
/// would connect; restricting to ["127.0.0.1"] must then permit the first and
/// refuse the second (ECONNREFUSED, errno 111).
#[tokio::test]
async fn test_policy_fn_restrict_network_takes_effect() {
    let out = temp_file("restrict-net-effect");
    let (_l1, p1) = loopback_listener("127.0.0.1");
    let (_l2, p2) = loopback_listener("127.0.0.2");

    let allowed: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
    let policy = base_policy()
        .net_allow(format!("127.0.0.1:{p1}"))
        .net_allow(format!("127.0.0.2:{p2}"))
        .policy_fn(move |event, ctx| {
            if event.syscall == "execve" {
                ctx.restrict_network(&allowed); // narrow to 127.0.0.1
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "def probe(ip, port):\n",
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)\n",
        "    try:\n",
        "        s.connect((ip, port)); return 'OK'\n",
        "    except OSError as e: return 'ERR%d' % e.errno\n",
        "    finally: s.close()\n",
        "open('{out}', 'w').write('allowed=' + probe('127.0.0.1', {p1}) + ' denied=' + probe('127.0.0.2', {p2}))\n",
    ), out = out.display(), p1 = p1, p2 = p2);

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert!(content.contains("allowed=OK"), "listed IP should still connect, got: {}", content);
    assert!(content.contains("denied=ERR111"), "non-listed IP should be refused, got: {}", content);
}

/// Test deny_path blocks filesystem access dynamically.
#[tokio::test]
async fn test_policy_fn_deny_path() {
    let out = temp_file("deny-path");

    let policy = base_policy()
        .policy_fn(move |event, ctx| {
            if event.syscall == "execve" {
                ctx.deny_path("/etc/hostname");
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let script = format!(concat!(
        "try:\n",
        "  with open('/etc/hostname') as f:\n",
        "    open('{out}', 'w').write('READ:' + f.read().strip())\n",
        "except (PermissionError, OSError) as e:\n",
        "  open('{out}', 'w').write(f'BLOCKED:{{e.errno}}')\n",
    ), out = out.display());

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(content.starts_with("BLOCKED"), "path should be denied, got: {}", content);

    let _ = std::fs::remove_file(&out);
}

/// Test passthrough — callback with Verdict::Allow doesn't interfere.
#[tokio::test]
async fn test_policy_fn_passthrough() {
    let call_count: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let count_clone = call_count.clone();

    let policy = base_policy()
        .policy_fn(move |_event, _ctx| {
            *count_clone.lock().unwrap() += 1;
            Verdict::Allow
        })
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", "print('hello')"],
    ).await.unwrap();
    assert!(result.success());

    let count = *call_count.lock().unwrap();
    assert!(count > 0, "callback should have been called at least once, got {}", count);
}

/// Test execve events include argv (TOCTOU-safe via sibling freeze).
#[tokio::test]
async fn test_policy_fn_execve_argv() {
    let argvs: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let argvs_clone = argvs.clone();

    let policy = base_policy()
        .policy_fn(move |event, _ctx| {
            if event.syscall == "execve" {
                if let Some(ref args) = event.argv {
                    argvs_clone.lock().unwrap().push(args.clone());
                }
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", "print('argv test')"],
    ).await.unwrap();
    assert!(result.success());

    let captured = argvs.lock().unwrap();
    assert!(!captured.is_empty(), "should have captured execve argv");
    let has_python = captured.iter().any(|args| args.iter().any(|a| a.contains("python3")));
    assert!(has_python, "argv should contain python3, got: {:?}", *captured);
}

/// Test argv_contains-based denial. The supervisor freezes sibling
/// threads of the calling tid before Continue, so the policy_fn's
/// argv inspection binds to what the kernel will run.
#[tokio::test]
async fn test_policy_fn_deny_by_argv() {
    let policy = base_policy()
        .policy_fn(move |event, _ctx| {
            if event.syscall == "execve" && event.argv_contains("malicious") {
                return Verdict::Deny;
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run_interactive(&["echo", "malicious"],
    ).await.unwrap();
    assert!(!result.success(), "execve with 'malicious' in argv should be denied");
}

/// Test event has host/port metadata for connect.
#[tokio::test]
async fn test_policy_fn_connect_metadata() {
    let events: Arc<Mutex<Vec<(Option<std::net::IpAddr>, Option<u16>)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();

    let policy = base_policy()
        .net_allow("127.0.0.1:443")
        .policy_fn(move |event, _ctx| {
            if event.syscall == "connect" {
                events_clone.lock().unwrap().push((event.host, event.port));
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run_interactive(&[
        "python3", "-c",
        "import socket; s=socket.socket(); s.settimeout(0.1); \
         s.connect_ex(('127.0.0.1', 9999)); s.close()",
    ]).await.unwrap();
    let _ = result;

    let captured = events.lock().unwrap();
    if !captured.is_empty() {
        let (host, port) = &captured[0];
        assert!(host.is_some(), "connect event should have host");
        assert!(port.is_some(), "connect event should have port");
    }
}

// ============================================================
// Category tests
// ============================================================

/// Test that events have correct categories.
#[tokio::test]
async fn test_policy_fn_event_categories() {
    let categories: Arc<Mutex<Vec<(String, SyscallCategory)>>> = Arc::new(Mutex::new(Vec::new()));
    let cats_clone = categories.clone();

    let policy = base_policy()
        .net_allow("127.0.0.1:443")
        .policy_fn(move |event, _ctx| {
            cats_clone.lock().unwrap().push((event.syscall.clone(), event.category));
            Verdict::Allow
        })
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", "print('categories')"],
    ).await.unwrap();
    assert!(result.success());

    let captured = categories.lock().unwrap();
    // openat should be File
    let has_file = captured.iter().any(|(_, c)| *c == SyscallCategory::File);
    assert!(has_file, "should have File category events, got: {:?}", *captured);
    // execve should be Process
    let has_process = captured.iter().any(|(_, c)| *c == SyscallCategory::Process);
    assert!(has_process, "should have Process category events, got: {:?}", *captured);
}

// ============================================================
// Parent PID tests
// ============================================================

/// Test that events include parent_pid.
#[tokio::test]
async fn test_policy_fn_parent_pid() {
    let ppids: Arc<Mutex<Vec<Option<u32>>>> = Arc::new(Mutex::new(Vec::new()));
    let ppids_clone = ppids.clone();

    let policy = base_policy()
        .policy_fn(move |event, _ctx| {
            if event.syscall == "execve" {
                ppids_clone.lock().unwrap().push(event.parent_pid);
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", "print('ppid')"],
    ).await.unwrap();
    assert!(result.success());

    let captured = ppids.lock().unwrap();
    assert!(!captured.is_empty(), "should have execve events");
    // At least one event should have a non-zero parent_pid
    let has_ppid = captured.iter().any(|p| p.map_or(false, |v| v > 0));
    assert!(has_ppid, "execve should have parent_pid > 0, got: {:?}", *captured);
}

// ============================================================
// DenyWith tests
// ============================================================

/// Test Verdict::DenyWith returns custom errno.
#[tokio::test]
async fn test_policy_fn_deny_with_eacces() {
    let out = temp_file("deny-eacces");

    let policy = base_policy()
        .net_allow("127.0.0.1:443")
        .policy_fn(move |event, _ctx| {
            if event.syscall == "connect" {
                return Verdict::DenyWith(libc::EACCES);
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket, errno\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.settimeout(1)\n",
        "try:\n",
        "  s.connect(('127.0.0.1', 1))\n",
        "  open('{out}', 'w').write('CONNECTED')\n",
        "except OSError as e:\n",
        "  open('{out}', 'w').write(f'ERR:{{e.errno}}')\n",
        "finally:\n",
        "  s.close()\n",
    ), out = out.display());

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    // EACCES = 13
    assert!(content.contains("ERR:13"), "should get EACCES (13), got: {}", content);

    let _ = std::fs::remove_file(&out);
}

// ============================================================
// Audit tests
// ============================================================

/// Test Verdict::Audit allows the syscall but can be tracked.
#[tokio::test]
async fn test_policy_fn_audit() {
    let audited: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let audited_clone = audited.clone();

    let policy = base_policy()
        .policy_fn(move |event, _ctx| {
            if event.category == SyscallCategory::File {
                audited_clone.lock().unwrap().push(event.syscall.clone());
                return Verdict::Audit;
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let result = policy.clone().with_name("test").run_interactive(&["cat", "/etc/hostname"],
    ).await.unwrap();
    // Audit should allow the syscall — cat should succeed
    assert!(result.success(), "Audit should allow, not deny");

    let captured = audited.lock().unwrap();
    assert!(!captured.is_empty(), "should have audited file events");
}

/// restrict_pid_network blocks a pid's outbound even without a net_allow
/// allowlist (policy_fn alone enables network interception). The previous
/// version connected to a dead port and accepted any error, so it passed even
/// if nothing was restricted. Target a *live* listener with no net_allow: the
/// connect would succeed (network unrestricted by default under policy_fn), so
/// the refusal can only come from restrict_pid_network([]).
#[tokio::test]
async fn test_policy_fn_restrict_pid_network_without_allowlist() {
    let out = temp_file("restrict-pid-net");
    let (_listener, port) = loopback_listener("127.0.0.1");

    // No net_allow: outbound is otherwise unrestricted; the callback restricts
    // the exec'd pid's network to the empty set (deny all) on execve.
    let policy = base_policy()
        .policy_fn(move |event, ctx| {
            if event.syscall == "execve" {
                ctx.restrict_pid_network(event.pid, &[]);
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)\n",
        "try:\n",
        "  s.connect(('127.0.0.1', {port}))\n",
        "  open('{out}', 'w').write('CONNECTED')\n",
        "except OSError as e:\n",
        "  open('{out}', 'w').write('ERR%d' % e.errno)\n",
    ), port = port, out = out.display());

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    // The listener is live, so a successful connect would read "CONNECTED";
    // ERR111 (ECONNREFUSED from the on-behalf deny) can only come from the
    // per-pid restriction.
    assert_eq!(content, "ERR111", "restrict_pid_network([]) must deny the connect");
}

// ---------------------------------------------------------------------------
// Dynamic resource-limit enforcement + fork-tracking regression
// ---------------------------------------------------------------------------

/// restrict_max_memory tightens the static ceiling and is enforced. Set a
/// 256 MiB ceiling, restrict to 64 MiB on execve, then allocate 128 MiB: the
/// process is killed. The control (same ceiling, no restriction) allocates the
/// same 128 MiB fine — proving the kill is the dynamic limit, not the ceiling.
#[tokio::test]
async fn test_policy_fn_restrict_max_memory_enforced() {
    let alloc_128 = concat!(
        "import sys\n",
        "print('STARTED', flush=True)\n",
        "b = bytearray(128 * 1024 * 1024)\n",
        "b[::4096] = b'\\x01' * (len(b) // 4096)\n",   // commit the pages
        "print('ALLOC_OK')\n",
    );

    let restricted = base_policy()
        .max_memory(ByteSize::mib(256))
        .policy_fn(|event, ctx| {
            if event.syscall == "execve" {
                ctx.restrict_max_memory(64 * 1024 * 1024);
            }
            Verdict::Allow
        })
        .build()
        .unwrap()
        .with_name("test")
        .run(&["python3", "-c", alloc_128])
        .await
        .unwrap();
    let out = String::from_utf8_lossy(restricted.stdout.as_deref().unwrap_or(b""));
    assert!(out.contains("STARTED"), "should start, got: {}", out);
    assert!(!out.contains("ALLOC_OK"), "128 MiB must exceed the 64 MiB dynamic limit, got: {}", out);
    assert!(!restricted.success(), "process should be killed by the memory limit");

    let baseline = base_policy()
        .max_memory(ByteSize::mib(256))
        .policy_fn(|_e, _c| Verdict::Allow)
        .build()
        .unwrap()
        .with_name("test")
        .run(&["python3", "-c", alloc_128])
        .await
        .unwrap();
    let out = String::from_utf8_lossy(baseline.stdout.as_deref().unwrap_or(b""));
    assert!(out.contains("ALLOC_OK"), "128 MiB under the 256 MiB ceiling should succeed, got: {}", out);
    assert!(baseline.success());
}

/// restrict_max_processes tightens the concurrent-process limit and is
/// enforced. Restrict to 1, then fork: the fork is denied with EAGAIN. The
/// control (no restriction) forks successfully.
#[tokio::test]
async fn test_policy_fn_restrict_max_processes_enforced() {
    let fork_once = concat!(
        "import os\n",
        "print('STARTED', flush=True)\n",
        "try:\n",
        "    pid = os.fork()\n",
        "    if pid == 0: os._exit(0)\n",
        "    os.waitpid(pid, 0); print('FORK_OK')\n",
        "except OSError as e: print('FORK_DENIED', e.errno)\n",
    );

    let restricted = base_policy()
        .policy_fn(|event, ctx| {
            if event.syscall == "execve" {
                ctx.restrict_max_processes(1);
            }
            Verdict::Allow
        })
        .build()
        .unwrap()
        .with_name("test")
        .run(&["python3", "-c", fork_once])
        .await
        .unwrap();
    let out = String::from_utf8_lossy(restricted.stdout.as_deref().unwrap_or(b""));
    assert!(out.contains("STARTED"), "should start, got: {}", out);
    assert!(!out.contains("FORK_OK"), "fork must be denied under the limit, got: {}", out);
    assert!(out.contains("FORK_DENIED 11"), "fork should be denied with EAGAIN, got: {}", out);

    let baseline = base_policy()
        .policy_fn(|_e, _c| Verdict::Allow)
        .build()
        .unwrap()
        .with_name("test")
        .run(&["python3", "-c", fork_once])
        .await
        .unwrap();
    let out = String::from_utf8_lossy(baseline.stdout.as_deref().unwrap_or(b""));
    assert!(out.contains("FORK_OK"), "unrestricted fork should succeed, got: {}", out);
}

/// Regression: a workload that forks under an active policy_fn must not
/// deadlock the supervisor's fork-event ptrace tracking. Fork many times in one
/// run and require it to complete (bounded so a regression fails instead of
/// hanging the suite forever).
#[tokio::test]
async fn test_policy_fn_fork_does_not_deadlock() {
    let many_forks = concat!(
        "import os\n",
        "ok = 0\n",
        "for _ in range(30):\n",
        "    pid = os.fork()\n",
        "    if pid == 0: os._exit(0)\n",
        "    os.waitpid(pid, 0); ok += 1\n",
        "print('FORKS_OK', ok)\n",
    );

    let mut sb = base_policy()
        // count events so the fork path is exercised under an active callback
        .policy_fn(|_e, _c| Verdict::Allow)
        .build()
        .unwrap()
        .with_name("test");

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        sb.run(&["python3", "-c", many_forks]),
    )
    .await
    .expect("policy_fn + fork() must not deadlock")
    .unwrap();

    assert!(result.success(), "run should complete");
    let out = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or(b""));
    assert!(out.contains("FORKS_OK 30"), "all 30 forks should complete, got: {}", out);
}
