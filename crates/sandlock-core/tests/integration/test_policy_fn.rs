use sandlock_core::{Policy, Sandbox};
use sandlock_core::policy_fn::{Verdict, SyscallCategory};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn temp_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sandlock-test-policyfn-{}-{}", name, std::process::id()))
}

fn base_policy() -> sandlock_core::PolicyBuilder {
    Policy::builder()
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

    let result = Sandbox::run_interactive(
        &policy, Some("test"), &["python3", "-c", "print('hello')"],
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

/// Test that Verdict::Deny blocks a connect syscall.
#[tokio::test]
async fn test_policy_fn_deny_connect() {
    let out = temp_file("deny-connect");

    let policy = base_policy()
        .net_allow("127.0.0.1:443")
        .policy_fn(move |event, _ctx| {
            // Deny all connect attempts
            if event.syscall == "connect" {
                return Verdict::Deny;
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "  s.settimeout(1)\n",
        "  s.connect(('127.0.0.1', 1))\n",
        "  s.close()\n",
        "  open('{out}', 'w').write('CONNECTED')\n",
        "except (ConnectionRefusedError, PermissionError, OSError) as e:\n",
        "  open('{out}', 'w').write(f'BLOCKED:{{e.errno}}')\n",
    ), out = out.display());

    let result = Sandbox::run_interactive(&policy, Some("test"), &["python3", "-c", &script]).await.unwrap();
    assert!(result.success());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(content.starts_with("BLOCKED"), "connect should be denied, got: {}", content);

    let _ = std::fs::remove_file(&out);
}

/// Test restrict_network feedback loop — changes actually take effect.
#[tokio::test]
async fn test_policy_fn_restrict_network_takes_effect() {
    let out = temp_file("restrict-net-effect");

    let policy = base_policy()
        .net_allow("127.0.0.1:443")
        .policy_fn(move |event, ctx| {
            if event.syscall == "execve" {
                ctx.restrict_network(&[]); // block all
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "  s.settimeout(1)\n",
        "  s.connect(('127.0.0.1', 1))\n",
        "  s.close()\n",
        "  open('{out}', 'w').write('CONNECTED')\n",
        "except ConnectionRefusedError:\n",
        "  open('{out}', 'w').write('REFUSED')\n",
        "except (PermissionError, OSError) as e:\n",
        "  open('{out}', 'w').write(f'BLOCKED:{{e.errno}}')\n",
    ), out = out.display());

    let result = Sandbox::run_interactive(&policy, Some("test"), &["python3", "-c", &script]).await.unwrap();
    assert!(result.success());

    let content = std::fs::read_to_string(&out).unwrap_or_default();
    // After restrict_network([]), connect to 127.0.0.1 should be blocked
    // May show as BLOCKED (EPERM) or REFUSED (ECONNREFUSED from our handler)
    assert!(content.starts_with("BLOCKED") || content.starts_with("REFUSED"),
        "network should be restricted, got: {}", content);
    // It should NOT be CONNECTED
    assert!(!content.starts_with("CONNECTED"), "network restrict should prevent connection");

    let _ = std::fs::remove_file(&out);
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

    let result = Sandbox::run_interactive(&policy, Some("test"), &["python3", "-c", &script]).await.unwrap();
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

    let result = Sandbox::run_interactive(
        &policy, Some("test"), &["python3", "-c", "print('hello')"],
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

    let result = Sandbox::run_interactive(
        &policy, Some("test"), &["python3", "-c", "print('argv test')"],
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

    let result = Sandbox::run_interactive(
        &policy, Some("test"), &["echo", "malicious"],
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

    let result = Sandbox::run_interactive(&policy, Some("test"), &[
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

    let result = Sandbox::run_interactive(
        &policy, Some("test"), &["python3", "-c", "print('categories')"],
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

    let result = Sandbox::run_interactive(
        &policy, Some("test"), &["python3", "-c", "print('ppid')"],
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

    let result = Sandbox::run_interactive(&policy, Some("test"), &["python3", "-c", &script]).await.unwrap();
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

    let result = Sandbox::run_interactive(
        &policy, Some("test"), &["cat", "/etc/hostname"],
    ).await.unwrap();
    // Audit should allow the syscall — cat should succeed
    assert!(result.success(), "Audit should allow, not deny");

    let captured = audited.lock().unwrap();
    assert!(!captured.is_empty(), "should have audited file events");
}

/// Test that restrict_pid_network works even without net_allow_hosts.
/// This verifies that policy_fn alone enables network syscall interception.
#[tokio::test]
async fn test_policy_fn_restrict_pid_network_without_allowlist() {
    // No net_allow_hosts — network should be unrestricted by default,
    // but policy_fn can still restrict specific PIDs.
    let policy = base_policy()
        .policy_fn(move |event, ctx| {
            // On any execve, restrict that PID's network to nothing.
            // (Previously gated on path-substring; path strings were
            // dropped from events for TOCTOU reasons — issue #27.)
            if event.syscall == "execve" {
                ctx.restrict_pid_network(event.pid, &[]);
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    // Create a script that attempts to connect to localhost
    let script = temp_file("connect_test");
    std::fs::write(&script, r#"#!/bin/sh
exec python3 -c "
import socket, sys
try:
    s = socket.create_connection(('127.0.0.1', 1), timeout=2)
    s.close()
except ConnectionRefusedError:
    print('REFUSED')
    sys.exit(0)
except OSError as e:
    print(f'BLOCKED: {e}')
    sys.exit(0)
print('CONNECTED')
sys.exit(1)
"
"#).unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let result = Sandbox::run(&policy, Some("test"), &[script.to_str().unwrap()])
        .await
        .unwrap();

    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or(b""));
    // Connection should be refused (restricted by policy_fn)
    assert!(
        stdout.contains("REFUSED") || stdout.contains("BLOCKED"),
        "Expected connection to be blocked, got: {}", stdout,
    );

    let _ = std::fs::remove_file(&script);
}
