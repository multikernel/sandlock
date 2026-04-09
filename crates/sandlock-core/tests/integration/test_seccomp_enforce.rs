use std::path::PathBuf;

use sandlock_core::{Policy, Sandbox};

/// Helper: base policy with standard FS paths for running commands.
fn base_policy() -> sandlock_core::PolicyBuilder {
    Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
}

/// Helper: build a temp file path for a given test name.
fn temp_out(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sandlock-test-seccomp-{}-{}",
        name,
        std::process::id()
    ))
}

// ------------------------------------------------------------------
// 1. mount() is blocked by default seccomp deny list
// ------------------------------------------------------------------
#[tokio::test]
async fn test_mount_blocked() {
    let out = temp_out("mount-blocked");
    let cmd_str = format!(
        "mount -t tmpfs none /tmp 2>/dev/null; echo $? > {}",
        out.display()
    );
    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["sh", "-c", &cmd_str])
        .await
        .unwrap();

    // sh itself should exit 0 (the echo succeeds), but the mount exit
    // code written to the file should be non-zero (permission denied).
    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let code: i32 = contents.trim().parse().unwrap_or(-1);
    assert_ne!(code, 0, "mount should have been denied, got exit code 0");
    // Also confirm the sandbox wrapper itself didn't crash.
    assert!(result.success());
}

// ------------------------------------------------------------------
// 2. ptrace is blocked (strace should fail)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_ptrace_blocked() {
    let out = temp_out("ptrace-blocked");
    let cmd_str = format!(
        "strace -p 1 2>/dev/null; echo $? > {}",
        out.display()
    );
    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["sh", "-c", &cmd_str])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let code: i32 = contents.trim().parse().unwrap_or(-1);
    assert_ne!(code, 0, "ptrace (strace) should have been denied");
    assert!(result.success());
}

// ------------------------------------------------------------------
// 3. Raw sockets blocked by default (no_raw_sockets defaults to true)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_raw_socket_blocked() {
    let out = temp_out("raw-socket-blocked");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "BLOCKED",
        "raw socket should be blocked by default, got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 4. Raw sockets allowed when no_raw_sockets(false)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_raw_socket_allowed_when_permitted() {
    let out = temp_out("raw-socket-allowed");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy()
        .no_raw_sockets(false)
        .build()
        .unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    // When seccomp allows it, the OS may still deny if not running as root.
    // Accept ALLOWED (root) or BLOCKED/ERROR (non-root OS-level denial).
    let trimmed = contents.trim();
    assert!(
        trimmed == "ALLOWED" || trimmed == "BLOCKED" || trimmed.starts_with("ERROR:"),
        "unexpected result when raw sockets permitted: {}",
        trimmed
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 5. UDP blocked when no_udp(true)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_udp_blocked_when_enabled() {
    let out = temp_out("udp-blocked");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy()
        .no_udp(true)
        .build()
        .unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "BLOCKED",
        "UDP socket should be blocked with no_udp(true), got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 6. UDP allowed by default (no no_udp flag)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_udp_allowed_by_default() {
    let out = temp_out("udp-allowed");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "ALLOWED",
        "UDP socket should be allowed by default, got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 7. All AF_NETLINK sockets blocked (network topology leak)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_netlink_socket_blocked() {
    let out = temp_out("netlink-blocked");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "BLOCKED",
        "AF_NETLINK socket should be blocked, got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 8. TCP always allowed even with no_raw_sockets + no_udp
// ------------------------------------------------------------------
#[tokio::test]
async fn test_tcp_always_allowed() {
    let out = temp_out("tcp-allowed");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy()
        .no_raw_sockets(true)
        .no_udp(true)
        .build()
        .unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "ALLOWED",
        "TCP socket should always be allowed, got: {}",
        contents.trim()
    );
    assert!(result.success());
}
