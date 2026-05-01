use std::path::PathBuf;

use sandlock_core::{Policy, Sandbox};

/// Helper: base policy with standard FS paths for running commands.
fn base_policy() -> sandlock_core::PolicyBuilder {
    Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
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
// 3. personality() blocked (ASLR bypass prevention)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_personality_blocked() {
    let out = temp_out("personality-blocked");
    let script = format!(concat!(
        "import ctypes\n",
        "libc = ctypes.CDLL(None)\n",
        "ADDR_NO_RANDOMIZE = 0x0040000\n",
        "current = libc.syscall(135, 0xffffffff)\n",
        "ret = libc.syscall(135, current | ADDR_NO_RANDOMIZE)\n",
        "if ret == -1:\n",
        "  result = 'BLOCKED'\n",
        "else:\n",
        "  new = libc.syscall(135, 0xffffffff)\n",
        "  result = 'ESCAPED' if new & ADDR_NO_RANDOMIZE else 'BLOCKED'\n",
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
        "personality(ADDR_NO_RANDOMIZE) should be blocked, got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 4. Raw sockets blocked by default (allow_icmp defaults to false)
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
// 4b. allow_icmp(true) permits AF_INET + SOCK_RAW + IPPROTO_ICMP
//     while other raw socket types remain denied.
// ------------------------------------------------------------------
#[tokio::test]
async fn test_allow_icmp_permits_icmp_raw() {
    let out = temp_out("allow-icmp-permits-icmp");
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
        .allow_icmp(true)
        .build()
        .unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    // seccomp must permit it; the kernel may still deny without CAP_NET_RAW
    // (errno 1 = EPERM). Accept ALLOWED (root) or BLOCKED/ERROR:1 (non-root
    // capability denial).
    let trimmed = contents.trim();
    assert!(
        trimmed == "ALLOWED" || trimmed == "BLOCKED" || trimmed == "ERROR:1",
        "ICMP raw socket should be permitted by seccomp under allow_icmp; got: {}",
        trimmed
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 4c. allow_icmp(true) still blocks SOCK_RAW with non-ICMP protocol
//     (verifies the BPF arg2 protocol check)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_allow_icmp_still_blocks_other_raw() {
    let out = temp_out("allow-icmp-blocks-tcp-raw");
    // AF_INET + SOCK_RAW + IPPROTO_TCP must still be denied by seccomp.
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy()
        .allow_icmp(true)
        .build()
        .unwrap();
    let result = Sandbox::run_interactive(&policy, &["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let trimmed = contents.trim();
    // Must be denied — either via seccomp (BLOCKED) or the kernel (EPERM).
    // Critically must NOT be ALLOWED.
    assert_ne!(
        trimmed, "ALLOWED",
        "non-ICMP raw socket must remain denied under allow_icmp; got: {}",
        trimmed
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 5. UDP allowed when allow_udp(true)
// ------------------------------------------------------------------
#[tokio::test]
async fn test_udp_allowed_when_opted_in() {
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

    let policy = base_policy()
        .allow_udp(true)
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
        "UDP socket should be allowed with allow_udp(true), got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 6. UDP denied by default
// ------------------------------------------------------------------
#[tokio::test]
async fn test_udp_denied_by_default() {
    let out = temp_out("udp-denied");
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
        "BLOCKED",
        "UDP should be denied by default; got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 8. TCP always allowed (default deny posture for raw + UDP)
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
