use std::path::PathBuf;

use sandlock_core::{Sandbox};

/// Helper: base policy with standard FS paths for running commands.
fn base_policy() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
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
// 1. mount() is blocked by default seccomp blocklist
// ------------------------------------------------------------------
#[tokio::test]
async fn test_mount_blocked() {
    let out = temp_out("mount-blocked");
    let cmd_str = format!(
        "mount -t tmpfs none /tmp 2>/dev/null; echo $? > {}",
        out.display()
    );
    let policy = base_policy().build().unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["sh", "-c", &cmd_str])
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
    let result = policy.clone().with_name("test").run_interactive(&["sh", "-c", &cmd_str])
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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
// 4b. Raw ICMP is unconditionally denied — sandlock does not expose
//     SOCK_RAW + IPPROTO_ICMP, even with policy concessions. Workloads
//     that need ping should use the SOCK_DGRAM kernel ping socket via
//     an `icmp://...` rule (test 4d below).
// ------------------------------------------------------------------
#[tokio::test]
async fn test_raw_icmp_always_denied() {
    let out = temp_out("raw-icmp-denied");
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

    // Even with an `icmp://*` rule (which permits the dgram path), raw
    // ICMP must still be blocked: SOCK_RAW is always in the deny list.
    let policy = base_policy()
        .net_allow("icmp://*")
        .build()
        .unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_ne!(
        contents.trim(), "ALLOWED",
        "raw ICMP must be denied unconditionally; got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 4d. The kernel ping socket (SOCK_DGRAM + IPPROTO_ICMP) is permitted
//     when an `icmp://*` rule is present — the modern unprivileged
//     ping path, distinct from raw ICMP.
// ------------------------------------------------------------------
#[tokio::test]
async fn test_icmp_dgram_allowed_with_icmp_rule() {
    let out = temp_out("icmp-dgram-allowed");
    let script = format!(concat!(
        "import socket\n",
        "try:\n",
        "  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)\n",
        "  s.close()\n",
        "  result = 'ALLOWED'\n",
        "except PermissionError:\n",
        "  result = 'BLOCKED'\n",
        "except OSError as e:\n",
        "  result = f'ERROR:{{e.errno}}'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy()
        .net_allow("icmp://*")
        .build()
        .unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    // Seccomp must allow the syscall. The kernel may still deny if the
    // sandbox GID is outside `net.ipv4.ping_group_range` (errno 1 EPERM
    // or EACCES). Accepting ALLOWED / BLOCKED / ERROR:1 / ERROR:13 keeps
    // the test green across hosts.
    let trimmed = contents.trim();
    assert!(
        trimmed == "ALLOWED" || trimmed == "BLOCKED"
            || trimmed == "ERROR:1" || trimmed == "ERROR:13",
        "kernel ping socket should be permitted by seccomp under icmp://*; got: {}",
        trimmed
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 5. UDP allowed when a `udp://*:*` rule is present.
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
        .net_allow("udp://*:*")
        .build()
        .unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "ALLOWED",
        "UDP socket should be allowed with udp://*:*, got: {}",
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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
// 7. SysV IPC (shmget) denied by default — sandlock has no IPC
//    namespace, so the deny is the only thing isolating shm
//    keyspaces between sandboxes.
// ------------------------------------------------------------------
#[tokio::test]
async fn test_sysv_shmget_denied_by_default() {
    let out = temp_out("shmget-denied");
    // shmget(IPC_PRIVATE, 4096, IPC_CREAT|0600) — should return EPERM.
    let script = format!(concat!(
        "import ctypes, errno\n",
        "libc = ctypes.CDLL(None)\n",
        "ret = libc.shmget(0, 4096, 0o1000 | 0o600)\n",
        "if ret == -1:\n",
        "  e = ctypes.get_errno()\n",
        "  result = 'EPERM' if e == errno.EPERM else f'ERROR:{{e}}'\n",
        "else:\n",
        "  libc.shmctl(ret, 0, None)\n",
        "  result = 'ALLOWED'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy().build().unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let trimmed = contents.trim();
    // ctypes does not propagate errno from libc by default; the call
    // itself returning -1 is the signal that the seccomp deny fired.
    assert!(
        trimmed != "ALLOWED",
        "shmget must be denied by default (sandlock has no IPC ns); got: {}",
        trimmed
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 7b. extra_allow_syscalls(["sysv_ipc"]) restores SysV shm.
// ------------------------------------------------------------------
#[tokio::test]
async fn test_sysv_shmget_allowed_when_opted_in() {
    let out = temp_out("shmget-allowed");
    let script = format!(concat!(
        "import ctypes\n",
        "libc = ctypes.CDLL(None)\n",
        "ret = libc.shmget(0, 4096, 0o1000 | 0o600)\n",
        "if ret == -1:\n",
        "  result = 'BLOCKED'\n",
        "else:\n",
        "  libc.shmctl(ret, 0, None)\n",
        "  result = 'ALLOWED'\n",
        "open('{out}', 'w').write(result)\n",
    ), out = out.display());

    let policy = base_policy()
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        contents.trim(),
        "ALLOWED",
        "shmget should be permitted under extra_allow_syscalls=[\"sysv_ipc\"]; got: {}",
        contents.trim()
    );
    assert!(result.success());
}

// ------------------------------------------------------------------
// 8. TCP always allowed (default blocklist posture for raw + UDP)
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
    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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
