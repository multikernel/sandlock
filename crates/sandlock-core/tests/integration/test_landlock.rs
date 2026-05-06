use sandlock_core::{Policy, Sandbox};
use std::path::PathBuf;

fn temp_file(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sandlock-test-landlock-{}-{}",
        name,
        std::process::id()
    ))
}

#[tokio::test]
async fn test_can_read_allowed_path() {
    let dir = temp_file("read-allowed-dir");
    let _ = std::fs::create_dir_all(&dir);
    let input = dir.join("input.txt");
    std::fs::write(&input, "sandlock-read-test").unwrap();

    let out = temp_file("read-allowed-out");

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(dir.to_str().unwrap())
        .fs_write("/tmp")
        .build()
        .unwrap();

    let cmd_str = format!("cat {} > {}", input.display(), out.display());
    let result = Sandbox::run_interactive(&policy, Some("test"), &["sh", "-c", &cmd_str])
        .await
        .unwrap();
    assert!(result.success(), "cat should succeed for allowed path");

    let contents = std::fs::read_to_string(&out).unwrap();
    assert_eq!(contents, "sandlock-read-test");

    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_cannot_read_outside_allowed() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    // /etc is NOT in fs_read, so cat /etc/os-release should fail
    let result = Sandbox::run(&policy, Some("test"), &["cat", "/etc/os-release"])
        .await
        .unwrap();
    assert!(!result.success(), "cat should fail without /etc in fs_read");
}

#[tokio::test]
async fn test_can_write_to_writable_path() {
    let out = temp_file("write-ok");

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let cmd_str = format!("echo hello > {}", out.display());
    let result = Sandbox::run_interactive(&policy, Some("test"), &["sh", "-c", &cmd_str])
        .await
        .unwrap();
    assert!(result.success(), "writing to /tmp should succeed");

    let contents = std::fs::read_to_string(&out).unwrap();
    assert_eq!(contents.trim(), "hello");

    let _ = std::fs::remove_file(&out);
}

#[tokio::test]
async fn test_cannot_write_to_readonly_path() {
    let dir = temp_file("readonly-dir");
    let _ = std::fs::create_dir_all(&dir);

    let target = dir.join("nope.txt");

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(dir.to_str().unwrap())
        .fs_write("/tmp")
        .build()
        .unwrap();

    // dir is read-only, writing should fail
    let cmd_str = format!("echo nope > {} 2>/dev/null", target.display());
    let result = Sandbox::run_interactive(&policy, Some("test"), &["sh", "-c", &cmd_str])
        .await
        .unwrap();
    assert!(!result.success(), "writing to read-only dir should fail");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_denied_path_blocks_read() {
    let dir = temp_file("deny-dir");
    let _ = std::fs::create_dir_all(&dir);
    let input = dir.join("secret.txt");
    std::fs::write(&input, "secret-data").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(dir.to_str().unwrap())
        .fs_deny(input.to_str().unwrap())
        .fs_write("/tmp")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, Some("test"), &["cat", input.to_str().unwrap()])
        .await
        .unwrap();
    assert!(!result.success(), "cat should fail on denied path");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_denied_path_blocks_exec() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_deny("/bin/cat")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let result = Sandbox::run(&policy, Some("test"), &["/bin/cat", "/etc/hostname"]).await.unwrap();
    assert!(!result.success(), "exec should fail on denied binary path");
}

#[tokio::test]
async fn test_isolate_ipc() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let out = temp_file("ipc-result");
    let ready_file = temp_file("ipc-ready");
    let _ = std::fs::remove_file(&ready_file);

    let sock_name = format!("sandlock_test_ipc_{}", std::process::id());

    // Spawn a parent-side Python process that creates an abstract unix socket listener
    let listener_script = format!(
        concat!(
            "import socket, time, os\n",
            "sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "sock.bind('\\x00{sock_name}')\n",
            "sock.listen(1)\n",
            "open('{ready}', 'w').write('ready')\n",
            "time.sleep(10)\n",
            "sock.close()\n",
        ),
        sock_name = sock_name,
        ready = ready_file.display(),
    );

    let mut listener_proc = std::process::Command::new("python3")
        .args(["-c", &listener_script])
        .spawn()
        .unwrap();

    // Wait for the listener to be ready
    for _ in 0..100 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready_file.exists(), "Listener should signal readiness");

    // Child sandbox tries to connect to the abstract socket
    let child_script = format!(
        concat!(
            "import socket\n",
            "sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "try:\n",
            "    sock.connect('\\x00{sock_name}')\n",
            "    result = 'CONNECTED'\n",
            "except (ConnectionRefusedError, FileNotFoundError, PermissionError, OSError):\n",
            "    result = 'BLOCKED'\n",
            "finally:\n",
            "    sock.close()\n",
            "open('{out}', 'w').write(result)\n",
        ),
        sock_name = sock_name,
        out = out.display(),
    );

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")

        .build()
        .unwrap();

    let _result = Sandbox::run_interactive(&policy, Some("test"), &["python3", "-c", &child_script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(
        contents, "BLOCKED",
        "IPC isolation should block connecting to parent abstract socket"
    );

    let _ = listener_proc.kill();
    let _ = listener_proc.wait();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);
}

#[tokio::test]
async fn test_isolate_signals_blocks_parent() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let out = temp_file("signal-parent");

    let script = format!(
        concat!(
            "import os\n",
            "try:\n",
            "    os.kill({ppid}, 0)\n",
            "    result = 'ALLOWED'\n",
            "except PermissionError:\n",
            "    result = 'BLOCKED'\n",
            "except OSError:\n",
            "    result = 'ERROR'\n",
            "open('{out}', 'w').write(result)\n",
        ),
        ppid = std::process::id(),
        out = out.display(),
    );

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")

        .build()
        .unwrap();

    let result = Sandbox::run_interactive(&policy, Some("test"), &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "python script should exit 0");

    let contents = std::fs::read_to_string(&out).unwrap();
    assert_eq!(
        contents, "BLOCKED",
        "signal isolation should block signaling parent"
    );

    let _ = std::fs::remove_file(&out);
}

#[tokio::test]
async fn test_isolate_signals_allows_self() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let out = temp_file("signal-self");

    let script = format!(
        concat!(
            "import os\n",
            "try:\n",
            "    os.kill(os.getpid(), 0)\n",
            "    result = 'ALLOWED'\n",
            "except PermissionError:\n",
            "    result = 'BLOCKED'\n",
            "except OSError:\n",
            "    result = 'ERROR'\n",
            "open('{out}', 'w').write(result)\n",
        ),
        out = out.display(),
    );

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")

        .build()
        .unwrap();

    let result = Sandbox::run_interactive(&policy, Some("test"), &["python3", "-c", &script])
        .await
        .unwrap();
    assert!(result.success(), "python script should exit 0");

    let contents = std::fs::read_to_string(&out).unwrap();
    assert_eq!(
        contents, "ALLOWED",
        "signal isolation should allow signaling self"
    );

    let _ = std::fs::remove_file(&out);
}
