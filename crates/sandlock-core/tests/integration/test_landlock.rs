use sandlock_core::{Sandbox};
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

    let policy = Sandbox::builder()
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
    let result = policy.clone().with_name("test").run_interactive(&["sh", "-c", &cmd_str])
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
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    // /etc is NOT in fs_read, so cat /etc/group should fail
    let result = policy.clone().with_name("test").run(&["cat", "/etc/group"])
        .await
        .unwrap();
    assert!(!result.success(), "cat should fail without /etc in fs_read");
}

#[tokio::test]
async fn test_can_write_to_writable_path() {
    let out = temp_file("write-ok");

    let policy = Sandbox::builder()
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
    let result = policy.clone().with_name("test").run_interactive(&["sh", "-c", &cmd_str])
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

    let policy = Sandbox::builder()
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
    let result = policy.clone().with_name("test").run_interactive(&["sh", "-c", &cmd_str])
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

    let policy = Sandbox::builder()
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

    let result = policy.clone().with_name("test").run(&["cat", input.to_str().unwrap()])
        .await
        .unwrap();
    assert!(!result.success(), "cat should fail on denied path");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_denied_path_blocks_exec() {
    let policy = Sandbox::builder()
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

    let result = policy.clone().with_name("test").run(&["/bin/cat", "/etc/hostname"]).await.unwrap();
    assert!(!result.success(), "exec should fail on denied binary path");
}

#[tokio::test]
async fn test_path_rule_on_regular_file() {
    // A path rule targeting a regular file (not a directory) must not crash
    // child setup. Landlock rejects directory-only access rights (READ_DIR,
    // MAKE_*, REMOVE_*, REFER) on a non-directory with EINVAL, so sandlock
    // must mask the requested access down to the file-applicable set.
    let dir = temp_file("regfile-read-dir");
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("data.txt");
    std::fs::write(&file, "regfile-contents").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(file.to_str().unwrap()) // regular file, not a directory
        .fs_write("/tmp")
        .build()
        .unwrap();

    let result = policy
        .clone()
        .with_name("test")
        .run(&["cat", file.to_str().unwrap()])
        .await
        .unwrap();
    assert!(
        result.success(),
        "a read rule on a regular file should not crash confinement"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_path_rule_on_device_node() {
    // A write rule targeting a device node (/dev/null is a char device, not a
    // directory) must not crash child setup, and the grant must let the child
    // write to it.
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .fs_write("/dev/null") // char device, not a directory
        .build()
        .unwrap();

    let result = policy
        .clone()
        .with_name("test")
        .run_interactive(&["sh", "-c", "echo hi > /dev/null"])
        .await
        .unwrap();
    assert!(
        result.success(),
        "a write rule on a device node should not crash confinement"
    );
}

#[tokio::test]
async fn test_path_rule_on_fifo_does_not_block() {
    // Opening a FIFO with O_RDONLY blocks until a writer appears. add_path_rule
    // must reference the path with O_PATH so a read rule on a FIFO does not hang
    // child setup.
    let dir = temp_file("fifo-dir");
    let _ = std::fs::create_dir_all(&dir);
    let fifo = dir.join("pipe");
    let _ = std::fs::remove_file(&fifo);
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("spawn mkfifo");
    assert!(status.success(), "mkfifo should create the FIFO");

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(fifo.to_str().unwrap()) // FIFO, not a directory
        .fs_write("/tmp")
        .build()
        .unwrap();

    let mut sandbox = policy.clone().with_name("test");
    let run = sandbox.run(&["/bin/true"]);
    let result = tokio::time::timeout(std::time::Duration::from_secs(20), run).await;
    assert!(
        result.is_ok(),
        "a read rule on a FIFO must not block child setup (open with O_PATH)"
    );
    assert!(
        result.unwrap().unwrap().success(),
        "child should run with a FIFO read rule present"
    );

    let _ = std::fs::remove_dir_all(&dir);
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

    let policy = Sandbox::builder()
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

    let _result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &child_script])
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

// Stronger companion to `test_isolate_ipc`: that test catches a bare
// `OSError` and so cannot tell a *contained* connect (Landlock scope ->
// EPERM) apart from a *refused* one (no listener -> ECONNREFUSED), which
// means a silently-dead listener would false-pass. This test removes both
// ambiguities:
//   1. a positive control proves the abstract socket is genuinely reachable
//      from *outside* the sandbox before we test the inside, and
//   2. the in-sandbox connect must fail with the specific errno the
//      `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` scope returns (EPERM), not just
//      "some error".
// So a pass attributes the block to the scope and nothing else.
#[tokio::test]
async fn test_abstract_unix_socket_contained() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let out = temp_file("abstract-sock-result");
    let ready_file = temp_file("abstract-sock-ready");
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);

    let sock_name = format!("sandlock_test_abstract_{}", std::process::id());

    // Host-side listener bound to an abstract-namespace address (leading NUL).
    // It is created *outside* any sandbox, so it lives in the shared host
    // abstract namespace that a netns-less sandbox would otherwise reach.
    let listener_script = format!(
        concat!(
            "import socket, time\n",
            "sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "sock.bind('\\x00{sock_name}')\n",
            "sock.listen(5)\n",
            "open('{ready}', 'w').write('ready')\n",
            "time.sleep(15)\n",
            "sock.close()\n",
        ),
        sock_name = sock_name,
        ready = ready_file.display(),
    );

    let mut listener_proc = std::process::Command::new("python3")
        .args(["-c", &listener_script])
        .spawn()
        .unwrap();

    for _ in 0..100 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready_file.exists(), "listener should signal readiness");

    // Positive control: from this (unsandboxed) test process the abstract
    // socket MUST be connectable. If this fails the listener is broken and
    // the negative result below would be meaningless, so we assert it first.
    {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(sock_name.as_bytes())
            .expect("build abstract socket addr");
        let control = std::os::unix::net::UnixStream::connect_addr(&addr);
        assert!(
            control.is_ok(),
            "positive control: host must be able to reach the abstract socket \
             (got {control:?}); the containment assertion would be meaningless otherwise"
        );
    }

    // In-sandbox connect: record the *exact* errno rather than collapsing
    // every failure to "BLOCKED".
    let child_script = format!(
        concat!(
            "import socket\n",
            "sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "try:\n",
            "    sock.connect('\\x00{sock_name}')\n",
            "    result = 'CONNECTED'\n",
            "except OSError as e:\n",
            "    result = 'ERRNO:%d' % e.errno\n",
            "finally:\n",
            "    sock.close()\n",
            "open('{out}', 'w').write(result)\n",
        ),
        sock_name = sock_name,
        out = out.display(),
    );

    let policy = Sandbox::builder()
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

    policy
        .clone()
        .with_name("test")
        .run_interactive(&["python3", "-c", &child_script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    // EPERM (1) is what LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET returns when a
    // sandboxed task connects to an abstract socket created outside its
    // Landlock domain. Anything else (CONNECTED, or ECONNREFUSED=111, etc.)
    // means the scope did not do the blocking.
    assert_eq!(
        contents, "ERRNO:1",
        "sandboxed connect to an outside abstract socket must be blocked by the \
         abstract-unix-socket scope with EPERM (got {contents:?})"
    );

    let _ = listener_proc.kill();
    let _ = listener_proc.wait();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);
}

// Named (pathname) unix sockets are a gap Landlock does not close: it has no
// access right for connecting to one, so a netns-less sandbox can reach a host
// service socket and escape. Connecting is a WRITE on the socket inode (kernel:
// unix_find_other -> path_permission(MAY_WRITE)), so the sandlock fs gate must
// deny a connect whose path is not covered by an fs-WRITE grant. Here the
// socket's directory is granted fs-READ (so the path resolves) but not write,
// so the connect must fail with EACCES.
#[tokio::test]
async fn test_named_unix_socket_connect_denied_without_fs_write() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    // Socket lives under the cargo target tmpdir (a real host mount visible in
    // the sandbox, unlike the virtualized /tmp), in a dir we grant READ only.
    let sock_dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("named-unixsock-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&sock_dir);
    let sock_path = sock_dir.join("svc.sock");
    let _ = std::fs::remove_file(&sock_path);

    // Result/ready files use the proven /tmp + fs_write("/tmp") pattern.
    let out = temp_file("named-sock-result");
    let ready_file = temp_file("named-sock-ready");
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);

    // Host-side NAMED unix socket listener, created outside any sandbox.
    let listener_script = format!(
        concat!(
            "import socket, time\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "s.bind('{sock}')\n",
            "s.listen(5)\n",
            "open('{ready}', 'w').write('ready')\n",
            "time.sleep(15)\n",
            "s.close()\n",
        ),
        sock = sock_path.display(),
        ready = ready_file.display(),
    );
    let mut listener_proc = std::process::Command::new("python3")
        .args(["-c", &listener_script])
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready_file.exists(), "listener should signal readiness");

    // Positive control: the unsandboxed test process can reach the socket, so a
    // negative result inside the sandbox is attributable to the gate, not a dead
    // listener.
    {
        let control = std::os::unix::net::UnixStream::connect(&sock_path);
        assert!(
            control.is_ok(),
            "positive control: host must reach the named socket (got {control:?})"
        );
    }

    let child_script = format!(
        concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "try:\n",
            "    s.connect('{sock}')\n",
            "    result = 'CONNECTED'\n",
            "except OSError as e:\n",
            "    result = 'ERRNO:%d' % e.errno\n",
            "finally:\n",
            "    s.close()\n",
            "open('{out}', 'w').write(result)\n",
        ),
        sock = sock_path.display(),
        out = out.display(),
    );

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        // socket dir is READable (path resolves) but NOT writable -> connect denied
        .fs_read(sock_dir.to_str().unwrap())
        .build()
        .unwrap();

    policy
        .clone()
        .with_name("test")
        .run_interactive(&["python3", "-c", &child_script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    // EACCES (13) mirrors the kernel's own DAC for connecting to a socket
    // without write permission. CONNECTED means the gap is still open;
    // ERRNO:2 (ENOENT) would mean the path wasn't even visible (test bug).
    assert_eq!(
        contents, "ERRNO:13",
        "connect to a named unix socket with no fs-write grant must be denied with EACCES (got {contents:?})"
    );

    let _ = listener_proc.kill();
    let _ = listener_proc.wait();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_dir_all(&sock_dir);
}

// Selectivity guard for the gate above: the same connect that is denied under
// an fs-READ grant must SUCCEED when the socket's directory is fs-WRITE granted.
// This pins the gate to write permission (mirroring the kernel's DAC) and stops
// a future regression from turning the gate into a blanket deny-all.
#[tokio::test]
async fn test_named_unix_socket_connect_allowed_with_fs_write() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let sock_dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("named-unixsock-rw-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&sock_dir);
    let sock_path = sock_dir.join("svc.sock");
    let _ = std::fs::remove_file(&sock_path);

    let out = temp_file("named-sock-rw-result");
    let ready_file = temp_file("named-sock-rw-ready");
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);

    let listener_script = format!(
        concat!(
            "import socket, time\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "s.bind('{sock}')\n",
            "s.listen(5)\n",
            "open('{ready}', 'w').write('ready')\n",
            "time.sleep(15)\n",
            "s.close()\n",
        ),
        sock = sock_path.display(),
        ready = ready_file.display(),
    );
    let mut listener_proc = std::process::Command::new("python3")
        .args(["-c", &listener_script])
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready_file.exists(), "listener should signal readiness");

    let child_script = format!(
        concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "try:\n",
            "    s.connect('{sock}')\n",
            "    result = 'CONNECTED'\n",
            "except OSError as e:\n",
            "    result = 'ERRNO:%d' % e.errno\n",
            "finally:\n",
            "    s.close()\n",
            "open('{out}', 'w').write(result)\n",
        ),
        sock = sock_path.display(),
        out = out.display(),
    );

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        // socket dir is WRITE granted -> connect permitted
        .fs_write(sock_dir.to_str().unwrap())
        .build()
        .unwrap();

    policy
        .clone()
        .with_name("test")
        .run_interactive(&["python3", "-c", &child_script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(
        contents, "CONNECTED",
        "connect to a named unix socket under an fs-write grant must be permitted (got {contents:?})"
    );

    let _ = listener_proc.kill();
    let _ = listener_proc.wait();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_dir_all(&sock_dir);
}

// Allow-path hardening (stage 2): a symlink inside a WRITE-granted directory
// whose real target is a socket OUTSIDE the grants must not be a bypass. A
// lexical check on the symlink's own path would see only the in-grant location
// and permit it; the decision must be made on the symlink's REAL target, which
// is ungranted, so the connect must be denied with EACCES.
#[tokio::test]
async fn test_named_unix_socket_symlink_escape_denied() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("named-unixsock-symlink-{}", std::process::id()));
    let granted = base.join("granted"); // fs_write granted
    let outside = base.join("outside"); // NOT granted: the escape target
    let _ = std::fs::create_dir_all(&granted);
    let _ = std::fs::create_dir_all(&outside);
    let real_sock = outside.join("real.sock");
    let link_sock = granted.join("link.sock");
    let _ = std::fs::remove_file(&real_sock);
    let _ = std::fs::remove_file(&link_sock);
    std::os::unix::fs::symlink(&real_sock, &link_sock).unwrap();

    let out = temp_file("named-sock-symlink-result");
    let ready_file = temp_file("named-sock-symlink-ready");
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);

    // Listener binds the REAL socket, in the ungranted directory.
    let listener_script = format!(
        concat!(
            "import socket, time\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "s.bind('{sock}')\n",
            "s.listen(5)\n",
            "open('{ready}', 'w').write('ready')\n",
            "time.sleep(15)\n",
            "s.close()\n",
        ),
        sock = real_sock.display(),
        ready = ready_file.display(),
    );
    let mut listener_proc = std::process::Command::new("python3")
        .args(["-c", &listener_script])
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if ready_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready_file.exists(), "listener should signal readiness");

    // Positive control: the symlink really does resolve and connect from outside
    // the sandbox, so the escape path is live and the sandbox must refuse it.
    {
        let control = std::os::unix::net::UnixStream::connect(&link_sock);
        assert!(
            control.is_ok(),
            "positive control: symlink must resolve+connect from host (got {control:?})"
        );
    }

    // Child connects to the in-grant SYMLINK; its real target is ungranted.
    let child_script = format!(
        concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n",
            "try:\n",
            "    s.connect('{sock}')\n",
            "    result = 'CONNECTED'\n",
            "except OSError as e:\n",
            "    result = 'ERRNO:%d' % e.errno\n",
            "finally:\n",
            "    s.close()\n",
            "open('{out}', 'w').write(result)\n",
        ),
        sock = link_sock.display(),
        out = out.display(),
    );

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        // the symlink's directory is writable; the real target's dir is NOT granted
        .fs_write(granted.to_str().unwrap())
        .build()
        .unwrap();

    policy
        .clone()
        .with_name("test")
        .run_interactive(&["python3", "-c", &child_script])
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&out).unwrap_or_default();
    assert_eq!(
        contents, "ERRNO:13",
        "a symlink to an ungranted socket must be denied on its real target (got {contents:?})"
    );

    let _ = listener_proc.kill();
    let _ = listener_proc.wait();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);
    let _ = std::fs::remove_file(&real_sock);
    let _ = std::fs::remove_file(&link_sock);
    let _ = std::fs::remove_dir_all(&base);
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

    let policy = Sandbox::builder()
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

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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

    let policy = Sandbox::builder()
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

    let result = policy.clone().with_name("test").run_interactive(&["python3", "-c", &script])
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
