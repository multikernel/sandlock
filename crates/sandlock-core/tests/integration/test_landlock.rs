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

// Datagram vector: a unix SOCK_DGRAM `sendto()` to a named socket reaches it
// without a prior connect(), and is a WRITE on the target inode just like
// connect. The gate must cover it too: a sendto to a socket whose path is not
// under an fs-write grant must be denied with EACCES.
#[tokio::test]
async fn test_named_unix_dgram_sendto_denied_without_fs_write() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let sock_dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("named-unixdgram-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&sock_dir);
    let sock_path = sock_dir.join("svc.dgram");
    let _ = std::fs::remove_file(&sock_path);

    let out = temp_file("named-dgram-result");
    let ready_file = temp_file("named-dgram-ready");
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);

    // Host-side NAMED datagram socket, bound outside any sandbox.
    let listener_script = format!(
        concat!(
            "import socket, time\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n",
            "s.bind('{sock}')\n",
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
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n",
            "try:\n",
            "    s.sendto(b'escape', '{sock}')\n",
            "    result = 'SENT'\n",
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
        // socket dir is READable but NOT writable -> sendto denied
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
    assert_eq!(
        contents, "ERRNO:13",
        "sendto to a named dgram socket with no fs-write grant must be denied with EACCES (got {contents:?})"
    );

    let _ = listener_proc.kill();
    let _ = listener_proc.wait();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_dir_all(&sock_dir);
}

// sendmsg() is an equivalent datagram path to sendto() (the address sits in
// msg_name), so it must be gated too or it is a trivial bypass. A sendmsg to a
// named socket outside the fs-write grants must be denied with EACCES.
#[tokio::test]
async fn test_named_unix_dgram_sendmsg_denied_without_fs_write() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let sock_dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("named-unixmsg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&sock_dir);
    let sock_path = sock_dir.join("svc.dgram");
    let _ = std::fs::remove_file(&sock_path);

    let out = temp_file("named-msg-result");
    let ready_file = temp_file("named-msg-ready");
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);

    let listener_script = format!(
        concat!(
            "import socket, time\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n",
            "s.bind('{sock}')\n",
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

    // sendmsg with msg_name set to the named socket address.
    let child_script = format!(
        concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n",
            "try:\n",
            "    s.sendmsg([b'escape'], [], 0, '{sock}')\n",
            "    result = 'SENT'\n",
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
    assert_eq!(
        contents, "ERRNO:13",
        "sendmsg to a named dgram socket with no fs-write grant must be denied with EACCES (got {contents:?})"
    );

    let _ = listener_proc.kill();
    let _ = listener_proc.wait();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_dir_all(&sock_dir);
}

// Allow+delivery guard for the datagram on-behalf send paths: a sendto/sendmsg
// to a socket UNDER a write grant must not only be permitted but actually
// deliver the payload (the supervisor performs the send on-behalf). Exercises
// the success path of sendto_named_unix_on_behalf / sendmsg_named_unix_on_behalf
// that the deny tests never reach. `which` selects the syscall; `net_allow` adds
// an IP destination rule so the same delivery can be asserted with a destination
// policy active.
async fn dgram_allow_delivers(which: &str, tag: &str, net_allow: Option<&str>) {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let sock_dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("named-dgram-allow-{}-{}", tag, std::process::id()));
    let _ = std::fs::create_dir_all(&sock_dir);
    let sock_path = sock_dir.join("svc.dgram");
    let _ = std::fs::remove_file(&sock_path);

    let out = temp_file(&format!("dgram-allow-{tag}-result"));
    let ready_file = temp_file(&format!("dgram-allow-{tag}-ready"));
    let recv_file = temp_file(&format!("dgram-allow-{tag}-recv"));
    for f in [&out, &ready_file, &recv_file] {
        let _ = std::fs::remove_file(f);
    }

    // Listener receives one datagram and records the payload it got.
    let listener_script = format!(
        concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n",
            "s.bind('{sock}')\n",
            "s.settimeout(12)\n",
            "open('{ready}', 'w').write('ready')\n",
            "try:\n",
            "    data, _ = s.recvfrom(64)\n",
            "    open('{recv}', 'w').write(data.decode())\n",
            "except socket.timeout:\n",
            "    open('{recv}', 'w').write('TIMEOUT')\n",
            "s.close()\n",
        ),
        sock = sock_path.display(),
        ready = ready_file.display(),
        recv = recv_file.display(),
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

    let send_call = if which == "sendmsg" {
        format!("s.sendmsg([b'payload-42'], [], 0, '{}')", sock_path.display())
    } else {
        format!("s.sendto(b'payload-42', '{}')", sock_path.display())
    };
    let child_script = format!(
        concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n",
            "try:\n",
            "    {send_call}\n",
            "    result = 'SENT'\n",
            "except OSError as e:\n",
            "    result = 'ERRNO:%d' % e.errno\n",
            "finally:\n",
            "    s.close()\n",
            "open('{out}', 'w').write(result)\n",
        ),
        send_call = send_call,
        out = out.display(),
    );

    let builder = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        // socket dir is WRITE granted -> send permitted, on-behalf
        .fs_write(sock_dir.to_str().unwrap());
    // A non-empty net_allow turns on the destination policy, which is what makes
    // the sendto/sendmsg handlers take their on-behalf paths for every send —
    // including this unix datagram, whose destination the IP allowlist cannot
    // describe.
    let builder = match net_allow {
        Some(rule) => builder.net_allow(rule),
        None => builder,
    };
    let policy = builder.build().unwrap();

    policy
        .clone()
        .with_name("test")
        .run_interactive(&["python3", "-c", &child_script])
        .await
        .unwrap();

    assert_eq!(
        std::fs::read_to_string(&out).unwrap_or_default(),
        "SENT",
        "{which} to a write-granted dgram socket must be permitted"
    );

    // Wait for the listener to record the delivered payload.
    for _ in 0..100 {
        if recv_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = listener_proc.wait();
    assert_eq!(
        std::fs::read_to_string(&recv_file).unwrap_or_default(),
        "payload-42",
        "{which} on-behalf send must actually deliver the payload"
    );

    let _ = listener_proc.kill();
    for f in [&out, &ready_file, &recv_file, &sock_path] {
        let _ = std::fs::remove_file(f);
    }
    let _ = std::fs::remove_dir_all(&sock_dir);
}

#[tokio::test]
async fn test_named_unix_dgram_sendto_allowed_delivers() {
    dgram_allow_delivers("sendto", "to", None).await;
}

#[tokio::test]
async fn test_named_unix_dgram_sendmsg_allowed_delivers() {
    dgram_allow_delivers("sendmsg", "msg", None).await;
}

/// Same delivery guarantee with an IP destination policy active. A non-empty
/// `net_allow` makes `has_net_destination_policy` true, which is the switch that
/// routes every sendto through the non-IP arm of `sendto_on_behalf` instead of
/// letting it Continue — the arm that resolves the destination in the child's
/// root view and pins the target inode. This is the happy path both hardening
/// changes sit on: a named unix datagram must still be delivered, byte-for-byte,
/// to the socket the child named. It is also the regression witness for the
/// resolution context — a handler that hands the child's raw `sun_path` to the
/// supervisor's `sendmsg` delivers to whatever that path names next to the
/// supervisor, so a relative or child-relative destination silently misses.
#[tokio::test]
async fn test_named_unix_dgram_sendto_delivers_under_destination_policy() {
    dgram_allow_delivers("sendto", "to-netpolicy", Some("127.0.0.1:9")).await;
}

// `sendmmsg()` (batched datagram send) is the last named-unix vector and Python
// has no binding for it, so the child drives it via ctypes. Its handler used to
// Continue the whole call whenever any entry was non-IP, which let a unix entry
// bypass the gate. A sendmmsg whose entry targets a socket outside the fs-write
// grants must be denied (EACCES).
#[tokio::test]
async fn test_named_unix_dgram_sendmmsg_denied_without_fs_write() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let sock_dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("named-unixmmsg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&sock_dir);
    let sock_path = sock_dir.join("svc.dgram");
    let _ = std::fs::remove_file(&sock_path);

    let out = temp_file("named-mmsg-result");
    let ready_file = temp_file("named-mmsg-ready");
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);

    let listener_script = format!(
        concat!(
            "import socket, time\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n",
            "s.bind('{sock}')\n",
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

    let child_script = format!("{}{}", sendmmsg_ctypes_preamble(), format!(
        concat!(
            "rc = send_one('{sock}', b'escape')\n",
            "open('{out}', 'w').write(rc)\n",
        ),
        sock = sock_path.display(),
        out = out.display(),
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
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
    assert_eq!(
        contents, "ERRNO:13",
        "sendmmsg to a named dgram socket with no fs-write grant must be denied with EACCES (got {contents:?})"
    );

    let _ = listener_proc.kill();
    let _ = listener_proc.wait();
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&ready_file);
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_dir_all(&sock_dir);
}

// Python ctypes preamble defining `send_one(path, data)` which issues a
// single-entry `sendmmsg()` to a named AF_UNIX address and returns
// "SENT:<n>" or "ERRNO:<e>".
fn sendmmsg_ctypes_preamble() -> &'static str {
    concat!(
        "import ctypes, socket, struct\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "class iovec(ctypes.Structure):\n",
        "    _fields_ = [('iov_base', ctypes.c_void_p), ('iov_len', ctypes.c_size_t)]\n",
        "class msghdr(ctypes.Structure):\n",
        "    _fields_ = [('msg_name', ctypes.c_void_p), ('msg_namelen', ctypes.c_uint),\n",
        "                ('msg_iov', ctypes.c_void_p), ('msg_iovlen', ctypes.c_size_t),\n",
        "                ('msg_control', ctypes.c_void_p), ('msg_controllen', ctypes.c_size_t),\n",
        "                ('msg_flags', ctypes.c_int)]\n",
        "class mmsghdr(ctypes.Structure):\n",
        "    _fields_ = [('msg_hdr', msghdr), ('msg_len', ctypes.c_uint)]\n",
        "def send_one(path, data):\n",
        "    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n",
        "    sun = struct.pack('H', socket.AF_UNIX) + path.encode() + b'\\x00'\n",
        "    sun_buf = ctypes.create_string_buffer(sun, len(sun))\n",
        "    buf = ctypes.create_string_buffer(data, len(data))\n",
        "    iov = iovec(ctypes.cast(buf, ctypes.c_void_p), len(data))\n",
        "    mm = mmsghdr()\n",
        "    mm.msg_hdr.msg_name = ctypes.cast(sun_buf, ctypes.c_void_p)\n",
        "    mm.msg_hdr.msg_namelen = len(sun)\n",
        "    mm.msg_hdr.msg_iov = ctypes.cast(ctypes.pointer(iov), ctypes.c_void_p)\n",
        "    mm.msg_hdr.msg_iovlen = 1\n",
        "    ctypes.set_errno(0)\n",
        "    r = libc.sendmmsg(s.fileno(), ctypes.byref(mm), 1, 0)\n",
        "    s.close()\n",
        "    return 'ERRNO:%d' % ctypes.get_errno() if r < 0 else 'SENT:%d' % r\n",
    )
}

// Allow+delivery guard for the sendmmsg on-behalf path: to a write-granted
// socket the batched send must be permitted AND deliver the payload (exercises
// sendmmsg_named_unix_on_behalf's success path, which the deny test misses).
#[tokio::test]
async fn test_named_unix_dgram_sendmmsg_allowed_delivers() {
    if sandlock_core::landlock_abi_version().unwrap_or(0) < 6 {
        eprintln!("Skipping: Landlock ABI v6 required");
        return;
    }

    let sock_dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("named-unixmmsg-rw-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&sock_dir);
    let sock_path = sock_dir.join("svc.dgram");
    let _ = std::fs::remove_file(&sock_path);

    let out = temp_file("named-mmsg-rw-result");
    let ready_file = temp_file("named-mmsg-rw-ready");
    let recv_file = temp_file("named-mmsg-rw-recv");
    for f in [&out, &ready_file, &recv_file] {
        let _ = std::fs::remove_file(f);
    }

    let listener_script = format!(
        concat!(
            "import socket\n",
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n",
            "s.bind('{sock}')\n",
            "s.settimeout(12)\n",
            "open('{ready}', 'w').write('ready')\n",
            "try:\n",
            "    data, _ = s.recvfrom(64)\n",
            "    open('{recv}', 'w').write(data.decode())\n",
            "except socket.timeout:\n",
            "    open('{recv}', 'w').write('TIMEOUT')\n",
            "s.close()\n",
        ),
        sock = sock_path.display(),
        ready = ready_file.display(),
        recv = recv_file.display(),
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

    let child_script = format!("{}{}", sendmmsg_ctypes_preamble(), format!(
        concat!(
            "rc = send_one('{sock}', b'payload-42')\n",
            "open('{out}', 'w').write(rc)\n",
        ),
        sock = sock_path.display(),
        out = out.display(),
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .fs_write(sock_dir.to_str().unwrap())
        .build()
        .unwrap();

    policy
        .clone()
        .with_name("test")
        .run_interactive(&["python3", "-c", &child_script])
        .await
        .unwrap();

    assert_eq!(
        std::fs::read_to_string(&out).unwrap_or_default(),
        "SENT:1",
        "sendmmsg to a write-granted dgram socket must be permitted"
    );
    for _ in 0..100 {
        if recv_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = listener_proc.wait();
    assert_eq!(
        std::fs::read_to_string(&recv_file).unwrap_or_default(),
        "payload-42",
        "sendmmsg on-behalf send must actually deliver the payload"
    );

    let _ = listener_proc.kill();
    for f in [&out, &ready_file, &recv_file, &sock_path] {
        let _ = std::fs::remove_file(f);
    }
    let _ = std::fs::remove_dir_all(&sock_dir);
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

#[tokio::test]
async fn test_deny_carveout_on_behalf_open_preserves_io() {
    // Issue #111: with a deny active, openat/open run on-behalf in the
    // supervisor (race-free) instead of Continue-ing to the kernel. This
    // checks that the new path preserves normal I/O — allowed reads, allowed
    // creates — while the denied carve-out inside the granted tree stays
    // blocked.
    let dir = temp_file("deny-onbehalf-dir");
    let _ = std::fs::create_dir_all(&dir);
    let ok = dir.join("ok.txt");
    let secret = dir.join("secret.txt");
    std::fs::write(&ok, "ok-data").unwrap();
    std::fs::write(&secret, "secret-data").unwrap();
    let created = dir.join("created.txt");
    let _ = std::fs::remove_file(&created);

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(dir.to_str().unwrap()) // grant the whole tree writable
        .fs_deny(secret.to_str().unwrap()) // carve-out inside the grant
        .build()
        .unwrap();

    // Allowed read still works (on-behalf probe + reopen path).
    let r = policy
        .clone()
        .with_name("t")
        .run(&["cat", ok.to_str().unwrap()])
        .await
        .unwrap();
    assert!(r.success(), "allowed read must work through on-behalf open");

    // Allowed create still works (on-behalf O_CREAT parent-resolve path).
    let cmd = format!("echo hi > {}", created.display());
    let w = policy
        .clone()
        .with_name("t")
        .run_interactive(&["sh", "-c", &cmd])
        .await
        .unwrap();
    assert!(w.success(), "allowed create must work through on-behalf open");
    assert_eq!(std::fs::read_to_string(&created).unwrap().trim(), "hi");

    // The denied carve-out stays blocked.
    let d = policy
        .clone()
        .with_name("t")
        .run(&["cat", secret.to_str().unwrap()])
        .await
        .unwrap();
    assert!(!d.success(), "denied carve-out must stay blocked");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_deny_openat2_does_not_bypass() {
    // Issue #111 follow-up: openat2 must be trapped and subject to the deny
    // just like openat. A program calling openat2 directly (glibc normally
    // does not) must not escape a deny carve-out, and openat2 of an allowed
    // sibling must still work. SYS_openat2 = 437 (x86_64 test host).
    let dir = temp_file("deny-openat2-dir");
    let _ = std::fs::create_dir_all(&dir);
    let ok = dir.join("ok.txt");
    let secret = dir.join("secret.txt");
    std::fs::write(&ok, "ok-data").unwrap();
    std::fs::write(&secret, "secret-data").unwrap();

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(dir.to_str().unwrap())
        .fs_deny(secret.to_str().unwrap())
        .fs_write("/tmp")
        .build()
        .unwrap();

    // raw openat2(AT_FDCWD, path, &open_how{O_RDONLY,0,0}, 24)
    let script = format!(
        "import ctypes, struct, sys\n\
         libc = ctypes.CDLL(None, use_errno=True)\n\
         def openat2(p):\n\
         \x20   how = struct.pack('QQQ', 0, 0, 0)\n\
         \x20   buf = ctypes.create_string_buffer(how, len(how))\n\
         \x20   return libc.syscall(437, -100, ctypes.c_char_p(p.encode()), buf, ctypes.c_size_t(len(how)))\n\
         secret = openat2('{}')\n\
         allowed = openat2('{}')\n\
         sys.exit(0 if (secret < 0 and allowed >= 0) else 1)\n",
        secret.display(),
        ok.display(),
    );

    let r = policy
        .clone()
        .with_name("t")
        .run(&["python3", "-c", &script])
        .await
        .unwrap();
    assert!(
        r.success(),
        "openat2 must be denied for the carve-out and allowed for the sibling"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
