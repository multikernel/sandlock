// Each test here spawns a full `sandlock` process.
// Running all tests in parallel exhausts kernel resources on most hosts.
// Limit parallelism when running this suite:
//   cargo test -p sandlock-cli --test learn_integration -- --test-threads=4

use std::process::Command;
use std::time::Duration;

fn sandlock_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sandlock"))
}

fn udp_sink(expected_datagrams: usize) -> (u16, std::thread::JoinHandle<usize>) {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp sink bind");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("udp sink timeout");
    let port = sock.local_addr().expect("udp sink addr").port();
    let handle = std::thread::spawn(move || {
        let mut buf = [0_u8; 64];
        let mut received = 0;
        while received < expected_datagrams {
            match sock.recv_from(&mut buf) {
                Ok(_) => received += 1,
                Err(_) => break,
            }
        }
        received
    });
    (port, handle)
}

fn learn_then_run_script(profile_path: &str, script: &str) {
    let learn = sandlock_bin()
        .args(["learn", "-o", profile_path, "--", "python3", "-c", script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        learn.status.success(),
        "learn failed: {}",
        String::from_utf8_lossy(&learn.stderr)
    );

    let run = sandlock_bin()
        .args(["run", "--profile-file", profile_path, "--", "python3", "-c", script])
        .output()
        .expect("failed to run sandlock run");
    assert!(
        run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// Learn → run with a read-only workload.
#[test]
fn test_learn_then_run() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();

    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(),
        "learn failed: stderr={}", String::from_utf8_lossy(&learn.stderr));

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(),
        "run failed: stderr={}", String::from_utf8_lossy(&run.stderr));
    assert!(!String::from_utf8_lossy(&run.stdout).trim().is_empty(),
        "expected output from cat /etc/hostname");
}

/// Connected UDP send: an address-less send confirms the earlier UDP connect
/// as real traffic, so the generated profile must replay.
#[test]
fn test_learn_then_run_connected_udp_send() {
    let (port, sink) = udp_sink(2);
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let script = format!(
        "import socket\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         s.connect(('127.0.0.1', {port}))\n\
         s.send(b'x')\n\
         s.close()\n"
    );

    learn_then_run_script(&profile_path, &script);
    let profile_toml = std::fs::read_to_string(&profile_path).expect("profile");
    assert!(
        profile_toml.contains(&format!("udp://127.0.0.1:{port}")),
        "expected connected UDP endpoint in profile:\n{profile_toml}"
    );
    assert_eq!(sink.join().unwrap(), 2, "learn and run should each send one UDP datagram");
}

/// A connect observed on one thread and a send observed on a sibling thread
/// still refer to the same process fd table.
#[test]
fn test_learn_then_run_connected_udp_send_from_thread() {
    let (port, sink) = udp_sink(2);
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let script = format!(
        "import socket, threading\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         s.connect(('127.0.0.1', {port}))\n\
         t = threading.Thread(target=lambda: s.send(b'x'))\n\
         t.start()\n\
         t.join()\n\
         s.close()\n"
    );

    learn_then_run_script(&profile_path, &script);
    let profile_toml = std::fs::read_to_string(&profile_path).expect("profile");
    assert!(
        profile_toml.contains(&format!("udp://127.0.0.1:{port}")),
        "expected connected UDP endpoint in profile:\n{profile_toml}"
    );
    assert_eq!(sink.join().unwrap(), 2, "learn and run should each send one UDP datagram");
}

/// Write path: COW isolates during learn; run creates the file for real.
#[test]
fn test_learn_then_run_write() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let write_dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let write_path = write_dir.path().join("run-write-test.txt");
    let write_path_str = write_path.to_str().unwrap();

    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "sh", "-c", &format!("echo hello > {write_path_str}")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&learn.stderr));
    assert!(!write_path.exists(), "COW isolation failed during learn");

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "sh", "-c", &format!("echo hello > {write_path_str}")])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(), "run failed: {}", String::from_utf8_lossy(&run.stderr));
    assert_eq!(std::fs::read_to_string(&write_path).unwrap_or_default().trim(), "hello",
        "file not written during run");
    let _ = std::fs::remove_file(&write_path);
}

/// Write then read in the same run: both grants coexist without Landlock conflicts.
#[test]
fn test_learn_then_run_write_and_read() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let write_dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let file = write_dir.path().join("rw-test.txt");
    let file_str = file.to_str().unwrap();
    let script = format!("echo hello > {file_str} && cat {file_str}");

    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "sh", "-c", &script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "sh", "-c", &script])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(), "run failed: {}", String::from_utf8_lossy(&run.stderr));
    assert_eq!(String::from_utf8_lossy(&run.stdout).trim(), "hello",
        "expected workload output");
    let _ = std::fs::remove_file(&file);
}

/// TCP connect: learned endpoint is allowed during run.
#[test]
fn test_learn_then_run_network() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || { let _ = listener.accept(); let _ = listener.accept(); });

    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let script = format!("import socket; s=socket.socket(); s.connect(('127.0.0.1',{port})); s.close()");

    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(), "learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(), "run failed: {}", String::from_utf8_lossy(&run.stderr));
}

/// Bind: learned allow_bind port is permitted during run.
#[test]
fn test_learn_then_run_bind() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let script = concat!(
        "import socket\n",
        "s = socket.socket()\n",
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "s.bind(('127.0.0.1', 19878))\n",
        "s.close()\n",
    );

    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "python3", "-c", script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(), "learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "python3", "-c", script])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(), "run failed: {}", String::from_utf8_lossy(&run.stderr));
}

/// AF_UNIX bind: socket parent observed during learn, bind succeeds during run.
#[test]
fn test_learn_then_run_unix_bind() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let sock = dir.path().join("rndtrip.sock");
    let sock_str = sock.to_str().unwrap();
    let script = format!(
        "import socket; s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); \
         s.bind('{sock_str}'); s.close()"
    );

    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    // bind() during learn is executed on-behalf by the supervisor (outside the
    // COW overlay), so the socket file exists on the real FS after learn.
    // Remove it so run can bind to the same path without EADDRINUSE.
    let _ = std::fs::remove_file(&sock);

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(),
        "run failed (unix bind parent not in writes?): {}",
        String::from_utf8_lossy(&run.stderr));
}

/// Collapsed profile: directory grant covers files not individually observed during learn.
///
/// Uses a private tempdir rather than /usr/bin: learn canonicalizes observed
/// paths, and on hosts where coreutils are symlinks into a multicall link farm
/// (e.g. Ubuntu rust-coreutils on riscv64) the /usr/bin names resolve to
/// parents that never reach the collapse threshold (issue #170).
#[test]
fn test_learn_then_run_collapse() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let dir_path = dir.path().canonicalize().expect("canonicalize tempdir");

    // Four observed files meet the pinned collapse threshold.
    let observed: Vec<String> = (1..=4)
        .map(|i| {
            let p = dir_path.join(format!("observed{i}.txt"));
            std::fs::write(&p, "collapse me\n").expect("write observed file");
            p.to_str().unwrap().to_owned()
        })
        .collect();
    let extra = dir_path.join("unobserved.txt");
    std::fs::write(&extra, "covered by directory grant\n").expect("write unobserved file");

    let mut learn_cmd = sandlock_bin();
    learn_cmd.args(["learn", "--collapse=4", "-o", &profile_path, "--", "cat"]);
    learn_cmd.args(&observed);
    let learn = learn_cmd.output().expect("failed to run sandlock learn");
    assert!(learn.status.success(), "learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    // Run reads a file that was not individually observed; the collapsed
    // directory grant covers it.
    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "cat", extra.to_str().unwrap()])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(),
        "run failed with collapsed profile: {}", String::from_utf8_lossy(&run.stderr));
    assert_eq!(String::from_utf8_lossy(&run.stdout).trim(), "covered by directory grant",
        "unexpected output from unobserved file");
}

/// Learned memory limit reflects actual anonymous allocation, not just the floor.
#[test]
fn test_learn_then_run_memory_limit() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();

    // Allocate 20 MiB, learned limit must exceed the 16M floor.
    let script = "import time; x = bytearray(20 * 1024 * 1024); time.sleep(0.05)";
    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "python3", "-c", script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(), "learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    let profile_toml = std::fs::read_to_string(&profile_path).expect("read profile");
    let mem_line = profile_toml.lines().find(|l| l.starts_with("memory")).unwrap();
    let mib: u64 = mem_line.trim_end_matches('"').split('"').nth(1)
        .and_then(|s| s.trim_end_matches('M').parse().ok()).unwrap_or(0);
    assert!(mib >= 25, "expected memory >= 25M (20M + 25% headroom), got {mib}M");

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "python3", "-c", script])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(), "run failed: {}", String::from_utf8_lossy(&run.stderr));
}

/// Learned process limit reflects observed child processes.
#[test]
fn test_learn_then_run_process_limit() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();

    // sh forks cat as a child, observed peak is 2 processes.
    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "sh", "-c", "cat /etc/hostname & wait"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(), "learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    let profile_toml = std::fs::read_to_string(&profile_path).expect("read profile");
    let proc_line = profile_toml.lines().find(|l| l.starts_with("processes")).unwrap();
    let procs: u32 = proc_line.split('=').nth(1)
        .and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    assert!(procs >= 4, "expected processes >= 4 (2 observed * 2), got {procs}");

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "sh", "-c", "cat /etc/hostname & wait"])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(), "run failed: {}", String::from_utf8_lossy(&run.stderr));
}

/// mknod: FIFO created during learn round-trips to run.
#[test]
fn test_learn_then_run_mknod() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let fifo = dir.path().join("rndtrip.fifo");
    let fifo_str = fifo.to_str().unwrap();
    let script = format!("import os; os.mkfifo('{fifo_str}')");

    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&learn.stderr));
    assert!(!fifo.exists(), "COW isolation failed during learn");

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(),
        "run failed (mknod not in profile writes?): {}", String::from_utf8_lossy(&run.stderr));
    assert!(fifo.exists(), "FIFO not created during run");
    let _ = std::fs::remove_file(&fifo);
}

/// Merged profile covers paths from both learn runs.
#[test]
fn test_learn_then_run_merge() {
    // Two separate workdirs so paths don't collapse into a shared ancestor.
    let dir_a = tempfile::TempDir::new_in("/var/tmp").expect("tempdir a");
    let dir_b = tempfile::TempDir::new_in("/var/tmp").expect("tempdir b");
    let file_a = dir_a.path().join("input.txt");
    let file_b = dir_b.path().join("input.txt");
    let secret = dir_a.path().join("secret.txt");
    std::fs::write(&file_a, "data-a").expect("write file_a");
    std::fs::write(&file_b, "data-b").expect("write file_b");
    std::fs::write(&secret, "sensitive").expect("write secret");

    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();

    // Phase 1: learn access to dir_a/input.txt.
    let learn1 = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "cat", file_a.to_str().unwrap()])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn1.status.success(), "learn1 failed: {}", String::from_utf8_lossy(&learn1.stderr));

    // Operator hardens the profile: deny the secret file in dir_a.
    // Insert deny into the existing [filesystem] section.
    let existing = std::fs::read_to_string(&profile_path).expect("read profile");
    let deny_line = format!("deny = [\"{}\"]", secret.display());
    let hardened = existing.replace("[filesystem]", &format!("[filesystem]\n{deny_line}"));
    std::fs::write(&profile_path, &hardened).expect("write hardened profile");

    // Phase 2: merge, learn access to dir_b/input.txt.
    let learn2 = sandlock_bin()
        .args(["learn", "--merge", &profile_path, "--", "cat", file_b.to_str().unwrap()])
        .output()
        .expect("failed to run sandlock learn --merge");
    assert!(learn2.status.success(), "learn2 failed: {}", String::from_utf8_lossy(&learn2.stderr));

    // Both files are readable, paths from both learn runs are in the profile.
    let run_ok = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--",
               "cat", file_a.to_str().unwrap(), file_b.to_str().unwrap()])
        .output()
        .expect("failed to run sandlock run");
    assert!(run_ok.status.success(),
        "run with merged profile failed: {}", String::from_utf8_lossy(&run_ok.stderr));

    // The deny rule survived the merge: the secret is blocked.
    let run_deny = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--",
               "cat", secret.to_str().unwrap()])
        .output()
        .expect("failed to run sandlock run (deny check)");
    assert!(!run_deny.status.success(),
        "secret should be blocked by deny rule after merge");
}

// ── HTTP learning ─────────────────────────────────────────────────────────────

fn spawn_http_server() -> u16 {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test http server");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream { Ok(s) => s, Err(_) => break };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            );
        }
    });
    port
}

/// Learn HTTP traffic then run with the learned profile:
/// - the learned path is allowed and returns the real response
/// - a different path that was not observed is blocked (403 from proxy)
#[cfg(feature = "http")]
#[test]
fn test_learn_then_run_http() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let port = spawn_http_server();
    let url_learned = format!("http://127.0.0.1:{port}/data");
    let url_other   = format!("http://127.0.0.1:{port}/other");
    let port_str = port.to_string();

    // Learn only GET /data.
    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--http-port", &port_str,
               "--", "curl", "-sf", &url_learned])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    let profile_content = std::fs::read_to_string(&profile_path).expect("read profile");
    assert!(profile_content.contains("[http]"), "profile must have [http] section: {profile_content}");
    assert!(profile_content.contains("/data"), "profile must record /data: {profile_content}");

    // Allowed: the learned path returns the real server response.
    let run_allow = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "curl", "-s", &url_learned])
        .output()
        .expect("failed to run sandlock run (allow)");
    assert!(run_allow.status.success(),
        "run failed for learned path: {}", String::from_utf8_lossy(&run_allow.stderr));
    assert_eq!(String::from_utf8_lossy(&run_allow.stdout).trim(), "ok",
        "expected 'ok' from test server for learned path");

    // Blocked: a path not in the learned allow list gets 403 from the proxy.
    // curl -f exits non-zero on HTTP 4xx/5xx.
    let run_deny = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "curl", "-sf", &url_other])
        .output()
        .expect("failed to run sandlock run (deny)");
    assert!(!run_deny.status.success(),
        "run should have been blocked for non-learned path /other");
}

fn system_ca_bundle() -> Option<&'static str> {
    for path in &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path);
        }
    }
    None
}

/// Returns true if host:443 accepts a TCP connection within 3 seconds.
fn https_reachable(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(mut it) = format!("{host}:443").to_socket_addrs() else { return false };
    let Some(addr) = it.next() else { return false };
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3)).is_ok()
}

/// HTTPS learn -> run round-trip against a real HTTPS server (example.com).
/// Exercises TLS termination, MITM cert signing, CA injection, and ACL enforcement.
/// - the learned HTTPS path is allowed
/// - an unlearned path is blocked (403 from proxy)
/// Skipped if example.com is unreachable or no system CA bundle is found.
#[cfg(feature = "http")]
#[test]
fn test_learn_then_run_https() {
    if !https_reachable("example.com") {
        eprintln!("skipping test_learn_then_run_https: example.com unreachable");
        return;
    }
    let Some(ca_bundle) = system_ca_bundle() else {
        eprintln!("skipping test_learn_then_run_https: no system CA bundle found");
        return;
    };

    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();

    let learn = sandlock_bin()
        .args([
            "learn", "-o", &profile_path,
            "--http-inject-ca", ca_bundle,
            "--", "curl", "-sf", "https://example.com/",
        ])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    let profile_content = std::fs::read_to_string(&profile_path).expect("read profile");
    assert!(profile_content.contains("http_inject_ca"),
        "profile must record http_inject_ca in [config]: {profile_content}");
    assert!(profile_content.contains("example.com"),
        "profile must record example.com in [http].allow: {profile_content}");

    // Allowed: sandlock run picks up http_inject_ca from [config], no extra flags.
    let run_allow = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "curl", "-sf", "https://example.com/"])
        .output()
        .expect("failed to run sandlock run (allow)");
    assert!(run_allow.status.success(),
        "run failed for learned path: {}", String::from_utf8_lossy(&run_allow.stderr));

    // Blocked: unlearned path returns 403 from proxy (curl -f exits non-zero on 4xx).
    let run_deny = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--",
               "curl", "-sf", "https://example.com/not-learned-path"])
        .output()
        .expect("failed to run sandlock run (deny)");
    assert!(!run_deny.status.success(),
        "run should have been blocked for non-learned path /not-learned-path");
}

/// --merge carries [http].allow and [http].ports from the observed run into the
/// existing profile.
#[cfg(feature = "http")]
#[test]
fn test_learn_then_run_merge_http() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let port = spawn_http_server();
    let url_a     = format!("http://127.0.0.1:{port}/path_a");
    let url_b     = format!("http://127.0.0.1:{port}/path_b");
    let url_other = format!("http://127.0.0.1:{port}/other");
    let port_str  = port.to_string();

    // Run 1: learn /path_a.
    let learn1 = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--http-port", &port_str,
               "--", "curl", "-sf", &url_a])
        .output()
        .expect("failed to run sandlock learn (run 1)");
    assert!(learn1.status.success(),
        "learn run 1 failed: {}", String::from_utf8_lossy(&learn1.stderr));

    // Run 2: merge, learn /path_b.
    let learn2 = sandlock_bin()
        .args(["learn", "--merge", &profile_path, "--http-port", &port_str,
               "--", "curl", "-sf", &url_b])
        .output()
        .expect("failed to run sandlock learn --merge (run 2)");
    assert!(learn2.status.success(),
        "learn run 2 (merge) failed: {}", String::from_utf8_lossy(&learn2.stderr));

    let merged = std::fs::read_to_string(&profile_path).expect("read merged profile");
    assert!(merged.contains("/path_a"), "merged profile must contain /path_a: {merged}");
    assert!(merged.contains("/path_b"), "merged profile must contain /path_b: {merged}");

    // Both learned paths are allowed.
    let run_a = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "curl", "-s", &url_a])
        .output()
        .expect("failed to run sandlock run (path_a)");
    assert!(run_a.status.success(),
        "run failed for /path_a: {}", String::from_utf8_lossy(&run_a.stderr));

    let run_b = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "curl", "-s", &url_b])
        .output()
        .expect("failed to run sandlock run (path_b)");
    assert!(run_b.status.success(),
        "run failed for /path_b: {}", String::from_utf8_lossy(&run_b.stderr));

    // Unlearned path is blocked.
    let run_deny = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "curl", "-sf", &url_other])
        .output()
        .expect("failed to run sandlock run (deny)");
    assert!(!run_deny.status.success(),
        "run should have been blocked for non-learned path /other");
}
