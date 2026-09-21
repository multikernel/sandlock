//! Integration tests for the per-sandbox control socket.
//!
//! Each test starts a real sandbox through the CLI binary and drives the
//! abstract control sockets the way `sandlock ps`, `inspect`, `ports`, and
//! `kill` do: discovery through /proc/net/unix, pids from SO_PEERCRED,
//! then info/config/ports.

use std::process::Command;
use std::time::Duration;

/// Locate the sandlock binary.  We're in sandlock-core's tests, so
/// CARGO_BIN_EXE_sandlock is not available; find it relative to the
/// current executable's location.
fn sandlock_bin() -> Command {
    // The test binary is in target/release/deps/; go up two levels to
    // the workspace root, then into target/release/sandlock.
    let exe = std::env::current_exe().expect("current_exe");
    let deps_dir = exe.parent().expect("parent of test binary");
    let target_dir = deps_dir.parent().expect("parent of deps dir");
    let sandlock_path = target_dir.join("sandlock");
    if sandlock_path.exists() {
        return Command::new(&sandlock_path);
    }
    // Fallback: assume workspace root is grandparent of target_dir.
    let workspace_root = target_dir.parent().expect("parent of target dir");
    let alt_path = workspace_root.join("target/release/sandlock");
    if alt_path.exists() {
        return Command::new(&alt_path);
    }
    Command::new("sandlock")
}

/// Start a sandbox running `sleep 30`, wait for it to appear in `ps`,
/// return the name. The caller should kill it.
fn start_sleep_sandbox(name: &str) -> std::process::Child {
    let has_lib64 = std::path::Path::new("/lib64").exists();
    let mut args: Vec<String> = vec![
        "run".into(), "--name".into(), name.into(),
        "-r".into(), "/usr".into(), "-r".into(), "/lib".into(),
        "-r".into(), "/bin".into(), "-r".into(), "/etc".into(),
        "-r".into(), "/proc".into(), "-r".into(), "/dev".into(),
        "--".into(), "/bin/sleep".into(), "30".into(),
    ];
    if has_lib64 {
        // Insert -r /lib64 before -r /bin.  Find the -r before /bin.
        let pos = args.iter().position(|s| s == "/bin").unwrap();
        // pos points to "/bin"; the "-r" is at pos-1.
        args.insert(pos - 1, "/lib64".into());
        args.insert(pos - 1, "-r".into());
    }
    sandlock_bin()
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sandlock")
}

/// Read stderr from a child process (if available).
fn child_stderr(child: &mut std::process::Child) -> String {
    use std::io::Read;
    let mut s = String::new();
    if let Some(ref mut stderr) = child.stderr {
        let _ = stderr.read_to_string(&mut s);
    }
    s
}

/// Poll `sandlock ps` until `name` appears, or timeout.
fn wait_for_sandbox(name: &str) -> Result<(), String> {
    for _ in 0..20 {
        let out = sandlock_bin()
            .args(["ps"])
            .output()
            .expect("sandlock ps");
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains(name) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!("sandbox '{}' did not appear in ps", name))
}

#[test]
fn test_control_list_sandboxes_via_cli() {
    let name = format!("test-ctrl-list-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin()
                .args(["ps"])
                .output()
                .expect("sandlock ps");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains(&name),
                "ps should contain sandbox name '{}':\n{}",
                name, stdout
            );
            assert!(
                stdout.contains("NAME") && stdout.contains("PID") && stdout.contains("UPTIME"),
                "ps should have column headers: {}",
                stdout
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_control_inspect_returns_policy_via_cli() {
    let name = format!("test-ctrl-config-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin()
                .args(["inspect", &name])
                .output()
                .expect("sandlock inspect");
            assert!(
                out.status.success(),
                "inspect should succeed: stderr={}",
                String::from_utf8_lossy(&out.stderr)
            );
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains("filesystem"),
                "inspect JSON should contain 'filesystem': {}",
                stdout
            );
            assert!(
                stdout.contains("/usr"),
                "inspect JSON should contain /usr: {}",
                stdout
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_control_inspect_nonexistent_sandbox() {
    let out = sandlock_bin()
        .args(["inspect", "nonexistent-sandbox-xyz-99999"])
        .output()
        .expect("sandlock inspect");
    assert!(!out.status.success(), "inspect for nonexistent sandbox should fail");
}

#[test]
fn test_control_unknown_verb() {
    // We can't test unknown verbs via the CLI (it only sends "config"),
    // so test via the core API directly.
    let result = sandlock_core::control::send_control_request(
        "nonexistent-sandbox-xyz-99999",
        "nonexistent_verb",
        serde_json::Value::Object(Default::default()),
    );
    // Should fail because the sandbox doesn't exist (not because of the verb).
    assert!(result.is_err(), "should error for nonexistent sandbox");
}

#[test]
fn test_control_sandbox_to_profile() {
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_write("/tmp")
        .fs_deny("/etc/shadow")
        .build()
        .unwrap();

    let profile = sandlock_core::profile::sandbox_to_profile(&sb, &[]);

    let read = &profile.filesystem.read;
    assert!(read.contains(&std::path::PathBuf::from("/usr")));
    assert!(read.contains(&std::path::PathBuf::from("/bin")));

    let write = &profile.filesystem.write;
    assert!(write.contains(&std::path::PathBuf::from("/tmp")));

    let deny = &profile.filesystem.deny;
    assert!(deny.contains(&std::path::PathBuf::from("/etc/shadow")));
}

#[test]
fn test_control_mode_stays_out_of_profile() {
    // The mode marker is ps metadata, not policy: inspect output (a
    // ProfileInput) must not carry it.
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .mode("learn")
        .build()
        .unwrap();

    let toml_str = sandlock_core::profile::sandbox_to_toml(&sb, &[]).unwrap();
    assert!(!toml_str.contains("mode"), "mode leaked into profile: {toml_str}");
}

#[test]
fn test_control_sandbox_to_profile_dedups_net_rules() {
    // "*" expands to tcp://* + udp://* at parse time, so the explicit
    // udp://* renders as a duplicate spec.
    let sb = sandlock_core::Sandbox::builder()
        .net_allow("*")
        .net_allow("udp://*")
        .net_allow("icmp://*")
        .build()
        .unwrap();

    let profile = sandlock_core::profile::sandbox_to_profile(&sb, &[]);
    let allow = &profile.network.allow;
    let unique: std::collections::HashSet<&String> = allow.iter().collect();
    assert_eq!(allow.len(), unique.len(), "duplicate net rules in {allow:?}");
    assert!(allow.contains(&"udp://*".to_string()));
    assert!(allow.contains(&"icmp://*".to_string()));
}

#[test]
fn test_control_sandbox_to_profile_merges_dynamic_denies() {
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_deny("/etc/shadow")
        .build()
        .unwrap();

    let extra = vec!["/etc/passwd".to_string(), "/tmp/secret".to_string()];
    let profile = sandlock_core::profile::sandbox_to_profile(&sb, &extra);

    let deny = &profile.filesystem.deny;
    assert!(deny.contains(&std::path::PathBuf::from("/etc/shadow")));
    assert!(deny.contains(&std::path::PathBuf::from("/etc/passwd")));
    assert!(deny.contains(&std::path::PathBuf::from("/tmp/secret")));
}

#[test]
fn test_control_sandbox_to_toml_roundtrip() {
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let toml_str = sandlock_core::profile::sandbox_to_toml(&sb, &[]).unwrap();
    assert!(!toml_str.is_empty(), "TOML output should not be empty");
    assert!(toml_str.contains("[filesystem]"), "TOML should have [filesystem] section");
    assert!(toml_str.contains("/usr"), "TOML should contain /usr");

    let reparsed: sandlock_core::ProfileInput = toml::from_str(&toml_str)
        .expect("TOML should re-parse");
    assert!(
        reparsed.filesystem.read.contains(&std::path::PathBuf::from("/usr")),
        "re-parsed profile should contain /usr in read"
    );
}

#[test]
fn test_control_sandbox_to_json() {
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let json_str = sandlock_core::profile::sandbox_to_json(&sb, &[]).unwrap();
    assert!(!json_str.is_empty(), "JSON output should not be empty");

    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .expect("JSON should parse");
    let fs = parsed.get("filesystem").expect("should have filesystem");
    let read = fs.get("read").and_then(|r| r.as_array())
        .expect("filesystem.read should be an array");
    assert!(
        read.iter().any(|v| v.as_str() == Some("/usr")),
        "filesystem.read should contain /usr"
    );
}

// ============================================================
// Name collision, --no-supervisor, ports
// ============================================================

#[test]
fn test_control_name_collision() {
    let name = format!("test-ctrl-collision-{}", std::process::id());
    let mut first = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin()
                .args([
                    "run", "--name", &name,
                    "-r", "/usr", "-r", "/bin", "-r", "/etc",
                    "-r", "/proc", "-r", "/dev",
                    "--", "/bin/sleep", "5",
                ])
                .output()
                .expect("sandlock run (collision)");
            assert!(
                !out.status.success(),
                "second sandbox with same name must fail"
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("already running"),
                "error should indicate name collision: {}",
                stderr
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut first);
            let _ = first.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = first.kill();
    let _ = first.wait();
}

#[test]
fn test_control_name_collision_no_supervisor() {
    // The no_supervisor path binds the same abstract name and must fail on
    // a live collision just like the supervisor path.
    let name = format!("test-ctrl-collision-nosup-{}", std::process::id());
    let mut first = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin()
                .args([
                    "run", "--name", &name, "--no-supervisor",
                    "-r", "/usr", "-r", "/bin", "-r", "/etc",
                    "-r", "/proc", "-r", "/dev",
                    "--", "/bin/sleep", "5",
                ])
                .output()
                .expect("sandlock run --no-supervisor (collision)");
            assert!(
                !out.status.success(),
                "no_supervisor sandbox with a live name must fail"
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("already running"),
                "error should indicate name collision: {}",
                stderr
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut first);
            let _ = first.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = first.kill();
    let _ = first.wait();
}

#[test]
fn test_control_no_supervisor() {
    let name = format!("test-ctrl-nosup-{}", std::process::id());
    let has_lib64 = std::path::Path::new("/lib64").exists();
    let mut args: Vec<&str> = vec![
        "run", "--name", &name, "--no-supervisor",
        "-r", "/usr", "-r", "/bin", "-r", "/lib",
        "-r", "/etc", "-r", "/proc", "-r", "/dev",
    ];
    if has_lib64 {
        args.push("-r");
        args.push("/lib64");
    }
    args.push("--");
    args.push("/bin/sleep");
    args.push("30");

    let mut child = sandlock_bin()
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sandlock --no-supervisor");

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin().args(["ps"]).output().expect("sandlock ps");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains(&name),
                "ps should list --no-supervisor sandbox: {}",
                stdout
            );
            assert!(
                stdout.contains("PORTS"),
                "ps should have PORTS column: {}",
                stdout
            );

            let pids = sandlock_core::control::sandbox_pids(&name).expect("pids");
            assert_eq!(pids.supervisor, child.id() as i32, "supervisor pid: {:?}", pids);
            assert_eq!(unsafe { libc::getpgid(pids.child) }, pids.child, "child leads its group: {:?}", pids);
            let info = sandlock_core::control::sandbox_info(&name).expect("info");
            assert_eq!(info.mode, None);

            let inspect = sandlock_bin().args(["inspect", &name]).output().expect("inspect");
            assert!(inspect.status.success(), "inspect should answer without a supervisor");

            let ports = sandlock_core::control::send_control_request(
                &name, "ports", serde_json::Value::Object(Default::default()),
            ).expect("ports");
            assert_eq!(ports.data, Some(serde_json::json!({})));
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_control_ports_verb() {
    let name = format!("test-ctrl-ports-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let resp = sandlock_core::control::send_control_request(
                &name,
                "ports",
                serde_json::Value::Object(Default::default()),
            );
            match resp {
                Ok(r) => {
                    assert!(r.ok, "ports verb should succeed: {:?}", r.err);
                    // With no port forwarding configured, the map should be empty.
                    if let Some(data) = r.data {
                        let map: std::collections::HashMap<u16, u16> =
                            serde_json::from_value(data).unwrap_or_default();
                        assert!(
                            map.is_empty(),
                            "ports map should be empty when no port forwarding configured"
                        );
                    }
                }
                Err(e) => {
                    panic!("ports verb failed: {}", e);
                }
            }
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_control_ps_ports_column() {
    let name = format!("test-ctrl-psports-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin().args(["ps"]).output().expect("sandlock ps");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains("PORTS"),
                "ps header should contain PORTS column: {}",
                stdout
            );
            assert!(
                stdout.contains(&name),
                "ps should list sandbox: {}",
                stdout
            );
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn test_control_invalid_names() {
    // Names that could not be listed back from /proc/net/unix, or that look like paths, are rejected at spawn time.
    for bad in &["/", "..", ".", "a/b", "../etc", "a b", "tab\tname", "nl\nname"] {
        let result = sandlock_core::Sandbox::builder()
            .fs_read("/usr")
            .fs_read("/bin")
            .fs_read("/lib")
            .fs_read_if_exists("/lib64")
            .fs_read("/proc")
            .build()
            .unwrap()
            .with_name(*bad)
            .run(&["true"])
            .await;
        assert!(
            result.is_err(),
            "sandbox name {:?} should be rejected", bad
        );
    }
}

// ============================================================
// Lifecycle: the name lives and dies with the supervisor
// ============================================================

/// Poll `list_sandboxes` until `name` is absent, or give up after 3s.
fn wait_for_gone(name: &str) -> bool {
    for _ in 0..30 {
        let names = sandlock_core::control::list_sandboxes().unwrap();
        if !names.iter().any(|n| n == name) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn test_control_killed_supervisor_vanishes_and_name_is_reusable() {
    let name = format!("test-ctrl-vanish-{}", std::process::id());
    let mut first = start_sleep_sandbox(&name);
    if let Err(e) = wait_for_sandbox(&name) {
        let stderr_output = child_stderr(&mut first);
        let _ = first.kill();
        panic!("{}; child stderr: {}", e, stderr_output);
    }
    let child_pid = sandlock_core::control::sandbox_pids(&name).expect("pids").child;

    // SIGKILL skips Drop entirely: nothing runs any cleanup.
    first.kill().expect("kill supervisor");
    first.wait().expect("wait supervisor");
    unsafe { libc::kill(child_pid, libc::SIGKILL) };

    assert!(wait_for_gone(&name), "name should disappear with the supervisor");

    let mut second = start_sleep_sandbox(&name);
    match wait_for_sandbox(&name) {
        Ok(()) => {}
        Err(e) => {
            let stderr_output = child_stderr(&mut second);
            let _ = second.kill();
            panic!("name should be reusable immediately: {}; stderr: {}", e, stderr_output);
        }
    }
    let _ = second.kill();
    let _ = second.wait();
}

#[test]
fn test_control_stopped_supervisor_is_listed_as_unresponsive() {
    let name = format!("test-ctrl-stopped-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);
    if let Err(e) = wait_for_sandbox(&name) {
        let stderr_output = child_stderr(&mut child);
        let _ = child.kill();
        panic!("{}; child stderr: {}", e, stderr_output);
    }

    unsafe { libc::kill(child.id() as i32, libc::SIGSTOP) };
    let out = sandlock_bin().args(["ps"]).output().expect("sandlock ps");
    unsafe { libc::kill(child.id() as i32, libc::SIGCONT) };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().find(|l| l.contains(&name));

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        line.is_some_and(|l| l.contains("unresponsive")),
        "a stopped supervisor should still be listed, as unresponsive: {}",
        stdout
    );
}

/// Poll until `pid` is gone, or give up after 3s.
fn wait_for_pid_gone(pid: i32) -> bool {
    for _ in 0..30 {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// A stopped supervisor answers nothing, and kill must not need it to.
#[test]
fn test_control_kill_terminates_a_stopped_supervisor() {
    let name = format!("test-ctrl-killstop-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);
    if let Err(e) = wait_for_sandbox(&name) {
        let stderr_output = child_stderr(&mut child);
        let _ = child.kill();
        panic!("{}; child stderr: {}", e, stderr_output);
    }
    let pids = sandlock_core::control::sandbox_pids(&name).expect("pids");
    assert_eq!(pids.supervisor, child.id() as i32);

    unsafe { libc::kill(child.id() as i32, libc::SIGSTOP) };
    let out = sandlock_bin().args(["kill", &name]).output().expect("sandlock kill");
    let supervisor_gone = child.wait();
    unsafe { libc::kill(pids.child, libc::SIGCONT) };

    assert!(
        out.status.success(),
        "kill should succeed against a stopped supervisor: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(supervisor_gone.is_ok_and(|s| !s.success()), "supervisor should be SIGKILLed");
    assert!(wait_for_pid_gone(pids.child), "child {} should be dead", pids.child);
    assert!(wait_for_gone(&name), "name should be free after kill");
}

/// wait() must release the name before it returns: a caller that runs the
/// same name twice in a row must not hit the collision check.
#[tokio::test]
async fn test_control_name_is_free_when_wait_returns() {
    let name = format!("test-ctrl-reuse-{}", std::process::id());
    for _ in 0..2 {
        let result = sandlock_core::Sandbox::builder()
            .fs_read("/usr")
            .fs_read("/bin")
            .fs_read("/lib")
            .fs_read_if_exists("/lib64")
            .fs_read("/proc")
            .build()
            .unwrap()
            .with_name(&name)
            .run(&["true"])
            .await;
        assert!(result.is_ok(), "second run with the same name must succeed: {:?}", result.err());
    }
}

/// An abstract name stays bound while any fd refers to it, and a child
/// forked while another sandbox exists copies the whole fd table. A
/// created-but-not-started sandbox must not pin the other names in the
/// process that way.
#[tokio::test]
async fn test_control_parked_child_does_not_pin_other_names() {
    let policy = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/proc")
        .build()
        .unwrap();
    let pid = std::process::id();

    let mut first = policy.clone().with_name(format!("test-ctrl-pinned-{pid}"));
    first.create(&["true"]).await.unwrap();
    let mut parked = policy.clone().with_name(format!("test-ctrl-parker-{pid}"));
    parked.create(&["true"]).await.unwrap();

    first.start().unwrap();
    first.wait().await.unwrap();

    let again = policy
        .clone()
        .with_name(format!("test-ctrl-pinned-{pid}"))
        .run(&["true"])
        .await;
    parked.start().unwrap();
    let _ = parked.wait().await;
    assert!(again.is_ok(), "a parked sibling must not pin the name: {:?}", again.err());
}

// ============================================================
// Forks the host makes on its own
// ============================================================

fn name_reuse_policy() -> sandlock_core::Sandbox {
    sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/proc")
        .build()
        .unwrap()
}

/// A child of this process that no libc hook sees, as vfork, posix_spawn
/// and a raw clone make them. It copies every fd and holds the copies for
/// `hold_ms`, without ever calling exec.
fn lingering_child(hold_ms: u32) -> libc::pid_t {
    let child = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) } as libc::pid_t;
    assert!(child >= 0, "clone: {}", std::io::Error::last_os_error());
    if child == 0 {
        unsafe {
            libc::usleep(hold_ms * 1000);
            libc::_exit(0);
        }
    }
    child
}

/// The host spawned a child while the sandbox was live, and that child is
/// still around, not exec'd, when the name is reused. wait() must neither
/// leave the name taken nor wait for that child.
#[tokio::test]
async fn test_control_name_survives_a_lingering_host_child() {
    let policy = name_reuse_policy();
    let name = format!("test-ctrl-lingering-{}", std::process::id());
    let mut first = policy.clone().with_name(&name);
    first.create(&["true"]).await.unwrap();

    let lingering = lingering_child(2000);
    let started = std::time::Instant::now();
    first.start().unwrap();
    first.wait().await.unwrap();
    let again = policy.with_name(&name).run(&["true"]).await;
    let took = started.elapsed();

    unsafe {
        libc::kill(lingering, libc::SIGKILL);
        libc::waitpid(lingering, std::ptr::null_mut(), 0);
    }
    assert!(again.is_ok(), "the name must be free once wait() returns: {:?}", again.err());
    assert!(took < Duration::from_millis(1500), "must not wait for the host's child, took {took:?}");
}

/// The child binds the name, so a collision is found after the fork. The
/// caller must see what a failure before the fork would have left: an
/// error, no child, and the owner of the name undisturbed.
#[tokio::test]
async fn test_control_name_collision_leaves_no_child() {
    let policy = name_reuse_policy();
    let name = format!("test-ctrl-collide-{}", std::process::id());
    let mut owner = policy.clone().with_name(&name);
    owner.create(&["true"]).await.unwrap();

    let mut second = policy.with_name(&name);
    let err = second.create(&["true"]).await.expect_err("the name is taken");
    assert!(err.to_string().contains("is already running"), "got: {err}");
    assert_eq!(second.pid(), None, "the losing child must be reaped, not left for drop");
    drop(second);

    let pids = sandlock_core::control::sandbox_pids(&name).expect("the owner keeps its name");
    assert_eq!(Some(pids.child), owner.pid());
    owner.start().unwrap();
    assert!(owner.wait().await.unwrap().success());
}

/// `sandlock kill` has to work on a sandbox that was created but not
/// started, so the child publishes its name before it parks, and an extra
/// fd still reaches the command afterwards.
#[tokio::test]
async fn test_control_created_sandbox_publishes_its_pids() {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;

    let name = format!("test-ctrl-created-{}", std::process::id());
    let (data_r, mut data_w) = std::io::pipe().unwrap();
    data_w.write_all(b"ping\n").unwrap();
    drop(data_w);
    let (mut out_r, out_w) = std::io::pipe().unwrap();

    let mut sb = name_reuse_policy().with_name(&name);
    sb.create_with_gather_io(
        &["cat", "/proc/self/fd/100"],
        None,
        Some(out_w.as_raw_fd()),
        None,
        vec![(100, data_r.as_raw_fd())],
    )
    .await
    .unwrap();

    let pids = sandlock_core::control::sandbox_pids(&name).expect("the name is published before start");
    assert_eq!(Some(pids.child), sb.pid());
    assert_eq!(pids.supervisor, std::process::id() as i32);

    sb.start().unwrap();
    let result = sb.wait().await.unwrap();
    drop(out_w);
    let mut out = String::new();
    out_r.read_to_string(&mut out).unwrap();
    assert_eq!(out, "ping\n", "extra fd must survive: {result:?}");
}

// ============================================================
// CLI kill / config input validation
// ============================================================

#[test]
fn test_control_cli_kill_rejects_bad_names() {
    for bad in &["..", ".", "a/b", "/dev/shm"] {
        let out = sandlock_bin()
            .args(["kill", bad])
            .output()
            .expect("sandlock kill");
        assert!(
            !out.status.success(),
            "sandlock kill {:?} should fail", bad
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("must not"),
            "kill {:?} should produce a validation error, got: {}",
            bad, stderr
        );
    }
}

#[test]
fn test_control_cli_inspect_rejects_bad_names() {
    for bad in &["..", ".", "a/b"] {
        let out = sandlock_bin()
            .args(["inspect", bad])
            .output()
            .expect("sandlock inspect");
        assert!(
            !out.status.success(),
            "sandlock inspect {:?} should fail", bad
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("must not"),
            "inspect {:?} should produce a validation error, got: {}",
            bad, stderr
        );
    }
}

#[test]
fn test_control_cli_kill_nonexistent() {
    let out = sandlock_bin()
        .args(["kill", "nonexistent-sandbox-xyz-99999"])
        .output()
        .expect("sandlock kill");
    assert!(
        !out.status.success(),
        "kill nonexistent sandbox should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no sandbox named") || stderr.contains("not running"),
        "kill nonexistent should say 'no sandbox named', got: {}",
        stderr
    );
}
