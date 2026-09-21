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

/// A process that made itself a session leader is outside the child's
/// group; `sandlock kill` reaches it through the supervisor.
#[test]
fn test_control_kill_reaches_a_process_outside_the_child_group() {
    let name = format!("test-ctrl-killsid-{}", std::process::id());
    let has_lib64 = std::path::Path::new("/lib64").exists();
    let mut args = vec!["run", "--name", &name, "-r", "/usr", "-r", "/lib"];
    if has_lib64 {
        args.extend(["-r", "/lib64"]);
    }
    args.extend(["-r", "/bin", "-r", "/etc", "-r", "/proc", "-r", "/dev"]);
    args.extend(["--", "sh", "-c", "setsid sleep 30 & exec sleep 30"]);
    let mut child = sandlock_bin()
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sandlock");
    if let Err(e) = wait_for_sandbox(&name) {
        let stderr_output = child_stderr(&mut child);
        let _ = child.kill();
        panic!("{}; child stderr: {}", e, stderr_output);
    }
    let pids = sandlock_core::control::sandbox_pids(&name).expect("pids");

    let leader = (0..100)
        .find_map(|_| {
            child_outside_group(pids.child).or_else(|| {
                std::thread::sleep(Duration::from_millis(50));
                None
            })
        })
        .expect("the setsid child never left the sandbox's group");

    let out = sandlock_bin().args(["kill", &name]).output().expect("sandlock kill");
    let _ = child.wait();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(wait_for_pid_gone(pids.child), "child {} should be dead", pids.child);
    assert!(wait_for_pid_gone(leader), "session leader {} should be dead", leader);
}

/// A child of `parent` that runs in a process group other than `parent`'s.
fn child_outside_group(parent: i32) -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()? {
        let Ok(pid) = entry.ok()?.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        let mut fields = stat.rsplit_once(") ")?.1.split_whitespace();
        let ppid: i32 = fields.nth(1)?.parse().ok()?;
        let pgid: i32 = fields.next()?.parse().ok()?;
        if ppid == parent && pgid != parent {
            return Some(pid);
        }
    }
    None
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

/// A child forked while another sandbox's listener exists inherits that fd,
/// and an abstract name stays bound while any fd refers to it. The child
/// must drop those copies before it parks, or a created-but-not-started
/// sandbox pins every other name in the process.
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
// pgrp socket vs extra fd targets
// ============================================================

fn open_devnull() -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert!(fd >= 0, "open /dev/null: {}", std::io::Error::last_os_error());
    unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }
}

/// Fill every hole in the fd table so later allocations are consecutive
/// from the returned number. `keep` holds the fillers open.
fn make_fd_table_contiguous(keep: &mut Vec<std::os::fd::OwnedFd>) -> i32 {
    use std::os::fd::AsRawFd;
    let top = (0..4096).rev().find(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0).unwrap();
    loop {
        let filler = open_devnull();
        let fd = filler.as_raw_fd();
        keep.push(filler);
        if fd > top {
            return fd + 1;
        }
    }
}

/// The fd number in this process bound to `name`'s pgrp socket.
fn pgrp_fd_of(name: &str) -> Option<i32> {
    let want = format!("\0sandlock/{}/{}/pgrp", unsafe { libc::getuid() }, name);
    (0..4096).find(|&fd| {
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        let rc = unsafe { libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len) };
        if rc != 0 {
            return false;
        }
        let path_len = (len as usize).saturating_sub(std::mem::offset_of!(libc::sockaddr_un, sun_path));
        let path: Vec<u8> = addr.sun_path[..path_len].iter().map(|&c| c as u8).collect();
        path == want.as_bytes()
    })
}

const FD_LAYOUT_ENV: &str = "SANDLOCK_TEST_FD_LAYOUT_CHILD";
const FD_LAYOUT_TEST: &str = "test_control::test_control_pgrp_published_before_extra_fd_dup2";

/// The child dup2s extra fds onto fixed low targets, and the pgrp socket
/// takes the lowest free fd in the supervisor, so a target can be the pgrp
/// socket's own number. Publishing after the dup2 would listen on the
/// caller's fd and then close it.
#[test]
fn test_control_pgrp_published_before_extra_fd_dup2() {
    // Fd numbers are only predictable while no other thread allocates,
    // so the body runs alone in a fresh process.
    if std::env::var_os(FD_LAYOUT_ENV).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", FD_LAYOUT_TEST, "--test-threads=1"])
            .env(FD_LAYOUT_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success(), "fd layout body failed in the child process");
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(pgrp_published_before_extra_fd_dup2());
}

async fn pgrp_published_before_extra_fd_dup2() {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;

    let policy = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/proc")
        .build()
        .unwrap();
    let pid = std::process::id();
    let mut fillers = Vec::new();

    // Learn how many fds create() allocates before the pgrp socket.
    let probe_name = format!("test-ctrl-pgrp-probe-{pid}");
    let (probe_out_r, probe_out_w) = std::io::pipe().unwrap();
    let base = make_fd_table_contiguous(&mut fillers);
    let mut probe = policy.clone().with_name(&probe_name);
    probe
        .create_with_gather_io(&["true"], None, Some(probe_out_w.as_raw_fd()), None, Vec::new())
        .await
        .unwrap();
    let offset = pgrp_fd_of(&probe_name).expect("probe pgrp socket") - base;
    probe.start().unwrap();
    probe.wait().await.unwrap();
    drop(probe);
    drop((probe_out_r, probe_out_w));
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }

    // Now aim an extra fd at exactly that number.
    let name = format!("test-ctrl-pgrp-dup2-{pid}");
    let (data_r, mut data_w) = std::io::pipe().unwrap();
    data_w.write_all(b"ping\n").unwrap();
    drop(data_w);
    let (mut out_r, out_w) = std::io::pipe().unwrap();
    let target = make_fd_table_contiguous(&mut fillers) + offset;
    let mut sb = policy.with_name(&name);
    sb.create_with_gather_io(
        &["cat", &format!("/proc/self/fd/{target}")],
        None,
        Some(out_w.as_raw_fd()),
        None,
        vec![(target, data_r.as_raw_fd())],
    )
    .await
    .unwrap();
    assert_eq!(pgrp_fd_of(&name), Some(target), "fd layout assumption broke");

    let pids = sandlock_core::control::sandbox_pids(&name).expect("pgrp socket listens before start");
    assert_eq!(Some(pids.child), sb.pid());

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
