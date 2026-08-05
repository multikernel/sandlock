//! Integration tests for the per-sandbox control socket (RFC #68).
//!
//! These tests exercise the control-socket wire protocol by starting a real
//! sandbox via the CLI binary and querying its `config` verb, verifying that
//! the effective policy returned matches the sandbox's configured policy.

use std::ffi::CString;
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
fn test_control_prunes_stale_dirs_via_cli() {
    let name = format!("test-ctrl-prune-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let dir = sandlock_core::control::sandbox_dir(&name);
            assert!(dir.exists(), "runtime dir should exist: {:?}", dir);

            // Read the child PID from the pid file (first line only;
            // the file now has format child_pid\nsupervisor_pid\n).
            let pid_file = sandlock_core::control::pid_path(&dir);
            let child_pid: i32 = std::fs::read_to_string(&pid_file)
                .unwrap()
                .lines()
                .next()
                .and_then(|l| l.trim().parse().ok())
                .expect("first line of pid file should be child PID");

            // Kill the supervisor process (SIGKILL — no Drop cleanup).
            child.kill().expect("kill supervisor");
            child.wait().expect("wait supervisor");

            // Also kill the sandboxed child (sleep), otherwise kill(pid,0)
            // still sees it as alive.
            unsafe { libc::kill(child_pid, libc::SIGKILL) };

            // Wait a moment for the child to die.
            std::thread::sleep(std::time::Duration::from_millis(500));

            // The stale dir may or may not still exist (depends on whether
            // the supervisor's Drop ran before SIGKILL was delivered).
            // Either way, list_live_sandboxes should not list this sandbox
            // and the dir should be gone after pruning.
            let sandboxes = sandlock_core::control::list_live_sandboxes().unwrap();
            assert!(
                !sandboxes.iter().any(|(n, _)| n == &name),
                "sandbox should not be listed after kill (pruned): {:?}",
                sandboxes
            );

            // The stale dir should be gone after pruning.
            assert!(!dir.exists(), "stale dir should be pruned: {:?}", dir);
        }
        Err(e) => {
            let stderr_output = child_stderr(&mut child);
            let _ = child.kill();
            panic!("{}; child stderr: {}", e, stderr_output);
        }
    }
}

#[test]
fn test_control_runtime_dir_paths() {
    let dir = sandlock_core::control::sandbox_dir("test-xyz");
    let s = dir.to_string_lossy();
    assert!(s.contains("sandlock-"), "dir should contain sandlock-: {}", s);
    assert!(s.contains("test-xyz"), "dir should contain name: {}", s);

    let pid_file = sandlock_core::control::pid_path(&dir);
    assert_eq!(pid_file.file_name().unwrap(), "pid");

    let sock = sandlock_core::control::sock_path(&dir);
    assert_eq!(sock.file_name().unwrap(), "control.sock");
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
fn test_control_sandbox_mode_absent_for_plain_runs() {
    assert_eq!(sandlock_core::control::sandbox_mode("no-such-sandbox-mode"), None);
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
// Name collision, --no-supervisor, control_socket=false, ports
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
    // The no_supervisor path shares setup_runtime_dir_no_socket and must
    // hard-fail on a live-name collision just like the supervisor path;
    // continuing would leave a second sandbox running invisible to ps.
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
fn test_control_socket_disabled() {
    // control_socket = false is a builder field, not a CLI flag.
    // The sandbox runs without binding the control socket — the pid file
    // is still written (via setup_runtime_dir_no_socket) so ps still sees
    // it, but config/ports/kill via the socket fail gracefully.
    let sb = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .control_socket(false)
        .build()
        .unwrap();
    assert!(
        !sb.control_socket,
        "control_socket should be false"
    );

    // Also test the default (true).
    let sb2 = sandlock_core::Sandbox::builder()
        .fs_read("/usr")
        .build()
        .unwrap();
    assert!(
        sb2.control_socket,
        "control_socket should default to true"
    );
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
    // Names that would escape /dev/shm/sandlock-$UID must be rejected
    // at spawn time (sandbox_resolve_name → sandbox_validate_name).
    for bad in &["/", "..", ".", "a/b", "../etc"] {
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

    // Test that sandbox_dir alone does join freely — the validation layer
    // is what prevents bad names from reaching filesystem ops.
    let dir = sandlock_core::control::sandbox_dir("..");
    let dir_str = dir.to_string_lossy();
    assert!(
        dir_str.ends_with(".."),
        "sandbox_dir('..') must append the name as-is (caller must validate): {}",
        dir_str
    );
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

// ============================================================
// pid file format — two lines required (old single-line shim removed)
// ============================================================

#[test]
fn test_control_single_line_pid_file_is_pruned() {
    let dir = sandlock_core::control::sandbox_dir("test-single-line-pid");
    std::fs::create_dir_all(&dir).expect("create test dir");

    // Write a pid file with only one line — the format that never shipped.
    let pid_path = sandlock_core::control::pid_path(&dir);
    std::fs::write(&pid_path, "12345\n").expect("write single-line pid file");

    // Set the dir mtime to >2s ago so the recency check allows pruning.
    // list_live_sandboxes won't prune dirs modified less than 2s ago
    // (concurrent setup protection).
    let old_time = libc::timespec {
        tv_sec: 1000, // Unix epoch + 1000s — ancient
        tv_nsec: 0,
    };
    let times = [old_time, old_time];
    let dir_cstr = CString::new(dir.to_str().unwrap()).expect("valid C string");
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            dir_cstr.as_ptr(),
            times.as_ptr(),
            0,
        )
    };
    assert_eq!(rc, 0, "utimensat failed on {:?}", dir);

    // list_live_sandboxes must prune this dir (supervisor_pid parse fails
    // and the mtime is old).
    let sandboxes = sandlock_core::control::list_live_sandboxes()
        .expect("list_live_sandboxes");
    assert!(
        !sandboxes.iter().any(|(n, _)| n == "test-single-line-pid"),
        "single-line pid dir should not be listed, got: {:?}",
        sandboxes
    );
    assert!(
        !dir.exists(),
        "single-line pid dir should be pruned"
    );
}
