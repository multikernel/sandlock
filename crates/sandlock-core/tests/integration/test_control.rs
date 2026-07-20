//! Integration tests for the per-sandbox control socket (RFC #68).
//!
//! These tests exercise the control-socket wire protocol by starting a real
//! sandbox via the CLI binary and querying its `config` verb, verifying that
//! the effective policy returned matches the sandbox's configured policy.

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
fn test_control_config_returns_policy_via_cli() {
    let name = format!("test-ctrl-config-{}", std::process::id());
    let mut child = start_sleep_sandbox(&name);

    match wait_for_sandbox(&name) {
        Ok(()) => {
            let out = sandlock_bin()
                .args(["config", &name])
                .output()
                .expect("sandlock config");
            assert!(
                out.status.success(),
                "config should succeed: stderr={}",
                String::from_utf8_lossy(&out.stderr)
            );
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains("filesystem"),
                "config JSON should contain 'filesystem': {}",
                stdout
            );
            assert!(
                stdout.contains("/usr"),
                "config JSON should contain /usr: {}",
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
fn test_control_config_nonexistent_sandbox() {
    let out = sandlock_bin()
        .args(["config", "nonexistent-sandbox-xyz-99999"])
        .output()
        .expect("sandlock config");
    assert!(!out.status.success(), "config for nonexistent sandbox should fail");
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

            // Read the child PID from the pid file.
            let pid_file = sandlock_core::control::pid_path(&dir);
            let child_pid: i32 = std::fs::read_to_string(&pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();

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
