use std::process::Command;

fn sandlock_bin() -> Command {
    // Use cargo to find the binary
    let cmd = Command::new(env!("CARGO_BIN_EXE_sandlock"));
    cmd
}

#[test]
fn test_check_command() {
    let output = sandlock_bin()
        .args(["check"])
        .output()
        .expect("failed to run sandlock check");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Landlock"), "Should mention Landlock");
}

#[test]
fn test_run_echo() {
    let output = sandlock_bin()
        .args(["run", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc", "--", "echo", "test123"])
        .output()
        .expect("failed to run sandlock");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("test123"));
}

#[test]
fn test_run_exit_code() {
    let output = sandlock_bin()
        .args(["run", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "sh", "-c", "exit 42"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(42));
}

#[test]
fn test_run_denied_path() {
    let output = sandlock_bin()
        .args(["run", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "cat", "/etc/group"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success(), "Should fail without /etc readable");
}

#[test]
fn test_run_hostname_virtualized() {
    // /etc/hostname is virtualized by the supervisor, so it should be readable
    // even when /etc is not in fs_read, and should return the sandbox hostname
    // (not the host's).
    let output = sandlock_bin()
        .args(["run", "--name", "mybox", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run");
    assert!(output.status.success(), "virtualized /etc/hostname should be readable: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "mybox", "expected virtual hostname, got {:?}", stdout.trim());
}

#[test]
fn test_profile_list_empty() {
    let output = sandlock_bin()
        .args(["profile", "list"])
        .output()
        .expect("failed to run");
    assert!(output.status.success());
}

#[test]
fn test_no_args_shows_help() {
    let output = sandlock_bin()
        .output()
        .expect("failed to run");
    // clap exits with code 2 when no subcommand given
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage") || stderr.contains("sandlock"));
}

#[test]
fn test_cpu_cores_flag_accepted() {
    let output = sandlock_bin()
        .args(["run", "--help"])
        .output()
        .expect("failed to run sandlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--cpu-cores"), "help should mention --cpu-cores");
}

#[test]
fn test_status_fd_flag_accepted() {
    // Just verify the flag is accepted without error
    let bin = env!("CARGO_BIN_EXE_sandlock");
    let output = std::process::Command::new(bin)
        .args(["run", "--help"])
        .output()
        .expect("failed to run sandlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--status-fd"), "help should mention --status-fd");
}

#[test]
fn test_time_start_fakes_year() {
    let output = sandlock_bin()
        .args([
            "run",
            "-r", "/usr",
            "-r", "/lib",
            "-r", "/lib64",
            "-r", "/bin",
            "-r", "/etc",
            "--time-start", "2000-06-15T00:00:00Z",
            "--",
            "date", "+%Y",
        ])
        .output()
        .expect("failed to run sandlock with --time-start");
    assert!(
        output.status.success(),
        "sandlock exited with failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim() == "2000",
        "Expected year 2000, got: {:?}",
        stdout.trim()
    );
}

#[test]
fn test_no_supervisor_echo() {
    let output = sandlock_bin()
        .args(["run", "--no-supervisor", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc", "--", "echo", "no-supervisor-test"])
        .output()
        .expect("failed to run sandlock --no-supervisor");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no-supervisor-test"));
}

#[test]
fn test_no_supervisor_blocks_denied_path() {
    let output = sandlock_bin()
        .args(["run", "--no-supervisor", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success(), "Should fail without /etc readable");
}

#[test]
fn test_no_supervisor_rejects_fs_deny() {
    let output = sandlock_bin()
        .args(["run", "--no-supervisor", "--fs-deny", "/etc/hostname", "-r", "/usr", "--", "echo", "hi"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--fs-deny"), "stderr: {}", stderr);
}

#[test]
fn test_no_supervisor_rejects_incompatible_flags() {
    let output = sandlock_bin()
        .args(["run", "--no-supervisor", "--max-memory", "100M", "-r", "/usr", "--", "echo", "hi"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--no-supervisor is incompatible with"), "stderr: {}", stderr);
}

#[test]
fn test_no_supervisor_writable_path() {
    let output = sandlock_bin()
        .args(["run", "--no-supervisor", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--fs-write", "/tmp", "--",
               "sh", "-c", "echo no-supervisor-write > /tmp/sandlock-no-supervisor-test && cat /tmp/sandlock-no-supervisor-test"])
        .output()
        .expect("failed to run");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no-supervisor-write"));
    let _ = std::fs::remove_file("/tmp/sandlock-no-supervisor-test");
}

#[test]
fn test_no_supervisor_nested_sandbox() {
    let sandlock_path = env!("CARGO_BIN_EXE_sandlock");
    let sandlock_dir = std::path::Path::new(sandlock_path).parent().unwrap().to_str().unwrap();
    let output = sandlock_bin()
        .args(["run", "--no-supervisor",
               "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
               "-r", "/proc", "-r", "/dev", "--fs-write", "/tmp",
               "-r", sandlock_dir,
               "--", sandlock_path, "run",
               "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
               "--", "echo", "nested-works"])
        .output()
        .expect("failed to run nested sandbox");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nested-works"));
}

#[test]
fn test_no_supervisor_exit_code() {
    let output = sandlock_bin()
        .args(["run", "--no-supervisor", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "sh", "-c", "exit 42"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(42));
}


// ── Docker CLI compatibility ─────────────────────────────────────────────────

/// True when the local Docker daemon can be reached and `alpine:latest` is
/// available. Docker-mode tests skip (pass as no-ops) otherwise so CI without a
/// Docker daemon stays green.
fn docker_alpine_available() -> bool {
    Command::new("docker")
        .args(["image", "inspect", "alpine:latest"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn docker_help_lists_compat_flags() {
    let output = sandlock_bin().args(["run", "--help"]).output().expect("run --help");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for flag in ["--volume", "--publish", "--workdir", "--user", "--network", "--tty", "--entrypoint"] {
        assert!(stdout.contains(flag), "run --help should mention {}", flag);
    }
}

#[test]
fn docker_run_image_positional() {
    if !docker_alpine_available() { eprintln!("skipping: alpine not available"); return; }
    let output = sandlock_bin()
        .args(["run", "alpine", "echo", "hello-docker"])
        .output()
        .expect("failed to run image");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("hello-docker"));
}

#[test]
fn docker_run_env_and_workdir() {
    if !docker_alpine_available() { eprintln!("skipping: alpine not available"); return; }
    let output = sandlock_bin()
        .args(["run", "-e", "FOO=bar", "-w", "/tmp", "alpine", "sh", "-c", "echo $FOO@$(pwd)"])
        .output()
        .expect("failed to run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "bar@/tmp");
}

#[test]
fn docker_run_applies_image_default_path() {
    if !docker_alpine_available() { eprintln!("skipping: alpine not available"); return; }
    // The image's baked-in PATH should be applied even without --env.
    let output = sandlock_bin()
        .args(["run", "alpine", "sh", "-c", "echo $PATH"])
        .output()
        .expect("failed to run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("/usr/bin"));
}

#[test]
fn docker_run_volume_readonly() {
    if !docker_alpine_available() { eprintln!("skipping: alpine not available"); return; }
    let dir = std::env::temp_dir().join("sandlock-vol-it");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("f.txt"), "mounted").unwrap();
    let output = sandlock_bin()
        .args(["run", "-v", &format!("{}:/mnt:ro", dir.display()), "alpine", "cat", "/mnt/f.txt"])
        .output()
        .expect("failed to run");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("mounted"));
}
