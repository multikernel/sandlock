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
        .args(["run", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success(), "Should fail without /etc readable");
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
fn test_landlock_only_echo() {
    let output = sandlock_bin()
        .args(["run", "--landlock-only", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc", "--", "echo", "landlock-only-test"])
        .output()
        .expect("failed to run sandlock --landlock-only");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("landlock-only-test"));
}

#[test]
fn test_landlock_only_blocks_denied_path() {
    let output = sandlock_bin()
        .args(["run", "--landlock-only", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success(), "Should fail without /etc readable");
}

#[test]
fn test_landlock_only_rejects_incompatible_flags() {
    let output = sandlock_bin()
        .args(["run", "--landlock-only", "--max-memory", "100M", "-r", "/usr", "--", "echo", "hi"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--landlock-only is incompatible with"), "stderr: {}", stderr);
}

#[test]
fn test_landlock_only_writable_path() {
    let output = sandlock_bin()
        .args(["run", "--landlock-only", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-w", "/tmp", "--",
               "sh", "-c", "echo landlock-only-write > /tmp/sandlock-landlock-only-test && cat /tmp/sandlock-landlock-only-test"])
        .output()
        .expect("failed to run");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("landlock-only-write"));
    let _ = std::fs::remove_file("/tmp/sandlock-landlock-only-test");
}

#[test]
fn test_landlock_only_nested_sandbox() {
    let sandlock_path = env!("CARGO_BIN_EXE_sandlock");
    let sandlock_dir = std::path::Path::new(sandlock_path).parent().unwrap().to_str().unwrap();
    let output = sandlock_bin()
        .args(["run", "--landlock-only",
               "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
               "-r", "/proc", "-r", "/dev", "-w", "/tmp",
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
fn test_landlock_only_exit_code() {
    let output = sandlock_bin()
        .args(["run", "--landlock-only", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "sh", "-c", "exit 42"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(42));
}

#[test]
fn test_landlock_only_with_isolate_ipc() {
    let output = sandlock_bin()
        .args(["run", "--landlock-only", "--isolate-ipc", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc", "--", "echo", "ipc-ok"])
        .output()
        .expect("failed to run");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ipc-ok"));
}

#[test]
fn test_landlock_only_with_isolate_signals() {
    let output = sandlock_bin()
        .args(["run", "--landlock-only", "--isolate-signals", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc", "--", "echo", "sig-ok"])
        .output()
        .expect("failed to run");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sig-ok"));
}
