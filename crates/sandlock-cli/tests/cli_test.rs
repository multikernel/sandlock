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
fn test_no_supervisor_rejects_net_deny() {
    let output = sandlock_bin()
        .args(["run", "--no-supervisor", "--net-deny", "10.0.0.0/8", "--", "/bin/true"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--net-deny"), "stderr: {}", stderr);
}

#[test]
fn test_net_allow_and_net_deny_are_mutually_exclusive() {
    // Also guards the CLI wiring: --net-deny must reach build(), otherwise
    // the exclusivity check never fires and the flag is silently dropped.
    let output = sandlock_bin()
        .args(["run", "--net-allow", "github.com:443", "--net-deny", "10.0.0.0/8", "--", "/bin/true"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mutually exclusive"), "stderr: {}", stderr);
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
        .args(["run", "--no-supervisor", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-w", "/tmp", "--",
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
fn test_no_supervisor_exit_code() {
    let output = sandlock_bin()
        .args(["run", "--no-supervisor", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "sh", "-c", "exit 42"])
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(42));
}

/// Regression: `Sandbox::Drop` must run when the CLI exits.
///
/// When `--workdir` is set, seccomp COW stages writes in an upper layer
/// and only copies them back to the workdir on commit, which runs in
/// `Sandbox::Drop`. A previous version of the CLI called
/// `std::process::exit(...)` from inside the function that owned the
/// `Sandbox`, which skipped destructors entirely. Result: the file
/// stayed orphaned in `/tmp/sandlock-cow-*/upper/` and never appeared
/// in the workdir, even though the default `on_exit` is `commit`.
#[test]
fn test_cow_commit_runs_on_cli_exit() {
    let workdir = tempfile::tempdir().expect("tempdir");
    let sentinel = workdir.path().join("sentinel.txt");
    assert!(!sentinel.exists(), "precondition: sentinel should not exist");

    let cmd = format!("echo committed > {}", sentinel.display());
    let output = sandlock_bin()
        .args([
            "run",
            "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
            "-w", workdir.path().to_str().unwrap(),
            "--workdir", workdir.path().to_str().unwrap(),
            "--", "sh", "-c", &cmd,
        ])
        .output()
        .expect("failed to run sandlock");
    assert!(
        output.status.success(),
        "sandlock exit={:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        sentinel.exists(),
        "COW commit did not run on CLI exit: {} missing. \
         Was process::exit called instead of returning the exit code?",
        sentinel.display(),
    );
    let contents = std::fs::read_to_string(&sentinel).unwrap_or_default();
    assert_eq!(contents.trim(), "committed");
}

/// `sandlock learn` must capture filesystem reads in the generated profile.
/// Runs `cat /etc/hostname` and verifies `/etc/hostname` appears under `read`.
#[test]
fn test_learn_captures_fs_read() {
    let output = sandlock_bin()
        .args(["learn", "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("/etc/hostname"),
        "expected /etc/hostname in learn output, got:\n{stdout}",
    );
}

/// `sandlock learn` must classify file opens with write flags under `write`.
/// Runs a shell that writes a temp file and verifies it appears under `write`.
#[test]
fn test_learn_captures_fs_write() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_str().unwrap().to_owned();
    let cmd = format!("echo x > {path}");
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&path),
        "expected {path} in learn write output, got:\n{stdout}",
    );
    // Confirm it appears in write = [...], not read
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(
        write_line.contains(&path),
        "expected {path} under write = [...], got: {write_line}",
    );
}

/// `sandlock learn` must record observed TCP connections under `[network] allow`.
/// Binds a real listener so the connect succeeds cleanly.
#[test]
fn test_learn_captures_net_connect() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // Accept one connection so the child doesn't hang waiting for handshake.
    let _t = std::thread::spawn(move || { let _ = listener.accept(); });

    let script = format!(
        "import socket; s=socket.socket(); s.connect(('127.0.0.1',{port})); s.close()"
    );
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = format!("127.0.0.1:{port}");
    assert!(
        stdout.contains(&expected),
        "expected {expected} in network output, got:\n{stdout}",
    );
    let net_line = stdout.lines().find(|l| l.starts_with("allow = [")).unwrap_or("");
    assert!(
        net_line.contains(&expected),
        "expected {expected} under [network] allow = [...], got: {net_line}",
    );
}

/// `--user N:N` maps the sandbox to UID `N` via an unprivileged
/// user namespace, even when the host UID is non-zero. This is the only
/// remaining `CLONE_NEWUSER` site after the overlayfs backend removal;
/// the test guards against accidentally tearing it out.
#[test]
fn test_uid_mapping_fakes_root() {
    // `id -u` reports the in-namespace UID. Passing --user 0:0 should make
    // the child see UID 0 (fake root) regardless of the host UID.
    let output = sandlock_bin()
        .args([
            "run",
            "--user", "0:0",
            "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
            "--", "id", "-u",
        ])
        .output()
        .expect("failed to run sandlock");
    assert!(
        output.status.success(),
        "sandlock --user 0:0 failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "0",
        "expected UID 0 inside sandbox; got stdout={:?}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
fn test_uid_mapping_arbitrary_uid() {
    // Arbitrary --user value should also map cleanly (not just 0).
    let output = sandlock_bin()
        .args([
            "run",
            "--user", "1234:1234",
            "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
            "--", "id", "-u",
        ])
        .output()
        .expect("failed to run sandlock");
    assert!(
        output.status.success(),
        "sandlock --user 1234:1234 failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "1234",
    );
}

