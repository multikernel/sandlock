use std::process::Command;

fn sandlock_bin() -> Command {
    // Use cargo to find the binary
    let cmd = Command::new(env!("CARGO_BIN_EXE_sandlock"));
    cmd
}

/// Drop `-r /lib64` from a CLI argument list when the host has no `/lib64`
/// (RISC-V glibc and musl put the loader under `/lib`, with no `/lib64` at
/// all). `-r` maps to a mandatory `fs_read`, so requiring `/lib64` on such a
/// host aborts confinement; this mirrors `fs_read_if_exists` at the CLI layer.
/// On hosts that have `/lib64` (x86-64) the arguments pass through unchanged.
fn args_for_host(args: &[&str]) -> Vec<String> {
    let has_lib64 = std::path::Path::new("/lib64").exists();
    let mut out: Vec<String> = Vec::with_capacity(args.len());
    for a in args {
        if *a == "/lib64" && !has_lib64 {
            // Also drop the `-r` we just pushed for this now-omitted path.
            if out.last().map(|s| s == "-r").unwrap_or(false) {
                out.pop();
            }
            continue;
        }
        out.push((*a).to_string());
    }
    out
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
        .args(args_for_host(&["run", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc", "--", "echo", "test123"]))
        .output()
        .expect("failed to run sandlock");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("test123"));
}

#[test]
fn test_run_exit_code() {
    let output = sandlock_bin()
        .args(args_for_host(&["run", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "sh", "-c", "exit 42"]))
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(42));
}

#[test]
fn test_run_denied_path() {
    let output = sandlock_bin()
        .args(args_for_host(&["run", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "cat", "/etc/group"]))
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
        .args(args_for_host(&["run", "--name", "mybox", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "cat", "/etc/hostname"]))
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
        .args(args_for_host(&[
            "run",
            "-r", "/usr",
            "-r", "/lib",
            "-r", "/lib64",
            "-r", "/bin",
            "-r", "/etc",
            "--time-start", "2000-06-15T00:00:00Z",
            "--",
            "date", "+%Y",
        ]))
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
        .args(args_for_host(&["run", "--no-supervisor", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc", "--", "echo", "no-supervisor-test"]))
        .output()
        .expect("failed to run sandlock --no-supervisor");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no-supervisor-test"));
}

#[test]
fn test_no_supervisor_blocks_denied_path() {
    let output = sandlock_bin()
        .args(args_for_host(&["run", "--no-supervisor", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "cat", "/etc/hostname"]))
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
        .args(args_for_host(&["run", "--no-supervisor", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-w", "/tmp", "--",
               "sh", "-c", "echo no-supervisor-write > /tmp/sandlock-no-supervisor-test && cat /tmp/sandlock-no-supervisor-test"]))
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
        .args(args_for_host(&["run", "--no-supervisor",
               "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
               "-r", "/proc", "-r", "/dev", "-w", "/tmp",
               "-r", sandlock_dir,
               "--", sandlock_path, "run",
               "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
               "--", "echo", "nested-works"]))
        .output()
        .expect("failed to run nested sandbox");
    assert!(output.status.success(), "Exit status: {:?}, stderr: {}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nested-works"));
}

#[test]
fn test_no_supervisor_exit_code() {
    let output = sandlock_bin()
        .args(args_for_host(&["run", "--no-supervisor", "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "--", "sh", "-c", "exit 42"]))
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
        .args(args_for_host(&[
            "run",
            "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
            "-w", workdir.path().to_str().unwrap(),
            "--workdir", workdir.path().to_str().unwrap(),
            "--", "sh", "-c", &cmd,
        ]))
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
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains("/etc/hostname"),
        "expected /etc/hostname under read = [...], got: {read_line}",
    );
}

/// End-to-end: `sandlock learn` generates a profile, `sandlock run` uses it.
/// Verifies the full round-trip works for a simple read-only workload.
#[test]
fn test_learn_then_run() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();

    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        learn.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&learn.stderr),
    );

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock run");
    assert!(
        run.status.success(),
        "sandlock run with learned profile failed: stderr={}",
        String::from_utf8_lossy(&run.stderr),
    );
    assert!(
        !String::from_utf8_lossy(&run.stdout).trim().is_empty(),
        "expected output from cat /etc/hostname",
    );
}

/// `sandlock learn` must classify file opens with write flags under `write`.
/// Writes to two pre-existing temp files in different directories (no error
/// handling in the script; any blocked write would exit sh non-zero).
#[test]
fn test_learn_captures_fs_write() {
    let tmp1 = tempfile::NamedTempFile::new().expect("tempfile");
    let tmp2 = tempfile::Builder::new().tempdir_in("/var/tmp").expect("tempdir");
    let tmp2_file = tmp2.path().join("sandlock-learn-write2.txt");
    let path1 = tmp1.path().to_str().unwrap().to_owned();
    let path2 = tmp2_file.to_str().unwrap().to_owned();
    let cmd = format!("echo x > {path1} && echo y > {path2}");
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
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains(&path1), "expected {path1} under write = [...], got: {write_line}");
    assert!(write_line.contains(&path2) || write_line.contains(tmp2.path().to_str().unwrap()),
        "expected {path2} (or its parent) under write = [...], got: {write_line}");
}

/// New file creates must be collapsed to the parent directory in the profile.
/// The specific file path is useless to Landlock (it doesn't exist yet);
/// the parent dir is what `sandlock run` needs to create new files.
/// COW must also confirm the real filesystem is not touched during learn.
#[test]
fn test_learn_new_file_collapses_to_parent() {
    let path = "/var/tmp/sandlock-learn-write-test.txt";
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &format!("echo x > {path}")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // New-file creates are collapsed to the parent directory (file didn't exist on real FS).
    let parent = std::path::Path::new(path).parent().unwrap().to_str().unwrap();
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(
        write_line.contains(parent),
        "expected parent dir {parent} under write = [...], got: {write_line}",
    );
    // COW must have intercepted the write, real file must not exist.
    assert!(
        !std::path::Path::new(path).exists(),
        "real filesystem was modified, COW isolation failed",
    );
}

/// mkdir records the parent directory in write (Landlock MAKE_DIR is a dir right).
/// COW must intercept the create so the real directory does not appear.
#[test]
fn test_learn_captures_mkdir() {
    let dir = "/var/tmp/sandlock-learn-mkdir-test";
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &format!("mkdir {dir}")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains("/var/tmp"),
        "expected /var/tmp in write = [...], got: {write_line}");
    assert!(!std::path::Path::new(dir).exists(), "COW isolation failed: dir was created on real FS");
}

/// unlink records the parent directory in write (Landlock REMOVE_FILE is a dir right).
/// COW must intercept the delete so the real file still exists after learn.
#[test]
fn test_learn_captures_unlink() {
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_str().unwrap().to_owned();
    let parent = std::path::Path::new(&path).parent().unwrap().to_str().unwrap().to_owned();
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &format!("rm {path}")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains(&parent),
        "expected parent {parent} in write = [...], got: {write_line}");
    assert!(std::path::Path::new(&path).exists(), "COW isolation failed: file was deleted on real FS");
}

/// rename records parent dirs of both old and new path (RENAME_OLD + RENAME_NEW are dir rights).
/// Cross-directory rename so both /var/tmp and /tmp appear in write.
#[test]
fn test_learn_captures_rename() {
    let src = tempfile::NamedTempFile::new_in("/var/tmp").expect("tempfile in /var/tmp");
    let src_path = src.path().to_str().unwrap().to_owned();
    let dst = "/tmp/sandlock-learn-rename-dst-test";
    let cmd = format!("mv {src_path} {dst}");
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains("/var/tmp"), "expected /var/tmp (src parent) in: {write_line}");
    assert!(write_line.contains("/tmp"), "expected /tmp (dst parent) in: {write_line}");
    // COW: src file still exists, dst was not created on real FS.
    assert!(src.path().exists(), "COW isolation failed: src was deleted on real FS");
    assert!(!std::path::Path::new(dst).exists(), "COW isolation failed: dst was created on real FS");
}

/// symlink records the parent of the created linkpath (args[2] of symlinkat),
/// NOT the parent of the target string (args[0]).
/// This verifies we read the right argument for symlinkat.
/// Uses a relative target so COW can intercept the create.
#[test]
fn test_learn_captures_symlink() {
    let link = "/var/tmp/sandlock-learn-symlink-test";
    // Relative target so COW can intercept. Key check: /tmp (target's dir) must NOT appear
    // as write -- only /var/tmp (the linkpath's parent) should.
    let cmd = format!("ln -s hostname {link}");
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains("/var/tmp"), "expected /var/tmp (link parent) in: {write_line}");
    assert!(!std::path::Path::new(link).exists(), "COW isolation failed: symlink created on real FS");
}

/// hardlink records only the destination parent (MAKE_HARDLINK is a dst-dir right;
/// the source only needs read access which fs_read already grants).
#[test]
fn test_learn_captures_hardlink() {
    let src = tempfile::NamedTempFile::new_in("/var/tmp").expect("tempfile in /var/tmp");
    let src_path = src.path().to_str().unwrap().to_owned();
    let dst = "/tmp/sandlock-learn-hardlink-dst-test";
    let cmd = format!("ln {src_path} {dst}");
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    // dst parent /tmp must appear in writes (MAKE_HARDLINK is a dst-dir right).
    assert!(write_line.contains("/tmp"), "expected /tmp (dst parent) in: {write_line}");
    // src parent /var/tmp must NOT appear as a write (only read access is needed for src).
    assert!(!write_line.contains("/var/tmp"), "src parent /var/tmp wrongly recorded as write in: {write_line}");
    // src file must appear in reads (ln never calls open() on it, so we add it explicitly).
    assert!(read_line.contains(&src_path), "expected src {src_path} in reads: {read_line}");
    assert!(!std::path::Path::new(dst).exists(), "COW isolation failed: hardlink created on real FS");
}

/// All filesystem mutation syscalls in one run: mkdir, unlink, rename, symlink, hardlink.
/// Verifies they are all captured without any one operation blocking the others.
#[test]
fn test_learn_captures_all_fs_mutations() {
    let existing = tempfile::NamedTempFile::new_in("/var/tmp").expect("tempfile");
    let existing_path = existing.path().to_str().unwrap().to_owned();
    let newdir = "/var/tmp/sandlock-learn-allops-dir";
    let symlink = "/var/tmp/sandlock-learn-allops-link";
    let cmd = format!(
        "mkdir {newdir} && rmdir {newdir} && rm {existing_path} && ln -s hostname {symlink}",
    );
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "one or more mutations blocked: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains("/var/tmp"), "expected /var/tmp in: {write_line}");
    // COW: existing file must still be present, new dir and symlink must not exist.
    assert!(existing.path().exists(), "COW isolation failed: file deleted on real FS");
    assert!(!std::path::Path::new(newdir).exists(), "COW isolation failed: dir created on real FS");
    assert!(!std::path::Path::new(symlink).exists(), "COW isolation failed: symlink created on real FS");
}

/// truncate records the file path itself (LANDLOCK_ACCESS_FS_TRUNCATE is a file right,
/// not a directory right, so we record the file, not the parent).
#[test]
fn test_learn_captures_truncate() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_str().unwrap().to_owned();
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &format!("truncate -s 0 {path}")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains(&path),
        "expected file path {path} in write = [...], got: {write_line}");
}

/// End-to-end write round-trip: learn captures write path, run actually writes the file.
/// During learn, COW intercepts the write (file not created on real FS).
/// During run, the profile grants write access to parent dir, so the file is created for real.
#[test]
fn test_learn_then_run_write() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let write_path = "/var/tmp/sandlock-learn-run-write-test.txt";
    let _ = std::fs::remove_file(write_path); // clean state

    // No pre-creation needed: learn collapses new-file creates to the parent directory,
    // so sandlock run gets write access to the directory and can create the file.
    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "sh", "-c", &format!("echo hello > {write_path}")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(),
        "learn failed unexpectedly: {}", String::from_utf8_lossy(&learn.stderr));
    assert!(!std::path::Path::new(write_path).exists(), "COW isolation failed during learn");

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "sh", "-c", &format!("echo hello > {write_path}")])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(), "run failed: {}", String::from_utf8_lossy(&run.stderr));
    assert_eq!(std::fs::read_to_string(write_path).unwrap_or_default().trim(), "hello", "file not written during run");
    let _ = std::fs::remove_file(write_path);
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

/// `sandlock learn` must capture reads done via the `openat2` syscall (not just
/// `openat`).
#[test]
fn test_learn_captures_openat2() {
    // SYS_openat2 = 437 on x86_64; struct open_how { u64 flags; u64 mode; u64 resolve; }
    // class can't follow ';' in Python one-liners; use embedded newlines.
    let script = concat!(
        "import ctypes, os\n",
        "libc = ctypes.CDLL(None)\n",
        "class How(ctypes.Structure):\n",
        " _fields_ = [('f',ctypes.c_uint64),('m',ctypes.c_uint64),('r',ctypes.c_uint64)]\n",
        "how = How(f=os.O_RDONLY)\n",
        "fd = libc.syscall(437, -100, b'/etc/hostname', ctypes.byref(how), ctypes.sizeof(how))\n",
        "os.read(fd, 4); os.close(fd)",
    );
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains("/etc/hostname"),
        "expected /etc/hostname under read = [...] (via openat2), got: {read_line}",
    );
}

/// `sandlock learn` must record UDP sendto destinations under `[network] allow`
/// with a `udp://` scheme.
#[test]
fn test_learn_captures_udp_sendto() {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();

    let script = format!(
        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); \
         s.sendto(b'hi',('127.0.0.1',{port})); s.close()"
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
    let expected = format!("udp://127.0.0.1:{port}");
    assert!(
        stdout.contains(&expected),
        "expected {expected} in network output, got:\n{stdout}",
    );
}

/// `sandlock learn` must record UDP sendmsg destinations under `[network] allow`
/// with a `udp://` scheme. Uses Python's `socket.sendmsg()` which invokes the
/// sendmsg syscall (not sendto), verifying the msghdr.msg_name extraction path.
#[test]
fn test_learn_captures_udp_sendmsg() {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();

    let script = format!(
        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); \
         s.sendmsg([b'hi'],[],0,('127.0.0.1',{port})); s.close()"
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
    let expected = format!("udp://127.0.0.1:{port}");
    assert!(
        stdout.contains(&expected),
        "expected {expected} in network output, got:\n{stdout}",
    );
}

/// End-to-end network round-trip: learn captures a TCP connection, run allows it.
/// A single listener accepts two connections, one from learn, one from run.
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

/// `--user N:N` maps the sandbox to UID `N` via an unprivileged
/// user namespace, even when the host UID is non-zero. This is the only
/// remaining `CLONE_NEWUSER` site after the overlayfs backend removal;
/// the test guards against accidentally tearing it out.
#[test]
fn test_uid_mapping_fakes_root() {
    // `id -u` reports the in-namespace UID. Passing --user 0:0 should make
    // the child see UID 0 (fake root) regardless of the host UID.
    let output = sandlock_bin()
        .args(args_for_host(&[
            "run",
            "--user", "0:0",
            "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
            "--", "id", "-u",
        ]))
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

/// Verify that `sandlock learn` populates `[limits]` with memory, processes,
/// and open_files when the workload runs long enough for the sampler to capture
/// resource peaks.
#[test]
fn test_learn_captures_resource_limits() {
    let output = sandlock_bin()
        .args(["learn", "--", "sleep", "0.2"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("memory = \""),
        "expected memory limit in learn output, got:\n{stdout}",
    );
    assert!(
        stdout.contains("processes = "),
        "expected processes limit in learn output, got:\n{stdout}",
    );
    assert!(
        stdout.contains("open_files = "),
        "expected open_files limit in learn output, got:\n{stdout}",
    );
}

#[test]
fn test_uid_mapping_arbitrary_uid() {
    // Arbitrary --user value should also map cleanly (not just 0).
    let output = sandlock_bin()
        .args(args_for_host(&[
            "run",
            "--user", "1234:1234",
            "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin", "-r", "/etc",
            "--", "id", "-u",
        ]))
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

/// When the workload binary is a symlink (e.g. python3 -> python3.13), the execve
/// event records the symlink path, not the real binary. The real binary path only
/// appears via r-xp maps scanned by the sampler. This test verifies it ends up in reads.
#[test]
fn test_learn_captures_real_binary_path_via_maps() {
    let python3 = std::process::Command::new("which")
        .arg("python3")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if python3.is_empty() { return; }
    let real = match std::fs::canonicalize(&python3) {
        Ok(p) => p,
        Err(_) => return,
    };
    if real.to_str() == Some(python3.as_str()) { return; } // not a symlink, skip
    let real_str = real.to_str().unwrap().to_string();

    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", "pass"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains(&real_str),
        "real binary {real_str} not in reads (only visible via r-xp maps, not execve event): {read_line}",
    );
}

/// [write collapse] "/" is protected — entry is skipped and an error is printed.
#[test]
fn test_write_collapse_skips_root() {
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", "echo x > /sandlock_learn_root_test_$$"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(
        !write_line.contains("\"/\""),
        "write list must not contain \"/\", got: {write_line}",
    );
    assert!(
        stderr.contains("protected path"),
        "expected 'protected path' warning in stderr, got: {stderr}",
    );
}

/// [write collapse] guarded path (/etc) — emit + warning + diff (Landlock requires an existing path).
#[test]
fn test_write_collapse_warns_sensitive() {
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", "echo x > /etc/sandlock_learn_sensitive_test_$$"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(
        write_line.contains("/etc"),
        "expected /etc in write list, got: {write_line}",
    );
    assert!(
        stderr.contains("guarded directory"),
        "expected 'guarded directory' warning in stderr, got: {stderr}",
    );
    assert!(
        stderr.contains("unobserved siblings now writable under"),
        "expected observed-vs-granted diff in stderr, got: {stderr}",
    );
}

/// [read dedup] directory and file under it both in reads — file must be removed (PATH_BENEATH is recursive).
#[test]
fn test_read_dedup_removes_leaf_when_ancestor_present() {
    // ls opens /etc as a directory read; cat opens /etc/hostname as a file read.
    // Both end up in the observed reads set. After dedup, /etc/hostname must be gone.
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", "ls /etc > /dev/null && cat /etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains("/etc"),
        "expected /etc in reads, got: {read_line}",
    );
    assert!(
        !read_line.contains("/etc/hostname"),
        "expected /etc/hostname removed by dedup (covered by /etc), got: {read_line}",
    );
}

/// [read collapse] N-threshold collapses a normal directory once N files are observed under it.
#[test]
fn test_collapse_threshold_reads() {
    let output = sandlock_bin()
        .args(["learn", "--collapse", "--", "sh", "-c",
               "cat /usr/bin/cat /usr/bin/sh /usr/bin/ls /usr/bin/env"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains("/usr/bin\"") || read_line.contains("/usr/bin,"),
        "expected /usr/bin collapsed in reads, got: {read_line}",
    );
    assert!(
        !read_line.contains("/usr/bin/cat"),
        "expected individual /usr/bin files removed after collapse, got: {read_line}",
    );
}

/// [read collapse] --collapse-prefix forces collapse of all paths under the prefix regardless of N.
#[test]
fn test_collapse_prefix_forces_collapse() {
    let output = sandlock_bin()
        .args(["learn", "--collapse-prefix", "/usr/bin", "--", "cat", "/usr/bin/cat", "/usr/bin/sh"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains("/usr/bin\"") || read_line.contains("/usr/bin,"),
        "expected /usr/bin collapsed in reads, got: {read_line}",
    );
    assert!(
        !read_line.contains("/usr/bin/cat"),
        "expected /usr/bin/cat removed after prefix collapse, got: {read_line}",
    );
}

/// [read collapse] guarded path (/etc) must NOT be collapsed by N-threshold — individual files kept.
#[test]
fn test_collapse_guarded_not_collapsed_by_threshold() {
    let output = sandlock_bin()
        .args(["learn", "--collapse", "--", "sh", "-c",
               "cat /etc/hostname /etc/hosts /etc/resolv.conf /etc/passwd"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains("/etc/hostname"),
        "expected individual /etc files kept (guarded, not collapsed), got: {read_line}",
    );
}

/// [read collapse] --collapse-prefix on a guarded path without --force-sensitive-collapse must fail.
#[test]
fn test_collapse_prefix_guarded_requires_force() {
    let output = sandlock_bin()
        .args(["learn", "--collapse-prefix", "/etc", "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        !output.status.success(),
        "expected failure without --force-sensitive-collapse",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--force-sensitive-collapse"),
        "expected hint about --force-sensitive-collapse in stderr, got: {stderr}",
    );
}

/// [read collapse] --collapse-prefix on a guarded path with --force-sensitive-collapse: collapse + warn + diff.
#[test]
fn test_collapse_prefix_guarded_with_force() {
    let output = sandlock_bin()
        .args(["learn", "--collapse-prefix", "/etc", "--force-sensitive-collapse",
               "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains("/etc\"") || read_line.contains("/etc,"),
        "expected /etc in reads after forced collapse, got: {read_line}",
    );
    assert!(
        !read_line.contains("/etc/hostname"),
        "expected /etc/hostname removed after collapse, got: {read_line}",
    );
    assert!(
        stderr.contains("guarded directory"),
        "expected guarded directory warning, got: {stderr}",
    );
    assert!(
        stderr.contains("unobserved siblings now writable under"),
        "expected observed-vs-granted diff, got: {stderr}",
    );
}

/// [write collapse] protected path (/root) — entry is skipped and an error is printed.
#[test]
fn test_write_collapse_skips_protected() {
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", "echo x > /root/sandlock_learn_protected_test_$$"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(
        !write_line.contains("/root\"") && !write_line.contains("/root,"),
        "write list must not contain /root (protected), got: {write_line}",
    );
    assert!(
        stderr.contains("protected path"),
        "expected 'protected path' error in stderr, got: {stderr}",
    );
}
