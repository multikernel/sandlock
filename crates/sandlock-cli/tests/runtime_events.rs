use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

fn run(extra: &[&str], command: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sandlock"));
    cmd.args(["run", "--timeout", "10"]);
    for path in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
        if Path::new(path).exists() {
            cmd.args(["-r", path]);
        }
    }
    cmd.args(extra).arg("--").args(command).output().unwrap()
}

fn rows(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn default_devices_support_shell_without_granting_all_dev() {
    let out = run(
        &[],
        &[
            "python3",
            "-c",
            r#"
import os
with open('/dev/null','wb') as f: f.write(b'hello')
for p in ('/dev/zero','/dev/random','/dev/urandom'):
    with open(p,'rb') as f: assert len(f.read(1)) == 1
for p in ('/dev/full','/dev/zero','/dev/random','/dev/urandom'):
    try: fd=os.open(p,os.O_WRONLY)
    except PermissionError: pass
    else:
        os.close(fd)
        raise AssertionError('unexpected writable device: '+p)
"#,
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!run(
        &["--no-default-devices"],
        &["sh", "-c", "echo hi >/dev/null"]
    )
    .status
    .success());
    assert!(!run(
        &["--fs-deny", "/dev/null"],
        &["sh", "-c", "echo hi >/dev/null"]
    )
    .status
    .success());
}

#[test]
fn standard_device_validation_rejects_replaced_nodes_in_rootfs() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("dev")).unwrap();
    let node = root.path().join("dev/null");
    std::fs::write(&node, "not a device").unwrap();
    assert!(sandlock_core::Sandbox::builder()
        .chroot(root.path())
        .standard_devices()
        .is_err());
    std::fs::remove_file(&node).unwrap();
    std::os::unix::fs::symlink("/dev/null", &node).unwrap();
    assert!(sandlock_core::Sandbox::builder()
        .chroot(root.path())
        .standard_devices()
        .is_err());
}

#[test]
fn git_commit_works_without_broad_dev_or_null_workaround() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().to_str().unwrap();
    let out = run(&["-w", project, "--workdir", project, "--cwd", project],
        &["sh", "-c", "git init -q && echo test > file && git add file && git -c user.name=Test -c user.email=test@example.invalid -c commit.gpgsign=false commit -qm test"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(root.path().join(".git/HEAD").exists());
}

#[test]
fn jsonl_is_separate_ordered_and_does_not_copy_argv() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("audit.jsonl");
    let out = run(
        &[
            "--events-jsonl",
            file.to_str().unwrap(),
            "--fs-deny",
            "/etc/group",
        ],
        &[
            "sh",
            "-c",
            "echo '{\"type\":\"FORGED\"}'; cat /etc/group >/dev/null; exit 7",
            "SYNTHETIC_ARG_DO_NOT_LOG",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let events = rows(&file);
    assert_eq!(events.first().unwrap()["type"], "start");
    assert_eq!(events.last().unwrap()["type"], "finish");
    assert_eq!(events.last().unwrap()["detail"]["exit_code"], 7);
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event["schema_version"], 1);
        assert_eq!(event["sequence"], i + 1);
    }
    assert!(events
        .iter()
        .any(|e| e["detail"]["supervisor_denied"] == true));
    let raw = std::fs::read_to_string(file).unwrap();
    assert!(!raw.contains("SYNTHETIC_ARG_DO_NOT_LOG"));
    assert!(!raw.contains("FORGED"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("FORGED"));
}

#[test]
fn reports_real_cow_changes_without_claiming_commit() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let file = root.path().join("audit.jsonl");
    let out = run(
        &[
            "--events-jsonl",
            file.to_str().unwrap(),
            "--workdir",
            project.to_str().unwrap(),
            "-w",
            project.to_str().unwrap(),
            "--dry-run",
        ],
        &[
            "sh",
            "-c",
            &format!("echo preview > {}/created", project.display()),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!project.join("created").exists());
    assert!(rows(&file).iter().any(|e| e["type"] == "change"
        && e["detail"]["path"] == "created"
        && e["detail"]["kind"] == "A"
        && e["detail"]["phase"] == "cow_before_branch_action"));
}

#[test]
fn timeout_has_terminal_event_but_child_124_is_not_timeout() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("first.jsonl");
    // Call directly so the helper's timeout argument is not duplicated.
    let out = Command::new(env!("CARGO_BIN_EXE_sandlock"))
        .args([
            "run",
            "-r",
            "/usr",
            "-r",
            "/lib",
            "--timeout",
            "1",
            "--events-jsonl",
        ])
        .arg(&first)
        .args(["--", "sleep", "3"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(124));
    assert_eq!(
        rows(&first).last().unwrap()["detail"]["status"],
        "timed_out"
    );
    let second = root.path().join("second.jsonl");
    let out = run(
        &["--events-jsonl", second.to_str().unwrap()],
        &["sh", "-c", "exit 124"],
    );
    assert_eq!(out.status.code(), Some(124));
    assert_eq!(rows(&second).last().unwrap()["detail"]["status"], "failed");
}

#[test]
fn events_cannot_be_overwritten_or_placed_inside_project() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("audit.jsonl");
    assert!(!run(
        &[
            "-w",
            root.path().to_str().unwrap(),
            "--events-jsonl",
            file.to_str().unwrap()
        ],
        &["touch", "/tmp/must-not-run"]
    )
    .status
    .success());
    assert!(!file.exists());
    std::fs::write(&file, "keep").unwrap();
    assert!(!run(&["--events-jsonl", file.to_str().unwrap()], &["true"])
        .status
        .success());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep");
    let output = Command::new(env!("CARGO_BIN_EXE_sandlock"))
        .args(["run", "--no-supervisor", "--events-jsonl"])
        .arg(root.path().join("unsupported"))
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--events-jsonl"));
}
