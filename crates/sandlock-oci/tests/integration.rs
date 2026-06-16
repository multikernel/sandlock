//! Integration tests for sandlock-oci.
//!
//! These tests exercise the OCI lifecycle commands (create/start/state/kill/delete)
//! against a real bundle on the local filesystem.
//!
//! To run: `cargo test -p sandlock-oci -- --test-threads=1`
//!
//! **Note**: the lifecycle commands that fork a sandboxed child need root or a
//! Landlock-capable kernel, but the smoke tests here only exercise argument
//! handling and error paths, so they run unprivileged (including in CI).

use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

/// Path to the sandlock-oci binary under test. Cargo builds it before running
/// the integration target and exposes its path here, so this resolves to the
/// correct profile (debug or release) automatically.
fn oci_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandlock-oci")
}

/// Create a minimal OCI bundle with a rootfs and config.json.
fn create_bundle(dir: &Path, cmd: &[&str]) {
    let rootfs = dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    // Minimal config.json that satisfies oci-spec-rs
    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "root": { "path": "rootfs", "readonly": false },
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "cwd": "/",
            "args": cmd,
            "env": ["PATH=/usr/bin:/bin"]
        },
        "mounts": [],
        "linux": {
            "resources": {
                "devices": [
                    { "allow": false, "access": "rwm" }
                ]
            },
            "namespaces": [
                { "type": "mount" }
            ]
        }
    });
    fs::write(
        dir.join("config.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
}

// ── spec / state unit tests (always run) ────────────────────────────────────

#[test]
fn spec_load_and_policy_mapping() {
    let dir = tempdir().unwrap();
    create_bundle(dir.path(), &["sh", "-c", "exit 0"]);

    // Load spec via the library API.
    let spec = sandlock_oci::spec::load_spec(dir.path())
        .map_err(|e| panic!("load_spec failed: {}", e))
        .unwrap();
    assert_eq!(spec.version(), "1.0.2");

    let policy = sandlock_oci::spec::spec_to_policy(&spec, dir.path(), "test").unwrap();
    // PATH env is forwarded
    assert!(policy.env.contains_key("PATH"));
    // Cwd is forwarded
    assert_eq!(policy.cwd.as_deref(), Some(Path::new("/")));
    // Default rootfs is set
    assert!(policy.rootfs.is_some());
}

#[test]
fn state_created_lifecycle() {
    use sandlock_oci::state::{SandboxState, Status};

    let dir = tempdir().unwrap();
    let mut state = SandboxState::new("test-lifecycle", dir.path(), "1.0.2");
    // new() starts in Creating; set_created() advances to Created.
    assert_eq!(state.status, Status::Creating);

    state.set_created(9999);
    assert_eq!(state.status, Status::Created);
    assert_eq!(state.pid, 9999);

    state.set_running();
    assert_eq!(state.status, Status::Running);

    state.set_stopped(Some(sandlock_oci::state::ExitInfo {
        code: Some(0),
        signal: None,
    }));
    assert_eq!(state.status, Status::Stopped);
    assert!(state.exit_info.is_some());
    assert_eq!(state.exit_info.as_ref().unwrap().code, Some(0));
}

#[test]
fn policy_from_spec_builds_sandbox() {
    let dir = tempdir().unwrap();
    create_bundle(dir.path(), &["sh", "-c", "exit 0"]);

    let spec = sandlock_oci::spec::load_spec(dir.path()).unwrap();
    let policy = sandlock_oci::spec::spec_to_policy(&spec, dir.path(), "test").unwrap();

    // Can convert to sandbox config
    let sandbox = policy.to_sandbox().unwrap();
    assert!(sandbox.chroot.is_some());
}

// ── CLI binary integration tests (require binary to be built) ────────────────

/// Helper: run the sandlock-oci binary with the given args.
fn run_oci(args: &[&str]) -> std::process::Output {
    Command::new(oci_bin())
        .args(args)
        .output()
        .expect("failed to run sandlock-oci")
}

#[test]
fn oci_check_exits_zero() {
    let out = run_oci(&["check"]);
    assert!(
        out.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn oci_state_unknown_sandbox_errors() {
    let out = run_oci(&["state", "this-does-not-exist-xyz-12345"]);
    assert!(!out.status.success(), "expected failure for unknown sandbox");
}

#[test]
fn oci_list_no_sandboxes() {
    // List should succeed even with no state dir.
    let out = run_oci(&["list"]);
    assert!(out.status.success());
}

#[test]
fn oci_kill_unknown_sandbox_errors() {
    let out = run_oci(&["kill", "no-such-sandbox-xyz", "SIGTERM"]);
    assert!(!out.status.success());
}

#[test]
fn oci_delete_nonexistent_is_ok() {
    // Deleting a sandbox that doesn't exist should not fail.
    let out = run_oci(&["delete", "ghost-sandbox-xyz-99"]);
    assert!(out.status.success());
}

#[test]
fn oci_create_rejects_duplicate_id() {
    // The uniqueness guard fires before any fork, so a pre-existing state.json
    // under --root is enough to trigger it — no rootfs or Landlock needed.
    let root = tempdir().unwrap();
    let id = "dup-id-test";
    let cdir = root.path().join(id);
    fs::create_dir_all(&cdir).unwrap();
    fs::write(
        cdir.join("state.json"),
        r#"{"ociVersion":"1.0.2","id":"dup-id-test","status":"created","pid":12345,"bundle":"/tmp","created":0}"#,
    )
    .unwrap();

    let out = Command::new(oci_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "create",
            id,
            "-b",
            "/tmp",
        ])
        .output()
        .expect("failed to run sandlock-oci");

    assert!(!out.status.success(), "duplicate create should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already exists"),
        "expected 'already exists' error, got: {}",
        stderr
    );
}

// ── end-to-end OCI restore (Landlock host, vDSO-free program) ───────────────

/// Freestanding x86_64 program (no libc, no vDSO; raw syscalls only) that opens
/// an output file once, then loops forever rewriting an incrementing counter
/// through the kept-open fd, sleeping via `nanosleep` between writes.
///
/// It is deliberately libc/vDSO-free: glibc caches vDSO pointers in process
/// memory and the injection-based restore engine does not relocate the kernel
/// vDSO, so a libc program (python, sh) resumes but crashes on its first vDSO
/// call. A raw-syscall program lets the test prove the restore engine itself
/// (memory, registers, reopened fd). Mirrors the core restore test.
fn counter_source(out_path: &str) -> String {
    format!(
        r##"
#define SYS_write 1
#define SYS_open 2
#define SYS_nanosleep 35
#define SYS_lseek 8
#define SYS_ftruncate 77
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
static long sys3(long n, long a, long b, long c){{
  long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory"); return r;
}}
struct ts {{ long sec; long nsec; }};
void _start(void){{
  const char *path = "{out_path}";
  long fd = sys3(SYS_open, (long)path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
  unsigned long i = 0;
  char buf[24];
  struct ts t; t.sec = 0; t.nsec = 20000000;
  for(;;){{
    i++;
    int p = 0; unsigned long v = i; char tmp[24]; int k=0;
    if(v==0){{ tmp[k++]='0'; }} while(v){{ tmp[k++]='0'+(v%10); v/=10; }}
    while(k>0){{ buf[p++]=tmp[--k]; }} buf[p++]='\n';
    sys3(SYS_lseek, fd, 0, 0);
    sys3(SYS_ftruncate, fd, 0, 0);
    sys3(SYS_write, fd, (long)buf, p);
    sys3(SYS_nanosleep, (long)&t, 0, 0);
  }}
}}
"##
    )
}

/// End-to-end proof that the OCI `restore` subcommand resumes a checkpointed,
/// vDSO-free program. The checkpoint is produced with sandlock-core (test
/// setup), then the real `sandlock-oci restore` CLI is invoked: it spawns the
/// detached supervisor (`run_supervisor_restore`), which restores AND resumes
/// the child immediately (no `start`). We verify the restored process advances
/// the counter past the checkpointed baseline, that `state` reports `running`,
/// then `delete --force` cleans up.
#[tokio::test(flavor = "multi_thread")]
async fn oci_restore_resumes_vdso_free_program() {
    if cfg!(not(target_arch = "x86_64")) {
        eprintln!("skipping: injection-based restore is x86_64-only");
        return;
    }
    if sandlock_core::landlock_abi_version().is_err() {
        eprintln!("skipping: Landlock unavailable on this host");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("sandlock-oci-restore-{}", std::process::id()));
    fs::create_dir_all(&tmp).unwrap();
    let src = tmp.join("counter.c");
    let bin = tmp.join("counter");
    let counter = tmp.join("counter.cnt");
    let counter_s = counter.to_str().unwrap().to_string();
    let image = tmp.join("image");

    fs::write(&src, counter_source(&counter_s)).unwrap();

    let cc = if which("cc") { "cc" } else if which("gcc") { "gcc" } else {
        eprintln!("skipping: no C compiler (cc/gcc) available");
        let _ = fs::remove_dir_all(&tmp);
        return;
    };
    let build = Command::new(cc)
        .args(["-static", "-nostdlib", "-no-pie", "-O0", "-o"])
        .arg(&bin).arg(&src)
        .output().unwrap();
    if !build.status.success() {
        eprintln!("skipping: build failed: {}", String::from_utf8_lossy(&build.stderr));
        let _ = fs::remove_dir_all(&tmp);
        return;
    }

    // ── Test setup: produce a checkpoint image with sandlock-core ───────────
    let policy = sandlock_core::Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_read(&tmp)
        .fs_write(&tmp)
        .build().unwrap();

    let bin_s = bin.to_str().unwrap().to_string();
    // Capturing spawn so the source's stdio are pipes (not inherited regular
    // files); pipe fds are skipped on restore, isolating the test from however
    // the harness wires the test process's own stdout/stderr.
    let mut sb = policy.clone().with_name("oci-restore-src");
    sb.spawn(&[bin_s.as_str()]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let cp = sb.checkpoint().await.unwrap();
    let read_counter = |path: &str| -> Option<u64> {
        fs::read_to_string(path).ok().and_then(|s| s.trim().parse::<u64>().ok())
    };
    let baseline = read_counter(&counter_s).expect("counter file should exist with a value");
    assert!(baseline > 2, "counter should have advanced before checkpoint, got {baseline}");
    cp.save(&image).unwrap();

    // Kill the source so only a restored process can advance the file.
    sb.kill().unwrap();
    let _ = sb.wait().await;
    // Sentinel: prove the *restored* process (not a leftover) is writing.
    fs::write(&counter, b"0\n").unwrap();

    // ── Exercise the OCI restore CLI ─────────────────────────────────────────
    let root = tempdir().unwrap();
    let root_s = root.path().to_str().unwrap().to_string();
    let id = "oci-restore-e2e";

    // NB: the restore CLI double-forks a long-lived supervisor daemon that
    // inherits stdout/stderr (left open for containerd log FIFOs). Capturing
    // via `Command::output()` would block until those fds close (container
    // exit), so redirect the CLI's stdio to a file and wait only on the CLI
    // with `.status()`.
    let restore_log = tmp.join("restore.log");
    let status = Command::new(oci_bin())
        .args(["--root", &root_s, "restore", id, "--image-path", image.to_str().unwrap()])
        .stdout(std::process::Stdio::from(fs::File::create(&restore_log).unwrap()))
        .stderr(std::process::Stdio::from(
            fs::OpenOptions::new().append(true).open(&restore_log).unwrap(),
        ))
        .status()
        .expect("failed to run sandlock-oci restore");
    let restore_out = fs::read_to_string(&restore_log).unwrap_or_default();
    assert!(
        status.success(),
        "restore CLI failed (exit {:?}): {}",
        status.code(),
        restore_out,
    );

    // State should report running immediately (restore resumes, no start).
    let st = Command::new(oci_bin())
        .args(["--root", &root_s, "state", id])
        .output()
        .expect("failed to run sandlock-oci state");
    let st_json = String::from_utf8_lossy(&st.stdout);
    assert!(
        st_json.contains("\"running\""),
        "expected running state after restore, got: {}",
        st_json
    );

    // Poll for the restored process to resume mid-loop and advance the counter.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    let mut last = 0u64;
    let mut advanced = false;
    while std::time::Instant::now() < deadline {
        if let Some(v) = read_counter(&counter_s) {
            last = v;
            if v > baseline {
                advanced = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Clean up via the CLI before asserting so a failure never leaks the child.
    let _ = Command::new(oci_bin())
        .args(["--root", &root_s, "delete", id, "--force"])
        .output();
    let _ = fs::remove_dir_all(&tmp);

    assert!(
        advanced,
        "OCI-restored process must resume mid-loop and advance the counter past {baseline}; \
         last seen {last}, restore log: {restore_out}",
    );
}

/// Minimal PATH lookup so the test does not depend on extra crates.
fn which(prog: &str) -> bool {
    std::env::var_os("PATH").map_or(false, |paths| {
        std::env::split_paths(&paths).any(|d| d.join(prog).is_file())
    })
}