//! The exec relay carries policy-checked execs: what the policy saw is what
//! runs, whatever the sandbox does to argv memory in the meantime, and the
//! program that finally runs cannot tell it was relayed.

use sandlock_core::policy_fn::Verdict;
use sandlock_core::Sandbox;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("tests/rootfs-helper is built by build.rs")
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sl-relay-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn base_policy() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
}

fn stdout_of(r: &sandlock_core::result::RunResult) -> String {
    String::from_utf8_lossy(r.stdout.as_deref().unwrap_or(b"")).trim().to_string()
}

fn stderr_of(r: &sandlock_core::result::RunResult) -> String {
    String::from_utf8_lossy(r.stderr.as_deref().unwrap_or(b"")).trim().to_string()
}

/// A sibling thread flips argv[1] between "allowed" and "blocked" while the
/// process execs. Whatever the policy judged is what must run: "blocked" is
/// denied, and anything that prints must be the word the policy recorded.
#[tokio::test]
async fn race_cannot_change_what_runs() {
    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();
    let policy = base_policy()
        .fs_read(&helper_dir)
        .policy_fn(move |event, _ctx| {
            if event.syscall == "execve" {
                if let Some(argv) = &event.argv {
                    if argv.first().map(|a| a == "echo").unwrap_or(false) {
                        seen_cb.lock().unwrap().push(argv.get(1).cloned().unwrap_or_default());
                        if event.argv_contains("blocked") {
                            return Verdict::Deny;
                        }
                    }
                }
            }
            Verdict::Allow
        })
        .build()
        .unwrap();

    let helper_s = helper.to_str().unwrap();
    let mut printed = 0;
    for _ in 0..40 {
        seen.lock().unwrap().clear();
        let r = policy.clone().run(&[helper_s, "argv-race"]).await.unwrap();
        let out = stdout_of(&r);
        assert!(!out.contains("blocked"), "a denied argv ran: {out:?}");
        let judged = seen.lock().unwrap().last().cloned();
        if !out.is_empty() {
            printed += 1;
            assert_eq!(Some(out.clone()), judged, "what ran differs from what the policy judged");
        } else {
            assert_eq!(judged.as_deref(), Some("blocked"), "silent run was not a deny: {}", stderr_of(&r));
        }
    }
    assert!(printed > 0, "the allowed word never ran in 40 attempts");
}

#[tokio::test]
async fn script_sees_its_own_path_as_dollar_zero() {
    let dir = scratch_dir("script");
    let script = dir.join("show-name.sh");
    std::fs::write(&script, "#!/bin/sh\necho \"$0\"\n").unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let policy = base_policy().fs_read(&dir).policy_fn(|_e, _c| Verdict::Allow).build().unwrap();
    let r = policy.clone().run(&[script.to_str().unwrap()]).await.unwrap();
    assert!(r.success(), "stderr: {}", stderr_of(&r));
    assert_eq!(stdout_of(&r), script.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn argv0_is_preserved_for_elf() {
    let policy = base_policy().policy_fn(|_e, _c| Verdict::Allow).build().unwrap();
    let r = policy
        .clone()
        .run(&["python3", "-c", "import os; os.execv('/bin/sh', ['custom0', '-c', 'echo $0'])"])
        .await
        .unwrap();
    assert!(r.success(), "stderr: {}", stderr_of(&r));
    assert_eq!(stdout_of(&r), "custom0");
}

#[tokio::test]
async fn comm_is_the_program_name() {
    let policy = base_policy().policy_fn(|_e, _c| Verdict::Allow).build().unwrap();
    let r = policy.clone().run(&["sh", "-c", "cat /proc/self/comm"]).await.unwrap();
    assert!(r.success(), "stderr: {}", stderr_of(&r));
    assert_eq!(stdout_of(&r), "cat");
}

/// execvp walks PATH on ENOENT, so a missing target must fail the caller's
/// execve itself rather than run a relay that fails later.
#[tokio::test]
async fn missing_binary_returns_enoent_to_the_caller() {
    let policy = base_policy().policy_fn(|_e, _c| Verdict::Allow).build().unwrap();
    let script = "import os\ntry:\n    os.execv('/nonexistent/x', ['x'])\nexcept FileNotFoundError:\n    print('ENOENT')\n";
    let r = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    assert_eq!(stdout_of(&r), "ENOENT", "stderr: {}", stderr_of(&r));
}

#[tokio::test]
async fn non_executable_file_returns_eacces_to_the_caller() {
    let dir = scratch_dir("noexec");
    let file = dir.join("plain");
    std::fs::write(&file, "not a program").unwrap();
    std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    let policy = base_policy().fs_read(&dir).policy_fn(|_e, _c| Verdict::Allow).build().unwrap();
    let script = format!(
        "import os\ntry:\n    os.execv('{}', ['plain'])\nexcept PermissionError:\n    print('EACCES')\n",
        file.display()
    );
    let r = policy.clone().run(&["python3", "-c", &script]).await.unwrap();
    assert_eq!(stdout_of(&r), "EACCES", "stderr: {}", stderr_of(&r));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The relay's own execve is not an application exec and must not reach
/// the callback a second time.
#[tokio::test]
async fn one_policy_event_per_exec() {
    let count = Arc::new(Mutex::new(0usize));
    let count_cb = count.clone();
    let policy = base_policy()
        .policy_fn(move |event, _ctx| {
            if event.syscall == "execve" {
                *count_cb.lock().unwrap() += 1;
            }
            Verdict::Allow
        })
        .build()
        .unwrap();
    let r = policy.clone().run(&["/bin/true"]).await.unwrap();
    assert!(r.success());
    assert_eq!(*count.lock().unwrap(), 1);
}

#[tokio::test]
async fn threads_spawning_subprocesses_all_succeed() {
    let policy = base_policy().policy_fn(|_e, _c| Verdict::Allow).build().unwrap();
    let script = concat!(
        "import subprocess, threading\n",
        "ok = []\n",
        "def work():\n",
        "    for _ in range(10):\n",
        "        ok.append(subprocess.run(['/bin/true']).returncode == 0)\n",
        "ts = [threading.Thread(target=work) for _ in range(8)]\n",
        "[t.start() for t in ts]; [t.join() for t in ts]\n",
        "print('SPAWNS', sum(ok))\n",
    );
    let r = tokio::time::timeout(std::time::Duration::from_secs(60), policy.clone().run(&["python3", "-c", script]))
        .await
        .expect("threaded spawns must not hang")
        .unwrap();
    assert_eq!(stdout_of(&r), "SPAWNS 80", "stderr: {}", stderr_of(&r));
}

/// The relay borrows the soft NOFILE limit to pin its fd; the program that
/// finally runs must see the limit it would have had.
#[tokio::test]
async fn soft_nofile_limit_is_restored_for_the_program() {
    let outside = std::process::Command::new("sh").args(["-c", "ulimit -Sn"]).output().unwrap();
    let outside = String::from_utf8_lossy(&outside.stdout).trim().to_string();
    let policy = base_policy().policy_fn(|_e, _c| Verdict::Allow).build().unwrap();
    let r = policy.clone().run(&["sh", "-c", "ulimit -Sn"]).await.unwrap();
    assert_eq!(stdout_of(&r), outside);
}

/// A process sharing its fd table with another process could repopulate the
/// pinned fd number, so that clone shape is refused under an argv policy.
#[tokio::test]
async fn clone_files_without_thread_is_rejected() {
    let policy = base_policy().policy_fn(|_e, _c| Verdict::Allow).build().unwrap();
    let script = concat!(
        "import ctypes, os, platform\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "CLONE_FILES = 0x400; SIGCHLD = 17\n",
        "nr = 56 if platform.machine() == 'x86_64' else 220\n",
        "r = libc.syscall(nr, CLONE_FILES | SIGCHLD, 0, 0, 0, 0)\n",
        "if r == 0: os._exit(0)\n",
        "print('EINVAL' if r < 0 and ctypes.get_errno() == 22 else 'RET %d' % r)\n",
    );
    let r = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    assert_eq!(stdout_of(&r), "EINVAL", "stderr: {}", stderr_of(&r));
}
