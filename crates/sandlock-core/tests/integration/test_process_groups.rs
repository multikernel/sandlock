use sandlock_core::Sandbox;

fn policy() -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap()
}

async fn python_stdout(script: &str) -> String {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        policy().run(&["python3", "-c", script]),
    )
    .await
    .expect("sandbox hung")
    .unwrap();
    String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default())
        .trim()
        .to_string()
}

/// The supervisor shares the sandbox's session, so the kernel alone would
/// let a sandboxed process move into its group, where no group signal
/// could be aimed at it without hitting the supervisor too.
#[tokio::test]
async fn test_joining_the_supervisors_group_is_refused() {
    let out = python_stdout(
        r#"
import errno, os
try:
    os.setpgid(0, os.getpgid(os.getppid()))
    print("moved")
except OSError as e:
    print(errno.errorcode[e.errno])
"#,
    )
    .await;
    assert_eq!(out, "EPERM");
}

/// What a job-control shell does for a pipeline: both sides put the first
/// process into a group of its own, and the second one joins it.
#[tokio::test]
async fn test_job_control_group_moves_are_allowed() {
    let out = python_stdout(
        r#"
import os, signal
def child():
    pid = os.fork()
    if pid == 0:
        os.setpgid(0, 0) if first is None else os.setpgid(0, first)
        signal.pause()
    return pid
first = None
first = child()
os.setpgid(first, first)
second = child()
os.setpgid(second, first)
print(os.getpgid(first) == first and os.getpgid(second) == first)
os.killpg(first, signal.SIGKILL)
"#,
    )
    .await;
    assert_eq!(out, "True");
}

#[tokio::test]
async fn test_a_process_can_leave_and_rejoin_the_main_group() {
    let out = python_stdout(
        r#"
import os
main = os.getpgid(0)
pid = os.fork()
if pid == 0:
    os.setsid()
    os._exit(0 if os.getpgid(0) == os.getpid() else 1)
left = os.waitpid(pid, 0)[1] == 0
pid = os.fork()
if pid == 0:
    os.setpgid(0, 0)
    os.setpgid(0, main)
    os._exit(0 if os.getpgid(0) == main else 1)
print(left and os.waitpid(pid, 0)[1] == 0)
"#,
    )
    .await;
    assert_eq!(out, "True");
}

fn wait_gone(pid: i32) -> bool {
    for _ in 0..300 {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    false
}

/// Spawn a sandbox whose main process has started a session leader of its
/// own, and return that leader's pid.
async fn spawn_with_session_leader(sb: &mut Sandbox) -> i32 {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("leader");
    let script = format!(
        r#"
import os, signal
pid = os.fork()
if pid == 0:
    os.setsid()
    signal.pause()
open("{}.tmp", "w").write(str(pid))
os.rename("{}.tmp", "{}")
signal.pause()
"#,
        pid_file.display(),
        pid_file.display(),
        pid_file.display(),
    );
    sb.fs_writable.push(dir.path().to_path_buf());
    sb.spawn(&["python3", "-c", &script]).await.unwrap();
    for _ in 0..600 {
        if let Ok(text) = std::fs::read_to_string(&pid_file) {
            return text.trim().parse().unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the sandbox never reported its session leader");
}

/// The repro from #252: a setsid() child used to outlive `kill()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_kill_reaches_a_process_that_left_the_main_group() {
    let mut sb = policy().with_name("pgroup-kill");
    let leader = spawn_with_session_leader(&mut sb).await;
    assert_ne!(unsafe { libc::getpgid(leader) }, sb.pid().unwrap());

    sb.kill().unwrap();
    assert!(wait_gone(leader), "session leader {leader} survived kill()");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), sb.wait()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pause_stops_a_process_that_left_the_main_group() {
    let mut sb = policy().with_name("pgroup-pause");
    let leader = spawn_with_session_leader(&mut sb).await;

    sb.pause().unwrap();
    let state = || {
        std::fs::read_to_string(format!("/proc/{leader}/stat"))
            .ok()
            .and_then(|s| s.rsplit_once(") ").map(|(_, rest)| rest.chars().next().unwrap()))
    };
    let mut stopped = false;
    for _ in 0..300 {
        if state() == Some('T') {
            stopped = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(stopped, "session leader {leader} kept running through pause()");

    sb.resume().unwrap();
    sb.kill().unwrap();
    assert!(wait_gone(leader));
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), sb.wait()).await;
}

/// The sweep at the main process's exit covers groups the sandbox created,
/// not only the main one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_exit_sweep_reaches_a_process_that_left_the_main_group() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("leader");
    let script = format!(
        r#"
import os, signal
pid = os.fork()
if pid == 0:
    os.setsid()
    signal.pause()
open("{0}.tmp", "w").write(str(pid))
os.rename("{0}.tmp", "{0}")
"#,
        pid_file.display(),
    );
    let mut sb = policy().with_name("pgroup-exit-sweep");
    sb.fs_writable.push(dir.path().to_path_buf());
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        sb.run(&["python3", "-c", &script]),
    )
    .await
    .expect("run() hung")
    .unwrap();
    assert!(result.success());

    let leader: i32 = std::fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
    assert!(wait_gone(leader), "session leader {leader} outlived the main process");
}
