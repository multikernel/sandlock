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
    open("{}.tmp", "w").write(str(os.getpid()))
    os.rename("{}.tmp", "{}")
    signal.pause()
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
            .and_then(|s| {
                s.rsplit_once(") ")
                    .map(|(_, rest)| rest.chars().next().unwrap())
            })
    };
    let mut stopped = false;
    for _ in 0..300 {
        if state() == Some('T') {
            stopped = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        stopped,
        "session leader {leader} kept running through pause()"
    );

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

    let leader: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(
        wait_gone(leader),
        "session leader {leader} outlived the main process"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wait_keeps_background_jobs_supervised() {
    use sandlock_core::result::ExitStatus;
    use std::time::Duration;

    let mut subreaper_before = 0i32;
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut subreaper_before) },
        0
    );
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let release = dir.path().join("release");
    let done = dir.path().join("done");
    let script = format!(
        r#"
import os, time
pid = os.fork()
if pid == 0:
    os.setsid()
    open({ready:?}, "w").write(str(os.getpid()))
    while not os.path.exists({release:?}):
        time.sleep(0.01)
    print("background output", flush=True)
    open({done:?}, "w").write("supervised")
    while True:
        time.sleep(1)
while not os.path.exists({ready:?}):
    time.sleep(0.01)
os._exit(7)
"#
    );
    let mut sb = policy();
    sb.fs_writable.push(dir.path().to_path_buf());
    sb.spawn(&["python3", "-c", &script]).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), sb.wait())
            .await
            .unwrap()
            .unwrap(),
        ExitStatus::Code(7)
    );
    let mut subreaper_after = 0i32;
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut subreaper_after) },
        0
    );
    assert_eq!(subreaper_before, subreaper_after);
    assert_eq!(sb.wait().await.unwrap(), ExitStatus::Code(7));
    assert!(!sb.is_running());
    let leader: i32 = std::fs::read_to_string(&ready).unwrap().parse().unwrap();
    assert_eq!(sb.process_groups().unwrap(), vec![leader]);
    sb.pause().unwrap();
    sb.resume().unwrap();
    assert_eq!(sb.wait().await.unwrap(), ExitStatus::Code(7));
    std::fs::write(release, "go").unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !done.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("background job lost supervision");
    let result = tokio::time::timeout(Duration::from_secs(10), sb.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.exit_status, ExitStatus::Code(7));
    assert_eq!(result.stdout_str(), Some("background output"));
    assert!(sb.process_groups().unwrap().is_empty());
    assert!(wait_gone(leader));
    assert_eq!(
        sb.shutdown().await.unwrap().exit_status,
        ExitStatus::Code(7)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_drop_after_wait_cleans_background_jobs() {
    use std::time::Duration;
    let mut sb = policy();
    let leader = spawn_with_session_leader(&mut sb).await;
    unsafe { libc::kill(sb.pid().unwrap(), libc::SIGTERM) };
    tokio::time::timeout(Duration::from_secs(10), sb.wait())
        .await
        .unwrap()
        .unwrap();
    drop(sb);
    assert!(wait_gone(leader));
}

#[tokio::test]
async fn test_wait_without_a_child_returns_an_error() {
    let mut sb = policy();
    assert!(sb.wait().await.is_err());
    assert!(sb.shutdown().await.is_err());
    assert!(sb.process_groups().is_err());
}

#[tokio::test]
async fn test_cancelled_wait_preserves_status_and_output() {
    use sandlock_core::result::ExitStatus;
    use std::time::Duration;
    let mut sb = policy();
    sb.spawn(&["sh", "-c", "echo before; sleep 0.2; echo after; exit 23"])
        .await
        .unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(20), sb.wait())
        .await
        .is_err());
    assert_eq!(sb.wait().await.unwrap(), ExitStatus::Code(23));
    let result = sb.shutdown().await.unwrap();
    assert_eq!(result.exit_status, ExitStatus::Code(23));
    assert_eq!(result.stdout_str(), Some("before\nafter"));
}

#[test]
fn test_shutdown_reaps_adopted_jobs_without_reaping_unrelated_children() {
    const CHILD: &str = "SANDLOCK_TEST_BACKGROUND_SUBREAPER";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["test_process_groups::test_shutdown_reaps_adopted_jobs_without_reaping_unrelated_children", "--exact", "--nocapture"])
            .env(CHILD, "1")
            .status().unwrap();
        assert!(status.success());
        return;
    }
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let mut unrelated = std::process::Command::new("sh")
        .args(["-c", "exit 29"])
        .spawn()
        .unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut sb = policy();
        let leader = spawn_with_session_leader(&mut sb).await;
        unsafe { libc::kill(sb.pid().unwrap(), libc::SIGTERM) };
        sb.wait().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), sb.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unsafe { libc::waitpid(leader, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert!(wait_gone(leader));
    });
    assert_eq!(unrelated.wait().unwrap().code(), Some(29));
}

#[test]
fn test_creation_under_fd_pressure_does_not_leave_children() {
    const CHILD: &str = "SANDLOCK_TEST_BACKGROUND_FD_PRESSURE";
    if std::env::var_os(CHILD).is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "test_process_groups::test_creation_under_fd_pressure_does_not_leave_children",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("sandbox creation or cleanup hung under fd pressure");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    for budget in [16, 20, 24, 28, 32] {
        let mut sb = policy();
        let constrained = libc::rlimit {
            rlim_cur: budget,
            rlim_max: limit.rlim_max,
        };
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &constrained) },
            0
        );
        let _ = rt.block_on(sb.create(&["sleep", "30"]));
        drop(sb);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        assert_eq!(
            unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}

#[tokio::test]
async fn test_shutdown_reaps_untracked_groups_without_syscall_supervision() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready");
    let script = format!(
        r#"
import os, signal, time
if os.fork() == 0:
    os.setsid()
    open({ready:?}, "w").write(str(os.getpid()))
    signal.pause()
while not os.path.exists({ready:?}):
    time.sleep(0.01)
"#
    );
    let mut sb = policy();
    sb.no_supervisor = true;
    sb.fs_writable.push(dir.path().to_path_buf());
    sb.spawn(&["python3", "-c", &script]).await.unwrap();
    sb.wait().await.unwrap();
    let leader: i32 = std::fs::read_to_string(ready).unwrap().parse().unwrap();
    let cleanup = tokio::time::timeout(std::time::Duration::from_secs(5), sb.shutdown()).await;
    if cleanup.is_err() {
        unsafe { libc::kill(leader, libc::SIGKILL) };
    }
    cleanup
        .expect("shutdown must also clean untracked descendants")
        .unwrap();
    assert!(wait_gone(leader));
}
