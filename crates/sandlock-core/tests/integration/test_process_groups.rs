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
    sb.fs_writable.push(dir.path().into());
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
    sb.fs_writable.push(dir.path().into());
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

fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wait_keeps_jobs_and_shutdown_ends_them() {
    use std::io::BufRead;
    let mut sb = policy();
    let mut proc = sb
        .popen(
            &["sh", "-c", "sleep 60 & echo $!; exit 3"],
            sandlock_core::StdioMode::Inherit,
            sandlock_core::StdioMode::Piped,
            sandlock_core::StdioMode::Inherit,
        )
        .await
        .unwrap();
    let mut job = String::new();
    std::io::BufReader::new(std::fs::File::from(proc.take_stdout().unwrap()))
        .read_line(&mut job)
        .unwrap();
    let job: i32 = job.trim().parse().unwrap();
    assert_eq!(
        proc.wait().await.unwrap(),
        sandlock_core::ExitStatus::Code(3)
    );
    assert!(alive(job), "the job survives wait()");
    assert!(!proc
        .controller()
        .unwrap()
        .process_groups()
        .unwrap()
        .is_empty());
    assert_eq!(
        proc.shutdown().await.unwrap().exit_status,
        sandlock_core::ExitStatus::Code(3)
    );
    assert!(wait_gone(job), "shutdown() ends the job");
}

#[tokio::test]
async fn test_join_lets_jobs_finish_and_returns_mains_status() {
    let mut sb = policy();
    sb.spawn(&[
        "sh",
        "-c",
        "(sleep 0.5; echo job-done) & echo main-done; exit 3",
    ])
    .await
    .unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), sb.join())
        .await
        .expect("join() hung")
        .unwrap();
    assert_eq!(status, sandlock_core::ExitStatus::Code(3));
    let result = sb.shutdown().await.unwrap();
    assert_eq!(result.exit_status, sandlock_core::ExitStatus::Code(3));
    assert_eq!(
        result.stdout.as_deref(),
        Some(b"main-done\njob-done\n".as_slice())
    );
}

#[tokio::test]
async fn test_shutdown_returns_output_while_a_job_holds_stdout() {
    let mut sb = policy();
    sb.spawn(&["sh", "-c", "sleep 60 & echo main-output"])
        .await
        .unwrap();
    sb.wait().await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), sb.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.stdout.as_deref(), Some(b"main-output\n".as_slice()));
}

/// The reaper collects a main that exits right after exec before spawn()
/// can see its new image; spawn() must still report success.
#[tokio::test]
async fn test_spawn_of_an_instantly_exiting_main() {
    for _ in 0..50 {
        let mut sb = policy();
        sb.spawn(&["true"]).await.unwrap();
        assert_eq!(sb.wait().await.unwrap(), sandlock_core::ExitStatus::Code(0));
        sb.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn test_spawn_beside_a_parked_sibling() {
    let mut parked = policy();
    parked.create(&["true"]).await.unwrap();
    let mut sb = policy();
    tokio::time::timeout(std::time::Duration::from_secs(5), sb.spawn(&["true"]))
        .await
        .unwrap()
        .unwrap();
    sb.wait().await.unwrap();
    sb.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_pid_is_gone_once_main_exits() {
    let mut sb = policy();
    sb.spawn(&["sh", "-c", "sleep 60 & exit 0"]).await.unwrap();
    let controller = sb.controller().unwrap();
    sb.wait().await.unwrap();
    assert_eq!(sb.pid(), None);
    assert_eq!(controller.pid(), None);
    sb.shutdown().await.unwrap();
}

/// Main's status must not depend on a task of the runtime that created the
/// sandbox.
#[test]
fn test_wait_on_another_runtime() {
    let runtime = || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    };
    let mut sb = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .no_supervisor(true)
        .build()
        .unwrap();
    let first = runtime();
    first
        .block_on(sb.spawn(&["sh", "-c", "sleep 0.2; exit 3"]))
        .unwrap();
    drop(first);
    let second = runtime();
    let status = second
        .block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), sb.wait()).await
        })
        .expect("wait() hangs")
        .unwrap();
    assert_eq!(status, sandlock_core::ExitStatus::Code(3));
    second.block_on(sb.shutdown()).unwrap();
}

#[tokio::test]
async fn test_spawn_reports_a_failed_exec() {
    let mut sb = policy();
    assert!(sb.spawn(&["/nonexistent-sandlock-binary"]).await.is_err());
}

#[tokio::test]
async fn test_shutdown_ends_a_paused_session() {
    let mut sb = policy();
    sb.spawn(&["sh", "-c", "sleep 60 & exit 0"]).await.unwrap();
    sb.wait().await.unwrap();
    sb.controller().unwrap().pause().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), sb.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_controller_kills_during_a_blocked_wait() {
    let mut sb = policy();
    sb.spawn(&["sleep", "60"]).await.unwrap();
    let controller = sb.controller().unwrap();
    let killer = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        controller.kill().unwrap();
    });
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), sb.wait())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(status, sandlock_core::ExitStatus::Code(0));
    killer.await.unwrap();
    sb.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_cancelled_wait_then_shutdown() {
    let mut sb = policy();
    sb.spawn(&["sh", "-c", "sleep 0.3; echo done"])
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), sb.wait())
            .await
            .is_err()
    );
    assert_eq!(sb.wait().await.unwrap(), sandlock_core::ExitStatus::Code(0));
    assert_eq!(
        sb.shutdown().await.unwrap().stdout.as_deref(),
        Some(b"done\n".as_slice())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_drop_after_wait_ends_jobs() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("job");
    let mut sb = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(dir.path())
        .build()
        .unwrap();
    sb.spawn(&[
        "sh",
        "-c",
        &format!("sleep 60 & echo $! > {}", pidfile.display()),
    ])
    .await
    .unwrap();
    sb.wait().await.unwrap();
    let job: i32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(alive(job));
    drop(sb);
    assert!(wait_gone(job));
}

/// Dropping the sandbox after wait() must also reach jobs that left main's
/// group, not only those the reaper can kill by itself.
#[tokio::test(flavor = "multi_thread")]
async fn test_drop_after_wait_ends_jobs_in_other_groups() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("leader");
    let script = format!(
        "import os, signal\npid = os.fork()\nif pid == 0:\n    os.setsid()\n    signal.pause()\nopen('{p}.tmp', 'w').write(str(pid))\nos.rename('{p}.tmp', '{p}')\n",
        p = pid_file.display()
    );
    let mut sb = policy();
    sb.fs_writable.push(dir.path().into());
    sb.spawn(&["python3", "-c", &script]).await.unwrap();
    sb.wait().await.unwrap();
    let leader: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(alive(leader), "the setsid job survives wait()");
    drop(sb);
    assert!(
        wait_gone(leader),
        "Drop must end jobs in groups the sandbox created"
    );
}
