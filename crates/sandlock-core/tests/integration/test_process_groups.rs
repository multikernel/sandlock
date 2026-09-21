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
