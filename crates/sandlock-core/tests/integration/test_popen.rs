//! Integration tests for the streaming-stdio `popen` API (RFC #67).
//!
//! `popen` generalizes the capture/inherit seam into a per-stream
//! `StdioMode`, returning a `Process` whose piped streams the caller owns and
//! drains while the process is alive — the thing capture-mode `run` cannot do.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};

use sandlock_core::{Sandbox, StdioMode};

fn base() -> Sandbox {
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

/// stdin + stdout piped: write to the child and read its streamed output
/// back while it is alive. `cat` echoes stdin to stdout, so the bytes we
/// write must come back, then EOF on stdin lets it exit cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_popen_pipe_roundtrip() {
    let mut sb = base().with_name("popen-cat");
    let mut child = sb
        .popen(&["cat"], StdioMode::Piped, StdioMode::Piped, StdioMode::Inherit)
        .await
        .unwrap();

    let mut stdin = File::from(child.take_stdin().expect("stdin pipe"));
    let mut stdout = File::from(child.take_stdout().expect("stdout pipe"));
    assert!(child.take_stderr().is_none(), "stderr was Inherit, not piped");

    stdin.write_all(b"hello\n").unwrap();
    drop(stdin); // EOF → cat exits and closes stdout

    let mut out = String::new();
    stdout.read_to_string(&mut out).unwrap();
    assert_eq!(out, "hello\n");

    let res = child.wait().await.unwrap();
    assert!(res.success());
}

/// Only stdout piped (stdin/stderr inherit): a plain capture-equivalent
/// where the caller drains the stream directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_popen_stdout_only() {
    let mut sb = base().with_name("popen-echo");
    let mut child = sb
        .popen(&["echo", "hi"], StdioMode::Inherit, StdioMode::Piped, StdioMode::Inherit)
        .await
        .unwrap();
    assert!(child.take_stdin().is_none(), "stdin was Inherit");
    let mut stdout = File::from(child.take_stdout().expect("stdout pipe"));
    let mut out = String::new();
    stdout.read_to_string(&mut out).unwrap();
    assert_eq!(out, "hi\n");
    assert!(child.wait().await.unwrap().success());
}

/// Null stdout is actually wired to `/dev/null`, not left inherited. The child
/// stats its own fd 1 and exits 0 only if it is the null device (char 1:3), so
/// the test fails if `Null` silently fell back to inherit or to a pipe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_popen_null_stdout_is_dev_null() {
    let mut sb = base().with_name("popen-null");
    let child = sb
        .popen(
            // Stat the *shell's* fd 1 via $$ — `$(...)` would rebind fd 1 for the
            // inner stat itself, so /proc/self/fd/1 there is the substitution pipe.
            &["sh", "-c", r#"[ "$(stat -L -c %t:%T /proc/$$/fd/1)" = 1:3 ]"#],
            StdioMode::Inherit,
            StdioMode::Null,
            StdioMode::Inherit,
        )
        .await
        .unwrap();
    let res = child.wait().await.unwrap();
    assert!(res.success(), "fd 1 was not /dev/null (1:3): exit={:?}", res.exit_status);
}

/// stderr piped independently of stdout: the stderr match arm must dup the
/// pipe onto fd 2 (not 1), which a copy-paste swap would break.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_popen_stderr_piped() {
    let mut sb = base().with_name("popen-stderr");
    let mut child = sb
        .popen(&["sh", "-c", "echo oops 1>&2"], StdioMode::Inherit, StdioMode::Inherit, StdioMode::Piped)
        .await
        .unwrap();
    assert!(child.take_stdout().is_none(), "stdout was Inherit");
    let mut stderr = File::from(child.take_stderr().expect("stderr pipe"));
    let mut out = String::new();
    stderr.read_to_string(&mut out).unwrap();
    assert_eq!(out, "oops\n");
    assert!(child.wait().await.unwrap().success());
}

/// A piped stdin the caller never takes must still reach EOF at `wait`, or a
/// child that reads stdin (`cat`) would block forever. Exercises wait()'s
/// drop of the untaken stdin write end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_popen_untaken_stdin_reaches_eof() {
    let mut sb = base().with_name("popen-stdin-eof");
    let child = sb
        .popen(&["cat"], StdioMode::Piped, StdioMode::Null, StdioMode::Inherit)
        .await
        .unwrap();
    // Deliberately do not take stdin. cat reads to EOF; wait must deliver it.
    let res = child.wait().await.unwrap();
    assert!(res.success(), "cat did not exit — untaken stdin never EOF'd");
}

/// Dropping the owning Sandbox kills the whole process group and reaps it,
/// including a grandchild the workload forked. The grandchild reparents to
/// init on death, so `kill(pid, 0)` returns ESRCH cleanly (no zombie).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_popen_group_killed_on_drop() {
    let gc_pid: i32;
    {
        let mut sb = base().with_name("popen-group");
        let mut child = sb
            .popen(
                &["sh", "-c", "sleep 100 & echo $! ; wait"],
                StdioMode::Inherit,
                StdioMode::Piped,
                StdioMode::Inherit,
            )
            .await
            .unwrap();
        let stdout = File::from(child.take_stdout().expect("stdout pipe"));
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        gc_pid = line.trim().parse().expect("grandchild pid");
        assert!(unsafe { libc::kill(gc_pid, 0) } == 0, "grandchild should be alive");
        // sb (and child borrow) dropped here → Sandbox::drop kills the group.
    }
    // Poll for ESRCH rather than a fixed sleep: after the group SIGKILL the
    // grandchild is a zombie until init/subreaper reaps it (kill(pid,0) returns
    // 0 for a zombie), and reaping can take >200ms on a loaded box.
    let mut reaped = false;
    for _ in 0..100 {
        if unsafe { libc::kill(gc_pid, 0) } != 0 {
            reaped = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(reaped, "grandchild {gc_pid} should be dead+reaped after group kill");
}

/// Regression: capture-mode `run` still buffers stdout into the RunResult
/// after the do_create stdio refactor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_run_still_captures_stdout() {
    let res = base().with_name("run-capture").run(&["echo", "captured"]).await.unwrap();
    assert!(res.success());
    assert_eq!(res.stdout_str(), Some("captured"));
}

/// All three streams piped at once — exercises the relocate/wire path for the
/// full set (a fd collision or wrong ordering would cross or drop a stream).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_popen_all_three_piped() {
    let mut sb = base().with_name("popen-3pipe");
    // cat echoes stdin→stdout; then a marker is written to stderr.
    let mut child = sb
        .popen(&["sh", "-c", "cat; echo err 1>&2"], StdioMode::Piped, StdioMode::Piped, StdioMode::Piped)
        .await
        .unwrap();
    let mut stdin = File::from(child.take_stdin().expect("stdin"));
    let mut stdout = File::from(child.take_stdout().expect("stdout"));
    let mut stderr = File::from(child.take_stderr().expect("stderr"));

    stdin.write_all(b"data\n").unwrap();
    drop(stdin); // EOF → cat finishes, sh runs the echo, then exits

    let mut out = String::new();
    stdout.read_to_string(&mut out).unwrap();
    let mut err = String::new();
    stderr.read_to_string(&mut err).unwrap();
    assert_eq!(out, "data\n");
    assert_eq!(err, "err\n");
    assert!(child.wait().await.unwrap().success());
}

/// Null stdin delivers immediate EOF: `cat` reading /dev/null exits 0 at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_popen_null_stdin_is_eof() {
    let mut sb = base().with_name("popen-null-stdin");
    let child = sb
        .popen(&["cat"], StdioMode::Null, StdioMode::Null, StdioMode::Inherit)
        .await
        .unwrap();
    assert!(child.wait().await.unwrap().success());
}

/// Explicit Process::kill terminates the child; wait still collects a
/// non-success exit status.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_popen_explicit_kill_then_wait() {
    let mut sb = base().with_name("popen-kill");
    let mut child = sb
        .popen(&["sleep", "100"], StdioMode::Inherit, StdioMode::Inherit, StdioMode::Inherit)
        .await
        .unwrap();
    child.kill().expect("kill");
    let res = child.wait().await.unwrap();
    assert!(!res.success(), "a killed process must not report success");
}

/// A Sandbox runs one process: popen on an already-used Sandbox is rejected
/// rather than silently corrupting runtime state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_popen_rejects_second_spawn() {
    let mut sb = base().with_name("popen-twice");
    let first = sb
        .popen(&["echo", "first"], StdioMode::Inherit, StdioMode::Inherit, StdioMode::Inherit)
        .await
        .unwrap();
    first.wait().await.unwrap(); // consume the Process → releases the &mut borrow

    let second = sb
        .popen(&["echo", "second"], StdioMode::Inherit, StdioMode::Inherit, StdioMode::Inherit)
        .await;
    assert!(second.is_err(), "second popen on a used Sandbox must error, not reuse state");
}
