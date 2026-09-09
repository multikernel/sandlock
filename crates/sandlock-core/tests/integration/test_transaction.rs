//! Transaction tests (RFC #65 Phase 1a).
//!
//! Sequential stages share one COW upper over a common workdir: a later stage
//! sees an earlier stage's writes (read-committed), and the whole transaction
//! commits all-or-nothing. Data is exchanged through the shared workspace, not
//! inter-stage pipes.

use sandlock_core::sandbox::BranchAction;
use sandlock_core::{AbortReason, ChangeKind, Sandbox, Stage, Transaction, TxnDisposition, TxnError};
use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandlock-test-txn-{}-{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Base policy shared by every stage: read the system, write+COW the workdir,
/// and run with the workdir as cwd so relative paths resolve into the upper.
/// `on_exit`/`on_error` are left at their defaults (the transaction owns commit).
fn stage_policy(workdir: &Path) -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(workdir)
        .workdir(workdir)
        .cwd(workdir)
        .build()
        .unwrap()
}

/// Whether this environment can actually run a sandbox (Landlock + seccomp). Used
/// to skip the behavioral tests EXPLICITLY, so a real regression in the
/// transaction logic hard-fails instead of hiding behind a tolerated error.
async fn sandbox_available() -> bool {
    let mut sb = Sandbox::builder().fs_read("/usr").fs_read("/bin").build().unwrap();
    matches!(sb.run(&["true"]).await, Ok(r) if r.success())
}

/// Number of branch subdirectories under a `fs_storage` dir. Zero means every COW
/// branch's upper has been reclaimed (committed or aborted or dropped).
fn branch_count(storage: &Path) -> usize {
    fs::read_dir(storage).map(|rd| rd.count()).unwrap_or(0)
}

/// Full success: stage 1 writes `a.txt`, stage 2 reads it (proving read-committed)
/// and writes `b.txt`, stage 3 reads both. On commit both files land in workdir.
#[tokio::test]
async fn test_txn_commits_on_success() {
    if !sandbox_available().await {
        eprintln!("commit test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("commit");
    let policy = stage_policy(&workdir);

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt b.txt"]),
    ])
    .run(None)
    .await
    .expect("transaction should run");

    assert!(outcome.committed(), "transaction should commit; disposition: {:?}", outcome.disposition);
    assert_eq!(outcome.stages.len(), 3, "all three stages should have run");
    assert!(workdir.join("a.txt").exists(), "a.txt must be committed to workdir");
    assert!(workdir.join("b.txt").exists(), "b.txt must be committed to workdir");
    assert_eq!(fs::read_to_string(workdir.join("a.txt")).unwrap(), "plan\n");

    let _ = fs::remove_dir_all(&workdir);
}

/// A later stage must be able to EXECUTE a file an earlier stage created.
///
/// Landlock checks EXECUTE against the file's real path at `execve` time, and a
/// file created in the workdir really lives in the shared upper — so unless the
/// stage's ruleset grants read+execute on that upper, `./x.sh` fails with
/// `EACCES` and the shell reports 126. Nothing else in the suite covers it: the
/// shared-COW path builds no branch of its own, so it does not go through the
/// grant that `Sandbox`'s own branch gets, and
/// `test_cow::test_seccomp_cow_exec_packed_argv_relocation` only covers the
/// plain-`Sandbox` half of that pair.
#[tokio::test]
async fn test_txn_stage_can_exec_what_an_earlier_stage_created() {
    if !sandbox_available().await {
        eprintln!("shared-upper exec test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("shared-upper-exec");
    let policy = stage_policy(&workdir);

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "printf '#!/bin/sh\\nexit 0\\n' > x.sh && chmod 755 x.sh"]),
        // `exec` so the stage's own status IS the exec's outcome: 126 when the
        // kernel refuses it, not a shell error swallowed into 1.
        Stage::new(&policy, &["sh", "-c", "exec ./x.sh"]),
    ])
    .run(None)
    .await
    .expect("transaction should run");

    assert_eq!(
        outcome.disposition, TxnDisposition::Committed,
        "a stage must be able to exec a file an earlier stage created in the shared upper",
    );
    assert!(outcome.committed(), "the transaction should have committed");
    assert!(workdir.join("x.sh").exists(), "x.sh must be committed to the workdir");

    let _ = fs::remove_dir_all(&workdir);
}

/// Whether any branch under `storage` has `name` in its upper. Used to observe
/// how far the stages have got from outside the transaction.
fn upper_holds(storage: &Path, name: &str) -> bool {
    fs::read_dir(storage)
        .map(|rd| rd.flatten().any(|e| e.path().join("upper").join(name).exists()))
        .unwrap_or(false)
}

/// The commit merge is serialized against another transaction's merge, and a
/// transaction that finds the workdir locked WAITS for it rather than
/// discarding a full run's work.
///
/// The lock is held until the transaction is DEMONSTRABLY blocked on it: the
/// test drives the transaction concurrently and fails the moment it finishes
/// while the lock is still held, so it cannot pass by having the holder let go
/// before the commit was ever reached. Only then is the lock released, and the
/// transaction must still commit.
#[tokio::test]
async fn test_txn_waits_for_a_concurrent_commit_lock() {
    if !sandbox_available().await {
        eprintln!("commit-lock-wait test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("commit-lock-wait-wd");
    let storage = temp_dir("commit-lock-wait-st");
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();

    // Stand in for another transaction mid-merge by holding the workdir lock.
    let held = std::fs::File::open(&workdir).unwrap();
    assert_eq!(
        unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test setup: could not take the workdir lock"
    );

    let txn = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
    ])
    .run(None);
    tokio::pin!(txn);

    // Drive the transaction while holding the lock. `b.txt` landing in the
    // shared upper is the last stage's write, so from that point the only thing
    // left for the transaction to do is the commit — and it must not get past
    // it. Completing here at all, committed or not, is the failure.
    let mut stages_done_at = None;
    loop {
        tokio::select! {
            early = &mut txn => panic!(
                "the transaction finished while the commit lock was held — it never waited: {early:?}"
            ),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        match stages_done_at {
            None if upper_holds(&storage, "b.txt") => {
                stages_done_at = Some(std::time::Instant::now())
            }
            // Keep holding for a grace period after the stages are done, so the
            // transaction has had time to reach the commit and block on it.
            Some(t) if t.elapsed() >= Duration::from_millis(500) => break,
            _ => {}
        }
    }
    drop(held);

    let outcome = txn.await.expect("transaction should run");
    assert!(
        outcome.committed(),
        "a transaction must wait out a concurrent commit, not lose its work; disposition: {:?}",
        outcome.disposition
    );
    assert_eq!(fs::read_to_string(workdir.join("a.txt")).unwrap(), "plan\n");
    assert_eq!(fs::read_to_string(workdir.join("b.txt")).unwrap(), "built\n");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// The wait is bounded, and expiring it must NOT throw the run away. Every stage
/// exited 0, so the upper holds a complete, mergeable change set; giving up on
/// the lock leaves the workdir untouched and PRESERVES that upper with its
/// content, naming it in the error.
#[tokio::test]
async fn test_txn_preserves_the_upper_when_the_commit_lock_never_frees() {
    if !sandbox_available().await {
        eprintln!("commit-lock-preserve test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("lock-preserve-wd");
    let storage = temp_dir("lock-preserve-st");
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();

    // Stand in for another transaction whose merge never finishes: the lock is
    // held for the whole test, well past this transaction's wait.
    let held = std::fs::File::open(&workdir).unwrap();
    assert_eq!(
        unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test setup: could not take the workdir lock"
    );

    let err = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
    ])
    .commit_lock_wait(Duration::from_millis(300))
    .run(None)
    .await
    .expect_err("a commit lock that never frees must fail the commit");
    drop(held);

    // All-or-nothing still holds on the workdir side: nothing was merged.
    assert!(!workdir.join("a.txt").exists(), "nothing may be merged when the lock was never taken");
    assert!(!workdir.join("b.txt").exists(), "nothing may be merged when the lock was never taken");

    // ...and the work itself survives, with its bytes, so it can still be
    // published out of band.
    let branches: Vec<PathBuf> =
        fs::read_dir(&storage).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(
        branches.len(),
        1,
        "the upper of a fully successful run must be preserved, not reclaimed; found {branches:?}",
    );
    let upper = branches[0].join("upper");
    assert_eq!(
        fs::read_to_string(upper.join("a.txt")).unwrap(),
        "plan\n",
        "the preserved upper must still hold stage 0's write",
    );
    assert_eq!(
        fs::read_to_string(upper.join("b.txt")).unwrap(),
        "built\n",
        "the preserved upper must still hold stage 1's write",
    );
    // The failure is typed as a CONFLICT — the retryable channel — not as a
    // stage or configuration failure, and it names the preserved upper.
    match &err {
        TxnError::Conflict { workdir: wd, preserved_upper, .. } => {
            assert_eq!(wd, &workdir, "the conflict must name the contended workdir");
            assert_eq!(preserved_upper, &upper, "the conflict must name the preserved upper");
        }
        other => panic!("expected a commit-lock conflict, got: {other:?}"),
    }
    assert_eq!(err.exit_code(), 75, "a conflict reports EX_TEMPFAIL: retry it");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// CANCELLING the run once the commit phase has begun must not destroy the
/// change set.
///
/// This is the case a caller reaches by construction, not an exotic one:
/// `run(timeout)` bounds the stage phase only, so anything wanting a wall-clock
/// bound on the whole thing wraps `run()` in `tokio::time::timeout`, and a
/// shutdown `select!` does the same. Dropping the future while an owned,
/// undisposed branch is alive across an await would reclaim its storage — every
/// stage exited 0 and the whole run would be gone, with no error, no marker and
/// nothing in the workdir.
///
/// The window is held open with the workdir lock, exactly as a concurrent merge
/// would: the transaction is dropped while it is waiting for it.
#[tokio::test]
async fn test_txn_cancelled_during_the_commit_lock_wait_keeps_the_change_set() {
    if !sandbox_available().await {
        eprintln!("commit-cancel test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("cancel-commit-wd");
    let storage = temp_dir("cancel-commit-st");
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();

    // Stand in for another transaction mid-merge, so the commit blocks on the
    // lock instead of racing through it.
    let held = std::fs::File::open(&workdir).unwrap();
    assert_eq!(
        unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test setup: could not take the workdir lock"
    );

    {
        let txn = Transaction::new([
            Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
            Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
        ])
        .commit_lock_wait(Duration::from_secs(5))
        .run(None);
        tokio::pin!(txn);

        // Drive it until the last stage's write is in the shared upper: from
        // there the only thing left is the commit, which cannot get past the
        // held lock. Finishing at all would mean the window never opened.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !upper_holds(&storage, "b.txt") {
            tokio::select! {
                early = &mut txn => panic!("the transaction finished while the lock was held: {early:?}"),
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
            assert!(std::time::Instant::now() < deadline, "stages never reached the commit");
        }
        // Grace for the last stage to be reaped and the commit to be entered.
        tokio::select! {
            early = &mut txn => panic!("the transaction finished while the lock was held: {early:?}"),
            _ = tokio::time::sleep(Duration::from_millis(300)) => {}
        }
    } // <-- the run future is dropped here, mid-wait: the cancellation.

    // The lock is still held, so the commit gives up on it and preserves. Poll
    // for the marker rather than sleeping a fixed time.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let preserved = loop {
        let found = sandlock_core::list_preserved(&storage);
        if !found.is_empty() {
            break found;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a cancelled run's change set was never preserved (storage now holds {} branches)",
            branch_count(&storage),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    drop(held);

    assert_eq!(preserved.len(), 1, "expected exactly one preserved branch, got {preserved:?}");
    let p = &preserved[0];
    assert_eq!(p.workdir, workdir.canonicalize().unwrap(), "the marker must name the workdir");
    assert_eq!(
        p.reason,
        sandlock_core::PreserveReason::CommitDeferred,
        "the changes were complete and never merged: the workdir is untouched",
    );
    // The bytes, not just the directory: a preserved upper that lost its
    // content is the same data loss with a marker on top.
    assert_eq!(
        fs::read_to_string(p.upper.join("a.txt")).unwrap(),
        "plan\n",
        "the cancelled run's stage 0 write must survive",
    );
    assert_eq!(
        fs::read_to_string(p.upper.join("b.txt")).unwrap(),
        "built\n",
        "the cancelled run's stage 1 write must survive",
    );
    // Nothing was published: all-or-nothing still holds on the workdir side.
    assert!(!workdir.join("a.txt").exists(), "the lock was never taken, so nothing may be merged");
    assert!(!workdir.join("b.txt").exists(), "the lock was never taken, so nothing may be merged");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// Any stage failing aborts the whole transaction: earlier stages' writes are
/// discarded and the workdir is byte-identical to before the run.
#[tokio::test]
async fn test_txn_aborts_on_stage_failure() {
    if !sandbox_available().await {
        eprintln!("abort test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("abort");
    fs::write(workdir.join("existing.txt"), "original\n").unwrap();
    let policy = stage_policy(&workdir);

    // Stage 2 writes b.txt but the final stage exits non-zero → abort all.
    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
        Stage::new(&policy, &["sh", "-c", "exit 1"]),
    ])
    .run(None)
    .await
    .expect("transaction should run");

    assert!(!outcome.committed(), "a failing stage must abort the transaction");
    // The reason is typed: a caller can tell WHICH stage failed and how, with no
    // string matching.
    assert_eq!(
        outcome.disposition,
        TxnDisposition::Aborted(AbortReason::StageFailed {
            index: 2,
            status: sandlock_core::ExitStatus::Code(1),
        }),
        "abort must name the failing stage and its status",
    );
    assert_eq!(
        outcome.exit_code(), 1,
        "the outcome reports the failing stage's own exit code",
    );
    assert!(!workdir.join("a.txt").exists(), "a.txt must NOT leak after abort");
    assert!(!workdir.join("b.txt").exists(), "b.txt must NOT leak after abort");
    assert_eq!(fs::read_to_string(workdir.join("existing.txt")).unwrap(), "original\n");

    let _ = fs::remove_dir_all(&workdir);
}

/// The shared upper is reclaimed from disk after BOTH abort and commit — the
/// end-to-end check that a failed/completed transaction never orphans its upper.
#[tokio::test]
async fn test_txn_reclaims_upper() {
    if !sandbox_available().await {
        eprintln!("reclaim test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("reclaim-wd");
    let storage = temp_dir("reclaim-st");
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();

    // Abort path: the upper must be gone from the storage dir.
    let aborted = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo x > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "exit 1"]),
    ])
    .run(None).await.expect("transaction should run");
    assert!(!aborted.committed());
    assert_eq!(branch_count(&storage), 0, "aborted transaction must reclaim its upper from the storage dir");

    // Commit path: also reclaimed after the merge.
    let committed = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo y > b.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat b.txt"]),
    ])
    .run(None).await.expect("transaction should run");
    assert!(committed.committed());
    assert_eq!(branch_count(&storage), 0, "committed transaction must reclaim its upper from the storage dir");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// A timeout aborts the whole transaction without leaking earlier stages'
/// writes into the workdir — and the outcome still carries the results of the
/// stages that DID complete before the deadline, so the caller can see how far
/// it got without a second call.
#[tokio::test]
async fn test_txn_timeout_aborts_and_keeps_completed_stage_results() {
    if !sandbox_available().await {
        eprintln!("timeout test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("timeout");
    let policy = stage_policy(&workdir);

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "sleep 30"]),
    ])
    .run(Some(Duration::from_millis(600)))
    .await
    .expect("transaction should run");

    assert!(!outcome.committed(), "a timed-out transaction must abort");
    assert_eq!(outcome.disposition, TxnDisposition::Aborted(AbortReason::TimedOut));
    assert_eq!(
        outcome.stages.len(),
        1,
        "the first stage completed before the deadline; its result must survive the cancellation",
    );
    assert!(outcome.stages[0].success(), "the completed stage exited 0");
    assert!(!workdir.join("a.txt").exists(), "a.txt must NOT leak after a timeout abort");

    let _ = fs::remove_dir_all(&workdir);
}

/// S1: a stage that exits non-zero but leaves a BACKGROUNDED descendant holding
/// its stderr pipe's write end must still abort as `StageFailed` carrying "boom",
/// and return PROMPTLY — not hang on the drain (which waits for stderr EOF) and not
/// be mis-reported as `TimedOut`.
///
/// The survivor is a NO-EXECVE shell-builtin busy loop in a backgrounded subshell
/// (`(while :; do :; done) & echo boom 1>&2; exit 1`). This matters on THIS cage:
/// a backgrounded `sleep` (the spec's prose scenario) is an exec'd child that
/// returns `ENOSYS` here and so never survives to hold the pipe — the test would
/// then pass even with the fix absent, testing nothing. A subshell running `:`
/// (`fork`, no `execve`) really does survive, inherits the stage's fd 2 (the stderr
/// pipe), and outlives the direct `sh`, which exits 1 immediately.
///
/// Without the post-`wait()` process-group kill (`let _ = sb.kill();`), the pipe's
/// write end stays open after the direct `sh` is reaped — there is no PID namespace
/// to reap the lingering subshell — so the drain (which reads to EOF, i.e. until
/// EVERY fd-2 holder closes) blocks. This drain runs AFTER the stage phase's
/// timeout has already been satisfied by `wait()` returning, so the transaction's
/// own 8s deadline does not fail it fast; the blocked drain is effectively
/// unbounded. The harness-level `tokio::time::timeout(15s)` below is therefore
/// mandatory: without the fix it trips and the test fails as a caught regression,
/// instead of hanging CI. With the fix, `kill()` SIGKILLs the stage's whole
/// process group, the pipe reaches EOF, and the run returns `StageFailed` in
/// milliseconds. Runs on a multi-threaded runtime, as the real runner does (the
/// notify supervisor and the blocking drain each want a thread, and a lingering
/// supervised descendant must not starve the timer).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_txn_stage_failure_is_not_masked_by_a_backgrounded_descendant() {
    if !sandbox_available().await {
        eprintln!("backgrounded-descendant test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("bg_descendant");
    // Grant /dev/null on top of the base policy: a POSIX shell redirects a
    // backgrounded job's stdin from /dev/null, so without it the descendant never
    // launches and never holds the stderr pipe — the scenario this test needs.
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev/null")
        .fs_write(&workdir)
        .workdir(&workdir)
        .cwd(&workdir)
        .build()
        .unwrap();

    let start = std::time::Instant::now();
    // The harness timeout is the fail-fast backstop for the "drain hangs" regression
    // (see the docstring): a broken fix trips it instead of hanging the suite.
    let outcome = tokio::time::timeout(
        Duration::from_secs(15),
        Transaction::new([
            Stage::new(&policy, &["sh", "-c", "true"]),
            Stage::new(
                &policy,
                &["sh", "-c", "(while :; do :; done) & echo boom 1>&2; exit 1"],
            ),
        ])
        // Capture-only, so 'boom' does not leak to the test terminal.
        .tee_stderr(false)
        .run(Some(Duration::from_secs(8))),
    )
    .await
    .expect("the drain must not hang: kill() must release the backgrounded fd-2 holder")
    .expect("transaction should run");
    let elapsed = start.elapsed();

    assert!(!outcome.committed(), "a failing stage must abort the transaction");
    assert_eq!(
        outcome.disposition,
        TxnDisposition::Aborted(AbortReason::StageFailed {
            index: 1,
            status: sandlock_core::ExitStatus::Code(1),
        }),
        "the stage's own failure must be reported, not TimedOut from a hung drain",
    );
    assert_eq!(outcome.stages.len(), 2, "both stages' results must be recorded");
    let stderr = String::from_utf8_lossy(outcome.stages[1].stderr.as_deref().unwrap_or(&[]));
    assert!(stderr.contains("boom"), "the failing stage's stderr must be captured, got: {stderr:?}");
    assert!(
        elapsed < Duration::from_secs(6),
        "must return promptly once the stage exits, not wait out the deadline; took {elapsed:?}",
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// The outcome reports the filesystem changes the transaction made, on both the
/// commit and the abort path. They are read off the shared upper before it is
/// disposed of — after a commit or an abort there is nothing left to read.
#[tokio::test]
async fn test_txn_reports_changes_on_commit_and_abort() {
    if !sandbox_available().await {
        eprintln!("changes test skipped: sandbox unavailable");
        return;
    }
    // Commit path: an added file and a modified pre-existing one.
    let wd_c = temp_dir("changes-commit");
    fs::write(wd_c.join("existing.txt"), "before\n").unwrap();
    let p_c = stage_policy(&wd_c);
    let committed = Transaction::new([
        Stage::new(&p_c, &["sh", "-c", "echo new > added.txt"]),
        Stage::new(&p_c, &["sh", "-c", "echo after > existing.txt"]),
    ])
    .run(None).await.expect("transaction should run");
    assert!(committed.committed(), "disposition: {:?}", committed.disposition);

    let mut got: Vec<(ChangeKind, String)> = committed
        .changes
        .iter()
        .map(|c| (c.kind.clone(), c.path.display().to_string()))
        .collect();
    got.sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(
        got,
        vec![
            (ChangeKind::Added, "added.txt".to_string()),
            (ChangeKind::Modified, "existing.txt".to_string()),
        ],
        "a committed transaction must report exactly what it merged",
    );

    // Abort path: the changes are still reported, even though nothing landed.
    let wd_a = temp_dir("changes-abort");
    let p_a = stage_policy(&wd_a);
    let aborted = Transaction::new([
        Stage::new(&p_a, &["sh", "-c", "echo new > added.txt"]),
        Stage::new(&p_a, &["sh", "-c", "exit 1"]),
    ])
    .run(None).await.expect("transaction should run");
    assert!(!aborted.committed());
    assert_eq!(
        aborted.changes.iter().map(|c| c.path.display().to_string()).collect::<Vec<_>>(),
        vec!["added.txt".to_string()],
        "an aborted transaction must still report what it discarded",
    );
    assert!(!wd_a.join("added.txt").exists(), "nothing may be merged on abort");

    let _ = fs::remove_dir_all(&wd_c);
    let _ = fs::remove_dir_all(&wd_a);
}

/// `dry_run` runs every stage and reports the changes, then discards them: the
/// workdir is byte-identical afterwards.
#[tokio::test]
async fn test_txn_dry_run_reports_without_committing() {
    if !sandbox_available().await {
        eprintln!("dry-run test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("dry-run");
    fs::write(workdir.join("existing.txt"), "before\n").unwrap();
    let policy = stage_policy(&workdir);

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt && echo after > existing.txt"]),
    ])
    .dry_run(None)
    .await
    .expect("dry run should run");

    assert!(!outcome.committed(), "a dry run must never commit");
    assert_eq!(outcome.disposition, TxnDisposition::DryRun);
    assert_eq!(outcome.stages.len(), 2, "a dry run still runs every stage");
    let mut paths: Vec<String> = outcome.changes.iter().map(|c| c.path.display().to_string()).collect();
    paths.sort();
    assert_eq!(paths, vec!["a.txt".to_string(), "existing.txt".to_string()]);

    assert!(!workdir.join("a.txt").exists(), "a dry run must not create a.txt in the workdir");
    assert_eq!(
        fs::read_to_string(workdir.join("existing.txt")).unwrap(),
        "before\n",
        "a dry run must leave the workdir byte-identical",
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: a non-default `on_exit`/`on_error` conflicts with the transaction
/// owning commit/abort, and is rejected before anything runs. (No sandbox needed.)
///
/// Misconfiguration is its own typed variant, NOT a stage or commit failure, so
/// a caller can tell a bad transaction from a failed command without reading the
/// message.
#[tokio::test]
async fn test_txn_rejects_branch_action() {
    let workdir = temp_dir("guard-action");
    let plain = stage_policy(&workdir);
    let with_action = Sandbox::builder()
        .fs_read("/usr").fs_write(&workdir).workdir(&workdir)
        .on_exit(BranchAction::Keep)
        .build()
        .unwrap();

    let err = Transaction::new([
        Stage::new(&plain, &["true"]),
        Stage::new(&with_action, &["true"]),
    ])
    .run(None).await.unwrap_err();
    assert!(
        matches!(err, TxnError::Invalid(_)),
        "a misconfigured transaction must not masquerade as a stage or commit failure, got: {err:?}"
    );
    assert_eq!(err.exit_code(), 78, "a configuration error reports EX_CONFIG");
    assert!(err.to_string().contains("on_exit/on_error"), "expected the on_exit guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: every stage must set a workdir (the shared transaction dir).
#[tokio::test]
async fn test_txn_rejects_missing_workdir() {
    let workdir = temp_dir("guard-workdir");
    let with_wd = stage_policy(&workdir);
    let no_wd = Sandbox::builder().fs_read("/usr").build().unwrap();

    let err = Transaction::new([Stage::new(&with_wd, &["true"]), Stage::new(&no_wd, &["true"])])
        .run(None).await.unwrap_err().to_string();
    assert!(err.contains("no workdir"), "expected the workdir guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: fewer than two stages is rejected, not a panic. `Transaction::new`
/// accepts any stage list, so the check in `run` is the only one there is. A
/// one-stage transaction would index fine but is not a transaction; the ZERO
/// stage case is the one that would panic, because the coordinator reads
/// `stages[0]` for the shared workdir.
#[tokio::test]
async fn test_txn_rejects_too_few_stages() {
    let workdir = temp_dir("guard-count");
    let policy = stage_policy(&workdir);
    let err = Transaction::new([Stage::new(&policy, &["true"])])
        .run(None).await.unwrap_err().to_string();
    assert!(err.contains("at least 2 stages"), "expected the stage-count guardrail, got: {err}");

    // An empty transaction must be rejected by the same check, not indexed into.
    let err = Transaction::new([]).run(None).await.unwrap_err().to_string();
    assert!(err.contains("at least 2 stages"), "expected the stage-count guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: stages that each set a workdir but a DIFFERENT one are rejected —
/// distinct from the missing-workdir case (they share one COW upper).
#[tokio::test]
async fn test_txn_rejects_mismatched_workdir() {
    let wd1 = temp_dir("guard-wd-a");
    let wd2 = temp_dir("guard-wd-b");
    let s0 = stage_policy(&wd1);
    let s1 = stage_policy(&wd2); // valid workdir, but not the same one
    let err = Transaction::new([Stage::new(&s0, &["true"]), Stage::new(&s1, &["true"])])
        .run(None).await.unwrap_err().to_string();
    assert!(err.contains("share one workdir"), "expected the shared-workdir guardrail, got: {err}");

    let _ = fs::remove_dir_all(&wd1);
    let _ = fs::remove_dir_all(&wd2);
}

/// Guardrail: a stage running without the supervisor cannot participate in a COW
/// transaction (no notif path to build/commit the shared upper).
#[tokio::test]
async fn test_txn_rejects_no_supervisor() {
    let workdir = temp_dir("guard-nosup");
    let ok = stage_policy(&workdir);
    // Same workdir (so the workdir guardrail doesn't fire first) but no supervisor.
    let nosup = Sandbox::builder()
        .fs_read("/usr").fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .no_supervisor(true)
        .build()
        .unwrap();
    let err = Transaction::new([Stage::new(&ok, &["true"]), Stage::new(&nosup, &["true"])])
        .run(None).await.unwrap_err().to_string();
    assert!(err.contains("no_supervisor"), "expected the no_supervisor guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: chroot is unsupported with a shared COW workdir (the workdir path
/// can't resolve the same across differing roots).
#[tokio::test]
async fn test_txn_rejects_chroot() {
    let workdir = temp_dir("guard-chroot");
    let rootfs = temp_dir("guard-chroot-root");
    let ok = stage_policy(&workdir);
    let with_chroot = Sandbox::builder()
        .fs_read("/usr").fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .chroot(&rootfs)
        .build()
        .unwrap();
    let err = Transaction::new([Stage::new(&ok, &["true"]), Stage::new(&with_chroot, &["true"])])
        .run(None).await.unwrap_err().to_string();
    assert!(err.contains("chroot"), "expected the chroot guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&rootfs);
}

/// Guardrail: stages must share one COW upper, so differing fs_storage/max_disk
/// (here stage 1 sets fs_storage while stage 0 does not) is rejected.
#[tokio::test]
async fn test_txn_rejects_mismatched_fs_storage() {
    let workdir = temp_dir("guard-store-wd");
    let storage = temp_dir("guard-store-st");
    let s0 = stage_policy(&workdir); // no fs_storage
    let s1 = Sandbox::builder()
        .fs_read("/usr").fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();
    let err = Transaction::new([Stage::new(&s0, &["true"]), Stage::new(&s1, &["true"])])
        .run(None).await.unwrap_err().to_string();
    assert!(err.contains("fs_storage/max_disk"), "expected the fs_storage guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// The guardrails also gate `dry_run`, which runs the same stages over the same
/// shared upper — it must not be a way around them.
#[tokio::test]
async fn test_txn_dry_run_enforces_the_same_guardrails() {
    let workdir = temp_dir("guard-dryrun");
    let with_wd = stage_policy(&workdir);
    let no_wd = Sandbox::builder().fs_read("/usr").build().unwrap();

    let err = Transaction::new([Stage::new(&with_wd, &["true"]), Stage::new(&no_wd, &["true"])])
        .dry_run(None).await.unwrap_err().to_string();
    assert!(err.contains("no workdir"), "dry_run must enforce the workdir guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Boundary: the FIRST stage failing aborts, and the transaction STOPS — later
/// stages must not run (outcome.stages holds only the failed stage). Distinct
/// from the last-stage-failure case.
#[tokio::test]
async fn test_txn_aborts_on_first_stage_failure() {
    if !sandbox_available().await {
        eprintln!("first-fail test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("first-fail");
    let policy = stage_policy(&workdir);
    // Stage 0 writes a.txt then exits non-zero; stages 1 and 2 must NOT run.
    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo a > a.txt; exit 1"]),
        Stage::new(&policy, &["sh", "-c", "echo b > b.txt"]),
        Stage::new(&policy, &["sh", "-c", "echo c > c.txt"]),
    ])
    .run(None).await.expect("transaction should run");

    assert!(!outcome.committed(), "first-stage failure must abort");
    assert_eq!(
        outcome.disposition,
        TxnDisposition::Aborted(AbortReason::StageFailed { index: 0, status: sandlock_core::ExitStatus::Code(1) }),
    );
    assert_eq!(outcome.stages.len(), 1, "transaction must stop at the failed stage — later stages must not run");
    assert!(!workdir.join("a.txt").exists(), "a.txt must NOT leak after abort");
    assert!(!workdir.join("b.txt").exists(), "stage 2 must not have run");
    assert!(!workdir.join("c.txt").exists(), "stage 3 must not have run");

    let _ = fs::remove_dir_all(&workdir);
}

/// Combination: a timeout aborts AND reclaims the shared upper (no orphan on the
/// timeout path — the reclaim test only covered clean abort/commit).
#[tokio::test]
async fn test_txn_timeout_reclaims_upper() {
    if !sandbox_available().await {
        eprintln!("timeout-reclaim test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("to-reclaim-wd");
    let storage = temp_dir("to-reclaim-st");
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo x > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "sleep 30"]),
    ])
    .run(Some(Duration::from_millis(600)))
    .await
    .expect("transaction should run");
    assert!(!outcome.committed(), "timed-out transaction must abort");
    assert_eq!(branch_count(&storage), 0, "timed-out transaction must reclaim its upper from the storage dir");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// COW deletion (whiteout) semantics through commit AND abort:
///   - commit: a stage deleting a pre-existing workdir file removes it from the
///     workdir, and a later stage sees the deletion (read-committed);
///   - abort: the deletion is discarded — the file survives byte-identical.
#[tokio::test]
async fn test_txn_deletion_commit_applies_abort_preserves() {
    if !sandbox_available().await {
        eprintln!("deletion test skipped: sandbox unavailable");
        return;
    }
    // Commit path.
    let wd_c = temp_dir("del-commit");
    fs::write(wd_c.join("keep.txt"), "orig\n").unwrap();
    let p_c = stage_policy(&wd_c);
    let committed = Transaction::new([
        Stage::new(&p_c, &["sh", "-c", "rm keep.txt"]),
        Stage::new(&p_c, &["sh", "-c", "test ! -e keep.txt"]), // stage 2 must SEE the deletion
    ])
    .run(None)
    .await
    .expect("transaction should run");
    assert!(committed.committed(), "commit expected; disposition: {:?}", committed.disposition);
    assert!(!wd_c.join("keep.txt").exists(), "committed deletion must remove keep.txt from the workdir");
    assert_eq!(
        committed.changes.iter().map(|c| (c.kind.clone(), c.path.display().to_string())).collect::<Vec<_>>(),
        vec![(ChangeKind::Deleted, "keep.txt".to_string())],
        "a deletion must be reported as a change",
    );

    // Abort path: same deletion, but the transaction aborts → deletion discarded.
    let wd_a = temp_dir("del-abort");
    fs::write(wd_a.join("keep.txt"), "orig\n").unwrap();
    let p_a = stage_policy(&wd_a);
    let aborted = Transaction::new([
        Stage::new(&p_a, &["sh", "-c", "rm keep.txt"]),
        Stage::new(&p_a, &["sh", "-c", "exit 1"]),
    ])
    .run(None)
    .await
    .expect("transaction should run");
    assert!(!aborted.committed(), "abort expected");
    assert_eq!(
        fs::read_to_string(wd_a.join("keep.txt")).unwrap(), "orig\n",
        "aborted deletion must leave keep.txt intact in the workdir",
    );

    let _ = fs::remove_dir_all(&wd_c);
    let _ = fs::remove_dir_all(&wd_a);
}

/// Policy for a transaction that keeps its COW branches in `storage`, so a test
/// can look at the upper from outside the run.
fn stage_policy_in(workdir: &Path, storage: &Path) -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(workdir)
        .workdir(workdir)
        .cwd(workdir)
        .fs_storage(storage)
        .build()
        .unwrap()
}

/// Restore write permission on a directory, so a failed assertion cannot leave a
/// read-only tree behind for the next run to trip over.
fn make_writable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = match fs::metadata(dir) {
        Ok(m) => m.permissions(),
        Err(_) => return,
    };
    perm.set_mode(0o755);
    let _ = fs::set_permissions(dir, perm);
}

fn make_read_only(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = fs::metadata(dir).unwrap().permissions();
    perm.set_mode(0o555);
    fs::set_permissions(dir, perm).unwrap();
}

/// A merge that cannot be applied does not throw the change set away: the run is
/// reported as `TxnError::Merge`, the storage is preserved as
/// `MergeInterrupted`, and the deletion that did not land is recorded in the
/// marker — the upper alone does not represent it, so recovering from the upper
/// on its own would resurrect the deleted file.
///
/// The merge is made to fail on its deletion half, which runs before any entry
/// is copied: the workdir's `sub/` is read-only, so `sub/f.txt` cannot be
/// unlinked. The stages themselves are unaffected — their unlink is intercepted
/// by the COW supervisor and only recorded — so this is a failure of the commit,
/// not of the transaction's stages.
#[tokio::test]
async fn test_txn_merge_failure_preserves_the_unmerged_change_set() {
    if !sandbox_available().await {
        eprintln!("merge-failure test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("merge-fail-wd");
    let storage = temp_dir("merge-fail-st");
    make_writable(&workdir.join("sub"));
    fs::create_dir_all(workdir.join("sub")).unwrap();
    fs::write(workdir.join("sub/f.txt"), "orig\n").unwrap();
    let policy = stage_policy_in(&workdir, &storage);

    let txn = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "rm -f sub/f.txt"]),
        Stage::new(&policy, &["sh", "-c", "echo new > added.txt"]),
    ]);
    make_read_only(&workdir.join("sub"));
    let err = txn.run(None).await.expect_err("a merge that cannot be applied must fail the commit");
    make_writable(&workdir.join("sub"));

    match &err {
        TxnError::Merge { workdir: wd, preserved_upper, .. } => {
            assert_eq!(wd, &workdir, "the merge failure must name the workdir it was merging into");
            assert!(
                preserved_upper.starts_with(&storage),
                "the merge failure must name the preserved upper, got {preserved_upper:?}",
            );
        }
        other => panic!("expected a merge failure, got: {other:?}"),
    }
    assert_eq!(err.exit_code(), 74, "a failed commit reports EX_IOERR");

    // The deletion did not land, and neither did the addition: the merge stops on
    // its deletion half before copying a single entry.
    assert_eq!(
        fs::read_to_string(workdir.join("sub/f.txt")).unwrap(),
        "orig\n",
        "the deletion could not be applied, so the file must still be there",
    );
    assert!(
        !workdir.join("added.txt").exists(),
        "no entry may be published once a deletion could not be applied",
    );

    // The whole change set survives — the upper for the addition, the marker for
    // the deletion the upper cannot represent.
    let preserved = sandlock_core::list_preserved(&storage);
    assert_eq!(preserved.len(), 1, "the unmerged change set must be preserved, got {preserved:?}");
    let p = &preserved[0];
    assert_eq!(
        p.reason,
        sandlock_core::PreserveReason::MergeInterrupted,
        "a merge that started and did not finish must say so: the workdir may be partial",
    );
    assert_eq!(p.workdir, workdir, "the marker must name the workdir the changes belong to");
    assert_eq!(
        p.deleted,
        vec![PathBuf::from("sub/f.txt")],
        "the deletion that did not land must be in the marker; nothing in the upper represents it",
    );
    assert_eq!(
        fs::read_to_string(p.upper.join("added.txt")).unwrap(),
        "new\n",
        "the preserved upper must still hold the addition that was not merged",
    );

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// A workdir that cannot be branched fails the transaction as `TxnError::Branch`
/// before any stage runs, and leaves nothing behind in the storage dir: the
/// branch dir is only created once the workdir has been resolved, so a failure
/// here cannot orphan an empty branch for a sweep to trip over.
#[tokio::test]
async fn test_txn_branch_failure_runs_nothing_and_orphans_no_storage() {
    let workdir = temp_dir("branch-fail-wd");
    let storage = temp_dir("branch-fail-st");
    let policy = stage_policy_in(&workdir, &storage);
    // Valid at build time, gone by the time the branch is created — the case the
    // guardrails cannot catch, because they only check that a workdir is set.
    fs::remove_dir_all(&workdir).unwrap();

    let err = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo a > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "echo b > b.txt"]),
    ])
    .run(None)
    .await
    .expect_err("a workdir that does not exist cannot be branched");

    match &err {
        TxnError::Branch { workdir: wd, .. } => {
            assert_eq!(wd, &workdir, "the branch failure must name the workdir it could not branch");
        }
        other => panic!("expected a branch-creation failure, got: {other:?}"),
    }
    assert_eq!(err.exit_code(), 74, "a branch that could not be created is a commit-channel failure");
    assert_eq!(
        branch_count(&storage),
        0,
        "a branch that was never created must not leave storage behind",
    );

    let _ = fs::remove_dir_all(&storage);
}

/// A stage that cannot be driven at all is `TxnError::Stage` naming its index —
/// and the shared upper is still disposed of as an abort, so the earlier stages'
/// writes are discarded rather than published.
///
/// Distinct from a stage that *fails*: that one produced an exit status and is
/// `Ok(TxnOutcome)` with an `AbortReason`. Here stage 1 has an empty command, so
/// it never starts and there is no status to report.
#[tokio::test]
async fn test_txn_undrivable_stage_errors_and_discards_the_shared_upper() {
    if !sandbox_available().await {
        eprintln!("undrivable-stage test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("undrivable-wd");
    let storage = temp_dir("undrivable-st");
    let policy = stage_policy_in(&workdir, &storage);

    let err = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &[]),
    ])
    .run(None)
    .await
    .expect_err("a stage that cannot be started must fail the transaction");

    assert!(
        matches!(err, TxnError::Stage { index: 1, .. }),
        "the failure must name the stage that could not be run, got: {err:?}",
    );
    assert_eq!(err.exit_code(), 70, "a stage that could not be driven reports EX_SOFTWARE");
    assert!(
        !workdir.join("a.txt").exists(),
        "the completed stage's write must be discarded, not committed, when a later stage cannot run",
    );
    assert_eq!(branch_count(&storage), 0, "the shared upper must not be left behind");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// Read fd `n` of the parent test process, as a `/proc` link target.
fn parent_fd(n: i32) -> PathBuf {
    fs::read_link(format!("/proc/self/fd/{n}"))
        .unwrap_or_else(|e| panic!("test setup: the parent has no fd {n}: {e}"))
}

/// A failing stage's stderr is captured into its `RunResult`, indexed by the
/// same `StageFailed.index` the abort carries — so an SDK caller gets the
/// diagnostic without redirection boilerplate. Before per-stage capture,
/// `stages[i].stderr` was always `None`, so this assertion could not hold.
///
/// This pins capture, NOT the cap: the payload is a few bytes and never reaches
/// `STAGE_STDERR_CAP`. The end-to-end proof that the cap is wired is
/// `test_txn_stage_stderr_is_capped_and_tail_biased`.
#[tokio::test]
async fn test_txn_stages_capture_stderr() {
    if !sandbox_available().await {
        eprintln!("stderr-capture test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("stderr-capture");
    let policy = stage_policy(&workdir);

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "echo boom 1>&2; exit 1"]),
    ])
    // Capture-only, so 'boom' does not leak to the test terminal.
    .tee_stderr(false)
    .run(None)
    .await
    .expect("transaction should run");

    assert_eq!(
        outcome.disposition,
        TxnDisposition::Aborted(AbortReason::StageFailed {
            index: 1,
            status: sandlock_core::ExitStatus::Code(1),
        }),
        "the failing stage aborts the transaction",
    );
    assert_eq!(
        outcome.stages[1].stderr.as_deref(),
        Some(b"boom\n".as_slice()),
        "the failing stage's stderr must be captured at stages[StageFailed.index]",
    );
    // Every stage that RAN carries captured stderr — a stage that emitted nothing
    // is `Some(empty)`, not `None`.
    assert_eq!(
        outcome.stages[0].stderr.as_deref(),
        Some(b"".as_slice()),
        "a stage that wrote no stderr still carries a captured (empty) buffer",
    );
    // GAP-12: fd 1 stays inherited on the abort path too, so there is nothing to
    // capture — stdout is `None`, never `Some(empty)`.
    assert!(
        outcome.stages[1].stdout.is_none(),
        "a stage's stdout stays inherited (None) even when it aborts: {:?}",
        outcome.stages[1],
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// GAP-1: a stage that floods more than `STAGE_STDERR_CAP` (64 KiB) to stderr has
/// its capture CAPPED and tail-biased. This is the only end-to-end proof that
/// `run_txn` wires the stage drain through `drain_capped_tee(STAGE_STDERR_CAP)`:
/// reverting the cap to unbounded captures the whole flood and fails the length
/// and marker assertions below.
#[tokio::test]
async fn test_txn_stage_stderr_is_capped_and_tail_biased() {
    if !sandbox_available().await {
        eprintln!("stderr-cap test skipped: sandbox unavailable");
        return;
    }
    // Kept in sync with the private `transaction::STAGE_STDERR_CAP`.
    const CAP: usize = 64 * 1024;
    let workdir = temp_dir("stderr-cap");
    let policy = stage_policy(&workdir);

    // 128 KiB of "X\n" to fd 2, then a distinct terminal sentinel: total > CAP, and
    // the LAST bytes written are the sentinel, so a tail-biased capture must end in
    // it while a head-only capture would lose it.
    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(
            &policy,
            &["sh", "-c", "yes X | head -c 131072 1>&2; printf ZZZEND 1>&2; exit 1"],
        ),
    ])
    // Capture-only: the live tee would flood the test terminal with the X's
    // (raw fd 2 writes bypass libtest's capture).
    .tee_stderr(false)
    .run(None)
    .await
    .expect("transaction should run");

    assert_eq!(
        outcome.disposition,
        TxnDisposition::Aborted(AbortReason::StageFailed {
            index: 1,
            status: sandlock_core::ExitStatus::Code(1),
        }),
        "the flooding stage exits 1 and aborts the transaction",
    );
    let stderr = outcome.stages[1]
        .stderr
        .as_deref()
        .expect("the flooding stage's stderr must be captured");
    assert!(
        stderr.len() >= CAP && stderr.len() <= CAP + 64,
        "the capture must be bounded to ~the cap, not the whole flood; got {}",
        stderr.len(),
    );
    assert!(
        stderr.windows(b"[stderr truncated]".len()).any(|w| w == b"[stderr truncated]"),
        "an over-cap capture must carry the truncation marker",
    );
    assert!(
        stderr.ends_with(b"ZZZEND"),
        "the terminal bytes must survive (tail-biased); capture ends with {:?}",
        String::from_utf8_lossy(&stderr[stderr.len().saturating_sub(16)..]),
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// Stdout stays inherited (fd 0 and fd 1 remain the parent's own open files,
/// streamed live), while stderr is redirected to the coordinator's capture pipe
/// (fd 2 is no longer the parent's) AND captured into the stage result.
///
/// Each stage records where its own fd 0/1/2 point (fd 1 through a dup, so the
/// recording redirect does not hide it). fd 0/1 must name the parent's own file;
/// fd 2 must not, because it is the capture pipe.
#[tokio::test]
async fn test_txn_stages_inherit_stdout_but_capture_stderr() {
    if !sandbox_available().await {
        eprintln!("stdout-inherit test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("stdio");
    let policy = stage_policy(&workdir);
    let record = |tag: &str| {
        format!(
            "exec 3>&1; readlink /proc/self/fd/0 > {tag}0; readlink /proc/self/fd/3 > {tag}1; \
             readlink /proc/self/fd/2 > {tag}2; echo on-stdout; echo on-stderr 1>&2"
        )
    };
    let s0 = record("s");
    let s1 = record("t");

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", &s0]),
        Stage::new(&policy, &["sh", "-c", &s1]),
    ])
    // Capture-only: the tee is parent-side, so disabling it does not change
    // the stage fd wiring this test asserts.
    .tee_stderr(false)
    .run(None)
    .await
    .expect("transaction should run");
    assert!(outcome.committed(), "disposition: {:?}", outcome.disposition);

    for (stage, tag) in [(0usize, "s"), (1, "t")] {
        // fd 0 and fd 1 are the parent's own open files (inherited live).
        for fd in 0..2i32 {
            let seen = fs::read_to_string(workdir.join(format!("{tag}{fd}"))).unwrap();
            assert_eq!(
                Path::new(seen.trim_end_matches('\n')),
                parent_fd(fd),
                "stage {stage} fd {fd} must be the parent's own, not a pipe",
            );
        }
        // fd 2 is the coordinator's capture pipe now, NOT the parent's stderr.
        let seen2 = fs::read_to_string(workdir.join(format!("{tag}2"))).unwrap();
        assert_ne!(
            Path::new(seen2.trim_end_matches('\n')),
            parent_fd(2),
            "stage {stage} fd 2 must be the capture pipe, not the parent's own stderr",
        );
    }
    // stdout stays uncaptured (inherited-live); stderr is captured.
    for (i, r) in outcome.stages.iter().enumerate() {
        assert!(r.stdout.is_none(), "stage {i} stdout must stay inherited (None): {r:?}");
        assert!(r.stderr.is_some(), "stage {i} stderr must be captured: {r:?}");
    }
    assert_eq!(
        outcome.stages[0].stderr.as_deref(),
        Some(b"on-stderr\n".as_slice()),
        "the captured stderr must be exactly what the stage wrote to fd 2",
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// A stage killed by a signal aborts the transaction with that signal in the
/// reason, and the outcome's exit code is the shell's `128 + signal` for it —
/// not the raw signal number, and not a generic failure code.
#[tokio::test]
async fn test_txn_signalled_stage_reports_the_signal_and_shell_exit_code() {
    if !sandbox_available().await {
        eprintln!("signal test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("signal");
    let policy = stage_policy(&workdir);

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "kill -TERM $$; sleep 5"]),
    ])
    .run(None)
    .await
    .expect("transaction should run");

    assert!(!outcome.committed(), "a signalled stage must abort the transaction");
    assert_eq!(
        outcome.disposition,
        TxnDisposition::Aborted(AbortReason::StageFailed {
            index: 1,
            status: sandlock_core::ExitStatus::Signal(libc::SIGTERM),
        }),
        "the abort must carry the signal the stage died from",
    );
    assert_eq!(
        outcome.exit_code(),
        128 + libc::SIGTERM,
        "a signalled stage reports 128 + signal, as a shell does",
    );
    assert!(!workdir.join("a.txt").exists(), "nothing may be committed after a signalled stage");

    let _ = fs::remove_dir_all(&workdir);
}

/// The outcome's exit code separates "did what was asked" from "aborted": a dry
/// run that completed is 0 even though it committed nothing, while a timeout is
/// 124, the code `timeout(1)` reports.
#[tokio::test]
async fn test_txn_exit_code_separates_a_completed_dry_run_from_a_timeout() {
    if !sandbox_available().await {
        eprintln!("outcome exit-code test skipped: sandbox unavailable");
        return;
    }
    let wd_d = temp_dir("code-dry");
    let p_d = stage_policy(&wd_d);
    let dry = Transaction::new([
        Stage::new(&p_d, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&p_d, &["sh", "-c", "cat a.txt"]),
    ])
    .dry_run(None)
    .await
    .expect("dry run should run");
    assert_eq!(dry.disposition, TxnDisposition::DryRun);
    assert_eq!(
        dry.exit_code(),
        0,
        "a dry run that ran every stage did what was asked, even though it committed nothing",
    );

    let wd_t = temp_dir("code-timeout");
    let p_t = stage_policy(&wd_t);
    let timed_out = Transaction::new([
        Stage::new(&p_t, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&p_t, &["sh", "-c", "sleep 30"]),
    ])
    .run(Some(Duration::from_millis(600)))
    .await
    .expect("transaction should run");
    assert_eq!(timed_out.disposition, TxnDisposition::Aborted(AbortReason::TimedOut));
    assert_eq!(timed_out.exit_code(), 124, "a timed-out transaction reports 124, as timeout(1) does");

    let _ = fs::remove_dir_all(&wd_d);
    let _ = fs::remove_dir_all(&wd_t);
}

/// A dry run must not take the workdir commit lock: it merges nothing, so
/// serializing it against a concurrent merge would only make it block.
///
/// The lock is held for the whole run, and the dry run is given a wait budget it
/// would visibly exceed if it ever asked for the lock — so hoisting the
/// acquisition above the discard path turns this into a `TxnError::Conflict`
/// instead of an outcome. The upper is reclaimed either way: a dry run that
/// preserved its storage would leak one branch per invocation.
#[tokio::test]
async fn test_txn_dry_run_neither_takes_the_commit_lock_nor_keeps_its_upper() {
    if !sandbox_available().await {
        eprintln!("dry-run lock test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("dry-lock-wd");
    let storage = temp_dir("dry-lock-st");
    let policy = stage_policy_in(&workdir, &storage);

    // Stand in for another transaction mid-merge, for the whole dry run.
    let held = std::fs::File::open(&workdir).unwrap();
    assert_eq!(
        unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test setup: could not take the workdir lock"
    );

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt"]),
    ])
    .commit_lock_wait(Duration::from_millis(50))
    .dry_run(None)
    .await
    .expect("a dry run does not merge, so a held commit lock cannot fail it");
    drop(held);

    assert_eq!(
        outcome.disposition, TxnDisposition::DryRun,
        "the dry run completed; the held lock is none of its business",
    );
    assert!(!outcome.committed(), "a dry run must never commit");
    assert!(!workdir.join("a.txt").exists(), "a dry run must not publish anything");
    assert_eq!(
        branch_count(&storage),
        0,
        "a dry run must reclaim its upper, not leave a branch behind per invocation",
    );
    assert!(
        sandlock_core::list_preserved(&storage).is_empty(),
        "a dry run has nothing to preserve: its change set was reported and discarded",
    );

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// A dry run that did NOT get through its stages reports why it stopped, not
/// `DryRun`.
///
/// `DryRun` means "every stage ran and the change set was discarded on purpose".
/// A caller reads this field to tell "here is the diff" from "could not get that
/// far", so a stage failure must keep its index and status and a timeout must
/// stay `TimedOut` — with the outcome's exit code following the same split.
#[tokio::test]
async fn test_txn_dry_run_reports_the_failure_that_stopped_it_not_dry_run() {
    if !sandbox_available().await {
        eprintln!("dry-run failure test skipped: sandbox unavailable");
        return;
    }
    let wd_f = temp_dir("dry-fail");
    let p_f = stage_policy(&wd_f);
    let failed = Transaction::new([
        Stage::new(&p_f, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&p_f, &["sh", "-c", "exit 3"]),
    ])
    .dry_run(None)
    .await
    .expect("a failing stage is an outcome, not a dry-run error");
    assert_eq!(
        failed.disposition,
        TxnDisposition::Aborted(AbortReason::StageFailed {
            index: 1,
            status: sandlock_core::ExitStatus::Code(3),
        }),
        "a dry run that stopped at a failing stage must say so, not claim it reported a diff",
    );
    assert_eq!(failed.exit_code(), 3, "the failing stage's own code, not the dry run's 0");
    assert!(!wd_f.join("a.txt").exists(), "a dry run publishes nothing either way");

    let wd_t = temp_dir("dry-timeout");
    let p_t = stage_policy(&wd_t);
    let timed_out = Transaction::new([
        Stage::new(&p_t, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&p_t, &["sh", "-c", "sleep 30"]),
    ])
    .dry_run(Some(Duration::from_millis(600)))
    .await
    .expect("a timeout is an outcome, not a dry-run error");
    assert_eq!(
        timed_out.disposition,
        TxnDisposition::Aborted(AbortReason::TimedOut),
        "a dry run cut short by its timeout never reported a full diff",
    );
    assert_eq!(timed_out.exit_code(), 124, "a timed-out dry run reports 124, as timeout(1) does");

    let _ = fs::remove_dir_all(&wd_f);
    let _ = fs::remove_dir_all(&wd_t);
}

/// `run`'s `timeout` bounds the STAGE phase only. A commit that has to wait out
/// another transaction's merge is not cut short by it — the stages have all
/// succeeded and the work is mergeable, so the wait is governed by
/// `commit_lock_wait` alone.
///
/// The lock is held past the timeout after the last stage's write is visible in
/// the shared upper, so the transaction is demonstrably inside the commit with
/// the deadline already expired. Finishing during that window at all is the
/// failure.
#[tokio::test]
async fn test_txn_timeout_bounds_the_stage_phase_not_the_commit() {
    if !sandbox_available().await {
        eprintln!("timeout-scope test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("to-scope-wd");
    let storage = temp_dir("to-scope-st");
    let policy = stage_policy_in(&workdir, &storage);

    let held = std::fs::File::open(&workdir).unwrap();
    assert_eq!(
        unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test setup: could not take the workdir lock"
    );

    let stage_timeout = Duration::from_millis(800);
    let txn = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
    ])
    .commit_lock_wait(Duration::from_secs(30))
    .run(Some(stage_timeout));
    tokio::pin!(txn);

    // Drive until the last stage's write is in the shared upper: the stage phase
    // is over and the only thing left is the commit.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !upper_holds(&storage, "b.txt") {
        tokio::select! {
            early = &mut txn => panic!("the transaction finished while the lock was held: {early:?}"),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        assert!(std::time::Instant::now() < deadline, "stages never reached the commit");
    }
    // Hold the lock well past the stage timeout. A transaction whose commit was
    // bounded by it would give up in here.
    let hold_until = std::time::Instant::now() + stage_timeout * 2;
    while std::time::Instant::now() < hold_until {
        tokio::select! {
            early = &mut txn => panic!(
                "the commit was cut short by the stage timeout instead of waiting for the lock: {early:?}"
            ),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    drop(held);

    let outcome = txn.await.expect("the commit is not bounded by the stage timeout");
    assert!(
        outcome.committed(),
        "every stage succeeded within the timeout, so the transaction must commit; disposition: {:?}",
        outcome.disposition,
    );
    assert_eq!(fs::read_to_string(workdir.join("b.txt")).unwrap(), "built\n");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// A timeout that expires before the first stage can start aborts with NO stage
/// results at all — the one outcome whose `stages` vector is empty.
///
/// `TxnOutcome::stages` is otherwise "every stage that ran", which invites
/// indexing `stages[0]` after an abort. It also pins that an expired deadline is
/// an abort and not a clean run: treating the cancelled driver as "nothing went
/// wrong" would commit an upper no stage ever wrote to.
#[tokio::test]
async fn test_txn_a_deadline_that_expires_immediately_aborts_with_no_stage_results() {
    if !sandbox_available().await {
        eprintln!("zero-timeout test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("zero-to-wd");
    let storage = temp_dir("zero-to-st");
    fs::write(workdir.join("existing.txt"), "before\n").unwrap();
    let policy = stage_policy_in(&workdir, &storage);

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["sh", "-c", "echo built > b.txt"]),
    ])
    .run(Some(Duration::ZERO))
    .await
    .expect("an expired deadline is an outcome, not an error");

    assert!(!outcome.committed(), "a transaction that never ran a stage must not commit");
    assert_eq!(outcome.disposition, TxnDisposition::Aborted(AbortReason::TimedOut));
    assert!(
        outcome.stages.is_empty(),
        "no stage completed, so there is nothing to report; got {:?}",
        outcome.stages,
    );
    assert_eq!(outcome.exit_code(), 124, "an expired deadline reports 124, as timeout(1) does");
    assert!(!workdir.join("a.txt").exists(), "no stage ran, so nothing may be published");
    assert_eq!(fs::read_to_string(workdir.join("existing.txt")).unwrap(), "before\n");
    assert_eq!(branch_count(&storage), 0, "the untouched upper must still be reclaimed");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// A transaction rejected by a guardrail runs NOTHING — the validation happens
/// before the shared branch is created and before the first stage is started.
///
/// Asserted with a side effect the COW layer cannot hide: stage 0 writes a
/// sentinel OUTSIDE the workdir, straight to the real filesystem, so a validator
/// that ran after the stages would leave it behind. The shared upper must not be
/// created either, or every rejected transaction orphans one branch dir.
#[tokio::test]
async fn test_txn_a_rejected_transaction_creates_no_branch_and_starts_no_stage() {
    if !sandbox_available().await {
        eprintln!("validation-ordering test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("reject-order-wd");
    let storage = temp_dir("reject-order-st");
    let outside = temp_dir("reject-order-out");
    let sentinel = outside.join("ran.txt");

    // Stage 0 is valid and, if it ever ran, would leave `sentinel` on the real
    // filesystem: `outside` is not the workdir, so it is not COW-intercepted.
    let base = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(&workdir).fs_write(&outside).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .build()
        .unwrap();
    // Stage 1 is the violation: a per-stage branch action the transaction owns.
    let bad = Sandbox::builder()
        .fs_read("/usr").fs_write(&workdir).workdir(&workdir).cwd(&workdir)
        .fs_storage(&storage)
        .on_error(BranchAction::Keep)
        .build()
        .unwrap();

    let cmd = format!("echo ran > {}", sentinel.display());
    let err = Transaction::new([
        Stage::new(&base, &["sh", "-c", &cmd]),
        Stage::new(&bad, &["true"]),
    ])
    .run(None)
    .await
    .expect_err("a per-stage branch action must be rejected");

    assert!(matches!(err, TxnError::Invalid(_)), "expected a configuration error, got: {err:?}");
    assert!(
        !sentinel.exists(),
        "a rejected transaction must not have started stage 0: {} exists",
        sentinel.display(),
    );
    assert_eq!(
        branch_count(&storage),
        0,
        "a rejected transaction must not create the shared branch",
    );

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
    let _ = fs::remove_dir_all(&outside);
}

/// `TxnOutcome::stages` holds every stage that RAN, in execution order, and the
/// failing stage's own result is one of them.
///
/// Both halves matter to a caller reporting on a failed transaction: dropping
/// the failing stage's result loses the only place its status is recorded
/// alongside the successful ones, and a reordered vector silently misattributes
/// every status. Pinned with a distinct exit code at a known index, so neither
/// can pass.
#[tokio::test]
async fn test_txn_stage_results_are_in_execution_order_and_include_the_failed_stage() {
    if !sandbox_available().await {
        eprintln!("stage-order test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("stage-order");
    let policy = stage_policy(&workdir);

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "exit 0"]),
        Stage::new(&policy, &["sh", "-c", "exit 0"]),
        Stage::new(&policy, &["sh", "-c", "exit 7"]),
        Stage::new(&policy, &["sh", "-c", "exit 0"]),
    ])
    .run(None)
    .await
    .expect("transaction should run");

    assert!(!outcome.committed());
    assert_eq!(
        outcome.stages.iter().map(|r| r.exit_status.clone()).collect::<Vec<_>>(),
        vec![
            sandlock_core::ExitStatus::Code(0),
            sandlock_core::ExitStatus::Code(0),
            sandlock_core::ExitStatus::Code(7),
        ],
        "the three stages that ran must be reported in order, the failing one included",
    );

    let _ = fs::remove_dir_all(&workdir);
}

/// A command that cannot be exec'd is a stage FAILURE, not a driver error: the
/// stage really started, the exec failed inside the child, and the shell
/// convention 127 comes back as the abort reason.
///
/// This is the boundary of `TxnError::Stage`, which is reserved for a stage that
/// never produced an exit status at all. A caller that expects `Err` for a
/// missing binary — the natural reading of "could not be run" — would never see
/// it.
#[tokio::test]
async fn test_txn_a_command_that_cannot_be_execed_is_a_stage_failure_not_a_driver_error() {
    if !sandbox_available().await {
        eprintln!("missing-binary test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("no-such-binary");
    let policy = stage_policy(&workdir);

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
        Stage::new(&policy, &["/no/such/binary"]),
    ])
    .run(None)
    .await
    .expect("a binary that cannot be exec'd is an abort, not a commit-channel error");

    assert_eq!(
        outcome.disposition,
        TxnDisposition::Aborted(AbortReason::StageFailed {
            index: 1,
            status: sandlock_core::ExitStatus::Code(127),
        }),
        "an exec failure surfaces as the stage's own 127, as a shell reports it",
    );
    assert_eq!(outcome.exit_code(), 127);
    assert_eq!(outcome.stages.len(), 2, "the stage ran and produced a status, so it is reported");
    assert!(!workdir.join("a.txt").exists(), "the earlier stage's write must be discarded");

    let _ = fs::remove_dir_all(&workdir);
}

/// Cancelling during the STAGE phase RECLAIMS the change set — the mirror image
/// of cancelling during the commit phase, which preserves it.
///
/// The distinction is the whole point: a run whose stages all succeeded holds a
/// complete, mergeable change set that must outlive the cancellation, while a
/// run abandoned mid-stage holds a partial one that no recovery could safely
/// publish. So this path must leave no storage and no `PRESERVED` marker for a
/// sweep to find — and the workdir must be byte-identical, since nothing was
/// ever merged.
///
/// The reclaim is asynchronous (the notification supervisor holds the branch
/// until its own abort lands), so it is polled for rather than assumed.
#[tokio::test]
async fn test_txn_cancelled_during_the_stage_phase_reclaims_the_change_set() {
    if !sandbox_available().await {
        eprintln!("stage-cancel test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("cancel-stage-wd");
    let storage = temp_dir("cancel-stage-st");
    fs::write(workdir.join("existing.txt"), "before\n").unwrap();
    let policy = stage_policy_in(&workdir, &storage);

    {
        let txn = Transaction::new([
            Stage::new(&policy, &["sh", "-c", "echo plan > a.txt && sleep 30"]),
            Stage::new(&policy, &["sh", "-c", "echo built > b.txt"]),
        ])
        .run(None);
        tokio::pin!(txn);

        // Drive until stage 0's write is in the shared upper: the run is
        // demonstrably mid-stage, with a change set on disk to lose.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !upper_holds(&storage, "a.txt") {
            tokio::select! {
                early = &mut txn => panic!("the transaction finished before it could be cancelled: {early:?}"),
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
            assert!(std::time::Instant::now() < deadline, "stage 0 never wrote into the shared upper");
        }
    } // <-- the run future is dropped here, mid-stage: the cancellation.

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while branch_count(&storage) != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "a run cancelled mid-stage must reclaim its upper, but {} branch(es) remain in {}",
            branch_count(&storage),
            storage.display(),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        sandlock_core::list_preserved(&storage).is_empty(),
        "a partial change set must not be preserved: no recovery could safely publish it",
    );
    assert!(!workdir.join("a.txt").exists(), "nothing was merged, so nothing may be in the workdir");
    assert_eq!(
        fs::read_to_string(workdir.join("existing.txt")).unwrap(),
        "before\n",
        "the workdir must be byte-identical to before the cancelled run",
    );

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// Read-committed for a MODIFIED pre-existing file: a later stage reading a
/// workdir file an earlier stage rewrote must see the NEW bytes.
///
/// This is the half of read-committed that fails silently. A stage reading a
/// file that was ADDED by an earlier stage gets a loud `ENOENT` if the read is
/// not resolved into the shared upper; a stage reading a file that was MODIFIED
/// gets the stale lower content and carries on, so the transaction commits a
/// result computed from data that was already superseded.
#[tokio::test]
async fn test_txn_stage_reads_an_earlier_stage_s_modification_not_the_workdir_copy() {
    if !sandbox_available().await {
        eprintln!("read-committed test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("read-modified");
    fs::write(workdir.join("in.txt"), "before\n").unwrap();
    let policy = stage_policy(&workdir);

    let outcome = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo after > in.txt"]),
        // `cat` (not `test -e`) so the assertion is on the CONTENT: a stale read
        // succeeds and would otherwise look identical to a fresh one.
        Stage::new(&policy, &["sh", "-c", "cat in.txt > seen.txt"]),
    ])
    .run(None)
    .await
    .expect("transaction should run");

    assert!(outcome.committed(), "disposition: {:?}", outcome.disposition);
    assert_eq!(
        fs::read_to_string(workdir.join("seen.txt")).unwrap(),
        "after\n",
        "stage 1 must read what stage 0 wrote, not the pre-transaction workdir copy",
    );
    assert_eq!(fs::read_to_string(workdir.join("in.txt")).unwrap(), "after\n");

    let _ = fs::remove_dir_all(&workdir);
}

/// Concern 5: the backend-neutral recovery module is not merely re-exported at
/// the right TYPE — it PARSES a preserved branch at runtime through
/// `sandlock_core::recovery::*`, not the flat aliases and not the backend-named
/// `cow::seccomp` path. `read_preserved` is the genuine residual: it is never
/// runtime-exercised through any other namespace, so a re-export pointed at a stub
/// (returning `None`/empty) would still COMPILE but fail here.
#[test]
fn recovery_module_reexports_parse_a_preserved_branch_on_disk() {
    use sandlock_core::recovery::{list_preserved, read_preserved, PreserveReason};

    // Drop a real preserved branch on disk: an upper plus a marker in the on-disk
    // format a preserved branch leaves (reason, workdir, upper, one deletion, and
    // the preserving pid).
    let base = temp_dir("recovery-reexport");
    let branch_dir = base.join("branch-xyz");
    let upper = branch_dir.join("upper");
    fs::create_dir_all(&upper).unwrap();
    let marker = format!(
        "reason=commit-deferred\nworkdir=/some/workdir\nupper={}\ndeleted=gone.txt\npid=4242\n",
        upper.display(),
    );
    fs::write(branch_dir.join("PRESERVED"), marker).unwrap();

    // list_preserved through recovery:: FINDS and PARSES it.
    let found = list_preserved(&base);
    assert_eq!(found.len(), 1, "recovery::list_preserved must find the marked branch");
    let p = &found[0];
    assert_eq!(p.pid, 4242, "the marker's pid must be parsed");
    assert_eq!(p.reason, PreserveReason::CommitDeferred, "the reason must be parsed");
    assert_eq!(p.upper, upper, "the upper path must be parsed");
    assert_eq!(p.workdir, PathBuf::from("/some/workdir"), "the workdir must be parsed");
    assert_eq!(p.deleted, vec![PathBuf::from("gone.txt")], "the deletion must be parsed");

    // read_preserved through recovery:: returns the same record for the branch dir.
    let one = read_preserved(&branch_dir)
        .expect("recovery::read_preserved must return Some for a marked branch");
    assert_eq!(one.pid, 4242);
    assert_eq!(one.reason, PreserveReason::CommitDeferred);
    assert_eq!(one.upper, upper);

    let _ = fs::remove_dir_all(&base);
}
