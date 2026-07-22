//! Transaction tests (RFC #65 Phase 1a).
//!
//! Sequential stages share one COW upper over a common workdir: a later stage
//! sees an earlier stage's writes (read-committed), and the whole transaction
//! commits all-or-nothing. Data is exchanged through the shared workspace, not
//! inter-stage pipes.

use sandlock_core::sandbox::BranchAction;
use sandlock_core::{AbortReason, ChangeKind, Sandbox, Stage, Transaction, TxnError};
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

    assert!(outcome.committed, "transaction should commit; abort_reason: {:?}", outcome.abort_reason);
    assert!(outcome.abort_reason.is_none(), "a committed transaction has no abort reason");
    assert_eq!(outcome.stages.len(), 3, "all three stages should have run");
    assert!(workdir.join("a.txt").exists(), "a.txt must be committed to workdir");
    assert!(workdir.join("b.txt").exists(), "b.txt must be committed to workdir");
    assert_eq!(fs::read_to_string(workdir.join("a.txt")).unwrap(), "plan\n");

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
        outcome.committed,
        "a transaction must wait out a concurrent commit, not lose its work; abort_reason: {:?}",
        outcome.abort_reason
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

    assert!(!outcome.committed, "a failing stage must abort the transaction");
    // The reason is typed: a caller can tell WHICH stage failed and how, with no
    // string matching.
    assert_eq!(
        outcome.abort_reason,
        Some(AbortReason::StageFailed {
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
    assert!(!aborted.committed);
    assert_eq!(branch_count(&storage), 0, "aborted transaction must reclaim its upper from the storage dir");

    // Commit path: also reclaimed after the merge.
    let committed = Transaction::new([
        Stage::new(&policy, &["sh", "-c", "echo y > b.txt"]),
        Stage::new(&policy, &["sh", "-c", "cat b.txt"]),
    ])
    .run(None).await.expect("transaction should run");
    assert!(committed.committed);
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

    assert!(!outcome.committed, "a timed-out transaction must abort");
    assert_eq!(outcome.abort_reason, Some(AbortReason::TimedOut));
    assert_eq!(
        outcome.stages.len(),
        1,
        "the first stage completed before the deadline; its result must survive the cancellation",
    );
    assert!(outcome.stages[0].success(), "the completed stage exited 0");
    assert!(!workdir.join("a.txt").exists(), "a.txt must NOT leak after a timeout abort");

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
    assert!(committed.committed, "abort_reason: {:?}", committed.abort_reason);

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
    assert!(!aborted.committed);
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

    assert!(!outcome.committed, "a dry run must never commit");
    assert_eq!(outcome.abort_reason, Some(AbortReason::DryRun));
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
/// accepts any stage list, so this is the only thing standing between a
/// one-stage transaction and an out-of-bounds index in the coordinator.
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

    assert!(!outcome.committed, "first-stage failure must abort");
    assert_eq!(
        outcome.abort_reason,
        Some(AbortReason::StageFailed { index: 0, status: sandlock_core::ExitStatus::Code(1) }),
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
    assert!(!outcome.committed, "timed-out transaction must abort");
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
    assert!(committed.committed, "commit expected; abort_reason: {:?}", committed.abort_reason);
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
    assert!(!aborted.committed, "abort expected");
    assert_eq!(
        fs::read_to_string(wd_a.join("keep.txt")).unwrap(), "orig\n",
        "aborted deletion must leave keep.txt intact in the workdir",
    );

    let _ = fs::remove_dir_all(&wd_c);
    let _ = fs::remove_dir_all(&wd_a);
}
