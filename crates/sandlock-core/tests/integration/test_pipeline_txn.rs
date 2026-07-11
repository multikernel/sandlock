//! Transactional pipeline tests (RFC #65 Phase 1).
//!
//! Sequential stages share one COW upper over a common workdir: a later stage
//! sees an earlier stage's writes (read-committed), and the whole pipeline
//! commits all-or-nothing. Data is exchanged through the shared workspace, not
//! inter-stage pipes.

use sandlock_core::sandbox::BranchAction;
use sandlock_core::{Sandbox, Stage};
use std::fs;
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
/// `on_exit`/`on_error` are left at their defaults (the pipeline owns commit).
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
async fn test_txn_pipeline_commits_on_success() {
    if !sandbox_available().await {
        eprintln!("commit test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("commit");
    let policy = stage_policy(&workdir);

    let pipeline = Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"])
        | Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"])
        | Stage::new(&policy, &["sh", "-c", "cat a.txt b.txt"]);

    let outcome = pipeline.run_transactional(None).await.expect("transaction should run");
    assert!(outcome.committed, "pipeline should commit; abort_reason: {:?}", outcome.abort_reason);
    assert_eq!(outcome.stages.len(), 3, "all three stages should have run");
    assert!(workdir.join("a.txt").exists(), "a.txt must be committed to workdir");
    assert!(workdir.join("b.txt").exists(), "b.txt must be committed to workdir");
    assert_eq!(fs::read_to_string(workdir.join("a.txt")).unwrap(), "plan\n");

    let _ = fs::remove_dir_all(&workdir);
}

/// Any stage failing aborts the whole transaction: earlier stages' writes are
/// discarded and the workdir is byte-identical to before the run.
#[tokio::test]
async fn test_txn_pipeline_aborts_on_stage_failure() {
    if !sandbox_available().await {
        eprintln!("abort test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("abort");
    fs::write(workdir.join("existing.txt"), "original\n").unwrap();
    let policy = stage_policy(&workdir);

    // Stage 2 writes b.txt but the final stage exits non-zero → abort all.
    let pipeline = Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"])
        | Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"])
        | Stage::new(&policy, &["sh", "-c", "exit 1"]);

    let outcome = pipeline.run_transactional(None).await.expect("transaction should run");
    assert!(!outcome.committed, "a failing stage must abort the transaction");
    assert!(outcome.abort_reason.is_some(), "abort must carry a reason");
    assert!(!workdir.join("a.txt").exists(), "a.txt must NOT leak after abort");
    assert!(!workdir.join("b.txt").exists(), "b.txt must NOT leak after abort");
    assert_eq!(fs::read_to_string(workdir.join("existing.txt")).unwrap(), "original\n");

    let _ = fs::remove_dir_all(&workdir);
}

/// The shared upper is reclaimed from disk after BOTH abort and commit — the
/// end-to-end check that a failed/completed transaction never orphans its upper.
#[tokio::test]
async fn test_txn_pipeline_reclaims_upper() {
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
    let aborted = (Stage::new(&policy, &["sh", "-c", "echo x > a.txt"])
        | Stage::new(&policy, &["sh", "-c", "exit 1"]))
        .run_transactional(None).await.expect("transaction should run");
    assert!(!aborted.committed);
    assert_eq!(branch_count(&storage), 0, "aborted pipeline must reclaim its upper from the storage dir");

    // Commit path: also reclaimed after the merge.
    let committed = (Stage::new(&policy, &["sh", "-c", "echo y > b.txt"])
        | Stage::new(&policy, &["sh", "-c", "cat b.txt"]))
        .run_transactional(None).await.expect("transaction should run");
    assert!(committed.committed);
    assert_eq!(branch_count(&storage), 0, "committed pipeline must reclaim its upper from the storage dir");

    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

/// A pipeline timeout aborts the whole transaction without leaking earlier
/// stages' writes into the workdir.
#[tokio::test]
async fn test_txn_pipeline_timeout_aborts() {
    if !sandbox_available().await {
        eprintln!("timeout test skipped: sandbox unavailable");
        return;
    }
    let workdir = temp_dir("timeout");
    let policy = stage_policy(&workdir);

    let pipeline = Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"])
        | Stage::new(&policy, &["sh", "-c", "sleep 30"]);

    let outcome = pipeline
        .run_transactional(Some(Duration::from_millis(600)))
        .await
        .expect("transaction should run");
    assert!(!outcome.committed, "a timed-out pipeline must abort");
    assert!(
        outcome.abort_reason.as_deref().unwrap_or("").contains("timed out"),
        "abort reason should mention the timeout, got: {:?}",
        outcome.abort_reason
    );
    assert!(!workdir.join("a.txt").exists(), "a.txt must NOT leak after a timeout abort");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: a non-default `on_exit`/`on_error` conflicts with the pipeline
/// owning commit/abort, and is rejected before anything runs. (No sandbox needed.)
#[tokio::test]
async fn test_txn_pipeline_rejects_branch_action() {
    let workdir = temp_dir("guard-action");
    let plain = stage_policy(&workdir);
    let with_action = Sandbox::builder()
        .fs_read("/usr").fs_write(&workdir).workdir(&workdir)
        .on_exit(BranchAction::Keep)
        .build()
        .unwrap();

    let pipeline = Stage::new(&plain, &["true"]) | Stage::new(&with_action, &["true"]);
    let err = pipeline.run_transactional(None).await.unwrap_err().to_string();
    assert!(err.contains("on_exit/on_error"), "expected the on_exit guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: every stage must set a workdir (the shared transaction dir).
#[tokio::test]
async fn test_txn_pipeline_rejects_missing_workdir() {
    let workdir = temp_dir("guard-workdir");
    let with_wd = stage_policy(&workdir);
    let no_wd = Sandbox::builder().fs_read("/usr").build().unwrap();

    let pipeline = Stage::new(&with_wd, &["true"]) | Stage::new(&no_wd, &["true"]);
    let err = pipeline.run_transactional(None).await.unwrap_err().to_string();
    assert!(err.contains("no workdir"), "expected the workdir guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}

/// Guardrail: fewer than two stages is rejected, not a panic (the `pub stages`
/// field bypasses `Pipeline::new`'s check).
#[tokio::test]
async fn test_txn_pipeline_rejects_too_few_stages() {
    let workdir = temp_dir("guard-count");
    let policy = stage_policy(&workdir);
    let single = sandlock_core::Pipeline { stages: vec![Stage::new(&policy, &["true"])] };
    let err = single.run_transactional(None).await.unwrap_err().to_string();
    assert!(err.contains("at least 2 stages"), "expected the stage-count guardrail, got: {err}");

    let _ = fs::remove_dir_all(&workdir);
}
