//! Every run reports its change set, and `BranchAction::Defer` hands the
//! disposition to the caller instead of `Drop`.

use sandlock_core::sandbox::BranchAction;
use sandlock_core::{ChangeKind, PreserveReason, Sandbox};
use std::fs;
use std::path::{Path, PathBuf};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandlock-test-branch-{}-{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::create_dir_all(&dir);
    dir
}

fn policy(workdir: &Path, storage: &Path) -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_write(workdir).workdir(workdir).cwd(workdir)
        .fs_storage(storage)
}

#[tokio::test]
async fn abort_reports_added_file_without_creating_it() {
    let workdir = temp_dir("abort-add-wd");
    let storage = temp_dir("abort-add-st");
    let mut sb = policy(&workdir, &storage).on_exit(BranchAction::Abort).build().unwrap();

    let result = sb.run(&["sh", "-c", "echo created > new.txt"]).await.unwrap();
    assert!(result.success(), "stderr={}", result.stderr_str().unwrap_or(""));
    drop(sb);

    assert!(!workdir.join("new.txt").exists(), "aborted run must not write the workdir");
    assert!(result.changes.iter().any(|c| c.kind() == ChangeKind::Added && c.path == Path::new("new.txt")));
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

#[tokio::test]
async fn abort_reports_modified_file_without_changing_it() {
    let workdir = temp_dir("abort-mod-wd");
    let storage = temp_dir("abort-mod-st");
    fs::write(workdir.join("data.txt"), "original").unwrap();
    let mut sb = policy(&workdir, &storage).on_exit(BranchAction::Abort).build().unwrap();

    let result = sb.run(&["sh", "-c", "echo modified > data.txt"]).await.unwrap();
    assert!(result.success(), "stderr={}", result.stderr_str().unwrap_or(""));
    drop(sb);

    assert_eq!(fs::read_to_string(workdir.join("data.txt")).unwrap(), "original");
    assert!(result.changes.iter().any(|c| c.kind() == ChangeKind::Modified && c.path == Path::new("data.txt")));
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

#[tokio::test]
async fn abort_reports_deleted_file_without_removing_it() {
    let workdir = temp_dir("abort-del-wd");
    let storage = temp_dir("abort-del-st");
    fs::write(workdir.join("victim.txt"), "delete me").unwrap();
    let mut sb = policy(&workdir, &storage).on_exit(BranchAction::Abort).build().unwrap();

    let result = sb.run(&["sh", "-c", "rm victim.txt"]).await.unwrap();
    assert!(result.success(), "stderr={}", result.stderr_str().unwrap_or(""));
    drop(sb);

    assert!(workdir.join("victim.txt").exists());
    assert!(result.changes.iter().any(|c| c.kind() == ChangeKind::Deleted && c.path == Path::new("victim.txt")));
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

#[tokio::test]
async fn commit_reports_the_changes_it_merged() {
    let workdir = temp_dir("commit-wd");
    let storage = temp_dir("commit-st");
    let mut sb = policy(&workdir, &storage).build().unwrap();

    let result = sb.run(&["sh", "-c", "echo hi > out.txt"]).await.unwrap();
    assert!(result.success(), "stderr={}", result.stderr_str().unwrap_or(""));
    drop(sb);

    assert_eq!(fs::read_to_string(workdir.join("out.txt")).unwrap(), "hi\n");
    assert!(result.changes.iter().any(|c| c.kind() == ChangeKind::Added && c.path == Path::new("out.txt")));
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

#[tokio::test]
async fn run_without_workdir_reports_no_changes() {
    let mut sb = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .build()
        .unwrap();
    let result = sb.run(&["true"]).await.unwrap();
    assert!(result.success());
    assert!(result.changes.is_empty());
    assert!(!sb.pending());
}

#[tokio::test]
async fn defer_holds_the_branch_until_commit() {
    let workdir = temp_dir("defer-commit-wd");
    let storage = temp_dir("defer-commit-st");
    let mut sb = policy(&workdir, &storage).on_exit(BranchAction::Defer).build().unwrap();

    let result = sb.run(&["sh", "-c", "echo hi > out.txt"]).await.unwrap();
    assert!(result.success(), "stderr={}", result.stderr_str().unwrap_or(""));

    assert!(sb.pending());
    assert!(!workdir.join("out.txt").exists(), "nothing lands before the caller decides");
    let upper = sb.upper_dir().expect("a pending branch has an upper").to_path_buf();
    assert_eq!(fs::read_to_string(upper.join("out.txt")).unwrap(), "hi\n");

    sb.commit().unwrap();
    assert!(!sb.pending());
    assert!(sb.upper_dir().is_none());
    assert_eq!(fs::read_to_string(workdir.join("out.txt")).unwrap(), "hi\n");
    drop(sb);
    assert!(sandlock_core::list_preserved(&storage).is_empty());
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

#[tokio::test]
async fn defer_then_abort_discards() {
    let workdir = temp_dir("defer-abort-wd");
    let storage = temp_dir("defer-abort-st");
    let mut sb = policy(&workdir, &storage).on_exit(BranchAction::Defer).build().unwrap();

    let result = sb.run(&["sh", "-c", "echo hi > out.txt"]).await.unwrap();
    assert!(result.success(), "stderr={}", result.stderr_str().unwrap_or(""));
    assert!(sb.pending());

    sb.abort().unwrap();
    assert!(!sb.pending());
    assert!(!workdir.join("out.txt").exists());
    drop(sb);
    assert!(sandlock_core::list_preserved(&storage).is_empty());
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

#[tokio::test]
async fn defer_dropped_undecided_preserves_the_branch() {
    let workdir = temp_dir("defer-drop-wd");
    let storage = temp_dir("defer-drop-st");
    {
        let mut sb = policy(&workdir, &storage).on_exit(BranchAction::Defer).build().unwrap();
        let result = sb.run(&["sh", "-c", "echo hi > out.txt"]).await.unwrap();
        assert!(result.success(), "stderr={}", result.stderr_str().unwrap_or(""));
        assert!(sb.pending());
    }

    assert!(!workdir.join("out.txt").exists());
    let preserved = sandlock_core::list_preserved(&storage);
    assert_eq!(preserved.len(), 1);
    assert_eq!(preserved[0].reason, PreserveReason::Kept);
    assert_eq!(fs::read_to_string(preserved[0].upper.join("out.txt")).unwrap(), "hi\n");
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

#[tokio::test]
async fn defer_on_exit_still_aborts_a_failed_run() {
    let workdir = temp_dir("defer-fail-wd");
    let storage = temp_dir("defer-fail-st");
    let mut sb = policy(&workdir, &storage)
        .on_exit(BranchAction::Defer)
        .on_error(BranchAction::Abort)
        .build()
        .unwrap();

    let result = sb.run(&["sh", "-c", "echo hi > out.txt; exit 3"]).await.unwrap();
    assert_eq!(result.code(), Some(3));
    assert!(result.changes.iter().any(|c| c.path == Path::new("out.txt")));

    assert!(!sb.pending());
    assert!(sb.commit().is_err());
    drop(sb);
    assert!(!workdir.join("out.txt").exists());
    assert!(sandlock_core::list_preserved(&storage).is_empty());
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}

#[tokio::test]
async fn commit_and_abort_need_a_pending_branch() {
    let workdir = temp_dir("not-pending-wd");
    let storage = temp_dir("not-pending-st");
    let mut sb = policy(&workdir, &storage).build().unwrap();

    assert!(sb.commit().is_err(), "nothing ran yet");
    assert!(sb.abort().is_err());

    let result = sb.run(&["true"]).await.unwrap();
    assert!(result.success());
    assert!(sb.commit().is_err(), "Commit disposed the branch in wait()");
    assert!(sb.abort().is_err());
    let _ = fs::remove_dir_all(&workdir);
    let _ = fs::remove_dir_all(&storage);
}
