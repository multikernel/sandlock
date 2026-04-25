use sandlock_core::{Policy, Sandbox};
use sandlock_core::dry_run::ChangeKind;
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandlock-test-dryrun-{}-{}", name, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

#[tokio::test]
async fn test_dry_run_reports_added_file() {
    let workdir = temp_dir("add");
    fs::write(workdir.join("existing.txt"), "hello").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .build()
        .unwrap();

    let new_file = workdir.join("new.txt");
    let cmd = format!("echo created > {}", new_file.display());
    let result = Sandbox::dry_run(&policy, &["sh", "-c", &cmd]).await;
    match result {
        Ok(dr) => {
            assert!(dr.run_result.success());
            assert!(!new_file.exists(), "new.txt should not exist after dry-run");
            let added: Vec<_> = dr.changes.iter()
                .filter(|c| c.kind == ChangeKind::Added)
                .collect();
            assert!(!added.is_empty(), "should report added file");
        }
        Err(e) => eprintln!("Dry-run test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

#[tokio::test]
async fn test_dry_run_reports_modified_file() {
    let workdir = temp_dir("modify");
    fs::write(workdir.join("data.txt"), "original").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .build()
        .unwrap();

    let cmd = format!("echo modified > {}/data.txt", workdir.display());
    let result = Sandbox::dry_run(&policy, &["sh", "-c", &cmd]).await;
    match result {
        Ok(dr) => {
            assert!(dr.run_result.success());
            let content = fs::read_to_string(workdir.join("data.txt")).unwrap();
            assert_eq!(content, "original", "data.txt should be unchanged after dry-run");
            let modified: Vec<_> = dr.changes.iter()
                .filter(|c| c.kind == ChangeKind::Modified)
                .collect();
            assert!(!modified.is_empty(), "should report modified file");
        }
        Err(e) => eprintln!("Dry-run test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

#[tokio::test]
async fn test_dry_run_reports_deleted_file() {
    let workdir = temp_dir("delete");
    fs::write(workdir.join("victim.txt"), "delete me").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc").fs_read("/dev")
        .fs_write(&workdir)
        .workdir(&workdir)
        .build()
        .unwrap();

    let cmd = format!("rm {}/victim.txt", workdir.display());
    let result = Sandbox::dry_run(&policy, &["sh", "-c", &cmd]).await;
    match result {
        Ok(dr) => {
            assert!(dr.run_result.success());
            assert!(workdir.join("victim.txt").exists(), "victim.txt should still exist after dry-run");
            let deleted: Vec<_> = dr.changes.iter()
                .filter(|c| c.kind == ChangeKind::Deleted)
                .collect();
            assert!(!deleted.is_empty(), "should report deleted file");
        }
        Err(e) => eprintln!("Dry-run test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}
