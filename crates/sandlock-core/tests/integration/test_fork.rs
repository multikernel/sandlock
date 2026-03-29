use sandlock_core::{Policy, Sandbox};
use std::sync::atomic::{AtomicU32, Ordering};

fn base_policy() -> Policy {
    Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap()
}

/// Test basic COW fork returns Sandbox handles.
#[tokio::test]
async fn test_fork_basic() {
    let out_dir = std::env::temp_dir().join(format!("sandlock-fork-basic-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&out_dir);
    let out = out_dir.clone();

    let policy = base_policy();
    let mut sb = Sandbox::new_with_fns(
        &policy,
        || {},
        move |clone_id| {
            let _ = std::fs::write(out.join(format!("{}", clone_id)), clone_id.to_string());
        },
    ).unwrap();

    let mut clones = sb.fork(4).await.unwrap();
    assert_eq!(clones.len(), 4);

    // Each clone is a live Sandbox — wait for all
    for c in clones.iter_mut() {
        let r = c.wait().await.unwrap();
        assert!(r.success());
    }

    // Verify each clone ran
    for i in 0..4u32 {
        let content = std::fs::read_to_string(out_dir.join(format!("{}", i))).unwrap_or_default();
        assert_eq!(content, i.to_string());
    }

    let _ = std::fs::remove_dir_all(&out_dir);
}

/// Test that COW fork shares memory (init state visible in clones).
#[tokio::test]
async fn test_fork_cow_sharing() {
    static SHARED: AtomicU32 = AtomicU32::new(0);
    SHARED.store(0, Ordering::Relaxed);

    let out_dir = std::env::temp_dir().join(format!("sandlock-fork-cow-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&out_dir);
    let out = out_dir.clone();

    let policy = base_policy();
    let mut sb = Sandbox::new_with_fns(
        &policy,
        || { SHARED.store(42, Ordering::Relaxed); },
        move |clone_id| {
            let val = SHARED.load(Ordering::Relaxed);
            let _ = std::fs::write(out.join(format!("{}", clone_id)), val.to_string());
        },
    ).unwrap();

    let mut clones = sb.fork(3).await.unwrap();
    for c in clones.iter_mut() { let _ = c.wait().await; }

    for i in 0..3u32 {
        let content = std::fs::read_to_string(out_dir.join(format!("{}", i))).unwrap_or_default();
        assert_eq!(content, "42", "clone {} should see shared state", i);
    }

    let _ = std::fs::remove_dir_all(&out_dir);
}

/// Test CLONE_ID environment variable.
#[tokio::test]
async fn test_fork_clone_id_env() {
    let out_dir = std::env::temp_dir().join(format!("sandlock-fork-env-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&out_dir);
    let out = out_dir.clone();

    let policy = base_policy();
    let mut sb = Sandbox::new_with_fns(
        &policy,
        || {},
        move |_| {
            let id = std::env::var("CLONE_ID").unwrap_or_default();
            let _ = std::fs::write(out.join(&id), &id);
        },
    ).unwrap();

    let mut clones = sb.fork(3).await.unwrap();
    for c in clones.iter_mut() { let _ = c.wait().await; }

    for i in 0..3u32 {
        let content = std::fs::read_to_string(out_dir.join(format!("{}", i))).unwrap_or_default();
        assert_eq!(content, i.to_string());
    }

    let _ = std::fs::remove_dir_all(&out_dir);
}

/// Test map-reduce: clone stdout flows via pipes to reducer stdin.
#[tokio::test]
async fn test_fork_reduce() {
    let map_policy = base_policy();
    let reduce_policy = base_policy();

    // Map: each clone prints its square to stdout (captured via pipe)
    let mut mapper = Sandbox::new_with_fns(
        &map_policy,
        || {},
        |clone_id| {
            // Write to stdout — goes to per-clone pipe
            use std::io::Write;
            let _ = writeln!(std::io::stdout(), "{}", clone_id * clone_id);
        },
    ).unwrap();

    let mut clones = mapper.fork(4).await.unwrap();

    // Reduce: reads all clone pipes, feeds to reducer stdin
    let reducer = Sandbox::new(&reduce_policy).unwrap();
    let result = reducer.reduce(
        &["python3", "-c", "import sys; print(sum(int(l) for l in sys.stdin))"],
        &mut clones,
    ).await.unwrap();

    assert!(result.success(), "reducer should succeed");
    let stdout = result.stdout_str().unwrap_or("");
    assert_eq!(stdout, "14", "0+1+4+9=14, got: {}", stdout);
}

/// Test clone exit status is captured.
#[tokio::test]
async fn test_fork_clone_exit_status() {
    let out_dir = std::env::temp_dir().join(format!("sandlock-fork-status-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&out_dir);
    let out = out_dir.clone();

    let policy = base_policy();
    let mut sb = Sandbox::new_with_fns(
        &policy,
        || {},
        move |clone_id| {
            let _ = std::fs::write(out.join(format!("{}", clone_id)), "done");
        },
    ).unwrap();

    let mut clones = sb.fork(3).await.unwrap();

    // All clones should have succeeded (already finished)
    for (i, c) in clones.iter_mut().enumerate() {
        let r = c.wait().await.unwrap();
        assert!(r.success(), "clone {} should succeed", i);
    }

    let _ = std::fs::remove_dir_all(&out_dir);
}
