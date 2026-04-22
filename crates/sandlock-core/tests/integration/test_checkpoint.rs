use sandlock_core::{Policy, Sandbox, Checkpoint};

/// Test that checkpoint save/load roundtrips correctly.
#[tokio::test]
#[cfg_attr(target_arch = "aarch64", ignore = "ARM64 checkpoint register capture is planned for stage 4")]
async fn test_checkpoint_save_load() {
    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .build().unwrap();

    // Start a long-running process
    let mut sb = Sandbox::new(&policy).unwrap();
    // We need to spawn something that stays alive long enough to checkpoint
    // Use "sleep 60" — we'll kill it after checkpoint
    sb.spawn(&["sleep", "60"]).await.unwrap();

    // Give it a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Checkpoint
    let cp = sb.checkpoint().await.unwrap();
    assert!(!cp.process_state.memory_maps.is_empty(), "Should capture memory maps");
    assert!(!cp.process_state.regs.is_empty(), "Should capture registers");
    assert!(!cp.fd_table.is_empty(), "Should capture file descriptors");

    // Save to temp directory
    let tmp = std::env::temp_dir().join(format!("sandlock-cp-test-{}", std::process::id()));
    cp.save(&tmp).unwrap();

    // Verify directory structure
    assert!(tmp.join("meta.json").exists());
    assert!(tmp.join("policy.dat").exists());
    assert!(tmp.join("process/info.json").exists());
    assert!(tmp.join("process/fds.json").exists());
    assert!(tmp.join("process/memory_map.json").exists());
    assert!(tmp.join("process/threads/0.bin").exists());

    // Load back
    let loaded = Checkpoint::load(&tmp).unwrap();
    assert_eq!(loaded.process_state.regs.len(), cp.process_state.regs.len());
    assert_eq!(loaded.process_state.memory_data.len(), cp.process_state.memory_data.len());
    assert_eq!(loaded.fd_table.len(), cp.fd_table.len());
    assert_eq!(loaded.process_state.pid, cp.process_state.pid);
    assert!(!loaded.process_state.exe.is_empty());

    // Cleanup
    sb.kill().unwrap();
    let _ = sb.wait().await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Test that checkpoint captures memory maps correctly.
#[tokio::test]
#[cfg_attr(target_arch = "aarch64", ignore = "ARM64 checkpoint register capture is planned for stage 4")]
async fn test_checkpoint_memory_maps() {
    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .build().unwrap();

    let mut sb = Sandbox::new(&policy).unwrap();
    sb.spawn(&["sleep", "60"]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let cp = sb.checkpoint().await.unwrap();

    // Should have at least stack, heap, and code segments
    let has_stack = cp.process_state.memory_maps.iter().any(|m| {
        m.path.as_ref().map_or(false, |p| p.contains("[stack]"))
    });
    assert!(has_stack, "Should capture stack mapping");

    // Memory data should have some writable segments captured
    assert!(!cp.process_state.memory_data.is_empty(), "Should capture writable memory");

    sb.kill().unwrap();
    let _ = sb.wait().await;
}

/// Test that app_state round-trips through save/load.
#[tokio::test]
#[cfg_attr(target_arch = "aarch64", ignore = "ARM64 checkpoint register capture is planned for stage 4")]
async fn test_checkpoint_app_state_roundtrip() {
    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .build().unwrap();

    let mut sb = Sandbox::new(&policy).unwrap();
    sb.spawn(&["sleep", "60"]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut cp = sb.checkpoint().await.unwrap();

    // Set app_state (simulating save_fn)
    let state = b"hello from save_fn \x00\xff".to_vec();
    cp.app_state = Some(state.clone());

    let tmp = std::env::temp_dir().join(format!("sandlock-cp-appstate-{}", std::process::id()));
    cp.save(&tmp).unwrap();

    // app_state.bin should exist
    assert!(tmp.join("app_state.bin").exists());

    // Load and verify
    let loaded = Checkpoint::load(&tmp).unwrap();
    assert_eq!(loaded.app_state, Some(state));

    sb.kill().unwrap();
    let _ = sb.wait().await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Test that checkpoint without app_state doesn't create app_state.bin.
#[tokio::test]
#[cfg_attr(target_arch = "aarch64", ignore = "ARM64 checkpoint register capture is planned for stage 4")]
async fn test_checkpoint_no_app_state_file() {
    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .build().unwrap();

    let mut sb = Sandbox::new(&policy).unwrap();
    sb.spawn(&["sleep", "60"]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let cp = sb.checkpoint().await.unwrap();
    assert!(cp.app_state.is_none());

    let tmp = std::env::temp_dir().join(format!("sandlock-cp-noapp-{}", std::process::id()));
    cp.save(&tmp).unwrap();
    assert!(!tmp.join("app_state.bin").exists());

    let loaded = Checkpoint::load(&tmp).unwrap();
    assert!(loaded.app_state.is_none());

    sb.kill().unwrap();
    let _ = sb.wait().await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Test that process info (pid, cwd, exe) is captured correctly.
#[tokio::test]
#[cfg_attr(target_arch = "aarch64", ignore = "ARM64 checkpoint register capture is planned for stage 4")]
async fn test_checkpoint_process_info() {
    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .build().unwrap();

    let mut sb = Sandbox::new(&policy).unwrap();
    sb.spawn(&["sleep", "60"]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let expected_pid = sb.pid().unwrap();
    let cp = sb.checkpoint().await.unwrap();

    assert_eq!(cp.process_state.pid, expected_pid);
    assert!(cp.process_state.exe.contains("sleep"), "exe should contain 'sleep', got: {}", cp.process_state.exe);
    assert!(!cp.process_state.cwd.is_empty(), "cwd should not be empty");

    sb.kill().unwrap();
    let _ = sb.wait().await;
}

/// Test loading from a nonexistent directory fails.
#[tokio::test]
async fn test_checkpoint_load_nonexistent() {
    let result = Checkpoint::load(std::path::Path::new("/tmp/sandlock-nonexistent-checkpoint"));
    assert!(result.is_err());
}

/// Test checkpoint on a non-running sandbox fails gracefully.
#[tokio::test]
async fn test_checkpoint_not_running() {
    let policy = Policy::builder().build().unwrap();
    let sb = Sandbox::new(&policy).unwrap();
    let result = sb.checkpoint().await;
    assert!(result.is_err(), "Checkpoint on non-running sandbox should error");
}
