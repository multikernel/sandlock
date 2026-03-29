use sandlock_core::{Policy, Sandbox, Checkpoint};

/// Test that checkpoint save/load roundtrips correctly.
#[tokio::test]
async fn test_checkpoint_save_load() {
    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin").fs_read("/etc")
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
async fn test_checkpoint_memory_maps() {
    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin").fs_read("/etc")
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

/// Test checkpoint on a non-running sandbox fails gracefully.
#[tokio::test]
async fn test_checkpoint_not_running() {
    let policy = Policy::builder().build().unwrap();
    let sb = Sandbox::new(&policy).unwrap();
    let result = sb.checkpoint().await;
    assert!(result.is_err(), "Checkpoint on non-running sandbox should error");
}
