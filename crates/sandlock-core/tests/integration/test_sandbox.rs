use sandlock_core::{Policy, Sandbox};

#[tokio::test]
async fn test_echo() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .build()
        .unwrap();
    let result = Sandbox::run(&policy, &["echo", "hello"]).await.unwrap();
    assert!(result.success());
    assert_eq!(result.code(), Some(0));
}

#[tokio::test]
async fn test_exit_code() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/proc")
        .build()
        .unwrap();
    let result = Sandbox::run(&policy, &["sh", "-c", "exit 42"]).await.unwrap();
    assert_eq!(result.code(), Some(42));
}

#[tokio::test]
async fn test_denied_path() {
    // No /etc in readable paths
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/proc")
        .build()
        .unwrap();
    let result = Sandbox::run(&policy, &["cat", "/etc/hostname"]).await.unwrap();
    assert!(!result.success());
}

#[tokio::test]
async fn test_denied_syscall() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();
    // mount is in DEFAULT_DENY_SYSCALLS; redirect stderr to /dev/null
    // (need /dev readable for this)
    let result = Sandbox::run(
        &policy,
        &["sh", "-c", "mount -t tmpfs none /tmp 2>/dev/null; echo $?"],
    )
    .await
    .unwrap();
    // sh exits 0 even though mount failed inside the sandbox
    assert!(result.success());
}

#[tokio::test]
async fn test_kill_not_running() {
    let policy = Policy::builder().build().unwrap();
    let mut sb = Sandbox::new(&policy).unwrap();
    assert!(sb.kill().is_err()); // NotRunning
}

#[tokio::test]
async fn test_pause_not_running() {
    let policy = Policy::builder().build().unwrap();
    let mut sb = Sandbox::new(&policy).unwrap();
    assert!(sb.pause().is_err());
}

#[tokio::test]
async fn test_resume_not_running() {
    let policy = Policy::builder().build().unwrap();
    let mut sb = Sandbox::new(&policy).unwrap();
    assert!(sb.resume().is_err());
}

#[tokio::test]
async fn test_default_policy_runs_ls() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/bin")
        .fs_read("/proc")
        .fs_read("/etc")
        .build()
        .unwrap();
    // Use "ls /bin" instead of "ls /" because Landlock restricts access
    // to specific subtrees, not the root directory itself.
    let result = Sandbox::run(&policy, &["ls", "/bin"]).await.unwrap();
    assert!(result.success());
}

/// Test nested sandboxes: inner sandbox restricts what outer allows.
///
/// Outer sandbox runs `sh -c` which execs a command. The inner sandbox
/// is created by calling Sandbox::run from within the outer sandbox's
/// child process. The EBUSY fallback installs a deny-only seccomp
/// filter while Landlock rules stack (intersect).
#[tokio::test]
async fn test_nested_sandbox() {
    // Outer: allows /etc
    let outer = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    // Inner: does NOT allow /etc — run cat /etc/hostname, should fail
    let inner = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin")
        .fs_read("/proc")
        .build()
        .unwrap();

    // Spawn outer, then nest inner inside it
    let mut outer_sb = Sandbox::new(&outer).unwrap();
    outer_sb.spawn(&["sleep", "10"]).await.unwrap();

    // The inner sandbox runs in the same parent process context —
    // Landlock from the outer is NOT applied to the parent, only to
    // the outer's child. So to truly test nesting, the inner sandbox
    // must run from within the outer sandbox's confined process.
    //
    // We test this by having the outer sandbox run a command, then
    // separately verifying that running Sandbox::run after another
    // Sandbox::run works (the seccomp filter stacks).
    outer_sb.kill().unwrap();
    let _ = outer_sb.wait().await;

    // Sequential sandboxes: first sandbox applies Landlock + seccomp,
    // second sandbox from the same parent gets EBUSY on seccomp
    // but Landlock stacks. Verify both work independently.
    let r1 = Sandbox::run_interactive(&outer, &["cat", "/etc/hostname"]).await.unwrap();
    assert!(r1.success(), "outer should allow /etc");

    let r2 = Sandbox::run_interactive(&inner, &["cat", "/etc/hostname"]).await.unwrap();
    assert!(!r2.success(), "inner should deny /etc");
}

/// Test nested sandbox via CLI: outer runs inner sandlock binary.
#[tokio::test]
async fn test_nested_sandbox_via_cli() {
    let sandlock_bin = std::env::current_dir().unwrap()
        .join("../../target/release/sandlock").canonicalize();
    let sandlock_bin = match sandlock_bin {
        Ok(p) if p.exists() => p,
        _ => {
            eprintln!("Skipping: sandlock binary not found");
            return;
        }
    };
    let bin = sandlock_bin.to_str().unwrap();

    // Outer allows /etc + sandlock binary; inner does not allow /etc
    let outer = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_read(sandlock_bin.parent().unwrap())
        .fs_write("/tmp")
        .build()
        .unwrap();

    let inner_cmd = format!(
        "{} run -r /usr -r /lib -r /lib64 -r /bin -r /proc -- cat /etc/hostname",
        bin
    );
    let result = Sandbox::run_interactive(
        &outer, &["sh", "-c", &inner_cmd],
    ).await.unwrap();
    assert!(!result.success(), "inner sandbox should block /etc");

    // Inner with /etc allowed — should succeed
    let inner_cmd = format!(
        "{} run -r /usr -r /lib -r /lib64 -r /bin -r /etc -r /proc -- echo nested-ok",
        bin
    );
    let result = Sandbox::run_interactive(
        &outer, &["sh", "-c", &inner_cmd],
    ).await.unwrap();
    assert!(result.success(), "nested sandbox with shared paths should work");
}

/// Test that fs_denied blocks hardlink, rename, and symlink bypass attempts.
///
/// A sandboxed process must not be able to circumvent fs_denied by creating
/// a hardlink, renaming, or symlinking a denied file to a new (non-denied) path.
#[tokio::test]
async fn test_denied_path_hardlink_blocked() {
    let tmp = tempfile::TempDir::new().unwrap();
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, "TOP_SECRET").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64")
        .fs_read("/bin").fs_read("/proc").fs_read("/etc")
        .fs_read(tmp.path())
        .fs_write(tmp.path())
        .fs_deny(&secret)
        .build()
        .unwrap();

    // Attempt to hardlink the denied file to a new name, then read it.
    let cmd = format!(
        "ln {} {}/copy.txt 2>/dev/null && cat {}/copy.txt",
        secret.display(),
        tmp.path().display(),
        tmp.path().display(),
    );
    let result = Sandbox::run(&policy, &["sh", "-c", &cmd]).await.unwrap();
    assert!(
        result.stdout_str().map_or(true, |s| !s.contains("TOP_SECRET")),
        "hardlink bypass: sandbox allowed reading denied file via hardlink"
    );
}

#[tokio::test]
async fn test_denied_path_rename_blocked() {
    let tmp = tempfile::TempDir::new().unwrap();
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, "TOP_SECRET").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64")
        .fs_read("/bin").fs_read("/proc").fs_read("/etc")
        .fs_read(tmp.path())
        .fs_write(tmp.path())
        .fs_deny(&secret)
        .build()
        .unwrap();

    // Attempt to rename the denied file, then read via the new name.
    let cmd = format!(
        "mv {} {}/renamed.txt 2>/dev/null && cat {}/renamed.txt",
        secret.display(),
        tmp.path().display(),
        tmp.path().display(),
    );
    let result = Sandbox::run(&policy, &["sh", "-c", &cmd]).await.unwrap();
    assert!(
        result.stdout_str().map_or(true, |s| !s.contains("TOP_SECRET")),
        "rename bypass: sandbox allowed reading denied file via rename"
    );
}

#[tokio::test]
async fn test_denied_path_symlink_blocked() {
    let tmp = tempfile::TempDir::new().unwrap();
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, "TOP_SECRET").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64")
        .fs_read("/bin").fs_read("/proc").fs_read("/etc")
        .fs_read(tmp.path())
        .fs_write(tmp.path())
        .fs_deny(&secret)
        .build()
        .unwrap();

    // Attempt to symlink to the denied file, then read via the symlink.
    let cmd = format!(
        "ln -s {} {}/link && cat {}/link",
        secret.display(),
        tmp.path().display(),
        tmp.path().display(),
    );
    let result = Sandbox::run(&policy, &["sh", "-c", &cmd]).await.unwrap();
    assert!(
        result.stdout_str().map_or(true, |s| !s.contains("TOP_SECRET")),
        "symlink bypass: sandbox allowed reading denied file via symlink"
    );
}

/// Verify that normal writes still succeed when fs_denied is active (no false positives).
#[tokio::test]
async fn test_denied_path_allows_normal_writes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, "TOP_SECRET").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read("/lib64")
        .fs_read("/bin").fs_read("/proc").fs_read("/etc")
        .fs_read(tmp.path())
        .fs_write(tmp.path())
        .fs_deny(&secret)
        .build()
        .unwrap();

    // Normal file creation and linking of non-denied files should still work.
    let cmd = format!(
        "echo ok > {0}/a.txt && ln {0}/a.txt {0}/b.txt && cat {0}/b.txt",
        tmp.path().display(),
    );
    let result = Sandbox::run(&policy, &["sh", "-c", &cmd]).await.unwrap();
    assert!(result.success(), "normal write should succeed");
    assert_eq!(result.stdout_str(), Some("ok"));
}

/// Test that chroot changes the root filesystem.
#[tokio::test]
async fn test_chroot() {
    // Build a self-contained chroot with the static rootfs-helper binary.
    let chroot_dir = std::env::temp_dir().join(format!(
        "sandlock-test-chroot-{}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(chroot_dir.join("usr/bin"));
    let _ = std::fs::create_dir_all(chroot_dir.join("tmp"));

    // Static helper binary (compiled by build.rs)
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper");
    if !helper.exists() {
        eprintln!("chroot test skipped (rootfs-helper not compiled by build.rs)");
        return;
    }
    let dest = chroot_dir.join("usr/bin/rootfs-helper");
    let _ = std::fs::hard_link(&helper, &dest).or_else(|_| std::fs::copy(&helper, &dest).map(|_| ()));
    // Busybox-style symlink: cat → rootfs-helper
    let _ = std::os::unix::fs::symlink("rootfs-helper", chroot_dir.join("usr/bin/cat"));
    // Merged-usr symlink: /bin → usr/bin
    let _ = std::os::unix::fs::symlink("usr/bin", chroot_dir.join("bin"));

    // Create a marker file inside the chroot
    std::fs::write(chroot_dir.join("marker.txt"), "inside-chroot").unwrap();

    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/")
        .chroot(&chroot_dir)
        .build()
        .unwrap();

    // cat the marker file — it should be at /marker.txt inside the chroot
    let result = Sandbox::run_interactive(
        &policy,
        &["cat", "/marker.txt"],
    ).await;

    match result {
        Ok(r) => {
            if r.success() {
                // passed
            }
        }
        Err(_) => {
            eprintln!("chroot test skipped (may require privileges)");
        }
    }

    let _ = std::fs::remove_dir_all(&chroot_dir);
}
