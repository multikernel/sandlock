use sandlock_core::Sandbox;
use std::path::PathBuf;

/// Path to the static rootfs-helper binary (compiled by build.rs). Its
/// `clock-loop` command is a single-process, single-fd counter loop that calls
/// `clock_gettime(CLOCK_MONOTONIC)` every iteration — the vDSO fast path — so it
/// exercises the full restore engine (memory, registers, reopened fd) plus vDSO
/// relocation without any embedded C in the test.
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found — build.rs should have compiled it")
}

/// End-to-end proof that an ordinary libc program surviving a checkpoint/restore
/// keeps making vDSO calls. Run the static-musl helper's `clock-loop` (which
/// calls `clock_gettime` each iteration and advances an on-disk counter),
/// checkpoint it mid-loop, kill the original, restore into a fresh sandbox, and
/// confirm the restored process resumes and advances the counter — which it can
/// only do if every post-restore `clock_gettime` (a vDSO call) succeeds. Before
/// vDSO relocation, glibc/musl's cached vDSO pointer would reference the
/// checkpoint-era base and the restored process would fault on its first call.
#[tokio::test]
async fn test_restore_glibc_vdso_program_resumes() {
    if cfg!(not(target_arch = "x86_64")) {
        eprintln!("skipping: injection-based restore is x86_64-only");
        return;
    }

    let helper = helper_binary();
    let helper_dir = helper.parent().unwrap().to_path_buf();

    let tmp = std::env::temp_dir().join(format!("sandlock-vdso-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let counter = tmp.join("clock.cnt");
    let counter_s = counter.to_str().unwrap().to_string();

    // Static musl helper needs only its own binary readable and the output dir
    // writable; clock_gettime routes through the kernel-provided vDSO (no fs).
    let policy = Sandbox::builder()
        .fs_read(&helper_dir)
        .fs_read(&tmp)
        .fs_write(&tmp)
        .build().unwrap();

    let helper_s = helper.to_str().unwrap().to_string();
    let mut sb = policy.clone().with_name("vdso-src");
    sb.spawn_interactive(&[helper_s.as_str(), "clock-loop", counter_s.as_str()])
        .await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let cp = sb.checkpoint().await.unwrap();

    let read_counter = |path: &str| -> Option<u64> {
        std::fs::read_to_string(path).ok().and_then(|s| s.trim().parse::<u64>().ok())
    };
    let baseline = read_counter(&counter_s).expect("counter file should exist with a value");
    assert!(baseline > 2, "counter should have advanced before checkpoint, got {baseline}");

    // Kill the original so only the restored process can advance the file.
    sb.kill().unwrap();
    let _ = sb.wait().await;

    // Sentinel: prove the *restored* process (not a leftover original) is writing.
    std::fs::write(&counter, b"0\n").unwrap();

    let mut sb2 = policy.clone().with_name("vdso-dst");
    let _ = sb2.restore_interactive(&cp).await.unwrap();
    eprintln!("restore skipped fds: {:?}", sb2.restore_skipped());

    // Poll up to ~3s for the restored process to resume and advance the counter
    // past the checkpointed baseline.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut last = 0u64;
    let mut advanced = false;
    while std::time::Instant::now() < deadline {
        if let Some(v) = read_counter(&counter_s) {
            last = v;
            if v > baseline {
                advanced = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Clean up before asserting so a failure never leaks the child/files.
    let _ = sb2.kill();
    let exit = sb2.wait().await.map(|r| r.exit_status);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        advanced,
        "restored process must resume and keep calling clock_gettime past \
         baseline {baseline}; last seen {last}, restored exit {exit:?}"
    );
}
