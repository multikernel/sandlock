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

/// The address range the restore-stub's own image is linked into. Must match
/// `checkpoint::restore_blob::STUB_BASE`/`STUB_SPAN`, which is crate-private;
/// `stub_links_at_the_reserved_base` guards the constant against the binary.
/// x86_64 uses 3 TiB; riscv64 uses 192 GiB (below Sv39 ceiling).
#[cfg(target_arch = "x86_64")]
const STUB_BASE: u64 = 0x300_0000_0000;
#[cfg(target_arch = "riscv64")]
const STUB_BASE: u64 = 0x30_0000_0000;
#[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
const STUB_BASE: u64 = 0;
const STUB_SPAN: u64 = 0x40_0000;

/// Parse `/proc/<pid>/maps` into `(start, end, path)` triples.
fn read_maps(pid: i32) -> Vec<(u64, u64, String)> {
    std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(6, ' ');
            let (lo, hi) = parts.next()?.split_once('-')?;
            let path = parts.nth(4).unwrap_or("").trim().to_string();
            Some((
                u64::from_str_radix(lo, 16).ok()?,
                u64::from_str_radix(hi, 16).ok()?,
                path,
            ))
        })
        .collect()
}

/// End-to-end proof that an ordinary libc program surviving a checkpoint/restore
/// keeps making vDSO calls. Run the static-musl helper's `clock-loop` (which
/// calls `clock_gettime` each iteration and advances an on-disk counter),
/// checkpoint it mid-loop, kill the original, restore into a fresh sandbox, and
/// confirm the restored process resumes and advances the counter — which it can
/// only do if every post-restore `clock_gettime` (a vDSO call) succeeds. Before
/// vDSO relocation, glibc/musl's cached vDSO pointer would reference the
/// checkpoint-era base and the restored process would fault on its first call.
///
/// Also asserts the restored address space is *clean*: nothing is mapped that
/// the checkpoint did not record, beyond the kernel's own special mappings and
/// the restore-stub's reserved window. That is the property the execve stub
/// exists for. The ptrace-injection engine it replaced could not hold it — it
/// rebuilt the image on top of a parked libc launcher, whose leftover text,
/// stack and heap stayed mapped and reachable.
#[tokio::test]
async fn test_restore_glibc_vdso_program_resumes() {
    if cfg!(not(any(target_arch = "x86_64", target_arch = "riscv64"))) {
        eprintln!("skipping: the restore engine is x86_64/riscv64 only");
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

    // Read the restored layout while the process is still alive.
    let restored_maps = sb2.pid().map(read_maps).unwrap_or_default();

    // Clean up before asserting so a failure never leaks the child/files.
    let _ = sb2.kill();
    let exit = sb2.wait().await.map(|r| r.exit_status);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        advanced,
        "restored process must resume and keep calling clock_gettime past \
         baseline {baseline}; last seen {last}, restored exit {exit:?}"
    );

    // Compare by address coverage, not by identity: the kernel merges and
    // splits adjacent mappings, so a restored VMA legitimately spans several
    // recorded ones. What must not happen is a *byte* being mapped that the
    // checkpoint never recorded.
    assert!(!restored_maps.is_empty(), "could not read the restored layout");
    let mut allowed: Vec<(u64, u64)> = cp
        .process_state
        .memory_maps
        .iter()
        .map(|m| (m.start, m.end))
        .chain(std::iter::once((STUB_BASE, STUB_BASE + STUB_SPAN)))
        .collect();
    allowed.sort_unstable();
    let mut covered: Vec<(u64, u64)> = Vec::new();
    for (lo, hi) in allowed {
        match covered.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => covered.push((lo, hi)),
        }
    }
    let mut strays = Vec::new();
    for (start, end, path) in &restored_maps {
        // The kernel always provides these; they are not checkpoint state.
        if matches!(path.as_str(), "[vdso]" | "[vvar]" | "[vvar_vclock]" | "[vsyscall]") {
            continue;
        }
        if !covered.iter().any(|&(lo, hi)| *start >= lo && *end <= hi) {
            strays.push(format!("{start:#x}-{end:#x} {path}"));
        }
    }
    assert!(
        strays.is_empty(),
        "restored address space must hold only the checkpoint image, the kernel's \
         special mappings and the stub's reserved window; found {} stray mapping(s): {strays:#?}",
        strays.len(),
    );
}
