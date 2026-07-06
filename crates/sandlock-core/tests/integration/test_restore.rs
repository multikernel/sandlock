use sandlock_core::Sandbox;

/// Freestanding x86_64 program (no libc, no vDSO; raw syscalls only) that opens
/// an output file ONCE, then loops forever incrementing a counter and writing
/// it through that same kept-open fd, sleeping via `nanosleep` between writes.
///
/// It is deliberately libc/vDSO-free: glibc caches vDSO function pointers in
/// process memory, and the injection-based restore engine does not relocate the
/// kernel vDSO, so a libc program (python, sh) resumes but crashes on its first
/// vDSO call (e.g. clock_gettime). A raw-syscall program avoids that and lets
/// the test prove the restore engine itself: memory (the loop counter),
/// registers (resumed mid-`nanosleep`), and the reopened open fd.
fn counter_source(out_path: &str) -> String {
    format!(
        r##"
#define SYS_write 1
#define SYS_open 2
#define SYS_nanosleep 35
#define SYS_lseek 8
#define SYS_ftruncate 77
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
static long sys3(long n, long a, long b, long c){{
  long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory"); return r;
}}
struct ts {{ long sec; long nsec; }};
void _start(void){{
  const char *path = "{out_path}";
  long fd = sys3(SYS_open, (long)path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
  unsigned long i = 0;
  char buf[24];
  struct ts t; t.sec = 0; t.nsec = 20000000;
  for(;;){{
    i++;
    int p = 0; unsigned long v = i; char tmp[24]; int k=0;
    if(v==0){{ tmp[k++]='0'; }} while(v){{ tmp[k++]='0'+(v%10); v/=10; }}
    while(k>0){{ buf[p++]=tmp[--k]; }} buf[p++]='\n';
    sys3(SYS_lseek, fd, 0, 0);
    sys3(SYS_ftruncate, fd, 0, 0);
    sys3(SYS_write, fd, (long)buf, p);
    sys3(SYS_nanosleep, (long)&t, 0, 0);
  }}
}}
"##
    )
}

/// End-to-end proof of transparent restore of a real program into a fresh,
/// fully-sandboxed process. Checkpoint the running counter program, kill the
/// original, then `restore_interactive` a fresh sandbox from the checkpoint and
/// prove the restored process resumes mid-loop and keeps advancing the counter,
/// all under the live Landlock + seccomp policy.
#[tokio::test]
async fn test_restore_real_program_resumes() {
    if cfg!(not(target_arch = "x86_64")) {
        eprintln!("skipping: injection-based restore is x86_64-only");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("sandlock-restore-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let src = tmp.join("counter.c");
    let bin = tmp.join("counter");
    let counter = tmp.join("counter.cnt");
    let counter_s = counter.to_str().unwrap().to_string();

    std::fs::write(&src, counter_source(&counter_s)).unwrap();

    // Build the freestanding binary; skip the test gracefully if no C compiler.
    let cc = if which("cc") { "cc" } else if which("gcc") { "gcc" } else {
        eprintln!("skipping: no C compiler (cc/gcc) available");
        let _ = std::fs::remove_dir_all(&tmp);
        return;
    };
    let build = std::process::Command::new(cc)
        .args(["-static", "-nostdlib", "-no-pie", "-O0", "-o"])
        .arg(&bin).arg(&src)
        .output().unwrap();
    if !build.status.success() {
        eprintln!("skipping: build failed: {}", String::from_utf8_lossy(&build.stderr));
        let _ = std::fs::remove_dir_all(&tmp);
        return;
    }

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin").fs_read("/etc")
        .fs_read("/proc")
        .fs_read(&tmp)            // the binary lives here (exec needs read)
        .fs_write(&tmp)          // ... and so does its output file
        .build().unwrap();

    let bin_s = bin.to_str().unwrap().to_string();
    let mut sb = policy.clone().with_name("restore-src");
    sb.spawn_interactive(&[bin_s.as_str()]).await.unwrap();

    // Let it run so the counter is well past a few.
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

    // Restore into a fresh, fully-sandboxed process. The returned Process is
    // the handle; the sandbox owns the child, so dropping it here is fine.
    let mut sb2 = policy.clone().with_name("restore-dst");
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
        "restored process must resume mid-loop and advance the counter past {baseline}; \
         last seen {last}, restored exit {exit:?}"
    );
}

/// Minimal PATH lookup so the test does not depend on extra crates.
fn which(prog: &str) -> bool {
    std::env::var_os("PATH").map_or(false, |paths| {
        std::env::split_paths(&paths).any(|d| d.join(prog).is_file())
    })
}
