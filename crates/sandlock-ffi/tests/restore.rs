//! Integration test for the C ABI checkpoint-restore `sandlock_restore_interactive`.
//!
//! Drives the FFI symbols directly (no C compilation step of the bindings;
//! only the freestanding guest program is compiled). Mirrors the core
//! `test_restore_real_program_resumes` proof through the C ABI: checkpoint a
//! running vDSO-free counter program, kill it, restore it into a fresh
//! sandbox handle, and prove the restored process advances the counter.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;

use sandlock_ffi::{
    sandlock_checkpoint_free, sandlock_handle_checkpoint, sandlock_handle_free,
    sandlock_handle_kill, sandlock_handle_pid, sandlock_handle_restore_skipped_fd,
    sandlock_handle_restore_skipped_len, sandlock_handle_restore_skipped_path,
    sandlock_handle_wait, sandlock_result_free, sandlock_restore_interactive,
    sandlock_sandbox_build, sandlock_sandbox_builder_fs_read, sandlock_sandbox_builder_fs_write,
    sandlock_sandbox_builder_new, sandlock_sandbox_free, sandlock_sandbox_t, sandlock_start,
    sandlock_string_free,
};

/// Freestanding x86_64 counter program (no libc, no vDSO); see the core
/// restore test for why the guest must be vDSO-free.
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

fn build_policy(tmp: &str) -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    for p in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev", tmp] {
        let c = CString::new(p).unwrap();
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    let c = CString::new(tmp).unwrap();
    b = unsafe { sandlock_sandbox_builder_fs_write(b, c.as_ptr()) };
    let mut err: c_int = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert_eq!(err, 0, "policy build failed");
    assert!(!policy.is_null());
    policy
}

fn which(prog: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|d| d.join(prog).is_file())
    })
}

fn read_counter(path: &str) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

#[test]
fn restore_interactive_resumes_via_c_abi() {
    if cfg!(not(target_arch = "x86_64")) {
        eprintln!("skipping: injection-based restore is x86_64-only");
        return;
    }
    let cc = if which("cc") {
        "cc"
    } else if which("gcc") {
        "gcc"
    } else {
        eprintln!("skipping: no C compiler (cc/gcc) available");
        return;
    };

    let tmp = std::env::temp_dir().join(format!("sandlock-ffi-restore-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let src = tmp.join("counter.c");
    let bin = tmp.join("counter");
    let counter = tmp.join("counter.cnt");
    let counter_s = counter.to_str().unwrap().to_string();
    std::fs::write(&src, counter_source(&counter_s)).unwrap();
    let build = std::process::Command::new(cc)
        .args(["-static", "-nostdlib", "-no-pie", "-O0", "-o"])
        .arg(&bin)
        .arg(&src)
        .output()
        .unwrap();
    if !build.status.success() {
        eprintln!(
            "skipping: build failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        let _ = std::fs::remove_dir_all(&tmp);
        return;
    }

    let tmp_s = tmp.to_str().unwrap();
    let policy = build_policy(tmp_s);

    // Spawn the counter, let it advance, checkpoint, then kill the original.
    let bin_c = CString::new(bin.to_str().unwrap()).unwrap();
    let av: Vec<*const c_char> = vec![bin_c.as_ptr()];
    let h = unsafe {
        sandlock_ffi::sandlock_create(policy, ptr::null(), av.as_ptr(), av.len() as c_uint)
    };
    assert!(!h.is_null(), "sandlock_create failed");
    assert_eq!(unsafe { sandlock_start(h) }, 0, "sandlock_start failed");
    std::thread::sleep(std::time::Duration::from_millis(400));

    let cp = unsafe { sandlock_handle_checkpoint(h) };
    assert!(!cp.is_null(), "sandlock_handle_checkpoint failed");

    // A handle that was not produced by restore has no skipped fds.
    assert_eq!(unsafe { sandlock_handle_restore_skipped_len(h) }, 0);

    let baseline = read_counter(&counter_s).expect("counter file should exist with a value");
    assert!(baseline > 2, "counter should have advanced, got {baseline}");

    assert_eq!(unsafe { sandlock_handle_kill(h) }, 0);
    let r = unsafe { sandlock_handle_wait(h) };
    if !r.is_null() {
        unsafe { sandlock_result_free(r) };
    }
    unsafe { sandlock_handle_free(h) };

    // Sentinel: only the restored process can advance the file past baseline.
    std::fs::write(&counter, b"0\n").unwrap();

    // Restore into a fresh, fully-sandboxed handle. The handle is the only
    // return value; skipped-fd diagnostics are queried from it afterwards.
    let h2 = unsafe { sandlock_restore_interactive(policy, ptr::null(), cp) };
    assert!(!h2.is_null(), "sandlock_restore_interactive failed");
    assert!(unsafe { sandlock_handle_pid(h2) } > 0);

    let n = unsafe { sandlock_handle_restore_skipped_len(h2) };
    for i in 0..n {
        let fd = unsafe { sandlock_handle_restore_skipped_fd(h2, i) };
        assert!(fd >= 0, "skipped entry {i} must carry a real fd, got {fd}");
        let p = unsafe { sandlock_handle_restore_skipped_path(h2, i) };
        assert!(!p.is_null(), "skipped entry {i} must carry a path");
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string();
        assert!(!s.is_empty());
        eprintln!("restore skipped fd {fd}: {s}");
        unsafe { sandlock_string_free(p) };
    }
    // Out-of-range indices answer with sentinels, not UB.
    assert_eq!(unsafe { sandlock_handle_restore_skipped_fd(h2, n) }, -1);
    assert!(unsafe { sandlock_handle_restore_skipped_path(h2, n) }.is_null());

    // Poll up to ~3s for the restored process to advance past baseline.
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
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Clean up before asserting so a failure never leaks the child/files.
    unsafe {
        sandlock_handle_kill(h2);
        let r2 = sandlock_handle_wait(h2);
        if !r2.is_null() {
            sandlock_result_free(r2);
        }
        sandlock_handle_free(h2);
        sandlock_checkpoint_free(cp);
        sandlock_sandbox_free(policy);
    }
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        advanced,
        "restored process must resume and advance the counter past {baseline}; last seen {last}"
    );
}

#[test]
fn restore_interactive_null_inputs_return_null() {
    let h = unsafe { sandlock_restore_interactive(ptr::null(), ptr::null(), ptr::null()) };
    assert!(h.is_null());
}

#[test]
fn restore_skipped_accessors_tolerate_null_handle() {
    assert_eq!(unsafe { sandlock_handle_restore_skipped_len(ptr::null()) }, 0);
    assert_eq!(unsafe { sandlock_handle_restore_skipped_fd(ptr::null(), 0) }, -1);
    assert!(unsafe { sandlock_handle_restore_skipped_path(ptr::null(), 0) }.is_null());
}
