//! Primitive proof of the execve-stub restore path: restore a trivial
//! single-anon-region "program" via the restore-stub + userfaultfd pager,
//! WITHOUT Landlock. The
//! "program" is a hand-assembled code payload that writes a sentinel byte to an
//! inherited pipe then exits; it lives in an anon region the supervisor pager
//! serves on fault. Success (reading the sentinel) proves: the stub mapped the
//! region, registered uffd, rt_sigreturn'd to the checkpoint rip/rsp, and the
//! pager filled the faulting code page.

use std::os::unix::io::RawFd;
use std::path::PathBuf;

const CTRL_FD: i32 = 3;
const READY_FD: i32 = 4;
const GO_FD: i32 = 5;
const UFFD_SLOT: i32 = 6;

const CODE_ADDR: u64 = 0x4500_0000_0000;
const STACK_ADDR: u64 = 0x4500_0001_0000;
const OUT_FD: i32 = 10; // sentinel pipe write end, inherited by the child
const SENTINEL: u8 = 0x5A;

/// The stub is a core restore component compiled by build.rs into OUT_DIR; its
/// path is handed to us via the RESTORE_STUB_PATH env var (set in build.rs).
fn stub_binary() -> PathBuf {
    PathBuf::from(env!("RESTORE_STUB_PATH"))
}

/// x86_64: write(OUT_FD, &sentinel, 1); exit(0). Sentinel byte is at CODE_ADDR+64.
fn code_payload() -> Vec<u8> {
    // mov edi, OUT_FD ; mov rsi, CODE_ADDR+64 ; mov edx, 1 ; mov eax, 1 ; syscall
    // xor edi, edi ; mov eax, 60 ; syscall
    let mut c = Vec::new();
    c.extend_from_slice(&[0xbf]); c.extend_from_slice(&(OUT_FD as u32).to_le_bytes()); // mov edi, imm32
    c.extend_from_slice(&[0x48, 0xbe]); c.extend_from_slice(&(CODE_ADDR + 64).to_le_bytes()); // mov rsi, imm64
    c.extend_from_slice(&[0xba, 0x01, 0x00, 0x00, 0x00]); // mov edx, 1
    c.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1 (write)
    c.extend_from_slice(&[0x0f, 0x05]);                   // syscall
    c.extend_from_slice(&[0x31, 0xff]);                   // xor edi, edi
    c.extend_from_slice(&[0xb8, 0x3c, 0x00, 0x00, 0x00]); // mov eax, 60 (exit)
    c.extend_from_slice(&[0x0f, 0x05]);                   // syscall
    c
}

/// The two region page images (code + stack) the pager serves, identical to the
/// bytes placed in the blob. Kept in one place so the blob and the pager agree.
fn region_pages() -> [(u64, Vec<u8>); 2] {
    let page = 0x1000usize;
    let mut code_page = vec![0u8; page];
    let payload = code_payload();
    code_page[..payload.len()].copy_from_slice(&payload);
    code_page[64] = SENTINEL;
    let stack_page = vec![0u8; page];
    [(CODE_ADDR, code_page), (STACK_ADDR, stack_page)]
}

/// Build the control blob (mirrors restore_blob.rs layout) for the trivial image:
/// one RWX anon region at CODE_ADDR (page) containing the code payload + sentinel,
/// plus a stack region at STACK_ADDR; regs.rip=CODE_ADDR, regs.rsp=STACK_ADDR+0xF00.
fn build_blob() -> Vec<u8> {
    let page = 0x1000usize;
    let pages = region_pages();

    // 27-entry user_regs_struct; only rip/rsp/eflags/cs/ss matter here.
    let mut regs = vec![0u64; 27];
    regs[16] = CODE_ADDR;              // rip
    regs[19] = STACK_ADDR + 0xF00;     // rsp
    regs[18] = 0x202;                  // eflags (IF set)
    regs[17] = 0x33;                   // cs (user 64-bit)
    regs[20] = 0x2b;                   // ss (user data)

    let regions = [
        (CODE_ADDR, CODE_ADDR + page as u64, pages[0].1.clone()),
        (STACK_ADDR, STACK_ADDR + page as u64, pages[1].1.clone()),
    ];

    const HEADER_LEN: usize = 40;
    const REGION_ENTRY_LEN: usize = 40;
    let region_table_len = regions.len() * REGION_ENTRY_LEN;
    let regs_off = HEADER_LEN + region_table_len;
    let anon_data_off = regs_off + regs.len() * 8;

    let mut out = Vec::new();
    out.extend_from_slice(&0x534c_5242u32.to_le_bytes()); // magic
    out.extend_from_slice(&1u32.to_le_bytes());           // version
    out.extend_from_slice(&(regions.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());           // n_fds
    out.extend_from_slice(&(regs_off as u64).to_le_bytes());
    out.extend_from_slice(&((regs.len() * 8) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());           // _pad
    out.extend_from_slice(&(anon_data_off as u64).to_le_bytes());

    let mut anon = Vec::new();
    for (start, end, bytes) in &regions {
        let data_off = anon.len() as u64;
        anon.extend_from_slice(bytes);
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&end.to_le_bytes());
        out.extend_from_slice(&(0x7u32).to_le_bytes());   // prot RWX
        out.push(0u8);                                    // src=anon
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&0u64.to_le_bytes());       // file_off
        out.extend_from_slice(&data_off.to_le_bytes());
    }
    for r in &regs { out.extend_from_slice(&r.to_le_bytes()); }
    out.extend_from_slice(&anon);
    out
}

fn eventfd() -> RawFd {
    let fd = unsafe { libc::eventfd(0, 0) };
    assert!(fd >= 0, "eventfd");
    fd
}

fn memfd_with(bytes: &[u8]) -> RawFd {
    let name = b"restore-blob\0";
    let fd = unsafe { libc::memfd_create(name.as_ptr() as *const libc::c_char, 0) } as i32;
    assert!(fd >= 0, "memfd_create");
    let mut off = 0usize;
    while off < bytes.len() {
        let n = unsafe {
            libc::write(fd, bytes[off..].as_ptr() as *const libc::c_void, bytes.len() - off)
        };
        assert!(n > 0, "write blob");
        off += n as usize;
    }
    fd
}

#[test]
fn restore_stub_trivial_image_runs() {
    if cfg!(not(target_arch = "x86_64")) { eprintln!("skip: x86_64 only"); return; }
    let stub = stub_binary();
    // Skip gracefully (like the other cc-dependent tests) if build.rs could not
    // compile the stub, e.g. no C compiler on the host.
    if !stub.exists() {
        eprintln!("skip: restore-stub not built ({})", stub.display());
        return;
    }
    // Build the execve path BEFORE fork: CString::new allocates, and allocating
    // between fork() and execve() in a multithreaded process (the test harness)
    // can deadlock on the allocator lock. The child then only calls
    // async-signal-safe dup2/execve. The pointers stay valid across fork.
    let stub_path = std::ffi::CString::new(stub.to_str().unwrap()).unwrap();

    let blob = build_blob();
    let ctrl = memfd_with(&blob);
    let ready = eventfd();
    let go = eventfd();

    // Sentinel pipe: child writes SENTINEL to OUT_FD, parent reads it.
    let mut pipefd = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(pipefd.as_mut_ptr()) }, 0);
    let (pipe_r, pipe_w) = (pipefd[0], pipefd[1]);

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork");
    if child == 0 {
        // Child: place inherited fds at the fixed numbers, clear CLOEXEC, execve.
        // Only async-signal-safe calls here (no allocation): stub_path is
        // already built, and the argv/envp arrays are stack-only pointer arrays.
        unsafe {
            libc::dup2(ctrl, CTRL_FD);
            libc::dup2(ready, READY_FD);
            libc::dup2(go, GO_FD);
            libc::dup2(pipe_w, OUT_FD);
            // Ensure the fixed fds survive execve (dup2 clears CLOEXEC already).
            let argv = [stub_path.as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            libc::execve(stub_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }

    // Parent = supervisor.
    unsafe { libc::close(pipe_w); }
    let childfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) } as i32;
    assert!(childfd >= 0, "pidfd_open");

    // Diagnose a stub that died before READY: report its die(code) exit status.
    let diagnose_dead_child = |child: i32| -> String {
        let mut st = 0i32;
        let r = unsafe { libc::waitpid(child, &mut st, libc::WNOHANG) };
        if r == child {
            if libc::WIFEXITED(st) {
                format!("stub exited with die code {}", libc::WEXITSTATUS(st))
            } else if libc::WIFSIGNALED(st) {
                format!("stub killed by signal {}", libc::WTERMSIG(st))
            } else {
                format!("stub status {st:#x}")
            }
        } else {
            "stub still running (hung before READY)".to_string()
        }
    };

    // Wait (bounded) for the stub's READY (uffd registered). Poll so a stub that
    // dies early cannot hang the test in an unbounded eventfd read.
    let mut rpfd = libc::pollfd { fd: ready, events: libc::POLLIN, revents: 0 };
    let rpn = unsafe { libc::poll(&mut rpfd, 1, 5000) };
    if rpn <= 0 || (rpfd.revents & libc::POLLIN) == 0 {
        let why = diagnose_dead_child(child);
        unsafe { libc::kill(child, libc::SIGKILL); libc::waitpid(child, &mut 0, 0); }
        panic!("stub never signalled READY within 5s: {why}");
    }
    let mut buf = [0u8; 8];
    let n = unsafe { libc::read(ready, buf.as_mut_ptr() as *mut libc::c_void, 8) };
    assert_eq!(n, 8, "stub READY");

    // Acquire the stub's uffd via pidfd_getfd(UFFD_SLOT), start a minimal pager.
    let uffd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, childfd, UFFD_SLOT, 0) } as i32;
    assert!(uffd >= 0, "pidfd_getfd uffd");

    // Minimal inline pager: serve the two region pages from the blob's anon data.
    // The stub created the uffd O_NONBLOCK (poll() on a *blocking* uffd reports
    // POLLERR), so we keep it non-blocking and drive it with poll() + a stop
    // flag. Relying on read() returning EOF once the child's mm is gone is
    // unreliable across kernels; an explicit stop flag terminates the thread
    // deterministically once the parent is done.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let page = 0x1000usize;
    let regions = region_pages();
    let stop = Arc::new(AtomicBool::new(false));

    let uffd_thread = uffd;
    let stop_thread = stop.clone();
    let pager = std::thread::spawn(move || {
        // UFFDIO_COPY ioctl in the parent (which shares the child's registered mm
        // view through the acquired uffd).
        #[repr(C)] struct Copy { dst: u64, src: u64, len: u64, mode: u64, copy: i64 }
        const UFFDIO_COPY: libc::c_ulong = 0xc028_aa03;
        while !stop_thread.load(Ordering::SeqCst) {
            let mut pfd = libc::pollfd { fd: uffd_thread, events: libc::POLLIN, revents: 0 };
            let pn = unsafe { libc::poll(&mut pfd, 1, 20) };
            if pn <= 0 || (pfd.revents & libc::POLLIN) == 0 { continue; }
            let mut msg = [0u8; 32];
            let n = unsafe {
                libc::read(uffd_thread, msg.as_mut_ptr() as *mut libc::c_void, 32) };
            if n <= 0 { continue; } // EAGAIN (non-blocking) or EOF: re-check stop
            if msg[0] != 0x12 { continue; } // UFFD_EVENT_PAGEFAULT
            // struct uffd_msg: 8-byte header, then pagefault { u64 flags; u64
            // address; ... }. The fault address is the SECOND u64 (offset 16),
            // not the third: arg[2]/offset 24 is the ptid.
            let addr = u64::from_le_bytes(msg[16..24].try_into().unwrap());
            let base = addr & !((page as u64) - 1);
            let src = regions.iter().find(|(s, _)| *s == base).map(|(_, b)| b);
            let zero = vec![0u8; page];
            let bytes = src.map(|b| b.as_slice()).unwrap_or(&zero);
            let mut c = Copy { dst: base, src: bytes.as_ptr() as u64,
                               len: page as u64, mode: 0, copy: 0 };
            let r = unsafe { libc::ioctl(uffd_thread, UFFDIO_COPY, &mut c) };
            if r < 0 { break; }
        }
    });

    // Pager is attached and polling (blocked in read); release the stub.
    let one: u64 = 1;
    let w = unsafe { libc::write(go, &one as *const u64 as *const libc::c_void, 8) };
    assert_eq!(w, 8, "GO");

    // Read the sentinel the restored code writes, bounded by a watchdog so a
    // failed restore (child SIGSEGVs / dies via die(code)) cannot hang the test.
    let mut got = [0u8; 1];
    let mut pfd = libc::pollfd { fd: pipe_r, events: libc::POLLIN, revents: 0 };
    let pn = unsafe { libc::poll(&mut pfd, 1, 5000) };
    let n = if pn > 0 && (pfd.revents & libc::POLLIN) != 0 {
        unsafe { libc::read(pipe_r, got.as_mut_ptr() as *mut libc::c_void, 1) }
    } else {
        0 // timeout or hangup: treat as "no sentinel"
    };

    // Reap and clean up. Kill first so a stuck child cannot linger, then the
    // uffd hangs up and the pager's blocking read returns 0 (thread ends).
    unsafe { libc::kill(child, libc::SIGKILL); }
    let mut status = 0i32;
    unsafe { libc::waitpid(child, &mut status, 0); }
    stop.store(true, Ordering::SeqCst);
    let _ = pager.join();
    unsafe {
        libc::close(pipe_r); libc::close(uffd); libc::close(childfd);
        libc::close(ctrl); libc::close(ready); libc::close(go);
    }

    assert_eq!(n, 1, "restored code must write exactly one sentinel byte");
    assert_eq!(got[0], SENTINEL,
        "restored code ran and wrote the sentinel (rt_sigreturn + uffd paging worked)");
}
