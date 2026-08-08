//! Supervisor side of the execve-stub restore.
//!
//! The stub (`checkpoint/restore-stub.c`) rebuilds the address space inside a
//! fresh, already-confined process; this module builds the fds it inherits,
//! drives the READY/GO handshake, and writes the anonymous page contents into
//! it. All of the planning lives in [`crate::checkpoint::restore_blob`].
//!
//! Page contents travel over `process_vm_writev` rather than the userfaultfd
//! pager the design originally sketched. `userfaultfd` is on sandlock's default
//! syscall blocklist and seccomp is one-way, so a stub that created one would
//! have to be granted the syscall permanently, handing every restored sandbox a
//! well-known exploit primitive for the rest of its life. Writing from the
//! supervisor needs no policy change at all, and it fills the working set
//! eagerly, so a restored program cannot stall on a page the pager was not
//! allowed to serve (`UFFD_USER_MODE_ONLY`, the only form available when
//! `vm.unprivileged_userfaultfd` is 0, cannot serve faults taken in kernel mode
//! on behalf of a syscall).

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use crate::checkpoint::{CTRL_FD, GO_FD, READY_FD};
use crate::error::{SandboxRuntimeError, SandlockError};

/// How long to wait for the stub to finish laying out the address space.
const READY_TIMEOUT_MS: i32 = 10_000;

/// The stub reads the sweep table into a fixed buffer (`MAX_SWEEP` in
/// `restore-stub.c`); keep the supervisor's side of that contract explicit
/// rather than overrunning it. A freshly `execve`'d stub has only its own image
/// and its startup stack to shed, so this is far above what a restore produces.
const MAX_SWEEP_ENTRIES: usize = 256;

fn child_err(msg: String) -> SandlockError {
    SandlockError::Runtime(SandboxRuntimeError::Child(msg))
}

/// Path to the freestanding restore-stub binary, compiled by `build.rs`.
pub(crate) fn stub_path() -> PathBuf {
    PathBuf::from(env!("RESTORE_STUB_PATH"))
}

/// The fds the stub inherits, held open in the supervisor for the handshake.
/// Their numbers in the child are fixed by the [`CTRL_FD`]/[`READY_FD`]/
/// [`GO_FD`] convention; `Sandbox`'s `extra_fds` mechanism does the `dup2`.
///
/// READY is an eventfd the stub signals once the address space is laid out. GO
/// is a pipe rather than an eventfd because it carries data back: the count of
/// leftover mappings to unmap, then one `(start, len)` pair each (see
/// [`restore_blob::plan_sweep`]). The supervisor cannot compute that list until
/// the stub has finished mapping, which is exactly what READY announces.
pub(crate) struct StubChannel {
    ctrl: OwnedFd,
    ready: OwnedFd,
    /// Read end, inherited by the stub at [`GO_FD`].
    go_r: OwnedFd,
    /// Write end, kept here.
    go_w: OwnedFd,
}

impl StubChannel {
    /// Build the control-blob memfd, the READY eventfd and the GO pipe, each
    /// relocated clear of the fixed child-side numbers (see [`relocate_above`]).
    pub(crate) fn new(blob: &[u8]) -> io::Result<Self> {
        let ctrl = relocate_above(memfd_with(blob)?, GO_FD + 1)?;
        let ready = relocate_above(eventfd()?, GO_FD + 1)?;
        let mut pipefd = [0i32; 2];
        if unsafe { libc::pipe2(pipefd.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let go_r = relocate_above(pipefd[0], GO_FD + 1)?;
        let go_w = relocate_above(pipefd[1], GO_FD + 1)?;
        Ok(StubChannel { ctrl, ready, go_r, go_w })
    }

    /// The `(child fd, supervisor fd)` pairs for `Sandbox`'s `extra_fds`.
    pub(crate) fn extra_fds(&self) -> Vec<(i32, i32)> {
        use std::os::fd::AsRawFd;
        vec![
            (CTRL_FD, self.ctrl.as_raw_fd()),
            (READY_FD, self.ready.as_raw_fd()),
            (GO_FD, self.go_r.as_raw_fd()),
        ]
    }
}

fn eventfd() -> io::Result<RawFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn memfd_with(bytes: &[u8]) -> io::Result<RawFd> {
    let name = c"sandlock-restore-blob";
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut off = 0usize;
    while off < bytes.len() {
        let n = unsafe {
            libc::write(fd, bytes[off..].as_ptr() as *const libc::c_void, bytes.len() - off)
        };
        if n <= 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        off += n as usize;
    }
    // The stub reads the blob from offset 0.
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// Move `fd` to a number at or above `floor` and take ownership of it.
///
/// Two hazards make this mandatory rather than tidy. `dup2` returns success
/// without clearing `FD_CLOEXEC` when source and target are the same
/// descriptor, so a control fd already sitting on its own child-side number
/// would silently close itself at `execve`. And the child installs the fixed
/// numbers in sequence, so any fd still living on a number that a *later*
/// `dup2` targets is destroyed before it can be used.
fn relocate_above(fd: RawFd, floor: RawFd) -> io::Result<OwnedFd> {
    let hi = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, floor) };
    unsafe { libc::close(fd) };
    if hi < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(hi) })
}

/// Write `bytes` into the stopped-at-READY child at `addr`.
///
/// `process_vm_writev` can come up short on a large transfer, and it honours the
/// target VMA's protections, which is why the stub maps every data-carrying
/// region read/write and narrows it only after GO.
fn write_child_mem(pid: i32, addr: u64, bytes: &[u8]) -> io::Result<()> {
    let mut done = 0usize;
    while done < bytes.len() {
        let chunk = &bytes[done..];
        let local = libc::iovec {
            iov_base: chunk.as_ptr() as *mut libc::c_void,
            iov_len: chunk.len(),
        };
        let remote = libc::iovec {
            iov_base: (addr + done as u64) as *mut libc::c_void,
            iov_len: chunk.len(),
        };
        let n = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("wrote {done} of {} bytes", bytes.len()),
            ));
        }
        done += n as usize;
    }
    Ok(())
}

/// Wait for `fd` to become readable, returning false on timeout.
fn wait_readable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
    loop {
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let n = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis() as i32) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                if std::time::Instant::now() >= deadline {
                    return Ok(false);
                }
                continue;
            }
            return Err(e);
        }
        return Ok(n > 0 && (pfd.revents & libc::POLLIN) != 0);
    }
}

/// Describe how a stub that never reached READY died, for the error message.
/// The stub's exit codes are documented at the top of `restore-stub.c`.
fn diagnose(pid: i32) -> String {
    let mut st = 0i32;
    let r = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
    if r != pid {
        return "still running (hung before READY)".into();
    }
    if libc::WIFEXITED(st) {
        format!("exited with restore-stub code {}", libc::WEXITSTATUS(st))
    } else if libc::WIFSIGNALED(st) {
        format!("killed by signal {}", libc::WTERMSIG(st))
    } else {
        format!("status {st:#x}")
    }
}

fn write_all(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    let mut done = 0usize;
    while done < bytes.len() {
        let n = unsafe {
            libc::write(fd, bytes[done..].as_ptr() as *const libc::c_void, bytes.len() - done)
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        done += n as usize;
    }
    Ok(())
}

/// Complete the restore of a stub that is already running under confinement:
/// wait for it to finish laying out the address space, write the anonymous page
/// contents in, and release it (with the list of leftover mappings to shed) to
/// `rt_sigreturn` into the checkpoint.
///
/// On `Err` the child is left mid-restore and blocked on GO; the caller must
/// kill and reap it.
pub(crate) fn finish_restore(
    pid: i32,
    channel: &StubChannel,
    plan: &crate::checkpoint::restore_blob::RestorePlan,
) -> Result<(), SandlockError> {
    use std::os::fd::AsRawFd;

    let ready = channel.ready.as_raw_fd();
    if !wait_readable(ready, READY_TIMEOUT_MS)
        .map_err(|e| child_err(format!("restore wait for stub READY: {e}")))?
    {
        return Err(child_err(format!(
            "restore stub never signalled READY within {}ms: {}",
            READY_TIMEOUT_MS,
            diagnose(pid)
        )));
    }
    let mut buf = [0u8; 8];
    let n = unsafe { libc::read(ready, buf.as_mut_ptr() as *mut libc::c_void, 8) };
    if n != 8 {
        return Err(child_err(format!(
            "restore read stub READY: {}",
            io::Error::last_os_error()
        )));
    }

    for (start, bytes) in &plan.anon {
        write_child_mem(pid, *start, bytes).map_err(|e| {
            child_err(format!("restore fill region {start:#x} ({} bytes): {e}", bytes.len()))
        })?;
    }

    // The stub has finished mapping, so /proc now shows the final layout plus
    // whatever the kernel left over from its own startup. Diff it against the
    // checkpoint and hand the stub the list to unmap.
    let current = crate::checkpoint::capture::parse_proc_maps(pid)
        .map_err(|e| child_err(format!("restore read stub layout: {e}")))?;
    crate::checkpoint::restore_blob::verify_special_mappings(&current, &plan.maps)
        .map_err(|e| child_err(format!("restore vdso relocation: {e}")))?;
    let sweep = crate::checkpoint::restore_blob::plan_sweep(&current, &plan.maps);
    if sweep.len() > MAX_SWEEP_ENTRIES {
        return Err(child_err(format!(
            "restore sweep list has {} entries, more than the stub accepts ({MAX_SWEEP_ENTRIES})",
            sweep.len()
        )));
    }

    let mut msg = Vec::with_capacity(8 + sweep.len() * 16);
    msg.extend_from_slice(&(sweep.len() as u64).to_le_bytes());
    for (start, len) in &sweep {
        msg.extend_from_slice(&start.to_le_bytes());
        msg.extend_from_slice(&len.to_le_bytes());
    }
    write_all(channel.go_w.as_raw_fd(), &msg)
        .map_err(|e| child_err(format!("restore signal GO: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, IntoRawFd};

    #[test]
    fn channel_fds_land_above_the_fixed_child_numbers() {
        // A control fd allocated at 3/4/5 would be dup2'd onto itself in the
        // child, which leaves FD_CLOEXEC set and closes it at execve.
        let ch = StubChannel::new(b"blob").expect("channel");
        for fd in [ch.ctrl.as_raw_fd(), ch.ready.as_raw_fd(),
                   ch.go_r.as_raw_fd(), ch.go_w.as_raw_fd()] {
            assert!(fd > GO_FD, "fd {fd} must sit above the fixed control fds");
        }
        let mut pairs = ch.extra_fds();
        pairs.sort();
        assert_eq!(
            pairs.iter().map(|&(child, _)| child).collect::<Vec<_>>(),
            vec![CTRL_FD, READY_FD, GO_FD],
        );
    }

    #[test]
    fn control_blob_memfd_reads_back_from_offset_zero() {
        let ch = StubChannel::new(b"hello blob").expect("channel");
        let mut buf = [0u8; 16];
        let n = unsafe {
            libc::read(ch.ctrl.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        assert_eq!(n, 10, "the stub must find the blob at offset 0");
        assert_eq!(&buf[..10], b"hello blob");
    }

    #[test]
    fn write_child_mem_fills_another_process() {
        // Proof that the page-fill primitive reaches a live child's anonymous
        // mapping: the child maps a page, reports where the kernel put it,
        // waits, and reports back what it sees after the parent writes into it.
        //
        // The kernel picks the address and the child sends it over the ready
        // pipe. Naming one here instead would be a bet on the architecture's
        // virtual address layout, and the high addresses that are free on
        // x86_64 do not exist on riscv64, whose Sv39 user space ends at 256 GiB.
        //
        // Two pipes, so neither side keeps the other's EOF from arriving:
        // `ready` carries the child's "mapping is live", `go` releases it.
        let mut ready = [0i32; 2];
        let mut go = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(go.as_mut_ptr()) }, 0);

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork");
        if child == 0 {
            unsafe {
                libc::close(ready[0]);
                libc::close(go[1]);
                let p = libc::mmap(
                    std::ptr::null_mut(), 4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0,
                );
                if p == libc::MAP_FAILED { libc::_exit(1) };
                // Announce the address, then block until the parent hangs up,
                // so the write lands while the mapping is live.
                let addr = p as u64;
                libc::write(ready[1], &addr as *const u64 as *const libc::c_void, 8);
                let mut b = 0u8;
                while libc::read(go[0], &mut b as *mut u8 as *mut libc::c_void, 1) > 0 {}
                libc::_exit(*(p as *const u8) as i32);
            }
        }
        unsafe { libc::close(ready[1]); libc::close(go[0]) };
        let mut addr_buf = [0u8; 8];
        let n = unsafe {
            libc::read(ready[0], addr_buf.as_mut_ptr() as *mut libc::c_void, 8)
        };
        assert_eq!(n, 8, "the child must report where the kernel mapped its page");
        let addr = u64::from_le_bytes(addr_buf);

        let res = write_child_mem(child, addr, &[0x5Au8; 4096]);

        unsafe { libc::close(go[1]); libc::close(ready[0]) };
        let mut st = 0i32;
        unsafe { libc::waitpid(child, &mut st, 0) };

        res.expect("process_vm_writev into the child");
        assert!(libc::WIFEXITED(st), "child exited normally");
        assert_eq!(libc::WEXITSTATUS(st), 0x5A, "the child observed the filled page");
    }

    #[test]
    fn ready_wait_times_out_rather_than_hanging() {
        let ch = StubChannel::new(b"blob").expect("channel");
        assert!(
            !wait_readable(ch.ready.as_raw_fd(), 20).expect("poll"),
            "an unsignalled READY eventfd must report a timeout",
        );
    }

    /// The built stub must load inside the window `restore_blob` reserves for
    /// it. If the two ever drift apart, a restore silently maps a checkpoint
    /// region over the running stub instead of being refused.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
    fn stub_links_at_the_reserved_base() {
        use crate::checkpoint::restore_blob::{STUB_BASE, STUB_SPAN};

        let Ok(elf) = std::fs::read(stub_path()) else {
            eprintln!("skip: restore-stub not built");
            return;
        };
        // ELF64 program headers: e_phoff@32, e_phentsize@54, e_phnum@56.
        // Each PT_LOAD entry: p_type@0, p_vaddr@16, p_memsz@40.
        let phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
        let phentsize = u16::from_le_bytes(elf[54..56].try_into().unwrap()) as usize;
        let phnum = u16::from_le_bytes(elf[56..58].try_into().unwrap()) as usize;

        let mut loads = 0;
        for i in 0..phnum {
            let ph = &elf[phoff + i * phentsize..phoff + (i + 1) * phentsize];
            if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != 1 {
                continue; // not PT_LOAD
            }
            loads += 1;
            let vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap());
            let memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());
            assert!(
                vaddr >= STUB_BASE && vaddr + memsz <= STUB_BASE + STUB_SPAN,
                "stub segment {vaddr:#x}+{memsz:#x} escapes the reserved window \
                 {STUB_BASE:#x}-{:#x}; build.rs and restore_blob::STUB_BASE disagree",
                STUB_BASE + STUB_SPAN,
            );
        }
        assert!(loads > 0, "stub has no PT_LOAD segments");
    }

    /// End-to-end proof that the serializer and the stub agree: build a real
    /// control blob for a hand-assembled one-page "program", exec the stub with
    /// the inherited fds, drive the handshake, and read the sentinel byte the
    /// restored code writes. Success means the stub parsed the v2 blob, mapped
    /// both regions, took the supervisor's page fill, narrowed the code page
    /// back to r-x, and `rt_sigreturn`ed to the checkpoint's rip/rsp.
    ///
    /// Deliberately unconfined (no Landlock, no seccomp): this isolates the
    /// stub protocol. `test_restore.rs` covers a real libc program under the
    /// full policy.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn restore_stub_reconstructs_a_synthetic_image() {
        use crate::checkpoint::{Checkpoint, MemoryMap, MemorySegment, ProcessState};
        use crate::checkpoint::restore_blob;

        const CODE: u64 = 0x4500_0000_0000;
        const STACK: u64 = 0x4500_0001_0000;
        const OUT_FD: i32 = 10; // sentinel pipe write end, inherited by the child
        const SENTINEL: u8 = 0x5A;
        const PAGE: u64 = 0x1000;

        let stub = stub_path();
        if !stub.exists() {
            eprintln!("skip: restore-stub not built ({})", stub.display());
            return;
        }

        // write(OUT_FD, CODE+64, 1); exit(result). The sentinel byte lives at
        // CODE+64, and exiting with write's return value turns a silent failure
        // into a readable status: 1 on success, 256-errno on failure.
        let mut code_page = vec![0u8; PAGE as usize];
        {
            let c = &mut code_page;
            let mut w = 0usize;
            let mut put = |bytes: &[u8]| { c[w..w + bytes.len()].copy_from_slice(bytes); w += bytes.len(); };
            put(&[0xbf]); put(&(OUT_FD as u32).to_le_bytes());     // mov edi, OUT_FD
            put(&[0x48, 0xbe]); put(&(CODE + 64).to_le_bytes());   // mov rsi, CODE+64
            put(&[0xba, 0x01, 0x00, 0x00, 0x00]);                  // mov edx, 1
            put(&[0xb8, 0x01, 0x00, 0x00, 0x00]);                  // mov eax, 1 (write)
            put(&[0x0f, 0x05]);                                    // syscall
            put(&[0x89, 0xc7]);                                    // mov edi, eax
            put(&[0xb8, 0x3c, 0x00, 0x00, 0x00]);                  // mov eax, 60 (exit)
            put(&[0x0f, 0x05]);                                    // syscall
        }
        code_page[64] = SENTINEL;

        let mut regs = vec![0u64; 27];
        regs[16] = CODE;          // rip
        regs[17] = 0x33;          // cs (user 64-bit)
        regs[18] = 0x202;         // eflags (IF set)
        regs[19] = STACK + 0xF00; // rsp
        regs[20] = 0x2b;          // ss (user data)

        // The code page is r-x in the checkpoint, so the stub has to map it
        // writable for the fill and mprotect it back before handing control over.
        let cp = Checkpoint {
            name: String::new(),
            policy: crate::Sandbox::builder().build().unwrap(),
            process_state: ProcessState {
                pid: 0,
                cwd: "/".into(),
                exe: String::new(),
                regs,
                fpregs: Vec::new(),
                memory_maps: vec![
                    MemoryMap { start: CODE, end: CODE + PAGE, perms: "r-xp".into(), offset: 0, path: None },
                    MemoryMap { start: STACK, end: STACK + PAGE, perms: "rw-p".into(), offset: 0, path: None },
                ],
                memory_data: vec![
                    MemorySegment { start: CODE, data: code_page },
                    MemorySegment { start: STACK, data: vec![0u8; PAGE as usize] },
                ],
            },
            fd_table: Vec::new(),
            cow_snapshot: None,
            app_state: None,
        };

        let plan = restore_blob::plan(&cp, None, &[]).expect("plan");
        let channel = StubChannel::new(&plan.blob).expect("channel");

        // Build the exec path before fork: CString::new allocates, and
        // allocating between fork() and execve() in a multithreaded process (the
        // test harness) can deadlock on the allocator lock.
        let stub_path = std::ffi::CString::new(stub.to_str().unwrap()).unwrap();

        // Relocate the sentinel pipe clear of every fixed number the child
        // installs, OUT_FD included. Left at 3/4 (which is exactly where the
        // kernel puts them, since the channel fds were moved up) the child's
        // own `dup2` sequence would destroy the pipe before using it.
        let mut pipefd = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipefd.as_mut_ptr()) }, 0);
        let pipe_r = relocate_above(pipefd[0], OUT_FD + 1).expect("relocate pipe read end");
        let pipe_w = relocate_above(pipefd[1], OUT_FD + 1).expect("relocate pipe write end");
        let (pipe_r, pipe_w) = (pipe_r.into_raw_fd(), pipe_w.into_raw_fd());

        let (ctrl, ready, go) =
            (channel.ctrl.as_raw_fd(), channel.ready.as_raw_fd(), channel.go_r.as_raw_fd());
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork");
        if child == 0 {
            // Only async-signal-safe calls here: dup2 clears CLOEXEC, so the
            // fixed fds survive execve.
            unsafe {
                libc::dup2(ctrl, CTRL_FD);
                libc::dup2(ready, READY_FD);
                libc::dup2(go, GO_FD);
                libc::dup2(pipe_w, OUT_FD);
                let argv = [stub_path.as_ptr(), std::ptr::null()];
                let envp = [std::ptr::null()];
                libc::execve(stub_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        unsafe { libc::close(pipe_w) };

        let restored = finish_restore(child, &channel, &plan);

        // Read the sentinel the restored code writes, bounded so a failed
        // restore cannot hang the test.
        let mut got = [0u8; 1];
        let n = if restored.is_ok() && wait_readable(pipe_r, 5000).unwrap_or(false) {
            unsafe { libc::read(pipe_r, got.as_mut_ptr() as *mut libc::c_void, 1) }
        } else {
            0
        };
        // A stub that never reached the payload is wedged in a syscall; a
        // payload that ran but could not write reports the errno as its status.
        let stalled_in = std::fs::read_to_string(format!("/proc/{child}/syscall"))
            .unwrap_or_else(|e| e.to_string());
        // Clean up before asserting so a failure never leaks the child.
        unsafe { libc::kill(child, libc::SIGKILL) };
        let mut st = 0i32;
        unsafe { libc::waitpid(child, &mut st, 0) };
        unsafe { libc::close(pipe_r) };

        restored.expect("finish_restore");
        assert_eq!(
            n, 1,
            "restored code must write exactly one sentinel byte; child exit status \
             {st:#x} (payload exits with write()'s return value), /proc syscall {stalled_in}",
        );
        assert_eq!(got[0], SENTINEL, "the restored program ran from its checkpoint rip");
    }

    /// End-to-end proof for riscv64: same protocol as the x86_64 test above,
    /// but with riscv64 machine code (a7+ecall convention), a 32-register file,
    /// and addresses within the Sv39 256 GiB user-space ceiling.
    #[test]
    #[cfg(target_arch = "riscv64")]
    fn restore_stub_reconstructs_a_synthetic_image() {
        use crate::checkpoint::{Checkpoint, MemoryMap, MemorySegment, ProcessState};
        use crate::checkpoint::restore_blob;

        // riscv64 Sv39 gives 256 GiB of user virtual space, so the addresses
        // must stay below 0x40_0000_0000.  Pick a region that stays clear of
        // the stub (0x30_0000_0000) and the vDSO (near the top).
        const CODE: u64 = 0x2000_0000;
        const STACK: u64 = 0x2001_0000;
        const OUT_FD: i32 = 10; // sentinel pipe write end, inherited by the child
        const SENTINEL: u8 = 0x5A;
        const PAGE: u64 = 0x1000;

        let stub = stub_path();
        if !stub.exists() {
            eprintln!("skip: restore-stub not built ({})", stub.display());
            return;
        }

        // riscv64: write(OUT_FD, CODE+64, 1); exit(write-retval).
        //
        //   addi a0, zero, OUT_FD    # a0 = fd
        //   lui  a1, 0x20000         # upper 20 bits of CODE+64
        //   addi a1, a1, 0x040       # lower 12 bits of CODE+64
        //   addi a2, zero, 1         # count
        //   addi a7, zero, 64        # __NR_write
        //   ecall
        //   addi a7, zero, 93        # __NR_exit  (a0 still holds write's ret)
        //   ecall
        let mut code_page = vec![0u8; PAGE as usize];
        {
            let c = &mut code_page;
            let mut w = 0usize;
            let mut put = |bytes: &[u8]| { c[w..w + bytes.len()].copy_from_slice(bytes); w += bytes.len(); };
            put(&0x00A00513u32.to_le_bytes()); // addi a0, zero, 10
            put(&0x200005B7u32.to_le_bytes()); // lui  a1, 0x20000
            put(&0x04058593u32.to_le_bytes()); // addi a1, a1, 0x40
            put(&0x00100613u32.to_le_bytes()); // addi a2, zero, 1
            put(&0x04000893u32.to_le_bytes()); // addi a7, zero, 64
            put(&0x00000073u32.to_le_bytes()); // ecall
            put(&0x05D00893u32.to_le_bytes()); // addi a7, zero, 93
            put(&0x00000073u32.to_le_bytes()); // ecall
        }
        code_page[64] = SENTINEL;

        // riscv64 user_regs_struct: 32 × u64.
        // Index 0=pc, 2=sp; all others zero.
        let mut regs = vec![0u64; 32];
        regs[0] = CODE;                 // pc
        regs[2] = STACK + 0xF00;        // sp

        // The code page is r-x in the checkpoint, so the stub has to map it
        // writable for the fill and mprotect it back before handing control over.
        let cp = Checkpoint {
            name: String::new(),
            policy: crate::Sandbox::builder().build().unwrap(),
            process_state: ProcessState {
                pid: 0,
                cwd: "/".into(),
                exe: String::new(),
                regs,
                fpregs: Vec::new(),
                memory_maps: vec![
                    MemoryMap { start: CODE, end: CODE + PAGE, perms: "r-xp".into(), offset: 0, path: None },
                    MemoryMap { start: STACK, end: STACK + PAGE, perms: "rw-p".into(), offset: 0, path: None },
                ],
                memory_data: vec![
                    MemorySegment { start: CODE, data: code_page },
                    MemorySegment { start: STACK, data: vec![0u8; PAGE as usize] },
                ],
            },
            fd_table: Vec::new(),
            cow_snapshot: None,
            app_state: None,
        };

        let plan = restore_blob::plan(&cp, None, &[]).expect("plan");
        let channel = StubChannel::new(&plan.blob).expect("channel");

        let stub_path = std::ffi::CString::new(stub.to_str().unwrap()).unwrap();

        let mut pipefd = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipefd.as_mut_ptr()) }, 0);
        let pipe_r = relocate_above(pipefd[0], OUT_FD + 1).expect("relocate pipe read end");
        let pipe_w = relocate_above(pipefd[1], OUT_FD + 1).expect("relocate pipe write end");
        let (pipe_r, pipe_w) = (pipe_r.into_raw_fd(), pipe_w.into_raw_fd());

        let (ctrl, ready, go) =
            (channel.ctrl.as_raw_fd(), channel.ready.as_raw_fd(), channel.go_r.as_raw_fd());
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork");
        if child == 0 {
            unsafe {
                libc::dup2(ctrl, CTRL_FD);
                libc::dup2(ready, READY_FD);
                libc::dup2(go, GO_FD);
                libc::dup2(pipe_w, OUT_FD);
                let argv = [stub_path.as_ptr(), std::ptr::null()];
                let envp = [std::ptr::null()];
                libc::execve(stub_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        unsafe { libc::close(pipe_w) };

        let restored = finish_restore(child, &channel, &plan);

        let mut got = [0u8; 1];
        let n = if restored.is_ok() && wait_readable(pipe_r, 5000).unwrap_or(false) {
            unsafe { libc::read(pipe_r, got.as_mut_ptr() as *mut libc::c_void, 1) }
        } else {
            0
        };
        let stalled_in = std::fs::read_to_string(format!("/proc/{child}/syscall"))
            .unwrap_or_else(|e| e.to_string());
        unsafe { libc::kill(child, libc::SIGKILL) };
        let mut st = 0i32;
        unsafe { libc::waitpid(child, &mut st, 0) };
        unsafe { libc::close(pipe_r) };

        restored.expect("finish_restore");
        assert_eq!(
            n, 1,
            "restored code must write exactly one sentinel byte; child exit status \
             {st:#x} (payload exits with write()'s return value), /proc syscall {stalled_in}",
        );
        assert_eq!(got[0], SENTINEL, "the restored program ran from its checkpoint pc");
    }
}
