use std::io;

use crate::checkpoint::MemoryMap;

#[cfg(target_arch = "x86_64")]
use std::os::raw::c_void;

// ---------------------------------------------------------------------------
// Raw ptrace helpers
// ---------------------------------------------------------------------------

/// PTRACE_PEEKTEXT reads the word at `addr` and returns it as the ptrace
/// return value. A legitimately-read word may be 0xFFFF...FF, which is
/// indistinguishable from the -1 error sentinel by value alone, so the
/// errno-cleared-first convention is mandatory: clear errno, peek, then on a
/// -1 return check errno to decide whether it was a real error.
#[cfg(target_arch = "x86_64")]
fn ptrace_peektext(pid: i32, addr: u64) -> io::Result<u64> {
    unsafe {
        *libc::__errno_location() = 0;
        let word = libc::ptrace(
            libc::PTRACE_PEEKTEXT,
            pid,
            addr as *mut c_void,
            std::ptr::null_mut::<c_void>(),
        );
        if word == -1 {
            let errno = *libc::__errno_location();
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno));
            }
        }
        Ok(word as u64)
    }
}

#[cfg(target_arch = "x86_64")]
fn ptrace_poketext(pid: i32, addr: u64, data: u64) -> io::Result<()> {
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_POKETEXT,
            pid,
            addr as *mut c_void,
            data as *mut c_void,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn ptrace_getregs(pid: i32) -> io::Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut::<c_void>(),
            &mut regs as *mut libc::user_regs_struct as *mut c_void,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(regs)
}

#[cfg(target_arch = "x86_64")]
fn ptrace_setregs(pid: i32, regs: &libc::user_regs_struct) -> io::Result<()> {
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid,
            std::ptr::null_mut::<c_void>(),
            regs as *const libc::user_regs_struct as *mut c_void,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn ptrace_singlestep(pid: i32) -> io::Result<()> {
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SINGLESTEP,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Execute one syscall in a ptrace-stopped child via register/text injection,
/// returning the raw syscall result (negative = -errno). The child must already
/// be ptrace-stopped at a valid executable rip. After return, the child's
/// registers and the text at rip are restored to their pre-call state, so this
/// may be called repeatedly. x86_64 only.
// used by the restore path (added in a later change)
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn inject_syscall(pid: i32, nr: u64, args: [u64; 6]) -> io::Result<i64> {
    // Save the pristine registers and the original instruction word at rip so
    // the child can be returned to its exact pre-call state afterwards.
    let saved_regs = ptrace_getregs(pid)?;
    let rip = saved_regs.rip;
    let orig_word = ptrace_peektext(pid, rip)?;

    // Plant the `syscall` instruction (0f 05) into the low two bytes of the
    // word at rip, leaving the rest of the word intact.
    let planted = (orig_word & !0xffffu64) | 0x050fu64;

    // Run the call inside a closure so that, regardless of where a middle step
    // fails, we always attempt to restore the text word and registers before
    // returning. A half-modified child is worse than a clean error.
    let result = (|| -> io::Result<i64> {
        ptrace_poketext(pid, rip, planted)?;

        let mut regs = saved_regs;
        regs.rax = nr;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        regs.rip = rip; // execute the planted `syscall`
        ptrace_setregs(pid, &regs)?;

        ptrace_singlestep(pid)?;
        let mut status: i32 = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w < 0 {
            return Err(io::Error::last_os_error());
        }

        // WIFSTOPPED: low byte == 0x7f. WSTOPSIG: (status >> 8) & 0xff.
        let stopped = (status & 0xff) == 0x7f;
        let stopsig = (status >> 8) & 0xff;
        if !stopped || stopsig != libc::SIGTRAP {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("injected syscall did not complete: status={status:#x}"),
            ));
        }

        let after = ptrace_getregs(pid)?;
        Ok(after.rax as i64)
    })();

    // Best-effort restore: original instruction word, then the saved registers
    // (so rip and everything else match the pre-call state). Run both even on
    // the error path; surface a restore failure only if the call itself
    // succeeded.
    let restore_word = ptrace_poketext(pid, rip, orig_word);
    let restore_regs = ptrace_setregs(pid, &saved_regs);

    let ret = result?;
    restore_word?;
    restore_regs?;
    Ok(ret)
}

#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
pub(crate) fn inject_syscall(_pid: i32, _nr: u64, _args: [u64; 6]) -> io::Result<i64> {
    Err(io::Error::new(io::ErrorKind::Unsupported,
        "syscall injection is only implemented on x86_64"))
}

/// Find a page-aligned (4096) userspace address that is not covered by any map
/// in `maps`, suitable for a one-page trampoline. Collects the `[start, end)`
/// ranges, sorts them by start, and returns the first gap of at least one page
/// within the sane userspace window `[0x1_0000, 0x7fff_0000_0000)`. Returns
/// `None` when no such gap exists. Pure function: no child process needed.
// used by the restore path (added in a later change)
#[allow(dead_code)]
pub(crate) fn find_free_page(maps: &[MemoryMap]) -> Option<u64> {
    const PAGE: u64 = 4096;
    const WINDOW_LO: u64 = 0x1_0000;
    const WINDOW_HI: u64 = 0x7fff_0000_0000;

    let mut ranges: Vec<(u64, u64)> = maps.iter().map(|m| (m.start, m.end)).collect();
    ranges.sort_by_key(|r| r.0);

    // Walk the window left to right, advancing a cursor past every map that
    // overlaps the region we are still considering. The first time the cursor
    // has at least one page of clearance before the next map, that is our gap.
    let mut cursor = WINDOW_LO;
    for (start, end) in &ranges {
        // Skip maps that end before the cursor; they cannot bound the gap.
        if *end <= cursor {
            continue;
        }
        // A map starting at or before the cursor just pushes the cursor forward.
        if *start <= cursor {
            cursor = *end;
            if cursor >= WINDOW_HI {
                return None;
            }
            continue;
        }
        // There is open space in [cursor, start). Is it at least one page and
        // inside the window?
        if start.saturating_sub(cursor) >= PAGE && cursor + PAGE <= WINDOW_HI {
            return Some(cursor);
        }
        // Gap too small; jump past this map and keep looking.
        cursor = *end;
        if cursor >= WINDOW_HI {
            return None;
        }
    }

    // Trailing space after the last map up to the window top.
    if cursor + PAGE <= WINDOW_HI {
        Some(cursor)
    } else {
        None
    }
}

/// Execute one syscall in a ptrace-stopped child through a permanent `syscall`
/// gadget that already exists at `gadget`. Unlike `inject_syscall`, this plants
/// no text and restores no text: it only saves the registers, points rip at the
/// gadget, single-steps, reads the result, and restores the saved registers.
/// This lets the caller drive injections that would otherwise clobber the page
/// holding a temporary gadget. x86_64 only.
// used by the restore path (added in a later change)
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn inject_syscall_at(pid: i32, gadget: u64, nr: u64, args: [u64; 6]) -> io::Result<i64> {
    let saved_regs = ptrace_getregs(pid)?;

    let result = (|| -> io::Result<i64> {
        let mut regs = saved_regs;
        regs.rax = nr;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        regs.rip = gadget; // execute the permanent `syscall`
        ptrace_setregs(pid, &regs)?;

        ptrace_singlestep(pid)?;
        let mut status: i32 = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w < 0 {
            return Err(io::Error::last_os_error());
        }

        // WIFSTOPPED: low byte == 0x7f. WSTOPSIG: (status >> 8) & 0xff.
        let stopped = (status & 0xff) == 0x7f;
        let stopsig = (status >> 8) & 0xff;
        if !stopped || stopsig != libc::SIGTRAP {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("injected syscall did not complete: status={status:#x}"),
            ));
        }

        let after = ptrace_getregs(pid)?;
        Ok(after.rax as i64)
    })();

    // Restore the saved registers (rip included) even on the error path; surface
    // a restore failure only if the call itself succeeded.
    let restore_regs = ptrace_setregs(pid, &saved_regs);

    let ret = result?;
    restore_regs?;
    Ok(ret)
}

#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
pub(crate) fn inject_syscall_at(_pid: i32, _gadget: u64, _nr: u64, _args: [u64; 6]) -> io::Result<i64> {
    Err(io::Error::new(io::ErrorKind::Unsupported,
        "syscall injection is only implemented on x86_64"))
}

/// Write `bytes` into the stopped child at `addr` via a single
/// `process_vm_writev`. The target page must be writable. Mirrors the private
/// `write_child_mem_vm` helper in `seccomp::notif` (copied locally because that
/// one is private and TOCTOU-bound to a live notification).
// used by the restore path (resume::restore_into) and setup_trampoline
pub(crate) fn write_child_mem(pid: i32, addr: u64, bytes: &[u8]) -> io::Result<()> {
    let local_iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let ret = unsafe {
        libc::process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else if (ret as usize) < bytes.len() {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short write: {} of {} bytes", ret, bytes.len()),
        ))
    } else {
        Ok(())
    }
}

/// Bootstrap a permanent `syscall` trampoline in a free hole of the stopped
/// child's address space. Finds an unused page, maps it `MAP_FIXED`
/// as read/write/exec anonymous memory using the temporary plant-at-rip injector,
/// writes a `syscall` instruction into it, and returns the page address. All
/// later injections can run through this fixed gadget without ever clobbering
/// the page that holds it (it lives in a gap the restored process never uses).
/// MAP_FIXED (not MAP_FIXED_NOREPLACE) is used deliberately to clobber any
/// disposable inherited stub mappings that occupy the chosen hole.
/// x86_64 only.
// used by the restore path (added in a later change)
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn setup_trampoline(pid: i32, maps: &[MemoryMap]) -> io::Result<u64> {
    let addr = find_free_page(maps)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no free page for restore trampoline"))?;

    // mmap(addr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
    //      MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0). nr = 9 on x86_64.
    //
    // MAP_FIXED (not MAP_FIXED_NOREPLACE) is deliberate: in a real restore the
    // stub's address space differs from the checkpoint, so the trampoline hole
    // (a gap in the TARGET/checkpoint layout) is typically still occupied by
    // disposable inherited mappings in the stub, which we MUST clobber to plant
    // the gadget. Safety against clobbering a RESTORED region is guaranteed by
    // the caller passing the CHECKPOINT's `memory_maps` here, so the hole does
    // not exist in the target and no restored region ever maps over it -- NOT by
    // NOREPLACE. The post-call check stays meaningful because MAP_FIXED returns
    // the requested address on success and a negative errno on failure (e.g. a
    // W^X denial of a writable+executable mapping).
    let prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64;
    let ret = inject_syscall(pid, 9, [addr, 4096, prot, flags, (-1i64) as u64, 0])?;

    // MAP_FIXED returns the requested address on success; a negative value
    // (-EPERM from a W^X denial, -ENOMEM, ...) means the mapping failed.
    if ret < 0 || (ret as u64) != addr {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("trampoline mmap at {addr:#x} failed (ret={ret:#x})"),
        ));
    }

    // Plant the permanent `syscall` instruction (0f 05) into the new page.
    write_child_mem(pid, addr, &[0x0f, 0x05])?;

    Ok(addr)
}

#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
pub(crate) fn setup_trampoline(_pid: i32, _maps: &[MemoryMap]) -> io::Result<u64> {
    Err(io::Error::new(io::ErrorKind::Unsupported,
        "trampoline setup is only implemented on x86_64"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn inject_getpid_returns_child_pid() {
        use std::os::unix::process::CommandExt;
        let mut child = unsafe {
            std::process::Command::new("sleep").arg("30")
                .pre_exec(|| {
                    // Become traceable; stop at execve so the tracer (parent) gets control.
                    libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                    Ok(())
                })
                .spawn().unwrap()
        };
        let pid = child.id() as i32;
        // Wait for the execve-stop (SIGTRAP).
        let mut st = 0i32;
        unsafe { libc::waitpid(pid, &mut st, 0); }

        // getpid == 39 on x86_64.
        let ret = inject_syscall(pid, 39, [0; 6]).expect("inject getpid");

        let _ = child.kill();
        let _ = child.wait();

        assert_eq!(ret as i32, pid, "injected getpid should return the child's pid");
    }

    #[test]
    fn find_free_page_finds_gap_between_maps() {
        // Two maps with a one-megabyte gap between them. The first map starts at
        // the window low bound so there is no leading gap to find; the only gap
        // starts at 0x20_0000 (end of the first map) and runs to 0x30_0000.
        let maps = vec![
            MemoryMap {
                start: 0x1_0000,
                end: 0x20_0000,
                perms: "r-xp".into(),
                offset: 0,
                path: None,
            },
            MemoryMap {
                start: 0x30_0000,
                end: 0x40_0000,
                perms: "rw-p".into(),
                offset: 0,
                path: None,
            },
        ];
        let addr = find_free_page(&maps).expect("a gap should be found");
        assert_eq!(addr % 4096, 0, "result must be page aligned");
        assert!(
            addr >= 0x20_0000 && addr + 4096 <= 0x30_0000,
            "result {addr:#x} should sit inside the gap"
        );
    }

    #[test]
    fn find_free_page_none_when_packed() {
        // A single map spanning the entire search window leaves no room.
        let maps = vec![MemoryMap {
            start: 0x1_0000,
            end: 0x7fff_0000_0000,
            perms: "rw-p".into(),
            offset: 0,
            path: None,
        }];
        assert!(find_free_page(&maps).is_none(), "packed window has no gap");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn trampoline_executes_getpid() {
        use std::os::unix::process::CommandExt;
        let mut child = unsafe {
            std::process::Command::new("sleep").arg("30")
                .pre_exec(|| { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0); Ok(()) })
                .spawn().unwrap()
        };
        let pid = child.id() as i32;
        let mut st = 0i32;
        unsafe { libc::waitpid(pid, &mut st, 0); }

        let maps = crate::checkpoint::capture::parse_proc_maps(pid).expect("read child maps");
        let tramp = setup_trampoline(pid, &maps).expect("setup trampoline");
        let ret = inject_syscall_at(pid, tramp, 39, [0; 6]).expect("getpid via trampoline");

        let _ = child.kill(); let _ = child.wait();
        assert_eq!(ret as i32, pid, "getpid via trampoline should return child pid");
    }
}
