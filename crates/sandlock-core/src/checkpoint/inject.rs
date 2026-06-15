use std::io;

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
}
