use std::io;

fn setregset(pid: i32, set: libc::c_int, bytes: &[u8]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid,
            set as usize as *mut libc::c_void,
            &mut iov as *mut libc::iovec as *mut libc::c_void,
        )
    };
    if ret < 0 { return Err(io::Error::last_os_error()); }
    Ok(())
}

/// Set the general-purpose register file. `regs` is the Vec<u64> produced by
/// capture::ptrace_getregs (architecture-specific width).
// used by the restore path (added in a later change)
#[allow(dead_code)]
pub(crate) fn set_gp_regs(pid: i32, regs: &[u64]) -> io::Result<()> {
    const NT_PRSTATUS: libc::c_int = 1;
    let bytes: Vec<u8> = regs.iter().flat_map(|r| r.to_le_bytes()).collect();
    setregset(pid, NT_PRSTATUS, &bytes)
}

/// Set the FP/extended register file from the raw blob captured by
/// capture::ptrace_getfpregs. No-op if the blob is empty.
// used by the restore path (added in a later change)
#[allow(dead_code)]
pub(crate) fn set_fp_regs(pid: i32, blob: &[u8]) -> io::Result<()> {
    if blob.is_empty() { return Ok(()); }
    #[cfg(target_arch = "x86_64")]
    { setregset(pid, 0x202, blob).or_else(|_| setregset(pid, 2, blob)) }
    #[cfg(not(target_arch = "x86_64"))]
    { setregset(pid, 2, blob) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setregset_roundtrips_gp_registers() {
        use std::os::unix::process::CommandExt;
        // Donor: capture a register file from a live child.
        let mut donor = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let dpid = donor.id() as i32;
        super::super::capture::ptrace_seize(dpid).unwrap();
        let regs = super::super::capture::ptrace_getregs(dpid).unwrap();
        super::super::capture::ptrace_detach(dpid).unwrap();
        let _ = donor.kill(); let _ = donor.wait();

        // Target: a child that stops itself for tracing (TRACEME, stops at execve).
        let mut target = unsafe {
            std::process::Command::new("sleep").arg("30")
                .pre_exec(|| { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0); Ok(()) })
                .spawn().unwrap()
        };
        let tpid = target.id() as i32;
        let mut st = 0i32;
        unsafe { libc::waitpid(tpid, &mut st, 0); } // stop at execve

        set_gp_regs(tpid, &regs).unwrap();
        let read_back = super::super::capture::ptrace_getregs(tpid).unwrap();
        let _ = target.kill(); let _ = target.wait();

        assert_eq!(read_back, regs, "GP register file must round-trip through SETREGSET");
    }
}
