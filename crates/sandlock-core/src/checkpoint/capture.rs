use std::io;
use super::{Checkpoint, ProcessState, MemorySegment, MemoryMap, FdInfo};
use crate::sandbox::Sandbox;
use crate::error::{SandlockError, SandboxRuntimeError};

// ---------------------------------------------------------------------------
// ptrace helpers -- PTRACE_SEIZE (doesn't auto-SIGSTOP like ATTACH)
// ---------------------------------------------------------------------------

pub(crate) fn ptrace_seize(pid: i32) -> io::Result<()> {
    let ret = unsafe {
        libc::ptrace(libc::PTRACE_SEIZE as libc::c_uint, pid, 0, 0)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // PTRACE_INTERRUPT stops the tracee without SIGSTOP side effects
    let ret = unsafe {
        libc::ptrace(libc::PTRACE_INTERRUPT as libc::c_uint, pid, 0, 0)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // Wait for the ptrace-stop
    let mut status: i32 = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    Ok(())
}

pub(crate) fn ptrace_detach(pid: i32) -> io::Result<()> {
    let ret = unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn ptrace_getregs(pid: i32) -> io::Result<Vec<u64>> {
    #[cfg(target_arch = "x86_64")]
    {
        // user_regs_struct is 27 u64 fields on x86_64 (216 bytes)
        let mut regs = vec![0u64; 27];
        let ret = unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid, 0, regs.as_mut_ptr()) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(regs)
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Linux arm64 exposes general-purpose registers through
        // PTRACE_GETREGSET/NT_PRSTATUS. user_pt_regs is:
        // x0-x30, sp, pc, pstate (34 u64 values).
        const NT_PRSTATUS: libc::c_int = 1;
        let mut regs = vec![0u64; 34];
        let mut iov = libc::iovec {
            iov_base: regs.as_mut_ptr() as *mut libc::c_void,
            iov_len: regs.len() * std::mem::size_of::<u64>(),
        };
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                pid,
                NT_PRSTATUS as usize as *mut libc::c_void,
                &mut iov as *mut libc::iovec as *mut libc::c_void,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        regs.truncate(iov.iov_len / std::mem::size_of::<u64>());
        Ok(regs)
    }

    #[cfg(target_arch = "riscv64")]
    {
        // Linux riscv64 exposes general-purpose registers through
        // PTRACE_GETREGSET/NT_PRSTATUS. struct user_regs_struct is:
        // pc, ra, sp, gp, tp, t0-t2, s0-s1, a0-a7, s2-s11, t3-t6
        // (32 u64 values; x0 is hardwired zero and not stored).
        const NT_PRSTATUS: libc::c_int = 1;
        let mut regs = vec![0u64; 32];
        let mut iov = libc::iovec {
            iov_base: regs.as_mut_ptr() as *mut libc::c_void,
            iov_len: regs.len() * std::mem::size_of::<u64>(),
        };
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                pid,
                NT_PRSTATUS as usize as *mut libc::c_void,
                &mut iov as *mut libc::iovec as *mut libc::c_void,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        regs.truncate(iov.iov_len / std::mem::size_of::<u64>());
        Ok(regs)
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        let _ = pid;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "checkpoint register capture is not implemented on this architecture",
        ))
    }
}

// ---------------------------------------------------------------------------
// FPU/extended register capture via PTRACE_GETREGSET
// ---------------------------------------------------------------------------

fn ptrace_getregset_bytes(pid: i32, set: libc::c_int, max: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; max];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            set as usize as *mut libc::c_void,
            &mut iov as *mut libc::iovec as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(iov.iov_len.min(buf.len()));
    Ok(buf)
}

fn ptrace_getfpregs(pid: i32) -> io::Result<Vec<u8>> {
    // NT_PRFPREG = 2; NT_X86_XSTATE = 0x202. 8 KiB upper-bounds AVX-512 xstate.
    #[cfg(target_arch = "x86_64")]
    { ptrace_getregset_bytes(pid, 0x202, 8192).or_else(|_| ptrace_getregset_bytes(pid, 2, 512)) }
    #[cfg(not(target_arch = "x86_64"))]
    { ptrace_getregset_bytes(pid, 2, 4096) }
}

// ---------------------------------------------------------------------------
// /proc parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_proc_maps(pid: i32) -> io::Result<Vec<MemoryMap>> {
    let content = std::fs::read_to_string(format!("/proc/{}/maps", pid))?;
    let mut maps = Vec::new();
    for line in content.lines() {
        // Format: start-end perms offset dev inode [pathname]
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 5 {
            continue;
        }
        let addrs: Vec<&str> = parts[0].split('-').collect();
        if addrs.len() != 2 {
            continue;
        }
        let start = u64::from_str_radix(addrs[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(addrs[1], 16).unwrap_or(0);
        let perms = parts[1].to_string();
        let offset = u64::from_str_radix(parts[2], 16).unwrap_or(0);
        let path = if parts.len() >= 6 {
            let p = parts[5].trim();
            if p.is_empty() {
                None
            } else {
                Some(p.to_string())
            }
        } else {
            None
        };
        maps.push(MemoryMap {
            start,
            end,
            perms,
            offset,
            path,
        });
    }
    Ok(maps)
}

// ---------------------------------------------------------------------------
// Memory capture -- process_vm_readv (scatter-gather, no file I/O)
// ---------------------------------------------------------------------------

fn capture_memory(pid: i32, maps: &[MemoryMap]) -> io::Result<Vec<MemorySegment>> {
    let mut segments = Vec::new();

    for map in maps {
        if !map.writable() || !map.private() || map.is_special() {
            continue;
        }
        let size = (map.end - map.start) as usize;
        if size > 256 * 1024 * 1024 {
            continue; // skip segments > 256MB
        }

        let mut data = vec![0u8; size];

        let local_iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut libc::c_void,
            iov_len: size,
        };
        let remote_iov = libc::iovec {
            iov_base: map.start as *mut libc::c_void,
            iov_len: size,
        };

        let ret = unsafe {
            libc::process_vm_readv(
                pid as libc::pid_t,
                &local_iov as *const libc::iovec,
                1,
                &remote_iov as *const libc::iovec,
                1,
                0,
            )
        };

        if ret == size as isize {
            segments.push(MemorySegment {
                start: map.start,
                data,
            });
        }
        // Skip unreadable segments silently (same as old behavior)
    }
    Ok(segments)
}

// ---------------------------------------------------------------------------
// FD table capture
// ---------------------------------------------------------------------------

fn capture_fd_table(pid: i32) -> io::Result<Vec<FdInfo>> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut fds = Vec::new();

    for entry in std::fs::read_dir(&fd_dir)? {
        let entry = entry?;
        let fd_str = entry.file_name().into_string().unwrap_or_default();
        let fd: i32 = match fd_str.parse() {
            Ok(f) => f,
            Err(_) => continue,
        };

        let path = std::fs::read_link(entry.path())
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        // Parse fdinfo for flags and offset
        let (flags, offset) = parse_fdinfo(pid, fd).unwrap_or((0, 0));

        fds.push(FdInfo {
            fd,
            path,
            flags,
            offset,
        });
    }

    fds.sort_by_key(|f| f.fd);
    Ok(fds)
}

fn parse_fdinfo(pid: i32, fd: i32) -> io::Result<(i32, u64)> {
    let content = std::fs::read_to_string(format!("/proc/{}/fdinfo/{}", pid, fd))?;
    let mut flags = 0i32;
    let mut pos = 0u64;
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("flags:\t") {
            flags = i32::from_str_radix(val.trim(), 8).unwrap_or(0);
        }
        if let Some(val) = line.strip_prefix("pos:\t") {
            pos = val.trim().parse().unwrap_or(0);
        }
    }
    Ok((flags, pos))
}

// ---------------------------------------------------------------------------
// Main capture function
// ---------------------------------------------------------------------------

/// Capture a checkpoint from a running, stopped sandbox.
/// The sandbox must already be frozen (SIGSTOP'd and fork-held).
pub(crate) fn capture(pid: i32, policy: &Sandbox) -> Result<Checkpoint, SandlockError> {
    // Seize via ptrace (PTRACE_SEIZE + PTRACE_INTERRUPT -- doesn't auto-SIGSTOP)
    ptrace_seize(pid).map_err(|e| {
        SandlockError::Runtime(SandboxRuntimeError::Child(format!("ptrace seize: {}", e)))
    })?;

    // Capture registers
    let regs = ptrace_getregs(pid).map_err(|e| {
        SandlockError::Runtime(SandboxRuntimeError::Child(format!("ptrace getregs: {}", e)))
    })?;

    // Capture FPU/extended register state
    let fpregs = ptrace_getfpregs(pid).unwrap_or_default();

    // Capture memory maps
    let maps =
        parse_proc_maps(pid).map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;

    // Capture memory data
    let memory_data =
        capture_memory(pid, &maps).map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;

    // Capture fd table
    let fd_table =
        capture_fd_table(pid).map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;

    // Detach
    ptrace_detach(pid).map_err(|e| {
        SandlockError::Runtime(SandboxRuntimeError::Child(format!("ptrace detach: {}", e)))
    })?;

    // Capture cwd and exe from /proc
    let cwd = std::fs::read_link(format!("/proc/{}/cwd", pid))
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    Ok(Checkpoint {
        name: String::new(),
        policy: policy.clone(),
        process_state: ProcessState {
            pid,
            cwd,
            exe,
            regs,
            fpregs,
            memory_maps: maps,
            memory_data,
        },
        fd_table,
        cow_snapshot: None,
        app_state: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// `ptrace_getregs` captures a full register file with a plausible,
    /// non-zero program counter from a live, seized child on the host
    /// architecture. This exercises the architecture-specific register
    /// capture path without requiring a full sandbox launch (no Landlock).
    #[test]
    fn ptrace_getregs_captures_program_counter() {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep child");
        let pid = child.id() as i32;

        let result = (|| -> io::Result<Vec<u64>> {
            ptrace_seize(pid)?;
            let regs = ptrace_getregs(pid)?;
            ptrace_detach(pid)?;
            Ok(regs)
        })();

        let _ = child.kill();
        let _ = child.wait();

        let regs = result.expect("register capture should succeed on this architecture");

        // Architecture-specific register-file width.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(regs.len(), 27, "x86_64 user_regs_struct is 27 u64");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(regs.len(), 34, "aarch64 user_pt_regs is 34 u64");
        #[cfg(target_arch = "riscv64")]
        assert_eq!(regs.len(), 32, "riscv64 user_regs_struct is 32 u64");

        // The program counter must be a non-zero userspace address; its index
        // into the register file differs per architecture.
        #[cfg(target_arch = "x86_64")]
        let pc = regs[16]; // rip
        #[cfg(target_arch = "aarch64")]
        let pc = regs[32]; // pc, after x0-x30 and sp
        #[cfg(target_arch = "riscv64")]
        let pc = regs[0]; // pc is first in riscv user_regs_struct

        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ))]
        assert!(pc != 0, "captured program counter should be non-zero, got {:#x}", pc);
    }

    #[test]
    fn ptrace_getfpregs_captures_nonempty_state() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let res = (|| -> io::Result<Vec<u8>> {
            ptrace_seize(pid)?;
            let fp = ptrace_getfpregs(pid)?;
            ptrace_detach(pid)?;
            Ok(fp)
        })();
        let _ = child.kill();
        let _ = child.wait();
        let fp = res.expect("fpreg capture should succeed");
        assert!(!fp.is_empty(), "captured FP/extended register blob should be non-empty");
    }

    /// Full capture -> save -> load roundtrip against a live child. `capture()`
    /// only ptraces and reads `/proc`, so this exercises the architecture-specific
    /// register arm plus the on-disk save/load format end to end WITHOUT a sandbox
    /// launch (no Landlock) -- the coverage the sandbox-launch integration test
    /// cannot provide on kernels below the required Landlock ABI.
    #[test]
    fn capture_save_load_roundtrips() {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep child");
        let pid = child.id() as i32;

        let policy = Sandbox::builder().build().expect("build policy");
        let captured = capture(pid, &policy);

        let _ = child.kill();
        let _ = child.wait();

        let cp = captured.expect("capture should succeed on this architecture");
        assert!(!cp.process_state.regs.is_empty(), "captured registers");
        assert!(!cp.process_state.memory_maps.is_empty(), "captured memory maps");
        assert!(!cp.fd_table.is_empty(), "captured fd table");

        // Save to a temp dir, load it back, and confirm the round-trip is faithful.
        let dir = std::env::temp_dir()
            .join(format!("sandlock-cp-roundtrip-{}", std::process::id()));
        cp.save(&dir).expect("save checkpoint");
        let loaded = Checkpoint::load(&dir).expect("load checkpoint");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(loaded.process_state.regs, cp.process_state.regs, "regs roundtrip");
        assert_eq!(loaded.process_state.fpregs, cp.process_state.fpregs, "fpregs roundtrip");
        assert_eq!(
            loaded.process_state.memory_data.len(),
            cp.process_state.memory_data.len(),
            "memory segment count roundtrip"
        );
        assert_eq!(loaded.fd_table.len(), cp.fd_table.len(), "fd count roundtrip");
        assert_eq!(loaded.process_state.pid, cp.process_state.pid, "pid roundtrip");
        assert!(!loaded.process_state.exe.is_empty(), "exe path captured");
    }
}
