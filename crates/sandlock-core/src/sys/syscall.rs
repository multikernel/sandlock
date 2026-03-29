use std::ffi::CString;
use std::io;
use std::os::unix::io::{FromRawFd, OwnedFd};

use super::structs::{
    LandlockRulesetAttr, SYS_LANDLOCK_ADD_RULE, SYS_LANDLOCK_CREATE_RULESET,
    SYS_LANDLOCK_RESTRICT_SELF,
};

// ============================================================
// Core raw syscall wrappers (x86_64 ABI)
// ============================================================

/// Raw 3-argument syscall using x86_64 ABI.
///
/// # Safety
/// Caller must ensure arguments are valid for the given syscall number.
pub unsafe fn syscall3(nr: i64, a1: u64, a2: u64, a3: u64) -> io::Result<i64> {
    let ret: i64;
    std::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    if ret < 0 && ret >= -4095 {
        Err(io::Error::from_raw_os_error(-ret as i32))
    } else {
        Ok(ret)
    }
}

/// Raw 2-argument syscall.
///
/// # Safety
/// Caller must ensure arguments are valid for the given syscall number.
pub unsafe fn syscall2(nr: i64, a1: u64, a2: u64) -> io::Result<i64> {
    syscall3(nr, a1, a2, 0)
}

/// Raw 1-argument syscall.
///
/// # Safety
/// Caller must ensure arguments are valid for the given syscall number.
pub unsafe fn syscall1(nr: i64, a1: u64) -> io::Result<i64> {
    syscall3(nr, a1, 0, 0)
}

// ============================================================
// Landlock wrappers
// ============================================================

/// Create a Landlock ruleset.
pub fn landlock_create_ruleset(
    attr: &LandlockRulesetAttr,
    size: usize,
    flags: u32,
) -> io::Result<OwnedFd> {
    let fd = unsafe {
        syscall3(
            SYS_LANDLOCK_CREATE_RULESET,
            attr as *const _ as u64,
            size as u64,
            flags as u64,
        )?
    };
    // SAFETY: kernel returned a valid fd on success
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Add a rule to a Landlock ruleset.
pub fn landlock_add_rule(
    ruleset_fd: &OwnedFd,
    rule_type: u32,
    rule_attr: *const std::ffi::c_void,
    flags: u32,
) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    unsafe {
        syscall3(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd.as_raw_fd() as u64,
            rule_type as u64,
            rule_attr as u64,
        )?;
        // flags is in arg4; re-issue as 4-arg syscall via inline asm
        let _ = flags; // flags documented as must be 0 in current kernel ABI
    }
    Ok(())
}

/// Enforce a Landlock ruleset on the calling thread.
pub fn landlock_restrict_self(ruleset_fd: &OwnedFd, flags: u32) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    unsafe {
        syscall2(
            SYS_LANDLOCK_RESTRICT_SELF,
            ruleset_fd.as_raw_fd() as u64,
            flags as u64,
        )?;
    }
    Ok(())
}

// ============================================================
// Seccomp wrapper
// ============================================================

/// Raw seccomp(2) syscall (syscall 317 on x86_64).
pub fn seccomp(operation: u32, flags: u64, args: *const std::ffi::c_void) -> io::Result<i64> {
    const SYS_SECCOMP: i64 = 317;
    unsafe { syscall3(SYS_SECCOMP, operation as u64, flags, args as u64) }
}

// ============================================================
// pidfd wrappers
// ============================================================

/// Open a pidfd for a process (syscall 434).
pub fn pidfd_open(pid: u32, flags: u32) -> io::Result<OwnedFd> {
    const SYS_PIDFD_OPEN: i64 = 434;
    let fd = unsafe { syscall2(SYS_PIDFD_OPEN, pid as u64, flags as u64)? };
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Duplicate a file descriptor from another process via pidfd (syscall 438).
pub fn pidfd_getfd(pidfd: &OwnedFd, targetfd: i32, flags: u32) -> io::Result<OwnedFd> {
    use std::os::unix::io::AsRawFd;
    const SYS_PIDFD_GETFD: i64 = 438;
    let fd = unsafe {
        syscall3(
            SYS_PIDFD_GETFD,
            pidfd.as_raw_fd() as u64,
            targetfd as u64,
            flags as u64,
        )?
    };
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

// ============================================================
// memfd_create wrapper
// ============================================================

/// Create an anonymous file in memory (syscall 319).
pub fn memfd_create(name: &str, flags: u32) -> io::Result<OwnedFd> {
    const SYS_MEMFD_CREATE: i64 = 319;
    let cname = CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let fd = unsafe { syscall2(SYS_MEMFD_CREATE, cname.as_ptr() as u64, flags as u64)? };
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
