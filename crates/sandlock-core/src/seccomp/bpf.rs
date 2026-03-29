// cBPF filter assembly for seccomp-bpf
//
// Layout:
//   [arch check block]          2 instructions (LD arch, JEQ arch)
//   [arg filter block]          variable length (pre-built SockFilter instructions)
//   [LD syscall nr]             1 instruction
//   [notif JEQ instructions]    1 per notif syscall
//   [deny JEQ instructions]     1 per deny syscall
//   [RET ALLOW]                 index = ret_allow_idx   (default fall-through)
//   [RET USER_NOTIF]            index = ret_notif_idx
//   [RET ERRNO(EPERM)]          index = ret_errno_idx
//   [RET KILL_PROCESS]          index = ret_kill_idx

use std::os::unix::io::{FromRawFd, OwnedFd};

use crate::sys::structs::{
    AUDIT_ARCH_X86_64,
    BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W,
    EPERM,
    OFFSET_ARCH, OFFSET_NR,
    SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_USER_NOTIF,
    SECCOMP_SET_MODE_FILTER,
    SockFilter, SockFprog,
};
use crate::sys::syscall::seccomp;

// ============================================================
// BPF helper constructors (pub(crate) for use by context.rs)
// ============================================================

#[inline]
pub(crate) fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}

#[inline]
pub(crate) fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

// ============================================================
// Filter assembly
// ============================================================

/// Assemble a cBPF program for `seccomp(SECCOMP_SET_MODE_FILTER, ...)`.
///
/// * `notif_syscalls`  — syscalls that generate SECCOMP_RET_USER_NOTIF
/// * `deny_syscalls`   — syscalls that return ERRNO(EPERM)
/// * `arg_block`       — pre-built arg filter instructions (from `context::arg_filters`)
pub fn assemble_filter(
    notif_syscalls: &[u32],
    deny_syscalls: &[u32],
    arg_block: &[SockFilter],
) -> Vec<SockFilter> {
    // ---- compute final layout sizes ----
    let arch_block = 2usize;                       // LD arch, JEQ arch (KILL is in ret section)
    let arg_block_len = arg_block.len();
    let load_nr = 1usize;
    let notif_jmps = notif_syscalls.len();
    let deny_jmps = deny_syscalls.len();
    let ret_section = 4usize;                      // ALLOW, USER_NOTIF, ERRNO, KILL

    let total = arch_block + arg_block_len + load_nr + notif_jmps + deny_jmps + ret_section;

    // Indices of the four return instructions (absolute, 0-based).
    let ret_kill_idx  = total - 1;

    let mut prog: Vec<SockFilter> = Vec::with_capacity(total);

    // ---- 1. Arch check block ----
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH));
    let arch_jf = (ret_kill_idx - 2) as u8;
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, arch_jf));

    // ---- 2. Pre-built arg filter block ----
    prog.extend_from_slice(arg_block);

    // ---- 3. Load syscall number ----
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));

    // ---- 4. Notif syscall JEQ instructions ----
    let ret_notif_idx = total - 3;
    let notif_base = arch_block + arg_block_len + load_nr;
    for (i, &nr) in notif_syscalls.iter().enumerate() {
        let pos = notif_base + i;
        let jt = (ret_notif_idx - (pos + 1)) as u8;
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, jt, 0));
    }

    // ---- 5. Deny syscall JEQ instructions ----
    let ret_errno_idx = total - 2;
    let deny_base = notif_base + notif_jmps;
    for (i, &nr) in deny_syscalls.iter().enumerate() {
        let pos = deny_base + i;
        let jt = (ret_errno_idx - (pos + 1)) as u8;
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, jt, 0));
    }

    // ---- 6. Return instructions ----
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));                      // ret_allow_idx
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));                 // ret_notif_idx
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM as u32));       // ret_errno_idx
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));               // ret_kill_idx

    debug_assert_eq!(prog.len(), total, "BPF program length mismatch");
    prog
}

// ============================================================
// Filter installation
// ============================================================

/// Install a cBPF seccomp filter on the calling thread as a pure deny filter.
///
/// Uses `seccomp(SECCOMP_SET_MODE_FILTER, 0, &fprog)` — no `NEW_LISTENER` flag.
/// This is used for `apply_seccomp_filter()` which only blocks syscalls.
pub fn install_deny_filter(prog: &[SockFilter]) -> std::io::Result<()> {
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    seccomp(
        SECCOMP_SET_MODE_FILTER,
        0,
        &fprog as *const SockFprog as *const std::ffi::c_void,
    )?;
    Ok(())
}

/// Install a cBPF seccomp filter on the calling thread with `NEW_LISTENER`.
///
/// Returns the seccomp notification file descriptor.
pub fn install_filter(prog: &[SockFilter]) -> std::io::Result<OwnedFd> {
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
    let fd = seccomp(
        SECCOMP_SET_MODE_FILTER,
        flags,
        &fprog as *const SockFprog as *const std::ffi::c_void,
    )?;
    // SAFETY: kernel returns a valid fd on success
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

// ============================================================
// Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_filter_has_arch_check_and_allow() {
        let prog = assemble_filter(&[], &[], &[]);
        assert!(prog.len() >= 5);
        // First instruction loads arch
        assert_eq!(prog[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(prog[0].k, OFFSET_ARCH);
    }

    #[test]
    fn test_deny_syscall_present() {
        let prog = assemble_filter(&[], &[libc::SYS_mount as u32], &[]);
        let has_mount = prog
            .iter()
            .any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K) && f.k == libc::SYS_mount as u32);
        assert!(has_mount);
    }

    #[test]
    fn test_notif_syscall_present() {
        let prog = assemble_filter(&[libc::SYS_openat as u32], &[], &[]);
        let has_openat = prog
            .iter()
            .any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K) && f.k == libc::SYS_openat as u32);
        assert!(has_openat);
    }

    #[test]
    fn test_arch_jf_lands_on_kill() {
        let prog = assemble_filter(&[], &[], &[]);
        // prog[1] is the JEQ arch check; jf should reach the KILL return.
        let arch_jeq = &prog[1];
        assert_eq!(arch_jeq.code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(arch_jeq.k, AUDIT_ARCH_X86_64);
        // The instruction following prog[1] is prog[2].
        // KILL is the last instruction.
        let kill_idx = prog.len() - 1;
        let expected_jf = (kill_idx - 2) as u8;
        assert_eq!(arch_jeq.jf, expected_jf);
        assert_eq!(prog[kill_idx].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_default_allow_is_before_returns() {
        let prog = assemble_filter(&[libc::SYS_openat as u32], &[libc::SYS_mount as u32], &[]);
        // RET section is last 4 instructions; first of them is ALLOW.
        let allow_instr = &prog[prog.len() - 4];
        assert_eq!(allow_instr.code, BPF_RET | BPF_K);
        assert_eq!(allow_instr.k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_notif_jt_lands_on_user_notif() {
        let prog = assemble_filter(&[libc::SYS_openat as u32], &[], &[]);
        // USER_NOTIF return is at prog.len()-3.
        let ret_notif_idx = prog.len() - 3;
        // arch_block=2, arg_blocks=0, LD NR at index 2, notif JEQ at index 3.
        let notif_jeq = &prog[3];
        assert_eq!(notif_jeq.code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(notif_jeq.k, libc::SYS_openat as u32);
        // jt = ret_notif_idx - (3+1)
        let expected_jt = (ret_notif_idx - 4) as u8;
        assert_eq!(notif_jeq.jt, expected_jt);
    }

    #[test]
    fn test_arg_block_is_embedded() {
        use crate::sys::structs::{BPF_JSET, OFFSET_ARGS0_LO};
        // Build a small arg block: LD NR, JEQ clone, LD arg0, JSET value, RET ERRNO
        let arg_block = vec![
            stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
            jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_clone as u32, 0, 3),
            stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO),
            jump(BPF_JMP | BPF_JSET | BPF_K, 0x0200_0000, 0, 1),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM as u32),
        ];
        let prog = assemble_filter(&[], &[], &arg_block);
        // Arch block = 2, arg block starts at index 2.
        // [2] LD NR
        assert_eq!(prog[2].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(prog[2].k, OFFSET_NR);
        // [3] JEQ clone
        assert_eq!(prog[3].code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(prog[3].k, libc::SYS_clone as u32);
        // [4] LD arg0
        assert_eq!(prog[4].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(prog[4].k, OFFSET_ARGS0_LO);
        // [5] JSET value
        assert_eq!(prog[5].code, BPF_JMP | BPF_JSET | BPF_K);
        assert_eq!(prog[5].k, 0x0200_0000);
    }
}
