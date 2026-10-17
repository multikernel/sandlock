// cBPF filter assembly for seccomp-bpf
//
// Layout:
//   [ABI check block]           3 instructions, plus 3 on x86_64 to reject x32
//   [arg filter block]          variable length (pre-built SockFilter instructions)
//   [LD syscall nr]             1 instruction
//   [notif JEQ instructions]    1 per notif syscall
//   [deny JEQ instructions]     1 per blocklisted syscall
//   [RET ALLOW]                 index = ret_allow_idx   (default fall-through)
//   [RET USER_NOTIF]            index = ret_notif_idx
//   [RET ERRNO(EPERM)]          index = ret_errno_idx

use std::os::unix::io::{FromRawFd, OwnedFd};

use crate::sys::structs::{
    SockFilter, SockFprog, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, EPERM,
    OFFSET_ARCH, OFFSET_NR, SECCOMP_FILTER_FLAG_NEW_LISTENER,
    SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_USER_NOTIF, SECCOMP_SET_MODE_FILTER,
};
use crate::sys::syscall::seccomp;

// ============================================================
// BPF helper constructors (pub(crate) for use by context.rs)
// ============================================================

#[inline]
pub(crate) fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
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
/// * `block_syscalls`   — syscalls that return ERRNO(EPERM)
/// * `arg_block`       — pre-built arg filter instructions (from `context::arg_filters`)
///
/// Returns an error if a syscall appears in both notification and deny lists,
/// or if the resulting program would exceed the kernel's `BPF_MAXINSNS`
/// (4096) instruction limit. Catching the size limit here gives a clearer
/// error than the kernel's `EINVAL` from `seccomp(2)`, and also guards the
/// `(idx - n) as u8` jump-offset arithmetic below — cBPF jump offsets are u8,
/// so a program over 256 instructions plus careless changes could silently
/// truncate offsets.
pub fn assemble_filter(
    notif_syscalls: &[u32],
    block_syscalls: &[u32],
    arg_block: &[SockFilter],
) -> Result<Vec<SockFilter>, std::io::Error> {
    if let Some(&nr) = notif_syscalls
        .iter()
        .find(|&&nr| block_syscalls.contains(&nr))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "syscall {} appears in both notification and deny lists; \
                 notification rules are evaluated first",
                nr
            ),
        ));
    }

    let mut prog = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, crate::arch::AUDIT_ARCH, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        use crate::sys::structs::BPF_JSET;
        const X32_SYSCALL_BIT: u32 = 0x4000_0000;

        // x32 shares AUDIT_ARCH_X86_64 but uses a different syscall ABI.
        prog.extend_from_slice(&[
            stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
            jump(BPF_JMP | BPF_JSET | BPF_K, X32_SYSCALL_BIT, 0, 1),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        ]);
    }
    let abi_block_len = prog.len();
    let arg_block_len = arg_block.len();
    let load_nr = 1usize;
    let notif_jmps = notif_syscalls.len();
    let deny_jmps = block_syscalls.len();
    let ret_section = 3usize; // ALLOW, USER_NOTIF, ERRNO

    let total = abi_block_len + arg_block_len + load_nr + notif_jmps + deny_jmps + ret_section;

    // Linux kernel cBPF program length limit (BPF_MAXINSNS).
    const MAX_BPF_INSNS: usize = 4096;
    if total > MAX_BPF_INSNS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "BPF program too large: {} instructions (max {})",
                total, MAX_BPF_INSNS
            ),
        ));
    }

    prog.reserve(total - prog.len());

    // ---- 2. Pre-built arg filter block ----
    prog.extend_from_slice(arg_block);

    // ---- 3. Load syscall number ----
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));

    // ---- 4. Notif syscall JEQ instructions ----
    let ret_notif_idx = total - 2;
    let notif_base = abi_block_len + arg_block_len + load_nr;
    for (i, &nr) in notif_syscalls.iter().enumerate() {
        let pos = notif_base + i;
        let jt = (ret_notif_idx - (pos + 1)) as u8;
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, jt, 0));
    }

    // ---- 5. Deny syscall JEQ instructions ----
    let ret_errno_idx = total - 1;
    let deny_base = notif_base + notif_jmps;
    for (i, &nr) in block_syscalls.iter().enumerate() {
        let pos = deny_base + i;
        let jt = (ret_errno_idx - (pos + 1)) as u8;
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, jt, 0));
    }

    // ---- 6. Return instructions ----
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)); // ret_allow_idx
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)); // ret_notif_idx
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM as u32)); // ret_errno_idx

    debug_assert_eq!(prog.len(), total, "BPF program length mismatch");
    Ok(prog)
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
/// `WAIT_KILLABLE_RECV` (Linux 5.19+) is preferred for reliable notification
/// delivery, but we fall back to `NEW_LISTENER`-only on older kernels that
/// reject the bit with `EINVAL`. The fallback matches the pre-Rust Python
/// implementation (`commit 50d5eb9`) and only trades a robustness flag —
/// the security boundary (kept by `NEW_LISTENER`) is unaffected.
///
/// Returns the seccomp notification file descriptor.
pub fn install_filter(prog: &[SockFilter]) -> std::io::Result<OwnedFd> {
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    let fd = install_with_einval_fallback(
        SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
        SECCOMP_FILTER_FLAG_NEW_LISTENER,
        |flags| {
            seccomp(
                SECCOMP_SET_MODE_FILTER,
                flags,
                &fprog as *const SockFprog as *const std::ffi::c_void,
            )
        },
    )?;
    // SAFETY: kernel returns a valid fd on success
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Call `install` with `preferred_flags`; on `EINVAL`, retry with `fallback_flags`.
///
/// Extracted as a generic helper so the EINVAL-retry control flow can be
/// unit-tested without the real `seccomp(2)` syscall.
pub(crate) fn install_with_einval_fallback<F>(
    preferred_flags: u64,
    fallback_flags: u64,
    mut install: F,
) -> std::io::Result<i64>
where
    F: FnMut(u64) -> std::io::Result<i64>,
{
    match install(preferred_flags) {
        Ok(fd) => Ok(fd),
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => install(fallback_flags),
        Err(e) => Err(e),
    }
}

// ============================================================
// Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(prog: &[SockFilter], arch: u32, nr: u32) -> u32 {
        use crate::sys::structs::{BPF_JSET, OFFSET_ARGS0_LO};

        let mut accumulator = 0;
        let mut pc = 0;
        while let Some(insn) = prog.get(pc) {
            match insn.code {
                code if code == BPF_LD | BPF_W | BPF_ABS => {
                    accumulator = match insn.k {
                        OFFSET_ARCH => arch,
                        OFFSET_NR => nr,
                        OFFSET_ARGS0_LO => 0,
                        offset => panic!("unsupported load offset {offset}"),
                    };
                }
                code if code == BPF_JMP | BPF_JEQ | BPF_K || code == BPF_JMP | BPF_JSET | BPF_K => {
                    let matches = if code == BPF_JMP | BPF_JEQ | BPF_K {
                        accumulator == insn.k
                    } else {
                        accumulator & insn.k != 0
                    };
                    pc += usize::from(if matches { insn.jt } else { insn.jf });
                }
                code if code == BPF_RET | BPF_K => return insn.k,
                code => panic!("unsupported opcode {code}"),
            }
            pc += 1;
        }
        panic!("filter fell through without returning");
    }

    #[test]
    fn native_syscall_actions_survive_argument_loads() {
        let args = [stmt(
            BPF_LD | BPF_W | BPF_ABS,
            crate::sys::structs::OFFSET_ARGS0_LO,
        )];
        let prog =
            assemble_filter(&[libc::SYS_openat as u32], &[libc::SYS_mount as u32], &args).unwrap();
        for (nr, action) in [
            (libc::SYS_getpid, SECCOMP_RET_ALLOW),
            (libc::SYS_openat, SECCOMP_RET_USER_NOTIF),
            (libc::SYS_mount, SECCOMP_RET_ERRNO | EPERM as u32),
        ] {
            assert_eq!(evaluate(&prog, crate::arch::AUDIT_ARCH, nr as u32), action);
        }
    }

    #[test]
    fn wrong_arch_is_killed_before_large_argument_block() {
        let args = vec![stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW); 300];
        let prog = assemble_filter(&[], &[], &args).unwrap();
        assert_eq!(evaluate(&prog, 0, 0), SECCOMP_RET_KILL_PROCESS);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_syscalls_are_killed_before_policy_rules() {
        for args in [vec![], vec![stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)]] {
            let prog =
                assemble_filter(&[libc::SYS_openat as u32], &[libc::SYS_mount as u32], &args)
                    .unwrap();
            for nr in [
                libc::SYS_getpid as u32,
                libc::SYS_openat as u32,
                libc::SYS_mount as u32,
                515,
                0,
                0x3fff_ffff,
            ] {
                assert_eq!(
                    evaluate(&prog, crate::arch::AUDIT_ARCH, nr | 0x4000_0000),
                    SECCOMP_RET_KILL_PROCESS,
                    "x32 syscall {nr} bypassed the ABI guard",
                );
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_syscall_kills_child_without_requiring_x32_support() {
        let prog = assemble_filter(&[], &[], &[]).unwrap();
        let fprog = SockFprog {
            len: prog.len() as u16,
            filter: prog.as_ptr(),
        };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // Only raw libc calls after fork: the test runner has other threads.
            unsafe {
                if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    libc::_exit(100);
                }
                if libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog) != 0 {
                    libc::_exit(101);
                }
                libc::syscall(libc::SYS_getpid | 0x4000_0000);
                libc::_exit(102);
            }
        }
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                break;
            }
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
        }
        assert!(libc::WIFSIGNALED(status), "child status: {status:#x}");
        assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
    }

    #[test]
    fn test_empty_filter_has_arch_check_and_allow() {
        let prog = assemble_filter(&[], &[], &[]).unwrap();
        assert!(prog.len() >= 5);
        // First instruction loads arch
        assert_eq!(prog[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(prog[0].k, OFFSET_ARCH);
    }

    #[test]
    fn test_deny_syscall_present() {
        let prog = assemble_filter(&[], &[libc::SYS_mount as u32], &[]).unwrap();
        let has_mount = prog
            .iter()
            .any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K) && f.k == libc::SYS_mount as u32);
        assert!(has_mount);
    }

    #[test]
    fn test_notif_syscall_present() {
        let prog = assemble_filter(&[libc::SYS_openat as u32], &[], &[]).unwrap();
        let has_openat = prog
            .iter()
            .any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K) && f.k == libc::SYS_openat as u32);
        assert!(has_openat);
    }

    #[test]
    fn test_rejects_notif_deny_overlap() {
        let err = match assemble_filter(&[libc::SYS_openat as u32], &[libc::SYS_openat as u32], &[])
        {
            Ok(_) => panic!("expected notif/deny overlap to be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("both notification and deny lists"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn wrong_arch_is_killed() {
        let prog = assemble_filter(&[], &[], &[]).unwrap();
        assert_eq!(evaluate(&prog, 0, 0), SECCOMP_RET_KILL_PROCESS);
        assert_eq!(
            evaluate(&prog, crate::arch::AUDIT_ARCH, 0),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn test_default_allow_is_before_returns() {
        let prog =
            assemble_filter(&[libc::SYS_openat as u32], &[libc::SYS_mount as u32], &[]).unwrap();
        // RET section is last 3 instructions; first of them is ALLOW.
        let allow_instr = &prog[prog.len() - 3];
        assert_eq!(allow_instr.code, BPF_RET | BPF_K);
        assert_eq!(allow_instr.k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_notif_jt_lands_on_user_notif() {
        let prog = assemble_filter(&[libc::SYS_openat as u32], &[], &[]).unwrap();
        let (pos, notif_jeq) = prog
            .iter()
            .enumerate()
            .find(|(_, insn)| {
                insn.code == BPF_JMP | BPF_JEQ | BPF_K && insn.k == libc::SYS_openat as u32
            })
            .unwrap();
        assert_eq!(
            prog[pos + 1 + usize::from(notif_jeq.jt)].k,
            SECCOMP_RET_USER_NOTIF
        );
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
        let prog = assemble_filter(&[], &[], &arg_block).unwrap();
        assert!(prog.windows(arg_block.len()).any(|window| {
            window.iter().zip(&arg_block).all(|(actual, expected)| {
                actual.code == expected.code
                    && actual.k == expected.k
                    && actual.jt == expected.jt
                    && actual.jf == expected.jf
            })
        }));
    }

    #[test]
    fn test_oversized_filter_is_rejected() {
        // The deny entries alone exceed the instruction limit.
        let deny: Vec<u32> = (0..4097u32).collect();
        let res = assemble_filter(&[], &deny, &[]);
        let err = match res {
            Ok(_) => panic!("expected oversize error"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    // --------------------------------------------------------
    // install_with_einval_fallback — regression coverage for the
    // SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV fallback on kernels < 5.19.
    // --------------------------------------------------------

    const PREFERRED: u64 =
        SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
    const FALLBACK: u64 = SECCOMP_FILTER_FLAG_NEW_LISTENER;

    #[test]
    fn fallback_succeeds_first_try_returns_fd_no_retry() {
        let mut calls = Vec::new();
        let fd = install_with_einval_fallback(PREFERRED, FALLBACK, |flags| {
            calls.push(flags);
            Ok(42)
        })
        .expect("should succeed");
        assert_eq!(fd, 42);
        assert_eq!(calls, vec![PREFERRED], "must not retry on success");
    }

    #[test]
    fn fallback_einval_retries_with_fallback_flags() {
        let mut calls = Vec::new();
        let fd = install_with_einval_fallback(PREFERRED, FALLBACK, |flags| {
            calls.push(flags);
            if flags & SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV != 0 {
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            } else {
                Ok(99)
            }
        })
        .expect("fallback must succeed");
        assert_eq!(fd, 99);
        assert_eq!(
            calls,
            vec![PREFERRED, FALLBACK],
            "EINVAL on preferred must trigger fallback retry"
        );
    }

    #[test]
    fn fallback_non_einval_error_propagates_without_retry() {
        let mut calls = 0;
        let res = install_with_einval_fallback(PREFERRED, FALLBACK, |_| {
            calls += 1;
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        });
        let err = res.expect_err("EPERM should not retry");
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        assert_eq!(calls, 1, "non-EINVAL error must not trigger retry");
    }

    #[test]
    fn fallback_einval_on_both_returns_second_einval() {
        let mut calls = 0;
        let res = install_with_einval_fallback(PREFERRED, FALLBACK, |_| {
            calls += 1;
            Err(std::io::Error::from_raw_os_error(libc::EINVAL))
        });
        let err = res.expect_err("both EINVAL should return error");
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        assert_eq!(calls, 2, "must attempt both flag sets exactly once");
    }
}
