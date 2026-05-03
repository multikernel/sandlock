// Fork + confinement sequence: child-side Landlock + seccomp application
// and parent-child pipe synchronization.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::arch;
use crate::policy::{FsIsolation, Policy};
use crate::seccomp::bpf::{self, stmt, jump};
use crate::sys::structs::{
    AF_INET, AF_INET6,
    BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JSET, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W,
    CLONE_NS_FLAGS, DEFAULT_DENY_SYSCALLS, EPERM,
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO,
    SIOCETHTOOL, SIOCGIFADDR, SIOCGIFBRDADDR, SIOCGIFCONF, SIOCGIFDSTADDR,
    SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFINDEX, SIOCGIFNAME, SIOCGIFNETMASK,
    SOCK_DGRAM, SOCK_RAW, SOCK_TYPE_MASK, IPPROTO_ICMP, IPPROTO_ICMPV6, TIOCLINUX, TIOCSTI,
    PR_SET_DUMPABLE, PR_SET_SECUREBITS, PR_SET_PTRACER,
    OFFSET_ARGS0_LO, OFFSET_ARGS1_LO, OFFSET_ARGS2_LO, OFFSET_ARGS3_LO, OFFSET_NR,
    SockFilter,
};

// ============================================================
// Pipe pair for parent-child synchronization
// ============================================================

/// Pipes for parent-child communication after fork().
pub struct PipePair {
    /// Parent reads the notif fd number written by the child.
    pub notif_r: OwnedFd,
    /// Child writes the notif fd number to the parent.
    pub notif_w: OwnedFd,
    /// Child reads the "supervisor ready" signal from the parent.
    pub ready_r: OwnedFd,
    /// Parent writes the "supervisor ready" signal to the child.
    pub ready_w: OwnedFd,
}

impl PipePair {
    /// Create two pipe pairs using `pipe2(O_CLOEXEC)`.
    pub fn new() -> io::Result<Self> {
        let mut notif_fds = [0i32; 2];
        let mut ready_fds = [0i32; 2];

        // SAFETY: pipe2 with valid pointers and O_CLOEXEC
        let ret = unsafe { libc::pipe2(notif_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let ret = unsafe { libc::pipe2(ready_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret < 0 {
            // Close the first pair on failure
            unsafe {
                libc::close(notif_fds[0]);
                libc::close(notif_fds[1]);
            }
            return Err(io::Error::last_os_error());
        }

        // SAFETY: pipe2 returned valid fds
        Ok(PipePair {
            notif_r: unsafe { OwnedFd::from_raw_fd(notif_fds[0]) },
            notif_w: unsafe { OwnedFd::from_raw_fd(notif_fds[1]) },
            ready_r: unsafe { OwnedFd::from_raw_fd(ready_fds[0]) },
            ready_w: unsafe { OwnedFd::from_raw_fd(ready_fds[1]) },
        })
    }
}

// ============================================================
// Pipe I/O helpers
// ============================================================

/// Write a `u32` as 4 little-endian bytes to a raw fd.
pub(crate) fn write_u32_fd(fd: RawFd, val: u32) -> io::Result<()> {
    let buf = val.to_le_bytes();
    let mut written = 0usize;
    while written < 4 {
        let ret = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr() as *const libc::c_void,
                4 - written,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        written += ret as usize;
    }
    Ok(())
}

/// Read a `u32` (4 little-endian bytes, blocking) from a raw fd.
pub(crate) fn read_u32_fd(fd: RawFd) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    let mut total = 0usize;
    while total < 4 {
        let ret = unsafe {
            libc::read(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                4 - total,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "pipe closed before 4 bytes read",
            ));
        }
        total += ret as usize;
    }
    Ok(u32::from_le_bytes(buf))
}

// ============================================================
// Syscall name → number mapping
// ============================================================

/// Map a syscall name to its `libc::SYS_*` number.
///
/// Covers all names in `DEFAULT_DENY_SYSCALLS` plus extras needed for
/// notif and arg-filter lists.
pub fn syscall_name_to_nr(name: &str) -> Option<u32> {
    let nr: i64 = match name {
        "mount" => libc::SYS_mount,
        "umount2" => libc::SYS_umount2,
        "pivot_root" => libc::SYS_pivot_root,
        "swapon" => libc::SYS_swapon,
        "swapoff" => libc::SYS_swapoff,
        "reboot" => libc::SYS_reboot,
        "sethostname" => libc::SYS_sethostname,
        "setdomainname" => libc::SYS_setdomainname,
        "kexec_load" => libc::SYS_kexec_load,
        "init_module" => libc::SYS_init_module,
        "finit_module" => libc::SYS_finit_module,
        "delete_module" => libc::SYS_delete_module,
        "unshare" => libc::SYS_unshare,
        "setns" => libc::SYS_setns,
        "perf_event_open" => libc::SYS_perf_event_open,
        "bpf" => libc::SYS_bpf,
        "userfaultfd" => libc::SYS_userfaultfd,
        "keyctl" => libc::SYS_keyctl,
        "add_key" => libc::SYS_add_key,
        "request_key" => libc::SYS_request_key,
        "ptrace" => libc::SYS_ptrace,
        "process_vm_readv" => libc::SYS_process_vm_readv,
        "process_vm_writev" => libc::SYS_process_vm_writev,
        "open_by_handle_at" => libc::SYS_open_by_handle_at,
        "name_to_handle_at" => libc::SYS_name_to_handle_at,
        "ioperm" => arch::SYS_IOPERM?,
        "iopl" => arch::SYS_IOPL?,
        "quotactl" => libc::SYS_quotactl,
        "acct" => libc::SYS_acct,
        "lookup_dcookie" => libc::SYS_lookup_dcookie,
        // nfsservctl was removed in Linux 3.1; no libc constant — skip
        "personality" => libc::SYS_personality,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        // Additional syscalls for notif/arg filters
        "clone" => libc::SYS_clone,
        "clone3" => libc::SYS_clone3,
        "vfork" => arch::SYS_VFORK?,
        "mmap" => libc::SYS_mmap,
        "munmap" => libc::SYS_munmap,
        "brk" => libc::SYS_brk,
        "mremap" => libc::SYS_mremap,
        "connect" => libc::SYS_connect,
        "sendto" => libc::SYS_sendto,
        "sendmsg" => libc::SYS_sendmsg,
        "ioctl" => libc::SYS_ioctl,
        "socket" => libc::SYS_socket,
        "prctl" => libc::SYS_prctl,
        "getrandom" => libc::SYS_getrandom,
        "openat" => libc::SYS_openat,
        "open" => arch::SYS_OPEN?,
        "getdents64" => libc::SYS_getdents64,
        "getdents" => arch::SYS_GETDENTS?,
        "bind" => libc::SYS_bind,
        "getsockname" => libc::SYS_getsockname,
        "clock_gettime" => libc::SYS_clock_gettime,
        "gettimeofday" => libc::SYS_gettimeofday,
        "time" => arch::SYS_TIME?,
        "clock_nanosleep" => libc::SYS_clock_nanosleep,
        "timerfd_settime" => libc::SYS_timerfd_settime,
        "timer_settime" => libc::SYS_timer_settime,
        "execve" => libc::SYS_execve,
        "execveat" => libc::SYS_execveat,
        // COW filesystem syscalls
        "unlinkat" => libc::SYS_unlinkat,
        "mkdirat" => libc::SYS_mkdirat,
        "renameat2" => libc::SYS_renameat2,
        "newfstatat" => libc::SYS_newfstatat,
        "statx" => libc::SYS_statx,
        "faccessat" => libc::SYS_faccessat,
        "symlinkat" => libc::SYS_symlinkat,
        "linkat" => libc::SYS_linkat,
        "fchmodat" => libc::SYS_fchmodat,
        "fchownat" => libc::SYS_fchownat,
        "readlinkat" => libc::SYS_readlinkat,
        "truncate" => libc::SYS_truncate,
        "utimensat" => libc::SYS_utimensat,
        "unlink" => arch::SYS_UNLINK?,
        "rmdir" => arch::SYS_RMDIR?,
        "mkdir" => arch::SYS_MKDIR?,
        "rename" => arch::SYS_RENAME?,
        "stat" => arch::SYS_STAT?,
        "lstat" => arch::SYS_LSTAT?,
        "access" => arch::SYS_ACCESS?,
        "symlink" => arch::SYS_SYMLINK?,
        "link" => arch::SYS_LINK?,
        "chmod" => arch::SYS_CHMOD?,
        "chown" => arch::SYS_CHOWN?,
        "lchown" => arch::SYS_LCHOWN?,
        "readlink" => arch::SYS_READLINK?,
        "futimesat" => arch::SYS_FUTIMESAT?,
        "fork" => arch::SYS_FORK?,
        _ => return None,
    };
    Some(nr as u32)
}

// ============================================================
// Policy → syscall lists
// ============================================================

/// Determine which syscalls need `SECCOMP_RET_USER_NOTIF`.
pub fn notif_syscalls(policy: &Policy) -> Vec<u32> {
    let mut nrs = vec![
        libc::SYS_clone as u32,
        libc::SYS_clone3 as u32,
        libc::SYS_wait4 as u32,
        libc::SYS_waitid as u32,
    ];
    arch::push_optional_syscall(&mut nrs, arch::SYS_VFORK);
    // Bare fork(2) carries none of the namespace/process-limit risk of
    // clone/clone3 and was historically left out of the BPF filter so
    // hot fork-loops (COW map-reduce) bypass the supervisor entirely.
    // It only needs interception when policy_fn is active, so the
    // supervisor can register the new child via ptrace fork events
    // before it can run user code (argv-safety invariant).
    if policy.policy_fn.is_some() {
        arch::push_optional_syscall(&mut nrs, arch::SYS_FORK);
    }

    if policy.max_memory.is_some() {
        nrs.push(libc::SYS_mmap as u32);
        nrs.push(libc::SYS_munmap as u32);
        nrs.push(libc::SYS_brk as u32);
        nrs.push(libc::SYS_mremap as u32);
        nrs.push(libc::SYS_shmget as u32);
    }

    if !policy.net_allow.is_empty()
        || policy.policy_fn.is_some()
        || !policy.http_allow.is_empty()
        || !policy.http_deny.is_empty()
    {
        nrs.push(libc::SYS_connect as u32);
        nrs.push(libc::SYS_sendto as u32);
        nrs.push(libc::SYS_sendmsg as u32);
        nrs.push(libc::SYS_bind as u32);
    }

    if policy.random_seed.is_some() {
        nrs.push(libc::SYS_getrandom as u32);
        // Also intercept openat so the supervisor can re-patch vDSO after exec.
        nrs.push(libc::SYS_openat as u32);
    }

    if policy.time_start.is_some() {
        nrs.extend_from_slice(&[
            libc::SYS_clock_nanosleep as u32,
            libc::SYS_timerfd_settime as u32,
            libc::SYS_timer_settime as u32,
        ]);
        // Also intercept openat so the supervisor gets a notification after exec
        // and can re-patch the vDSO (exec replaces vDSO with a fresh copy).
        nrs.push(libc::SYS_openat as u32);
    }

    // /proc virtualization (always on: PID filtering, sensitive path blocking)
    nrs.push(libc::SYS_openat as u32);
    nrs.push(libc::SYS_getdents64 as u32);
    arch::push_optional_syscall(&mut nrs, arch::SYS_GETDENTS);

    // Netlink virtualization (always on):
    //   socket, bind, getsockname — swap in a unix socketpair for AF_NETLINK
    //   recvfrom, recvmsg         — zero msg_name so glibc accepts the reply
    //                                (kernel only writes sun_family on unix
    //                                 recvmsg, leaving nl_pid uninitialized)
    //   close                     — unregister (pid, fd) so reuse doesn't
    //                                collide with the cookie set
    // Send traffic flows through the real socketpair untouched.
    nrs.push(libc::SYS_socket as u32);
    nrs.push(libc::SYS_bind as u32);
    nrs.push(libc::SYS_getsockname as u32);
    nrs.push(libc::SYS_recvfrom as u32);
    nrs.push(libc::SYS_recvmsg as u32);
    nrs.push(libc::SYS_close as u32);
    // Virtualize sched_getaffinity so nproc/sysconf agree with /proc/cpuinfo
    if policy.num_cpus.is_some() {
        nrs.push(libc::SYS_sched_getaffinity as u32);
    }
    if policy.hostname.is_some() {
        nrs.push(libc::SYS_uname as u32);
        nrs.push(libc::SYS_openat as u32);
    }

    // COW filesystem interception (seccomp-based, unprivileged)
    if policy.workdir.is_some() && policy.fs_isolation == FsIsolation::None {
        nrs.extend_from_slice(&[
            libc::SYS_openat as u32,
            libc::SYS_unlinkat as u32,
            libc::SYS_mkdirat as u32,
            libc::SYS_renameat2 as u32,
            libc::SYS_symlinkat as u32,
            libc::SYS_linkat as u32,
            libc::SYS_fchmodat as u32,
            libc::SYS_fchownat as u32,
            libc::SYS_truncate as u32,
            libc::SYS_utimensat as u32,
            libc::SYS_newfstatat as u32,
            libc::SYS_statx as u32,
            libc::SYS_faccessat as u32,
            439u32,                       // SYS_faccessat2 — glibc 2.33+ uses this instead of faccessat
            libc::SYS_readlinkat as u32,
            libc::SYS_getdents64 as u32,
            libc::SYS_chdir as u32,
            libc::SYS_getcwd as u32,
        ]);
        for nr in [
            arch::SYS_OPEN, arch::SYS_UNLINK, arch::SYS_RMDIR, arch::SYS_MKDIR,
            arch::SYS_RENAME, arch::SYS_SYMLINK, arch::SYS_LINK, arch::SYS_CHMOD,
            arch::SYS_CHOWN, arch::SYS_LCHOWN, arch::SYS_STAT, arch::SYS_LSTAT,
            arch::SYS_ACCESS, arch::SYS_READLINK, arch::SYS_GETDENTS,
        ] {
            arch::push_optional_syscall(&mut nrs, nr);
        }
    }

    // Chroot path interception
    if policy.chroot.is_some() {
        nrs.extend_from_slice(&[
            libc::SYS_openat as u32,
            libc::SYS_execve as u32,
            libc::SYS_execveat as u32,
            libc::SYS_unlinkat as u32,
            libc::SYS_mkdirat as u32,
            libc::SYS_renameat2 as u32,
            libc::SYS_symlinkat as u32,
            libc::SYS_linkat as u32,
            libc::SYS_fchmodat as u32,
            libc::SYS_fchownat as u32,
            libc::SYS_truncate as u32,
            libc::SYS_newfstatat as u32,
            libc::SYS_statx as u32,
            libc::SYS_faccessat as u32,
            439u32,                       // SYS_faccessat2 — glibc 2.33+ uses this instead of faccessat
            libc::SYS_readlinkat as u32,
            libc::SYS_getdents64 as u32,
            libc::SYS_chdir as u32,
            libc::SYS_getcwd as u32,
            libc::SYS_statfs as u32,
            libc::SYS_utimensat as u32,
        ]);
        for nr in [
            arch::SYS_OPEN, arch::SYS_STAT, arch::SYS_LSTAT, arch::SYS_ACCESS,
            arch::SYS_READLINK, arch::SYS_GETDENTS, arch::SYS_UNLINK,
            arch::SYS_RMDIR, arch::SYS_MKDIR, arch::SYS_RENAME,
            arch::SYS_SYMLINK, arch::SYS_LINK, arch::SYS_CHMOD,
            arch::SYS_CHOWN, arch::SYS_LCHOWN,
        ] {
            arch::push_optional_syscall(&mut nrs, nr);
        }
    }

    // Explicit deny-paths need path-bearing syscalls intercepted.
    if !policy.fs_denied.is_empty() {
        nrs.extend_from_slice(&[
            libc::SYS_openat as u32,
            libc::SYS_execve as u32,
            libc::SYS_execveat as u32,
            libc::SYS_linkat as u32,
            libc::SYS_renameat2 as u32,
            libc::SYS_symlinkat as u32,
        ]);
        for nr in [arch::SYS_OPEN, arch::SYS_LINK, arch::SYS_RENAME, arch::SYS_SYMLINK] {
            arch::push_optional_syscall(&mut nrs, nr);
        }
    }

    // Dynamic policy callback — intercept key syscalls for event emission.
    if policy.policy_fn.is_some() {
        nrs.extend_from_slice(&[
            libc::SYS_openat as u32,
            libc::SYS_connect as u32,
            libc::SYS_sendto as u32,
            libc::SYS_bind as u32,
            libc::SYS_execve as u32,
            libc::SYS_execveat as u32,
        ]);
    }

    // Port remapping
    if policy.port_remap {
        nrs.extend_from_slice(&[
            libc::SYS_bind as u32,
            libc::SYS_getsockname as u32,
        ]);
    }

    nrs.sort_unstable();
    nrs.dedup();
    nrs
}

/// Resolve `NO_SUPERVISOR_DENY_SYSCALLS` names to numbers.
pub fn no_supervisor_deny_syscall_numbers() -> Vec<u32> {
    use crate::sys::structs::NO_SUPERVISOR_DENY_SYSCALLS;
    NO_SUPERVISOR_DENY_SYSCALLS
        .iter()
        .filter_map(|n| syscall_name_to_nr(n))
        .collect()
}

/// Resolve `deny_syscalls` names to numbers.
///
/// If both `deny_syscalls` and `allow_syscalls` are `None`, returns the
/// numbers for `DEFAULT_DENY_SYSCALLS`.
pub fn deny_syscall_numbers(policy: &Policy) -> Vec<u32> {
    if let Some(ref names) = policy.deny_syscalls {
        names
            .iter()
            .filter_map(|n| syscall_name_to_nr(n))
            .collect()
    } else if policy.allow_syscalls.is_none() {
        DEFAULT_DENY_SYSCALLS
            .iter()
            .filter_map(|n| syscall_name_to_nr(n))
            .collect()
    } else {
        // allow_syscalls is set — no deny list
        Vec::new()
    }
}

/// Build argument-level seccomp filter instructions matching the Python
/// `_build_arg_filters()` exactly.
///
/// Returns a `Vec<SockFilter>` containing self-contained BPF blocks for:
///   - clone: block namespace creation flags
///   - ioctl: block TIOCSTI, TIOCLINUX, SIOCGIF*, SIOCETHTOOL
///   - prctl: block PR_SET_DUMPABLE, PR_SET_SECUREBITS, PR_SET_PTRACER
///   - socket: block SOCK_RAW/SOCK_DGRAM on AF_INET/AF_INET6 (with type mask)
pub fn arg_filters(policy: &Policy) -> Vec<SockFilter> {
    let ret_errno = SECCOMP_RET_ERRNO | EPERM as u32;
    let nr_clone = libc::SYS_clone as u32;
    let nr_ioctl = libc::SYS_ioctl as u32;
    let nr_prctl = libc::SYS_prctl as u32;
    let nr_socket = libc::SYS_socket as u32;

    let mut insns: Vec<SockFilter> = Vec::new();

    // --- clone: block namespace creation flags ---
    // 5 instructions:
    //   LD NR
    //   JEQ clone → +0, skip 3
    //   LD arg0
    //   JSET NS_FLAGS → +0, skip 1
    //   RET ERRNO
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
    insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_clone, 0, 3));
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO));
    insns.push(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NS_FLAGS as u32, 0, 1));
    insns.push(stmt(BPF_RET | BPF_K, ret_errno));

    // --- ioctl: block dangerous commands ---
    // Block terminal injection (TIOCSTI, TIOCLINUX) and network interface
    // enumeration ioctls (SIOCGIF*, SIOCETHTOOL) to complement NETLINK_ROUTE
    // virtualization.
    // Layout: LD NR, JEQ ioctl (skip 1 + N*2), LD arg1, [JEQ cmd, RET ERRNO] * N
    let dangerous_ioctls: &[u32] = &[
        TIOCSTI as u32,
        TIOCLINUX as u32,
        SIOCGIFNAME as u32,
        SIOCGIFCONF as u32,
        SIOCGIFFLAGS as u32,
        SIOCGIFADDR as u32,
        SIOCGIFDSTADDR as u32,
        SIOCGIFBRDADDR as u32,
        SIOCGIFNETMASK as u32,
        SIOCGIFHWADDR as u32,
        SIOCGIFINDEX as u32,
        SIOCETHTOOL as u32,
    ];
    let n_ioctls = dangerous_ioctls.len();
    let skip_count = (1 + n_ioctls * 2) as u8;
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
    insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_ioctl, 0, skip_count));
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS1_LO));
    for &cmd in dangerous_ioctls {
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, cmd, 0, 1));
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
    }

    // --- prctl: block dangerous options ---
    // Layout: LD NR, JEQ prctl (skip 1 + N*2), LD arg0, [JEQ op, RET ERRNO] * N
    let dangerous_prctl_ops: &[u32] = &[PR_SET_DUMPABLE, PR_SET_SECUREBITS, PR_SET_PTRACER];
    let n_ops = dangerous_prctl_ops.len();
    let skip_count = (1 + n_ops * 2) as u8;
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
    insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_prctl, 0, skip_count));
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO));
    for &op in dangerous_prctl_ops {
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, op, 0, 1));
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
    }

    // --- socket: block SOCK_RAW and/or SOCK_DGRAM on AF_INET/AF_INET6 ---
    //
    // Raw sockets are always denied by default. The narrow `allow_icmp`
    // carve-out permits only `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`
    // and the IPv6 equivalent — handled by a separate `socket()` filter
    // further down. When `allow_icmp` is set, SOCK_RAW is excluded from
    // the simple blocked_types list so the carve-out can decide.
    let raw_narrow = policy.allow_icmp;
    let mut blocked_types: Vec<u32> = Vec::new();
    if !policy.allow_icmp {
        blocked_types.push(SOCK_RAW);
    }
    if !policy.allow_udp {
        blocked_types.push(SOCK_DGRAM);
    }

    if !blocked_types.is_empty() {
        let n = blocked_types.len();
        // Instructions after domain checks: 2 (load+AND) + N (JEQs) + 1 (RET)
        let after_domain = 2 + n + 1;
        // Total after NR check: 3 (load domain + 2 JEQs) + after_domain
        let skip_all = (3 + after_domain) as u8;

        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_socket, 0, skip_all));
        // Load domain (arg0)
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO));
        // AF_INET → skip to type check (jump over AF_INET6 check)
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 1, 0));
        // AF_INET6 → type check; else skip everything remaining
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, after_domain as u8));
        // Load type (arg1) and mask off SOCK_NONBLOCK|SOCK_CLOEXEC
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS1_LO));
        insns.push(stmt(BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK));
        // Check each blocked type
        for (i, &sock_type) in blocked_types.iter().enumerate() {
            let remaining = n - i - 1;
            // Match → jump to RET ERRNO (skip 'remaining' JEQs ahead)
            // No match on last type → skip past RET ERRNO (jf=1)
            // No match on non-last → check next type (jf=0)
            let jf: u8 = if remaining == 0 { 1 } else { 0 };
            insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, sock_type, remaining as u8, jf));
        }
        // Deny return (reached by any matching JEQ)
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
    }

    // --- socket: ICMP-only carve-out for SOCK_RAW ---
    // Active when raw sockets are otherwise denied AND --allow-icmp is set.
    // Permits `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` and
    // `socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)`; denies every other
    // SOCK_RAW. The block has 14 instructions; offsets reference the
    // post-block instruction count (skip-to-end).
    if raw_narrow {
        // INST 0: LD NR
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
        // INST 1: JEQ socket → fall through (jt=0); not socket → skip 12
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_socket, 0, 12));
        // INST 2-3: LD type, AND TYPE_MASK
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS1_LO));
        insns.push(stmt(BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK));
        // INST 4: JEQ SOCK_RAW → fall through; not raw → skip 9 (allow)
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, SOCK_RAW, 0, 9));
        // INST 5: LD domain
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO));
        // INST 6: JEQ AF_INET → fall to v4 proto check; else skip 3 to v6 check at INST 10
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 0, 3));
        // INST 7: LD proto (arg2)
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS2_LO));
        // INST 8: JEQ IPPROTO_ICMP → skip 5 to end (allow); else fall to RET errno
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMP, 5, 0));
        // INST 9: RET errno (v4 SOCK_RAW with non-ICMP proto)
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
        // INST 10: JEQ AF_INET6 → fall to v6 proto check; else skip 2 to RET errno
        // (other AF + SOCK_RAW, e.g. AF_PACKET/AF_NETLINK, must be denied)
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, 2));
        // INST 11: LD proto
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS2_LO));
        // INST 12: JEQ IPPROTO_ICMPV6 → skip 1 past RET (allow); else fall to RET errno
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 1, 0));
        // INST 13: RET errno (v6 SOCK_RAW with non-ICMPv6 proto)
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
        // (post-block — fall through to wait4 block below)
    }

    // --- wait4: skip notification for WNOHANG/WNOWAIT (non-blocking) ---
    // wait4(pid, status, options, rusage) — options is arg2
    // 5 instructions:
    //   LD NR
    //   JEQ wait4 → +0, skip 3
    //   LD arg2
    //   JSET (WNOHANG|WNOWAIT) → +0, skip 1
    //   RET ALLOW
    {
        let nr_wait4 = libc::SYS_wait4 as u32;
        let wnohang_or_wnowait = (libc::WNOHANG | 0x0100_0000/* WNOWAIT */) as u32;
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_wait4, 0, 3));
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS2_LO));
        insns.push(jump(BPF_JMP | BPF_JSET | BPF_K, wnohang_or_wnowait, 0, 1));
        insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    // --- waitid: skip notification for WNOHANG/WNOWAIT (non-blocking) ---
    // waitid(idtype, id, infop, options, rusage) — options is arg3
    {
        let nr_waitid = libc::SYS_waitid as u32;
        let wnohang_or_wnowait = (libc::WNOHANG | 0x0100_0000/* WNOWAIT */) as u32;
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr_waitid, 0, 3));
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS3_LO));
        insns.push(jump(BPF_JMP | BPF_JSET | BPF_K, wnohang_or_wnowait, 0, 1));
        insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    insns
}

// ============================================================
// Close fds above threshold
// ============================================================

/// Close all file descriptors above `min_fd`, except those in `keep`.
fn close_fds_above(min_fd: RawFd, keep: &[RawFd]) {
    // Read /proc/self/fd to enumerate open fds.
    // Collect all fd numbers first, then close them after dropping the directory
    // iterator. This avoids closing the directory fd during iteration.
    let fds_to_close: Vec<RawFd> = {
        let dir = match std::fs::read_dir("/proc/self/fd") {
            Ok(d) => d,
            Err(_) => return,
        };
        dir.flatten()
            .filter_map(|entry| {
                entry.file_name().into_string().ok()
                    .and_then(|name| name.parse::<RawFd>().ok())
            })
            .filter(|&fd| fd > min_fd && !keep.contains(&fd))
            .collect()
    };
    // The directory is now closed; safe to close the collected fds.
    for fd in fds_to_close {
        unsafe { libc::close(fd) };
    }
}

// ============================================================
// COW filesystem config passed from parent to child
// ============================================================

// Re-export ChildMountConfig so callers can use the old import path.
pub(crate) use crate::cow::ChildMountConfig;

/// Write uid/gid maps for an unprivileged user namespace.
/// `real_uid`/`real_gid` must be captured *before* unshare(CLONE_NEWUSER),
/// since getuid()/getgid() return the overflow id (65534) after unshare.
/// `target_uid`/`target_gid` are the UIDs visible inside the namespace.
fn write_id_maps(real_uid: u32, real_gid: u32, target_uid: u32, target_gid: u32) {
    let _ = std::fs::write("/proc/self/uid_map", format!("{} {} 1\n", target_uid, real_uid));
    let _ = std::fs::write("/proc/self/setgroups", "deny\n");
    let _ = std::fs::write("/proc/self/gid_map", format!("{} {} 1\n", target_gid, real_gid));
}

/// Write uid/gid maps using the post-unshare overflow uid (65534).
/// Used by the OverlayFS COW path which maps to root (UID 0) inside.
fn write_id_maps_overflow() {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    write_id_maps(uid, gid, 0, 0);
}

// ============================================================
// Child-side confinement (never returns)
// ============================================================

/// Arguments threaded from the parent's `do_spawn` into the child-side
/// `confine_child`.  Packed into a struct because `confine_child` historically
/// grew to seven positional parameters and a struct keeps the call site
/// readable when new flags get added (e.g. `extra_syscalls` for user
/// handlers).  Lifetimes tie everything to the parent's stack frame — the
/// child never outlives the fork point because `confine_child` either execs
/// or exits.
pub(crate) struct ChildSpawnArgs<'a> {
    pub policy: &'a Policy,
    pub cmd: &'a [CString],
    pub pipes: &'a PipePair,
    pub cow_config: Option<&'a ChildMountConfig>,
    pub nested: bool,
    pub keep_fds: &'a [RawFd],
    /// Syscall numbers for which the parent registered `ExtraHandler`s.
    /// Merged into the child's BPF notif list so the kernel actually
    /// raises USER_NOTIF for them.
    pub extra_syscalls: &'a [u32],
}

/// Apply irreversible confinement (Landlock + seccomp) then exec the command.
///
/// This function **never returns**: it calls `execvp` on success or
/// `_exit(127)` on any error.
pub(crate) fn confine_child(args: ChildSpawnArgs<'_>) -> ! {
    let ChildSpawnArgs {
        policy,
        cmd,
        pipes,
        cow_config,
        nested,
        keep_fds,
        extra_syscalls,
    } = args;
    // Helper: abort child on error. Includes the OS error automatically.
    macro_rules! fail {
        ($msg:expr) => {{
            let err = std::io::Error::last_os_error();
            let _ = write!(std::io::stderr(), "sandlock child: {}: {}\n", $msg, err);
            unsafe { libc::_exit(127) };
        }};
    }

    use std::io::Write;

    // 1. New process group
    if unsafe { libc::setpgid(0, 0) } != 0 {
        fail!("setpgid");
    }

    // 1b. If stdin is a terminal, become the foreground process group
    //     so interactive shells can read from the TTY.
    //     Must ignore SIGTTOU first — a background pgrp calling tcsetpgrp
    //     gets stopped by SIGTTOU otherwise.
    if unsafe { libc::isatty(0) } == 1 {
        unsafe {
            libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            libc::tcsetpgrp(0, libc::getpgrp());
            libc::signal(libc::SIGTTOU, libc::SIG_DFL);
        }
    }

    // 2. Die if parent exits
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        fail!("prctl(PR_SET_PDEATHSIG)");
    }

    // 3. Check parent didn't die between fork and prctl
    if unsafe { libc::getppid() } == 1 {
        fail!("parent died before confinement");
    }

    // 4. Optional: disable ASLR
    if policy.no_randomize_memory {
        const ADDR_NO_RANDOMIZE: libc::c_ulong = 0x0040000;
        // Read current personality first (0xffffffff = query), then OR in the flag.
        let current = unsafe { libc::personality(0xffffffff) };
        if current == -1 {
            fail!("personality(query)");
        }
        if unsafe { libc::personality(current as libc::c_ulong | ADDR_NO_RANDOMIZE) } == -1 {
            fail!("personality(ADDR_NO_RANDOMIZE)");
        }
    }

    // 4b. Optional: CPU core binding
    if let Some(ref cores) = policy.cpu_cores {
        if !cores.is_empty() {
            let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
            unsafe { libc::CPU_ZERO(&mut set) };
            for &core in cores {
                unsafe { libc::CPU_SET(core as usize, &mut set) };
            }
            if unsafe {
                libc::sched_setaffinity(
                    0,
                    std::mem::size_of::<libc::cpu_set_t>(),
                    &set,
                )
            } != 0
            {
                fail!("sched_setaffinity");
            }
        }
    }

    // 5. Optional: disable THP
    if policy.no_huge_pages {
        if unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0) } != 0 {
            fail!("prctl(PR_SET_THP_DISABLE)");
        }
    }

    // 5c. Optional: disable core dumps
    if policy.no_coredump {
        // Set RLIMIT_CORE to 0 — the kernel will not write a core file.
        // We intentionally do NOT call prctl(PR_SET_DUMPABLE, 0) because
        // that would break pidfd_getfd which the supervisor needs.
        // The seccomp filter already blocks the child from calling
        // prctl(PR_SET_DUMPABLE, ...) so it can't re-enable it.
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) } != 0 {
            fail!("setrlimit(RLIMIT_CORE, 0)");
        }
    }

    // Capture real uid/gid before any unshare (after unshare they become 65534)
    let real_uid = unsafe { libc::getuid() };
    let real_gid = unsafe { libc::getgid() };

    // 5b. User namespace for --uid mapping (when not using OverlayFS COW,
    //     which sets up its own user namespace)
    if let Some(target_uid) = policy.uid {
        if cow_config.is_none() {
            if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
                fail!("unshare(CLONE_NEWUSER)");
            }
            write_id_maps(real_uid, real_gid, target_uid, target_uid);
        }
    }

    // 5c. User + mount namespace for OverlayFS COW (includes CLONE_NEWUSER)
    if let Some(ref cow) = cow_config {
        // unshare user + mount namespaces (unprivileged)
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            fail!("unshare(CLONE_NEWUSER | CLONE_NEWNS)");
        }

        // Write uid/gid maps using overflow uid (preserves existing COW behavior)
        write_id_maps_overflow();

        // Mount the overlay filesystem ON TOP of the workdir so the child
        // sees the merged view at the original path.  The kernel resolves
        // lowerdir before the covering mount takes effect, so using the
        // same path as both lowerdir and mount-point is safe inside our
        // private mount namespace.
        let lowerdir = cow.lowers.iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(":");
        let opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            lowerdir,
            cow.upper.display(),
            cow.work.display(),
        );

        let mount_cstr = match CString::new(cow.mount_point.to_str().unwrap_or("")) {
            Ok(c) => c,
            Err(_) => fail!("invalid overlay mount point path"),
        };
        let overlay_cstr = CString::new("overlay").unwrap();
        let opts_cstr = match CString::new(opts) {
            Ok(c) => c,
            Err(_) => fail!("invalid overlay opts"),
        };

        let ret = unsafe {
            libc::mount(
                overlay_cstr.as_ptr(),
                mount_cstr.as_ptr(),
                overlay_cstr.as_ptr(),
                0,
                opts_cstr.as_ptr() as *const libc::c_void,
            )
        };
        if ret != 0 {
            fail!("mount overlay");
        }
    }

    // 6. Optional: change working directory
    // cwd controls where the child starts; workdir is only for COW
    let effective_cwd = if let Some(ref cwd) = policy.cwd {
        if let Some(ref chroot_root) = policy.chroot {
            Some(chroot_root.join(cwd.strip_prefix("/").unwrap_or(cwd)))
        } else {
            Some(cwd.clone())
        }
    } else if let Some(ref chroot_root) = policy.chroot {
        // Default to chroot root
        Some(chroot_root.to_path_buf())
    } else if let Some(ref workdir) = policy.workdir {
        // Default to workdir when set (COW working directory)
        Some(workdir.clone())
    } else {
        None
    };

    if let Some(ref cwd) = effective_cwd {
        let c_path = match CString::new(cwd.as_os_str().as_encoded_bytes()) {
            Ok(c) => c,
            Err(_) => fail!("invalid cwd path"),
        };
        if unsafe { libc::chdir(c_path.as_ptr()) } != 0 {
            fail!("chdir");
        }
    }

    // 7. Set NO_NEW_PRIVS (required for both Landlock and seccomp without CAP_SYS_ADMIN)
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        fail!("prctl(PR_SET_NO_NEW_PRIVS)");
    }

    // 8. Apply Landlock confinement (IRREVERSIBLE)
    if let Err(e) = crate::landlock::confine(policy) {
        fail!(format!("landlock: {}", e));
    }

    // 9. Assemble and install seccomp filter (IRREVERSIBLE)
    let deny = deny_syscall_numbers(policy);
    let args = arg_filters(policy);
    let mut keep_fd: i32 = -1;

    if nested {
        // Nested sandbox: deny-only filter (no supervisor — parent handles it).
        // BPF filters are ANDed by the kernel, so each level can only tighten.
        let filter = match bpf::assemble_filter(&[], &deny, &args) {
            Ok(f) => f,
            Err(e) => fail!(format!("seccomp assemble: {}", e)),
        };
        if let Err(e) = bpf::install_deny_filter(&filter) {
            fail!(format!("seccomp deny filter: {}", e));
        }
        // Signal nested mode to parent (fd=0 means no supervisor needed)
        if let Err(e) = write_u32_fd(pipes.notif_w.as_raw_fd(), 0) {
            fail!(format!("write nested signal: {}", e));
        }
    } else {
        // First-level sandbox: notif + deny filter with NEW_LISTENER.
        //
        // Caller-supplied extra handlers must have their syscalls registered in
        // the BPF filter, otherwise the kernel never raises a notification for
        // them and the handler silently never fires.  We merge `extra_syscalls`
        // into the notif list and dedup so each syscall produces exactly one
        // JEQ in the assembled program.
        let mut notif = notif_syscalls(policy);
        if !extra_syscalls.is_empty() {
            notif.extend_from_slice(extra_syscalls);
        }
        // Argv-safety gate (companion to the policy_fn case in
        // notif_syscalls): an extra handler bound to execve/execveat
        // can call `read_child_mem` to inspect argv, so the supervisor
        // must register newly forked children before they can run user
        // code — same invariant policy_fn relies on. Bare fork(2)
        // therefore needs to be intercepted here too.
        let exec_extra = extra_syscalls.iter().any(|&n| {
            n == libc::SYS_execve as u32 || n == libc::SYS_execveat as u32
        });
        if exec_extra {
            arch::push_optional_syscall(&mut notif, arch::SYS_FORK);
        }
        notif.sort_unstable();
        notif.dedup();
        let filter = match bpf::assemble_filter(&notif, &deny, &args) {
            Ok(f) => f,
            Err(e) => fail!(format!("seccomp assemble: {}", e)),
        };
        let notif_fd = match bpf::install_filter(&filter) {
            Ok(fd) => fd,
            Err(e) => fail!(format!("seccomp install: {}", e)),
        };
        keep_fd = notif_fd.as_raw_fd();
        if let Err(e) = write_u32_fd(pipes.notif_w.as_raw_fd(), keep_fd as u32) {
            fail!(format!("write notif fd: {}", e));
        }
        std::mem::forget(notif_fd);
    }

    // Mark this process as confined for in-process nesting detection
    crate::sandbox::CONFINED.store(true, std::sync::atomic::Ordering::Relaxed);

    // 10. Wait for parent to signal ready
    match read_u32_fd(pipes.ready_r.as_raw_fd()) {
        Ok(_) => {}
        Err(e) => fail!(format!("read ready signal: {}", e)),
    }

    // 12. Close all fds above stderr (always on for isolation)
    let mut fds_to_keep: Vec<RawFd> = keep_fds.to_vec();
    if keep_fd >= 0 {
        fds_to_keep.push(keep_fd);
    }
    close_fds_above(2, &fds_to_keep);

    // 13. Apply environment
    if policy.clean_env {
        // Clear all env vars first
        for (key, _) in std::env::vars_os() {
            std::env::remove_var(&key);
        }
    }
    for (key, value) in &policy.env {
        std::env::set_var(key, value);
    }

    // 13b. GPU device visibility
    if let Some(ref devices) = policy.gpu_devices {
        if !devices.is_empty() {
            let vis = devices.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(",");
            std::env::set_var("CUDA_VISIBLE_DEVICES", &vis);
            std::env::set_var("ROCR_VISIBLE_DEVICES", &vis);
        }
        // Empty list = all GPUs visible, don't set env vars
    }

    // 14. exec
    debug_assert!(!cmd.is_empty(), "cmd must not be empty");
    let argv_ptrs: Vec<*const libc::c_char> = cmd
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    if policy.chroot.is_some() {
        // With chroot the seccomp handler rewrites the filename to a host path
        // (or /proc/self/fd/N).  Pass a separate PATH_MAX buffer as the `file`
        // argument so the rewrite does not corrupt argv[0] — which must stay as
        // the original command name (e.g. busybox uses argv[0] for applet
        // detection).  execvp still handles PATH lookup for bare command names.
        let mut exec_path = vec![0u8; libc::PATH_MAX as usize];
        let orig = cmd[0].as_bytes_with_nul();
        exec_path[..orig.len()].copy_from_slice(orig);

        unsafe {
            libc::execvp(
                exec_path.as_ptr() as *const libc::c_char,
                argv_ptrs.as_ptr(),
            )
        };
    } else {
        unsafe { libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr()) };
    }

    // If we get here, exec failed
    fail!(format!("execvp '{}'", cmd[0].to_string_lossy()));
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipe_pair_creation() {
        let pipes = PipePair::new().expect("pipe creation failed");
        // Verify fds are valid (non-negative)
        assert!(pipes.notif_r.as_raw_fd() >= 0);
        assert!(pipes.notif_w.as_raw_fd() >= 0);
        assert!(pipes.ready_r.as_raw_fd() >= 0);
        assert!(pipes.ready_w.as_raw_fd() >= 0);
        // All four fds should be distinct
        let fds = [
            pipes.notif_r.as_raw_fd(),
            pipes.notif_w.as_raw_fd(),
            pipes.ready_r.as_raw_fd(),
            pipes.ready_w.as_raw_fd(),
        ];
        for i in 0..4 {
            for j in (i + 1)..4 {
                assert_ne!(fds[i], fds[j]);
            }
        }
    }

    #[test]
    fn test_write_read_u32() {
        let pipes = PipePair::new().expect("pipe creation failed");
        let val = 42u32;
        write_u32_fd(pipes.notif_w.as_raw_fd(), val).expect("write failed");
        let got = read_u32_fd(pipes.notif_r.as_raw_fd()).expect("read failed");
        assert_eq!(got, val);
    }

    #[test]
    fn test_write_read_u32_large() {
        let pipes = PipePair::new().expect("pipe creation failed");
        let val = 0xDEAD_BEEFu32;
        write_u32_fd(pipes.notif_w.as_raw_fd(), val).expect("write failed");
        let got = read_u32_fd(pipes.notif_r.as_raw_fd()).expect("read failed");
        assert_eq!(got, val);
    }

    #[test]
    fn test_notif_syscalls_always_has_clone() {
        let policy = Policy::builder().build().unwrap();
        let nrs = notif_syscalls(&policy);
        assert!(nrs.contains(&(libc::SYS_clone as u32)));
        assert!(nrs.contains(&(libc::SYS_clone3 as u32)));
        if let Some(vfork) = arch::SYS_VFORK {
            assert!(nrs.contains(&(vfork as u32)));
        }
        // Bare fork(2) is intercepted only when policy_fn is active —
        // see notif_syscalls. The default policy has no policy_fn, so
        // fork stays out of the BPF filter and hot fork-loops keep
        // bypassing the supervisor.
        if let Some(fork) = arch::SYS_FORK {
            assert!(!nrs.contains(&(fork as u32)));
        }
    }

    #[test]
    fn test_notif_syscalls_fork_gated_on_policy_fn() {
        let Some(fork) = arch::SYS_FORK else { return };
        let policy = Policy::builder()
            .policy_fn(|_event, _ctx| crate::policy_fn::Verdict::Allow)
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy);
        assert!(nrs.contains(&(fork as u32)));
    }

    #[test]
    fn test_notif_syscalls_memory() {
        let policy = Policy::builder()
            .max_memory(crate::policy::ByteSize::mib(256))
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy);
        assert!(nrs.contains(&(libc::SYS_mmap as u32)));
        assert!(nrs.contains(&(libc::SYS_munmap as u32)));
        assert!(nrs.contains(&(libc::SYS_brk as u32)));
        assert!(nrs.contains(&(libc::SYS_mremap as u32)));
        assert!(nrs.contains(&(libc::SYS_shmget as u32)));
    }

    #[test]
    fn test_notif_syscalls_net() {
        let policy = Policy::builder()
            .net_allow("example.com:443")
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy);
        assert!(nrs.contains(&(libc::SYS_connect as u32)));
        assert!(nrs.contains(&(libc::SYS_sendto as u32)));
        assert!(nrs.contains(&(libc::SYS_sendmsg as u32)));
    }

    /// SYS_faccessat2 (439) must be in the notification filter for both
    /// chroot and COW modes — glibc 2.33+ uses it instead of faccessat.
    #[test]
    fn test_notif_syscalls_faccessat2() {
        const SYS_FACCESSAT2: u32 = 439;

        // Chroot mode
        let policy = Policy::builder()
            .chroot("/tmp")
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy);
        assert!(nrs.contains(&(libc::SYS_faccessat as u32)));
        assert!(nrs.contains(&SYS_FACCESSAT2),
                "chroot notif filter must include SYS_faccessat2 (439)");

        // COW mode
        let policy = Policy::builder()
            .workdir("/tmp")
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy);
        assert!(nrs.contains(&(libc::SYS_faccessat as u32)));
        assert!(nrs.contains(&SYS_FACCESSAT2),
                "COW notif filter must include SYS_faccessat2 (439)");
    }

    #[test]
    fn test_deny_syscall_numbers_default() {
        let policy = Policy::builder().build().unwrap();
        let nrs = deny_syscall_numbers(&policy);
        // Should contain mount, ptrace, etc.
        assert!(nrs.contains(&(libc::SYS_mount as u32)));
        assert!(nrs.contains(&(libc::SYS_ptrace as u32)));
        assert!(nrs.contains(&(libc::SYS_bpf as u32)));
        // nfsservctl has no libc constant, so it is skipped
        assert!(!nrs.is_empty());
    }

    #[test]
    fn test_deny_syscall_numbers_custom() {
        let policy = Policy::builder()
            .deny_syscalls(vec!["mount".into(), "ptrace".into()])
            .build()
            .unwrap();
        let nrs = deny_syscall_numbers(&policy);
        assert_eq!(nrs.len(), 2);
        assert!(nrs.contains(&(libc::SYS_mount as u32)));
        assert!(nrs.contains(&(libc::SYS_ptrace as u32)));
    }

    #[test]
    fn test_deny_syscall_numbers_empty_when_allow_set() {
        let policy = Policy::builder()
            .allow_syscalls(vec!["read".into(), "write".into()])
            .build()
            .unwrap();
        let nrs = deny_syscall_numbers(&policy);
        assert!(nrs.is_empty());
    }

    #[test]
    fn test_arg_filters_has_clone_ioctl_prctl_socket() {
        use crate::sys::structs::{
            BPF_JEQ, BPF_JSET, BPF_JMP, BPF_K,
        };
        let policy = Policy::builder().build().unwrap();
        let filters = arg_filters(&policy);
        // Should contain JEQ for clone syscall nr
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == libc::SYS_clone as u32));
        // Should contain JSET for CLONE_NS_FLAGS
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JSET | BPF_K)
            && f.k == CLONE_NS_FLAGS as u32));
        // Should contain JEQ for ioctl syscall nr
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == libc::SYS_ioctl as u32));
        // Should contain JEQ for TIOCSTI, TIOCLINUX, and SIOCGIF*/SIOCETHTOOL
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == TIOCSTI as u32));
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == TIOCLINUX as u32));
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == SIOCGIFCONF as u32));
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == SIOCETHTOOL as u32));
        // Should contain JEQ for prctl syscall nr
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == libc::SYS_prctl as u32));
        // Should contain JEQ for PR_SET_DUMPABLE
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == PR_SET_DUMPABLE));
    }

    #[test]
    fn test_arg_filters_raw_sockets() {
        use crate::sys::structs::{BPF_ALU, BPF_AND, BPF_JEQ, BPF_JMP, BPF_K};
        // Raw sockets are blocked by default; allow_icmp is false.
        let policy = Policy::builder().build().unwrap();
        let filters = arg_filters(&policy);
        // Should have AF_INET check
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == AF_INET));
        // Should have AF_INET6 check
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == AF_INET6));
        // Should have ALU AND SOCK_TYPE_MASK
        assert!(filters.iter().any(|f| f.code == (BPF_ALU | BPF_AND | BPF_K)
            && f.k == SOCK_TYPE_MASK));
        // Should have JEQ SOCK_RAW
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == SOCK_RAW));
    }

    #[test]
    fn test_arg_filters_udp_denied_by_default() {
        use crate::sys::structs::{BPF_JEQ, BPF_JMP, BPF_K};
        // UDP is denied by default; allow_udp(false) is the default state.
        let policy = Policy::builder().build().unwrap();
        let filters = arg_filters(&policy);
        // Should have JEQ SOCK_DGRAM
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == SOCK_DGRAM));
    }

    #[test]
    fn test_syscall_name_to_nr_covers_defaults() {
        // Every name in DEFAULT_DENY_SYSCALLS should resolve unless the
        // running architecture does not expose that syscall.
        let expected_unresolved: &[&str] = &[
            "nfsservctl",
            #[cfg(target_arch = "aarch64")]
            "ioperm",
            #[cfg(target_arch = "aarch64")]
            "iopl",
        ];
        let mut skipped = 0;
        for name in DEFAULT_DENY_SYSCALLS {
            match syscall_name_to_nr(name) {
                Some(_) => {}
                None => {
                    assert!(
                        expected_unresolved.contains(name),
                        "unexpected unresolved syscall: {}",
                        name
                    );
                    skipped += 1;
                }
            }
        }
        assert_eq!(skipped, expected_unresolved.len());
    }
}
