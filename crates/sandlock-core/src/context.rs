// Fork + confinement sequence: child-side Landlock + seccomp application
// and parent-child pipe synchronization.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use syscalls::{Sysno, SysnoSet};

use crate::arch;
use crate::sandbox::Sandbox;
use crate::seccomp::bpf::{self, stmt, jump};
use crate::sys::structs::{
    AF_INET, AF_INET6,
    BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JSET, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W,
    CLONE_NS_FLAGS, DEFAULT_BLOCKLIST_SYSCALLS, EPERM, SYSV_IPC_BLOCKLIST_SYSCALLS,
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO,
    SIOCETHTOOL, SIOCGIFADDR, SIOCGIFBRDADDR, SIOCGIFCONF, SIOCGIFDSTADDR,
    SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFINDEX, SIOCGIFNAME, SIOCGIFNETMASK,
    SOCK_DGRAM, SOCK_RAW, SOCK_TYPE_MASK, TIOCLINUX, TIOCSTI,
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

#[cfg(test)]
use crate::seccomp::syscall::syscall_name_to_nr;

// ============================================================
// Sandbox → syscall lists
// ============================================================

#[derive(Default)]
struct SyscallList {
    nrs: Vec<u32>,
}

impl SyscallList {
    fn with(syscalls: &[i64]) -> Self {
        let mut list = Self::default();
        list.extend(syscalls);
        list
    }

    fn push(&mut self, nr: i64) {
        self.nrs.push(nr as u32);
    }

    fn extend(&mut self, syscalls: &[i64]) {
        self.nrs.extend(syscalls.iter().map(|&nr| nr as u32));
    }

    fn push_optional(&mut self, nr: Option<i64>) {
        if let Some(nr) = nr {
            self.push(nr);
        }
    }


    fn finish(mut self) -> Vec<u32> {
        self.nrs.sort_unstable();
        self.nrs.dedup();
        self.nrs
    }
}

const BASE_NOTIF_SYSCALLS: &[i64] = &[
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_wait4,
    libc::SYS_waitid,
];

const MEMORY_NOTIF_SYSCALLS: &[i64] = &[
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_brk,
    libc::SYS_mremap,
];

const NETWORK_POLICY_SYSCALLS: &[i64] = &[
    libc::SYS_connect,
    libc::SYS_sendto,
    libc::SYS_sendmsg,
    libc::SYS_sendmmsg,
    libc::SYS_bind,
];

// Also intercept openat so the supervisor can re-patch vDSO after exec.
const RANDOM_NOTIF_SYSCALLS: &[i64] = &[libc::SYS_getrandom, libc::SYS_openat];

// Also intercept openat so the supervisor gets a notification after exec
// and can re-patch the vDSO (exec replaces vDSO with a fresh copy).
const TIME_NOTIF_SYSCALLS: &[i64] = &[
    libc::SYS_clock_nanosleep,
    libc::SYS_timerfd_settime,
    libc::SYS_timer_settime,
    libc::SYS_openat,
];

// /proc virtualization + /etc/hosts virtualization (always on).
//
// `openat` carries the simple `(AT_FDCWD, "/proc/...")` and
// `(AT_FDCWD, "/etc/hosts")` spellings; `openat2` is the same shape
// on newer libcs; legacy `open(path, ...)` is the same path without a
// dirfd. The handlers normalize all three into a single absolute path
// check, so we have to put every variant on the notif list -- otherwise
// a caller that picks `open` or `openat2` slips past virtualization
// and reads the real on-disk file.
fn procfs_hosts_notif_syscalls() -> Vec<i64> {
    let mut v = vec![libc::SYS_openat, arch::SYS_OPENAT2, libc::SYS_getdents64];
    v.extend([arch::sys_open(), arch::sys_getdents()].into_iter().flatten());
    v
}

// Netlink virtualization (always on):
//   socket, bind, getsockname -- swap in a unix socketpair for AF_NETLINK
//   recvfrom, recvmsg         -- zero msg_name so glibc accepts the reply
//                                (kernel only writes sun_family on unix
//                                 recvmsg, leaving nl_pid uninitialized)
//   close                     -- unregister (pid, fd) so reuse doesn't
//                                collide with the cookie set
// Send traffic flows through the real socketpair untouched.
const NETLINK_NOTIF_SYSCALLS: &[i64] = &[
    libc::SYS_socket,
    libc::SYS_bind,
    libc::SYS_getsockname,
    libc::SYS_recvfrom,
    libc::SYS_recvmsg,
    libc::SYS_close,
];

fn cow_path_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_openat,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_renameat2,
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_fchmodat,
        libc::SYS_fchownat,
        libc::SYS_truncate,
        libc::SYS_utimensat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_faccessat,
        arch::SYS_FACCESSAT2,
        libc::SYS_readlinkat,
        libc::SYS_getdents64,
        libc::SYS_chdir,
        libc::SYS_getcwd,
    ];
    v.extend(
        [
            arch::sys_open(),
            arch::sys_unlink(),
            arch::sys_rmdir(),
            arch::sys_mkdir(),
            arch::sys_rename(),
            arch::sys_symlink(),
            arch::sys_link(),
            arch::sys_chmod(),
            arch::sys_chown(),
            arch::sys_lchown(),
            arch::sys_stat(),
            arch::sys_lstat(),
            arch::sys_access(),
            arch::sys_readlink(),
            arch::sys_getdents(),
        ]
        .into_iter()
        .flatten(),
    );
    v
}

fn chroot_path_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_openat,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_renameat2,
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_fchmodat,
        libc::SYS_fchownat,
        libc::SYS_truncate,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_faccessat,
        arch::SYS_FACCESSAT2,
        libc::SYS_readlinkat,
        libc::SYS_getdents64,
        libc::SYS_chdir,
        libc::SYS_getcwd,
        libc::SYS_statfs,
        libc::SYS_utimensat,
        // xattr family (path-based): must be mediated so that paths under an
        // fs_mount/chroot resolve to the real backing file rather than the
        // empty mount point (issue #84). The fd-based f*xattr variants need
        // no mediation — their fd already points at the resolved file.
        libc::SYS_getxattr,
        libc::SYS_lgetxattr,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_listxattr,
        libc::SYS_llistxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
    ];
    v.extend(
        [
            arch::sys_open(),
            arch::sys_stat(),
            arch::sys_lstat(),
            arch::sys_access(),
            arch::sys_readlink(),
            arch::sys_getdents(),
            arch::sys_unlink(),
            arch::sys_rmdir(),
            arch::sys_mkdir(),
            arch::sys_rename(),
            arch::sys_symlink(),
            arch::sys_link(),
            arch::sys_chmod(),
            arch::sys_chown(),
            arch::sys_lchown(),
        ]
        .into_iter()
        .flatten(),
    );
    v
}

fn fs_denied_path_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_openat,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_linkat,
        libc::SYS_renameat2,
        libc::SYS_symlinkat,
    ];
    v.extend(
        [
            arch::sys_open(),
            arch::sys_link(),
            arch::sys_rename(),
            arch::sys_symlink(),
        ]
        .into_iter()
        .flatten(),
    );
    v
}

const POLICY_EVENT_SYSCALLS: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_connect,
    libc::SYS_sendto,
    libc::SYS_bind,
    libc::SYS_execve,
    libc::SYS_execveat,
];

const PORT_REMAP_SYSCALLS: &[i64] = &[
    libc::SYS_bind,
    libc::SYS_getsockname,
];

fn needs_network_supervision(policy: &Sandbox) -> bool {
    !policy.net_allow.is_empty()
        || !policy.net_deny.is_empty()
        || !policy.net_deny_bind.is_empty()
        || policy.policy_fn.is_some()
        || !policy.http_allow.is_empty()
        || !policy.http_deny.is_empty()
}

/// Determine which syscalls need `SECCOMP_RET_USER_NOTIF`.
pub fn notif_syscalls(policy: &Sandbox, sandbox_name: Option<&str>) -> Vec<u32> {
    let mut nrs = SyscallList::with(BASE_NOTIF_SYSCALLS);
    nrs.push_optional(arch::sys_vfork());

    // Bare fork(2) carries none of the namespace/process-limit risk of
    // clone/clone3 and was historically left out of the BPF filter so
    // hot fork-loops (COW map-reduce) bypass the supervisor entirely.
    // It only needs interception when policy_fn is active, so the
    // supervisor can register the new child via ptrace fork events
    // before it can run user code (argv-safety invariant).
    if policy.policy_fn.is_some() {
        nrs.push_optional(arch::sys_fork());
    }

    if policy.max_memory.is_some() {
        nrs.extend(MEMORY_NOTIF_SYSCALLS);
        // shmget is in notif only when SysV IPC is allowed. The BPF
        // layout puts notif JEQs before deny JEQs, so a syscall on
        // both lists would notify (RET_USER_NOTIF) and silently
        // bypass the kernel-level deny. When extra_allow_syscalls does not contain "sysv_ipc",
        // shmget belongs only on the blocklist.
        if policy.allows_sysv_ipc() {
            nrs.push(libc::SYS_shmget);
        }
    }

    if needs_network_supervision(policy) {
        nrs.extend(NETWORK_POLICY_SYSCALLS);
    } else if policy.has_unix_fs_gate() {
        // Named-unix connect gate: trap connect() so a connect to a unix socket
        // outside the fs-write grants is denied, even when no IP network rules
        // are present. Landlock cannot gate this.
        nrs.push(libc::SYS_connect);
    }

    if policy.random_seed.is_some() {
        nrs.extend(RANDOM_NOTIF_SYSCALLS);
    }

    if policy.time_start.is_some() {
        nrs.extend(TIME_NOTIF_SYSCALLS);
    }

    nrs.extend(&procfs_hosts_notif_syscalls());
    nrs.extend(NETLINK_NOTIF_SYSCALLS);

    // Virtualize sched_getaffinity so nproc/sysconf agree with /proc/cpuinfo
    if policy.num_cpus.is_some() {
        nrs.push(libc::SYS_sched_getaffinity);
    }
    if sandbox_name.is_some() {
        nrs.extend(&[libc::SYS_uname, libc::SYS_openat]);
    }

    // COW filesystem interception (seccomp-based, unprivileged)
    if policy.workdir.is_some() {
        nrs.extend(&cow_path_syscalls());
    }

    // Chroot path interception
    if policy.chroot.is_some() {
        nrs.extend(&chroot_path_syscalls());
    }

    // Explicit deny-paths need path-bearing syscalls intercepted.
    if !policy.fs_denied.is_empty() {
        nrs.extend(&fs_denied_path_syscalls());
    }

    // Dynamic policy callback — intercept key syscalls for event emission.
    if policy.policy_fn.is_some() {
        nrs.extend(POLICY_EVENT_SYSCALLS);
    }

    // Port remapping
    if policy.port_remap {
        nrs.extend(PORT_REMAP_SYSCALLS);
    }

    nrs.finish()
}

/// Resolve `base` syscall names plus policy extras (and SysV IPC syscalls when
/// `policy.allows_sysv_ipc()` is false) to a deduplicated, ascending list of
/// numbers for the current architecture.
///
/// A `SysnoSet` accumulates the membership: it dedups inherently (so SysV IPC
/// folds in with a plain `insert`) and iterates in ascending syscall order.
/// Names that do not exist on this architecture resolve to nothing and are
/// skipped, so the result stays arch-correct.
fn resolve_blocklist(base: &[&str], policy: &Sandbox) -> Vec<u32> {
    let mut set: SysnoSet = base
        .iter()
        .copied()
        .chain(policy.extra_deny_syscalls.iter().map(String::as_str))
        .filter_map(|n| n.parse::<Sysno>().ok())
        .collect();
    if !policy.allows_sysv_ipc() {
        for name in SYSV_IPC_BLOCKLIST_SYSCALLS {
            if let Ok(sysno) = name.parse::<Sysno>() {
                set.insert(sysno);
            }
        }
    }
    set.iter().map(|s| s.id() as u32).collect()
}

/// Resolve `NO_SUPERVISOR_BLOCKLIST_SYSCALLS` names to numbers, plus
/// SysV IPC syscalls when `policy.allows_sysv_ipc()` is false.
pub fn no_supervisor_blocklist_syscall_numbers(policy: &Sandbox) -> Vec<u32> {
    use crate::sys::structs::NO_SUPERVISOR_BLOCKLIST_SYSCALLS;
    resolve_blocklist(NO_SUPERVISOR_BLOCKLIST_SYSCALLS, policy)
}

/// Resolve the default syscall blocklist plus policy extras to numbers.
///
/// SysV IPC syscalls are appended to the resolved blocklist when
/// `policy.allows_sysv_ipc()` is false.
pub fn blocklist_syscall_numbers(policy: &Sandbox) -> Vec<u32> {
    resolve_blocklist(DEFAULT_BLOCKLIST_SYSCALLS, policy)
}

/// Build argument-level seccomp filter instructions matching the Python
/// `_build_arg_filters()` exactly.
///
/// Returns a `Vec<SockFilter>` containing self-contained BPF blocks for:
///   - clone: block namespace creation flags
///   - ioctl: block TIOCSTI, TIOCLINUX, SIOCGIF*, SIOCETHTOOL
///   - prctl: block PR_SET_DUMPABLE, PR_SET_SECUREBITS, PR_SET_PTRACER
///   - socket: block SOCK_RAW/SOCK_DGRAM on AF_INET/AF_INET6 (with type mask)
pub fn arg_filters(policy: &Sandbox) -> Vec<SockFilter> {
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
    // SOCK_RAW is unconditionally denied. Sandlock does not expose
    // raw ICMP — packet-crafting capabilities aren't part of the XOA
    // threat model, and destination filtering at `sendto` can't be
    // honestly enforced for raw sockets (the agent controls the IP
    // header). Workloads that need ping should use the kernel ping
    // socket (SOCK_DGRAM + IPPROTO_ICMP) via an `icmp://...` rule.
    //
    // SOCK_DGRAM is denied unless a UDP or ICMP rule exists in
    // net_allow. The kernel ping socket uses SOCK_DGRAM with
    // IPPROTO_ICMP, so the same type bit gates both — destination
    // filtering at sendto (Phase 2) is what separates them per-rule.
    use crate::sandbox::Protocol;
    let any_udp_rule = policy.net_allow.iter().any(|r| r.protocol == Protocol::Udp);
    let any_icmp_rule = policy.net_allow.iter().any(|r| r.protocol == Protocol::Icmp);
    // `--net-deny` is default-allow, so UDP and the kernel ping socket
    // (both SOCK_DGRAM) must be creatable; without this the sandbox
    // could not even do DNS over UDP. Per-destination UDP/ICMP denial
    // is still enforced on the sendto on-behalf path via the DenyList.
    let net_deny_active = !policy.net_deny.is_empty();
    let mut blocked_types: Vec<u32> = Vec::new();
    blocked_types.push(SOCK_RAW);
    if !any_udp_rule && !any_icmp_rule && !net_deny_active {
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

    // (raw ICMP carve-out removed — SOCK_RAW is unconditionally denied
    // by the blocked_types block above. Sandlock does not expose raw
    // sockets; ping uses the SOCK_DGRAM kernel ping socket via an
    // `icmp://...` rule, gated by host `ping_group_range`.)

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
// User-namespace uid/gid mapping helpers
// ============================================================

/// Write uid/gid maps for an unprivileged user namespace.
/// `real_uid`/`real_gid` must be captured *before* unshare(CLONE_NEWUSER),
/// since getuid()/getgid() return the overflow id (65534) after unshare.
/// `target_uid`/`target_gid` are the UIDs visible inside the namespace.
fn write_id_maps(real_uid: u32, real_gid: u32, target_uid: u32, target_gid: u32) {
    let _ = std::fs::write("/proc/self/uid_map", format!("{} {} 1\n", target_uid, real_uid));
    let _ = std::fs::write("/proc/self/setgroups", "deny\n");
    let _ = std::fs::write("/proc/self/gid_map", format!("{} {} 1\n", target_gid, real_gid));
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
    pub sandbox: &'a Sandbox,
    pub cmd: &'a [CString],
    pub pipes: &'a PipePair,
    /// Skip the user-notification supervisor: child installs a kernel-only
    /// deny filter, parent reads `notif_fd_num = 0` and never starts a
    /// supervisor. Mirrors `Sandbox::no_supervisor`.
    pub no_supervisor: bool,
    pub keep_fds: &'a [RawFd],
    /// Sandbox instance name. When set, it is also exposed as the
    /// sandbox's virtual hostname.
    pub sandbox_name: Option<&'a str>,
    /// Syscall numbers for which the parent registered user `Handler`s.
    /// Merged into the child's BPF notif list so the kernel actually
    /// raises USER_NOTIF for them.
    pub extra_syscalls: &'a [u32],
    /// PID of the parent process captured before fork. Used to detect
    /// parent death in the child without assuming PID 1 is always init
    /// (incorrect in containers where the entrypoint runs as PID 1).
    pub parent_pid: libc::pid_t,
}

/// Apply irreversible confinement (Landlock + seccomp) then exec the command.
///
/// This function **never returns**: it calls `execvp` on success or
/// `_exit(127)` on any error.
pub(crate) fn confine_child(args: ChildSpawnArgs<'_>) -> ! {
    let ChildSpawnArgs {
        sandbox,
        cmd,
        pipes,
        no_supervisor,
        keep_fds,
        sandbox_name,
        extra_syscalls,
        parent_pid,
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

    // 3. Check parent didn't die between fork and prctl.
    // Compare against the actual parent PID captured before fork rather than
    // hardcoding 1, since containers often run the entrypoint as PID 1 and a
    // child forked from it legitimately has getppid() == 1.
    if unsafe { libc::getppid() } != parent_pid {
        fail!("parent died before confinement");
    }

    // 4. Optional: disable ASLR
    if sandbox.no_randomize_memory {
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
    if let Some(ref cores) = sandbox.cpu_cores {
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
    if sandbox.no_huge_pages {
        if unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0) } != 0 {
            fail!("prctl(PR_SET_THP_DISABLE)");
        }
    }

    // 5c. Optional: disable core dumps
    if sandbox.no_coredump {
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

    // 5b. User namespace for --uid mapping.
    if let Some(target_uid) = sandbox.uid {
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            fail!("unshare(CLONE_NEWUSER)");
        }
        write_id_maps(real_uid, real_gid, target_uid, target_uid);
    }

    // 6. Optional: change working directory
    // cwd controls where the child starts; workdir is only for COW
    let effective_cwd = if let Some(ref cwd) = sandbox.cwd {
        if let Some(ref chroot_root) = sandbox.chroot {
            Some(chroot_root.join(cwd.strip_prefix("/").unwrap_or(cwd)))
        } else {
            Some(cwd.clone())
        }
    } else if let Some(ref chroot_root) = sandbox.chroot {
        // Default to chroot root
        Some(chroot_root.to_path_buf())
    } else if let Some(ref workdir) = sandbox.workdir {
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
    if let Err(e) = crate::landlock::confine(sandbox) {
        fail!(format!("landlock: {}", e));
    }

    // 9. Assemble and install seccomp filter (IRREVERSIBLE)
    let args = arg_filters(sandbox);
    let mut keep_fd: i32 = -1;

    if no_supervisor {
        // No-supervisor mode: deny-only kernel filter, no NEW_LISTENER.
        // BPF filters are ANDed by the kernel, so an outer filter (from a
        // wrapping sandbox) keeps tightening this layer too.
        //
        // Uses the relaxed `no_supervisor_blocklist_syscall_numbers` deny
        // list (which leaves `ptrace`, `unshare`, `process_vm_*`, etc.
        // alone) so an inner full-supervisor sandlock nested under this
        // one still has the syscalls its supervisor needs.
        let deny = no_supervisor_blocklist_syscall_numbers(sandbox);
        let filter = match bpf::assemble_filter(&[], &deny, &args) {
            Ok(f) => f,
            Err(e) => fail!(format!("seccomp assemble: {}", e)),
        };
        if let Err(e) = bpf::install_deny_filter(&filter) {
            fail!(format!("seccomp deny filter: {}", e));
        }
        // fd=0 tells the parent there's no supervisor to attach to.
        if let Err(e) = write_u32_fd(pipes.notif_w.as_raw_fd(), 0) {
            fail!(format!("write no-supervisor signal: {}", e));
        }
    } else {
        let deny = blocklist_syscall_numbers(sandbox);
        // First-level sandbox: notif + deny filter with NEW_LISTENER.
        //
        // Caller-supplied handlers must have their syscalls registered in
        // the BPF filter, otherwise the kernel never raises a notification for
        // them and the handler silently never fires.  We merge `extra_syscalls`
        // into the notif list and dedup so each syscall produces exactly one
        // JEQ in the assembled program.
        let mut notif = notif_syscalls(sandbox, sandbox_name);
        if !extra_syscalls.is_empty() {
            notif.extend_from_slice(extra_syscalls);
        }
        // Argv-safety gate (companion to the policy_fn case in
        // notif_syscalls): a handler bound to execve/execveat
        // can call `read_child_mem` to inspect argv, so the supervisor
        // must register newly forked children before they can run user
        // code — same invariant policy_fn relies on. Bare fork(2)
        // therefore needs to be intercepted here too.
        let exec_extra = extra_syscalls.iter().any(|&n| {
            n == libc::SYS_execve as u32 || n == libc::SYS_execveat as u32
        });
        if exec_extra {
            arch::push_optional_syscall(&mut notif, arch::sys_fork());
        }
        notif.sort_unstable();
        notif.dedup();
        let filter = match bpf::assemble_filter(&notif, &deny, &args) {
            Ok(f) => f,
            Err(e) => fail!(format!("seccomp assemble: {}", e)),
        };
        let notif_fd = match bpf::install_filter(&filter) {
            Ok(fd) => fd,
            Err(e) => {
                // EBUSY here means another seccomp filter on this task already
                // owns the SECCOMP_FILTER_FLAG_NEW_LISTENER slot. The kernel
                // permits at most one listener per task — to nest, opt this
                // sandbox out of the supervisor via `Sandbox::no_supervisor`
                // (or the CLI's `--no-supervisor` flag).
                if e.raw_os_error() == Some(libc::EBUSY) {
                    let _ = write!(
                        std::io::stderr(),
                        "sandlock child: seccomp install: {} (an outer sandbox already owns the \
                         seccomp listener; pass --no-supervisor or Sandbox::no_supervisor(true) \
                         on this sandbox to nest)\n",
                        e,
                    );
                    unsafe { libc::_exit(127) };
                }
                fail!(format!("seccomp install: {}", e));
            }
        };
        keep_fd = notif_fd.as_raw_fd();
        if let Err(e) = write_u32_fd(pipes.notif_w.as_raw_fd(), keep_fd as u32) {
            fail!(format!("write notif fd: {}", e));
        }
        std::mem::forget(notif_fd);
    }

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
    if sandbox.clean_env {
        // Clear all env vars first
        for (key, _) in std::env::vars_os() {
            std::env::remove_var(&key);
        }
    }
    for (key, value) in &sandbox.env {
        std::env::set_var(key, value);
    }

    // 13b. GPU device visibility
    if let Some(ref devices) = sandbox.gpu_devices {
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

    if sandbox.chroot.is_some() {
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
        let policy = Sandbox::builder().build().unwrap();
        let nrs = notif_syscalls(&policy, None);
        assert!(nrs.contains(&(libc::SYS_clone as u32)));
        assert!(nrs.contains(&(libc::SYS_clone3 as u32)));
        if let Some(vfork) = arch::sys_vfork() {
            assert!(nrs.contains(&(vfork as u32)));
        }
        // Bare fork(2) is intercepted only when policy_fn is active —
        // see notif_syscalls. The default policy has no policy_fn, so
        // fork stays out of the BPF filter and hot fork-loops keep
        // bypassing the supervisor.
        if let Some(fork) = arch::sys_fork() {
            assert!(!nrs.contains(&(fork as u32)));
        }
    }

    #[test]
    fn test_notif_syscalls_fork_gated_on_policy_fn() {
        let Some(fork) = arch::sys_fork() else { return };
        let policy = Sandbox::builder()
            .policy_fn(|_event, _ctx| crate::policy_fn::Verdict::Allow)
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy, None);
        assert!(nrs.contains(&(fork as u32)));
    }

    #[test]
    fn test_notif_syscalls_memory() {
        // shmget only appears in notif when SysV IPC is allowed —
        // otherwise it is on the kernel blocklist and notifying would
        // bypass the deny (notif JEQs precede deny JEQs in the BPF
        // layout).
        let policy = Sandbox::builder()
            .max_memory(crate::sandbox::ByteSize::mib(256))
            .extra_allow_syscalls(vec!["sysv_ipc".into()])
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy, None);
        assert!(nrs.contains(&(libc::SYS_mmap as u32)));
        assert!(nrs.contains(&(libc::SYS_munmap as u32)));
        assert!(nrs.contains(&(libc::SYS_brk as u32)));
        assert!(nrs.contains(&(libc::SYS_mremap as u32)));
        assert!(nrs.contains(&(libc::SYS_shmget as u32)));
    }

    #[test]
    fn test_notif_syscalls_memory_excludes_shmget_when_sysv_ipc_denied() {
        // With max_memory but allows_sysv_ipc()=false (the default),
        // shmget must NOT be in notif: if it were, the BPF filter
        // would route it to RET_USER_NOTIF before reaching the deny
        // JEQ, silently bypassing the kernel-level deny.
        let policy = Sandbox::builder()
            .max_memory(crate::sandbox::ByteSize::mib(256))
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy, None);
        assert!(!nrs.contains(&(libc::SYS_shmget as u32)));
        // Other memory syscalls remain notified — they are not denied.
        assert!(nrs.contains(&(libc::SYS_mmap as u32)));
        assert!(nrs.contains(&(libc::SYS_brk as u32)));
    }

    #[test]
    fn test_notif_syscalls_net() {
        let policy = Sandbox::builder()
            .net_allow("example.com:443")
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy, None);
        assert!(nrs.contains(&(libc::SYS_connect as u32)));
        assert!(nrs.contains(&(libc::SYS_sendto as u32)));
        assert!(nrs.contains(&(libc::SYS_sendmsg as u32)));
        assert!(nrs.contains(&(libc::SYS_sendmmsg as u32)));
    }

    #[test]
    fn test_notif_syscalls_net_deny() {
        // --net-deny is default-allow but still needs every connect/sendto
        // routed to the on-behalf path so the DenyList can refuse matches.
        let policy = Sandbox::builder()
            .net_deny("10.0.0.0/8")
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy, None);
        assert!(nrs.contains(&(libc::SYS_connect as u32)));
        assert!(nrs.contains(&(libc::SYS_sendto as u32)));
    }

    #[test]
    fn test_notif_syscalls_sandbox_name_enables_hostname_virtualization() {
        let policy = Sandbox::builder().build().unwrap();
        let nrs = notif_syscalls(&policy, Some("api.local"));
        assert!(nrs.contains(&(libc::SYS_uname as u32)));
        assert!(nrs.contains(&(libc::SYS_openat as u32)));
    }

    /// SYS_faccessat2 (439) must be in the notification filter for both
    /// chroot and COW modes — glibc 2.33+ uses it instead of faccessat.
    #[test]
    fn test_notif_syscalls_faccessat2() {
        // Chroot mode
        let policy = Sandbox::builder()
            .chroot("/tmp")
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy, None);
        assert!(nrs.contains(&(libc::SYS_faccessat as u32)));
        assert!(nrs.contains(&(arch::SYS_FACCESSAT2 as u32)),
                "chroot notif filter must include SYS_faccessat2 (439)");

        // COW mode
        let policy = Sandbox::builder()
            .workdir("/tmp")
            .build()
            .unwrap();
        let nrs = notif_syscalls(&policy, None);
        assert!(nrs.contains(&(libc::SYS_faccessat as u32)));
        assert!(nrs.contains(&(arch::SYS_FACCESSAT2 as u32)),
                "COW notif filter must include SYS_faccessat2 (439)");
    }

    #[test]
    fn test_blocklist_syscall_numbers_default() {
        let policy = Sandbox::builder().build().unwrap();
        let nrs = blocklist_syscall_numbers(&policy);
        // Should contain mount, ptrace, etc.
        assert!(nrs.contains(&(libc::SYS_mount as u32)));
        assert!(nrs.contains(&(libc::SYS_ptrace as u32)));
        assert!(nrs.contains(&(libc::SYS_bpf as u32)));
        // SysV IPC denied by default (no IPC namespace in sandlock)
        assert!(nrs.contains(&(libc::SYS_shmget as u32)));
        assert!(nrs.contains(&(libc::SYS_shmat as u32)));
        assert!(nrs.contains(&(libc::SYS_msgget as u32)));
        assert!(nrs.contains(&(libc::SYS_semget as u32)));
        // nfsservctl has no libc constant, so it is skipped
        assert!(!nrs.is_empty());
    }

    #[test]
    fn test_blocklist_syscall_numbers_custom() {
        let policy = Sandbox::builder()
            .extra_deny_syscalls(vec!["mount".into(), "ptrace".into()])
            .build()
            .unwrap();
        let nrs = blocklist_syscall_numbers(&policy);
        // User-supplied blocklist still gets SysV IPC appended
        // (allows_sysv_ipc() defaults to false).
        assert!(nrs.contains(&(libc::SYS_mount as u32)));
        assert!(nrs.contains(&(libc::SYS_ptrace as u32)));
        assert!(nrs.contains(&(libc::SYS_shmget as u32)));
    }

    #[test]
    fn test_blocklist_syscall_numbers_custom_with_sysv_ipc_allowed() {
        let policy = Sandbox::builder()
            .extra_deny_syscalls(vec!["mount".into(), "ptrace".into()])
            .extra_allow_syscalls(vec!["sysv_ipc".into()])
            .build()
            .unwrap();
        let nrs = blocklist_syscall_numbers(&policy);
        // Default blocklist plus user extras — no SysV IPC append.
        assert!(nrs.contains(&(libc::SYS_mount as u32)));
        assert!(nrs.contains(&(libc::SYS_ptrace as u32)));
        assert!(nrs.contains(&(libc::SYS_bpf as u32)));
        assert!(!nrs.contains(&(libc::SYS_shmget as u32)));
    }

    #[test]
    fn test_blocklist_syscall_numbers_default_with_sysv_ipc_allowed() {
        let policy = Sandbox::builder()
            .extra_allow_syscalls(vec!["sysv_ipc".into()])
            .build()
            .unwrap();
        let nrs = blocklist_syscall_numbers(&policy);
        // Default blocklist still present, but SysV IPC is permitted.
        assert!(nrs.contains(&(libc::SYS_mount as u32)));
        assert!(!nrs.contains(&(libc::SYS_shmget as u32)));
        assert!(!nrs.contains(&(libc::SYS_msgget as u32)));
        assert!(!nrs.contains(&(libc::SYS_semget as u32)));
    }

    #[test]
    fn test_no_supervisor_blocklist_includes_sysv_ipc_by_default() {
        let policy = Sandbox::builder().build().unwrap();
        let nrs = no_supervisor_blocklist_syscall_numbers(&policy);
        assert!(nrs.contains(&(libc::SYS_shmget as u32)));
        assert!(nrs.contains(&(libc::SYS_msgget as u32)));
        assert!(nrs.contains(&(libc::SYS_semget as u32)));
    }

    #[test]
    fn test_no_supervisor_blocklist_excludes_sysv_ipc_when_allowed() {
        let policy = Sandbox::builder()
            .extra_allow_syscalls(vec!["sysv_ipc".into()])
            .build()
            .unwrap();
        let nrs = no_supervisor_blocklist_syscall_numbers(&policy);
        assert!(!nrs.contains(&(libc::SYS_shmget as u32)));
        assert!(!nrs.contains(&(libc::SYS_msgget as u32)));
        assert!(!nrs.contains(&(libc::SYS_semget as u32)));
    }

    #[test]
    fn test_arg_filters_has_clone_ioctl_prctl_socket() {
        use crate::sys::structs::{
            BPF_JEQ, BPF_JSET, BPF_JMP, BPF_K,
        };
        let policy = Sandbox::builder().build().unwrap();
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
        // Raw sockets are blocked by default — no `icmp-raw://*` rule.
        let policy = Sandbox::builder().build().unwrap();
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
        // UDP is denied by default — no `udp://...` rule in net_allow.
        let policy = Sandbox::builder().build().unwrap();
        let filters = arg_filters(&policy);
        // Should have JEQ SOCK_DGRAM
        assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
            && f.k == SOCK_DGRAM));
    }

    #[test]
    fn test_syscall_name_to_nr_covers_defaults() {
        // Every name in DEFAULT_BLOCKLIST_SYSCALLS should resolve unless the
        // running architecture does not expose that syscall.
        // `nfsservctl` now resolves: the syscalls crate carries it (kernel
        // returns ENOSYS, but the ABI number exists), so it is enforced in the
        // blocklist rather than silently dropped. `ioperm`/`iopl` are x86-only.
        let expected_unresolved: &[&str] = &[
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            "ioperm",
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            "iopl",
        ];
        let mut skipped = 0;
        for name in DEFAULT_BLOCKLIST_SYSCALLS {
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
