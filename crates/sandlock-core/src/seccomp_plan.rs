//! Seccomp syscall and argument-filter planning.
//!
//! This module turns the normalized sandbox feature view into the concrete
//! syscall notification lists, blocklists, and BPF argument filters installed
//! by the child-side confinement path.

use syscalls::{Sysno, SysnoSet};

use crate::arch;
use crate::resolved::ResolvedSandbox;
use crate::sandbox::Sandbox;
use crate::seccomp::bpf::{jump, stmt};
use crate::sys::structs::{
    AF_INET, AF_INET6, BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K,
    BPF_LD, BPF_RET, BPF_W, CLONE_NS_FLAGS, DEFAULT_BLOCKLIST_SYSCALLS, EPERM,
    OFFSET_ARGS0_LO, OFFSET_ARGS1_LO, OFFSET_ARGS2_LO, OFFSET_ARGS3_LO, OFFSET_NR,
    PR_SET_DUMPABLE, PR_SET_PTRACER, PR_SET_SECUREBITS, SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO, SIOCETHTOOL, SIOCGIFADDR, SIOCGIFBRDADDR, SIOCGIFCONF,
    SIOCGIFDSTADDR, SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFINDEX, SIOCGIFNAME,
    SIOCGIFNETMASK, SOCK_DGRAM, SOCK_RAW, SOCK_TYPE_MASK, SYSV_IPC_BLOCKLIST_SYSCALLS,
    TIOCLINUX, TIOCSTI, SockFilter,
};

// ============================================================
// Sandbox -> syscall lists
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
        // no mediation; their fd already points at the resolved file.
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

/// Determine which syscalls need `SECCOMP_RET_USER_NOTIF`.
pub(crate) fn notif_syscalls(policy: &Sandbox, sandbox_name: Option<&str>) -> Vec<u32> {
    let resolved = ResolvedSandbox::from_sandbox(policy, sandbox_name, &[]);
    notif_syscalls_resolved(&resolved)
}

/// Determine which syscalls need `SECCOMP_RET_USER_NOTIF` from the resolved
/// internal feature view.
pub(crate) fn notif_syscalls_resolved(resolved: &ResolvedSandbox) -> Vec<u32> {
    let features = &resolved.features;
    let mut nrs = SyscallList::with(BASE_NOTIF_SYSCALLS);
    nrs.push_optional(arch::sys_vfork());

    // Bare fork(2) carries none of the namespace/process-limit risk of
    // clone/clone3 and was historically left out of the BPF filter so
    // hot fork-loops (COW map-reduce) bypass the supervisor entirely.
    // It only needs interception when argv safety is required, so the
    // supervisor can register the new child via ptrace fork events before
    // user code can mutate argv observed by policy_fn or exec handlers.
    if features.argv_safety_required {
        nrs.push_optional(arch::sys_fork());
    }

    if features.memory_limit {
        nrs.extend(MEMORY_NOTIF_SYSCALLS);
        // shmget is in notif only when SysV IPC is allowed. The BPF
        // layout puts notif JEQs before deny JEQs, so a syscall on
        // both lists would notify (RET_USER_NOTIF) and silently
        // bypass the kernel-level deny. When extra_allow_syscalls does not contain "sysv_ipc",
        // shmget belongs only on the blocklist.
        if features.sysv_ipc_allowed {
            nrs.push(libc::SYS_shmget);
        }
    }

    if features.network_supervision {
        nrs.extend(NETWORK_POLICY_SYSCALLS);
    } else if features.unix_fs_gate {
        // Named-unix gate: trap connect() (stream) and sendto()/sendmsg()
        // (datagram) so reaching a unix socket outside the fs-write grants is
        // denied, even when no IP network rules are present. Landlock cannot
        // gate this. Handlers bail cheaply on addr-less (connected) sends.
        nrs.push(libc::SYS_connect);
        nrs.push(libc::SYS_sendto);
        nrs.push(libc::SYS_sendmsg);
    }

    if features.random_seed {
        nrs.extend(RANDOM_NOTIF_SYSCALLS);
    }

    if features.time_start {
        nrs.extend(TIME_NOTIF_SYSCALLS);
    }

    nrs.extend(&procfs_hosts_notif_syscalls());
    nrs.extend(NETLINK_NOTIF_SYSCALLS);

    // Virtualize sched_getaffinity so nproc/sysconf agree with /proc/cpuinfo
    if features.virtual_cpu_count {
        nrs.push(libc::SYS_sched_getaffinity);
    }
    if features.virtual_hostname {
        nrs.extend(&[libc::SYS_uname, libc::SYS_openat]);
    }

    // COW filesystem interception (seccomp-based, unprivileged)
    if features.cow {
        nrs.extend(&cow_path_syscalls());
    }

    // Chroot path interception
    if features.chroot {
        nrs.extend(&chroot_path_syscalls());
    }

    // Explicit deny-paths need path-bearing syscalls intercepted.
    if features.fs_denies {
        nrs.extend(&fs_denied_path_syscalls());
    }

    // Dynamic policy callback: intercept key syscalls for event emission.
    if features.policy_fn {
        nrs.extend(POLICY_EVENT_SYSCALLS);
    }

    // Port remapping
    if features.port_remap {
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
pub(crate) fn no_supervisor_blocklist_syscall_numbers(policy: &Sandbox) -> Vec<u32> {
    use crate::sys::structs::NO_SUPERVISOR_BLOCKLIST_SYSCALLS;
    resolve_blocklist(NO_SUPERVISOR_BLOCKLIST_SYSCALLS, policy)
}

/// Resolve the default syscall blocklist plus policy extras to numbers.
///
/// SysV IPC syscalls are appended to the resolved blocklist when
/// `policy.allows_sysv_ipc()` is false.
pub(crate) fn blocklist_syscall_numbers(policy: &Sandbox) -> Vec<u32> {
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
pub(crate) fn arg_filters(policy: &Sandbox) -> Vec<SockFilter> {
    let resolved = ResolvedSandbox::from_sandbox(policy, None, &[]);
    arg_filters_resolved(&resolved)
}

pub(crate) fn arg_filters_resolved(resolved: &ResolvedSandbox) -> Vec<SockFilter> {
    let features = &resolved.features;
    let ret_errno = SECCOMP_RET_ERRNO | EPERM as u32;
    let nr_clone = libc::SYS_clone as u32;
    let nr_ioctl = libc::SYS_ioctl as u32;
    let nr_prctl = libc::SYS_prctl as u32;
    let nr_socket = libc::SYS_socket as u32;

    let mut insns: Vec<SockFilter> = Vec::new();

    // --- clone: block namespace creation flags ---
    // 5 instructions:
    //   LD NR
    //   JEQ clone -> +0, skip 3
    //   LD arg0
    //   JSET NS_FLAGS -> +0, skip 1
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
    // raw ICMP: packet-crafting capabilities aren't part of the XOA
    // threat model, and destination filtering at `sendto` can't be
    // honestly enforced for raw sockets (the agent controls the IP
    // header). Workloads that need ping should use the kernel ping
    // socket (SOCK_DGRAM + IPPROTO_ICMP) via an `icmp://...` rule.
    //
    // SOCK_DGRAM is denied unless a UDP or ICMP rule exists in
    // net_allow. The kernel ping socket uses SOCK_DGRAM with
    // IPPROTO_ICMP, so the same type bit gates both; destination
    // filtering at sendto (Phase 2) is what separates them per-rule.
    // `--net-deny` is default-allow, so UDP and the kernel ping socket
    // (both SOCK_DGRAM) must be creatable; without this the sandbox
    // could not even do DNS over UDP. Per-destination UDP/ICMP denial
    // is still enforced on the sendto on-behalf path via the DenyList.
    let mut blocked_types: Vec<u32> = Vec::new();
    blocked_types.push(SOCK_RAW);
    if !features.udp_or_icmp_allowed && !features.net_deny {
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
        // AF_INET -> skip to type check (jump over AF_INET6 check)
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 1, 0));
        // AF_INET6 -> type check; else skip everything remaining
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, after_domain as u8));
        // Load type (arg1) and mask off SOCK_NONBLOCK|SOCK_CLOEXEC
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS1_LO));
        insns.push(stmt(BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK));
        // Check each blocked type
        for (i, &sock_type) in blocked_types.iter().enumerate() {
            let remaining = n - i - 1;
            // Match -> jump to RET ERRNO (skip 'remaining' JEQs ahead)
            // No match on last type -> skip past RET ERRNO (jf=1)
            // No match on non-last -> check next type (jf=0)
            let jf: u8 = if remaining == 0 { 1 } else { 0 };
            insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, sock_type, remaining as u8, jf));
        }
        // Deny return (reached by any matching JEQ)
        insns.push(stmt(BPF_RET | BPF_K, ret_errno));
    }

    // (raw ICMP carve-out removed: SOCK_RAW is unconditionally denied
    // by the blocked_types block above. Sandlock does not expose raw
    // sockets; ping uses the SOCK_DGRAM kernel ping socket via an
    // `icmp://...` rule, gated by host `ping_group_range`.)

    // --- wait4: skip notification for WNOHANG/WNOWAIT (non-blocking) ---
    // wait4(pid, status, options, rusage): options is arg2
    // 5 instructions:
    //   LD NR
    //   JEQ wait4 -> +0, skip 3
    //   LD arg2
    //   JSET (WNOHANG|WNOWAIT) -> +0, skip 1
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
    // waitid(idtype, id, infop, options, rusage): options is arg3
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
