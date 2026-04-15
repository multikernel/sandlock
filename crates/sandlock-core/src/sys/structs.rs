// Kernel struct definitions matching ABI exactly for x86_64

// ============================================================
// Landlock structs
// ============================================================

/// Ruleset attributes for landlock_create_ruleset (24 bytes)
#[repr(C)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub scoped: u64,
}

/// Path beneath attribute for landlock_add_rule (12 bytes, packed)
#[repr(C, packed)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

/// Network port attribute for landlock_add_rule (16 bytes)
#[repr(C)]
pub struct LandlockNetPortAttr {
    pub allowed_access: u64,
    pub port: u64,
}

// ============================================================
// Seccomp structs
// ============================================================

/// Seccomp BPF data passed to filters (64 bytes)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// Seccomp user notification (80 bytes)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// Seccomp user notification response (24 bytes)
#[repr(C)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// Seccomp add file descriptor (24 bytes)
#[repr(C)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

/// BPF filter instruction
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// BPF filter program
#[repr(C)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

// SAFETY: SockFprog is only used in single-threaded syscall context
unsafe impl Send for SockFprog {}
unsafe impl Sync for SockFprog {}

// ============================================================
// Landlock syscall numbers
// ============================================================

pub const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
pub const SYS_LANDLOCK_ADD_RULE: i64 = 445;
pub const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

// ============================================================
// Landlock FS access flags (bits 0-15)
// ============================================================

pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
pub const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

// ============================================================
// Landlock net access flags
// ============================================================

pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

// ============================================================
// Landlock rule types
// ============================================================

pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
pub const LANDLOCK_RULE_NET_PORT: u32 = 2;

// ============================================================
// Landlock scope flags
// ============================================================

pub const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
pub const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

// ============================================================
// Seccomp constants
// ============================================================

pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 1 << 3;
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u64 = 1 << 5;
pub const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7FC0_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
pub const SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP: u32 = 1;
/// Atomically install the fd and respond to the syscall (Linux 5.14+).
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;

// ============================================================
// Seccomp ioctl commands
// ============================================================

pub const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0xc050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xc018_2101;
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = 0x4008_2102;
pub const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = 0xc018_2103;
pub const SECCOMP_IOCTL_NOTIF_SET_FLAGS: u64 = 0x4008_2104;

// ============================================================
// Architecture
// ============================================================

pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// ============================================================
// BPF opcodes
// ============================================================

pub const BPF_LD: u16 = 0x00;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;
pub const BPF_RET: u16 = 0x06;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_AND: u16 = 0x50;

// ============================================================
// seccomp_data field offsets
// ============================================================

pub const OFFSET_NR: u32 = 0;
pub const OFFSET_ARCH: u32 = 4;
pub const OFFSET_ARGS0_LO: u32 = 16;
pub const OFFSET_ARGS1_LO: u32 = 24;
pub const OFFSET_ARGS2_LO: u32 = 32;
pub const OFFSET_ARGS3_LO: u32 = 40;

// ============================================================
// Clone namespace flags
// ============================================================

pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;

pub const CLONE_NS_FLAGS: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET;

// ============================================================
// Dangerous ioctls
// ============================================================

pub const TIOCSTI: u64 = 0x5412;
pub const TIOCLINUX: u64 = 0x541C;

// ============================================================
// Dangerous prctl options
// ============================================================

pub const PR_SET_DUMPABLE: u32 = 4;
pub const PR_SET_SECUREBITS: u32 = 28;
pub const PR_SET_PTRACER: u32 = 0x5961_6d61;

// ============================================================
// Socket constants
// ============================================================

pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_TYPE_MASK: u32 = 0xFF;

// ============================================================
// Errno values
// ============================================================

pub const EPERM: i32 = 1;
pub const EACCES: i32 = 13;
pub const ENOMEM: i32 = 12;
pub const EAGAIN: i32 = 11;
pub const ECONNREFUSED: i32 = 111;

// ============================================================
// Default deny syscall list
// ============================================================

pub const DEFAULT_DENY_SYSCALLS: &[&str] = &[
    "mount",
    "umount2",
    "pivot_root",
    "swapon",
    "swapoff",
    "reboot",
    "sethostname",
    "setdomainname",
    "kexec_load",
    "init_module",
    "finit_module",
    "delete_module",
    "unshare",
    "setns",
    "perf_event_open",
    "bpf",
    "userfaultfd",
    "keyctl",
    "add_key",
    "request_key",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "open_by_handle_at",
    "name_to_handle_at",
    "ioperm",
    "iopl",
    "quotactl",
    "acct",
    "lookup_dcookie",
    "nfsservctl",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "personality",
];

/// Deny list for --no-supervisor mode.
///
/// More relaxed than DEFAULT_DENY_SYSCALLS because a full sandbox supervisor
/// may run inside the outer no-supervisor sandbox and needs syscalls like
/// ptrace, process_vm_readv/writev, unshare, mount, and setns.
///
/// Only blocks syscalls that could damage the host or escape all containment.
pub const NO_SUPERVISOR_DENY_SYSCALLS: &[&str] = &[
    // Swap / reboot / shutdown — host-wide damage
    "swapon",
    "swapoff",
    "reboot",
    "kexec_load",
    // Kernel modules — arbitrary kernel code execution
    "init_module",
    "finit_module",
    "delete_module",
    // Kernel introspection / attack surface
    "perf_event_open",
    "bpf",
    // Direct hardware access
    "ioperm",
    "iopl",
    // io_uring bypasses seccomp for I/O operations
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];
