//! Architecture-specific syscall and seccomp helpers.

#[cfg(target_arch = "x86_64")]
mod imp {
    pub const AUDIT_ARCH: u32 = 0xC000_003E;
    pub const SYS_SECCOMP: i64 = 317;
    pub const SYS_MEMFD_CREATE: i64 = 319;
    pub const SYS_PIDFD_OPEN: i64 = 434;
    pub const SYS_PIDFD_GETFD: i64 = 438;

    pub const SYS_OPEN: Option<i64> = Some(libc::SYS_open);
    pub const SYS_STAT: Option<i64> = Some(libc::SYS_stat);
    pub const SYS_LSTAT: Option<i64> = Some(libc::SYS_lstat);
    pub const SYS_ACCESS: Option<i64> = Some(libc::SYS_access);
    pub const SYS_READLINK: Option<i64> = Some(libc::SYS_readlink);
    pub const SYS_GETDENTS: Option<i64> = Some(libc::SYS_getdents);
    pub const SYS_UNLINK: Option<i64> = Some(libc::SYS_unlink);
    pub const SYS_RMDIR: Option<i64> = Some(libc::SYS_rmdir);
    pub const SYS_MKDIR: Option<i64> = Some(libc::SYS_mkdir);
    pub const SYS_RENAME: Option<i64> = Some(libc::SYS_rename);
    pub const SYS_SYMLINK: Option<i64> = Some(libc::SYS_symlink);
    pub const SYS_LINK: Option<i64> = Some(libc::SYS_link);
    pub const SYS_CHMOD: Option<i64> = Some(libc::SYS_chmod);
    pub const SYS_CHOWN: Option<i64> = Some(libc::SYS_chown);
    pub const SYS_LCHOWN: Option<i64> = Some(libc::SYS_lchown);
    pub const SYS_VFORK: Option<i64> = Some(libc::SYS_vfork);
    pub const SYS_FUTIMESAT: Option<i64> = Some(libc::SYS_futimesat);
    pub const SYS_FORK: Option<i64> = Some(libc::SYS_fork);
    pub const SYS_IOPERM: Option<i64> = Some(libc::SYS_ioperm);
    pub const SYS_IOPL: Option<i64> = Some(libc::SYS_iopl);
    pub const SYS_TIME: Option<i64> = Some(libc::SYS_time);

    /// Every syscall the kernel will dispatch through `handle_fork`.
    /// Single source of truth for callers that enumerate fork-class
    /// syscalls (BPF notif registration in `seccomp::dispatch`,
    /// classification in `resource::is_process_creation_notif`).
    pub const FORK_LIKE_SYSCALLS: &[i64] = &[
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_vfork,
        libc::SYS_fork,
    ];
}

#[cfg(target_arch = "aarch64")]
mod imp {
    pub const AUDIT_ARCH: u32 = 0xC000_00B7;
    pub const SYS_SECCOMP: i64 = 277;
    pub const SYS_MEMFD_CREATE: i64 = 279;
    pub const SYS_PIDFD_OPEN: i64 = 434;
    pub const SYS_PIDFD_GETFD: i64 = 438;

    pub const SYS_OPEN: Option<i64> = None;
    pub const SYS_STAT: Option<i64> = None;
    pub const SYS_LSTAT: Option<i64> = None;
    pub const SYS_ACCESS: Option<i64> = None;
    pub const SYS_READLINK: Option<i64> = None;
    pub const SYS_GETDENTS: Option<i64> = None;
    pub const SYS_UNLINK: Option<i64> = None;
    pub const SYS_RMDIR: Option<i64> = None;
    pub const SYS_MKDIR: Option<i64> = None;
    pub const SYS_RENAME: Option<i64> = None;
    pub const SYS_SYMLINK: Option<i64> = None;
    pub const SYS_LINK: Option<i64> = None;
    pub const SYS_CHMOD: Option<i64> = None;
    pub const SYS_CHOWN: Option<i64> = None;
    pub const SYS_LCHOWN: Option<i64> = None;
    pub const SYS_VFORK: Option<i64> = None;
    pub const SYS_FUTIMESAT: Option<i64> = None;
    pub const SYS_FORK: Option<i64> = None;
    pub const SYS_IOPERM: Option<i64> = None;
    pub const SYS_IOPL: Option<i64> = None;
    pub const SYS_TIME: Option<i64> = None;

    /// Every syscall the kernel will dispatch through `handle_fork`.
    /// aarch64 has no `fork`/`vfork` (glibc emulates via `clone`).
    pub const FORK_LIKE_SYSCALLS: &[i64] = &[
        libc::SYS_clone,
        libc::SYS_clone3,
    ];
}

pub use imp::*;

pub fn push_optional_syscall(v: &mut Vec<u32>, nr: Option<i64>) {
    if let Some(nr) = nr {
        v.push(nr as u32);
    }
}
