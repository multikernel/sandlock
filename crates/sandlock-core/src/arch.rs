//! Architecture-specific seccomp helpers.
//!
//! Syscall numbers come from the `syscalls` crate (generated from the kernel
//! ABI tables). The only genuinely per-architecture datum that the crate does
//! not provide is `AUDIT_ARCH` (a `linux/audit.h` token, not a syscall
//! number), so that is the sole hand-maintained per-arch constant here.

use syscalls::Sysno;

// Numbers for syscalls that exist on every architecture Sandlock targets, so a
// single definition resolves to the correct per-arch number at compile time.
// The `tests` module pins the resolved values to the historical constants.
pub const SYS_FACCESSAT2: i64 = Sysno::faccessat2 as i64;
pub const SYS_OPENAT2: i64 = Sysno::openat2 as i64;
pub const SYS_SECCOMP: i64 = Sysno::seccomp as i64;
pub const SYS_MEMFD_CREATE: i64 = Sysno::memfd_create as i64;
pub const SYS_PIDFD_OPEN: i64 = Sysno::pidfd_open as i64;
pub const SYS_PIDFD_GETFD: i64 = Sysno::pidfd_getfd as i64;

#[cfg(target_arch = "x86_64")]
mod imp {
    pub const AUDIT_ARCH: u32 = 0xC000_003E;
}

#[cfg(target_arch = "aarch64")]
mod imp {
    pub const AUDIT_ARCH: u32 = 0xC000_00B7;
}

#[cfg(target_arch = "riscv64")]
mod imp {
    // AUDIT_ARCH_RISCV64 = EM_RISCV(243) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
    pub const AUDIT_ARCH: u32 = 0xC000_00F3;
}

pub use imp::*;

/// Resolve a syscall name to its number on the current architecture, or `None`
/// if this architecture's ABI does not provide it.
fn sysno(name: &str) -> Option<i64> {
    name.parse::<Sysno>().ok().map(|s| s.id() as i64)
}

macro_rules! legacy_syscall {
    ($fn:ident, $name:literal) => {
        #[doc = concat!(
            "`", $name, "` syscall number on this architecture, or `None` if ",
            "the generic syscall ABI (aarch64, riscv64) omits it."
        )]
        pub fn $fn() -> Option<i64> {
            sysno($name)
        }
    };
}

// Legacy (pre-generic-ABI) syscalls: present on x86_64, absent on the
// generic-ABI architectures. Presence is derived from the crate's per-arch
// tables rather than hand-maintained.
legacy_syscall!(sys_open, "open");
legacy_syscall!(sys_stat, "stat");
legacy_syscall!(sys_lstat, "lstat");
legacy_syscall!(sys_access, "access");
legacy_syscall!(sys_readlink, "readlink");
legacy_syscall!(sys_getdents, "getdents");
legacy_syscall!(sys_unlink, "unlink");
legacy_syscall!(sys_rmdir, "rmdir");
legacy_syscall!(sys_mkdir, "mkdir");
legacy_syscall!(sys_rename, "rename");
legacy_syscall!(sys_symlink, "symlink");
legacy_syscall!(sys_link, "link");
legacy_syscall!(sys_chmod, "chmod");
legacy_syscall!(sys_chown, "chown");
legacy_syscall!(sys_lchown, "lchown");
legacy_syscall!(sys_vfork, "vfork");
legacy_syscall!(sys_fork, "fork");

/// Fork-class syscalls present on this architecture: `clone`/`clone3` always,
/// plus `fork`/`vfork` only where the legacy ABI provides them. Single source
/// of truth for callers enumerating fork-class syscalls (BPF notif
/// registration in `seccomp::dispatch`, classification in
/// `resource::is_process_creation_notif`).
pub fn fork_like_syscalls() -> Vec<i64> {
    ["clone", "clone3", "vfork", "fork"]
        .into_iter()
        .filter_map(sysno)
        .collect()
}

/// True if `nr` is a real syscall number on the current architecture.
/// Used by [`crate::seccomp::syscall::Syscall::checked`] to reject foot-gun
/// cases like negative or arch-mismatched numbers.
///
/// Exact: backed by the `syscalls` crate's per-arch table, so unassigned
/// numbers within the table's range are rejected too (unlike a bare range
/// check against the highest known number).
pub fn is_known_syscall(nr: i64) -> bool {
    nr >= 0 && Sysno::new(nr as usize).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the crate-sourced syscall numbers to the values Sandlock used
    /// before adopting the crate, per architecture. A divergence here means a
    /// crate upgrade changed an ABI number out from under the seccomp filters.
    #[test]
    fn crate_sourced_consts_match_historical_values() {
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(SYS_SECCOMP, 317);
            assert_eq!(SYS_MEMFD_CREATE, 319);
            assert_eq!(SYS_PIDFD_OPEN, 434);
            assert_eq!(SYS_PIDFD_GETFD, 438);
            assert_eq!(SYS_OPENAT2, 437);
            assert_eq!(SYS_FACCESSAT2, 439);
        }
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        {
            assert_eq!(SYS_SECCOMP, 277);
            assert_eq!(SYS_MEMFD_CREATE, 279);
            assert_eq!(SYS_PIDFD_OPEN, 434);
            assert_eq!(SYS_PIDFD_GETFD, 438);
            assert_eq!(SYS_OPENAT2, 437);
            assert_eq!(SYS_FACCESSAT2, 439);
        }
    }

    /// The legacy-syscall accessors must reflect this arch's ABI: present on
    /// x86_64, absent on the generic-ABI arches.
    #[test]
    fn legacy_accessors_match_arch() {
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(sys_open(), Some(libc::SYS_open));
            assert_eq!(sys_fork(), Some(libc::SYS_fork));
            assert_eq!(sys_vfork(), Some(libc::SYS_vfork));
            assert_eq!(
                fork_like_syscalls(),
                vec![
                    libc::SYS_clone,
                    libc::SYS_clone3,
                    libc::SYS_vfork,
                    libc::SYS_fork
                ]
            );
        }
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        {
            assert_eq!(sys_open(), None);
            assert_eq!(sys_fork(), None);
            assert_eq!(sys_vfork(), None);
            assert_eq!(fork_like_syscalls(), vec![libc::SYS_clone, libc::SYS_clone3]);
        }
    }

    #[test]
    fn is_known_syscall_accepts_real_and_rejects_bogus() {
        assert!(is_known_syscall(libc::SYS_openat));
        assert!(is_known_syscall(libc::SYS_clone));
        assert!(!is_known_syscall(-1));
        assert!(!is_known_syscall(99_999));
    }
}
