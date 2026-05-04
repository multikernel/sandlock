//! `Syscall` — checked syscall number newtype.
//!
//! Closes the footgun where `add_handler(-5, h)` would compile but
//! silently never fire because the cBPF filter cannot emit a JEQ for
//! an architecture-unknown syscall number.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SyscallError {
    #[error("syscall number {0} is negative")]
    Negative(i64),
    #[error("syscall number {0} is unknown for the current architecture")]
    UnknownForArch(i64),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Syscall(i64);

impl Syscall {
    /// Validates that `nr` is non-negative and known on the current architecture.
    pub fn checked(nr: i64) -> Result<Self, SyscallError> {
        if nr < 0 {
            return Err(SyscallError::Negative(nr));
        }
        if !crate::arch::is_known_syscall(nr) {
            return Err(SyscallError::UnknownForArch(nr));
        }
        Ok(Self(nr))
    }

    pub fn raw(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for Syscall {
    type Error = SyscallError;
    fn try_from(nr: i64) -> Result<Self, Self::Error> {
        Self::checked(nr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_accepts_valid_openat() {
        let s = Syscall::checked(libc::SYS_openat).expect("openat is valid");
        assert_eq!(s.raw(), libc::SYS_openat);
    }

    #[test]
    fn checked_rejects_negative() {
        match Syscall::checked(-5) {
            Err(SyscallError::Negative(-5)) => {}
            other => panic!("expected Negative(-5), got {:?}", other),
        }
    }

    #[test]
    fn checked_rejects_arch_unknown() {
        // 99_999 is above any reasonable MAX_SYSCALL_NR.
        match Syscall::checked(99_999) {
            Err(SyscallError::UnknownForArch(99_999)) => {}
            other => panic!("expected UnknownForArch(99_999), got {:?}", other),
        }
    }

    #[test]
    fn try_from_i64_delegates_to_checked() {
        let s: Syscall = libc::SYS_openat.try_into().expect("openat valid");
        assert_eq!(s.raw(), libc::SYS_openat);
        let bad: Result<Syscall, _> = (-1i64).try_into();
        assert!(matches!(bad, Err(SyscallError::Negative(-1))));
    }
}
