//! Per-protection ABI floor for Landlock protections.
//!
//! Sandlock relies on a set of Landlock-provided protections, each
//! introduced in a specific Landlock ABI version. This module names
//! them as `Protection` variants and maps each to the minimum ABI the
//! host kernel must support.
//!
//! The actual policy that decides whether a protection is enforced,
//! degraded, or disabled lives in the higher-level
//! `ProtectionPolicy` (also in this module). The decision-vs-availability
//! resolution happens in `landlock::confine_inner`.

/// A single Landlock-provided protection, ABI-gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protection {
    /// `LANDLOCK_ACCESS_FS_REFER` — ABI v2+.
    FsRefer,
    /// `LANDLOCK_ACCESS_FS_TRUNCATE` — ABI v3+.
    FsTruncate,
    /// `LANDLOCK_ACCESS_NET_BIND_TCP` / `_CONNECT_TCP` — ABI v4+.
    NetTcp,
    /// `LANDLOCK_ACCESS_FS_IOCTL_DEV` — ABI v5+.
    FsIoctlDev,
    /// `LANDLOCK_SCOPE_SIGNAL` — ABI v6+.
    SignalScope,
    /// `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` — ABI v6+.
    AbstractUnixScope,
}

impl Protection {
    /// Minimum Landlock ABI version the host kernel must support for
    /// this protection to be available.
    pub const fn min_abi(self) -> u32 {
        match self {
            Protection::FsRefer => 2,
            Protection::FsTruncate => 3,
            Protection::NetTcp => 4,
            Protection::FsIoctlDev => 5,
            Protection::SignalScope => 6,
            Protection::AbstractUnixScope => 6,
        }
    }

    /// Iterator over every known protection.
    pub fn all() -> impl Iterator<Item = Protection> {
        [
            Protection::FsRefer,
            Protection::FsTruncate,
            Protection::NetTcp,
            Protection::FsIoctlDev,
            Protection::SignalScope,
            Protection::AbstractUnixScope,
        ]
        .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_abi_matches_kernel_documented_floors() {
        // These numbers come from the kernel Landlock documentation
        // (https://docs.kernel.org/userspace-api/landlock.html);
        // they MUST NOT drift.
        assert_eq!(Protection::FsRefer.min_abi(), 2);
        assert_eq!(Protection::FsTruncate.min_abi(), 3);
        assert_eq!(Protection::NetTcp.min_abi(), 4);
        assert_eq!(Protection::FsIoctlDev.min_abi(), 5);
        assert_eq!(Protection::SignalScope.min_abi(), 6);
        assert_eq!(Protection::AbstractUnixScope.min_abi(), 6);
    }

    #[test]
    fn all_iterates_every_variant_exactly_once() {
        let collected: Vec<Protection> = Protection::all().collect();
        assert_eq!(collected.len(), 6);
        // No duplicates.
        for p in &collected {
            assert_eq!(collected.iter().filter(|&q| q == p).count(), 1);
        }
    }
}
