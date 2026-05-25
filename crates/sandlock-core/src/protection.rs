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

use std::collections::HashMap;

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

/// What a `ProtectionPolicy` instructs sandlock to do with a given
/// `Protection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionState {
    /// Enforce; if the host kernel cannot provide this protection,
    /// `confine_inner` returns an error naming the protection and the
    /// kernel's actual ABI version. This is the default for every
    /// protection.
    Strict,
    /// Enforce where the host kernel supports it; skip silently when
    /// it does not. The skip is observable via `Sandbox::active_protections()`
    /// and `sandlock check`.
    Degradable,
    /// Never enforce, even on a host kernel that supports the protection.
    /// Intended for workloads that genuinely need the capability the
    /// protection blocks.
    Disabled,
}

/// Per-`Protection` state collection. The default for any protection
/// not explicitly named is `ProtectionState::Strict` — meaning a
/// freshly-constructed `ProtectionPolicy` produces the same behaviour
/// as the current hard `MIN_ABI = 6` floor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtectionPolicy {
    states: HashMap<Protection, ProtectionState>,
}

impl ProtectionPolicy {
    /// A policy with no overrides — every protection defaults to
    /// `Strict`. Equivalent to the pre-Protection behaviour.
    pub fn strict_all() -> Self {
        Self::default()
    }

    /// Look up the state for a given protection. Returns `Strict`
    /// for protections not explicitly named.
    pub fn state(&self, protection: Protection) -> ProtectionState {
        self.states.get(&protection).copied().unwrap_or(ProtectionState::Strict)
    }

    /// Set the state for a single protection. Internal API — public
    /// builder methods (in the polarity-dependent layer landing later)
    /// call this. Marked `#[doc(hidden)] pub` so integration tests in
    /// the `tests/` directory can drive the resolver directly; not part
    /// of the stable public surface.
    #[doc(hidden)]
    pub fn set(&mut self, protection: Protection, state: ProtectionState) {
        self.states.insert(protection, state);
    }

    /// Iterator over every protection paired with its resolved state
    /// (including the implicit `Strict` for unnamed ones).
    pub fn iter(&self) -> impl Iterator<Item = (Protection, ProtectionState)> + '_ {
        Protection::all().map(|p| (p, self.state(p)))
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn strict_all_returns_strict_for_every_protection() {
        let pol = ProtectionPolicy::strict_all();
        for p in Protection::all() {
            assert_eq!(pol.state(p), ProtectionState::Strict);
        }
    }

    #[test]
    fn unnamed_protections_default_to_strict_even_after_other_overrides() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::SignalScope, ProtectionState::Degradable);
        assert_eq!(pol.state(Protection::SignalScope), ProtectionState::Degradable);
        assert_eq!(pol.state(Protection::FsTruncate), ProtectionState::Strict);
        assert_eq!(pol.state(Protection::AbstractUnixScope), ProtectionState::Strict);
    }

    #[test]
    fn iter_yields_every_protection_with_resolved_state() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::FsIoctlDev, ProtectionState::Disabled);
        let collected: Vec<_> = pol.iter().collect();
        assert_eq!(collected.len(), 6);
        assert!(collected.iter().any(|(p, s)| *p == Protection::FsIoctlDev && *s == ProtectionState::Disabled));
        for (p, s) in &collected {
            if *p != Protection::FsIoctlDev {
                assert_eq!(*s, ProtectionState::Strict, "{:?} should default to Strict", p);
            }
        }
    }
}
