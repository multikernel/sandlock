pub(crate) mod arch;
pub(crate) mod ca_inject;
#[cfg(feature = "checkpoint")]
pub(crate) mod checkpoint;
pub(crate) mod chroot;
pub mod context;
pub mod control;
pub mod controller;
#[cfg(feature = "cow")]
pub(crate) mod cow;
#[cfg(feature = "http")]
pub(crate) mod credential;
#[cfg(not(feature = "http"))]
#[path = "credential_disabled.rs"]
pub(crate) mod credential;
pub mod error;
pub mod expand;
pub mod fork;
pub(crate) mod freeze;
pub mod http;
#[cfg(feature = "image")]
pub mod image;
pub mod landlock;
pub mod netlink;
pub(crate) mod network;
pub(crate) mod pgroup;
pub mod pipeline;
pub mod policy_fn;
pub(crate) mod port_remap;
pub(crate) mod procfs;
pub mod profile;
pub mod protection;
pub(crate) mod random;
pub(crate) mod reaper;
#[cfg(feature = "cow")]
pub mod recovery;
pub(crate) mod resolved;
pub(crate) mod resource;
pub mod result;
pub mod sandbox; // formerly `policy`; contains Sandbox + SandboxBuilder + Confinement
pub mod seccomp;
pub(crate) mod seccomp_plan;
pub(crate) mod sys;
pub(crate) mod time;
#[cfg(feature = "cow")]
pub mod transaction;
#[cfg(feature = "http")]
mod transparent_proxy;
#[cfg(not(feature = "http"))]
#[path = "transparent_proxy/disabled.rs"]
mod transparent_proxy;
pub(crate) mod vdso;

#[cfg(feature = "checkpoint")]
pub use checkpoint::{Checkpoint, SkippedFd};
pub use controller::Controller;
pub use error::SandlockError;
pub use pipeline::{Gather, Pipeline, Stage};
pub use policy_fn::PolicyFn;
pub use protection::{Protection, ProtectionPolicy, ProtectionState, ProtectionStatus};
pub use result::{renames, Change, ChangeKind, Entry, EntryKind, ExitStatus, RunResult};
pub use sandbox::{
    BindPorts, Confinement, ConfinementBuilder, Process, Sandbox, SandboxBuilder, StdioMode,
};
pub use sys::structs::{SeccompData, SeccompNotif};
#[cfg(feature = "cow")]
pub use transaction::{AbortReason, Transaction, TxnDisposition, TxnError, TxnOutcome};
// Recovery of COW branch storage that was preserved rather than reclaimed. The
// rest of `cow` is internal; the `recovery` module is the backend-neutral path
// these belong to, and the flat aliases here are kept for convenience.
#[cfg(feature = "cow")]
pub use recovery::{list_preserved, read_preserved, PreserveReason, PreservedBranch};
// Sectioned-profile parsing types: ProfileInput is the top-level deserialization
// target; ProgramSpec carries [program].exec/args (not a Sandbox field).
// format_net_rule renders a NetRule back into the --net-allow/--net-deny
// grammar (the CLI round-trips profiles through it); the other reverse
// serializers live unre-exported in `profile`.
pub use crate::profile::{format_net_rule, ProfileInput, ProgramSpec};

// Public extension API — see docs/extension-handlers.md.
pub use seccomp::dispatch::{Handler, HandlerCtx, HandlerError};
pub use seccomp::syscall::{Syscall, SyscallError};

/// Query the Landlock ABI version supported by the running kernel.
pub fn landlock_abi_version() -> Result<u32, error::ConfinementError> {
    landlock::abi_version()
}

/// Minimum Landlock ABI version required by sandlock.
pub const MIN_LANDLOCK_ABI: u32 = landlock::MIN_ABI;

/// Confine the calling process with Landlock restrictions.
///
/// This applies `PR_SET_NO_NEW_PRIVS` and Landlock rules from the sandbox's
/// filesystem fields. IPC and signal isolation are always enabled. The
/// confinement is **irreversible**.
///
/// This does NOT fork or exec — it confines the current process in-place.
pub fn confine(confinement: &Confinement) -> Result<(), SandlockError> {
    // Set NO_NEW_PRIVS (required for Landlock)
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(SandlockError::Runtime(
            error::SandboxRuntimeError::Confinement(error::ConfinementError::Landlock(format!(
                "prctl(PR_SET_NO_NEW_PRIVS): {}",
                std::io::Error::last_os_error()
            ))),
        ));
    }

    let mut builder = Sandbox::builder();
    for path in &confinement.fs_readable {
        builder = builder.fs_read(path.clone());
    }
    for path in &confinement.fs_writable {
        builder = builder.fs_write(path.clone());
    }
    let stripped = builder.build()?;

    // Apply Landlock filesystem rules.
    landlock::confine_filesystem(&stripped)
}
