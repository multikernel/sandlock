pub mod error;
pub mod policy;
pub mod profile;
pub mod result;
pub mod sandbox;
pub(crate) mod arch;
pub(crate) mod sys;
pub mod landlock;
pub mod seccomp;
pub(crate) mod resource;
pub(crate) mod network;
pub mod context;
pub(crate) mod vdso;
pub(crate) mod random;
pub(crate) mod time;
pub(crate) mod cow;
pub(crate) mod checkpoint;
pub(crate) mod sandbox_freeze;
pub mod netlink;
pub(crate) mod procfs;
pub(crate) mod port_remap;
pub mod pipeline;
pub mod policy_fn;
pub mod image;
pub mod fork;
pub(crate) mod chroot;
pub mod dry_run;
pub(crate) mod http_acl;

pub use error::SandlockError;
pub use checkpoint::Checkpoint;
pub use policy::{ConfinePolicy, ConfinePolicyBuilder, Policy, PolicyBuilder};
pub use result::{RunResult, ExitStatus};
pub use sandbox::Sandbox;
pub use pipeline::{Stage, Pipeline, Gather};
pub use dry_run::{Change, ChangeKind, DryRunResult};

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
/// This applies `PR_SET_NO_NEW_PRIVS` and Landlock rules from the policy.
/// IPC and signal isolation are always enabled. The confinement is
/// **irreversible**.
///
/// This does NOT fork or exec — it confines the current process in-place.
pub fn confine(policy: &ConfinePolicy) -> Result<(), SandlockError> {
    // Set NO_NEW_PRIVS (required for Landlock)
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(SandlockError::Sandbox(
            error::SandboxError::Confinement(
                error::ConfinementError::Landlock(format!(
                    "prctl(PR_SET_NO_NEW_PRIVS): {}",
                    std::io::Error::last_os_error()
                ))
            )
        ));
    }

    let mut builder = Policy::builder();
    for path in &policy.fs_readable {
        builder = builder.fs_read(path.clone());
    }
    for path in &policy.fs_writable {
        builder = builder.fs_write(path.clone());
    }
    let stripped = builder.build()?;

    // Apply Landlock filesystem rules.
    landlock::confine_filesystem(&stripped)
}
