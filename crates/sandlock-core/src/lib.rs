pub mod error;
pub mod policy;
pub mod profile;
pub mod result;
pub mod sandbox;
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
pub use policy::{Policy, PolicyBuilder};
pub use result::{RunResult, ExitStatus};
pub use sandbox::Sandbox;
pub use pipeline::{Stage, Pipeline};
pub use dry_run::{Change, ChangeKind, DryRunResult};

/// Query the Landlock ABI version supported by the running kernel.
pub fn landlock_abi_version() -> Result<u32, error::ConfinementError> {
    landlock::abi_version()
}

/// Minimum Landlock ABI version required by sandlock.
pub const MIN_LANDLOCK_ABI: u32 = landlock::MIN_ABI;

/// Confine the calling process with Landlock restrictions.
///
/// This applies `PR_SET_NO_NEW_PRIVS` and Landlock rules from the policy's
/// filesystem (`fs_readable`, `fs_writable`) fields. IPC and signal
/// isolation are always enabled. The confinement is **irreversible**.
///
/// `fs_denied` is not enforced here because it requires supervisor-mediated
/// path interception rather than Landlock's allowlist model.
///
/// Network, seccomp, resource limits, and other policy fields are ignored.
///
/// This does NOT fork or exec — it confines the current process in-place.
pub fn confine_current_process(policy: &Policy) -> Result<(), SandlockError> {
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

    // Build a stripped policy with only Landlock-native fields that
    // confine_current_process supports: filesystem + IPC + signals.
    // Network port rules are excluded — they require the full sandbox.
    let mut stripped = policy.clone();
    stripped.net_bind.clear();
    stripped.net_connect.clear();

    // Apply Landlock rules
    landlock::confine(&stripped)
}
