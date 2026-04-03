pub(crate) mod overlayfs;
pub(crate) mod branchfs;
pub(crate) mod seccomp;
pub(crate) mod dispatch;

use crate::dry_run::Change;
use crate::error::BranchError;
use std::path::{Path, PathBuf};

/// Mount configuration that the child process needs to set up its COW view.
/// Backends that don't need a mount in the child (e.g. seccomp, branchfs)
/// return `None` from `child_mount_config()`.
pub(crate) struct ChildMountConfig {
    /// Where to mount the overlay (should be the workdir itself so the child
    /// sees the COW view at the original path).
    pub mount_point: PathBuf,
    /// Upper layer for writes.
    pub upper: PathBuf,
    /// Overlay work directory.
    pub work: PathBuf,
    /// Lower layer(s) — the original directories (read-only).
    pub lowers: Vec<PathBuf>,
}

/// Common interface for COW filesystem backends.
pub(crate) trait CowBranch: Send + Sync {
    /// Path to the branch's working directory (what the sandbox sees).
    fn branch_path(&self) -> &Path;

    /// Returns the mount configuration the child process needs, if any.
    /// `None` means no mount setup is needed (the backend handles isolation
    /// via other mechanisms like seccomp interception or kernel ioctls).
    fn child_mount_config(&self) -> Option<ChildMountConfig> {
        None
    }

    /// Merge COW writes into the original directory.
    fn commit(&self) -> Result<(), BranchError>;

    /// Discard COW writes.
    fn abort(&self) -> Result<(), BranchError>;

    /// Clean up (unmount, remove dirs). Called on drop.
    fn cleanup(&self) -> Result<(), BranchError>;

    /// List filesystem changes in the COW layer (for dry-run).
    fn changes(&self) -> Result<Vec<Change>, BranchError>;
}
