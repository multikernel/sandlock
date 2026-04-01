pub(crate) mod overlayfs;
pub(crate) mod branchfs;
pub(crate) mod seccomp;
pub(crate) mod dispatch;

use crate::dry_run::Change;
use crate::error::BranchError;
use std::path::Path;

/// Common interface for COW filesystem backends.
pub(crate) trait CowBranch: Send + Sync {
    /// Path to the branch's working directory (what the sandbox sees).
    fn branch_path(&self) -> &Path;

    /// Merge COW writes into the original directory.
    fn commit(&self) -> Result<(), BranchError>;

    /// Discard COW writes.
    fn abort(&self) -> Result<(), BranchError>;

    /// Clean up (unmount, remove dirs). Called on drop.
    fn cleanup(&self) -> Result<(), BranchError>;

    /// List filesystem changes in the COW layer (for dry-run).
    fn changes(&self) -> Result<Vec<Change>, BranchError>;
}
