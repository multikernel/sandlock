pub(crate) mod overlayfs;
pub(crate) mod branchfs;
pub(crate) mod seccomp;
pub(crate) mod dispatch;

use crate::error::BranchError;
use std::path::{Path, PathBuf};

/// Common interface for COW filesystem backends.
pub(crate) trait CowBranch: Send + Sync {
    /// Path to the branch's working directory (what the sandbox sees).
    fn branch_path(&self) -> &Path;

    /// Merge COW writes into the original directory.
    fn commit(&self) -> Result<(), BranchError>;

    /// Discard COW writes.
    fn abort(&self) -> Result<(), BranchError>;

    /// Create a nested child branch (for fork clones).
    fn create_child(&self) -> Result<Box<dyn CowBranch>, BranchError>;

    /// Disk usage of the COW layer (bytes written).
    fn disk_usage(&self) -> Result<u64, BranchError>;

    /// Clean up (unmount, remove dirs). Called on drop.
    fn cleanup(&self) -> Result<(), BranchError>;
}
