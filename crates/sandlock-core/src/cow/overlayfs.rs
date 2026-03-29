use super::CowBranch;
use crate::error::BranchError;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use walkdir::WalkDir;

pub(crate) struct OverlayBranch {
    base_dir: PathBuf,
    storage: PathBuf,
    upper: PathBuf,
    merged: PathBuf,
}

impl OverlayBranch {
    /// Create a new overlay branch.
    pub fn create(base: &Path, storage: &Path) -> Result<Self, BranchError> {
        let id = Uuid::new_v4().to_string();
        let branch_dir = storage.join(&id);
        let upper = branch_dir.join("upper");
        let work = branch_dir.join("work");
        let merged = branch_dir.join("merged");

        fs::create_dir_all(&upper).map_err(|e| BranchError::Operation(format!("create upper: {}", e)))?;
        fs::create_dir_all(&work).map_err(|e| BranchError::Operation(format!("create work: {}", e)))?;
        fs::create_dir_all(&merged).map_err(|e| BranchError::Operation(format!("create merged: {}", e)))?;

        Ok(Self {
            base_dir: base.to_path_buf(),
            storage: branch_dir,
            upper,
            merged,
        })
    }
}

impl CowBranch for OverlayBranch {
    fn branch_path(&self) -> &Path {
        &self.merged
    }

    fn commit(&self) -> Result<(), BranchError> {
        // Walk upper/, copy each entry to the base dir
        // Handle whiteouts: char device with major=0, minor=0 means deletion
        for entry in WalkDir::new(&self.upper).min_depth(1) {
            let entry = entry.map_err(|e| BranchError::Operation(format!("walk: {}", e)))?;
            let rel = entry.path().strip_prefix(&self.upper).unwrap();
            let target = self.base_dir.join(rel);

            if is_whiteout(entry.path())? {
                let _ = fs::remove_file(&target);
                let _ = fs::remove_dir_all(&target);
            } else if entry.file_type().is_dir() {
                fs::create_dir_all(&target)
                    .map_err(|e| BranchError::Operation(format!("mkdir {}: {}", target.display(), e)))?;
            } else {
                if let Some(parent) = target.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                fs::copy(entry.path(), &target)
                    .map_err(|e| BranchError::Operation(format!("copy to {}: {}", target.display(), e)))?;
            }
        }
        self.cleanup()
    }

    fn abort(&self) -> Result<(), BranchError> {
        self.cleanup()
    }

    fn cleanup(&self) -> Result<(), BranchError> {
        // Try unmount (may fail if not mounted)
        let merged_cstr = std::ffi::CString::new(self.merged.to_str().unwrap_or("")).unwrap();
        unsafe { libc::umount2(merged_cstr.as_ptr(), libc::MNT_DETACH); }
        // Remove storage dir
        let _ = fs::remove_dir_all(&self.storage);
        Ok(())
    }
}

/// Check if a path is an overlayfs whiteout (char device 0:0).
fn is_whiteout(path: &Path) -> Result<bool, BranchError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };
    // Whiteout: character device with rdev == 0
    Ok(meta.file_type().is_char_device() && meta.rdev() == 0)
}

