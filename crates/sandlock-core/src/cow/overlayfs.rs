use super::CowBranch;
use crate::error::BranchError;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use walkdir::WalkDir;

pub(crate) struct OverlayBranch {
    id: String,
    base_dir: PathBuf,
    storage: PathBuf,
    upper: PathBuf,
    work: PathBuf,
    merged: PathBuf,
    lowers: Vec<PathBuf>,
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
            id,
            base_dir: base.to_path_buf(),
            storage: branch_dir,
            upper,
            work,
            merged,
            lowers: vec![base.to_path_buf()],
        })
    }

    /// Mount the overlay filesystem. Requires user+mount namespace.
    pub fn mount(&self) -> Result<(), BranchError> {
        let lowerdir = self.lowers.iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(":");
        let opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            lowerdir,
            self.upper.display(),
            self.work.display(),
        );

        let merged_cstr = std::ffi::CString::new(self.merged.to_str().unwrap()).unwrap();
        let overlay_cstr = std::ffi::CString::new("overlay").unwrap();
        let opts_cstr = std::ffi::CString::new(opts).unwrap();

        let ret = unsafe {
            libc::mount(
                overlay_cstr.as_ptr(),
                merged_cstr.as_ptr(),
                overlay_cstr.as_ptr(),
                0,
                opts_cstr.as_ptr() as *const libc::c_void,
            )
        };
        if ret != 0 {
            Err(BranchError::Operation(format!(
                "mount overlay: {}", std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
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

    fn create_child(&self) -> Result<Box<dyn CowBranch>, BranchError> {
        let storage_parent = self.storage.parent()
            .ok_or_else(|| BranchError::Operation("no parent for storage".into()))?;
        let mut child = OverlayBranch::create(&self.merged, storage_parent)?;
        // Chain: child's lower = [self.upper, self.lowers...]
        child.lowers = vec![self.upper.clone()];
        child.lowers.extend(self.lowers.iter().cloned());
        Ok(Box::new(child))
    }

    fn disk_usage(&self) -> Result<u64, BranchError> {
        dir_size(&self.upper)
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

/// Calculate recursive directory size.
fn dir_size(path: &Path) -> Result<u64, BranchError> {
    let mut total = 0u64;
    for entry in WalkDir::new(path) {
        if let Ok(entry) = entry {
            if entry.file_type().is_file() {
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
            }
        }
    }
    Ok(total)
}
