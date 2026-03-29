//! Unprivileged COW via seccomp user notification.
//!
//! Manages an upper directory for writes and tracks deletions in memory.
//! No root, no mount namespace, no kernel filesystem support needed.
//! Works on any Linux 5.9+ kernel with seccomp user notification.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::BranchError;

/// O_* flags for detecting writes.
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o200000;
const WRITE_FLAGS: u64 = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND;

/// Seccomp-based COW branch. Redirects writes to an upper directory
/// and tracks deletions in memory.
pub struct SeccompCowBranch {
    workdir: PathBuf,
    workdir_str: String,
    upper: PathBuf,
    storage_dir: PathBuf,
    deleted: HashSet<String>,
    has_changes: bool,
    finished: bool,
}

impl SeccompCowBranch {
    /// Create a new seccomp COW branch.
    pub fn create(workdir: &Path, storage: Option<&Path>) -> Result<Self, BranchError> {
        let storage_base = storage
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::temp_dir().join(format!("sandlock-cow-{}", std::process::id())));
        let branch_id = uuid::Uuid::new_v4().to_string();
        let branch_dir = storage_base.join(&branch_id);
        let upper = branch_dir.join("upper");

        fs::create_dir_all(&upper)
            .map_err(|e| BranchError::Operation(format!("create upper: {}", e)))?;

        let workdir = workdir.canonicalize()
            .map_err(|e| BranchError::Operation(format!("canonicalize workdir: {}", e)))?;

        Ok(Self {
            workdir_str: workdir.to_string_lossy().into_owned(),
            workdir,
            upper,
            storage_dir: branch_dir,
            deleted: HashSet::new(),
            has_changes: false,
            finished: false,
        })
    }

    /// The upper directory where writes are stored.
    pub fn upper_dir(&self) -> &Path {
        &self.upper
    }

    /// The original workdir (lower layer).
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// The workdir as a string (for fast prefix matching).
    pub fn workdir_str(&self) -> &str {
        &self.workdir_str
    }

    /// Whether any writes or deletions have occurred.
    pub fn has_changes(&self) -> bool {
        self.has_changes
    }

    /// Check if a path is under the workdir.
    pub fn matches(&self, path: &str) -> bool {
        path == self.workdir_str || path.starts_with(&format!("{}/", self.workdir_str))
    }

    /// Compute relative path from workdir. Returns None if path escapes.
    fn safe_rel(&self, path: &str) -> Option<String> {
        let rel = pathdiff::diff_paths(path, &self.workdir)?;
        let rel_str = rel.to_string_lossy().into_owned();
        if rel_str == ".." || rel_str.starts_with("../") {
            return None;
        }
        Some(rel_str)
    }

    /// Check if a relative path has been deleted.
    pub fn is_deleted(&self, rel_path: &str) -> bool {
        self.deleted.contains(rel_path)
    }

    /// Mark a relative path as deleted.
    pub fn mark_deleted(&mut self, rel_path: &str) {
        self.deleted.insert(rel_path.to_string());
        self.has_changes = true;
    }

    /// Ensure a COW copy exists in upper. Returns the upper path.
    pub fn ensure_cow_copy(&mut self, rel_path: &str) -> Result<PathBuf, BranchError> {
        self.deleted.remove(rel_path);
        self.has_changes = true;

        let upper_file = self.upper.join(rel_path);
        let lower_file = self.workdir.join(rel_path);

        if upper_file.exists() || upper_file.is_symlink() {
            return Ok(upper_file);
        }

        if let Some(parent) = upper_file.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| BranchError::Operation(format!("create parent: {}", e)))?;
        }

        if lower_file.is_symlink() {
            let target = fs::read_link(&lower_file)
                .map_err(|e| BranchError::Operation(format!("readlink: {}", e)))?;
            std::os::unix::fs::symlink(&target, &upper_file)
                .map_err(|e| BranchError::Operation(format!("symlink: {}", e)))?;
        } else if lower_file.exists() {
            fs::copy(&lower_file, &upper_file)
                .map_err(|e| BranchError::Operation(format!("copy: {}", e)))?;
            // Preserve permissions
            let meta = lower_file.metadata()
                .map_err(|e| BranchError::Operation(format!("metadata: {}", e)))?;
            fs::set_permissions(&upper_file, meta.permissions())
                .map_err(|e| BranchError::Operation(format!("set permissions: {}", e)))?;
        }

        Ok(upper_file)
    }

    /// Resolve a read path: upper if modified, else lower.
    pub fn resolve_read(&self, rel_path: &str) -> PathBuf {
        let upper_file = self.upper.join(rel_path);
        if upper_file.exists() || upper_file.is_symlink() {
            upper_file
        } else {
            self.workdir.join(rel_path)
        }
    }

    // ---- Syscall handlers (called by cow::dispatch) ----

    /// Handle openat: resolve to upper or lower path.
    pub fn handle_open(&mut self, path: &str, flags: u64) -> Option<PathBuf> {
        if flags & O_DIRECTORY != 0 {
            return None;
        }
        let rel = self.safe_rel(path)?;
        if self.is_deleted(&rel) {
            if flags & O_CREAT != 0 {
                return self.ensure_cow_copy(&rel).ok();
            }
            return None;
        }
        if flags & WRITE_FLAGS != 0 {
            self.ensure_cow_copy(&rel).ok()
        } else {
            let resolved = self.resolve_read(&rel);
            if resolved.exists() || resolved.is_symlink() {
                Some(resolved)
            } else {
                None
            }
        }
    }

    /// Handle unlink/rmdir.
    pub fn handle_unlink(&mut self, path: &str, is_dir: bool) -> bool {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return false,
        };
        let upper_file = self.upper.join(&rel);
        let lower_file = self.workdir.join(&rel);

        if upper_file.exists() || upper_file.is_symlink() {
            if is_dir {
                let _ = fs::remove_dir_all(&upper_file);
            } else {
                let _ = fs::remove_file(&upper_file);
            }
        }

        if lower_file.exists() || lower_file.is_symlink() {
            self.mark_deleted(&rel);
        } else {
            self.has_changes = true;
        }
        true
    }

    /// Handle mkdirat.
    pub fn handle_mkdir(&mut self, path: &str) -> bool {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return false,
        };
        self.deleted.remove(&rel);
        self.has_changes = true;
        let upper_dir = self.upper.join(&rel);
        fs::create_dir_all(&upper_dir).is_ok()
    }

    /// Handle rename.
    pub fn handle_rename(&mut self, old_path: &str, new_path: &str) -> bool {
        let old_rel = match self.safe_rel(old_path) {
            Some(r) => r,
            None => return false,
        };
        let new_rel = match self.safe_rel(new_path) {
            Some(r) => r,
            None => return false,
        };
        let old_upper = match self.ensure_cow_copy(&old_rel) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let new_upper = self.upper.join(&new_rel);
        if let Some(parent) = new_upper.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::rename(&old_upper, &new_upper).is_err() {
            return false;
        }
        let lower_old = self.workdir.join(&old_rel);
        if lower_old.exists() || lower_old.is_symlink() {
            self.mark_deleted(&old_rel);
        }
        true
    }

    /// Handle stat: resolve path to upper or lower.
    pub fn handle_stat(&self, path: &str) -> Option<PathBuf> {
        let rel = self.safe_rel(path)?;
        if self.is_deleted(&rel) {
            return None;
        }
        let resolved = self.resolve_read(&rel);
        if resolved.exists() || resolved.is_symlink() {
            Some(resolved)
        } else {
            None
        }
    }

    /// Handle symlinkat.
    pub fn handle_symlink(&mut self, target: &str, linkpath: &str) -> bool {
        let rel = match self.safe_rel(linkpath) {
            Some(r) => r,
            None => return false,
        };
        if std::path::Path::new(target).is_absolute() || target.split('/').any(|c| c == "..") {
            return false;
        }
        self.deleted.remove(&rel);
        self.has_changes = true;
        let upper_link = self.upper.join(&rel);
        if let Some(parent) = upper_link.parent() {
            let _ = fs::create_dir_all(parent);
        }
        std::os::unix::fs::symlink(target, &upper_link).is_ok()
    }

    /// Handle linkat.
    pub fn handle_link(&mut self, oldpath: &str, newpath: &str) -> bool {
        let old_rel = match self.safe_rel(oldpath) {
            Some(r) => r,
            None => return false,
        };
        let new_rel = match self.safe_rel(newpath) {
            Some(r) => r,
            None => return false,
        };
        let old_upper = match self.ensure_cow_copy(&old_rel) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let new_upper = self.upper.join(&new_rel);
        if let Some(parent) = new_upper.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::hard_link(&old_upper, &new_upper).is_ok()
    }

    /// Handle fchmodat.
    pub fn handle_chmod(&mut self, path: &str, mode: u32) -> bool {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return false,
        };
        let upper = match self.ensure_cow_copy(&rel) {
            Ok(p) => p,
            Err(_) => return false,
        };
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&upper, fs::Permissions::from_mode(mode)).is_ok()
    }

    /// Handle fchownat.
    pub fn handle_chown(&mut self, path: &str, uid: u32, gid: u32) -> bool {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return false,
        };
        let upper = match self.ensure_cow_copy(&rel) {
            Ok(p) => p,
            Err(_) => return false,
        };
        unsafe {
            let c_path = std::ffi::CString::new(upper.to_str().unwrap_or("")).unwrap();
            libc::chown(c_path.as_ptr(), uid, gid) == 0
        }
    }

    /// Handle truncate.
    pub fn handle_truncate(&mut self, path: &str, length: i64) -> bool {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return false,
        };
        let upper = match self.ensure_cow_copy(&rel) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let file = match fs::OpenOptions::new().write(true).open(&upper) {
            Ok(f) => f,
            Err(_) => return false,
        };
        file.set_len(length as u64).is_ok()
    }

    /// Handle readlink.
    pub fn handle_readlink(&self, path: &str) -> Option<String> {
        let rel = self.safe_rel(path)?;
        if self.is_deleted(&rel) {
            return None;
        }
        let upper = self.upper.join(&rel);
        let lower = self.workdir.join(&rel);
        if upper.is_symlink() {
            fs::read_link(&upper).ok().map(|p| p.to_string_lossy().into_owned())
        } else if lower.is_symlink() {
            fs::read_link(&lower).ok().map(|p| p.to_string_lossy().into_owned())
        } else {
            None
        }
    }

    /// List merged directory entries (upper + lower - deleted).
    pub fn list_merged_dir(&self, rel_path: &str) -> Vec<String> {
        let lower_dir = self.workdir.join(rel_path);
        let upper_dir = self.upper.join(rel_path);
        let mut entries = std::collections::BTreeSet::new();

        if let Ok(rd) = fs::read_dir(&upper_dir) {
            for e in rd.flatten() {
                entries.insert(e.file_name().to_string_lossy().into_owned());
            }
        }
        if let Ok(rd) = fs::read_dir(&lower_dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let child_rel = if rel_path == "." || rel_path.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", rel_path, name)
                };
                if !self.is_deleted(&child_rel) {
                    entries.insert(name);
                }
            }
        }
        entries.into_iter().collect()
    }

    /// Commit: merge upper into workdir.
    pub fn commit(&mut self) -> Result<(), BranchError> {
        if self.finished { return Ok(()); }

        // Apply deletions
        for rel_path in &self.deleted {
            let dest = self.workdir.join(rel_path);
            if dest.is_dir() {
                let _ = fs::remove_dir_all(&dest);
            } else if dest.exists() || dest.is_symlink() {
                let _ = fs::remove_file(&dest);
            }
        }

        // Copy upper to workdir
        let mut synced_dirs = HashSet::new();
        for entry in walkdir::WalkDir::new(&self.upper).min_depth(1) {
            let entry = entry.map_err(|e| BranchError::Operation(format!("walk: {}", e)))?;
            let rel = entry.path().strip_prefix(&self.upper).unwrap();
            let dest = self.workdir.join(rel);
            if entry.file_type().is_dir() {
                fs::create_dir_all(&dest)
                    .map_err(|e| BranchError::Operation(format!("mkdir: {}", e)))?;
            } else {
                if let Some(parent) = dest.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                fs::copy(entry.path(), &dest)
                    .map_err(|e| BranchError::Operation(format!("copy: {}", e)))?;
                synced_dirs.insert(dest.parent().unwrap().to_path_buf());
            }
        }

        // fsync modified directories
        for d in &synced_dirs {
            if let Ok(fd) = fs::OpenOptions::new().read(true).open(d) {
                let _ = fd.sync_all();
            }
        }

        self.cleanup();
        self.finished = true;
        Ok(())
    }

    /// Abort: discard all changes.
    pub fn abort(&mut self) -> Result<(), BranchError> {
        if self.finished { return Ok(()); }
        self.cleanup();
        self.finished = true;
        Ok(())
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.storage_dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_workdir() -> (tempfile::TempDir, tempfile::TempDir) {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        // Create a test file in workdir
        fs::write(workdir.path().join("existing.txt"), "hello").unwrap();
        fs::create_dir(workdir.path().join("subdir")).unwrap();
        fs::write(workdir.path().join("subdir/nested.txt"), "nested").unwrap();
        (workdir, storage)
    }

    #[test]
    fn test_create_branch() {
        let (workdir, storage) = setup_workdir();
        let branch = SeccompCowBranch::create(workdir.path(), Some(storage.path())).unwrap();
        assert!(branch.upper_dir().exists());
        assert!(!branch.has_changes());
    }

    #[test]
    fn test_matches() {
        let (workdir, storage) = setup_workdir();
        let branch = SeccompCowBranch::create(workdir.path(), Some(storage.path())).unwrap();
        let wdstr = workdir.path().canonicalize().unwrap();
        let wdstr = wdstr.to_str().unwrap();
        assert!(branch.matches(&format!("{}/foo.txt", wdstr)));
        assert!(branch.matches(wdstr));
        assert!(!branch.matches("/tmp/other"));
    }

    #[test]
    fn test_ensure_cow_copy() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path())).unwrap();
        let upper = branch.ensure_cow_copy("existing.txt").unwrap();
        assert!(upper.exists());
        assert_eq!(fs::read_to_string(&upper).unwrap(), "hello");
        assert!(branch.has_changes());
    }

    #[test]
    fn test_resolve_read_prefers_upper() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path())).unwrap();
        let upper = branch.ensure_cow_copy("existing.txt").unwrap();
        fs::write(&upper, "modified").unwrap();
        let resolved = branch.resolve_read("existing.txt");
        assert_eq!(fs::read_to_string(&resolved).unwrap(), "modified");
    }

    #[test]
    fn test_is_deleted() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path())).unwrap();
        assert!(!branch.is_deleted("existing.txt"));
        branch.mark_deleted("existing.txt");
        assert!(branch.is_deleted("existing.txt"));
    }

    #[test]
    fn test_commit_merges_upper() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path())).unwrap();
        // Write a new file via COW
        let upper = branch.ensure_cow_copy("new.txt").unwrap();
        fs::write(&upper, "new content").unwrap();
        branch.commit().unwrap();
        assert_eq!(fs::read_to_string(workdir.path().join("new.txt")).unwrap(), "new content");
    }

    #[test]
    fn test_commit_applies_deletions() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path())).unwrap();
        branch.mark_deleted("existing.txt");
        branch.commit().unwrap();
        assert!(!workdir.path().join("existing.txt").exists());
    }

    #[test]
    fn test_abort_discards_changes() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path())).unwrap();
        let upper = branch.ensure_cow_copy("new.txt").unwrap();
        fs::write(&upper, "should be discarded").unwrap();
        branch.abort().unwrap();
        assert!(!workdir.path().join("new.txt").exists());
    }
}
