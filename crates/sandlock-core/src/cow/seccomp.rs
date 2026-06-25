//! Unprivileged COW via seccomp user notification.
//!
//! Manages an upper directory for writes and tracks deletions in memory.
//! No root, no mount namespace, no kernel filesystem support needed.
//! Works on any Linux 5.9+ kernel with seccomp user notification.

use std::collections::HashSet;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};

use crate::error::BranchError;

/// O_* flags for detecting writes. These differ across Linux architectures.
const O_WRONLY: u64 = libc::O_WRONLY as u64;
const O_RDWR: u64 = libc::O_RDWR as u64;
const O_CREAT: u64 = libc::O_CREAT as u64;
const O_TRUNC: u64 = libc::O_TRUNC as u64;
const O_APPEND: u64 = libc::O_APPEND as u64;
const O_EXCL: u64 = libc::O_EXCL as u64;
const O_DIRECTORY: u64 = libc::O_DIRECTORY as u64;
const WRITE_FLAGS: u64 = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND;

/// Parent of a relative path, or None if it has no parent component.
fn parent_rel(rel: &str) -> Option<&str> {
    rel.trim_end_matches('/').rfind('/').map(|i| &rel[..i])
}

/// Plan for a COW copy — returned by `prepare_copy()` to separate metadata
/// updates (under lock) from potentially expensive file I/O (outside lock).
#[derive(Debug)]
pub enum CowCopyPlan {
    /// File is already in upper (or was a symlink/dir handled immediately).
    Ready(PathBuf),
    /// Regular file needs copy from lower to upper (potentially large).
    NeedsCopy {
        upper: PathBuf,
        lower: PathBuf,
        file_size: u64,
    },
}

/// Plan returned by `prepare_open` — describes what I/O to do after releasing the lock.
#[derive(Debug)]
pub enum CowOpenPlan {
    /// No interception needed — let the kernel handle it.
    Skip,
    /// File already resolved (upper or lower) — open this path directly.
    Resolved(PathBuf),
    /// Need to copy lower to upper, then open upper.
    NeedsCopy {
        upper: PathBuf,
        lower: PathBuf,
        file_size: u64,
        rel_path: String,
    },
    /// Upper path ready (already exists in upper, or new file placeholder).
    UpperReady {
        upper: PathBuf,
    },
}

/// Recursively compute the total size of all files under `dir`.
fn dir_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                total += dir_size(&path);
            } else if let Ok(meta) = path.symlink_metadata() {
                total += meta.len();
            }
        }
    }
    total
}

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
    max_disk_bytes: u64,
    disk_used: u64,
}

impl SeccompCowBranch {
    /// Create a new seccomp COW branch.
    ///
    /// `max_disk_bytes`: maximum bytes allowed in the upper directory (0 = unlimited).
    pub fn create(workdir: &Path, storage: Option<&Path>, max_disk_bytes: u64) -> Result<Self, BranchError> {
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
            max_disk_bytes,
            disk_used: 0,
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

    /// Check if a path is under the workdir (but not inside the COW storage).
    pub fn matches(&self, path: &str) -> bool {
        let p = std::path::Path::new(path);
        p.starts_with(&self.workdir_str) && !p.starts_with(&self.storage_dir)
    }

    /// Check if a path has been modified or deleted in the COW layer.
    /// Used to skip read-only opens for unmodified files.
    pub fn needs_read_intercept(&self, path: &str) -> bool {
        if let Some(rel) = self.safe_rel(path) {
            self.is_deleted(&rel) || self.upper.join(&rel).exists()
        } else {
            false
        }
    }

    /// Compute relative path from workdir. Returns None if path escapes.
    pub fn safe_rel(&self, path: &str) -> Option<String> {
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

    /// Check whether `additional` bytes would exceed the disk quota.
    /// Returns `Ok(())` if within quota or quota is unlimited (0).
    /// Check whether `additional` bytes would exceed the disk quota.
    /// Returns `Ok(())` if within quota or quota is unlimited (0).
    /// When `additional` is 0 the check uses `>=` — meaning "quota is
    /// already exhausted, don't allow any new allocations".
    fn check_quota(&self, additional: u64) -> Result<(), BranchError> {
        if self.max_disk_bytes > 0 {
            if additional == 0 {
                if self.disk_used >= self.max_disk_bytes {
                    return Err(BranchError::QuotaExceeded);
                }
            } else if self.disk_used + additional > self.max_disk_bytes {
                return Err(BranchError::QuotaExceeded);
            }
        }
        Ok(())
    }

    /// Recalculate `disk_used` by walking the upper directory.
    fn recalc_disk_used(&mut self) {
        self.disk_used = dir_size(&self.upper);
    }

    /// Prepare a COW copy: update metadata (deleted set, quota reservation)
    /// and handle small items (symlinks, dirs) immediately, but defer large
    /// file copies to the caller. This is the shared core used by both
    /// `ensure_cow_copy` (synchronous) and the async two-phase dispatch.
    pub fn prepare_copy(&mut self, rel_path: &str) -> Result<CowCopyPlan, BranchError> {
        self.deleted.remove(rel_path);
        self.has_changes = true;

        let upper_file = self.upper.join(rel_path);
        let lower_file = self.workdir.join(rel_path);

        // Already materialized in upper? Confined lstat succeeds for any
        // existing entry (including a dangling symlink).
        if crate::sys::fs::statat_in_root(&self.upper, rel_path, false).is_ok() {
            return Ok(CowCopyPlan::Ready(upper_file));
        }

        if let Some(p) = parent_rel(rel_path) {
            let _ = crate::sys::fs::mkdirp_in_root(&self.upper, p, 0o755);
        }

        // Classify the lower entry confined to the workdir root, so a symlinked
        // parent component cannot make us follow out of the tree (issue #112).
        // The lstat also yields the size of the entry we will actually copy.
        let st = match crate::sys::fs::statat_in_root(&self.workdir, rel_path, false) {
            Ok(st) => st,
            // Absent or confined-out: treat as a new file created in upper.
            Err(libc::ENOENT) => {
                self.check_quota(0)?;
                return Ok(CowCopyPlan::Ready(upper_file));
            }
            Err(e) => return Err(BranchError::Operation(format!("stat lower: {}", e))),
        };
        let kind = st.st_mode & libc::S_IFMT;

        // Symlink — copy verbatim (tiny, not worth deferring)
        if kind == libc::S_IFLNK {
            self.check_quota(256)?;
            let target = crate::sys::fs::readlink_in_root(&self.workdir, rel_path)
                .map_err(|e| BranchError::Operation(format!("readlink: {}", e)))?;
            let target = std::path::PathBuf::from(std::ffi::OsString::from_vec(target));
            crate::sys::fs::symlinkat_in_root(&self.upper, rel_path, &target.to_string_lossy())
                .map_err(|e| BranchError::Operation(format!("symlink: {}", e)))?;
            self.disk_used += 256;
            return Ok(CowCopyPlan::Ready(upper_file));
        }

        // Directory — create immediately (no data copy)
        if kind == libc::S_IFDIR {
            self.check_quota(4096)?;
            crate::sys::fs::mkdirp_in_root(&self.upper, rel_path, st.st_mode & 0o7777)
                .map_err(|e| BranchError::Operation(format!("create dir: {}", e)))?;
            let _ = crate::sys::fs::chmod_in_root(&self.upper, rel_path, st.st_mode & 0o7777);
            self.disk_used += 4096;
            return Ok(CowCopyPlan::Ready(upper_file));
        }

        // Regular file — defer the potentially expensive copy. Size comes from
        // the confined lstat, so the quota reservation matches the file
        // execute_copy will actually read.
        let file_size = st.st_size as u64;
        self.check_quota(file_size)?;
        self.disk_used += file_size;
        Ok(CowCopyPlan::NeedsCopy {
            upper: upper_file,
            lower: lower_file,
            file_size,
        })
    }

    /// Execute a file copy synchronously. Used by `ensure_cow_copy` and the
    /// async dispatch (via `spawn_blocking`).
    pub fn execute_copy(
        workdir_root: &Path,
        upper_root: &Path,
        rel: &str,
    ) -> Result<(), std::io::Error> {
        let create_dest = || -> Result<fs::File, std::io::Error> {
            let fd = crate::sys::fs::openat2_in_root(
                upper_root,
                rel,
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
            .map_err(std::io::Error::from_raw_os_error)?;
            Ok(unsafe { fs::File::from_raw_fd(fd) })
        };

        // Read the lower source confined to the workdir root: a symlink or
        // `..` in `rel` cannot escape the tree (issue #112).
        let src_fd = match crate::sys::fs::openat2_in_root(
            workdir_root,
            rel,
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        ) {
            Ok(fd) => fd,
            // Unreadable (EACCES) or confined-out / absent (ENOENT): give the
            // child an empty COW file so writes proceed, never leaking the
            // escape target.
            Err(libc::EACCES) | Err(libc::ENOENT) => {
                create_dest()?;
                return Ok(());
            }
            // On a kernel without openat2 (ENOSYS) the copy fails and the caller
            // rolls back / returns Continue; the child then hits Landlock, which
            // is the backstop. Do not "fix" this with an unconfined fs::copy.
            Err(e) => return Err(std::io::Error::from_raw_os_error(e)),
        };

        let mut src = unsafe { fs::File::from_raw_fd(src_fd) };
        let mut dst = create_dest()?;
        std::io::copy(&mut src, &mut dst)?;
        if let Ok(meta) = src.metadata() {
            let _ = dst.set_permissions(meta.permissions());
        }
        Ok(())
    }

    /// Ensure a COW copy exists in upper (synchronous). Returns the upper path.
    /// For callers that don't need async two-phase behavior.
    pub fn ensure_cow_copy(&mut self, rel_path: &str) -> Result<PathBuf, BranchError> {
        match self.prepare_copy(rel_path)? {
            CowCopyPlan::Ready(upper) => Ok(upper),
            CowCopyPlan::NeedsCopy { upper, lower: _lower, file_size } => {
                match Self::execute_copy(&self.workdir, &self.upper, rel_path) {
                    Ok(()) => Ok(upper),
                    Err(e) => {
                        self.rollback_copy(file_size);
                        Err(BranchError::Operation(format!("copy: {}", e)))
                    }
                }
            }
        }
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
    ///
    /// Returns `Err(QuotaExceeded)` when the write would exceed `max_disk`.
    ///
    /// When a quota is active and the open is a write, resync `disk_used`
    /// from the real upper directory first.  This catches growth from
    /// `write()` syscalls on previously injected fds (which bypass the
    /// seccomp supervisor) and prevents new opens once the quota is
    /// exhausted.
    pub fn handle_open(&mut self, path: &str, flags: u64) -> Result<Option<PathBuf>, BranchError> {
        if flags & O_DIRECTORY != 0 {
            return Ok(None);
        }
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(None),
        };

        let is_write = flags & WRITE_FLAGS != 0;

        // Resync quota accounting before any write open so that bytes
        // written through previously injected fds are counted.
        if is_write && self.max_disk_bytes > 0 {
            self.recalc_disk_used();
            self.check_quota(0)?;
        }

        if self.is_deleted(&rel) {
            if flags & O_CREAT != 0 {
                return self.ensure_cow_copy(&rel).map(Some);
            }
            return Ok(None);
        }

        // O_EXCL: fail if file already exists (in upper or lower)
        if flags & O_CREAT != 0 && flags & O_EXCL != 0 {
            // Confined existence check: a symlinked parent component must not
            // let this probe follow out of the tree, which would turn O_EXCL
            // into a host-file existence oracle (issue #112).
            if crate::sys::fs::statat_in_root(&self.upper, &rel, false).is_ok()
                || crate::sys::fs::statat_in_root(&self.workdir, &rel, false).is_ok()
            {
                return Err(BranchError::Exists);
            }
            // File truly doesn't exist — create in upper
            return self.ensure_cow_copy(&rel).map(Some);
        }

        if is_write {
            self.ensure_cow_copy(&rel).map(Some)
        } else {
            let resolved = self.resolve_read(&rel);
            if resolved.exists() || resolved.is_symlink() {
                Ok(Some(resolved))
            } else {
                Ok(None)
            }
        }
    }

    /// Prepare an open without doing the file copy.
    ///
    /// Returns a plan that describes what I/O needs to happen after the lock
    /// is released. This keeps the lock held only for metadata checks.
    pub fn prepare_open(&mut self, path: &str, flags: u64) -> Result<CowOpenPlan, BranchError> {
        if flags & O_DIRECTORY != 0 {
            // Resolve O_DIRECTORY opens to the upper layer if the directory
            // was created by COW and doesn't exist on the real filesystem.
            let rel = match self.safe_rel(path) {
                Some(r) => r,
                None => return Ok(CowOpenPlan::Skip),
            };
            let upper_dir = self.upper.join(&rel);
            let lower_dir = self.workdir.join(&rel);
            if upper_dir.is_dir() && !lower_dir.is_dir() {
                return Ok(CowOpenPlan::Resolved(upper_dir));
            }
            return Ok(CowOpenPlan::Skip);
        }
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(CowOpenPlan::Skip),
        };

        let is_write = flags & WRITE_FLAGS != 0;

        // Resync quota accounting before any write open.
        if is_write && self.max_disk_bytes > 0 {
            self.recalc_disk_used();
            self.check_quota(0)?;
        }

        if self.is_deleted(&rel) {
            if flags & O_CREAT != 0 {
                return self.prepare_cow_copy(&rel);
            }
            return Ok(CowOpenPlan::Skip);
        }

        // O_EXCL: fail if file already exists
        if flags & O_CREAT != 0 && flags & O_EXCL != 0 {
            // Confined existence check: a symlinked parent component must not
            // let this probe follow out of the tree, which would turn O_EXCL
            // into a host-file existence oracle (issue #112).
            if crate::sys::fs::statat_in_root(&self.upper, &rel, false).is_ok()
                || crate::sys::fs::statat_in_root(&self.workdir, &rel, false).is_ok()
            {
                return Err(BranchError::Exists);
            }
            return self.prepare_cow_copy(&rel);
        }

        if is_write {
            self.prepare_cow_copy(&rel)
        } else {
            let resolved = self.resolve_read(&rel);
            if resolved.exists() || resolved.is_symlink() {
                Ok(CowOpenPlan::Resolved(resolved))
            } else {
                Ok(CowOpenPlan::Skip)
            }
        }
    }

    /// Prepare a COW copy for openat — wraps `prepare_copy` into `CowOpenPlan`.
    fn prepare_cow_copy(&mut self, rel_path: &str) -> Result<CowOpenPlan, BranchError> {
        match self.prepare_copy(rel_path)? {
            CowCopyPlan::Ready(upper) => Ok(CowOpenPlan::UpperReady { upper }),
            CowCopyPlan::NeedsCopy { upper, lower, file_size } => {
                Ok(CowOpenPlan::NeedsCopy {
                    upper,
                    lower,
                    file_size,
                    rel_path: rel_path.to_string(),
                })
            }
        }
    }

    /// Roll back quota reservation if the copy failed.
    pub fn rollback_copy(&mut self, file_size: u64) {
        self.disk_used = self.disk_used.saturating_sub(file_size);
    }

    /// Handle unlink/rmdir.
    ///
    /// Returns `Ok(true)` on success, `Ok(false)` if the path doesn't match,
    /// or `Err(errno)` for filesystem errors (e.g. ENOTDIR when rmdir is
    /// called on a non-directory, EISDIR when unlink is called on a directory).
    pub fn handle_unlink(&mut self, path: &str, is_dir: bool) -> Result<bool, i32> {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(false),
        };
        let upper_file = self.upper.join(&rel);
        let lower_file = self.workdir.join(&rel);

        // Check type mismatches: rmdir on a non-directory or unlink on a directory.
        // We check both upper (COW layer) and lower (real filesystem).
        let check_path = if upper_file.exists() || upper_file.is_symlink() {
            Some(&upper_file)
        } else if lower_file.exists() || lower_file.is_symlink() {
            Some(&lower_file)
        } else {
            None
        };

        if let Some(p) = check_path {
            let is_actual_dir = p.is_dir();
            if is_dir && !is_actual_dir {
                // rmdir() on a non-directory → ENOTDIR
                return Err(libc::ENOTDIR);
            }
            if !is_dir && is_actual_dir {
                // unlink() on a directory → EISDIR
                return Err(libc::EISDIR);
            }
        }

        if upper_file.exists() || upper_file.is_symlink() {
            if is_dir {
                let _ = crate::sys::fs::remove_dir_all_in_root(&self.upper, &rel);
            } else {
                let _ = crate::sys::fs::unlinkat_in_root(&self.upper, &rel, false);
            }
            self.recalc_disk_used();
        }

        if lower_file.exists() || lower_file.is_symlink() {
            self.mark_deleted(&rel);
        } else {
            self.has_changes = true;
        }
        Ok(true)
    }

    /// Handle mkdirat.
    ///
    /// Returns `Err(QuotaExceeded)` when the directory would exceed `max_disk`.
    pub fn handle_mkdir(&mut self, path: &str) -> Result<bool, BranchError> {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(false),
        };
        self.check_quota(4096)?; // directory metadata
        self.deleted.remove(&rel);
        self.has_changes = true;
        let ok = crate::sys::fs::mkdirp_in_root(&self.upper, &rel, 0o755).is_ok();
        if ok {
            self.disk_used += 4096;
        }
        Ok(ok)
    }

    /// Handle rename.
    ///
    /// Returns `Err(QuotaExceeded)` when the COW copy would exceed `max_disk`.
    pub fn handle_rename(&mut self, old_path: &str, new_path: &str) -> Result<bool, BranchError> {
        let old_rel = match self.safe_rel(old_path) {
            Some(r) => r,
            None => return Ok(false),
        };
        let new_rel = match self.safe_rel(new_path) {
            Some(r) => r,
            None => return Ok(false),
        };
        let _old_upper = self.ensure_cow_copy(&old_rel)?;
        if let Some(p) = parent_rel(&new_rel) {
            let _ = crate::sys::fs::mkdirp_in_root(&self.upper, p, 0o755);
        }
        if crate::sys::fs::renameat_in_root(&self.upper, &old_rel, &new_rel).is_err() {
            return Ok(false);
        }
        let lower_old = self.workdir.join(&old_rel);
        if lower_old.exists() || lower_old.is_symlink() {
            self.mark_deleted(&old_rel);
        }
        Ok(true)
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
    ///
    /// Returns `Err(QuotaExceeded)` when the symlink would exceed `max_disk`.
    pub fn handle_symlink(&mut self, target: &str, linkpath: &str) -> Result<bool, BranchError> {
        let rel = match self.safe_rel(linkpath) {
            Some(r) => r,
            None => return Ok(false),
        };
        if std::path::Path::new(target).is_absolute() || target.split('/').any(|c| c == "..") {
            return Ok(false);
        }
        self.check_quota(256)?;
        self.deleted.remove(&rel);
        self.has_changes = true;
        if let Some(p) = parent_rel(&rel) {
            let _ = crate::sys::fs::mkdirp_in_root(&self.upper, p, 0o755);
        }
        let ok = crate::sys::fs::symlinkat_in_root(&self.upper, &rel, target).is_ok();
        if ok {
            self.disk_used += 256;
        }
        Ok(ok)
    }

    /// Handle linkat.
    ///
    /// Returns `Err(QuotaExceeded)` when the COW copy would exceed `max_disk`.
    pub fn handle_link(&mut self, oldpath: &str, newpath: &str) -> Result<bool, BranchError> {
        let old_rel = match self.safe_rel(oldpath) {
            Some(r) => r,
            None => return Ok(false),
        };
        let new_rel = match self.safe_rel(newpath) {
            Some(r) => r,
            None => return Ok(false),
        };
        let _ = self.ensure_cow_copy(&old_rel)?;
        if let Some(p) = parent_rel(&new_rel) {
            let _ = crate::sys::fs::mkdirp_in_root(&self.upper, p, 0o755);
        }
        Ok(crate::sys::fs::linkat_in_root(&self.upper, &old_rel, &new_rel).is_ok())
    }

    /// Handle fchmodat.
    ///
    /// Returns `Err(QuotaExceeded)` when the COW copy would exceed `max_disk`.
    pub fn handle_chmod(&mut self, path: &str, mode: u32) -> Result<bool, BranchError> {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(false),
        };
        let _ = self.ensure_cow_copy(&rel)?;
        Ok(crate::sys::fs::chmod_in_root(&self.upper, &rel, mode).is_ok())
    }

    /// Handle fchownat.
    ///
    /// Returns `Err(QuotaExceeded)` when the COW copy would exceed `max_disk`.
    pub fn handle_chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<bool, BranchError> {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(false),
        };
        let _ = self.ensure_cow_copy(&rel)?;
        // Best-effort: try the real chown but succeed either way — the
        // supervisor typically lacks CAP_CHOWN so this will fail, but
        // in COW/dry-run mode the ownership doesn't matter.
        let _ = crate::sys::fs::chown_in_root(&self.upper, &rel, uid, gid);
        Ok(true)
    }

    /// Handle truncate.
    ///
    /// Returns `Err(QuotaExceeded)` when the truncate would exceed `max_disk`.
    pub fn handle_truncate(&mut self, path: &str, length: i64) -> Result<bool, BranchError> {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(false),
        };
        let new_len = length as u64;
        let _ = self.ensure_cow_copy(&rel)?;
        let old_len = crate::sys::fs::statat_in_root(&self.upper, &rel, true)
            .map(|st| st.st_size as u64)
            .unwrap_or(0);
        if new_len > old_len {
            self.check_quota(new_len - old_len)?;
        }
        let fd = match crate::sys::fs::openat2_in_root(
            &self.upper, &rel,
            libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0,
        ) {
            Ok(fd) => fd,
            Err(_) => return Ok(false),
        };
        let ok = unsafe { libc::ftruncate(fd, new_len as libc::off_t) } == 0;
        unsafe { libc::close(fd) };
        if ok {
            if new_len > old_len {
                self.disk_used += new_len - old_len;
            } else {
                self.disk_used = self.disk_used.saturating_sub(old_len - new_len);
            }
        }
        Ok(ok)
    }

    /// Handle utimensat — resolve to upper, return the upper path for the
    /// caller to call utimensat on.
    pub fn handle_utimensat(&mut self, path: &str) -> Result<Option<PathBuf>, BranchError> {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(None),
        };
        let upper = self.ensure_cow_copy(&rel)?;
        Ok(Some(upper))
    }

    /// Handle readlink.
    pub fn handle_readlink(&self, path: &str) -> Option<String> {
        let rel = self.safe_rel(path)?;
        if self.is_deleted(&rel) {
            return None;
        }
        // Read the link confined to each layer root so a symlinked parent
        // component cannot escape the tree (issue #112).
        for root in [&self.upper, &self.workdir] {
            if let Ok(target) = crate::sys::fs::readlink_in_root(root, &rel) {
                return Some(String::from_utf8_lossy(&target).into_owned());
            }
        }
        None
    }

    /// List all filesystem changes in the COW layer.
    pub fn changes(&self) -> Result<Vec<crate::dry_run::Change>, BranchError> {
        use crate::dry_run::{Change, ChangeKind};

        let mut result = Vec::new();

        // Walk upper directory for added/modified files
        for entry in walkdir::WalkDir::new(&self.upper).min_depth(1) {
            let entry = entry.map_err(|e| BranchError::Operation(format!("walk: {}", e)))?;
            if entry.file_type().is_dir() {
                continue;
            }
            let rel = entry.path().strip_prefix(&self.upper).unwrap();
            let lower = self.workdir.join(rel);
            let kind = if lower.exists() {
                ChangeKind::Modified
            } else {
                ChangeKind::Added
            };
            result.push(Change { kind, path: rel.to_path_buf() });
        }

        // Deletions from tracked set
        for rel_path in &self.deleted {
            result.push(Change {
                kind: ChangeKind::Deleted,
                path: std::path::PathBuf::from(rel_path),
            });
        }

        Ok(result)
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
                let _ = crate::sys::fs::remove_dir_all_in_root(&self.workdir, rel_path);
            } else if dest.exists() || dest.is_symlink() {
                let _ = crate::sys::fs::unlinkat_in_root(&self.workdir, rel_path, false);
            }
        }

        // Copy upper to workdir
        let mut synced_dirs = HashSet::new();
        for entry in walkdir::WalkDir::new(&self.upper).min_depth(1) {
            let entry = entry.map_err(|e| BranchError::Operation(format!("walk: {}", e)))?;
            let rel = entry.path().strip_prefix(&self.upper).unwrap();
            let rel_str = match rel.to_str() {
                Some(s) => s,
                None => continue,
            };
            let dest = self.workdir.join(rel);
            if entry.file_type().is_dir() {
                crate::sys::fs::mkdirp_in_root(&self.workdir, rel_str, 0o755)
                    .map_err(|e| BranchError::Operation(format!("mkdir: {}", e)))?;
            } else if entry.file_type().is_symlink() {
                // Recreate the symlink verbatim. fs::copy would follow it and
                // read the target outside any root or Landlock (issue #112),
                // and dereferencing would also lose the link in the workdir.
                if let Some(p) = parent_rel(rel_str) {
                    let _ = crate::sys::fs::mkdirp_in_root(&self.workdir, p, 0o755);
                }
                let target = fs::read_link(entry.path())
                    .map_err(|e| BranchError::Operation(format!("readlink: {}", e)))?;
                let _ = crate::sys::fs::unlinkat_in_root(&self.workdir, rel_str, false);
                crate::sys::fs::symlinkat_in_root(
                    &self.workdir,
                    rel_str,
                    &target.to_string_lossy(),
                )
                .map_err(|e| BranchError::Operation(format!("symlink: {}", e)))?;
                synced_dirs.insert(dest.parent().unwrap().to_path_buf());
            } else {
                if let Some(p) = parent_rel(rel_str) {
                    let _ = crate::sys::fs::mkdirp_in_root(&self.workdir, p, 0o755);
                }
                // Source is the upper entry (supervisor-owned real path, safe to read directly).
                let mut src = fs::File::open(entry.path())
                    .map_err(|e| BranchError::Operation(format!("copy: {}", e)))?;
                let dst_fd = crate::sys::fs::openat2_in_root(
                    &self.workdir,
                    rel_str,
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o644,
                )
                .map_err(|e| BranchError::Operation(format!("copy: {}", e)))?;
                let mut dst = unsafe { fs::File::from_raw_fd(dst_fd) };
                std::io::copy(&mut src, &mut dst)
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
        let branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        assert!(branch.upper_dir().exists());
        assert!(!branch.has_changes());
    }

    #[test]
    fn test_matches() {
        let (workdir, storage) = setup_workdir();
        let branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let wdstr = workdir.path().canonicalize().unwrap();
        let wdstr = wdstr.to_str().unwrap();
        assert!(branch.matches(&format!("{}/foo.txt", wdstr)));
        assert!(branch.matches(wdstr));
        assert!(!branch.matches("/tmp/other"));
    }

    #[test]
    fn test_ensure_cow_copy() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let upper = branch.ensure_cow_copy("existing.txt").unwrap();
        assert!(upper.exists());
        assert_eq!(fs::read_to_string(&upper).unwrap(), "hello");
        assert!(branch.has_changes());
    }

    #[test]
    fn test_resolve_read_prefers_upper() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let upper = branch.ensure_cow_copy("existing.txt").unwrap();
        fs::write(&upper, "modified").unwrap();
        let resolved = branch.resolve_read("existing.txt");
        assert_eq!(fs::read_to_string(&resolved).unwrap(), "modified");
    }

    #[test]
    fn test_is_deleted() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        assert!(!branch.is_deleted("existing.txt"));
        branch.mark_deleted("existing.txt");
        assert!(branch.is_deleted("existing.txt"));
    }

    #[test]
    fn test_commit_merges_upper() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        // Write a new file via COW
        let upper = branch.ensure_cow_copy("new.txt").unwrap();
        fs::write(&upper, "new content").unwrap();
        branch.commit().unwrap();
        assert_eq!(fs::read_to_string(workdir.path().join("new.txt")).unwrap(), "new content");
    }

    #[test]
    fn test_commit_applies_deletions() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("existing.txt");
        branch.commit().unwrap();
        assert!(!workdir.path().join("existing.txt").exists());
    }

    #[test]
    fn test_abort_discards_changes() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let upper = branch.ensure_cow_copy("new.txt").unwrap();
        fs::write(&upper, "should be discarded").unwrap();
        branch.abort().unwrap();
        assert!(!workdir.path().join("new.txt").exists());
    }

    #[test]
    fn test_changes_added_file() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let upper = branch.ensure_cow_copy("brand_new.txt").unwrap();
        fs::write(&upper, "new content").unwrap();
        let changes = branch.changes().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, crate::dry_run::ChangeKind::Added);
        assert_eq!(changes[0].path, std::path::PathBuf::from("brand_new.txt"));
    }

    #[test]
    fn test_changes_modified_file() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let upper = branch.ensure_cow_copy("existing.txt").unwrap();
        fs::write(&upper, "modified content").unwrap();
        let changes = branch.changes().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, crate::dry_run::ChangeKind::Modified);
        assert_eq!(changes[0].path, std::path::PathBuf::from("existing.txt"));
    }

    #[test]
    fn test_changes_deleted_file() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("existing.txt");
        let changes = branch.changes().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, crate::dry_run::ChangeKind::Deleted);
        assert_eq!(changes[0].path, std::path::PathBuf::from("existing.txt"));
    }

    #[test]
    fn test_changes_no_changes() {
        let (workdir, storage) = setup_workdir();
        let branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let changes = branch.changes().unwrap();
        assert!(changes.is_empty());
    }

    #[test]
    fn test_changes_mixed() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let upper = branch.ensure_cow_copy("new.txt").unwrap();
        fs::write(&upper, "new").unwrap();
        let upper2 = branch.ensure_cow_copy("existing.txt").unwrap();
        fs::write(&upper2, "changed").unwrap();
        branch.mark_deleted("subdir/nested.txt");

        let mut changes = branch.changes().unwrap();
        changes.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].kind, crate::dry_run::ChangeKind::Modified);
        assert_eq!(changes[0].path, std::path::PathBuf::from("existing.txt"));
        assert_eq!(changes[1].kind, crate::dry_run::ChangeKind::Added);
        assert_eq!(changes[1].path, std::path::PathBuf::from("new.txt"));
        assert_eq!(changes[2].kind, crate::dry_run::ChangeKind::Deleted);
        assert_eq!(changes[2].path, std::path::PathBuf::from("subdir/nested.txt"));
    }

    // ---- Disk quota tests ----

    /// Helper: absolute path string for a file under the workdir.
    fn abs(branch: &SeccompCowBranch, rel: &str) -> String {
        format!("{}/{}", branch.workdir_str(), rel)
    }

    #[test]
    fn test_quota_exceeded_on_cow_copy() {
        let (workdir, storage) = setup_workdir();
        // "existing.txt" = "hello" (5 bytes). Quota = 4 bytes.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 4).unwrap();
        let err = branch.ensure_cow_copy("existing.txt").unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_allows_within_limit() {
        let (workdir, storage) = setup_workdir();
        // 5 bytes fits in 100-byte quota.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 100).unwrap();
        assert!(branch.ensure_cow_copy("existing.txt").is_ok());
    }

    #[test]
    fn test_quota_unlimited() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        assert!(branch.ensure_cow_copy("existing.txt").is_ok());
    }

    #[test]
    fn test_quota_cumulative_exhaustion() {
        let (workdir, storage) = setup_workdir();
        // "existing.txt" = 5 bytes, "subdir/nested.txt" = 6 bytes. Quota = 10.
        // First copy fits (5 <= 10), second doesn't (5 + 6 > 10).
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 10).unwrap();
        assert!(branch.ensure_cow_copy("existing.txt").is_ok());
        let err = branch.ensure_cow_copy("subdir/nested.txt").unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_exact_boundary() {
        let (workdir, storage) = setup_workdir();
        // Quota exactly equals file size — should succeed.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 5).unwrap();
        assert!(branch.ensure_cow_copy("existing.txt").is_ok());
    }

    #[test]
    fn test_quota_handle_open_write_denied() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 4).unwrap();
        let path = abs(&branch, "existing.txt");
        let err = branch.handle_open(&path, O_WRONLY).unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_handle_open_read_allowed() {
        let (workdir, storage) = setup_workdir();
        // Reads don't consume quota — even a tiny quota should allow reads.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 1).unwrap();
        let path = abs(&branch, "existing.txt");
        let result = branch.handle_open(&path, 0).unwrap(); // O_RDONLY = 0
        assert!(result.is_some());
    }

    #[test]
    fn test_quota_handle_open_create_denied() {
        let (workdir, storage) = setup_workdir();
        // O_CREAT on a deleted file triggers ensure_cow_copy.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 4).unwrap();
        let path = abs(&branch, "existing.txt");
        branch.mark_deleted("existing.txt");
        // O_CREAT on a deleted path — tries to COW-copy the 5-byte file, should fail.
        let err = branch.handle_open(&path, O_CREAT).unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_handle_mkdir_denied() {
        let (workdir, storage) = setup_workdir();
        // mkdir adds 4096 bytes of metadata accounting.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 100).unwrap();
        let path = abs(&branch, "newdir");
        let err = branch.handle_mkdir(&path).unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_handle_mkdir_allowed() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 5000).unwrap();
        let path = abs(&branch, "newdir");
        assert!(matches!(branch.handle_mkdir(&path), Ok(true)));
    }

    #[test]
    fn test_quota_handle_symlink_denied() {
        let (workdir, storage) = setup_workdir();
        // symlink adds 256 bytes of accounting.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 100).unwrap();
        let linkpath = abs(&branch, "mylink");
        let err = branch.handle_symlink("existing.txt", &linkpath).unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_handle_symlink_allowed() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 500).unwrap();
        let linkpath = abs(&branch, "mylink");
        assert!(matches!(branch.handle_symlink("existing.txt", &linkpath), Ok(true)));
    }

    #[test]
    fn test_quota_handle_rename_denied() {
        let (workdir, storage) = setup_workdir();
        // rename triggers ensure_cow_copy of the source.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 4).unwrap();
        let old = abs(&branch, "existing.txt");
        let new = abs(&branch, "renamed.txt");
        let err = branch.handle_rename(&old, &new).unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_handle_link_denied() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 4).unwrap();
        let old = abs(&branch, "existing.txt");
        let new = abs(&branch, "hardlink.txt");
        let err = branch.handle_link(&old, &new).unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_handle_chmod_denied() {
        let (workdir, storage) = setup_workdir();
        // chmod triggers ensure_cow_copy.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 4).unwrap();
        let path = abs(&branch, "existing.txt");
        let err = branch.handle_chmod(&path, 0o644).unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_handle_chown_denied() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 4).unwrap();
        let path = abs(&branch, "existing.txt");
        let err = branch.handle_chown(&path, 1000, 1000).unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_handle_truncate_grow_denied() {
        let (workdir, storage) = setup_workdir();
        // First, allow the cow copy (5 bytes), then truncate to grow beyond quota.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 10).unwrap();
        let path = abs(&branch, "existing.txt");
        // cow copy uses 5 bytes (5 of 10 used).
        // Truncating to 20 bytes needs 15 more — exceeds remaining 5.
        let err = branch.handle_truncate(&path, 20).unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_handle_truncate_shrink_allowed() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 10).unwrap();
        let path = abs(&branch, "existing.txt");
        // Truncate to 2 bytes — cow copy (5) + shrink is fine.
        assert!(matches!(branch.handle_truncate(&path, 2), Ok(true)));
        // disk_used should now be 2, not 5.
        assert_eq!(branch.disk_used, 2);
    }

    #[test]
    fn test_quota_freed_after_unlink() {
        let (workdir, storage) = setup_workdir();
        // Quota = 11 bytes. existing.txt=5, nested.txt=6. Both fit individually.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 11).unwrap();
        assert!(branch.ensure_cow_copy("existing.txt").is_ok());
        // 5 used — nested.txt (6 bytes) fits exactly.
        assert!(branch.ensure_cow_copy("subdir/nested.txt").is_ok());

        // Now at 11 used. Can't add anything — but unlink existing.txt to free 5 bytes.
        let path = abs(&branch, "existing.txt");
        assert!(branch.handle_unlink(&path, false).unwrap());
        // disk_used should now be 6 (only nested.txt in upper).
        assert_eq!(branch.disk_used, 6);

        // Now we can write a new 5-byte file (6 + 5 = 11 <= 11).
        assert!(branch.ensure_cow_copy("existing.txt").is_ok());
    }

    #[test]
    fn test_quota_second_cow_copy_is_free() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 5).unwrap();
        // First cow copy: 5 bytes used.
        assert!(branch.ensure_cow_copy("existing.txt").is_ok());
        // Second cow copy of same file: already in upper, should be free (no quota hit).
        assert!(branch.ensure_cow_copy("existing.txt").is_ok());
    }

    #[test]
    fn test_quota_disk_used_tracking() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 1000).unwrap();
        assert_eq!(branch.disk_used, 0);
        branch.ensure_cow_copy("existing.txt").unwrap(); // 5 bytes
        assert_eq!(branch.disk_used, 5);
        branch.ensure_cow_copy("subdir/nested.txt").unwrap(); // 6 bytes
        assert_eq!(branch.disk_used, 11);
    }

    #[test]
    fn test_quota_new_file_blocked_when_exhausted() {
        let (workdir, storage) = setup_workdir();
        // Quota = 5 bytes. COW-copy existing.txt to fill it exactly.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 5).unwrap();
        assert!(branch.ensure_cow_copy("existing.txt").is_ok()); // 5 of 5 used

        // Creating a new file (not in lower) should be blocked — quota is full.
        let err = branch.ensure_cow_copy("brand_new.txt").unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
    }

    #[test]
    fn test_quota_new_file_allowed_when_space_remains() {
        let (workdir, storage) = setup_workdir();
        // Quota = 100 bytes, 0 used — new file creation should succeed.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 100).unwrap();
        assert!(branch.ensure_cow_copy("brand_new.txt").is_ok());
    }

    #[test]
    fn test_quota_resync_on_write_open() {
        let (workdir, storage) = setup_workdir();
        // Quota = 50 bytes. COW-copy existing.txt (5 bytes tracked).
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 50).unwrap();
        let path = abs(&branch, "existing.txt");
        let upper = branch.handle_open(&path, O_WRONLY).unwrap().unwrap();

        // Simulate a write() that bypasses the supervisor — grow the
        // file in upper directly (as the kernel would via the injected fd).
        fs::write(&upper, vec![0u8; 50]).unwrap();

        // disk_used counter is stale (still 5), but the next write open
        // should resync from the real upper dir and see 50 bytes.
        assert_eq!(branch.disk_used, 5); // stale before resync

        let path2 = abs(&branch, "subdir/nested.txt");
        let err = branch.handle_open(&path2, O_WRONLY).unwrap_err();
        assert!(matches!(err, BranchError::QuotaExceeded));
        // After resync, disk_used reflects the real upper size.
        assert!(branch.disk_used >= 50);
    }

    #[test]
    fn test_quota_resync_not_triggered_on_read() {
        let (workdir, storage) = setup_workdir();
        // Quota = 10 bytes. COW-copy existing.txt (5 bytes), then grow
        // it behind our back. A read-only open should NOT resync or fail.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 10).unwrap();
        let write_path = abs(&branch, "existing.txt");
        let upper = branch.handle_open(&write_path, O_WRONLY).unwrap().unwrap();
        fs::write(&upper, vec![0u8; 50]).unwrap(); // way over quota

        // Read-only open should succeed without resyncing.
        let read_path = abs(&branch, "existing.txt");
        let result = branch.handle_open(&read_path, 0).unwrap(); // O_RDONLY
        assert!(result.is_some());
        // disk_used still stale — resync only happens on write opens.
        assert_eq!(branch.disk_used, 5);
    }

    #[test]
    fn test_handle_open_excl_existing_file_returns_exists() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let path = abs(&branch, "existing.txt");
        // O_WRONLY | O_CREAT | O_EXCL
        let flags = 0o1 | 0o100 | 0o200;
        let err = branch.handle_open(&path, flags).unwrap_err();
        assert!(matches!(err, BranchError::Exists));
    }

    #[test]
    fn test_handle_open_excl_new_file_succeeds() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let path = abs(&branch, "brand_new.txt");
        // O_WRONLY | O_CREAT | O_EXCL
        let flags = 0o1 | 0o100 | 0o200;
        let result = branch.handle_open(&path, flags).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_handle_open_excl_deleted_file_succeeds() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let path = abs(&branch, "existing.txt");
        branch.mark_deleted("existing.txt");
        // O_WRONLY | O_CREAT | O_EXCL — deleted file should be recreatable
        let flags = 0o1 | 0o100 | 0o200;
        let result = branch.handle_open(&path, flags).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_handle_open_excl_upper_only_returns_exists() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        // Create a file only in upper (brand new file)
        let upper = branch.ensure_cow_copy("brand_new.txt").unwrap();
        std::fs::write(&upper, "content").unwrap();
        let path = abs(&branch, "brand_new.txt");
        // O_WRONLY | O_CREAT | O_EXCL — file exists in upper
        let flags = 0o1 | 0o100 | 0o200;
        let err = branch.handle_open(&path, flags).unwrap_err();
        assert!(matches!(err, BranchError::Exists));
    }

    #[test]
    fn test_prepare_open_read_unmodified_skips() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let path = abs(&branch, "existing.txt");
        // O_RDONLY
        let plan = branch.prepare_open(&path, 0).unwrap();
        assert!(matches!(plan, CowOpenPlan::Resolved(_)));
    }

    #[test]
    fn test_prepare_open_write_existing_needs_copy() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let path = abs(&branch, "existing.txt");
        // O_WRONLY
        let plan = branch.prepare_open(&path, 0o1).unwrap();
        assert!(matches!(plan, CowOpenPlan::NeedsCopy { .. }));
    }

    #[test]
    fn test_prepare_open_write_already_in_upper() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.ensure_cow_copy("existing.txt").unwrap();
        let path = abs(&branch, "existing.txt");
        let plan = branch.prepare_open(&path, 0o1).unwrap();
        assert!(matches!(plan, CowOpenPlan::UpperReady { .. }));
    }

    #[test]
    fn test_prepare_open_new_file() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let path = abs(&branch, "brand_new.txt");
        // O_WRONLY | O_CREAT
        let plan = branch.prepare_open(&path, 0o1 | 0o100).unwrap();
        assert!(matches!(plan, CowOpenPlan::UpperReady { .. }));
    }

    #[test]
    fn test_prepare_open_excl_existing_returns_exists() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let path = abs(&branch, "existing.txt");
        let flags = 0o1 | 0o100 | 0o200;
        let err = branch.prepare_open(&path, flags).unwrap_err();
        assert!(matches!(err, BranchError::Exists));
    }

    #[test]
    fn test_prepare_open_quota_reserves_before_copy() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 100).unwrap();
        let path = abs(&branch, "existing.txt");
        let plan = branch.prepare_open(&path, 0o1).unwrap();
        assert!(matches!(plan, CowOpenPlan::NeedsCopy { file_size: 5, .. }));
        assert_eq!(branch.disk_used, 5);
    }

    #[test]
    fn test_rollback_copy() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 100).unwrap();
        branch.disk_used = 50;
        branch.rollback_copy(30);
        assert_eq!(branch.disk_used, 20);
    }

    #[test]
    fn test_safe_rel_root_workdir() {
        let storage = tempfile::tempdir().unwrap();
        // Use "/" as workdir — the bug was that getdents used
        // strip_prefix("{workdir}/") which produced "//" for root,
        // causing all paths to fall back to "." and list the root
        // directory contents instead of the target directory.
        let branch = SeccompCowBranch::create(Path::new("/"), Some(storage.path()), 0).unwrap();

        assert_eq!(branch.safe_rel("/etc/apt"), Some("etc/apt".to_string()));
        assert_eq!(branch.safe_rel("/var/lib"), Some("var/lib".to_string()));
        assert_eq!(branch.safe_rel("/"), Some("".to_string()));
        assert!(branch.matches("/anything"));
    }

    #[test]
    fn test_list_merged_dir_root_workdir() {
        let storage = tempfile::tempdir().unwrap();
        let branch = SeccompCowBranch::create(Path::new("/"), Some(storage.path()), 0).unwrap();

        // list_merged_dir with a path derived from safe_rel should list
        // that directory, not the root.
        let rel = branch.safe_rel("/etc/apt/sources.list.d").unwrap();
        let entries = branch.list_merged_dir(&rel);
        // Should contain actual files from /etc/apt/sources.list.d/,
        // not top-level dirs like "bin", "usr", "var".
        assert!(!entries.iter().any(|e| e == "bin" || e == "usr" || e == "var"),
            "list_merged_dir returned root entries instead of target dir: {:?}", entries);
    }

    #[test]
    fn test_rmdir_on_file_returns_enotdir() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();

        // existing.txt is a regular file in the lower layer.
        // rmdir (is_dir=true) on it must fail with ENOTDIR.
        let path = abs(&branch, "existing.txt");
        let err = branch.handle_unlink(&path, true).unwrap_err();
        assert_eq!(err, libc::ENOTDIR);

        // The file should still exist (rmdir must not remove it).
        assert!(workdir.path().join("existing.txt").exists());
    }

    #[test]
    fn test_rmdir_on_cow_file_returns_enotdir() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();

        // Copy file to upper layer, then try rmdir on it.
        branch.ensure_cow_copy("existing.txt").unwrap();
        let path = abs(&branch, "existing.txt");
        let err = branch.handle_unlink(&path, true).unwrap_err();
        assert_eq!(err, libc::ENOTDIR);

        // The file should still be in the upper layer.
        assert!(branch.upper_dir().join("existing.txt").exists());
    }

    #[test]
    fn test_unlink_on_directory_returns_eisdir() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();

        // Create a directory in the upper layer via handle_mkdir.
        let dir_path = abs(&branch, "mydir");
        assert!(branch.handle_mkdir(&dir_path).unwrap());

        // unlink (is_dir=false) on a directory must fail with EISDIR.
        let err = branch.handle_unlink(&dir_path, false).unwrap_err();
        assert_eq!(err, libc::EISDIR);
    }

    #[test]
    fn test_rmdir_on_directory_succeeds() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();

        // Create a directory in the upper layer.
        let dir_path = abs(&branch, "mydir");
        assert!(branch.handle_mkdir(&dir_path).unwrap());

        // rmdir (is_dir=true) on a real directory should succeed.
        assert!(branch.handle_unlink(&dir_path, true).unwrap());
    }

    #[test]
    fn test_unlink_on_file_succeeds() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();

        // unlink (is_dir=false) on a regular file should succeed.
        let path = abs(&branch, "existing.txt");
        assert!(branch.handle_unlink(&path, false).unwrap());
    }

    #[test]
    fn copy_up_does_not_follow_symlinked_parent() {
        // workdir/evil -> /etc ; writing evil/group must not copy /etc/group.
        let (workdir, storage) = setup_workdir();
        std::os::unix::fs::symlink("/etc", workdir.path().join("evil")).unwrap();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();

        // ensure_cow_copy on a path reached through the symlinked parent.
        let upper = branch.ensure_cow_copy("evil/group").unwrap();

        // The upper file must NOT contain the host /etc/group contents.
        let host = std::fs::read_to_string("/etc/group").unwrap_or_default();
        let copied = std::fs::read_to_string(&upper).unwrap_or_default();
        assert!(
            copied.is_empty() || copied != host,
            "copy-up leaked /etc/group into the upper layer"
        );
    }

    #[test]
    fn copy_up_copies_legitimate_in_tree_file() {
        let (workdir, storage) = setup_workdir();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let upper = branch.ensure_cow_copy("existing.txt").unwrap();
        assert_eq!(std::fs::read_to_string(&upper).unwrap(), "hello");
    }

    #[test]
    fn commit_does_not_dereference_escaping_symlink() {
        // A pre-existing workdir symlink with an absolute target gets copied
        // verbatim into upper by prepare_copy; commit() must recreate it as a
        // symlink, never read the target's content (issue #112, commit path).
        let (workdir, storage) = setup_workdir();
        std::os::unix::fs::symlink("/etc/group", workdir.path().join("secret")).unwrap();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        // Trigger copy-up of the symlink into upper.
        let upper = branch.ensure_cow_copy("secret").unwrap();
        assert!(upper.is_symlink(), "precondition: upper holds a verbatim symlink");

        branch.commit().unwrap();

        let committed = workdir.path().join("secret");
        assert!(
            committed.is_symlink(),
            "commit dereferenced the symlink instead of recreating it"
        );
        assert_eq!(std::fs::read_link(&committed).unwrap(), std::path::Path::new("/etc/group"));
        // The workdir entry must not have become a regular file holding the host content.
        let meta = std::fs::symlink_metadata(&committed).unwrap();
        assert!(meta.file_type().is_symlink());
    }

    #[test]
    fn cow_copy_preserves_in_tree_symlink() {
        // The confined-stat classification in prepare_copy must still treat an
        // in-tree symlink as a symlink and copy it verbatim into upper.
        let (workdir, storage) = setup_workdir();
        std::os::unix::fs::symlink("existing.txt", workdir.path().join("link")).unwrap();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let upper = branch.ensure_cow_copy("link").unwrap();
        assert!(upper.is_symlink(), "in-tree symlink was not preserved");
        assert_eq!(
            std::fs::read_link(&upper).unwrap(),
            std::path::Path::new("existing.txt")
        );
    }

    #[test]
    fn o_excl_does_not_probe_through_symlinked_parent() {
        // workdir/evil -> /etc ; open("evil/group", O_CREAT|O_EXCL) must not
        // report EEXIST based on the host /etc/group: the existence probe is
        // confined, so it cannot become a host-file oracle (issue #112).
        let (workdir, storage) = setup_workdir();
        std::os::unix::fs::symlink("/etc", workdir.path().join("evil")).unwrap();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let wd = workdir.path().canonicalize().unwrap();
        let path = format!("{}/evil/group", wd.display());
        let flags = (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY) as u64;
        assert!(
            !matches!(branch.prepare_open(&path, flags), Err(BranchError::Exists)),
            "O_EXCL followed a symlinked parent into the host /etc/group"
        );
    }

    #[test]
    fn upper_write_does_not_escape_through_symlink() {
        // workdir/evil -> <outside> (absolute symlink to a writable dir
        // outside the sandbox). Copy it up verbatim so upper/evil is also that
        // absolute symlink, then mkdir through it. The confined mkdirp must
        // clamp to the upper root, refuse, and never create the dir in
        // <outside>. Pointing at a writable TempDir (not /etc) means the test
        // distinguishes the fix from the old lexical code even when not root.
        let (workdir, storage) = setup_workdir();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), workdir.path().join("evil")).unwrap();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();

        branch.ensure_cow_copy("evil").unwrap();
        assert!(
            branch.upper_dir().join("evil").is_symlink(),
            "precondition: upper/evil must be a verbatim symlink"
        );

        let wd = workdir.path().canonicalize().unwrap();
        let escape_path = format!("{}/evil/sandlock_escape_dir", wd.display());
        // Confined: the write is clamped to the upper root and must be refused.
        assert!(
            !branch.handle_mkdir(&escape_path).unwrap(),
            "handle_mkdir reported success writing through an escaping symlink"
        );
        assert!(
            !outside.path().join("sandlock_escape_dir").exists(),
            "upper write escaped through symlinked parent into the outside dir"
        );
    }
}
