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
    /// The path was deleted in this branch (a whiteout) and is opened without
    /// `O_CREAT`. The caller must return `ENOENT` rather than letting the kernel
    /// open the untouched lower file, which still holds the pre-delete bytes.
    Deleted,
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

/// File name of the marker a preserved branch leaves in its storage dir. Lives
/// next to `upper/`, never inside it, so it is not part of the change set.
const PRESERVED_MARKER: &str = "PRESERVED";

/// Why a branch's private storage was preserved instead of reclaimed.
///
/// Every preserved branch is storage that nothing in this process will free
/// again — see [`SeccompCowBranch::preserve`]. What it holds is the upper plus
/// the marker's deletions, together: see [`PreservedBranch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreserveReason {
    /// A merge into the workdir was started and did not finish. The workdir may
    /// be partially modified — the marker is written before the first
    /// destructive step, so this is also what a merge still in flight looks
    /// like — and the storage holds the part that had not landed.
    MergeInterrupted,
    /// The changes were complete and mergeable, but the merge never started —
    /// the commit could not take the workdir lock in time. The workdir is
    /// untouched and the storage holds the whole change set.
    CommitDeferred,
    /// The caller asked for the changes to be kept for inspection rather than
    /// merged or discarded ([`crate::sandbox::BranchAction::Keep`]).
    Kept,
}

impl PreserveReason {
    /// Stable token for this reason, as written into the on-disk marker.
    fn as_token(self) -> &'static str {
        match self {
            PreserveReason::MergeInterrupted => "merge-interrupted",
            PreserveReason::CommitDeferred => "commit-deferred",
            PreserveReason::Kept => "kept",
        }
    }

    fn from_token(token: &[u8]) -> Option<Self> {
        match token {
            b"merge-interrupted" => Some(PreserveReason::MergeInterrupted),
            b"commit-deferred" => Some(PreserveReason::CommitDeferred),
            b"kept" => Some(PreserveReason::Kept),
            _ => None,
        }
    }
}

/// A branch whose storage was preserved, as read back off disk.
///
/// This is what an out-of-band recovery works from: the process that created
/// the branch is gone, so the only thing tying an upper on disk to the workdir
/// it belongs to is the marker this was parsed from.
///
/// A change set is the upper **and** [`deleted`](Self::deleted) together.
/// Deletions are tracked in RAM while the branch is live (there are no whiteout
/// entries in the upper), so recovering by copying the upper over the workdir
/// and nothing else would resurrect every file the run deleted; the marker
/// records them for exactly that reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedBranch {
    /// The branch's private storage dir, i.e. what to remove once recovered.
    pub branch_dir: PathBuf,
    /// The upper holding the preserved additions and modifications.
    pub upper: PathBuf,
    /// The workdir the changes belong to, canonicalized when the branch was
    /// created.
    pub workdir: PathBuf,
    /// Paths the run deleted, relative to `workdir`, in sorted order. The other
    /// half of the change set: nothing in `upper` represents them.
    pub deleted: Vec<PathBuf>,
    /// Why it was preserved, which says what state the workdir is in.
    pub reason: PreserveReason,
    /// The process that preserved it.
    ///
    /// Load-bearing for one thing: a `MergeInterrupted` marker is written
    /// *before* the merge, so a live merge and an interrupted one are the same
    /// record and this pid is what tells them apart (see [`list_preserved`]).
    /// Beyond that it is triage only — the process may have exited and the pid
    /// may since have been reused.
    pub pid: u32,
}

/// Escape a path's raw bytes for the line-based marker format: a path may
/// legally contain a newline, and it need not be UTF-8, so the bytes go through
/// verbatim with `\` and `\n` escaped.
fn marker_escape(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            _ => out.push(b),
        }
    }
    out
}

fn marker_unescape(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut it = raw.iter().copied();
    while let Some(b) = it.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match it.next() {
            Some(b'n') => out.push(b'\n'),
            Some(other) => out.push(other),
            None => out.push(b'\\'),
        }
    }
    out
}

/// Read the preservation marker of one branch storage dir, if it has one.
///
/// `None` means the dir is not a preserved branch: either it is live storage of
/// a running process, or it was orphaned by something that never marked it.
pub fn read_preserved(branch_dir: &Path) -> Option<PreservedBranch> {
    use std::os::unix::ffi::OsStringExt;

    let body = fs::read(branch_dir.join(PRESERVED_MARKER)).ok()?;
    let mut reason = None;
    let mut workdir = None;
    let mut upper = None;
    let mut pid = None;
    let mut deleted = Vec::new();
    for line in body.split(|&b| b == b'\n') {
        let sep = match line.iter().position(|&b| b == b'=') {
            Some(i) => i,
            None => continue,
        };
        let (key, value) = (&line[..sep], &line[sep + 1..]);
        let path = || PathBuf::from(std::ffi::OsString::from_vec(marker_unescape(value)));
        match key {
            b"reason" => reason = PreserveReason::from_token(value),
            b"workdir" => workdir = Some(path()),
            b"upper" => upper = Some(path()),
            // Repeated, one per deleted path — the only multi-valued key.
            b"deleted" => deleted.push(path()),
            b"pid" => pid = std::str::from_utf8(value).ok().and_then(|s| s.parse().ok()),
            _ => {}
        }
    }
    Some(PreservedBranch {
        branch_dir: branch_dir.to_path_buf(),
        upper: upper?,
        workdir: workdir?,
        deleted,
        reason: reason?,
        pid: pid?,
    })
}

/// Enumerate every preserved branch directly under `storage_base` — the sweep
/// primitive for recovering work this process (or a previous one) could not
/// publish.
///
/// `storage_base` is one `fs_storage` dir. With the default storage the base is
/// per-process (`$TMPDIR/sandlock-cow-<pid>`), so a sweep across process
/// lifetimes has to enumerate those bases itself; pass an explicit `fs_storage`
/// to keep every branch under one root.
///
/// Unreadable entries are skipped rather than failing the sweep: one broken
/// branch dir must not hide the rest.
///
/// **A merge that is still running looks exactly like one that was
/// interrupted.** `commit()` writes the [`PreserveReason::MergeInterrupted`]
/// marker before its first destructive step — it has to, or a crash mid-merge
/// would leave nothing to find — so for the duration of the merge the live
/// branch is listed here. The marker's `pid` is the only thing that separates
/// the two: a sweep that acts on a branch, rather than only reporting it, must
/// check that pid is not a live process first.
pub fn list_preserved(storage_base: &Path) -> Vec<PreservedBranch> {
    let mut found = Vec::new();
    if let Ok(rd) = fs::read_dir(storage_base) {
        for entry in rd.flatten() {
            if let Some(p) = read_preserved(&entry.path()) {
                found.push(p);
            }
        }
    }
    found
}

/// Disposition of a branch's private storage, which decides what `Drop` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchState {
    /// No disposition yet. The upper holds nothing the caller has asked to keep,
    /// so dropping the branch reclaims it.
    Open,
    /// The upper holds changes that must outlive this branch, for the reason
    /// carried here. The storage MUST survive `Drop`: it is the only copy of
    /// those changes, and the only thing a retry (in this process) or a sweep
    /// over [`list_preserved`] (after it is gone) can work from. Nothing frees
    /// it automatically — see [`SeccompCowBranch::preserve`].
    Preserved(PreserveReason),
    /// `commit()` or `abort()` completed. Nothing is left to reclaim — both
    /// already removed the storage.
    Finished,
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
    state: BranchState,
    /// What `Drop` does with a branch that was never disposed of: reclaim it
    /// (the default) or preserve it. Set from `BranchAction::Keep`, whose
    /// holder may never reach a disposition at all — see `Drop`.
    keep_if_abandoned: bool,
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

        // Canonicalize the workdir BEFORE creating the branch dir, so a failure
        // here (e.g. the workdir was removed between validation and now) can't
        // orphan an empty branch/upper dir on disk.
        let workdir = workdir.canonicalize()
            .map_err(|e| BranchError::Operation(format!("canonicalize workdir: {}", e)))?;

        fs::create_dir_all(&upper)
            .map_err(|e| BranchError::Operation(format!("create upper: {}", e)))?;

        Ok(Self {
            workdir_str: workdir.to_string_lossy().into_owned(),
            workdir,
            upper,
            storage_dir: branch_dir,
            deleted: HashSet::new(),
            has_changes: false,
            state: BranchState::Open,
            keep_if_abandoned: false,
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
            // Whiteout: the lower file still physically exists with its
            // pre-delete bytes. Surface the deletion so the caller returns
            // ENOENT rather than falling through to the lower file — matching
            // the async prepare_open (CowOpenPlan::Deleted) and the stat/access
            // handlers.
            return Err(BranchError::Deleted);
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
            // Whiteout: the file was deleted in this branch. Do NOT skip to the
            // lower file (which still physically exists with its pre-delete
            // content); report the deletion so the caller returns ENOENT,
            // matching the stat/access path.
            return Ok(CowOpenPlan::Deleted);
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
    /// or `Err(errno)` for filesystem errors: `ENOTDIR` when rmdir is called on
    /// a non-directory, `EISDIR` when unlink is called on a directory, `EBUSY`
    /// for the workdir root itself.
    ///
    /// Diverges from `rmdir(2)` in one destructive direction: `rmdir` on a
    /// NON-EMPTY directory is accepted here and becomes a recursive delete at
    /// commit time, where `rmdir(2)` would return `ENOTEMPTY`.
    pub fn handle_unlink(&mut self, path: &str, is_dir: bool) -> Result<bool, i32> {
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(false),
        };
        // The workdir root is not a deletable entry. Recording it would put an
        // empty relative path in `deleted`, and `commit()` would then empty the
        // whole workdir through `remove_dir_all_in_root(wd, "")` and fail
        // `EINVAL` on the root itself — permanently, on every retry.
        if rel.is_empty() || rel == "." {
            return Err(libc::EBUSY);
        }
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
    ///
    /// The merge is file-by-file and not crash-atomic. If it fails
    /// (`ENOSPC`, `EACCES`, an obstructing symlink, ...) the workdir may be left
    /// partially merged and this returns `Err` — but the upper is **preserved**,
    /// holding exactly what did not make it across: each change is dropped from
    /// the upper as it lands, so after a failure `changes()` reports the
    /// REMAINDER and not the whole run. Call `commit()` again to retry it once
    /// the cause is cleared, or `abort()` to discard the remainder. Dropping the
    /// branch after a failed commit does NOT reclaim it.
    ///
    /// Deletions are applied first, one at a time, and each is dropped from the
    /// set as it lands; if any is still outstanding when they have all been
    /// tried the commit fails there, before a single addition is copied. So a
    /// failure on this side is not "the workdir is untouched" — every deletion
    /// that could be applied already has been — it is "no addition was
    /// published, and what is left in `deleted` is what still has to happen".
    ///
    /// `Ok(())` from a merge means every recorded change landed: the successful
    /// tail removes the storage, so a change reported as merged but left behind
    /// would have no copy anywhere. Two things the merge cannot carry across,
    /// and so fail rather than claim: an entry whose name is not UTF-8, and a
    /// workdir entry of the wrong type where the upper holds a directory.
    ///
    /// The short-circuit below is the exception, and it is not a merge. On a
    /// [`BranchState::Finished`] branch there is nothing left to merge — the
    /// storage is already gone — so `Ok(())` is an idempotent no-op. On a
    /// [`PreserveReason::Kept`] branch it is a **caller error reported as
    /// success**: the upper still holds the change set, `Ok(())` comes back, and
    /// nothing lands. `Kept` means the holder deliberately took the storage over
    /// for later inspection, so committing it afterwards is a contradiction the
    /// caller has to resolve; today this code answers it by doing nothing
    /// quietly, which is a wart worth fixing before the surface is public
    /// (either exclude `Kept` from the short-circuit, or return an error).
    /// Guarded by `a_kept_branch_reports_a_commit_it_did_not_perform`.
    ///
    /// The mode of each merged file is the upper's, not the destination's.
    ///
    /// A change is dropped from the upper only after its workdir side is in
    /// place, so the failure mode of that bookkeeping is a change reported (and
    /// re-merged) twice, never one silently lost. Re-merging is idempotent: the
    /// copy truncates and the symlink is recreated.
    ///
    /// Entries are merged in sorted order, so a partial merge is a prefix of a
    /// deterministic sequence rather than an arbitrary subset.
    pub fn commit(&mut self) -> Result<(), BranchError> {
        if self.is_disposed() { return Ok(()); }

        // Enter the interrupted state BEFORE the first destructive operation,
        // which also puts the marker on disk before the workdir is touched, so a
        // crash mid-merge still leaves a sweep something to find. Every `?`
        // below returns with the state still set, which is what keeps `Drop`
        // from reclaiming an upper that holds unmerged data. Both are cleared
        // only by the successful tail of this function, which removes the whole
        // storage dir.
        //
        // The cost is that a merge in flight is indistinguishable on disk from
        // one that was interrupted, for as long as it runs. That is the right
        // way round — the alternative loses the crash — and the marker's pid is
        // what a sweep uses to tell them apart (see `list_preserved`).
        self.preserve(PreserveReason::MergeInterrupted);

        // Apply deletions, forgetting each one that is no longer outstanding so
        // a retry (and `changes()`) sees only what is left to do. Whether the
        // removal call succeeded is not the test — the entry being gone is —
        // because a deletion of something the workdir no longer has is already
        // applied.
        let pending_deletions: Vec<String> = self.deleted.iter().cloned().collect();
        let mut deletion_failure: Option<String> = None;
        for rel_path in pending_deletions {
            let dest = self.workdir.join(&rel_path);
            // Classify without dereferencing: `is_dir()` follows a symlink, so
            // a symlink pointing at a directory was dispatched to the recursive
            // remove, which then refused it with `ENOTDIR`. The guard below
            // turned that into a permanent failure of the whole merge — the
            // same errno on every retry, with no way past it.
            let dest_kind = dest.symlink_metadata();
            let removal = if dest_kind.as_ref().map(|m| m.is_dir()).unwrap_or(false) {
                crate::sys::fs::remove_dir_all_in_root(&self.workdir, &rel_path)
            } else if dest_kind.is_ok() {
                crate::sys::fs::unlinkat_in_root(&self.workdir, &rel_path, false)
            } else {
                Ok(())
            };
            if !dest.exists() && !dest.is_symlink() {
                self.deleted.remove(&rel_path);
            } else if deletion_failure.is_none() {
                deletion_failure = Some(match removal {
                    Err(e) => format!("{}: errno {}", rel_path, e),
                    Ok(()) => format!("{}: still present after removal", rel_path),
                });
            }
        }
        // A deletion left outstanding is a merge that did not happen. Stopping
        // here — before a single entry is copied — is what keeps the ADDITIONS
        // all-or-nothing: running on would publish them, and the successful
        // tail would then remove the storage and destroy the record of the
        // deletion that never landed.
        //
        // The deletions themselves are NOT all-or-nothing. The loop above
        // applies each one in turn, so by the time this fires every deletion
        // that could be applied already has been, and the workdir is not what
        // it was before the commit. Only the ones still listed in `deleted`
        // (and reported by `changes()`) are outstanding.
        if !self.deleted.is_empty() {
            let detail = deletion_failure.unwrap_or_else(|| "unknown".to_string());
            return Err(BranchError::Operation(format!(
                "delete: {} deletion(s) could not be applied to the workdir, first: {}",
                self.deleted.len(),
                detail
            )));
        }

        // Collect the entries before merging: the loop unlinks from the upper as
        // it goes, and mutating a tree while walking it is not something walkdir
        // promises to survive.
        let walk = walkdir::WalkDir::new(&self.upper)
            .min_depth(1)
            .sort_by_file_name();
        let mut entries = Vec::new();
        for entry in walk {
            entries.push(entry.map_err(|e| BranchError::Operation(format!("walk: {}", e)))?);
        }

        // Copy upper to workdir
        let mut synced_dirs = HashSet::new();
        for entry in entries {
            let rel = entry.path().strip_prefix(&self.upper).unwrap();
            let rel_str = match rel.to_str() {
                Some(s) => s,
                // The confined merge helpers take a `&str`, so this entry
                // cannot be merged. Skipping it and running on would reach the
                // successful tail, which removes the storage — reporting
                // `Ok(())` while destroying the only copy of the change.
                None => {
                    return Err(BranchError::Operation(format!(
                        "copy: {} is not valid UTF-8 and cannot be merged",
                        rel.display()
                    )))
                }
            };
            let dest = self.workdir.join(rel);
            if entry.file_type().is_dir() {
                crate::sys::fs::mkdirp_in_root(&self.workdir, rel_str, 0o755)
                    .map_err(|e| BranchError::Operation(format!("mkdir: {}", e)))?;
                // `mkdirp_in_root` reports `EEXIST` as success, so without this
                // an entry of another type already at that path would swallow
                // the whole subdirectory and still return `Ok(())`.
                if !dest.symlink_metadata().map(|m| m.is_dir()).unwrap_or(false) {
                    return Err(BranchError::Operation(format!(
                        "mkdir: {} exists in the workdir and is not a directory",
                        rel_str
                    )));
                }
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
                self.drop_merged_entry(entry.path());
                synced_dirs.insert(dest.parent().unwrap().to_path_buf());
            } else {
                if let Some(p) = parent_rel(rel_str) {
                    let _ = crate::sys::fs::mkdirp_in_root(&self.workdir, p, 0o755);
                }
                // Source is the upper entry (supervisor-owned real path, safe to read directly).
                let mut src = fs::File::open(entry.path())
                    .map_err(|e| BranchError::Operation(format!("copy: {}", e)))?;
                // The upper's mode is the run's intent: a copy-up carries the
                // lower file's mode across, and a file the child created carries
                // the mode the child asked for. The create mode below only
                // applies to a destination that does not exist yet, and never to
                // one being truncated, so the mode has to be set explicitly.
                let src_mode = src
                    .metadata()
                    .ok()
                    .map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o7777);
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
                if let Some(mode) = src_mode {
                    // fchmod on the fd this merge opened — no second path
                    // resolution, so nothing can be swapped in underneath it.
                    dst.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(mode))
                        .map_err(|e| BranchError::Operation(format!("chmod: {}", e)))?;
                }
                drop((src, dst));
                self.drop_merged_entry(entry.path());
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
        self.state = BranchState::Finished;
        Ok(())
    }

    /// Forget an upper entry that is now in the workdir, so what is left in the
    /// upper is the unmerged remainder.
    ///
    /// Best-effort: if the unlink fails the entry stays and is merged again on a
    /// retry, which is harmless — the alternative (assuming it is gone) would
    /// drop a change that never landed. Directories are left in place; they are
    /// not changes (`changes()` skips them) and removing them here would have to
    /// wait for their contents anyway.
    fn drop_merged_entry(&mut self, upper_path: &Path) {
        if let Ok(meta) = upper_path.symlink_metadata() {
            if fs::remove_file(upper_path).is_ok() {
                self.disk_used = self.disk_used.saturating_sub(meta.len());
            }
        }
    }

    /// Abort: discard all changes.
    ///
    /// After a failed `commit()` this is a deliberate request to throw the
    /// unmerged remainder away; the workdir stays as the partial merge left it.
    pub fn abort(&mut self) -> Result<(), BranchError> {
        if self.is_disposed() { return Ok(()); }
        self.cleanup();
        self.state = BranchState::Finished;
        Ok(())
    }

    /// Mark the branch as intentionally kept: its upper is left on disk and the
    /// `Drop` backstop below will not clean it up. Used for `BranchAction::Keep`,
    /// which preserves the changes for later inspection rather than merging or
    /// discarding them.
    pub(crate) fn keep(&mut self) {
        self.preserve(PreserveReason::Kept);
    }

    /// Record that this branch's holder asked for `BranchAction::Keep`, so an
    /// abandoned branch (never committed, aborted or kept) is preserved by
    /// `Drop` instead of reclaimed.
    ///
    /// The holder that configured `Keep` may never run a disposition at all: a
    /// `Sandbox` only moves its branch into its own `Drop` handler after a
    /// completed `wait()`, and a sandbox abandoned before that is exactly the
    /// case `Keep` exists for. Without this the branch's `Drop` would silently
    /// override the request and delete the upper.
    pub(crate) fn set_keep_if_abandoned(&mut self, keep: bool) {
        self.keep_if_abandoned = keep;
    }

    /// Hand the branch's private storage over to whoever recovers it: `Drop`
    /// will not reclaim it and no other code path frees it either.
    ///
    /// This is a **deliberate leak** — the caller is asserting that the storage
    /// holds the only copy of changes that must survive this process. Reclaiming
    /// it is out-of-band work, so a marker naming the workdir, the upper, the
    /// reason and this pid is written alongside the upper: without it a
    /// preserved upper is indistinguishable from any orphaned one and a sweep
    /// cannot tell which workdir it belongs to. Read it back with
    /// [`read_preserved`] / [`list_preserved`].
    ///
    /// The marker also carries the deletions. They live only in this struct's
    /// `deleted` set while the branch is live — nothing in the upper represents
    /// them — so without writing them down a preserved branch would be an upper
    /// that resurrects every file the run deleted when it is recovered.
    ///
    /// Writing the marker is best-effort. If it fails the upper is still
    /// preserved in this process — losing the data would be worse than losing
    /// the record — but an out-of-band sweep will not find it.
    pub(crate) fn preserve(&mut self, reason: PreserveReason) {
        self.state = BranchState::Preserved(reason);
        let _ = self.write_preserved_marker(reason);
    }

    fn write_preserved_marker(&self, reason: PreserveReason) -> std::io::Result<()> {
        use std::os::unix::ffi::OsStrExt;

        let mut body = Vec::new();
        body.extend_from_slice(b"reason=");
        body.extend_from_slice(reason.as_token().as_bytes());
        body.extend_from_slice(b"\nworkdir=");
        body.extend_from_slice(&marker_escape(self.workdir.as_os_str().as_bytes()));
        body.extend_from_slice(b"\nupper=");
        body.extend_from_slice(&marker_escape(self.upper.as_os_str().as_bytes()));
        // One line per deletion, sorted so the marker is byte-stable for the
        // same change set. This is the set as it stood when `preserve` was
        // called — `commit()` calls it before applying any of them — so a
        // recovery may re-apply a deletion that has since landed. That is a
        // no-op, and it is the safe direction: the other one loses a deletion.
        let mut deletions: Vec<&String> = self.deleted.iter().collect();
        deletions.sort();
        for rel in deletions {
            body.extend_from_slice(b"\ndeleted=");
            body.extend_from_slice(&marker_escape(rel.as_bytes()));
        }
        body.extend_from_slice(format!("\npid={}\n", std::process::id()).as_bytes());
        fs::write(self.storage_dir.join(PRESERVED_MARKER), body)
    }

    /// Whether a further `commit()`/`abort()` would be a no-op: the storage is
    /// either already gone or deliberately handed over to the caller.
    fn is_disposed(&self) -> bool {
        matches!(
            self.state,
            BranchState::Finished | BranchState::Preserved(PreserveReason::Kept)
        )
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.storage_dir);
    }
}

impl Drop for SeccompCowBranch {
    /// Reclaims the branch's private storage when it was never disposed of.
    ///
    /// **Blast radius**: this applies to *every* holder of a `SeccompCowBranch`,
    /// not only transactions. A `Sandbox` whose branch is abandoned without
    /// `wait()` (or that panicked before its `Drop` ran a disposition) no longer
    /// leaves its upper behind; scratch branches in tests likewise vanish at end
    /// of scope. That is a behavior change, not a pure leak fix. The one thing it
    /// deliberately does not override is an explicit `BranchAction::Keep`, which
    /// the holder records with [`Self::set_keep_if_abandoned`] — "keep for later
    /// inspection" has to survive the abandoned case, which *is* the forensic
    /// case.
    ///
    /// It is deliberately **not** a "clean up on error" hook: anything the code
    /// marked [`BranchState::Preserved`] holds changes that must outlive the
    /// failure (see [`PreserveReason`]) and is kept. Only [`BranchState::Open`],
    /// i.e. no disposition was ever attempted, reclaims here.
    ///
    /// `remove_dir_all` is idempotent and scoped to this branch's own uuid dir,
    /// never to a caller-supplied `fs_storage` base.
    fn drop(&mut self) {
        if self.state == BranchState::Open {
            if self.keep_if_abandoned {
                self.preserve(PreserveReason::Kept);
            } else {
                self.cleanup();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn drop_cleans_undisposed_branch_but_keep_preserves() {
        let workdir = tempfile::tempdir().unwrap();

        // A branch dropped without commit/abort/keep must remove its private
        // storage dir — otherwise a failed/aborted-by-error transaction orphans
        // the upper on disk (the leak this Drop backstop closes).
        let leaked = {
            let branch = SeccompCowBranch::create(workdir.path(), None, 0).unwrap();
            let dir = branch.storage_dir.clone();
            assert!(dir.exists());
            dir
        };
        assert!(!leaked.exists(), "an undisposed branch must clean its storage on drop");

        // keep() marks the branch finished, so Drop preserves the upper.
        let kept = {
            let mut branch = SeccompCowBranch::create(workdir.path(), None, 0).unwrap();
            let dir = branch.storage_dir.clone();
            branch.keep();
            dir
        };
        assert!(kept.exists(), "a kept branch must survive drop");
        let _ = fs::remove_dir_all(&kept);
    }

    /// A deletion that could not be applied must FAIL the commit. Reporting
    /// `Ok(())` here is worse than any other merge failure: it claims an
    /// all-or-nothing merge that did not happen, and the successful tail then
    /// removes the storage, so the record of the missing deletion is destroyed
    /// along with the change set.
    ///
    /// The failure is injected the way it actually happens in the field, with no
    /// permission games (so it fails as intended when the suite runs as root): a
    /// symlinked parent component in the workdir. The child unlinked
    /// `link/x.txt`, which the COW layer recorded as a deletion; applying it goes
    /// through the confined `unlinkat`, which resolves `link` inside the workdir
    /// root (issue #112) and so does not reach the file the host path names.
    #[test]
    fn commit_fails_when_a_deletion_could_not_be_applied() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("x.txt"), "survives").unwrap();
        std::os::unix::fs::symlink(outside.path(), workdir.path().join("link")).unwrap();

        let storage_dir;
        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            storage_dir = branch.storage_dir.clone();
            fs::write(branch.upper.join("added.txt"), "payload").unwrap();
            branch.mark_deleted("link/x.txt");

            let err = branch
                .commit()
                .expect_err("a deletion that was not applied must fail the commit");
            assert!(
                matches!(err, BranchError::Operation(ref m) if m.starts_with("delete:")),
                "expected the deletion step to fail, got: {err:?}"
            );
            assert!(
                branch.is_deleted("link/x.txt"),
                "an unapplied deletion must stay outstanding so a retry still sees it"
            );
        }

        // All-or-nothing: the merge stopped before copying anything across.
        assert!(
            !workdir.path().join("added.txt").exists(),
            "a commit that failed on a deletion must not have merged the additions"
        );
        // ...and the change set survives the drop, marked for recovery.
        assert!(
            storage_dir.join("upper").join("added.txt").exists(),
            "the unmerged change set must be preserved, not destroyed by a bogus success"
        );
        assert!(
            read_preserved(&storage_dir).is_some(),
            "the preserved branch must be findable by an out-of-band sweep"
        );
    }

    /// A commit that fails partway must PRESERVE the upper: the workdir is
    /// already partially merged, so the unmerged remainder in the upper is the
    /// only copy of the outstanding data and the only thing a retry or an
    /// out-of-band recovery can work from. Dropping the branch after such a
    /// failure must not reclaim it either.
    ///
    /// The failure is injected the way it actually happens in the field: the
    /// workdir holds a symlink where the upper holds a regular file, so the
    /// merge's `openat2(O_NOFOLLOW)` fails with `ELOOP`. No permission games, so
    /// this also fails as intended when the suite runs as root.
    #[test]
    fn failed_commit_preserves_the_unmerged_upper() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        // The obstruction: a symlink in the workdir at the path the merge will
        // try to write a regular file to.
        std::os::unix::fs::symlink("/dev/null", workdir.path().join("blocked.txt")).unwrap();

        let storage_dir;
        let upper_dir;
        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            storage_dir = branch.storage_dir.clone();
            upper_dir = branch.upper.clone();
            fs::write(upper_dir.join("blocked.txt"), "unmerged payload").unwrap();

            let err = branch.commit().expect_err("the obstructed merge must fail");
            assert!(
                matches!(err, BranchError::Operation(ref m) if m.starts_with("copy:")),
                "expected the copy step to fail, got: {err:?}"
            );
            // Still on disk WHILE the branch is alive...
            assert!(upper_dir.join("blocked.txt").exists());
        }
        // ...and still on disk AFTER the drop. This is the regression that
        // matters: reclaiming here destroys the only copy of the remainder.
        assert!(
            storage_dir.exists(),
            "a branch whose commit failed must keep its storage after drop"
        );
        assert_eq!(
            fs::read_to_string(upper_dir.join("blocked.txt")).unwrap(),
            "unmerged payload",
            "the unmerged remainder must survive intact"
        );
    }

    /// Because a failed commit does not latch the branch as finished, clearing
    /// the cause and calling `commit()` again completes the merge. A guard that
    /// simply marked the branch finished on entry would turn the retry into a
    /// silent no-op that reports success.
    #[test]
    fn commit_is_retryable_after_a_failed_merge() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/null", workdir.path().join("blocked.txt")).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
        fs::write(branch.upper.join("blocked.txt"), "payload").unwrap();
        branch.commit().expect_err("the obstructed merge must fail");

        // Clear the obstruction and retry.
        fs::remove_file(workdir.path().join("blocked.txt")).unwrap();
        branch.commit().expect("the retry must complete the merge");

        assert_eq!(
            fs::read_to_string(workdir.path().join("blocked.txt")).unwrap(),
            "payload",
            "the retried commit must actually merge the remainder"
        );
        assert!(!storage_dir.exists(), "a completed commit reclaims its storage");
    }

    /// After a partial merge the upper must hold the REMAINDER, not the whole
    /// run: `changes()` is what an operator recovering a half-merged workdir
    /// reads to find out what is still outstanding, and it walks the upper. So
    /// each change has to leave the upper as it lands — otherwise a 2-of-3 merge
    /// reports the same three changes as a 0-of-3 merge and the answer is
    /// useless.
    #[test]
    fn a_partial_merge_leaves_only_the_remainder_in_the_upper() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        // Merged in sorted order: a.txt lands, b.txt hits the obstruction
        // (symlink vs regular file → ELOOP under O_NOFOLLOW), c.txt is never
        // reached.
        std::os::unix::fs::symlink("/dev/null", workdir.path().join("b.txt")).unwrap();
        fs::write(workdir.path().join("gone.txt"), "delete me").unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        for name in ["a.txt", "b.txt", "c.txt"] {
            fs::write(branch.upper.join(name), name).unwrap();
        }
        branch.mark_deleted("gone.txt");

        branch.commit().expect_err("the obstructed merge must fail");

        assert_eq!(
            fs::read_to_string(workdir.path().join("a.txt")).unwrap(),
            "a.txt",
            "a.txt was merged before the failure",
        );
        assert!(!branch.upper.join("a.txt").exists(), "a merged change must leave the upper");
        assert!(
            !workdir.path().join("gone.txt").exists(),
            "the deletion was applied before the failure",
        );

        let mut outstanding: Vec<(crate::dry_run::ChangeKind, String)> = branch
            .changes()
            .unwrap()
            .into_iter()
            .map(|c| (c.kind, c.path.display().to_string()))
            .collect();
        outstanding.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(
            outstanding,
            vec![
                // b.txt is "modified" because the obstructing symlink is still
                // there in the workdir; c.txt was never reached.
                (crate::dry_run::ChangeKind::Modified, "b.txt".to_string()),
                (crate::dry_run::ChangeKind::Added, "c.txt".to_string()),
            ],
            "changes() after a partial merge must report the remainder only",
        );

        // And the retry finishes exactly that remainder.
        fs::remove_file(workdir.path().join("b.txt")).unwrap();
        branch.commit().expect("the retry must complete the merge");
        assert_eq!(fs::read_to_string(workdir.path().join("b.txt")).unwrap(), "b.txt");
        assert_eq!(fs::read_to_string(workdir.path().join("c.txt")).unwrap(), "c.txt");
    }

    /// Preserving is only half a guarantee if it lives in RAM: once the process
    /// is gone a preserved upper is indistinguishable from any orphaned one and
    /// nothing says which workdir it belongs to. A sweep must be able to find it
    /// on disk, with the workdir, the reason and the payload.
    #[test]
    fn a_preserved_branch_is_findable_on_disk_after_its_process_forgets_it() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/null", workdir.path().join("blocked.txt")).unwrap();

        assert!(
            list_preserved(storage.path()).is_empty(),
            "nothing is preserved before anything has run"
        );

        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            fs::write(branch.upper.join("blocked.txt"), "unmerged payload").unwrap();
            branch.commit().expect_err("the obstructed merge must fail");
            // Dropped here: everything the process knew about this branch is gone.
        }

        let found = list_preserved(storage.path());
        assert_eq!(found.len(), 1, "the sweep must find the preserved branch, got {found:?}");
        let b = &found[0];
        assert_eq!(
            b.reason,
            PreserveReason::MergeInterrupted,
            "the marker must say what state the workdir is in",
        );
        assert_eq!(
            b.workdir,
            workdir.path().canonicalize().unwrap(),
            "the marker must name the workdir the changes belong to",
        );
        assert_eq!(b.pid, std::process::id());
        assert_eq!(
            fs::read_to_string(b.upper.join("blocked.txt")).unwrap(),
            "unmerged payload",
            "the sweep must reach the preserved payload through the marker",
        );

        // A branch that WAS disposed of leaves nothing behind for the sweep.
        let mut clean = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(clean.upper.join("fine.txt"), "merged").unwrap();
        clean.abort().unwrap();
        assert_eq!(
            list_preserved(storage.path()).len(),
            1,
            "an aborted branch must not show up as work awaiting recovery",
        );
    }

    /// A preserved branch must carry the DELETIONS as well as the upper.
    ///
    /// Deletions live only in the branch's in-RAM `deleted` set — there are no
    /// whiteout entries in the upper — so a recovery that reads the upper alone
    /// resurrects every file the run deleted. That is the worst case of all,
    /// `commit()` on a `Kept` branch answers `Ok(())` without merging anything.
    ///
    /// This pins a WART, not a guarantee: `Ok(())` from `commit()` otherwise
    /// means the whole change set landed, and here it means the opposite — the
    /// upper still holds every byte. `is_disposed()` covers
    /// `Preserved(Kept)`, so the short-circuit at the top of `commit()` fires
    /// before any merge work. The test exists so the wart cannot be lost:
    /// whichever way it is resolved (excluding `Kept` from the short-circuit, or
    /// returning an error), this test must be updated deliberately rather than
    /// keep passing by accident.
    #[test]
    fn a_kept_branch_reports_a_commit_it_did_not_perform() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("added.txt"), "payload").unwrap();

        branch.keep();
        assert_eq!(branch.state, BranchState::Preserved(PreserveReason::Kept));

        // Reported as a successful commit...
        branch
            .commit()
            .expect("the short-circuit reports success on a Kept branch");

        // ...while nothing was merged and the change set is still in the upper.
        assert!(
            !workdir.path().join("added.txt").exists(),
            "commit() on a Kept branch must not be believed: it published nothing"
        );
        assert!(
            branch.upper.join("added.txt").exists(),
            "the Kept branch still holds the whole change set"
        );
        assert_eq!(
            branch.state,
            BranchState::Preserved(PreserveReason::Kept),
            "the short-circuit must not move a Kept branch to Finished"
        );
    }

    /// because `TxnError::Merge` tells the operator that recovering the
    /// preserved storage IS how the transaction gets finished.
    #[test]
    fn a_preserved_branch_carries_its_deletions_not_only_its_upper() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("keep.txt"), "still here").unwrap();

        // The commit-lock path: the whole change set is complete and NONE of it
        // has been applied, so a recovery that only copies the upper over the
        // workdir leaves keep.txt behind — a file the run deleted.
        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            fs::write(branch.upper.join("added.txt"), "payload").unwrap();
            branch.mark_deleted("keep.txt");
            branch.mark_deleted("sub/also gone.txt");
            branch.preserve(PreserveReason::CommitDeferred);
        }

        let found = list_preserved(storage.path());
        assert_eq!(found.len(), 1, "the sweep must find the preserved branch, got {found:?}");
        assert!(
            found[0].upper.join("added.txt").exists(),
            "the additions are the half that lives in the upper",
        );
        assert_eq!(
            found[0].deleted,
            vec![PathBuf::from("keep.txt"), PathBuf::from("sub/also gone.txt")],
            "recovering the preserved branch must not resurrect what the run deleted",
        );
    }

    /// The marker is a line-based format holding paths, and a path may contain a
    /// newline (and need not be UTF-8). Round-trip one so the format cannot be
    /// silently broken by a legal workdir name — including a DELETED path, which
    /// is a name the child chose and so is even less constrained.
    #[test]
    fn the_preserved_marker_round_trips_a_deleted_path_with_a_newline() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/null", workdir.path().join("blocked.txt")).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("blocked.txt"), "payload").unwrap();
        branch.mark_deleted("we\nird\\name.txt");
        branch.commit().expect_err("the obstructed merge must fail");

        let found = list_preserved(storage.path());
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].deleted,
            vec![PathBuf::from("we\nird\\name.txt")],
            "a deleted path with a newline and a backslash must survive the round-trip",
        );
    }

    /// The marker is a line-based format holding paths, and a path may contain a
    /// newline (and need not be UTF-8). Round-trip one so the format cannot be
    /// silently broken by a legal workdir name.
    #[test]
    fn the_preserved_marker_round_trips_a_path_with_a_newline() {
        let root = tempfile::tempdir().unwrap();
        let workdir = root.path().join("we\nird dir");
        fs::create_dir(&workdir).unwrap();
        let storage = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/null", workdir.join("blocked.txt")).unwrap();

        let mut branch = SeccompCowBranch::create(&workdir, Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("blocked.txt"), "payload").unwrap();
        branch.commit().expect_err("the obstructed merge must fail");

        let found = list_preserved(storage.path());
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].workdir,
            workdir.canonicalize().unwrap(),
            "a workdir path with a newline must survive the marker round-trip",
        );
    }

    /// `matches()` is the gate on every interception (`cow::dispatch` returns
    /// `Continue` when it says no), and it must say no to the branch's own
    /// storage. With `fs_storage` inside the workdir the upper is itself under
    /// the workdir prefix, so without the storage exclusion an access to
    /// `<upper>/f` would be treated as a workdir path and copied up again into
    /// `<upper>/.cow/<id>/upper/f`.
    #[test]
    fn matches_excludes_the_branch_storage_that_lives_under_the_workdir() {
        let workdir = tempfile::tempdir().unwrap();
        let wd = workdir.path().canonicalize().unwrap();
        let storage = wd.join(".cow");
        fs::create_dir(&storage).unwrap();

        let branch = SeccompCowBranch::create(&wd, Some(&storage), 0).unwrap();

        assert!(
            branch.matches(&abs(&branch, "existing.txt")),
            "a plain workdir path is what the branch is there to intercept",
        );
        let upper_file = branch.upper_dir().join("existing.txt");
        assert!(
            !branch.matches(upper_file.to_str().unwrap()),
            "the branch's own upper must not be intercepted as a workdir path",
        );
        assert!(
            !branch.matches(branch.storage_dir.to_str().unwrap()),
            "the branch's own storage dir must not be intercepted either",
        );
    }

    /// Nothing outside the workdir may be mapped into the upper. `safe_rel` is
    /// the only thing standing between a host path and a COW copy of it, so it
    /// must reject both an ordinary escape and the string-prefix trap — a
    /// sibling directory whose name merely extends the workdir's, which a
    /// non-component-wise prefix test would swallow whole.
    #[test]
    fn a_path_outside_the_workdir_is_neither_mapped_nor_intercepted() {
        let root = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let workdir = root.path().join("wd");
        let sibling = root.path().join("wd-extra");
        fs::create_dir(&workdir).unwrap();
        fs::create_dir(&sibling).unwrap();
        fs::write(sibling.join("secret.txt"), "host bytes").unwrap();

        let mut branch = SeccompCowBranch::create(&workdir, Some(storage.path()), 0).unwrap();
        let escape = sibling.canonicalize().unwrap().join("secret.txt");
        let escape = escape.to_str().unwrap();

        assert_eq!(
            branch.safe_rel(escape),
            None,
            "a sibling that merely shares the workdir's name prefix is outside the workdir",
        );
        assert!(
            !branch.matches(escape),
            "a path outside the workdir must not be intercepted at all",
        );

        // ...and a write open of it is left to the kernel: no relative path, no
        // copy-up, and the branch does not claim to hold a change.
        assert!(
            branch.handle_open(escape, O_WRONLY).unwrap().is_none(),
            "a write outside the workdir must not be redirected into the upper",
        );
        assert!(!branch.has_changes(), "nothing in the workdir was changed");
        assert!(
            !branch.upper_dir().join("secret.txt").exists()
                && !branch.upper_dir().join("../wd-extra/secret.txt").exists(),
            "the outside file must not have been copied up",
        );
    }

    /// One branch dir a sweep cannot parse must not hide the rest: a marker is
    /// written by a process that may be killed mid-write, and a storage base
    /// also holds the live storage of running branches, which have no marker at
    /// all. Either one aborting the sweep would strand every preserved change
    /// set beside it.
    #[test]
    fn a_branch_dir_the_sweep_cannot_parse_does_not_hide_the_ones_beside_it() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();

        // Live storage of a running branch: no marker.
        fs::create_dir_all(storage.path().join("live/upper")).unwrap();
        // A marker cut short before the `upper=` line was written.
        fs::create_dir(storage.path().join("truncated")).unwrap();
        fs::write(
            storage.path().join("truncated").join(PRESERVED_MARKER),
            b"reason=kept\nworkdir=/some/workdir\npid=1\n".as_slice(),
        )
        .unwrap();
        // Not a branch dir at all.
        fs::write(storage.path().join("stray-file"), "junk").unwrap();

        let preserved_dir;
        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            preserved_dir = branch.storage_dir.clone();
            fs::write(branch.upper.join("added.txt"), "payload").unwrap();
            branch.preserve(PreserveReason::CommitDeferred);
        }

        assert!(
            read_preserved(&storage.path().join("truncated")).is_none(),
            "a marker missing the upper it points at is not a recoverable branch",
        );
        assert!(
            read_preserved(&storage.path().join("live")).is_none(),
            "a branch that never marked itself is not awaiting recovery",
        );

        let found: Vec<PathBuf> = list_preserved(storage.path())
            .into_iter()
            .map(|p| p.branch_dir)
            .collect();
        assert_eq!(
            found,
            vec![preserved_dir],
            "the sweep must report the parseable branch and only that one",
        );
    }

    /// A branch kept for inspection must read back as [`PreserveReason::Kept`]:
    /// the reason is what tells a recovery what state the workdir is in, and
    /// `Kept` is the one that says the workdir was never touched and nothing is
    /// owed to it. Reading it back as an interrupted merge would send an
    /// operator looking for a half-merged workdir that does not exist.
    #[test]
    fn a_kept_branch_reads_back_as_kept_with_its_whole_change_set() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("gone.txt"), "still here").unwrap();

        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            fs::write(branch.upper.join("added.txt"), "payload").unwrap();
            branch.mark_deleted("gone.txt");
            branch.keep();
        }

        let found = list_preserved(storage.path());
        assert_eq!(found.len(), 1, "the kept branch must be findable, got {found:?}");
        assert_eq!(
            found[0].reason,
            PreserveReason::Kept,
            "the marker must say the changes were kept, not that a merge was interrupted",
        );
        assert_eq!(
            fs::read_to_string(found[0].upper.join("added.txt")).unwrap(),
            "payload",
            "the additions must be reachable through the marker",
        );
        assert_eq!(
            found[0].deleted,
            vec![PathBuf::from("gone.txt")],
            "the deletions are the half of the change set that lives only in the marker",
        );
        // Keep merges nothing: the workdir is exactly as the run found it.
        assert!(workdir.path().join("gone.txt").exists());
        assert!(!workdir.path().join("added.txt").exists());
    }

    /// `keep()` hands the storage to the caller, so a later `abort()` must not
    /// throw it away. `abort()` normally means "discard the changes", and a
    /// holder that runs one after the other — a disposition followed by a
    /// blanket cleanup — would otherwise destroy the only copy of the change
    /// set that was explicitly kept for inspection.
    #[test]
    fn abort_after_keep_does_not_destroy_the_kept_change_set() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("added.txt"), "payload").unwrap();
        branch.keep();

        branch.abort().unwrap();

        assert!(
            branch.upper.join("added.txt").exists(),
            "abort must not discard a change set that was already kept",
        );
        assert_eq!(
            fs::read_to_string(branch.upper.join("added.txt")).unwrap(),
            "payload",
            "the kept change set must survive intact",
        );
        assert_eq!(
            list_preserved(storage.path()).len(),
            1,
            "the kept branch must still be findable by a sweep after the abort",
        );
    }

    /// The marker's reason describes the state of the WORKDIR, so a second
    /// `preserve()` has to overwrite the first record rather than leave the
    /// stale one on disk.
    ///
    /// A commit that could not take the workdir lock preserves as
    /// `CommitDeferred` — the workdir is untouched — and the branch stays
    /// committable. If the retry then merges part way and fails, the workdir is
    /// half merged; a sweep still reading `commit-deferred` would recover it as
    /// though nothing had landed.
    #[test]
    fn a_second_preserve_replaces_the_reason_recorded_on_disk() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        // The obstruction that fails the merge: a symlink in the workdir where
        // the upper holds a regular file (ELOOP under O_NOFOLLOW).
        std::os::unix::fs::symlink("/dev/null", workdir.path().join("blocked.txt")).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
        fs::write(branch.upper.join("blocked.txt"), "payload").unwrap();

        branch.preserve(PreserveReason::CommitDeferred);
        assert_eq!(
            read_preserved(&storage_dir).unwrap().reason,
            PreserveReason::CommitDeferred,
            "the deferred commit left the workdir untouched",
        );

        branch.commit().expect_err("the obstructed merge must fail");

        assert_eq!(
            read_preserved(&storage_dir).unwrap().reason,
            PreserveReason::MergeInterrupted,
            "once the merge has run, the marker must say the workdir may be partial",
        );
    }

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
    fn test_prepare_open_read_deleted_reports_deleted() {
        // A file deleted in this branch is a whiteout: a read-only open must NOT
        // fall through to the untouched lower file (which still holds the
        // pre-delete bytes). It must report the deletion so the caller returns
        // ENOENT, matching the stat/access path.
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("existing.txt");
        let path = abs(&branch, "existing.txt");
        // O_RDONLY
        let plan = branch.prepare_open(&path, 0).unwrap();
        assert!(matches!(plan, CowOpenPlan::Deleted));
    }

    #[test]
    fn test_handle_open_read_deleted_reports_deleted() {
        // Sync mirror of test_prepare_open_read_deleted_reports_deleted: the
        // chroot dispatcher calls the sync handle_open, so a read-only open of a
        // whiteout must surface BranchError::Deleted (mapped to ENOENT at the
        // chroot call site) instead of Ok(None), which fell through to the
        // untouched lower file and leaked its pre-delete bytes.
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("existing.txt");
        let path = abs(&branch, "existing.txt");
        // O_RDONLY
        let err = branch.handle_open(&path, 0).unwrap_err();
        assert!(matches!(err, BranchError::Deleted));
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

    // ---- Deletions: what the merge does with each shape of workdir entry ----

    /// A deletion of a symlink that points at a directory must unlink the LINK
    /// and leave the directory alone.
    ///
    /// `is_dir()` follows the link, so classifying the deletion with it sent a
    /// symlink-to-a-directory down the recursive-remove path, which refused it
    /// with `ENOTDIR`. That is not a transient failure: the deletion stays
    /// outstanding, the guard fails the whole merge, and every retry produces
    /// the identical errno. `mv ld renamed` on a workdir holding such a link is
    /// enough to reach it.
    #[test]
    fn a_deletion_of_a_symlink_to_a_directory_unlinks_the_link_not_the_directory() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::create_dir(workdir.path().join("d")).unwrap();
        fs::write(workdir.path().join("d/inner.txt"), "must survive").unwrap();
        std::os::unix::fs::symlink("d", workdir.path().join("ld")).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("ld");
        branch
            .commit()
            .expect("deleting a symlink to a directory must not fail the merge");

        assert!(
            !workdir.path().join("ld").is_symlink(),
            "the symlink itself must be gone",
        );
        assert!(
            workdir.path().join("d").is_dir() && workdir.path().join("d/inner.txt").exists(),
            "the directory the link pointed at must be untouched, with its contents",
        );
    }

    /// A deletion of a dangling symlink, and of a symlink to a regular file,
    /// must remove the LINK without touching (or needing) the target.
    ///
    /// Both are decided by the `symlink_metadata` classification: dereferencing
    /// anywhere in that chain either makes a dangling link permanently
    /// unappliable, or deletes the target instead of the link.
    #[test]
    fn a_deletion_of_a_symlink_removes_the_link_and_never_its_target() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("target.txt"), "must survive").unwrap();
        std::os::unix::fs::symlink("target.txt", workdir.path().join("to_file")).unwrap();
        std::os::unix::fs::symlink("nowhere", workdir.path().join("dangling")).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("to_file");
        branch.mark_deleted("dangling");
        branch.commit().expect("both symlink deletions must apply");

        assert!(!workdir.path().join("to_file").is_symlink(), "the link to a file must be gone");
        assert!(!workdir.path().join("dangling").is_symlink(), "the dangling link must be gone");
        assert_eq!(
            fs::read_to_string(workdir.path().join("target.txt")).unwrap(),
            "must survive",
            "the link's target is not part of the deletion",
        );
    }

    /// A deletion at a nested path removes that entry in place and leaves every
    /// parent directory standing. Only the root-level shape was exercised
    /// before, so a merge that removed the parent instead would have gone
    /// unnoticed.
    #[test]
    fn a_nested_deletion_removes_only_the_entry_not_its_parents() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::create_dir_all(workdir.path().join("sub/dir")).unwrap();
        fs::write(workdir.path().join("sub/dir/file.txt"), "doomed").unwrap();
        fs::write(workdir.path().join("sub/sibling.txt"), "survives").unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("sub/dir/file.txt");
        branch.commit().expect("a nested deletion must apply");

        assert!(!workdir.path().join("sub/dir/file.txt").exists(), "the entry must be gone");
        assert!(workdir.path().join("sub/dir").is_dir(), "its parent must stay");
        assert!(
            workdir.path().join("sub/sibling.txt").exists(),
            "a sibling under the same parent must be untouched",
        );
    }

    /// A deletion of something the workdir no longer has is ALREADY APPLIED: it
    /// is dropped from the set and the commit succeeds.
    ///
    /// The test is "is the entry gone", not "did the removal call succeed" —
    /// which is what makes a retry after a partly-applied merge converge
    /// instead of failing forever on the deletions that landed the first time.
    #[test]
    fn a_deletion_of_something_already_absent_counts_as_applied() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("never-existed.txt");
        branch
            .commit()
            .expect("a deletion of an absent path is already applied");
        assert!(
            !branch.is_deleted("never-existed.txt"),
            "an applied deletion must be dropped from the set, or a retry re-runs it forever",
        );
    }

    /// A directory and everything recorded under it must all apply, in whatever
    /// order they come out of the set.
    ///
    /// `deleted` is a `HashSet`, so the iteration order genuinely varies per
    /// run; only order-INDEPENDENCE is assertable. It holds because each entry
    /// is tested for absence rather than for a successful removal — the
    /// recursive delete of the parent takes the children with it, and they are
    /// then already applied whichever way round they are visited.
    #[test]
    fn deletions_of_a_directory_and_its_children_apply_whatever_the_order() {
        for _ in 0..8 {
            let workdir = tempfile::tempdir().unwrap();
            let storage = tempfile::tempdir().unwrap();
            fs::create_dir_all(workdir.path().join("d/e")).unwrap();
            fs::write(workdir.path().join("d/e/f.txt"), "doomed").unwrap();

            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            branch.mark_deleted("d");
            branch.mark_deleted("d/e");
            branch.mark_deleted("d/e/f.txt");
            branch
                .commit()
                .expect("overlapping deletions must apply in any order");
            assert!(!workdir.path().join("d").exists(), "the whole subtree must be gone");
        }
    }

    /// Deletions run before additions, so `rm -rf d` followed by writing
    /// `d/new.txt` in the same run publishes `new.txt` into a directory that no
    /// longer holds the stale contents.
    ///
    /// This ordering is the only thing that makes the sequence work; run the
    /// additions first and the recursive delete takes the new file with it.
    #[test]
    fn deletions_are_applied_before_additions_at_the_same_path() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::create_dir(workdir.path().join("d")).unwrap();
        fs::write(workdir.path().join("d/stale.txt"), "from a previous run").unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("d");
        fs::create_dir_all(branch.upper.join("d")).unwrap();
        fs::write(branch.upper.join("d/new.txt"), "fresh").unwrap();
        branch.commit().expect("delete-then-recreate must merge");

        assert!(
            !workdir.path().join("d/stale.txt").exists(),
            "the deletion must have run before the addition re-created the directory",
        );
        assert_eq!(
            fs::read_to_string(workdir.path().join("d/new.txt")).unwrap(),
            "fresh",
            "the addition must survive the deletion of its parent",
        );
    }

    /// When one deletion cannot be applied, the ones that CAN already have
    /// been: deletions are applied one at a time, not as a group.
    ///
    /// The doc above `commit()` says the additions are all-or-nothing, and they
    /// are — nothing is copied. It does NOT say the deletions are, because they
    /// are not, and a caller that reads a `delete:` failure as "the workdir is
    /// as I left it" is wrong. The single-deletion test cannot see this: one
    /// deletion is a degenerate group.
    #[test]
    fn a_failed_deletion_does_not_undo_the_deletions_that_already_landed() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        // The obstruction, injected the way it happens in the field and with no
        // permission games: a symlinked parent component, which the confined
        // unlinkat resolves inside the workdir root and so cannot reach.
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("x.txt"), "outside the root").unwrap();
        std::os::unix::fs::symlink(outside.path(), workdir.path().join("link")).unwrap();
        for i in 0..6 {
            fs::write(workdir.path().join(format!("f{i}.txt")), "doomed").unwrap();
        }

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("added.txt"), "payload").unwrap();
        for i in 0..6 {
            branch.mark_deleted(&format!("f{i}.txt"));
        }
        branch.mark_deleted("link/x.txt");

        let err = branch.commit().expect_err("the unappliable deletion must fail the merge");
        assert!(
            matches!(err, BranchError::Operation(ref m) if m.starts_with("delete:")),
            "expected the deletion step to fail, got: {err:?}"
        );

        for i in 0..6 {
            assert!(
                !workdir.path().join(format!("f{i}.txt")).exists(),
                "f{i}.txt was removable, so it was removed before the failure",
            );
        }
        assert_eq!(
            branch
                .changes()
                .unwrap()
                .into_iter()
                .filter(|c| c.kind == crate::dry_run::ChangeKind::Deleted)
                .map(|c| c.path)
                .collect::<Vec<_>>(),
            vec![PathBuf::from("link/x.txt")],
            "only the deletion that did not land may still be reported outstanding",
        );
        assert!(
            !workdir.path().join("added.txt").exists(),
            "the additions are the half that IS all-or-nothing",
        );
    }

    /// A commit that failed on a deletion must complete once the obstruction is
    /// cleared: the guard is a stopping point, not a latch.
    ///
    /// Nothing else proves a branch can get past that guard at all. If it could
    /// not, `TxnError::Merge`'s promise that recovering the preserved storage
    /// finishes the transaction would be unreachable by the one route the crate
    /// does provide — calling `commit()` again.
    #[test]
    fn a_commit_that_failed_on_a_deletion_completes_after_the_obstruction_is_cleared() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("x.txt"), "outside the root").unwrap();
        std::os::unix::fs::symlink(outside.path(), workdir.path().join("link")).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
        fs::write(branch.upper.join("added.txt"), "payload").unwrap();
        branch.mark_deleted("link/x.txt");
        branch.commit().expect_err("the unappliable deletion must fail the merge");

        // Clear it the way an operator would: the deletion's target is gone, so
        // it is now already applied.
        fs::remove_file(outside.path().join("x.txt")).unwrap();

        branch.commit().expect("the retry must get past the deletion guard");
        assert_eq!(
            fs::read_to_string(workdir.path().join("added.txt")).unwrap(),
            "payload",
            "the additions held back by the guard must publish on the retry",
        );
        assert!(
            !storage_dir.exists(),
            "a completed merge must reclaim the storage it was preserving",
        );
        assert!(
            list_preserved(storage.path()).is_empty(),
            "and it must no longer look like work awaiting recovery",
        );
    }

    /// The workdir root itself is not a deletable entry.
    ///
    /// `safe_rel` maps it to the empty relative path, which `commit()` would
    /// hand to the recursive remove as "everything under the root" — emptying
    /// the workdir — and then fail `EINVAL` trying to remove the root from
    /// inside itself, permanently, on every retry. An `rmdir` of its own cwd is
    /// all it takes.
    #[test]
    fn unlinking_the_workdir_root_is_refused_before_anything_is_recorded() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("a.txt"), "must survive").unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let wd = workdir.path().canonicalize().unwrap();

        assert_eq!(
            branch.handle_unlink(wd.to_str().unwrap(), true),
            Err(libc::EBUSY),
            "rmdir of the workdir root must be refused",
        );
        assert_eq!(
            branch.handle_unlink(&format!("{}/.", wd.display()), true),
            Err(libc::EBUSY),
            "and so must the same root spelled with a trailing dot",
        );
        assert!(!branch.is_deleted(""), "nothing may have been recorded");
        assert!(!branch.has_changes(), "a refused unlink is not a change");

        branch.commit().expect("a branch with nothing recorded must commit cleanly");
        assert_eq!(
            fs::read_to_string(workdir.path().join("a.txt")).unwrap(),
            "must survive",
            "the workdir contents must not have been swept away",
        );
    }

    // ---- What `Ok(())` is allowed to mean ----

    /// A chmod with no content change must land in the workdir.
    ///
    /// `handle_chmod` copies the file up and chmods the upper, and `changes()`
    /// reports it Modified — so the run's whole visible contract says the mode
    /// change is a recorded change. The merge opens the destination with a
    /// create mode, which does nothing to a file that already exists, so
    /// without propagating the upper's mode the commit returned `Ok(())` having
    /// published nothing at all.
    #[test]
    fn a_chmod_only_change_lands_in_the_workdir() {
        use std::os::unix::fs::PermissionsExt;
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let f = workdir.path().join("f.txt");
        fs::write(&f, "content").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let wd = workdir.path().canonicalize().unwrap();
        assert!(branch.handle_chmod(&format!("{}/f.txt", wd.display()), 0o600).unwrap());
        assert_eq!(
            branch
                .changes()
                .unwrap()
                .into_iter()
                .map(|c| (c.kind, c.path))
                .collect::<Vec<_>>(),
            vec![(crate::dry_run::ChangeKind::Modified, PathBuf::from("f.txt"))],
            "precondition: the run reports the chmod as a recorded change",
        );

        branch.commit().unwrap();

        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600,
            "a change reported as merged must actually be in the workdir",
        );
        assert_eq!(
            fs::read_to_string(&f).unwrap(),
            "content",
            "and the content must be intact",
        );
    }

    /// The mode of a file created in the upper survives the merge.
    ///
    /// The merge used to hardcode the destination mode, so a script or binary
    /// the run produced arrived in the workdir un-executable — a committed
    /// result that cannot be run. `execute_copy` already carries the mode on
    /// the way down into the upper; this is the same property on the way back.
    #[test]
    fn the_mode_of_a_file_created_in_the_upper_survives_the_merge() {
        use std::os::unix::fs::PermissionsExt;
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        for (name, mode) in [("script.sh", 0o755u32), ("secret", 0o600), ("plain", 0o644)] {
            let up = branch.upper.join(name);
            fs::write(&up, "payload").unwrap();
            fs::set_permissions(&up, fs::Permissions::from_mode(mode)).unwrap();
        }
        branch.commit().unwrap();

        for (name, mode) in [("script.sh", 0o755u32), ("secret", 0o600), ("plain", 0o644)] {
            assert_eq!(
                fs::metadata(workdir.path().join(name)).unwrap().permissions().mode() & 0o777,
                mode,
                "{name} must be committed with the mode the run gave it",
            );
        }
    }

    /// An upper entry whose name is not valid UTF-8 must FAIL the merge.
    ///
    /// The confined merge helpers take a `&str`, so such an entry cannot be
    /// carried across. Skipping it and running on reached the successful tail,
    /// which removes the whole storage dir — reporting `Ok(())` while
    /// destroying the only copy of that change, with nothing left on disk for a
    /// sweep to find. Failing instead preserves the branch, which is what
    /// `Ok(())` is documented to exclude.
    #[test]
    fn a_non_utf8_upper_entry_fails_the_merge_instead_of_being_destroyed() {
        use std::os::unix::ffi::OsStrExt;
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let name = std::ffi::OsStr::from_bytes(b"bad-\xff.bin");

        let storage_dir;
        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            storage_dir = branch.storage_dir.clone();
            fs::write(branch.upper.join(name), "payload").unwrap();
            let err = branch
                .commit()
                .expect_err("an entry the merge cannot carry across must not report success");
            assert!(
                matches!(err, BranchError::Operation(ref m) if m.contains("not valid UTF-8")),
                "expected the UTF-8 refusal, got: {err:?}"
            );
        }

        assert_eq!(
            fs::read(storage_dir.join("upper").join(name)).unwrap(),
            b"payload",
            "the unmergeable change must survive on disk, not be reclaimed",
        );
        assert_eq!(
            list_preserved(storage.path()).len(),
            1,
            "and it must be findable by an out-of-band sweep",
        );
    }

    /// An upper DIRECTORY over a workdir entry of another type must fail the
    /// merge.
    ///
    /// `mkdirp_in_root` reports `EEXIST` as success and does not check the
    /// type, so the directory silently never landed while the commit returned
    /// `Ok(())` and then destroyed the storage — the same "reported merged,
    /// no copy anywhere" class as the non-UTF-8 entry, reached by an ordinary
    /// `mkdir` over a stale file.
    #[test]
    fn an_upper_directory_over_a_workdir_file_fails_the_merge() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("x"), "a file is in the way").unwrap();

        let storage_dir;
        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            storage_dir = branch.storage_dir.clone();
            fs::create_dir(branch.upper.join("x")).unwrap();
            let err = branch
                .commit()
                .expect_err("a directory that cannot be created must not report success");
            assert!(
                matches!(err, BranchError::Operation(ref m) if m.starts_with("mkdir:")),
                "expected the mkdir step to fail, got: {err:?}"
            );
        }

        assert!(
            workdir.path().join("x").is_file(),
            "the workdir entry that blocked the merge is left as it was",
        );
        assert!(
            storage_dir.join("upper").join("x").is_dir(),
            "the unmerged directory must survive for a retry",
        );
    }

    /// A commit that already succeeded is a no-op, so a workdir the caller
    /// edited afterwards is not silently overwritten by a second call.
    ///
    /// Deliberately asymmetric with a FAILED commit, which must NOT latch —
    /// see the retry test above. Both halves are the `is_disposed` /
    /// `BranchState::Finished` split, and collapsing them either way breaks one
    /// of the two.
    #[test]
    fn a_successful_commit_does_not_republish_on_a_second_call() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("f.txt"), "from the run").unwrap();
        branch.commit().unwrap();
        assert_eq!(fs::read_to_string(workdir.path().join("f.txt")).unwrap(), "from the run");

        fs::write(workdir.path().join("f.txt"), "edited afterwards").unwrap();
        branch.commit().expect("a second commit is a no-op, not an error");

        assert_eq!(
            fs::read_to_string(workdir.path().join("f.txt")).unwrap(),
            "edited afterwards",
            "a committed branch must not re-merge over a workdir that has moved on",
        );
    }

    /// `changes()` labels an entry Added or Modified by looking at the LIVE
    /// workdir, not at a snapshot taken when the branch was created.
    ///
    /// The same branch reports the same upper entry differently depending on
    /// what the workdir holds at the moment of the call, which is what a caller
    /// reading a dry run or a recovery report is actually being told.
    #[test]
    fn changes_labels_an_entry_against_the_workdir_as_it_stands_now() {
        use crate::dry_run::ChangeKind;
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();

        let branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("f.txt"), "from the run").unwrap();
        assert_eq!(
            branch.changes().unwrap()[0].kind,
            ChangeKind::Added,
            "nothing in the workdir yet, so the entry is an addition",
        );

        fs::write(workdir.path().join("f.txt"), "appeared underneath").unwrap();
        assert_eq!(
            branch.changes().unwrap()[0].kind,
            ChangeKind::Modified,
            "the label follows the live workdir: the commit will now overwrite a file",
        );
    }

    // ---- Names, symlinks and the confined path helpers ----

    /// `safe_rel` normalises the spellings that name the same entry, rejects an
    /// escape out of the workdir, and passes an INTERIOR `..` through verbatim
    /// — confinement for that lives downstream in `openat2(RESOLVE_IN_ROOT)`,
    /// not here.
    ///
    /// That split is what the whole COW layer rests on and it is written down
    /// nowhere else; a "hardening" that rejected interior `..` here, or a
    /// simplification that accepted a leading one, would both change it
    /// silently.
    #[test]
    fn safe_rel_normalises_spellings_and_rejects_only_an_escaping_prefix() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let wd = workdir.path().canonicalize().unwrap();
        let rel = |suffix: &str| branch.safe_rel(&format!("{}{}", wd.display(), suffix));

        assert_eq!(rel("/a.txt").as_deref(), Some("a.txt"));
        assert_eq!(rel("/./a.txt").as_deref(), Some("a.txt"), "a `.` component normalises away");
        assert_eq!(rel("//a.txt").as_deref(), Some("a.txt"), "a doubled separator normalises away");
        assert_eq!(rel("/sub/").as_deref(), Some("sub"), "a trailing separator normalises away");
        assert_eq!(
            branch.safe_rel(wd.to_str().unwrap()).as_deref(),
            Some(""),
            "the workdir root maps to the empty relative path",
        );

        assert_eq!(rel("/.."), None, "a leading escape is refused outright");
        assert_eq!(
            rel("/sub/../x").as_deref(),
            Some("sub/../x"),
            "an interior `..` is passed through, to be clamped by the confined syscall",
        );
        assert_eq!(
            rel("/sub/../../outside.txt").as_deref(),
            Some("sub/../../outside.txt"),
            "even one that lexically escapes: `safe_rel` is not the confinement boundary",
        );
    }

    /// `handle_symlink` refuses to record a link whose target is absolute or
    /// walks up out of the tree, and records an ordinary in-tree one.
    ///
    /// This is a deliberate security decision with an asymmetry worth pinning:
    /// a link the run CREATES with such a target is refused, while a
    /// pre-existing workdir link with the very same target is copied up
    /// verbatim by `prepare_copy` and merged back.
    #[test]
    fn handle_symlink_refuses_an_absolute_or_escaping_target_but_copies_up_a_lower_one() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc/passwd", workdir.path().join("preexisting")).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let wd = workdir.path().canonicalize().unwrap();
        let link = |n: &str| format!("{}/{}", wd.display(), n);

        assert!(
            !branch.handle_symlink("/etc/passwd", &link("abs")).unwrap(),
            "an absolute target must be refused",
        );
        assert!(
            !branch.handle_symlink("../outside", &link("up")).unwrap(),
            "a target walking out of the tree must be refused",
        );
        assert!(
            !branch.upper_dir().join("abs").is_symlink() && !branch.upper_dir().join("up").is_symlink(),
            "a refused symlink must not be recorded in the upper",
        );
        assert!(
            branch.handle_symlink("inside.txt", &link("ok")).unwrap(),
            "an ordinary relative in-tree target is recorded",
        );
        assert_eq!(fs::read_link(branch.upper_dir().join("ok")).unwrap(), PathBuf::from("inside.txt"));

        // The asymmetry: the same target, already on disk, IS copied up.
        branch.ensure_cow_copy("preexisting").unwrap();
        assert_eq!(
            fs::read_link(branch.upper_dir().join("preexisting")).unwrap(),
            PathBuf::from("/etc/passwd"),
            "a pre-existing absolute link is copied up verbatim, unlike a newly created one",
        );
    }

    // ---- The on-disk marker: what a sweep in another binary can rely on ----

    /// A marker written before `deleted=` existed must still parse, with an
    /// empty deletion list.
    ///
    /// Preserved branches outlive the binary that wrote them by construction —
    /// that is what preserving them is for — so a rolling upgrade meets old
    /// markers. Making the key required would make every one of them invisible
    /// to the sweep that is supposed to recover them.
    #[test]
    fn a_marker_written_before_the_deleted_key_existed_still_parses() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(PRESERVED_MARKER),
            b"reason=commit-deferred\nworkdir=/w\nupper=/s/upper\npid=41\n".as_slice(),
        )
        .unwrap();

        let p = read_preserved(dir.path()).expect("an older marker must still be recoverable");
        assert_eq!(p.reason, PreserveReason::CommitDeferred);
        assert_eq!(p.workdir, PathBuf::from("/w"));
        assert_eq!(p.upper, PathBuf::from("/s/upper"));
        assert_eq!(p.pid, 41);
        assert!(p.deleted.is_empty(), "no deletions were recorded, so there are none");
    }

    /// Forward compatibility has two halves that must stay apart: an UNKNOWN
    /// KEY is ignored, but an UNKNOWN REASON makes the whole branch vanish from
    /// the sweep.
    ///
    /// The second half is a trap — a newer writer plus an older sweeper reports
    /// "nothing to recover" over a complete change set — and it is the reason
    /// the first half must keep working: extending the format by adding keys is
    /// safe, extending it by adding reasons is not.
    #[test]
    fn an_unknown_marker_key_is_ignored_but_an_unknown_reason_hides_the_branch() {
        let with_key = tempfile::tempdir().unwrap();
        fs::write(
            with_key.path().join(PRESERVED_MARKER),
            b"reason=kept\nworkdir=/w\nupper=/u\npid=1\nsomething-new=x\n".as_slice(),
        )
        .unwrap();
        assert_eq!(
            read_preserved(with_key.path()).expect("an unknown key must not break parsing").reason,
            PreserveReason::Kept,
        );

        let with_reason = tempfile::tempdir().unwrap();
        fs::write(
            with_reason.path().join(PRESERVED_MARKER),
            b"reason=written-by-a-newer-build\nworkdir=/w\nupper=/u\npid=1\n".as_slice(),
        )
        .unwrap();
        assert_eq!(
            read_preserved(with_reason.path()),
            None,
            "an unrecognised reason must not be guessed at",
        );
        assert!(
            list_preserved(with_reason.path().parent().unwrap())
                .iter()
                .all(|p| p.branch_dir != with_reason.path()),
            "and the branch is then invisible to the sweep — the cost of that choice",
        );
    }

    /// Every required key is required: a marker missing any one of them is not
    /// a preserved branch.
    ///
    /// The alternative is worse than dropping it. A record defaulting `workdir`
    /// to empty joins to the process CWD, and a recovery acting on it would
    /// merge a stranger's upper into whatever directory it happened to be in.
    #[test]
    fn a_marker_missing_any_required_key_is_not_a_preserved_branch() {
        let full = "reason=kept\nworkdir=/w\nupper=/u\npid=1\n";
        for dropped in ["reason=", "workdir=", "upper=", "pid="] {
            let dir = tempfile::tempdir().unwrap();
            let body: String = full
                .lines()
                .filter(|l| !l.starts_with(dropped))
                .map(|l| format!("{l}\n"))
                .collect();
            fs::write(dir.path().join(PRESERVED_MARKER), &body).unwrap();
            assert_eq!(
                read_preserved(dir.path()),
                None,
                "a marker without {dropped} must not parse, got a record from: {body:?}",
            );
        }
        // ...and the same body with nothing dropped does parse, so the loop is
        // not passing for some unrelated reason.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(PRESERVED_MARKER), full).unwrap();
        assert!(read_preserved(dir.path()).is_some(), "the control must parse");
    }

    /// A marker truncated at any byte offset must read back as "not a preserved
    /// branch", never as a half-populated record.
    ///
    /// `write_preserved_marker` is a plain `fs::write` — create, truncate,
    /// write, no temp file and no rename — and it runs immediately before the
    /// merge's first destructive step, so a crash there leaves exactly these
    /// bytes. The dangerous shape is a prefix cut inside the `deleted=` lines:
    /// it parses as a complete record whose change set is missing deletions,
    /// and recovering from that resurrects the files the run deleted.
    #[test]
    fn a_marker_truncated_at_any_offset_never_reads_back_as_a_partial_record() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let storage_dir;
        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            storage_dir = branch.storage_dir.clone();
            branch.mark_deleted("gone-a.txt");
            branch.mark_deleted("gone-b.txt");
            branch.preserve(PreserveReason::CommitDeferred);
        }
        let marker = storage_dir.join(PRESERVED_MARKER);
        let full = fs::read(&marker).unwrap();
        let complete = read_preserved(&storage_dir).expect("the complete marker must parse");
        assert_eq!(complete.deleted.len(), 2, "precondition: both deletions are recorded");

        for cut in 0..full.len() {
            fs::write(&marker, &full[..cut]).unwrap();
            if let Some(partial) = read_preserved(&storage_dir) {
                assert_eq!(
                    partial.deleted, complete.deleted,
                    "a marker truncated at byte {cut} parsed with a SHORTER deletion list; \
                     recovering from it would resurrect the files the run deleted",
                );
            }
        }
        fs::write(&marker, &full).unwrap();
    }

    /// A non-UTF-8 workdir path round-trips through the marker byte-exactly.
    ///
    /// The escaping is documented to be byte-based rather than string-based;
    /// nothing tested it, and the failure mode is a recovery that merges into a
    /// path with `U+FFFD` where the real bytes were — a directory that does not
    /// exist, or worse, a different one that does.
    #[test]
    fn the_marker_round_trips_a_workdir_path_that_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt;
        let root = tempfile::tempdir().unwrap();
        let workdir = root.path().join(std::ffi::OsStr::from_bytes(b"dir-\xff-name"));
        fs::create_dir(&workdir).unwrap();
        let storage = tempfile::tempdir().unwrap();

        {
            let mut branch = SeccompCowBranch::create(&workdir, Some(storage.path()), 0).unwrap();
            branch.preserve(PreserveReason::CommitDeferred);
        }

        let found = list_preserved(storage.path());
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].workdir,
            workdir.canonicalize().unwrap(),
            "the raw bytes of the workdir path must survive the marker round-trip",
        );
        assert!(
            found[0].workdir.as_os_str().as_bytes().ends_with(b"dir-\xff-name"),
            "the 0xff byte must come back as itself; a lossy conversion anywhere in the \
             round-trip would have replaced it with the three bytes of U+FFFD",
        );
    }

    /// The marker is the trust anchor and the child is untrusted, so a workdir
    /// file called `PRESERVED` must not be able to become one.
    ///
    /// The child's file goes through the COW layer into `upper/PRESERVED`; the
    /// marker lives one level up, beside the upper. Flatten that layout and a
    /// child could forge or clobber the record that says which workdir a
    /// preserved change set belongs to.
    #[test]
    fn a_child_created_preserved_file_lands_inside_the_upper_not_beside_it() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
        let wd = workdir.path().canonicalize().unwrap();

        let upper = branch
            .handle_open(&format!("{}/{}", wd.display(), PRESERVED_MARKER), O_WRONLY | O_CREAT)
            .unwrap()
            .expect("the child's write must be redirected into the upper");
        assert_eq!(upper, branch.upper_dir().join(PRESERVED_MARKER));
        fs::write(&upper, b"reason=kept\nworkdir=/etc\nupper=/etc\npid=1\n".as_slice()).unwrap();

        assert_eq!(
            read_preserved(&storage_dir),
            None,
            "a file the child wrote must not be readable as this branch's marker",
        );

        branch.preserve(PreserveReason::CommitDeferred);
        let p = read_preserved(&storage_dir).expect("the real marker must be there");
        assert_eq!(p.workdir, wd, "the real marker names the real workdir, not the forged one");

        branch.abort().unwrap();
        // ...and the child's file was an ordinary change all along.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper_dir().join(PRESERVED_MARKER), "child bytes").unwrap();
        branch.commit().unwrap();
        assert_eq!(
            fs::read_to_string(workdir.path().join(PRESERVED_MARKER)).unwrap(),
            "child bytes",
            "and it merges into the workdir like any other file",
        );
    }

    /// A branch preserved as `CommitDeferred` is deliberately NOT disposed: the
    /// commit it deferred can still be run, and running it merges and reclaims.
    ///
    /// This is the documented recovery for a transaction that lost the race for
    /// the workdir lock. If `is_disposed()` were ever widened to cover it — it
    /// already covers `Kept`, which looks similar from the outside — every
    /// conflicted retry would return `Ok(())` having merged nothing.
    #[test]
    fn a_commit_deferred_branch_can_still_run_the_commit_it_deferred() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("gone.txt"), "still here").unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
        fs::write(branch.upper.join("added.txt"), "payload").unwrap();
        branch.mark_deleted("gone.txt");
        branch.preserve(PreserveReason::CommitDeferred);
        assert_eq!(list_preserved(storage.path()).len(), 1, "precondition: it is preserved");

        branch.commit().expect("a deferred commit must still be runnable");

        assert_eq!(
            fs::read_to_string(workdir.path().join("added.txt")).unwrap(),
            "payload",
            "the deferred change set must publish",
        );
        assert!(!workdir.path().join("gone.txt").exists(), "including its deletions");
        assert!(!storage_dir.exists(), "and the storage is reclaimed once it has landed");
        assert!(list_preserved(storage.path()).is_empty(), "so no sweep still sees work here");
    }

    /// A preserved branch listed by the sweep can be destroyed by `abort()` —
    /// for `MergeInterrupted` and `CommitDeferred`, but not for `Kept`.
    ///
    /// `abort()` is documented unconditionally as "discard all changes" and
    /// this is where that is literally true, including for storage another
    /// process may already have listed. The `Kept` exception is the only one,
    /// and it is what the whole `is_disposed` split exists for.
    #[test]
    fn abort_destroys_preserved_storage_except_when_it_was_kept() {
        for reason in [PreserveReason::MergeInterrupted, PreserveReason::CommitDeferred] {
            let workdir = tempfile::tempdir().unwrap();
            let storage = tempfile::tempdir().unwrap();
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            let storage_dir = branch.storage_dir.clone();
            fs::write(branch.upper.join("added.txt"), "payload").unwrap();
            branch.preserve(reason);
            assert_eq!(list_preserved(storage.path()).len(), 1, "precondition for {reason:?}");

            branch.abort().unwrap();

            assert!(!storage_dir.exists(), "abort must destroy {reason:?} storage");
            assert!(
                list_preserved(storage.path()).is_empty(),
                "and it must disappear from the sweep, mid-flight or not",
            );
        }

        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
        fs::write(branch.upper.join("added.txt"), "payload").unwrap();
        branch.keep();
        branch.abort().unwrap();
        assert!(storage_dir.exists(), "abort must not destroy storage that was kept");
    }

    /// `changes()` on a branch kept for inspection still reports the whole
    /// change set, additions and deletions.
    ///
    /// Inspecting the change set is the entire point of `Keep`, and the
    /// deletions are the half that exists nowhere but in RAM and in the marker
    /// — so a `Keep` that reported only the upper would answer "what did this
    /// run do" with half the truth.
    #[test]
    fn changes_on_a_kept_branch_still_reports_the_whole_change_set() {
        use crate::dry_run::ChangeKind;
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("gone.txt"), "still here").unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("added.txt"), "payload").unwrap();
        branch.mark_deleted("gone.txt");
        branch.keep();

        let mut reported: Vec<(ChangeKind, PathBuf)> =
            branch.changes().unwrap().into_iter().map(|c| (c.kind, c.path)).collect();
        reported.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(
            reported,
            vec![
                (ChangeKind::Added, PathBuf::from("added.txt")),
                (ChangeKind::Deleted, PathBuf::from("gone.txt")),
            ],
            "a kept branch must still describe what the run did",
        );
    }
}
