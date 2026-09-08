//! Unprivileged COW via seccomp user notification.
//!
//! Manages an upper directory for writes and tracks deletions in memory.
//! No root, no mount namespace, no kernel filesystem support needed.
//! Works on any Linux 5.9+ kernel with seccomp user notification.

use std::collections::HashSet;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// Errno for a branch failure, for handlers that answer the child directly
/// (the `handle_unlink` convention) rather than returning a `BranchError`.
fn branch_errno(e: BranchError) -> i32 {
    match e {
        BranchError::QuotaExceeded => libc::ENOSPC,
        BranchError::Denied => libc::EPERM,
        BranchError::Deleted => libc::ENOENT,
        BranchError::Exists => libc::EEXIST,
        // A kernel object cannot be staged in the upper; EXDEV makes mv and
        // ln fall back to mknod plus unlink, which the branch virtualizes.
        BranchError::NotOwned => libc::EXDEV,
        BranchError::Operation(_) | BranchError::Conflict(_) => libc::EIO,
    }
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

/// Staging name for an atomic marker rewrite. Invisible to the sweep:
/// [`read_preserved`] opens the exact name `PRESERVED`, and [`list_preserved`]
/// only descends directories.
const PRESERVED_TMP: &str = ".PRESERVED.tmp";

/// `fsync` a directory, so a name created or removed in it survives a power
/// loss. Mirrors `deletions::sync_parent_dir`, but returns the error: the
/// caller here has a decision to make on it.
///
/// `O_DIRECTORY` is not decoration. A plain open of a path that turns out to be
/// a FIFO BLOCKS until the other end is opened, and this runs with the workdir
/// commit lock held, so a non-directory at the path would wedge the commit
/// indefinitely rather than fail it. `O_DIRECTORY` is checked before the file
/// operation's `open` can block, so such a path is refused with `ENOTDIR`.
/// `O_NOFOLLOW` refuses a symlink at the final component.
///
/// For a path derived from a workdir name use [`sync_dir_in_root`] instead:
/// this one still resolves intermediate components unconfined.
fn sync_dir(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?
        .sync_all()
}

/// [`sync_dir`] for a directory named relative to a root, resolved through
/// `openat2(RESOLVE_IN_ROOT)` like every other workdir touch in the merge.
///
/// The merge fsyncs the parents of entries it removed, and those names come
/// from the child, so an unconfined open would follow a symlink or a `..` out
/// of the workdir. Confining the walk closes that; `O_DIRECTORY`/`O_NOFOLLOW`
/// close the FIFO-wedge and final-symlink cases described on [`sync_dir`].
///
/// An empty `rel` means the root itself.
///
/// Returns the raw errno rather than an `io::Error`: the caller has to decide
/// per-errno which failures are tolerable, and matching on errno is what makes
/// that decision readable.
fn sync_dir_in_root(root: &Path, rel: &str) -> Result<(), i32> {
    let fd = crate::sys::fs::openat2_in_root(
        root,
        rel,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    // SAFETY: `openat2_in_root` returns an owned fd we have not shared.
    let dir = unsafe { fs::File::from_raw_fd(fd) };
    dir.sync_all()
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

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
/// `None` means the dir is not a usable preserved branch, in one of three ways:
/// it is live storage of a running process; it was orphaned by something that
/// never marked it; or its marker exists but was cut mid-line by a crash. All
/// three return the same bare `None` — the caller cannot tell them apart, and
/// [`list_preserved`] contracts the skip — so the third, which is precisely the
/// case a sweep exists for, is rejected WHOLE rather than half-parsed, but not
/// reported.
///
/// Part of the on-disk format: **every record ends with a newline**, and a body
/// that does not is a crash-truncated record and is rejected whole.
pub fn read_preserved(branch_dir: &Path) -> Option<PreservedBranch> {
    use std::os::unix::ffi::OsStringExt;

    let body = fs::read(branch_dir.join(PRESERVED_MARKER)).ok()?;
    // The writer always ends with "\npid=<n>\n" and `marker_escape` escapes
    // b'\n' in every value, so a raw newline is only ever a line terminator: a
    // body that does not end in one was cut mid-line by a crash. Reject the
    // whole record — a truncated "pid=412" reads back as a COMPLETE record with
    // pid 41, and pid liveness is what separates a live merge from a dead one.
    // A cut that lands exactly on a line boundary drops the pid line instead,
    // which `pid?` below already rejects. This also rejects a zero-length
    // marker, the shape delayed allocation leaves.
    if body.last() != Some(&b'\n') {
        return None;
    }
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
/// `storage_base` is one `fs_storage` dir. The default storage base is now
/// **per-user, not per-process** (`$XDG_RUNTIME_DIR/sandlock-cow`, or a secure
/// `$TMPDIR/sandlock-cow-<uid>`), so one sweep of that base enumerates every
/// preserved branch this user's live and dead pids left behind —
/// [`PreservedBranch::pid`] liveness is what disambiguates an in-flight merge
/// from a crashed one. That base is nonetheless session-scoped when it is
/// `$XDG_RUNTIME_DIR` (logind reaps it on last-session-exit, size-limited
/// tmpfs); a daemon or cross-session recovery MUST pin a durable `fs_storage`.
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

/// Choose the base directory for COW branch storage when no explicit
/// `fs_storage` is set.
///
/// Prefers a per-user `$XDG_RUNTIME_DIR/sandlock-cow` — 0700, per-user, and not
/// reaped by tmp-cleaners — but **only** when the real and effective uid are
/// equal (`uid == euid`), i.e. no privilege change is in effect: a root/setuid
/// process must never write a user's preserved work into their runtime dir.
/// Gating on `euid != 0` alone was not enough — a setuid-to-non-root process
/// (`ruid=1000, euid=1001`) would still pass it and write into ruid 1000's
/// `$XDG_RUNTIME_DIR` (`/run/user/1000`) with files owned by euid 1001, the very
/// cross-user write this guard exists to prevent. Otherwise it falls back to a
/// per-uid `$TMPDIR/sandlock-cow-<uid>`
/// so a sweep still spans that user's dead pids. The pid is deliberately gone
/// from the base name — that is what lets [`list_preserved`] cross process
/// lifetimes.
///
/// Pure: the environment is injected so the choice can be tested without racing
/// process-global state.
fn preferred_storage_base(
    xdg_runtime_dir: Option<&std::ffi::OsStr>,
    tmp: &Path,
    uid: u32,
    euid: u32,
) -> PathBuf {
    if uid == euid {
        if let Some(xdg) = xdg_runtime_dir {
            if !xdg.is_empty() {
                return PathBuf::from(xdg).join("sandlock-cow");
            }
        }
    }
    tmp_storage_base(tmp, uid)
}

/// The per-uid fallback base under `$TMPDIR`.
fn tmp_storage_base(tmp: &Path, uid: u32) -> PathBuf {
    tmp.join(format!("sandlock-cow-{uid}"))
}

/// The default storage base: the XDG primary when it is usable, otherwise the
/// per-uid `$TMPDIR` fallback, both owner- and mode-checked.
///
/// No pid in the base name: the default is per-uid so a sweep spans this user's
/// dead pids. XDG is euid-gated and the tmp fallback is created 0700 with an
/// owner/symlink check.
///
/// Pure like its two callees: the environment is injected, so the whole fallback
/// chain (and its hard failure) is testable against planted directories without
/// mutating process-global state that every other test in this binary reads.
fn resolve_default_storage_base(
    xdg_runtime_dir: Option<&std::ffi::OsStr>,
    tmp: &Path,
    uid: u32,
    euid: u32,
) -> Result<PathBuf, BranchError> {
    let primary = preferred_storage_base(xdg_runtime_dir, tmp, uid, euid);
    match ensure_secure_base(&primary, uid) {
        Ok(()) => Ok(primary),
        // A stale/wrong-owner XDG (e.g. an inherited /run/user/0 after de-priv)
        // falls back to the secure tmp base rather than hard-failing.
        Err(_) => {
            let fb = tmp_storage_base(tmp, uid);
            ensure_secure_base(&fb, uid)
                .map_err(|e| BranchError::Operation(format!("create storage base: {e}")))?;
            Ok(fb)
        }
    }
}

/// Create `base` with mode 0700, or — if it already exists — require that it is
/// a real directory (not a symlink) owned by `uid`.
///
/// The default base name is now durable and predictable per user, which would
/// otherwise widen a pre-creation / symlink-swap attack: an attacker who wins
/// the race to create `$TMPDIR/sandlock-cow-<uid>` as a symlink, or as a dir
/// they own, could redirect or read another user's preserved uppers. Rejecting
/// a foreign or symlinked base closes that; the caller falls back to a base it
/// can create securely.
fn ensure_secure_base(base: &Path, uid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    match base.symlink_metadata() {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "storage base exists and is not a directory (possible symlink attack)",
                ));
            }
            if meta.uid() != uid {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "storage base is not owned by the current user",
                ));
            }
            // create() makes the base 0700; a reused base owned by us but with any
            // group/world bit set (0o077) was widened out from under us (or planted
            // pre-created and mode-relaxed), which would let another user read or
            // meddle with preserved uppers. Reject it so the caller falls back to a
            // base it can create securely, matching create()'s "0700, owner-checked"
            // contract.
            if meta.mode() & 0o077 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "storage base is group- or world-accessible (expected 0700)",
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_base_or_revalidate(base, uid),
        Err(e) => Err(e),
    }
}

/// The "base is absent" arm of [`ensure_secure_base`]: create the leaf, and if
/// something got there first, re-validate what is actually there rather than
/// trust it.
///
/// Non-recursive create on the leaf: a plain mkdir(2) fails `EEXIST` on a
/// symlink WITHOUT following it, closing the create-through-a-planted-symlink
/// TOCTOU that `recursive(true)` (create_dir_all, which accepts an existing
/// symlink-to-dir) would leave open in a world-writable `$TMPDIR`. The parent
/// (`$XDG_RUNTIME_DIR` or `$TMPDIR`) always exists, so no intermediates are
/// needed. On `EEXIST` the re-validation goes back through
/// [`ensure_secure_base`], which accepts a same-user 0700 directory and rejects
/// a symlink, a foreign-owned dir or a widened one.
///
/// Split out from its caller so the `EEXIST` path can be exercised directly.
/// It is otherwise reachable only by losing a create race, and what it does
/// depends solely on what is at the name — not on how it got there — so
/// planting the obstruction up front tests the same code with no dependence on
/// thread scheduling.
fn create_base_or_revalidate(base: &Path, uid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::DirBuilder::new().mode(0o700).create(base) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => ensure_secure_base(base, uid),
        Err(e) => Err(e),
    }
}

// ============================================================
// Cross-process commit lock
// ============================================================

/// Default for [`crate::transaction::Transaction::commit_lock_wait`]: how long a
/// transaction's commit merge waits for another commit to release the workdir
/// lock before giving up. Merges are short (a file-by-file copy of one upper),
/// so a wait this long only expires when something is genuinely wrong.
pub(crate) const COMMIT_LOCK_WAIT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for the commit lock. `flock` has no timed
/// variant, so the wait is a bounded retry over the non-blocking form.
pub(crate) const COMMIT_LOCK_POLL: Duration = Duration::from_millis(20);

/// How long a plain `Sandbox`'s commit — run synchronously in `Drop` — waits on a
/// contended workdir lock before deferring. Long enough to cover a typical
/// concurrent merge, short enough that teardown never spins the 30s a transaction
/// coordinator would.
pub(crate) const DROP_COMMIT_LOCK_WAIT: Duration = Duration::from_secs(5);

/// Why acquiring the workdir commit lock gave up, so the caller can tell
/// contention (a conflict, worth retrying) from a broken workdir.
#[derive(Debug)]
pub(crate) enum LockFailure {
    /// The lock was held by someone else for the whole wait.
    Contended(Duration),
    /// The workdir could not be opened, or `flock` failed for a reason other
    /// than contention.
    Io(std::io::Error),
}

/// Take an exclusive lock on the workdir, waiting up to `deadline_after` for a
/// concurrent commit merge to release it. `flock` has no timed variant, so this
/// is a bounded poll over the non-blocking form, with the poll sleep injected so
/// a test can observe how many times — if at all — the loop actually waited.
///
/// The lock object is an fd on the workdir DIRECTORY inode itself (not a separate
/// `.lock` file), so two `open()`s of the same workdir contend even within one
/// process — which is exactly the mutual exclusion between a transaction merge
/// and a plain-Sandbox merge that concern requires.
pub(crate) fn acquire_commit_lock_polling(
    workdir: &Path,
    deadline_after: Duration,
    mut sleep: impl FnMut(Duration),
) -> Result<std::fs::File, LockFailure> {
    use std::os::unix::io::AsRawFd;
    let lock = std::fs::File::open(workdir).map_err(LockFailure::Io)?;
    let deadline = std::time::Instant::now() + deadline_after;
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(lock);
        }
        let err = std::io::Error::last_os_error();
        // EWOULDBLOCK (== EAGAIN on Linux) means another commit holds the lock.
        // Any other errno is a real failure and must not be retried.
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(LockFailure::Io(err));
        }
        if std::time::Instant::now() >= deadline {
            return Err(LockFailure::Contended(deadline_after));
        }
        sleep(COMMIT_LOCK_POLL);
    }
}

/// Why a locked commit ([`SeccompCowBranch::commit_with_lock_polling`]) could not
/// publish the change set. The transaction coordinator maps this to a `TxnError`
/// (it holds the workdir and preserved-upper paths); a plain `Sandbox`'s `Drop`
/// collapses it into a `BranchError`. In every non-`Ok` case the upper has
/// already been preserved for recovery.
#[derive(Debug)]
pub(crate) enum CommitError {
    /// Another commit held the workdir lock for the whole wait.
    Contended(Duration),
    /// The workdir lock could not be taken for a reason other than contention.
    Lock(std::io::Error),
    /// The merge itself failed partway.
    Merge(BranchError),
}

/// Seccomp-based COW branch. Redirects writes to an upper directory
/// and tracks deletions in a subtree-aware whiteout set, mirrored to an
/// append-only log beside the upper.
pub struct SeccompCowBranch {
    workdir: PathBuf,
    workdir_str: String,
    upper: PathBuf,
    storage_dir: PathBuf,
    deleted: crate::cow::deletions::DeletionSet,
    /// Deletions this branch has already applied to the workdir.
    ///
    /// `deleted` is the durable, append-only whiteout set: it answers "is this
    /// path hidden in the merged view". It cannot answer "is this deletion
    /// still to do", because an applied entry must stay in it (removing it
    /// would resurrect the path) while the merge must not run it again. This
    /// set is that second question. RAM-only and deliberately not logged: the
    /// durable form of the remainder is the preserved marker's `deleted=`
    /// lines, not this.
    ///
    /// Accepted limitation: the commit lock is held only for the duration of
    /// ONE attempt — `commit_with_lock_polling` drops it on return — so between
    /// a failed commit and its retry the workdir is unlocked and another writer
    /// may re-create a path this branch already deleted. The retry would then
    /// not delete it again, because the entry is recorded applied. Nothing here
    /// can close that: the whiteout set cannot carry the distinction, and
    /// re-deleting unconditionally would instead let a retry destroy a file
    /// created after the branch's own deletion landed. Callers that need the
    /// workdir quiescent across retries have to hold it quiescent themselves.
    applied_deletions: HashSet<String>,
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
    ///
    /// With an explicit `storage` the base is that path verbatim (the caller
    /// owns its security). With no `storage`, the base defaults to a **stable,
    /// per-user** location so preserved work survives and a sweep can cross a
    /// user's dead pids: `$XDG_RUNTIME_DIR/sandlock-cow` when running unprivileged
    /// and that dir is available, otherwise a securely-created (0700, owner-checked)
    /// `$TMPDIR/sandlock-cow-<uid>`. `$XDG_RUNTIME_DIR` is session-scoped
    /// (reaped by logind on last-session-exit, size-limited tmpfs), so a daemon or
    /// cross-session recovery MUST set an explicit durable `fs_storage`. See
    /// [`crate::recovery`].
    pub fn create(workdir: &Path, storage: Option<&Path>, max_disk_bytes: u64) -> Result<Self, BranchError> {
        let storage_base = match storage {
            Some(p) => p.to_path_buf(),
            None => resolve_default_storage_base(
                std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
                &std::env::temp_dir(),
                unsafe { libc::getuid() },
                unsafe { libc::geteuid() },
            )?,
        };
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

        // Strictly after `create_dir_all`: the log lives IN `branch_dir`, and
        // `DeletionSet::create` swallows the open error by design (it degrades to
        // a RAM-only set). Opening it before the directory exists would silently
        // cost every branch its durable whiteout record.
        let deleted =
            crate::cow::deletions::DeletionSet::create(Some(&branch_dir.join("deleted.log")));

        Ok(Self {
            workdir_str: workdir.to_string_lossy().into_owned(),
            workdir,
            upper,
            storage_dir: branch_dir,
            deleted,
            applied_deletions: HashSet::new(),
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
    /// Used to skip read-only opens for unmodified files. A path covered by
    /// a whiteout needs interception even when re-created in the upper: the
    /// read must be redirected there, never fall through to the lower file.
    pub fn needs_read_intercept(&self, path: &str) -> bool {
        if let Some(rel) = self.safe_rel(path) {
            self.deleted.covers(&rel) || self.upper.join(&rel).exists()
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

    /// Confined lstat: does the upper hold an entry (any type) at `rel`?
    fn upper_has(&self, rel: &str) -> bool {
        crate::sys::fs::statat_in_root(&self.upper, rel, false).is_ok()
    }

    /// The branch owns filesystem data: regular files, directories, and
    /// symlinks. A FIFO, socket, or device is a kernel object that merely
    /// has a name in the tree; a copy of it is meaningless (a stub cannot be
    /// a terminal) and opening it can block the supervisor (issue #158), so
    /// its content and metadata stay with the kernel and Landlock.
    fn is_kernel_object_kind(kind: libc::mode_t) -> bool {
        matches!(kind, libc::S_IFIFO | libc::S_IFSOCK | libc::S_IFCHR | libc::S_IFBLK)
    }

    /// True when the merged entry at `rel` is a lower kernel object. An
    /// entry the branch materialized itself (a FIFO it mknod'ed) is owned.
    fn is_kernel_object(&self, rel: &str) -> bool {
        !self.upper_has(rel)
            && matches!(
                crate::sys::fs::statat_in_root(&self.workdir, rel, false),
                Ok(st) if Self::is_kernel_object_kind(st.st_mode & libc::S_IFMT)
            )
    }

    /// Check if a relative path is hidden by a whiteout in the merged view.
    /// A whiteout covers its whole subtree; an entry re-created in the upper
    /// shadows the whiteout and is visible again.
    pub fn is_deleted(&self, rel_path: &str) -> bool {
        self.deleted.covers(rel_path) && !self.upper_has(rel_path)
    }

    /// Mark a relative path as deleted (whiteout over it and its subtree).
    ///
    /// Deliberately does not touch `applied_deletions`: re-marking a path this
    /// branch already removed from the workdir leaves it non-outstanding, which
    /// is correct — the workdir entry is already gone.
    pub fn mark_deleted(&mut self, rel_path: &str) {
        self.deleted.insert(rel_path);
        self.has_changes = true;
    }

    /// The deletions still to apply. NOT filtered by upper presence: a
    /// whiteout whose path the upper re-creates must still be applied to the
    /// workdir first — that ordering is what makes `rm -rf d` then writing
    /// `d/new.txt` publish into a directory that no longer holds the stale
    /// contents (`deletions_are_applied_before_additions_at_the_same_path`).
    fn outstanding_deletions(&self) -> impl Iterator<Item = &str> {
        self.deleted.iter().filter(|r| !self.applied_deletions.contains(*r))
    }

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

        // A whiteout covers this path: the lower entry is logically gone, so
        // there is nothing to copy up. Creating over the whiteout starts
        // fresh, and the entry appearing in the upper is what re-exposes it
        // in the merged view (and what makes a re-created directory opaque).
        if self.deleted.covers(rel_path) {
            self.check_quota(0)?;
            return Ok(CowCopyPlan::Ready(upper_file));
        }

        // Classify the lower entry confined to the workdir root, so a symlinked
        // parent component cannot make us follow out of the tree (issue #112).
        // The lstat also yields the size of the entry we will actually copy.
        let st = match crate::sys::fs::statat_in_root(&self.workdir, rel_path, false) {
            Ok(st) => st,
            // Absent or confined-out: treat as a new file created in upper.
            // EACCES gets the same disposition as execute_copy's source-open
            // gives it: the supervisor cannot see inside the lower directory
            // (e.g. /root under a workdir of "/"), so the write proceeds on
            // an empty upper file rather than falling through to a real
            // permission error the virtualized child was promised not to hit.
            Err(libc::ENOENT) | Err(libc::EACCES) => {
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

        if Self::is_kernel_object_kind(kind) {
            return Err(BranchError::NotOwned);
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
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
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
        // prepare_copy classified this entry as a regular file, but it can
        // change type between that lstat and this open. Never stream a
        // non-regular source: a FIFO read blocks or steals pipe data (issue
        // #158). O_NONBLOCK above makes the FIFO open itself return instead
        // of waiting for a writer; on a regular file it is a no-op for reads.
        if !src.metadata()?.file_type().is_file() {
            create_dest()?;
            return Ok(());
        }
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

    /// Copy a lower tree into the upper, entry by entry, so a directory
    /// rename can be staged in the branch without losing the contents
    /// (issue #160). Each entry goes through the same confined,
    /// quota-accounted single-entry copy-up, so symlinks are copied verbatim
    /// and never followed (issue #112).
    ///
    /// Staging is all-or-nothing: a mid-tree failure (EACCES, EIO, quota)
    /// must propagate rather than truncate the copy, because the caller
    /// whiteouts the source afterwards and untraversed children would be
    /// silently lost at commit. On failure every upper entry this staging
    /// created is removed again and the quota re-derived.
    fn copy_up_tree(&mut self, rel: &str) -> Result<(), i32> {
        let mut created: Vec<String> = Vec::new();
        let result = self.stage_tree(rel, &mut created);
        if result.is_err() {
            for c in created.iter().rev() {
                let is_dir = crate::sys::fs::statat_in_root(&self.upper, c, false)
                    .map(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR)
                    .unwrap_or(false);
                if is_dir {
                    let _ = crate::sys::fs::remove_dir_all_in_root(&self.upper, c);
                } else {
                    let _ = crate::sys::fs::unlinkat_in_root(&self.upper, c, false);
                }
            }
            self.recalc_disk_used();
        }
        result
    }

    /// The traversal half of `copy_up_tree`: an explicit worklist (child
    /// directory depth must not become supervisor stack depth) that records
    /// every upper entry it creates into `created` for rollback.
    fn stage_tree(&mut self, root: &str, created: &mut Vec<String>) -> Result<(), i32> {
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(root.to_string());
        while let Some(rel) = queue.pop_front() {
            let was_in_upper = self.upper_has(&rel);
            self.ensure_cow_copy(&rel).map_err(branch_errno)?;
            if !was_in_upper && self.upper_has(&rel) {
                created.push(rel.clone());
            }
            let st = match crate::sys::fs::statat_in_root(&self.workdir, &rel, false) {
                Ok(st) => st,
                // Upper-only entry: nothing below it in the lower to stage.
                Err(libc::ENOENT) => continue,
                Err(e) => return Err(e),
            };
            if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                continue;
            }
            let rd = fs::read_dir(self.workdir.join(&rel))
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            for entry in rd {
                let entry = entry.map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let child = format!("{}/{}", rel, name);
                if self.deleted.covers(&child) && !self.upper_has(&child) {
                    continue;
                }
                queue.push_back(child);
            }
        }
        Ok(())
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
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(None),
        };
        if flags & O_DIRECTORY != 0 {
            // A whiteouted directory must not fall through to the kernel:
            // the lower directory still exists, so opendir would hand the
            // child a live fd (and fstat its inode) where the merged answer
            // is ENOENT.
            if self.is_deleted(&rel) {
                return Err(BranchError::Deleted);
            }
            return Ok(None);
        }

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

        if self.is_kernel_object(&rel) {
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
            // Same whiteout gate as the non-directory path: Skip would let
            // the kernel open the still-existing lower directory where the
            // merged answer is ENOENT.
            if self.is_deleted(&rel) {
                return Ok(CowOpenPlan::Deleted);
            }
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

        if self.is_kernel_object(&rel) {
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
    /// or `Err(errno)` for filesystem errors: `ENOTDIR` when rmdir is called on
    /// a non-directory, `EISDIR` when unlink is called on a directory, `EBUSY`
    /// for the workdir root itself.
    ///
    /// Matches `rmdir(2)` on a non-empty directory: emptiness is judged against
    /// the MERGED view (upper over workdir, minus whiteouts), and a non-empty
    /// one gives `ENOTEMPTY` rather than becoming a recursive delete at commit
    /// time.
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
        if self.is_deleted(&rel) {
            return Err(libc::ENOENT);
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

        // rmdir semantics come from the merged view: entries in either layer
        // that the child can still see make the directory non-empty (issue
        // #161). The path-based whiteout would otherwise delete a subtree the
        // child never emptied, and would do it while reporting success.
        if is_dir && !self.list_merged_dir(&rel).is_empty() {
            return Err(libc::ENOTEMPTY);
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
        self.has_changes = true;
        let ok = crate::sys::fs::mkdirp_in_root(&self.upper, &rel, 0o755).is_ok();
        if ok {
            self.disk_used += 4096;
        }
        Ok(ok)
    }

    /// Handle mknodat: create a file-system node in the upper layer.
    ///
    /// Returns `Err(QuotaExceeded)` when the node would exceed `max_disk`.
    /// Returns `Err(Denied)` when the node type is S_IFBLK or S_IFCHR.
    pub fn handle_mknod(&mut self, path: &str, mode: u32, dev: u64) -> Result<bool, BranchError> {
        // Only S_IFIFO, S_IFSOCK, S_IFREG, and 0 are permitted.
        // S_IFBLK/S_IFCHR are rejected: the supervisor creates nodes under its
        // own credentials, making device nodes a sandbox escape on root runs.
        let file_type = mode & libc::S_IFMT as u32; // strips the permission bits 
        let allowed = file_type == 0
            || file_type == libc::S_IFREG as u32
            || file_type == libc::S_IFIFO as u32
            || file_type == libc::S_IFSOCK as u32;
        if !allowed {
            return Err(BranchError::Denied);
        }
        let rel = match self.safe_rel(path) {
            Some(r) => r,
            None => return Ok(false),
        };
        self.check_quota(256)?;
        self.has_changes = true;
        // Ensure the parent directory exists in the upper layer before creating
        // the node (mirrors handle_symlink; parent may only exist in lower).
        if let Some(p) = parent_rel(&rel) {
            let _ = crate::sys::fs::mkdirp_in_root(&self.upper, p, 0o755);
        }
        let ok = crate::sys::fs::mknod_in_root(&self.upper, &rel, mode, dev).is_ok();
        if ok {
            self.disk_used += 256;
        }
        Ok(ok)
    }

    /// Merged-view classification of `rel`: `Some(is_dir)` when the child can
    /// see an entry there, `None` when the merged answer is ENOENT. The upper
    /// is consulted first because upper presence shadows both the lower entry
    /// and any whiteout; a trailing symlink classifies as a non-directory
    /// (rename never follows it).
    fn merged_entry_is_dir(&self, rel: &str) -> Option<bool> {
        if let Ok(st) = crate::sys::fs::statat_in_root(&self.upper, rel, false) {
            return Some(st.st_mode & libc::S_IFMT == libc::S_IFDIR);
        }
        if self.deleted.covers(rel) {
            return None;
        }
        crate::sys::fs::statat_in_root(&self.workdir, rel, false)
            .ok()
            .map(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR)
    }

    /// Handle rename.
    ///
    /// Returns `Ok(true)` on success, `Ok(false)` when the branch does not
    /// handle the path, or `Err(errno)` when the merged view forbids the
    /// rename (ENOENT for an absent or whiteouted source, ENOTEMPTY for a
    /// non-empty directory destination, EISDIR/ENOTDIR for type mismatches,
    /// ENOSPC for quota).
    pub fn handle_rename(&mut self, old_path: &str, new_path: &str) -> Result<bool, i32> {
        let old_rel = match self.safe_rel(old_path) {
            Some(r) => r,
            None => return Ok(false),
        };
        let new_rel = match self.safe_rel(new_path) {
            Some(r) => r,
            None => return Ok(false),
        };
        let src_is_dir = match self.merged_entry_is_dir(&old_rel) {
            Some(d) => d,
            None => return Err(libc::ENOENT),
        };
        // Destination semantics come from the merged view: renaming onto an
        // existing directory must replace it or refuse, never publish the
        // union of the renamed tree and the pre-existing one (issue #160
        // review). The kernel cannot give these answers because it sees only
        // one layer at a time.
        if let Some(dest_is_dir) = self.merged_entry_is_dir(&new_rel) {
            match (src_is_dir, dest_is_dir) {
                (false, true) => return Err(libc::EISDIR),
                (true, false) => return Err(libc::ENOTDIR),
                (true, true) if !self.list_merged_dir(&new_rel).is_empty() => {
                    return Err(libc::ENOTEMPTY)
                }
                _ => {}
            }
        }
        self.copy_up_tree(&old_rel)?;
        if let Some(p) = parent_rel(&new_rel) {
            let _ = crate::sys::fs::mkdirp_in_root(&self.upper, p, 0o755);
        }
        if crate::sys::fs::renameat_in_root(&self.upper, &old_rel, &new_rel).is_err() {
            return Ok(false);
        }
        // A surviving lower entry under either name gets a whiteout: the
        // source so it stops existing, the destination so commit removes it
        // before publishing the renamed entry instead of merging into it.
        // The staged upper entry shadows the destination whiteout until then.
        if crate::sys::fs::statat_in_root(&self.workdir, &old_rel, false).is_ok() {
            self.mark_deleted(&old_rel);
        }
        if crate::sys::fs::statat_in_root(&self.workdir, &new_rel, false).is_ok() {
            self.mark_deleted(&new_rel);
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
        if self.is_deleted(&old_rel) {
            return Err(BranchError::Deleted);
        }
        // linkat on a directory is the kernel's EPERM to give; staging a
        // copy for it would leave a meaningless empty dir in the upper.
        let src_is_dir = crate::sys::fs::statat_in_root(&self.upper, &old_rel, false)
            .or_else(|_| crate::sys::fs::statat_in_root(&self.workdir, &old_rel, false))
            .map(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR)
            .unwrap_or(false);
        if src_is_dir {
            return Ok(false);
        }
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
        // component cannot escape the tree (issue #112). A covered path only
        // consults the upper: falling through to the lower link would leak
        // the pre-delete target of a whiteouted-then-recreated entry.
        let roots: &[&PathBuf] = if self.deleted.covers(&rel) {
            &[&self.upper]
        } else {
            &[&self.upper, &self.workdir]
        };
        for root in roots {
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
            // A covered path's lower entry is logically gone, so a re-created
            // upper entry is an addition even though lower bytes still exist.
            let kind = if self.deleted.covers(&rel.to_string_lossy()) {
                ChangeKind::Added
            } else if lower.exists() {
                ChangeKind::Modified
            } else {
                ChangeKind::Added
            };
            result.push(Change { kind, path: rel.to_path_buf() });
        }

        // Deletions from the whiteout set; an entry re-created in the upper
        // is reported by the upper walk instead.
        for rel_path in self.deleted.iter() {
            // Already landed this run: not something the next commit will do.
            if self.applied_deletions.contains(rel_path) {
                continue;
            }
            // Re-created in the upper: the upper walk reports it instead.
            if self.upper_has(rel_path) {
                continue;
            }
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
                // covers, not is_deleted: a covered child re-created in the
                // upper was already inserted by the upper loop above.
                if !self.deleted.covers(&child_rel) {
                    entries.insert(name);
                }
            }
        }
        entries.into_iter().collect()
    }

    /// Commit: take the cross-process workdir lock, then merge upper into workdir.
    ///
    /// **Locking, blocking and the deferred-error contract.** This is the
    /// plain-`Sandbox` commit path (also run synchronously in `Sandbox::Drop`,
    /// which ignores this `Result`). It takes the SAME cross-process workdir lock
    /// as a transaction merge — so the two can no longer interleave and tear each
    /// other — but waits only `DROP_COMMIT_LOCK_WAIT` (5s) before deferring, so
    /// teardown never spins the 30s a transaction coordinator would. Because that
    /// wait is synchronous, `commit()` (and therefore dropping a committing
    /// `Sandbox`) **blocks the calling thread up to `DROP_COMMIT_LOCK_WAIT` on a
    /// contended workdir** — bounded, no CPU spin (a non-blocking `flock` polled
    /// at `COMMIT_LOCK_POLL`): do not drop a committing `Sandbox` on an async
    /// runtime worker. On a genuinely contended lock it preserves the upper as
    /// `CommitDeferred` and returns `Err` rather than tearing a merge in flight;
    /// the two lock-failure kinds map to distinct messages (contention vs a broken
    /// workdir, the latter interpolating the io error).
    ///
    /// Three failure shapes, not to be conflated:
    /// - **Contended / lock failure** (the deferral): the lock could not be taken,
    ///   the workdir is UNTOUCHED, and the WHOLE change set is preserved as
    ///   `CommitDeferred` (recoverable via [`crate::recovery::list_preserved`]).
    ///   Retry by re-running the commit once the contention clears.
    /// - **`preserve marker: ...`**: the lock WAS taken, but the crash record
    ///   could not be written, so the merge never started. The workdir is
    ///   provably untouched — this is the first thing the merge does — the
    ///   whole change set is still in the storage, and there is no marker on
    ///   disk, so an out-of-band sweep will NOT find it; only a retry in this
    ///   process will. Retryable once the storage dir is writable again.
    /// - **Merge failure** (`ENOSPC`, `EACCES`, an obstructing symlink, ...): the
    ///   lock WAS held and the merge ran; the workdir may be left partially merged
    ///   and this returns `Err`, but the upper is **preserved** holding exactly
    ///   the ADDITIONS that did not make it across — each is dropped from the
    ///   upper as it lands, so the additions remainder is what the upper still
    ///   holds and what `changes()` still reports. Call `commit()` again to
    ///   retry the remainder once the cause is cleared, or `abort()` to discard
    ///   it. Dropping the branch after a failed commit does NOT reclaim it.
    ///
    /// Deletions are applied first, one at a time, and each is recorded applied
    /// as it lands; if any is still outstanding when they have all been tried
    /// the commit fails there (`delete: ...`), before a single addition is
    /// copied. So a failure on this side is not "the workdir is untouched" —
    /// every deletion that could be applied already has been — it is "no
    /// addition was published, and some deletions are still to do".
    ///
    /// `sync workdir dir: ...` belongs to that same window: the deletions have
    /// landed, no addition has been published, and the merge stopped because
    /// making a removal durable failed with a real I/O error. Errnos for which
    /// the fsync is simply unavailable (a `0o300` directory, a parent replaced
    /// by a non-directory) do NOT fail the merge — they cannot be satisfied by
    /// any retry, and the exposure they leave is a removal that a power loss
    /// could undo, which is not destructive.
    ///
    /// `refresh preserved marker: ...` is from that same window too, and it is
    /// NOT the head `preserve marker: ...` failure: deletions have landed, and
    /// the marker still on disk is the head one, which OVER-lists what is
    /// outstanding (the safe direction, since nothing has been drained from the
    /// upper), so a sweep CAN find this branch. Retryable; the retry rewrites
    /// the marker from the current outstanding set.
    ///
    /// The deletions remainder is NOT derivable from `changes()`. The whiteout
    /// set is append-only (a landed deletion has to stay in it, or the path
    /// would reappear in the merged view), and a deletion whose path the upper
    /// re-created is folded into the upper walk rather than reported as
    /// `Deleted`. It is recorded instead in the PRESERVED marker beside the
    /// upper, refreshed after the deletion loop, which is where
    /// [`crate::error::TxnError::Merge`] points an operator.
    ///
    /// `Ok(())` from a merge means every recorded change landed: the successful
    /// tail removes the storage, so a change reported as merged but left behind
    /// would have no copy anywhere. Two things the merge cannot carry across,
    /// and so fail rather than claim: an entry whose name is not UTF-8, and a
    /// workdir entry of the wrong type where the upper holds a directory.
    ///
    /// Two short-circuits are the exception, and neither is a merge. A branch
    /// with no recorded changes returns `Ok(())` after reclaiming its storage,
    /// without writing a marker: there is no change set for a crash record to
    /// describe, so a storage dir that cannot hold one must not fail a commit
    /// that has nothing to publish.
    ///
    /// The other is disposition. On a
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
        self.commit_inner(DROP_COMMIT_LOCK_WAIT, std::thread::sleep)
    }

    /// The body of [`Self::commit`], with the lock-wait bound and the poll sleep
    /// injected so a test can exercise the contended-deferral path without
    /// actually sleeping `DROP_COMMIT_LOCK_WAIT`. Production always calls it with
    /// [`DROP_COMMIT_LOCK_WAIT`] and the real `std::thread::sleep` via
    /// [`Self::commit`].
    fn commit_inner(
        &mut self,
        lock_wait: Duration,
        sleep: impl FnMut(Duration),
    ) -> Result<(), BranchError> {
        match self.commit_with_lock_polling(lock_wait, sleep) {
            Ok(()) => Ok(()),
            Err(CommitError::Merge(e)) => Err(e),
            // The upper was preserved (CommitDeferred, or a stronger reason left
            // in place on a retry) inside `commit_with_lock_polling`; make the
            // deferral observable so it is recoverable rather than a silent lost
            // commit. Contention and a broken workdir are distinct — do not
            // collapse them into one message.
            Err(CommitError::Contended(waited)) => {
                eprintln!(
                    "sandlock: commit deferred: workdir lock on {} contended for {:?}; \
                     upper preserved for recovery",
                    self.workdir_str, waited
                );
                Err(BranchError::Operation(
                    "commit deferred: workdir lock contended".into(),
                ))
            }
            Err(CommitError::Lock(e)) => {
                eprintln!(
                    "sandlock: commit deferred: workdir lock on {} could not be taken ({}); \
                     upper preserved for recovery",
                    self.workdir_str, e
                );
                Err(BranchError::Operation(format!(
                    "commit deferred: workdir lock error: {e}"
                )))
            }
        }
    }

    /// Take the cross-process workdir lock, then merge. This is the ONE lock
    /// layer both a transaction coordinator and a plain `Sandbox` serialize on;
    /// no caller wraps this in a second lock, so there is no self-deadlock.
    ///
    /// Ordering is load-bearing:
    /// 1. a disposed/`Kept` branch never opens the lock;
    /// 2. the flock is taken BEFORE the branch is marked `MergeInterrupted`, so a
    ///    contended FRESH commit is preserved as `CommitDeferred` (workdir
    ///    untouched) and never mis-reported as a half-merge. A contended RETRY of
    ///    a commit that already failed part way keeps its stronger
    ///    `MergeInterrupted` marker rather than downgrading it (see
    ///    `preserve_deferred_unless_interrupted`), so the
    ///    `CommitDeferred => workdir untouched` implication holds across
    ///    retries. Only that direction holds: a head-marker write failure
    ///    leaves an UNTOUCHED workdir preserved as `MergeInterrupted`, the
    ///    over-strong direction, which that reason's contract ("may have
    ///    touched") permits;
    /// 3. only with the lock held does the destructive merge run.
    pub(crate) fn commit_with_lock_polling(
        &mut self,
        lock_wait: Duration,
        sleep: impl FnMut(Duration),
    ) -> Result<(), CommitError> {
        if self.is_disposed() {
            return Ok(());
        }
        let _lock = match acquire_commit_lock_polling(&self.workdir, lock_wait, sleep) {
            Ok(l) => l,
            Err(LockFailure::Contended(d)) => {
                // On a FRESH commit the upper holds a complete, mergeable change
                // set that only failed to be published and the workdir was never
                // touched: that is `CommitDeferred`. But `commit()` is retryable
                // and a retry after a partial merge is already
                // `Preserved(MergeInterrupted)` over a HALF-MERGED workdir —
                // downgrading it to `CommitDeferred` ("workdir untouched") would
                // let a recovery sweep re-apply a half-merged change set. Never
                // weaken a stronger reason; what must hold is
                // CommitDeferred => workdir untouched.
                self.preserve_deferred_unless_interrupted();
                return Err(CommitError::Contended(d));
            }
            Err(LockFailure::Io(e)) => {
                self.preserve_deferred_unless_interrupted();
                return Err(CommitError::Lock(e));
            }
        };
        // `_lock` is held across the merge and released when this scope ends.
        self.commit_merge().map_err(CommitError::Merge)
    }


    /// The destructive merge of the upper into the workdir. The caller holds the
    /// workdir lock; this marks the branch `MergeInterrupted` before its first
    /// destructive step so a crash mid-merge still leaves a sweep something to
    /// find.
    fn commit_merge(&mut self) -> Result<(), BranchError> {
        // Nothing to merge — and therefore nothing for a crash record to
        // describe. Short-circuiting here is not an optimisation of the merge
        // below, it removes a failure the merge cannot justify:
        // `preserve_durable` is STRICT, so a storage dir whose marker cannot be
        // written (an obstructed `.PRESERVED.tmp`, a full filesystem) would
        // turn a commit with NO CHANGES into `Err("preserve marker: ...")`
        // naming a change set that does not exist. It also drops the marker's
        // fsyncs off every no-op commit, and `Sandbox` runs one from `Drop`.
        //
        // The test is deliberately "provably nothing to publish", not just the
        // `has_changes` flag. This arm RECLAIMS THE STORAGE, so a false
        // positive destroys data; a flag that every writer has to remember to
        // set is the wrong thing to stake that on, and the upper is on disk and
        // can be asked directly. `has_changes` is kept as the cheap first cut,
        // so a branch that did record changes pays nothing for the check.
        if !self.has_changes()
            && self.outstanding_deletions().next().is_none()
            && fs::read_dir(&self.upper).map(|mut d| d.next().is_none()).unwrap_or(false)
        {
            self.cleanup();
            self.state = BranchState::Finished;
            return Ok(());
        }

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
        //
        // Strict, unlike every other `preserve` call site: this is the one
        // moment the marker exists for, so a workdir that cannot be described
        // is a workdir that is not touched. Failing here loses nothing — the
        // upper still holds the whole change set and the commit is retryable.
        self.preserve_durable(PreserveReason::MergeInterrupted).map_err(|e| {
            BranchError::Operation(format!(
                "preserve marker: {e}; the workdir was not touched, but the change set at {} \
                 has no marker and a sweep will not find it",
                self.storage_dir.display()
            ))
        })?;

        // Apply deletions, recording each one that is no longer outstanding so
        // a retry sees only what is left to do. Whether the removal call
        // succeeded is not the test — the entry being gone is — because a
        // deletion of something the workdir no longer has is already applied.
        //
        // The whiteout set itself is append-only and cannot carry this: a
        // landed deletion has to stay in it or the path would reappear in the
        // merged view. `applied_deletions` is the second question.
        let pending_deletions: Vec<String> = self.outstanding_deletions().map(str::to_string).collect();
        let mut deletion_failure: Option<String> = None;
        let mut applied_any = false;
        // Whether the OUTSTANDING SET shrank, which is the question the marker
        // refresh below turns on. Not the same as `applied_any`, which is only
        // "an unlink happened": a deletion of a path the workdir no longer has
        // shrinks the set without unlinking anything.
        let mut shrank = false;
        // Parents of entries this attempt unlinked, RELATIVE to the workdir, so
        // the fsync can be resolved confined. Empty string = the workdir root.
        let mut removed_parents: HashSet<String> = HashSet::new();
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
            // "Applied" has to mean a DEFINITIVE "not there". `Path::exists()`
            // is false for any stat error, not just `ENOENT`: a whiteout that
            // cannot be statted (`EACCES` on a parent, `ENOTDIR` through a
            // parent replaced by a file, `ELOOP`) would read as applied, drop
            // out of `outstanding_deletions`, and leave the `remaining > 0`
            // guard below unfired — so the merge would run on, the successful
            // tail would remove the storage AND the marker, and `commit()`
            // would return `Ok(())` over a file that is still in the workdir
            // with its record destroyed.
            let stat_after = dest.symlink_metadata();
            let gone = matches!(stat_after, Err(ref e) if e.kind() == std::io::ErrorKind::NotFound);
            if gone {
                shrank |= self.applied_deletions.insert(rel_path.clone());
                // Only fsync entries this attempt actually removed. An entry
                // that was already absent is applied, but nothing was
                // unlinked, so there is no directory entry to make durable.
                if dest_kind.is_ok() {
                    applied_any = true;
                    removed_parents.insert(parent_rel(&rel_path).unwrap_or("").to_string());
                }
            } else if deletion_failure.is_none() {
                deletion_failure = Some(match (removal, &stat_after) {
                    (Err(e), _) => format!("{}: errno {}", rel_path, e),
                    // The removal reported success but the path cannot be
                    // confirmed gone. Carry the stat errno: "still present
                    // after removal" would be a guess, and the wrong one.
                    (Ok(()), Err(e)) => format!("{}: cannot confirm removal: {}", rel_path, e),
                    (Ok(()), Ok(_)) => format!("{}: still present after removal", rel_path),
                });
            }
        }
        // Gated on the OUTSTANDING SET having shrunk, not on an unlink having
        // happened. Deleting a path the workdir no longer has shrinks the set
        // with `applied_any == false`; skipping the refresh there would let the
        // copy phase run behind a marker naming a path it publishes and
        // `drop_merged_entry` drains — and a recovery replaying that marker
        // would then destroy the only copy.
        if shrank {
            if applied_any {
                // Order matters both ways round.
                //
                // The removals go durable BEFORE the marker stops naming them:
                // the unlinks above are plain syscalls and the copy phase's
                // fsyncs cover only directories the COPY touched. Shrinking a
                // durable marker over page-cache-only removals means a power
                // loss leaves a record saying "nothing outstanding" over a
                // workdir that still holds the files, and `applied_deletions`
                // is RAM-only, so the deletions are lost.
                for d in &removed_parents {
                    if let Err(errno) = sync_dir_in_root(&self.workdir, d) {
                        // Tolerated errnos: the fsync is either unavailable or
                        // moot here, and it must not fail the merge. A workdir
                        // directory that is writable and searchable but not
                        // readable (0o300) is the structural case — the child
                        // can unlink in it, but it cannot be opened for fsync
                        // by ANY means, so a strict call would turn an
                        // otherwise complete merge into a hard failure AFTER
                        // its deletions had landed and BEFORE any addition was
                        // published, with no way past it on a retry.
                        //
                        // Tolerating is the safe direction, and skipping the
                        // refresh below is not. The worst case here is an
                        // unsynced removal: a power loss resurrects a file,
                        // which is non-destructive and still named by the head
                        // marker. Returning instead would leave the refresh
                        // undone, and the copy phase must never run behind a
                        // marker that over-reports deletions against an upper
                        // it is draining — that direction destroys data that
                        // has already been published.
                        //
                        // Real I/O errors (`EIO`, `ENOSPC`) are NOT tolerated:
                        // there the filesystem itself is failing, and running
                        // the destructive copy phase on is not defensible.
                        const TOLERATED: [i32; 5] = [
                            libc::EACCES,
                            libc::EPERM,
                            libc::ELOOP,
                            libc::ENOTDIR,
                            libc::ENOENT,
                        ];
                        if !TOLERATED.contains(&errno) {
                            return Err(BranchError::Operation(format!(
                                "sync workdir dir: {}",
                                std::io::Error::from_raw_os_error(errno)
                            )));
                        }
                    }
                }
            }
            // And the marker is refreshed BEFORE the copy phase, strictly. The
            // head marker names deletions that have since landed; once the copy
            // phase publishes an entry and `drop_merged_entry` DRAINS it from
            // the upper, replaying that stale list destroys work that landed.
            // So the copy phase must never run behind a marker that
            // over-reports deletions relative to a drained upper. Failing here
            // loses nothing: the upper is not yet drained and the commit is
            // retryable, and the marker still on disk is the head one, which
            // OVER-lists — the safe direction, because nothing has been
            // drained.
            self.preserve_durable(PreserveReason::MergeInterrupted)
                .map_err(|e| BranchError::Operation(format!("refresh preserved marker: {e}")))?;
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
        // it was before the commit. The ones still outstanding are listed in
        // the refreshed PRESERVED marker beside the upper.
        let remaining = self.outstanding_deletions().count();
        if remaining > 0 {
            let detail = deletion_failure.unwrap_or_else(|| "unknown".to_string());
            return Err(BranchError::Operation(format!(
                "delete: {} deletion(s) could not be applied to the workdir, first: {}",
                remaining, detail
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
            } else if entry.file_type().is_fifo() || entry.file_type().is_socket() {
                // A node the workload mknod'ed carries no bytes, and opening a
                // FIFO to copy it would block on a peer that never comes.
                if let Some(p) = parent_rel(rel_str) {
                    let _ = crate::sys::fs::mkdirp_in_root(&self.workdir, p, 0o755);
                }
                let mode = entry
                    .metadata()
                    .map(|m| m.mode())
                    .map_err(|e| BranchError::Operation(format!("stat: {}", e)))?;
                let _ = crate::sys::fs::unlinkat_in_root(&self.workdir, rel_str, false);
                crate::sys::fs::mknod_in_root(&self.workdir, rel_str, mode, 0)
                    .map_err(|e| BranchError::Operation(format!("mknod: {}", e)))?;
                let _ = crate::sys::fs::chmod_in_root(&self.workdir, rel_str, mode & 0o7777);
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
                // The merged bytes, before the directory entry that names them.
                // The tail below fsyncs each destination directory but the file
                // itself was never synced, and the successful tail then removes
                // the storage that held the only other copy — so a power loss
                // could leave a durable name over unwritten blocks with nothing
                // left to re-merge. Best-effort: this is a durability
                // improvement, not a new way for a merge to fail.
                let _ = dst.sync_all();
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
    /// Writing the marker is best-effort here. If it fails the upper is still
    /// preserved in this process — losing the data would be worse than losing
    /// the record — but an out-of-band sweep will not find it. The write is
    /// still ATOMIC (temp + rename): that costs nothing and it is what stops a
    /// rewrite from truncating a marker that was already valid. It is not made
    /// DURABLE, because on these paths the workdir is untouched and there is
    /// nothing half-done for a crash to leave behind. See
    /// [`Self::preserve_durable`] for the path where there is.
    pub(crate) fn preserve(&mut self, reason: PreserveReason) {
        self.state = BranchState::Preserved(reason);
        let _ = self.write_preserved_marker(reason, false);
    }

    /// [`Self::preserve`], but the marker is fsynced and its error propagates.
    ///
    /// Used only by the merge, where the marker is the crash record for work in
    /// flight: it is written immediately before the first destructive step, so
    /// a marker that never reached disk over a half-merged workdir is precisely
    /// the failure it exists to prevent. The state is set BEFORE the write, so
    /// a caller that returns on the error still leaves `Drop` preserving the
    /// storage.
    pub(crate) fn preserve_durable(&mut self, reason: PreserveReason) -> std::io::Result<()> {
        self.state = BranchState::Preserved(reason);
        self.write_preserved_marker(reason, true)
    }

    /// Preserve as [`PreserveReason::CommitDeferred`] on a lock failure, but only
    /// if the branch is not already [`PreserveReason::MergeInterrupted`].
    ///
    /// `CommitDeferred` promises "the workdir is untouched, the whole set is
    /// preserved"; `MergeInterrupted` means "the workdir may be half merged". A
    /// contended retry of a commit that previously failed part way through the
    /// merge must not overwrite the stronger, half-merged marker with the weaker
    /// untouched one — that would tell a recovery sweep to re-apply a change set
    /// that has already partly landed.
    fn preserve_deferred_unless_interrupted(&mut self) {
        if !matches!(self.state, BranchState::Preserved(PreserveReason::MergeInterrupted)) {
            self.preserve(PreserveReason::CommitDeferred);
        }
    }

    /// Write (or replace) this branch's PRESERVED marker.
    ///
    /// Atomicity and durability are separate properties with separate costs,
    /// and only one caller needs both:
    ///
    /// - **Atomic** (temp + rename) for everyone, unconditionally. `preserve`
    ///   REWRITES an existing marker — the merge calls it on every attempt and
    ///   `commit()` is documented and tested as retryable — and a plain
    ///   `fs::write` truncates in place, so a crash inside a rewrite loses a
    ///   marker that was already valid, over a workdir that may be half merged.
    /// - **Durable** (`fsync` of the file, then of the storage dir, then
    ///   best-effort of the base) only when `durable`, i.e. only from the
    ///   merge, where the marker is the crash record for work in flight.
    ///
    /// The file is fsynced BEFORE the rename: delayed allocation can otherwise
    /// persist the new name over blocks that were never written. The storage
    /// dir is fsynced after, to persist the `PRESERVED` name; the base above it
    /// is fsynced best-effort, to persist the branch dir's own name, since
    /// `list_preserved` enumerates that base.
    ///
    /// Scope of the guarantee, so it is not overclaimed: a SIGKILL or a panic
    /// leaves the page cache intact and the old unsynced write was already
    /// enough. These fsyncs change behaviour only on power loss or a kernel
    /// panic — and there they make the RECORD durable while the upper it names
    /// is written by `ensure_cow_copy` and by the child with no sync at all,
    /// and the default storage base is `$XDG_RUNTIME_DIR` or `$TMPDIR`, i.e.
    /// tmpfs, where the whole tree is gone anyway. They are meaningful with an
    /// explicit disk-backed `fs_storage`, and inert without one.
    fn write_preserved_marker(&self, reason: PreserveReason, durable: bool) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;

        let mut body = Vec::new();
        body.extend_from_slice(b"reason=");
        body.extend_from_slice(reason.as_token().as_bytes());
        body.extend_from_slice(b"\nworkdir=");
        body.extend_from_slice(&marker_escape(self.workdir.as_os_str().as_bytes()));
        body.extend_from_slice(b"\nupper=");
        body.extend_from_slice(&marker_escape(self.upper.as_os_str().as_bytes()));
        // One line per OUTSTANDING deletion, in the whiteout set's own (sorted)
        // order so the marker is byte-stable for the same change set. These are
        // the deletions still to do as of this write: `commit()` refreshes the
        // marker after its deletion loop, so what is listed here is what a
        // recovery would still have to apply.
        //
        // The durable whiteout set in `deleted.log` is a DIFFERENT question and
        // must not be used here. It is the full history, including deletions
        // that already landed; re-applying one of those over a path the upper
        // re-created and the merge already drained destroys work that landed.
        for rel in self.outstanding_deletions() {
            body.extend_from_slice(b"\ndeleted=");
            body.extend_from_slice(&marker_escape(rel.as_bytes()));
        }
        body.extend_from_slice(format!("\npid={}\n", std::process::id()).as_bytes());

        let tmp = self.storage_dir.join(PRESERVED_TMP);
        let publish = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&body)?;
            if durable {
                // Content AND the temp inode, before the rename publishes the name.
                f.sync_all()?;
            }
            drop(f);
            fs::rename(&tmp, self.storage_dir.join(PRESERVED_MARKER))?;
            if durable {
                sync_dir(&self.storage_dir)?;
                // The branch dir's own name in the base `list_preserved` walks.
                // Best-effort: an exotic `$TMPDIR` must not be able to fail a commit.
                if let Some(base) = self.storage_dir.parent() {
                    let _ = sync_dir(base);
                }
            }
            Ok(())
        };
        // A rewrite that fails between the create and the rename must not
        // strand the staging file in the branch dir. Nothing else ever clears
        // it: `preserve` swallows the error, so the leak would be permanent,
        // and the branch dir is what a recovery sweep walks. Best-effort
        // removal — the error worth reporting is the write's, not the
        // cleanup's.
        if let Err(e) = publish() {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
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
        // Retire the record before the storage it describes, durably.
        //
        // The marker is now guaranteed on disk while the `remove_dir_all` that
        // takes it away is not, so a power loss just after a fully successful
        // commit would otherwise resurrect `<base>/<uuid>/PRESERVED` with
        // `reason=merge-interrupted` over an already-merged workdir — and after
        // a reboot the pid gate cannot help, because the pid is dead either
        // way. What survives a crash mid-teardown must be an unmarked orphan,
        // which `read_preserved` ignores.
        //
        // Best-effort throughout: `cleanup` has no error channel and runs in
        // `Drop`.
        if fs::remove_file(self.storage_dir.join(PRESERVED_MARKER)).is_ok() {
            let _ = sync_dir(&self.storage_dir);
        }
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

    /// A commit that cannot record itself must not start destroying.
    ///
    /// The marker is written immediately before the merge's first destructive
    /// step precisely so a crash mid-merge leaves a sweep something to find, so
    /// a marker that could not be written is the one case where running on
    /// would produce exactly what the marker exists to prevent: a modified
    /// workdir with no record of the change set that modified it. The commit
    /// fails instead, and the error names the storage dir — an operator told
    /// only "preserve marker: ENOSPC" has nowhere to look.
    ///
    /// This is a NEW `commit()` failure mode and it can leave a provably
    /// untouched workdir marked `MergeInterrupted`. Both are the over-strong
    /// direction, which `PreserveReason::MergeInterrupted`'s own doc permits.
    #[test]
    fn a_commit_whose_marker_cannot_be_written_fails_before_touching_the_workdir() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("victim.txt"), "still here").unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
        branch.mark_deleted("victim.txt");
        // Occupy the staging name with a DIRECTORY: `File::create` then fails
        // EISDIR. Not overridable by CAP_DAC_OVERRIDE, unlike a chmod-based
        // obstruction, so this holds under root with no conditional assertion.
        fs::create_dir(storage_dir.join(PRESERVED_TMP)).unwrap();

        let err = branch.commit().expect_err("an unwritable marker must fail the commit");
        let msg = match err {
            BranchError::Operation(m) => m,
            other => panic!("expected an Operation error, got: {other:?}"),
        };
        assert!(
            workdir.path().join("victim.txt").exists(),
            "a commit that could not record itself must not have started deleting; got {msg:?}",
        );
        assert!(msg.starts_with("preserve marker"), "expected a marker error, got: {msg:?}");
        assert!(
            msg.contains(&storage_dir.display().to_string()),
            "the operator has to be told WHERE the unfindable change set is, got: {msg:?}",
        );
    }

    /// The marker of a partly merged branch lists only the deletions that are
    /// still outstanding, not the whole whiteout set.
    ///
    /// Two independent things have to hold for this to pass, and either
    /// regression gives the same seven-element vector: the applied deletions
    /// must leave the outstanding set, and the marker must be REFRESHED after
    /// the deletion loop rather than left as the one written at the head of the
    /// merge, before any of them ran.
    ///
    /// Coverage note: this does NOT test the refresh's STRICTNESS. It would
    /// still pass with the refresh error swallowed. That is carried by
    /// `a_commit_whose_marker_cannot_be_written_fails_before_touching_the_workdir`
    /// and by the argument in the commit message, not by this test.
    #[test]
    fn the_marker_of_a_partly_merged_branch_lists_only_the_outstanding_deletions() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("x.txt"), "outside the root").unwrap();
        std::os::unix::fs::symlink(outside.path(), workdir.path().join("link")).unwrap();
        for i in 0..6 {
            fs::write(workdir.path().join(format!("f{i}.txt")), "doomed").unwrap();
        }

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
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

        let p = read_preserved(&storage_dir).expect("a half-merged branch must have a marker");
        assert_eq!(
            p.deleted,
            vec![PathBuf::from("link/x.txt")],
            "the marker must name what is LEFT TO DO, not the six that already landed",
        );
        assert_eq!(p.reason, PreserveReason::MergeInterrupted);
    }

    /// Rewriting the marker must not strand the staging file.
    ///
    /// HONEST FRAMING: this test does NOT fail before the change that
    /// introduced the rename — there was no temp file to leak. It is the guard
    /// for the mechanism the fix adds, so that a future sweep (or a
    /// `deleted.log` consumer) walking a branch dir cannot trip over a
    /// half-written `.PRESERVED.tmp`. It is not evidence for the durability
    /// work; nothing in-process can be.
    #[test]
    fn rewriting_the_marker_leaves_no_temp_file_in_the_branch_dir() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();

        branch.preserve(PreserveReason::CommitDeferred);
        branch.preserve(PreserveReason::MergeInterrupted); // the REWRITE path

        let p = read_preserved(&storage_dir).expect("the rewritten marker must parse");
        assert_eq!(p.reason, PreserveReason::MergeInterrupted, "the rewrite must have taken");

        let mut names: Vec<String> = fs::read_dir(&storage_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                PRESERVED_MARKER.to_string(),
                "deleted.log".to_string(),
                "upper".to_string()
            ],
            "the branch dir must hold exactly the marker, the whiteout log and the upper",
        );

        // ...and, load-bearing, when the rewrite FAILS. The success path above
        // cannot leak — the rename consumes the staging file — so it is the
        // failure path that needs the cleanup, and nothing else ever clears it:
        // `preserve` swallows the error, so a stranded `.PRESERVED.tmp` would
        // sit in the dir a recovery sweep walks for good.
        //
        // The failure is injected after the staging file is written, by making
        // the rename fail: a non-empty directory at `PRESERVED` cannot be
        // replaced by a file. No permission games, so it works as root.
        fs::remove_file(storage_dir.join(PRESERVED_MARKER)).unwrap();
        fs::create_dir(storage_dir.join(PRESERVED_MARKER)).unwrap();
        fs::write(storage_dir.join(PRESERVED_MARKER).join("occupied"), "x").unwrap();

        branch.preserve(PreserveReason::CommitDeferred);

        assert!(
            !storage_dir.join(PRESERVED_TMP).exists(),
            "a rewrite that could not be published must not strand its staging file",
        );
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

    /// A deletion whose path cannot be STATTED must not be read as applied.
    ///
    /// `Path::exists()` is false for ANY stat error, so an unstatable whiteout
    /// would be recorded applied, drop out of `outstanding_deletions()`, leave
    /// the `remaining > 0` guard unfired, and let the successful tail remove
    /// the storage AND the marker — `Ok(())` over a file that is still there,
    /// with the record of it destroyed.
    ///
    /// `ENOTDIR` is the shape used here because it needs no permission games
    /// and so fails as intended when the suite runs as root: `d` is replaced by
    /// a regular file after the deletion of `d/x.txt` was recorded, so statting
    /// the whiteout's path fails on the ancestor. The file `d` must still be
    /// there afterwards, and the commit must report the deletion.
    #[test]
    fn a_deletion_whose_path_cannot_be_statted_is_not_counted_applied() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::create_dir(workdir.path().join("d")).unwrap();
        fs::write(workdir.path().join("d/x.txt"), "lower").unwrap();

        let storage_dir;
        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            storage_dir = branch.storage_dir.clone();
            fs::write(branch.upper.join("added.txt"), "payload").unwrap();
            branch.mark_deleted("d/x.txt");

            // Now make `d` a regular file, so every stat through it is ENOTDIR.
            fs::remove_dir_all(workdir.path().join("d")).unwrap();
            fs::write(workdir.path().join("d"), "not a directory").unwrap();

            let err = branch
                .commit()
                .expect_err("an unstattable deletion must NOT be reported as a successful merge");
            assert!(
                matches!(err, BranchError::Operation(ref m) if m.starts_with("delete:")),
                "expected the deletion step to fail, got: {err:?}"
            );
            assert!(
                branch.is_deleted("d/x.txt"),
                "the deletion must stay outstanding so a retry still sees it"
            );
        }

        assert!(
            !workdir.path().join("added.txt").exists(),
            "a commit that failed on a deletion must not have merged the additions"
        );
        // The storage and the marker must both have survived: the successful
        // tail is what removes them, and it must not have been reached.
        assert!(
            storage_dir.join("upper").join("added.txt").exists(),
            "the unmerged change set must not have been destroyed by a bogus success"
        );
        let p = read_preserved(&storage_dir)
            .expect("the record of the outstanding deletion must survive");
        assert_eq!(
            p.deleted,
            vec![PathBuf::from("d/x.txt")],
            "the marker must still name the deletion that never landed",
        );
    }

    /// The same invariant through `EACCES` rather than `ENOTDIR`: a whiteout
    /// under a parent with mode 0o000 cannot be statted at all, and must not be
    /// counted applied. Skipped as root, where `CAP_DAC_OVERRIDE` defeats the
    /// mode and the stat succeeds.
    #[test]
    fn a_deletion_under_an_unreadable_parent_is_not_counted_applied() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::getuid() } == 0 {
            eprintln!("skipped: root ignores mode bits");
            return;
        }
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let parent = workdir.path().join("d");
        fs::create_dir(&parent).unwrap();
        fs::write(parent.join("x.txt"), "lower").unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("added.txt"), "payload").unwrap();
        branch.mark_deleted("d/x.txt");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o000)).unwrap();

        let result = branch.commit();

        // Restore before asserting, so a failure cannot leave an unremovable tree.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();

        let err = result.expect_err("an unstattable deletion must not be reported as merged");
        assert!(
            matches!(err, BranchError::Operation(ref m) if m.starts_with("delete:")),
            "expected the deletion step to fail, got: {err:?}"
        );
        assert!(
            parent.join("x.txt").exists(),
            "the file was never removed, so the commit claiming success would be a lie"
        );
        assert!(
            branch.is_deleted("d/x.txt"),
            "the deletion must stay outstanding so a retry still sees it"
        );
    }

    /// A workdir directory the merge cannot fsync must not fail the merge when
    /// the fsync is STRUCTURALLY unavailable, and the marker must still be
    /// refreshed.
    ///
    /// `0o300` (writable and searchable, not readable) is the case: the child
    /// could unlink in it, but no open-for-fsync can succeed, on any retry. A
    /// strict fsync turns a merge that would otherwise complete into a hard
    /// failure AFTER its deletions have landed and BEFORE any addition is
    /// published — unsatisfiable, so the commit could never make progress.
    /// Skipped as root, where `CAP_DAC_OVERRIDE` makes the directory readable.
    #[test]
    fn an_unfsyncable_workdir_dir_does_not_fail_the_merge() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::getuid() } == 0 {
            eprintln!("skipped: root ignores mode bits");
            return;
        }
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let dir = workdir.path().join("d");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("gone.txt"), "to be deleted").unwrap();

        let storage_dir;
        let result;
        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            storage_dir = branch.storage_dir.clone();
            fs::write(branch.upper.join("added.txt"), "payload").unwrap();
            branch.mark_deleted("d/gone.txt");
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o300)).unwrap();

            result = branch.commit();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        }

        result.expect("an fsync that cannot be satisfied must not fail an otherwise good merge");
        assert!(
            !dir.join("gone.txt").exists(),
            "the deletion must have landed"
        );
        assert!(
            workdir.path().join("added.txt").exists(),
            "the addition must have been published"
        );
        assert!(
            !storage_dir.exists(),
            "a successful commit reclaims the storage"
        );
    }

    /// Syncing a directory must never BLOCK on what is at the path.
    ///
    /// The merge fsyncs the parents of the entries it removed, and those names
    /// come from the child. A plain `File::open` of a path that turns out to be
    /// a FIFO blocks until the other end is opened — and this runs with the
    /// workdir commit lock held, so instead of failing the commit it wedges it,
    /// and every other commit on that workdir behind it, forever. `O_DIRECTORY`
    /// is refused before the open can block, so the call returns `ENOTDIR`.
    ///
    /// Bounded by a watchdog rather than asserted directly: a regression here
    /// HANGS, and a test that hangs instead of failing is worth nothing. Both
    /// entry points are covered — the confined one the merge uses for workdir
    /// names, and the plain one used for the branch's own storage dir.
    ///
    /// The confinement of the relative form is checked in the same place: a
    /// symlink at the final component is refused (`ELOOP`) rather than
    /// followed, and a `..` escape is clamped to the root instead of syncing
    /// something outside it.
    #[test]
    fn syncing_a_dir_refuses_a_fifo_instead_of_blocking_on_it() {
        use std::ffi::CString;
        use std::sync::mpsc;

        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("d");
        let c = CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo failed");
        // A symlink pointing at a real directory, to prove O_NOFOLLOW.
        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, root.path().join("link")).unwrap();

        let (tx, rx) = mpsc::channel();
        let rp = root.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            let confined = sync_dir_in_root(&rp, "d");
            let plain = sync_dir(&rp.join("d")).map_err(|e| e.raw_os_error().unwrap_or(0));
            let symlinked = sync_dir_in_root(&rp, "link");
            let escaped = sync_dir_in_root(&rp, "../..");
            let ok = sync_dir_in_root(&rp, "real");
            let _ = tx.send((confined, plain, symlinked, escaped, ok));
        });

        let (confined, plain, symlinked, escaped, ok) = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("syncing a dir BLOCKED on a FIFO; with the commit lock held this wedges");
        worker.join().unwrap();

        assert_eq!(confined, Err(libc::ENOTDIR), "a FIFO must be refused, not opened");
        assert_eq!(plain, Err(libc::ENOTDIR), "the plain form must refuse it too");
        // Refused, not followed. Which errno depends on the order the kernel
        // applies the two flags — `ENOTDIR` for `O_DIRECTORY` against the
        // symlink itself, `ELOOP` for `O_NOFOLLOW` — and both are in the
        // tolerated set, so accept either rather than pin kernel internals.
        // That this is a refusal and not a blanket failure is what `ok` below
        // establishes: the very directory it points at IS syncable by name.
        assert!(
            matches!(symlinked, Err(libc::ELOOP) | Err(libc::ENOTDIR)),
            "a symlinked dir must be refused, not followed; got {symlinked:?}",
        );
        // `..` is clamped to the root by RESOLVE_IN_ROOT, so this syncs the
        // root itself rather than escaping to its parent.
        assert_eq!(escaped, Ok(()), "a `..` escape must be clamped, not refused or followed out");
        assert_eq!(ok, Ok(()), "a real directory must still be syncable");
    }

    /// A deletion of a path the workdir does not have must be dropped from the
    /// marker BEFORE the copy phase, exactly like one that was unlinked.
    ///
    /// Such a deletion is applied on sight — the workdir entry is already gone
    /// — so it shrinks the outstanding set without unlinking anything. Gating
    /// the marker refresh on "an unlink happened" instead of "the outstanding
    /// set shrank" skips it, and the copy phase then runs behind a marker that
    /// names a path it is publishing while `drop_merged_entry` DRAINS that path
    /// from the upper. A recovery working from that marker would re-apply the
    /// deletion over the merged workdir and destroy the only copy.
    ///
    /// The commit is failed at the LAST upper entry so the marker survives to
    /// be read back, with an earlier entry published and drained first — the
    /// state the stale marker would be lethal over.
    #[test]
    fn a_deletion_of_an_absent_path_leaves_the_marker_before_the_copy_phase() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        // Sorts after "a-published.txt", so the merge publishes that one and
        // then fails here (ELOOP: a symlink where the upper holds a file).
        std::os::unix::fs::symlink("/dev/null", workdir.path().join("z-blocked.txt")).unwrap();

        let storage_dir;
        {
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            storage_dir = branch.storage_dir.clone();
            fs::write(branch.upper.join("a-published.txt"), "lands").unwrap();
            fs::write(branch.upper.join("z-blocked.txt"), "does not").unwrap();
            // Never existed in the workdir: applied on sight, nothing unlinked.
            branch.mark_deleted("a-published.txt");

            branch.commit().expect_err("the obstructed merge must fail");
        }

        // The precondition that makes a stale marker lethal: the entry is in
        // the workdir and no longer in the upper.
        assert!(
            workdir.path().join("a-published.txt").exists(),
            "the addition must have been published to the workdir"
        );
        assert!(
            !storage_dir.join("upper").join("a-published.txt").exists(),
            "and drained from the upper, so the workdir holds the only copy"
        );

        let p = read_preserved(&storage_dir).expect("the failed merge must leave a marker");
        assert!(
            p.deleted.is_empty(),
            "an applied deletion must not still be named by the marker over a drained \
             upper — replaying it would destroy the published copy; got {:?}",
            p.deleted,
        );
    }

    /// A commit with nothing recorded must be `Ok(())` and must write no
    /// marker, even when the marker COULD NOT be written.
    ///
    /// The head marker is the crash record for a merge in flight; with no
    /// change set there is nothing for it to describe, and writing it strictly
    /// means an obstructed storage dir turns a no-op commit into
    /// `Err("preserve marker: ...")` naming a change set that does not exist.
    /// `Sandbox` runs a commit from `Drop`, so this is the common path.
    ///
    /// The obstruction is a directory at `.PRESERVED.tmp`, which makes the
    /// staging `File::create` fail with `EISDIR` — no permission games, so it
    /// works as root too.
    #[test]
    fn a_commit_with_no_changes_succeeds_even_when_no_marker_can_be_written() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
        fs::create_dir(storage_dir.join(PRESERVED_TMP)).unwrap();

        assert!(!branch.has_changes(), "the branch must start with nothing recorded");
        branch
            .commit()
            .expect("a commit with nothing to publish must not fail on its crash record");

        assert!(
            !storage_dir.join(PRESERVED_MARKER).exists(),
            "no marker may be written for a change set that does not exist",
        );
        assert!(
            list_preserved(storage.path()).is_empty(),
            "a no-change commit must leave nothing for a recovery sweep to find",
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
    ///
    /// The deletion has to be a GENUINELY OUTSTANDING one, or the test proves
    /// nothing: a deletion of a path the workdir does not have is applied on
    /// sight and drops straight out of the marker, so it would round-trip only
    /// through a marker the merge failed to refresh. The unapplicable shape is
    /// the same one `commit_fails_when_a_deletion_could_not_be_applied` uses —
    /// a symlinked parent component, which the confined `unlinkat` resolves
    /// inside the workdir root and so cannot reach — with the newline moved
    /// into the leaf name.
    #[test]
    fn the_preserved_marker_round_trips_a_deleted_path_with_a_newline() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("we\nird\\name.txt"), "survives").unwrap();
        std::os::unix::fs::symlink(outside.path(), workdir.path().join("link")).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("added.txt"), "payload").unwrap();
        branch.mark_deleted("link/we\nird\\name.txt");
        let err = branch.commit().expect_err("the unapplicable deletion must fail the merge");
        // `delete:` is what the outstanding-deletion guard reports, so this is
        // the proof that the path below reaches the marker as a REMAINDER
        // rather than through a refresh the merge happened to skip.
        assert!(
            matches!(err, BranchError::Operation(ref m) if m.starts_with("delete:")),
            "the deletion must still be outstanding, or this proves nothing: {err:?}",
        );

        let found = list_preserved(storage.path());
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].deleted,
            vec![PathBuf::from("link/we\nird\\name.txt")],
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
        // O_CREAT on an existing (not deleted) file triggers the copy-up,
        // which must fail when the 5-byte file exceeds the 4-byte quota.
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 4).unwrap();
        let path = abs(&branch, "existing.txt");
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
        assert_eq!(err, libc::ENOSPC);
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

    #[test]
    fn write_open_in_unreadable_dir_virtualizes() {
        // The supervisor may not be able to stat inside a 0o000 lower dir
        // (as with /root under learn's workdir="/"). The write must still
        // virtualize onto an empty upper file instead of erroring out and
        // letting the child hit the real permission wall.
        use std::os::unix::fs::PermissionsExt;
        let (workdir, storage) = setup_workdir();
        fs::create_dir(workdir.path().join("locked")).unwrap();
        fs::write(workdir.path().join("locked/f"), "x").unwrap();
        let locked = workdir.path().join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let result = branch.ensure_cow_copy("locked/f");
        // Restore before asserting so the tempdir can be cleaned up either way.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

        let upper = result.unwrap();
        assert_eq!(upper, branch.upper_dir().join("locked/f"));
        // Nothing was readable to copy, so the plan is a fresh (absent or
        // empty) upper entry, never the lower bytes and never an error.
        assert!(!upper.exists() || fs::read(&upper).unwrap().is_empty());
    }

    // ---- Subtree whiteout semantics (issues #159/#160/#161 family) ----

    #[test]
    fn deleted_dir_hides_children() {
        // Issue #159: a whiteout must cover the subtree, not just the path.
        let (workdir, storage) = setup_workdir();
        fs::create_dir(workdir.path().join("d")).unwrap();
        fs::write(workdir.path().join("d/secret.txt"), "SECRET").unwrap();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("d");

        assert!(branch.is_deleted("d"));
        assert!(branch.is_deleted("d/secret.txt"));
        assert!(branch.list_merged_dir("d").is_empty());
        assert!(matches!(
            branch.handle_open(&format!("{}/d/secret.txt", branch.workdir_str()), 0),
            Err(BranchError::Deleted)
        ));
        assert!(branch
            .handle_stat(&format!("{}/d/secret.txt", branch.workdir_str()))
            .is_none());
        // Sibling boundary: d2 is not covered by the d whiteout.
        fs::write(workdir.path().join("d2"), "kept").unwrap();
        assert!(!branch.is_deleted("d2"));
    }

    #[test]
    fn o_directory_open_of_whiteouted_dir_reports_deleted() {
        // #159 review follow-up: opendir takes the O_DIRECTORY early-return,
        // which used to skip the whiteout check entirely; the child got a
        // live fd on the surviving lower directory (and could fstat its
        // inode) where stat on the same path already said ENOENT.
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("d")).unwrap();
        fs::write(wd.join("d/x"), "x").unwrap();
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        branch.mark_deleted("d");
        let path = format!("{}/d", wd.display());
        let dirflag = libc::O_DIRECTORY as u64;
        assert!(matches!(
            branch.handle_open(&path, dirflag),
            Err(BranchError::Deleted)
        ));
        assert!(matches!(
            branch.prepare_open(&path, dirflag),
            Ok(CowOpenPlan::Deleted)
        ));
        // Re-created in the upper: the shadow makes it visible again and the
        // open goes back to the normal resolution.
        assert!(branch.handle_mkdir(&path).unwrap());
        assert!(matches!(branch.handle_open(&path, dirflag), Ok(None)));
        assert!(!matches!(
            branch.prepare_open(&path, dirflag),
            Ok(CowOpenPlan::Deleted)
        ));
    }

    #[test]
    fn write_under_deleted_dir_does_not_republish_on_commit() {
        // Issue #159 integrity half: a write-open under the deleted directory
        // must not resurrect the deleted file's bytes into the commit.
        let (workdir, storage) = setup_workdir();
        fs::create_dir(workdir.path().join("d")).unwrap();
        fs::write(workdir.path().join("d/secret.txt"), "SECRET").unwrap();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("d");

        let flags = (libc::O_WRONLY | libc::O_CREAT) as u64;
        let upper = branch
            .handle_open(&format!("{}/d/secret.txt", branch.workdir_str()), flags)
            .unwrap()
            .expect("create over whiteout resolves into upper");
        // The plan points at the upper path; the child's O_CREAT would create
        // it empty. Simulate that create with fresh bytes.
        fs::write(&upper, "NEW").unwrap();

        branch.commit().unwrap();
        assert_eq!(
            fs::read_to_string(workdir.path().join("d/secret.txt")).unwrap(),
            "NEW"
        );
    }

    #[test]
    fn create_over_deleted_file_starts_empty() {
        // Same failure class as #159: O_CREAT on a whiteouted file used to
        // copy the pre-delete lower bytes up. It must start fresh.
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("existing.txt");
        let upper = branch.ensure_cow_copy("existing.txt").unwrap();
        assert!(!upper.exists() || fs::read(&upper).unwrap().is_empty());
    }

    #[test]
    fn mkdir_over_deleted_dir_is_opaque() {
        // rmdir d; mkdir d must yield an EMPTY d: the old contents stay hidden.
        let (workdir, storage) = setup_workdir();
        fs::create_dir(workdir.path().join("d")).unwrap();
        fs::write(workdir.path().join("d/old.txt"), "old").unwrap();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("d");
        let wd = branch.workdir_str().to_string();
        assert!(branch.handle_mkdir(&format!("{}/d", wd)).unwrap());

        assert!(!branch.is_deleted("d"));
        assert!(branch.is_deleted("d/old.txt"));
        assert!(branch.list_merged_dir("d").is_empty());

        branch.commit().unwrap();
        assert!(workdir.path().join("d").is_dir());
        assert!(!workdir.path().join("d/old.txt").exists());
    }

    #[test]
    fn changes_skips_shadowed_whiteouts() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("existing.txt");
        let upper = branch.ensure_cow_copy("existing.txt").unwrap();
        fs::write(&upper, "recreated").unwrap();
        let changes = branch.changes().unwrap();
        // The recreated file is a single Added entry, not Deleted + Modified.
        let for_path: Vec<_> = changes
            .iter()
            .filter(|c| c.path == std::path::Path::new("existing.txt"))
            .collect();
        assert_eq!(for_path.len(), 1);
        assert_eq!(for_path[0].kind, crate::dry_run::ChangeKind::Added);
    }

    #[test]
    fn rmdir_nonempty_gives_enotempty() {
        // Issue #161: rmdir must consult the merged view, as the kernel would.
        let (workdir, storage) = setup_workdir();
        fs::create_dir(workdir.path().join("d")).unwrap();
        fs::write(workdir.path().join("d/inner.txt"), "DATA").unwrap();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let wd = branch.workdir_str().to_string();

        assert_eq!(
            branch.handle_unlink(&format!("{}/d", wd), true),
            Err(libc::ENOTEMPTY)
        );
        assert!(workdir.path().join("d/inner.txt").exists());
        branch.commit().unwrap();
        assert!(workdir.path().join("d/inner.txt").exists());
    }

    #[test]
    fn rmdir_succeeds_after_draining_merged_view() {
        let (workdir, storage) = setup_workdir();
        fs::create_dir(workdir.path().join("d")).unwrap();
        fs::write(workdir.path().join("d/inner.txt"), "DATA").unwrap();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let wd = branch.workdir_str().to_string();

        assert_eq!(
            branch.handle_unlink(&format!("{}/d/inner.txt", wd), false),
            Ok(true)
        );
        assert_eq!(branch.handle_unlink(&format!("{}/d", wd), true), Ok(true));
        branch.commit().unwrap();
        assert!(!workdir.path().join("d").exists());
    }

    #[test]
    fn rmdir_nonempty_in_upper_only_gives_enotempty() {
        // Emptiness is about the merged view: content that exists only in
        // the upper still blocks the rmdir.
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let wd = branch.workdir_str().to_string();
        assert!(branch.handle_mkdir(&format!("{}/newdir", wd)).unwrap());
        fs::write(branch.upper_dir().join("newdir/f.txt"), "x").unwrap();
        assert_eq!(
            branch.handle_unlink(&format!("{}/newdir", wd), true),
            Err(libc::ENOTEMPTY)
        );
    }

    #[test]
    fn unlink_hidden_path_gives_enoent() {
        let (workdir, storage) = setup_workdir();
        fs::create_dir(workdir.path().join("d")).unwrap();
        fs::write(workdir.path().join("d/inner.txt"), "DATA").unwrap();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("d");
        let wd = branch.workdir_str().to_string();
        assert_eq!(
            branch.handle_unlink(&format!("{}/d/inner.txt", wd), false),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn rename_lower_dir_preserves_contents() {
        // Issue #160: renaming a lower-only directory must not destroy it.
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("d")).unwrap();
        fs::write(wd.join("d/inner.txt"), "PRECIOUS").unwrap();
        fs::create_dir(wd.join("d/sub")).unwrap();
        fs::write(wd.join("d/sub/deep.txt"), "DEEP").unwrap();

        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert!(branch
            .handle_rename(&format!("{}/d", wd.display()), &format!("{}/d2", wd.display()))
            .unwrap());

        // Merged view before commit: d hidden, d2 holds the tree.
        assert!(branch.is_deleted("d"));
        assert_eq!(
            branch.list_merged_dir("d2"),
            vec!["inner.txt".to_string(), "sub".to_string()]
        );

        branch.commit().unwrap();
        assert!(!wd.join("d").exists());
        assert_eq!(fs::read_to_string(wd.join("d2/inner.txt")).unwrap(), "PRECIOUS");
        assert_eq!(fs::read_to_string(wd.join("d2/sub/deep.txt")).unwrap(), "DEEP");
    }

    #[test]
    fn rename_dir_skips_deleted_children() {
        // A child already whiteouted must not reappear under the new name.
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("d")).unwrap();
        fs::write(wd.join("d/keep.txt"), "keep").unwrap();
        fs::write(wd.join("d/gone.txt"), "gone").unwrap();

        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert_eq!(
            branch.handle_unlink(&format!("{}/d/gone.txt", wd.display()), false),
            Ok(true)
        );
        assert!(branch
            .handle_rename(&format!("{}/d", wd.display()), &format!("{}/d2", wd.display()))
            .unwrap());
        branch.commit().unwrap();
        assert!(wd.join("d2/keep.txt").exists());
        assert!(!wd.join("d2/gone.txt").exists());
    }

    #[test]
    fn rename_hidden_source_gives_deleted() {
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        branch.mark_deleted("existing.txt");
        assert_eq!(
            branch.handle_rename(
                &format!("{}/existing.txt", wd.display()),
                &format!("{}/moved.txt", wd.display())
            ),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn rename_onto_nonempty_dir_is_enotempty() {
        // #160 review follow-up: with lower-only a/{a1} and b/{b1}, a
        // dir-onto-dir rename must refuse with ENOTEMPTY, never publish the
        // union b = {a1, b1}.
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("a")).unwrap();
        fs::write(wd.join("a/a1"), "A").unwrap();
        fs::create_dir(wd.join("b")).unwrap();
        fs::write(wd.join("b/b1"), "B").unwrap();
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert_eq!(
            branch.handle_rename(&format!("{}/a", wd.display()), &format!("{}/b", wd.display())),
            Err(libc::ENOTEMPTY)
        );
        // The refusal must leave no trace: nothing staged, nothing whiteouted.
        assert!(!branch.is_deleted("a"));
        assert_eq!(branch.list_merged_dir("b"), vec!["b1".to_string()]);
        branch.commit().unwrap();
        assert_eq!(fs::read_to_string(wd.join("a/a1")).unwrap(), "A");
        assert_eq!(fs::read_to_string(wd.join("b/b1")).unwrap(), "B");
        assert!(!wd.join("b/a1").exists());
    }

    #[test]
    fn rename_onto_empty_dir_replaces() {
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("a")).unwrap();
        fs::write(wd.join("a/a1"), "A").unwrap();
        fs::create_dir(wd.join("b")).unwrap();
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert_eq!(
            branch.handle_rename(&format!("{}/a", wd.display()), &format!("{}/b", wd.display())),
            Ok(true)
        );
        assert!(branch.is_deleted("a"));
        assert_eq!(branch.list_merged_dir("b"), vec!["a1".to_string()]);
        branch.commit().unwrap();
        assert!(!wd.join("a").exists());
        assert_eq!(fs::read_to_string(wd.join("b/a1")).unwrap(), "A");
    }

    #[test]
    fn rename_onto_lower_file_replaces_not_merges() {
        // The destination's lower bytes must be gone after commit, replaced
        // by the renamed entry, and the source name must stop existing.
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::write(wd.join("target.txt"), "OLD").unwrap();
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert_eq!(
            branch.handle_rename(
                &format!("{}/existing.txt", wd.display()),
                &format!("{}/target.txt", wd.display())
            ),
            Ok(true)
        );
        branch.commit().unwrap();
        assert!(!wd.join("existing.txt").exists());
        assert_eq!(fs::read_to_string(wd.join("target.txt")).unwrap(), "hello");
    }

    #[test]
    fn rename_onto_lower_symlink_dest_commits_as_regular_file() {
        // The discriminating case for the destination whiteout: an empty-dir
        // or regular-file destination commits identical bytes whether the
        // rename replaces or merges, so only a special-file destination can
        // tell the two apart. Without the whiteout the lower symlink survives
        // into commit, whose O_NOFOLLOW publish refuses to write through it
        // (and a FIFO destination would hang it, the #158 class).
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::write(wd.join("real.txt"), "REAL").unwrap();
        std::os::unix::fs::symlink("real.txt", wd.join("dest")).unwrap();

        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert_eq!(
            branch.handle_rename(
                &format!("{}/existing.txt", wd.display()),
                &format!("{}/dest", wd.display())
            ),
            Ok(true)
        );
        branch.commit().unwrap();

        let meta = fs::symlink_metadata(wd.join("dest")).unwrap();
        assert!(
            meta.file_type().is_file(),
            "dest must be the renamed regular file, not the surviving symlink"
        );
        assert_eq!(fs::read_to_string(wd.join("dest")).unwrap(), "hello");
        assert!(!wd.join("existing.txt").exists());
        // The link's old target is untouched: the rename replaced the link
        // itself and never wrote through it.
        assert_eq!(fs::read_to_string(wd.join("real.txt")).unwrap(), "REAL");
    }

    #[test]
    fn rename_type_mismatch_refused() {
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("d")).unwrap();
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        // File onto directory: EISDIR. Directory onto file: ENOTDIR.
        assert_eq!(
            branch.handle_rename(
                &format!("{}/existing.txt", wd.display()),
                &format!("{}/d", wd.display())
            ),
            Err(libc::EISDIR)
        );
        assert_eq!(
            branch.handle_rename(
                &format!("{}/d", wd.display()),
                &format!("{}/existing.txt", wd.display())
            ),
            Err(libc::ENOTDIR)
        );
    }

    #[test]
    fn rename_onto_whiteouted_dest_is_plain_rename() {
        // A whiteouted destination is absent in the merged view; the rename
        // must succeed and expose only the renamed content.
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("b")).unwrap();
        fs::write(wd.join("b/b1"), "B").unwrap();
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert_eq!(branch.handle_unlink(&format!("{}/b/b1", wd.display()), false), Ok(true));
        assert_eq!(branch.handle_unlink(&format!("{}/b", wd.display()), true), Ok(true));
        assert_eq!(
            branch.handle_rename(
                &format!("{}/existing.txt", wd.display()),
                &format!("{}/b", wd.display())
            ),
            Ok(true)
        );
        branch.commit().unwrap();
        let meta = fs::metadata(wd.join("b")).unwrap();
        assert!(meta.is_file());
        assert_eq!(fs::read_to_string(wd.join("b")).unwrap(), "hello");
        assert!(!wd.join("existing.txt").exists());
    }

    #[test]
    fn rename_absent_source_is_enoent() {
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert_eq!(
            branch.handle_rename(
                &format!("{}/nope", wd.display()),
                &format!("{}/dest", wd.display())
            ),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn rename_staging_failure_fails_rename_and_rolls_back() {
        // A mid-tree staging error used to be swallowed, after which the
        // source was whiteouted anyway and the untraversed children were
        // lost at commit. The rename must fail, leave the merged view
        // untouched, and leave no partially staged destination behind.
        use std::os::unix::fs::PermissionsExt;
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("d")).unwrap();
        fs::write(wd.join("d/top.txt"), "top").unwrap();
        fs::create_dir(wd.join("d/inner")).unwrap();
        fs::write(wd.join("d/inner/deep.txt"), "deep").unwrap();
        fs::set_permissions(wd.join("d/inner"), fs::Permissions::from_mode(0o000)).unwrap();

        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        let result = branch.handle_rename(
            &format!("{}/d", wd.display()),
            &format!("{}/moved", wd.display()),
        );
        fs::set_permissions(wd.join("d/inner"), fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(result, Err(libc::EACCES));
        assert!(!branch.is_deleted("d"), "failed rename must not whiteout the source");
        assert!(!branch.upper_dir().join("d").exists(), "partial staging left behind");
        let merged = branch.list_merged_dir("d");
        assert!(merged.contains(&"inner".to_string()));
        assert!(merged.contains(&"top.txt".to_string()));
        branch.commit().unwrap();
        assert_eq!(fs::read_to_string(wd.join("d/inner/deep.txt")).unwrap(), "deep");
    }

    #[test]
    fn rename_quota_failure_leaves_no_partial_staging() {
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("d")).unwrap();
        fs::write(wd.join("d/f1"), vec![b'x'; 50]).unwrap();
        // Quota fits the staged directory (4096) but not the file after it.
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 4100).unwrap();
        assert_eq!(
            branch.handle_rename(&format!("{}/d", wd.display()), &format!("{}/m", wd.display())),
            Err(libc::ENOSPC)
        );
        assert!(!branch.is_deleted("d"));
        assert!(!branch.upper_dir().join("d").exists(), "partial staging left behind");
        // The rollback must also return the reserved quota: a small write
        // elsewhere still fits.
        assert!(branch.ensure_cow_copy("existing.txt").is_ok());
    }

    #[test]
    fn rename_deep_tree_stages_iteratively() {
        // The staging walk is a worklist, not recursion: child-controlled
        // directory depth must not become supervisor stack depth.
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        let mut rel = String::from("d");
        fs::create_dir(wd.join(&rel)).unwrap();
        for _ in 0..400 {
            rel.push_str("/d");
            fs::create_dir(wd.join(&rel)).unwrap();
        }
        fs::write(wd.join(format!("{}/leaf.txt", rel)), "LEAF").unwrap();

        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert_eq!(
            branch.handle_rename(&format!("{}/d", wd.display()), &format!("{}/m", wd.display())),
            Ok(true)
        );
        branch.commit().unwrap();
        let deep = format!("m{}", &rel[1..]);
        assert_eq!(fs::read_to_string(wd.join(format!("{}/leaf.txt", deep))).unwrap(), "LEAF");
        assert!(!wd.join("d").exists());
    }

    #[test]
    fn rename_file_still_works() {
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert!(branch
            .handle_rename(
                &format!("{}/existing.txt", wd.display()),
                &format!("{}/renamed.txt", wd.display())
            )
            .unwrap());
        branch.commit().unwrap();
        assert!(!wd.join("existing.txt").exists());
        assert_eq!(fs::read_to_string(wd.join("renamed.txt")).unwrap(), "hello");
    }

    #[test]
    fn link_on_directory_falls_through() {
        // linkat on a directory is the kernel's EPERM to give; the branch
        // must not stage an empty-dir copy for it.
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("d")).unwrap();
        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        assert_eq!(
            branch
                .handle_link(&format!("{}/d", wd.display()), &format!("{}/d2", wd.display()))
                .unwrap(),
            false
        );
        assert!(!branch.upper_dir().join("d").exists());
    }

    fn make_fifo(path: &Path) {
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    }

    #[test]
    fn copy_up_of_fifo_is_refused_without_blocking() {
        // Issue #158: opening a FIFO O_RDONLY blocks until a writer appears,
        // so the copy-up path must never touch a non-regular file. The probe
        // runs on a thread with a timeout so a regression hangs the test, not
        // the suite.
        let (workdir, storage) = setup_workdir();
        make_fifo(&workdir.path().join("pipe"));
        let wd = workdir.path().to_path_buf();
        let sd = storage.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut b = SeccompCowBranch::create(&wd, Some(&sd), 0).unwrap();
            let _ = tx.send(b.ensure_cow_copy("pipe"));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Err(BranchError::NotOwned)) => {}
            Ok(other) => panic!("expected NotOwned for a FIFO, got {:?}", other),
            Err(_) => panic!("copy-up of a FIFO hung"),
        }
    }

    #[test]
    fn open_of_fifo_passes_through_to_kernel() {
        // A FIFO is a rendezvous, not data: an upper stub would discard what
        // the writer sends, and a supervisor-side open would block the
        // supervisor instead of the child.
        let (workdir, storage) = setup_workdir();
        make_fifo(&workdir.path().join("pipe"));
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let path = format!("{}/pipe", branch.workdir_str());
        for flags in [libc::O_RDONLY as u64, libc::O_WRONLY as u64] {
            assert_eq!(branch.handle_open(&path, flags).unwrap(), None);
            assert!(matches!(branch.prepare_open(&path, flags).unwrap(), CowOpenPlan::Skip));
        }
        assert!(!branch.upper_dir().join("pipe").exists(), "no stub may be created");
    }

    #[test]
    fn commit_leaves_lower_fifo_alone() {
        // Commit runs on a thread with a timeout: a stub or whiteout for the
        // FIFO would make the publish walk open it and block (issue #158).
        let (workdir, storage) = setup_workdir();
        make_fifo(&workdir.path().join("pipe"));
        let wd = workdir.path().to_path_buf();
        let sd = storage.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut b = SeccompCowBranch::create(&wd, Some(&sd), 0).unwrap();
            let path = format!("{}/pipe", b.workdir_str());
            assert_eq!(b.handle_open(&path, libc::O_WRONLY as u64).unwrap(), None);
            let _ = tx.send(b.commit());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("commit failed: {:?}", e),
            Err(_) => panic!("commit hung on the lower FIFO"),
        }
        let ft = fs::symlink_metadata(workdir.path().join("pipe")).unwrap().file_type();
        assert!(std::os::unix::fs::FileTypeExt::is_fifo(&ft), "lower FIFO must survive as a FIFO");
    }

    #[test]
    fn chmod_of_fifo_passes_through_to_kernel() {
        let (workdir, storage) = setup_workdir();
        let fifo = workdir.path().join("pipe");
        make_fifo(&fifo);
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let path = format!("{}/pipe", branch.workdir_str());
        assert!(matches!(branch.handle_chmod(&path, 0o600), Err(BranchError::NotOwned)));
        assert!(!branch.upper_dir().join("pipe").exists(), "no stub may be created");
        let lower_mode = fs::metadata(&fifo).unwrap().permissions();
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&lower_mode) & 0o777, 0o644);
    }

    #[test]
    fn rename_of_fifo_reports_exdev() {
        // A kernel object cannot be staged in the upper. EXDEV is the answer
        // mv already handles: it falls back to mknod plus unlink, both of
        // which the branch virtualizes.
        let (workdir, storage) = setup_workdir();
        make_fifo(&workdir.path().join("pipe"));
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let wd = branch.workdir_str().to_string();
        assert_eq!(
            branch.handle_rename(&format!("{wd}/pipe"), &format!("{wd}/pipe2")),
            Err(libc::EXDEV),
        );
        assert!(!branch.upper_dir().join("pipe").exists(), "no stub may be created");
    }

    #[test]
    fn fifo_created_in_branch_stays_virtualized() {
        // Ownership is about the lower tree: a FIFO the workload itself made
        // lives in the upper and keeps resolving there.
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let path = format!("{}/made", branch.workdir_str());
        assert!(branch.handle_mknod(&path, libc::S_IFIFO as u32 | 0o644, 0).unwrap());
        assert_eq!(
            branch.handle_open(&path, libc::O_WRONLY as u64).unwrap(),
            Some(branch.upper_dir().join("made")),
        );
    }

    #[test]
    fn commit_publishes_a_fifo_the_branch_made() {
        // The branch lets the workload mknod a FIFO, so commit must be able
        // to publish one. Byte-copying it opens the FIFO and blocks forever;
        // commit runs on a thread with a timeout so that shows as a failure.
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().to_path_buf();
        let sd = storage.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut b = SeccompCowBranch::create(&wd, Some(&sd), 0).unwrap();
            let path = format!("{}/made", b.workdir_str());
            assert!(b.handle_mknod(&path, libc::S_IFIFO as u32 | 0o640, 0).unwrap());
            let _ = tx.send(b.commit());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("commit failed: {:?}", e),
            Err(_) => panic!("commit hung publishing a FIFO"),
        }
        let meta = fs::symlink_metadata(workdir.path().join("made")).unwrap();
        assert!(std::os::unix::fs::FileTypeExt::is_fifo(&meta.file_type()), "published as a FIFO");
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777, 0o640);
    }

    #[test]
    fn write_open_of_device_node_passes_through_to_kernel() {
        // A terminal, /dev/null, or a GPU node cannot be virtualized: a stub
        // in the upper is a regular file the program cannot ioctl, so
        // ncurses apps lose their tty under a COW workdir of "/".
        // Device opens go to the kernel, where Landlock decides.
        let storage = tempfile::tempdir().unwrap();
        let mut branch = SeccompCowBranch::create(Path::new("/"), Some(storage.path()), 0).unwrap();
        let flags = (libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC) as u64;
        assert_eq!(branch.handle_open("/dev/null", flags).unwrap(), None);
        assert!(matches!(branch.prepare_open("/dev/null", flags).unwrap(), CowOpenPlan::Skip));
        assert!(
            !branch.upper_dir().join("dev/null").exists(),
            "no stub may be created for a device node",
        );
    }

    #[test]
    fn metadata_op_on_device_does_not_bring_back_a_stub() {
        // chmod/utimes on a device used to stage a stub that every later
        // open then resolved to, undoing the passthrough.
        let storage = tempfile::tempdir().unwrap();
        let mut branch = SeccompCowBranch::create(Path::new("/"), Some(storage.path()), 0).unwrap();
        assert!(matches!(branch.handle_chmod("/dev/null", 0o666), Err(BranchError::NotOwned)));
        assert!(matches!(branch.handle_utimensat("/dev/null"), Err(BranchError::NotOwned)));
        assert_eq!(branch.handle_open("/dev/null", libc::O_RDWR as u64).unwrap(), None);
        assert!(!branch.upper_dir().join("dev/null").exists());
    }

    #[test]
    fn execute_copy_guards_against_type_race() {
        // Defense in depth: if the entry changes type between prepare_copy's
        // lstat and execute_copy's open, the O_NONBLOCK+fstat guard must
        // catch it and produce an empty destination instead of streaming.
        let (workdir, storage) = setup_workdir();
        let fifo = workdir.path().join("race");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let workdir_root = branch.workdir().to_path_buf();
        let upper_root = branch.upper_dir().to_path_buf();
        SeccompCowBranch::execute_copy(&workdir_root, &upper_root, "race").unwrap();
        assert_eq!(fs::read(upper_root.join("race")).unwrap(), b"");
    }

    /// Recursively snapshot the merged view as (rel path -> Option<bytes>),
    /// None for directories. This is what the child observes during the run.
    fn merged_snapshot(
        branch: &SeccompCowBranch,
        rel: &str,
        out: &mut std::collections::BTreeMap<String, Option<Vec<u8>>>,
    ) {
        for name in branch.list_merged_dir(rel) {
            let child = if rel == "." { name.clone() } else { format!("{}/{}", rel, name) };
            let resolved = branch.resolve_read(&child);
            if resolved.is_dir() {
                out.insert(child.clone(), None);
                merged_snapshot(branch, &child, out);
            } else if resolved.is_file() {
                out.insert(child.clone(), Some(fs::read(&resolved).unwrap()));
            }
        }
    }

    /// Snapshot a real directory tree in the same shape.
    fn dir_snapshot(
        root: &std::path::Path,
        rel: &str,
        out: &mut std::collections::BTreeMap<String, Option<Vec<u8>>>,
    ) {
        let dir = if rel == "." { root.to_path_buf() } else { root.join(rel) };
        for e in fs::read_dir(dir).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let child = if rel == "." { name } else { format!("{}/{}", rel, name) };
            let p = e.path();
            if p.is_dir() {
                out.insert(child.clone(), None);
                dir_snapshot(root, &child, out);
            } else if p.is_file() {
                out.insert(child.clone(), Some(fs::read(&p).unwrap()));
            }
        }
    }

    #[test]
    fn commit_reproduces_merged_view() {
        // The invariant behind #159/#160/#161: what the child observed during
        // the run is exactly what commit() publishes.
        let (workdir, storage) = setup_workdir();
        let wd = workdir.path().canonicalize().unwrap();
        fs::create_dir(wd.join("d")).unwrap();
        fs::write(wd.join("d/a.txt"), "A").unwrap();
        fs::write(wd.join("d/b.txt"), "B").unwrap();
        fs::create_dir(wd.join("e")).unwrap();
        fs::write(wd.join("e/keep.txt"), "K").unwrap();

        let mut branch = SeccompCowBranch::create(&wd, Some(storage.path()), 0).unwrap();
        let w = |r: &str| format!("{}/{}", wd.display(), r);

        // A mix of the operations the four issues cover.
        let up = branch
            .handle_open(&w("new.txt"), (libc::O_WRONLY | libc::O_CREAT) as u64)
            .unwrap()
            .unwrap();
        fs::write(&up, "NEW").unwrap();
        let up = branch
            .handle_open(&w("existing.txt"), libc::O_WRONLY as u64)
            .unwrap()
            .unwrap();
        fs::write(&up, "MODIFIED").unwrap();
        assert_eq!(branch.handle_unlink(&w("d/a.txt"), false), Ok(true));
        assert!(branch.handle_rename(&w("d"), &w("moved")).unwrap());
        assert_eq!(branch.handle_unlink(&w("subdir/nested.txt"), false), Ok(true));
        assert_eq!(branch.handle_unlink(&w("subdir"), true), Ok(true));

        let mut merged = std::collections::BTreeMap::new();
        merged_snapshot(&branch, ".", &mut merged);
        branch.commit().unwrap();
        let mut committed = std::collections::BTreeMap::new();
        dir_snapshot(&wd, ".", &mut committed);
        assert_eq!(merged, committed);
    }

    #[test]
    fn deletion_log_written_beside_upper() {
        let (workdir, storage) = setup_workdir();
        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("existing.txt");
        let log = branch.upper_dir().parent().unwrap().join("deleted.log");
        let replayed = crate::cow::deletions::DeletionSet::load(&log);
        assert!(replayed.covers("existing.txt"));
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
    /// leaves the outstanding set and the commit succeeds.
    ///
    /// The test is "is the entry gone", not "did the removal call succeed" —
    /// which is what makes a retry after a partly-applied merge converge
    /// instead of failing forever on the deletions that landed the first time.
    ///
    /// It asserts on `outstanding_deletions`, not `is_deleted`: the whiteout
    /// set is append-only, so `is_deleted` (`covers` minus upper presence) stays
    /// true forever by design. The outstanding set is the one that carries the
    /// "still to do" contract.
    #[test]
    fn a_deletion_of_something_already_absent_counts_as_applied() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("never-existed.txt");
        branch
            .commit()
            .expect("a deletion of an absent path is already applied");
        assert_eq!(
            branch.outstanding_deletions().count(),
            0,
            "an applied deletion must leave the outstanding set, or a retry re-runs it forever",
        );
    }

    /// A directory and everything recorded under it must all apply.
    ///
    /// The whiteout set is a `BTreeSet` and its `iter()` is sorted, so the
    /// visit order is deterministic and parent-first: "d" < "d/e" <
    /// "d/e/f.txt". The parent's recursive delete therefore takes the children
    /// with it, and each child is then recorded APPLIED through the "the entry
    /// is gone" branch rather than through a successful removal call — which is
    /// what keeps them out of the outstanding set and off the commit's guard.
    #[test]
    fn deletions_of_a_directory_and_its_children_apply_whatever_the_order() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::create_dir_all(workdir.path().join("d/e")).unwrap();
        fs::write(workdir.path().join("d/e/f.txt"), "doomed").unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("d");
        branch.mark_deleted("d/e");
        branch.mark_deleted("d/e/f.txt");
        branch
            .commit()
            .expect("overlapping deletions must all apply");
        assert!(!workdir.path().join("d").exists(), "the whole subtree must be gone");
        assert_eq!(
            branch.outstanding_deletions().count(),
            0,
            "a child swept away by its parent's recursive delete must count as applied",
        );
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

    /// A deletion that is BOTH outstanding AND re-created in the upper must
    /// still be applied by the retry.
    ///
    /// This is where the two deletion questions genuinely diverge, and nothing
    /// else exercises it. `changes()` answers "what will the next commit do to
    /// the MERGED VIEW": a whiteouted path the upper holds is reported by the
    /// upper walk as an addition, never as `Deleted`. The remainder ledger (and
    /// the PRESERVED marker fed from it) answers "what is LEFT TO DO": the same
    /// path still has stale workdir contents under it, and the merge has to
    /// remove them before the addition is published. Filtering the remainder by
    /// upper presence collapses the second question into the first and loses
    /// the deletion.
    ///
    /// The obstruction is the one from
    /// `a_commit_that_failed_on_a_deletion_completes_after_the_obstruction_is_cleared`:
    /// a symlinked parent component, which the confined removal resolves inside
    /// the workdir root and so cannot reach, while `exists()` follows it out and
    /// still sees the entry. No permission games, so it holds under root too.
    #[test]
    fn an_outstanding_deletion_the_upper_re_created_is_still_applied_by_the_retry() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(outside.path().join("d")).unwrap();
        fs::write(outside.path().join("d/stale.txt"), "from a previous run").unwrap();
        std::os::unix::fs::symlink(outside.path(), workdir.path().join("link")).unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("link/d");
        // Re-create the whiteouted directory in the upper through the production
        // path: `handle_mkdir` is what puts the entry there in a real run, and
        // it is what makes `upper_has("link/d")` true while the deletion is
        // still outstanding.
        let recreated = format!("{}/link/d", branch.workdir.display());
        assert!(branch.handle_mkdir(&recreated).unwrap(), "the upper mkdir must succeed");
        fs::write(branch.upper.join("link/d/new.txt"), "fresh").unwrap();
        assert!(branch.upper_has("link/d"), "the upper must hold the re-created path");

        let err = branch.commit().expect_err("the obstructed deletion must fail the merge");
        assert!(
            matches!(err, BranchError::Operation(ref m) if m.starts_with("delete:")),
            "expected the deletion step to fail, got: {err:?}"
        );
        assert_eq!(
            branch.outstanding_deletions().count(),
            1,
            "the remainder must still hold the deletion the upper re-created",
        );
        // The DOCUMENTED divergence, asserted so it is behaviour and not an
        // oversight: the merged-view report folds it into the upper walk.
        assert!(
            branch
                .changes()
                .unwrap()
                .iter()
                .all(|c| c.kind != crate::dry_run::ChangeKind::Deleted),
            "a whiteout the upper re-created must not be reported as a deletion",
        );

        // Clear the obstruction: the symlinked component becomes a real
        // directory holding the same stale contents.
        fs::remove_file(workdir.path().join("link")).unwrap();
        fs::create_dir_all(workdir.path().join("link/d")).unwrap();
        fs::write(workdir.path().join("link/d/stale.txt"), "from a previous run").unwrap();

        branch.commit().expect("the retry must finish the remainder");
        assert!(
            !workdir.path().join("link/d/stale.txt").exists(),
            "the deletion had to run again even though the upper held the path",
        );
        assert_eq!(
            fs::read_to_string(workdir.path().join("link/d/new.txt")).unwrap(),
            "fresh",
            "and the addition must publish into the emptied directory",
        );
    }

    /// A retry must not re-run a deletion whose path the copy phase already
    /// published — the upper no longer holds a copy to put back.
    ///
    /// Attempt 1 removes `f.txt` from the workdir, copies the upper's version
    /// across, and drops it from the upper; a later entry then fails the merge.
    /// If the retry treats that whiteout as still outstanding it unlinks the
    /// freshly published file with nothing left to restore it — a silent loss,
    /// not a visible error.
    ///
    /// The obstruction is a FILE in the workdir under an upper DIRECTORY, the
    /// merge's documented hard failure. A file rather than a directory on
    /// purpose: `drop_merged_entry` leaves directories in the upper, so a
    /// directory-shaped obstruction would be rescued by an upper-presence
    /// filter and would not discriminate. The walk is `sort_by_file_name`, so
    /// "f.txt" merges before "z" fails.
    #[test]
    fn a_retry_after_a_partial_merge_must_not_re_delete_a_path_the_upper_already_published() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("f.txt"), "old").unwrap();
        fs::write(workdir.path().join("z"), "a file where the upper has a dir").unwrap();

        let mut branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        branch.mark_deleted("f.txt");
        fs::write(branch.upper.join("f.txt"), "new").unwrap();
        fs::create_dir(branch.upper.join("z")).unwrap();

        let err = branch.commit().expect_err("the type clash at z must fail the merge");
        assert!(
            matches!(err, BranchError::Operation(ref m) if m.starts_with("mkdir:")),
            "expected the copy phase to fail at z, got: {err:?}"
        );

        fs::remove_file(workdir.path().join("z")).unwrap();

        // Inspect the workdir BEFORE unwrapping. A retry that re-deletes the
        // published file goes on to fail the commit on a whiteout it can never
        // clear, and unwrapping first would record that error instead of the
        // loss it is a symptom of.
        let retry = branch.commit();
        assert_eq!(
            fs::read_to_string(workdir.path().join("f.txt")).unwrap_or_default(),
            "new",
            "the retry must not re-delete a path the copy phase already published",
        );
        retry.expect("the retry must finish the remainder");
        assert!(
            workdir.path().join("z").is_dir(),
            "and the entry that blocked the first attempt must land",
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
    /// branch" — `None`, not a half-populated record.
    ///
    /// The marker is written immediately before the merge's first destructive
    /// step, so a crash there leaves exactly these bytes on disk. Two dangerous
    /// shapes, and the second is why the assertion is `is_none()` rather than a
    /// comparison of the deletion lists:
    ///
    /// - a cut inside the `deleted=` lines parses as a complete record whose
    ///   change set is missing deletions, and recovering from that resurrects
    ///   the files the run deleted;
    /// - a cut inside the LAST line, `pid=412` -> `pid=41`, parses as a
    ///   complete record with a plausible but WRONG pid — and pid liveness is
    ///   exactly what `list_preserved` uses to tell a live merge from a dead
    ///   one, so the sweep either skips a crashed half-merge forever or acts on
    ///   a merge that is still running.
    ///
    /// The trailing-newline rule in `read_preserved` is what closes both: the
    /// pid line is written last, so every cut either lands mid-line (rejected
    /// there) or on a line boundary (no pid line, rejected by `pid?`).
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
            assert!(
                read_preserved(&storage_dir).is_none(),
                "a marker truncated at byte {cut} of {} parsed as a complete record",
                full.len(),
            );
        }
        fs::write(&marker, &full).unwrap();
        assert!(
            read_preserved(&storage_dir).is_some(),
            "and the untruncated marker must still parse, so the loop is not vacuous",
        );
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

    // ------------------------------------------------------------
    // Concern 1: the workdir commit lock now lives INSIDE the branch
    // ------------------------------------------------------------

    /// A commit must serialize on the workdir lock: while another holder has it,
    /// `commit_with_lock_polling` must NOT merge — it waits (the injected sleep
    /// loop runs), then defers, preserving the whole change set as
    /// `CommitDeferred` with the workdir untouched. On the old lock-free `commit`
    /// this merged straight over the concurrent one and tore the workdir.
    #[test]
    fn commit_respects_external_workdir_lock() {
        use std::os::unix::io::AsRawFd;
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("a.txt"), "plan\n").unwrap();

        // Another merge in flight: hold LOCK_EX on the workdir from a second fd.
        let held = std::fs::File::open(workdir.path()).unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "test setup: could not take the workdir lock"
        );

        let mut polls = 0usize;
        let err = branch
            .commit_with_lock_polling(Duration::from_millis(50), |_| polls += 1)
            .expect_err("a held workdir lock must block the commit");
        drop(held);

        assert!(matches!(err, CommitError::Contended(_)), "expected contention, got: {err:?}");
        assert!(polls > 0, "the poll loop must actually have waited for the holder");
        assert!(
            !workdir.path().join("a.txt").exists(),
            "nothing may be merged while another holder has the lock"
        );
        assert_eq!(
            branch.state,
            BranchState::Preserved(PreserveReason::CommitDeferred),
            "a contended commit preserves the untouched change set as CommitDeferred"
        );
        assert_eq!(
            std::fs::read_to_string(branch.upper.join("a.txt")).unwrap(),
            "plan\n",
            "the preserved upper must still hold the bytes"
        );
    }

    /// S3: a contended RETRY of a commit that already failed part way through the
    /// merge must NOT downgrade the on-disk `MergeInterrupted` marker to
    /// `CommitDeferred`. `CommitDeferred` means "workdir untouched, whole set
    /// preserved"; `MergeInterrupted` means "workdir may be half merged". A
    /// recovery sweep that read a downgraded `CommitDeferred` over a half-merged
    /// workdir would re-apply a partial change set. Without the guard in
    /// `commit_with_lock_polling`, the contended retry below overwrites the marker
    /// (and state) with `CommitDeferred`; with it, both stay `MergeInterrupted`.
    #[test]
    fn contended_retry_does_not_downgrade_merge_interrupted() {
        use std::os::unix::io::AsRawFd;
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        // Obstruct the merge: a symlink in the workdir where the upper holds a
        // regular file (fails under O_NOFOLLOW), leaving the branch half merged.
        std::os::unix::fs::symlink("/dev/null", workdir.path().join("blocked.txt")).unwrap();

        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
        fs::write(branch.upper.join("blocked.txt"), "payload").unwrap();

        // First commit runs the merge and fails on the obstruction -> the branch
        // is Preserved(MergeInterrupted), on disk and in memory.
        branch.commit().expect_err("the obstructed merge must fail");
        assert_eq!(
            branch.state,
            BranchState::Preserved(PreserveReason::MergeInterrupted),
            "an obstructed merge leaves the branch MergeInterrupted",
        );
        assert_eq!(
            read_preserved(&storage_dir).unwrap().reason,
            PreserveReason::MergeInterrupted,
            "the on-disk marker records the half-merge before the retry",
        );

        // Clear the obstruction, then contend the workdir lock so the RETRY fails
        // at lock acquisition (before it can run the merge again).
        fs::remove_file(workdir.path().join("blocked.txt")).unwrap();
        let held = std::fs::File::open(workdir.path()).unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "test setup: could not take the workdir lock"
        );

        let err = branch
            .commit_with_lock_polling(Duration::from_millis(20), |_| {})
            .expect_err("the retry must fail: the lock is held");
        drop(held);

        assert!(matches!(err, CommitError::Contended(_)), "expected contention, got: {err:?}");
        // The invariant: the stronger reason must survive the contended retry, in
        // memory AND on disk. A downgrade here is the S3 bug.
        assert_eq!(
            branch.state,
            BranchState::Preserved(PreserveReason::MergeInterrupted),
            "a contended retry must not downgrade MergeInterrupted in memory",
        );
        assert_eq!(
            read_preserved(&storage_dir).unwrap().reason,
            PreserveReason::MergeInterrupted,
            "a contended retry must not downgrade the on-disk marker to CommitDeferred",
        );
    }

    /// The single lock layer must not self-deadlock: an uncontended commit takes
    /// the workdir flock once, merges, and succeeds — proving there is no second
    /// lock wrapping the first (which would fail to re-acquire the same directory
    /// flock and spin to `Contended`).
    ///
    /// The lock-wait is a fast bound and the poll sleep is a no-op counter, so a
    /// self-deadlock regression fails in milliseconds rather than burning the real
    /// wait, and the counter proves the loop never had to wait at all on the
    /// uncontended path. This does NOT assert the lock is present — that a merge
    /// serializes at all is `commit_wrapper_defers_and_preserves_under_contention`;
    /// this only asserts the one lock does not deadlock on itself.
    #[test]
    fn commit_does_not_self_deadlock_uncontended() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("a.txt"), "plan\n").unwrap();

        let mut polls = 0usize;
        branch
            .commit_with_lock_polling(Duration::from_millis(20), |_| polls += 1)
            .expect("an uncontended commit must not deadlock on its own lock");
        assert_eq!(polls, 0, "an uncontended commit must take the lock without waiting");
        assert_eq!(
            std::fs::read_to_string(workdir.path().join("a.txt")).unwrap(),
            "plan\n",
            "the merge must have landed"
        );
        assert_eq!(branch.state, BranchState::Finished, "a merged branch is Finished");
    }

    /// The thin `commit()` wrapper (the plain-Sandbox / Drop path) also
    /// serializes: under contention it defers-and-preserves as `CommitDeferred`
    /// and returns an error, rather than tearing a merge in flight. Driven through
    /// `commit_inner` with an injected fast lock-wait and a no-op poll sleep so the
    /// test does not block the real `DROP_COMMIT_LOCK_WAIT` (5s).
    #[test]
    fn commit_wrapper_defers_and_preserves_under_contention() {
        use std::os::unix::io::AsRawFd;
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("a.txt"), "plan\n").unwrap();

        let held = std::fs::File::open(workdir.path()).unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "test setup: could not take the workdir lock"
        );

        let err = branch
            .commit_inner(Duration::from_millis(20), |_| {})
            .expect_err("a contended plain-Sandbox commit must defer, not tear the workdir");
        drop(held);

        assert!(
            err.to_string().contains("lock contended"),
            "a contended commit must report the contention message distinctly, got: {err}",
        );
        assert_eq!(
            branch.state,
            BranchState::Preserved(PreserveReason::CommitDeferred),
            "the deferred commit must preserve for recovery, not reclaim"
        );
        assert!(!workdir.path().join("a.txt").exists(), "nothing may be merged under contention");
        assert_eq!(
            std::fs::read_to_string(branch.upper.join("a.txt")).unwrap(),
            "plan\n",
            "the preserved upper must still hold the bytes"
        );
    }

    /// GAP-4: the Io arm of the commit lock obeys the same no-downgrade rule as the
    /// contended arm. A branch already `Preserved(MergeInterrupted)` whose retry
    /// cannot even OPEN the workdir (ENOENT -> `LockFailure::Io`) must keep its
    /// stronger MergeInterrupted marker — in memory AND on disk — and leave the
    /// upper intact, never downgrading to CommitDeferred (which would tell a sweep
    /// the half-merged workdir is untouched). Reverting the Io arm's guard to
    /// `preserve(CommitDeferred)` unconditionally fails this.
    #[test]
    fn io_lock_failure_retry_does_not_downgrade_merge_interrupted() {
        // SEPARATE storage dir: it survives removing the workdir below.
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        // Obstruct the merge so the first commit half-merges and leaves the branch
        // MergeInterrupted: a symlink in the workdir where the upper holds a regular
        // file fails under O_NOFOLLOW.
        std::os::unix::fs::symlink("/dev/null", workdir.path().join("blocked.txt")).unwrap();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let storage_dir = branch.storage_dir.clone();
        fs::write(branch.upper.join("blocked.txt"), "payload").unwrap();

        branch.commit().expect_err("the obstructed merge must fail");
        assert_eq!(
            branch.state,
            BranchState::Preserved(PreserveReason::MergeInterrupted),
            "an obstructed merge leaves the branch MergeInterrupted",
        );

        // Remove the workdir so the RETRY's File::open(workdir) is ENOENT -> Io, not
        // contention.
        fs::remove_dir_all(workdir.path()).unwrap();

        let err = branch
            .commit_with_lock_polling(Duration::from_millis(20), |_| {})
            .expect_err("a workdir that cannot be opened fails the retry with Io");
        assert!(
            matches!(err, CommitError::Lock(_)),
            "a missing workdir is an Io lock failure, got: {err:?}",
        );
        assert_eq!(
            branch.state,
            BranchState::Preserved(PreserveReason::MergeInterrupted),
            "the Io retry must not downgrade MergeInterrupted in memory",
        );
        assert_eq!(
            read_preserved(&storage_dir).unwrap().reason,
            PreserveReason::MergeInterrupted,
            "the Io retry must not downgrade the on-disk marker to CommitDeferred",
        );
        assert_eq!(
            fs::read_to_string(branch.upper.join("blocked.txt")).unwrap(),
            "payload",
            "the unmerged upper must stay intact across the failed retry",
        );
    }

    /// GAP-5: a disposed branch (Kept, or Finished) short-circuits the commit
    /// BEFORE it touches the workdir lock. Even with an external LOCK_EX held on the
    /// workdir, commit returns Ok(()) without a single poll and leaves the state
    /// unchanged. This pins the `is_disposed()`-before-lock ordering: moving the
    /// check after acquisition would block on the held lock and return
    /// Err(Contended).
    #[test]
    fn disposed_branch_commits_ok_under_external_lock_without_polling() {
        use std::os::unix::io::AsRawFd;

        for kept in [true, false] {
            let workdir = tempfile::tempdir().unwrap();
            let storage = tempfile::tempdir().unwrap();
            let mut branch =
                SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
            fs::write(branch.upper.join("a.txt"), "plan\n").unwrap();
            let expected_state = if kept {
                branch.keep();
                BranchState::Preserved(PreserveReason::Kept)
            } else {
                branch.abort().unwrap();
                BranchState::Finished
            };

            // Hold the workdir lock externally, as a concurrent merge would.
            let held = std::fs::File::open(workdir.path()).unwrap();
            assert_eq!(
                unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0,
                "test setup: could not take the workdir lock"
            );

            let mut polls = 0usize;
            let started = std::time::Instant::now();
            branch
                .commit_with_lock_polling(Duration::from_millis(20), |_| polls += 1)
                .expect("a disposed branch must commit-Ok without touching the lock");
            let elapsed = started.elapsed();
            drop(held);

            assert_eq!(polls, 0, "a disposed branch must not poll the workdir lock (kept={kept})");
            assert!(elapsed < Duration::from_secs(1), "must return at once, took {elapsed:?}");
            assert_eq!(branch.state, expected_state, "disposition must be unchanged (kept={kept})");
        }
    }

    /// GAP-9: the `commit()` wrapper maps an Io lock failure to a message DISTINCT
    /// from the contended one ("commit deferred: workdir lock error:" vs
    /// "... lock contended"), and preserves as CommitDeferred. Collapsing the two
    /// arms into one message would fail this.
    #[test]
    fn wrapper_maps_lock_io_to_distinct_message() {
        // Separate storage: survives removing the workdir below.
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let mut branch =
            SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper.join("a.txt"), "plan\n").unwrap();

        // Remove the workdir so the lock's File::open is ENOENT -> Io (not contention).
        fs::remove_dir_all(workdir.path()).unwrap();

        let err = branch
            .commit_inner(Duration::from_millis(20), |_| {})
            .expect_err("a workdir that cannot be opened fails the commit");
        assert!(
            err.to_string().contains("commit deferred: workdir lock error:"),
            "the Io lock failure must map to its own distinct message, got: {err}",
        );
        assert!(
            !err.to_string().contains("lock contended"),
            "the Io message must not be the contended one, got: {err}",
        );
        assert_eq!(
            branch.state,
            BranchState::Preserved(PreserveReason::CommitDeferred),
            "a fresh Io-deferred commit preserves as CommitDeferred",
        );
    }

    // ------------------------------------------------------------
    // Concern 2: stable, per-user, securely-created default storage base
    // ------------------------------------------------------------

    /// The default base is per-user (no pid), XDG only when the real and
    /// effective uid match (no privilege change in effect), and falls back to a
    /// per-uid `$TMPDIR` base otherwise.
    #[test]
    fn preferred_storage_base_euid_gated_and_per_uid() {
        let tmp = Path::new("/tmp");
        let xdg = std::ffi::OsStr::new("/run/user/1000");

        // real == effective + XDG present -> the XDG base.
        assert_eq!(
            preferred_storage_base(Some(xdg), tmp, 1000, 1000),
            PathBuf::from("/run/user/1000/sandlock-cow"),
        );
        // A setuid-to-non-root process (ruid=1000, euid=1001) -> the per-uid tmp
        // base, NEVER the XDG path: it must not write euid-owned files into
        // ruid's `$XDG_RUNTIME_DIR` (/run/user/1000). This is the S2 regression:
        // the old `euid != 0` gate wrongly returned the XDG base here.
        assert_eq!(
            preferred_storage_base(Some(xdg), tmp, 1000, 1001),
            PathBuf::from("/tmp/sandlock-cow-1000"),
        );
        // A setuid-to-root process (ruid=1000, euid=0) -> the per-uid tmp base:
        // real != effective, so no XDG write as root into a user's runtime dir.
        assert_eq!(
            preferred_storage_base(Some(xdg), tmp, 1000, 0),
            PathBuf::from("/tmp/sandlock-cow-1000"),
        );
        // Empty / absent XDG -> the per-uid tmp base.
        assert_eq!(
            preferred_storage_base(Some(std::ffi::OsStr::new("")), tmp, 1000, 1000),
            PathBuf::from("/tmp/sandlock-cow-1000"),
        );
        assert_eq!(
            preferred_storage_base(None, tmp, 1000, 1000),
            PathBuf::from("/tmp/sandlock-cow-1000"),
        );
    }

    /// A foreign-owned or symlinked base is rejected (closing the predictable-name
    /// pre-creation / symlink-swap attack the durable name would widen); a base we
    /// create is 0700, and the check is idempotent on our own dir.
    #[test]
    fn ensure_secure_base_rejects_foreign_or_symlink_base() {
        use std::os::unix::fs::PermissionsExt;
        let uid = unsafe { libc::getuid() };
        let root = tempfile::tempdir().unwrap();

        // A symlink where the base should be is rejected.
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        let linkbase = root.path().join("link-base");
        std::os::unix::fs::symlink(&target, &linkbase).unwrap();
        assert!(
            ensure_secure_base(&linkbase, uid).is_err(),
            "a symlinked base must be rejected"
        );

        // A base we create is accepted and is 0700; re-checking it is idempotent.
        let fresh = root.path().join("fresh-base");
        ensure_secure_base(&fresh, uid).expect("a base we create must be accepted");
        let mode = fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "a freshly-created base must be 0700, got {mode:o}");
        ensure_secure_base(&fresh, uid).expect("an existing owned dir must still be accepted");

        // A reused base owned by us but widened to group/world access is rejected
        // (N4): create()'s contract is 0700, and a relaxed mode could expose
        // preserved uppers to another user.
        let widened = root.path().join("widened-base");
        fs::create_dir(&widened).unwrap();
        fs::set_permissions(&widened, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(
            ensure_secure_base(&widened, uid).is_err(),
            "a group/world-accessible owned base must be rejected"
        );

        // A base not owned by the EXPECTED uid is rejected. We own `owned`, so
        // asking for it as uid+1 fails the ownership check without needing root.
        let owned = root.path().join("owned");
        fs::create_dir(&owned).unwrap();
        assert!(
            ensure_secure_base(&owned, uid.wrapping_add(1)).is_err(),
            "a base not owned by the expected uid must be rejected"
        );
    }

    /// GAP-7: `ensure_secure_base` creates only the LEAF, never intermediates. A
    /// base under a MISSING parent fails with ENOENT and does NOT fabricate the
    /// parent — substituting `create_dir_all` for the non-recursive mkdir would
    /// create `missing/` and succeed, failing this.
    #[test]
    fn ensure_secure_base_does_not_create_intermediates() {
        let uid = unsafe { libc::getuid() };
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let leaf = missing.join("child");

        let err = ensure_secure_base(&leaf, uid)
            .expect_err("a base under a missing parent cannot be created non-recursively");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "expected ENOENT, got: {err:?}");
        assert!(!missing.exists(), "the missing parent must NOT be fabricated");
        assert!(!leaf.exists(), "the leaf must not exist either");
    }

    /// GAP-11: a stat error OTHER than NotFound is PROPAGATED, not read as "absent,
    /// create it". A parent dir with mode 0o000 makes `symlink_metadata` on a child
    /// fail with EACCES, which must surface as Err. Skipped as root, where mode bits
    /// are ignored.
    #[test]
    fn ensure_secure_base_propagates_non_notfound_stat_error() {
        use std::os::unix::fs::PermissionsExt;
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            eprintln!("skipped: root ignores mode bits");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("noaccess");
        fs::create_dir(&parent).unwrap();
        let leaf = parent.join("child");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o000)).unwrap();

        let result = ensure_secure_base(&leaf, uid);

        // Restore before asserting so a failure cannot leave an unremovable tree.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        let err = result.expect_err("a non-NotFound stat error must propagate");
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "EACCES must not be collapsed into NotFound, got: {err:?}",
        );
    }

    /// GAP-6: the create -> `EEXIST` -> re-validate arm REJECTS a planted symlink
    /// rather than failing open, and does not follow it.
    ///
    /// In production that arm is reached by losing a create race: `lstat` sees
    /// the leaf absent, then `mkdir(2)` returns `EEXIST`. What the arm does,
    /// though, depends only on WHAT is at the name, not on how it got there —
    /// `mkdir(2)` reports `EEXIST` on a symlink without following it either way
    /// — so planting the symlink first and calling the arm directly reaches
    /// exactly the state a lost race leaves, with no dependence on thread
    /// scheduling. (It used to be driven by a spin-loop planter thread that had
    /// to win a race within a fixed number of attempts, which failed whenever
    /// the machine was busy.)
    ///
    /// Mutating the `AlreadyExists` arm to `Ok(())` makes this return Ok over a
    /// symlinked base, failing here.
    #[test]
    fn create_base_or_revalidate_rejects_a_planted_symlink() {
        let uid = unsafe { libc::getuid() };
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        let base = root.path().join("planted-base");
        std::os::unix::fs::symlink(&target, &base).unwrap();

        let err = create_base_or_revalidate(&base, uid)
            .expect_err("a symlink at the base must be rejected, not accepted or followed");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "expected the symlink rejection, got: {err:?}",
        );
        assert!(
            base.symlink_metadata().unwrap().file_type().is_symlink(),
            "the planted symlink must be left exactly as it was",
        );
        assert_eq!(
            fs::read_dir(&target).unwrap().count(),
            0,
            "nothing may have been created THROUGH the symlink into its target",
        );
    }

    /// GAP-8: when the XDG primary base cannot be secured, the default-base
    /// resolver falls back to the secure per-uid `$TMPDIR/sandlock-cow-<uid>`
    /// base — and if THAT also cannot be secured, it HARD-ERRORS rather than
    /// silently using an insecure base.
    ///
    /// Runs against the pure resolver with both directories injected, so it
    /// mutates no process-global state. It used to set `XDG_RUNTIME_DIR` and
    /// `TMPDIR` for the whole process, which is unsound under a parallel test
    /// runner twice over: the sibling tests that call `create(None)` read the
    /// same two variables, and the `TMPDIR` write additionally reparents every
    /// `tempfile::tempdir()` in this binary under a directory this test then
    /// removes. `create(None)` calling the same resolver is what
    /// `list_preserved_default_base_spans_pids` proves end to end.
    #[test]
    fn default_storage_base_falls_back_off_a_foreign_xdg_and_then_hard_fails() {
        use std::os::unix::fs::PermissionsExt;
        let uid = unsafe { libc::getuid() };

        let xdg_root = tempfile::tempdir().unwrap();
        let tmp_root = tempfile::tempdir().unwrap();

        // Plant $XDG/sandlock-cow (the primary) group/world-accessible -> insecure.
        let foreign_primary = xdg_root.path().join("sandlock-cow");
        fs::create_dir(&foreign_primary).unwrap();
        fs::set_permissions(&foreign_primary, fs::Permissions::from_mode(0o777)).unwrap();

        // The resolver must fall back to the secure per-uid tmp base, creating
        // it 0700 on the way.
        let tmp_base = tmp_storage_base(tmp_root.path(), uid);
        let chosen =
            resolve_default_storage_base(Some(xdg_root.path().as_os_str()), tmp_root.path(), uid, uid)
                .expect("an insecure XDG base must fall back, not fail");
        assert_eq!(
            chosen, tmp_base,
            "an insecure XDG base must fall back to the secure per-uid tmp base",
        );
        assert_eq!(
            fs::metadata(&tmp_base).unwrap().permissions().mode() & 0o777,
            0o700,
            "the fallback base must be created 0700",
        );

        // Now make the tmp fallback ALSO insecure: the chain must HARD-ERROR,
        // never silently land on an insecure base and never fall back twice.
        fs::set_permissions(&tmp_base, fs::Permissions::from_mode(0o777)).unwrap();
        let err = match resolve_default_storage_base(
            Some(xdg_root.path().as_os_str()),
            tmp_root.path(),
            uid,
            uid,
        ) {
            Ok(b) => panic!("both bases insecure must be a hard error, got base {}", b.display()),
            Err(e) => e,
        };
        assert!(
            matches!(err, BranchError::Operation(ref m) if m.starts_with("create storage base")),
            "expected a create-storage-base error, got: {err:?}",
        );
    }

    /// One sweep of the per-uid default base spans MULTIPLE pids' preserved work —
    /// the point of dropping the pid from the base name — AND the base a real
    /// `create(None)` actually chooses is that per-user base, carrying no pid
    /// component.
    ///
    /// The base-selection half is load-bearing for the None-arm of `create`:
    /// reverting it to a per-pid base name (e.g. `sandlock-cow-<pid>`) makes the
    /// chosen base's parent differ from `preferred_storage_base(...)` and puts the
    /// pid back into the base, failing the assertions below. The old form of this
    /// test never called `create(None)` at all, so that revert could not fail it.
    #[test]
    fn list_preserved_default_base_spans_pids() {
        let uid = unsafe { libc::getuid() };
        let euid = unsafe { libc::geteuid() };

        // A real create(None) chooses the per-user default base, not a per-pid one.
        // Mirror create()'s selection exactly (same XDG-vs-tmp decision) so the
        // expectation tracks it, then assert the branch dir's parent IS that base
        // and that the base has NO pid component.
        let tmp = std::env::temp_dir();
        let primary = preferred_storage_base(
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
            &tmp,
            uid,
            euid,
        );
        let expected_base = if ensure_secure_base(&primary, uid).is_ok() {
            primary
        } else {
            tmp_storage_base(&tmp, uid)
        };
        let workdir = tempfile::tempdir().unwrap();
        let branch = SeccompCowBranch::create(workdir.path(), None, 0).unwrap();
        let chosen_base = branch.storage_dir.parent().unwrap();
        assert_eq!(
            chosen_base, expected_base,
            "create(None) must store under the per-user default base",
        );
        let pid = std::process::id().to_string();
        assert!(
            !chosen_base.components().any(|c| c.as_os_str() == pid.as_str()),
            "the default base must carry NO pid component, got {}",
            chosen_base.display(),
        );
        assert!(
            !chosen_base.to_string_lossy().contains(&pid),
            "the default base name must not embed the pid, got {}",
            chosen_base.display(),
        );
        drop(branch); // reclaim the branch dir created under the shared default base

        // The sweep half: two markers with different pids under one per-uid base
        // (forced to the tmp fallback under a private root) are both found by a
        // single sweep — pid liveness disambiguates them, not the base name.
        let sweep_tmp = tempfile::tempdir().unwrap();
        let base = preferred_storage_base(None, sweep_tmp.path(), uid, euid);
        ensure_secure_base(&base, uid).unwrap();
        for (i, pid) in [111u32, 222u32].into_iter().enumerate() {
            let bd = base.join(format!("branch-{i}"));
            fs::create_dir_all(bd.join("upper")).unwrap();
            fs::write(
                bd.join(PRESERVED_MARKER),
                format!(
                    "reason=commit-deferred\nworkdir=/wd{i}\nupper={}\npid={pid}\n",
                    bd.join("upper").display()
                ),
            )
            .unwrap();
        }

        let mut pids: Vec<u32> = list_preserved(&base).into_iter().map(|p| p.pid).collect();
        pids.sort();
        assert_eq!(
            pids,
            vec![111, 222],
            "one sweep of the per-uid base must span both pids"
        );
    }
}
