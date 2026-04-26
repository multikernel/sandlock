//! Seccomp notification handlers for COW filesystem interception.
//!
//! Reads paths from child memory, delegates to SeccompCowBranch,
//! and injects results (fds, stat structs, readlink strings, dirents) back.

use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::sync::Mutex as AsyncMutex;

use crate::arch;
use crate::cow::seccomp::SeccompCowBranch;
use crate::procfs::{build_dirent64, DT_DIR, DT_LNK, DT_REG};
use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction};
use crate::seccomp::state::{CowState, PerProcessState, ProcessIndex};
use crate::sys::structs::SeccompNotif;

/// Acquire the per-process state handle for `notif.pid`. Returns
/// None if the pid isn't tracked (pidfd_open failed at fork on an
/// old kernel, or the process is gone) — callers should fall back
/// to `NotifAction::Continue`.
fn pp_handle(
    processes: &Arc<ProcessIndex>,
    pid: u32,
) -> Option<Arc<AsyncMutex<PerProcessState>>> {
    processes
        .entry_for(i32::try_from(pid).ok()?)
        .map(|(_, s)| s)
}

/// Read the current virtual cwd for `pid` (None if the process
/// hasn't chdir'd into a COW-only directory, or isn't tracked).
async fn current_virtual_cwd(
    processes: &Arc<ProcessIndex>,
    pid: u32,
) -> Option<String> {
    let handle = pp_handle(processes, pid)?;
    let cwd = handle.lock().await.virtual_cwd.clone();
    cwd
}

/// Read a NUL-terminated path from child memory (up to 4096 bytes for filesystem paths).
///
/// Reads page-by-page to avoid crossing into unmapped memory (e.g. when the path
/// pointer is near a page boundary on the stack).
fn read_path(notif: &SeccompNotif, addr: u64, notif_fd: RawFd) -> Option<String> {
    if addr == 0 {
        return None;
    }
    const PAGE_SIZE: u64 = 4096;
    let mut result = Vec::with_capacity(256);
    let mut cur = addr;
    while result.len() < 4096 {
        let page_remaining = PAGE_SIZE - (cur % PAGE_SIZE);
        let to_read = page_remaining.min((4096 - result.len()) as u64) as usize;
        let bytes = read_child_mem(notif_fd, notif.id, notif.pid, cur, to_read).ok()?;
        if let Some(nul) = bytes.iter().position(|&b| b == 0) {
            result.extend_from_slice(&bytes[..nul]);
            return String::from_utf8(result).ok();
        }
        result.extend_from_slice(&bytes);
        cur += to_read as u64;
    }
    String::from_utf8(result).ok()
}

/// Resolve a path that may be relative to a dirfd.
/// For AT_FDCWD (-100), returns the path as-is (assumed absolute or cwd-relative).
/// For other dirfds, reads /proc/{pid}/fd/{dirfd} to get the base path.
fn normalize_path(path: PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

fn resolve_at_path_with_virtual(
    notif: &SeccompNotif,
    dirfd: i64,
    path: &str,
    virtual_cwd: Option<&str>,
) -> String {
    if Path::new(path).is_absolute() {
        return normalize_path(PathBuf::from(path)).to_string_lossy().into_owned();
    }
    // dirfd is stored as u64 in seccomp_data.args but AT_FDCWD is a negative i32.
    // Truncate to i32 for correct sign comparison.
    let dirfd32 = dirfd as i32;
    if dirfd32 == libc::AT_FDCWD {
        if let Some(cwd) = virtual_cwd {
            return normalize_path(Path::new(cwd).join(path))
                .to_string_lossy()
                .into_owned();
        }
        // Relative to cwd — read /proc/{pid}/cwd
        if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
            return normalize_path(cwd.join(path)).to_string_lossy().into_owned();
        }
        return path.to_string();
    }
    // Relative to dirfd
    if let Ok(base) = std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd)) {
        normalize_path(base.join(path)).to_string_lossy().into_owned()
    } else {
        path.to_string()
    }
}

fn map_cow_upper_path(cow: &SeccompCowBranch, path: &str) -> String {
    let path = PathBuf::from(path);
    if let Ok(rel) = path.strip_prefix(cow.upper_dir()) {
        return normalize_path(cow.workdir().join(rel)).to_string_lossy().into_owned();
    }
    normalize_path(path).to_string_lossy().into_owned()
}

// ============================================================
// openat handler
// ============================================================

/// Handle openat under workdir: redirect to COW upper/lower.
/// openat(dirfd, pathname, flags, mode): args[0]=dirfd, args[1]=path, args[2]=flags
pub(crate) async fn handle_cow_open(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    use crate::cow::seccomp::CowOpenPlan;

    let nr = notif.data.nr as i64;

    // open(path, flags, mode):     args[0]=path, args[1]=flags
    // openat(dirfd, path, flags):  args[0]=dirfd, args[1]=path, args[2]=flags
    let (path_ptr, dirfd, flags) = if Some(nr) == arch::SYS_OPEN {
        (notif.data.args[0], libc::AT_FDCWD as i64, notif.data.args[1])
    } else {
        (notif.data.args[1], notif.data.args[0] as i64, notif.data.args[2])
    };

    let rel_path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    let virtual_cwd = if (dirfd as i32) == libc::AT_FDCWD && !Path::new(&rel_path).is_absolute() {
        current_virtual_cwd(processes, notif.pid).await
    } else {
        None
    };
    let mut path = resolve_at_path_with_virtual(notif, dirfd, &rel_path, virtual_cwd.as_deref());

    // Phase 1: determine plan under lock (no heavy I/O)
    let plan = {
        let mut st = cow_state.lock().await;
        let cow = match st.branch.as_mut() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };

        path = map_cow_upper_path(cow, &path);
        if !cow.matches(&path) {
            return NotifAction::Continue;
        }

        // Read-only opens don't need interception unless the file was
        // modified or deleted in the COW layer.
        const WRITE_FLAGS: u64 = (libc::O_WRONLY
            | libc::O_RDWR
            | libc::O_CREAT
            | libc::O_TRUNC
            | libc::O_APPEND) as u64;
        let is_write = flags & WRITE_FLAGS != 0;
        if !is_write && !cow.needs_read_intercept(&path) {
            return NotifAction::Continue;
        }

        match cow.prepare_open(&path, flags) {
            Ok(plan) => plan,
            Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
            Err(crate::error::BranchError::Exists) => return NotifAction::Errno(libc::EEXIST),
            Err(_) => return NotifAction::Continue,
        }
    };
    // Lock is released here

    // Phase 2: execute I/O plan without holding the lock
    let real_path = match plan {
        CowOpenPlan::Skip => return NotifAction::Continue,
        CowOpenPlan::Resolved(p) | CowOpenPlan::UpperReady { upper: p } => p,
        CowOpenPlan::NeedsCopy { upper, lower, file_size, rel_path: _rel } => {
            // Do the potentially-expensive copy on a blocking thread
            let upper_clone = upper.clone();
            let copy_result = tokio::task::spawn_blocking(move || {
                crate::cow::seccomp::SeccompCowBranch::execute_copy(&upper_clone, &lower)
            }).await;

            match copy_result {
                Ok(Ok(())) => upper,
                Ok(Err(_)) | Err(_) => {
                    // Copy failed — roll back quota and let kernel handle it
                    let mut st = cow_state.lock().await;
                    if let Some(cow) = st.branch.as_mut() {
                        cow.rollback_copy(file_size);
                    }
                    return NotifAction::Continue;
                }
            }
        }
    };

    // Phase 3: open the resolved path and inject fd
    // Strip O_EXCL — the COW layer already verified exclusivity. Keeping it
    // would fail because we may have just copied the file into upper.
    let open_flags = (flags & !(libc::O_EXCL as u64)) as i32;
    let c_path = match std::ffi::CString::new(real_path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => return NotifAction::Continue,
    };
    let fd = unsafe { libc::open(c_path.as_ptr(), open_flags, 0o666) };
    if fd < 0 {
        return NotifAction::Continue;
    }

    // Preserve O_CLOEXEC from the original openat flags.
    let newfd_flags = if flags & libc::O_CLOEXEC as u64 != 0 {
        libc::O_CLOEXEC as u32
    } else {
        0
    };
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    NotifAction::InjectFdSend { srcfd: owned, newfd_flags }
}

// ============================================================
// Write operation handlers
// ============================================================

/// Parsed COW write operation with resolved paths and extracted arguments.
enum CowWriteOp {
    Unlink { path: String, is_dir: bool },
    Mkdir { path: String },
    Rename { old_path: String, new_path: String },
    Symlink { target: String, linkpath: String },
    Link { old_path: String, new_path: String },
    Chmod { path: String, mode: u32 },
    Chown { path: String, uid: u32, gid: u32 },
    Truncate { path: String, length: i64 },
}

impl CowWriteOp {
    fn remap_upper_paths(&mut self, cow: &SeccompCowBranch) {
        match self {
            CowWriteOp::Unlink { path, .. }
            | CowWriteOp::Mkdir { path }
            | CowWriteOp::Chmod { path, .. }
            | CowWriteOp::Chown { path, .. }
            | CowWriteOp::Truncate { path, .. } => {
                *path = map_cow_upper_path(cow, path);
            }
            CowWriteOp::Rename { old_path, new_path }
            | CowWriteOp::Link { old_path, new_path } => {
                *old_path = map_cow_upper_path(cow, old_path);
                *new_path = map_cow_upper_path(cow, new_path);
            }
            CowWriteOp::Symlink { linkpath, .. } => {
                *linkpath = map_cow_upper_path(cow, linkpath);
            }
        }
    }
}

/// Read and resolve a path argument. For *at syscalls, pass the dirfd arg index;
/// for legacy syscalls, pass None to use the raw path.
fn read_resolved(
    notif: &SeccompNotif,
    path_arg: usize,
    dirfd_arg: Option<usize>,
    notif_fd: RawFd,
    virtual_cwd: Option<&str>,
) -> Option<String> {
    let raw = read_path(notif, notif.data.args[path_arg], notif_fd)?;
    match dirfd_arg {
        Some(i) => Some(resolve_at_path_with_virtual(
            notif,
            notif.data.args[i] as i64,
            &raw,
            virtual_cwd,
        )),
        None => Some(resolve_at_path_with_virtual(
            notif,
            libc::AT_FDCWD as i64,
            &raw,
            virtual_cwd,
        )),
    }
}

/// Parse the syscall into a CowWriteOp, reading and resolving paths from child memory.
fn parse_cow_write(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    virtual_cwd: Option<&str>,
) -> Option<CowWriteOp> {
    let nr = notif.data.nr as i64;

    // *at variants (dirfd in args[0], path in args[1])
    if nr == libc::SYS_unlinkat {
        let path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let is_dir = (notif.data.args[2] & libc::AT_REMOVEDIR as u64) != 0;
        return Some(CowWriteOp::Unlink { path, is_dir });
    }
    if nr == libc::SYS_mkdirat {
        return Some(CowWriteOp::Mkdir {
            path: read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?,
        });
    }
    if nr == libc::SYS_renameat2 {
        let old_path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 3, Some(2), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Rename { old_path, new_path });
    }
    if nr == libc::SYS_symlinkat {
        // symlinkat(target, newdirfd, linkpath): target is raw, linkpath is resolved
        let target = read_path(notif, notif.data.args[0], notif_fd)?;
        let linkpath = read_resolved(notif, 2, Some(1), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Symlink { target, linkpath });
    }
    if nr == libc::SYS_linkat {
        let old_path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 3, Some(2), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Link { old_path, new_path });
    }
    if nr == libc::SYS_fchmodat {
        let path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Chmod { path, mode: (notif.data.args[2] & 0o7777) as u32 });
    }
    if nr == libc::SYS_fchownat {
        let path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Chown { path, uid: notif.data.args[2] as u32, gid: notif.data.args[3] as u32 });
    }

    // Legacy variants (path in args[0], no dirfd)
    if Some(nr) == arch::SYS_UNLINK {
        return Some(CowWriteOp::Unlink {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
            is_dir: false,
        });
    }
    if Some(nr) == arch::SYS_RMDIR {
        return Some(CowWriteOp::Unlink {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
            is_dir: true,
        });
    }
    if Some(nr) == arch::SYS_MKDIR {
        return Some(CowWriteOp::Mkdir {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
        });
    }
    if Some(nr) == arch::SYS_RENAME {
        let old_path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 1, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Rename { old_path, new_path });
    }
    if Some(nr) == arch::SYS_SYMLINK {
        let target = read_path(notif, notif.data.args[0], notif_fd)?;
        let linkpath = read_resolved(notif, 1, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Symlink { target, linkpath });
    }
    if Some(nr) == arch::SYS_LINK {
        let old_path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 1, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Link { old_path, new_path });
    }
    if Some(nr) == arch::SYS_CHMOD {
        let path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Chmod { path, mode: (notif.data.args[1] & 0o7777) as u32 });
    }
    if Some(nr) == arch::SYS_CHOWN || Some(nr) == arch::SYS_LCHOWN {
        let path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Chown { path, uid: notif.data.args[1] as u32, gid: notif.data.args[2] as u32 });
    }

    // truncate (legacy only, path in args[0])
    if nr == libc::SYS_truncate {
        let path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Truncate { path, length: notif.data.args[1] as i64 });
    }

    None
}

/// Map a BranchError result to a NotifAction.
fn cow_result(r: Result<bool, crate::error::BranchError>) -> NotifAction {
    match r {
        Ok(true) => NotifAction::ReturnValue(0),
        Err(crate::error::BranchError::QuotaExceeded) => NotifAction::Errno(libc::ENOSPC),
        _ => NotifAction::Continue,
    }
}

/// Map an unlink result (returns errno directly) to a NotifAction.
fn unlink_result(r: Result<bool, i32>) -> NotifAction {
    match r {
        Ok(true) => NotifAction::ReturnValue(0),
        Err(errno) => NotifAction::Errno(errno),
        _ => NotifAction::Continue,
    }
}

/// Determine which relative path (if any) needs a COW copy for this operation.
/// Returns `(match_path, copy_rel)` where match_path is checked against
/// `cow.matches()` and copy_rel is the relative path to pre-copy.
fn cow_copy_rel<'a>(
    op: &'a CowWriteOp,
    cow: &crate::cow::seccomp::SeccompCowBranch,
) -> Option<(&'a str, String)> {
    let (match_path, copy_path) = match op {
        // These ops call ensure_cow_copy internally — pre-copy the target
        CowWriteOp::Chmod { ref path, .. }
        | CowWriteOp::Chown { ref path, .. }
        | CowWriteOp::Truncate { ref path, .. } => (path.as_str(), path.as_str()),
        CowWriteOp::Rename { ref old_path, .. } => (old_path.as_str(), old_path.as_str()),
        CowWriteOp::Link { ref old_path, ref new_path, .. } => (new_path.as_str(), old_path.as_str()),
        // These ops don't need a pre-copy
        _ => return None,
    };
    if !cow.matches(match_path) {
        return None;
    }
    cow.safe_rel(copy_path)
        .map(|rel| (match_path, rel))
}

/// Execute a deferred `CowCopyPlan::NeedsCopy` on a blocking thread.
/// Returns the upper path on success, or rolls back quota on failure.
async fn execute_deferred_copy(
    cow_state: &Arc<Mutex<CowState>>,
    upper: std::path::PathBuf,
    lower: std::path::PathBuf,
    file_size: u64,
) -> Option<std::path::PathBuf> {
    let upper_clone = upper.clone();
    let copy_result = tokio::task::spawn_blocking(move || {
        crate::cow::seccomp::SeccompCowBranch::execute_copy(&upper_clone, &lower)
    }).await;
    match copy_result {
        Ok(Ok(())) => Some(upper),
        _ => {
            let mut st = cow_state.lock().await;
            if let Some(cow) = st.branch.as_mut() {
                cow.rollback_copy(file_size);
            }
            None
        }
    }
}

/// Handle all write-type syscalls: both *at variants (unlinkat, mkdirat, etc.)
/// and legacy variants (unlink, rmdir, mkdir, etc.).
///
/// For operations that modify existing files (chmod, chown, rename, link,
/// truncate), the handler uses a two-phase pattern: prepare the copy plan
/// under the lock, execute the potentially expensive file copy outside the
/// lock, then re-acquire the lock and run the actual operation (which finds
/// the file already in upper).
pub(crate) async fn handle_cow_write(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let mut op = match parse_cow_write(notif, notif_fd, virtual_cwd.as_deref()) {
        Some(op) => op,
        None => return NotifAction::Continue,
    };

    // Phase 1: check if we need to pre-copy a file (under lock, no heavy I/O)
    let copy_plan = {
        let mut st = cow_state.lock().await;
        let cow = match st.branch.as_mut() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };

        op.remap_upper_paths(cow);
        match cow_copy_rel(&op, cow) {
            Some((_match_path, ref rel)) => {
                match cow.prepare_copy(rel) {
                    Ok(plan) => Some(plan),
                    Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                    Err(_) => return NotifAction::Continue,
                }
            }
            None => None,
        }
    };
    // Lock is released here

    // Phase 2: execute the file copy outside the lock (if needed)
    if let Some(crate::cow::seccomp::CowCopyPlan::NeedsCopy { upper, lower, file_size }) = copy_plan {
        if execute_deferred_copy(cow_state, upper, lower, file_size).await.is_none() {
            return NotifAction::Continue;
        }
    }

    // Phase 3: execute the operation under lock (ensure_cow_copy is now a no-op
    // for the pre-copied file since it's already in upper)
    let mut st = cow_state.lock().await;
    let cow = match st.branch.as_mut() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    match op {
        CowWriteOp::Unlink { ref path, is_dir } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            unlink_result(cow.handle_unlink(path, is_dir))
        }
        CowWriteOp::Mkdir { ref path } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            cow_result(cow.handle_mkdir(path))
        }
        CowWriteOp::Rename { ref old_path, ref new_path } => {
            if !cow.matches(old_path) { return NotifAction::Continue; }
            cow_result(cow.handle_rename(old_path, new_path))
        }
        CowWriteOp::Symlink { ref target, ref linkpath } => {
            if !cow.matches(linkpath) { return NotifAction::Continue; }
            cow_result(cow.handle_symlink(target, linkpath))
        }
        CowWriteOp::Link { ref old_path, ref new_path } => {
            if !cow.matches(new_path) { return NotifAction::Continue; }
            cow_result(cow.handle_link(old_path, new_path))
        }
        CowWriteOp::Chmod { ref path, mode } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            cow_result(cow.handle_chmod(path, mode))
        }
        CowWriteOp::Chown { ref path, uid, gid } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            cow_result(cow.handle_chown(path, uid, gid))
        }
        CowWriteOp::Truncate { ref path, length } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            cow_result(cow.handle_truncate(path, length))
        }
    }
}

// ============================================================
// access() handler — fake W_OK for COW-managed paths
// ============================================================

/// SYS_faccessat2 syscall number on x86_64 (439). Not always in libc crate.
pub(crate) const SYS_FACCESSAT2: i64 = 439;

/// Handle faccessat/faccessat2/access — return success for W_OK checks on
/// COW-managed paths so programs that pre-check write permissions (like dpkg)
/// don't fail before the COW layer can redirect their writes.
pub(crate) async fn handle_cow_access(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;

    // access(pathname, mode): args[0]=path, args[1]=mode
    // faccessat(dirfd, pathname, mode, flags): args[0]=dirfd, args[1]=path, args[2]=mode
    let (path, mode) = if Some(nr) == arch::SYS_ACCESS {
        let p = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => resolve_at_path_with_virtual(
                notif,
                libc::AT_FDCWD as i64,
                &p,
                virtual_cwd.as_deref(),
            ),
            None => return NotifAction::Continue,
        };
        (p, notif.data.args[1] as i32)
    } else {
        let dirfd = notif.data.args[0] as i64;
        let p = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref()),
            None => return NotifAction::Continue,
        };
        (p, notif.data.args[2] as i32)
    };

    // Only intercept W_OK checks
    if mode & libc::W_OK == 0 {
        return NotifAction::Continue;
    }

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    let path = map_cow_upper_path(cow, &path);
    if !cow.matches(&path) {
        return NotifAction::Continue;
    }

    // Path is under workdir and W_OK was requested — writes will be
    // redirected to the COW upper layer, so report success.
    // Check the path actually exists on the real filesystem.
    if std::path::Path::new(&path).exists() || cow.handle_stat(&path).is_some() {
        return NotifAction::ReturnValue(0);
    }

    NotifAction::Continue
}

// ============================================================
// utimensat handler
// ============================================================

/// Handle utimensat — resolve path to COW upper then set timestamps.
/// utimensat(dirfd, pathname, times, flags)
pub(crate) async fn handle_cow_utimensat(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let dirfd = notif.data.args[0] as i64;
    let path_ptr = notif.data.args[1];
    let times_ptr = notif.data.args[2];
    let flags = notif.data.args[3] as i32;

    if path_ptr == 0 {
        return NotifAction::Continue;
    }

    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref()),
        None => return NotifAction::Continue,
    };

    let upper_path = {
        let mut st = cow_state.lock().await;
        let cow = match st.branch.as_mut() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let path = map_cow_upper_path(cow, &path);
        if !cow.matches(&path) {
            return NotifAction::Continue;
        }
        match cow.handle_utimensat(&path) {
            Ok(Some(p)) => p,
            Ok(None) => return NotifAction::Continue,
            Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
            Err(_) => return NotifAction::Continue,
        }
    };

    // Read times from child memory (2 x struct timespec = 32 bytes on x86_64)
    let times = if times_ptr != 0 {
        match read_child_mem(notif_fd, notif.id, notif.pid, times_ptr, 32) {
            Ok(data) => {
                let mut ts: [libc::timespec; 2] = unsafe { std::mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), &mut ts as *mut _ as *mut u8, 32);
                }
                Some(ts)
            }
            Err(_) => return NotifAction::Errno(libc::EFAULT),
        }
    } else {
        None
    };

    let c_path = match std::ffi::CString::new(upper_path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => return NotifAction::Continue,
    };
    let times_raw = times.as_ref().map(|t| t.as_ptr()).unwrap_or(std::ptr::null());
    if unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times_raw, flags) } < 0 {
        return NotifAction::Errno(libc::EIO);
    }
    NotifAction::ReturnValue(0)
}

// ============================================================
// Read operation handlers (stat, readlink, getdents)
// ============================================================

/// Handle newfstatat / faccessat — resolve path then Continue to let kernel stat.
/// The trick: we rewrite the path pointer in child memory to point to the resolved path.
/// Actually, simpler: for stat, we do the stat ourselves and write the result.
pub(crate) async fn handle_cow_stat(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    // newfstatat(dirfd, pathname, statbuf, flags)
    // faccessat(dirfd, pathname, mode, flags)
    let dirfd = notif.data.args[0] as i64;
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = match read_path(notif, notif.data.args[1], notif_fd) {
        Some(p) => resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref()),
        None => return NotifAction::Continue,
    };

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    let path = map_cow_upper_path(cow, &path);
    if !cow.has_changes() || !cow.matches(&path) {
        return NotifAction::Continue;
    }

    let real_path = match cow.handle_stat(&path) {
        Some(p) => p,
        None => {
            return NotifAction::Errno(libc::ENOENT);
        }
    };
    drop(st);

    if nr == libc::SYS_faccessat || nr == SYS_FACCESSAT2 {
        // For faccessat, just check if the file exists (we already resolved it)
        if real_path.exists() || real_path.is_symlink() {
            return NotifAction::ReturnValue(0);
        }
        return NotifAction::Errno(libc::ENOENT);
    }

    // newfstatat — stat the resolved path and write the native libc layout
    // back to the child. Do not hand-pack struct stat; its layout is
    // architecture-specific.
    let statbuf_addr = notif.data.args[2];
    let flags = (notif.data.args[3] & 0xFFFF_FFFF) as i32;
    let c_path = match std::ffi::CString::new(real_path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => return NotifAction::Continue,
    };
    let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(libc::AT_FDCWD, c_path.as_ptr(), &mut statbuf, flags) } < 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return NotifAction::Errno(errno);
    }
    let buf = unsafe {
        std::slice::from_raw_parts(
            &statbuf as *const libc::stat as *const u8,
            std::mem::size_of::<libc::stat>(),
        )
    };

    if write_child_mem(notif_fd, notif.id, notif.pid, statbuf_addr, buf).is_err() {
        return NotifAction::Continue;
    }

    NotifAction::ReturnValue(0)
}

/// Handle statx — resolve path then let kernel handle (complex struct).
pub(crate) async fn handle_cow_statx(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    // statx(dirfd, pathname, flags, mask, statxbuf)
    let dirfd = notif.data.args[0] as i64;
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = match read_path(notif, notif.data.args[1], notif_fd) {
        Some(p) => resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref()),
        None => return NotifAction::Continue,
    };

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    let path = map_cow_upper_path(cow, &path);
    if !cow.has_changes() || !cow.matches(&path) {
        return NotifAction::Continue;
    }

    match cow.handle_stat(&path) {
        Some(_) => NotifAction::Continue, // exists, let kernel handle
        None => NotifAction::Errno(libc::ENOENT), // deleted
    }
}

/// Handle readlinkat — read symlink from upper/lower, write to child buffer.
pub(crate) async fn handle_cow_readlink(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    // readlinkat(dirfd, pathname, buf, bufsiz)
    let dirfd = notif.data.args[0] as i64;
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = match read_path(notif, notif.data.args[1], notif_fd) {
        Some(p) => resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref()),
        None => return NotifAction::Continue,
    };
    let buf_addr = notif.data.args[2];
    let bufsiz = (notif.data.args[3] & 0xFFFFFFFF) as usize;

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    let path = map_cow_upper_path(cow, &path);
    if !cow.has_changes() || !cow.matches(&path) {
        return NotifAction::Continue;
    }

    let target = match cow.handle_readlink(&path) {
        Some(t) => t,
        None => return NotifAction::Errno(libc::ENOENT),
    };
    drop(st);

    let target_bytes = target.as_bytes();
    let write_len = target_bytes.len().min(bufsiz);

    if write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, &target_bytes[..write_len]).is_err()
    {
        return NotifAction::Continue;
    }

    NotifAction::ReturnValue(write_len as i64)
}

/// Handle getdents64 for COW directories — merge upper + lower entries.
pub(crate) async fn handle_cow_getdents(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let pid = notif.pid;
    let child_fd = (notif.data.args[0] & 0xFFFFFFFF) as u32;
    let buf_addr = notif.data.args[1];
    let buf_size = (notif.data.args[2] & 0xFFFFFFFF) as usize;

    // Check if fd points to a COW-managed directory.
    let link_path = format!("/proc/{}/fd/{}", pid, child_fd);
    let target = match std::fs::read_link(&link_path) {
        Ok(t) => t.to_string_lossy().into_owned(),
        Err(_) => return NotifAction::Continue,
    };

    // Compute rel_path under the global COW lock, but do not hold it
    // across the per-process lock acquired below.
    let rel_path = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        if !cow.has_changes() {
            return NotifAction::Continue;
        }
        let target_path = Path::new(&target);
        if cow.matches(&target) {
            cow.safe_rel(&target).unwrap_or_else(|| ".".to_string())
        } else if let Ok(rel) = target_path.strip_prefix(cow.upper_dir()) {
            let rel = rel.to_string_lossy();
            if rel.is_empty() {
                ".".to_string()
            } else {
                rel.into_owned()
            }
        } else {
            return NotifAction::Continue;
        }
    };

    // Per-process dir cache lookup.
    let pp = match pp_handle(processes, pid) {
        Some(h) => h,
        None => return NotifAction::Continue,
    };
    let mut perproc = pp.lock().await;

    // Invalidate stale cache (fd reused for a different directory),
    // and short-circuit EOF on a previously fully-drained entry.
    if let Some((cached_target, entries)) = perproc.cow_dir_cache.get(&child_fd) {
        if *cached_target != target {
            perproc.cow_dir_cache.remove(&child_fd);
        } else if entries.is_empty() {
            perproc.cow_dir_cache.remove(&child_fd);
            return NotifAction::ReturnValue(0);
        }
    }

    // Build cache on first call.
    if !perproc.cow_dir_cache.contains_key(&child_fd) {
        let entries = {
            let st = cow_state.lock().await;
            let cow = match st.branch.as_ref() {
                Some(c) => c,
                None => return NotifAction::Continue,
            };
            let merged = cow.list_merged_dir(&rel_path);
            let upper_dir = cow.upper_dir().join(&rel_path);
            let lower_dir = cow.workdir().join(&rel_path);

            let mut out = Vec::new();
            let mut d_off: i64 = 0;
            for name in &merged {
                d_off += 1;
                let upper_p = upper_dir.join(name);
                let lower_p = lower_dir.join(name);
                let check = if upper_p.exists() || upper_p.is_symlink() {
                    &upper_p
                } else {
                    &lower_p
                };
                let d_type = if check.is_dir() {
                    DT_DIR
                } else if check.is_symlink() {
                    DT_LNK
                } else {
                    DT_REG
                };
                use std::os::unix::fs::MetadataExt;
                let d_ino = std::fs::symlink_metadata(check)
                    .map(|m| m.ino())
                    .unwrap_or(0);
                out.push(build_dirent64(d_ino, d_off, d_type, name));
            }
            out
        };
        perproc.cow_dir_cache.insert(child_fd, (target.clone(), entries));
    }

    let entries = match perproc.cow_dir_cache.get_mut(&child_fd) {
        Some((_, e)) => e,
        None => return NotifAction::Continue,
    };

    let mut result = Vec::new();
    let mut consumed = 0;
    for entry in entries.iter() {
        if result.len() + entry.len() > buf_size {
            break;
        }
        result.extend_from_slice(entry);
        consumed += 1;
    }

    if consumed > 0 {
        entries.drain(..consumed);
    }
    drop(perproc);

    if !result.is_empty() {
        if write_child_mem(notif_fd, notif.id, pid, buf_addr, &result).is_err() {
            return NotifAction::Continue;
        }
    }

    NotifAction::ReturnValue(result.len() as i64)
}

/// Handle chdir — redirect to COW upper directory if the target was created
/// by COW and doesn't exist on the real filesystem.
///
/// Opens the upper directory, injects the fd into the child, and rewrites
/// the path arg to /proc/self/fd/N so the kernel chdir succeeds.
pub(crate) async fn handle_cow_chdir(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let path_ptr = notif.data.args[0];
    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    let orig_path_buf_len = path.len() + 1; // NUL-terminated size in child memory

    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let resolved = resolve_at_path_with_virtual(
        notif,
        libc::AT_FDCWD as i64,
        &path,
        virtual_cwd.as_deref(),
    );

    let (abs_path, upper_path) = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let abs_path = map_cow_upper_path(cow, &resolved);
        if !cow.matches(&abs_path) {
            return NotifAction::Continue;
        }
        let rel = match cow.safe_rel(&abs_path) {
            Some(r) => r,
            None => return NotifAction::Continue,
        };
        let upper_path = cow.upper_dir().join(&rel);
        (abs_path, upper_path)
    };

    // If the directory exists on the real filesystem, let the kernel handle it.
    if std::path::Path::new(&abs_path).is_dir() {
        return NotifAction::Continue;
    }

    // Only intervene if the directory exists in the COW upper layer.
    if !upper_path.is_dir() {
        return NotifAction::Continue;
    }

    // Open the upper directory and inject fd into the child.
    let c_path = match std::ffi::CString::new(upper_path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => return NotifAction::Continue,
    };
    let src_fd = unsafe {
        libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
    };
    if src_fd < 0 {
        return NotifAction::Errno(libc::ENOENT);
    }

    let addfd = crate::sys::structs::SeccompNotifAddfd {
        id: notif.id,
        flags: 0,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags: libc::O_CLOEXEC as u32,
    };
    let child_fd = unsafe {
        libc::ioctl(
            notif_fd,
            crate::sys::structs::SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong,
            &addfd as *const _,
        )
    };
    unsafe { libc::close(src_fd) };

    if child_fd < 0 {
        return NotifAction::Errno(libc::EIO);
    }

    // Rewrite the path argument to /proc/self/fd/N so the kernel chdir
    // follows the injected fd.  The original buffer at path_ptr must be
    // large enough — otherwise we'd corrupt adjacent child memory.
    let fd_path = format!("/proc/self/fd/{}\0", child_fd);
    if orig_path_buf_len < fd_path.len() {
        // Original path buffer too small for the rewrite.  The injected
        // fd has O_CLOEXEC so it will be cleaned up on exit/exec.
        return NotifAction::Errno(libc::ENOENT);
    }
    if write_child_mem(notif_fd, notif.id, notif.pid, path_ptr, fd_path.as_bytes()).is_err() {
        return NotifAction::Errno(libc::EFAULT);
    }

    // We insert the virtual cwd here, before returning Continue and
    // letting the kernel run the rewritten chdir. We can't observe
    // the kernel's verdict without polling, but at this point we've
    // verified upper_path is a directory, the addfd ioctl succeeded,
    // and write_child_mem rewrote the path argument — so a kernel
    // chdir to /proc/self/fd/N is essentially guaranteed. If it does
    // somehow fail, the per-child pidfd watcher will drop this entry
    // when the process exits, so the inconsistency is bounded by
    // process lifetime.
    if let Some(pp) = pp_handle(processes, notif.pid) {
        pp.lock().await.virtual_cwd = Some(abs_path);
    }

    NotifAction::Continue
}

/// Handle getcwd after chdir into a COW-only directory.
pub(crate) async fn handle_cow_getcwd(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let buf_addr = notif.data.args[0];
    let buf_size = (notif.data.args[1] & 0xFFFF_FFFF) as usize;

    let cached_virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let virtual_cwd = if let Some(cwd) = cached_virtual_cwd {
        cwd
    } else {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let cwd = match std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
            Ok(c) => c,
            Err(_) => return NotifAction::Continue,
        };
        match cwd.strip_prefix(cow.upper_dir()) {
            Ok(rel) => cow.workdir().join(rel).to_string_lossy().into_owned(),
            Err(_) => return NotifAction::Continue,
        }
    };

    let cwd_bytes = virtual_cwd.as_bytes();
    if cwd_bytes.len() + 1 > buf_size {
        return NotifAction::Errno(libc::ERANGE);
    }

    let mut write_buf = cwd_bytes.to_vec();
    write_buf.push(0);

    if write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, &write_buf).is_err() {
        return NotifAction::Continue;
    }
    NotifAction::ReturnValue(write_buf.len() as i64)
}
