//! Seccomp notification handlers for COW filesystem interception.
//!
//! Reads paths from child memory, delegates to SeccompCowBranch,
//! and injects results (fds, stat structs, readlink strings, dirents) back.

use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::procfs::{build_dirent64, DT_DIR, DT_LNK, DT_REG};
use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction};
use crate::seccomp::state::CowState;
use crate::sys::structs::SeccompNotif;

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
fn resolve_at_path(notif: &SeccompNotif, dirfd: i64, path: &str) -> String {
    if std::path::Path::new(path).is_absolute() {
        return path.to_string();
    }
    // dirfd is stored as u64 in seccomp_data.args but AT_FDCWD is a negative i32.
    // Truncate to i32 for correct sign comparison.
    let dirfd32 = dirfd as i32;
    if dirfd32 == libc::AT_FDCWD {
        // Relative to cwd — read /proc/{pid}/cwd
        if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
            return format!("{}/{}", cwd.display(), path);
        }
        return path.to_string();
    }
    // Relative to dirfd
    if let Ok(base) = std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd)) {
        format!("{}/{}", base.display(), path)
    } else {
        path.to_string()
    }
}

// ============================================================
// openat handler
// ============================================================

/// Handle openat under workdir: redirect to COW upper/lower.
/// openat(dirfd, pathname, flags, mode): args[0]=dirfd, args[1]=path, args[2]=flags
pub(crate) async fn handle_cow_open(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
) -> NotifAction {
    use crate::cow::seccomp::CowOpenPlan;

    let dirfd = notif.data.args[0] as i64;
    let path_ptr = notif.data.args[1];
    let flags = notif.data.args[2];

    let rel_path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    let path = resolve_at_path(notif, dirfd, &rel_path);

    // Phase 1: determine plan under lock (no heavy I/O)
    let plan = {
        let mut st = cow_state.lock().await;
        let cow = match st.branch.as_mut() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };

        if !cow.matches(&path) {
            return NotifAction::Continue;
        }

        // Read-only opens don't need interception unless the file was
        // modified or deleted in the COW layer.
        const WRITE_FLAGS: u64 = 0o1 | 0o2 | 0o100 | 0o1000 | 0o2000;
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
                match std::fs::copy(&lower, &upper_clone) {
                    Ok(_) => {
                        // Preserve permissions
                        if let Ok(meta) = lower.metadata() {
                            let _ = std::fs::set_permissions(&upper_clone, meta.permissions());
                        }
                        Ok(())
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        // Can't read the lower file — create empty fallback
                        std::fs::File::create(&upper_clone).map(|_| ())
                    }
                    Err(e) => Err(e),
                }
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
    let c_path = match std::ffi::CString::new(real_path.to_str().unwrap_or("")) {
        Ok(c) => c,
        Err(_) => return NotifAction::Continue,
    };
    let fd = unsafe { libc::open(c_path.as_ptr(), flags as i32, 0o666) };
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

/// Handle write-type syscalls: unlinkat, mkdirat, renameat2, symlinkat, linkat,
/// fchmodat, fchownat, utimensat, truncate.
pub(crate) async fn handle_cow_write(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    // Read the path from child memory based on syscall
    macro_rules! try_cow {
        ($cow:expr, $call:expr) => {
            match $call {
                Ok(true) => return NotifAction::ReturnValue(0),
                Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                _ => {}
            }
        };
    }

    if nr == libc::SYS_unlinkat {
        // unlinkat(dirfd, pathname, flags): args[0]=dirfd, args[1]=path, args[2]=flags
        let dirfd = notif.data.args[0] as i64;
        let path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => resolve_at_path(notif, dirfd, &p),
            None => return NotifAction::Continue,
        };
        let is_dir = (notif.data.args[2] & libc::AT_REMOVEDIR as u64) != 0;
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&path) && cow.handle_unlink(&path, is_dir) {
                return NotifAction::ReturnValue(0);
            }
        }
    } else if nr == libc::SYS_mkdirat {
        // mkdirat(dirfd, pathname, mode)
        let dirfd = notif.data.args[0] as i64;
        let path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => resolve_at_path(notif, dirfd, &p),
            None => return NotifAction::Continue,
        };
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&path) {
                try_cow!(cow, cow.handle_mkdir(&path));
            }
        }
    } else if nr == libc::SYS_renameat2 {
        // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        let old_dirfd = notif.data.args[0] as i64;
        let new_dirfd = notif.data.args[2] as i64;
        let old_path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => resolve_at_path(notif, old_dirfd, &p),
            None => return NotifAction::Continue,
        };
        let new_path = match read_path(notif, notif.data.args[3], notif_fd) {
            Some(p) => resolve_at_path(notif, new_dirfd, &p),
            None => return NotifAction::Continue,
        };
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&old_path) {
                try_cow!(cow, cow.handle_rename(&old_path, &new_path));
            }
        }
    } else if nr == libc::SYS_symlinkat {
        // symlinkat(target, newdirfd, linkpath)
        let target = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let dirfd = notif.data.args[1] as i64;
        let linkpath = match read_path(notif, notif.data.args[2], notif_fd) {
            Some(p) => resolve_at_path(notif, dirfd, &p),
            None => return NotifAction::Continue,
        };
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&linkpath) {
                try_cow!(cow, cow.handle_symlink(&target, &linkpath));
            }
        }
    } else if nr == libc::SYS_linkat {
        // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        let old_dirfd = notif.data.args[0] as i64;
        let new_dirfd = notif.data.args[2] as i64;
        let old_path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => resolve_at_path(notif, old_dirfd, &p),
            None => return NotifAction::Continue,
        };
        let new_path = match read_path(notif, notif.data.args[3], notif_fd) {
            Some(p) => resolve_at_path(notif, new_dirfd, &p),
            None => return NotifAction::Continue,
        };
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&new_path) {
                try_cow!(cow, cow.handle_link(&old_path, &new_path));
            }
        }
    } else if nr == libc::SYS_fchmodat {
        // fchmodat(dirfd, pathname, mode, flags)
        let dirfd = notif.data.args[0] as i64;
        let path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => resolve_at_path(notif, dirfd, &p),
            None => return NotifAction::Continue,
        };
        let mode = (notif.data.args[2] & 0o7777) as u32;
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&path) {
                try_cow!(cow, cow.handle_chmod(&path, mode));
            }
        }
    } else if nr == libc::SYS_fchownat {
        // fchownat(dirfd, pathname, uid, gid, flags)
        let dirfd = notif.data.args[0] as i64;
        let path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => resolve_at_path(notif, dirfd, &p),
            None => return NotifAction::Continue,
        };
        let uid = notif.data.args[2] as u32;
        let gid = notif.data.args[3] as u32;
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&path) {
                try_cow!(cow, cow.handle_chown(&path, uid, gid));
            }
        }
    } else if nr == libc::SYS_truncate {
        // truncate(path, length): args[0]=path, args[1]=length
        let path = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let length = notif.data.args[1] as i64;
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&path) {
                try_cow!(cow, cow.handle_truncate(&path, length));
            }
        }
    }

    NotifAction::Continue
}

// ============================================================
// Legacy write syscall handlers (chmod, unlink, mkdir, etc.)
// ============================================================

/// Handle legacy write syscalls where the path is in args[0] instead of args[1].
/// These are used by some libc implementations instead of the *at variants.
pub(crate) async fn handle_cow_legacy_write(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    macro_rules! try_cow {
        ($cow:expr, $call:expr) => {
            match $call {
                Ok(true) => return NotifAction::ReturnValue(0),
                Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                _ => {}
            }
        };
    }

    if nr == libc::SYS_unlink as i64 {
        // unlink(pathname): args[0]=path
        let path = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&path) && cow.handle_unlink(&path, false) {
                return NotifAction::ReturnValue(0);
            }
        }
    } else if nr == libc::SYS_rmdir as i64 {
        // rmdir(pathname): args[0]=path
        let path = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&path) && cow.handle_unlink(&path, true) {
                return NotifAction::ReturnValue(0);
            }
        }
    } else if nr == libc::SYS_mkdir as i64 {
        // mkdir(pathname, mode): args[0]=path
        let path = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&path) {
                try_cow!(cow, cow.handle_mkdir(&path));
            }
        }
    } else if nr == libc::SYS_rename as i64 {
        // rename(oldpath, newpath): args[0]=old, args[1]=new
        let old_path = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let new_path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&old_path) {
                try_cow!(cow, cow.handle_rename(&old_path, &new_path));
            }
        }
    } else if nr == libc::SYS_symlink as i64 {
        // symlink(target, linkpath): args[0]=target, args[1]=linkpath
        let target = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let linkpath = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&linkpath) {
                try_cow!(cow, cow.handle_symlink(&target, &linkpath));
            }
        }
    } else if nr == libc::SYS_link as i64 {
        // link(oldpath, newpath): args[0]=old, args[1]=new
        let old_path = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let new_path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&new_path) {
                try_cow!(cow, cow.handle_link(&old_path, &new_path));
            }
        }
    } else if nr == libc::SYS_chmod as i64 {
        // chmod(pathname, mode): args[0]=path, args[1]=mode
        let path = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let mode = (notif.data.args[1] & 0o7777) as u32;
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&path) {
                try_cow!(cow, cow.handle_chmod(&path, mode));
            }
        }
    } else if nr == libc::SYS_chown as i64 || nr == libc::SYS_lchown as i64 {
        // chown(pathname, uid, gid): args[0]=path, args[1]=uid, args[2]=gid
        let path = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let uid = notif.data.args[1] as u32;
        let gid = notif.data.args[2] as u32;
        let mut st = cow_state.lock().await;
        if let Some(cow) = st.branch.as_mut() {
            if cow.matches(&path) {
                try_cow!(cow, cow.handle_chown(&path, uid, gid));
            }
        }
    }

    NotifAction::Continue
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
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    // access(pathname, mode): args[0]=path, args[1]=mode
    // faccessat(dirfd, pathname, mode, flags): args[0]=dirfd, args[1]=path, args[2]=mode
    let (path, mode) = if nr == libc::SYS_access as i64 {
        let p = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        (p, notif.data.args[1] as i32)
    } else {
        let dirfd = notif.data.args[0] as i64;
        let p = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => resolve_at_path(notif, dirfd, &p),
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

    if !cow.matches(&path) {
        return NotifAction::Continue;
    }

    // Path is under workdir and W_OK was requested — writes will be
    // redirected to the COW upper layer, so report success.
    // Check the path actually exists on the real filesystem.
    if std::path::Path::new(&path).exists() {
        return NotifAction::ReturnValue(0);
    }

    NotifAction::Continue
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
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    // newfstatat(dirfd, pathname, statbuf, flags)
    // faccessat(dirfd, pathname, mode, flags)
    let dirfd = notif.data.args[0] as i64;
    let path = match read_path(notif, notif.data.args[1], notif_fd) {
        Some(p) => resolve_at_path(notif, dirfd, &p),
        None => return NotifAction::Continue,
    };

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

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

    // newfstatat — stat the resolved path and write to child's buffer
    let statbuf_addr = notif.data.args[2];
    let flags = notif.data.args[3];
    let follow = (flags & libc::AT_SYMLINK_NOFOLLOW as u64) == 0;

    let meta = if follow {
        std::fs::metadata(&real_path)
    } else {
        std::fs::symlink_metadata(&real_path)
    };

    let meta = match meta {
        Ok(m) => m,
        Err(_) => return NotifAction::Errno(libc::ENOENT),
    };

    // Pack struct stat (x86_64 layout, 144 bytes)
    use std::os::unix::fs::MetadataExt;
    let mut buf = vec![0u8; 144];
    // struct stat { st_dev(8), st_ino(8), st_nlink(8), st_mode(4), st_uid(4), st_gid(4), __pad0(4),
    //              st_rdev(8), st_size(8), st_blksize(8), st_blocks(8),
    //              st_atime(8), st_atime_nsec(8), st_mtime(8), st_mtime_nsec(8),
    //              st_ctime(8), st_ctime_nsec(8), __unused[3](24) }
    let mut off = 0;
    macro_rules! pack_u64 { ($v:expr) => { buf[off..off+8].copy_from_slice(&($v as u64).to_ne_bytes()); off += 8; } }
    macro_rules! pack_u32 { ($v:expr) => { buf[off..off+4].copy_from_slice(&($v as u32).to_ne_bytes()); off += 4; } }
    pack_u64!(meta.dev());
    pack_u64!(meta.ino());
    pack_u64!(meta.nlink());
    pack_u32!(meta.mode());
    pack_u32!(meta.uid());
    pack_u32!(meta.gid());
    pack_u32!(0u32); // __pad0
    pack_u64!(meta.rdev());
    pack_u64!(meta.size() as u64);
    pack_u64!(meta.blksize());
    pack_u64!(meta.blocks() as u64);
    pack_u64!(meta.atime() as u64);
    pack_u64!(meta.atime_nsec() as u64);
    pack_u64!(meta.mtime() as u64);
    pack_u64!(meta.mtime_nsec() as u64);
    pack_u64!(meta.ctime() as u64);
    pack_u64!(meta.ctime_nsec() as u64);
    let _ = off;

    if write_child_mem(notif_fd, notif.id, notif.pid, statbuf_addr, &buf).is_err() {
        return NotifAction::Continue;
    }

    NotifAction::ReturnValue(0)
}

/// Handle statx — resolve path then let kernel handle (complex struct).
pub(crate) async fn handle_cow_statx(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
) -> NotifAction {
    // statx(dirfd, pathname, flags, mask, statxbuf)
    let dirfd = notif.data.args[0] as i64;
    let path = match read_path(notif, notif.data.args[1], notif_fd) {
        Some(p) => resolve_at_path(notif, dirfd, &p),
        None => return NotifAction::Continue,
    };

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

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
    notif_fd: RawFd,
) -> NotifAction {
    // readlinkat(dirfd, pathname, buf, bufsiz)
    let dirfd = notif.data.args[0] as i64;
    let path = match read_path(notif, notif.data.args[1], notif_fd) {
        Some(p) => resolve_at_path(notif, dirfd, &p),
        None => return NotifAction::Continue,
    };
    let buf_addr = notif.data.args[2];
    let bufsiz = (notif.data.args[3] & 0xFFFFFFFF) as usize;

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

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
    notif_fd: RawFd,
) -> NotifAction {
    let pid = notif.pid;
    let child_fd = (notif.data.args[0] & 0xFFFFFFFF) as u32;
    let buf_addr = notif.data.args[1];
    let buf_size = (notif.data.args[2] & 0xFFFFFFFF) as usize;

    // Check if fd points to a COW-managed directory
    let link_path = format!("/proc/{}/fd/{}", pid, child_fd);
    let target = match std::fs::read_link(&link_path) {
        Ok(t) => t.to_string_lossy().into_owned(),
        Err(_) => return NotifAction::Continue,
    };

    let mut st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    if !cow.has_changes() || !cow.matches(&target) {
        return NotifAction::Continue;
    }

    // Build cache on first call; invalidate if fd was reused for a different dir.
    let cache_key = (pid as i32, child_fd);
    if let Some((cached_target, _)) = st.dir_cache.get(&cache_key) {
        if *cached_target != target {
            st.dir_cache.remove(&cache_key);
        }
    }
    if !st.dir_cache.contains_key(&cache_key) {
        let cow = st.branch.as_ref().unwrap();
        let workdir_str = cow.workdir_str();
        let rel_path = if target == workdir_str {
            ".".to_string()
        } else {
            target
                .strip_prefix(&format!("{}/", workdir_str))
                .unwrap_or(".")
                .to_string()
        };
        let merged = cow.list_merged_dir(&rel_path);

        let upper_dir = cow.upper_dir().join(&rel_path);
        let lower_dir = cow.workdir().join(&rel_path);

        let mut entries = Vec::new();
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
            entries.push(build_dirent64(d_ino, d_off, d_type, name));
        }
        st.dir_cache.insert(cache_key, (target.clone(), entries));
    }

    let entries = match st.dir_cache.get_mut(&cache_key) {
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
    if entries.is_empty() {
        st.dir_cache.remove(&cache_key);
    }
    drop(st);

    if !result.is_empty() {
        if write_child_mem(notif_fd, notif.id, pid, buf_addr, &result).is_err() {
            return NotifAction::Continue;
        }
    }

    NotifAction::ReturnValue(result.len() as i64)
}
