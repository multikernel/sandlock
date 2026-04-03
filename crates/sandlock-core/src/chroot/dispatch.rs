//! Seccomp notification handlers for chroot filesystem interception.
//!
//! Intercepts path-resolving syscalls, rewrites paths via the resolve module,
//! and performs on-behalf operations. Composes with COW when active.

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::chroot::resolve::{resolve_in_root, to_virtual_path};
use crate::procfs::{build_dirent64, DT_DIR, DT_LNK, DT_REG};
use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction, SupervisorState};
use crate::sys::structs::{SeccompNotif, SeccompNotifAddfd, SECCOMP_IOCTL_NOTIF_ADDFD};

// ============================================================
// Chroot policy context
// ============================================================

/// Bundled chroot policy passed to all handlers.
pub(crate) struct ChrootCtx<'a> {
    pub root: &'a Path,
    pub readable: &'a [PathBuf],
    pub writable: &'a [PathBuf],
}

impl ChrootCtx<'_> {
    /// Check if `virtual_path` is allowed for reading.
    /// Also allows access to ancestor directories of readable paths
    /// (e.g. "/" is allowed if "/usr" is readable, since you need to open "/"
    /// to list or traverse to "/usr").
    fn can_read(&self, virtual_path: &Path) -> bool {
        self.readable.is_empty()
            || self.readable.iter().any(|p| virtual_path.starts_with(p) || p.starts_with(virtual_path))
            || self.writable.iter().any(|p| virtual_path.starts_with(p) || p.starts_with(virtual_path))
    }

    /// Check if `virtual_path` is allowed for writing.
    fn can_write(&self, virtual_path: &Path) -> bool {
        self.writable.iter().any(|p| virtual_path.starts_with(p))
    }
}

// ============================================================
// Shared helpers
// ============================================================

/// Read a NUL-terminated path from child memory, page-by-page.
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

/// Resolve a child path to (host_path, virtual_path) within the chroot.
///
/// Uses `openat2(RESOLVE_IN_ROOT)` for kernel-based symlink resolution,
/// falling back to manual resolution on older kernels.
fn resolve_chroot_path(
    notif: &SeccompNotif,
    dirfd: i64,
    path: &str,
    chroot_root: &Path, // kept as bare Path for internal use
) -> Option<(PathBuf, PathBuf)> {
    let full_path = if Path::new(path).is_absolute() {
        path.to_string()
    } else {
        let dirfd32 = dirfd as i32;
        let base_host = if dirfd32 == libc::AT_FDCWD {
            std::fs::read_link(format!("/proc/{}/cwd", notif.pid)).ok()?
        } else {
            std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd)).ok()?
        };
        let base_virtual = to_virtual_path(chroot_root, &base_host)?;
        let combined = base_virtual.join(path);
        combined.to_string_lossy().to_string()
    };
    resolve_in_root(chroot_root, &full_path)
}

/// Convert a Path to CString, returning Errno on failure.
fn path_cstr(path: &Path, err: i32) -> Result<CString, NotifAction> {
    CString::new(path.to_str().unwrap_or("")).map_err(|_| NotifAction::Errno(err))
}

/// Get the errno from the last OS error, with a fallback.
fn last_errno(fallback: i32) -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(fallback)
}

/// Resolve host_path through COW (handle_stat), returning the real path.
/// Falls back to host_path if COW is inactive or doesn't match.
async fn cow_resolve(
    state: &Arc<Mutex<SupervisorState>>,
    host_path: &Path,
) -> Result<PathBuf, NotifAction> {
    let st = state.lock().await;
    if let Some(ref cow) = st.cow_branch {
        let host_str = host_path.to_string_lossy();
        if cow.matches(&host_str) {
            return cow
                .handle_stat(&host_str)
                .ok_or(NotifAction::Errno(libc::ENOENT));
        }
    }
    Ok(host_path.to_path_buf())
}

/// Open a host path in the supervisor, inject the fd into the child via
/// SECCOMP_ADDFD, then write `/proc/self/fd/N\0` to the child's path buffer.
/// Returns the action to send back (Continue on success, Errno on failure).
fn inject_fd_and_rewrite_path(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    host_path: &Path,
    path_ptr: u64,
    open_flags: i32,
    newfd_flags: u32,
) -> NotifAction {
    let c_path = match path_cstr(host_path, libc::ENOENT) {
        Ok(c) => c,
        Err(a) => return a,
    };
    let src_fd = unsafe { libc::open(c_path.as_ptr(), open_flags) };
    if src_fd < 0 {
        return NotifAction::Errno(last_errno(libc::ENOENT));
    }

    let addfd = SeccompNotifAddfd {
        id: notif.id,
        flags: 0,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags,
    };
    let child_fd = unsafe {
        libc::ioctl(
            notif_fd,
            SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong,
            &addfd as *const _,
        )
    };
    unsafe { libc::close(src_fd) };

    if child_fd < 0 {
        return NotifAction::Errno(libc::EIO);
    }

    let fd_path = format!("/proc/self/fd/{}\0", child_fd);
    if write_child_mem(notif_fd, notif.id, notif.pid, path_ptr, fd_path.as_bytes()).is_err() {
        return NotifAction::Errno(libc::EFAULT);
    }

    NotifAction::Continue
}

/// Read path arg at `arg_idx`, resolve chroot path using dirfd at `dirfd_idx`.
/// Returns (path_string, host_path) or an appropriate NotifAction.
/// Returns (path_string, host_path, virtual_path).
fn read_and_resolve(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    chroot_root: &Path, // kept as bare Path for internal use
    dirfd_idx: usize,
    path_idx: usize,
) -> Result<(String, PathBuf, PathBuf), NotifAction> {
    let path = read_path(notif, notif.data.args[path_idx], notif_fd)
        .ok_or(NotifAction::Continue)?;
    let dirfd = notif.data.args[dirfd_idx] as i64;
    let (host_path, virtual_path) =
        resolve_chroot_path(notif, dirfd, &path, chroot_root).ok_or(NotifAction::Errno(libc::EACCES))?;
    Ok((path, host_path, virtual_path))
}

/// Perform a libc syscall on a host path; return ReturnValue(0) or Errno.
fn exec_on_host(f: impl FnOnce(*const libc::c_char) -> libc::c_int, host: &Path) -> NotifAction {
    let c = match path_cstr(host, libc::EINVAL) {
        Ok(c) => c,
        Err(a) => return a,
    };
    if f(c.as_ptr()) < 0 {
        NotifAction::Errno(last_errno(libc::EIO))
    } else {
        NotifAction::ReturnValue(0)
    }
}

/// SYS_faccessat2 syscall number (439 on both x86_64 and aarch64).
pub(crate) const SYS_FACCESSAT2: i64 = 439;

// ============================================================
// openat handler
// ============================================================

pub(crate) async fn handle_chroot_open(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let dirfd = notif.data.args[0] as i64;
    let path_ptr = notif.data.args[1];
    let flags = notif.data.args[2];

    let rel_path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    let (host_path, virtual_path) = match resolve_chroot_path(notif, dirfd, &rel_path, ctx.root) {
        Some(r) => r,
        None => return NotifAction::Errno(libc::EACCES),
    };

    // Access check: writes need can_write, reads need can_read
    let is_write = (flags as i32 & (libc::O_WRONLY | libc::O_RDWR)) != 0;
    if is_write {
        if !ctx.can_write(&virtual_path) {
            return NotifAction::Errno(libc::EACCES);
        }
    } else if !ctx.can_read(&virtual_path) {
        return NotifAction::Errno(libc::EACCES);
    }

    // COW path
    {
        let mut st = state.lock().await;
        if let Some(cow) = st.cow_branch.as_mut() {
            let host_str = host_path.to_string_lossy();
            if cow.matches(&host_str) {
                let real_path = match cow.handle_open(&host_str, flags) {
                    Some(p) => p,
                    None => return NotifAction::Continue,
                };
                drop(st);
                let c_path = match path_cstr(&real_path, libc::EIO) {
                    Ok(c) => c,
                    Err(_) => return NotifAction::Continue,
                };
                let fd = unsafe { libc::open(c_path.as_ptr(), flags as i32, 0o666) };
                if fd < 0 {
                    return NotifAction::Continue;
                }
                return NotifAction::InjectFdSend { srcfd: fd };
            }
        }
    }

    let c_path = match path_cstr(&host_path, libc::EIO) {
        Ok(c) => c,
        Err(_) => return NotifAction::Continue,
    };
    let fd = unsafe { libc::open(c_path.as_ptr(), flags as i32, 0o666) };
    if fd < 0 {
        return NotifAction::Errno(last_errno(libc::EIO));
    }
    NotifAction::InjectFdSend { srcfd: fd }
}

// ============================================================
// execve/execveat handler
// ============================================================

pub(crate) async fn handle_chroot_exec(
    notif: &SeccompNotif,
    _state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let (dirfd, path_ptr) = if nr == libc::SYS_execveat {
        (notif.data.args[0] as i64, notif.data.args[1])
    } else {
        (libc::AT_FDCWD as i64, notif.data.args[0])
    };

    let rel_path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    let (host_path, _) = match resolve_chroot_path(notif, dirfd, &rel_path, ctx.root) {
        Some(r) => r,
        None => return NotifAction::Errno(libc::EACCES),
    };

    // Open the binary in the supervisor (no Landlock restrictions), inject the
    // fd into the child, and rewrite the path to /proc/self/fd/N.  This avoids
    // buffer overflow (the host path is typically much longer than the virtual
    // path) and lets the kernel load the ELF interpreter via the supervisor's
    // open fd rather than the child's restricted Landlock domain.
    inject_fd_and_rewrite_path(
        notif,
        notif_fd,
        &host_path,
        path_ptr,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0, // no O_CLOEXEC on the child fd — must survive exec
    )
}

// ============================================================
// Write operation handlers
// ============================================================

pub(crate) async fn handle_chroot_write(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    if nr == libc::SYS_unlinkat {
        let (_, host_path, vp) = match read_and_resolve(notif, notif_fd, ctx.root, 0, 1) {
            Ok(r) => r,
            Err(a) => return a,
        };
        if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }
        let is_dir = (notif.data.args[2] & libc::AT_REMOVEDIR as u64) != 0;

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = host_path.to_string_lossy();
                if cow.matches(&s) && cow.handle_unlink(&s, is_dir) {
                    return NotifAction::ReturnValue(0);
                }
            }
        }
        return exec_on_host(
            |p| if is_dir { unsafe { libc::rmdir(p) } } else { unsafe { libc::unlink(p) } },
            &host_path,
        );
    }

    if nr == libc::SYS_mkdirat {
        let (_, host_path, vp) = match read_and_resolve(notif, notif_fd, ctx.root, 0, 1) {
            Ok(r) => r,
            Err(a) => return a,
        };
        if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }
        let mode = notif.data.args[2] as u32;

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = host_path.to_string_lossy();
                if cow.matches(&s) && cow.handle_mkdir(&s) {
                    return NotifAction::ReturnValue(0);
                }
            }
        }
        return exec_on_host(|p| unsafe { libc::mkdir(p, mode) }, &host_path);
    }

    if nr == libc::SYS_renameat2 {
        let old_path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let new_path = match read_path(notif, notif.data.args[3], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let (old_host, old_vp) = match resolve_chroot_path(notif, notif.data.args[0] as i64, &old_path, ctx.root) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        let (new_host, new_vp) = match resolve_chroot_path(notif, notif.data.args[2] as i64, &new_path, ctx.root) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        if !ctx.can_write(&old_vp) || !ctx.can_write(&new_vp) {
            return NotifAction::Errno(libc::EACCES);
        }

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let old_str = old_host.to_string_lossy();
                if cow.matches(&old_str) && cow.handle_rename(&old_str, &new_host.to_string_lossy()) {
                    return NotifAction::ReturnValue(0);
                }
            }
        }

        let c_old = match path_cstr(&old_host, libc::EINVAL) { Ok(c) => c, Err(a) => return a };
        let c_new = match path_cstr(&new_host, libc::EINVAL) { Ok(c) => c, Err(a) => return a };
        return if unsafe { libc::rename(c_old.as_ptr(), c_new.as_ptr()) } < 0 {
            NotifAction::Errno(last_errno(libc::EIO))
        } else {
            NotifAction::ReturnValue(0)
        };
    }

    if nr == libc::SYS_symlinkat {
        // symlinkat(target, newdirfd, linkpath)
        let target = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let linkpath = match read_path(notif, notif.data.args[2], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let (host_link, link_vp) = match resolve_chroot_path(notif, notif.data.args[1] as i64, &linkpath, ctx.root) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        if !ctx.can_write(&link_vp) { return NotifAction::Errno(libc::EACCES); }

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = host_link.to_string_lossy();
                if cow.matches(&s) && cow.handle_symlink(&target, &s) {
                    return NotifAction::ReturnValue(0);
                }
            }
        }

        let c_target = match CString::new(target.as_str()) { Ok(c) => c, Err(_) => return NotifAction::Errno(libc::EINVAL) };
        let c_link = match path_cstr(&host_link, libc::EINVAL) { Ok(c) => c, Err(a) => return a };
        return if unsafe { libc::symlink(c_target.as_ptr(), c_link.as_ptr()) } < 0 {
            NotifAction::Errno(last_errno(libc::EIO))
        } else {
            NotifAction::ReturnValue(0)
        };
    }

    if nr == libc::SYS_linkat {
        // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        let old_path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let new_path = match read_path(notif, notif.data.args[3], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let (old_host, _) = match resolve_chroot_path(notif, notif.data.args[0] as i64, &old_path, ctx.root) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        let (new_host, new_vp) = match resolve_chroot_path(notif, notif.data.args[2] as i64, &new_path, ctx.root) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        if !ctx.can_write(&new_vp) { return NotifAction::Errno(libc::EACCES); }

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = new_host.to_string_lossy();
                if cow.matches(&s) && cow.handle_link(&old_host.to_string_lossy(), &s) {
                    return NotifAction::ReturnValue(0);
                }
            }
        }

        let c_old = match path_cstr(&old_host, libc::EINVAL) { Ok(c) => c, Err(a) => return a };
        let c_new = match path_cstr(&new_host, libc::EINVAL) { Ok(c) => c, Err(a) => return a };
        let flags = notif.data.args[4] as i32;
        return if unsafe { libc::linkat(libc::AT_FDCWD, c_old.as_ptr(), libc::AT_FDCWD, c_new.as_ptr(), flags) } < 0 {
            NotifAction::Errno(last_errno(libc::EIO))
        } else {
            NotifAction::ReturnValue(0)
        };
    }

    if nr == libc::SYS_fchmodat {
        let (_, host_path, vp) = match read_and_resolve(notif, notif_fd, ctx.root, 0, 1) {
            Ok(r) => r,
            Err(a) => return a,
        };
        if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }
        let mode = (notif.data.args[2] & 0o7777) as u32;

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = host_path.to_string_lossy();
                if cow.matches(&s) && cow.handle_chmod(&s, mode) {
                    return NotifAction::ReturnValue(0);
                }
            }
        }
        return exec_on_host(|p| unsafe { libc::chmod(p, mode) }, &host_path);
    }

    if nr == libc::SYS_fchownat {
        let (_, host_path, vp) = match read_and_resolve(notif, notif_fd, ctx.root, 0, 1) {
            Ok(r) => r,
            Err(a) => return a,
        };
        if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }
        let uid = notif.data.args[2] as u32;
        let gid = notif.data.args[3] as u32;

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = host_path.to_string_lossy();
                if cow.matches(&s) && cow.handle_chown(&s, uid, gid) {
                    return NotifAction::ReturnValue(0);
                }
            }
        }
        return exec_on_host(|p| unsafe { libc::chown(p, uid, gid) }, &host_path);
    }

    if nr == libc::SYS_truncate {
        let path = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let (host_path, _) = match resolve_chroot_path(notif, libc::AT_FDCWD as i64, &path, ctx.root) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        let length = notif.data.args[1] as i64;

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = host_path.to_string_lossy();
                if cow.matches(&s) && cow.handle_truncate(&s, length) {
                    return NotifAction::ReturnValue(0);
                }
            }
        }
        return exec_on_host(|p| unsafe { libc::truncate(p, length) }, &host_path);
    }

    NotifAction::Continue
}

// ============================================================
// stat/access handler
// ============================================================

/// Pack struct stat and write to child buffer.
fn stat_and_write(notif: &SeccompNotif, notif_fd: RawFd, path: &Path) -> NotifAction {
    let statbuf_addr = notif.data.args[2];
    let flags = notif.data.args[3];
    let follow = (flags & libc::AT_SYMLINK_NOFOLLOW as u64) == 0;

    let meta = if follow {
        std::fs::metadata(path)
    } else {
        std::fs::symlink_metadata(path)
    };
    let meta = match meta {
        Ok(m) => m,
        Err(_) => return NotifAction::Errno(libc::ENOENT),
    };

    use std::os::unix::fs::MetadataExt;
    let mut buf = vec![0u8; std::mem::size_of::<libc::stat>()];
    let mut off = 0;
    macro_rules! pack_u64 { ($v:expr) => { buf[off..off+8].copy_from_slice(&($v as u64).to_ne_bytes()); off += 8; }; }
    macro_rules! pack_u32 { ($v:expr) => { buf[off..off+4].copy_from_slice(&($v as u32).to_ne_bytes()); off += 4; }; }
    pack_u64!(meta.dev()); pack_u64!(meta.ino()); pack_u64!(meta.nlink());
    pack_u32!(meta.mode()); pack_u32!(meta.uid()); pack_u32!(meta.gid()); pack_u32!(0u32);
    pack_u64!(meta.rdev()); pack_u64!(meta.size() as u64);
    pack_u64!(meta.blksize()); pack_u64!(meta.blocks() as u64);
    pack_u64!(meta.atime() as u64); pack_u64!(meta.atime_nsec() as u64);
    pack_u64!(meta.mtime() as u64); pack_u64!(meta.mtime_nsec() as u64);
    pack_u64!(meta.ctime() as u64); pack_u64!(meta.ctime_nsec() as u64);
    let _ = off;

    if write_child_mem(notif_fd, notif.id, notif.pid, statbuf_addr, &buf).is_err() {
        return NotifAction::Continue;
    }
    NotifAction::ReturnValue(0)
}

pub(crate) async fn handle_chroot_stat(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let (_, host_path, vp) = match read_and_resolve(notif, notif_fd, ctx.root, 0, 1) {
        Ok(r) => r,
        Err(a) => return a,
    };
    if !ctx.can_read(&vp) { return NotifAction::Errno(libc::EACCES); }

    let real_path = match cow_resolve(state, &host_path).await {
        Ok(p) => p,
        Err(a) => return a,
    };

    if nr == libc::SYS_faccessat || nr == SYS_FACCESSAT2 {
        return if real_path.exists() || real_path.is_symlink() {
            NotifAction::ReturnValue(0)
        } else {
            NotifAction::Errno(libc::ENOENT)
        };
    }

    stat_and_write(notif, notif_fd, &real_path)
}

// ============================================================
// statx handler
// ============================================================

pub(crate) async fn handle_chroot_statx(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let dirfd = notif.data.args[0] as i64;
    let path_ptr = notif.data.args[1];
    let flags = notif.data.args[2] as i32;
    let mask = notif.data.args[3] as u32;
    let statxbuf_addr = notif.data.args[4];

    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    if path.is_empty() {
        return NotifAction::Continue;
    }

    let (host_path, vp) = match resolve_chroot_path(notif, dirfd, &path, ctx.root) {
        Some(r) => r,
        None => return NotifAction::Errno(libc::EACCES),
    };
    if !ctx.can_read(&vp) { return NotifAction::Errno(libc::EACCES); }

    let real_path = match cow_resolve(state, &host_path).await {
        Ok(p) => p,
        Err(a) => return a,
    };

    let c_path = match path_cstr(&real_path, libc::ENOENT) {
        Ok(c) => c,
        Err(a) => return a,
    };
    let mut stx_buf = vec![0u8; 256];
    let ret = unsafe {
        libc::syscall(libc::SYS_statx, libc::AT_FDCWD, c_path.as_ptr(), flags, mask, stx_buf.as_mut_ptr())
    };
    if ret < 0 {
        return NotifAction::Errno(last_errno(libc::ENOENT));
    }

    if write_child_mem(notif_fd, notif.id, notif.pid, statxbuf_addr, &stx_buf).is_err() {
        return NotifAction::Continue;
    }
    NotifAction::ReturnValue(0)
}

// ============================================================
// readlink handler
// ============================================================

pub(crate) async fn handle_chroot_readlink(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let dirfd = notif.data.args[0] as i64;
    let path = match read_path(notif, notif.data.args[1], notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    let buf_addr = notif.data.args[2];
    let bufsiz = (notif.data.args[3] & 0xFFFFFFFF) as usize;

    // Helper: write target bytes to child buffer
    let write_target = |target: &[u8]| -> NotifAction {
        let len = target.len().min(bufsiz);
        if write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, &target[..len]).is_err() {
            return NotifAction::Continue;
        }
        NotifAction::ReturnValue(len as i64)
    };

    // Special case: /proc/self/root -> "/"
    if path == "/proc/self/root" {
        return write_target(b"/");
    }

    // Special case: /proc/self/exe -> strip chroot prefix
    if path == "/proc/self/exe" {
        if let Ok(real_exe) = std::fs::read_link(format!("/proc/{}/exe", notif.pid)) {
            let virtual_exe = to_virtual_path(ctx.root, &real_exe).unwrap_or(real_exe);
            let s = virtual_exe.to_string_lossy();
            return write_target(s.as_bytes());
        }
        return NotifAction::Continue;
    }

    let (host_path, _) = match resolve_chroot_path(notif, dirfd, &path, ctx.root) {
        Some(r) => r,
        None => return NotifAction::Errno(libc::EACCES),
    };

    // COW
    {
        let st = state.lock().await;
        if let Some(cow) = st.cow_branch.as_ref() {
            let host_str = host_path.to_string_lossy();
            if cow.matches(&host_str) {
                let target = match cow.handle_readlink(&host_str) {
                    Some(t) => t,
                    None => return NotifAction::Errno(libc::ENOENT),
                };
                drop(st);
                return write_target(target.as_bytes());
            }
        }
    }

    let target = match std::fs::read_link(&host_path) {
        Ok(t) => t,
        Err(_) => return NotifAction::Errno(libc::ENOENT),
    };

    // Strip chroot prefix from absolute targets
    let display = if target.is_absolute() {
        to_virtual_path(ctx.root, &target).unwrap_or(target)
    } else {
        target
    };
    write_target(display.to_string_lossy().as_bytes())
}

// ============================================================
// getdents handler
// ============================================================

pub(crate) async fn handle_chroot_getdents(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let pid = notif.pid;
    let child_fd = (notif.data.args[0] & 0xFFFFFFFF) as u32;
    let buf_addr = notif.data.args[1];
    let buf_size = (notif.data.args[2] & 0xFFFFFFFF) as usize;

    let link_path = format!("/proc/{}/fd/{}", pid, child_fd);
    let target = match std::fs::read_link(&link_path) {
        Ok(t) => t,
        Err(_) => return NotifAction::Continue,
    };

    let host_dir = if to_virtual_path(ctx.root, &target).is_some() {
        target
    } else {
        return NotifAction::Continue;
    };

    // COW delegation
    {
        let st = state.lock().await;
        if let Some(cow) = st.cow_branch.as_ref() {
            if cow.matches(&host_dir.to_string_lossy()) {
                return NotifAction::Continue;
            }
        }
    }

    let cache_key = (pid as i32, child_fd);
    let mut st = state.lock().await;

    if !st.chroot_dir_cache.contains_key(&cache_key) {
        let dir = match std::fs::read_dir(&host_dir) {
            Ok(d) => d,
            Err(_) => return NotifAction::Errno(libc::ENOENT),
        };

        let mut entries = Vec::new();
        let mut d_off: i64 = 0;
        for entry in dir.flatten() {
            let name = entry.file_name();
            d_off += 1;
            let d_type = match entry.file_type() {
                Ok(ft) if ft.is_dir() => DT_DIR,
                Ok(ft) if ft.is_symlink() => DT_LNK,
                _ => DT_REG,
            };
            use std::os::unix::fs::MetadataExt;
            let d_ino = std::fs::symlink_metadata(entry.path())
                .map(|m| m.ino())
                .unwrap_or(0);
            entries.push(build_dirent64(d_ino, d_off, d_type, &name.to_string_lossy()));
        }
        st.chroot_dir_cache.insert(cache_key, entries);
    }

    let entries = match st.chroot_dir_cache.get_mut(&cache_key) {
        Some(e) => e,
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
    // Keep empty Vec as EOF sentinel — don't remove.
    drop(st);

    if !result.is_empty() {
        if write_child_mem(notif_fd, notif.id, pid, buf_addr, &result).is_err() {
            return NotifAction::Continue;
        }
    }
    NotifAction::ReturnValue(result.len() as i64)
}

// ============================================================
// chdir handler
// ============================================================

pub(crate) async fn handle_chroot_chdir(
    notif: &SeccompNotif,
    _state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let path_ptr = notif.data.args[0];
    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    let (host_path, _) = match resolve_chroot_path(notif, libc::AT_FDCWD as i64, &path, ctx.root) {
        Some(r) => r,
        None => return NotifAction::Errno(libc::EACCES),
    };

    if !host_path.is_dir() {
        return NotifAction::Errno(libc::ENOTDIR);
    }

    inject_fd_and_rewrite_path(
        notif,
        notif_fd,
        &host_path,
        path_ptr,
        libc::O_RDONLY | libc::O_DIRECTORY,
        libc::O_CLOEXEC as u32,
    )
}

// ============================================================
// getcwd handler
// ============================================================

pub(crate) async fn handle_chroot_getcwd(
    notif: &SeccompNotif,
    _state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let buf_addr = notif.data.args[0];
    let buf_size = (notif.data.args[1] & 0xFFFFFFFF) as usize;

    let cwd = match std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
        Ok(c) => c,
        Err(_) => return NotifAction::Continue,
    };

    let virtual_cwd = to_virtual_path(ctx.root, &cwd).unwrap_or_else(|| PathBuf::from("/"));
    let cwd_str = virtual_cwd.to_string_lossy();
    let cwd_bytes = cwd_str.as_bytes();

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

// ============================================================
// statfs handler
// ============================================================

pub(crate) async fn handle_chroot_statfs(
    notif: &SeccompNotif,
    _state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let path_ptr = notif.data.args[0];
    let statfsbuf_addr = notif.data.args[1];
    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    let (host_path, _) = match resolve_chroot_path(notif, libc::AT_FDCWD as i64, &path, ctx.root) {
        Some(r) => r,
        None => return NotifAction::Errno(libc::EACCES),
    };

    let c_path = match path_cstr(&host_path, libc::ENOENT) {
        Ok(c) => c,
        Err(a) => return a,
    };
    let mut statfs_buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut statfs_buf) } < 0 {
        return NotifAction::Errno(last_errno(libc::ENOENT));
    }

    let buf_bytes = unsafe {
        std::slice::from_raw_parts(
            &statfs_buf as *const libc::statfs as *const u8,
            std::mem::size_of::<libc::statfs>(),
        )
    };
    if write_child_mem(notif_fd, notif.id, notif.pid, statfsbuf_addr, buf_bytes).is_err() {
        return NotifAction::Continue;
    }
    NotifAction::ReturnValue(0)
}

// ============================================================
// utimensat handler
// ============================================================

pub(crate) async fn handle_chroot_utimensat(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let dirfd = notif.data.args[0] as i64;
    let path_ptr = notif.data.args[1];
    let times_ptr = notif.data.args[2];
    let flags = notif.data.args[3] as i32;

    if path_ptr == 0 {
        return NotifAction::Continue;
    }

    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    let (host_path, vp) = match resolve_chroot_path(notif, dirfd, &path, ctx.root) {
        Some(r) => r,
        None => return NotifAction::Errno(libc::EACCES),
    };
    if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }

    let real_path = match cow_resolve(state, &host_path).await {
        Ok(p) => p,
        Err(a) => return a,
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

    let c_path = match path_cstr(&real_path, libc::ENOENT) {
        Ok(c) => c,
        Err(a) => return a,
    };
    let times_raw = times.as_ref().map(|t| t.as_ptr()).unwrap_or(std::ptr::null());
    if unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times_raw, flags) } < 0 {
        return NotifAction::Errno(last_errno(libc::EIO));
    }
    NotifAction::ReturnValue(0)
}
