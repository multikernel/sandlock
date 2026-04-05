//! Seccomp notification handlers for chroot filesystem interception.
//!
//! Intercepts path-resolving syscalls, rewrites paths via the resolve module,
//! and performs on-behalf operations. Composes with COW when active.

use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::chroot::resolve::{confine, openat2_in_root, resolve_existing_in_root, resolve_in_root, to_virtual_path};
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
    pub denied: &'a [PathBuf],
    pub mounts: &'a [(PathBuf, PathBuf)],
}

impl ChrootCtx<'_> {
    fn is_denied(&self, virtual_path: &Path) -> bool {
        self.denied.iter().any(|p| virtual_path.starts_with(p))
    }

    /// Check if `virtual_path` is allowed for reading.
    /// Also allows access to ancestor directories of readable paths
    /// (e.g. "/" is allowed if "/usr" is readable, since you need to open "/"
    /// to list or traverse to "/usr").
    fn can_read(&self, virtual_path: &Path) -> bool {
        if self.is_denied(virtual_path) {
            return false;
        }
        if self.is_mounted(virtual_path) {
            return true;
        }
        self.readable.is_empty()
            || self.readable.iter().any(|p| virtual_path.starts_with(p) || p.starts_with(virtual_path))
            || self.writable.iter().any(|p| virtual_path.starts_with(p) || p.starts_with(virtual_path))
    }

    /// Check if `virtual_path` is allowed for writing.
    fn can_write(&self, virtual_path: &Path) -> bool {
        if self.is_denied(virtual_path) {
            return false;
        }
        if self.is_mounted(virtual_path) {
            return true;
        }
        self.writable.iter().any(|p| virtual_path.starts_with(p))
    }

    /// Check if a virtual path falls under any mount point.
    fn is_mounted(&self, virtual_path: &Path) -> bool {
        self.mounts.iter().any(|(vp, _)| virtual_path.starts_with(vp))
    }

    /// Return (mount_target_dir, sub_path_string) for a virtual path under a mount.
    /// Uses longest-prefix matching when multiple mounts could match.
    fn mount_target(&self, virtual_path: &Path) -> Option<(&Path, String)> {
        let mut best: Option<(&Path, &Path)> = None;
        for (vp, hp) in self.mounts {
            if virtual_path.starts_with(vp) {
                if best.is_none() || vp.as_os_str().len() > best.unwrap().0.as_os_str().len() {
                    best = Some((vp.as_path(), hp.as_path()));
                }
            }
        }
        let (mount_vp, mount_hp) = best?;
        let sub = virtual_path.strip_prefix(mount_vp).ok()?;
        let sub_str = if sub.as_os_str().is_empty() {
            "/".to_string()
        } else {
            format!("/{}", sub.to_string_lossy())
        };
        Some((mount_hp, sub_str))
    }

    /// Resolve a virtual path against mounts for paths that may not exist yet (O_CREAT).
    /// Returns (host_path, virtual_path).
    fn resolve_mount(&self, virtual_path: &str) -> Option<(PathBuf, PathBuf)> {
        let confined = confine(virtual_path);
        let (mount_target, sub_path) = self.mount_target(&confined)?;
        if let Some(result) = resolve_in_root(mount_target, &sub_path) {
            let vp = confined;
            return Some((result.0, vp));
        }
        None
    }

    /// Resolve a virtual path against mounts for paths that must exist.
    /// Returns (host_path, virtual_path).
    fn resolve_mount_existing(&self, virtual_path: &str) -> Option<(PathBuf, PathBuf)> {
        let confined = confine(virtual_path);
        let (mount_target, sub_path) = self.mount_target(&confined)?;
        if let Some(result) = resolve_existing_in_root(mount_target, &sub_path) {
            let vp = confined;
            return Some((result.0, vp));
        }
        None
    }

    /// Inverse: given a host path, return the virtual path.
    /// Checks mount targets first, then falls back to chroot root.
    fn host_to_virtual(&self, host_path: &Path) -> Option<PathBuf> {
        // Check mounts first (longest prefix match)
        let mut best: Option<(&Path, &Path, usize)> = None;
        for (vp, hp) in self.mounts {
            if host_path.starts_with(hp) {
                let len = hp.as_os_str().len();
                if best.is_none() || len > best.unwrap().2 {
                    best = Some((vp.as_path(), hp.as_path(), len));
                }
            }
        }
        if let Some((mount_vp, mount_hp, _)) = best {
            let rel = host_path.strip_prefix(mount_hp).ok()?;
            return Some(mount_vp.join(rel));
        }
        // Fall back to chroot root
        to_virtual_path(self.root, host_path)
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

/// Build the full virtual path from dirfd + relative path.
fn build_virtual_path(
    notif: &SeccompNotif,
    dirfd: i64,
    path: &str,
    ctx: &ChrootCtx<'_>,
) -> Option<String> {
    if Path::new(path).is_absolute() {
        Some(path.to_string())
    } else {
        let dirfd32 = dirfd as i32;
        let base_host = if dirfd32 == libc::AT_FDCWD {
            std::fs::read_link(format!("/proc/{}/cwd", notif.pid)).ok()?
        } else {
            std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd)).ok()?
        };
        let base_virtual = ctx.host_to_virtual(&base_host)?;
        let combined = base_virtual.join(path);
        Some(combined.to_string_lossy().to_string())
    }
}

/// Resolve a child path to (host_path, virtual_path) within the chroot.
///
/// Falls back to parent resolution for paths whose final component does not
/// yet exist (needed for O_CREAT targets).
/// Checks mounts first — if the virtual path falls under a mount point,
/// resolution is confined to the mount target directory.
fn resolve_chroot_path(
    notif: &SeccompNotif,
    dirfd: i64,
    path: &str,
    ctx: &ChrootCtx<'_>,
) -> Option<(PathBuf, PathBuf)> {
    let full_path = build_virtual_path(notif, dirfd, path, ctx)?;
    if let Some(result) = ctx.resolve_mount(&full_path) {
        return Some(result);
    }
    resolve_in_root(ctx.root, &full_path)
}

/// Resolve a child path that must already exist within the chroot.
///
/// Unlike [`resolve_chroot_path`], this does NOT fall back to parent
/// resolution, so the returned host path is always fully resolved by the
/// kernel — no unresolved symlinks that could escape the chroot.
/// Checks mounts first.
fn resolve_chroot_path_existing(
    notif: &SeccompNotif,
    dirfd: i64,
    path: &str,
    ctx: &ChrootCtx<'_>,
) -> Option<(PathBuf, PathBuf)> {
    let full_path = build_virtual_path(notif, dirfd, path, ctx)?;
    if let Some(result) = ctx.resolve_mount_existing(&full_path) {
        return Some(result);
    }
    resolve_existing_in_root(ctx.root, &full_path)
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

/// Read path arg at `arg_idx`, resolve chroot path using dirfd at `dirfd_idx`.
/// Falls back to parent resolution for O_CREAT targets.
/// Returns (path_string, host_path, virtual_path).
fn read_and_resolve(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
    dirfd_idx: usize,
    path_idx: usize,
) -> Result<(String, PathBuf, PathBuf), NotifAction> {
    let path = read_path(notif, notif.data.args[path_idx], notif_fd)
        .ok_or(NotifAction::Continue)?;
    let dirfd = notif.data.args[dirfd_idx] as i64;
    let (host_path, virtual_path) =
        resolve_chroot_path(notif, dirfd, &path, ctx).ok_or(NotifAction::Errno(libc::EACCES))?;
    Ok((path, host_path, virtual_path))
}

/// Like [`read_and_resolve`] but requires the path to already exist.
/// Returns a fully kernel-resolved host path with no unresolved symlinks.
fn read_and_resolve_existing(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
    dirfd_idx: usize,
    path_idx: usize,
) -> Result<(String, PathBuf, PathBuf), NotifAction> {
    let path = read_path(notif, notif.data.args[path_idx], notif_fd)
        .ok_or(NotifAction::Continue)?;
    let dirfd = notif.data.args[dirfd_idx] as i64;
    let (host_path, virtual_path) =
        resolve_chroot_path_existing(notif, dirfd, &path, ctx)
            .ok_or(NotifAction::Errno(libc::ENOENT))?;
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

    // Resolve to get the virtual path for access control.
    let (host_path, virtual_path) = match resolve_chroot_path(notif, dirfd, &rel_path, ctx) {
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

    // COW path — COW operates on host paths, must use libc::open.
    {
        let mut st = state.lock().await;
        if let Some(cow) = st.cow_branch.as_mut() {
            let host_str = host_path.to_string_lossy();
            if cow.matches(&host_str) {
                match cow.handle_open(&host_str, flags) {
                    Ok(Some(real_path)) => {
                        drop(st);
                        let c_path = match path_cstr(&real_path, libc::EINVAL) {
                            Ok(c) => c,
                            Err(a) => return a,
                        };
                        let fd = unsafe { libc::open(c_path.as_ptr(), flags as i32, 0o666) };
                        if fd < 0 {
                            return NotifAction::Errno(last_errno(libc::EIO));
                        }
                        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
                        return NotifAction::InjectFdSend { srcfd: owned };
                    }
                    Ok(None) => {
                        // Fall through to openat2_in_root below. This keeps
                        // directory opens and other non-COW cases confined to
                        // the chroot instead of executing the original host
                        // syscall.
                    }
                    Err(crate::error::BranchError::QuotaExceeded) => {
                        return NotifAction::Errno(libc::ENOSPC);
                    }
                    Err(_) => return NotifAction::Errno(libc::EIO),
                }
            }
        }
    }

    // Open directly via openat2(RESOLVE_IN_ROOT) — single atomic open
    // confined to the chroot root (or mount target), no resolve-then-reopen TOCTOU gap.
    let vp_str = virtual_path.to_string_lossy();
    let mode = if is_write { 0o666 } else { 0 };
    let (resolve_root, resolve_path) = if let Some((mt, sub)) = ctx.mount_target(&virtual_path) {
        (mt.to_path_buf(), sub)
    } else {
        (ctx.root.to_path_buf(), vp_str.to_string())
    };
    let fd = match openat2_in_root(&resolve_root, &resolve_path, flags as i32, mode) {
        Ok(fd) => fd,
        Err(errno) => return NotifAction::Errno(errno),
    };
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    NotifAction::InjectFdSend { srcfd: owned }
}

// ============================================================
// ELF PT_INTERP helpers
// ============================================================

/// Read PT_INTERP from an ELF binary fd. Returns the interpreter path and its
/// file offset + length so we can patch it in a memfd copy.
fn read_pt_interp(fd: RawFd) -> Option<(String, u64, usize)> {
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut header = [0u8; 64]; // ELF64 header is 64 bytes
    if file.read_exact(&mut header).is_err() {
        std::mem::forget(file); // don't close the fd
        return None;
    }

    // Verify ELF magic
    if &header[..4] != b"\x7fELF" {
        std::mem::forget(file);
        return None;
    }

    // ELF64: e_phoff at offset 32 (8 bytes), e_phentsize at 54 (2 bytes), e_phnum at 56 (2 bytes)
    let e_phoff = u64::from_le_bytes(header[32..40].try_into().ok()?);
    let e_phentsize = u16::from_le_bytes(header[54..56].try_into().ok()?) as u64;
    let e_phnum = u16::from_le_bytes(header[56..58].try_into().ok()?) as usize;

    // Scan program headers for PT_INTERP (type 3)
    const PT_INTERP: u32 = 3;
    for i in 0..e_phnum {
        let ph_offset = e_phoff + (i as u64) * e_phentsize;
        let mut phdr = [0u8; 56]; // ELF64 Phdr is 56 bytes
        if file.seek(SeekFrom::Start(ph_offset)).is_err() {
            break;
        }
        if file.read_exact(&mut phdr).is_err() {
            break;
        }
        let p_type = u32::from_le_bytes(phdr[0..4].try_into().ok()?);
        if p_type != PT_INTERP {
            continue;
        }
        let p_offset = u64::from_le_bytes(phdr[8..16].try_into().ok()?);
        let p_filesz = u64::from_le_bytes(phdr[32..40].try_into().ok()?) as usize;
        if p_filesz == 0 || p_filesz > 256 {
            break;
        }

        // Read the interpreter path string
        let mut buf = vec![0u8; p_filesz];
        if file.seek(SeekFrom::Start(p_offset)).is_err() {
            break;
        }
        if file.read_exact(&mut buf).is_err() {
            break;
        }
        let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let interp = String::from_utf8_lossy(&buf[..nul]).to_string();

        std::mem::forget(file);
        return Some((interp, p_offset, p_filesz));
    }

    std::mem::forget(file);
    None
}

/// Create a memfd copy of `src_fd` with PT_INTERP patched to `new_interp`.
/// Uses sendfile for efficient kernel-to-kernel copy, then patches the
/// interpreter path in place.
fn memfd_with_patched_interp(
    src_fd: RawFd,
    new_interp: &str,
    interp_offset: u64,
    interp_capacity: usize,
) -> Option<OwnedFd> {
    // Get file size
    let size = {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(src_fd, &mut stat) } < 0 {
            return None;
        }
        stat.st_size as usize
    };

    // Create memfd
    let memfd = crate::sys::syscall::memfd_create("sandlock-exec", 0).ok()?;
    let mfd = memfd.as_raw_fd();

    // Set size
    if unsafe { libc::ftruncate(mfd, size as libc::off_t) } < 0 {
        return None;
    }

    // sendfile: kernel-to-kernel copy, no userspace buffer
    let mut offset: libc::off_t = 0;
    let mut remaining = size;
    while remaining > 0 {
        let n = unsafe {
            libc::sendfile(mfd, src_fd, &mut offset, remaining)
        };
        if n <= 0 {
            return None;
        }
        remaining -= n as usize;
    }

    // Patch PT_INTERP in the memfd
    let new_bytes = new_interp.as_bytes();
    if new_bytes.len() >= interp_capacity {
        return None; // new path too long for the PT_INTERP field
    }
    let mut patch = vec![0u8; interp_capacity];
    patch[..new_bytes.len()].copy_from_slice(new_bytes);
    // NUL-fill the rest (already zeroed)

    let mut mfd_file = unsafe { std::fs::File::from_raw_fd(mfd) };
    if mfd_file.seek(SeekFrom::Start(interp_offset)).is_err() {
        std::mem::forget(mfd_file);
        return None;
    }
    if mfd_file.write_all(&patch).is_err() {
        std::mem::forget(mfd_file);
        return None;
    }
    std::mem::forget(mfd_file); // don't close — OwnedFd owns it

    Some(memfd)
}

// ============================================================
// execve/execveat handler
// ============================================================

pub(crate) async fn handle_chroot_exec(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
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

    // Build the full virtual path from dirfd + relative path.
    let full_path = if Path::new(&rel_path).is_absolute() {
        rel_path
    } else {
        let dirfd32 = dirfd as i32;
        let base_host = if dirfd32 == libc::AT_FDCWD {
            match std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
                Ok(p) => p,
                Err(_) => return NotifAction::Errno(libc::EACCES),
            }
        } else {
            match std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd)) {
                Ok(p) => p,
                Err(_) => return NotifAction::Errno(libc::EACCES),
            }
        };
        match ctx.host_to_virtual(&base_host) {
            Some(base) => base.join(&rel_path).to_string_lossy().to_string(),
            None => return NotifAction::Errno(libc::EACCES),
        }
    };

    let virtual_path = crate::chroot::resolve::confine(&full_path);
    if !ctx.can_read(&virtual_path) {
        return NotifAction::Errno(libc::EACCES);
    }

    // Open the binary directly via openat2(RESOLVE_IN_ROOT). Single atomic
    // open confined to the chroot root (or mount target) — no resolve-then-reopen TOCTOU gap.
    let (exec_root, exec_path) = if let Some((mt, sub)) = ctx.mount_target(&virtual_path) {
        (mt.to_path_buf(), sub)
    } else {
        (ctx.root.to_path_buf(), virtual_path.to_string_lossy().to_string())
    };
    let src_fd = match openat2_in_root(
        &exec_root,
        &exec_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    ) {
        Ok(fd) => fd,
        Err(_) => return NotifAction::Errno(libc::ENOENT),
    };

    // Read PT_INTERP from the binary. If it has one, open the image's
    // interpreter and create a memfd copy with PT_INTERP patched to
    // point at the injected interpreter fd. This ensures the kernel loads
    // the image's ld-linux (not the host's), avoiding glibc version
    // mismatches between ld.so and libc.so.
    let exec_fd = if let Some((interp_path, interp_offset, interp_cap)) = read_pt_interp(src_fd) {
        // Open the image's interpreter from the chroot root (intentionally
        // NOT mount-aware ��� the dynamic linker should come from the base
        // image, not from workspace mounts).
        let interp_src = match openat2_in_root(
            ctx.root,
            &interp_path,
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        ) {
            Ok(fd) => fd,
            Err(_) => {
                unsafe { libc::close(src_fd) };
                return NotifAction::Errno(libc::ENOENT);
            }
        };

        // Inject the interpreter fd into the child (must survive exec)
        let addfd_interp = SeccompNotifAddfd {
            id: notif.id,
            flags: 0,
            srcfd: interp_src as u32,
            newfd: 0,
            newfd_flags: 0,
        };
        let child_interp_fd = unsafe {
            libc::ioctl(
                notif_fd,
                SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong,
                &addfd_interp as *const _,
            )
        };
        unsafe { libc::close(interp_src) };

        if child_interp_fd < 0 {
            unsafe { libc::close(src_fd) };
            return NotifAction::Errno(libc::EIO);
        }

        // Create a memfd copy with PT_INTERP patched to /proc/self/fd/<interp_fd>
        let new_interp = format!("/proc/self/fd/{}", child_interp_fd);
        match memfd_with_patched_interp(src_fd, &new_interp, interp_offset, interp_cap) {
            Some(memfd) => {
                unsafe { libc::close(src_fd) };
                memfd
            }
            None => {
                // Patching failed (e.g., new path too long) — fall back to
                // original binary. Host ld-linux will be used; this is the
                // pre-existing behavior and may work if versions are compatible.
                unsafe { OwnedFd::from_raw_fd(src_fd) }
            }
        }
    } else {
        // Statically linked or not ELF — use the binary directly.
        unsafe { OwnedFd::from_raw_fd(src_fd) }
    };

    // Record the virtual exe path so /proc/self/exe queries return the
    // correct path (memfd-backed binaries would otherwise show the memfd path).
    {
        let mut st = state.lock().await;
        st.chroot_exe = Some(virtual_path.clone());
    }

    // Inject the (possibly patched) binary fd into the child and rewrite
    // the path to /proc/self/fd/N so the kernel loads it.
    let addfd = SeccompNotifAddfd {
        id: notif.id,
        flags: 0,
        srcfd: exec_fd.as_raw_fd() as u32,
        newfd: 0,
        newfd_flags: 0, // no O_CLOEXEC — must survive exec
    };
    let child_fd = unsafe {
        libc::ioctl(
            notif_fd,
            SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong,
            &addfd as *const _,
        )
    };
    drop(exec_fd);

    if child_fd < 0 {
        return NotifAction::Errno(libc::EIO);
    }

    let fd_path = format!("/proc/self/fd/{}\0", child_fd);
    if write_child_mem(notif_fd, notif.id, notif.pid, path_ptr, fd_path.as_bytes()).is_err() {
        return NotifAction::Errno(libc::EFAULT);
    }

    NotifAction::Continue
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
        let (_, host_path, vp) = match read_and_resolve(notif, notif_fd, ctx, 0, 1) {
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
        let (_, host_path, vp) = match read_and_resolve(notif, notif_fd, ctx, 0, 1) {
            Ok(r) => r,
            Err(a) => return a,
        };
        if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }
        let mode = notif.data.args[2] as u32;

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = host_path.to_string_lossy();
                if cow.matches(&s) {
                    match cow.handle_mkdir(&s) {
                        Ok(true) => return NotifAction::ReturnValue(0),
                        Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                        _ => {}
                    }
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
        let (old_host, old_vp) = match resolve_chroot_path(notif, notif.data.args[0] as i64, &old_path, ctx) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        let (new_host, new_vp) = match resolve_chroot_path(notif, notif.data.args[2] as i64, &new_path, ctx) {
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
                if cow.matches(&old_str) {
                    match cow.handle_rename(&old_str, &new_host.to_string_lossy()) {
                        Ok(true) => return NotifAction::ReturnValue(0),
                        Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                        _ => {}
                    }
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
        let (host_link, link_vp) = match resolve_chroot_path(notif, notif.data.args[1] as i64, &linkpath, ctx) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        if !ctx.can_write(&link_vp) { return NotifAction::Errno(libc::EACCES); }

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = host_link.to_string_lossy();
                if cow.matches(&s) {
                    match cow.handle_symlink(&target, &s) {
                        Ok(true) => return NotifAction::ReturnValue(0),
                        Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                        _ => {}
                    }
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
        let (old_host, _) = match resolve_chroot_path(notif, notif.data.args[0] as i64, &old_path, ctx) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        let (new_host, new_vp) = match resolve_chroot_path(notif, notif.data.args[2] as i64, &new_path, ctx) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        if !ctx.can_write(&new_vp) { return NotifAction::Errno(libc::EACCES); }

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = new_host.to_string_lossy();
                if cow.matches(&s) {
                    match cow.handle_link(&old_host.to_string_lossy(), &s) {
                        Ok(true) => return NotifAction::ReturnValue(0),
                        Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                        _ => {}
                    }
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
        let (_, host_path, vp) = match read_and_resolve(notif, notif_fd, ctx, 0, 1) {
            Ok(r) => r,
            Err(a) => return a,
        };
        if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }
        let mode = (notif.data.args[2] & 0o7777) as u32;

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = host_path.to_string_lossy();
                if cow.matches(&s) {
                    match cow.handle_chmod(&s, mode) {
                        Ok(true) => return NotifAction::ReturnValue(0),
                        Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                        _ => {}
                    }
                }
            }
        }
        return exec_on_host(|p| unsafe { libc::chmod(p, mode) }, &host_path);
    }

    if nr == libc::SYS_fchownat {
        let (_, host_path, vp) = match read_and_resolve(notif, notif_fd, ctx, 0, 1) {
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
                if cow.matches(&s) {
                    match cow.handle_chown(&s, uid, gid) {
                        Ok(true) => return NotifAction::ReturnValue(0),
                        Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                        _ => {}
                    }
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
        let (host_path, vp) = match resolve_chroot_path(notif, libc::AT_FDCWD as i64, &path, ctx) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }
        let length = notif.data.args[1] as i64;

        {
            let mut st = state.lock().await;
            if let Some(cow) = st.cow_branch.as_mut() {
                let s = host_path.to_string_lossy();
                if cow.matches(&s) {
                    match cow.handle_truncate(&s, length) {
                        Ok(true) => return NotifAction::ReturnValue(0),
                        Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                        _ => {}
                    }
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
    let flags = notif.data.args[3];

    // AT_EMPTY_PATH: fstat(fd, &statbuf) — the fd already points to the
    // correct file (injected by the chroot handler or inherited). Let the
    // kernel stat it directly.
    if (flags & libc::AT_EMPTY_PATH as u64) != 0 {
        return NotifAction::Continue;
    }

    let (_, host_path, vp) = match read_and_resolve_existing(notif, notif_fd, ctx, 0, 1) {
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

    // AT_EMPTY_PATH: stat the fd directly, no chroot path resolution needed.
    if (flags & libc::AT_EMPTY_PATH) != 0 {
        return NotifAction::Continue;
    }

    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) if !p.is_empty() => p,
        _ => return NotifAction::Continue,
    };

    let (host_path, vp) = match resolve_chroot_path_existing(notif, dirfd, &path, ctx) {
        Some(r) => r,
        None => return NotifAction::Errno(libc::ENOENT),
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

    // Special case: /proc/self/exe -> return the virtual path recorded during exec
    // (needed because memfd-backed binaries would show "/memfd:sandlock-exec" otherwise).
    if path == "/proc/self/exe" {
        let st = state.lock().await;
        if let Some(ref exe) = st.chroot_exe {
            let s = exe.to_string_lossy();
            return write_target(s.as_bytes());
        }
        drop(st);
        // Fallback: strip chroot prefix from /proc/{pid}/exe
        if let Ok(real_exe) = std::fs::read_link(format!("/proc/{}/exe", notif.pid)) {
            let virtual_exe = ctx.host_to_virtual(&real_exe).unwrap_or(real_exe);
            let s = virtual_exe.to_string_lossy();
            return write_target(s.as_bytes());
        }
        return NotifAction::Continue;
    }

    // Resolve the path WITHOUT following the final symlink.  readlink
    // must read the link itself, not its target.  We resolve the parent
    // directory (following intermediate symlinks) and append the filename.
    let full_path = if Path::new(&path).is_absolute() {
        path.clone()
    } else {
        let dirfd32 = dirfd as i32;
        let base_host = if dirfd32 == libc::AT_FDCWD {
            match std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
                Ok(p) => p,
                Err(_) => return NotifAction::Errno(libc::EACCES),
            }
        } else {
            match std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd)) {
                Ok(p) => p,
                Err(_) => return NotifAction::Errno(libc::EACCES),
            }
        };
        let base_virtual = match ctx.host_to_virtual(&base_host) {
            Some(p) => p,
            None => return NotifAction::Errno(libc::EACCES),
        };
        base_virtual.join(&path).to_string_lossy().to_string()
    };
    let confined = crate::chroot::resolve::confine(&full_path);
    let file_name = match confined.file_name() {
        Some(f) => f.to_os_string(),
        None => return NotifAction::Errno(libc::EINVAL),
    };
    let parent = confined.parent().unwrap_or(Path::new("/"));

    // Check mount first for parent resolution
    let parent_str = parent.to_str().unwrap_or("/");
    let parent_host = if let Some((mt, sub)) = ctx.mount_target(parent) {
        match resolve_in_root(mt, &sub) {
            Some((hp, _)) => hp,
            None => return NotifAction::Errno(libc::EACCES),
        }
    } else {
        match resolve_in_root(ctx.root, parent_str) {
            Some((hp, _)) => hp,
            None => return NotifAction::Errno(libc::EACCES),
        }
    };
    let host_path = parent_host.join(&file_name);

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

    // Strip chroot/mount prefix from absolute targets
    let display = if target.is_absolute() {
        ctx.host_to_virtual(&target).unwrap_or(target)
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

    let host_dir = if ctx.host_to_virtual(&target).is_some() {
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

    // Build the full virtual path from AT_FDCWD + path.
    let full_path = if Path::new(&path).is_absolute() {
        path
    } else {
        match std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
            Ok(cwd) => match ctx.host_to_virtual(&cwd) {
                Some(base) => base.join(&path).to_string_lossy().to_string(),
                None => return NotifAction::Errno(libc::EACCES),
            },
            Err(_) => return NotifAction::Errno(libc::EACCES),
        }
    };

    // Open directly via openat2(RESOLVE_IN_ROOT), routing to mount target if applicable.
    let confined = confine(&full_path);
    let (chdir_root, chdir_path) = if let Some((mt, sub)) = ctx.mount_target(&confined) {
        (mt.to_path_buf(), sub)
    } else {
        (ctx.root.to_path_buf(), full_path.clone())
    };
    let src_fd = match openat2_in_root(
        &chdir_root,
        &chdir_path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    ) {
        Ok(fd) => fd,
        Err(errno) => return NotifAction::Errno(errno),
    };

    // Inject fd into child and rewrite path to /proc/self/fd/N.
    let addfd = SeccompNotifAddfd {
        id: notif.id,
        flags: 0,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags: libc::O_CLOEXEC as u32,
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

    let virtual_cwd = ctx.host_to_virtual(&cwd).unwrap_or_else(|| PathBuf::from("/"));
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

    let (host_path, _) = match resolve_chroot_path_existing(notif, libc::AT_FDCWD as i64, &path, ctx) {
        Some(r) => r,
        None => return NotifAction::Errno(libc::ENOENT),
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

    let (host_path, vp) = match resolve_chroot_path(notif, dirfd, &path, ctx) {
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

// ============================================================
// Legacy (non-*at) syscall handlers for musl compatibility
// ============================================================
//
// musl libc uses the older stat/open/access/readlink syscalls instead
// of the *at variants.  These wrappers translate the argument layout
// and delegate to the existing *at handlers.

/// Build a synthetic SeccompNotif with modified args, preserving all other fields.
fn notif_with_args(notif: &SeccompNotif, args: [u64; 6]) -> SeccompNotif {
    let mut copy = *notif;
    copy.data.args = args;
    copy
}

/// SYS_open(path, flags, mode) → handle_chroot_open via openat(AT_FDCWD, path, flags, mode)
pub(crate) async fn handle_chroot_legacy_open(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    // open(path, flags, mode) → openat(AT_FDCWD, path, flags, mode)
    let synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // path
        notif.data.args[1], // flags
        notif.data.args[2], // mode
        0, 0,
    ]);
    handle_chroot_open(&synth, state, notif_fd, ctx).await
}

/// SYS_stat(path, statbuf) → handle_chroot_stat via newfstatat(AT_FDCWD, path, statbuf, 0)
pub(crate) async fn handle_chroot_legacy_stat(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // path
        notif.data.args[1], // statbuf
        0,                  // flags = 0 (follow symlinks)
        0, 0,
    ]);
    handle_chroot_stat(&synth, state, notif_fd, ctx).await
}

/// SYS_lstat(path, statbuf) → handle_chroot_stat via newfstatat(AT_FDCWD, path, statbuf, AT_SYMLINK_NOFOLLOW)
pub(crate) async fn handle_chroot_legacy_lstat(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // path
        notif.data.args[1], // statbuf
        libc::AT_SYMLINK_NOFOLLOW as u64,
        0, 0,
    ]);
    handle_chroot_stat(&synth, state, notif_fd, ctx).await
}

/// SYS_access(path, mode) → handle_chroot_stat via faccessat(AT_FDCWD, path, mode, 0)
pub(crate) async fn handle_chroot_legacy_access(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    // Synthesize as faccessat — reuse SYS_faccessat nr so the handler
    // recognises it as an access check.
    let mut synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // path
        0,                  // statbuf (unused for faccessat path)
        0,                  // flags
        0, 0,
    ]);
    synth.data.nr = libc::SYS_faccessat as i32;
    handle_chroot_stat(&synth, state, notif_fd, ctx).await
}

/// SYS_readlink(path, buf, bufsiz) → handle_chroot_readlink via readlinkat(AT_FDCWD, path, buf, bufsiz)
pub(crate) async fn handle_chroot_legacy_readlink(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // path
        notif.data.args[1], // buf
        notif.data.args[2], // bufsiz
        0, 0,
    ]);
    handle_chroot_readlink(&synth, state, notif_fd, ctx).await
}

/// SYS_unlink(path) → handle_chroot_write via unlinkat(AT_FDCWD, path, 0)
pub(crate) async fn handle_chroot_legacy_unlink(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let mut synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // path
        0,                  // flags
        0, 0, 0,
    ]);
    synth.data.nr = libc::SYS_unlinkat as i32;
    handle_chroot_write(&synth, state, notif_fd, ctx).await
}

/// SYS_rmdir(path) → handle_chroot_write via unlinkat(AT_FDCWD, path, AT_REMOVEDIR)
pub(crate) async fn handle_chroot_legacy_rmdir(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let mut synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // path
        libc::AT_REMOVEDIR as u64,
        0, 0, 0,
    ]);
    synth.data.nr = libc::SYS_unlinkat as i32;
    handle_chroot_write(&synth, state, notif_fd, ctx).await
}

/// SYS_mkdir(path, mode) → handle_chroot_write via mkdirat(AT_FDCWD, path, mode)
pub(crate) async fn handle_chroot_legacy_mkdir(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let mut synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // path
        notif.data.args[1], // mode
        0, 0, 0,
    ]);
    synth.data.nr = libc::SYS_mkdirat as i32;
    handle_chroot_write(&synth, state, notif_fd, ctx).await
}

/// SYS_rename(oldpath, newpath) → handle_chroot_write via renameat2(AT_FDCWD, old, AT_FDCWD, new, 0)
pub(crate) async fn handle_chroot_legacy_rename(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let mut synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // oldpath
        libc::AT_FDCWD as u64,
        notif.data.args[1], // newpath
        0, 0,
    ]);
    synth.data.nr = libc::SYS_renameat2 as i32;
    handle_chroot_write(&synth, state, notif_fd, ctx).await
}

/// SYS_symlink(target, linkpath) → handle_chroot_write via symlinkat(target, AT_FDCWD, linkpath)
pub(crate) async fn handle_chroot_legacy_symlink(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let mut synth = notif_with_args(notif, [
        notif.data.args[0], // target
        libc::AT_FDCWD as u64,
        notif.data.args[1], // linkpath
        0, 0, 0,
    ]);
    synth.data.nr = libc::SYS_symlinkat as i32;
    handle_chroot_write(&synth, state, notif_fd, ctx).await
}

/// SYS_link(oldpath, newpath) → handle_chroot_write via linkat(AT_FDCWD, old, AT_FDCWD, new, 0)
pub(crate) async fn handle_chroot_legacy_link(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let mut synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // oldpath
        libc::AT_FDCWD as u64,
        notif.data.args[1], // newpath
        0, 0,
    ]);
    synth.data.nr = libc::SYS_linkat as i32;
    handle_chroot_write(&synth, state, notif_fd, ctx).await
}

/// SYS_chmod(path, mode) → handle_chroot_write via fchmodat(AT_FDCWD, path, mode)
pub(crate) async fn handle_chroot_legacy_chmod(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let mut synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // path
        notif.data.args[1], // mode
        0, 0, 0,
    ]);
    synth.data.nr = libc::SYS_fchmodat as i32;
    handle_chroot_write(&synth, state, notif_fd, ctx).await
}

/// SYS_chown/lchown(path, uid, gid) → handle_chroot_write via fchownat(AT_FDCWD, path, uid, gid, flags)
pub(crate) async fn handle_chroot_legacy_chown(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
    nofollow: bool,
) -> NotifAction {
    let flags = if nofollow { libc::AT_SYMLINK_NOFOLLOW as u64 } else { 0 };
    let mut synth = notif_with_args(notif, [
        libc::AT_FDCWD as u64,
        notif.data.args[0], // path
        notif.data.args[1], // uid
        notif.data.args[2], // gid
        flags,
        0,
    ]);
    synth.data.nr = libc::SYS_fchownat as i32;
    handle_chroot_write(&synth, state, notif_fd, ctx).await
}
