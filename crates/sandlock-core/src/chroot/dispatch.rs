//! Seccomp notification handlers for chroot filesystem interception.
//!
//! Intercepts path-resolving syscalls, rewrites paths via the resolve module,
//! and performs on-behalf operations. Composes with COW when active.
//!
//! # Continue safety (issue #27)
//!
//! Per `seccomp_unotify(2)`, returning `Continue` lets the kernel re-read
//! user-memory pointers after the supervisor's decision, which is racy in a
//! multi-threaded child. The handlers in this module fall into four
//! categories:
//!
//! 1. **On-behalf with injected fd** (handle_chroot_open's primary path):
//!    the supervisor opens via `openat2(RESOLVE_IN_ROOT)` and returns
//!    `InjectFdSend` — the kernel does not re-read the path string at all.
//!    TOCTOU-safe.
//!
//! 2. **On-behalf result writes** (stat/statx/readlink/getcwd/statfs):
//!    the supervisor performs the underlying syscall against the
//!    chroot-resolved host path and writes the result into the child's
//!    output buffer. The decision returned is `ReturnValue`/`Errno`,
//!    not `Continue` — TOCTOU-safe.
//!
//! 3. **Soft fall-through on read failure**: many handlers `return
//!    Continue` if `read_path` or `write_child_mem` fails. The kernel's
//!    own re-read will fail the same way and the syscall surfaces an
//!    EFAULT/-style error to the child. No security decision was made
//!    on contents we couldn't read, so this is safe.
//!
//! 4. **Path-rewrite-then-Continue** (handle_chroot_exec): the supervisor
//!    rewrites `path_ptr` to `/proc/self/fd/N` and returns `Continue`
//!    because the kernel must run the syscall itself — execve replaces
//!    the address space. The TOCTOU window is real here: a racing sibling
//!    thread can substitute a different path string between our write and
//!    the kernel's read. The bound is Landlock, since a racing path is
//!    still subject to `landlock_restrict_self`.
//!
//! A `Continue` on a *healthy* path syscall would be a bug in this module,
//! not merely a race: the kernel resolves the path it is given against the
//! real root and the real cwd, so an absolute path would escape the virtual
//! root and a relative one would resolve against wherever exec left the
//! child. Since `handle_chroot_chdir` services chdir by recording the cwd
//! rather than moving the child's own (see there for why), that real cwd is
//! frozen for the process's whole life and diverges from the sandbox's view
//! the moment anything chdirs. Every `Continue` above is therefore either
//! fd-based, where no path is resolved at all (AT_EMPTY_PATH stat, getdents,
//! fchdir), or reached only after a fault that makes the kernel fail the
//! same syscall the same way. A new handler must keep to one of those two.

use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::chroot::resolve::{
    confine, resolve_existing_in_root, resolve_in_root, resolve_in_root_nofollow,
};
use crate::sys::fs::{openat2_in_root, openat2_in_root_with_resolve};
use crate::seccomp::notif::{decode_open_args, read_child_mem, write_child_mem, NotifAction, NotifPolicy};
use crate::seccomp::state::{ChrootState, CowState, ProcessIndex};
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
    /// Virtual paths of read-only mounts: reads allowed, writes denied.
    pub mount_ro: &'a [PathBuf],
    /// Per-process supervisor state, for handlers that track the caller's
    /// filesystem context rather than just resolving one path.
    pub processes: &'a Arc<ProcessIndex>,
}

impl<'a> ChrootCtx<'a> {
    /// Borrow the chroot half of a notification policy.
    ///
    /// Only ever called from handlers registered when `chroot_root` is set,
    /// which is what makes the unwrap sound.
    pub(crate) fn new(policy: &'a NotifPolicy, processes: &'a Arc<ProcessIndex>) -> Self {
        ChrootCtx {
            root: policy.chroot_root.as_ref().expect("chroot handlers are only registered with a chroot root"),
            readable: &policy.chroot_readable,
            writable: &policy.chroot_writable,
            denied: &policy.chroot_denied,
            mounts: &policy.chroot_mounts,
            mount_ro: &policy.chroot_mount_ro,
            processes,
        }
    }
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

    /// Check if a virtual path falls under a read-only mount.
    fn is_mount_ro(&self, virtual_path: &Path) -> bool {
        self.mount_ro.iter().any(|vp| virtual_path.starts_with(vp))
    }

    /// Check if `virtual_path` is allowed for writing.
    fn can_write(&self, virtual_path: &Path) -> bool {
        if self.is_denied(virtual_path) {
            return false;
        }
        // Read-only mounts deny writes even though they are mounted (and so
        // readable). Checked before the is_mounted allow so a read-only mount
        // (e.g. the host procfs) can't be made writable by a broad writable
        // prefix such as a read-write rootfs granting "/".
        if self.is_mount_ro(virtual_path) {
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

    /// Resolve a virtual path against mounts, using `resolver` for the part
    /// below the mount point. Returns (host_path, virtual_path); the virtual
    /// path is the confined form of what the child asked for, since that is
    /// what the policy check reads.
    fn resolve_mount_with(
        &self,
        virtual_path: &str,
        resolver: fn(&Path, &str) -> Option<(PathBuf, PathBuf)>,
    ) -> Option<(PathBuf, PathBuf)> {
        let confined = confine(virtual_path);
        let (mount_target, sub_path) = self.mount_target(&confined)?;
        resolver(mount_target, &sub_path).map(|(host, _)| (host, confined))
    }

    /// Resolve against mounts for paths that may not exist yet (O_CREAT).
    fn resolve_mount(&self, virtual_path: &str) -> Option<(PathBuf, PathBuf)> {
        self.resolve_mount_with(virtual_path, resolve_in_root)
    }

    /// Resolve against mounts for paths that must exist.
    fn resolve_mount_existing(&self, virtual_path: &str) -> Option<(PathBuf, PathBuf)> {
        self.resolve_mount_with(virtual_path, resolve_existing_in_root)
    }

    /// Resolve against mounts without following a final symlink.
    fn resolve_mount_nofollow(&self, virtual_path: &str) -> Option<(PathBuf, PathBuf)> {
        self.resolve_mount_with(virtual_path, resolve_in_root_nofollow)
    }

    /// Inverse: given a host path, return the virtual path.
    /// Checks mount targets first, then falls back to chroot root.
    fn host_to_virtual(&self, host_path: &Path) -> Option<PathBuf> {
        crate::chroot::resolve::host_to_virtual(self.root, self.mounts, host_path)
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

/// Rewrite the magic `/proc/self` and `/proc/thread-self` symlinks to the
/// caller's real PID.  Under chroot, `/proc` is serviced by an on-behalf
/// `openat2` in the *supervisor*, so the kernel would otherwise resolve `self`
/// to the supervisor instead of the workload — both wrong (every
/// `/proc/self/*` would reflect `sandlock-oci`) and a way to reach a non-sandbox
/// process the numeric per-PID filter never sees.  Rewriting to `/proc/<pid>`
/// (the workload PID seccomp reports) makes `self` resolve to the real caller
/// and re-subjects it to the per-PID check.
fn canon_proc_self(virtual_path: &str, pid: u32) -> String {
    for magic in ["/proc/self", "/proc/thread-self"] {
        if virtual_path == magic {
            return format!("/proc/{}", pid);
        }
        if let Some(rest) = virtual_path.strip_prefix(magic) {
            if rest.starts_with('/') {
                return format!("/proc/{}{}", pid, rest);
            }
        }
    }
    virtual_path.to_string()
}

/// The virtual cwd of the calling task.
///
/// The supervisor's own notion wins: since chdir is serviced without moving
/// the child's real cwd, `/proc/<pid>/cwd` still points wherever exec left
/// it. That kernel value is the right answer only for a task that has never
/// moved, which is exactly when nothing is tracked.
fn virtual_cwd_of(notif: &SeccompNotif, ctx: &ChrootCtx<'_>) -> Option<PathBuf> {
    if let Ok(pid) = i32::try_from(notif.pid) {
        if let Some(cwd) = ctx.processes.virtual_cwd(pid) {
            return Some(cwd);
        }
    }
    let host_cwd = std::fs::read_link(format!("/proc/{}/cwd", notif.pid)).ok()?;
    ctx.host_to_virtual(&host_cwd)
}

/// Record the calling task's new virtual cwd.
fn set_virtual_cwd(notif: &SeccompNotif, ctx: &ChrootCtx<'_>, cwd: PathBuf) {
    if let Ok(pid) = i32::try_from(notif.pid) {
        ctx.processes.set_virtual_cwd(pid, cwd);
    }
}

/// `RESOLVE_NO_MAGICLINKS`: refuse traversal through a /proc magic link.
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
/// `RESOLVE_NO_SYMLINKS`: refuse traversal through any symlink.
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

/// The subset of an `openat2` caller's `RESOLVE_*` request the supervisor can
/// reproduce when it services the open itself.
///
/// NO_SYMLINKS and NO_MAGICLINKS constrain the shape of the path, so they
/// hold whatever directory the walk starts from. RESOLVE_BENEATH, IN_ROOT and
/// NO_XDEV are all relative to the child's own starting dirfd, and the
/// supervisor walks from the sandbox root instead, so replaying them there
/// would refuse paths the child never asked to refuse. They are dropped, and
/// the sandbox's own RESOLVE_IN_ROOT is what bounds the walk in their place.
fn honorable_resolve_flags(resolve: u64) -> u64 {
    resolve & (RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)
}

/// Refuse an open whose `RESOLVE_*` request the path as written violates.
///
/// Resolution for the policy check deliberately follows symlinks to find the
/// file the child would reach, which would quietly satisfy a NO_SYMLINKS
/// request the kernel was asked to refuse. Re-walk the original path under
/// the child's flags first and hand back the kernel's own ELOOP. Any other
/// failure (a missing O_CREAT target, most of all) belongs to the normal path
/// below, which knows how to create and how to phrase the error.
fn enforce_resolve_flags(
    notif: &SeccompNotif,
    dirfd: i64,
    rel_path: &str,
    ctx: &ChrootCtx<'_>,
    resolve: u64,
) -> Option<NotifAction> {
    if resolve == 0 {
        return None;
    }
    let full_path = build_virtual_path(notif, dirfd, rel_path, ctx)?;
    let confined = confine(&full_path);
    let (root, sub) = match ctx.mount_target(&confined) {
        Some((mt, sub)) => (mt.to_path_buf(), sub),
        None => (ctx.root.to_path_buf(), full_path),
    };
    match openat2_in_root_with_resolve(&root, &sub, libc::O_PATH | libc::O_CLOEXEC, 0, resolve) {
        Ok(fd) => {
            unsafe { libc::close(fd) };
            None
        }
        Err(libc::ELOOP) => Some(NotifAction::Errno(libc::ELOOP)),
        Err(_) => None,
    }
}

/// The pid whose cwd a `/proc/<pid>/cwd[/...]` path names, if any.
///
/// Callers must canonicalize `/proc/self` first; this only matches the
/// numeric spelling.
fn proc_cwd_link_pid(virtual_path: &str) -> Option<(i32, &str)> {
    let rest = virtual_path.strip_prefix("/proc/")?;
    let (pid, rest) = rest.split_once('/')?;
    let pid: i32 = pid.parse().ok()?;
    let tail = rest.strip_prefix("cwd")?;
    if tail.is_empty() || tail.starts_with('/') {
        Some((pid, tail))
    } else {
        None
    }
}

/// The `(pid, fd)` a `/proc/<pid>/fd/<n>` path names, if any. Anything
/// deeper (`/proc/<pid>/fd/3/x`) is a path *through* the link, not the link.
fn proc_fd_link(virtual_path: &str) -> Option<(i32, i32)> {
    let rest = virtual_path.strip_prefix("/proc/")?;
    let (pid, rest) = rest.split_once('/')?;
    let fd = rest.strip_prefix("fd/")?;
    Some((pid.parse().ok()?, fd.parse().ok()?))
}

/// Name an open file the sandbox has no path for.
///
/// Modelled on the kernel's own `pipe:[inode]` spelling for fds that are not
/// reachable by name. A caller that reads an fd link to tell one stream from
/// another still gets a stable answer, without being handed a host path the
/// sandbox exists to keep out of reach.
fn unnameable_fd_name(link: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    let ino = std::fs::metadata(link).map(|m| m.ino()).unwrap_or(0);
    format!("file:[{}]", ino)
}

/// Rewrite a `/proc/<pid>/cwd` prefix to the cwd the sandbox believes that
/// task is in.
///
/// The kernel's magic link points at the task's real cwd, which the
/// supervisor deliberately stopped moving when it took over chdir, so
/// resolving through the link would land wherever exec left the child (and
/// under the host root at that, since the launch directory is usually
/// outside the virtual root entirely). Left alone for an untracked pid,
/// where the kernel's link is still the only answer there is.
fn canon_proc_cwd(virtual_path: &str, ctx: &ChrootCtx<'_>) -> String {
    let Some((pid, tail)) = proc_cwd_link_pid(virtual_path) else {
        return virtual_path.to_string();
    };
    match ctx.processes.virtual_cwd(pid) {
        Some(cwd) => format!("{}{}", cwd.to_string_lossy(), tail),
        None => virtual_path.to_string(),
    }
}

/// Build the full virtual path from dirfd + relative path.
fn build_virtual_path(
    notif: &SeccompNotif,
    dirfd: i64,
    path: &str,
    ctx: &ChrootCtx<'_>,
) -> Option<String> {
    let vpath = if Path::new(path).is_absolute() {
        path.to_string()
    } else {
        let dirfd32 = dirfd as i32;
        let base_virtual = if dirfd32 == libc::AT_FDCWD {
            virtual_cwd_of(notif, ctx)?
        } else {
            let base_host = std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd)).ok()?;
            ctx.host_to_virtual(&base_host)?
        };
        let combined = base_virtual.join(path);
        combined.to_string_lossy().to_string()
    };
    Some(canon_proc_cwd(&canon_proc_self(&vpath, notif.pid), ctx))
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

/// Resolve a child path without following a final symlink.
///
/// For the no-follow family: lstat describes the link, unlink removes it,
/// rename moves it, lchown owns it. Following the last component would point
/// every one of them at the target instead.
fn resolve_chroot_path_nofollow(
    notif: &SeccompNotif,
    dirfd: i64,
    path: &str,
    ctx: &ChrootCtx<'_>,
) -> Option<(PathBuf, PathBuf)> {
    let full_path = build_virtual_path(notif, dirfd, path, ctx)?;
    if let Some(result) = ctx.resolve_mount_nofollow(&full_path) {
        return Some(result);
    }
    resolve_in_root_nofollow(ctx.root, &full_path)
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
    cow_state: &Arc<Mutex<CowState>>,
    host_path: &Path,
) -> Result<PathBuf, NotifAction> {
    let cs = cow_state.lock().await;
    if let Some(ref cow) = cs.branch {
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

/// Like [`read_and_resolve`] but stops at a final symlink, for the callers
/// that must act on the link rather than on what it points at.
fn read_and_resolve_nofollow(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
    dirfd_idx: usize,
    path_idx: usize,
) -> Result<(String, PathBuf, PathBuf), NotifAction> {
    let path = read_path(notif, notif.data.args[path_idx], notif_fd)
        .ok_or(NotifAction::Continue)?;
    let dirfd = notif.data.args[dirfd_idx] as i64;
    let (host_path, virtual_path) = resolve_chroot_path_nofollow(notif, dirfd, &path, ctx)
        .ok_or(NotifAction::Errno(libc::EACCES))?;
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

// ============================================================
// openat handler
// ============================================================

pub(crate) async fn handle_chroot_open(
    notif: &SeccompNotif,
    _chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    // Every open spelling lands here, and they do not share an argument
    // layout: openat2 keeps flags, mode and resolve in a struct open_how in
    // child memory, where args[2] is the pointer to it rather than the flags.
    let (dirfd, path_ptr, flags, resolve) = match decode_open_args(notif, notif_fd) {
        Some(a) => (a.dirfd, a.path_ptr, a.flags, a.resolve),
        None => return NotifAction::Continue,
    };

    let rel_path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    let honored = honorable_resolve_flags(resolve);
    if let Some(refusal) = enforce_resolve_flags(notif, dirfd, &rel_path, ctx, honored) {
        return refusal;
    }

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
        let mut cs = cow_state.lock().await;
        if let Some(cow) = cs.branch.as_mut() {
            let host_str = host_path.to_string_lossy();
            if cow.matches(&host_str) {
                match cow.handle_open(&host_str, flags) {
                    Ok(Some(real_path)) => {
                        drop(cs);
                        let c_path = match path_cstr(&real_path, libc::EINVAL) {
                            Ok(c) => c,
                            Err(a) => return a,
                        };
                        let fd = unsafe { libc::open(c_path.as_ptr(), flags as i32, 0o666) };
                        if fd < 0 {
                            return NotifAction::Errno(last_errno(libc::EIO));
                        }
                        let newfd_flags = if flags & libc::O_CLOEXEC as u64 != 0 {
                            libc::O_CLOEXEC as u32
                        } else {
                            0
                        };
                        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
                        return NotifAction::InjectFdSend { srcfd: owned, newfd_flags };
                    }
                    Ok(None) => {
                        // Fall through to openat2_in_root below. This keeps
                        // directory opens and other non-COW / non-whiteout
                        // cases confined to the chroot instead of executing the
                        // original host syscall. (Whiteouts are handled by the
                        // BranchError::Deleted arm below, not here.)
                    }
                    Err(crate::error::BranchError::QuotaExceeded) => {
                        return NotifAction::Errno(libc::ENOSPC);
                    }
                    Err(crate::error::BranchError::Exists) => {
                        return NotifAction::Errno(libc::EEXIST);
                    }
                    Err(crate::error::BranchError::Deleted) => {
                        // Whiteout read-open: the lower file still physically
                        // exists, but the branch deleted it. Return ENOENT
                        // rather than leaking pre-delete bytes — parity with the
                        // async cow open path (cow/dispatch.rs) and
                        // stat/statx/access/readlink.
                        return NotifAction::Errno(libc::ENOENT);
                    }
                    Err(_) => return NotifAction::Errno(libc::EIO),
                }
            }
        }
    }

    // Resolve the path to an fd to hand the child: either a freshly opened tree
    // file or a dup of one of the child's own fds (a magic link). See
    // `open_in_namespace`.
    //
    // openat2 rejects a non-zero mode unless O_CREAT/O_TMPFILE is set (stricter
    // than openat), so only supply a creation mode when the child asks to create.
    // O_TMPFILE is a composite (__O_TMPFILE | O_DIRECTORY), so it must be matched
    // as a full mask, not with a bitwise-and that any O_DIRECTORY open would trip.
    let flags_i = flags as i32;
    let creates = flags_i & libc::O_CREAT != 0 || flags_i & libc::O_TMPFILE == libc::O_TMPFILE;
    let mode = if creates { 0o666 } else { 0 };
    let newfd_flags = if flags & libc::O_CLOEXEC as u64 != 0 {
        libc::O_CLOEXEC as u32
    } else {
        0
    };
    match open_in_namespace(ctx, notif.pid, &virtual_path, flags as i32, mode, honored) {
        Ok(srcfd) => NotifAction::InjectFdSend { srcfd, newfd_flags },
        Err(errno) => NotifAction::Errno(errno),
    }
}

/// Open `virtual_path` within the child's virtual namespace, returning an fd to
/// inject into the child.
///
/// A path names one of two things:
///
/// 1. A **tree object** reachable by walking the rootfs (or a mount target).
///    `openat2(RESOLVE_IN_ROOT)` opens these atomically and confined, with no
///    resolve-then-reopen TOCTOU gap. This is the overwhelmingly common case.
///
/// 2. An **fd reference** such as `/proc/self/fd/N` (named directly, or reached
///    through a symlink chain like `/dev/stderr -> /proc/self/fd/N` that
///    container images use for logging). This is not a filesystem object at
///    all; it names an entry in the child's *own* fd table, which the child
///    already holds. `openat2(RESOLVE_IN_ROOT)` rightly declines to fabricate
///    it (a magic link points outside the root by definition), so we serve it
///    by dup'ing the child's fd. No new access: the open was already authorized
///    by the caller and the child already owns the fd.
///
/// openat2 success proves category 1 (it refuses magic links), so we only look
/// for category 2 when it can't complete: EXDEV when the magic link sits in the
/// same root, ENOENT/ENOTDIR when it points into another mount (e.g.
/// `/dev/stderr -> /proc/...` resolved within the `/dev` mount). The fd walk is
/// authoritative and returns None for genuine misses, so non-magic paths
/// propagate their original errno unchanged.
fn open_in_namespace(
    ctx: &ChrootCtx<'_>,
    child_pid: u32,
    virtual_path: &Path,
    flags: i32,
    mode: u32,
    resolve: u64,
) -> Result<OwnedFd, i32> {
    let vp_str = virtual_path.to_string_lossy();

    // Category 2, named directly: skip the open and dup straight away.
    if let Some(child_fd) = magic_self_fd(&vp_str, child_pid) {
        return crate::seccomp::notif::dup_fd_from_pid(child_pid, child_fd)
            .map_err(|_| libc::EBADF);
    }

    let (root, sub) = match ctx.mount_target(virtual_path) {
        Some((mt, sub)) => (mt.to_path_buf(), sub),
        None => (ctx.root.to_path_buf(), vp_str.to_string()),
    };
    match openat2_in_root_with_resolve(&root, &sub, flags, mode, resolve) {
        // Category 1.
        Ok(fd) => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
        // Category 2, reached through symlinks.
        Err(errno) if matches!(errno, libc::EXDEV | libc::ENOENT | libc::ENOTDIR) => {
            match resolve_self_fd_magic(ctx, child_pid, &vp_str) {
                Some(child_fd) => crate::seccomp::notif::dup_fd_from_pid(child_pid, child_fd)
                    .map_err(|_| errno),
                None => Err(errno),
            }
        }
        Err(errno) => Err(errno),
    }
}

/// If `path` is a self-referential `/proc/.../fd/N` magic link for the calling
/// child (`/proc/self`, `/proc/thread-self`, or `/proc/<child_pid>`), return the
/// child fd `N`. The fd component must be a bare number (no trailing path).
fn magic_self_fd(path: &str, child_pid: u32) -> Option<i32> {
    let (who, fd_part) = path.strip_prefix("/proc/")?.split_once("/fd/")?;
    let is_self =
        who == "self" || who == "thread-self" || who.parse::<u32>().ok() == Some(child_pid);
    if !is_self || fd_part.contains('/') {
        return None;
    }
    fd_part.parse::<i32>().ok()
}

/// Read the symlink target at `virtual_path`, resolved within the chroot/mounts,
/// without following the final component. Returns None if it is not a symlink.
fn read_symlink_in_root(ctx: &ChrootCtx<'_>, virtual_path: &str) -> Option<String> {
    let confined = crate::chroot::resolve::confine(virtual_path);
    let (root, sub) = if let Some((mt, sub)) = ctx.mount_target(&confined) {
        (mt.to_path_buf(), sub)
    } else {
        (ctx.root.to_path_buf(), confined.to_string_lossy().into_owned())
    };
    let fd = openat2_in_root(
        &root,
        &sub,
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
    .ok()?;
    let mut buf = [0u8; 4096];
    let n = unsafe {
        libc::readlinkat(
            fd,
            c"".as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    unsafe { libc::close(fd) };
    if n <= 0 {
        return None; // EINVAL (not a symlink) or read error
    }
    Some(String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

/// Walk the symlink chain at `virtual_path` (confined to the chroot/mounts)
/// looking for a terminating self-fd magic link; return the child fd it names.
fn resolve_self_fd_magic(ctx: &ChrootCtx<'_>, child_pid: u32, virtual_path: &str) -> Option<i32> {
    let mut cur = virtual_path.to_string();
    for _ in 0..40 {
        if let Some(fd) = magic_self_fd(&cur, child_pid) {
            return Some(fd);
        }
        let target = read_symlink_in_root(ctx, &cur)?;
        let next = if Path::new(&target).is_absolute() {
            target
        } else {
            let parent = Path::new(&cur).parent().unwrap_or_else(|| Path::new("/"));
            parent.join(&target).to_string_lossy().into_owned()
        };
        cur = crate::chroot::resolve::confine(&next).to_string_lossy().into_owned();
    }
    None
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
    chroot_state: &Arc<Mutex<ChrootState>>,
    _cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let (dirfd, path_ptr, argv_ptr, envp_ptr) = if nr == libc::SYS_execveat {
        (notif.data.args[0] as i64, notif.data.args[1], notif.data.args[2], notif.data.args[3])
    } else {
        (libc::AT_FDCWD as i64, notif.data.args[0], notif.data.args[1], notif.data.args[2])
    };

    let rel_path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    // Build the full virtual path from dirfd + relative path.
    let full_path = if Path::new(&rel_path).is_absolute() {
        rel_path
    } else {
        let base = match dirfd as i32 {
            libc::AT_FDCWD => virtual_cwd_of(notif, ctx),
            _ => std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd))
                .ok()
                .and_then(|host| ctx.host_to_virtual(&host)),
        };
        match base {
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
                SECCOMP_IOCTL_NOTIF_ADDFD as libc::Ioctl,
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
        let mut cs = chroot_state.lock().await;
        cs.chroot_exe = Some(virtual_path.clone());
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
            SECCOMP_IOCTL_NOTIF_ADDFD as libc::Ioctl,
            &addfd as *const _,
        )
    };
    drop(exec_fd);

    if child_fd < 0 {
        return NotifAction::Errno(libc::EIO);
    }

    // Rewrite the path to /proc/self/fd/N, relocating argv[0] when it aliases
    // the path buffer (see rewrite_exec_path_to_fd). Force-writes past
    // read-only page protections: the child commonly passes a .rodata path
    // literal to execve, which process_vm_writev can't overwrite. No length
    // guard needed — execve replaces the address space on success, so a write
    // past the original buffer is harmless.
    if crate::seccomp::notif::rewrite_exec_path_to_fd(
        notif_fd, notif.id, notif.pid, path_ptr, argv_ptr, envp_ptr, child_fd,
    )
    .is_err()
    {
        return NotifAction::Errno(libc::EFAULT);
    }

    NotifAction::Continue
}

// ============================================================
// Write operation handlers
// ============================================================

pub(crate) async fn handle_chroot_write(
    notif: &SeccompNotif,
    _chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    if nr == libc::SYS_unlinkat {
        // unlink(2) removes the link, never what it points at.
        let (_, host_path, vp) = match read_and_resolve_nofollow(notif, notif_fd, ctx, 0, 1) {
            Ok(r) => r,
            Err(a) => return a,
        };
        if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }
        let is_dir = (notif.data.args[2] & libc::AT_REMOVEDIR as u64) != 0;

        {
            let mut cs = cow_state.lock().await;
            if let Some(cow) = cs.branch.as_mut() {
                let s = host_path.to_string_lossy();
                if cow.matches(&s) {
                    match cow.handle_unlink(&s, is_dir) {
                        Ok(true) => return NotifAction::ReturnValue(0),
                        Err(errno) => return NotifAction::Errno(errno),
                        _ => {}
                    }
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
            let mut cs = cow_state.lock().await;
            if let Some(cow) = cs.branch.as_mut() {
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

    // renameat carries the same (olddirfd, oldpath, newdirfd, newpath) slots
    // as renameat2 and differs only by the flags argument, which this handler
    // does not read.
    if nr == libc::SYS_renameat2 || Some(nr) == crate::arch::sys_renameat() {
        let old_path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        let new_path = match read_path(notif, notif.data.args[3], notif_fd) {
            Some(p) => p,
            None => return NotifAction::Continue,
        };
        // rename(2) moves the names themselves: a symlink on either side is
        // renamed, not chased.
        let (old_host, old_vp) = match resolve_chroot_path_nofollow(notif, notif.data.args[0] as i64, &old_path, ctx) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        let (new_host, new_vp) = match resolve_chroot_path_nofollow(notif, notif.data.args[2] as i64, &new_path, ctx) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        if !ctx.can_write(&old_vp) || !ctx.can_write(&new_vp) {
            return NotifAction::Errno(libc::EACCES);
        }

        {
            let mut cs = cow_state.lock().await;
            if let Some(cow) = cs.branch.as_mut() {
                let old_str = old_host.to_string_lossy();
                if cow.matches(&old_str) {
                    match cow.handle_rename(&old_str, &new_host.to_string_lossy()) {
                        Ok(true) => return NotifAction::ReturnValue(0),
                        Err(errno) => return NotifAction::Errno(errno),
                        Ok(false) => {}
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
            let mut cs = cow_state.lock().await;
            if let Some(cow) = cs.branch.as_mut() {
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
        // link(2) hardlinks the source name itself; only AT_SYMLINK_FOLLOW
        // asks for the target. The destination is a name being created, so it
        // never follows either.
        let follow_old = (notif.data.args[4] & libc::AT_SYMLINK_FOLLOW as u64) != 0;
        let old_resolved = if follow_old {
            // The source has to resolve as a path that already exists, which
            // is what pins the result inside the root: the O_CREAT-style
            // fallback in resolve_chroot_path walks the parent and then appends
            // the last component verbatim, so a symlink whose target does not
            // exist inside the root comes back as the symlink's own name. The
            // supervisor runs outside the chroot, so handing that name to the
            // host linkat below would resolve the guest's symlink from the real
            // root and hard-link a host file into the sandbox.
            //
            // The virtual path is re-derived from the resolved host path
            // because a resolution under a mount reports the name the child
            // asked for, not the name it reached. The gate below has to read
            // the name of the inode being linked: a symlink inside a mount
            // would otherwise be judged by the link's own name, and a denied
            // or read-only target would pass under any allowed spelling.
            resolve_chroot_path_existing(notif, notif.data.args[0] as i64, &old_path, ctx)
                .and_then(|(host, _)| ctx.host_to_virtual(&host).map(|vp| (host, vp)))
        } else {
            resolve_chroot_path_nofollow(notif, notif.data.args[0] as i64, &old_path, ctx)
        };
        let (old_host, old_vp) = match old_resolved {
            Some(r) => r,
            // A followed source that will not resolve is either missing or
            // pointing out of the root, and the sandbox says the same thing
            // about both: ENOENT is also what the kernel reports natively for
            // AT_SYMLINK_FOLLOW on a dangling symlink.
            None if follow_old => return NotifAction::Errno(libc::ENOENT),
            None => return NotifAction::Errno(libc::EACCES),
        };
        let (new_host, new_vp) = match resolve_chroot_path_nofollow(notif, notif.data.args[2] as i64, &new_path, ctx) {
            Some(r) => r,
            None => return NotifAction::Errno(libc::EACCES),
        };
        // A hard link is a second name for one inode, so afterwards the
        // authority over that inode is the union of the policy on both names.
        // Gating the destination alone lets a guest re-file a readable but
        // unwritable file (a read-only mount, a denied path) under a writable
        // prefix and then write to it there. Requiring write on the source too
        // keeps the weaker name from being upgraded, the same rule rename
        // already applies to the name it destroys. Off the chroot path
        // Landlock enforces this already: linking needs REFER on both sides.
        if !ctx.can_write(&old_vp) || !ctx.can_write(&new_vp) {
            return NotifAction::Errno(libc::EACCES);
        }

        {
            let mut cs = cow_state.lock().await;
            if let Some(cow) = cs.branch.as_mut() {
                let old_s = old_host.to_string_lossy();
                let new_s = new_host.to_string_lossy();
                // A hard link cannot be half staged. With one name inside the
                // branch and the other below it there is nothing to stage:
                // linking in would create the name in the workdir the branch
                // promised to leave untouched, and linking out would hand the
                // child an alias for the lower inode that survives an abort.
                // EXDEV is what the kernel says about a link that cannot span
                // the two sides.
                if cow.matches(&old_s) != cow.matches(&new_s) {
                    return NotifAction::Errno(libc::EXDEV);
                }
                if cow.matches(&new_s) {
                    return crate::cow::result::link_result(cow.handle_link(&old_s, &new_s));
                }
            }
        }

        let c_old = match path_cstr(&old_host, libc::EINVAL) { Ok(c) => c, Err(a) => return a };
        let c_new = match path_cstr(&new_host, libc::EINVAL) { Ok(c) => c, Err(a) => return a };
        // Both defined flags describe a source this code has already resolved,
        // so neither is forwarded. AT_SYMLINK_FOLLOW was consumed by the branch
        // above; leaving it set would make the host kernel resolve the last
        // component a second time, unconfined, which is both an escape and a
        // window for the child to swap that component after the check.
        // AT_EMPTY_PATH names a dirfd, and the path below is never empty.
        // Anything else the child passes stays, so the kernel keeps rejecting
        // unknown flags with EINVAL exactly as it would without the sandbox.
        let flags =
            notif.data.args[4] as i32 & !(libc::AT_EMPTY_PATH | libc::AT_SYMLINK_FOLLOW);
        return if unsafe { libc::linkat(libc::AT_FDCWD, c_old.as_ptr(), libc::AT_FDCWD, c_new.as_ptr(), flags) } < 0 {
            NotifAction::Errno(last_errno(libc::EIO))
        } else {
            NotifAction::ReturnValue(0)
        };
    }

    if nr == libc::SYS_fchmodat || nr == crate::arch::SYS_FCHMODAT2 {
        let nofollow = nr == crate::arch::SYS_FCHMODAT2
            && (notif.data.args[3] & libc::AT_SYMLINK_NOFOLLOW as u64) != 0;
        let resolved = if nofollow {
            read_and_resolve_nofollow(notif, notif_fd, ctx, 0, 1)
        } else {
            read_and_resolve(notif, notif_fd, ctx, 0, 1)
        };
        let (_, host_path, vp) = match resolved {
            Ok(r) => r,
            Err(a) => return a,
        };
        if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }
        // Linux has no symlink modes: the kernel's answer for
        // AT_SYMLINK_NOFOLLOW on a symlink, given before the target is touched.
        if nofollow && host_path.is_symlink() {
            return NotifAction::Errno(libc::EOPNOTSUPP);
        }
        let mode = (notif.data.args[2] & 0o7777) as u32;

        {
            let mut cs = cow_state.lock().await;
            if let Some(cow) = cs.branch.as_mut() {
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
        let nofollow = (notif.data.args[4] & libc::AT_SYMLINK_NOFOLLOW as u64) != 0;
        let resolved = if nofollow {
            read_and_resolve_nofollow(notif, notif_fd, ctx, 0, 1)
        } else {
            read_and_resolve(notif, notif_fd, ctx, 0, 1)
        };
        let (_, host_path, vp) = match resolved {
            Ok(r) => r,
            Err(a) => return a,
        };
        if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }
        let uid = notif.data.args[2] as u32;
        let gid = notif.data.args[3] as u32;

        {
            let mut cs = cow_state.lock().await;
            if let Some(cow) = cs.branch.as_mut() {
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
        return exec_on_host(
            |p| unsafe {
                if nofollow { libc::lchown(p, uid, gid) } else { libc::chown(p, uid, gid) }
            },
            &host_path,
        );
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
            let mut cs = cow_state.lock().await;
            if let Some(cow) = cs.branch.as_mut() {
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

    // Let libc lay the struct out. Hand-packing it in field order is an
    // x86_64 assumption: aarch64 and riscv64 put st_mode and st_nlink before
    // st_uid in 32-bit slots where x86_64 has a 64-bit st_nlink first, so the
    // child read st_nlink's low half as its mode. st_size happens to land at
    // the same offset on all three, which is why only a test that looks at
    // the mode ever noticed.
    let c_path = match path_cstr(path, libc::ENOENT) {
        Ok(c) => c,
        Err(a) => return a,
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        if follow {
            libc::stat(c_path.as_ptr(), &mut st)
        } else {
            libc::lstat(c_path.as_ptr(), &mut st)
        }
    };
    if rc < 0 {
        return NotifAction::Errno(last_errno(libc::ENOENT));
    }

    let bytes = unsafe {
        std::slice::from_raw_parts(
            &st as *const libc::stat as *const u8,
            std::mem::size_of::<libc::stat>(),
        )
    };
    if write_child_mem(notif_fd, notif.id, notif.pid, statbuf_addr, bytes).is_err() {
        return NotifAction::Continue;
    }
    NotifAction::ReturnValue(0)
}

pub(crate) async fn handle_chroot_stat(
    notif: &SeccompNotif,
    _chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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

    let resolved = if (flags & libc::AT_SYMLINK_NOFOLLOW as u64) != 0 {
        read_and_resolve_nofollow(notif, notif_fd, ctx, 0, 1)
    } else {
        read_and_resolve_existing(notif, notif_fd, ctx, 0, 1)
    };
    let (_, host_path, vp) = match resolved {
        Ok(r) => r,
        Err(a) => return a,
    };
    if !ctx.can_read(&vp) { return NotifAction::Errno(libc::EACCES); }

    let real_path = match cow_resolve(cow_state, &host_path).await {
        Ok(p) => p,
        Err(a) => return a,
    };

    if nr == libc::SYS_faccessat || nr == crate::arch::SYS_FACCESSAT2 {
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
    _chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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

    let resolved = if (flags & libc::AT_SYMLINK_NOFOLLOW) != 0 {
        resolve_chroot_path_nofollow(notif, dirfd, &path, ctx)
    } else {
        resolve_chroot_path_existing(notif, dirfd, &path, ctx)
    };
    let (host_path, vp) = match resolved {
        Some(r) => r,
        None => return NotifAction::Errno(libc::ENOENT),
    };
    if !ctx.can_read(&vp) { return NotifAction::Errno(libc::EACCES); }

    let real_path = match cow_resolve(cow_state, &host_path).await {
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
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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

    // "self" here would be the SUPERVISOR: it services /proc through an
    // on-behalf openat2, so the magic links below resolve in its own
    // process unless the caller's pid is substituted first, exactly as
    // build_virtual_path does for every other handler.
    let path = canon_proc_self(&path, notif.pid);
    let own_proc = format!("/proc/{}", notif.pid);

    // Reading a /proc/<pid> link reads another process's state, so it takes
    // the same per-PID gate the /proc open path applies. Without it a child
    // could not open /proc/<host pid>/cwd but could still readlink it, and
    // the supervisor answering on its behalf sees the whole host process
    // table.
    if let Some(pid) = crate::procfs::extract_proc_pid(&path) {
        if !ctx.processes.contains(pid) {
            return NotifAction::Errno(libc::EACCES);
        }
    }

    // Special case: the caller's own /proc/<pid>/root -> "/"
    if path == format!("{}/root", own_proc) {
        return write_target(b"/");
    }

    // Special case: /proc/<pid>/cwd is a magic link to the task's real cwd,
    // which the supervisor no longer moves. Answer from what it tracks, and
    // never fall back to the host path the link actually points at.
    if let Some((pid, tail)) = proc_cwd_link_pid(&path) {
        if tail.is_empty() {
            let cwd = ctx
                .processes
                .virtual_cwd(pid)
                .or_else(|| {
                    std::fs::read_link(format!("/proc/{}/cwd", pid))
                        .ok()
                        .and_then(|host| ctx.host_to_virtual(&host))
                })
                .unwrap_or_else(|| PathBuf::from("/"));
            return write_target(cwd.to_string_lossy().as_bytes());
        }
    }

    // Special case: /proc/<pid>/fd/N is a magic link, so what the kernel
    // returns is a real host path it synthesized rather than link text that
    // the generic tail below could pass through untouched.
    if let Some((pid, fd)) = proc_fd_link(&path) {
        let link = format!("/proc/{}/fd/{}", pid, fd);
        let target = match std::fs::read_link(&link) {
            Ok(t) => t,
            Err(_) => return NotifAction::Errno(libc::EBADF),
        };
        // pipe:[…], socket:[…], anon_inode:… — the kernel's own synthetic
        // names for fds with no path. Nothing to map, nothing to hide.
        if !target.is_absolute() {
            return write_target(target.to_string_lossy().as_bytes());
        }
        let named = match ctx.host_to_virtual(&target) {
            Some(virtual_target) => virtual_target.to_string_lossy().into_owned(),
            None => unnameable_fd_name(&link),
        };
        return write_target(named.as_bytes());
    }

    // Special case: /proc/<pid>/exe -> return the virtual path recorded during exec
    // (needed because memfd-backed binaries would show "/memfd:sandlock-exec" otherwise).
    if path == format!("{}/exe", own_proc) {
        let cs = chroot_state.lock().await;
        if let Some(ref exe) = cs.chroot_exe {
            let s = exe.to_string_lossy();
            return write_target(s.as_bytes());
        }
        drop(cs);
        // Fallback: strip chroot prefix from /proc/{pid}/exe
        if let Ok(real_exe) = std::fs::read_link(format!("/proc/{}/exe", notif.pid)) {
            let virtual_exe = ctx.host_to_virtual(&real_exe).unwrap_or(real_exe);
            let s = virtual_exe.to_string_lossy();
            return write_target(s.as_bytes());
        }
        return NotifAction::Continue;
    }

    // readlink must read the link itself, never what it points at, which is
    // exactly what the no-follow resolver gives.
    let (host_path, _) = match resolve_chroot_path_nofollow(notif, dirfd, &path, ctx) {
        Some(r) => r,
        None => return NotifAction::Errno(libc::EACCES),
    };

    // COW
    {
        let cs = cow_state.lock().await;
        if let Some(cow) = cs.branch.as_ref() {
            let host_str = host_path.to_string_lossy();
            if cow.matches(&host_str) {
                let target = match cow.handle_readlink(&host_str) {
                    Some(t) => t,
                    None => return NotifAction::Errno(libc::ENOENT),
                };
                drop(cs);
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
// xattr handler
// ============================================================

/// The four path-based xattr operations. Each maps onto a pair of libc
/// syscalls (follow / no-follow) that differ only in their `l` prefix.
#[derive(Clone, Copy)]
enum XattrOp {
    /// `getxattr(path, name, value, size)` — copy a value out to the child.
    Get,
    /// `setxattr(path, name, value, size, flags)` — copy a value in.
    Set,
    /// `listxattr(path, list, size)` — copy the name list out.
    List,
    /// `removexattr(path, name)`.
    Remove,
}

/// Classify a syscall as a path-based xattr op plus whether it follows the
/// final symlink. Returns `None` for anything else.
fn classify_xattr(nr: i64) -> Option<(XattrOp, bool)> {
    Some(match nr {
        libc::SYS_getxattr => (XattrOp::Get, true),
        libc::SYS_lgetxattr => (XattrOp::Get, false),
        libc::SYS_setxattr => (XattrOp::Set, true),
        libc::SYS_lsetxattr => (XattrOp::Set, false),
        libc::SYS_listxattr => (XattrOp::List, true),
        libc::SYS_llistxattr => (XattrOp::List, false),
        libc::SYS_removexattr => (XattrOp::Remove, true),
        libc::SYS_lremovexattr => (XattrOp::Remove, false),
        _ => return None,
    })
}

/// Kernel ceiling for an xattr value (`XATTR_SIZE_MAX`) and name list
/// (`XATTR_LIST_MAX`). The supervisor never needs a larger buffer, so
/// clamping the child's requested size here both bounds our allocation and
/// can never cause a spurious `ERANGE` (a real result never exceeds it).
const XATTR_MAX: usize = 65536;

/// Shared read path for `getxattr`/`listxattr`: run the syscall on the
/// rewritten host path into a supervisor buffer, then copy the result back
/// into the child's buffer. `name` is `Some` for getxattr, `None` for
/// listxattr. `buf_idx`/`size_idx` are the child arg positions of the output
/// buffer pointer and its capacity.
fn xattr_read(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    c_path: &CString,
    name: Option<&CString>,
    follow: bool,
    buf_idx: usize,
    size_idx: usize,
) -> NotifAction {
    let buf_addr = notif.data.args[buf_idx];
    let size = (notif.data.args[size_idx] as usize).min(XATTR_MAX);
    let mut buf = vec![0u8; size];
    // size == 0 is a probe for the needed length — pass NULL so the kernel
    // just reports the size without touching a buffer.
    let buf_ptr = if size == 0 {
        std::ptr::null_mut()
    } else {
        buf.as_mut_ptr() as *mut libc::c_void
    };
    // getxattr takes a name (4 args), listxattr does not (3 args).
    let ret = unsafe {
        match name {
            Some(n) if follow => {
                libc::syscall(libc::SYS_getxattr, c_path.as_ptr(), n.as_ptr(), buf_ptr, size)
            }
            Some(n) => {
                libc::syscall(libc::SYS_lgetxattr, c_path.as_ptr(), n.as_ptr(), buf_ptr, size)
            }
            None if follow => libc::syscall(libc::SYS_listxattr, c_path.as_ptr(), buf_ptr, size),
            None => libc::syscall(libc::SYS_llistxattr, c_path.as_ptr(), buf_ptr, size),
        }
    };
    if ret < 0 {
        return NotifAction::Errno(last_errno(libc::ENODATA));
    }
    // size == 0 returns the needed length without writing anything back.
    if size > 0 && ret as usize > 0 {
        let written = write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, &buf[..ret as usize]);
        if written.is_err() {
            return NotifAction::Errno(libc::EFAULT);
        }
    }
    NotifAction::ReturnValue(ret)
}

/// Mediate the path-based xattr syscalls. Without this, a `getxattr` on a
/// path under an `fs_mount`/chroot resolves against the empty real mount
/// point and returns `ENOENT`, even though `statx` on the same path is
/// rewritten correctly (issue #84).
pub(crate) async fn handle_chroot_xattr(
    notif: &SeccompNotif,
    _chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let (op, follow) = match classify_xattr(notif.data.nr as i64) {
        Some(x) => x,
        None => return NotifAction::Continue,
    };

    // The path is always arg 0; xattr syscalls have no dirfd, so relative
    // paths resolve against the child's cwd (AT_FDCWD).
    let path = match read_path(notif, notif.data.args[0], notif_fd) {
        Some(p) if !p.is_empty() => p,
        _ => return NotifAction::Continue,
    };
    let (host_path, vp) =
        match if follow {
            resolve_chroot_path_existing(notif, libc::AT_FDCWD as i64, &path, ctx)
        } else {
            resolve_chroot_path_nofollow(notif, libc::AT_FDCWD as i64, &path, ctx)
        } {
            Some(r) => r,
            None => return NotifAction::Errno(libc::ENOENT),
        };

    let writing = matches!(op, XattrOp::Set | XattrOp::Remove);
    let allowed = if writing { ctx.can_write(&vp) } else { ctx.can_read(&vp) };
    if !allowed {
        return NotifAction::Errno(libc::EACCES);
    }

    let real_path = match cow_resolve(cow_state, &host_path).await {
        Ok(p) => p,
        Err(a) => return a,
    };
    let c_path = match path_cstr(&real_path, libc::ENOENT) {
        Ok(c) => c,
        Err(a) => return a,
    };

    // Read the attribute name (arg 1) for the ops that carry one.
    let read_name = || -> Result<CString, NotifAction> {
        let n = read_path(notif, notif.data.args[1], notif_fd)
            .ok_or(NotifAction::Errno(libc::EFAULT))?;
        CString::new(n).map_err(|_| NotifAction::Errno(libc::EINVAL))
    };

    match op {
        XattrOp::Get => {
            let name = match read_name() {
                Ok(n) => n,
                Err(a) => return a,
            };
            xattr_read(notif, notif_fd, &c_path, Some(&name), follow, 2, 3)
        }
        XattrOp::List => xattr_read(notif, notif_fd, &c_path, None, follow, 1, 2),
        XattrOp::Set => {
            let name = match read_name() {
                Ok(n) => n,
                Err(a) => return a,
            };
            let size = notif.data.args[3] as usize;
            let flags = notif.data.args[4] as i32;
            let value = match read_child_mem(notif_fd, notif.id, notif.pid, notif.data.args[2], size) {
                Ok(v) => v,
                Err(_) => return NotifAction::Errno(libc::EFAULT),
            };
            let nr = if follow { libc::SYS_setxattr } else { libc::SYS_lsetxattr };
            let ret = unsafe {
                libc::syscall(
                    nr,
                    c_path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    size,
                    flags,
                )
            };
            if ret < 0 {
                NotifAction::Errno(last_errno(libc::EIO))
            } else {
                NotifAction::ReturnValue(0)
            }
        }
        XattrOp::Remove => {
            let name = match read_name() {
                Ok(n) => n,
                Err(a) => return a,
            };
            let nr = if follow { libc::SYS_removexattr } else { libc::SYS_lremovexattr };
            let ret = unsafe { libc::syscall(nr, c_path.as_ptr(), name.as_ptr()) };
            if ret < 0 {
                NotifAction::Errno(last_errno(libc::EIO))
            } else {
                NotifAction::ReturnValue(0)
            }
        }
    }
}

// ============================================================
// getdents handler
// ============================================================

pub(crate) async fn handle_chroot_getdents(
    _notif: &SeccompNotif,
    _chroot_state: &Arc<Mutex<ChrootState>>,
    _cow_state: &Arc<Mutex<CowState>>,
    _notif_fd: RawFd,
    _ctx: &ChrootCtx<'_>,
) -> NotifAction {
    // The child's fd already points to the real host directory (injected
    // by the chroot openat handler).  Let the kernel handle getdents
    // directly — it returns the correct entries from the host path.
    // No filtering or caching needed; denied paths are enforced at open
    // time, not at directory listing time.
    NotifAction::Continue
}

// ============================================================
// chdir handler
// ============================================================

pub(crate) async fn handle_chroot_chdir(
    notif: &SeccompNotif,
    _chroot_state: &Arc<Mutex<ChrootState>>,
    _cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let path = match read_path(notif, notif.data.args[0], notif_fd) {
        Some(p) => p,
        None => return NotifAction::Errno(libc::EFAULT),
    };

    let full_path = match build_virtual_path(notif, libc::AT_FDCWD as i64, &path, ctx) {
        Some(p) => p,
        None => return NotifAction::Errno(libc::EACCES),
    };

    // Resolve on-behalf: this is what decides whether the directory exists,
    // is reachable inside the root, and is a directory at all, and it gives
    // the errno the child gets when it is not.
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
    // Record where the kernel actually landed, not what the child asked for:
    // symlinks and .. are already collapsed in the resolved fd.
    let resolved = std::fs::read_link(format!("/proc/self/fd/{}", src_fd)).ok();
    unsafe { libc::close(src_fd) };
    let virtual_cwd = resolved
        .as_deref()
        .and_then(|host| ctx.host_to_virtual(host))
        .unwrap_or(confined);

    // The child's own cwd never moves. chdir cannot be run on-behalf (only
    // the kernel can update the calling task's fs_struct) and the argument
    // registers are not writable from seccomp-notify, so the handler used to
    // rewrite the child's path buffer in place to /proc/self/fd/N and let the
    // kernel run that. It could not: 16 bytes do not fit the buffer behind a
    // path as short as "/tmp" or "/", which is issue #178. Tracking the cwd
    // here instead serves every spelling, and it drops both a TOCTOU window
    // (the kernel re-read the path we wrote) and a force-write through
    // /proc/<pid>/mem that permanently corrupted a .rodata path literal.
    set_virtual_cwd(notif, ctx, virtual_cwd);
    NotifAction::ReturnValue(0)
}

// ============================================================
// fchdir handler
// ============================================================

/// Observe an fchdir so the tracked cwd cannot go stale.
///
/// The child's real cwd does move here, since the fd is already open and the
/// kernel needs no path from us. But the supervisor's notion is what resolves
/// every later relative path, so it has to follow along.
pub(crate) async fn handle_chroot_fchdir(
    notif: &SeccompNotif,
    _chroot_state: &Arc<Mutex<ChrootState>>,
    _cow_state: &Arc<Mutex<CowState>>,
    _notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let target = std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, fd)).ok();
    // Only follow a target that is really a directory: anything else fails
    // the kernel's fchdir, and recording it would desync the tracked cwd.
    if let Some(host) = target.filter(|t| t.is_dir()) {
        if let Some(virtual_cwd) = ctx.host_to_virtual(&host) {
            set_virtual_cwd(notif, ctx, virtual_cwd);
        }
    }
    NotifAction::Continue
}

// ============================================================
// getcwd handler
// ============================================================

pub(crate) async fn handle_chroot_getcwd(
    notif: &SeccompNotif,
    _chroot_state: &Arc<Mutex<ChrootState>>,
    _cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    let buf_addr = notif.data.args[0];
    let buf_size = (notif.data.args[1] & 0xFFFFFFFF) as usize;

    let virtual_cwd = virtual_cwd_of(notif, ctx).unwrap_or_else(|| PathBuf::from("/"));
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
    _chroot_state: &Arc<Mutex<ChrootState>>,
    _cow_state: &Arc<Mutex<CowState>>,
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
    _chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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

    let resolved = if (flags & libc::AT_SYMLINK_NOFOLLOW) != 0 {
        resolve_chroot_path_nofollow(notif, dirfd, &path, ctx)
    } else {
        resolve_chroot_path(notif, dirfd, &path, ctx)
    };
    let (host_path, vp) = match resolved {
        Some(r) => r,
        None => return NotifAction::Errno(libc::EACCES),
    };
    if !ctx.can_write(&vp) { return NotifAction::Errno(libc::EACCES); }

    let real_path = match cow_resolve(cow_state, &host_path).await {
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
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
    notif_fd: RawFd,
    ctx: &ChrootCtx<'_>,
) -> NotifAction {
    // open(path, flags, mode) needs no reshaping: decode_open_args reads the
    // legacy layout from the syscall number and supplies the implied AT_FDCWD.
    handle_chroot_open(notif, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_stat(path, statbuf) → handle_chroot_stat via newfstatat(AT_FDCWD, path, statbuf, 0)
pub(crate) async fn handle_chroot_legacy_stat(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_stat(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_lstat(path, statbuf) → handle_chroot_stat via newfstatat(AT_FDCWD, path, statbuf, AT_SYMLINK_NOFOLLOW)
pub(crate) async fn handle_chroot_legacy_lstat(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_stat(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_access(path, mode) → handle_chroot_stat via faccessat(AT_FDCWD, path, mode, 0)
pub(crate) async fn handle_chroot_legacy_access(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_stat(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_readlink(path, buf, bufsiz) → handle_chroot_readlink via readlinkat(AT_FDCWD, path, buf, bufsiz)
pub(crate) async fn handle_chroot_legacy_readlink(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_readlink(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_unlink(path) → handle_chroot_write via unlinkat(AT_FDCWD, path, 0)
pub(crate) async fn handle_chroot_legacy_unlink(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_write(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_rmdir(path) → handle_chroot_write via unlinkat(AT_FDCWD, path, AT_REMOVEDIR)
pub(crate) async fn handle_chroot_legacy_rmdir(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_write(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_mkdir(path, mode) → handle_chroot_write via mkdirat(AT_FDCWD, path, mode)
pub(crate) async fn handle_chroot_legacy_mkdir(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_write(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_rename(oldpath, newpath) → handle_chroot_write via renameat2(AT_FDCWD, old, AT_FDCWD, new, 0)
pub(crate) async fn handle_chroot_legacy_rename(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_write(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_symlink(target, linkpath) → handle_chroot_write via symlinkat(target, AT_FDCWD, linkpath)
pub(crate) async fn handle_chroot_legacy_symlink(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_write(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_link(oldpath, newpath) → handle_chroot_write via linkat(AT_FDCWD, old, AT_FDCWD, new, 0)
pub(crate) async fn handle_chroot_legacy_link(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_write(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_chmod(path, mode) → handle_chroot_write via fchmodat(AT_FDCWD, path, mode)
pub(crate) async fn handle_chroot_legacy_chmod(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_write(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

/// SYS_chown/lchown(path, uid, gid) → handle_chroot_write via fchownat(AT_FDCWD, path, uid, gid, flags)
pub(crate) async fn handle_chroot_legacy_chown(
    notif: &SeccompNotif,
    chroot_state: &Arc<Mutex<ChrootState>>,
    cow_state: &Arc<Mutex<CowState>>,
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
    handle_chroot_write(&synth, chroot_state, cow_state, notif_fd, ctx).await
}

#[cfg(test)]
mod self_rewrite_tests {
    use super::canon_proc_self;

    #[test]
    fn rewrites_self_and_thread_self_to_pid() {
        assert_eq!(canon_proc_self("/proc/self", 42), "/proc/42");
        assert_eq!(canon_proc_self("/proc/self/status", 42), "/proc/42/status");
        assert_eq!(canon_proc_self("/proc/self/fd/3", 42), "/proc/42/fd/3");
        assert_eq!(canon_proc_self("/proc/thread-self", 42), "/proc/42");
        assert_eq!(canon_proc_self("/proc/thread-self/maps", 42), "/proc/42/maps");
    }

    #[test]
    fn leaves_other_paths_untouched() {
        // Numeric PIDs, non-self /proc paths, and "selfish" lookalikes must not
        // be rewritten.
        assert_eq!(canon_proc_self("/proc/7/status", 42), "/proc/7/status");
        assert_eq!(canon_proc_self("/proc/cpuinfo", 42), "/proc/cpuinfo");
        assert_eq!(canon_proc_self("/proc/selfish", 42), "/proc/selfish");
        assert_eq!(canon_proc_self("/etc/passwd", 42), "/etc/passwd");
    }
}

#[cfg(test)]
mod mount_ro_tests {
    use super::{ChrootCtx, ProcessIndex};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    fn ctx<'a>(
        mounts: &'a [(PathBuf, PathBuf)],
        mount_ro: &'a [PathBuf],
        writable: &'a [PathBuf],
        processes: &'a Arc<ProcessIndex>,
    ) -> ChrootCtx<'a> {
        ChrootCtx {
            root: Path::new("/rootfs"),
            readable: &[],
            writable,
            denied: &[],
            mounts,
            mount_ro,
            processes,
        }
    }

    #[test]
    fn read_only_mount_denies_writes_but_allows_reads() {
        let mounts = vec![(PathBuf::from("/proc"), PathBuf::from("/proc"))];
        let ro = vec![PathBuf::from("/proc")];
        // Even with a writable rootfs ("/" granted), the read-only /proc mount
        // must still deny writes — this is the host-escape guard.
        let writable = vec![PathBuf::from("/")];
        let processes = Arc::new(ProcessIndex::new());
        let c = ctx(&mounts, &ro, &writable, &processes);
        assert!(c.can_read(Path::new("/proc/version")));
        assert!(!c.can_write(Path::new("/proc/sys/kernel/core_pattern")));
        assert!(!c.can_write(Path::new("/proc/self/oom_score_adj")));
    }

    #[test]
    fn writable_mount_still_allows_writes() {
        let mounts = vec![(PathBuf::from("/data"), PathBuf::from("/host/data"))];
        let ro: Vec<PathBuf> = vec![];
        let writable = vec![PathBuf::from("/data")];
        let processes = Arc::new(ProcessIndex::new());
        let c = ctx(&mounts, &ro, &writable, &processes);
        assert!(c.can_read(Path::new("/data/file")));
        assert!(c.can_write(Path::new("/data/file")));
    }
}
