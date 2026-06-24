//! Filesystem syscall helpers shared by the chroot and COW supervisors.
//!
//! `openat2_in_root` is the single confined-open primitive: it asks the
//! kernel to resolve a path with `RESOLVE_IN_ROOT`, so symlinks and `..`
//! cannot escape the given root. Both supervisors route child-controlled
//! path opens through it (see issue #112).

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::Path;

/// openat2 syscall number, sourced from the `syscalls` crate via `arch`.
const SYS_OPENAT2: libc::c_long = crate::arch::SYS_OPENAT2 as libc::c_long;

/// RESOLVE_IN_ROOT: treat the dirfd as the filesystem root for resolution.
const RESOLVE_IN_ROOT: u64 = 0x10;

/// Kernel `struct open_how` for openat2().
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn last_errno(fallback: i32) -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(fallback)
}

/// Open a path confined within `root` using `openat2(RESOLVE_IN_ROOT)`.
///
/// The kernel handles symlink resolution, `..` traversal, and prevents
/// escapes above the root, eliminating TOCTOU races and the edge cases
/// inherent in userspace path walking.
pub(crate) fn openat2_in_root(
    root: &Path,
    path: &str,
    flags: i32,
    mode: u32,
) -> Result<RawFd, i32> {
    let c_root = CString::new(root.to_str().unwrap_or("")).map_err(|_| libc::EINVAL)?;
    let root_fd = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(last_errno(libc::EIO));
    }

    let rel_path = path.strip_prefix('/').unwrap_or(path);
    let rel_path = if rel_path.is_empty() { "." } else { rel_path };
    let c_path = CString::new(rel_path).map_err(|_| {
        unsafe { libc::close(root_fd) };
        libc::EINVAL
    })?;

    let how = OpenHow {
        flags: flags as u64,
        mode: mode as u64,
        resolve: RESOLVE_IN_ROOT,
    };

    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            root_fd,
            c_path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;

    unsafe { libc::close(root_fd) };

    if fd < 0 {
        Err(last_errno(libc::ENOENT))
    } else {
        Ok(fd)
    }
}

/// Empty C string for the `AT_EMPTY_PATH` family of calls (operate on the fd).
const EMPTY: *const libc::c_char = b"\0".as_ptr() as *const libc::c_char;

/// Open a confined `O_PATH` handle to `path` under `root`.
///
/// `O_PATH` needs no read permission and does no I/O, so it is the right
/// handle for metadata operations. `RESOLVE_IN_ROOT` confines every component
/// of the walk to `root`. When `follow` is false the final component is opened
/// with `O_NOFOLLOW`, yielding a handle to the symlink itself (lstat
/// semantics); when true the final symlink is followed, but still confined.
fn opath_in_root(root: &Path, path: &str, follow: bool) -> Result<RawFd, i32> {
    let mut flags = libc::O_PATH | libc::O_CLOEXEC;
    if !follow {
        flags |= libc::O_NOFOLLOW;
    }
    openat2_in_root(root, path, flags, 0)
}

/// `stat`/`lstat` a path confined within `root`.
///
/// `follow` selects `stat` (follow the final symlink) vs `lstat` (stat the
/// link itself) semantics for the final component; intermediate components are
/// always confined to `root`.
pub(crate) fn statat_in_root(root: &Path, path: &str, follow: bool) -> Result<libc::stat, i32> {
    let fd = opath_in_root(root, path, follow)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(fd, EMPTY, &mut st, libc::AT_EMPTY_PATH) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(st)
    }
}

/// `statx` a path confined within `root`, writing the raw `struct statx` into
/// `buf` (must be at least `sizeof(struct statx)`, 256 bytes). The child's
/// `AT_SYMLINK_NOFOLLOW` in `flags` selects follow vs nofollow; other `flags`
/// bits (sync hints) are preserved.
pub(crate) fn statx_in_root(
    root: &Path,
    path: &str,
    flags: i32,
    mask: u32,
    buf: &mut [u8],
) -> Result<(), i32> {
    // The kernel writes sizeof(struct statx) = 256 bytes; refuse a short buffer
    // rather than risk a heap overflow if a future caller passes a smaller one.
    if buf.len() < 256 {
        return Err(libc::EINVAL);
    }
    let follow = (flags & libc::AT_SYMLINK_NOFOLLOW) == 0;
    let fd = opath_in_root(root, path, follow)?;
    // statx the handle itself via AT_EMPTY_PATH; follow/nofollow is already
    // baked into how the fd was opened, so drop AT_SYMLINK_NOFOLLOW here.
    let stx_flags = (flags & !libc::AT_SYMLINK_NOFOLLOW) | libc::AT_EMPTY_PATH;
    let rc = unsafe {
        libc::syscall(libc::SYS_statx, fd, EMPTY, stx_flags, mask, buf.as_mut_ptr())
    };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Set timestamps on a path confined within `root`.
///
/// Resolves a confined `O_PATH` handle, then stamps it through its
/// `/proc/self/fd/N` magic link. The kernel cannot take an `O_PATH` fd
/// directly for `utimensat` (EBADF), but the magic link jumps straight to the
/// already-confined inode, so resolution cannot escape. `follow` selects
/// whether the final symlink is followed or stamped in place (baked into how
/// the handle is opened).
pub(crate) fn utimensat_in_root(
    root: &Path,
    path: &str,
    times: *const libc::timespec,
    follow: bool,
) -> Result<(), i32> {
    let fd = opath_in_root(root, path, follow)?;
    let proc = CString::new(format!("/proc/self/fd/{}", fd)).map_err(|_| {
        unsafe { libc::close(fd) };
        libc::EINVAL
    })?;
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, proc.as_ptr(), times, 0) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Read a symlink's target confined within `root`. Returns the raw target
/// bytes. `Err(EINVAL)` means the final component is not a symlink.
pub(crate) fn readlink_in_root(root: &Path, path: &str) -> Result<Vec<u8>, i32> {
    // O_PATH|O_NOFOLLOW opens the link itself; readlinkat with an empty path
    // then reads its target. The parent walk is confined to root.
    let fd = opath_in_root(root, path, false)?;
    let mut buf = vec![0u8; 4096];
    let n = unsafe {
        libc::readlinkat(fd, EMPTY, buf.as_mut_ptr() as *mut libc::c_char, buf.len())
    };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if n < 0 {
        return Err(err);
    }
    buf.truncate(n as usize);
    Ok(buf)
}

// ============================================================
// Confined mutating operations (write side, issue #112)
//
// Every upper-layer mutation must resolve its target's PARENT confined to the
// layer root, then act via an `*at` call on the basename. A verbatim-copied
// symlink in upper must never let `create_dir_all`/`File::create`/`symlink`/
// `rename`/`unlink` follow out of the tree and write/delete on the host.
// ============================================================

/// Split a relative path into (parent, basename). Parent is "" when `rel` is a
/// single component (meaning the root itself).
fn split_rel(rel: &str) -> (&str, &str) {
    let rel = rel.trim_matches('/');
    match rel.rfind('/') {
        Some(i) => (&rel[..i], &rel[i + 1..]),
        None => ("", rel),
    }
}

/// Open a confined `O_PATH|O_DIRECTORY` handle to the PARENT of `rel` under
/// `root`, returning (parent_fd, basename). The parent must already exist;
/// `RESOLVE_IN_ROOT` clamps any symlink/`..` in the parent walk to `root`.
fn parent_dir_in_root(root: &Path, rel: &str) -> Result<(RawFd, String), i32> {
    let (parent, base) = split_rel(rel);
    if base.is_empty() || base == "." || base == ".." {
        return Err(libc::EINVAL);
    }
    let parent = if parent.is_empty() { "." } else { parent };
    let fd = openat2_in_root(root, parent, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC, 0)?;
    Ok((fd, base.to_string()))
}

/// `mkdir` a single component confined within `root` (parent must exist).
pub(crate) fn mkdir_in_root(root: &Path, rel: &str, mode: u32) -> Result<(), i32> {
    let (pfd, base) = parent_dir_in_root(root, rel)?;
    let cbase = CString::new(base).map_err(|_| {
        unsafe { libc::close(pfd) };
        libc::EINVAL
    })?;
    let rc = unsafe { libc::mkdirat(pfd, cbase.as_ptr(), mode as libc::mode_t) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(pfd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// `mkdir -p` confined within `root`. Each level is created via `mkdir_in_root`,
/// so a symlinked parent component is clamped to the root and cannot escape.
pub(crate) fn mkdirp_in_root(root: &Path, rel: &str, mode: u32) -> Result<(), i32> {
    let mut prefix = String::new();
    for comp in rel.split('/').filter(|c| !c.is_empty() && *c != ".") {
        if comp == ".." {
            return Err(libc::EINVAL);
        }
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(comp);
        match mkdir_in_root(root, &prefix, mode) {
            Ok(()) | Err(libc::EEXIST) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Create a symlink `rel -> target` confined within `root` (parent must exist).
pub(crate) fn symlinkat_in_root(root: &Path, rel: &str, target: &str) -> Result<(), i32> {
    let (pfd, base) = parent_dir_in_root(root, rel)?;
    let cbase = CString::new(base).ok();
    let ctarget = CString::new(target).ok();
    let (cbase, ctarget) = match (cbase, ctarget) {
        (Some(b), Some(t)) => (b, t),
        _ => {
            unsafe { libc::close(pfd) };
            return Err(libc::EINVAL);
        }
    };
    let rc = unsafe { libc::symlinkat(ctarget.as_ptr(), pfd, cbase.as_ptr()) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(pfd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Unlink a file (or rmdir an empty dir) confined within `root`.
pub(crate) fn unlinkat_in_root(root: &Path, rel: &str, remove_dir: bool) -> Result<(), i32> {
    let (pfd, base) = parent_dir_in_root(root, rel)?;
    let cbase = CString::new(base).map_err(|_| {
        unsafe { libc::close(pfd) };
        libc::EINVAL
    })?;
    let flag = if remove_dir { libc::AT_REMOVEDIR } else { 0 };
    let rc = unsafe { libc::unlinkat(pfd, cbase.as_ptr(), flag) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(pfd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Recursively remove a directory tree confined within `root`. Each descent
/// uses `O_NOFOLLOW`, so a symlink entry is unlinked (never traversed).
pub(crate) fn remove_dir_all_in_root(root: &Path, rel: &str) -> Result<(), i32> {
    // Open the target directory itself confined, without following a final
    // symlink, then empty it via the dirfd before removing the now-empty dir.
    let dir_fd = openat2_in_root(
        root,
        rel,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    remove_dir_contents(dir_fd); // consumes/closes dir_fd
    unlinkat_in_root(root, rel, true)
}

/// Empty a directory referred to by `dir_fd` (which this function takes
/// ownership of and closes), recursing into subdirectories via `O_NOFOLLOW`.
fn remove_dir_contents(dir_fd: RawFd) {
    // fdopendir takes ownership of dir_fd; closedir closes it.
    let dirp = unsafe { libc::fdopendir(dir_fd) };
    if dirp.is_null() {
        unsafe { libc::close(dir_fd) };
        return;
    }
    loop {
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        let name_ptr = unsafe { (*ent).d_name.as_ptr() };
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        // Is this entry a directory (without following a symlink)?
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let is_dir = unsafe {
            libc::fstatat(
                libc::dirfd(dirp),
                name_ptr,
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            ) == 0
        } && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        if is_dir {
            let child = unsafe {
                libc::openat(
                    libc::dirfd(dirp),
                    name_ptr,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if child >= 0 {
                remove_dir_contents(child);
            }
            unsafe { libc::unlinkat(libc::dirfd(dirp), name_ptr, libc::AT_REMOVEDIR) };
        } else {
            unsafe { libc::unlinkat(libc::dirfd(dirp), name_ptr, 0) };
        }
    }
    unsafe { libc::closedir(dirp) };
}

/// Rename `old_rel` to `new_rel`, both confined within `root`.
pub(crate) fn renameat_in_root(root: &Path, old_rel: &str, new_rel: &str) -> Result<(), i32> {
    let (opfd, ob) = parent_dir_in_root(root, old_rel)?;
    let (npfd, nb) = match parent_dir_in_root(root, new_rel) {
        Ok(v) => v,
        Err(e) => {
            unsafe { libc::close(opfd) };
            return Err(e);
        }
    };
    let close_both = || unsafe {
        libc::close(opfd);
        libc::close(npfd);
    };
    let (cob, cnb) = match (CString::new(ob), CString::new(nb)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => {
            close_both();
            return Err(libc::EINVAL);
        }
    };
    let rc = unsafe { libc::renameat(opfd, cob.as_ptr(), npfd, cnb.as_ptr()) };
    let err = last_errno(libc::EIO);
    close_both();
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// Create a hard link `new_rel -> old_rel` confined within `root`. The old path
/// is not dereferenced (no `AT_SYMLINK_FOLLOW`).
pub(crate) fn linkat_in_root(root: &Path, old_rel: &str, new_rel: &str) -> Result<(), i32> {
    let (opfd, ob) = parent_dir_in_root(root, old_rel)?;
    let (npfd, nb) = match parent_dir_in_root(root, new_rel) {
        Ok(v) => v,
        Err(e) => {
            unsafe { libc::close(opfd) };
            return Err(e);
        }
    };
    let close_both = || unsafe {
        libc::close(opfd);
        libc::close(npfd);
    };
    let (cob, cnb) = match (CString::new(ob), CString::new(nb)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => {
            close_both();
            return Err(libc::EINVAL);
        }
    };
    let rc = unsafe { libc::linkat(opfd, cob.as_ptr(), npfd, cnb.as_ptr(), 0) };
    let err = last_errno(libc::EIO);
    close_both();
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// `chmod` a path confined within `root`, following the final symlink (as
/// `chmod` does) but never escaping the root. Operates through the confined
/// `O_PATH` handle's `/proc/self/fd` magic link.
pub(crate) fn chmod_in_root(root: &Path, rel: &str, mode: u32) -> Result<(), i32> {
    let fd = opath_in_root(root, rel, true)?;
    let proc = CString::new(format!("/proc/self/fd/{}", fd)).map_err(|_| {
        unsafe { libc::close(fd) };
        libc::EINVAL
    })?;
    let rc = unsafe { libc::chmod(proc.as_ptr(), mode as libc::mode_t) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

/// `chown` a path confined within `root`, following the final symlink (as
/// `chown` does) but never escaping the root, via the confined `O_PATH`
/// handle's `/proc/self/fd` magic link.
pub(crate) fn chown_in_root(root: &Path, rel: &str, uid: u32, gid: u32) -> Result<(), i32> {
    let fd = opath_in_root(root, rel, true)?;
    let proc = CString::new(format!("/proc/self/fd/{}", fd)).map_err(|_| {
        unsafe { libc::close(fd) };
        libc::EINVAL
    })?;
    let rc = unsafe { libc::chown(proc.as_ptr(), uid, gid) };
    let err = last_errno(libc::EIO);
    unsafe { libc::close(fd) };
    if rc < 0 {
        Err(err)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn openat2_in_root_confines_absolute_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/shadow"), "confined").unwrap();
        // Absolute symlink to the host /etc/shadow: kernel keeps it in root.
        symlink("/etc/shadow", root.join("evil")).unwrap();

        match openat2_in_root(root, "/evil", libc::O_PATH, 0) {
            Ok(fd) => {
                let resolved =
                    std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
                unsafe { libc::close(fd) };
                assert!(resolved.starts_with(root), "escaped root: {:?}", resolved);
            }
            Err(libc::ENOSYS) => {} // kernel without openat2
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn openat2_in_root_clamps_parent_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        match openat2_in_root(root, "/../../../etc/group", libc::O_PATH, 0) {
            Err(libc::ENOENT) => {} // clamped to <root>/etc/group, absent
            Err(libc::ENOSYS) => {}
            Ok(fd) => {
                let resolved =
                    std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
                unsafe { libc::close(fd) };
                assert!(resolved.starts_with(root), "escaped root: {:?}", resolved);
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    // Skip a test body cleanly on kernels without openat2.
    macro_rules! skip_if_nosys {
        ($e:expr) => {
            match $e {
                Err(libc::ENOSYS) => return,
                other => other,
            }
        };
    }

    #[test]
    fn statat_lstat_does_not_follow_escaping_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        symlink("/etc/group", root.join("evil")).unwrap();

        // lstat: stat the link itself, confined; must report a symlink, never
        // the host /etc/group it points at.
        let st = skip_if_nosys!(statat_in_root(root, "evil", false)).unwrap();
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFLNK, "expected a symlink");

        // stat (follow): the absolute target is clamped to <root>/etc/group,
        // which does not exist, so the host file is never reached.
        assert_eq!(statat_in_root(root, "evil", true), Err(libc::ENOENT));
    }

    #[test]
    fn statat_confines_symlinked_parent() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        symlink("/etc", root.join("dirlink")).unwrap();
        // dirlink/group would be /etc/group on the host; confined it is absent.
        assert_eq!(
            skip_if_nosys!(statat_in_root(root, "dirlink/group", true)),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn readlink_confined_reads_in_tree_link_but_not_through_escaping_parent() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        symlink("/etc/group", root.join("evil")).unwrap();
        symlink("/etc", root.join("dirlink")).unwrap();

        // The link's own target string is the child's data: returning it is fine.
        let target = skip_if_nosys!(readlink_in_root(root, "evil")).unwrap();
        assert_eq!(target, b"/etc/group");

        // But a link reached through an escaping parent is not visible.
        assert_eq!(readlink_in_root(root, "dirlink/group"), Err(libc::ENOENT));
    }

    #[test]
    fn utimensat_confined_stamps_in_tree_and_refuses_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("f"), "x").unwrap();
        symlink("/etc", root.join("dirlink")).unwrap();

        let times = [
            libc::timespec { tv_sec: 1_000_000, tv_nsec: 0 },
            libc::timespec { tv_sec: 1_000_000, tv_nsec: 0 },
        ];
        // In-tree file: stamp succeeds and takes effect.
        skip_if_nosys!(utimensat_in_root(root, "f", times.as_ptr(), true)).unwrap();
        let meta = std::fs::metadata(root.join("f")).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(meta.mtime(), 1_000_000);

        // Escaping parent: refused, so the host /etc/group is never stamped.
        assert_eq!(
            utimensat_in_root(root, "dirlink/group", times.as_ptr(), true),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn statx_confines_symlinked_parent() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("f"), "data").unwrap();
        symlink("/etc", root.join("dirlink")).unwrap();
        let mut buf = vec![0u8; 256];

        // In-tree file resolves; escaping parent does not.
        skip_if_nosys!(statx_in_root(root, "f", 0, libc::STATX_BASIC_STATS, &mut buf)).unwrap();
        assert_eq!(
            statx_in_root(root, "dirlink/group", 0, libc::STATX_BASIC_STATS, &mut buf),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn mkdirp_creates_in_tree_and_refuses_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        if mkdirp_in_root(root, "a/b/c", 0o755) == Err(libc::ENOSYS) {
            return;
        }
        assert!(root.join("a/b/c").is_dir());

        // Under an escaping symlinked parent: refused, and nothing created on host.
        symlink("/etc", root.join("evil")).unwrap();
        let r = mkdirp_in_root(root, "evil/sandlock_escape_probe", 0o755);
        assert!(matches!(r, Err(libc::ENOENT)), "got {:?}", r);
        assert!(!std::path::Path::new("/etc/sandlock_escape_probe").exists());
    }

    #[test]
    fn symlinkat_creates_in_tree_and_refuses_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        if mkdirp_in_root(root, "d", 0o755) == Err(libc::ENOSYS) {
            return;
        }
        symlinkat_in_root(root, "d/link", "target").unwrap();
        assert_eq!(
            std::fs::read_link(root.join("d/link")).unwrap(),
            std::path::Path::new("target")
        );

        symlink("/etc", root.join("evil")).unwrap();
        let r = symlinkat_in_root(root, "evil/sandlock_escape_link", "x");
        assert!(matches!(r, Err(libc::ENOENT)), "got {:?}", r);
        assert!(!std::path::Path::new("/etc/sandlock_escape_link").is_symlink());
    }

    #[test]
    fn unlinkat_and_rename_in_tree() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        if mkdirp_in_root(root, "d", 0o755) == Err(libc::ENOSYS) {
            return;
        }
        std::fs::write(root.join("d/old"), "v").unwrap();
        renameat_in_root(root, "d/old", "d/new").unwrap();
        assert!(!root.join("d/old").exists());
        assert_eq!(std::fs::read_to_string(root.join("d/new")).unwrap(), "v");
        unlinkat_in_root(root, "d/new", false).unwrap();
        assert!(!root.join("d/new").exists());
    }

    #[test]
    fn remove_dir_all_does_not_follow_symlink_entries() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("keep.txt"), "important").unwrap();
        if mkdirp_in_root(root, "a", 0o755) == Err(libc::ENOSYS) {
            return;
        }
        std::fs::write(root.join("a/file.txt"), "x").unwrap();
        symlink(outside.path(), root.join("a/lnk")).unwrap();

        remove_dir_all_in_root(root, "a").unwrap();
        assert!(!root.join("a").exists(), "tree not removed");
        // The symlink entry was unlinked, never traversed: outside survives.
        assert!(
            outside.path().join("keep.txt").exists(),
            "recursive remove followed a symlink out of the tree"
        );
    }

    #[test]
    fn chmod_in_tree_and_refuses_escape() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("f"), "x").unwrap();
        if chmod_in_root(root, "f", 0o600) == Err(libc::ENOSYS) {
            return;
        }
        assert_eq!(
            std::fs::metadata(root.join("f")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        symlink("/etc", root.join("evil")).unwrap();
        assert!(matches!(
            chmod_in_root(root, "evil/group", 0o777),
            Err(libc::ENOENT)
        ));
    }
}
