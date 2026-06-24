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
}
