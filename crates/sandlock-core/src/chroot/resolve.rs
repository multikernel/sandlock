use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

/// Collapse `..` components clamping at `/` (pivot_root semantics).
/// Always returns an absolute path under `/`.
pub fn confine(virtual_path: &str) -> PathBuf {
    let mut components: Vec<&str> = Vec::new();

    // Split on '/' and process each component
    for part in virtual_path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            other => {
                components.push(other);
            }
        }
    }

    let mut result = PathBuf::from("/");
    for c in components {
        result.push(c);
    }
    result
}

/// Strip chroot root prefix from host path.
/// Returns None if host path is not under chroot root.
pub fn to_virtual_path(chroot_root: &Path, host_path: &Path) -> Option<PathBuf> {
    host_path
        .strip_prefix(chroot_root)
        .ok()
        .map(|rel| PathBuf::from("/").join(rel))
}

// ============================================================
// openat2(RESOLVE_IN_ROOT) based resolution
// ============================================================

/// openat2 syscall number (same on x86_64 and aarch64).
const SYS_OPENAT2: libc::c_long = 437;

/// RESOLVE_IN_ROOT — treat the dirfd as the filesystem root for resolution.
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

/// Open a path confined within `chroot_root` using `openat2(RESOLVE_IN_ROOT)`.
///
/// The kernel handles symlink resolution, `..` traversal, and prevents
/// escapes above the root — eliminating TOCTOU races and edge cases
/// inherent in userspace path walking.
pub fn openat2_in_root(
    chroot_root: &Path,
    path: &str,
    flags: i32,
    mode: u32,
) -> Result<RawFd, i32> {
    let c_root =
        CString::new(chroot_root.to_str().unwrap_or("")).map_err(|_| libc::EINVAL)?;
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
    // Empty path means the root itself — use "."
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

/// Resolve a virtual path within the chroot using `openat2(RESOLVE_IN_ROOT)`.
///
/// The kernel resolves all symlinks and `..` components, keeping the result
/// confined to `chroot_root`.  Returns `(host_path, virtual_path)`.
///
/// For paths whose final component does not yet exist (e.g. `O_CREAT` targets),
/// the parent directory is resolved and the filename is appended.
///
/// Self-referential symlinks (e.g. `rootfs/bin → /bin`) return `ELOOP` and
/// are treated as resolution failures — such rootfs layouts are unsupported.
pub fn resolve_in_root(chroot_root: &Path, child_path: &str) -> Option<(PathBuf, PathBuf)> {
    if let Some(result) = resolve_existing_in_root(chroot_root, child_path) {
        return Some(result);
    }

    // Full path doesn't exist — resolve parent directory and append the
    // missing filename.  This is needed for O_CREAT targets where the
    // final component will be created.
    let confined = confine(child_path);
    let file_name = confined.file_name()?;
    let parent = confined.parent().unwrap_or(Path::new("/"));

    match openat2_in_root(
        chroot_root,
        parent.to_str()?,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    ) {
        Ok(fd) => {
            let parent_host = std::fs::read_link(format!("/proc/self/fd/{}", fd)).ok();
            unsafe { libc::close(fd) };
            let parent_host = parent_host?;
            let host_path = parent_host.join(file_name);
            let parent_virtual = to_virtual_path(chroot_root, &parent_host)?;
            let virtual_path = parent_virtual.join(file_name);
            Some((host_path, virtual_path))
        }
        Err(_) => None,
    }
}

/// Resolve a virtual path that must already exist within the chroot.
///
/// Unlike [`resolve_in_root`], this does NOT fall back to parent resolution
/// when the path doesn't exist. The kernel resolves all symlinks confined to
/// `chroot_root`, so the returned host path is always fully resolved — no
/// dangling symlinks that could escape the chroot when followed by the host.
///
/// Use this for read-only lookups (stat, access, readlink) where the file
/// must already exist.
pub fn resolve_existing_in_root(chroot_root: &Path, child_path: &str) -> Option<(PathBuf, PathBuf)> {
    match openat2_in_root(
        chroot_root,
        child_path,
        libc::O_PATH | libc::O_CLOEXEC,
        0,
    ) {
        Ok(fd) => {
            let host_path = std::fs::read_link(format!("/proc/self/fd/{}", fd)).ok();
            unsafe { libc::close(fd) };
            let host_path = host_path?;
            let virtual_path = to_virtual_path(chroot_root, &host_path)?;
            Some((host_path, virtual_path))
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn test_confine_absolute() {
        assert_eq!(confine("/etc/os-release"), PathBuf::from("/etc/os-release"));
    }

    #[test]
    fn test_confine_dotdot_at_root() {
        assert_eq!(confine("/../../etc/os-release"), PathBuf::from("/etc/os-release"));
    }

    #[test]
    fn test_confine_many_dotdots() {
        assert_eq!(confine("/../../../../../.."), PathBuf::from("/"));
    }

    #[test]
    fn test_confine_relative() {
        assert_eq!(confine("usr/bin/python"), PathBuf::from("/usr/bin/python"));
    }

    #[test]
    fn test_confine_dot() {
        assert_eq!(confine("/usr/./bin/../lib"), PathBuf::from("/usr/lib"));
    }

    #[test]
    fn test_to_virtual_path() {
        assert_eq!(
            to_virtual_path(Path::new("/rootfs"), Path::new("/rootfs/etc/os-release")),
            Some(PathBuf::from("/etc/os-release"))
        );
    }

    #[test]
    fn test_to_virtual_path_outside() {
        assert_eq!(
            to_virtual_path(Path::new("/rootfs"), Path::new("/other/path")),
            None
        );
    }

    #[test]
    fn test_confine_escape_attempt() {
        // Deeply nested .. should always clamp at /
        assert_eq!(
            confine("/a/b/c/../../../../../../../../etc/shadow"),
            PathBuf::from("/etc/shadow")
        );
    }

    // ============================================================
    // openat2 / resolve_in_root tests
    // ============================================================

    #[test]
    fn test_openat2_in_root_regular_file() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/os-release"), "ID=test\n").unwrap();

        let fd = openat2_in_root(root, "/etc/os-release", libc::O_RDONLY, 0);
        match fd {
            Ok(fd) => unsafe { libc::close(fd) },
            Err(libc::ENOSYS) => return, // kernel too old
            Err(e) => panic!("unexpected error: {}", e),
        };
    }

    #[test]
    fn test_openat2_in_root_blocks_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("a")).unwrap();

        let fd = openat2_in_root(root, "/../../../etc/os-release", libc::O_PATH, 0);
        match fd {
            // RESOLVE_IN_ROOT clamps ".." at the root, so this resolves
            // to <root>/etc/os-release which doesn't exist → ENOENT.
            Err(libc::ENOENT) => {}
            Err(libc::ENOSYS) => return,
            Ok(fd) => {
                // If it succeeds, the resolved path must be under root.
                let resolved = std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
                unsafe { libc::close(fd) };
                assert!(
                    resolved.starts_with(root),
                    "escaped chroot: {:?}",
                    resolved
                );
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn test_openat2_in_root_symlink_confined() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/shadow"), "confined").unwrap();
        // Absolute symlink pointing to /etc/shadow — kernel keeps it
        // confined to root.
        symlink("/etc/shadow", root.join("evil")).unwrap();

        let fd = openat2_in_root(root, "/evil", libc::O_PATH, 0);
        match fd {
            Ok(fd) => {
                let resolved = std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap();
                unsafe { libc::close(fd) };
                assert!(resolved.starts_with(root));
                assert!(resolved.ends_with("etc/shadow"));
            }
            Err(libc::ENOSYS) => return,
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn test_resolve_in_root_no_symlinks() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/hello"), "").unwrap();

        let result = resolve_in_root(root, "/usr/bin/hello");
        assert!(result.is_some());
        let (host, virt) = result.unwrap();
        assert_eq!(virt, PathBuf::from("/usr/bin/hello"));
        assert!(host.starts_with(root));
    }

    #[test]
    fn test_resolve_in_root_with_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("usr/lib64")).unwrap();
        std::fs::write(root.join("usr/lib64/foo"), "").unwrap();
        symlink("/usr/lib64", root.join("lib")).unwrap();

        let result = resolve_in_root(root, "/lib/foo");
        assert!(result.is_some());
        let (host, virt) = result.unwrap();
        assert_eq!(virt, PathBuf::from("/usr/lib64/foo"));
        assert!(host.starts_with(root));
    }

    #[test]
    fn test_resolve_in_root_nonexistent_file() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("tmp")).unwrap();

        // File doesn't exist but parent does — should resolve via parent.
        let result = resolve_in_root(root, "/tmp/newfile");
        assert!(result.is_some());
        let (host, virt) = result.unwrap();
        assert_eq!(virt, PathBuf::from("/tmp/newfile"));
        assert!(host.ends_with("tmp/newfile"));
    }

    #[test]
    fn test_resolve_in_root_escape_via_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/shadow"), "confined").unwrap();
        // Symlink to absolute path — must stay confined.
        symlink("/etc/shadow", root.join("evil")).unwrap();

        let result = resolve_in_root(root, "/evil");
        assert!(result.is_some());
        let (host, virt) = result.unwrap();
        assert_eq!(virt, PathBuf::from("/etc/shadow"));
        assert!(host.starts_with(root));
    }

    #[test]
    fn test_resolve_in_root_dotdot_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("a")).unwrap();

        let result = resolve_in_root(root, "/a/../../etc/os-release");
        // Either resolves within root or returns None — never escapes.
        if let Some((host, _)) = result {
            assert!(host.starts_with(root));
        }
    }

    #[test]
    fn test_resolve_in_root_root_path() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        let result = resolve_in_root(root, "/");
        assert!(result.is_some());
        let (host, virt) = result.unwrap();
        assert_eq!(virt, PathBuf::from("/"));
        assert_eq!(host, root);
    }

    #[test]
    fn test_resolve_existing_follows_symlink() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("usr/local/bin")).unwrap();
        std::fs::write(root.join("usr/local/bin/python3.12"), "binary").unwrap();
        symlink("python3.12", root.join("usr/local/bin/python3")).unwrap();

        // resolve_existing_in_root should follow the symlink and return
        // the resolved target path, not the symlink itself.
        let result = resolve_existing_in_root(root, "/usr/local/bin/python3");
        match result {
            Some((host, virt)) => {
                assert!(host.starts_with(root));
                assert!(host.ends_with("python3.12"),
                    "host path should be resolved through symlink: {:?}", host);
                assert_eq!(virt, PathBuf::from("/usr/local/bin/python3.12"));
            }
            None => {
                // openat2 not available on this kernel — skip
            }
        }
    }

    #[test]
    fn test_resolve_existing_absolute_symlink_confined() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/bin/python3.12"), "binary").unwrap();
        std::fs::create_dir_all(root.join("usr/local/bin")).unwrap();
        // Absolute symlink — must stay confined to chroot root.
        symlink("/usr/bin/python3.12", root.join("usr/local/bin/python3")).unwrap();

        let result = resolve_existing_in_root(root, "/usr/local/bin/python3");
        match result {
            Some((host, virt)) => {
                assert!(host.starts_with(root),
                    "absolute symlink must not escape chroot: {:?}", host);
                assert!(host.ends_with("usr/bin/python3.12"));
                assert_eq!(virt, PathBuf::from("/usr/bin/python3.12"));
            }
            None => {
                // openat2 not available — skip
            }
        }
    }

    #[test]
    fn test_resolve_existing_returns_none_for_missing() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();

        let result = resolve_existing_in_root(root, "/usr/bin/nonexistent");
        // openat2 may not be available, but if it is, missing file → None
        if resolve_existing_in_root(root, "/usr/bin").is_some() {
            assert!(result.is_none());
        }
    }
}
