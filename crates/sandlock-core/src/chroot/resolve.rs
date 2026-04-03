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

/// Prepend chroot root to virtual path.
/// e.g. `/etc/passwd` with root `/rootfs` -> `/rootfs/etc/passwd`
pub fn to_host_path(chroot_root: &Path, virtual_path: &Path) -> PathBuf {
    let stripped = virtual_path
        .strip_prefix("/")
        .unwrap_or(virtual_path.as_ref());
    chroot_root.join(stripped)
}

/// Strip chroot root prefix from host path.
/// Returns None if host path is not under chroot root.
pub fn to_virtual_path(chroot_root: &Path, host_path: &Path) -> Option<PathBuf> {
    host_path
        .strip_prefix(chroot_root)
        .ok()
        .map(|rel| PathBuf::from("/").join(rel))
}

/// Maximum depth for symlink resolution to prevent ELOOP.
const MAX_SYMLINK_DEPTH: u32 = 40;

/// Resolve a symlink target within the chroot.
/// Absolute targets are treated as relative to chroot root.
/// Follows chains up to MAX_SYMLINK_DEPTH. Returns None on ELOOP.
fn resolve_symlink(chroot_root: &Path, link_virtual_path: &Path, depth: u32) -> Option<PathBuf> {
    if depth >= MAX_SYMLINK_DEPTH {
        return None;
    }

    let host_path = to_host_path(chroot_root, link_virtual_path);
    let target = std::fs::read_link(&host_path).ok()?;

    let virtual_target = if target.is_absolute() {
        confine(target.to_str().unwrap_or("/"))
    } else {
        let parent = link_virtual_path.parent().unwrap_or(Path::new("/"));
        let combined = parent.join(&target);
        confine(combined.to_str().unwrap_or("/"))
    };

    // If the confined target points back to the same virtual path, the
    // symlink is self-referential after confinement (e.g. rootfs/usr -> /usr).
    // Treat it as passthrough — the kernel will follow the host symlink and
    // Landlock constrains the actual access.
    if virtual_target == link_virtual_path {
        return Some(virtual_target);
    }

    let host_target = to_host_path(chroot_root, &virtual_target);
    if host_target.symlink_metadata().ok()?.file_type().is_symlink() {
        resolve_symlink(chroot_root, &virtual_target, depth + 1)
    } else {
        Some(virtual_target)
    }
}

/// Confine path then follow symlinks along each component, re-confining
/// absolute targets so they stay inside the chroot.  Returns the final
/// virtual path or None on ELOOP.
pub fn resolve_full(chroot_root: &Path, child_path: &str) -> Option<PathBuf> {
    let confined = confine(child_path);

    let mut current = PathBuf::from("/");
    let components: Vec<_> = confined
        .strip_prefix("/")
        .unwrap_or(confined.as_ref())
        .iter()
        .collect();

    for component in components {
        current.push(component);

        let host_path = to_host_path(chroot_root, &current);
        match host_path.symlink_metadata() {
            Ok(meta) if meta.file_type().is_symlink() => {
                match resolve_symlink(chroot_root, &current, 0) {
                    Some(resolved) => current = resolved,
                    None => return None,
                }
            }
            _ => {}
        }
    }

    Some(current)
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
/// On `ELOOP` (self-referential symlinks like `rootfs/bin → /bin`), falls back
/// to the manual [`resolve_full`] which has explicit loop-detection for this.
pub fn resolve_in_root(chroot_root: &Path, child_path: &str) -> Option<(PathBuf, PathBuf)> {
    // Try resolving the full path.
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
            return Some((host_path, virtual_path));
        }
        Err(libc::ELOOP) => {
            // Self-referential symlinks (e.g. rootfs/bin → /bin) that
            // the kernel can't resolve under RESOLVE_IN_ROOT — the
            // manual resolver has explicit loop-detection for this.
            let virtual_path = resolve_full(chroot_root, child_path)?;
            let host_path = to_host_path(chroot_root, &virtual_path);
            return Some((host_path, virtual_path));
        }
        Err(libc::ENOENT) | Err(libc::ENOTDIR) => {
            // Final component doesn't exist — resolve the parent instead.
        }
        Err(_) => return None,
    }

    // Resolve parent directory, then append the missing filename.
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
        Err(libc::ELOOP) => {
            let virtual_path = resolve_full(chroot_root, child_path)?;
            let host_path = to_host_path(chroot_root, &virtual_path);
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
        assert_eq!(confine("/etc/passwd"), PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn test_confine_dotdot_at_root() {
        assert_eq!(confine("/../../etc/passwd"), PathBuf::from("/etc/passwd"));
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
    fn test_to_host_path() {
        assert_eq!(
            to_host_path(Path::new("/rootfs"), Path::new("/etc/passwd")),
            PathBuf::from("/rootfs/etc/passwd")
        );
    }

    #[test]
    fn test_to_host_path_root() {
        assert_eq!(
            to_host_path(Path::new("/rootfs"), Path::new("/")),
            PathBuf::from("/rootfs")
        );
    }

    #[test]
    fn test_to_virtual_path() {
        assert_eq!(
            to_virtual_path(Path::new("/rootfs"), Path::new("/rootfs/etc/passwd")),
            Some(PathBuf::from("/etc/passwd"))
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
    fn test_resolve_symlink_absolute_target() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/passwd"), "root:x:0:0").unwrap();

        // /link -> /etc/passwd (absolute symlink confined to chroot)
        symlink("/etc/passwd", root.join("link")).unwrap();

        let result = resolve_symlink(root, Path::new("/link"), 0);
        assert_eq!(result, Some(PathBuf::from("/etc/passwd")));
    }

    #[test]
    fn test_resolve_symlink_relative_target() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        std::fs::create_dir_all(root.join("usr/lib64")).unwrap();
        std::fs::write(root.join("usr/lib64/libc.so"), "").unwrap();

        // /usr/lib64/libc.so.6 -> libc.so (relative symlink)
        symlink("libc.so", root.join("usr/lib64/libc.so.6")).unwrap();

        let result = resolve_symlink(root, Path::new("/usr/lib64/libc.so.6"), 0);
        assert_eq!(result, Some(PathBuf::from("/usr/lib64/libc.so")));
    }

    #[test]
    fn test_resolve_full_no_symlinks() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/passwd"), "root:x:0:0").unwrap();

        let result = resolve_full(root, "/etc/passwd");
        assert_eq!(result, Some(PathBuf::from("/etc/passwd")));
    }

    #[test]
    fn test_resolve_full_with_symlink_component() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        std::fs::create_dir_all(root.join("usr/lib64")).unwrap();
        std::fs::write(root.join("usr/lib64/foo"), "").unwrap();

        // /lib -> /usr/lib64 (absolute symlink in path component)
        symlink("/usr/lib64", root.join("lib")).unwrap();

        let result = resolve_full(root, "/lib/foo");
        assert_eq!(result, Some(PathBuf::from("/usr/lib64/foo")));
    }

    #[test]
    fn test_resolve_full_absolute_symlink_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Symlink pointing to absolute host path — resolve_full must
        // re-confine it within the chroot rather than following it to
        // the real host filesystem.
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/shadow"), "confined").unwrap();
        symlink("/etc/shadow", root.join("evil")).unwrap();

        let result = resolve_full(root, "/evil");
        assert_eq!(result, Some(PathBuf::from("/etc/shadow")));
        // The host_path must be under the chroot root
        let host = to_host_path(root, &result.unwrap());
        assert!(host.starts_with(root));
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
        std::fs::write(root.join("etc/passwd"), "root:x:0:0").unwrap();

        let fd = openat2_in_root(root, "/etc/passwd", libc::O_RDONLY, 0);
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

        let fd = openat2_in_root(root, "/../../../etc/passwd", libc::O_PATH, 0);
        match fd {
            // RESOLVE_IN_ROOT clamps ".." at the root, so this resolves
            // to <root>/etc/passwd which doesn't exist → ENOENT.
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

        let result = resolve_in_root(root, "/a/../../etc/passwd");
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
}
