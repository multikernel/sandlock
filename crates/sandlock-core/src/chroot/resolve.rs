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
}
