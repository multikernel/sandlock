use std::path::{Path, PathBuf};

use crate::sys::fs::openat2_in_root;

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

/// Byte-preserving variant of [`confine`] for Linux filesystem names that do
/// not originate in UTF-8 APIs, such as pathname AF_UNIX addresses.
pub fn confine_path(virtual_path: &Path) -> PathBuf {
    use std::path::Component;

    let mut result = PathBuf::from("/");
    for component in virtual_path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(part) => result.push(part),
            Component::Prefix(prefix) => result.push(prefix.as_os_str()),
        }
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

/// Inverse of mount/chroot resolution: map a real host path back to the
/// sandbox's virtual path.
///
/// The chroot root is just the virtual `/` mount, so this is a single
/// most-specific-prefix lookup over `{ "/" => chroot_root } ∪ mounts` —
/// the same rule the kernel uses to pick among overlapping mounts. Returns
/// None when the host path is under neither the root nor any mount.
pub fn host_to_virtual(
    chroot_root: &Path,
    mounts: &[(PathBuf, PathBuf)],
    host_path: &Path,
) -> Option<PathBuf> {
    std::iter::once((Path::new("/"), chroot_root))
        .chain(mounts.iter().map(|(v, h)| (v.as_path(), h.as_path())))
        .filter(|(_, source)| host_path.starts_with(source))
        .max_by_key(|(_, source)| source.as_os_str().len())
        .map(|(virtual_base, source)| {
            // strip_prefix cannot fail: the filter above already matched it.
            let rest = host_path.strip_prefix(source).expect("prefix matched");
            // join("") appends a separator, so the mount point itself would
            // render as "/proc/" and reach the child that way through getcwd.
            if rest.as_os_str().is_empty() {
                virtual_base.to_path_buf()
            } else {
                virtual_base.join(rest)
            }
        })
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

    // Full path doesn't exist — resolve the parent and append the missing
    // filename.  This is needed for O_CREAT targets where the final
    // component will be created.
    resolve_in_root_nofollow(chroot_root, child_path)
}

/// Resolve a virtual path *without* following a final symlink.
///
/// The parent is resolved by the kernel (following intermediate symlinks,
/// confined to `chroot_root`) and the final component is appended verbatim,
/// so the caller acts on the last component itself.
///
/// This is what the no-follow family needs. `lstat` must describe the link,
/// `unlink` and `rename` must remove and move the link, and `lchown` must own
/// it: resolving through the final component would silently redirect every
/// one of them onto the target. It is also how an `O_CREAT` target resolves,
/// since a name that does not exist yet cannot be walked to.
pub fn resolve_in_root_nofollow(
    chroot_root: &Path,
    child_path: &str,
) -> Option<(PathBuf, PathBuf)> {
    let confined = confine(child_path);
    // "/" has no final component to leave unresolved.
    let Some(file_name) = confined.file_name() else {
        return resolve_existing_in_root(chroot_root, child_path);
    };
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

/// Resolve the configured chroot root to a canonical, on-disk path.
///
/// `None` chroot yields `Ok(None)`. A configured chroot path that cannot be
/// canonicalized (missing or inaccessible) is a hard error: silently dropping
/// it would disable the seccomp-notify chroot mediation without telling the
/// caller, leaving the workload effectively unconfined.
pub fn resolve_chroot_root(
    chroot: Option<&Path>,
) -> Result<Option<PathBuf>, crate::error::SandboxError> {
    match chroot {
        Some(p) => match std::fs::canonicalize(p) {
            Ok(resolved) => Ok(Some(resolved)),
            Err(source) => Err(crate::error::SandboxError::ChrootNotFound {
                path: p.to_path_buf(),
                source,
            }),
        },
        None => Ok(None),
    }
}

/// Canonicalize the host source of each bind mount, preserving the virtual
/// destination unchanged.
///
/// A host path that cannot be canonicalized falls back to the path as given:
/// unlike the chroot root (which gates confinement), a mount source may be
/// created later or resolved relative to another mount, so a missing source is
/// not treated as fatal here.
pub fn resolve_chroot_mounts(mounts: &[(PathBuf, PathBuf)]) -> Vec<(PathBuf, PathBuf)> {
    mounts
        .iter()
        .map(|(virtual_path, host_path)| {
            (
                virtual_path.clone(),
                std::fs::canonicalize(host_path).unwrap_or_else(|_| host_path.clone()),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn confine_path_preserves_non_utf8_components_and_clamps_parent() {
        let raw = PathBuf::from(std::ffi::OsString::from_vec(
            b"/allowed/\xff/../service/../../../../etc".to_vec(),
        ));
        assert_eq!(
            confine_path(&raw).as_os_str().as_encoded_bytes(),
            b"/etc"
        );

        let raw = PathBuf::from(std::ffi::OsString::from_vec(b"/allowed/\xff/service".to_vec()));
        assert_eq!(
            confine_path(&raw).as_os_str().as_encoded_bytes(),
            b"/allowed/\xff/service"
        );
    }

    #[test]
    fn resolve_chroot_root_none_is_ok_none() {
        assert!(resolve_chroot_root(None).unwrap().is_none());
    }

    #[test]
    fn resolve_chroot_root_existing_canonicalizes() {
        // /tmp exists on every supported target.
        let resolved = resolve_chroot_root(Some(Path::new("/tmp")))
            .unwrap()
            .expect("an existing chroot path should resolve to Some");
        assert!(resolved.is_absolute());
    }

    #[test]
    fn resolve_chroot_root_missing_path_errors() {
        // A configured chroot that does not exist must error rather than
        // silently disabling confinement. Regression: the old
        // `canonicalize(p).ok()` swallowed this into `None`, turning off the
        // seccomp-notify chroot mediation without telling the caller.
        let err = resolve_chroot_root(Some(Path::new(
            "/nonexistent/sandlock/rootfs/does-not-exist",
        )))
        .unwrap_err();
        assert!(
            matches!(err, crate::error::SandboxError::ChrootNotFound { .. }),
            "expected ChrootNotFound, got: {err:?}"
        );
    }

    #[test]
    fn resolve_chroot_mounts_canonicalizes_existing_and_falls_back_on_missing() {
        let dir = TempDir::new().unwrap();
        let existing = dir.path().join("src");
        std::fs::create_dir(&existing).unwrap();
        let missing = PathBuf::from("/nonexistent/sandlock/mount-src");

        let resolved = resolve_chroot_mounts(&[
            (PathBuf::from("/data"), existing.clone()),
            (PathBuf::from("/cache"), missing.clone()),
        ]);

        // Virtual destinations are preserved verbatim.
        assert_eq!(resolved[0].0, PathBuf::from("/data"));
        assert_eq!(resolved[1].0, PathBuf::from("/cache"));
        // Existing source is canonicalized; missing source falls back as-is.
        assert_eq!(resolved[0].1, existing.canonicalize().unwrap());
        assert_eq!(resolved[1].1, missing);
    }

    #[test]
    fn test_confine_absolute() {
        assert_eq!(confine("/etc/group"), PathBuf::from("/etc/group"));
    }

    #[test]
    fn test_confine_dotdot_at_root() {
        assert_eq!(confine("/../../etc/group"), PathBuf::from("/etc/group"));
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
            to_virtual_path(Path::new("/rootfs"), Path::new("/rootfs/etc/group")),
            Some(PathBuf::from("/etc/group"))
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
    fn host_to_virtual_at_a_mount_point_renders_without_a_trailing_slash() {
        // The rendered bytes matter, not just Path equality (which ignores a
        // trailing separator): getcwd copies this string into the child, and a
        // child sitting exactly on a mount point saw "/proc/".
        let mounts = vec![(PathBuf::from("/proc"), PathBuf::from("/proc"))];
        let virtual_path = host_to_virtual(Path::new("/rootfs"), &mounts, Path::new("/proc"))
            .expect("a mount point maps to its own virtual path");
        assert_eq!(virtual_path.to_string_lossy(), "/proc");
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
        std::fs::write(root.join("etc/group"), "root:x:0:\n").unwrap();

        let fd = openat2_in_root(root, "/etc/group", libc::O_RDONLY, 0);
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

        let fd = openat2_in_root(root, "/../../../etc/group", libc::O_PATH, 0);
        match fd {
            // RESOLVE_IN_ROOT clamps ".." at the root, so this resolves
            // to <root>/etc/group which doesn't exist → ENOENT.
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

        let result = resolve_in_root(root, "/a/../../etc/group");
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
