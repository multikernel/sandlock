//! Apply image layer tarballs onto a rootfs directory, unprivileged.
//!
//! Every mutation resolves through `RESOLVE_IN_ROOT`, so a symlink planted by
//! a lower layer cannot redirect a later layer's write outside the rootfs.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::path::Path;

use crate::error::{SandboxRuntimeError, SandlockError};
use crate::sys::fs::{
    linkat_in_root, list_dir_in_root, mkdir_in_root, mkdirp_in_root, mknod_in_root,
    openat2_in_root, remove_dir_all_in_root, statat_in_root, symlinkat_in_root, unlinkat_in_root,
};

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

/// Apply one layer tarball (already decompressed) onto `root`.
pub(crate) fn apply_layer(root: &Path, layer: impl Read) -> Result<(), SandlockError> {
    let mut applier = Applier {
        root,
        in_layer: HashSet::new(),
        pending_links: HashMap::new(),
    };
    let mut archive = tar::Archive::new(layer);
    for entry in archive.entries().map_err(SandboxRuntimeError::Io)? {
        let mut entry = entry.map_err(SandboxRuntimeError::Io)?;
        applier.apply_entry(&mut entry)?;
    }
    applier.finish()
}

struct Applier<'a> {
    root: &'a Path,
    // Paths this layer created, plus their ancestors. Whiteouts only hide
    // lower layers, so these survive a whiteout in the same layer.
    in_layer: HashSet<String>,
    // Hard links whose target appears later in the same tar, keyed by target.
    pending_links: HashMap<String, Vec<String>>,
}

impl Applier<'_> {
    fn apply_entry<R: Read>(&mut self, entry: &mut tar::Entry<'_, R>) -> Result<(), SandlockError> {
        let raw = entry.path_bytes().into_owned();
        let Some(path) = normalize(&raw)? else {
            return Ok(());
        };
        let (parent, name) = split(&path);

        if let Some(hidden) = name.strip_prefix(WHITEOUT_PREFIX) {
            if name == OPAQUE_WHITEOUT {
                return self.opaque(parent);
            }
            if hidden.starts_with(WHITEOUT_PREFIX) {
                return Ok(());
            }
            return self.whiteout(&join(parent, hidden));
        }

        let header = entry.header();
        let mode = header.mode().map_err(SandboxRuntimeError::Io)?;
        let kind = header.entry_type();
        if matches!(kind, tar::EntryType::Char | tar::EntryType::Block) {
            return Ok(());
        }
        if !parent.is_empty() {
            mkdirp_in_root(self.root, parent, 0o755).map_err(|e| errno(parent, e))?;
        }

        match kind {
            tar::EntryType::Directory => self.dir(&path, mode)?,
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let mtime = header.mtime().ok();
                self.file(&path, mode, mtime, entry)?
            }
            tar::EntryType::Symlink => {
                let target = link_name(entry, &path)?;
                self.replace(&path)?;
                symlinkat_in_root(self.root, &path, &target).map_err(|e| errno(&path, e))?;
            }
            tar::EntryType::Link => {
                let target = link_name(entry, &path)?;
                let Some(target) = normalize(target.as_bytes())? else {
                    return Err(layer_error(&path, "hard link to the root"));
                };
                if !self.in_layer.contains(&target) {
                    self.pending_links.entry(target).or_default().push(path);
                    return Ok(());
                }
                self.link(&target, &path)?;
            }
            tar::EntryType::Fifo => {
                self.replace(&path)?;
                mknod_in_root(self.root, &path, libc::S_IFIFO | file_mode(mode), 0)
                    .map_err(|e| errno(&path, e))?;
            }
            _ => return Ok(()),
        }
        self.created(path)
    }

    fn created(&mut self, path: String) -> Result<(), SandlockError> {
        let mut ancestor = path.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            self.in_layer.insert(parent.to_string());
            ancestor = parent;
        }
        self.in_layer.insert(path.clone());
        if let Some(links) = self.pending_links.remove(&path) {
            for link in links {
                self.link(&path, &link)?;
                self.created(link)?;
            }
        }
        Ok(())
    }

    fn dir(&self, path: &str, mode: u32) -> Result<(), SandlockError> {
        if !is_dir(self.root, path) {
            self.replace(path)?;
            mkdir_in_root(self.root, path, 0o700).map_err(|e| errno(path, e))?;
        }
        let fd = openat2_in_root(
            self.root,
            path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
        .map_err(|e| errno(path, e))?;
        let dir = unsafe { File::from_raw_fd(fd) };
        dir.set_permissions(std::fs::Permissions::from_mode(dir_mode(mode)))
            .map_err(|e| io_error(path, e))
    }

    fn file(
        &self,
        path: &str,
        mode: u32,
        mtime: Option<u64>,
        data: &mut impl Read,
    ) -> Result<(), SandlockError> {
        // Unlink first: writing through an existing inode would also change
        // every hard link that shares it.
        self.replace(path)?;
        let fd = openat2_in_root(
            self.root,
            path,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .map_err(|e| errno(path, e))?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        io::copy(data, &mut file).map_err(|e| io_error(path, e))?;
        file.set_permissions(std::fs::Permissions::from_mode(file_mode(mode)))
            .map_err(|e| io_error(path, e))?;
        if let Some(secs) = mtime {
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
            file.set_modified(t).map_err(|e| io_error(path, e))?;
        }
        Ok(())
    }

    fn link(&self, target: &str, path: &str) -> Result<(), SandlockError> {
        if target == path {
            return Ok(());
        }
        self.replace(path)?;
        linkat_in_root(self.root, target, path).map_err(|e| errno(path, e))
    }

    /// Remove whatever a lower layer left at `path`, so this layer's entry
    /// replaces it rather than merging into it.
    fn replace(&self, path: &str) -> Result<(), SandlockError> {
        let res = if is_dir(self.root, path) {
            remove_dir_all_in_root(self.root, path)
        } else {
            unlinkat_in_root(self.root, path, false)
        };
        match res {
            Ok(()) | Err(libc::ENOENT) => Ok(()),
            Err(e) => Err(errno(path, e)),
        }
    }

    fn whiteout(&self, path: &str) -> Result<(), SandlockError> {
        if self.in_layer.contains(path) {
            return Ok(());
        }
        self.replace(path)
    }

    fn opaque(&self, dir: &str) -> Result<(), SandlockError> {
        let dir = if dir.is_empty() { "." } else { dir };
        if !is_dir(self.root, dir) {
            return Ok(());
        }
        self.clear_lower_children(dir)
    }

    fn clear_lower_children(&self, dir: &str) -> Result<(), SandlockError> {
        let names = list_dir_in_root(self.root, dir).map_err(|e| errno(dir, e))?;
        for name in names {
            let child = if dir == "." { name } else { join(dir, &name) };
            if !self.in_layer.contains(&child) {
                self.replace(&child)?;
            } else if is_dir(self.root, &child) {
                self.clear_lower_children(&child)?;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(), SandlockError> {
        // A hard link may also name a file from a lower layer.
        for (target, links) in std::mem::take(&mut self.pending_links) {
            if statat_in_root(self.root, &target, false).is_err() {
                return Err(layer_error(&links[0], "hard link target missing"));
            }
            for link in links {
                self.link(&target, &link)?;
            }
        }
        Ok(())
    }
}

/// Canonical relative form of a tar path; `None` for the root itself.
fn normalize(raw: &[u8]) -> Result<Option<String>, SandlockError> {
    let s = std::str::from_utf8(raw)
        .map_err(|_| layer_error(&String::from_utf8_lossy(raw), "non-UTF-8 path"))?;
    let mut parts = Vec::new();
    for comp in s.split('/') {
        match comp {
            "" | "." => {}
            ".." => return Err(layer_error(s, "path escapes the layer root")),
            c => parts.push(c),
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join("/")))
}

fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn link_name<R: Read>(entry: &tar::Entry<'_, R>, path: &str) -> Result<String, SandlockError> {
    let target = entry
        .link_name_bytes()
        .ok_or_else(|| layer_error(path, "link without a target"))?;
    String::from_utf8(target.into_owned()).map_err(|_| layer_error(path, "non-UTF-8 link target"))
}

fn is_dir(root: &Path, path: &str) -> bool {
    statat_in_root(root, path, false)
        .map(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR)
        .unwrap_or(false)
}

// The sandbox runs as the unpacking uid, so the owner bits must always grant
// what root would have had: read on files, full access on directories.
// Setuid/setgid are dropped since ownership is not preserved.
fn file_mode(mode: u32) -> u32 {
    (mode & 0o1777) | 0o400
}

fn dir_mode(mode: u32) -> u32 {
    (mode & 0o1777) | 0o700
}

fn layer_error(path: &str, what: &str) -> SandlockError {
    SandboxRuntimeError::Child(format!("image layer: {path}: {what}")).into()
}

fn errno(path: &str, e: i32) -> SandlockError {
    io_error(path, io::Error::from_raw_os_error(e))
}

fn io_error(path: &str, e: io::Error) -> SandlockError {
    layer_error(path, &e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    fn layer(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        build(&mut b);
        b.into_inner().unwrap()
    }

    fn entry(
        b: &mut tar::Builder<Vec<u8>>,
        kind: tar::EntryType,
        path: &str,
        mode: u32,
        data: &[u8],
    ) {
        let mut h = tar::Header::new_gnu();
        h.set_path(path).unwrap();
        h.set_entry_type(kind);
        h.set_size(data.len() as u64);
        h.set_mode(mode);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    fn file(b: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) {
        entry(b, tar::EntryType::Regular, path, 0o644, data);
    }

    fn dir(b: &mut tar::Builder<Vec<u8>>, path: &str) {
        entry(b, tar::EntryType::Directory, path, 0o755, b"");
    }

    fn link(b: &mut tar::Builder<Vec<u8>>, kind: tar::EntryType, path: &str, target: &str) {
        let mut h = tar::Header::new_gnu();
        h.set_path(path).unwrap();
        h.set_entry_type(kind);
        h.set_size(0);
        h.set_mode(0o777);
        h.set_link_name(target).unwrap();
        h.set_cksum();
        b.append(&h, io::empty()).unwrap();
    }

    fn apply(root: &Path, bytes: Vec<u8>) -> Result<(), SandlockError> {
        apply_layer(root, bytes.as_slice())
    }

    #[test]
    fn writes_files_with_implicit_parents() {
        let root = tempfile::tempdir().unwrap();
        apply(
            root.path(),
            layer(|b| file(b, "a/b/greeting.txt", b"hello")),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("a/b/greeting.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn hardlink_forward_reference_shares_inode() {
        let root = tempfile::tempdir().unwrap();
        apply(
            root.path(),
            layer(|b| {
                link(
                    b,
                    tar::EntryType::Link,
                    "usr/bin/perl5.34.0",
                    "usr/bin/perl",
                );
                file(b, "usr/bin/perl", b"#!perl");
            }),
        )
        .unwrap();
        let a = fs::metadata(root.path().join("usr/bin/perl")).unwrap();
        let c = fs::metadata(root.path().join("usr/bin/perl5.34.0")).unwrap();
        assert_eq!(a.ino(), c.ino());
    }

    #[test]
    fn hardlink_to_lower_layer_file() {
        let root = tempfile::tempdir().unwrap();
        apply(root.path(), layer(|b| file(b, "bin/busybox", b"bb"))).unwrap();
        apply(
            root.path(),
            layer(|b| link(b, tar::EntryType::Link, "bin/sh", "bin/busybox")),
        )
        .unwrap();
        assert_eq!(fs::read(root.path().join("bin/sh")).unwrap(), b"bb");
    }

    #[test]
    fn rewriting_a_file_does_not_touch_its_hardlinks() {
        let root = tempfile::tempdir().unwrap();
        apply(
            root.path(),
            layer(|b| {
                file(b, "a", b"old");
                link(b, tar::EntryType::Link, "b", "a");
            }),
        )
        .unwrap();
        apply(root.path(), layer(|b| file(b, "a", b"new"))).unwrap();
        assert_eq!(fs::read(root.path().join("a")).unwrap(), b"new");
        assert_eq!(fs::read(root.path().join("b")).unwrap(), b"old");
    }

    #[test]
    fn symlink_from_lower_layer_cannot_redirect_writes_outside() {
        let outside = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        apply(
            root.path(),
            layer(|b| link(b, tar::EntryType::Symlink, "up", "../../../../../../..")),
        )
        .unwrap();
        apply(
            root.path(),
            layer(|b| {
                link(
                    b,
                    tar::EntryType::Symlink,
                    "abs",
                    outside.path().to_str().unwrap(),
                );
            }),
        )
        .unwrap();

        apply(root.path(), layer(|b| file(b, "up/pwned", b"x"))).unwrap();
        assert!(
            root.path().join("pwned").is_file(),
            ".. must clamp at the rootfs"
        );

        let _ = apply(root.path(), layer(|b| file(b, "abs/pwned", b"x")));
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn absolute_symlink_resolves_inside_rootfs() {
        let root = tempfile::tempdir().unwrap();
        apply(
            root.path(),
            layer(|b| {
                dir(b, "usr/lib/");
                link(b, tar::EntryType::Symlink, "lib", "/usr/lib");
            }),
        )
        .unwrap();
        apply(root.path(), layer(|b| file(b, "lib/libc.so", b"elf"))).unwrap();
        assert_eq!(
            fs::read(root.path().join("usr/lib/libc.so")).unwrap(),
            b"elf"
        );
    }

    #[test]
    fn whiteout_removes_lower_file_and_tree() {
        let root = tempfile::tempdir().unwrap();
        apply(
            root.path(),
            layer(|b| {
                file(b, "etc/motd", b"hi");
                file(b, "var/cache/apt/pkg", b"deb");
            }),
        )
        .unwrap();
        apply(
            root.path(),
            layer(|b| {
                file(b, "etc/.wh.motd", b"");
                file(b, "var/cache/.wh.apt", b"");
            }),
        )
        .unwrap();
        assert!(!root.path().join("etc/motd").exists());
        assert!(!root.path().join("var/cache/apt").exists());
        assert!(root.path().join("var/cache").is_dir());
    }

    #[test]
    fn opaque_dir_hides_lower_but_keeps_same_layer_entries() {
        let root = tempfile::tempdir().unwrap();
        apply(
            root.path(),
            layer(|b| {
                file(b, "d/lower", b"");
                file(b, "d/sub/lower", b"");
            }),
        )
        .unwrap();
        apply(
            root.path(),
            layer(|b| {
                file(b, "d/sub/upper", b"");
                file(b, "d/.wh..wh..opq", b"");
                file(b, "d/after", b"");
            }),
        )
        .unwrap();
        let d = root.path().join("d");
        assert!(!d.join("lower").exists());
        assert!(!d.join("sub/lower").exists());
        assert!(d.join("sub/upper").is_file());
        assert!(d.join("after").is_file());
    }

    #[test]
    fn upper_entry_replaces_lower_entry_of_other_type() {
        let root = tempfile::tempdir().unwrap();
        apply(
            root.path(),
            layer(|b| {
                file(b, "x/inner", b"");
                file(b, "y", b"");
            }),
        )
        .unwrap();
        apply(
            root.path(),
            layer(|b| {
                file(b, "x", b"now a file");
                dir(b, "y/");
            }),
        )
        .unwrap();
        assert!(root.path().join("x").is_file());
        assert!(root.path().join("y").is_dir());
    }

    #[test]
    fn modes_keep_owner_access_and_drop_setuid() {
        let root = tempfile::tempdir().unwrap();
        apply(
            root.path(),
            layer(|b| {
                entry(b, tar::EntryType::Directory, "locked/", 0o555, b"");
                entry(b, tar::EntryType::Regular, "locked/secret", 0o000, b"s");
                entry(b, tar::EntryType::Regular, "su", 0o4755, b"");
            }),
        )
        .unwrap();
        let mode = |p: &str| fs::metadata(root.path().join(p)).unwrap().mode() & 0o7777;
        assert_eq!(mode("locked"), 0o755);
        assert_eq!(mode("locked/secret"), 0o400);
        assert_eq!(mode("su"), 0o755);
        assert_eq!(fs::read(root.path().join("locked/secret")).unwrap(), b"s");
    }

    #[test]
    fn device_nodes_are_skipped() {
        let root = tempfile::tempdir().unwrap();
        apply(
            root.path(),
            layer(|b| entry(b, tar::EntryType::Char, "dev/null", 0o666, b"")),
        )
        .unwrap();
        assert!(!root.path().join("dev/null").exists());
    }

    #[test]
    fn dotdot_path_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let mut h = tar::Header::new_gnu();
        // set_path refuses "..", so write the raw name field.
        h.as_old_mut().name[..9].copy_from_slice(b"../escape");
        h.set_size(0);
        h.set_mode(0o644);
        h.set_cksum();
        let mut b = tar::Builder::new(Vec::new());
        b.append(&h, io::empty()).unwrap();
        assert!(apply(root.path(), b.into_inner().unwrap()).is_err());
    }
}
