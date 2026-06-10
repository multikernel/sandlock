//! Materialize a local Docker image into a rootfs for sandboxing by
//! talking to the Docker daemon over its HTTP API (via bollard).
//!
//! `--image <ref>` resolves a *local* image only; sandlock never pulls
//! from a registry.  The daemon must be running and its socket
//! accessible: callers fail early (see [`extract`] / [`inspect_cmd`])
//! when it is not reachable, before any sandbox is built.
//!
//! The image filesystem is obtained the same way `docker export` does:
//! a throwaway stopped container is created from the image, its
//! flattened rootfs is streamed out as a tar, and unpacked into a cache
//! keyed by the image's content id.
//!
//! ```ignore
//! let rootfs = image::extract("python:3.12-slim", None).await?;
//! let cmd = image::inspect_cmd("python:3.12-slim").await?;
//! ```
//!
//! Extracted rootfs is cached at
//! `$HOME/.cache/sandlock/images/<image-id>/rootfs/` and reused on
//! subsequent invocations referencing the same image content.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use bollard::models::{ContainerCreateBody, ImageInspect};
use bollard::query_parameters::RemoveContainerOptionsBuilder;
use bollard::Docker;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::error::{SandboxRuntimeError, SandlockError};

// ============================================================
// Public API
// ============================================================

/// Default cache directory for extracted images.
fn default_cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".cache/sandlock/images")
}

/// Resolve a local Docker image into a cached rootfs directory.
///
/// `image_ref` is a Docker image reference (`python:3.12-slim`, a
/// digest, an image id, ...) that must already be present in local
/// Docker storage.  The extracted rootfs is keyed by the image's
/// content id so repeated calls hit the same cache.
///
/// Fails early if the Docker daemon is not reachable, or if the image
/// is not in local storage.
pub async fn extract(image_ref: &str, cache_dir: Option<&Path>) -> Result<PathBuf, SandlockError> {
    let docker = connect().await?;
    let info = inspect(&docker, image_ref).await?;
    let id = info.id.ok_or_else(|| {
        SandboxRuntimeError::Child(format!("Docker returned no id for image {image_ref}"))
    })?;

    let cache = cache_dir.map(PathBuf::from).unwrap_or_else(default_cache_dir);
    let dest = cache.join(sanitize_id(&id));
    let rootfs = dest.join("rootfs");

    // Cache hit: the .complete marker means we fully unpacked this image
    // before.  A partial directory (interrupted run) lacks the marker.
    if rootfs.is_dir() && dest.join(".complete").is_file() {
        return Ok(rootfs);
    }

    // Stale or partial cache: start clean.
    let _ = fs::remove_dir_all(&dest);
    fs::create_dir_all(&rootfs).map_err(SandboxRuntimeError::Io)?;

    // `docker create`: a stopped container we use only as an export
    // source.  No command is started.
    let body = ContainerCreateBody {
        image: Some(image_ref.to_string()),
        ..Default::default()
    };
    let created = docker
        .create_container(None, body)
        .await
        .map_err(|e| SandboxRuntimeError::Child(format!("docker create failed: {e}")))?;
    let cid = created.id;

    // `docker export`: stream the flattened rootfs to a temp tar so we
    // never hold a whole image in memory.
    let tar_path = dest.join("export.tar");
    let export_res = stream_export(&docker, &cid, &tar_path).await;

    // Always remove the throwaway container, even if the export failed.
    let _ = docker
        .remove_container(
            &cid,
            Some(RemoveContainerOptionsBuilder::new().force(true).build()),
        )
        .await;
    export_res?;

    // Unpack the tar (blocking work) off the async reactor.
    let rootfs_out = rootfs.clone();
    let tar_in = tar_path.clone();
    tokio::task::spawn_blocking(move || unpack_rootfs(&tar_in, &rootfs_out))
        .await
        .map_err(|e| SandboxRuntimeError::Child(format!("image unpack task failed: {e}")))??;

    let _ = fs::remove_file(&tar_path);
    fs::write(dest.join(".complete"), b"").map_err(SandboxRuntimeError::Io)?;
    Ok(rootfs)
}

/// Get the default command (Entrypoint + Cmd) for a local Docker image.
///
/// Returns the concatenation of Entrypoint and Cmd from the image
/// config, or `["/bin/sh"]` if neither is set.  Fails early if the
/// daemon is unreachable or the image is not in local storage.
pub async fn inspect_cmd(image_ref: &str) -> Result<Vec<String>, SandlockError> {
    let docker = connect().await?;
    let info = inspect(&docker, image_ref).await?;
    Ok(default_cmd(&info))
}

// ============================================================
// Docker daemon access
// ============================================================

/// Connect to the local Docker daemon and verify it is actually
/// reachable, so `--image` fails up front rather than mid-setup.
async fn connect() -> Result<Docker, SandlockError> {
    let docker = Docker::connect_with_local_defaults().map_err(daemon_unreachable)?;
    docker.ping().await.map_err(daemon_unreachable)?;
    Ok(docker)
}

fn daemon_unreachable(e: bollard::errors::Error) -> SandlockError {
    SandboxRuntimeError::Child(format!(
        "cannot reach the Docker daemon, required for --image \
         (is dockerd running and the socket accessible?): {e}"
    ))
    .into()
}

/// Inspect a local image, mapping a missing image to a clear error.
async fn inspect(docker: &Docker, image_ref: &str) -> Result<ImageInspect, SandlockError> {
    docker.inspect_image(image_ref).await.map_err(|e| {
        SandboxRuntimeError::Child(format!(
            "image not found in local Docker storage: {image_ref} ({e})"
        ))
        .into()
    })
}

/// Stream a container's exported filesystem into `tar_path`.
async fn stream_export(docker: &Docker, cid: &str, tar_path: &Path) -> Result<(), SandlockError> {
    let mut file = tokio::fs::File::create(tar_path)
        .await
        .map_err(SandboxRuntimeError::Io)?;
    let mut stream = docker.export_container(cid);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| SandboxRuntimeError::Child(format!("docker export failed: {e}")))?;
        file.write_all(&chunk).await.map_err(SandboxRuntimeError::Io)?;
    }
    file.flush().await.map_err(SandboxRuntimeError::Io)?;
    Ok(())
}

fn default_cmd(info: &ImageInspect) -> Vec<String> {
    let cfg = info.config.as_ref();
    let entrypoint = cfg.and_then(|c| c.entrypoint.clone()).unwrap_or_default();
    let cmd = cfg.and_then(|c| c.cmd.clone()).unwrap_or_default();
    let combined: Vec<String> = entrypoint.into_iter().chain(cmd).collect();
    if combined.is_empty() {
        vec!["/bin/sh".into()]
    } else {
        combined
    }
}

/// Turn an image id (`sha256:abcd...`) into a filesystem-safe cache key.
fn sanitize_id(id: &str) -> String {
    id.split_once(':').map(|(_, h)| h).unwrap_or(id).to_string()
}

// ============================================================
// Rootfs extraction
// ============================================================

/// Unpack a flattened container-export tarball into `rootfs`.
///
/// `docker export` produces a single already-merged filesystem, so
/// there are no AUFS/OCI whiteouts to apply.  Hard links still need
/// care: an entry can reference a target that appears later in the same
/// stream, and the tar crate's own hard-link handling resolves link
/// targets against the process cwd rather than the destination root.
/// We unpack non-link entries first, then resolve links manually under
/// `rootfs`.
fn unpack_rootfs(tar_path: &Path, rootfs: &Path) -> Result<(), SandlockError> {
    // Pass 1: extract everything except hard links.
    let mut deferred_hardlinks: Vec<PathBuf> = Vec::new();
    {
        let file = fs::File::open(tar_path).map_err(SandboxRuntimeError::Io)?;
        let mut archive = tar::Archive::new(file);
        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_overwrite(true);
        for entry in archive.entries().map_err(SandboxRuntimeError::Io)? {
            let mut entry = entry.map_err(SandboxRuntimeError::Io)?;
            let raw = entry.path().map_err(SandboxRuntimeError::Io)?.into_owned();
            let dest = rootfs.join(&raw);
            if !dest.starts_with(rootfs) {
                continue;
            }
            if entry.header().entry_type() == tar::EntryType::Link {
                deferred_hardlinks.push(raw);
                continue;
            }
            entry.unpack(&dest).map_err(SandboxRuntimeError::Io)?;
        }
    }

    // Pass 2: resolve hard links manually.  The tar crate's
    // entry.unpack(dest) passes the link_name straight to
    // fs::hard_link, which resolves against the process cwd rather than
    // the rootfs.  We rewrite both endpoints to absolute paths under
    // rootfs ourselves.  A hard link's target can itself be another
    // hard link, so loop until everything resolves or a full sweep
    // makes no progress.
    while !deferred_hardlinks.is_empty() {
        let mut remaining: Vec<PathBuf> = Vec::new();
        let mut applied_this_round = 0usize;
        let target_set: HashSet<PathBuf> = deferred_hardlinks.iter().cloned().collect();

        let file = fs::File::open(tar_path).map_err(SandboxRuntimeError::Io)?;
        let mut archive = tar::Archive::new(file);
        for entry in archive.entries().map_err(SandboxRuntimeError::Io)? {
            let entry = entry.map_err(SandboxRuntimeError::Io)?;
            if entry.header().entry_type() != tar::EntryType::Link {
                continue;
            }
            let raw = entry.path().map_err(SandboxRuntimeError::Io)?.into_owned();
            if !target_set.contains(&raw) {
                continue;
            }
            let link_target = match entry.link_name().map_err(SandboxRuntimeError::Io)? {
                Some(t) => t.into_owned(),
                None => {
                    remaining.push(raw);
                    continue;
                }
            };
            let src = rootfs.join(&link_target);
            let dest = rootfs.join(&raw);
            if !src.starts_with(rootfs) || !dest.starts_with(rootfs) {
                continue;
            }
            if let Some(parent) = dest.parent() {
                let _ = fs::create_dir_all(parent);
            }
            // Remove any leftover from a previous failed round;
            // fs::hard_link refuses to overwrite.
            if dest.exists() || dest.is_symlink() {
                let _ = fs::remove_file(&dest);
            }
            match fs::hard_link(&src, &dest) {
                Ok(_) => applied_this_round += 1,
                Err(_) => remaining.push(raw),
            }
        }

        if applied_this_round == 0 {
            return Err(SandboxRuntimeError::Child(format!(
                "image export has {} unresolved hard link(s); broken export",
                remaining.len(),
            ))
            .into());
        }
        deferred_hardlinks = remaining;
    }

    Ok(())
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::ImageConfig;

    /// Write a tar with the given entries to a temp file and return it.
    fn write_tar(entries: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> (tempfile::TempDir, PathBuf) {
        let mut builder = tar::Builder::new(Vec::new());
        entries(&mut builder);
        let bytes = builder.into_inner().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("export.tar");
        fs::write(&p, bytes).unwrap();
        (tmp, p)
    }

    fn append_file(b: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_path(path).unwrap();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    fn append_dir(b: &mut tar::Builder<Vec<u8>>, path: &str) {
        let mut h = tar::Header::new_gnu();
        h.set_path(path).unwrap();
        h.set_size(0);
        h.set_mode(0o755);
        h.set_entry_type(tar::EntryType::Directory);
        h.set_cksum();
        b.append(&h, std::io::empty()).unwrap();
    }

    #[test]
    fn unpack_writes_regular_files() {
        let (_tmp, tar_path) = write_tar(|b| {
            append_file(b, "greeting.txt", b"hello sandlock");
        });
        let rootfs_tmp = tempfile::tempdir().unwrap();
        let rootfs = rootfs_tmp.path();

        unpack_rootfs(&tar_path, rootfs).unwrap();
        let greeting = rootfs.join("greeting.txt");
        assert!(greeting.is_file());
        assert_eq!(fs::read_to_string(&greeting).unwrap(), "hello sandlock");
    }

    /// Real Docker images contain hard links whose source paths are
    /// relative to the rootfs (e.g. `usr/bin/perl5.34.0` ->
    /// `usr/bin/perl`), and the source can appear later in the same tar.
    /// Regression test for the resolve-relative-to-rootfs +
    /// defer-until-source-exists fix.
    #[test]
    fn unpack_resolves_hardlinks_with_forward_references() {
        let (_tmp, tar_path) = write_tar(|b| {
            append_dir(b, "usr/");
            append_dir(b, "usr/bin/");
            // Hard link entry referencing a file that appears LATER.
            let mut h = tar::Header::new_gnu();
            h.set_path("usr/bin/perl5.34.0").unwrap();
            h.set_size(0);
            h.set_mode(0o755);
            h.set_entry_type(tar::EntryType::Link);
            h.set_link_name("usr/bin/perl").unwrap();
            h.set_cksum();
            b.append(&h, std::io::empty()).unwrap();
            // The actual binary, defined after the hard link.
            append_file(b, "usr/bin/perl", b"#!perl\nnop");
        });
        let rootfs_tmp = tempfile::tempdir().unwrap();
        let rootfs = rootfs_tmp.path();

        unpack_rootfs(&tar_path, rootfs).unwrap();
        let perl = rootfs.join("usr/bin/perl");
        let perl_versioned = rootfs.join("usr/bin/perl5.34.0");
        assert!(perl.is_file(), "perl should exist as a regular file");
        assert!(perl_versioned.is_file(), "perl5.34.0 should exist as a hard link");
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(&perl).unwrap().ino(),
            fs::metadata(&perl_versioned).unwrap().ino(),
            "hard link should share inode with target",
        );
    }

    #[test]
    fn default_cmd_combines_entrypoint_and_cmd() {
        let info = ImageInspect {
            config: Some(ImageConfig {
                entrypoint: Some(vec!["/bin/sh".into(), "-c".into()]),
                cmd: Some(vec!["echo hi".into()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(default_cmd(&info), vec!["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn default_cmd_falls_back_to_bin_sh() {
        let info = ImageInspect {
            config: Some(ImageConfig::default()),
            ..Default::default()
        };
        assert_eq!(default_cmd(&info), vec!["/bin/sh"]);
    }

    #[test]
    fn sanitize_id_strips_algorithm_prefix() {
        assert_eq!(sanitize_id("sha256:abcdef0123"), "abcdef0123");
        assert_eq!(sanitize_id("abcdef0123"), "abcdef0123");
    }
}
