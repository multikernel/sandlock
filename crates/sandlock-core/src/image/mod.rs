//! Materialize a container image into a cached rootfs for sandboxing.
//!
//! References follow skopeo's transport syntax (containers-transports(5)),
//! and like skopeo require the transport:
//!
//! - `docker://<ref>`: a registry, Docker Hub by default
//! - `docker-daemon:<ref>` or `docker-daemon:sha256:<id>`: an image in the
//!   local Docker daemon, fetched through its image-save API (Docker 25+)
//! - `oci:<dir>[:<tag>]`: an OCI image layout directory
//! - `oci-archive:<file>[:<tag>]`: a tar of an OCI image layout
//!
//! Every blob is checked against its digest, layers are applied without
//! privileges (see [`layer`]), and each image is unpacked once into
//! `$XDG_CACHE_HOME/sandlock/images/<config digest>/`. The config digest
//! is Docker's image id and names the content whatever the source or layer
//! compression, so one image is cached once.
//!
//! ```ignore
//! let image = image::pull("docker://python:3.12", None).await?;
//! let cmd = image.config.default_cmd();
//! ```

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{SandboxRuntimeError, SandlockError};

#[cfg(feature = "http")]
mod docker;
mod layer;
mod oci;
#[cfg(feature = "http")]
mod registry;

/// An unpacked image: its root filesystem and how it expects to be run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image {
    pub rootfs: PathBuf,
    pub config: ImageConfig,
}

/// The run settings an image carries in its config blob.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ImageConfig {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: Option<String>,
}

impl ImageConfig {
    /// Entrypoint followed by Cmd, or `/bin/sh` when the image sets neither.
    pub fn default_cmd(&self) -> Vec<String> {
        let combined: Vec<String> = self.entrypoint.iter().chain(&self.cmd).cloned().collect();
        if combined.is_empty() {
            vec!["/bin/sh".into()]
        } else {
            combined
        }
    }
}

/// Resolve `reference` to an unpacked image, unpacking it on first use.
pub async fn pull(reference: &str, cache_dir: Option<&Path>) -> Result<Image, SandlockError> {
    let cache = Cache::new(cache_dir);
    match Source::parse(reference)? {
        #[cfg(feature = "http")]
        Source::Registry(name) => registry::pull(&cache, &name).await,
        #[cfg(feature = "http")]
        Source::DockerDaemon(name) => docker::pull(&cache, &name).await,
        #[cfg(not(feature = "http"))]
        Source::Registry(_) | Source::DockerDaemon(_) => Err(crate::error::SandboxError::FeatureDisabled {
            what: format!("image reference {reference:?}"),
            feature: "http",
        }
        .into()),
        Source::OciDir { path, tag } => {
            blocking(move || {
                let blobs = oci::LayoutDir::open(&path)?;
                from_layout(&cache, &blobs, tag.as_deref())
            })
            .await
        }
        Source::OciArchive { path, tag } => {
            blocking(move || {
                let blobs = oci::LayoutArchive::open(&path)?;
                from_layout(&cache, &blobs, tag.as_deref())
            })
            .await
        }
    }
}

#[derive(Debug, PartialEq)]
enum Source {
    OciDir { path: PathBuf, tag: Option<String> },
    OciArchive { path: PathBuf, tag: Option<String> },
    Registry(String),
    DockerDaemon(String),
}

impl Source {
    fn parse(reference: &str) -> Result<Source, SandlockError> {
        if let Some(rest) = reference.strip_prefix("oci:") {
            let (path, tag) = split_tag(rest);
            Ok(Source::OciDir { path, tag })
        } else if let Some(rest) = reference.strip_prefix("oci-archive:") {
            let (path, tag) = split_tag(rest);
            Ok(Source::OciArchive { path, tag })
        } else if let Some(name) = reference.strip_prefix("docker-daemon:").filter(|n| !n.is_empty()) {
            Ok(Source::DockerDaemon(name.to_string()))
        } else if let Some(name) = reference.strip_prefix("docker://").filter(|n| !n.is_empty()) {
            Ok(Source::Registry(name.to_string()))
        } else {
            Err(SandboxRuntimeError::Child(format!(
                "image reference {reference:?} needs a transport, as with skopeo: \
                 docker://{reference} for a registry, docker-daemon:{reference} for \
                 the local Docker daemon, oci:<dir> or oci-archive:<file>"
            ))
            .into())
        }
    }
}

/// `path[:tag]`, where a trailing `:x` only counts as a tag if `x` could
/// not be part of a path.
fn split_tag(rest: &str) -> (PathBuf, Option<String>) {
    match rest.rsplit_once(':') {
        Some((path, tag)) if !tag.is_empty() && !tag.contains('/') => (path.into(), Some(tag.to_string())),
        _ => (rest.into(), None),
    }
}

fn from_layout(cache: &Cache, blobs: &dyn oci::Blobs, tag: Option<&str>) -> Result<Image, SandlockError> {
    let manifest = oci::resolve(blobs, tag)?;
    cache.get_or_build(oci::digest_hex(&manifest.config.digest)?, |rootfs| unpack(blobs, &manifest, rootfs))
}

fn unpack(blobs: &dyn oci::Blobs, manifest: &oci::Manifest, rootfs: &Path) -> Result<ImageConfig, SandlockError> {
    oci::unpack(blobs, manifest, rootfs)?;
    let mut config = oci::config(blobs, manifest)?;
    if let Some(dir) = config.working_dir.take() {
        config.working_dir = Some(resolve_working_dir(rootfs, &dir)?);
    }
    Ok(config)
}

/// Create WorkingDir if missing, as Docker does, and pin it to its
/// symlink-free path inside the rootfs: the child chdirs to a host path
/// joined from it, so a symlink in the image could otherwise start the
/// sandbox outside its rootfs.
fn resolve_working_dir(rootfs: &Path, dir: &str) -> Result<String, SandlockError> {
    use crate::sys::fs::{mkdirp_in_root, openat2_in_root};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let fail = |e: io::Error| SandboxRuntimeError::Child(format!("image: WorkingDir {dir}: {e}"));
    mkdirp_in_root(rootfs, dir, 0o755).map_err(|e| fail(io::Error::from_raw_os_error(e)))?;
    let fd = openat2_in_root(rootfs, dir, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC, 0)
        .map_err(|e| fail(io::Error::from_raw_os_error(e)))?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let real = fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).map_err(fail)?;
    let root = fs::canonicalize(rootfs).map_err(fail)?;
    let inside = real
        .strip_prefix(&root)
        .map_err(|_| fail(io::Error::other("resolves outside the rootfs")))?;
    Ok(format!("/{}", inside.display()))
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, SandlockError> + Send + 'static,
) -> Result<T, SandlockError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| SandboxRuntimeError::Child(format!("image task failed: {e}")))?
}

/// Unpacked images keyed by content digest. An entry is built in a private
/// temp dir and renamed into place, so a visible entry is always complete
/// and concurrent first uses of one image cannot corrupt each other.
#[derive(Clone)]
struct Cache {
    dir: PathBuf,
}

const CONFIG_FILE: &str = "config.json";

impl Cache {
    fn new(dir: Option<&Path>) -> Self {
        let dir = dir.map(PathBuf::from).unwrap_or_else(|| {
            let base = std::env::var_os("XDG_CACHE_HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
                    PathBuf::from(home).join(".cache")
                });
            base.join("sandlock/images")
        });
        Cache { dir }
    }

    fn lookup(&self, key: &str) -> Option<Image> {
        let entry = self.dir.join(key);
        let config = fs::read(entry.join(CONFIG_FILE)).ok()?;
        let config = serde_json::from_slice(&config).ok()?;
        Some(Image { rootfs: entry.join("rootfs"), config })
    }

    fn temp_path(&self, suffix: &str) -> Result<PathBuf, SandlockError> {
        fs::create_dir_all(&self.dir).map_err(SandboxRuntimeError::Io)?;
        Ok(self.dir.join(format!(".tmp-{}{suffix}", uuid::Uuid::new_v4())))
    }

    fn get_or_build(
        &self,
        key: &str,
        build: impl FnOnce(&Path) -> Result<ImageConfig, SandlockError>,
    ) -> Result<Image, SandlockError> {
        if let Some(image) = self.lookup(key) {
            return Ok(image);
        }
        let tmp = self.temp_path("")?;
        let result = self.build_into(&tmp, key, build);
        if result.is_err() {
            let _ = fs::remove_dir_all(&tmp);
        }
        result
    }

    fn build_into(
        &self,
        tmp: &Path,
        key: &str,
        build: impl FnOnce(&Path) -> Result<ImageConfig, SandlockError>,
    ) -> Result<Image, SandlockError> {
        let rootfs = tmp.join("rootfs");
        fs::create_dir_all(&rootfs).map_err(SandboxRuntimeError::Io)?;
        let config = build(&rootfs)?;
        let json = serde_json::to_vec(&config).map_err(|e| SandboxRuntimeError::Child(e.to_string()))?;
        fs::write(tmp.join(CONFIG_FILE), json).map_err(SandboxRuntimeError::Io)?;

        let entry = self.dir.join(key);
        // Only an entry without a config can be stale: complete ones are
        // renamed into place whole.
        if entry.exists() && self.lookup(key).is_none() {
            let _ = fs::remove_dir_all(&entry);
        }
        match fs::rename(tmp, &entry) {
            Ok(()) => {}
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY) | Some(libc::EEXIST)) => {
                let _ = fs::remove_dir_all(tmp);
            }
            Err(e) => return Err(SandboxRuntimeError::Io(e).into()),
        }
        self.lookup(key)
            .ok_or_else(|| SandboxRuntimeError::Io(io::Error::other(format!("image cache entry {key} vanished"))).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci::tests::{tar_of, TestLayout};

    #[cfg(not(feature = "http"))]
    #[tokio::test]
    async fn network_transports_need_the_http_feature() {
        for reference in ["docker://alpine", "docker-daemon:alpine"] {
            let err = pull(reference, Some(Path::new("/nonexistent"))).await.unwrap_err();
            assert!(err.to_string().contains("\"http\" feature"), "{err}");
        }
    }

    #[test]
    fn default_cmd_combines_entrypoint_and_cmd() {
        let cfg = ImageConfig {
            entrypoint: vec!["/bin/sh".into(), "-c".into()],
            cmd: vec!["echo hi".into()],
            ..Default::default()
        };
        assert_eq!(cfg.default_cmd(), vec!["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn default_cmd_falls_back_to_bin_sh() {
        assert_eq!(ImageConfig::default().default_cmd(), vec!["/bin/sh"]);
    }

    #[test]
    fn parses_transports() {
        let dir = |p: &str, t: Option<&str>| Source::OciDir { path: p.into(), tag: t.map(String::from) };
        assert_eq!(Source::parse("oci:/srv/img").unwrap(), dir("/srv/img", None));
        assert_eq!(Source::parse("oci:/srv/img:v1").unwrap(), dir("/srv/img", Some("v1")));
        assert_eq!(Source::parse("oci:rel/img").unwrap(), dir("rel/img", None));
        assert_eq!(
            Source::parse("oci-archive:/tmp/x.tar:latest").unwrap(),
            Source::OciArchive { path: "/tmp/x.tar".into(), tag: Some("latest".into()) }
        );
        assert_eq!(
            Source::parse("docker-daemon:python:3.12").unwrap(),
            Source::DockerDaemon("python:3.12".into())
        );
        assert_eq!(
            Source::parse("docker-daemon:sha256:abc").unwrap(),
            Source::DockerDaemon("sha256:abc".into())
        );
        assert_eq!(Source::parse("docker://ghcr.io/a/b").unwrap(), Source::Registry("ghcr.io/a/b".into()));
        let err = Source::parse("python:3.12").unwrap_err().to_string();
        assert!(err.contains("docker://python:3.12") && err.contains("docker-daemon:python:3.12"), "{err}");
        assert!(Source::parse("docker-daemon:").is_err());
        assert!(Source::parse("docker://").is_err());
    }

    fn one_layer_layout(file: &str) -> TestLayout {
        let layout = TestLayout::new();
        let img = layout.image(
            &[("application/vnd.oci.image.layer.v1.tar", tar_of(&[(file, b"x")]))],
            serde_json::json!({"config": {"Cmd": ["run"]}}),
        );
        layout.index(vec![img]);
        layout
    }

    #[tokio::test]
    async fn pull_unpacks_once_then_hits_cache() {
        let layout = one_layer_layout("hello");
        let cache = tempfile::tempdir().unwrap();
        let reference = format!("oci:{}", layout.path().display());

        let first = pull(&reference, Some(cache.path())).await.unwrap();
        assert!(first.rootfs.join("hello").is_file());
        assert_eq!(first.config.cmd, vec!["run"]);

        // Only the index and manifest are consulted on a hit.
        let index: serde_json::Value = serde_json::from_slice(&fs::read(layout.path().join("index.json")).unwrap()).unwrap();
        let manifest = index["manifests"][0]["digest"].as_str().unwrap().trim_start_matches("sha256:").to_string();
        for blob in fs::read_dir(layout.path().join("blobs/sha256")).unwrap() {
            let blob = blob.unwrap();
            if blob.file_name() != manifest.as_str() {
                fs::remove_file(blob.path()).unwrap();
            }
        }
        let second = pull(&reference, Some(cache.path())).await.unwrap();
        assert_eq!(second.rootfs, first.rootfs);
        assert_eq!(second.config, first.config);
        let entries: Vec<_> = fs::read_dir(cache.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(entries.len(), 1, "no temp dirs left behind: {entries:?}");
    }

    #[test]
    fn builder_image_only_fills_unset_env_and_cwd() {
        let image = Image {
            rootfs: "/cache/img/rootfs".into(),
            config: ImageConfig {
                env: vec!["PATH=/usr/local/bin:/usr/bin".into(), "LANG=C.UTF-8".into(), "NOEQUALS".into()],
                working_dir: Some("/srv".into()),
                ..Default::default()
            },
        };
        let b = crate::SandboxBuilder::default().env_var("LANG", "en_US.UTF-8").image(&image);
        assert_eq!(b.env["PATH"], "/usr/local/bin:/usr/bin");
        assert_eq!(b.env["LANG"], "en_US.UTF-8");
        assert!(!b.env.contains_key("NOEQUALS"));
        assert_eq!(b.cwd.as_deref(), Some(Path::new("/srv")));
        assert_eq!(b.chroot.as_deref(), Some(image.rootfs.as_path()));
        assert_eq!(b.workdir.as_deref(), Some(image.rootfs.as_path()));

        let b = crate::SandboxBuilder::default().image(&image).cwd("/tmp").env_var("PATH", "/bin");
        assert_eq!(b.cwd.as_deref(), Some(Path::new("/tmp")));
        assert_eq!(b.env["PATH"], "/bin");
    }

    #[test]
    fn image_writes_are_always_discarded() {
        use crate::sandbox::BranchAction;
        let rootfs = tempfile::tempdir().unwrap();
        let image = Image { rootfs: rootfs.path().to_path_buf(), config: ImageConfig::default() };
        let build = |b: crate::SandboxBuilder| b.build();

        let sb = build(crate::SandboxBuilder::default().image(&image)).unwrap();
        assert_eq!(sb.on_exit, BranchAction::Abort);
        assert_eq!(sb.on_error, BranchAction::Abort);
        assert_eq!(sb.workdir.as_deref(), Some(rootfs.path()));

        let explicit = crate::SandboxBuilder::default().on_exit(BranchAction::Abort).image(&image);
        assert!(build(explicit).is_ok());

        let other = tempfile::tempdir().unwrap();
        let err = build(crate::SandboxBuilder::default().workdir(other.path()).image(&image)).unwrap_err();
        assert!(err.to_string().contains("copy-on-write root"), "{err}");

        for action in [BranchAction::Commit, BranchAction::Keep] {
            let err = build(crate::SandboxBuilder::default().image(&image).on_exit(action.clone())).unwrap_err();
            assert!(err.to_string().contains("on_exit must be abort"), "{err}");
            let err = build(crate::SandboxBuilder::default().on_error(action).image(&image)).unwrap_err();
            assert!(err.to_string().contains("on_error must be abort"), "{err}");
        }
    }

    #[test]
    fn working_dir_is_created_and_pinned_inside_rootfs() {
        let outside = tempfile::tempdir().unwrap();
        let rootfs = tempfile::tempdir().unwrap();
        let r = rootfs.path();
        fs::create_dir_all(r.join("usr/src")).unwrap();
        std::os::unix::fs::symlink("/usr/src", r.join("app")).unwrap();
        std::os::unix::fs::symlink("../../../../../../..", r.join("up")).unwrap();
        std::os::unix::fs::symlink(outside.path(), r.join("out")).unwrap();

        assert_eq!(resolve_working_dir(r, "/work/dir").unwrap(), "/work/dir");
        assert!(r.join("work/dir").is_dir());
        assert_eq!(resolve_working_dir(r, "/app/proj").unwrap(), "/usr/src/proj");
        assert_eq!(resolve_working_dir(r, "/up").unwrap(), "/");
        let _ = resolve_working_dir(r, "/out/x");
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn stale_entry_without_config_is_rebuilt() {
        let cache = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(cache.path()));
        fs::create_dir_all(cache.dir.join("k/rootfs/old")).unwrap();

        let image = cache
            .get_or_build("k", |rootfs| {
                fs::write(rootfs.join("new"), b"").unwrap();
                Ok(ImageConfig::default())
            })
            .unwrap();
        assert!(image.rootfs.join("new").exists());
        assert!(!image.rootfs.join("old").exists());
    }

    #[test]
    fn losing_a_build_race_keeps_the_winner() {
        let cache = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(cache.path()));
        let image = cache
            .get_or_build("k", |rootfs| {
                // Another process finishes the same image mid-build.
                cache
                    .get_or_build("k", |r| {
                        fs::write(r.join("winner"), b"").unwrap();
                        Ok(ImageConfig::default())
                    })
                    .unwrap();
                fs::write(rootfs.join("loser"), b"").unwrap();
                Ok(ImageConfig::default())
            })
            .unwrap();
        assert!(image.rootfs.join("winner").exists());
        assert!(!image.rootfs.join("loser").exists());
        assert_eq!(fs::read_dir(&cache.dir).unwrap().count(), 1);
    }

    #[test]
    fn failed_build_leaves_nothing_behind() {
        let cache = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(cache.path()));
        let res = cache.get_or_build("k", |_| Err(SandboxRuntimeError::Child("boom".into()).into()));
        assert!(res.is_err());
        assert_eq!(fs::read_dir(&cache.dir).unwrap().count(), 0);
    }
}
