//! OCI image layouts: resolve a manifest, read blobs with digest
//! verification, and unpack layers onto a rootfs.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::layer::apply_layer;
use super::ImageConfig;
use crate::error::{SandboxRuntimeError, SandlockError};

const REF_NAME: &str = "org.opencontainers.image.ref.name";
// Index and manifest JSON is read into memory; real ones are a few KiB.
pub(super) const MAX_JSON_BLOB: u64 = 4 << 20;

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct Descriptor {
    #[serde(default)]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default)]
    platform: Option<Platform>,
    #[serde(default)]
    annotations: HashMap<String, String>,
}

#[derive(Deserialize, Clone, Debug)]
struct Platform {
    architecture: String,
    os: String,
}

/// An index or a manifest: registries and layouts do not always label
/// which one a descriptor points at, so the shape decides.
#[derive(Deserialize)]
struct Node {
    manifests: Option<Vec<Descriptor>>,
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

pub(super) struct Manifest {
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

#[derive(Deserialize, Default)]
struct ConfigBlob {
    #[serde(default)]
    config: Option<RunConfig>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct RunConfig {
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    env: Option<Vec<String>>,
    working_dir: Option<String>,
}

/// Where the blobs of an image layout live.
pub(super) trait Blobs {
    fn index(&self) -> io::Result<Vec<u8>>;
    fn open(&self, hex: &str) -> io::Result<Box<dyn Read + '_>>;
}

/// An OCI image layout directory.
pub(super) struct LayoutDir {
    root: PathBuf,
}

impl LayoutDir {
    pub fn open(root: &Path) -> Result<Self, SandlockError> {
        if !root.join("index.json").is_file() {
            return Err(oci_error(format!("{}: not an OCI image layout (no index.json)", root.display())));
        }
        Ok(LayoutDir { root: root.to_path_buf() })
    }
}

impl Blobs for LayoutDir {
    fn index(&self) -> io::Result<Vec<u8>> {
        std::fs::read(self.root.join("index.json"))
    }

    fn open(&self, hex: &str) -> io::Result<Box<dyn Read + '_>> {
        Ok(Box::new(File::open(self.root.join("blobs/sha256").join(hex))?))
    }
}

/// A bare directory of blobs named by their sha256 hex.
#[cfg(feature = "http")]
pub(super) struct BlobDir(pub PathBuf);

#[cfg(feature = "http")]
impl Blobs for BlobDir {
    fn index(&self) -> io::Result<Vec<u8>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "a blob directory has no index"))
    }

    fn open(&self, hex: &str) -> io::Result<Box<dyn Read + '_>> {
        Ok(Box::new(File::open(self.0.join(hex))?))
    }
}

/// A tar of an OCI image layout, read in place: one scan records where
/// each member lives, and blobs are then served by seeking.
pub(super) struct LayoutArchive {
    path: PathBuf,
    members: HashMap<String, (u64, u64)>,
}

impl LayoutArchive {
    pub fn open(path: &Path) -> Result<Self, SandlockError> {
        let file = File::open(path).map_err(SandboxRuntimeError::Io)?;
        let mut archive = tar::Archive::new(BufReader::new(file));
        let mut members = HashMap::new();
        for entry in archive.entries().map_err(SandboxRuntimeError::Io)? {
            let entry = entry.map_err(SandboxRuntimeError::Io)?;
            if entry.header().entry_type() != tar::EntryType::Regular {
                continue;
            }
            let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
            let name = name.trim_start_matches("./").to_string();
            members.insert(name, (entry.raw_file_position(), entry.size()));
        }
        if !members.contains_key("index.json") {
            return Err(oci_error(format!(
                "{}: not an OCI image archive (no index.json)",
                path.display()
            )));
        }
        Ok(LayoutArchive { path: path.to_path_buf(), members })
    }

    fn member(&self, name: &str) -> io::Result<io::Take<File>> {
        let &(offset, size) = self
            .members
            .get(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} not in archive")))?;
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(offset))?;
        Ok(file.take(size))
    }
}

impl Blobs for LayoutArchive {
    fn index(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.member("index.json")?.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn open(&self, hex: &str) -> io::Result<Box<dyn Read + '_>> {
        Ok(Box::new(self.member(&format!("blobs/sha256/{hex}"))?))
    }
}

/// Pick the manifest for this host from the layout's index, descending
/// through nested indexes. `tag` selects by `org.opencontainers.image.ref.name`.
pub(super) fn resolve(blobs: &dyn Blobs, tag: Option<&str>) -> Result<Manifest, SandlockError> {
    let index = blobs.index().map_err(|e| oci_error(format!("index.json: {e}")))?;
    let Parsed::Index(mut candidates) = parse_node(&index, "index.json")? else {
        return Err(oci_error("index.json is not an index".into()));
    };
    if let Some(tag) = tag {
        candidates.retain(|d| d.annotations.get(REF_NAME).map(String::as_str) == Some(tag));
        if candidates.is_empty() {
            return Err(oci_error(format!("no image tagged {tag:?} in the layout")));
        }
    }
    loop {
        let desc = pick_platform(candidates)?;
        match parse_node(&read_json_blob(blobs, &desc)?, &desc.digest)? {
            Parsed::Index(nested) => candidates = nested,
            Parsed::Manifest(manifest) => return Ok(manifest),
        }
    }
}

pub(super) enum Parsed {
    Index(Vec<Descriptor>),
    Manifest(Manifest),
}

pub(super) fn parse_node(bytes: &[u8], what: &str) -> Result<Parsed, SandlockError> {
    let node: Node = parse_json(bytes, what)?;
    match (node.manifests, node.config) {
        (Some(manifests), _) => Ok(Parsed::Index(manifests)),
        (None, Some(config)) => Ok(Parsed::Manifest(Manifest { config, layers: node.layers })),
        (None, None) => Err(oci_error(format!("{what}: neither an index nor a manifest"))),
    }
}

pub(super) fn pick_platform(candidates: Vec<Descriptor>) -> Result<Descriptor, SandlockError> {
    let arch = host_arch();
    let fits = |d: &Descriptor| d.platform.as_ref().is_none_or(|p| p.os == "linux" && p.architecture == arch);
    let offered: Vec<String> = candidates
        .iter()
        .filter_map(|d| d.platform.as_ref().map(|p| format!("{}/{}", p.os, p.architecture)))
        .collect();
    let mut fitting = candidates.into_iter().filter(fits);
    match (fitting.next(), fitting.next()) {
        (Some(d), None) => Ok(d),
        (Some(_), Some(_)) => Err(oci_error("several images fit this host; select one with :<tag>".into())),
        (None, _) if offered.is_empty() => Err(oci_error("index lists no images".into())),
        (None, _) => Err(oci_error(format!("no linux/{arch} image (offered: {})", offered.join(", ")))),
    }
}

fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "powerpc64" => "ppc64le",
        other => other,
    }
}

pub(super) fn config(blobs: &dyn Blobs, manifest: &Manifest) -> Result<ImageConfig, SandlockError> {
    let blob: ConfigBlob = parse_json(&read_json_blob(blobs, &manifest.config)?, &manifest.config.digest)?;
    let run = blob.config.unwrap_or_default();
    Ok(ImageConfig {
        entrypoint: run.entrypoint.unwrap_or_default(),
        cmd: run.cmd.unwrap_or_default(),
        env: run.env.unwrap_or_default(),
        working_dir: run.working_dir.filter(|w| !w.is_empty()),
    })
}

/// Apply every layer of `manifest`, in order, onto `root`.
pub(super) fn unpack(blobs: &dyn Blobs, manifest: &Manifest, root: &Path) -> Result<(), SandlockError> {
    for desc in &manifest.layers {
        let raw = verified(blobs, desc)?;
        match compression(&desc.media_type)? {
            Compression::None => {
                let mut raw = raw;
                apply_layer(root, &mut raw)?;
                drain(raw, desc)?;
            }
            Compression::Gzip => {
                let mut dec = flate2::read::GzDecoder::new(raw);
                apply_layer(root, &mut dec)?;
                drain(&mut dec, desc)?;
                drain(dec.into_inner(), desc)?;
            }
            Compression::Zstd => {
                let mut dec = ZstdReader::new(BufReader::new(raw));
                apply_layer(root, &mut dec)?;
                drain(&mut dec, desc)?;
                drain(dec.src, desc)?;
            }
        }
    }
    Ok(())
}

enum Compression {
    None,
    Gzip,
    Zstd,
}

fn compression(media_type: &str) -> Result<Compression, SandlockError> {
    if media_type.ends_with("+gzip") || media_type.ends_with(".tar.gzip") {
        Ok(Compression::Gzip)
    } else if media_type.ends_with("+zstd") {
        Ok(Compression::Zstd)
    } else if media_type.ends_with(".tar") {
        Ok(Compression::None)
    } else {
        Err(oci_error(format!("unsupported layer media type {media_type:?}")))
    }
}

/// Read to EOF: the tar reader stops at the end-of-archive marker, but the
/// digest (and the gzip trailer) only check out once every byte is consumed.
fn drain(mut r: impl Read, desc: &Descriptor) -> Result<(), SandlockError> {
    io::copy(&mut r, &mut io::sink()).map_err(|e| oci_error(format!("{}: {e}", desc.digest)))?;
    Ok(())
}

fn read_json_blob(blobs: &dyn Blobs, desc: &Descriptor) -> Result<Vec<u8>, SandlockError> {
    if desc.size > MAX_JSON_BLOB {
        return Err(oci_error(format!("{}: {} bytes is too large for metadata", desc.digest, desc.size)));
    }
    let mut buf = Vec::with_capacity(desc.size as usize);
    verified(blobs, desc)?
        .read_to_end(&mut buf)
        .map_err(|e| oci_error(format!("{}: {e}", desc.digest)))?;
    Ok(buf)
}

fn verified<'a>(blobs: &'a dyn Blobs, desc: &Descriptor) -> Result<Verified<Box<dyn Read + 'a>>, SandlockError> {
    let hex = digest_hex(&desc.digest)?;
    let inner = blobs.open(hex).map_err(|e| oci_error(format!("blob {}: {e}", desc.digest)))?;
    Ok(Verified {
        inner,
        ctx: ring::digest::Context::new(&ring::digest::SHA256),
        expected: hex.to_string(),
        remaining: desc.size,
    })
}

/// The hex part of a `sha256:` digest, validated so it can name a file.
pub(super) fn digest_hex(digest: &str) -> Result<&str, SandlockError> {
    match digest.split_once(':') {
        Some(("sha256", hex)) if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) => {
            Ok(hex)
        }
        _ => Err(oci_error(format!("unsupported or malformed digest {digest:?}"))),
    }
}

/// Hashes everything read through it and fails at EOF unless the content
/// matches the descriptor's size and digest.
struct Verified<R> {
    inner: R,
    ctx: ring::digest::Context,
    expected: String,
    remaining: u64,
}

impl<R: Read> Read for Verified<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.remaining {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "blob larger than its descriptor"));
        }
        self.remaining -= n as u64;
        self.ctx.update(&buf[..n]);
        if n == 0 && !buf.is_empty() {
            if self.remaining != 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "blob shorter than its descriptor"));
            }
            let actual: String = self.ctx.clone().finish().as_ref().iter().map(|b| format!("{b:02x}")).collect();
            if actual != self.expected {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("digest mismatch: got sha256:{actual}")));
            }
        }
        Ok(n)
    }
}

/// zstd decoder spanning every frame of a stream, skipping skippable frames
/// (zstd:chunked layers are many frames plus skippable metadata).
struct ZstdReader<R> {
    src: R,
    frame: ruzstd::decoding::FrameDecoder,
    in_frame: bool,
}

impl<R: BufRead> ZstdReader<R> {
    fn new(src: R) -> Self {
        ZstdReader { src, frame: ruzstd::decoding::FrameDecoder::new(), in_frame: false }
    }
}

impl<R: BufRead> Read for ZstdReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
        use ruzstd::decoding::BlockDecodingStrategy;
        let invalid = |e: FrameDecoderError| io::Error::new(io::ErrorKind::InvalidData, format!("zstd: {e}"));
        loop {
            if self.in_frame {
                if self.frame.can_collect() > 0 {
                    return self.frame.read(buf);
                }
                if !self.frame.is_finished() {
                    self.frame
                        .decode_blocks(&mut self.src, BlockDecodingStrategy::UptoBytes(buf.len().max(1)))
                        .map_err(invalid)?;
                    continue;
                }
                self.in_frame = false;
            }
            if self.src.fill_buf()?.is_empty() {
                return Ok(0);
            }
            match self.frame.init(&mut self.src) {
                Ok(()) => self.in_frame = true,
                Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame { length, .. })) => {
                    io::copy(&mut (&mut self.src).take(length as u64), &mut io::sink())?;
                }
                Err(e) => return Err(invalid(e)),
            }
        }
    }
}

pub(super) fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], what: &str) -> Result<T, SandlockError> {
    serde_json::from_slice(bytes).map_err(|e| oci_error(format!("{what}: {e}")))
}

pub(super) fn oci_error(msg: String) -> SandlockError {
    SandboxRuntimeError::Child(format!("image: {msg}")).into()
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::fs;

    #[cfg(feature = "http")]
    pub(in crate::image) fn host_arch_for_tests() -> &'static str {
        host_arch()
    }

    pub(in crate::image) fn sha256_hex(data: &[u8]) -> String {
        ring::digest::digest(&ring::digest::SHA256, data).as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Builds an OCI image layout directory for tests.
    pub(in crate::image) struct TestLayout {
        pub dir: tempfile::TempDir,
    }

    impl TestLayout {
        pub fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir_all(dir.path().join("blobs/sha256")).unwrap();
            fs::write(dir.path().join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
            TestLayout { dir }
        }

        pub fn blob(&self, media_type: &str, data: &[u8]) -> serde_json::Value {
            let hex = sha256_hex(data);
            fs::write(self.dir.path().join("blobs/sha256").join(&hex), data).unwrap();
            serde_json::json!({"mediaType": media_type, "digest": format!("sha256:{hex}"), "size": data.len()})
        }

        pub fn image(&self, layers: &[(&str, Vec<u8>)], config: serde_json::Value) -> serde_json::Value {
            let config = self.blob("application/vnd.oci.image.config.v1+json", config.to_string().as_bytes());
            let layers: Vec<_> = layers.iter().map(|(mt, data)| self.blob(mt, data)).collect();
            let manifest = serde_json::json!({"schemaVersion": 2, "config": config, "layers": layers});
            self.blob("application/vnd.oci.image.manifest.v1+json", manifest.to_string().as_bytes())
        }

        pub fn index(&self, manifests: Vec<serde_json::Value>) {
            let index = serde_json::json!({"schemaVersion": 2, "manifests": manifests});
            fs::write(self.dir.path().join("index.json"), index.to_string()).unwrap();
        }

        pub fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    pub(in crate::image) fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_path(path).unwrap();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn zstd_frames(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in parts {
            // A skippable frame between data frames, as zstd:chunked emits.
            out.extend_from_slice(&0x184D2A50u32.to_le_bytes());
            out.extend_from_slice(&4u32.to_le_bytes());
            out.extend_from_slice(b"meta");
            out.extend(ruzstd::encoding::compress_to_vec(*part, ruzstd::encoding::CompressionLevel::Fastest));
        }
        out
    }

    fn with_platform(mut desc: serde_json::Value, arch: &str) -> serde_json::Value {
        desc["platform"] = serde_json::json!({"os": "linux", "architecture": arch});
        desc
    }

    fn with_tag(mut desc: serde_json::Value, tag: &str) -> serde_json::Value {
        desc["annotations"] = serde_json::json!({REF_NAME: tag});
        desc
    }

    fn unpack_layout(layout: &TestLayout, tag: Option<&str>) -> Result<(tempfile::TempDir, ImageConfig), SandlockError> {
        let blobs = LayoutDir::open(layout.path())?;
        let manifest = resolve(&blobs, tag)?;
        let root = tempfile::tempdir().unwrap();
        unpack(&blobs, &manifest, root.path())?;
        Ok((root, config(&blobs, &manifest)?))
    }

    #[test]
    fn unpacks_mixed_compression_layers_in_order() {
        let layout = TestLayout::new();
        let base = tar_of(&[("etc/motd", b"base"), ("etc/issue", b"base")]);
        let mid = tar_of(&[("etc/.wh.issue", b""), ("bin/tool", b"t")]);
        // Split one tar across two zstd frames to cover multi-frame streams.
        let top = tar_of(&[("etc/motd", b"top")]);
        let (a, b) = top.split_at(700);
        let img = layout.image(
            &[
                ("application/vnd.oci.image.layer.v1.tar+gzip", gzip(&base)),
                ("application/vnd.oci.image.layer.v1.tar", mid),
                ("application/vnd.oci.image.layer.v1.tar+zstd", zstd_frames(&[a, b])),
            ],
            serde_json::json!({"config": {"Cmd": ["/bin/tool"], "Env": ["PATH=/bin"], "WorkingDir": "/srv"}}),
        );
        layout.index(vec![img]);

        let (root, cfg) = unpack_layout(&layout, None).unwrap();
        assert_eq!(fs::read(root.path().join("etc/motd")).unwrap(), b"top");
        assert!(!root.path().join("etc/issue").exists());
        assert!(root.path().join("bin/tool").is_file());
        assert_eq!(cfg.cmd, vec!["/bin/tool"]);
        assert_eq!(cfg.env, vec!["PATH=/bin"]);
        assert_eq!(cfg.working_dir.as_deref(), Some("/srv"));
    }

    #[test]
    fn nested_index_selects_host_platform() {
        let layout = TestLayout::new();
        let cfg = serde_json::json!({"config": {}});
        let host = layout.image(&[("application/vnd.oci.image.layer.v1.tar", tar_of(&[("host", b"")]))], cfg.clone());
        let other = layout.image(&[("application/vnd.oci.image.layer.v1.tar", tar_of(&[("other", b"")]))], cfg);
        let other_arch = if host_arch() == "s390x" { "amd64" } else { "s390x" };
        let nested = serde_json::json!({"schemaVersion": 2, "manifests": [
            with_platform(other, other_arch),
            with_platform(host, host_arch()),
        ]});
        let nested = layout.blob("application/vnd.oci.image.index.v1+json", nested.to_string().as_bytes());
        layout.index(vec![nested]);

        let (root, _) = unpack_layout(&layout, None).unwrap();
        assert!(root.path().join("host").exists());
        assert!(!root.path().join("other").exists());
    }

    #[test]
    fn tag_selects_among_several_images() {
        let layout = TestLayout::new();
        let cfg = serde_json::json!({});
        let a = layout.image(&[("application/vnd.oci.image.layer.v1.tar", tar_of(&[("a", b"")]))], cfg.clone());
        let b = layout.image(&[("application/vnd.oci.image.layer.v1.tar", tar_of(&[("b", b"")]))], cfg);
        layout.index(vec![with_tag(a, "one"), with_tag(b, "two")]);

        assert!(unpack_layout(&layout, None).is_err());
        let (root, _) = unpack_layout(&layout, Some("two")).unwrap();
        assert!(root.path().join("b").exists());
        assert!(unpack_layout(&layout, Some("three")).is_err());
    }

    #[test]
    fn foreign_platform_only_is_rejected() {
        let layout = TestLayout::new();
        let img = layout.image(&[], serde_json::json!({}));
        let foreign = if host_arch() == "s390x" { "amd64" } else { "s390x" };
        layout.index(vec![with_platform(img, foreign)]);
        let err = unpack_layout(&layout, None).err().unwrap().to_string();
        assert!(err.contains(foreign), "{err}");
    }

    #[test]
    fn tampered_layer_fails_verification() {
        let layout = TestLayout::new();
        let img = layout.image(
            &[("application/vnd.oci.image.layer.v1.tar", tar_of(&[("f", b"original")]))],
            serde_json::json!({}),
        );
        layout.index(vec![img]);
        let blobs = LayoutDir::open(layout.path()).unwrap();
        let manifest = resolve(&blobs, None).unwrap();
        let hex = digest_hex(&manifest.layers[0].digest).unwrap().to_string();
        let blob = layout.path().join("blobs/sha256").join(&hex);
        let tampered = fs::read(&blob).unwrap().iter().map(|b| if *b == b'o' { b'O' } else { *b }).collect::<Vec<_>>();
        fs::write(&blob, tampered).unwrap();

        let root = tempfile::tempdir().unwrap();
        let err = unpack(&blobs, &manifest, root.path()).err().unwrap().to_string();
        assert!(err.contains("digest mismatch"), "{err}");
    }

    #[test]
    fn digest_must_be_lowercase_sha256_hex() {
        assert!(digest_hex(&format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(digest_hex("sha256:../../../etc/passwd").is_err());
        assert!(digest_hex(&format!("sha512:{}", "a".repeat(128))).is_err());
        assert!(digest_hex(&format!("sha256:{}", "A".repeat(64))).is_err());
    }

    #[test]
    fn archive_serves_the_same_blobs_as_the_directory() {
        let layout = TestLayout::new();
        let img = layout.image(
            &[("application/vnd.oci.image.layer.v1.tar", tar_of(&[("inside", b"x")]))],
            serde_json::json!({}),
        );
        layout.index(vec![img]);
        let tar_path = layout.path().with_extension("tar");
        let mut b = tar::Builder::new(File::create(&tar_path).unwrap());
        b.append_dir_all(".", layout.path()).unwrap();
        b.finish().unwrap();

        let blobs = LayoutArchive::open(&tar_path).unwrap();
        let manifest = resolve(&blobs, None).unwrap();
        let root = tempfile::tempdir().unwrap();
        unpack(&blobs, &manifest, root.path()).unwrap();
        assert_eq!(fs::read(root.path().join("inside")).unwrap(), b"x");
        fs::remove_file(tar_path).unwrap();
    }
}
