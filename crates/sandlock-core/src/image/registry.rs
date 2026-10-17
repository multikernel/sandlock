//! Pull images from a registry speaking the OCI distribution API.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::{header, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::AsyncWriteExt;

use super::oci::{self, Descriptor, Manifest, Parsed};
use super::{blocking, unpack, Cache, Image};
use crate::error::{SandboxRuntimeError, SandlockError};

const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.docker.distribution.manifest.v2+json";
const MAX_REDIRECTS: usize = 5;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn pull(cache: &Cache, reference: &str) -> Result<Image, SandlockError> {
    let reference = Reference::parse(reference)?;
    let basic = credentials(&docker_config_dir(), &reference.registry);
    let mut registry = Registry::new(reference, basic)?;

    let mut target = registry.reference.reference.clone();
    let manifest = loop {
        let bytes = registry.manifest(cache, &target).await?;
        match oci::parse_node(&bytes, &target)? {
            Parsed::Index(candidates) => target = oci::pick_platform(candidates)?.digest,
            Parsed::Manifest(manifest) => break manifest,
        }
    };
    let key = oci::digest_hex(&manifest.config.digest)?.to_string();
    if let Some(image) = cache.lookup(&key) {
        return Ok(image);
    }

    let staging = cache.temp_path("-blobs")?;
    let result = download_and_unpack(&mut registry, cache, &staging, key, manifest).await;
    let _ = std::fs::remove_dir_all(&staging);
    result
}

async fn download_and_unpack(
    registry: &mut Registry,
    cache: &Cache,
    staging: &Path,
    key: String,
    manifest: Manifest,
) -> Result<Image, SandlockError> {
    std::fs::create_dir_all(staging).map_err(SandboxRuntimeError::Io)?;
    // Authenticate once up front so the parallel downloads share the token.
    registry.ensure_auth().await?;
    let downloads = std::iter::once(&manifest.config)
        .chain(&manifest.layers)
        .map(|desc| registry.download(desc, staging));
    futures_util::future::try_join_all(downloads).await?;

    let (cache, staging) = (cache.clone(), staging.to_path_buf());
    blocking(move || {
        let blobs = oci::BlobDir(staging);
        cache.get_or_build(&key, |rootfs| unpack(&blobs, &manifest, rootfs))
    })
    .await
}

/// A parsed `docker://` reference (without the transport), normalized as
/// Docker and skopeo do.
#[derive(Debug, PartialEq)]
pub(super) struct Reference {
    registry: String,
    repository: String,
    /// A tag or a `sha256:` digest.
    reference: String,
}

impl Reference {
    pub fn parse(input: &str) -> Result<Self, SandlockError> {
        let bad = |why: &str| registry_error(format!("invalid image reference {input:?}: {why}"));
        let (name, digest) = match input.split_once('@') {
            Some((name, digest)) => {
                oci::digest_hex(digest)?;
                (name, Some(digest))
            }
            None => (input, None),
        };
        let (name, tag) = match name.rsplit_once(':') {
            Some((n, t)) if !t.contains('/') => (n, Some(t)),
            _ => (name, None),
        };
        if tag.is_some() && digest.is_some() {
            return Err(bad("a tag and a digest together are ambiguous; use one"));
        }
        let (registry, repository) = match name.split_once('/') {
            Some((host, rest)) if host.contains(['.', ':']) || host == "localhost" => {
                (host, rest.to_string())
            }
            _ => ("docker.io", name.to_string()),
        };
        let registry = if registry == "index.docker.io" {
            "docker.io"
        } else {
            registry
        };
        let repository = if registry == "docker.io" && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository
        };
        let valid_path = |p: &str| {
            !p.is_empty()
                && p.split('/').all(|c| {
                    let alnum = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
                    c.bytes().all(|b| alnum(&b) || b"._-".contains(&b))
                        && c.as_bytes().first().is_some_and(alnum)
                        && c.as_bytes().last().is_some_and(alnum)
                })
        };
        if !valid_path(&repository) {
            return Err(bad(
                "repository components are lowercase alphanumerics joined by '.', '_' or '-'",
            ));
        }
        if let Some(tag) = tag {
            if tag.is_empty()
                || tag.len() > 128
                || !tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err(bad("malformed tag"));
            }
        }
        let reference = digest.or(tag).unwrap_or("latest").to_string();
        Ok(Reference {
            registry: registry.to_string(),
            repository,
            reference,
        })
    }

    fn host(&self) -> &str {
        if self.registry == "docker.io" {
            "registry-1.docker.io"
        } else {
            &self.registry
        }
    }

    // Docker also talks plain HTTP to loopback registries by default.
    fn scheme(&self) -> &str {
        let host = self
            .registry
            .rsplit_once(':')
            .map_or(self.registry.as_str(), |(h, _)| h);
        if host == "localhost" || host == "127.0.0.1" || host == "[::1]" {
            "http"
        } else {
            "https"
        }
    }
}

struct Registry {
    reference: Reference,
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>,
    basic: Option<String>,
    authorization: Option<String>,
}

impl Registry {
    fn new(reference: Reference, basic: Option<String>) -> Result<Self, SandlockError> {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls::crypto::ring::default_provider())
            .map_err(SandboxRuntimeError::Io)?
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Registry {
            reference,
            client,
            basic,
            authorization: None,
        })
    }

    fn url(&self, path: &str) -> String {
        let r = &self.reference;
        format!("{}://{}/v2/{}/{path}", r.scheme(), r.host(), r.repository)
    }

    /// Fetch a manifest or index. Content addressed by digest is verified
    /// and kept in the cache, so a digest reference is served offline.
    async fn manifest(&mut self, cache: &Cache, reference: &str) -> Result<Vec<u8>, SandlockError> {
        let stored = oci::digest_hex(reference)
            .ok()
            .map(|hex| cache.dir.join("blobs/sha256").join(hex));
        if let Some(bytes) = stored.as_ref().and_then(|p| std::fs::read(p).ok()) {
            return Ok(bytes);
        }
        let resp = self
            .get(
                &self.url(&format!("manifests/{reference}")),
                Some(MANIFEST_TYPES),
            )
            .await?;
        let bytes = read_capped(resp, oci::MAX_JSON_BLOB, reference).await?;
        if let Some(path) = stored {
            let actual = sha256_hex(&bytes);
            if Some(actual.as_str()) != oci::digest_hex(reference).ok() {
                return Err(registry_error(format!(
                    "manifest {reference}: digest mismatch: got sha256:{actual}"
                )));
            }
            store_atomically(&path, &bytes)?;
        }
        Ok(bytes)
    }

    /// Stream a blob to `dir/<hex>`. Its digest is checked when it is read
    /// back for unpacking.
    async fn download(&self, desc: &Descriptor, dir: &Path) -> Result<(), SandlockError> {
        let hex = oci::digest_hex(&desc.digest)?;
        let mut resp = self
            .get_authorized(&self.url(&format!("blobs/{}", desc.digest)))
            .await?;
        let mut file = tokio::fs::File::create(dir.join(hex))
            .await
            .map_err(SandboxRuntimeError::Io)?;
        let mut written = 0u64;
        while let Some(frame) = resp.body_mut().frame().await {
            let frame = frame.map_err(|e| registry_error(format!("blob {}: {e}", desc.digest)))?;
            if let Ok(data) = frame.into_data() {
                written += data.len() as u64;
                if written > desc.size {
                    return Err(registry_error(format!(
                        "blob {}: larger than its descriptor",
                        desc.digest
                    )));
                }
                file.write_all(&data)
                    .await
                    .map_err(SandboxRuntimeError::Io)?;
            }
        }
        file.flush().await.map_err(SandboxRuntimeError::Io)?;
        Ok(())
    }

    /// Answer the registry's challenge, if it has one, before blob downloads
    /// run in parallel. A cached manifest means no request has been challenged yet.
    async fn ensure_auth(&mut self) -> Result<(), SandlockError> {
        if self.authorization.is_some() {
            return Ok(());
        }
        let r = &self.reference;
        let ping = format!("{}://{}/v2/", r.scheme(), r.host());
        let resp = self.send(&ping, None).await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            if let Some(challenge) = resp
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
            {
                let challenge = challenge.to_string();
                self.authorization = Some(self.authenticate(&challenge).await?);
            }
        }
        Ok(())
    }

    /// GET that answers an auth challenge once, then retries.
    async fn get(
        &mut self,
        url: &str,
        accept: Option<&str>,
    ) -> Result<Response<Incoming>, SandlockError> {
        let resp = self.send(url, accept).await?;
        if resp.status() != StatusCode::UNAUTHORIZED {
            return check_status(resp, url);
        }
        let challenge = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| registry_error(format!("{url}: unauthorized without a challenge")))?;
        self.authorization = Some(self.authenticate(&challenge).await?);
        check_status(self.send(url, accept).await?, url)
    }

    async fn get_authorized(&self, url: &str) -> Result<Response<Incoming>, SandlockError> {
        check_status(self.send(url, None).await?, url)
    }

    /// One request, following redirects. Credentials only go to the
    /// registry itself, never to the storage a blob redirects to.
    async fn send(
        &self,
        url: &str,
        accept: Option<&str>,
    ) -> Result<Response<Incoming>, SandlockError> {
        let origin: Uri = url
            .parse()
            .map_err(|e| registry_error(format!("{url}: {e}")))?;
        let mut uri = origin.clone();
        for _ in 0..=MAX_REDIRECTS {
            let mut req = Request::get(uri.clone());
            if let Some(accept) = accept {
                req = req.header(header::ACCEPT, accept);
            }
            if uri.authority() == origin.authority() {
                if let Some(auth) = &self.authorization {
                    req = req.header(header::AUTHORIZATION, auth);
                }
            }
            let req = req
                .body(Empty::new())
                .map_err(|e| registry_error(format!("{uri}: {e}")))?;
            let resp = tokio::time::timeout(RESPONSE_TIMEOUT, self.client.request(req))
                .await
                .map_err(|_| {
                    registry_error(format!(
                        "{uri}: no response in {}s",
                        RESPONSE_TIMEOUT.as_secs()
                    ))
                })?
                .map_err(|e| registry_error(format!("{uri}: {e}")))?;
            if !resp.status().is_redirection() {
                return Ok(resp);
            }
            let location = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| registry_error(format!("{uri}: redirect without a location")))?;
            uri = resolve_location(&uri, location)?;
        }
        Err(registry_error(format!("{url}: too many redirects")))
    }

    async fn authenticate(&self, challenge: &str) -> Result<String, SandlockError> {
        let (scheme, params) = parse_challenge(challenge);
        if scheme.eq_ignore_ascii_case("basic") {
            let basic = self.basic.as_ref().ok_or_else(|| {
                registry_error(format!(
                    "{} requires credentials (docker login)",
                    self.reference.registry
                ))
            })?;
            return Ok(format!("Basic {basic}"));
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(registry_error(format!(
                "unsupported auth scheme {scheme:?}"
            )));
        }
        let realm = params
            .iter()
            .find(|(k, _)| k == "realm")
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| registry_error("bearer challenge without a realm".into()))?;
        let scope = format!("repository:{}:pull", self.reference.repository);
        let mut query = vec![("scope", scope.as_str())];
        if let Some((_, service)) = params.iter().find(|(k, _)| k == "service") {
            query.push(("service", service));
        }
        let query: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{k}={}", percent_encode(v)))
            .collect();
        let sep = if realm.contains('?') { '&' } else { '?' };
        let url = format!("{realm}{sep}{}", query.join("&"));

        let uri: Uri = url
            .parse()
            .map_err(|e| registry_error(format!("token realm {realm}: {e}")))?;
        let mut req = Request::get(uri);
        if let Some(basic) = &self.basic {
            req = req.header(header::AUTHORIZATION, format!("Basic {basic}"));
        }
        let req = req
            .body(Empty::new())
            .map_err(|e| registry_error(e.to_string()))?;
        let resp = tokio::time::timeout(RESPONSE_TIMEOUT, self.client.request(req))
            .await
            .map_err(|_| registry_error(format!("{realm}: no response")))?
            .map_err(|e| registry_error(format!("{realm}: {e}")))?;
        let resp = check_status(resp, realm)?;
        let body = read_capped(resp, 1 << 20, realm).await?;
        #[derive(serde::Deserialize)]
        struct Token {
            token: Option<String>,
            access_token: Option<String>,
        }
        let token: Token = oci::parse_json(&body, realm)?;
        let token = token
            .token
            .or(token.access_token)
            .ok_or_else(|| registry_error(format!("{realm}: response carries no token")))?;
        Ok(format!("Bearer {token}"))
    }
}

fn check_status(resp: Response<Incoming>, url: &str) -> Result<Response<Incoming>, SandlockError> {
    match resp.status() {
        s if s.is_success() => Ok(resp),
        StatusCode::NOT_FOUND => Err(registry_error(format!("{url}: not found"))),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(registry_error(format!(
            "{url}: access denied (private image? try docker login)"
        ))),
        s => Err(registry_error(format!("{url}: HTTP {s}"))),
    }
}

async fn read_capped(
    resp: Response<Incoming>,
    cap: u64,
    what: &str,
) -> Result<Vec<u8>, SandlockError> {
    let mut body = resp.into_body();
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| registry_error(format!("{what}: {e}")))?;
        if let Ok(data) = frame.into_data() {
            if (out.len() + data.len()) as u64 > cap {
                return Err(registry_error(format!("{what}: response too large")));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

fn resolve_location(base: &Uri, location: &str) -> Result<Uri, SandlockError> {
    let bad = |e: String| registry_error(format!("redirect to {location}: {e}"));
    let target = if location.starts_with('/') {
        let scheme = base.scheme_str().unwrap_or("https");
        let authority = base.authority().map(|a| a.as_str()).unwrap_or_default();
        format!("{scheme}://{authority}{location}")
    } else {
        location.to_string()
    };
    let uri: Uri = target
        .parse()
        .map_err(|e: hyper::http::uri::InvalidUri| bad(e.to_string()))?;
    // Never downgrade a registry's HTTPS to plain HTTP on a redirect.
    if base.scheme_str() == Some("https") && uri.scheme_str() != Some("https") {
        return Err(bad("refusing to leave HTTPS".into()));
    }
    Ok(uri)
}

/// `Bearer realm="...",service="..."` into its scheme and parameters.
fn parse_challenge(header: &str) -> (String, Vec<(String, String)>) {
    let header = header.trim();
    let (scheme, rest) = header.split_once(' ').unwrap_or((header, ""));
    let mut params = Vec::new();
    let mut chars = rest.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(c) if *c == ',' || c.is_whitespace()) {
            chars.next();
        }
        let key: String = chars
            .by_ref()
            .take_while(|c| *c != '=')
            .collect::<String>()
            .trim()
            .to_string();
        if key.is_empty() {
            break;
        }
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => value.extend(chars.next()),
                    '"' => break,
                    c => value.push(c),
                }
            }
        } else {
            value = chars
                .by_ref()
                .take_while(|c| *c != ',')
                .collect::<String>()
                .trim()
                .to_string();
        }
        params.push((key.to_ascii_lowercase(), value));
    }
    (scheme.to_string(), params)
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' | b'/' => {
                (b as char).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect()
}

fn docker_config_dir() -> PathBuf {
    std::env::var_os("DOCKER_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".docker")
        })
}

/// Base64 `user:password` for `registry` from `docker login`'s config.
/// Credential helpers are external programs and deliberately not run.
fn credentials(config_dir: &Path, registry: &str) -> Option<String> {
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config_dir.join("config.json")).ok()?).ok()?;
    let wanted: &[&str] = if registry == "docker.io" {
        &["docker.io", "index.docker.io", "registry-1.docker.io"]
    } else {
        &[registry]
    };
    config
        .get("auths")?
        .as_object()?
        .iter()
        .find_map(|(key, entry)| {
            let host = key
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            let host = host.split('/').next().unwrap_or(host);
            if !wanted.contains(&host) {
                return None;
            }
            let auth = entry.get("auth")?.as_str()?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(auth)
                .ok()?;
            decoded.contains(&b':').then(|| auth.to_string())
        })
}

fn store_atomically(path: &Path, bytes: &[u8]) -> Result<(), SandlockError> {
    let dir = path.parent().expect("blob path has a parent");
    std::fs::create_dir_all(dir).map_err(SandboxRuntimeError::Io)?;
    let tmp = dir.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, bytes).map_err(SandboxRuntimeError::Io)?;
    std::fs::rename(&tmp, path).map_err(SandboxRuntimeError::Io)?;
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn registry_error(msg: String) -> SandlockError {
    SandboxRuntimeError::Child(format!("registry: {msg}")).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::oci::tests::{tar_of, TestLayout};
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn parsed(s: &str) -> (String, String, String) {
        let r = Reference::parse(s).unwrap();
        (r.registry, r.repository, r.reference)
    }

    #[test]
    fn references_normalize_like_docker() {
        let t = |a: &str, b: &str, c: &str| (a.to_string(), b.to_string(), c.to_string());
        assert_eq!(parsed("ubuntu"), t("docker.io", "library/ubuntu", "latest"));
        assert_eq!(
            parsed("python:3.12-slim"),
            t("docker.io", "library/python", "3.12-slim")
        );
        assert_eq!(
            parsed("bitnami/redis:7"),
            t("docker.io", "bitnami/redis", "7")
        );
        assert_eq!(
            parsed("index.docker.io/library/alpine"),
            t("docker.io", "library/alpine", "latest")
        );
        assert_eq!(
            parsed("ghcr.io/org/tool:v1"),
            t("ghcr.io", "org/tool", "v1")
        );
        assert_eq!(
            parsed("localhost:5000/img"),
            t("localhost:5000", "img", "latest")
        );
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            parsed(&format!("ghcr.io/o/i@{digest}")),
            t("ghcr.io", "o/i", &digest)
        );
        assert!(Reference::parse(&format!("ghcr.io/o/i:v1@{digest}")).is_err());
        assert!(Reference::parse("Ubuntu").is_err());
        assert!(Reference::parse("ubuntu@sha256:short").is_err());
        assert!(Reference::parse("ubuntu:bad/tag?").is_err());
        assert!(Reference::parse("ghcr.io/../x").is_err());
        assert!(Reference::parse("ghcr.io/org/-x").is_err());
    }

    #[test]
    fn scheme_is_plain_http_only_for_loopback() {
        assert_eq!(
            Reference::parse("localhost:5000/a").unwrap().scheme(),
            "http"
        );
        assert_eq!(
            Reference::parse("127.0.0.1:5000/a").unwrap().scheme(),
            "http"
        );
        assert_eq!(Reference::parse("ghcr.io/a").unwrap().scheme(), "https");
        assert_eq!(
            Reference::parse("a").unwrap().host(),
            "registry-1.docker.io"
        );
    }

    #[test]
    fn challenge_parameters_are_parsed() {
        let (scheme, params) = parse_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull,push""#,
        );
        assert_eq!(scheme, "Bearer");
        assert_eq!(
            params[0],
            ("realm".into(), "https://auth.docker.io/token".into())
        );
        assert_eq!(params[1], ("service".into(), "registry.docker.io".into()));
        assert_eq!(
            params[2],
            ("scope".into(), "repository:library/ubuntu:pull,push".into())
        );
        assert_eq!(parse_challenge("Basic realm=reg").0, "Basic");
    }

    #[test]
    fn redirects_resolve_and_never_downgrade() {
        let base: Uri = "https://reg.io/v2/a/blobs/x".parse().unwrap();
        assert_eq!(
            resolve_location(&base, "/cdn/x").unwrap().to_string(),
            "https://reg.io/cdn/x"
        );
        assert_eq!(
            resolve_location(&base, "https://cdn.io/x?sig=1")
                .unwrap()
                .to_string(),
            "https://cdn.io/x?sig=1"
        );
        assert!(resolve_location(&base, "http://cdn.io/x").is_err());
    }

    #[test]
    fn credentials_come_from_docker_config_auths() {
        let dir = tempfile::tempdir().unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode("user:pw");
        let config = serde_json::json!({"auths": {
            "https://index.docker.io/v1/": {"auth": auth},
            "ghcr.io": {"auth": auth},
            "helper.io": {},
        }, "credsStore": "desktop"});
        std::fs::write(dir.path().join("config.json"), config.to_string()).unwrap();
        assert_eq!(
            credentials(dir.path(), "docker.io").as_deref(),
            Some(auth.as_str())
        );
        assert_eq!(
            credentials(dir.path(), "ghcr.io").as_deref(),
            Some(auth.as_str())
        );
        assert_eq!(credentials(dir.path(), "helper.io"), None);
        assert_eq!(credentials(dir.path(), "quay.io"), None);
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// A registry that demands a bearer token and serves blobs through a
    /// redirect to another authority, which must not see the token.
    async fn serve(
        layout: Arc<TestLayout>,
        tag_target: String,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let layout = layout.clone();
                let tag_target = tag_target.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let layout = layout.clone();
                        let tag_target = tag_target.clone();
                        async move {
                            let path = req.uri().path().to_string();
                            let auth = req
                                .headers()
                                .get(header::AUTHORIZATION)
                                .map(|v| v.to_str().unwrap().to_string());
                            let reply = |status: u16, body: Vec<u8>| {
                                Response::builder()
                                    .status(status)
                                    .body(http_body_util::Full::new(Bytes::from(body)))
                                    .unwrap()
                            };
                            let blob = |hex: &str| {
                                std::fs::read(layout.path().join("blobs/sha256").join(hex)).ok()
                            };
                            if path == "/token" {
                                let q = req.uri().query().unwrap_or_default();
                                assert!(q.contains("scope=repository:test/img:pull"), "{q}");
                                return Ok::<_, std::convert::Infallible>(reply(
                                    200,
                                    br#"{"token":"t0k"}"#.to_vec(),
                                ));
                            }
                            if let Some(hex) = path.strip_prefix("/storage/") {
                                if auth.is_some() {
                                    return Ok(reply(400, b"token leaked to storage".to_vec()));
                                }
                                return Ok(
                                    blob(hex).map_or_else(|| reply(404, vec![]), |b| reply(200, b))
                                );
                            }
                            if auth.as_deref() != Some("Bearer t0k") {
                                let mut r = reply(401, vec![]);
                                let challenge =
                                    format!(r#"Bearer realm="http://{addr}/token",service="test""#);
                                r.headers_mut()
                                    .insert(header::WWW_AUTHENTICATE, challenge.parse().unwrap());
                                return Ok(r);
                            }
                            if path == "/v2/" {
                                return Ok(reply(200, vec![]));
                            }
                            if let Some(r) = path.strip_prefix("/v2/test/img/manifests/") {
                                let digest = if r.starts_with("sha256:") {
                                    r.to_string()
                                } else {
                                    tag_target.clone()
                                };
                                let hex = digest.trim_start_matches("sha256:");
                                return Ok(
                                    blob(hex).map_or_else(|| reply(404, vec![]), |b| reply(200, b))
                                );
                            }
                            if let Some(d) = path.strip_prefix("/v2/test/img/blobs/sha256:") {
                                let mut r = reply(307, vec![]);
                                let to = format!("http://localhost:{}/storage/{d}", addr.port());
                                r.headers_mut()
                                    .insert(header::LOCATION, to.parse().unwrap());
                                return Ok(r);
                            }
                            Ok(reply(404, vec![]))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn pulls_through_auth_and_redirects_then_serves_digests_offline() {
        let layout = TestLayout::new();
        let img = layout.image(
            &[
                (
                    "application/vnd.oci.image.layer.v1.tar+gzip",
                    gzip(&tar_of(&[("etc/motd", b"one")])),
                ),
                (
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    gzip(&tar_of(&[("etc/motd", b"two")])),
                ),
            ],
            serde_json::json!({"config": {"Env": ["A=1"]}}),
        );
        let mut img = img;
        img["platform"] = serde_json::json!({"os": "linux", "architecture": super::oci::tests::host_arch_for_tests()});
        let index = serde_json::json!({"schemaVersion": 2, "manifests": [img]});
        let index = layout.blob(
            "application/vnd.oci.image.index.v1+json",
            index.to_string().as_bytes(),
        );
        let index_digest = index["digest"].as_str().unwrap().to_string();

        let (addr, server) = serve(Arc::new(layout), index_digest.clone()).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(cache_dir.path()));

        let image = pull(&cache, &format!("{addr}/test/img:v1")).await.unwrap();
        assert_eq!(
            std::fs::read(image.rootfs.join("etc/motd")).unwrap(),
            b"two"
        );
        assert_eq!(image.config.env, vec!["A=1"]);

        let by_digest = format!("{addr}/test/img@{index_digest}");
        pull(&cache, &by_digest).await.unwrap();
        server.abort();
        let _ = server.await;
        let offline = pull(&cache, &by_digest).await.unwrap();
        assert_eq!(offline.rootfs, image.rootfs);

        let mut names: Vec<String> = std::fs::read_dir(cache_dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names.len(),
            2,
            "one image and the manifest store, no staging left: {names:?}"
        );
        assert!(names.contains(&"blobs".to_string()));
    }
}
