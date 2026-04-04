use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::{Request, Response, StatusCode};
use hudsucker::rcgen::{CertificateParams, KeyPair};
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::policy::{http_acl_check, HttpRule};

/// Shared map from proxy client address to the original destination IP
/// that the sandboxed process tried to connect to. Written by the seccomp
/// supervisor on redirect, read by the proxy handler to verify the Host header.
pub type OrigDestMap = Arc<std::sync::RwLock<HashMap<SocketAddr, IpAddr>>>;

/// ACL-enforcing HTTP handler for hudsucker.
#[derive(Clone)]
struct AclHandler {
    allow_rules: Arc<Vec<HttpRule>>,
    deny_rules: Arc<Vec<HttpRule>>,
    /// Map of client_addr → original destination IP, populated by supervisor.
    orig_dest: OrigDestMap,
}

impl AclHandler {
    /// Verify that the claimed host resolves to the original destination IP.
    /// Returns true if verification passes or is not applicable.
    async fn verify_host(&self, client_addr: &SocketAddr, claimed_host: &str) -> bool {
        // Look up the original dest IP recorded by the supervisor.
        let orig_ip = {
            let map = self.orig_dest.read().unwrap_or_else(|e| e.into_inner());
            map.get(client_addr).copied()
        };

        let orig_ip = match orig_ip {
            Some(ip) => ip,
            // No mapping means the connection wasn't redirected by us — allow.
            None => return true,
        };

        // If the claimed host is already an IP, compare directly.
        if let Ok(ip) = claimed_host.parse::<IpAddr>() {
            return ip == orig_ip;
        }

        // Resolve the claimed hostname and check if any result matches.
        let lookup = format!("{}:0", claimed_host);
        let resolved = tokio::net::lookup_host(&lookup).await;
        match resolved {
            Ok(addrs) => addrs
                .into_iter()
                .any(|sa| sa.ip() == orig_ip),
            // DNS failure for the claimed host — deny.
            Err(_) => false,
        }
    }
}

impl HttpHandler for AclHandler {
    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let method = req.method().as_str().to_string();

        // Extract host from URI authority or Host header.
        let host = req
            .uri()
            .host()
            .map(|h| h.to_string())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|h| {
                        // Strip port from host header if present.
                        h.split(':').next().unwrap_or(h).to_string()
                    })
            })
            .unwrap_or_default();

        let path = req.uri().path().to_string();

        // Verify the Host header matches the original destination IP to
        // prevent spoofing (e.g. Host: allowed.com while connecting to evil.com).
        if !self.verify_host(&ctx.client_addr, &host).await {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Blocked by sandlock: Host header does not match connection destination"))
                .expect("failed to build 403 response")
                .into();
        }

        if http_acl_check(&self.allow_rules, &self.deny_rules, &method, &host, &path) {
            // Clean up the mapping now that the request has been validated.
            if let Ok(mut map) = self.orig_dest.write() {
                map.remove(&ctx.client_addr);
            }
            req.into()
        } else {
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Blocked by sandlock HTTP ACL policy"))
                .expect("failed to build 403 response")
                .into()
        }
    }
}

/// Handle returned by [`spawn_http_acl_proxy`].
pub struct HttpAclProxyHandle {
    /// Local address the proxy is listening on.
    pub addr: SocketAddr,
    /// Whether HTTPS MITM is active (user provided CA cert+key).
    pub has_https: bool,
    /// Shared map for the supervisor to record original destination IPs.
    pub orig_dest: OrigDestMap,
    /// Send to this channel to trigger graceful proxy shutdown.
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Drop for HttpAclProxyHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Pre-generated dummy CA for HTTP-only mode, avoiding per-spawn keygen cost.
fn dummy_ca() -> std::io::Result<(KeyPair, hudsucker::rcgen::Certificate)> {
    use hudsucker::rcgen::{BasicConstraints, IsCa};

    let kp = KeyPair::generate().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("keygen failed: {e}"))
    })?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&kp).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("self-sign failed: {e}"))
    })?;
    Ok((kp, cert))
}

static DUMMY_CA: std::sync::LazyLock<std::io::Result<(Vec<u8>, Vec<u8>)>> =
    std::sync::LazyLock::new(|| {
        let (kp, cert) = dummy_ca()?;
        Ok((kp.serialize_pem().into_bytes(), cert.pem().into_bytes()))
    });

/// Spawn a hudsucker-based HTTP ACL proxy.
///
/// If `ca_cert` and `ca_key` are provided, the proxy also intercepts HTTPS
/// traffic via MITM using the given CA. Otherwise, only plaintext HTTP
/// (port 80) is intercepted.
pub async fn spawn_http_acl_proxy(
    allow: Vec<HttpRule>,
    deny: Vec<HttpRule>,
    ca_cert: Option<&Path>,
    ca_key: Option<&Path>,
) -> std::io::Result<HttpAclProxyHandle> {
    // Load or skip CA for HTTPS MITM.
    let has_https = ca_cert.is_some() && ca_key.is_some();

    let (key_pair, cert) = if let (Some(cert_path), Some(key_path)) = (ca_cert, ca_key) {
        let key_pem = std::fs::read_to_string(key_path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("failed to read --https-key {:?}: {e}", key_path))
        })?;
        let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("failed to read --https-ca {:?}: {e}", cert_path))
        })?;
        let kp = KeyPair::from_pem(&key_pem).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid CA key: {e}"))
        })?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid CA cert: {e}"))
        })?;
        let cert = params.self_signed(&kp).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("CA cert error: {e}"))
        })?;
        (kp, cert)
    } else {
        // HTTP-only mode — reuse a lazily-generated dummy CA to avoid
        // expensive keygen on every spawn.
        let (key_pem, cert_pem) = DUMMY_CA.as_ref().map_err(|e| {
            std::io::Error::new(e.kind(), format!("dummy CA init failed: {e}"))
        })?;
        let kp = KeyPair::from_pem(std::str::from_utf8(key_pem).unwrap()).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("dummy CA key: {e}"))
        })?;
        let params = CertificateParams::from_ca_cert_pem(std::str::from_utf8(cert_pem).unwrap())
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("dummy CA cert: {e}"))
            })?;
        let cert = params.self_signed(&kp).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("dummy CA sign: {e}"))
        })?;
        (kp, cert)
    };

    let ca = RcgenAuthority::new(key_pair, cert, 1_000);

    let orig_dest: OrigDestMap = Arc::new(std::sync::RwLock::new(HashMap::new()));

    let handler = AclHandler {
        allow_rules: Arc::new(allow),
        deny_rules: Arc::new(deny),
        orig_dest: Arc::clone(&orig_dest),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(handler)
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .build();

    tokio::spawn(async move {
        if let Err(e) = proxy.start().await {
            eprintln!("sandlock HTTP ACL proxy error: {e}");
        }
    });

    Ok(HttpAclProxyHandle {
        addr,
        has_https,
        orig_dest,
        shutdown_tx: Some(shutdown_tx),
    })
}
