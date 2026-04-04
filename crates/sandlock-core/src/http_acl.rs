use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::{Request, Response, StatusCode};
use hudsucker::rcgen::{CertificateParams, KeyPair};
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use tokio::net::TcpListener;

use crate::policy::{http_acl_check, HttpRule};

/// ACL-enforcing HTTP handler for hudsucker.
#[derive(Clone)]
struct AclHandler {
    allow_rules: Arc<Vec<HttpRule>>,
    deny_rules: Arc<Vec<HttpRule>>,
}

impl HttpHandler for AclHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
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

        if http_acl_check(&self.allow_rules, &self.deny_rules, &method, &host, &path) {
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
}

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
        // No HTTPS — generate a dummy CA (hudsucker requires one, but it
        // won't be used since we only intercept port 80).
        let kp = KeyPair::generate().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("keygen failed: {e}"))
        })?;
        let mut params = CertificateParams::default();
        params.is_ca = hudsucker::rcgen::IsCa::Ca(hudsucker::rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&kp).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("self-sign failed: {e}"))
        })?;
        (kp, cert)
    };

    let ca = RcgenAuthority::new(key_pair, cert, 1_000);

    let handler = AclHandler {
        allow_rules: Arc::new(allow),
        deny_rules: Arc::new(deny),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(handler)
        .build();

    tokio::spawn(async move {
        if let Err(e) = proxy.start().await {
            eprintln!("sandlock HTTP ACL proxy error: {e}");
        }
    });

    Ok(HttpAclProxyHandle { addr, has_https })
}
