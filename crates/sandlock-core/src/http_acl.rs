use std::net::SocketAddr;
use std::path::PathBuf;
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

/// Handle returned by [`spawn_http_acl_proxy`] with the proxy's address and CA cert path.
pub struct HttpAclProxyHandle {
    /// Local address the proxy is listening on.
    pub addr: SocketAddr,
    /// Path to the PEM-encoded CA certificate file.
    pub ca_cert_path: PathBuf,
}

/// Spawn a hudsucker-based transparent MITM proxy that enforces HTTP ACL rules.
///
/// The proxy listens on a random local port and generates a self-signed CA
/// certificate for HTTPS interception. Returns a handle with the bound address
/// and the path to the CA cert PEM file.
pub async fn spawn_http_acl_proxy(
    allow: Vec<HttpRule>,
    deny: Vec<HttpRule>,
) -> std::io::Result<HttpAclProxyHandle> {
    // Generate a CA key pair and self-signed certificate.
    let key_pair = KeyPair::generate().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("failed to generate CA key: {e}"))
    })?;

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = hudsucker::rcgen::IsCa::Ca(hudsucker::rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(hudsucker::rcgen::DnType::CommonName, "sandlock CA");

    let ca_cert = ca_params.self_signed(&key_pair).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("failed to self-sign CA cert: {e}"),
        )
    })?;

    // Write CA cert PEM to a temp file so the child can trust it.
    let pid = std::process::id();
    let ca_cert_path = PathBuf::from(format!("/tmp/sandlock-http-acl-ca-{pid}.pem"));
    let pem = ca_cert.pem();
    std::fs::write(&ca_cert_path, pem.as_bytes())?;

    // Build the RcgenAuthority for hudsucker.
    let ca = RcgenAuthority::new(key_pair, ca_cert, 1_000);

    // Build the ACL handler.
    let handler = AclHandler {
        allow_rules: Arc::new(allow),
        deny_rules: Arc::new(deny),
    };

    // Bind to a random local port.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Build and spawn the proxy.
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

    Ok(HttpAclProxyHandle { addr, ca_cert_path })
}
