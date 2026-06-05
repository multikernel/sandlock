// Per-request handling shared by the plaintext and TLS-terminated paths:
// reconstruct the absolute URL, verify the claimed host against the orig-dest
// IP, apply the HTTP ACL, and forward allowed requests upstream.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use tokio::sync::Mutex;

use super::upstream::{box_incoming, Forwarder};
use crate::http::{http_acl_check, HttpRule};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type OrigDestMap = Arc<std::sync::RwLock<HashMap<SocketAddr, IpAddr>>>;

const DNS_CACHE_TTL: Duration = Duration::from_secs(30);

struct DnsEntry {
    ips: Vec<IpAddr>,
    expires: Instant,
}

/// Shared, cloneable state for the request handler.
#[derive(Clone)]
pub(crate) struct AclService {
    pub(crate) allow: Arc<Vec<HttpRule>>,
    pub(crate) deny: Arc<Vec<HttpRule>>,
    pub(crate) orig_dest: OrigDestMap,
    pub(crate) forwarder: Forwarder,
    dns_cache: Arc<Mutex<HashMap<String, DnsEntry>>>,
}

impl AclService {
    pub(crate) fn new(
        allow: Vec<HttpRule>,
        deny: Vec<HttpRule>,
        orig_dest: OrigDestMap,
        forwarder: Forwarder,
    ) -> Self {
        Self {
            allow: Arc::new(allow),
            deny: Arc::new(deny),
            orig_dest,
            forwarder,
            dns_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn resolve_cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        {
            let cache = self.dns_cache.lock().await;
            if let Some(e) = cache.get(host) {
                if e.expires > Instant::now() {
                    return Some(e.ips.clone());
                }
            }
        }
        let resolved = tokio::net::lookup_host(format!("{host}:0")).await.ok()?;
        let ips: Vec<IpAddr> = resolved.map(|sa| sa.ip()).collect();
        let mut cache = self.dns_cache.lock().await;
        cache.insert(
            host.to_string(),
            DnsEntry {
                ips: ips.clone(),
                expires: Instant::now() + DNS_CACHE_TTL,
            },
        );
        Some(ips)
    }

    async fn verify_host(&self, client_addr: &SocketAddr, claimed_host: &str) -> bool {
        let orig_ip = {
            let map = self.orig_dest.read().unwrap_or_else(|e| e.into_inner());
            map.get(client_addr).copied()
        };
        let orig_ip = match orig_ip {
            Some(ip) => ip,
            None => return true,
        };
        if let Ok(ip) = claimed_host.parse::<IpAddr>() {
            return ip == orig_ip;
        }
        match self.resolve_cached(claimed_host).await {
            Some(ips) => ips.iter().any(|ip| *ip == orig_ip),
            None => false,
        }
    }

    /// Handle one request. `scheme` is "https" for the MITM path, "http" for plaintext.
    pub(crate) async fn handle(
        &self,
        client_addr: SocketAddr,
        scheme: &str,
        req: Request<hyper::body::Incoming>,
    ) -> Response<BoxBody<Bytes, BoxError>> {
        let method = req.method().as_str().to_string();
        let host = req
            .uri()
            .host()
            .map(|h| h.to_string())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|h| h.split(':').next().unwrap_or(h).to_string())
            })
            .unwrap_or_default();
        let path = req.uri().path().to_string();

        if !self.verify_host(&client_addr, &host).await {
            if let Ok(mut m) = self.orig_dest.write() {
                m.remove(&client_addr);
            }
            return text_response(
                StatusCode::FORBIDDEN,
                "Blocked by sandlock: Host header does not match connection destination",
            );
        }
        if let Ok(mut m) = self.orig_dest.write() {
            m.remove(&client_addr);
        }

        if !http_acl_check(&self.allow, &self.deny, &method, &host, &path) {
            return text_response(StatusCode::FORBIDDEN, "Blocked by sandlock HTTP ACL policy");
        }

        // Rebuild an absolute-URI request for the upstream client.
        let host_hdr = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| host.clone());
        let pq = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();
        let uri: hyper::Uri = match format!("{scheme}://{host_hdr}{pq}").parse() {
            Ok(u) => u,
            Err(_) => return text_response(StatusCode::BAD_GATEWAY, "bad upstream URI"),
        };

        let (mut parts, body) = req.into_parts();
        parts.uri = uri;
        let out_req = Request::from_parts(parts, box_incoming(body));

        match self.forwarder.forward(out_req).await {
            Ok(resp) => resp,
            Err(_) => text_response(StatusCode::BAD_GATEWAY, "upstream error"),
        }
    }
}

fn text_response(status: StatusCode, msg: &str) -> Response<BoxBody<Bytes, BoxError>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(msg.to_string())).map_err(|e| match e {}).boxed())
        .expect("response build")
}
