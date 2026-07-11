// Per-request handling shared by the plaintext and TLS-terminated paths:
// reconstruct the absolute URL, verify the claimed host against the orig-dest
// IP, apply the HTTP ACL, and forward allowed requests upstream.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use tokio::sync::Mutex;

use super::upstream::{box_incoming, Forwarder};
use crate::credential::InjectRule;
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
    pub(crate) inject: Arc<Vec<InjectRule>>,
    pub(crate) orig_dest: OrigDestMap,
    pub(crate) forwarder: Forwarder,
    dns_cache: Arc<Mutex<HashMap<String, DnsEntry>>>,
    /// Latched once the first cleartext (`http`) credential injection is warned,
    /// so a library/API caller gets the warning once per run instead of per
    /// request. See [`first_cleartext_warn`].
    cleartext_warned: Arc<AtomicBool>,
}

/// Whether this cleartext injection should emit the one-per-run warning: true the
/// first time a credential is injected over plaintext `http` (and latches `seen`),
/// false afterwards and always false for `https`. Split out so the warn-once
/// contract is unit-tested without capturing the supervisor's stderr.
fn first_cleartext_warn(scheme: &str, seen: &AtomicBool) -> bool {
    scheme == "http" && !seen.swap(true, Ordering::Relaxed)
}

/// The single upstream authority for a request, or `Err` if it is missing,
/// malformed, or ambiguous.
///
/// Both the absolute-form URI authority and the `Host` header are parsed as an
/// [`Authority`] (not split on the first `:`, which mis-handles userinfo and
/// IPv6). Userinfo (`user@host`) is rejected because its `@` lets the real host
/// diverge from a naive `split(':')` view; when both a URI authority and a Host
/// header are present their hosts must agree. The returned authority — never the
/// raw Host header — drives `verify_host`, the ACL, the credential match, AND the
/// outbound request, so the host a credential is matched for is exactly the host
/// it is sent to. Split out so it is unit-tested without a live `Incoming` body.
fn request_authority(
    uri: &hyper::Uri,
    headers: &hyper::HeaderMap,
) -> Result<hyper::http::uri::Authority, ()> {
    use hyper::http::uri::Authority;

    let hdr_auth: Option<Authority> = match headers.get("host") {
        Some(v) => Some(v.to_str().map_err(|_| ())?.parse::<Authority>().map_err(|_| ())?),
        None => None,
    };
    let uri_auth: Option<Authority> = uri.authority().cloned();

    let has_userinfo = |a: &Authority| a.as_str().contains('@');
    if hdr_auth.as_ref().is_some_and(has_userinfo) || uri_auth.as_ref().is_some_and(has_userinfo) {
        return Err(());
    }

    match (uri_auth, hdr_auth) {
        (Some(u), Some(h)) if u.host().eq_ignore_ascii_case(h.host()) => Ok(u),
        (Some(_), Some(_)) => Err(()), // split host: URI authority vs Host header
        (Some(u), None) => Ok(u),
        (None, Some(h)) => Ok(h),
        (None, None) => Err(()), // no host at all
    }
}

impl AclService {
    pub(crate) fn new(
        allow: Vec<HttpRule>,
        deny: Vec<HttpRule>,
        inject: Arc<Vec<InjectRule>>,
        orig_dest: OrigDestMap,
        forwarder: Forwarder,
    ) -> Self {
        Self {
            allow: Arc::new(allow),
            deny: Arc::new(deny),
            inject,
            orig_dest,
            forwarder,
            dns_cache: Arc::new(Mutex::new(HashMap::new())),
            cleartext_warned: Arc::new(AtomicBool::new(false)),
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

        // Resolve ONE authority for the whole request (see `request_authority`).
        // `verify_host`, the ACL, the credential match, and the outbound request
        // are all keyed off this single parsed value, so the host a credential is
        // matched for is exactly the host it is forwarded to. This closes the
        // split-host exfiltration where a child sends an allowed URI/Host but
        // smuggles a different forward host (e.g. via userinfo `a:b@attacker`).
        let authority = match request_authority(req.uri(), req.headers()) {
            Ok(a) => a,
            Err(()) => {
                if let Ok(mut m) = self.orig_dest.write() {
                    m.remove(&client_addr);
                }
                return text_response(
                    StatusCode::FORBIDDEN,
                    "Blocked by sandlock: missing, malformed, or mismatched request host",
                );
            }
        };
        let host = authority.host().to_string();
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

        // Rebuild an absolute-URI request for the upstream client from the SAME
        // validated authority — never the raw Host header — so the forward host
        // equals the host the ACL/credential match ran against.
        let pq = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();
        let uri: hyper::Uri = match format!("{scheme}://{authority}{pq}").parse() {
            Ok(u) => u,
            Err(_) => return text_response(StatusCode::BAD_GATEWAY, "bad upstream URI"),
        };

        let (mut parts, body) = req.into_parts();
        parts.uri = uri;

        // ACL passed: attach a credential if a rule matches. First match wins.
        // The secret is rendered into the outbound request only here — never on
        // the deny path above — and only its name is recorded, never the value.
        for r in self.inject.iter() {
            if r.matches(&method, &host, &path) {
                match r.apply(&mut parts) {
                    Err(()) => {
                        // Rendering failed (e.g. the secret has bytes illegal in a
                        // header) — fail the request rather than forward it with no
                        // credential, which would look like an auth bug to the caller.
                        eprintln!(
                            "sandlock: credential {:?} could not be rendered for {} {}{} — rejecting",
                            r.name, method, host, path
                        );
                        return text_response(
                            StatusCode::BAD_GATEWAY,
                            "Blocked by sandlock: credential could not be applied",
                        );
                    }
                    Ok(crate::credential::Applied::Skipped) => {
                        // add-only and the caller already set the target — keep
                        // theirs and record it truthfully (not as an injection).
                        eprintln!(
                            "sandlock: kept caller-supplied credential {:?} for {} {}{} (add-only)",
                            r.name, method, host, path
                        );
                    }
                    Ok(crate::credential::Applied::Injected) => {
                        eprintln!(
                            "sandlock: injected credential {:?} for {} {}{}",
                            r.name, method, host, path
                        );
                        // Fires for any caller (library/API, not just the CLI) since the
                        // proxy is in core: the scheme is only known here at request time.
                        // Once per run — over cleartext the secret is exposed on the wire.
                        if first_cleartext_warn(scheme, &self.cleartext_warned) {
                            eprintln!(
                                "sandlock: warning: credential {:?} injected over cleartext HTTP (no TLS) \
                                 to {} — the secret is exposed on the wire; prefer an HTTPS host \
                                 (configure MITM via --http-ca / --http-inject-ca)",
                                r.name, host
                            );
                        }
                    }
                }
                // First match wins whether it injected or deliberately kept the
                // caller's value.
                break;
            }
        }

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

#[cfg(test)]
mod tests {
    use super::{first_cleartext_warn, request_authority};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn cleartext_warns_once_and_https_never() {
        let seen = AtomicBool::new(false);
        // First cleartext injection warns and latches; later ones are silent.
        assert!(first_cleartext_warn("http", &seen));
        assert!(!first_cleartext_warn("http", &seen));
        // https never warns, and must not consume a fresh latch.
        let fresh = AtomicBool::new(false);
        assert!(!first_cleartext_warn("https", &fresh));
        assert!(!fresh.load(Ordering::Relaxed));
        assert!(first_cleartext_warn("http", &fresh));
    }

    fn authority_of(uri: &str, host: Option<&str>) -> Result<String, ()> {
        let uri: hyper::Uri = uri.parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        if let Some(h) = host {
            headers.insert("host", h.parse().unwrap());
        }
        request_authority(&uri, &headers).map(|a| a.to_string())
    }

    #[test]
    fn request_authority_collapses_to_one_safe_host() {
        // Agreement, origin-form, a port, and a case-only difference all resolve.
        assert_eq!(authority_of("http://allowed.example/v1", Some("allowed.example")).unwrap(), "allowed.example");
        assert_eq!(authority_of("/v1", Some("allowed.example")).unwrap(), "allowed.example");
        assert_eq!(authority_of("http://allowed.example/v1", Some("ALLOWED.EXAMPLE")).unwrap(), "allowed.example");
        assert_eq!(authority_of("/v1", Some("allowed.example:443")).unwrap(), "allowed.example:443");

        // The exfiltration vectors are all rejected:
        // absolute-form URI host vs a spoofed Host header,
        assert!(authority_of("http://allowed.example/v1", Some("attacker.example")).is_err());
        // and userinfo smuggling that hides the real forward host behind `@`,
        // in both origin-form and absolute-form.
        assert!(authority_of("/v1", Some("allowed.example:x@attacker.example")).is_err());
        assert!(authority_of("http://allowed.example/v1", Some("allowed.example:x@attacker.example")).is_err());

        // A request with no host at all is rejected (fail closed).
        assert!(authority_of("/v1", None).is_err());
    }
}
