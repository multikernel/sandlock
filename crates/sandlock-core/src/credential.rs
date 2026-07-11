//! Credential injection (RFC #66, Phase 1 — Layer 2 primitives, transparent mode).
//!
//! A named secret lives only in the supervisor. Requests the sandboxed child
//! makes to a matching upstream have the secret rendered into an auth header (or
//! query parameter) inside the MITM proxy — after the ACL check, so a denied
//! request never touches the secret — and the child never sees the real value.
//!
//! This module holds the primitives: [`SecretString`] (zeroed on drop, never
//! printable), the [`AuthShape`] renderings, source loading (`env:`/`file:`/
//! `fd:`), and [`InjectRule`] (a matcher + auth shape + secret). Higher layers
//! (`--service openai`) and the phantom-token swap build on top of these.

use std::io::Read;
use std::ptr;
use std::sync::Arc;

use crate::error::SandboxError;
use crate::http::HttpRule;

/// A secret held in the supervisor, zeroed on drop.
///
/// It deliberately does **not** implement `Display`, `ToString`, or
/// `serde::Serialize`, and is not reachable through any `std::error::Error`
/// chain — so a stray `format!("{}", ..)` or a serialized policy cannot re-open
/// the leak the type exists to close. Only [`SecretString::expose`], used at the
/// single point where the value is rendered into an outbound request, reaches
/// the bytes.
pub struct SecretString(Vec<u8>);

impl SecretString {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The raw secret bytes. Call this only to render the value into an outbound
    /// header/query at send time — never to log, store, or return it.
    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // Volatile writes so the zeroing can't be optimized away.
        for b in self.0.iter_mut() {
            unsafe { ptr::write_volatile(b as *mut u8, 0) };
        }
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// Load a secret into the supervisor from a source spec. `literal:` is
/// intentionally unsupported — an inline value leaks via `ps` and shell history
/// even when used correctly; use `env:`/`file:`/`fd:`.
///
/// A single trailing newline (`\n` or `\r\n`) is stripped, since files and
/// heredocs commonly add one.
pub fn load_secret(source: &str) -> Result<SecretString, SandboxError> {
    let (kind, val) = source.split_once(':').ok_or_else(|| {
        SandboxError::Invalid(format!(
            "credential source must be env:/file:/fd:<...>, got {source:?}"
        ))
    })?;
    let mut bytes = match kind {
        "env" => std::env::var_os(val)
            .ok_or_else(|| SandboxError::Invalid(format!("credential env var {val} is not set")))?
            .into_encoded_bytes(),
        "file" => read_capped(
            &mut std::fs::File::open(val)
                .map_err(|e| SandboxError::Invalid(format!("credential file {val}: {e}")))?,
            &format!("file {val}"),
        )?,
        "fd" => {
            let n: i32 = val
                .parse()
                .map_err(|_| SandboxError::Invalid(format!("credential fd must be an integer, got {val:?}")))?;
            read_fd(n)?
        }
        "literal" => {
            return Err(SandboxError::Invalid(
                "credential source 'literal:' is unsupported (it leaks via ps / shell history); \
                 use env:/file:/fd:"
                    .into(),
            ))
        }
        other => return Err(SandboxError::Invalid(format!("unknown credential source {other:?}"))),
    };
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() {
        return Err(SandboxError::Invalid(format!("credential from {source:?} is empty")));
    }
    Ok(SecretString::new(bytes))
}

/// Largest secret we read from a `file:`/`fd:` source. Bounds supervisor memory
/// so a hostile/careless `file:/dev/zero` or an endless `fd:` pipe can't OOM it.
const MAX_SECRET_BYTES: u64 = 64 << 10;

/// Read at most `MAX_SECRET_BYTES` from `r`, erroring if the source is larger.
fn read_capped<R: std::io::Read>(r: &mut R, what: &str) -> Result<Vec<u8>, SandboxError> {
    let mut buf = Vec::new();
    // Read one past the cap so an oversized source is detected, not truncated.
    r.take(MAX_SECRET_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| SandboxError::Invalid(format!("credential {what}: {e}")))?;
    if buf.len() as u64 > MAX_SECRET_BYTES {
        return Err(SandboxError::Invalid(format!(
            "credential {what} exceeds {MAX_SECRET_BYTES} bytes"
        )));
    }
    Ok(buf)
}

/// Read a credential from an already-open fd (e.g. a shell `<(...)` process
/// substitution passed as `fd:N`, or the secret piped on stdin as `fd:0`). Reads
/// through a *dup*, so the caller's fd is left open. `fd:0` (stdin) is allowed —
/// it's the most portable secret-passing pattern (`printf %s "$SECRET" | sandlock
/// … --credential k=fd:0`, docker `-i`, systemd credential fds) — but `fd:1`/`fd:2`
/// are refused so a typo can't close/consume stdout/stderr.
fn read_fd(n: i32) -> Result<Vec<u8>, SandboxError> {
    use std::os::fd::FromRawFd;
    if n == 1 || n == 2 {
        return Err(SandboxError::Invalid(format!(
            "credential fd {n} refers to stdout/stderr; pass a dedicated fd (or fd:0 for stdin)"
        )));
    }
    let dup = unsafe { libc::dup(n) };
    if dup < 0 {
        return Err(SandboxError::Invalid(format!(
            "credential fd {n}: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Owns `dup` (not `n`), so only the dup is closed on drop.
    let mut f = unsafe { std::fs::File::from_raw_fd(dup) };
    read_capped(&mut f, &format!("fd {n}"))
}

/// How the secret is attached to a matching request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthShape {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// `Authorization: Basic base64(<username>:<secret>)`.
    Basic { username: String },
    /// A custom header carrying the raw secret, e.g. `x-api-key: <secret>`.
    Header { name: String },
    /// A query parameter carrying the raw secret, e.g. `?key=<secret>`.
    ///
    /// Less private than the header shapes: unlike an injected header, a query
    /// value can't be marked sensitive, so it lands in the upstream's access
    /// logs and any `Referer`, and a request-level tracing subscriber would log
    /// it. Prefer `bearer`/`header` when the upstream accepts them; use `query`
    /// only for APIs that require it, and not in a traced environment.
    Query { param: String },
}

/// What to do when the target header/param already exists on the child's request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnExistingHeader {
    /// Overwrite the value the child already set (default). The proxy owns the
    /// credential, and every major SDK (openai, anthropic, …) *requires* an API
    /// key to be set and always sends its own `Authorization: Bearer <placeholder>`
    /// — so keeping the child's value would forward the placeholder and never
    /// inject. Replacing that one header the rule targets is what makes
    /// `--http-auth "* api.openai.com/* bearer openai"` work at all.
    #[default]
    Replace,
    /// Leave the header/param the child already set, injecting only when absent.
    /// Opt in with the trailing `add-only` token when the agent legitimately owns
    /// the credential and the rule is a fallback.
    AddOnly,
}

/// A credential-injection rule: match a request, then attach `secret` per `auth`.
/// `name` is the credential's declared name, recorded in the audit trail — never
/// the value.
pub struct InjectRule {
    pub name: String,
    pub matcher: HttpRule,
    pub auth: AuthShape,
    /// Shared so several rules can reference one credential without re-loading
    /// its source (an `fd:` source is consumed on first read).
    pub secret: Arc<SecretString>,
    pub on_existing: OnExistingHeader,
}

impl std::fmt::Debug for InjectRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InjectRule")
            .field("name", &self.name)
            .field("matcher", &self.matcher)
            .field("auth", &self.auth)
            .field("on_existing", &self.on_existing)
            .field("secret", &self.secret) // redacted
            .finish()
    }
}

/// What [`InjectRule::apply`] did on the `Ok` path — so the caller logs a
/// truthful audit line instead of claiming "injected" when an `add-only` rule
/// actually left the caller's own credential in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// The secret was rendered into the request.
    Injected,
    /// `add-only` and the request already carried the target header/param, so
    /// the caller's value was kept and no secret was written.
    Skipped,
}

impl InjectRule {
    /// True if this rule applies to the given request.
    pub fn matches(&self, method: &str, host: &str, path: &str) -> bool {
        self.matcher.matches(method, host, path)
    }

    /// Render the secret into `parts` (header or query), honoring `on_existing`.
    /// The rendered header is marked sensitive so downstream logging redacts it.
    ///
    /// `Ok(Injected)` wrote the secret; `Ok(Skipped)` left a caller-supplied
    /// value in place under `add-only`. `Err(())` means the secret could not be
    /// rendered (e.g. it contains bytes illegal in an HTTP header value) — the
    /// caller must reject the request rather than forward it with no (or a
    /// partial) credential.
    ///
    /// Zeroing is best-effort: [`SecretString`] itself is wiped on drop, but the
    /// transient buffers built here (the `Bearer `/`Basic ` byte vecs, the base64
    /// string, the query pair) hold a copy of the secret and are dropped without
    /// volatile zeroing, so a copy briefly lives in freed heap.
    pub fn apply(&self, parts: &mut hyper::http::request::Parts) -> Result<Applied, ()> {
        match &self.auth {
            AuthShape::Bearer => {
                let mut v = b"Bearer ".to_vec();
                v.extend_from_slice(self.secret.expose());
                self.set_header(parts, "authorization", &v)
            }
            AuthShape::Basic { username } => {
                let mut raw = username.clone().into_bytes();
                raw.push(b':');
                raw.extend_from_slice(self.secret.expose());
                let mut v = b"Basic ".to_vec();
                v.extend_from_slice(base64_encode(&raw).as_bytes());
                self.set_header(parts, "authorization", &v)
            }
            AuthShape::Header { name } => self.set_header(parts, name, self.secret.expose()),
            AuthShape::Query { param } => self.set_query(parts, param),
        }
    }

    fn set_header(
        &self,
        parts: &mut hyper::http::request::Parts,
        name: &str,
        value: &[u8],
    ) -> Result<Applied, ()> {
        let hn = hyper::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
        if self.on_existing == OnExistingHeader::AddOnly && parts.headers.contains_key(&hn) {
            return Ok(Applied::Skipped); // agent already set it — leave it, not a failure
        }
        let mut hv = hyper::header::HeaderValue::from_bytes(value).map_err(|_| ())?;
        hv.set_sensitive(true);
        parts.headers.insert(hn, hv);
        Ok(Applied::Injected)
    }

    fn set_query(&self, parts: &mut hyper::http::request::Parts, param: &str) -> Result<Applied, ()> {
        let uri = &parts.uri;
        let path = uri.path();
        let existing = uri.query();
        let enc = urlencode_bytes(param.as_bytes());
        // Match on the param NAME (the token before `=`), so a value-less `?key`
        // — no `=`, which `starts_with("key=")` would miss — is still recognised
        // as the target: otherwise Replace would append `key&key=secret`, and a
        // first-occurrence-reading upstream would authenticate with the child's
        // empty value instead of the injected one.
        let is_target = |kv: &str| kv.split('=').next().unwrap_or(kv) == enc;
        // Honor AddOnly: don't append a param the request already carries.
        if self.on_existing == OnExistingHeader::AddOnly {
            if let Some(q) = existing {
                if q.split('&').any(is_target) {
                    return Ok(Applied::Skipped);
                }
            }
        }
        // Percent-encode the raw secret bytes (never lossy-stringify — a binary
        // key would be corrupted).
        let pair = format!("{}={}", enc, urlencode_bytes(self.secret.expose()));
        // Drop any existing occurrence of this param before appending, so
        // `Replace` actually replaces instead of appending a duplicate (most
        // frameworks read the first occurrence, so a duplicate would leave the
        // child's placeholder winning). For `AddOnly` this only runs when the
        // param is absent, so the filter is a no-op there.
        let kept: Option<String> = existing.map(|q| {
            q.split('&')
                .filter(|kv| !kv.is_empty() && !is_target(kv))
                .collect::<Vec<_>>()
                .join("&")
        });
        let new_pq = match kept {
            Some(ref k) if !k.is_empty() => format!("{path}?{k}&{pair}"),
            _ => format!("{path}?{pair}"),
        };
        let mut b = hyper::http::uri::Builder::new();
        if let Some(s) = uri.scheme() {
            b = b.scheme(s.clone());
        }
        if let Some(a) = uri.authority() {
            b = b.authority(a.clone());
        }
        parts.uri = b.path_and_query(new_pq).build().map_err(|_| ())?;
        Ok(Applied::Injected)
    }
}

/// Parse an `AuthShape` from the auth token of an `--http-auth` rule:
/// `bearer` | `basic:<user>` | `header:<name>` | `apikey:<name>` | `query:<param>`.
pub fn parse_auth(spec: &str, credential: &str) -> Result<AuthShape, SandboxError> {
    let (kind, arg) = match spec.split_once(':') {
        Some((k, a)) => (k, Some(a)),
        None => (spec, None),
    };
    let shape = match (kind, arg) {
        ("bearer", None) => AuthShape::Bearer,
        // RFC 7617 forbids ':' in the user-id: it would shift the `user:pass`
        // boundary in the base64 payload (upstream would parse part of the secret
        // as the password), so reject it rather than silently mis-encode.
        ("basic", Some(user)) if user.contains(':') => {
            return Err(SandboxError::Invalid(format!(
                "basic auth user-id must not contain ':' (RFC 7617), got {user:?}"
            )))
        }
        ("basic", Some(user)) if !user.is_empty() => AuthShape::Basic { username: user.to_string() },
        // `apikey:<header>` and `header:<name>` are the same rendering.
        ("header" | "apikey", Some(name)) if !name.is_empty() => AuthShape::Header { name: name.to_string() },
        ("query", Some(param)) if !param.is_empty() => AuthShape::Query { param: param.to_string() },
        _ => {
            return Err(SandboxError::Invalid(format!(
                "invalid auth shape {spec:?} for credential {credential:?} \
                 (expected bearer | basic:<user> | header:<name> | apikey:<name> | query:<param>)"
            )))
        }
    };
    Ok(shape)
}

/// Resolve `--credential`/`--http-auth` specs into ready-to-apply rules,
/// loading each secret into the supervisor.
///
/// - `credentials`: `NAME=SOURCE` where SOURCE is `env:`/`file:`/`fd:` (see
///   [`load_secret`]).
/// - `inject`: `METHOD HOST/PATH AUTHSPEC CREDNAME [replace|add-only]`, e.g.
///   `"* api.openai.com/* bearer openai"` or `"GET x.com/* header:x-api-key key add-only"`.
///   AUTHSPEC is `bearer | basic:<user> | header:<name> | apikey:<name> | query:<param>`.
///   The trailing token defaults to `replace` (the proxy overwrites the
///   placeholder auth SDKs always send); pass `add-only` to keep a value the
///   child set.
///
/// Each rule loads its own secret from the named credential's source, so a
/// credential may back several rules (an `fd:` source is single-use, so it can
/// back only one). Referencing an undeclared credential is an error.
pub fn resolve_inject_rules(
    credentials: &[String],
    inject: &[String],
) -> Result<(Vec<InjectRule>, Vec<String>), SandboxError> {
    use std::collections::HashMap;

    let mut sources: HashMap<&str, &str> = HashMap::new();
    for c in credentials {
        let (name, source) = c.split_once('=').ok_or_else(|| {
            SandboxError::Invalid(format!("--credential must be NAME=SOURCE, got {c:?}"))
        })?;
        if name.is_empty() {
            return Err(SandboxError::Invalid(format!("--credential has empty name: {c:?}")));
        }
        if sources.insert(name, source).is_some() {
            return Err(SandboxError::Invalid(format!("--credential {name:?} declared twice")));
        }
    }

    // Parse every rule first so we know which credentials are actually used.
    struct Parsed<'a> {
        name: &'a str,
        matcher: HttpRule,
        auth: AuthShape,
        on_existing: OnExistingHeader,
        source: &'a str,
    }
    let mut parsed: Vec<Parsed> = Vec::with_capacity(inject.len());
    for spec in inject {
        let toks: Vec<&str> = spec.split_whitespace().collect();
        if toks.len() < 4 || toks.len() > 5 {
            return Err(SandboxError::Invalid(format!(
                "--http-auth must be 'METHOD HOST/PATH AUTHSPEC CREDNAME [replace|add-only]', got {spec:?}"
            )));
        }
        let matcher = HttpRule::parse(&format!("{} {}", toks[0], toks[1]))?;
        let cred = toks[3];
        let auth = parse_auth(toks[2], cred)?;
        let on_existing = match toks.get(4) {
            // Default Replace: the proxy owns the credential, and SDKs always send
            // a placeholder auth header (see OnExistingHeader::Replace).
            None | Some(&"replace") => OnExistingHeader::Replace,
            Some(&"add-only") => OnExistingHeader::AddOnly,
            Some(other) => {
                return Err(SandboxError::Invalid(format!(
                    "--http-auth trailing token must be 'replace', 'add-only', or absent, got {other:?}"
                )))
            }
        };
        let source = *sources.get(cred).ok_or_else(|| {
            SandboxError::Invalid(format!("--http-auth references undeclared credential {cred:?}"))
        })?;
        parsed.push(Parsed { name: cred, matcher, auth, on_existing, source });
    }

    // Load each referenced credential exactly once (so an `fd:` source is read
    // once and several rules can share the secret), and collect the env-var
    // names of `env:` sources so the child can be denied them — otherwise the
    // agent would just read the value straight from its own environment.
    let mut loaded: HashMap<&str, Arc<SecretString>> = HashMap::new();
    for p in &parsed {
        if !loaded.contains_key(p.name) {
            loaded.insert(p.name, Arc::new(load_secret(p.source)?));
        }
    }

    // Strip the env var of EVERY declared `env:` credential from the child —
    // including one no `--http-auth` rule references. Declaring
    // `--credential X=env:VAR` is the signal that VAR is a secret; stripping
    // only the *referenced* ones would leave the child able to read the value
    // straight from its own environment whenever the rule was omitted, typo'd,
    // or commented out — handing it the exact secret the feature withholds.
    let mut env_strip: Vec<String> = Vec::new();
    for source in sources.values() {
        if let Some(var) = source.strip_prefix("env:") {
            if !env_strip.iter().any(|v| v == var) {
                env_strip.push(var.to_string());
            }
        }
    }

    let rules = parsed
        .into_iter()
        .map(|p| InjectRule {
            name: p.name.to_string(),
            matcher: p.matcher,
            auth: p.auth,
            secret: Arc::clone(&loaded[p.name]),
            on_existing: p.on_existing,
        })
        .collect();
    Ok((rules, env_strip))
}

/// Standard base64 (RFC 4648) — small inline encoder to avoid a dependency.
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Percent-encode raw bytes as a query component (encode everything not
/// unreserved, so `&`/`=`/`#`/`%` and any binary byte can't break out).
fn urlencode_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts_of(uri: &str, headers: &[(&str, &str)]) -> hyper::http::request::Parts {
        let mut b = hyper::Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn rule(auth: AuthShape, secret: &str, on_existing: OnExistingHeader) -> InjectRule {
        InjectRule {
            name: "test".into(),
            matcher: HttpRule::parse("* api.example.com/*").unwrap(),
            auth,
            secret: Arc::new(SecretString::new(secret.as_bytes().to_vec())),
            on_existing,
        }
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = SecretString::new(b"sk-supersecret".to_vec());
        assert_eq!(format!("{s:?}"), "SecretString(<redacted>)");
        // The rule's Debug must not leak the secret either.
        let r = rule(AuthShape::Bearer, "sk-supersecret", OnExistingHeader::AddOnly);
        assert!(!format!("{r:?}").contains("supersecret"));
    }

    #[test]
    fn load_secret_rejects_literal_and_unknown() {
        assert!(load_secret("literal:sk-x").is_err());
        assert!(load_secret("weird:x").is_err());
        assert!(load_secret("no-colon").is_err());
    }

    #[test]
    fn load_secret_env_strips_newline() {
        std::env::set_var("SANDLOCK_TEST_CRED", "sk-abc\n");
        let s = load_secret("env:SANDLOCK_TEST_CRED").unwrap();
        assert_eq!(s.expose(), b"sk-abc");
        std::env::remove_var("SANDLOCK_TEST_CRED");
        assert!(load_secret("env:SANDLOCK_TEST_CRED").is_err());
    }

    #[test]
    fn bearer_injects_authorization() {
        let mut p = parts_of("https://api.example.com/v1/x", &[]);
        rule(AuthShape::Bearer, "sk-abc", OnExistingHeader::AddOnly).apply(&mut p).unwrap();
        assert_eq!(p.headers.get("authorization").unwrap(), "Bearer sk-abc");
        assert!(p.headers.get("authorization").unwrap().is_sensitive());
    }

    #[test]
    fn basic_injects_base64() {
        let mut p = parts_of("https://api.example.com/x", &[]);
        rule(AuthShape::Basic { username: "user".into() }, "pass", OnExistingHeader::AddOnly).apply(&mut p).unwrap();
        // base64("user:pass") == "dXNlcjpwYXNz"
        assert_eq!(p.headers.get("authorization").unwrap(), "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn header_shape_sets_named_header() {
        let mut p = parts_of("https://api.example.com/x", &[]);
        rule(AuthShape::Header { name: "x-api-key".into() }, "k123", OnExistingHeader::AddOnly).apply(&mut p).unwrap();
        assert_eq!(p.headers.get("x-api-key").unwrap(), "k123");
    }

    #[test]
    fn add_only_does_not_overwrite_but_replace_does() {
        let mut p = parts_of("https://api.example.com/x", &[("authorization", "Bearer child-set")]);
        rule(AuthShape::Bearer, "sk-real", OnExistingHeader::AddOnly).apply(&mut p).unwrap();
        assert_eq!(p.headers.get("authorization").unwrap(), "Bearer child-set");

        let mut p2 = parts_of("https://api.example.com/x", &[("authorization", "Bearer child-set")]);
        rule(AuthShape::Bearer, "sk-real", OnExistingHeader::Replace).apply(&mut p2).unwrap();
        assert_eq!(p2.headers.get("authorization").unwrap(), "Bearer sk-real");
    }

    #[test]
    fn query_shape_appends_param() {
        let mut p = parts_of("https://api.example.com/v1/x?a=1", &[]);
        rule(AuthShape::Query { param: "key".into() }, "s e/cret", OnExistingHeader::AddOnly).apply(&mut p).unwrap();
        assert_eq!(p.uri.query().unwrap(), "a=1&key=s%20e%2Fcret");

        let mut p2 = parts_of("https://api.example.com/v1/x", &[]);
        rule(AuthShape::Query { param: "key".into() }, "abc", OnExistingHeader::AddOnly).apply(&mut p2).unwrap();
        assert_eq!(p2.uri.query().unwrap(), "key=abc");
    }

    #[test]
    fn parse_auth_shapes() {
        assert_eq!(parse_auth("bearer", "c").unwrap(), AuthShape::Bearer);
        assert_eq!(parse_auth("basic:user", "c").unwrap(), AuthShape::Basic { username: "user".into() });
        assert_eq!(parse_auth("header:x-api-key", "c").unwrap(), AuthShape::Header { name: "x-api-key".into() });
        assert_eq!(parse_auth("apikey:x-key", "c").unwrap(), AuthShape::Header { name: "x-key".into() });
        assert_eq!(parse_auth("query:token", "c").unwrap(), AuthShape::Query { param: "token".into() });
        assert!(parse_auth("basic:", "c").is_err());
        assert!(parse_auth("bogus", "c").is_err());
        // RFC 7617: ':' in the user-id is rejected (would shift the user:pass
        // boundary and leak part of the secret into the password field).
        assert!(parse_auth("basic:a:b", "c").is_err());
        assert!(matches!(parse_auth("basic:alice", "c"), Ok(AuthShape::Basic { username }) if username == "alice"));
    }

    #[test]
    fn apply_fails_on_secret_with_illegal_header_bytes() {
        // A secret containing CR/LF can't be a header value — apply must report
        // failure (so the caller rejects the request) rather than silently drop.
        let mut p = parts_of("https://api.example.com/x", &[]);
        let r = rule(AuthShape::Bearer, "sk\r\nx-evil: 1", OnExistingHeader::AddOnly);
        assert!(r.apply(&mut p).is_err());
        assert!(p.headers.get("authorization").is_none());
        assert!(p.headers.get("x-evil").is_none()); // no header injection
    }

    #[test]
    fn query_add_only_keeps_child_replace_overwrites() {
        // AddOnly: a param the child already carries is left untouched.
        let mut p = parts_of("https://api.example.com/x?key=child", &[]);
        rule(AuthShape::Query { param: "key".into() }, "sk-real", OnExistingHeader::AddOnly)
            .apply(&mut p).unwrap();
        assert_eq!(p.uri.query().unwrap(), "key=child");

        // Replace must *replace*, not append a duplicate — otherwise a framework
        // reading the first occurrence authenticates against the child's value.
        let mut p2 = parts_of("https://api.example.com/x?key=child", &[]);
        rule(AuthShape::Query { param: "key".into() }, "sk-real", OnExistingHeader::Replace)
            .apply(&mut p2).unwrap();
        assert_eq!(p2.uri.query().unwrap(), "key=sk-real");

        // Replace preserves other params and drops only the target's duplicates.
        let mut p3 = parts_of("https://api.example.com/x?a=1&key=old&b=2", &[]);
        rule(AuthShape::Query { param: "key".into() }, "sk-real", OnExistingHeader::Replace)
            .apply(&mut p3).unwrap();
        assert_eq!(p3.uri.query().unwrap(), "a=1&b=2&key=sk-real");

        // Replace on a request without the param just appends it.
        let mut p4 = parts_of("https://api.example.com/x", &[]);
        rule(AuthShape::Query { param: "key".into() }, "sk-real", OnExistingHeader::Replace)
            .apply(&mut p4).unwrap();
        assert_eq!(p4.uri.query().unwrap(), "key=sk-real");
    }

    #[test]
    fn query_targets_value_less_param() {
        // A bare `?key` (no `=`) is still the target: Replace must drop it and
        // inject, not append `key&key=secret` (a first-occurrence-reading upstream
        // would authenticate with the child's empty value).
        let mut p = parts_of("https://api.example.com/x?key", &[]);
        rule(AuthShape::Query { param: "key".into() }, "sk-real", OnExistingHeader::Replace)
            .apply(&mut p).unwrap();
        assert_eq!(p.uri.query().unwrap(), "key=sk-real");

        // AddOnly sees the value-less param as present → keep the child's, skip.
        let mut p2 = parts_of("https://api.example.com/x?key", &[]);
        let r = rule(AuthShape::Query { param: "key".into() }, "sk-real", OnExistingHeader::AddOnly);
        assert!(matches!(r.apply(&mut p2), Ok(Applied::Skipped)));
        assert_eq!(p2.uri.query().unwrap(), "key");
    }

    #[test]
    fn resolve_dedups_credentials_and_collects_env_strip() {
        std::env::set_var("SANDLOCK_TEST_RESOLVE", "sk-resolve");
        let creds = vec!["a=env:SANDLOCK_TEST_RESOLVE".to_string()];
        let inject = vec![
            "GET x.com/* bearer a".to_string(),
            "POST x.com/* header:x-key a".to_string(), // same credential, second rule
        ];
        let (rules, env_strip) = resolve_inject_rules(&creds, &inject).unwrap();
        assert_eq!(rules.len(), 2);
        // Both rules share one loaded secret (one Arc).
        assert!(Arc::ptr_eq(&rules[0].secret, &rules[1].secret));
        assert_eq!(env_strip, vec!["SANDLOCK_TEST_RESOLVE".to_string()]);
        std::env::remove_var("SANDLOCK_TEST_RESOLVE");
    }

    #[test]
    fn resolve_strips_declared_but_unreferenced_env_credential() {
        // A credential declared via env: but referenced by no --http-auth rule
        // must STILL be stripped from the child — otherwise the child reads the
        // secret straight from its own environment. The var need not even be set
        // (unreferenced credentials are not loaded), so this is pure config.
        let creds = vec!["unused=env:SANDLOCK_TEST_UNREF".to_string()];
        let (rules, env_strip) = resolve_inject_rules(&creds, &[]).unwrap();
        assert!(rules.is_empty(), "no rule references the credential");
        assert_eq!(
            env_strip,
            vec!["SANDLOCK_TEST_UNREF".to_string()],
            "the declared env var must be stripped even though it is unused"
        );
    }

    #[test]
    fn resolve_rejects_undeclared_and_std_fd() {
        assert!(resolve_inject_rules(&[], &["GET x/* bearer missing".to_string()]).is_err());
        assert!(load_secret("fd:1").is_err()); // stdout
        assert!(load_secret("fd:2").is_err()); // stderr (fd:0/stdin is now allowed)
    }

    #[test]
    fn resolve_default_is_replace_add_only_is_opt_in() {
        std::env::set_var("SANDLOCK_TEST_ONEX", "sk-x");
        let creds = vec!["a=env:SANDLOCK_TEST_ONEX".to_string()];
        // No trailing token → Replace, so an SDK's placeholder Authorization is
        // overwritten (the whole point of the feature — regression guard).
        let (r, _) = resolve_inject_rules(&creds, &["* x.com/* bearer a".to_string()]).unwrap();
        assert_eq!(r[0].on_existing, OnExistingHeader::Replace);
        // Prove it at the apply level: a child-set Authorization is replaced.
        let mut p = parts_of("https://x.com/v1", &[("authorization", "Bearer sk-placeholder")]);
        r[0].apply(&mut p).unwrap();
        assert_eq!(p.headers.get("authorization").unwrap(), "Bearer sk-x");

        let (r2, _) = resolve_inject_rules(&creds, &["* x.com/* bearer a add-only".to_string()]).unwrap();
        assert_eq!(r2[0].on_existing, OnExistingHeader::AddOnly);
        // Unknown trailing token is rejected.
        assert!(resolve_inject_rules(&creds, &["* x.com/* bearer a keep".to_string()]).is_err());
        std::env::remove_var("SANDLOCK_TEST_ONEX");
    }
}
