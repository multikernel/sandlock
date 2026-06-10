use serde::{Deserialize, Serialize};

use crate::error::SandboxError;
use crate::network::{NetAllow, NetTarget, Protocol};

/// An HTTP access control rule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HttpRule {
    pub method: String,
    pub host: String,
    pub path: String,
}

impl HttpRule {
    /// Parse a rule from "METHOD host/path" format.
    ///
    /// Examples:
    /// - `"GET api.example.com/v1/*"` -> method="GET", host="api.example.com", path="/v1/*"
    /// - `"* */admin/*"` -> method="*", host="*", path="/admin/*"
    /// - `"GET example.com"` -> method="GET", host="example.com", path="/*"
    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        let s = s.trim();
        let (method, rest) = s
            .split_once(char::is_whitespace)
            .ok_or_else(|| SandboxError::Invalid(format!("invalid http rule: {}", s)))?;
        let rest = rest.trim();
        if rest.is_empty() {
            return Err(SandboxError::Invalid(format!("invalid http rule: {}", s)));
        }

        let (host, path) = if let Some(pos) = rest.find('/') {
            let (h, p) = rest.split_at(pos);
            // Normalize the rule path, but preserve trailing * for glob matching.
            let has_wildcard = p.ends_with('*');
            let mut normalized = normalize_path(p);
            if has_wildcard && !normalized.ends_with('*') {
                normalized.push('*');
            }
            (h.to_string(), normalized)
        } else {
            (rest.to_string(), "/*".to_string())
        };

        Ok(HttpRule {
            method: method.to_uppercase(),
            host,
            path,
        })
    }

    /// Check whether this rule matches the given request parameters.
    /// The request path is normalized before matching to prevent bypasses
    /// via `//`, `/../`, `/.`, or percent-encoding.
    pub fn matches(&self, method: &str, host: &str, path: &str) -> bool {
        // Method match
        if self.method != "*" && !self.method.eq_ignore_ascii_case(method) {
            return false;
        }
        // Host match
        if self.host != "*" && !self.host.eq_ignore_ascii_case(host) {
            return false;
        }
        // Path match: normalize to prevent encoding/traversal bypasses.
        let normalized = normalize_path(path);
        prefix_or_exact_match(&self.path, &normalized)
    }
}

/// Normalize an HTTP path to prevent ACL bypasses via encoding tricks.
///
/// - Decodes percent-encoded characters (e.g. `%2F` -> `/`, `%61` -> `a`)
/// - Collapses duplicate slashes (`//` -> `/`)
/// - Resolves `.` and `..` segments
/// - Ensures the path starts with `/`
pub fn normalize_path(path: &str) -> String {
    // 1. Percent-decode
    let mut decoded = String::with_capacity(path.len());
    let mut chars = path.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next();
            let lo = chars.next();
            if let (Some(h), Some(l)) = (hi, lo) {
                let hex = [h, l];
                if let Ok(s) = std::str::from_utf8(&hex) {
                    if let Ok(val) = u8::from_str_radix(s, 16) {
                        decoded.push(val as char);
                        continue;
                    }
                }
                // Malformed percent encoding: keep as-is.
                decoded.push(b as char);
                decoded.push(h as char);
                decoded.push(l as char);
            } else {
                decoded.push(b as char);
            }
        } else {
            decoded.push(b as char);
        }
    }

    // 2. Split into segments, resolve . and .., skip empty segments (collapses //)
    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }

    // 3. Reconstruct with leading /
    let mut result = String::with_capacity(decoded.len());
    result.push('/');
    result.push_str(&segments.join("/"));
    result
}

/// Simple prefix or exact matching for paths. Supports trailing `*` as a prefix match.
///
/// Only supports:
/// - `"/*"` or `"*"` matches everything
/// - `"/v1/*"` matches "/v1/foo", "/v1/foo/bar" (prefix match)
/// - `"/v1/models"` matches exactly "/v1/models" (exact match)
///
/// Does NOT support mid-pattern wildcards (e.g., "/v1/*/models").
pub fn prefix_or_exact_match(pattern: &str, value: &str) -> bool {
    if pattern == "/*" || pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

/// Evaluate HTTP ACL rules against a request.
///
/// - Block rules are checked first; if any match, return false.
/// - Allow rules are checked next; if any match, return true.
/// - If allow rules exist but none matched, return false (deny-by-default).
/// - If no rules at all, return true (unrestricted).
pub fn http_acl_check(
    allow: &[HttpRule],
    deny: &[HttpRule],
    method: &str,
    host: &str,
    path: &str,
) -> bool {
    // Block rules checked first
    for rule in deny {
        if rule.matches(method, host, path) {
            return false;
        }
    }
    // Allow rules checked next
    if allow.is_empty() && deny.is_empty() {
        return true; // unrestricted
    }
    if allow.is_empty() {
        // Only block rules exist; anything not denied is allowed
        return true;
    }
    for rule in allow {
        if rule.matches(method, host, path) {
            return true;
        }
    }
    false // allow rules exist but none matched
}

/// Add the network allowlist entries needed for HTTP ACL interception.
///
/// HTTP ACLs are enforced by a local proxy, but the sandbox still needs to be
/// allowed to reach the original destination on the intercepted ports. Concrete
/// HTTP rule hosts tighten the IP allowlist to those hosts; wildcard hosts or
/// explicit HTTP ports with no rules allow any IP on the HTTP ports.
pub(crate) fn extend_net_allow_for_http(
    net_allow: &mut Vec<NetAllow>,
    http_allow: &[HttpRule],
    http_deny: &[HttpRule],
    http_ports: &[u16],
) {
    if http_ports.is_empty() {
        return;
    }

    let mut wildcard_seen = false;
    let mut concrete_hosts: Vec<String> = Vec::new();
    for rule in http_allow.iter().chain(http_deny.iter()) {
        if rule.host == "*" {
            wildcard_seen = true;
        } else if !concrete_hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case(&rule.host))
        {
            concrete_hosts.push(rule.host.clone());
        }
    }

    if wildcard_seen || (http_allow.is_empty() && http_deny.is_empty()) {
        net_allow.push(NetAllow {
            protocol: Protocol::Tcp,
            target: NetTarget::AnyIp,
            ports: http_ports.to_vec(),
            all_ports: false,
        });
    }

    for host in concrete_hosts {
        net_allow.push(NetAllow {
            protocol: Protocol::Tcp,
            target: NetTarget::Host(host),
            ports: http_ports.to_vec(),
            all_ports: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- HttpRule::parse tests ---

    #[test]
    fn parse_basic_get() {
        let rule = HttpRule::parse("GET api.example.com/v1/*").unwrap();
        assert_eq!(rule.method, "GET");
        assert_eq!(rule.host, "api.example.com");
        assert_eq!(rule.path, "/v1/*");
    }

    #[test]
    fn parse_wildcard_method_and_host() {
        let rule = HttpRule::parse("* */admin/*").unwrap();
        assert_eq!(rule.method, "*");
        assert_eq!(rule.host, "*");
        assert_eq!(rule.path, "/admin/*");
    }

    #[test]
    fn parse_post_with_exact_path() {
        let rule = HttpRule::parse("POST example.com/upload").unwrap();
        assert_eq!(rule.method, "POST");
        assert_eq!(rule.host, "example.com");
        assert_eq!(rule.path, "/upload");
    }

    #[test]
    fn parse_no_path_defaults_to_wildcard() {
        let rule = HttpRule::parse("GET example.com").unwrap();
        assert_eq!(rule.method, "GET");
        assert_eq!(rule.host, "example.com");
        assert_eq!(rule.path, "/*");
    }

    #[test]
    fn parse_method_uppercased() {
        let rule = HttpRule::parse("get example.com/foo").unwrap();
        assert_eq!(rule.method, "GET");
    }

    #[test]
    fn parse_error_no_space() {
        assert!(HttpRule::parse("GETexample.com").is_err());
    }

    #[test]
    fn parse_error_empty_host() {
        assert!(HttpRule::parse("GET  ").is_err());
    }

    // --- prefix_or_exact_match tests ---

    #[test]
    fn prefix_or_exact_match_wildcard_all() {
        assert!(prefix_or_exact_match("/*", "/anything"));
        assert!(prefix_or_exact_match("*", "/anything"));
        assert!(prefix_or_exact_match("/*", "/"));
    }

    #[test]
    fn prefix_or_exact_match_prefix() {
        assert!(prefix_or_exact_match("/v1/*", "/v1/foo"));
        assert!(prefix_or_exact_match("/v1/*", "/v1/foo/bar"));
        assert!(prefix_or_exact_match("/v1/*", "/v1/"));
        assert!(!prefix_or_exact_match("/v1/*", "/v2/foo"));
    }

    #[test]
    fn prefix_or_exact_match_exact() {
        assert!(prefix_or_exact_match("/v1/models", "/v1/models"));
        assert!(!prefix_or_exact_match("/v1/models", "/v1/models/extra"));
        assert!(!prefix_or_exact_match("/v1/models", "/v1/model"));
    }

    // --- HttpRule::matches tests ---

    #[test]
    fn matches_exact() {
        let rule = HttpRule::parse("GET api.example.com/v1/models").unwrap();
        assert!(rule.matches("GET", "api.example.com", "/v1/models"));
        assert!(!rule.matches("POST", "api.example.com", "/v1/models"));
        assert!(!rule.matches("GET", "other.com", "/v1/models"));
        assert!(!rule.matches("GET", "api.example.com", "/v1/other"));
    }

    #[test]
    fn matches_wildcard_method() {
        let rule = HttpRule::parse("* api.example.com/v1/*").unwrap();
        assert!(rule.matches("GET", "api.example.com", "/v1/foo"));
        assert!(rule.matches("POST", "api.example.com", "/v1/bar"));
    }

    #[test]
    fn matches_wildcard_host() {
        let rule = HttpRule::parse("GET */v1/*").unwrap();
        assert!(rule.matches("GET", "any.host.com", "/v1/foo"));
    }

    #[test]
    fn matches_case_insensitive_method() {
        let rule = HttpRule::parse("GET example.com/foo").unwrap();
        assert!(rule.matches("get", "example.com", "/foo"));
        assert!(rule.matches("Get", "example.com", "/foo"));
    }

    #[test]
    fn matches_case_insensitive_host() {
        let rule = HttpRule::parse("GET Example.COM/foo").unwrap();
        assert!(rule.matches("GET", "example.com", "/foo"));
    }

    // --- http_acl_check tests ---

    #[test]
    fn acl_no_rules_allows_all() {
        assert!(http_acl_check(&[], &[], "GET", "example.com", "/foo"));
    }

    #[test]
    fn acl_allow_only_permits_matching() {
        let allow = vec![HttpRule::parse("GET api.example.com/v1/*").unwrap()];
        assert!(http_acl_check(&allow, &[], "GET", "api.example.com", "/v1/foo"));
        assert!(!http_acl_check(&allow, &[], "POST", "api.example.com", "/v1/foo"));
        assert!(!http_acl_check(&allow, &[], "GET", "other.com", "/v1/foo"));
    }

    #[test]
    fn acl_deny_only_blocks_matching() {
        let deny = vec![HttpRule::parse("* */admin/*").unwrap()];
        assert!(!http_acl_check(&[], &deny, "GET", "example.com", "/admin/settings"));
        assert!(http_acl_check(&[], &deny, "GET", "example.com", "/public/page"));
    }

    #[test]
    fn acl_deny_takes_precedence_over_allow() {
        let allow = vec![HttpRule::parse("* example.com/*").unwrap()];
        let deny = vec![HttpRule::parse("* example.com/admin/*").unwrap()];
        assert!(http_acl_check(&allow, &deny, "GET", "example.com", "/public"));
        assert!(!http_acl_check(&allow, &deny, "GET", "example.com", "/admin/settings"));
    }

    #[test]
    fn acl_allow_deny_by_default_when_no_match() {
        let allow = vec![HttpRule::parse("GET api.example.com/v1/*").unwrap()];
        // Different host, not matched by allow -> denied
        assert!(!http_acl_check(&allow, &[], "GET", "evil.com", "/v1/foo"));
    }

    // --- normalize_path tests ---

    #[test]
    fn normalize_path_basic() {
        assert_eq!(normalize_path("/foo/bar"), "/foo/bar");
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn normalize_path_double_slashes() {
        assert_eq!(normalize_path("/foo//bar"), "/foo/bar");
        assert_eq!(normalize_path("//foo///bar//"), "/foo/bar");
    }

    #[test]
    fn normalize_path_dot_segments() {
        assert_eq!(normalize_path("/foo/./bar"), "/foo/bar");
        assert_eq!(normalize_path("/foo/../bar"), "/bar");
        assert_eq!(normalize_path("/foo/bar/../../baz"), "/baz");
    }

    #[test]
    fn normalize_path_dotdot_at_root() {
        assert_eq!(normalize_path("/../foo"), "/foo");
        assert_eq!(normalize_path("/../../foo"), "/foo");
    }

    #[test]
    fn normalize_path_percent_encoding() {
        // %2F = /, %61 = a
        assert_eq!(normalize_path("/foo%2Fbar"), "/foo/bar");
        assert_eq!(normalize_path("/%61dmin/settings"), "/admin/settings");
    }

    #[test]
    fn normalize_path_mixed_bypass_attempts() {
        // Double-encoded traversal
        assert_eq!(normalize_path("/v1/./admin/settings"), "/v1/admin/settings");
        assert_eq!(normalize_path("/v1/../admin/settings"), "/admin/settings");
        assert_eq!(normalize_path("/v1//admin/settings"), "/v1/admin/settings");
        assert_eq!(normalize_path("/v1/%2e%2e/admin"), "/admin");
    }

    // --- ACL bypass prevention tests ---

    #[test]
    fn acl_deny_prevents_double_slash_bypass() {
        let deny = vec![HttpRule::parse("* */admin/*").unwrap()];
        // These should all be caught by the deny rule
        assert!(!http_acl_check(&[], &deny, "GET", "example.com", "/admin/settings"));
        assert!(!http_acl_check(&[], &deny, "GET", "example.com", "//admin/settings"));
        assert!(!http_acl_check(&[], &deny, "GET", "example.com", "/admin//settings"));
    }

    #[test]
    fn acl_deny_prevents_dot_segment_bypass() {
        let deny = vec![HttpRule::parse("* */admin/*").unwrap()];
        assert!(!http_acl_check(&[], &deny, "GET", "example.com", "/./admin/settings"));
        assert!(!http_acl_check(&[], &deny, "GET", "example.com", "/public/../admin/settings"));
    }

    #[test]
    fn acl_deny_prevents_percent_encoding_bypass() {
        let deny = vec![HttpRule::parse("* */admin/*").unwrap()];
        // %61dmin = admin
        assert!(!http_acl_check(&[], &deny, "GET", "example.com", "/%61dmin/settings"));
    }

    #[test]
    fn acl_allow_normalized_path_still_works() {
        let allow = vec![HttpRule::parse("GET example.com/v1/models").unwrap()];
        assert!(http_acl_check(&allow, &[], "GET", "example.com", "/v1/models"));
        assert!(http_acl_check(&allow, &[], "GET", "example.com", "/v1/./models"));
        assert!(http_acl_check(&allow, &[], "GET", "example.com", "/v1//models"));
        // These resolve to different paths and should be denied
        assert!(!http_acl_check(&allow, &[], "GET", "example.com", "/v1/models/extra"));
        assert!(!http_acl_check(&allow, &[], "GET", "example.com", "/v2/models"));
    }

    #[test]
    fn parse_normalizes_rule_path() {
        let rule = HttpRule::parse("GET example.com/v1/./models/*").unwrap();
        assert_eq!(rule.path, "/v1/models/*");

        let rule = HttpRule::parse("GET example.com/v1//models").unwrap();
        assert_eq!(rule.path, "/v1/models");
    }

    #[test]
    fn extend_net_allow_for_http_adds_concrete_hosts() {
        let allow = vec![
            HttpRule::parse("GET api.example.com/v1/*").unwrap(),
            HttpRule::parse("POST API.example.com/v2/*").unwrap(),
        ];
        let deny = vec![HttpRule::parse("* admin.example.com/*").unwrap()];
        let mut net_allow = Vec::new();

        extend_net_allow_for_http(&mut net_allow, &allow, &deny, &[80, 443]);

        assert_eq!(net_allow.len(), 2);
        assert_eq!(net_allow[0].protocol, Protocol::Tcp);
        assert!(matches!(&net_allow[0].target, NetTarget::Host(h) if h == "api.example.com"));
        assert_eq!(net_allow[0].ports, vec![80, 443]);
        assert_eq!(net_allow[1].protocol, Protocol::Tcp);
        assert!(matches!(&net_allow[1].target, NetTarget::Host(h) if h == "admin.example.com"));
        assert_eq!(net_allow[1].ports, vec![80, 443]);
    }

    #[test]
    fn extend_net_allow_for_http_adds_any_ip_for_wildcard_or_bare_port() {
        let mut net_allow = Vec::new();
        extend_net_allow_for_http(&mut net_allow, &[], &[], &[8080]);
        assert_eq!(net_allow.len(), 1);
        assert_eq!(net_allow[0].protocol, Protocol::Tcp);
        assert_eq!(net_allow[0].target, NetTarget::AnyIp);
        assert_eq!(net_allow[0].ports, vec![8080]);

        let allow = vec![HttpRule::parse("* */public/*").unwrap()];
        let mut net_allow = Vec::new();
        extend_net_allow_for_http(&mut net_allow, &allow, &[], &[80]);
        assert_eq!(net_allow.len(), 1);
        assert_eq!(net_allow[0].protocol, Protocol::Tcp);
        assert_eq!(net_allow[0].target, NetTarget::AnyIp);
        assert_eq!(net_allow[0].ports, vec![80]);
    }
}
