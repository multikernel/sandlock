use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

/// A byte size value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub fn bytes(n: u64) -> Self {
        ByteSize(n)
    }

    pub fn kib(n: u64) -> Self {
        ByteSize(n * 1024)
    }

    pub fn mib(n: u64) -> Self {
        ByteSize(n * 1024 * 1024)
    }

    pub fn gib(n: u64) -> Self {
        ByteSize(n * 1024 * 1024 * 1024)
    }

    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(PolicyError::Invalid("empty byte size string".into()));
        }

        // Check for suffix
        let last = s.chars().last().unwrap();
        if last.is_ascii_alphabetic() {
            let (num_str, suffix) = s.split_at(s.len() - 1);
            let n: u64 = num_str
                .trim()
                .parse()
                .map_err(|_| PolicyError::Invalid(format!("invalid byte size: {}", s)))?;
            match suffix.to_ascii_uppercase().as_str() {
                "K" => Ok(ByteSize::kib(n)),
                "M" => Ok(ByteSize::mib(n)),
                "G" => Ok(ByteSize::gib(n)),
                other => Err(PolicyError::Invalid(format!("unknown byte size suffix: {}", other))),
            }
        } else {
            let n: u64 = s
                .parse()
                .map_err(|_| PolicyError::Invalid(format!("invalid byte size: {}", s)))?;
            Ok(ByteSize(n))
        }
    }
}

/// Filesystem isolation mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FsIsolation {
    #[default]
    None,
    OverlayFs,
    BranchFs,
}

/// Action to take on branch exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BranchAction {
    #[default]
    Commit,
    Abort,
    Keep,
}

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
    /// - `"GET api.example.com/v1/*"` → method="GET", host="api.example.com", path="/v1/*"
    /// - `"* */admin/*"` → method="*", host="*", path="/admin/*"
    /// - `"GET example.com"` → method="GET", host="example.com", path="/*"
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let s = s.trim();
        let (method, rest) = s
            .split_once(char::is_whitespace)
            .ok_or_else(|| PolicyError::Invalid(format!("invalid http rule: {}", s)))?;
        let rest = rest.trim();
        if rest.is_empty() {
            return Err(PolicyError::Invalid(format!("invalid http rule: {}", s)));
        }

        let (host, path) = if let Some(pos) = rest.find('/') {
            let (h, p) = rest.split_at(pos);
            (h.to_string(), p.to_string())
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
    pub fn matches(&self, method: &str, host: &str, path: &str) -> bool {
        // Method match
        if self.method != "*" && !self.method.eq_ignore_ascii_case(method) {
            return false;
        }
        // Host match
        if self.host != "*" && !self.host.eq_ignore_ascii_case(host) {
            return false;
        }
        // Path match
        prefix_or_exact_match(&self.path, path)
    }
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
/// - Deny rules are checked first; if any match, return false.
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
    // Deny rules checked first
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
        // Only deny rules exist; anything not denied is allowed
        return true;
    }
    for rule in allow {
        if rule.matches(method, host, path) {
            return true;
        }
    }
    false // allow rules exist but none matched
}

/// Sandbox policy configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct Policy {
    // Filesystem access
    pub fs_writable: Vec<PathBuf>,
    pub fs_readable: Vec<PathBuf>,
    pub fs_denied: Vec<PathBuf>,

    // Syscall filtering
    pub deny_syscalls: Option<Vec<String>>,
    pub allow_syscalls: Option<Vec<String>>,

    // Network
    pub net_allow_hosts: Vec<String>,
    pub net_bind: Vec<u16>,
    pub net_connect: Vec<u16>,
    pub no_raw_sockets: bool,
    pub no_udp: bool,

    // HTTP ACL
    pub http_allow: Vec<HttpRule>,
    pub http_deny: Vec<HttpRule>,

    // Namespace isolation
    pub isolate_ipc: bool,
    pub isolate_signals: bool,
    pub isolate_pids: bool,

    // Resource limits
    pub max_memory: Option<ByteSize>,
    pub max_processes: u32,
    pub max_open_files: Option<u32>,
    pub max_cpu: Option<u8>,

    // Reproducibility
    pub random_seed: Option<u64>,
    pub time_start: Option<SystemTime>,
    pub no_randomize_memory: bool,
    pub no_huge_pages: bool,
    pub no_coredump: bool,
    pub deterministic_dirs: bool,
    pub hostname: Option<String>,

    // Filesystem branch
    pub fs_isolation: FsIsolation,
    pub workdir: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub fs_storage: Option<PathBuf>,
    pub max_disk: Option<ByteSize>,
    pub on_exit: BranchAction,
    pub on_error: BranchAction,

    // Environment
    pub chroot: Option<PathBuf>,
    pub clean_env: bool,
    pub env: HashMap<String, String>,
    pub close_fds: bool,

    // Devices
    pub gpu_devices: Option<Vec<u32>>,

    // CPU
    pub cpu_cores: Option<Vec<u32>>,
    pub num_cpus: Option<u32>,
    pub port_remap: bool,

    // User namespace
    pub uid: Option<u32>,

    // Dynamic policy callback
    #[serde(skip)]
    pub policy_fn: Option<crate::policy_fn::PolicyCallback>,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("fs_readable", &self.fs_readable)
            .field("fs_writable", &self.fs_writable)
            .field("max_memory", &self.max_memory)
            .field("max_processes", &self.max_processes)
            .field("policy_fn", &self.policy_fn.as_ref().map(|_| "<callback>"))
            .finish_non_exhaustive()
    }
}

impl Policy {
    pub fn builder() -> PolicyBuilder {
        PolicyBuilder::default()
    }
}

/// Fluent builder for `Policy`.
#[derive(Default)]
pub struct PolicyBuilder {
    fs_writable: Vec<PathBuf>,
    fs_readable: Vec<PathBuf>,
    fs_denied: Vec<PathBuf>,

    deny_syscalls: Option<Vec<String>>,
    allow_syscalls: Option<Vec<String>>,

    net_allow_hosts: Vec<String>,
    net_bind: Vec<u16>,
    net_connect: Vec<u16>,
    no_raw_sockets: Option<bool>,
    no_udp: bool,

    http_allow: Vec<HttpRule>,
    http_deny: Vec<HttpRule>,

    isolate_ipc: bool,
    isolate_signals: bool,
    isolate_pids: bool,

    max_memory: Option<ByteSize>,
    max_processes: Option<u32>,
    max_open_files: Option<u32>,
    max_cpu: Option<u8>,

    random_seed: Option<u64>,
    time_start: Option<SystemTime>,
    no_randomize_memory: bool,
    no_huge_pages: bool,
    no_coredump: bool,
    deterministic_dirs: bool,
    hostname: Option<String>,

    fs_isolation: Option<FsIsolation>,
    workdir: Option<PathBuf>,
    cwd: Option<PathBuf>,
    fs_storage: Option<PathBuf>,
    max_disk: Option<ByteSize>,
    on_exit: Option<BranchAction>,
    on_error: Option<BranchAction>,

    chroot: Option<PathBuf>,
    clean_env: bool,
    env: HashMap<String, String>,
    close_fds: Option<bool>,

    gpu_devices: Option<Vec<u32>>,

    cpu_cores: Option<Vec<u32>>,
    num_cpus: Option<u32>,
    port_remap: bool,

    uid: Option<u32>,
    policy_fn: Option<crate::policy_fn::PolicyCallback>,
}

impl PolicyBuilder {
    pub fn fs_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_writable.push(path.into());
        self
    }

    pub fn fs_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_readable.push(path.into());
        self
    }

    pub fn fs_deny(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_denied.push(path.into());
        self
    }

    pub fn deny_syscalls(mut self, calls: Vec<String>) -> Self {
        self.deny_syscalls = Some(calls);
        self
    }

    pub fn allow_syscalls(mut self, calls: Vec<String>) -> Self {
        self.allow_syscalls = Some(calls);
        self
    }

    pub fn net_allow_host(mut self, host: impl Into<String>) -> Self {
        self.net_allow_hosts.push(host.into());
        self
    }

    pub fn net_bind_port(mut self, port: u16) -> Self {
        self.net_bind.push(port);
        self
    }

    pub fn net_connect_port(mut self, port: u16) -> Self {
        self.net_connect.push(port);
        self
    }

    pub fn no_raw_sockets(mut self, v: bool) -> Self {
        self.no_raw_sockets = Some(v);
        self
    }

    pub fn no_udp(mut self, v: bool) -> Self {
        self.no_udp = v;
        self
    }

    pub fn http_allow(mut self, rule: &str) -> Self {
        self.http_allow.push(HttpRule::parse(rule).expect("invalid HTTP allow rule"));
        self
    }

    pub fn http_deny(mut self, rule: &str) -> Self {
        self.http_deny.push(HttpRule::parse(rule).expect("invalid HTTP deny rule"));
        self
    }

    pub fn isolate_ipc(mut self, v: bool) -> Self {
        self.isolate_ipc = v;
        self
    }

    pub fn isolate_signals(mut self, v: bool) -> Self {
        self.isolate_signals = v;
        self
    }

    pub fn isolate_pids(mut self, v: bool) -> Self {
        self.isolate_pids = v;
        self
    }

    pub fn max_memory(mut self, size: ByteSize) -> Self {
        self.max_memory = Some(size);
        self
    }

    pub fn max_processes(mut self, n: u32) -> Self {
        self.max_processes = Some(n);
        self
    }

    pub fn max_open_files(mut self, n: u32) -> Self {
        self.max_open_files = Some(n);
        self
    }

    pub fn max_cpu(mut self, pct: u8) -> Self {
        self.max_cpu = Some(pct);
        self
    }

    pub fn random_seed(mut self, seed: u64) -> Self {
        self.random_seed = Some(seed);
        self
    }

    pub fn time_start(mut self, t: SystemTime) -> Self {
        self.time_start = Some(t);
        self
    }

    pub fn no_randomize_memory(mut self, v: bool) -> Self {
        self.no_randomize_memory = v;
        self
    }

    pub fn no_huge_pages(mut self, v: bool) -> Self {
        self.no_huge_pages = v;
        self
    }

    pub fn no_coredump(mut self, v: bool) -> Self {
        self.no_coredump = v;
        self
    }

    pub fn deterministic_dirs(mut self, v: bool) -> Self {
        self.deterministic_dirs = v;
        self
    }

    pub fn hostname(mut self, name: impl Into<String>) -> Self {
        self.hostname = Some(name.into());
        self
    }

    pub fn fs_isolation(mut self, iso: FsIsolation) -> Self {
        self.fs_isolation = Some(iso);
        self
    }

    pub fn workdir(mut self, path: impl Into<PathBuf>) -> Self {
        self.workdir = Some(path.into());
        self
    }

    pub fn cwd(mut self, path: impl Into<PathBuf>) -> Self {
        self.cwd = Some(path.into());
        self
    }

    pub fn fs_storage(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_storage = Some(path.into());
        self
    }

    pub fn max_disk(mut self, size: ByteSize) -> Self {
        self.max_disk = Some(size);
        self
    }

    pub fn on_exit(mut self, action: BranchAction) -> Self {
        self.on_exit = Some(action);
        self
    }

    pub fn on_error(mut self, action: BranchAction) -> Self {
        self.on_error = Some(action);
        self
    }

    pub fn chroot(mut self, path: impl Into<PathBuf>) -> Self {
        self.chroot = Some(path.into());
        self
    }

    pub fn clean_env(mut self, v: bool) -> Self {
        self.clean_env = v;
        self
    }

    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn close_fds(mut self, v: bool) -> Self {
        self.close_fds = Some(v);
        self
    }

    pub fn gpu_devices(mut self, devices: Vec<u32>) -> Self {
        self.gpu_devices = Some(devices);
        self
    }

    pub fn cpu_cores(mut self, cores: Vec<u32>) -> Self {
        self.cpu_cores = Some(cores);
        self
    }

    pub fn num_cpus(mut self, n: u32) -> Self {
        self.num_cpus = Some(n);
        self
    }

    pub fn port_remap(mut self, v: bool) -> Self {
        self.port_remap = v;
        self
    }

    pub fn policy_fn(
        mut self,
        f: impl Fn(crate::policy_fn::SyscallEvent, &mut crate::policy_fn::PolicyContext) -> crate::policy_fn::Verdict + Send + Sync + 'static,
    ) -> Self {
        self.policy_fn = Some(std::sync::Arc::new(f));
        self
    }

    pub fn uid(mut self, id: u32) -> Self {
        self.uid = Some(id);
        self
    }

    pub fn build(self) -> Result<Policy, PolicyError> {
        // Validate: deny_syscalls and allow_syscalls are mutually exclusive
        if self.deny_syscalls.is_some() && self.allow_syscalls.is_some() {
            return Err(PolicyError::MutuallyExclusiveSyscalls);
        }

        // Validate: max_cpu must be 1-100
        if let Some(cpu) = self.max_cpu {
            if cpu == 0 || cpu > 100 {
                return Err(PolicyError::InvalidCpuPercent(cpu));
            }
        }

        // Validate: fs_isolation != None requires workdir
        let fs_isolation = self.fs_isolation.unwrap_or_default();
        if fs_isolation != FsIsolation::None && self.workdir.is_none() {
            return Err(PolicyError::FsIsolationRequiresWorkdir);
        }

        Ok(Policy {
            fs_writable: self.fs_writable,
            fs_readable: self.fs_readable,
            fs_denied: self.fs_denied,
            deny_syscalls: self.deny_syscalls,
            allow_syscalls: self.allow_syscalls,
            net_allow_hosts: self.net_allow_hosts,
            net_bind: self.net_bind,
            net_connect: self.net_connect,
            no_raw_sockets: self.no_raw_sockets.unwrap_or(true),
            no_udp: self.no_udp,
            http_allow: self.http_allow,
            http_deny: self.http_deny,
            isolate_ipc: self.isolate_ipc,
            isolate_signals: self.isolate_signals,
            isolate_pids: self.isolate_pids,
            max_memory: self.max_memory,
            max_processes: self.max_processes.unwrap_or(64),
            max_open_files: self.max_open_files,
            max_cpu: self.max_cpu,
            random_seed: self.random_seed,
            time_start: self.time_start,
            no_randomize_memory: self.no_randomize_memory,
            no_huge_pages: self.no_huge_pages,
            no_coredump: self.no_coredump,
            deterministic_dirs: self.deterministic_dirs,
            hostname: self.hostname,
            fs_isolation,
            workdir: self.workdir,
            cwd: self.cwd,
            fs_storage: self.fs_storage,
            max_disk: self.max_disk,
            on_exit: self.on_exit.unwrap_or_default(),
            on_error: self.on_error.unwrap_or_default(),
            chroot: self.chroot,
            clean_env: self.clean_env,
            env: self.env,
            close_fds: self.close_fds.unwrap_or(true),
            gpu_devices: self.gpu_devices,
            cpu_cores: self.cpu_cores,
            num_cpus: self.num_cpus,
            port_remap: self.port_remap,
            uid: self.uid,
            policy_fn: self.policy_fn,
        })
    }
}

#[cfg(test)]
mod http_rule_tests {
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

    // --- PolicyBuilder integration ---

    #[test]
    fn builder_http_rules() {
        let policy = Policy::builder()
            .http_allow("GET api.example.com/v1/*")
            .http_deny("* */admin/*")
            .build()
            .unwrap();
        assert_eq!(policy.http_allow.len(), 1);
        assert_eq!(policy.http_deny.len(), 1);
        assert_eq!(policy.http_allow[0].method, "GET");
        assert_eq!(policy.http_deny[0].host, "*");
    }
}
