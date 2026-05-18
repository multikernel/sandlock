use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::context;
use crate::error::SandboxError;

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

    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(SandboxError::Invalid("empty byte size string".into()));
        }

        // Check for suffix
        let last = s.chars().last().unwrap();
        if last.is_ascii_alphabetic() {
            let (num_str, suffix) = s.split_at(s.len() - 1);
            let n: u64 = num_str
                .trim()
                .parse()
                .map_err(|_| SandboxError::Invalid(format!("invalid byte size: {}", s)))?;
            match suffix.to_ascii_uppercase().as_str() {
                "K" => Ok(ByteSize::kib(n)),
                "M" => Ok(ByteSize::mib(n)),
                "G" => Ok(ByteSize::gib(n)),
                other => Err(SandboxError::Invalid(format!("unknown byte size suffix: {}", other))),
            }
        } else {
            let n: u64 = s
                .parse()
                .map_err(|_| SandboxError::Invalid(format!("invalid byte size: {}", s)))?;
            Ok(ByteSize(n))
        }
    }
}

/// Confinement for confining the current process in place.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confinement {
    pub fs_writable: Vec<PathBuf>,
    pub fs_readable: Vec<PathBuf>,
}

impl Confinement {
    pub fn builder() -> ConfinementBuilder {
        ConfinementBuilder::default()
    }
}

#[derive(Default)]
pub struct ConfinementBuilder {
    fs_writable: Vec<PathBuf>,
    fs_readable: Vec<PathBuf>,
}

impl ConfinementBuilder {
    pub fn fs_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_writable.push(path.into());
        self
    }

    pub fn fs_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_readable.push(path.into());
        self
    }

    pub fn build(self) -> Confinement {
        Confinement {
            fs_writable: self.fs_writable,
            fs_readable: self.fs_readable,
        }
    }
}

impl TryFrom<&Sandbox> for Confinement {
    type Error = SandboxError;

    fn try_from(sandbox: &Sandbox) -> Result<Self, Self::Error> {
        let mut unsupported = Vec::new();
        if !sandbox.fs_denied.is_empty() { unsupported.push("fs_denied"); }
        if !sandbox.extra_deny_syscalls.is_empty() { unsupported.push("extra_deny_syscalls"); }
        if !sandbox.net_allow.is_empty() { unsupported.push("net_allow"); }
        if !sandbox.net_bind.is_empty() { unsupported.push("net_bind"); }
        if sandbox.allows_sysv_ipc() { unsupported.push("extra_allow_syscalls=[\"sysv_ipc\"]"); }
        if !sandbox.http_allow.is_empty() { unsupported.push("http_allow"); }
        if !sandbox.http_deny.is_empty() { unsupported.push("http_deny"); }
        if !sandbox.http_ports.is_empty() { unsupported.push("http_ports"); }
        if sandbox.http_ca.is_some() { unsupported.push("http_ca"); }
        if sandbox.http_key.is_some() { unsupported.push("http_key"); }
        if sandbox.max_memory.is_some() { unsupported.push("max_memory"); }
        if sandbox.max_processes != 64 { unsupported.push("max_processes"); }
        if sandbox.max_open_files.is_some() { unsupported.push("max_open_files"); }
        if sandbox.max_cpu.is_some() { unsupported.push("max_cpu"); }
        if sandbox.random_seed.is_some() { unsupported.push("random_seed"); }
        if sandbox.time_start.is_some() { unsupported.push("time_start"); }
        if sandbox.no_randomize_memory { unsupported.push("no_randomize_memory"); }
        if sandbox.no_huge_pages { unsupported.push("no_huge_pages"); }
        if sandbox.no_coredump { unsupported.push("no_coredump"); }
        if sandbox.deterministic_dirs { unsupported.push("deterministic_dirs"); }
        if sandbox.fs_isolation != FsIsolation::None { unsupported.push("fs_isolation"); }
        if sandbox.workdir.is_some() { unsupported.push("workdir"); }
        if sandbox.cwd.is_some() { unsupported.push("cwd"); }
        if sandbox.fs_storage.is_some() { unsupported.push("fs_storage"); }
        if sandbox.max_disk.is_some() { unsupported.push("max_disk"); }
        if sandbox.on_exit != BranchAction::Commit { unsupported.push("on_exit"); }
        if sandbox.on_error != BranchAction::Abort { unsupported.push("on_error"); }
        if !sandbox.fs_mount.is_empty() { unsupported.push("fs_mount"); }
        if sandbox.chroot.is_some() { unsupported.push("chroot"); }
        if sandbox.clean_env { unsupported.push("clean_env"); }
        if !sandbox.env.is_empty() { unsupported.push("env"); }
        if sandbox.gpu_devices.is_some() { unsupported.push("gpu_devices"); }
        if sandbox.cpu_cores.is_some() { unsupported.push("cpu_cores"); }
        if sandbox.num_cpus.is_some() { unsupported.push("num_cpus"); }
        if sandbox.port_remap { unsupported.push("port_remap"); }
        if sandbox.uid.is_some() { unsupported.push("uid"); }
        if sandbox.policy_fn.is_some() { unsupported.push("policy_fn"); }

        if !unsupported.is_empty() {
            return Err(SandboxError::UnsupportedForConfine(unsupported.join(", ")));
        }

        Ok(Self {
            fs_writable: sandbox.fs_writable.clone(),
            fs_readable: sandbox.fs_readable.clone(),
        })
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

/// L4 protocol that a `NetAllow` rule applies to.
///
/// `Tcp` is the default if a rule has no scheme (the bare `host:port`
/// form). `Udp` and `Icmp` require an explicit scheme.
///
/// `Icmp` is the kernel's unprivileged ping socket
/// (`SOCK_DGRAM + IPPROTO_ICMP{,V6}`), gated by `ping_group_range` —
/// destinations are filterable per host. Sandlock does not expose raw
/// ICMP (`SOCK_RAW + IPPROTO_ICMP`): destination filtering at `sendto`
/// would lie because raw sockets let the agent craft the IP header,
/// and packet-crafting capabilities aren't part of the XOA threat
/// model. Workloads that genuinely need raw ICMP should run outside
/// sandlock or rely on the host's `ping_group_range` for the dgram
/// path instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Protocol {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            _ => None,
        }
    }
}

/// A network endpoint allow rule.
///
/// Each rule permits one protocol's traffic to one host (or any IP, for
/// the `:port` form) on a specific set of ports. Multiple rules are
/// OR'd: traffic is permitted if any rule matches the protocol, the
/// destination IP, and the destination port.
///
/// ICMP rules carry no port (ICMP has none); their `ports` is empty
/// and `all_ports` is false.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NetAllow {
    /// L4 protocol this rule applies to.
    #[serde(default = "default_protocol_tcp")]
    pub protocol: Protocol,
    /// Hostname; `None` means "any IP" (the `:port` form, or `icmp://*`).
    pub host: Option<String>,
    /// Permitted ports. Must be non-empty unless `all_ports` is true,
    /// in which case it must be empty. Always empty for `Protocol::Icmp`.
    pub ports: Vec<u16>,
    /// "Any port" wildcard from the `*` token in port position. When
    /// true, `ports` is empty; the rule permits every TCP/UDP port to
    /// the host (or to any IP, when `host` is `None`).
    #[serde(default)]
    pub all_ports: bool,
}

fn default_protocol_tcp() -> Protocol { Protocol::Tcp }

impl NetAllow {
    /// Parse a rule spec. Forms:
    ///
    /// - `host:port[,port,...]`, `:port`, `*:port`, `host:*`, `:*`, `*:*`
    ///   — TCP (the default scheme).
    /// - `tcp://...` — explicit TCP, same suffix grammar as the bare form.
    /// - `udp://...` — UDP, same suffix grammar as the bare form.
    /// - `icmp://host` or `icmp://*` — ICMP echo (kernel ping socket).
    ///   No port field; `icmp://host:80` is rejected.
    ///
    /// `*` in port position means "any port" (the all-ports wildcard).
    /// Mixing `*` with concrete ports (e.g. `host:80,*`) is rejected.
    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        // Split off the optional scheme prefix `<proto>://`. If absent,
        // default to TCP and the rest of the parser is unchanged.
        let (protocol, rest) = match s.split_once("://") {
            Some((scheme, body)) => {
                let proto = Protocol::parse(scheme).ok_or_else(|| {
                    SandboxError::Invalid(format!(
                        "--net-allow: unknown scheme `{}://` in `{}` (expected tcp, udp, icmp)",
                        scheme, s
                    ))
                })?;
                (proto, body)
            }
            None => (Protocol::Tcp, s),
        };

        if protocol == Protocol::Icmp {
            return Self::parse_icmp(rest, s);
        }

        let (host_part, port_part) = rest.rsplit_once(':').ok_or_else(|| {
            SandboxError::Invalid(format!(
                "--net-allow: expected `host:port` or `:port`, got `{}`",
                s
            ))
        })?;
        let host = match host_part {
            "" | "*" => None,
            h => Some(h.to_string()),
        };

        // Detect the wildcard token. We split on ',' first so a
        // single `*` is a clean match — `*,80` is rejected explicitly
        // below rather than letting `*` parse as port 0.
        let mut ports = Vec::new();
        let mut saw_wildcard = false;
        for p in port_part.split(',') {
            let p = p.trim();
            if p == "*" {
                saw_wildcard = true;
                continue;
            }
            let n: u16 = p.parse().map_err(|_| {
                SandboxError::Invalid(format!("--net-allow: invalid port `{}` in `{}`", p, s))
            })?;
            if n == 0 {
                return Err(SandboxError::Invalid(format!(
                    "--net-allow: port 0 is not valid in `{}`",
                    s
                )));
            }
            ports.push(n);
        }
        if saw_wildcard && !ports.is_empty() {
            return Err(SandboxError::Invalid(format!(
                "--net-allow: cannot mix `*` with concrete ports in `{}`",
                s
            )));
        }
        if !saw_wildcard && ports.is_empty() {
            return Err(SandboxError::Invalid(format!(
                "--net-allow: at least one port required in `{}`",
                s
            )));
        }
        Ok(NetAllow { protocol, host, ports, all_ports: saw_wildcard })
    }

    /// Parse the body of an `icmp://` rule. Accepts a host or `*` —
    /// ICMP has no ports, so any `:` separator is rejected.
    fn parse_icmp(body: &str, full: &str) -> Result<Self, SandboxError> {
        if body.contains(':') {
            return Err(SandboxError::Invalid(format!(
                "--net-allow: icmp rules take no port, got `{}`",
                full
            )));
        }
        if body.is_empty() {
            return Err(SandboxError::Invalid(format!(
                "--net-allow: icmp rule needs a host or `*`, got `{}`",
                full
            )));
        }
        let host = match body {
            "*" => None,
            h => Some(h.to_string()),
        };
        Ok(NetAllow {
            protocol: Protocol::Icmp,
            host,
            ports: Vec::new(),
            all_ports: false,
        })
    }
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
        // Path match — normalize to prevent encoding/traversal bypasses
        let normalized = normalize_path(path);
        prefix_or_exact_match(&self.path, &normalized)
    }
}

/// Normalize an HTTP path to prevent ACL bypasses via encoding tricks.
///
/// - Decodes percent-encoded characters (e.g. `%2F` → `/`, `%61` → `a`)
/// - Collapses duplicate slashes (`//` → `/`)
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
                // Malformed percent encoding — keep as-is
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

// ============================================================
// Runtime — private heap-allocated state, present only while running
// ============================================================

/// Private runtime state.  Only allocated after `start()` / `run()` is
/// called; `None` for config-only `Sandbox` instances.
struct Runtime {
    name: String,
    state: RuntimeState,
    child_pid: Option<i32>,
    pidfd: Option<std::os::fd::OwnedFd>,
    notif_handle: Option<JoinHandle<()>>,
    throttle_handle: Option<JoinHandle<()>>,
    loadavg_handle: Option<JoinHandle<()>>,
    _stdout_read: Option<std::os::fd::OwnedFd>,
    _stderr_read: Option<std::os::fd::OwnedFd>,
    cow_branch: Option<Box<dyn crate::cow::CowBranch>>,
    seccomp_cow: Option<crate::cow::seccomp::SeccompCowBranch>,
    supervisor_resource: Option<Arc<tokio::sync::Mutex<crate::seccomp::state::ResourceState>>>,
    supervisor_cow: Option<Arc<tokio::sync::Mutex<crate::seccomp::state::CowState>>>,
    supervisor_network: Option<Arc<tokio::sync::Mutex<crate::seccomp::state::NetworkState>>>,
    ctrl_fd: Option<std::os::fd::OwnedFd>,
    stdout_pipe: Option<std::os::fd::OwnedFd>,
    io_overrides: Option<(Option<i32>, Option<i32>, Option<i32>)>,
    extra_fds: Vec<(i32, i32)>,
    http_acl_handle: Option<crate::http_acl::HttpAclProxyHandle>,
    #[allow(clippy::type_complexity)]
    on_bind: Option<Box<dyn Fn(&HashMap<u16, u16>) + Send + Sync>>,
    extra_handlers: Vec<(i64, Arc<dyn crate::seccomp::dispatch::Handler>)>,
    ready_w: Option<std::os::fd::OwnedFd>,
}

/// Lifecycle state for the runtime.
enum RuntimeState {
    Created,
    Running,
    Paused,
    Stopped(crate::result::ExitStatus),
}

/// Sandbox configuration.
#[derive(Serialize, Deserialize)]
pub struct Sandbox {
    // Filesystem access
    pub fs_writable: Vec<PathBuf>,
    pub fs_readable: Vec<PathBuf>,
    pub fs_denied: Vec<PathBuf>,

    // Extra syscall filtering on top of Sandlock's default blocklist.
    pub extra_deny_syscalls: Vec<String>,
    pub extra_allow_syscalls: Vec<String>,

    // Network
    /// Outbound endpoint allowlist as a list of `(protocol, host?, ports)`
    /// rules. Each rule names a protocol (TCP/UDP/ICMP) and either a
    /// concrete host or "any IP." TCP and UDP rules carry ports; ICMP
    /// rules have none.
    ///
    /// **Protocol gating falls out of rule presence.** Sandlock denies
    /// UDP and ICMP socket creation by default; opting in is "list at
    /// least one rule for that protocol" (e.g. `udp://*:*` for any UDP,
    /// `icmp://*` for any ICMP echo). TCP is always permitted.
    ///
    /// Empty `net_allow` and empty `http_allow`/`http_deny` together
    /// mean "deny all outbound" (Landlock direct path denies, no
    /// on-behalf path is enabled). Otherwise, the on-behalf path
    /// enforces these rules: a destination is permitted iff any rule
    /// matches the protocol, destination IP (or has `host: None` = any
    /// IP), and destination port (N/A for ICMP).
    ///
    /// HTTP rules with concrete hosts auto-add a matching
    /// `(Tcp, host, [80])` (and `(Tcp, host, [443])` when `--http-ca`
    /// is set) entry at build time so the proxy's intercept ports
    /// remain reachable. HTTP rules with wildcard hosts auto-add
    /// `(Tcp, None, [80])` instead.
    pub net_allow: Vec<NetAllow>,
    pub net_bind: Vec<u16>,
    // HTTP ACL
    pub http_allow: Vec<HttpRule>,
    pub http_deny: Vec<HttpRule>,
    /// TCP ports to intercept for HTTP ACL. Defaults to [80] (plus 443 when
    /// http_ca is set). Override with `http_ports` to intercept custom ports.
    pub http_ports: Vec<u16>,
    /// PEM CA cert for HTTPS MITM. When set, port 443 is also intercepted.
    pub http_ca: Option<PathBuf>,
    /// PEM CA key for HTTPS MITM. Required when http_ca is set.
    pub http_key: Option<PathBuf>,

    // Namespace isolation — always enabled, not user-configurable.

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

    // Filesystem branch
    pub fs_isolation: FsIsolation,
    pub workdir: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub fs_storage: Option<PathBuf>,
    pub max_disk: Option<ByteSize>,
    pub on_exit: BranchAction,
    pub on_error: BranchAction,

    // Mount mappings: (virtual_path_inside_chroot, host_path_on_disk)
    pub fs_mount: Vec<(PathBuf, PathBuf)>,

    // Environment
    pub chroot: Option<PathBuf>,
    pub clean_env: bool,
    pub env: HashMap<String, String>,
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

    // Sandbox instance name (exposed as virtual hostname; auto-generated if None).
    // Not serialized — instance names are set at runtime, not in the policy file.
    #[serde(skip)]
    pub name: Option<String>,

    // COW fork init function — runs once in the child before COW cloning.
    // Not serialized; not cloned (FnOnce can't be cloned — drops to None on clone).
    #[serde(skip)]
    init_fn: Option<Box<dyn FnOnce() + Send + 'static>>,

    // COW fork work function — runs in each COW clone.
    // Not serialized; cloned via Arc (cheap).
    #[serde(skip)]
    work_fn: Option<Arc<dyn Fn(u32) + Send + Sync + 'static>>,

    // Heap-allocated runtime state; `None` when not started.
    #[serde(skip)]
    runtime: Option<Box<Runtime>>,
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandbox")
            .field("fs_readable", &self.fs_readable)
            .field("fs_writable", &self.fs_writable)
            .field("max_memory", &self.max_memory)
            .field("max_processes", &self.max_processes)
            .field("policy_fn", &self.policy_fn.as_ref().map(|_| "<callback>"))
            .field("name", &self.name)
            .field("runtime", &self.runtime.as_ref().map(|_| "<runtime>"))
            .finish_non_exhaustive()
    }
}

impl Clone for Sandbox {
    /// Clone a `Sandbox` — config and runtime-kwargs fields are cloned; the
    /// runtime state is not (the clone starts with `runtime: None`).
    ///
    /// Field clone semantics:
    /// - `policy_fn` — Arc bump (cheap).
    /// - `work_fn`   — Arc bump (cheap); multiple Sandboxes share the closure.
    /// - `init_fn`   — **dropped to `None`** (FnOnce can't be cloned). If the
    ///   clone also needs an init function, call `.init_fn(...)` on it
    ///   separately or set it via `SandboxBuilder::init_fn`.
    /// - `runtime`   — always `None`; the clone is a fresh, un-started Sandbox.
    fn clone(&self) -> Self {
        Self {
            fs_writable: self.fs_writable.clone(),
            fs_readable: self.fs_readable.clone(),
            fs_denied: self.fs_denied.clone(),
            extra_deny_syscalls: self.extra_deny_syscalls.clone(),
            extra_allow_syscalls: self.extra_allow_syscalls.clone(),
            net_allow: self.net_allow.clone(),
            net_bind: self.net_bind.clone(),
            http_allow: self.http_allow.clone(),
            http_deny: self.http_deny.clone(),
            http_ports: self.http_ports.clone(),
            http_ca: self.http_ca.clone(),
            http_key: self.http_key.clone(),
            max_memory: self.max_memory,
            max_processes: self.max_processes,
            max_open_files: self.max_open_files,
            max_cpu: self.max_cpu,
            random_seed: self.random_seed,
            time_start: self.time_start,
            no_randomize_memory: self.no_randomize_memory,
            no_huge_pages: self.no_huge_pages,
            no_coredump: self.no_coredump,
            deterministic_dirs: self.deterministic_dirs,
            fs_isolation: self.fs_isolation.clone(),
            workdir: self.workdir.clone(),
            cwd: self.cwd.clone(),
            fs_storage: self.fs_storage.clone(),
            max_disk: self.max_disk,
            on_exit: self.on_exit.clone(),
            on_error: self.on_error.clone(),
            fs_mount: self.fs_mount.clone(),
            chroot: self.chroot.clone(),
            clean_env: self.clean_env,
            env: self.env.clone(),
            gpu_devices: self.gpu_devices.clone(),
            cpu_cores: self.cpu_cores.clone(),
            num_cpus: self.num_cpus,
            port_remap: self.port_remap,
            uid: self.uid,
            policy_fn: self.policy_fn.clone(),
            name: self.name.clone(),
            // init_fn (FnOnce) cannot be cloned — the clone gets None.
            // If the clone also needs an init function, set it explicitly.
            init_fn: None,
            // work_fn is Arc-wrapped — clone bumps the reference count.
            work_fn: self.work_fn.clone(),
            // Runtime is NOT cloned — the clone starts with no runtime.
            runtime: None,
        }
    }
}

impl Sandbox {
    pub fn builder() -> SandboxBuilder {
        SandboxBuilder::default()
    }

    /// Returns true iff the policy grants the `sysv_ipc` syscall group.
    pub fn allows_sysv_ipc(&self) -> bool {
        self.extra_allow_syscalls.iter().any(|s| s == "sysv_ipc")
    }

    /// Validate cross-section invariants — checks that span multiple fields.
    ///
    /// Currently:
    /// - `fs_isolation != "none"` requires `workdir` to be set.
    ///
    /// Idempotent: calling repeatedly is safe.
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.fs_isolation != FsIsolation::None && self.workdir.is_none() {
            return Err(SandboxError::FsIsolationRequiresWorkdir);
        }
        Ok(())
    }

    // ================================================================
    // Runtime accessor helpers (private)
    // ================================================================

    fn rt(&self) -> &Runtime {
        self.runtime.as_ref().expect("sandbox not started")
    }

    fn rt_mut(&mut self) -> &mut Runtime {
        self.runtime.as_mut().expect("sandbox not started")
    }

    // ================================================================
    // Runtime lifecycle API (public)
    // ================================================================

    /// Set the sandbox instance name (also exposed as the virtual hostname).
    /// Auto-generated if not set.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    /// Set the sandbox instance name and return `self`. Convenience for
    /// pipeline fan-out where a base config is cloned and each clone gets a
    /// fresh name:
    ///
    /// ```ignore
    /// let template = Sandbox::builder()...build()?;
    /// let mut s1 = template.clone().with_name("worker-1");
    /// let mut s2 = template.clone().with_name("worker-2");
    /// ```
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the COW-fork init function and return `self`.
    ///
    /// The init function runs once in the child process before any COW clones
    /// are created. Use it to load expensive shared state.
    pub fn with_init_fn(mut self, f: impl FnOnce() + Send + 'static) -> Self {
        self.init_fn = Some(Box::new(f));
        self
    }

    /// Set the COW-fork work function and return `self`.
    ///
    /// The work function runs in each COW clone (`fork(N)` produces N clones).
    pub fn with_work_fn(mut self, f: impl Fn(u32) + Send + Sync + 'static) -> Self {
        self.work_fn = Some(Arc::new(f));
        self
    }

    /// Return the sandbox name if set, or `None` if not yet started.
    pub fn instance_name(&self) -> Option<&str> {
        self.runtime.as_ref().map(|r| r.name.as_str())
            .or_else(|| self.name.as_deref())
    }

    /// Return the child PID if spawned.
    pub fn pid(&self) -> Option<i32> {
        self.runtime.as_ref().and_then(|r| r.child_pid)
    }

    /// Return whether the child is currently running or paused.
    pub fn is_running(&self) -> bool {
        self.runtime.as_ref().map(|r| {
            matches!(r.state, RuntimeState::Running | RuntimeState::Paused)
        }).unwrap_or(false)
    }

    /// Send SIGSTOP to the child's process group.
    pub fn pause(&mut self) -> Result<(), crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        let pid = self.runtime.as_ref()
            .and_then(|rt| rt.child_pid)
            .ok_or(SandboxRuntimeError::NotRunning)?;
        let ret = unsafe { libc::killpg(pid, libc::SIGSTOP) };
        if ret < 0 {
            return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
        }
        self.rt_mut().state = RuntimeState::Paused;
        Ok(())
    }

    /// Send SIGCONT to the child's process group.
    pub fn resume(&mut self) -> Result<(), crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        let pid = self.runtime.as_ref()
            .and_then(|rt| rt.child_pid)
            .ok_or(SandboxRuntimeError::NotRunning)?;
        let ret = unsafe { libc::killpg(pid, libc::SIGCONT) };
        if ret < 0 {
            return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
        }
        self.rt_mut().state = RuntimeState::Running;
        Ok(())
    }

    /// Send SIGKILL to the child's process group.
    pub fn kill(&mut self) -> Result<(), crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        let pid = self.runtime.as_ref()
            .and_then(|rt| rt.child_pid)
            .ok_or(SandboxRuntimeError::NotRunning)?;
        let ret = unsafe { libc::killpg(pid, libc::SIGKILL) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(SandboxRuntimeError::Io(err).into());
            }
        }
        Ok(())
    }

    /// Set a callback invoked whenever a port bind is recorded.
    pub fn set_on_bind(&mut self, cb: impl Fn(&HashMap<u16, u16>) + Send + Sync + 'static) {
        // Ensure runtime exists so we have somewhere to store the callback.
        // In practice, set_on_bind is always called before spawn.
        let _ = self.ensure_runtime();
        self.rt_mut().on_bind = Some(Box::new(cb));
    }

    /// Return the current virtual-to-real port mappings.
    pub async fn port_mappings(&self) -> HashMap<u16, u16> {
        if let Some(ref rt) = self.runtime {
            if let Some(ref net) = rt.supervisor_network {
                let ns = net.lock().await;
                return ns.port_map.virtual_to_real.clone();
            }
        }
        HashMap::new()
    }

    /// Wait for the child process to exit.
    pub async fn wait(&mut self) -> Result<crate::result::RunResult, crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        use crate::result::{ExitStatus, RunResult};

        let pid = self.rt().child_pid.ok_or(SandboxRuntimeError::NotRunning)?;

        if let RuntimeState::Stopped(ref es) = self.rt().state {
            return Ok(RunResult {
                exit_status: es.clone(),
                stdout: None,
                stderr: None,
            });
        }

        let exit_status = tokio::task::spawn_blocking(move || -> ExitStatus {
            let mut status: i32 = 0;
            loop {
                let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return ExitStatus::Killed;
                }
                break;
            }
            sandbox_wait_status_to_exit(status)
        })
        .await
        .unwrap_or(ExitStatus::Killed);

        self.rt_mut().state = RuntimeState::Stopped(exit_status.clone());

        let rt = self.rt_mut();
        if let Some(h) = rt.notif_handle.take() { h.abort(); }
        if let Some(h) = rt.throttle_handle.take() { h.abort(); }
        if let Some(h) = rt.loadavg_handle.take() { h.abort(); }

        if let Some(ref cow_state) = self.rt().supervisor_cow.clone() {
            let mut cow = cow_state.lock().await;
            self.rt_mut().seccomp_cow = cow.branch.take();
        }

        let stdout = self.rt_mut()._stdout_read.take().map(sandbox_read_fd_to_end);
        let stderr = self.rt_mut()._stderr_read.take().map(sandbox_read_fd_to_end);

        Ok(RunResult { exit_status, stdout, stderr })
    }

    /// Fork the sandboxed child and install policy (seccomp + notif
    /// supervisor + rlimits + landlock + COW + network/HTTP proxies).
    /// The child is parked between policy install and `execve`; call
    /// `start()` to release it. Stdout/stderr are captured for later
    /// retrieval via `wait()`.
    pub async fn create(&mut self, cmd: &[&str]) -> Result<(), crate::error::SandlockError> {
        self.do_create(cmd, true).await
    }

    /// Like `create` but inherits stdio (no capture).
    pub async fn create_interactive(&mut self, cmd: &[&str]) -> Result<(), crate::error::SandlockError> {
        self.do_create(cmd, false).await
    }

    /// Release a previously `create()`d child to `execve` the configured
    /// command. Returns immediately; use `wait()` to collect the exit
    /// status when the child finishes.
    pub fn start(&mut self) -> Result<(), crate::error::SandlockError> {
        self.do_start()
    }

    /// Create with explicit stdin/stdout/stderr fd redirection. Child is
    /// parked after policy install; call `start()` to release.
    #[doc(hidden)]
    pub async fn create_with_io(
        &mut self,
        cmd: &[&str],
        stdin_fd: Option<std::os::unix::io::RawFd>,
        stdout_fd: Option<std::os::unix::io::RawFd>,
        stderr_fd: Option<std::os::unix::io::RawFd>,
    ) -> Result<(), crate::error::SandlockError> {
        self.ensure_runtime()?;
        self.rt_mut().io_overrides = Some((stdin_fd, stdout_fd, stderr_fd));
        self.do_create(cmd, false).await
    }

    /// Like `create_with_io` but also maps extra fds into the child.
    #[doc(hidden)]
    pub async fn create_with_gather_io(
        &mut self,
        cmd: &[&str],
        stdin_fd: Option<std::os::unix::io::RawFd>,
        stdout_fd: Option<std::os::unix::io::RawFd>,
        stderr_fd: Option<std::os::unix::io::RawFd>,
        extra_fds: Vec<(i32, i32)>,
    ) -> Result<(), crate::error::SandlockError> {
        self.ensure_runtime()?;
        self.rt_mut().io_overrides = Some((stdin_fd, stdout_fd, stderr_fd));
        self.rt_mut().extra_fds = extra_fds;
        self.do_create(cmd, false).await
    }

    /// Commit COW writes to the original directory.
    #[doc(hidden)]
    pub async fn commit(&mut self) -> Result<(), crate::error::SandlockError> {
        use crate::error::{SandboxRuntimeError, SandlockError};
        if let Some(ref mut rt) = self.runtime {
            if let Some(branch) = rt.cow_branch.take() {
                branch.commit().map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Branch(e)))?;
            }
        }
        Ok(())
    }

    /// Discard COW writes.
    #[doc(hidden)]
    pub async fn abort_branch(&mut self) -> Result<(), crate::error::SandlockError> {
        use crate::error::{SandboxRuntimeError, SandlockError};
        if let Some(ref mut rt) = self.runtime {
            if let Some(branch) = rt.cow_branch.take() {
                branch.abort().map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Branch(e)))?;
            }
        }
        Ok(())
    }

    /// Freeze the sandbox: hold fork notifications + SIGSTOP the process group.
    pub(crate) async fn freeze(&self) -> Result<(), crate::error::SandlockError> {
        use crate::error::{SandboxRuntimeError, SandlockError};
        let rt = self.runtime.as_ref().ok_or(SandlockError::Runtime(SandboxRuntimeError::NotRunning))?;
        let pid = rt.child_pid.ok_or(SandlockError::Runtime(SandboxRuntimeError::NotRunning))?;
        if let Some(ref resource) = rt.supervisor_resource {
            let mut rs = resource.lock().await;
            rs.hold_forks = true;
        }
        unsafe { libc::killpg(pid, libc::SIGSTOP); }
        Ok(())
    }

    /// Thaw the sandbox: release held fork notifications + SIGCONT.
    pub(crate) async fn thaw(&self) -> Result<(), crate::error::SandlockError> {
        use crate::error::{SandboxRuntimeError, SandlockError};
        let rt = self.runtime.as_ref().ok_or(SandlockError::Runtime(SandboxRuntimeError::NotRunning))?;
        let pid = rt.child_pid.ok_or(SandlockError::Runtime(SandboxRuntimeError::NotRunning))?;
        if let Some(ref resource) = rt.supervisor_resource {
            let mut rs = resource.lock().await;
            rs.hold_forks = false;
            rs.held_notif_ids.clear();
        }
        unsafe { libc::killpg(pid, libc::SIGCONT); }
        Ok(())
    }

    /// Capture a checkpoint of the running sandbox.
    pub async fn checkpoint(&self) -> Result<crate::checkpoint::Checkpoint, crate::error::SandlockError> {
        use crate::error::{SandboxRuntimeError, SandlockError};
        let pid = self.runtime.as_ref()
            .and_then(|rt| rt.child_pid)
            .ok_or(SandlockError::Runtime(SandboxRuntimeError::NotRunning))?;
        self.freeze().await?;
        let cp = crate::checkpoint::capture(pid, self);
        self.thaw().await?;
        cp
    }

    // ================================================================
    // One-shot / lifecycle instance API
    // ================================================================

    /// One-shot: spawn, wait, and return the result. Stdout and stderr are
    /// captured. This is the primary way to run a sandboxed command:
    ///
    /// ```ignore
    /// let mut sandbox = Sandbox::builder()
    ///     .fs_read("/usr")
    ///     .name("my-sandbox")
    ///     .build()?;
    /// let result = sandbox.run(&["echo", "hello"]).await?;
    /// ```
    pub async fn run(
        &mut self,
        cmd: &[&str],
    ) -> Result<crate::result::RunResult, crate::error::SandlockError> {
        self.do_create(cmd, true).await?;
        self.do_start()?;
        self.wait().await
    }

    /// Run with inherited stdio (interactive mode).
    pub async fn run_interactive(
        &mut self,
        cmd: &[&str],
    ) -> Result<crate::result::RunResult, crate::error::SandlockError> {
        self.do_create(cmd, false).await?;
        self.do_start()?;
        self.wait().await
    }

    /// One-shot run with user-supplied syscall handlers.
    pub async fn run_with_extra_handlers<I, S, H>(
        &mut self,
        cmd: &[&str],
        extra_handlers: I,
    ) -> Result<crate::result::RunResult, crate::error::SandlockError>
    where
        I: IntoIterator<Item = (S, H)>,
        S: TryInto<crate::seccomp::syscall::Syscall, Error = crate::seccomp::syscall::SyscallError>,
        H: crate::seccomp::dispatch::Handler,
    {
        let pending = sandbox_collect_extra_handlers(extra_handlers, self)?;
        self.ensure_runtime()?;
        self.rt_mut().extra_handlers = pending;
        self.do_create(cmd, true).await?;
        self.do_start()?;
        self.wait().await
    }

    /// Interactive-stdio counterpart of `run_with_extra_handlers`.
    pub async fn run_interactive_with_extra_handlers<I, S, H>(
        &mut self,
        cmd: &[&str],
        extra_handlers: I,
    ) -> Result<crate::result::RunResult, crate::error::SandlockError>
    where
        I: IntoIterator<Item = (S, H)>,
        S: TryInto<crate::seccomp::syscall::Syscall, Error = crate::seccomp::syscall::SyscallError>,
        H: crate::seccomp::dispatch::Handler,
    {
        let pending = sandbox_collect_extra_handlers(extra_handlers, self)?;
        self.ensure_runtime()?;
        self.rt_mut().extra_handlers = pending;
        self.do_create(cmd, false).await?;
        self.do_start()?;
        self.wait().await
    }

    /// Dry-run: create, start, wait, collect filesystem changes, then abort.
    pub async fn dry_run(
        &mut self,
        cmd: &[&str],
    ) -> Result<crate::dry_run::DryRunResult, crate::error::SandlockError> {
        self.on_exit = BranchAction::Keep;
        self.on_error = BranchAction::Keep;
        self.do_create(cmd, true).await?;
        self.do_start()?;
        let run_result = self.wait().await?;
        let changes = self.collect_changes().await;
        self.do_abort().await;
        Ok(crate::dry_run::DryRunResult { run_result, changes })
    }

    /// Dry-run with inherited stdio.
    pub async fn dry_run_interactive(
        &mut self,
        cmd: &[&str],
    ) -> Result<crate::dry_run::DryRunResult, crate::error::SandlockError> {
        self.on_exit = BranchAction::Keep;
        self.on_error = BranchAction::Keep;
        self.do_create(cmd, false).await?;
        self.do_start()?;
        let run_result = self.wait().await?;
        let changes = self.collect_changes().await;
        self.do_abort().await;
        Ok(crate::dry_run::DryRunResult { run_result, changes })
    }

    /// Create N COW clones of this sandbox.
    ///
    /// `fork()` requires `init_fn` and `work_fn` to be set on the sandbox (via
    /// `SandboxBuilder::init_fn` / `work_fn`, or `Sandbox::with_init_fn` /
    /// `with_work_fn`). Returns an error if either is missing.
    pub async fn fork(&mut self, n: u32) -> Result<Vec<Sandbox>, crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        use std::os::fd::{FromRawFd, OwnedFd};

        // Pull init_fn / work_fn directly from self (they live on Sandbox, not
        // Runtime, so ensure_runtime hasn't consumed them yet).
        let init_fn = self.init_fn.take()
            .ok_or_else(|| SandboxRuntimeError::Child("fork() requires init_fn and work_fn — use SandboxBuilder::init_fn() / work_fn() or Sandbox::with_init_fn() / with_work_fn()".into()))?;
        let work_fn = self.work_fn.take()
            .ok_or_else(|| SandboxRuntimeError::Child("fork() requires init_fn and work_fn — use SandboxBuilder::init_fn() / work_fn() or Sandbox::with_init_fn() / with_work_fn()".into()))?;

        // Initialize the runtime block so we can record child PID / state below.
        self.ensure_runtime()?;

        let sandbox_cfg = self.clone(); // config only, no runtime

        let mut ctrl_fds = [0i32; 2];
        if unsafe { libc::pipe2(ctrl_fds.as_mut_ptr(), 0) } < 0 {
            return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
        }
        let ctrl_parent = unsafe { OwnedFd::from_raw_fd(ctrl_fds[0]) };
        let ctrl_child_fd = ctrl_fds[1];

        let mut pipe_read_ends: Vec<OwnedFd> = Vec::with_capacity(n as usize);
        let mut pipe_write_fds: Vec<i32> = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let mut pfds = [0i32; 2];
            if unsafe { libc::pipe(pfds.as_mut_ptr()) } >= 0 {
                pipe_read_ends.push(unsafe { OwnedFd::from_raw_fd(pfds[0]) });
                pipe_write_fds.push(pfds[1]);
            } else {
                pipe_write_fds.push(-1);
            }
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe { libc::close(ctrl_child_fd) };
            return Err(SandboxRuntimeError::Fork(std::io::Error::last_os_error()).into());
        }

        if pid == 0 {
            drop(ctrl_parent);
            unsafe { libc::setpgid(0, 0) };
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

            let _ = crate::landlock::confine(&sandbox_cfg);

            let deny = crate::context::blocklist_syscall_numbers(&sandbox_cfg);
            let args = crate::context::arg_filters(&sandbox_cfg);
            let filter = match crate::seccomp::bpf::assemble_filter(&[], &deny, &args) {
                Ok(f) => f,
                Err(_) => unsafe { libc::_exit(1) },
            };
            let _ = crate::seccomp::bpf::install_deny_filter(&filter);

            crate::process::CONFINED.store(true, std::sync::atomic::Ordering::Relaxed);

            init_fn();

            drop(pipe_read_ends);
            crate::fork::fork_ready_loop_fn(ctrl_child_fd, n, &*work_fn, &pipe_write_fds);
            unsafe { libc::_exit(0) };
        }

        unsafe { libc::close(ctrl_child_fd) };
        for wfd in &pipe_write_fds {
            if *wfd >= 0 { unsafe { libc::close(*wfd) }; }
        }
        self.rt_mut().child_pid = Some(pid);
        self.rt_mut().state = RuntimeState::Running;

        let ctrl_fd = ctrl_parent.as_raw_fd();
        let mut pid_buf = vec![0u8; n as usize * 4];
        sandbox_read_exact(ctrl_fd, &mut pid_buf);

        let clone_pids: Vec<i32> = pid_buf.chunks(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap_or([0; 4])) as i32)
            .collect();
        let live_count = clone_pids.iter().filter(|&&p| p > 0).count();

        let mut code_buf = vec![0u8; live_count * 4];
        sandbox_read_exact(ctrl_fd, &mut code_buf);
        self.rt_mut().ctrl_fd = Some(ctrl_parent);

        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        let mut code_idx = 0;
        let mut clones = Vec::with_capacity(live_count);
        let mut pipe_iter = pipe_read_ends.into_iter();

        let rt_name = self.rt().name.clone();
        for &clone_pid in &clone_pids {
            let pipe = pipe_iter.next();
            if clone_pid <= 0 { continue; }

            let code = i32::from_be_bytes(
                code_buf[code_idx * 4..(code_idx + 1) * 4].try_into().unwrap_or([0; 4])
            );
            code_idx += 1;

            let mut clone_sb = sandbox_cfg.clone();
            let clone_name = format!("{}-fork-{}", rt_name, clone_pid);
            clone_sb.runtime = Some(Box::new(Runtime {
                name: clone_name,
                state: RuntimeState::Stopped(if code == 0 {
                    crate::result::ExitStatus::Code(0)
                } else if code > 0 {
                    crate::result::ExitStatus::Code(code)
                } else {
                    crate::result::ExitStatus::Killed
                }),
                child_pid: Some(clone_pid),
                pidfd: None,
                notif_handle: None,
                throttle_handle: None,
                loadavg_handle: None,
                _stdout_read: None,
                _stderr_read: None,
                cow_branch: None,
                seccomp_cow: None,
                supervisor_resource: None,
                supervisor_cow: None,
                supervisor_network: None,
                ctrl_fd: None,
                stdout_pipe: pipe,
                io_overrides: None,
                extra_fds: Vec::new(),
                http_acl_handle: None,
                on_bind: None,
                extra_handlers: Vec::new(),
                ready_w: None,
            }));
            clones.push(clone_sb);
        }

        Ok(clones)
    }

    /// Reduce: wait for all clones, then run a reducer command.
    pub async fn reduce(
        &self,
        cmd: &[&str],
        clones: &mut [Sandbox],
    ) -> Result<crate::result::RunResult, crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;

        let mut combined = Vec::new();
        for clone in clones.iter_mut() {
            if let Some(ref mut rt) = clone.runtime {
                if let Some(pipe) = rt.stdout_pipe.take() {
                    combined.extend_from_slice(&sandbox_read_fd_to_end(pipe));
                }
            }
        }

        let mut stdin_fds = [0i32; 2];
        if unsafe { libc::pipe2(stdin_fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
        }

        let write_fd = stdin_fds[1];
        let write_handle = tokio::task::spawn_blocking(move || {
            unsafe {
                libc::write(write_fd, combined.as_ptr() as *const _, combined.len());
                libc::close(write_fd);
            }
        });

        let base_name = self.instance_name()
            .unwrap_or("sandbox")
            .to_owned();
        let reducer_name = base_name + "-reduce";
        let mut reducer = self.clone().with_name(reducer_name);
        reducer.ensure_runtime()?;
        reducer.rt_mut().io_overrides = Some((Some(stdin_fds[0]), None, None));
        reducer.do_create(cmd, true).await?;
        reducer.do_start()?;
        unsafe { libc::close(stdin_fds[0]) };

        let _ = write_handle.await;
        reducer.wait().await
    }

    /// Lazily initialize the runtime block.
    ///
    /// Called by lifecycle methods (`spawn`, `run`, `fork`, etc.) on first
    /// use. Validates and resolves the sandbox name. Idempotent: returns
    /// immediately if runtime is already set.
    fn ensure_runtime(&mut self) -> Result<(), crate::error::SandlockError> {
        if self.runtime.is_some() {
            return Ok(());
        }
        let name = sandbox_resolve_name(self.name.as_deref())?;
        self.runtime = Some(Box::new(Runtime {
            name,
            state: RuntimeState::Created,
            child_pid: None,
            pidfd: None,
            notif_handle: None,
            throttle_handle: None,
            loadavg_handle: None,
            _stdout_read: None,
            _stderr_read: None,
            cow_branch: None,
            seccomp_cow: None,
            supervisor_resource: None,
            supervisor_cow: None,
            supervisor_network: None,
            ctrl_fd: None,
            stdout_pipe: None,
            io_overrides: None,
            extra_fds: Vec::new(),
            http_acl_handle: None,
            on_bind: None,
            extra_handlers: Vec::new(),
            ready_w: None,
        }));
        Ok(())
    }

    // ================================================================
    // Internal: collect_changes / do_abort
    // ================================================================

    async fn collect_changes(&self) -> Vec<crate::dry_run::Change> {
        if let Some(ref rt) = self.runtime {
            if let Some(ref branch) = rt.cow_branch {
                return branch.changes().unwrap_or_default();
            }
            if let Some(ref cow) = rt.seccomp_cow {
                return cow.changes().unwrap_or_default();
            }
        }
        Vec::new()
    }

    async fn do_abort(&mut self) {
        if let Some(ref mut rt) = self.runtime {
            if let Some(branch) = rt.cow_branch.take() {
                let _ = branch.abort();
            }
            if let Some(ref mut cow) = rt.seccomp_cow {
                let _ = cow.abort();
            }
        }
    }

    // ================================================================
    // Internal: do_create (fork + policy install; child parks at the
    // ready_r read, awaiting do_start to release it to execve).
    // ================================================================

    async fn do_create(&mut self, cmd: &[&str], capture: bool) -> Result<(), crate::error::SandlockError> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use crate::error::SandboxRuntimeError;
        use crate::context::{PipePair, read_u32_fd};
        use crate::cow::{CowBranch, overlayfs::OverlayBranch, branchfs::BranchFsBranch};
        use crate::network;
        use crate::seccomp::ctx::SupervisorCtx;
        use crate::seccomp::notif::{self, NotifPolicy};
        use crate::seccomp::state::{ChrootState, CowState, NetworkState, PolicyFnState, ProcfsState, ResourceState, TimeRandomState};
        use crate::sys::syscall;
        use std::time::Duration;

        self.ensure_runtime()?;

        if !matches!(self.rt().state, RuntimeState::Created) {
            return Err(SandboxRuntimeError::Child("sandbox already spawned".into()).into());
        }

        if cmd.is_empty() {
            return Err(SandboxRuntimeError::Child("empty command".into()).into());
        }

        let c_cmd: Vec<CString> = cmd
            .iter()
            .map(|s| CString::new(*s).map_err(|_| SandboxRuntimeError::Child("invalid command string".into())))
            .collect::<Result<Vec<_>, _>>()?;

        let nested = crate::process::is_nested();

        let pipes = PipePair::new().map_err(SandboxRuntimeError::Io)?;

        let resolved_net_allow = network::resolve_net_allow(&self.net_allow)
            .await
            .map_err(SandboxRuntimeError::Io)?;
        let virtual_etc_hosts = resolved_net_allow.etc_hosts.clone();

        if !self.http_allow.is_empty() || !self.http_deny.is_empty() {
            let handle = crate::http_acl::spawn_http_acl_proxy(
                self.http_allow.clone(),
                self.http_deny.clone(),
                self.http_ca.as_deref(),
                self.http_key.as_deref(),
            ).await.map_err(SandboxRuntimeError::Io)?;
            self.rt_mut().http_acl_handle = Some(handle);
        }

        let cow_branch: Option<Box<dyn CowBranch>> = match self.fs_isolation {
            FsIsolation::OverlayFs => {
                let workdir = self.workdir.as_ref()
                    .ok_or_else(|| crate::error::SandlockError::Runtime(SandboxRuntimeError::Child("OverlayFs requires workdir".into())))?;
                let storage = self.fs_storage.as_ref()
                    .cloned()
                    .unwrap_or_else(|| std::env::temp_dir().join("sandlock-overlay"));
                std::fs::create_dir_all(&storage)
                    .map_err(|e| crate::error::SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
                let branch = OverlayBranch::create(workdir, &storage)
                    .map_err(|e| crate::error::SandlockError::Runtime(SandboxRuntimeError::Branch(e)))?;
                Some(Box::new(branch))
            }
            FsIsolation::BranchFs => {
                let workdir = self.workdir.as_ref()
                    .ok_or_else(|| crate::error::SandlockError::Runtime(SandboxRuntimeError::Child("BranchFs requires workdir".into())))?;
                let branch = BranchFsBranch::create(workdir)
                    .map_err(|e| crate::error::SandlockError::Runtime(SandboxRuntimeError::Branch(e)))?;
                Some(Box::new(branch))
            }
            FsIsolation::None => None,
        };

        let cow_config = cow_branch.as_ref().and_then(|b| b.child_mount_config());

        let (stdout_r, stderr_r) = if capture {
            let mut stdout_fds = [0i32; 2];
            let mut stderr_fds = [0i32; 2];
            if unsafe { libc::pipe2(stdout_fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
                return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
            }
            if unsafe { libc::pipe2(stderr_fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
                unsafe {
                    libc::close(stdout_fds[0]);
                    libc::close(stdout_fds[1]);
                }
                return Err(SandboxRuntimeError::Io(std::io::Error::last_os_error()).into());
            }
            (
                Some((
                    unsafe { OwnedFd::from_raw_fd(stdout_fds[0]) },
                    unsafe { OwnedFd::from_raw_fd(stdout_fds[1]) },
                )),
                Some((
                    unsafe { OwnedFd::from_raw_fd(stderr_fds[0]) },
                    unsafe { OwnedFd::from_raw_fd(stderr_fds[1]) },
                )),
            )
        } else {
            (None, None)
        };

        // Capture our PID before fork so the child can detect parent death
        // without assuming PID 1 is always init (wrong in containers).
        let parent_pid = unsafe { libc::getpid() };

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(SandboxRuntimeError::Fork(std::io::Error::last_os_error()).into());
        }

        if pid == 0 {
            // ===== CHILD PROCESS =====
            let io_overrides = self.rt().io_overrides;
            if let Some((stdin_fd, stdout_fd, stderr_fd)) = io_overrides {
                if let Some(fd) = stdin_fd { unsafe { libc::dup2(fd, 0) }; }
                if let Some(fd) = stdout_fd { unsafe { libc::dup2(fd, 1) }; }
                if let Some(fd) = stderr_fd { unsafe { libc::dup2(fd, 2) }; }
            }

            let extra_fds_copy = self.rt().extra_fds.clone();
            for &(target_fd, source_fd) in &extra_fds_copy {
                unsafe { libc::dup2(source_fd, target_fd) };
            }

            if let Some((_, ref stdout_w)) = stdout_r {
                unsafe { libc::dup2(stdout_w.as_raw_fd(), 1) };
            }
            if let Some((_, ref stderr_w)) = stderr_r {
                unsafe { libc::dup2(stderr_w.as_raw_fd(), 2) };
            }
            drop(stdout_r);
            drop(stderr_r);

            let gather_keep_fds: Vec<i32> = extra_fds_copy.iter().map(|&(target, _)| target).collect();

            let extra_syscalls: Vec<u32> = self.rt().extra_handlers
                .iter()
                .map(|h| h.0 as u32)
                .collect();

            let sandbox_name = self.rt().name.clone();
            context::confine_child(context::ChildSpawnArgs {
                sandbox: self,
                cmd: &c_cmd,
                pipes: &pipes,
                cow_config: cow_config.as_ref(),
                nested,
                keep_fds: &gather_keep_fds,
                sandbox_name: Some(sandbox_name.as_str()),
                extra_syscalls: &extra_syscalls,
                parent_pid,
            });
        }

        // ===== PARENT PROCESS =====
        self.rt_mut().cow_branch = cow_branch;

        drop(pipes.notif_w);
        drop(pipes.ready_r);

        self.rt_mut()._stdout_read = stdout_r.map(|(r, _w)| r);
        self.rt_mut()._stderr_read = stderr_r.map(|(r, _w)| r);

        self.rt_mut().child_pid = Some(pid);
        // State remains `Created` until `do_start` writes ready_w to release
        // the child to execve.

        let pidfd = match syscall::pidfd_open(pid as u32, 0) {
            Ok(fd) => Some(fd),
            Err(_) => None,
        };

        let notif_fd_num = read_u32_fd(pipes.notif_r.as_raw_fd())
            .map_err(|e| SandboxRuntimeError::Child(format!("read notif fd from child: {}", e)))?;

        let is_nested_mode = notif_fd_num == 0;

        let notif_fd = if is_nested_mode {
            None
        } else if let Some(ref pfd) = pidfd {
            Some(syscall::pidfd_getfd(pfd, notif_fd_num as i32, 0)
                .map_err(|e| SandboxRuntimeError::Child(format!("pidfd_getfd: {}", e)))?)
        } else {
            let path = format!("/proc/{}/fd/{}", pid, notif_fd_num);
            let cpath = CString::new(path).unwrap();
            let raw = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
            if raw < 0 {
                return Err(SandboxRuntimeError::Child("failed to open notif fd from /proc".into()).into());
            }
            Some(unsafe { OwnedFd::from_raw_fd(raw) })
        };

        if let Some(notif_fd) = notif_fd {
            if self.time_start.is_some() || self.random_seed.is_some() {
                let time_offset = self.time_start.map(|t| crate::time::calculate_time_offset(t));
                if let Err(e) = crate::vdso::patch(pid, time_offset, self.random_seed.is_some()) {
                    eprintln!("sandlock: pre-exec vDSO patching failed (will retry after exec): {}", e);
                }
            }

            let time_offset_val = self.time_start
                .map(|t| crate::time::calculate_time_offset(t))
                .unwrap_or(0);

            let rt_name = self.rt().name.clone();
            let notif_policy = NotifPolicy {
                max_memory_bytes: self.max_memory.map(|m| m.0).unwrap_or(0),
                max_processes: self.max_processes,
                has_memory_limit: self.max_memory.is_some(),
                has_net_allowlist: !self.net_allow.is_empty()
                    || self.policy_fn.is_some()
                    || !self.http_allow.is_empty()
                    || !self.http_deny.is_empty(),
                has_random_seed: self.random_seed.is_some(),
                has_time_start: self.time_start.is_some(),
                argv_safety_required: self.policy_fn.is_some()
                    || self.rt().extra_handlers.iter().any(|h| {
                        h.0 == libc::SYS_execve || h.0 == libc::SYS_execveat
                    }),
                time_offset: time_offset_val,
                num_cpus: self.num_cpus,
                port_remap: self.port_remap,
                cow_enabled: self.workdir.is_some() && self.fs_isolation == FsIsolation::None,
                chroot_root: self.chroot.as_ref().and_then(|p| std::fs::canonicalize(p).ok()),
                chroot_readable: self.fs_readable.clone(),
                chroot_writable: self.fs_writable.clone(),
                chroot_denied: self.fs_denied.clone(),
                chroot_mounts: self.fs_mount.iter().map(|(vp, hp)| {
                    (vp.clone(), std::fs::canonicalize(hp).unwrap_or_else(|_| hp.clone()))
                }).collect(),
                deterministic_dirs: self.deterministic_dirs,
                virtual_hostname: Some(rt_name),
                has_http_acl: !self.http_allow.is_empty() || !self.http_deny.is_empty(),
                virtual_etc_hosts,
            };

            use rand::SeedableRng;
            use rand_chacha::ChaCha8Rng;

            let random_state = self.random_seed.map(|seed| ChaCha8Rng::seed_from_u64(seed));
            let time_offset = self.time_start.map(|t| crate::time::calculate_time_offset(t));

            let time_random_state = TimeRandomState::new(time_offset, random_state);

            let mut net_state = NetworkState::new();
            let no_rules = self.net_allow.is_empty();
            let policy_from = |resolved: &network::ResolvedNetAllow| {
                if no_rules || resolved.any_ip_all_ports {
                    crate::seccomp::notif::NetworkPolicy::Unrestricted
                } else {
                    use crate::seccomp::notif::PortAllow;
                    let per_ip = resolved
                        .per_ip
                        .iter()
                        .map(|(ip, ports)| {
                            let allow = if resolved.per_ip_all_ports.contains(ip) {
                                PortAllow::Any
                            } else {
                                PortAllow::Specific(ports.clone())
                            };
                            (*ip, allow)
                        })
                        .collect();
                    crate::seccomp::notif::NetworkPolicy::AllowList {
                        per_ip,
                        any_ip_ports: resolved.any_ip_ports.clone(),
                    }
                }
            };
            net_state.tcp_policy = policy_from(&resolved_net_allow.tcp);
            net_state.udp_policy = policy_from(&resolved_net_allow.udp);
            net_state.icmp_policy = policy_from(&resolved_net_allow.icmp);
            net_state.http_acl_addr = self.rt().http_acl_handle.as_ref().map(|h| h.addr);
            net_state.http_acl_ports = self.http_ports.iter().copied().collect();
            net_state.http_acl_orig_dest = self.rt().http_acl_handle.as_ref().map(|h| h.orig_dest.clone());
            if let Some(cb) = self.rt_mut().on_bind.take() {
                net_state.port_map.on_bind = Some(cb);
            }

            let procfs_state = ProcfsState::new();

            let mut res_state = ResourceState::new(
                notif_policy.max_memory_bytes,
                notif_policy.max_processes,
            );
            res_state.proc_count = 1;

            let mut cow_state = CowState::new();
            if self.workdir.is_some() && self.fs_isolation == FsIsolation::None {
                let workdir = self.workdir.as_ref().unwrap();
                let storage = self.fs_storage.as_deref();
                let max_disk = self.max_disk.map(|b| b.0).unwrap_or(0);
                match crate::cow::seccomp::SeccompCowBranch::create(workdir, storage, max_disk) {
                    Ok(branch) => { cow_state.branch = Some(branch); }
                    Err(e) => { eprintln!("sandlock: seccomp COW branch creation failed: {}", e); }
                }
            }

            let mut policy_fn_state = PolicyFnState::new();

            if let Ok(mut denied) = policy_fn_state.denied_paths.write() {
                for path in &self.fs_denied {
                    denied.insert(path.to_string_lossy().into_owned());
                }
            }

            if let Some(ref callback) = self.policy_fn {
                let mut allowed_ips: std::collections::HashSet<std::net::IpAddr> =
                    std::collections::HashSet::new();
                for p in [&net_state.tcp_policy, &net_state.udp_policy, &net_state.icmp_policy] {
                    if let crate::seccomp::notif::NetworkPolicy::AllowList { per_ip, .. } = p {
                        allowed_ips.extend(per_ip.keys().copied());
                    }
                }
                let live = crate::policy_fn::LivePolicy {
                    allowed_ips,
                    max_memory_bytes: notif_policy.max_memory_bytes,
                    max_processes: notif_policy.max_processes,
                };
                let ceiling = live.clone();
                let live = std::sync::Arc::new(std::sync::RwLock::new(live));
                let denied_paths = policy_fn_state.denied_paths.clone();
                let pid_overrides = net_state.pid_ip_overrides.clone();
                policy_fn_state.live_policy = Some(live.clone());
                let tx = crate::policy_fn::spawn_policy_fn(
                    callback.clone(), live, ceiling, pid_overrides, denied_paths,
                );
                policy_fn_state.event_tx = Some(tx);
            }

            let chroot_state = ChrootState::new();

            let notif_raw_fd = notif_fd.as_raw_fd();
            let child_pidfd_raw = pidfd.as_ref().map(|pfd| pfd.as_raw_fd());

            let res_state = Arc::new(tokio::sync::Mutex::new(res_state));
            self.rt_mut().supervisor_resource = Some(Arc::clone(&res_state));

            let cow_state = Arc::new(tokio::sync::Mutex::new(cow_state));
            self.rt_mut().supervisor_cow = Some(Arc::clone(&cow_state));

            let net_state = Arc::new(tokio::sync::Mutex::new(net_state));
            self.rt_mut().supervisor_network = Some(Arc::clone(&net_state));

            let procfs_state = Arc::new(tokio::sync::Mutex::new(procfs_state));
            let time_random_state = Arc::new(tokio::sync::Mutex::new(time_random_state));
            let policy_fn_state = Arc::new(tokio::sync::Mutex::new(policy_fn_state));
            let chroot_state = Arc::new(tokio::sync::Mutex::new(chroot_state));
            let processes = Arc::new(crate::seccomp::state::ProcessIndex::new());

            let ctx = Arc::new(SupervisorCtx {
                resource: Arc::clone(&res_state),
                cow: Arc::clone(&cow_state),
                procfs: Arc::clone(&procfs_state),
                network: Arc::clone(&net_state),
                time_random: Arc::clone(&time_random_state),
                policy_fn: Arc::clone(&policy_fn_state),
                chroot: Arc::clone(&chroot_state),
                netlink: Arc::new(crate::netlink::NetlinkState::new()),
                processes: Arc::clone(&processes),
                policy: Arc::new(notif_policy),
                child_pidfd: child_pidfd_raw,
                notif_fd: notif_raw_fd,
            });

            let extra_handlers = std::mem::take(&mut self.rt_mut().extra_handlers);
            self.rt_mut().notif_handle = Some(tokio::spawn(
                notif::supervisor(notif_fd, ctx, extra_handlers),
            ));

            let la_resource = Arc::clone(&res_state);
            self.rt_mut().loadavg_handle = Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let mut rs = la_resource.lock().await;
                    let running = rs.proc_count;
                    rs.load_avg.sample(running);
                }
            }));
        }

        if let Some(cpu_pct) = self.max_cpu {
            if cpu_pct < 100 {
                let child_pid = pid;
                self.rt_mut().throttle_handle = Some(tokio::spawn(sandbox_throttle_cpu(child_pid, cpu_pct)));
            }
        }

        self.rt_mut().pidfd = pidfd;
        self.rt_mut().ready_w = Some(pipes.ready_w);

        Ok(())
    }

    // ================================================================
    // Internal: do_start (release the parked child to execve)
    // ================================================================

    fn do_start(&mut self) -> Result<(), crate::error::SandlockError> {
        use std::os::fd::AsRawFd;
        use crate::context::write_u32_fd;
        use crate::error::SandboxRuntimeError;

        if !matches!(self.rt().state, RuntimeState::Created) {
            return Err(SandboxRuntimeError::Child("start() requires a created sandbox".into()).into());
        }
        let ready_w = self.rt_mut().ready_w.take()
            .ok_or_else(|| SandboxRuntimeError::Child("start() called without a prior create()".into()))?;
        write_u32_fd(ready_w.as_raw_fd(), 1)
            .map_err(|e| SandboxRuntimeError::Child(format!("write ready signal: {}", e)))?;
        drop(ready_w);
        self.rt_mut().state = RuntimeState::Running;
        Ok(())
    }
}

// ================================================================
// Drop for Sandbox — kills and reaps child if still running
// ================================================================

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Some(ref mut rt) = self.runtime {
            if let Some(pid) = rt.child_pid {
                if matches!(rt.state, RuntimeState::Created | RuntimeState::Running | RuntimeState::Paused) {
                    unsafe { libc::killpg(pid, libc::SIGKILL) };
                    let mut status: i32 = 0;
                    unsafe { libc::waitpid(pid, &mut status, 0) };
                }
            }

            if let Some(h) = rt.notif_handle.take() { h.abort(); }
            if let Some(h) = rt.throttle_handle.take() { h.abort(); }
            if let Some(h) = rt.loadavg_handle.take() { h.abort(); }

            let is_error = matches!(
                rt.state,
                RuntimeState::Stopped(ref s) if !matches!(s, crate::result::ExitStatus::Code(0))
            );
            let action = if is_error { &self.on_error } else { &self.on_exit };
            let action = action.clone();

            if let Some(ref branch) = rt.cow_branch {
                match action {
                    BranchAction::Commit => { let _ = branch.commit(); }
                    BranchAction::Abort => { let _ = branch.abort(); }
                    BranchAction::Keep => {}
                }
            }

            if let Some(ref mut cow) = rt.seccomp_cow {
                match action {
                    BranchAction::Commit => { let _ = cow.commit(); }
                    BranchAction::Abort => { let _ = cow.abort(); }
                    BranchAction::Keep => {}
                }
            }
        }
    }
}

// ================================================================
// CPU throttle
// ================================================================

async fn sandbox_throttle_cpu(pid: i32, cpu_pct: u8) {
    use std::time::Duration;
    let period = Duration::from_millis(100);
    let run_time = period * cpu_pct as u32 / 100;
    let stop_time = period - run_time;
    loop {
        tokio::time::sleep(run_time).await;
        if unsafe { libc::killpg(pid, libc::SIGSTOP) } < 0 { break; }
        tokio::time::sleep(stop_time).await;
        if unsafe { libc::killpg(pid, libc::SIGCONT) } < 0 { break; }
    }
}

// ================================================================
// Process name resolution
// ================================================================

static NEXT_SANDBOX_NAME: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn sandbox_resolve_name(name: Option<&str>) -> Result<String, crate::error::SandlockError> {
    match name {
        Some(n) => sandbox_validate_name(n.to_string()),
        None => Ok(format!(
            "sandbox-{}-{}",
            std::process::id(),
            NEXT_SANDBOX_NAME.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )),
    }
}

fn sandbox_validate_name(name: String) -> Result<String, crate::error::SandlockError> {
    use crate::error::SandboxRuntimeError;
    if name.is_empty() {
        return Err(SandboxRuntimeError::Child("sandbox name must not be empty".into()).into());
    }
    if name.len() > 64 {
        return Err(SandboxRuntimeError::Child("sandbox name must be at most 64 bytes".into()).into());
    }
    if name.as_bytes().contains(&0) {
        return Err(SandboxRuntimeError::Child("sandbox name must not contain NUL bytes".into()).into());
    }
    Ok(name)
}

// ================================================================
// I/O helpers (private)
// ================================================================

fn sandbox_read_exact(fd: i32, buf: &mut [u8]) {
    let mut off = 0;
    while off < buf.len() {
        let r = unsafe { libc::read(fd, buf[off..].as_mut_ptr() as *mut _, buf.len() - off) };
        if r <= 0 { break; }
        off += r as usize;
    }
}

fn sandbox_read_fd_to_end(fd: std::os::fd::OwnedFd) -> Vec<u8> {
    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::io::FromRawFd;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) };
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf);
    buf
}

fn sandbox_wait_status_to_exit(status: i32) -> crate::result::ExitStatus {
    use crate::result::ExitStatus;
    if libc::WIFEXITED(status) {
        ExitStatus::Code(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        if sig == libc::SIGKILL {
            ExitStatus::Killed
        } else {
            ExitStatus::Signal(sig)
        }
    } else {
        ExitStatus::Killed
    }
}

fn sandbox_collect_extra_handlers<I, S, H>(
    extra_handlers: I,
    sandbox: &Sandbox,
) -> Result<Vec<(i64, Arc<dyn crate::seccomp::dispatch::Handler>)>, crate::error::SandlockError>
where
    I: IntoIterator<Item = (S, H)>,
    S: TryInto<crate::seccomp::syscall::Syscall, Error = crate::seccomp::syscall::SyscallError>,
    H: crate::seccomp::dispatch::Handler,
{
    use crate::seccomp::dispatch::{Handler, HandlerError};

    let pending: Vec<(i64, Arc<dyn Handler>)> = extra_handlers
        .into_iter()
        .map(|(syscall, handler)| {
            let nr = syscall.try_into().map_err(HandlerError::from)?.raw();
            let h: Arc<dyn Handler> = Arc::new(handler);
            Ok::<_, HandlerError>((nr, h))
        })
        .collect::<Result<_, _>>()?;

    let nrs: Vec<i64> = pending.iter().map(|(nr, _)| *nr).collect();
    crate::seccomp::dispatch::validate_handler_syscalls_against_policy(&nrs, sandbox)
        .map_err(|syscall_nr| HandlerError::OnDenySyscall { syscall_nr })?;

    Ok(pending)
}

fn validate_syscall_names(names: &[String]) -> Result<(), SandboxError> {
    let unknown: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| crate::context::syscall_name_to_nr(name).is_none())
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(SandboxError::Invalid(format!(
            "unknown syscall name(s): {}",
            unknown.join(", ")
        )))
    }
}

/// Fluent builder for `Sandbox`.
///
/// When the `cli` feature is enabled this struct also derives `clap::Args` so
/// that the CLI can expose all per-field flags via `#[clap(flatten)]` without
/// duplicating the flag declarations.
#[derive(Default)]
#[cfg_attr(feature = "cli", derive(clap::Args))]
pub struct SandboxBuilder {
    #[cfg_attr(feature = "cli", arg(short = 'r', long = "fs-read", value_name = "PATH"))]
    pub fs_readable: Vec<PathBuf>,

    #[cfg_attr(feature = "cli", arg(short = 'w', long = "fs-write", value_name = "PATH"))]
    pub fs_writable: Vec<PathBuf>,

    #[cfg_attr(feature = "cli", arg(long = "fs-deny", value_name = "PATH"))]
    pub fs_denied: Vec<PathBuf>,

    /// Extra syscall names to deny (in addition to Sandlock's default blocklist)
    #[cfg_attr(feature = "cli", arg(long = "extra-deny-syscall", value_name = "NAME"))]
    pub extra_deny_syscalls: Vec<String>,

    /// Extra syscall group names to allow (e.g. sysv_ipc)
    #[cfg_attr(feature = "cli", arg(long = "extra-allow-syscall", value_name = "NAME"))]
    pub extra_allow_syscalls: Vec<String>,

    /// Outbound endpoint allow rule. Repeatable. Each value is
    /// `host:port[,port,...]` (IP-restricted), `:port` or `*:port`
    /// (any IP), or `udp://...` / `icmp://...` for UDP/ICMP.
    /// Examples: `api.openai.com:443`, `github.com:22,443`, `:8080`.
    #[cfg_attr(feature = "cli", arg(long = "net-allow", value_name = "SPEC"))]
    pub net_allow: Vec<String>,

    #[cfg_attr(feature = "cli", arg(long = "net-bind"))]
    pub net_bind: Vec<u16>,

    #[cfg_attr(feature = "cli", arg(long = "http-allow", value_name = "RULE"))]
    pub http_allow: Vec<String>,

    #[cfg_attr(feature = "cli", arg(long = "http-deny", value_name = "RULE"))]
    pub http_deny: Vec<String>,

    /// TCP ports to intercept for HTTP ACL (default: 80, plus 443 with --http-ca)
    #[cfg_attr(feature = "cli", arg(long = "http-port", value_name = "PORT"))]
    pub http_ports: Vec<u16>,

    /// PEM CA certificate for HTTPS MITM (enables port 443 interception)
    #[cfg_attr(feature = "cli", arg(long = "http-ca", value_name = "PATH"))]
    pub http_ca: Option<PathBuf>,

    /// PEM CA private key for HTTPS MITM (required with --http-ca)
    #[cfg_attr(feature = "cli", arg(long = "http-key", value_name = "PATH"))]
    pub http_key: Option<PathBuf>,

    // max_memory uses a string in the CLI (e.g. "512M"); not directly clap-friendly as ByteSize.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub max_memory: Option<ByteSize>,

    #[cfg_attr(feature = "cli", arg(short = 'P', long = "max-processes"))]
    pub max_processes: Option<u32>,

    #[cfg_attr(feature = "cli", arg(long = "max-open-files"))]
    pub max_open_files: Option<u32>,

    #[cfg_attr(feature = "cli", arg(short = 'c', long = "cpu"))]
    pub max_cpu: Option<u8>,

    #[cfg_attr(feature = "cli", arg(long = "random-seed"))]
    pub random_seed: Option<u64>,

    // time_start requires ISO 8601 string parsing; not directly clap-friendly as SystemTime.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub time_start: Option<SystemTime>,

    #[cfg_attr(feature = "cli", arg(long = "no-randomize-memory"))]
    pub no_randomize_memory: bool,

    #[cfg_attr(feature = "cli", arg(long = "no-huge-pages"))]
    pub no_huge_pages: bool,

    #[cfg_attr(feature = "cli", arg(long = "no-coredump"))]
    pub no_coredump: bool,

    #[cfg_attr(feature = "cli", arg(long = "deterministic-dirs"))]
    pub deterministic_dirs: bool,

    // fs_isolation requires string-to-enum parsing; not directly clap-friendly as FsIsolation.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub fs_isolation: Option<FsIsolation>,

    #[cfg_attr(feature = "cli", arg(long = "workdir"))]
    pub workdir: Option<PathBuf>,

    #[cfg_attr(feature = "cli", arg(long = "cwd"))]
    pub cwd: Option<PathBuf>,

    #[cfg_attr(feature = "cli", arg(long = "fs-storage", value_name = "PATH"))]
    pub fs_storage: Option<PathBuf>,

    // max_disk uses a string in the CLI (e.g. "10G"); not directly clap-friendly as ByteSize.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub max_disk: Option<ByteSize>,

    // on_exit/on_error are not exposed as CLI flags.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub on_exit: Option<BranchAction>,

    #[cfg_attr(feature = "cli", clap(skip))]
    pub on_error: Option<BranchAction>,

    // fs_mount requires VIRTUAL:HOST string splitting; not directly clap-friendly as Vec<(PathBuf,PathBuf)>.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub fs_mount: Vec<(PathBuf, PathBuf)>,

    #[cfg_attr(feature = "cli", arg(long = "chroot"))]
    pub chroot: Option<PathBuf>,

    #[cfg_attr(feature = "cli", arg(long = "clean-env"))]
    pub clean_env: bool,

    // env requires KEY=VALUE string splitting; not directly clap-friendly as HashMap.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub env: HashMap<String, String>,

    // gpu_devices in CLI uses Vec<u32> with value_delimiter; SandboxBuilder stores Option<Vec<u32>>.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub gpu_devices: Option<Vec<u32>>,

    // cpu_cores in CLI uses Vec<u32> with value_delimiter; SandboxBuilder stores Option<Vec<u32>>.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub cpu_cores: Option<Vec<u32>>,

    #[cfg_attr(feature = "cli", arg(long = "num-cpus"))]
    pub num_cpus: Option<u32>,

    #[cfg_attr(feature = "cli", arg(long = "port-remap"))]
    pub port_remap: bool,

    #[cfg_attr(feature = "cli", arg(long = "uid"))]
    pub uid: Option<u32>,

    // Internal callback — never a CLI flag.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub policy_fn: Option<crate::policy_fn::PolicyCallback>,

    // Sandbox instance name — stored for transfer into the Sandbox at build time.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub name: Option<String>,

    // COW fork init function — runs once in the child before COW cloning.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub(crate) init_fn: Option<Box<dyn FnOnce() + Send + 'static>>,

    // COW fork work function — runs in each COW clone.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub(crate) work_fn: Option<Arc<dyn Fn(u32) + Send + Sync + 'static>>,
}

impl std::fmt::Debug for SandboxBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxBuilder")
            .field("fs_readable", &self.fs_readable)
            .field("fs_writable", &self.fs_writable)
            .field("max_memory", &self.max_memory)
            .field("max_processes", &self.max_processes)
            .field("policy_fn", &self.policy_fn.as_ref().map(|_| "<callback>"))
            .finish_non_exhaustive()
    }
}

impl Clone for SandboxBuilder {
    /// Clone a `SandboxBuilder`. All config and callback fields are cloned.
    /// `init_fn` (FnOnce) is dropped to `None` on the clone; `work_fn` clones
    /// via Arc. If the clone also needs an init function, set it again with
    /// `.init_fn(...)`.
    fn clone(&self) -> Self {
        Self {
            fs_readable: self.fs_readable.clone(),
            fs_writable: self.fs_writable.clone(),
            fs_denied: self.fs_denied.clone(),
            extra_deny_syscalls: self.extra_deny_syscalls.clone(),
            extra_allow_syscalls: self.extra_allow_syscalls.clone(),
            net_allow: self.net_allow.clone(),
            net_bind: self.net_bind.clone(),
            http_allow: self.http_allow.clone(),
            http_deny: self.http_deny.clone(),
            http_ports: self.http_ports.clone(),
            http_ca: self.http_ca.clone(),
            http_key: self.http_key.clone(),
            max_memory: self.max_memory,
            max_processes: self.max_processes,
            max_open_files: self.max_open_files,
            max_cpu: self.max_cpu,
            random_seed: self.random_seed,
            time_start: self.time_start,
            no_randomize_memory: self.no_randomize_memory,
            no_huge_pages: self.no_huge_pages,
            no_coredump: self.no_coredump,
            deterministic_dirs: self.deterministic_dirs,
            fs_isolation: self.fs_isolation.clone(),
            workdir: self.workdir.clone(),
            cwd: self.cwd.clone(),
            fs_storage: self.fs_storage.clone(),
            max_disk: self.max_disk,
            on_exit: self.on_exit.clone(),
            on_error: self.on_error.clone(),
            fs_mount: self.fs_mount.clone(),
            chroot: self.chroot.clone(),
            clean_env: self.clean_env,
            env: self.env.clone(),
            gpu_devices: self.gpu_devices.clone(),
            cpu_cores: self.cpu_cores.clone(),
            num_cpus: self.num_cpus,
            port_remap: self.port_remap,
            uid: self.uid,
            policy_fn: self.policy_fn.clone(),
            name: self.name.clone(),
            // init_fn (FnOnce) cannot be cloned — drop to None.
            init_fn: None,
            // work_fn is Arc-wrapped — clone bumps the reference count.
            work_fn: self.work_fn.clone(),
        }
    }
}

impl SandboxBuilder {
    pub fn fs_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_writable.push(path.into());
        self
    }

    pub fn fs_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_readable.push(path.into());
        self
    }

    pub fn fs_read_if_exists(self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if path.exists() {
            self.fs_read(path)
        } else {
            self
        }
    }

    pub fn fs_deny(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs_denied.push(path.into());
        self
    }

    pub fn extra_deny_syscalls(mut self, calls: Vec<String>) -> Self {
        self.extra_deny_syscalls.extend(calls);
        self
    }

    pub fn extra_allow_syscalls(mut self, names: Vec<String>) -> Self {
        self.extra_allow_syscalls.extend(names);
        self
    }

    /// Add a network endpoint rule. Spec is `host:port[,port,...]`,
    /// `:port`, or `*:port`. Validated at `build()` time so callers
    /// receive parse errors via the standard `SandboxBuilder` flow.
    ///
    /// Examples:
    /// - `.net_allow("api.openai.com:443")` — HTTPS to OpenAI only
    /// - `.net_allow("github.com:22,443")` — SSH and HTTPS to GitHub
    /// - `.net_allow(":8080")` — any IP on port 8080
    pub fn net_allow(mut self, spec: impl Into<String>) -> Self {
        self.net_allow.push(spec.into());
        self
    }

    pub fn net_bind_port(mut self, port: u16) -> Self {
        self.net_bind.push(port);
        self
    }

    pub fn http_allow(mut self, rule: &str) -> Self {
        self.http_allow.push(rule.to_string());
        self
    }

    pub fn http_deny(mut self, rule: &str) -> Self {
        self.http_deny.push(rule.to_string());
        self
    }

    pub fn http_port(mut self, port: u16) -> Self {
        self.http_ports.push(port);
        self
    }

    pub fn http_ca(mut self, path: impl Into<PathBuf>) -> Self {
        self.http_ca = Some(path.into());
        self
    }

    pub fn http_key(mut self, path: impl Into<PathBuf>) -> Self {
        self.http_key = Some(path.into());
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

    pub fn fs_mount(mut self, virtual_path: impl Into<PathBuf>, host_path: impl Into<PathBuf>) -> Self {
        self.fs_mount.push((virtual_path.into(), host_path.into()));
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

    /// Set the sandbox instance name (exposed as the virtual hostname).
    /// Auto-generated if not set.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the COW-fork init function.
    ///
    /// The init function runs once in the child process before any COW clones
    /// are created. Required for `Sandbox::fork()`.
    pub fn init_fn(mut self, f: impl FnOnce() + Send + 'static) -> Self {
        self.init_fn = Some(Box::new(f));
        self
    }

    /// Set the COW-fork work function.
    ///
    /// The work function runs in each COW clone (`fork(N)` produces N clones).
    /// Required for `Sandbox::fork()`.
    pub fn work_fn(mut self, f: impl Fn(u32) + Send + Sync + 'static) -> Self {
        self.work_fn = Some(Arc::new(f));
        self
    }

    /// Build a `Sandbox`, parsing all string fields and running per-field
    /// validation, but **without** the cross-section checks that
    /// `Sandbox::validate` performs. Use this in tests that deliberately
    /// construct sandboxes violating cross-section invariants.
    pub fn build_unchecked(self) -> Result<Sandbox, SandboxError> {
        validate_syscall_names(&self.extra_deny_syscalls)?;

        // Validate: max_cpu must be 1-100
        if let Some(cpu) = self.max_cpu {
            if cpu == 0 || cpu > 100 {
                return Err(SandboxError::InvalidCpuPercent(cpu));
            }
        }

        // Validate: http_ca and http_key must both be set or both unset
        if self.http_ca.is_some() != self.http_key.is_some() {
            return Err(SandboxError::Invalid(
                "--http-ca and --http-key must both be provided together".into(),
            ));
        }

        // Parse HTTP rules (deferred from builder methods to propagate errors)
        let http_allow: Vec<HttpRule> = self
            .http_allow
            .into_iter()
            .map(|s| HttpRule::parse(&s))
            .collect::<Result<_, _>>()?;
        let http_deny: Vec<HttpRule> = self
            .http_deny
            .into_iter()
            .map(|s| HttpRule::parse(&s))
            .collect::<Result<_, _>>()?;

        // Default HTTP intercept ports: 80 always, 443 when HTTPS CA is configured.
        let http_ports = if self.http_ports.is_empty() && (!http_allow.is_empty() || !http_deny.is_empty()) {
            let mut ports = vec![80];
            if self.http_ca.is_some() {
                ports.push(443);
            }
            ports
        } else {
            self.http_ports
        };

        // Parse user-supplied --net-allow specs.
        let mut net_allow: Vec<NetAllow> = self
            .net_allow
            .into_iter()
            .map(|s| NetAllow::parse(&s))
            .collect::<Result<_, _>>()?;

        // Auto-merge HTTP rules into the network allowlist so the proxy's
        // intercept ports remain reachable. A rule with a concrete host
        // tightens the IP allowlist (only that host on http_ports);
        // wildcard hosts add a `:port` (any IP) rule. This mirrors the
        // intent of the old `http_port → net_connect` merge but at the
        // endpoint level so HTTP and net_allow stay aligned.
        if !http_ports.is_empty() {
            let mut wildcard_seen = false;
            let mut concrete_hosts: Vec<String> = Vec::new();
            for rule in http_allow.iter().chain(http_deny.iter()) {
                if rule.host == "*" {
                    wildcard_seen = true;
                } else if !concrete_hosts.iter().any(|h| h.eq_ignore_ascii_case(&rule.host)) {
                    concrete_hosts.push(rule.host.clone());
                }
            }
            if wildcard_seen || (http_allow.is_empty() && http_deny.is_empty()) {
                // Fallback: explicit --http-port without rules, or wildcard rules.
                net_allow.push(NetAllow {
                    protocol: Protocol::Tcp,
                    host: None,
                    ports: http_ports.clone(),
                    all_ports: false,
                });
            }
            for h in concrete_hosts {
                net_allow.push(NetAllow {
                    protocol: Protocol::Tcp,
                    host: Some(h),
                    ports: http_ports.clone(),
                    all_ports: false,
                });
            }
        }

        let fs_isolation = self.fs_isolation.unwrap_or_default();
        Ok(Sandbox {
            fs_writable: self.fs_writable,
            fs_readable: self.fs_readable,
            fs_denied: self.fs_denied,
            extra_deny_syscalls: self.extra_deny_syscalls,
            extra_allow_syscalls: self.extra_allow_syscalls,
            net_allow,
            net_bind: self.net_bind,
            http_allow,
            http_deny,
            http_ports,
            http_ca: self.http_ca,
            http_key: self.http_key,
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
            fs_isolation,
            workdir: self.workdir,
            cwd: self.cwd,
            fs_storage: self.fs_storage,
            max_disk: self.max_disk,
            on_exit: self.on_exit.unwrap_or_default(),
            on_error: self.on_error.unwrap_or_default(),
            fs_mount: self.fs_mount,
            chroot: self.chroot,
            clean_env: self.clean_env,
            env: self.env,
            gpu_devices: self.gpu_devices,
            cpu_cores: self.cpu_cores,
            num_cpus: self.num_cpus,
            port_remap: self.port_remap,
            uid: self.uid,
            policy_fn: self.policy_fn,
            name: self.name,
            init_fn: self.init_fn,
            work_fn: self.work_fn,
            runtime: None,
        })
    }

    /// Build a `Sandbox`, parsing all string fields, running per-field validation,
    /// and verifying cross-section invariants via `Sandbox::validate`.
    pub fn build(self) -> Result<Sandbox, SandboxError> {
        let p = self.build_unchecked()?;
        p.validate()?;
        Ok(p)
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

    // --- SandboxBuilder integration ---

    #[test]
    fn builder_http_rules() {
        let policy = Sandbox::builder()
            .http_allow("GET api.example.com/v1/*")
            .http_deny("* */admin/*")
            .build()
            .unwrap();
        assert_eq!(policy.http_allow.len(), 1);
        assert_eq!(policy.http_deny.len(), 1);
        assert_eq!(policy.http_allow[0].method, "GET");
        assert_eq!(policy.http_deny[0].host, "*");
    }

    #[test]
    fn builder_invalid_http_allow_returns_error() {
        let result = Sandbox::builder()
            .http_allow("GETexample.com")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_invalid_http_deny_returns_error() {
        let result = Sandbox::builder()
            .http_deny("BADRULE")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_http_ca_without_key_returns_error() {
        let result = Sandbox::builder()
            .http_ca("/tmp/ca.pem")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_http_key_without_ca_returns_error() {
        let result = Sandbox::builder()
            .http_key("/tmp/key.pem")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_http_ca_and_key_together_ok() {
        let policy = Sandbox::builder()
            .http_ca("/tmp/ca.pem")
            .http_key("/tmp/key.pem")
            .build()
            .unwrap();
        assert!(policy.http_ca.is_some());
        assert!(policy.http_key.is_some());
    }

    #[test]
    fn allows_sysv_ipc_reads_extra_allow_syscalls() {
        let p = Sandbox::builder()
            .extra_allow_syscalls(vec!["sysv_ipc".into()])
            .build()
            .unwrap();
        assert!(p.allows_sysv_ipc());

        let p2 = Sandbox::builder().build().unwrap();
        assert!(!p2.allows_sysv_ipc());

        let p3 = Sandbox::builder()
            .extra_allow_syscalls(vec!["other_group".into()])
            .build()
            .unwrap();
        assert!(!p3.allows_sysv_ipc());
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

    // --- NetAllow::parse tests ---

    #[test]
    fn netallow_parse_concrete_host_port() {
        let r = NetAllow::parse("example.com:443").unwrap();
        assert_eq!(r.host.as_deref(), Some("example.com"));
        assert_eq!(r.ports, vec![443]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_parse_any_host_port() {
        let r = NetAllow::parse(":8080").unwrap();
        assert_eq!(r.host, None);
        assert_eq!(r.ports, vec![8080]);
        assert!(!r.all_ports);

        let r = NetAllow::parse("*:8080").unwrap();
        assert_eq!(r.host, None);
        assert_eq!(r.ports, vec![8080]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_parse_multiple_ports() {
        let r = NetAllow::parse("github.com:22,80,443").unwrap();
        assert_eq!(r.host.as_deref(), Some("github.com"));
        assert_eq!(r.ports, vec![22, 80, 443]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_parse_wildcard_any_host_any_port_colon() {
        let r = NetAllow::parse(":*").unwrap();
        assert_eq!(r.host, None);
        assert!(r.ports.is_empty());
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_parse_wildcard_any_host_any_port_star() {
        let r = NetAllow::parse("*:*").unwrap();
        assert_eq!(r.host, None);
        assert!(r.ports.is_empty());
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_parse_wildcard_concrete_host_any_port() {
        let r = NetAllow::parse("example.com:*").unwrap();
        assert_eq!(r.host.as_deref(), Some("example.com"));
        assert!(r.ports.is_empty());
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_parse_rejects_mixed_wildcard_and_concrete() {
        // `host:80,*` and `host:*,80` are both ambiguous: the user
        // either meant "any port" (wildcard wins) or "ports 80 plus
        // some weird placeholder". Refuse and force a clean spec.
        let err = NetAllow::parse("example.com:80,*").unwrap_err();
        assert!(format!("{}", err).contains("cannot mix"));
        let err = NetAllow::parse("example.com:*,80").unwrap_err();
        assert!(format!("{}", err).contains("cannot mix"));
    }

    #[test]
    fn netallow_parse_rejects_port_zero() {
        let err = NetAllow::parse("example.com:0").unwrap_err();
        assert!(format!("{}", err).contains("port 0"));
    }

    #[test]
    fn netallow_parse_rejects_empty_port() {
        let err = NetAllow::parse("example.com:").unwrap_err();
        assert!(format!("{}", err).contains("invalid port"));
    }

    #[test]
    fn netallow_parse_rejects_no_colon() {
        let err = NetAllow::parse("example.com").unwrap_err();
        assert!(format!("{}", err).contains("expected"));
    }

    #[test]
    fn netallow_parse_repeated_wildcard_is_idempotent() {
        // `*,*` collapses to a single wildcard — neither token contributes
        // a concrete port, so the rule remains "any port".
        let r = NetAllow::parse(":*,*").unwrap();
        assert!(r.all_ports);
        assert!(r.ports.is_empty());
    }

    // --- Protocol scheme prefix tests ---

    #[test]
    fn netallow_bare_form_defaults_to_tcp() {
        let r = NetAllow::parse("example.com:443").unwrap();
        assert_eq!(r.protocol, Protocol::Tcp);
    }

    #[test]
    fn netallow_explicit_tcp_scheme() {
        let r = NetAllow::parse("tcp://example.com:443").unwrap();
        assert_eq!(r.protocol, Protocol::Tcp);
        assert_eq!(r.host.as_deref(), Some("example.com"));
        assert_eq!(r.ports, vec![443]);
    }

    #[test]
    fn netallow_udp_scheme_with_host_port() {
        let r = NetAllow::parse("udp://1.1.1.1:53").unwrap();
        assert_eq!(r.protocol, Protocol::Udp);
        assert_eq!(r.host.as_deref(), Some("1.1.1.1"));
        assert_eq!(r.ports, vec![53]);
    }

    #[test]
    fn netallow_udp_wildcard_any_anywhere() {
        // The "any UDP" gate, equivalent to the old `allow_udp = true`.
        let r = NetAllow::parse("udp://*:*").unwrap();
        assert_eq!(r.protocol, Protocol::Udp);
        assert_eq!(r.host, None);
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_icmp_scheme_with_host() {
        let r = NetAllow::parse("icmp://github.com").unwrap();
        assert_eq!(r.protocol, Protocol::Icmp);
        assert_eq!(r.host.as_deref(), Some("github.com"));
        assert!(r.ports.is_empty());
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_icmp_wildcard() {
        // The "any ICMP echo" gate, equivalent to the old
        // `allow_icmp = true` for the SOCK_DGRAM path.
        let r = NetAllow::parse("icmp://*").unwrap();
        assert_eq!(r.protocol, Protocol::Icmp);
        assert_eq!(r.host, None);
    }

    #[test]
    fn netallow_icmp_rejects_port() {
        // ICMP has no port — `:port` is meaningless and refused
        // explicitly so users can't write a rule that doesn't do what
        // they think.
        let err = NetAllow::parse("icmp://github.com:80").unwrap_err();
        assert!(format!("{}", err).contains("icmp rules take no port"));
    }

    #[test]
    fn netallow_icmp_rejects_empty_body() {
        let err = NetAllow::parse("icmp://").unwrap_err();
        assert!(format!("{}", err).contains("needs a host or `*`"));
    }

    #[test]
    fn netallow_unknown_scheme_rejected() {
        // Including `icmp-raw` — sandlock does not expose raw ICMP, so
        // the scheme is unknown rather than a special-case error.
        for spec in ["sctp://host:1234", "icmp-raw://*"] {
            let err = NetAllow::parse(spec).unwrap_err();
            assert!(format!("{}", err).contains("unknown scheme"), "spec: {}", spec);
        }
    }
}
