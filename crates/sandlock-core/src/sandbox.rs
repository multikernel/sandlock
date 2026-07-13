use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::context;
use crate::error::SandboxError;
pub use crate::http::{http_acl_check, normalize_path, prefix_or_exact_match, HttpRule};
pub use crate::network::{IpCidr, NetAllow, NetDeny, NetRule, NetTarget, Protocol};
use crate::protection::{Protection, ProtectionPolicy, ProtectionState, ProtectionStatus};

mod builder;
pub use builder::SandboxBuilder;

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

/// Identity to run the sandboxed process as.
///
/// Applied via a single-entry user-namespace map (`unshare(CLONE_NEWUSER)` +
/// `uid_map`/`gid_map`), so it requires no host privilege.  Because an
/// unprivileged user namespace can only map a single id and must deny
/// `setgroups`, exactly one uid and one gid are representable (no supplementary
/// groups, no id ranges).
///
/// Parsed from `UID:GID`; both ids are required (no implicit default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
}

impl std::str::FromStr for RunAs {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (u, g) = s
            .split_once(':')
            .ok_or_else(|| format!("expected UID:GID, got {:?}", s))?;
        let uid = u.trim().parse::<u32>().map_err(|_| format!("invalid uid {:?}", u))?;
        let gid = g.trim().parse::<u32>().map_err(|_| format!("invalid gid {:?}", g))?;
        Ok(RunAs { uid, gid })
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
        if !sandbox.net_deny.is_empty() { unsupported.push("net_deny"); }
        if !sandbox.net_allow_bind.is_default() { unsupported.push("net_allow_bind"); }
        if !sandbox.net_deny_bind.is_empty() { unsupported.push("net_deny_bind"); }
        if sandbox.allows_sysv_ipc() { unsupported.push("extra_allow_syscalls=[\"sysv_ipc\"]"); }
        if !sandbox.http_allow.is_empty() { unsupported.push("http_allow"); }
        if !sandbox.http_deny.is_empty() { unsupported.push("http_deny"); }
        if !sandbox.inject.is_empty() { unsupported.push("http_auth"); }
        if !sandbox.http_ports.is_empty() { unsupported.push("http_ports"); }
        if sandbox.http_ca.is_some() { unsupported.push("http_ca"); }
        if sandbox.http_key.is_some() { unsupported.push("http_key"); }
        if !sandbox.http_inject_ca.is_empty() { unsupported.push("http_inject_ca"); }
        if sandbox.http_ca_out.is_some() { unsupported.push("http_ca_out"); }
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
        if sandbox.user.is_some() { unsupported.push("user"); }
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

/// Action to take on branch exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BranchAction {
    #[default]
    Commit,
    Abort,
    Keep,
}

// ============================================================
// Runtime — private heap-allocated state, present only while running
// ============================================================

/// How one of a child's standard streams (stdin/stdout/stderr) is wired.
///
/// `Inherit` shares the supervisor's own fd (the child writes to the same
/// terminal/file the parent has). `Piped` creates a pipe whose caller-side end
/// is handed out via [`Process`] so the caller can stream to/from the live
/// process. `Null` connects the stream to `/dev/null`.
///
/// The discriminants are a stable contract: the FFI/Python bindings pass them
/// as a `u32`, so they are pinned with `#[repr(u32)]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StdioMode {
    /// Inherit the supervisor's corresponding fd.
    Inherit = 0,
    /// Connect to a pipe; the caller owns the other end (see [`Process`]).
    Piped = 1,
    /// Connect to `/dev/null`.
    Null = 2,
}

/// Per-stream stdio wiring for a child process.
#[derive(Debug, Clone, Copy)]
struct StdioSpec {
    stdin: StdioMode,
    stdout: StdioMode,
    stderr: StdioMode,
}

impl StdioSpec {
    /// Capture mode used by `run`/`spawn`: stdin inherited, stdout/stderr piped
    /// and drained into the `RunResult` by `wait`.
    fn capture() -> Self {
        StdioSpec { stdin: StdioMode::Inherit, stdout: StdioMode::Piped, stderr: StdioMode::Piped }
    }

    /// Interactive mode: every stream inherits the supervisor's fd.
    fn inherit() -> Self {
        StdioSpec { stdin: StdioMode::Inherit, stdout: StdioMode::Inherit, stderr: StdioMode::Inherit }
    }
}

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
    // Parent-held write end of a piped stdin (popen). The caller takes it via
    // `Process::take_stdin`; closing it signals EOF to the child.
    _stdin_write: Option<std::os::fd::OwnedFd>,
    seccomp_cow: Option<crate::cow::seccomp::SeccompCowBranch>,
    supervisor_resource: Option<Arc<tokio::sync::Mutex<crate::seccomp::state::ResourceState>>>,
    supervisor_cow: Option<Arc<tokio::sync::Mutex<crate::seccomp::state::CowState>>>,
    supervisor_network: Option<Arc<tokio::sync::Mutex<crate::seccomp::state::NetworkState>>>,
    ctrl_fd: Option<std::os::fd::OwnedFd>,
    stdout_pipe: Option<std::os::fd::OwnedFd>,
    io_overrides: Option<(Option<i32>, Option<i32>, Option<i32>)>,
    extra_fds: Vec<(i32, i32)>,
    http_acl_handle: Option<crate::transparent_proxy::HttpAclProxyHandle>,
    #[allow(clippy::type_complexity)]
    on_bind: Option<Box<dyn Fn(&HashMap<u16, u16>) + Send + Sync>>,
    handlers: Vec<(i64, Arc<dyn crate::seccomp::dispatch::Handler>)>,
    ready_w: Option<std::os::fd::OwnedFd>,
}

/// Lifecycle state for the runtime.
enum RuntimeState {
    Created,
    Running,
    Paused,
    Stopped(crate::result::ExitStatus),
}

/// TCP bind allowlist (`--net-allow-bind`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindPorts {
    /// Allow binding only the listed ports. Empty means no bind is
    /// permitted while the NetTcp protection is active (the default).
    Ports(Vec<u16>),
    /// `--net-allow-bind '*'`: any TCP port may be bound.
    All,
}

impl Default for BindPorts {
    fn default() -> Self {
        BindPorts::Ports(Vec::new())
    }
}

impl BindPorts {
    /// True when no allowlist was configured (the default deny-all state).
    pub fn is_default(&self) -> bool {
        matches!(self, BindPorts::Ports(p) if p.is_empty())
    }

    /// True for the `'*'` wildcard (any port may be bound).
    pub fn is_all(&self) -> bool {
        matches!(self, BindPorts::All)
    }
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

    /// Per-protection enforcement policy. Default
    /// (`ProtectionPolicy::strict_all()`) preserves the historical hard
    /// `MIN_ABI = 6` behaviour; `SandboxBuilder::allow_degraded` /
    /// `::disable` deviate from strict-all per protection.
    ///
    /// Part of the checkpoint: a saved sandbox restores with its exact
    /// protection posture. Without this, a sandbox built with a
    /// `disable()` opt-out (required on, e.g., a v5 host that cannot
    /// provide a v6 scope) would silently reset to `strict_all()` on
    /// load and fail to restore.
    pub protection_policy: ProtectionPolicy,

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
    /// Parsed `--net-deny` rules (default-allow, IP/CIDR/port denylist).
    /// Mutually exclusive with `net_allow`.
    pub net_deny: Vec<NetDeny>,
    /// `--net-allow-bind`: TCP ports the sandbox may bind (default-deny
    /// allowlist, Landlock-enforced; `All` leaves Landlock's `BIND_TCP`
    /// hook unhandled so any port may be bound). Mutually exclusive with
    /// `net_deny_bind`.
    pub net_allow_bind: BindPorts,
    /// `--net-deny-bind`: TCP ports the sandbox may NOT bind (default-allow
    /// denylist, enforced on the on-behalf `bind()` path). Mutually
    /// exclusive with `net_allow_bind`.
    pub net_deny_bind: Vec<u16>,
    // HTTP ACL
    pub http_allow: Vec<HttpRule>,
    pub http_deny: Vec<HttpRule>,
    /// Credential-injection rules, applied in the MITM proxy after the ACL
    /// check. `Arc` so the (non-Clone) secrets flow to the proxy by sharing.
    /// Not serialized: the resolved secrets live only in the supervisor and are
    /// re-loaded from their sources on each build, never persisted in a policy.
    #[serde(skip)]
    pub(crate) inject: std::sync::Arc<Vec<crate::credential::InjectRule>>,
    /// `env:` var names to remove from the child's environment (so an env-sourced
    /// credential can't be read straight out of the agent's own env). Just names,
    /// no secrets — safe to serialize, but tied to `inject` which isn't restored.
    #[serde(skip)]
    pub(crate) inject_env_strip: Vec<String>,
    /// TCP ports to intercept for HTTP ACL. Defaults to [80] (plus 443 when
    /// http_ca is set). Override with `http_ports` to intercept custom ports.
    pub http_ports: Vec<u16>,
    /// PEM CA cert for HTTPS MITM. When set, port 443 is also intercepted.
    pub http_ca: Option<PathBuf>,
    /// PEM CA key for HTTPS MITM. Required when http_ca is set.
    pub http_key: Option<PathBuf>,
    /// Trust-bundle paths to splice the MITM CA into (zero-config HTTPS).
    pub http_inject_ca: Vec<PathBuf>,
    /// Path to write the active MITM CA public cert (PEM) for external trust
    /// wiring (e.g. NODE_EXTRA_CA_CERTS). Never writes the private key.
    pub http_ca_out: Option<PathBuf>,

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
    pub workdir: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub fs_storage: Option<PathBuf>,
    pub max_disk: Option<ByteSize>,
    pub on_exit: BranchAction,
    pub on_error: BranchAction,

    // Mount mappings: (virtual_path_inside_chroot, host_path_on_disk)
    pub fs_mount: Vec<(PathBuf, PathBuf)>,
    // Virtual paths (a subset of fs_mount destinations) mounted read-only:
    // reads allowed, writes denied even on a writable rootfs.
    pub fs_mount_ro: Vec<PathBuf>,

    // Environment
    pub chroot: Option<PathBuf>,

    /// When set, the confined child runs this function in-process instead of
    /// `execve`-ing a workload. Used to run an in-sandbox PID-1 (the OCI
    /// `sandlock-init` control loop) without exec'ing a separate image: the
    /// child is already a fork of the supervisor, so its code is mapped, and
    /// because nothing is exec'd, Landlock has no execution to authorize. The
    /// function must not return (it loops and `_exit`s); `confine_child` calls
    /// `_exit(0)` if it does.
    #[serde(skip)]
    pub in_child_main: Option<fn()>,

    pub clean_env: bool,
    pub env: HashMap<String, String>,
    // Devices
    pub gpu_devices: Option<Vec<u32>>,

    // CPU
    pub cpu_cores: Option<Vec<u32>>,
    pub num_cpus: Option<u32>,
    pub port_remap: bool,

    /// Skip the seccomp user-notification supervisor. The sandbox runs
    /// with Landlock + a kernel-only deny filter, with none of the
    /// supervisor-mediated features (IP allowlist, resource limits,
    /// COW, chroot mediation, /proc virtualization, custom handlers).
    /// Required when nesting inside another sandlock — the kernel only
    /// allows one `SECCOMP_FILTER_FLAG_NEW_LISTENER` per task.
    pub no_supervisor: bool,

    // User-namespace identity (run-as uid/gid)
    pub user: Option<RunAs>,

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

    // Fds the last `restore_interactive` could not transparently recreate.
    // Runtime state: not serialized, not cloned.
    #[serde(skip)]
    restore_skipped: Vec<crate::checkpoint::SkippedFd>,
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
            protection_policy: self.protection_policy.clone(),
            net_allow: self.net_allow.clone(),
            net_deny: self.net_deny.clone(),
            net_allow_bind: self.net_allow_bind.clone(),
            net_deny_bind: self.net_deny_bind.clone(),
            http_allow: self.http_allow.clone(),
            http_deny: self.http_deny.clone(),
            inject: self.inject.clone(),
            inject_env_strip: self.inject_env_strip.clone(),
            http_ports: self.http_ports.clone(),
            http_ca: self.http_ca.clone(),
            http_key: self.http_key.clone(),
            http_inject_ca: self.http_inject_ca.clone(),
            http_ca_out: self.http_ca_out.clone(),
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
            workdir: self.workdir.clone(),
            cwd: self.cwd.clone(),
            fs_storage: self.fs_storage.clone(),
            max_disk: self.max_disk,
            on_exit: self.on_exit.clone(),
            on_error: self.on_error.clone(),
            fs_mount: self.fs_mount.clone(),
            fs_mount_ro: self.fs_mount_ro.clone(),
            chroot: self.chroot.clone(),
            in_child_main: self.in_child_main,
            clean_env: self.clean_env,
            env: self.env.clone(),
            gpu_devices: self.gpu_devices.clone(),
            cpu_cores: self.cpu_cores.clone(),
            num_cpus: self.num_cpus,
            port_remap: self.port_remap,
            no_supervisor: self.no_supervisor,
            user: self.user,
            policy_fn: self.policy_fn.clone(),
            name: self.name.clone(),
            // init_fn (FnOnce) cannot be cloned — the clone gets None.
            // If the clone also needs an init function, set it explicitly.
            init_fn: None,
            // work_fn is Arc-wrapped — clone bumps the reference count.
            work_fn: self.work_fn.clone(),
            // Runtime is NOT cloned — the clone starts with no runtime.
            runtime: None,
            // Restore diagnostics belong to the original's run, not the clone.
            restore_skipped: Vec::new(),
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
    /// Currently a no-op; retained as an extension point and for API
    /// stability. Idempotent: calling repeatedly is safe.
    pub fn validate(&self) -> Result<(), SandboxError> {
        Ok(())
    }

    /// Resolve the per-protection state against the host's current
    /// Landlock ABI. Returns one entry per `Protection`. Useful for
    /// post-`build()` posture inspection.
    pub fn active_protections(&self) -> Result<Vec<(Protection, ProtectionStatus)>, crate::error::SandlockError> {
        let host_abi = crate::landlock::abi_version().map_err(|e| {
            crate::error::SandlockError::Runtime(crate::error::SandboxRuntimeError::Confinement(e))
        })?;
        Ok(Protection::all()
            .map(|p| (p, ProtectionStatus::resolve(p, host_abi, &self.protection_policy)))
            .collect())
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
        use crate::result::RunResult;

        let pid = self.rt().child_pid.ok_or(SandboxRuntimeError::NotRunning)?;

        if let RuntimeState::Stopped(ref es) = self.rt().state {
            return Ok(RunResult {
                exit_status: es.clone(),
                stdout: None,
                stderr: None,
            });
        }

        // Deliver EOF to a piped stdin the caller never took: otherwise a child
        // that reads stdin (e.g. `cat`) blocks forever and this wait never
        // returns. A taken stdin is already None here (the caller owns it).
        drop(self.rt_mut()._stdin_write.take());

        // Wait for the top-level child to exit. Prefer the child's pidfd via
        // `AsyncFd`: pidfd readiness fires only on *exit*, so — unlike a
        // `waitpid` loop — it never consumes the child's ptrace-stops, which
        // the `policy_fn` fork-tracking worker reaps (`waitpid` with any flags
        // reaps a tracee's ptrace-stops, so a concurrent `waitpid` here would
        // race the worker for fork events and hang it). Mirrors
        // `spawn_pid_watcher`. Falls back to a blocking `waitpid` only when no
        // pidfd is available (kernel without `pidfd_open`).
        let exit_status = match self.rt_mut().pidfd.take() {
            Some(pidfd) => wait_child_exit_via_pidfd(pidfd, pid).await,
            None => wait_child_exit_blocking(pid).await,
        };

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

    /// Sugar for `create()` + `start()` that also blocks until the child
    /// has completed `execve()` and is executing user code. After this
    /// returns, operations that read user-code state (e.g. `checkpoint()`,
    /// `/proc/<pid>/exe`) observe the requested binary rather than the
    /// supervisor.
    pub async fn spawn(&mut self, cmd: &[&str]) -> Result<(), crate::error::SandlockError> {
        self.create(cmd).await?;
        self.start()?;
        self.wait_until_exec().await
    }

    /// Like `spawn` but inherits stdio (no capture).
    pub async fn spawn_interactive(&mut self, cmd: &[&str]) -> Result<(), crate::error::SandlockError> {
        self.create_interactive(cmd).await?;
        self.start()?;
        self.wait_until_exec().await
    }

    /// Spawn `cmd` with per-stream stdio wiring and return a live [`Process`].
    ///
    /// Unlike `run` (which buffers stdout/stderr into a `RunResult` only after
    /// the process exits), `popen` hands the caller the pipe end of every
    /// [`StdioMode::Piped`] stream so it can drive the process's stdio while it
    /// is alive — MCP/LSP servers, REPLs, any request/response protocol over
    /// stdio. The child is released to `execve` before this returns and runs
    /// under the full confinement. It is owned by this `Sandbox`: dropping the
    /// `Sandbox` (or calling [`Sandbox::kill`] / [`Process::kill`]) sends SIGKILL
    /// to its process group and reaps it.
    ///
    /// Note: the seccomp-notify supervisor runs as a task on the async runtime,
    /// and a confined child only makes progress while that supervisor is pumped.
    /// Do not block the runtime's executor on a piped stream — read/write the
    /// `Process` fds from a separate thread (or async IO), and run on a
    /// multi-threaded runtime. A blocking pipe read on a single-threaded runtime
    /// starves the supervisor and deadlocks the child.
    pub async fn popen(
        &mut self,
        cmd: &[&str],
        stdin: StdioMode,
        stdout: StdioMode,
        stderr: StdioMode,
    ) -> Result<Process<'_>, crate::error::SandlockError> {
        self.do_create_stdio(cmd, StdioSpec { stdin, stdout, stderr }).await?;
        // No wait_until_exec here: a streaming caller does not need the child to
        // have reached user code (a reader naturally blocks until bytes arrive),
        // and the exec poll would spuriously time out on a process that exits
        // before it is observed. `start` releases the child to execve.
        self.start()?;
        Ok(Process { sandbox: self })
    }

    /// Restore a checkpoint into a fresh, fully-sandboxed process.
    ///
    /// Reuses the normal create path to fork a child with the saved policy and the
    /// full notify stack in place (the child parks before execve), then takes the
    /// parked child over with ptrace and injects the checkpoint image over it via
    /// `restore_into`, resuming it at the saved program counter. The process comes
    /// up already sandboxed and running; like [`Sandbox::popen`], the returned
    /// [`Process`] is the handle to it (no `start()` step). Fds that could not be
    /// transparently recreated are recorded on this `Sandbox`; query them with
    /// [`Sandbox::restore_skipped`]. x86_64 restore engine only.
    ///
    /// The kernel vDSO is relocated onto the checkpoint-recorded base during
    /// restore, so ordinary libc/glibc programs that call vDSO functions (e.g.
    /// `clock_gettime`) resume correctly. Assumes a same-kernel restore.
    ///
    /// On error the child may be left half-built; the caller should drop/kill the
    /// Sandbox (Drop reaps it).
    pub async fn restore_interactive(
        &mut self,
        cp: &crate::checkpoint::Checkpoint,
    ) -> Result<Process<'_>, crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;

        // The exe to launch is the checkpoint's original binary (within the
        // policy's fs_read/exec grant). It is never actually execve'd: the child
        // parks blocked in read() on the ready-pipe, and we inject the checkpoint
        // over it before it could ever be released. Fall back to a benign command
        // only when the checkpoint recorded no exe path.
        let exe = if cp.process_state.exe.is_empty() {
            "/bin/true".to_string()
        } else {
            cp.process_state.exe.clone()
        };
        self.create_interactive(&[exe.as_str()]).await?;
        let pid = self.pid().ok_or(SandboxRuntimeError::NotRunning)?;

        // ptrace is per-thread: the seize, inject, and detach must all run on the
        // SAME OS thread (the seizing thread becomes the tracer). Do the entire
        // synchronous sequence inside one spawn_blocking closure with no awaits.
        // `restore_into` borrows the checkpoint, and spawn_blocking requires a
        // 'static closure, so move a clone of `cp` in. The clone resets the
        // policy's runtime to None (Sandbox::clone), which is harmless here:
        // restore_into reads only process_state + fd_table, never policy.
        let cp = cp.clone();
        let skipped = tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::checkpoint::SkippedFd>, crate::error::SandlockError> {
                // PTRACE_SEIZE + PTRACE_INTERRUPT + waitpid to reach the ptrace-stop.
                crate::checkpoint::capture::ptrace_seize(pid).map_err(|e| {
                    SandboxRuntimeError::Child(format!("restore ptrace seize {pid}: {e}"))
                })?;
                // Inject the checkpoint image; leaves the child stopped with the
                // saved registers (including rip at the checkpoint pc) loaded.
                // On error, best-effort detach so the child is not left seized
                // with a dangling tracer thread.
                let skipped = match crate::checkpoint::resume::restore_into(pid, &cp) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = crate::checkpoint::capture::ptrace_detach(pid);
                        return Err(e);
                    }
                };
                // PTRACE_DETACH resumes the child; because rip points at the
                // checkpoint pc, it resumes the checkpointed program, abandoning
                // the ready-pipe read, under the already-installed policy.
                crate::checkpoint::capture::ptrace_detach(pid).map_err(|e| {
                    SandboxRuntimeError::Child(format!("restore ptrace detach {pid}: {e}"))
                })?;
                Ok(skipped)
            },
        )
        .await
        .map_err(|e| SandboxRuntimeError::Child(format!("restore join error: {e}")))??;

        self.restore_skipped = skipped;
        Ok(Process { sandbox: self })
    }

    /// Fds that the last [`Sandbox::restore_interactive`] on this sandbox could
    /// not transparently recreate (sockets, pipes, memfds, pseudo-filesystem
    /// paths); the restored process runs without them. Empty if this sandbox
    /// never restored a checkpoint or every fd was restored.
    pub fn restore_skipped(&self) -> &[crate::checkpoint::SkippedFd] {
        &self.restore_skipped
    }

    /// Wait for the child to finish `execve`. Detected by `/proc/<pid>/exe`
    /// no longer matching `/proc/self/exe` (before execve the child still
    /// shares the supervisor's binary). The kernel offers no direct event
    /// for execve completion, so this polls every 1ms with a 5s ceiling.
    async fn wait_until_exec(&self) -> Result<(), crate::error::SandlockError> {
        use crate::error::SandboxRuntimeError;
        let pid = self.pid().ok_or(SandboxRuntimeError::NotRunning)?;
        let Some(our_exe) = std::fs::read_link("/proc/self/exe").ok() else {
            return Ok(());
        };
        let child_link = format!("/proc/{}/exe", pid);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Ok(child_exe) = std::fs::read_link(&child_link) {
                if child_exe != our_exe {
                    return Ok(());
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(SandboxRuntimeError::Child(
                    "child did not exec() within 5s".into(),
                ).into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
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

    /// Create a confined child that, instead of `execve`-ing a workload, runs
    /// `entrypoint` in-process after confinement is installed. The child is a
    /// `fork()` of this process, so `entrypoint`'s code is already mapped; no
    /// image is exec'd, so Landlock has nothing to authorize for the child's own
    /// startup. `extra_fds` maps caller fds onto fixed fd numbers in the child
    /// (e.g. the control channel). Used to run the OCI in-sandbox PID-1.
    ///
    /// `name` is not exec'd; it sets the child's process name
    /// (`/proc/<pid>/comm`). `start()` releases the parked child to run
    /// `entrypoint`.
    pub async fn create_with_in_child_main(
        &mut self,
        name: &str,
        extra_fds: Vec<(i32, i32)>,
        entrypoint: fn(),
    ) -> Result<(), crate::error::SandlockError> {
        self.ensure_runtime()?;
        self.in_child_main = Some(entrypoint);
        self.rt_mut().extra_fds = extra_fds;
        self.do_create(&[name], false).await
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
        self.checkpoint_pid(pid).await
    }

    /// Capture a checkpoint targeting a specific pid instead of the sandbox's
    /// direct child. The target must be a fork-descendant confined by the same
    /// policy (e.g. the workload spawned by sandlock-init). `target_pid` must
    /// be positive.
    pub async fn checkpoint_pid(&self, target_pid: i32) -> Result<crate::checkpoint::Checkpoint, crate::error::SandlockError> {
        use crate::error::{SandboxRuntimeError, SandlockError};
        if target_pid <= 0 {
            return Err(SandlockError::Runtime(SandboxRuntimeError::NotRunning));
        }
        self.freeze().await?;
        let cp = crate::checkpoint::capture(target_pid, self);
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
    pub async fn run_with_handlers<I, S, H>(
        &mut self,
        cmd: &[&str],
        handlers: I,
    ) -> Result<crate::result::RunResult, crate::error::SandlockError>
    where
        I: IntoIterator<Item = (S, H)>,
        S: TryInto<crate::seccomp::syscall::Syscall, Error = crate::seccomp::syscall::SyscallError>,
        H: crate::seccomp::dispatch::Handler,
    {
        let pending = sandbox_collect_handlers(handlers, self)?;
        self.ensure_runtime()?;
        self.rt_mut().handlers = pending;
        self.do_create(cmd, true).await?;
        self.do_start()?;
        self.wait().await
    }

    /// Interactive-stdio counterpart of `run_with_handlers`.
    pub async fn run_interactive_with_handlers<I, S, H>(
        &mut self,
        cmd: &[&str],
        handlers: I,
    ) -> Result<crate::result::RunResult, crate::error::SandlockError>
    where
        I: IntoIterator<Item = (S, H)>,
        S: TryInto<crate::seccomp::syscall::Syscall, Error = crate::seccomp::syscall::SyscallError>,
        H: crate::seccomp::dispatch::Handler,
    {
        let pending = sandbox_collect_handlers(handlers, self)?;
        self.ensure_runtime()?;
        self.rt_mut().handlers = pending;
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
                _stdin_write: None,
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
                handlers: Vec::new(),
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

    /// Whether named (pathname) `AF_UNIX` connects should be gated by the
    /// fs-write grants (`has_unix_fs_gate`). Active whenever the sandbox
    /// confines the filesystem; Landlock cannot gate unix-socket connect, so
    /// the seccomp layer does. Single source of truth for both the
    /// `NotifPolicy` flag and the `notif_syscalls` BPF set.
    pub(crate) fn has_unix_fs_gate(&self) -> bool {
        !self.fs_readable.is_empty() || !self.fs_writable.is_empty()
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
            _stdin_write: None,
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
            handlers: Vec::new(),
            ready_w: None,
        }));
        Ok(())
    }

    // ================================================================
    // Internal: collect_changes / do_abort
    // ================================================================

    async fn collect_changes(&self) -> Vec<crate::dry_run::Change> {
        if let Some(ref rt) = self.runtime {
            if let Some(ref cow) = rt.seccomp_cow {
                return cow.changes().unwrap_or_default();
            }
        }
        Vec::new()
    }

    async fn do_abort(&mut self) {
        if let Some(ref mut rt) = self.runtime {
            if let Some(ref mut cow) = rt.seccomp_cow {
                let _ = cow.abort();
            }
        }
    }

    // ================================================================
    // Internal: do_create (fork + policy install; child parks at the
    // ready_r read, awaiting do_start to release it to execve).
    // ================================================================

    /// Thin compatibility wrapper: `capture` selects between the capture stdio
    /// spec (stdin inherited, stdout/stderr piped-and-drained) and full inherit.
    async fn do_create(&mut self, cmd: &[&str], capture: bool) -> Result<(), crate::error::SandlockError> {
        let stdio = if capture { StdioSpec::capture() } else { StdioSpec::inherit() };
        self.do_create_stdio(cmd, stdio).await
    }

    async fn do_create_stdio(&mut self, cmd: &[&str], stdio: StdioSpec) -> Result<(), crate::error::SandlockError> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use crate::error::SandboxRuntimeError;
        use crate::context::{PipePair, read_u32_fd};
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

        // Resolve the chroot root eagerly, before any fork or confinement work:
        // a configured-but-missing chroot must be a hard error, never a silent
        // drop to "no confinement".
        let chroot_root = crate::chroot::resolve::resolve_chroot_root(self.chroot.as_deref())?;

        // Each --http-inject-ca target must exist in the sandbox's view, or the
        // CA cannot be spliced into it and TLS interception silently fails. A
        // configured-but-missing trust bundle is a hard error, resolved through
        // --fs-mount and chroot so the check matches the workload's view.
        if !self.http_inject_ca.is_empty() {
            let mounts = crate::chroot::resolve::resolve_chroot_mounts(&self.fs_mount);
            for p in &self.http_inject_ca {
                let host = resolve_sandbox_path_to_host(p, chroot_root.as_deref(), &mounts);
                if !host.exists() {
                    return Err(SandboxRuntimeError::Child(format!(
                        "--http-inject-ca {:?} not found in the sandbox view (resolved to {:?}); \
                         the CA cannot be injected into it. Point it at the trust bundle the \
                         workload actually reads (e.g. /etc/ssl/certs/ca-certificates.crt, or \
                         certifi's cacert.pem).",
                        p, host
                    ))
                    .into());
                }
            }
        }

        let c_cmd: Vec<CString> = cmd
            .iter()
            .map(|s| CString::new(*s).map_err(|_| SandboxRuntimeError::Child("invalid command string".into())))
            .collect::<Result<Vec<_>, _>>()?;

        let no_supervisor = self.no_supervisor;

        let pipes = PipePair::new().map_err(SandboxRuntimeError::Io)?;

        let resolved_net_allow = network::resolve_net_allow(&self.net_allow)
            .await
            .map_err(SandboxRuntimeError::Io)?;
        // In chroot/image mode, seed the synthetic /etc/hosts from the
        // rootfs's own file so entries baked into the image (private
        // registries, internal hostnames, etc.) survive virtualization.
        // Without a chroot, the helper returns the fixed loopback base.
        // Either way, concrete-host rules from `net_allow` are appended
        // on top.
        let virtual_etc_hosts = network::compose_virtual_etc_hosts(
            self.chroot.as_deref(),
            &resolved_net_allow.concrete_host_entries,
        );

        let mut ca_inject_pem: Option<std::sync::Arc<Vec<u8>>> = None;
        if !self.http_allow.is_empty() || !self.http_deny.is_empty() {
            // Generate an ephemeral CA when injection is requested without BYO.
            let generate = !self.http_inject_ca.is_empty();
            let ca_material = crate::transparent_proxy::resolve_ca(
                self.http_ca.as_deref(),
                self.http_key.as_deref(),
                generate,
            )
            .map_err(SandboxRuntimeError::Io)?;

            // Export the public cert if requested.
            if let (Some(out), Some(cm)) = (self.http_ca_out.as_deref(), ca_material.as_ref()) {
                std::fs::write(out, cm.cert_pem.as_bytes()).map_err(SandboxRuntimeError::Io)?;
            }

            // Keep the public cert for trust injection (only when paths declared).
            if !self.http_inject_ca.is_empty() {
                if let Some(cm) = ca_material.as_ref() {
                    ca_inject_pem = Some(std::sync::Arc::new(cm.cert_pem.clone().into_bytes()));
                }
            }

            let (cert_pem, key_pem) = match ca_material.as_ref() {
                Some(cm) => (Some(cm.cert_pem.as_str()), Some(cm.key_pem.as_str())),
                None => (None, None),
            };

            let handle = crate::transparent_proxy::spawn_transparent_proxy(
                self.http_allow.clone(),
                self.http_deny.clone(),
                std::sync::Arc::clone(&self.inject),
                cert_pem,
                key_pem,
            )
            .await
            .map_err(SandboxRuntimeError::Io)?;
            self.rt_mut().http_acl_handle = Some(handle);
        }

        // Seccomp COW: create the branch before fork so the child's Landlock
        // ruleset can include the upper layer. Binaries created inside the
        // workdir live in the upper dir, and Landlock checks EXECUTE on the
        // file's real path at execve time — so the upper dir must be granted
        // read+execute (READ_ACCESS) or `./created-binary` fails with EACCES.
        let seccomp_cow_branch = if !no_supervisor && self.workdir.is_some() {
            let workdir = self.workdir.as_ref().unwrap().clone();
            let storage = self.fs_storage.clone();
            let max_disk = self.max_disk.map(|b| b.0).unwrap_or(0);
            match crate::cow::seccomp::SeccompCowBranch::create(&workdir, storage.as_deref(), max_disk) {
                Ok(branch) => {
                    self.fs_readable.push(branch.upper_dir().to_path_buf());
                    Some(branch)
                }
                Err(e) => {
                    eprintln!("sandlock: seccomp COW branch creation failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let handler_syscalls: Vec<i64> = self.rt().handlers.iter().map(|(nr, _)| *nr).collect();
        let resolved_sandbox_name = self.rt().name.clone();
        let resolved = crate::resolved::ResolvedSandbox::from_sandbox(
            self,
            Some(resolved_sandbox_name.as_str()),
            &handler_syscalls,
        );

        // Per-stream stdio wiring. Each Piped stream gets a CLOEXEC pipe whose
        // parent-side end we keep: the caller writes the child's stdin and reads
        // its stdout/stderr (see `popen` / `Process`). `pipe2` returns
        // (read=fds[0], write=fds[1]); for stdin the child reads, so the parent
        // keeps the write end, and vice-versa for stdout/stderr.
        let stdin_p = if stdio.stdin == StdioMode::Piped {
            Some(make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?)
        } else {
            None
        };
        let stdout_p = if stdio.stdout == StdioMode::Piped {
            Some(make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?)
        } else {
            None
        };
        let stderr_p = if stdio.stderr == StdioMode::Piped {
            Some(make_cloexec_pipe().map_err(SandboxRuntimeError::Io)?)
        } else {
            None
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

            // Wire stdin/stdout/stderr per their modes. This is a post-fork path
            // with a real class of fd hazards: when the supervisor was started
            // with a std fd (0/1/2) closed, `pipe2` can allocate a pipe end onto
            // that very fd, so a naive `dup2(end, std)` either aliases the target
            // or a sibling stream's later dup2 clobbers an end still needed, and a
            // raw-fd snapshot taken before the dup2s goes stale. To make wiring
            // order-independent, first relocate each Piped source to a fresh high
            // fd (>= 3, disjoint from the 0/1/2 targets), then dup2 it down.
            //
            // The original OwnedFd ends are O_CLOEXEC, so they close on their own
            // at execve; `mem::forget` them so their Drop cannot close a fd number
            // we have since reassigned to 0/1/2.
            let safe_in = if stdio.stdin == StdioMode::Piped {
                stdin_p.as_ref().map(|(r, _)| unsafe { relocate_high(r.as_raw_fd()) })
            } else {
                None
            };
            let safe_out = if stdio.stdout == StdioMode::Piped {
                stdout_p.as_ref().map(|(_, w)| unsafe { relocate_high(w.as_raw_fd()) })
            } else {
                None
            };
            let safe_err = if stdio.stderr == StdioMode::Piped {
                stderr_p.as_ref().map(|(_, w)| unsafe { relocate_high(w.as_raw_fd()) })
            } else {
                None
            };
            std::mem::forget(stdin_p);
            std::mem::forget(stdout_p);
            std::mem::forget(stderr_p);
            unsafe {
                wire_child_stdio(stdio.stdin, 0, safe_in, libc::O_RDONLY);
                wire_child_stdio(stdio.stdout, 1, safe_out, libc::O_WRONLY);
                wire_child_stdio(stdio.stderr, 2, safe_err, libc::O_WRONLY);
            }

            let gather_keep_fds: Vec<i32> = extra_fds_copy.iter().map(|&(target, _)| target).collect();

            let extra_syscalls: Vec<u32> = self.rt().handlers
                .iter()
                .map(|h| h.0 as u32)
                .collect();

            let sandbox_name = self.rt().name.clone();
            // In-process entrypoint (OCI PID-1) names the process from cmd[0];
            // otherwise execve the command.
            let entry = match self.in_child_main {
                Some(run) => context::ChildEntry::InProcess { name: c_cmd[0].as_c_str(), run },
                None => context::ChildEntry::Exec(&c_cmd),
            };
            context::confine_child(context::ChildSpawnArgs {
                sandbox: self,
                entry,
                pipes: &pipes,
                no_supervisor,
                keep_fds: &gather_keep_fds,
                sandbox_name: Some(sandbox_name.as_str()),
                extra_syscalls: &extra_syscalls,
                parent_pid,
            });
        }

        // ===== PARENT PROCESS =====
        drop(pipes.notif_w);
        drop(pipes.ready_r);

        self.rt_mut()._stdin_write = stdin_p.map(|(_r, w)| w);
        self.rt_mut()._stdout_read = stdout_p.map(|(r, _w)| r);
        self.rt_mut()._stderr_read = stderr_p.map(|(r, _w)| r);

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
                has_memory_limit: resolved.features.memory_limit,
                has_net_destination_policy: resolved.features.network_destination_policy,
                has_bind_denylist: resolved.features.bind_denylist,
                has_unix_fs_gate: resolved.features.unix_fs_gate,
                has_random_seed: resolved.features.random_seed,
                has_time_start: resolved.features.time_start,
                argv_safety_required: resolved.features.argv_safety_required,
                time_offset: time_offset_val,
                num_cpus: self.num_cpus,
                port_remap: resolved.features.port_remap,
                cow_enabled: resolved.features.cow,
                chroot_root: chroot_root.clone(),
                chroot_readable: self.fs_readable.clone(),
                chroot_writable: self.fs_writable.clone(),
                chroot_denied: self.fs_denied.clone(),
                chroot_mounts: crate::chroot::resolve::resolve_chroot_mounts(&self.fs_mount),
                chroot_mount_ro: self.fs_mount_ro.clone(),
                deterministic_dirs: self.deterministic_dirs,
                virtual_hostname: Some(rt_name),
                has_http_acl: resolved.features.http_acl,
                virtual_etc_hosts,
                ca_inject_paths: self.http_inject_ca.clone(),
                ca_inject_pem: ca_inject_pem.clone(),
            };

            use rand::SeedableRng;
            use rand_chacha::ChaCha8Rng;

            let random_state = self.random_seed.map(|seed| ChaCha8Rng::seed_from_u64(seed));
            let time_offset = self.time_start.map(|t| crate::time::calculate_time_offset(t));

            let time_random_state = TimeRandomState::new(time_offset, random_state);

            let mut net_state = NetworkState::new();
            if !self.net_deny.is_empty() {
                let resolved_deny = network::resolve_net_deny(&self.net_deny);
                net_state.tcp_policy = resolved_deny.tcp;
                net_state.udp_policy = resolved_deny.udp;
                net_state.icmp_policy = resolved_deny.icmp;
            } else {
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
                            cidrs: resolved.cidrs.clone(),
                            any_ip_ports: resolved.any_ip_ports.clone(),
                        }
                    }
                };
                net_state.tcp_policy = policy_from(&resolved_net_allow.tcp);
                net_state.udp_policy = policy_from(&resolved_net_allow.udp);
                net_state.icmp_policy = policy_from(&resolved_net_allow.icmp);
            }
            net_state.http_acl_addr = self.rt().http_acl_handle.as_ref().map(|h| h.addr);
            net_state.http_acl_ports = self.http_ports.iter().copied().collect();
            net_state.http_acl_orig_dest = self.rt().http_acl_handle.as_ref().map(|h| h.orig_dest.clone());
            net_state.bind_deny_ports = self.net_deny_bind.iter().copied().collect();
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
            cow_state.branch = seccomp_cow_branch;

            let mut policy_fn_state = PolicyFnState::new();

            for path in &self.fs_denied {
                // Captures the path prefix and the file's inode identity, so
                // the deny survives hardlinks/renames to a non-denied name.
                policy_fn_state.denied.deny(&path.to_string_lossy());
            }

            if let Some(ref callback) = self.policy_fn {
                let mut allowed_ips: std::collections::HashSet<std::net::IpAddr> =
                    std::collections::HashSet::new();
                for p in [&net_state.tcp_policy, &net_state.udp_policy, &net_state.icmp_policy] {
                    if let crate::seccomp::notif::NetworkPolicy::AllowList { per_ip, cidrs, .. } = p {
                        allowed_ips.extend(per_ip.keys().copied());
                        // IP literals resolve to single-host CIDRs (/32 or
                        // /128); surface them as concrete allowed IPs too.
                        for (net, _) in cidrs {
                            if net.is_single_host() {
                                allowed_ips.insert(net.addr);
                            }
                        }
                    }
                }
                let live = crate::policy_fn::LivePolicy {
                    allowed_ips,
                    max_memory_bytes: notif_policy.max_memory_bytes,
                    max_processes: notif_policy.max_processes,
                };
                let ceiling = live.clone();
                let live = std::sync::Arc::new(std::sync::RwLock::new(live));
                let denied = policy_fn_state.denied.clone();
                let pid_overrides = net_state.pid_ip_overrides.clone();
                policy_fn_state.live_policy = Some(live.clone());
                let tx = crate::policy_fn::spawn_policy_fn(
                    callback.clone(), live, ceiling, pid_overrides, denied,
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

            let handlers = std::mem::take(&mut self.rt_mut().handlers);
            let (startup_tx, startup_rx) = tokio::sync::oneshot::channel();
            self.rt_mut().notif_handle = Some(tokio::spawn(
                notif::supervisor(notif_fd, ctx, handlers, startup_tx),
            ));
            // Wait for the supervisor to register the notif fd with the IO
            // driver before we release the child to execve. Otherwise an
            // early traced syscall would queue a notification on a fd no
            // one is polling, and the child would block until the next
            // `block_on` re-enters the runtime. Critical for current-thread
            // runtimes, harmless overhead for multi-thread.
            match startup_rx.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(SandboxRuntimeError::Io(e).into()),
                Err(_) => {
                    return Err(SandboxRuntimeError::Child(
                        "seccomp supervisor exited during startup".into(),
                    ).into());
                }
            }

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
// ================================================================
// Process — a live process with caller-owned stdio (popen)
// ================================================================

/// A live sandboxed process with caller-owned stdio streams, returned by
/// [`Sandbox::popen`].
///
/// `take_stdin` / `take_stdout` / `take_stderr` move out the pipe end of each
/// stream opened with [`StdioMode::Piped`] (each available once); the caller
/// reads/writes those while the process runs. Unlike `std::process::Child`,
/// this *borrows* the originating [`Sandbox`] rather than owning the process:
/// the process is killed and reaped when that `Sandbox` is dropped, or eagerly
/// via [`Process::kill`].
///
/// A `Process` that is dropped without [`Process::wait`] leaves the child
/// running until the `Sandbox` is dropped — call `wait` (or `kill`) to end it.
#[must_use = "a Process is a live confined child; call wait() (or kill()) or it runs until the Sandbox is dropped"]
pub struct Process<'a> {
    sandbox: &'a mut Sandbox,
}

impl Process<'_> {
    /// Take the write end of a `Piped` stdin. The caller writes the child's
    /// input; closing this fd signals EOF. `None` if stdin was not piped or was
    /// already taken.
    ///
    /// Deadlock warning (as with `std::process::Child`): if you take stdin you
    /// own it — drop/close it before [`Process::wait`], or a child that reads to
    /// EOF (e.g. `cat`) never exits and `wait` blocks forever. (An *untaken*
    /// piped stdin is closed by `wait` for you.)
    pub fn take_stdin(&mut self) -> Option<std::os::fd::OwnedFd> {
        self.sandbox.rt_mut()._stdin_write.take()
    }

    /// Take the read end of a `Piped` stdout. `None` if stdout was not piped or
    /// was already taken.
    pub fn take_stdout(&mut self) -> Option<std::os::fd::OwnedFd> {
        self.sandbox.rt_mut()._stdout_read.take()
    }

    /// Take the read end of a `Piped` stderr. `None` if stderr was not piped or
    /// was already taken.
    pub fn take_stderr(&mut self) -> Option<std::os::fd::OwnedFd> {
        self.sandbox.rt_mut()._stderr_read.take()
    }

    /// The child PID, or `None` if not spawned. Remains `Some` after the child
    /// exits (until the `Sandbox` is dropped).
    pub fn pid(&self) -> Option<i32> {
        self.sandbox.pid()
    }

    /// Send SIGKILL to the child's *entire process group* (every process the
    /// workload spawned, not just the top-level child). Idempotent — a process
    /// that already exited is not an error.
    pub fn kill(&mut self) -> Result<(), crate::error::SandlockError> {
        self.sandbox.kill()
    }

    /// Wait for the child to exit. Any `Piped` stdout/stderr the caller did not
    /// take is drained into the returned `RunResult`; taken streams are `None`
    /// because the caller owns them. An untaken piped stdin is closed here so the
    /// child sees EOF; a *taken* stdin the caller must close itself first (see
    /// [`Process::take_stdin`]) or this blocks forever.
    pub async fn wait(self) -> Result<crate::result::RunResult, crate::error::SandlockError> {
        self.sandbox.wait().await
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

/// Create a `O_CLOEXEC` pipe, returning `(read_end, write_end)` as owned fds.
/// `pipe2` yields `fds[0]` = read, `fds[1]` = write.
fn make_cloexec_pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), std::io::Error> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Duplicate `src` to a fresh fd `>= 3` with `O_CLOEXEC`, in the forked child.
/// Used to move a pipe end out of the 0/1/2 target range before wiring so that
/// `dup2(_, std)` can never alias the target or clobber a sibling stream's end.
/// Best-effort: returns the original `src` if the dup fails (caller still wires
/// it; a failure here only degrades to the legacy hazard, never a leak).
///
/// # Safety
/// Must run in the forked child; `src` must be a valid fd.
unsafe fn relocate_high(src: i32) -> i32 {
    let hi = libc::fcntl(src, libc::F_DUPFD_CLOEXEC, 3);
    if hi >= 0 {
        hi
    } else {
        src
    }
}

/// Wire one of the child's std fds (`target` = 0/1/2) according to `mode`, in
/// the forked child just before execve. Single audited path for all three
/// streams (async-signal-safe: only open/dup2/close/fcntl).
///
/// For `Piped`, `pipe_src` is a relocated high fd (see `relocate_high`), so
/// `src != target` in the normal case and `dup2` clears `O_CLOEXEC` on the
/// target (it survives execve); the relocated copy is then closed. The
/// `src == target` arm is only reached if relocation failed (fd exhaustion).
///
/// # Safety
/// Must run in the forked child before execve; `pipe_src` (if any) must be a
/// valid fd. `devnull_flags` is `O_RDONLY` for stdin, `O_WRONLY` for stdout/err.
unsafe fn wire_child_stdio(mode: StdioMode, target: i32, pipe_src: Option<i32>, devnull_flags: i32) {
    match mode {
        StdioMode::Inherit => {}
        StdioMode::Piped => {
            if let Some(src) = pipe_src {
                if src == target {
                    // Relocation failed and the end sits on `target`; dup2 would
                    // no-op and leave O_CLOEXEC set, so clear it so the fd
                    // survives execve. Do not close it — it *is* the target.
                    let flags = libc::fcntl(target, libc::F_GETFD);
                    if flags >= 0 {
                        libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                    }
                } else if libc::dup2(src, target) < 0 {
                    // Fail closed (mirror Null): never leave the supervisor's fd.
                    libc::close(target);
                    libc::close(src);
                } else {
                    libc::close(src);
                }
            }
        }
        StdioMode::Null => {
            // Opened without O_CLOEXEC so it survives execve.
            let fd = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, devnull_flags);
            if fd < 0 {
                // Fail closed: workload gets EBADF, never the supervisor's fd.
                libc::close(target);
            } else if fd == target {
                // /dev/null landed on the (previously closed) target — done.
            } else if libc::dup2(fd, target) < 0 {
                libc::close(target);
                libc::close(fd);
            } else {
                libc::close(fd);
            }
        }
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

/// Await the top-level child's exit via its `pidfd` (readable on exit only),
/// then reap the status. Because it never calls `waitpid` until the child has
/// already exited, it does not consume the child's ptrace-stops the way a
/// `waitpid`-loop would — so it doesn't race the `policy_fn` fork-tracking
/// worker. Falls back to the blocking waiter on any pidfd/`AsyncFd` error.
async fn wait_child_exit_via_pidfd(
    pidfd: std::os::unix::io::OwnedFd,
    pid: libc::pid_t,
) -> crate::result::ExitStatus {
    use crate::result::ExitStatus;

    let async_fd = match tokio::io::unix::AsyncFd::with_interest(
        pidfd,
        tokio::io::Interest::READABLE,
    ) {
        Ok(fd) => fd,
        Err(_) => return wait_child_exit_blocking(pid).await,
    };

    loop {
        // pidfd becomes readable when the process exits; no data is read.
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(_) => return ExitStatus::Killed,
        };
        let mut status: i32 = 0;
        // The child has exited and is reapable now, so this never blocks.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r > 0 {
            return sandbox_wait_status_to_exit(status);
        }
        if r == 0 {
            // Spurious readiness (not yet reapable): clear and re-await.
            guard.clear_ready();
            continue;
        }
        // r < 0 (e.g. ECHILD): already reaped elsewhere. Status is unavailable.
        return ExitStatus::Killed;
    }
}

/// Blocking `waitpid` fallback for kernels without `pidfd_open`. Used only when
/// no pidfd is available; on such kernels `policy_fn` fork-tracking is the only
/// thing that could race it, and the lack of pidfd is itself rare.
async fn wait_child_exit_blocking(pid: libc::pid_t) -> crate::result::ExitStatus {
    use crate::result::ExitStatus;
    tokio::task::spawn_blocking(move || -> ExitStatus {
        let mut status: i32 = 0;
        loop {
            let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
            if ret < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return ExitStatus::Killed;
            }
            break;
        }
        sandbox_wait_status_to_exit(status)
    })
    .await
    .unwrap_or(ExitStatus::Killed)
}

fn sandbox_collect_handlers<I, S, H>(
    handlers: I,
    sandbox: &Sandbox,
) -> Result<Vec<(i64, Arc<dyn crate::seccomp::dispatch::Handler>)>, crate::error::SandlockError>
where
    I: IntoIterator<Item = (S, H)>,
    S: TryInto<crate::seccomp::syscall::Syscall, Error = crate::seccomp::syscall::SyscallError>,
    H: crate::seccomp::dispatch::Handler,
{
    use crate::seccomp::dispatch::{Handler, HandlerError};

    let pending: Vec<(i64, Arc<dyn Handler>)> = handlers
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
        .filter(|name| crate::seccomp::syscall::syscall_name_to_nr(name).is_none())
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

/// Parse `--net-allow-bind` specs. Accepts the `*` wildcard (any port),
/// which cannot be combined with port lists; repeating the bare wildcard
/// is idempotent.
fn parse_allow_bind_ports(specs: &[String], label: &str) -> Result<BindPorts, SandboxError> {
    let mut parts = specs.iter().flat_map(|s| s.split(',')).map(str::trim);
    if !parts.clone().any(|part| part == "*") {
        return Ok(BindPorts::Ports(parse_bind_ports(specs, label)?));
    }
    if !parts.all(|part| part == "*") {
        return Err(SandboxError::Invalid(format!(
            "{}: wildcard `*` cannot be combined with port lists",
            label
        )));
    }
    Ok(BindPorts::All)
}

/// Expand `--net-allow-bind` specs into a sorted, deduplicated port list.
/// Each spec is a comma-separated list of single ports (`8080`) or inclusive
/// `lo-hi` ranges (`8000-8010`). Mirrors the Python SDK's `parse_ports`.
fn parse_bind_ports(specs: &[String], label: &str) -> Result<Vec<u16>, SandboxError> {
    let mut ports: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    for spec in specs {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(SandboxError::Invalid(format!(
                    "{}: empty port in `{}`",
                    label, spec
                )));
            }
            if part == "*" {
                return Err(SandboxError::Invalid(format!(
                    "{}: wildcard `*` is only supported for --net-allow-bind",
                    label
                )));
            }
            match part.split_once('-') {
                Some((lo, hi)) => {
                    let lo: u16 = lo.trim().parse().map_err(|_| {
                        SandboxError::Invalid(format!("{}: invalid port range `{}`", label, part))
                    })?;
                    let hi: u16 = hi.trim().parse().map_err(|_| {
                        SandboxError::Invalid(format!("{}: invalid port range `{}`", label, part))
                    })?;
                    if lo > hi {
                        return Err(SandboxError::Invalid(format!(
                            "{}: reversed port range `{}` (lo > hi)",
                            label, part
                        )));
                    }
                    ports.extend(lo..=hi);
                }
                None => {
                    let p: u16 = part.parse().map_err(|_| {
                        SandboxError::Invalid(format!("{}: invalid port `{}`", label, part))
                    })?;
                    ports.insert(p);
                }
            }
        }
    }
    Ok(ports.into_iter().collect())
}

/// Resolve a path as seen inside the sandbox to its host-side location, so its
/// existence can be checked before spawn. Honors `--fs-mount` (virtual:host)
/// mappings (which take precedence) and chroot. Used to validate
/// `--http-inject-ca` targets.
fn resolve_sandbox_path_to_host(
    child_path: &std::path::Path,
    chroot_root: Option<&std::path::Path>,
    mounts: &[(std::path::PathBuf, std::path::PathBuf)],
) -> std::path::PathBuf {
    for (virt, host) in mounts {
        if let Ok(rest) = child_path.strip_prefix(virt) {
            return host.join(rest);
        }
    }
    if let Some(root) = chroot_root {
        if let Ok(rest) = child_path.strip_prefix("/") {
            return root.join(rest);
        }
    }
    child_path.to_path_buf()
}

#[cfg(test)]
mod tests;
