use super::*;

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

    /// `--net-deny`: default-allow networking, block these IPs/CIDRs/ports.
    /// Accepts `<ip>`, `<cidr>`, `<cidr>:<port[,port]>`, `:<port>`, `*`, and
    /// `[<ipv6>]:<port>`. The port is optional (no `:port` means all ports).
    /// Hostnames are rejected; use `--http-deny` for domains. Repeat the flag
    /// for multiple rules. Mutually exclusive with `--net-allow`.
    #[cfg_attr(feature = "cli", arg(long = "net-deny", value_name = "SPEC"))]
    pub net_deny: Vec<String>,

    /// `--net-allow-bind`: TCP ports the sandbox may bind/listen on
    /// (default-deny). Each value is a comma-separated list of single ports
    /// or inclusive `lo-hi` ranges, e.g. `8080,9000-9005`, or `'*'` to
    /// allow binding any port (cannot be mixed with port lists). Repeatable.
    #[cfg_attr(feature = "cli", arg(long = "net-allow-bind", value_name = "PORTS"))]
    pub net_allow_bind: Vec<String>,

    /// `--net-deny-bind`: TCP ports the sandbox may NOT bind/listen on
    /// (default-allow denylist; the inverse of `--net-allow-bind`). Same
    /// port syntax (comma-separated ports / `lo-hi` ranges). Repeatable.
    /// Mutually exclusive with `--net-allow-bind`.
    #[cfg_attr(feature = "cli", arg(long = "net-deny-bind", value_name = "PORTS"))]
    pub net_deny_bind: Vec<String>,

    #[cfg_attr(feature = "cli", arg(long = "http-allow", value_name = "RULE"))]
    pub http_allow: Vec<String>,

    #[cfg_attr(feature = "cli", arg(long = "http-deny", value_name = "RULE"))]
    pub http_deny: Vec<String>,

    /// Named credential loaded into the supervisor: `NAME=SOURCE`, where SOURCE
    /// is `env:VAR`, `file:/path`, or `fd:N`. The resolved secret is never handed
    /// to the child: an `env:` var is stripped from the child's environment and an
    /// `fd:` is read supervisor-side only. A `file:` source, however, is only as
    /// private as the path — keep it outside the sandbox's readable paths, or the
    /// child can open it directly.
    #[cfg_attr(feature = "cli", arg(long = "credential", value_name = "NAME=SOURCE"))]
    pub credentials: Vec<String>,

    /// Credential-injection rule (needs an HTTPS MITM proxy, i.e. `--http-ca` /
    /// `--http-inject-ca`): `METHOD HOST/PATH AUTHSPEC CREDNAME [replace|add-only]`,
    /// where AUTHSPEC is `bearer | basic:<user> | header:<name> | apikey:<name> |
    /// query:<param>`. The matching request gets the credential attached in the
    /// proxy, after the ACL check. The trailing token defaults to `replace` (the
    /// proxy overwrites the placeholder auth SDKs send); pass `add-only` to keep a
    /// value the child set.
    #[cfg_attr(feature = "cli", arg(long = "http-auth", value_name = "RULE"))]
    pub http_auth: Vec<String>,

    /// TCP ports to intercept for HTTP ACL (default: 80, plus 443 with --http-ca)
    #[cfg_attr(feature = "cli", arg(long = "http-port", value_name = "PORT"))]
    pub http_ports: Vec<u16>,

    /// PEM CA certificate for HTTPS MITM (enables port 443 interception)
    #[cfg_attr(feature = "cli", arg(long = "http-ca", value_name = "PATH"))]
    pub http_ca: Option<PathBuf>,

    /// PEM CA private key for HTTPS MITM (required with --http-ca)
    #[cfg_attr(feature = "cli", arg(long = "http-key", value_name = "PATH"))]
    pub http_key: Option<PathBuf>,

    /// Inject the MITM CA into these trust bundle paths (repeatable). Without
    /// --http-ca this generates an ephemeral CA and intercepts port 443.
    #[cfg_attr(feature = "cli", arg(long = "http-inject-ca", value_name = "PATH"))]
    pub http_inject_ca: Vec<PathBuf>,

    /// Write the active MITM CA public certificate (PEM) to this path.
    #[cfg_attr(feature = "cli", arg(long = "http-ca-out", value_name = "PATH"))]
    pub http_ca_out: Option<PathBuf>,

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

    // Virtual paths (subset of fs_mount destinations) mounted read-only.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub fs_mount_ro: Vec<PathBuf>,

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

    /// Skip the seccomp user-notification supervisor. The CLI exposes
    /// its own `--no-supervisor` flag on `RunArgs` (which short-circuits
    /// to a direct exec); this field is the API-level counterpart used
    /// when the caller still wants the normal `Sandbox::run` lifecycle
    /// but cannot install a listener (e.g. nested inside another
    /// sandbox).
    #[cfg_attr(feature = "cli", clap(skip))]
    pub no_supervisor: bool,

    #[cfg_attr(feature = "cli", arg(long = "user", value_name = "UID:GID"))]
    pub user: Option<RunAs>,

    /// Per-protection state overrides. Defaults to `strict_all`: every
    /// protection enforced, matching the historical `MIN_ABI = 6` floor.
    /// Use the `allow_degraded` / `disable` builder methods to deviate.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub protection_policy: ProtectionPolicy,

    // Internal callback: never a CLI flag.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub policy_fn: Option<crate::policy_fn::PolicyCallback>,

    // Sandbox instance name: stored for transfer into the Sandbox at build time.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub name: Option<String>,

    // COW fork init function: runs once in the child before COW cloning.
    #[cfg_attr(feature = "cli", clap(skip))]
    pub(crate) init_fn: Option<Box<dyn FnOnce() + Send + 'static>>,

    // COW fork work function: runs in each COW clone.
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
            net_deny: self.net_deny.clone(),
            net_allow_bind: self.net_allow_bind.clone(),
            net_deny_bind: self.net_deny_bind.clone(),
            http_allow: self.http_allow.clone(),
            http_deny: self.http_deny.clone(),
            credentials: self.credentials.clone(),
            http_auth: self.http_auth.clone(),
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
            clean_env: self.clean_env,
            env: self.env.clone(),
            gpu_devices: self.gpu_devices.clone(),
            cpu_cores: self.cpu_cores.clone(),
            num_cpus: self.num_cpus,
            port_remap: self.port_remap,
            no_supervisor: self.no_supervisor,
            user: self.user,
            protection_policy: self.protection_policy.clone(),
            policy_fn: self.policy_fn.clone(),
            name: self.name.clone(),
            // init_fn (FnOnce) cannot be cloned; drop to None.
            init_fn: None,
            // work_fn is Arc-wrapped; clone bumps the reference count.
            work_fn: self.work_fn.clone(),
        }
    }
}

impl SandboxBuilder {
    /// Permit `protection` to be enforced when the host kernel
    /// supports it, and silently skipped when it does not (fallback
    /// for kernels below the protection's `min_abi()`).
    ///
    /// The default policy enforces every protection strictly; calling
    /// `allow_degraded` lifts the strictness for the named protection
    /// only. `sandlock check` and `Sandbox::active_protections()`
    /// continue to report the degraded protection so the posture is
    /// observable.
    pub fn allow_degraded(mut self, protection: Protection) -> Self {
        self.protection_policy.set(protection, ProtectionState::Degradable);
        self
    }

    /// Never enforce `protection`, even on a host kernel that supports
    /// it. Intended for workloads that legitimately need the capability
    /// the protection blocks (e.g. signalling a sibling process when
    /// `SignalScope` would normally prevent it).
    ///
    /// `Protection::FsRefer` cannot be disabled: Landlock denies REFER
    /// (cross-directory rename/link) by default in every ruleset even when
    /// it is not handled, so disabling it only tightens the sandbox rather
    /// than loosening it. `build()` (and `build_unchecked()`) return
    /// `SandboxError::Invalid` if `disable(Protection::FsRefer)` was called.
    /// Use [`allow_degraded`](Self::allow_degraded) if you want REFER
    /// enforced only where the kernel supports it.
    pub fn disable(mut self, protection: Protection) -> Self {
        self.protection_policy.set(protection, ProtectionState::Disabled);
        self
    }

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
    /// `:port`, or `*:port`; a spec with no scheme covers both TCP and
    /// UDP, while `tcp://`, `udp://`, or `icmp://` pins one protocol.
    /// Validated at `build()` time so callers receive parse errors via
    /// the standard `SandboxBuilder` flow.
    ///
    /// Examples:
    /// - `.net_allow("api.openai.com:443")`: port 443 to OpenAI only
    /// - `.net_allow("github.com:22,443")`: SSH and HTTPS to GitHub
    /// - `.net_allow(":8080")`: any IP on port 8080
    /// - `.net_allow("tcp://10.0.0.5:22")`: TCP only, no UDP
    pub fn net_allow(mut self, spec: impl Into<String>) -> Self {
        self.net_allow.push(spec.into());
        self
    }

    /// Add a `--net-deny` rule. See the field docs for accepted forms.
    pub fn net_deny(mut self, spec: impl Into<String>) -> Self {
        self.net_deny.push(spec.into());
        self
    }

    /// Allow binding a single TCP port. For comma-separated lists or
    /// `lo-hi` ranges, use [`net_allow_bind`](Self::net_allow_bind).
    pub fn net_allow_bind_port(mut self, port: u16) -> Self {
        self.net_allow_bind.push(port.to_string());
        self
    }

    /// Allow binding TCP ports from a spec: a comma-separated list of single
    /// ports or inclusive `lo-hi` ranges (e.g. `"8080,9000-9005"`), or the
    /// `"*"` wildcard to allow binding any port. Mixing the wildcard with
    /// port lists fails at build time; repeating the bare wildcard is
    /// idempotent.
    pub fn net_allow_bind(mut self, spec: impl Into<String>) -> Self {
        self.net_allow_bind.push(spec.into());
        self
    }

    /// Deny binding a single TCP port (default-allow denylist). For
    /// comma-separated lists or `lo-hi` ranges, use
    /// [`net_deny_bind`](Self::net_deny_bind).
    pub fn net_deny_bind_port(mut self, port: u16) -> Self {
        self.net_deny_bind.push(port.to_string());
        self
    }

    /// Deny binding TCP ports from a spec: a comma-separated list of single
    /// ports or inclusive `lo-hi` ranges (e.g. `"8080,9000-9005"`). The
    /// inverse of [`net_allow_bind`](Self::net_allow_bind).
    pub fn net_deny_bind(mut self, spec: impl Into<String>) -> Self {
        self.net_deny_bind.push(spec.into());
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

    /// Declare a named credential: `name` and a `source` (`env:`/`file:`/`fd:`).
    pub fn credential(mut self, name: &str, source: &str) -> Self {
        self.credentials.push(format!("{name}={source}"));
        self
    }

    /// Declare a credential from a raw `NAME=SOURCE` spec (as the CLI parses it).
    pub fn credential_spec(mut self, spec: &str) -> Self {
        self.credentials.push(spec.to_string());
        self
    }

    /// Add a credential-injection rule (see the `--http-auth` field docs).
    pub fn http_auth(mut self, rule: &str) -> Self {
        self.http_auth.push(rule.to_string());
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

    pub fn http_inject_ca(mut self, path: impl Into<PathBuf>) -> Self {
        self.http_inject_ca.push(path.into());
        self
    }

    pub fn http_ca_out(mut self, path: impl Into<PathBuf>) -> Self {
        self.http_ca_out = Some(path.into());
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

    /// Add a read-only mount: the host path is visible at `virtual_path` for
    /// reading, but writes through it are denied (e.g. the host procfs mount).
    pub fn fs_mount_ro(mut self, virtual_path: impl Into<PathBuf>, host_path: impl Into<PathBuf>) -> Self {
        let virtual_path = virtual_path.into();
        self.fs_mount.push((virtual_path.clone(), host_path.into()));
        self.fs_mount_ro.push(virtual_path);
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

    /// Skip the seccomp user-notification supervisor. The sandbox keeps
    /// Landlock and the kernel-level deny filter but loses every
    /// supervisor-mediated feature (IP allowlist, resource limits, COW,
    /// chroot mediation, /proc virtualization, custom handlers). The
    /// kernel only permits one `SECCOMP_FILTER_FLAG_NEW_LISTENER` per
    /// task, so set this when nesting `Sandbox::run` inside an already-
    /// confined process; otherwise the inner seccomp install returns
    /// `EBUSY`.
    pub fn no_supervisor(mut self, v: bool) -> Self {
        self.no_supervisor = v;
        self
    }

    pub fn policy_fn(
        mut self,
        f: impl Fn(crate::policy_fn::SyscallEvent, &mut crate::policy_fn::PolicyContext) -> crate::policy_fn::Verdict + Send + Sync + 'static,
    ) -> Self {
        self.policy_fn = Some(std::sync::Arc::new(f));
        self
    }

    /// Run the sandboxed process as `uid`/`gid` via a single-entry user
    /// namespace map (no host privilege required).
    ///
    /// If `uid`/`gid` already match the process's real uid/gid at launch, no
    /// user namespace is created — the process already has that identity, so
    /// the request is satisfied without one (and without requiring unprivileged
    /// user namespaces to be available on the host).
    pub fn user(mut self, uid: u32, gid: u32) -> Self {
        self.user = Some(RunAs { uid, gid });
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

        // Reject disable(FsRefer): the kernel denies REFER (cross-directory
        // rename/link) by default in every ruleset even when REFER is not
        // handled. Controlled cross-directory rename within writable areas
        // works precisely *because* REFER is handled and granted on writable
        // paths (the Strict and Degradable states do this). Disabling REFER
        // un-handles it, which can only make rename stricter, never looser,
        // so it cannot do what disable() promises and is a footgun. Degrading
        // (allow_degraded) REFER is still meaningful and remains allowed.
        if self.protection_policy.state(Protection::FsRefer) == ProtectionState::Disabled {
            return Err(SandboxError::Invalid(
                "disable(Protection::FsRefer) is not permitted: Landlock denies \
                 REFER (cross-directory rename/link) by default even when it is \
                 not handled, so disabling it only tightens the sandbox, never \
                 loosens it. Remove the disable() call (use allow_degraded() if \
                 you wanted REFER enforced only where the kernel supports it)."
                    .into(),
            ));
        }

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

        // --http-inject-ca / --http-ca-out are meaningless without an HTTP ACL
        // proxy to do MITM, which only spawns when http rules exist.
        let has_http_rules = !self.http_allow.is_empty() || !self.http_deny.is_empty();
        if !self.http_inject_ca.is_empty() && !has_http_rules {
            return Err(SandboxError::Invalid(
                "--http-inject-ca requires --http-allow or --http-deny".into(),
            ));
        }
        // --http-ca-out needs an actual CA to export (BYO or generated).
        if self.http_ca_out.is_some()
            && self.http_ca.is_none()
            && self.http_inject_ca.is_empty()
        {
            return Err(SandboxError::Invalid(
                "--http-ca-out requires --http-ca or --http-inject-ca".into(),
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

        // Credential injection happens inside the ACL proxy, so it needs the
        // proxy to run at all (i.e. some http rule). Injecting into HTTPS
        // additionally needs a CA (--http-ca / --http-inject-ca) to MITM 443;
        // without one only plaintext HTTP is intercepted. Reject a rule that
        // could never fire (no proxy).
        if !self.http_auth.is_empty() && http_allow.is_empty() && http_deny.is_empty() {
            return Err(SandboxError::Invalid(
                "--http-auth requires an HTTP ACL proxy (--http-allow or --http-deny); \
                 HTTPS injection additionally needs --http-ca or --http-inject-ca"
                    .into(),
            ));
        }
        // Without a CA only port 80 is intercepted, so a rule for an HTTPS host
        // (the common case: `bearer openai` → api.openai.com:443) silently never
        // fires — the request bypasses the proxy and goes out uncredentialed. We
        // can't know a rule's scheme at build time, so warn rather than reject.
        if !self.http_auth.is_empty() && self.http_ca.is_none() && self.http_inject_ca.is_empty() {
            eprintln!(
                "sandlock: warning: --http-auth with no CA (--http-ca/--http-inject-ca) only \
                 injects into plaintext HTTP (port 80); requests to HTTPS hosts bypass the proxy \
                 and are sent without the credential"
            );
        }
        // A `file:` credential is the one source with no automatic backstop:
        // `env:` vars are stripped from the child and `fd:` is read through a
        // dup, but a secret file sitting inside any grant that lets the child
        // reach it is `cat`-able directly. We can't safely auto-deny (the grant
        // is often a broad dir the workload needs), so warn on the overlap. Every
        // exposing grant is covered: read grants, write grants (write access
        // includes read), bind-mounted host dirs, and the chroot root (visible
        // regardless of Landlock). An fs-deny covering the file suppresses the
        // warning, so following its own advice actually silences it.
        for c in &self.credentials {
            let Some(path) = c.split_once('=').and_then(|(_, s)| s.strip_prefix("file:")) else {
                continue;
            };
            let grants = self
                .fs_readable
                .iter()
                .chain(self.fs_writable.iter())
                .chain(self.fs_mount.iter().map(|(_, host)| host))
                .chain(self.chroot.as_ref());
            if let Some(exposure) = exposing_grant(
                std::path::Path::new(path),
                grants,
                &self.fs_denied,
                self.chroot.as_deref(),
            ) {
                eprintln!(
                    "sandlock: warning: credential file {} is inside the sandbox grant {}; \
                     the sandboxed child can read the secret directly; keep it outside every \
                     fs grant (or add `--fs-deny {}` to close it)",
                    path,
                    exposure.grant.display(),
                    exposure.deny_target.display(),
                );
            }
        }
        // Resolve credentials + injection rules, loading each secret into the
        // supervisor. Wrapped in Arc so it flows to the proxy without cloning
        // the (deliberately non-Clone) secrets. `inject_env_strip` is the set of
        // `env:` var names to remove from the child, so an env-sourced secret
        // can't just be read out of the child's own environment.
        let (inject_rules, inject_env_strip) =
            crate::credential::resolve_inject_rules(&self.credentials, &self.http_auth)?;
        let inject = std::sync::Arc::new(inject_rules);

        // Default HTTP intercept ports: 80 always, 443 when HTTPS CA is configured.
        let http_ports = if self.http_ports.is_empty() && (!http_allow.is_empty() || !http_deny.is_empty()) {
            let mut ports = vec![80];
            if self.http_ca.is_some() || !self.http_inject_ca.is_empty() {
                ports.push(443);
            }
            ports
        } else {
            self.http_ports
        };

        // Parse user-supplied --net-allow specs. A scheme-less spec
        // covers TCP and UDP, so one spec can yield two rules.
        let mut net_allow: Vec<NetAllow> = Vec::new();
        for s in self.net_allow {
            net_allow.extend(NetRule::parse_allow(&s)?);
        }

        // Parse --net-deny rules, expanded the same way.
        let mut net_deny: Vec<NetDeny> = Vec::new();
        for s in self.net_deny {
            net_deny.extend(NetRule::parse_deny(&s)?);
        }

        // --net-allow and --net-deny are mutually exclusive. Check the
        // user-supplied allow count (the original specs), not the post-HTTP
        // extension, so a coexisting --http-deny does not false-trigger.
        if !net_allow.is_empty() && !net_deny.is_empty() {
            return Err(SandboxError::Invalid(
                "--net-allow and --net-deny are mutually exclusive".into(),
            ));
        }

        // Expand bind port specs. --net-allow-bind (default-deny allowlist)
        // and --net-deny-bind (default-allow denylist) are contradictory.
        let net_allow_bind = parse_allow_bind_ports(&self.net_allow_bind, "--net-allow-bind")?;
        let net_deny_bind = parse_bind_ports(&self.net_deny_bind, "--net-deny-bind")?;
        if !net_allow_bind.is_default() && !net_deny_bind.is_empty() {
            return Err(SandboxError::Invalid(
                "--net-allow-bind and --net-deny-bind are mutually exclusive".into(),
            ));
        }

        crate::http::extend_net_allow_for_http(
            &mut net_allow,
            &http_allow,
            &http_deny,
            &http_ports,
        );

        Ok(Sandbox {
            fs_writable: self.fs_writable,
            fs_readable: self.fs_readable,
            fs_denied: self.fs_denied,
            extra_deny_syscalls: self.extra_deny_syscalls,
            extra_allow_syscalls: self.extra_allow_syscalls,
            protection_policy: self.protection_policy,
            net_allow,
            net_deny,
            net_allow_bind,
            net_deny_bind,
            http_allow,
            http_deny,
            inject,
            inject_env_strip,
            http_ports,
            http_ca: self.http_ca,
            http_key: self.http_key,
            http_inject_ca: self.http_inject_ca,
            http_ca_out: self.http_ca_out,
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
            workdir: self.workdir,
            cwd: self.cwd,
            fs_storage: self.fs_storage,
            max_disk: self.max_disk,
            on_exit: self.on_exit.unwrap_or_default(),
            on_error: self.on_error.unwrap_or_default(),
            fs_mount: self.fs_mount,
            fs_mount_ro: self.fs_mount_ro,
            chroot: self.chroot,
            in_child_main: None,
            clean_env: self.clean_env,
            env: self.env,
            gpu_devices: self.gpu_devices,
            cpu_cores: self.cpu_cores,
            num_cpus: self.num_cpus,
            port_remap: self.port_remap,
            no_supervisor: self.no_supervisor,
            user: self.user,
            policy_fn: self.policy_fn,
            name: self.name,
            init_fn: self.init_fn,
            work_fn: self.work_fn,
            runtime: None,
            restore_skipped: Vec::new(),
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

/// An fs grant that exposes a credential file to the sandboxed child, with the
/// path an operator should hand `--fs-deny` to actually close the hole.
struct Exposure {
    /// The first fs grant that reaches the secret (named in the diagnostic).
    grant: std::path::PathBuf,
    /// What `--fs-deny` must target to suppress this: the host path normally,
    /// but the in-jail (virtual) path under chroot, where the notif layer
    /// matches `--fs-deny` values as virtual prefixes (`ChrootCtx::is_denied`).
    deny_target: std::path::PathBuf,
}

/// The first fs grant that exposes `secret` to the sandboxed child, or `None`
/// when no grant reaches it or an fs-deny covers it (the deny closes the hole,
/// so no warning is due). Best-effort: canonicalize where possible.
///
/// `chroot` is the jail root when running chrooted. In that mode `--fs-deny`
/// values are matched as in-jail (virtual) prefixes, not host paths, so the
/// deny suppression and the advised deny path are computed in the virtual
/// namespace: a host-path deny like `/jail/etc/token` would silence the warning
/// here yet never fire at runtime (the child opens `/etc/token`).
fn exposing_grant<'a>(
    secret: &std::path::Path,
    grants: impl Iterator<Item = &'a std::path::PathBuf>,
    denies: &[std::path::PathBuf],
    chroot: Option<&std::path::Path>,
) -> Option<Exposure> {
    let secret_abs = secret.canonicalize();
    let secret_ref = secret_abs.as_deref().unwrap_or(secret);

    // Whether the child's view of the secret is host-native or in-jail, and the
    // path a matching `--fs-deny` targets. Under chroot the secret at host
    // `<root>/etc/token` appears to the child at `/etc/token`; a deny is matched
    // against that virtual path, so translate before testing.
    let (deny_target, deny_is_virtual) = match chroot {
        Some(root) => {
            let root_abs = root.canonicalize();
            let root_ref = root_abs.as_deref().unwrap_or(root);
            match secret_ref.strip_prefix(root_ref) {
                Ok(sub) => (std::path::Path::new("/").join(sub), true),
                // Secret lives outside the jail: chroot can't expose it, but a
                // host grant still might, so keep host-path deny semantics.
                Err(_) => (secret_ref.to_path_buf(), false),
            }
        }
        None => (secret_ref.to_path_buf(), false),
    };

    let covered_by_deny = |d: &std::path::PathBuf| {
        if deny_is_virtual {
            // Virtual prefix match mirroring `ChrootCtx::is_denied`. No
            // canonicalize: an in-jail path need not exist on the host.
            deny_target.starts_with(d)
        } else {
            let abs = d.canonicalize();
            deny_target.starts_with(abs.as_deref().unwrap_or(d.as_path()))
        }
    };
    if denies.iter().any(covered_by_deny) {
        return None;
    }

    // Grant overlap stays host-native: the file physically sits inside the
    // grant (chroot root, bind-mount host dir, or read/write grant).
    let covered_by_grant = |g: &std::path::PathBuf| {
        let abs = g.canonicalize();
        secret_ref.starts_with(abs.as_deref().unwrap_or(g.as_path()))
    };
    let grant = grants.into_iter().find(|g| covered_by_grant(g)).cloned()?;
    Some(Exposure { grant, deny_target })
}

#[cfg(test)]
mod tests {
    use super::exposing_grant;
    use std::path::PathBuf;

    #[test]
    fn exposing_grant_reports_overlap_and_fs_deny_suppresses() {
        let dir = std::env::temp_dir().join(format!("sandlock-grant-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("key.txt");
        std::fs::write(&secret, "s").unwrap();
        let grants = vec![dir.clone()];
        let found = |denies: &[PathBuf]| {
            exposing_grant(&secret, grants.iter(), denies, None).map(|e| e.grant)
        };

        // Inside a read grant: the exposing grant is reported.
        assert_eq!(found(&[]), Some(dir.clone()));
        // An fs-deny on the file itself, or on a covering directory, closes the
        // hole: following the warning's own advice must silence it.
        assert_eq!(found(std::slice::from_ref(&secret)), None);
        assert_eq!(found(std::slice::from_ref(&dir)), None);
        // A deny elsewhere does not suppress the warning.
        assert_eq!(found(&[PathBuf::from("/nonexistent-deny")]), Some(dir.clone()));
        // Outside every grant: nothing to report.
        let other = vec![PathBuf::from("/nonexistent-grant")];
        assert_eq!(exposing_grant(&secret, other.iter(), &[], None).map(|e| e.grant), None);

        let _ = std::fs::remove_file(&secret);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn exposing_grant_chroot_deny_uses_virtual_namespace() {
        // Jail root with the secret at <root>/etc/token; the child sees it at
        // the in-jail path /etc/token, which is also what --fs-deny matches.
        let root = std::env::temp_dir().join(format!("sandlock-jail-{}", std::process::id()));
        let etc = root.join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        let secret = etc.join("token");
        std::fs::write(&secret, "s").unwrap();
        let grants = vec![root.clone()];
        let chroot = Some(root.as_path());
        let virtual_path = PathBuf::from("/etc/token");

        // The whole jail is visible: the chroot root grant is reported, and the
        // advised deny path is the in-jail path, not the host path.
        let exposure = exposing_grant(&secret, grants.iter(), &[], chroot).unwrap();
        assert_eq!(exposure.grant, root);
        assert_eq!(exposure.deny_target, virtual_path);

        // Denying the in-jail path (what the notif layer actually matches, and
        // what the warning now advises) suppresses it.
        assert!(exposing_grant(&secret, grants.iter(), &[virtual_path.clone()], chroot).is_none());
        // Denying a covering in-jail directory also suppresses.
        assert!(
            exposing_grant(&secret, grants.iter(), &[PathBuf::from("/etc")], chroot).is_none()
        );
        // The old advice (the host path) does NOT suppress: at runtime the child
        // opens /etc/token, so a /jail/etc/token deny never fires. This is the
        // regression the fix closes.
        assert!(
            exposing_grant(&secret, grants.iter(), std::slice::from_ref(&secret), chroot).is_some()
        );

        let _ = std::fs::remove_file(&secret);
        let _ = std::fs::remove_dir(&etc);
        let _ = std::fs::remove_dir(&root);
    }
}
