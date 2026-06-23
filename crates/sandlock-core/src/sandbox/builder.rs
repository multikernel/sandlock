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
    /// or inclusive `lo-hi` ranges, e.g. `8080,9000-9005`. Repeatable.
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
    /// `:port`, or `*:port`. Validated at `build()` time so callers
    /// receive parse errors via the standard `SandboxBuilder` flow.
    ///
    /// Examples:
    /// - `.net_allow("api.openai.com:443")`: HTTPS to OpenAI only
    /// - `.net_allow("github.com:22,443")`: SSH and HTTPS to GitHub
    /// - `.net_allow(":8080")`: any IP on port 8080
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
    /// ports or inclusive `lo-hi` ranges (e.g. `"8080,9000-9005"`).
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

        // Parse user-supplied --net-allow specs.
        let mut net_allow: Vec<NetAllow> = self
            .net_allow
            .into_iter()
            .map(|s| NetRule::parse_allow(&s))
            .collect::<Result<_, _>>()?;

        // Parse --net-deny rules (one rule per spec).
        let net_deny: Vec<NetDeny> = self
            .net_deny
            .into_iter()
            .map(|s| NetRule::parse_deny(&s))
            .collect::<Result<_, _>>()?;

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
        let net_allow_bind = parse_bind_ports(&self.net_allow_bind, "--net-allow-bind")?;
        let net_deny_bind = parse_bind_ports(&self.net_deny_bind, "--net-deny-bind")?;
        if !net_allow_bind.is_empty() && !net_deny_bind.is_empty() {
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
