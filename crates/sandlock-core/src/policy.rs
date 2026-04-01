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
    pub deterministic_dirs: bool,

    // Filesystem branch
    pub fs_isolation: FsIsolation,
    pub workdir: Option<PathBuf>,
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

    // Mode flags
    pub privileged: bool,

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
    deterministic_dirs: bool,

    fs_isolation: Option<FsIsolation>,
    workdir: Option<PathBuf>,
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

    privileged: bool,
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

    pub fn privileged(mut self, v: bool) -> Self {
        self.privileged = v;
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
            deterministic_dirs: self.deterministic_dirs,
            fs_isolation,
            workdir: self.workdir,
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
            privileged: self.privileged,
            policy_fn: self.policy_fn,
        })
    }
}
