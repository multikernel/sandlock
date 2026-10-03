use crate::sandbox::{ByteSize, Sandbox};
use crate::error::SandlockError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::collections::HashMap;

/// Program identity supplied by a profile alongside the policy.
/// Not a `Sandbox` field — passed separately to the sandbox runner.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProgramSpec {
    pub exec: Option<PathBuf>,
    pub args: Vec<String>,
}

/// Top-level profile input. Each section maps to one schema section.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct ProfileInput {
    #[serde(skip_serializing_if = "is_default")]
    pub config: ConfigSection,
    #[serde(skip_serializing_if = "is_default")]
    pub determinism: DeterminismSection,
    #[serde(skip_serializing_if = "is_default")]
    pub program: ProgramSection,
    #[serde(skip_serializing_if = "is_default")]
    pub filesystem: FilesystemSection,
    #[serde(skip_serializing_if = "is_default")]
    pub network: NetworkSection,
    #[serde(skip_serializing_if = "is_default")]
    pub http: HttpSection,
    #[serde(skip_serializing_if = "is_default")]
    pub syscalls: SyscallsSection,
    #[serde(skip_serializing_if = "is_default")]
    pub limits: LimitsSection,
}

fn is_false(b: &bool) -> bool { !b }
fn is_default<T: Default + PartialEq>(v: &T) -> bool { *v == T::default() }

// Field names follow the schema vocabulary and match `Sandbox`'s field names 1:1.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct ConfigSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_ca: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_key: Option<PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub http_inject_ca: Vec<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_ca_out: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_storage: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workdir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct DeterminismSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_seed: Option<u64>,
    /// RFC3339 timestamp string. Maps to `Sandbox::time_start`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_start: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub deterministic_dirs: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub no_randomize_memory: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct ProgramSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "is_false")]
    pub clean_env: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub no_coredump: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub no_huge_pages: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct FilesystemSection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chroot: Option<PathBuf>,
    /// Each entry has the form `"VIRTUAL:HOST"`, matching `--fs-mount` syntax.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mount: Vec<String>,
    /// One of `"commit"`, `"abort"`, `"keep"`, `"defer"`. Maps to `Sandbox::on_exit`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_exit: Option<String>,
    /// One of `"commit"`, `"abort"`, `"keep"`, `"defer"`. Maps to `Sandbox::on_error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_error: Option<String>,
}

/// One `[network].allow_bind` entry: a bare integer port (`8080`) or a
/// quoted string holding a comma list and/or `lo-hi` range (`"9000-9005"`).
/// The untagged form lets a TOML array mix the two, e.g.
/// `allow_bind = [8080, "9000-9005"]`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum PortSpec {
    Port(u16),
    Spec(String),
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkSection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow_bind: Vec<PortSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny_bind: Vec<PortSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub port_remap: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct HttpSection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct SyscallsSection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_allow: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_deny: Vec<String>,
}

// Field names drop the `max_` prefix that `Sandbox` uses (`memory`, not
// `max_memory`) — the section name `[limits]` makes the prefix redundant.
// `parse_input` maps each of these to the corresponding `Sandbox::max_*` field.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsSection {
    /// `ByteSize` string, e.g. `"512M"` (suffixes K/M/G only; IEC `MiB`/`GiB`
    /// not yet supported). Maps to `Sandbox::max_memory`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_files: Option<u32>,
    /// CPU cap as a percentage (0–100). Maps to `Sandbox::max_cpu`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<u8>,
    /// `ByteSize` string, e.g. `"256M"` (suffixes K/M/G only; IEC `MiB`/`GiB`
    /// not yet supported). Maps to `Sandbox::max_disk`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_devices: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_cpus: Option<u32>,
}

impl ProfileInput {
    /// Serialize the profile to a TOML string.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }
}

/// Lazily resolves `${HOME}` so a profile that uses no variables still loads
/// on a host where home cannot be resolved.
struct Expander {
    /// Under chroot the grants are relative to the jail, so the only home
    /// sandlock can see is in the wrong namespace.
    chroot: bool,
    home: Option<String>,
}

impl Expander {
    fn new(chroot: bool) -> Self {
        Self { chroot, home: None }
    }

    fn path(&mut self, field: &str, p: &std::path::Path) -> Result<PathBuf, SandlockError> {
        Ok(PathBuf::from(self.text(field, &p.to_string_lossy())?))
    }

    fn text(&mut self, field: &str, s: &str) -> Result<String, SandlockError> {
        if !s.contains('$') && !s.starts_with('~') {
            return Ok(s.to_string());
        }
        if self.chroot {
            // Expanding anyway builds the rule from a host path that does not
            // exist in the jail, and Landlock then skips it in silence.
            return Err(SandlockError::Sandbox(crate::error::SandboxError::Invalid(
                format!(
                    "{field}: {s:?}: ${{HOME}} cannot be expanded under \
                     [filesystem].chroot, where paths name the jail rather than \
                     the host. Write the path as it exists inside the jail"
                ),
            )));
        }
        if self.home.is_none() {
            self.home = Some(crate::expand::resolve_home()?);
        }
        crate::expand::expand(s, self.home.as_deref().unwrap()).map_err(|e| match e {
            SandlockError::Sandbox(crate::error::SandboxError::Invalid(m)) => {
                SandlockError::Sandbox(crate::error::SandboxError::Invalid(format!("{field}: {m}")))
            }
            other => other,
        })
    }
}

/// A profile with `${HOME}` expanded and mount specs split, keyed by
/// `Sandbox` field names. The CLI builds from it and the SDKs receive it as
/// JSON, so no front end has a profile grammar of its own to drift.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct ResolvedProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_ca: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_key: Option<PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub http_inject_ca: Vec<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_ca_out: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_storage: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workdir: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_start: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub deterministic_dirs: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub no_randomize_memory: bool,

    #[serde(skip)]
    pub exec: Option<PathBuf>,
    #[serde(skip)]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "is_false")]
    pub clean_env: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub no_coredump: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub no_huge_pages: bool,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fs_readable: Vec<PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fs_writable: Vec<PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fs_denied: Vec<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chroot: Option<PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty", serialize_with = "pairs_as_map")]
    pub fs_mount: Vec<(PathBuf, PathBuf)>,
    #[serde(skip_serializing_if = "Vec::is_empty", serialize_with = "pairs_as_map")]
    pub fs_mount_ro: Vec<(PathBuf, PathBuf)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_exit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_error: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub net_allow_bind: Vec<PortSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub net_deny_bind: Vec<PortSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub net_allow: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub net_deny: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub port_remap: bool,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub http_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub http_allow: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub http_deny: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_allow_syscalls: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_deny_syscalls: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_memory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_processes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_open_files: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cpu: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_disk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_devices: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_cpus: Option<u32>,
}

fn pairs_as_map<S: serde::Serializer>(
    pairs: &[(PathBuf, PathBuf)],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(pairs.iter().map(|(k, v)| (k, v)))
}

/// Expand `${HOME}` and split mount specs; semantic checks wait for `build`.
pub fn resolve(input: ProfileInput) -> Result<ResolvedProfile, SandlockError> {
    let mut ex = Expander::new(input.filesystem.chroot.is_some());
    let paths = |ex: &mut Expander, field: &str, ps: Vec<PathBuf>| -> Result<Vec<PathBuf>, SandlockError> {
        ps.iter().map(|p| ex.path(field, p)).collect()
    };
    let path = |ex: &mut Expander, field: &str, p: Option<PathBuf>| -> Result<Option<PathBuf>, SandlockError> {
        p.map(|p| ex.path(field, &p)).transpose()
    };

    let mut fs_mount = Vec::new();
    let mut fs_mount_ro = Vec::new();
    for spec in input.filesystem.mount.iter() {
        let (virt, host, read_only) = parse_mount_spec(spec)?;
        // Expand after the split so a resolved value containing a colon
        // cannot be read as a spec separator.
        let pair = (ex.path("[filesystem].mount", &virt)?, ex.path("[filesystem].mount", &host)?);
        if read_only { fs_mount_ro.push(pair) } else { fs_mount.push(pair) }
    }

    let c = input.config;
    let d = input.determinism;
    let p = input.program;
    let f = input.filesystem;
    let l = input.limits;
    Ok(ResolvedProfile {
        http_ca: path(&mut ex, "[config].http_ca", c.http_ca)?,
        http_key: path(&mut ex, "[config].http_key", c.http_key)?,
        http_inject_ca: paths(&mut ex, "[config].http_inject_ca", c.http_inject_ca)?,
        http_ca_out: path(&mut ex, "[config].http_ca_out", c.http_ca_out)?,
        fs_storage: path(&mut ex, "[config].fs_storage", c.fs_storage)?,
        workdir: path(&mut ex, "[config].workdir", c.workdir)?,

        random_seed: d.random_seed,
        time_start: d.time_start,
        deterministic_dirs: d.deterministic_dirs,
        no_randomize_memory: d.no_randomize_memory,

        exec: path(&mut ex, "[program].exec", p.exec)?,
        args: p.args,
        env: p.env,
        cwd: path(&mut ex, "[program].cwd", p.cwd)?,
        uid: p.uid,
        gid: p.gid,
        clean_env: p.clean_env,
        no_coredump: p.no_coredump,
        no_huge_pages: p.no_huge_pages,

        fs_readable: paths(&mut ex, "[filesystem].read", f.read)?,
        fs_writable: paths(&mut ex, "[filesystem].write", f.write)?,
        fs_denied: paths(&mut ex, "[filesystem].deny", f.deny)?,
        chroot: path(&mut ex, "[filesystem].chroot", f.chroot)?,
        fs_mount,
        fs_mount_ro,
        on_exit: f.on_exit,
        on_error: f.on_error,

        net_allow_bind: input.network.allow_bind,
        net_deny_bind: input.network.deny_bind,
        net_allow: input.network.allow,
        net_deny: input.network.deny,
        port_remap: input.network.port_remap,

        http_ports: input.http.ports,
        http_allow: input.http.allow,
        http_deny: input.http.deny,

        extra_allow_syscalls: input.syscalls.extra_allow,
        extra_deny_syscalls: input.syscalls.extra_deny,

        max_memory: l.memory,
        max_processes: l.processes,
        max_open_files: l.open_files,
        max_cpu: l.cpu,
        max_disk: l.disk,
        gpu_devices: l.gpu_devices,
        cpu_cores: l.cpu_cores,
        num_cpus: l.num_cpus,
    })
}

impl ResolvedProfile {
    pub fn build(self) -> Result<(Sandbox, ProgramSpec), SandlockError> {
        let mut b = Sandbox::builder();

        if let Some(p) = self.http_ca     { b = b.http_ca(p); }
        if let Some(p) = self.http_key    { b = b.http_key(p); }
        for p in self.http_inject_ca      { b = b.http_inject_ca(p); }
        if let Some(p) = self.http_ca_out { b = b.http_ca_out(p); }
        if let Some(p) = self.fs_storage  { b = b.fs_storage(p); }
        if let Some(p) = self.workdir     { b = b.workdir(p); }

        if let Some(s) = self.random_seed { b = b.random_seed(s); }
        if let Some(s) = self.time_start.as_deref() {
            let t = crate::sandbox::parse_timestamp("[determinism].time_start", s)
                .map_err(SandlockError::Sandbox)?;
            b = b.time_start(t);
        }
        if self.deterministic_dirs        { b = b.deterministic_dirs(true); }
        if self.no_randomize_memory       { b = b.no_randomize_memory(true); }

        for (k, v) in self.env.iter()     { b = b.env_var(k, v); }
        if let Some(c) = self.cwd         { b = b.cwd(c); }
        match (self.uid, self.gid) {
            (Some(u), Some(g)) => b = b.user(u, g),
            (None, None) => {}
            _ => return Err(SandlockError::Sandbox(crate::error::SandboxError::Invalid(
                "program.uid and program.gid must both be set".into(),
            ))),
        }
        if self.clean_env                 { b = b.clean_env(true); }
        if self.no_coredump               { b = b.no_coredump(true); }
        if self.no_huge_pages             { b = b.no_huge_pages(true); }

        for p in self.fs_readable         { b = b.fs_read(p); }
        for p in self.fs_writable         { b = b.fs_write(p); }
        for p in self.fs_denied           { b = b.fs_deny(p); }
        if let Some(c) = self.chroot      { b = b.chroot(c); }
        for (v, h) in self.fs_mount       { b = b.fs_mount(v, h); }
        for (v, h) in self.fs_mount_ro    { b = b.fs_mount_ro(v, h); }
        if let Some(s) = self.on_exit.as_deref()  { b = b.on_exit(parse_branch_action("[filesystem].on_exit", s)?); }
        if let Some(s) = self.on_error.as_deref() { b = b.on_error(parse_branch_action("[filesystem].on_error", s)?); }

        for entry in self.net_allow_bind.iter() {
            b = match entry {
                PortSpec::Port(p) => b.net_allow_bind_port(*p),
                PortSpec::Spec(s) => b.net_allow_bind(s),
            };
        }
        for entry in self.net_deny_bind.iter() {
            b = match entry {
                PortSpec::Port(p) => b.net_deny_bind_port(*p),
                PortSpec::Spec(s) => b.net_deny_bind(s),
            };
        }
        for r in self.net_allow.iter()    { b = b.net_allow(r.as_str()); }
        for r in self.net_deny.iter()     { b = b.net_deny(r.as_str()); }
        if self.port_remap                { b = b.port_remap(true); }

        for p in self.http_ports.iter()   { b = b.http_port(*p); }
        for r in self.http_allow.iter()   { b = b.http_allow(r); }
        for r in self.http_deny.iter()    { b = b.http_deny(r); }

        if !self.extra_allow_syscalls.is_empty() { b = b.extra_allow_syscalls(self.extra_allow_syscalls); }
        if !self.extra_deny_syscalls.is_empty()  { b = b.extra_deny_syscalls(self.extra_deny_syscalls); }

        if let Some(s) = self.max_memory.as_deref() {
            b = b.max_memory(ByteSize::parse(s).map_err(SandlockError::Sandbox)?);
        }
        if let Some(n) = self.max_processes  { b = b.max_processes(n); }
        if let Some(n) = self.max_open_files { b = b.max_open_files(n); }
        if let Some(p) = self.max_cpu        { b = b.max_cpu(p); }
        if let Some(s) = self.max_disk.as_deref() {
            b = b.max_disk(ByteSize::parse(s).map_err(SandlockError::Sandbox)?);
        }
        if let Some(g) = self.gpu_devices    { b = b.gpu_devices(g); }
        if let Some(c) = self.cpu_cores      { b = b.cpu_cores(c); }
        if let Some(n) = self.num_cpus       { b = b.num_cpus(n); }

        let policy = b.build()?;
        Ok((policy, ProgramSpec { exec: self.exec, args: self.args }))
    }
}

/// Convert a parsed `ProfileInput` into a `(Sandbox, ProgramSpec)` pair.
pub fn parse_input(input: ProfileInput) -> Result<(Sandbox, ProgramSpec), SandlockError> {
    resolve(input)?.build()
}

/// Parses an `[filesystem].on_exit` / `on_error` string into a `BranchAction`.
fn parse_branch_action(field: &str, s: &str) -> Result<crate::sandbox::BranchAction, SandlockError> {
    use crate::error::SandboxError;
    use crate::sandbox::BranchAction;
    Ok(match s {
        "commit" => BranchAction::Commit,
        "abort"  => BranchAction::Abort,
        "keep"   => BranchAction::Keep,
        "defer"  => BranchAction::Defer,
        other    => return Err(SandlockError::Sandbox(SandboxError::Invalid(
            format!("{field}: invalid branch action {other:?}; expected \"commit\" | \"abort\" | \"keep\" | \"defer\""),
        ))),
    })
}

/// Parses a `"VIRTUAL:HOST"` mount spec string into a `(virtual, host)` pair.
/// Parse a `VIRTUAL:HOST` mount spec, with an optional trailing `:ro` (or the
/// default `:rw`) selecting a read-only mount. Returns
/// `(virtual_path, host_path, read_only)`.
pub fn parse_mount_spec(s: &str) -> Result<(PathBuf, PathBuf, bool), SandlockError> {
    use crate::error::SandboxError;
    let (body, read_only) = if let Some(b) = s.strip_suffix(":ro") {
        (b, true)
    } else if let Some(b) = s.strip_suffix(":rw") {
        (b, false)
    } else {
        (s, false)
    };
    let (virt, host) = body.split_once(':').ok_or_else(|| SandlockError::Sandbox(SandboxError::Invalid(
        format!("invalid mount spec {s:?}; expected \"VIRTUAL:HOST[:ro]\""),
    )))?;
    if virt.is_empty() || host.is_empty() {
        return Err(SandlockError::Sandbox(SandboxError::Invalid(
            format!("invalid mount spec {s:?}; both VIRTUAL and HOST must be non-empty"),
        )));
    }
    Ok((PathBuf::from(virt), PathBuf::from(host), read_only))
}

// ============================================================
// Reverse serialization: Sandbox -> ProfileInput (and JSON/TOML)
// ============================================================

/// Render a `BranchAction` as the profile string form.
fn branch_action_str(a: &crate::sandbox::BranchAction) -> &'static str {
    use crate::sandbox::BranchAction;
    match a {
        BranchAction::Commit => "commit",
        BranchAction::Abort => "abort",
        BranchAction::Keep => "keep",
        BranchAction::Defer => "defer",
    }
}

/// Render a `NetRule` back into the `--net-allow`/`--net-deny` string grammar.
/// This is the inverse of `SandboxBuilder::net_allow` / `net_deny` parsing.
pub fn format_net_rule(rule: &crate::sandbox::NetRule) -> String {
    use crate::sandbox::{NetTarget, Protocol};
    let target = match &rule.target {
        NetTarget::AnyIp => "*".to_string(),
        NetTarget::Host(h) => h.clone(),
        NetTarget::Cidr(c) => {
            // Bracket IPv6 only when a port suffix will follow, because a
            // bare addr:port is itself a valid IPv6 address.
            if matches!(c.addr, std::net::IpAddr::V6(_)) && !rule.all_ports {
                format!("[{}]", c)
            } else {
                c.to_string()
            }
        }
    };
    match rule.protocol {
        Protocol::Icmp => format!("icmp://{}", target),
        proto => {
            let scheme = if matches!(proto, Protocol::Udp) { "udp://" } else { "tcp://" };
            if rule.all_ports {
                format!("{}{}", scheme, target)
            } else {
                let ports: String = rule.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                format!("{}{}:{}", scheme, target, ports)
            }
        }
    }
}

/// Render an `HttpRule` back into `"METHOD host/path"` form.
pub(crate) fn format_http_rule(rule: &crate::http::HttpRule) -> String {
    format!("{} {}{}", rule.method, rule.host, rule.path)
}

/// Render a `BindPorts` value into the `PortSpec` list used by `[network]`.
fn bind_ports_to_specs(ports: &crate::sandbox::BindPorts) -> Vec<PortSpec> {
    use crate::sandbox::BindPorts;
    match ports {
        BindPorts::All => vec![PortSpec::Spec("*".to_string())],
        BindPorts::Ports(ps) => ps.iter().map(|p| PortSpec::Port(*p)).collect(),
    }
}

/// Render a `ByteSize` as the profile string form (e.g. `"512M"`).
fn byte_size_str(b: crate::sandbox::ByteSize) -> String {
    let n = b.0;
    if n == 0 {
        return "0".to_string();
    }
    if n % (1024 * 1024 * 1024) == 0 {
        format!("{}G", n / (1024 * 1024 * 1024))
    } else if n % (1024 * 1024) == 0 {
        format!("{}M", n / (1024 * 1024))
    } else if n % 1024 == 0 {
        format!("{}K", n / 1024)
    } else {
        format!("{}", n)
    }
}

/// Build a `ProfileInput` from a `Sandbox` (the effective policy).
///
/// This is the reverse of `parse_input`: it flattens the `Sandbox` dataclass
/// back into the sectioned profile shape so it can be serialized to JSON (the
/// control-socket `config` verb) or TOML (`sandlock inspect <name> --toml`).
///
/// Runtime-only kwargs (`policy_fn`, `init_fn`, `work_fn`) are not `Sandbox`
/// fields and so do not appear; the `config` handler emits a `"<callback>"`
/// marker for them separately.
///
/// `extra_denied` carries dynamic `policy_fn`-issued `deny_path()` calls so
/// the effective policy reflects runtime mutations (RFC acceptance criterion).
/// Collect rendered rule specs, dropping duplicates while preserving order.
fn dedup_rendered(rules: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    rules.filter(|r| seen.insert(r.clone())).collect()
}

pub fn sandbox_to_profile(s: &Sandbox, extra_denied: &[String]) -> ProfileInput {
    let mut mount_specs: Vec<String> = Vec::new();
    for (virt, host) in &s.fs_mount {
        let suffix = if s.fs_mount_ro.iter().any(|d| d == virt) { ":ro" } else { "" };
        // Render paths lossy; profile mount specs are strings.
        mount_specs.push(format!(
            "{}:{}{}",
            virt.to_string_lossy(),
            host.to_string_lossy(),
            suffix
        ));
    }

    let mut fs_deny: Vec<PathBuf> = s.fs_denied.clone();
    for d in extra_denied {
        let p = PathBuf::from(d);
        if !fs_deny.contains(&p) {
            fs_deny.push(p);
        }
    }

    // Distinct rules can render to the same spec: a scheme-less "*" expands
    // to a tcp://* + udp://* pair at parse time, so an explicit udp://* rule
    // next to it repeats the rendered form. List each spec once.
    let net_allow = dedup_rendered(s.net_allow.iter().map(format_net_rule));
    let net_deny = dedup_rendered(s.net_deny.iter().map(format_net_rule));
    let http_allow: Vec<String> = s.http_allow.iter().map(format_http_rule).collect();
    let http_deny: Vec<String> = s.http_deny.iter().map(format_http_rule).collect();

    ProfileInput {
        config: ConfigSection {
            http_ca: s.http_ca.clone(),
            http_key: s.http_key.clone(),
            http_inject_ca: s.http_inject_ca.clone(),
            http_ca_out: s.http_ca_out.clone(),
            fs_storage: s.fs_storage.clone(),
            workdir: s.workdir.clone(),
        },
        determinism: DeterminismSection {
            random_seed: s.random_seed,
            time_start: s.time_start.and_then(crate::sandbox::format_timestamp),
            deterministic_dirs: s.deterministic_dirs,
            no_randomize_memory: s.no_randomize_memory,
        },
        program: ProgramSection {
            exec: None,
            args: Vec::new(),
            env: s.env.clone(),
            cwd: s.cwd.clone(),
            uid: s.user.map(|u| u.uid),
            gid: s.user.map(|u| u.gid),
            clean_env: s.clean_env,
            no_coredump: s.no_coredump,
            no_huge_pages: s.no_huge_pages,
        },
        filesystem: FilesystemSection {
            // The COW upper dir grant is spawn-time plumbing, not user policy.
            read: s.fs_readable.iter()
                .filter(|p| Some(p.as_path()) != s.cow_upper.as_deref())
                .cloned()
                .collect(),
            write: s.fs_writable.clone(),
            deny: fs_deny,
            chroot: s.chroot.clone(),
            mount: mount_specs,
            on_exit: Some(branch_action_str(&s.on_exit).to_string()),
            on_error: Some(branch_action_str(&s.on_error).to_string()),
        },
        network: NetworkSection {
            allow_bind: bind_ports_to_specs(&s.net_allow_bind),
            deny_bind: s.net_deny_bind.iter().map(|p| PortSpec::Port(*p)).collect(),
            allow: net_allow,
            deny: net_deny,
            port_remap: s.port_remap,
        },
        http: HttpSection {
            ports: s.http_ports.clone(),
            allow: http_allow,
            deny: http_deny,
        },
        syscalls: SyscallsSection {
            extra_allow: s.extra_allow_syscalls.clone(),
            extra_deny: s.extra_deny_syscalls.clone(),
        },
        limits: LimitsSection {
            memory: s.max_memory.map(byte_size_str),
            processes: s.max_processes,
            open_files: s.max_open_files,
            cpu: s.max_cpu,
            disk: s.max_disk.map(byte_size_str),
            gpu_devices: s.gpu_devices.clone(),
            cpu_cores: s.cpu_cores.clone(),
            num_cpus: s.num_cpus,
        },
    }
}

/// Serialize a `Sandbox` to a TOML profile string.
pub fn sandbox_to_toml(s: &Sandbox, extra_denied: &[String]) -> Result<String, SandlockError> {
    let input = sandbox_to_profile(s, extra_denied);
    toml::to_string_pretty(&input).map_err(|e| SandlockError::Sandbox(crate::error::SandboxError::Invalid(
        format!("TOML serialize error: {e}"),
    )))
}

/// Serialize a `Sandbox` to a pretty JSON string (the `config` verb body).
pub fn sandbox_to_json(s: &Sandbox, extra_denied: &[String]) -> Result<String, SandlockError> {
    let input = sandbox_to_profile(s, extra_denied);
    serde_json::to_string_pretty(&input).map_err(|e| SandlockError::Sandbox(crate::error::SandboxError::Invalid(
        format!("JSON serialize error: {e}"),
    )))
}

/// Named profiles live only under the user's home, resolved as `${HOME}` is
/// inside profiles, so policy is never read from a shared or relative path.
pub fn profile_dir() -> Result<PathBuf, SandlockError> {
    Ok(PathBuf::from(crate::expand::resolve_home()?).join(".config/sandlock/profiles"))
}

fn parse_toml(content: &str) -> Result<ProfileInput, SandlockError> {
    toml::from_str(content)
        .map_err(|e| SandlockError::Sandbox(crate::error::SandboxError::Invalid(
            format!("TOML parse error: {e}"),
        )))
}

/// Parse a TOML profile string into a Sandbox + ProgramSpec.
pub fn parse_profile(content: &str) -> Result<(Sandbox, ProgramSpec), SandlockError> {
    parse_input(parse_toml(content)?)
}

/// Parse and fully validate a TOML profile, returning the form the SDKs
/// build from.
pub fn resolve_profile(content: &str) -> Result<ResolvedProfile, SandlockError> {
    let resolved = resolve(parse_toml(content)?)?;
    resolved.clone().build()?;
    Ok(resolved)
}

/// Load a profile by name.
pub fn load_profile(name: &str) -> Result<(Sandbox, ProgramSpec), SandlockError> {
    let path = profile_dir()?.join(format!("{}.toml", name));
    let content = std::fs::read_to_string(&path)
        .map_err(|e| SandlockError::Sandbox(crate::error::SandboxError::Invalid(
            format!("profile '{}': {}", name, e),
        )))?;
    parse_profile(&content)
}

/// List available profile names.
pub fn list_profiles() -> Result<Vec<String>, SandlockError> {
    let dir = profile_dir()?;
    if !dir.exists() { return Ok(Vec::new()); }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .map_err(|e| SandlockError::Sandbox(crate::error::SandboxError::Invalid(format!("read dir: {}", e))))? {
        if let Ok(entry) = entry {
            if let Some(name) = entry.path().file_stem() {
                if entry.path().extension().map_or(false, |e| e == "toml") {
                    names.push(name.to_string_lossy().into_owned());
                }
            }
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_profile_splits_mounts_under_sandbox_field_names() {
        let toml = r#"
            [filesystem]
            read = ["/usr"]
            mount = ["/w:/a:b:ro", "/v:/c:rw", "/u:/d"]
            [limits]
            memory = "64M"
            [network]
            allow_bind = [8080, "9000-9001"]
        "#;
        let json = serde_json::to_value(resolve_profile(toml).unwrap()).unwrap();
        assert_eq!(json, serde_json::json!({
            "fs_readable": ["/usr"],
            "fs_mount": {"/v": "/c", "/u": "/d"},
            "fs_mount_ro": {"/w": "/a:b"},
            "max_memory": "64M",
            "net_allow_bind": [8080, "9000-9001"],
        }));
    }

    #[test]
    fn resolve_profile_runs_build_validation() {
        // The SDKs build later, so a profile they are handed must already be
        // one the CLI would accept.
        for toml in [
            "[limits]\nmemory = \"lots\"",
            "[program]\nuid = 1000",
            "[filesystem]\nmount = [\"/w:/a\", \"/w:/b:ro\"]",
            "[filesystem]\non_exit = \"maybe\"",
        ] {
            assert!(resolve_profile(toml).is_err(), "accepted {toml:?}");
        }
    }

    #[test]
    fn parse_profile_refuses_home_under_chroot() {
        // Grants are relative to the jail, so a host home is the wrong
        // namespace: Landlock would drop the rule without a word.
        let toml = r#"
            [filesystem]
            chroot = "/jail"
            read = ["${HOME}/src"]
        "#;
        let err = parse_profile(toml).unwrap_err().to_string();
        assert!(err.contains("[filesystem].read"), "error was {err:?}");
        assert!(err.contains("chroot"), "error was {err:?}");
    }

    #[test]
    fn parse_profile_allows_chroot_without_variables() {
        let toml = r#"
            [filesystem]
            chroot = "/jail"
            read = ["/usr/lib"]
        "#;
        let (policy, _spec) = parse_profile(toml).unwrap();
        assert_eq!(policy.chroot, Some(PathBuf::from("/jail")));
    }

    #[test]
    fn parse_profile_expands_home_in_path_fields() {
        let home = crate::expand::resolve_home().unwrap();
        let toml = r#"
            [filesystem]
            read = ["${HOME}/src"]
            write = ["${HOME}/out"]
            mount = ["/work:${HOME}/host:ro"]

            [program]
            cwd = "${HOME}/src"
            args = ["${HOME}"]
        "#;
        let (policy, _spec) = parse_profile(toml).unwrap();
        assert_eq!(policy.fs_readable, vec![PathBuf::from(format!("{home}/src"))]);
        assert_eq!(policy.fs_writable, vec![PathBuf::from(format!("{home}/out"))]);
        assert_eq!(policy.cwd, Some(PathBuf::from(format!("{home}/src"))));
    }

    #[test]
    fn parse_profile_leaves_program_args_untouched() {
        let toml = r#"
            [program]
            args = ["${HOME}", "$PATH", "~/x"]
        "#;
        let (_policy, spec) = parse_profile(toml).unwrap();
        assert_eq!(spec.args, vec!["${HOME}", "$PATH", "~/x"]);
    }

    #[test]
    fn parse_profile_reports_the_offending_field() {
        let toml = r#"
            [filesystem]
            read = ["${NOPE}/src"]
        "#;
        let err = parse_profile(toml).unwrap_err().to_string();
        assert!(err.contains("[filesystem].read"), "error was {err:?}");
        assert!(err.contains("unknown variable"), "error was {err:?}");
    }

    #[test]
    fn parse_profile_without_variables_never_resolves_home() {
        // A profile with no variables must load even where HOME cannot be
        // resolved, so resolution has to stay lazy.
        let toml = r#"
            [filesystem]
            read = ["/usr/lib"]
        "#;
        let (policy, _spec) = parse_profile(toml).unwrap();
        assert_eq!(policy.fs_readable, vec![PathBuf::from("/usr/lib")]);
    }

    #[test]
    fn sandbox_to_profile_hides_cow_upper_grant() {
        // Simulate the spawn-time upper grant: pushed into fs_readable with
        // cow_upper recording which entry is internal.
        let mut sb = crate::Sandbox::builder().fs_read("/usr").build().unwrap();
        let upper = PathBuf::from("/run/user/1000/sandlock-cow/deadbeef/upper");
        sb.fs_readable.push(upper.clone());
        sb.cow_upper = Some(upper.clone());

        let profile = sandbox_to_profile(&sb, &[]);
        assert!(profile.filesystem.read.contains(&PathBuf::from("/usr")));
        assert!(
            !profile.filesystem.read.contains(&upper),
            "internal COW upper grant leaked into profile: {:?}",
            profile.filesystem.read
        );
    }

    #[test]
    fn profile_dir_is_under_home() {
        let home = crate::expand::resolve_home().unwrap();
        assert_eq!(
            profile_dir().unwrap(),
            PathBuf::from(home).join(".config/sandlock/profiles")
        );
    }

    #[test]
    fn profile_input_deserializes_minimal() {
        let toml = r#"
            [program]
            exec = "/bin/true"
        "#;
        let parsed: ProfileInput = toml::from_str(toml).unwrap();
        assert_eq!(parsed.program.exec, Some("/bin/true".into()));
        assert!(parsed.program.args.is_empty());
        assert_eq!(parsed.config, ConfigSection::default());
        assert_eq!(parsed.filesystem, FilesystemSection::default());
    }

    #[test]
    fn config_section_maps_to_policy_http_fields() {
        let toml = r#"
            [config]
            http_ca  = "/tmp/ca.pem"
            http_key = "/tmp/ca.key"
            [program]
            exec = "/bin/true"
        "#;
        let input: ProfileInput = toml::from_str(toml).unwrap();
        let (policy, _spec) = parse_input(input).unwrap();
        assert_eq!(policy.http_ca.as_deref(), Some(std::path::Path::new("/tmp/ca.pem")));
        assert_eq!(policy.http_key.as_deref(), Some(std::path::Path::new("/tmp/ca.key")));
    }

    #[test]
    fn parses_http_inject_ca_and_ca_out() {
        let toml = r#"
            [config]
            http_inject_ca = ["/etc/ssl/certs/ca-certificates.crt"]
            http_ca_out = "/tmp/ca.pem"
            [http]
            allow = ["GET example.com/*"]
            [program]
            exec = "/bin/true"
        "#;
        let input: ProfileInput = toml::from_str(toml).unwrap();
        let (policy, _prog) = parse_input(input).unwrap();
        assert_eq!(policy.http_inject_ca.len(), 1);
        assert_eq!(policy.http_ca_out.as_deref(), Some(std::path::Path::new("/tmp/ca.pem")));
    }

    #[test]
    fn syscalls_extra_allow_sysv_ipc_sets_vec() {
        let toml = r#"
            [program]
            exec = "/bin/true"
            [syscalls]
            extra_allow = ["sysv_ipc"]
            extra_deny  = ["ptrace"]
        "#;
        let input: ProfileInput = toml::from_str(toml).unwrap();
        let (policy, _spec) = parse_input(input).unwrap();
        assert!(policy.allows_sysv_ipc());
        assert_eq!(policy.extra_deny_syscalls, vec!["ptrace".to_string()]);
    }

    #[test]
    fn parse_mount_spec_ro_suffix() {
        let (v, h, ro) = parse_mount_spec("/work:/host").unwrap();
        assert_eq!((v.to_str().unwrap(), h.to_str().unwrap(), ro), ("/work", "/host", false));
        let (_, _, ro) = parse_mount_spec("/work:/host:rw").unwrap();
        assert!(!ro);
        let (v, h, ro) = parse_mount_spec("/work:/host:ro").unwrap();
        assert_eq!((v.to_str().unwrap(), h.to_str().unwrap(), ro), ("/work", "/host", true));
        // a host path containing colons still parses; only a trailing :ro/:rw is an option
        let (_, h, ro) = parse_mount_spec("/v:/a:b:ro").unwrap();
        assert_eq!((h.to_str().unwrap(), ro), ("/a:b", true));
        assert!(parse_mount_spec("nocolon").is_err());
    }

    #[test]
    fn parse_mount_spec_rejects_missing_colon() {
        let toml = r#"
            [program]
            exec = "/bin/true"
            [filesystem]
            mount = ["nocolon"]
        "#;
        let input: ProfileInput = toml::from_str(toml).unwrap();
        let err = parse_input(input).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("VIRTUAL:HOST"), "got: {msg}");
    }

    #[test]
    fn parse_mount_spec_rejects_empty_half() {
        let toml = r#"
            [program]
            exec = "/bin/true"
            [filesystem]
            mount = [":/host"]
        "#;
        let input: ProfileInput = toml::from_str(toml).unwrap();
        let err = parse_input(input).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("non-empty"), "got: {msg}");
    }

    #[test]
    fn parse_profile_full_example() {
        let toml = r#"
            [config]
            http_ca    = "/etc/sandlock/ca.pem"
            http_key   = "/etc/sandlock/ca.key"
            fs_storage = "/var/sandlock/redis-worker"
            workdir    = "/var/sandlock/redis-worker/work"

            [determinism]
            random_seed         = 42
            deterministic_dirs  = true
            no_randomize_memory = true

            [program]
            exec      = "/usr/bin/redis-cli"
            args      = ["-h", "cache.internal", "-p", "6379"]
            cwd       = "/var/lib/redis"
            uid       = 1000
            gid       = 1000
            clean_env = true
            no_coredump = true

            [filesystem]
            read      = ["/usr", "/etc/redis"]
            write     = ["/var/lib/redis/state"]
            deny      = ["/proc/sys"]
            chroot    = "/var/lib/redis-rootfs"
            mount     = ["/data:/srv/redis-data"]
            on_exit   = "commit"
            on_error  = "abort"

            [network]
            allow_bind = [8080, "9000-9002"]
            allow      = ["tcp://cache.internal:6379"]
            port_remap = true

            [http]
            ports = [80, 443]
            allow = ["GET api.internal/v1/*"]
            deny  = ["* */admin/*"]

            [syscalls]
            extra_allow = ["sysv_ipc"]
            extra_deny  = ["ptrace", "mount"]

            [limits]
            memory    = "512M"
            processes = 32
            cpu       = 80
        "#;

        let (policy, spec) = parse_profile(toml).unwrap();
        assert_eq!(spec.exec.as_deref(), Some(std::path::Path::new("/usr/bin/redis-cli")));
        assert_eq!(spec.args.len(), 4);
        assert!(policy.allows_sysv_ipc());
        assert_eq!(policy.extra_deny_syscalls.len(), 2);
        assert_eq!(policy.fs_readable.len(), 2);
        // 1 user rule only; HTTP reachability is generated at resolution time
        // and merged only at consumption (effective_net_allow), not stored:
        // 1 explicit TCP rule + 1 concrete HTTP host + 1 wildcard AnyIp rule.
        assert_eq!(policy.net_allow.len(), 1);
        assert_eq!(policy.effective_net_allow().len(), 3);
        // allow_bind mixes a bare int port and a quoted range string.
        assert_eq!(
            policy.net_allow_bind,
            crate::sandbox::BindPorts::Ports(vec![8080, 9000, 9001, 9002])
        );
        assert_eq!(policy.http_allow.len(), 1);
        assert_eq!(policy.fs_mount.len(), 1);
    }

    #[test]
    fn parse_profile_unknown_section_field_is_error() {
        let toml = r#"
            [program]
            exec = "/bin/true"
            bogus = 1
        "#;
        let err = parse_profile(toml).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown field"), "got: {msg}");
    }

    #[test]
    fn parse_profile_old_flat_format_is_error() {
        // Old format used top-level "fs_readable = [...]"; we no longer accept it.
        let toml = r#"
            fs_readable = ["/usr"]
        "#;
        let err = parse_profile(toml).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown field"), "got: {msg}");
    }

    #[test]
    fn parse_profile_time_start_sets_policy_field() {
        let toml = r#"
            [program]
            exec = "/bin/true"
            [determinism]
            time_start = "2026-01-01T00:00:00Z"
        "#;
        let (policy, _spec) = parse_profile(toml).unwrap();
        assert!(policy.time_start.is_some());
    }

    #[test]
    fn parse_profile_invalid_time_start_is_error() {
        let toml = r#"
            [program]
            exec = "/bin/true"
            [determinism]
            time_start = "not-a-time"
        "#;
        let err = parse_profile(toml).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("time_start"), "got: {msg}");
    }

    #[test]
    fn profile_time_start_round_trips_before_epoch_and_below_a_second() {
        for stamp in ["1969-07-20T20:17:00Z", "2026-01-01T00:00:00.9999999Z"] {
            let toml = format!(
                "[program]\nexec = \"/bin/true\"\n[determinism]\ntime_start = \"{stamp}\"\n"
            );
            let (policy, _spec) = parse_profile(&toml).unwrap();
            let rendered = sandbox_to_profile(&policy, &[]);
            assert_eq!(rendered.determinism.time_start.as_deref(), Some(stamp));
        }
    }

    #[test]
    fn profile_network_deny_parses() {
        let toml = r#"
            [network]
            deny = ["10.0.0.0/8", "192.168.0.0/16"]
        "#;
        let (policy, _spec) = parse_profile(toml).unwrap();
        assert!(policy.net_deny.len() > 1);
    }

    #[test]
    fn profile_network_deny_bind_parses() {
        // Mixed int + range string, same as allow_bind.
        let toml = r#"
            [network]
            deny_bind = [8080, "9000-9002"]
        "#;
        let (policy, _spec) = parse_profile(toml).unwrap();
        assert_eq!(policy.net_deny_bind, vec![8080, 9000, 9001, 9002]);
        assert!(policy.net_allow_bind.is_default());
    }

    #[test]
    fn profile_combined_network_policy_round_trips() {
        let toml = r#"
            [network]
            allow = ["tcp://127.0.0.1:443"]
            deny = ["10.0.0.0/8"]
            allow_bind = [8080]
            deny_bind = [9090]
        "#;
        let (policy, _) = parse_profile(toml).unwrap();
        let rendered = sandbox_to_profile(&policy, &[]);
        assert_eq!(rendered.network.allow.len(), 1);
        assert!(!rendered.network.deny.is_empty());
        assert_eq!(rendered.network.allow_bind, vec![PortSpec::Port(8080)]);
        assert_eq!(rendered.network.deny_bind, vec![PortSpec::Port(9090)]);

        let (round_tripped, _) = parse_input(rendered).unwrap();
        assert!(round_tripped.net_allow_is_active());
        assert_eq!(round_tripped.net_allow.len(), policy.net_allow.len());
        assert_eq!(round_tripped.net_deny.len(), policy.net_deny.len());
        assert_eq!(round_tripped.net_allow_bind, policy.net_allow_bind);
        assert_eq!(round_tripped.net_deny_bind, policy.net_deny_bind);
    }

    #[test]
    fn profile_deny_only_http_policy_does_not_promote_generated_allow_rules() {
        let toml = r#"
            [network]
            deny = ["10.0.0.0/8"]

            [http]
            allow = ["GET api.example.com/v1/*"]
        "#;
        let (policy, _) = parse_profile(toml).unwrap();
        assert!(policy.net_allow.is_empty());
        assert!(!policy.net_allow_is_active());
        assert_eq!(policy.effective_net_allow().len(), 1);

        let rendered = sandbox_to_profile(&policy, &[]);
        assert!(rendered.network.allow.is_empty());
        assert_eq!(rendered.http.allow, vec!["GET api.example.com/v1/*"]);

        let (round_tripped, _) = parse_input(rendered).unwrap();
        assert!(!round_tripped.net_allow_is_active());
        assert!(round_tripped.net_allow.is_empty());
        assert_eq!(round_tripped.effective_net_allow().len(), 1);
    }

    #[test]
    fn profile_http_only_round_trips_as_restrictive_allowlist() {
        let toml = r#"
            [http]
            allow = ["GET api.example.com/v1/*"]
        "#;
        let (policy, _) = parse_profile(toml).unwrap();
        assert!(policy.net_allow.is_empty());
        assert!(policy.net_allow_is_active());

        let rendered = sandbox_to_profile(&policy, &[]);
        assert!(rendered.network.allow.is_empty());
        assert_eq!(rendered.http.allow, vec!["GET api.example.com/v1/*"]);

        let (round_tripped, _) = parse_input(rendered).unwrap();
        assert!(round_tripped.net_allow.is_empty());
        assert!(round_tripped.net_allow_is_active());
        assert_eq!(
            round_tripped.effective_net_allow().len(),
            policy.effective_net_allow().len()
        );
    }

    #[test]
    fn profile_combined_http_round_trips_without_duplicating_derived_rules() {
        let toml = r#"
            [network]
            allow = ["tcp://127.0.0.1:443"]
            deny = ["10.0.0.0/8"]

            [http]
            allow = ["GET api.example.com/v1/*"]
        "#;
        let (policy, _) = parse_profile(toml).unwrap();
        assert_eq!(policy.net_allow.len(), 1);
        assert!(policy.net_allow_is_active());

        let rendered = sandbox_to_profile(&policy, &[]);
        assert_eq!(rendered.network.allow.len(), 1);
        assert_eq!(rendered.http.allow, vec!["GET api.example.com/v1/*"]);

        let (round_tripped, _) = parse_input(rendered).unwrap();
        assert_eq!(round_tripped.net_allow.len(), 1);
        assert_eq!(
            round_tripped.effective_net_allow().len(),
            policy.effective_net_allow().len()
        );
        assert!(round_tripped.net_allow_is_active());
    }

    #[test]
    fn isolation_key_is_rejected() {
        let toml = r#"
            [program]
            exec = "/bin/true"
            [filesystem]
            isolation = "none"
        "#;
        let err = parse_profile(toml).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown field"), "got: {msg}");
    }
}
