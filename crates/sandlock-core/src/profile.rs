use crate::sandbox::{ByteSize, Sandbox};
use crate::error::SandlockError;
use serde::Deserialize;
use std::path::PathBuf;
use std::collections::HashMap;
use std::time::SystemTime;

/// Program identity supplied by a profile alongside the policy.
/// Not a `Sandbox` field — passed separately to the sandbox runner.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProgramSpec {
    pub exec: Option<PathBuf>,
    pub args: Vec<String>,
}

/// Top-level profile input. Each section maps to one schema section.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct ProfileInput {
    pub config: ConfigSection,
    pub determinism: DeterminismSection,
    pub program: ProgramSection,
    pub filesystem: FilesystemSection,
    pub network: NetworkSection,
    pub http: HttpSection,
    pub syscalls: SyscallsSection,
    pub limits: LimitsSection,
}

// Field names follow the schema vocabulary and match `Sandbox`'s field names 1:1.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct ConfigSection {
    pub http_ca: Option<PathBuf>,
    pub http_key: Option<PathBuf>,
    pub http_inject_ca: Vec<PathBuf>,
    pub http_ca_out: Option<PathBuf>,
    pub fs_storage: Option<PathBuf>,
    pub workdir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct DeterminismSection {
    pub random_seed: Option<u64>,
    /// RFC3339 timestamp string. Maps to `Sandbox::time_start`.
    pub time_start: Option<String>,
    pub deterministic_dirs: bool,
    pub no_randomize_memory: bool,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct ProgramSection {
    pub exec: Option<PathBuf>,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub clean_env: bool,
    pub no_coredump: bool,
    pub no_huge_pages: bool,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct FilesystemSection {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub deny: Vec<PathBuf>,
    pub chroot: Option<PathBuf>,
    /// Each entry has the form `"VIRTUAL:HOST"`, matching `--fs-mount` syntax.
    pub mount: Vec<String>,
    /// One of `"commit"`, `"abort"`, `"keep"`. Maps to `Sandbox::on_exit`.
    pub on_exit: Option<String>,
    /// One of `"commit"`, `"abort"`, `"keep"`. Maps to `Sandbox::on_error`.
    pub on_error: Option<String>,
}

/// One `[network].allow_bind` entry: a bare integer port (`8080`) or a
/// quoted string holding a comma list and/or `lo-hi` range (`"9000-9005"`).
/// The untagged form lets a TOML array mix the two, e.g.
/// `allow_bind = [8080, "9000-9005"]`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum PortSpec {
    Port(u16),
    Spec(String),
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkSection {
    pub allow_bind: Vec<PortSpec>,
    pub deny_bind: Vec<PortSpec>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub port_remap: bool,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct HttpSection {
    pub ports: Vec<u16>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct SyscallsSection {
    pub extra_allow: Vec<String>,
    pub extra_deny: Vec<String>,
}

// Field names drop the `max_` prefix that `Sandbox` uses (`memory`, not
// `max_memory`) — the section name `[limits]` makes the prefix redundant.
// `parse_input` maps each of these to the corresponding `Sandbox::max_*` field.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsSection {
    /// `ByteSize` string, e.g. `"512M"` (suffixes K/M/G only; IEC `MiB`/`GiB`
    /// not yet supported). Maps to `Sandbox::max_memory`.
    pub memory: Option<String>,
    pub processes: Option<u32>,
    pub open_files: Option<u32>,
    /// CPU cap as a percentage (0–100). Maps to `Sandbox::max_cpu`.
    pub cpu: Option<u8>,
    /// `ByteSize` string, e.g. `"256M"` (suffixes K/M/G only; IEC `MiB`/`GiB`
    /// not yet supported). Maps to `Sandbox::max_disk`.
    pub disk: Option<String>,
    pub gpu_devices: Option<Vec<u32>>,
    pub cpu_cores: Option<Vec<u32>>,
    pub num_cpus: Option<u32>,
}

/// Convert a parsed `ProfileInput` into a `(Sandbox, ProgramSpec)` pair.
///
/// Forwards each schema section's fields to the corresponding `SandboxBuilder`
/// method calls. The two private helpers (`parse_branch_action`,
/// `parse_mount_spec`) handle string-to-typed-value conversions for fields
/// that lack `FromStr` impls on their target types.
pub fn parse_input(input: ProfileInput) -> Result<(Sandbox, ProgramSpec), SandlockError> {
    let mut b = Sandbox::builder();

    // [config]
    if let Some(p) = input.config.http_ca       { b = b.http_ca(p); }
    if let Some(p) = input.config.http_key      { b = b.http_key(p); }
    for p in input.config.http_inject_ca       { b = b.http_inject_ca(p); }
    if let Some(p) = input.config.http_ca_out  { b = b.http_ca_out(p); }
    if let Some(p) = input.config.fs_storage    { b = b.fs_storage(p); }
    if let Some(p) = input.config.workdir       { b = b.workdir(p); }

    // [determinism]
    if let Some(s) = input.determinism.random_seed { b = b.random_seed(s); }
    if let Some(s) = input.determinism.time_start.as_deref() {
        b = b.time_start(parse_time_start(s)?);
    }
    if input.determinism.deterministic_dirs        { b = b.deterministic_dirs(true); }
    if input.determinism.no_randomize_memory       { b = b.no_randomize_memory(true); }

    // [program] — process knobs go to Sandbox; exec/args go to ProgramSpec.
    for (k, v) in input.program.env.iter() { b = b.env_var(k, v); }
    if let Some(c) = input.program.cwd             { b = b.cwd(c); }
    match (input.program.uid, input.program.gid) {
        (Some(u), Some(g)) => b = b.user(u, g),
        (None, None) => {}
        _ => return Err(SandlockError::Sandbox(crate::error::SandboxError::Invalid(
            "program.uid and program.gid must both be set".into(),
        ))),
    }
    if input.program.clean_env                     { b = b.clean_env(true); }
    if input.program.no_coredump                   { b = b.no_coredump(true); }
    if input.program.no_huge_pages                 { b = b.no_huge_pages(true); }

    // [filesystem]
    for p in input.filesystem.read.iter()  { b = b.fs_read(p); }
    for p in input.filesystem.write.iter() { b = b.fs_write(p); }
    for p in input.filesystem.deny.iter()  { b = b.fs_deny(p); }
    if let Some(c) = input.filesystem.chroot         { b = b.chroot(c); }
    for spec in input.filesystem.mount.iter() {
        let (virt, host, read_only) = parse_mount_spec(spec)?;
        b = if read_only { b.fs_mount_ro(virt, host) } else { b.fs_mount(virt, host) };
    }
    if let Some(s) = input.filesystem.on_exit.as_deref()  { b = b.on_exit(parse_branch_action(s)?); }
    if let Some(s) = input.filesystem.on_error.as_deref() { b = b.on_error(parse_branch_action(s)?); }

    // [network]
    for entry in input.network.allow_bind.iter() {
        b = match entry {
            PortSpec::Port(p) => b.net_allow_bind_port(*p),
            PortSpec::Spec(s) => b.net_allow_bind(s),
        };
    }
    for entry in input.network.deny_bind.iter() {
        b = match entry {
            PortSpec::Port(p) => b.net_deny_bind_port(*p),
            PortSpec::Spec(s) => b.net_deny_bind(s),
        };
    }
    for r in input.network.allow.iter() { b = b.net_allow(r.as_str()); }
    for r in input.network.deny.iter()  { b = b.net_deny(r.as_str()); }
    if input.network.port_remap         { b = b.port_remap(true); }

    // [http]
    for p in input.http.ports.iter() { b = b.http_port(*p); }
    for r in input.http.allow.iter() { b = b.http_allow(r); }
    for r in input.http.deny.iter()  { b = b.http_deny(r); }

    // [syscalls]
    if !input.syscalls.extra_allow.is_empty() {
        b = b.extra_allow_syscalls(input.syscalls.extra_allow);
    }
    if !input.syscalls.extra_deny.is_empty() {
        b = b.extra_deny_syscalls(input.syscalls.extra_deny);
    }

    // [limits]
    if let Some(s) = input.limits.memory.as_deref()    {
        b = b.max_memory(ByteSize::parse(s).map_err(SandlockError::Sandbox)?);
    }
    if let Some(n) = input.limits.processes            { b = b.max_processes(n); }
    if let Some(n) = input.limits.open_files           { b = b.max_open_files(n); }
    if let Some(p) = input.limits.cpu                  { b = b.max_cpu(p); }
    if let Some(s) = input.limits.disk.as_deref()      {
        b = b.max_disk(ByteSize::parse(s).map_err(SandlockError::Sandbox)?);
    }
    if let Some(g) = input.limits.gpu_devices  { b = b.gpu_devices(g); }
    if let Some(c) = input.limits.cpu_cores    { b = b.cpu_cores(c); }
    if let Some(n) = input.limits.num_cpus             { b = b.num_cpus(n); }

    let policy = b.build()?;
    let spec = ProgramSpec { exec: input.program.exec, args: input.program.args };
    Ok((policy, spec))
}

/// Parses an `[filesystem].on_exit` / `on_error` string into a `BranchAction`.
fn parse_branch_action(s: &str) -> Result<crate::sandbox::BranchAction, SandlockError> {
    use crate::error::SandboxError;
    use crate::sandbox::BranchAction;
    Ok(match s {
        "commit" => BranchAction::Commit,
        "abort"  => BranchAction::Abort,
        "keep"   => BranchAction::Keep,
        other    => return Err(SandlockError::Sandbox(SandboxError::Invalid(
            format!("invalid branch action {other:?}; expected \"commit\" | \"abort\" | \"keep\""),
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

/// Parses an RFC3339 timestamp string into `SystemTime`.
fn parse_time_start(s: &str) -> Result<SystemTime, SandlockError> {
    use crate::error::SandboxError;
    let ts: jiff::Timestamp = s.parse().map_err(|e| {
        SandlockError::Sandbox(SandboxError::Invalid(
            format!("invalid [determinism].time_start {s:?}: {e}"),
        ))
    })?;
    Ok(ts.into())
}

/// Default profile directory.
pub fn profile_dir() -> PathBuf {
    dirs_or_fallback().join("profiles")
}

fn dirs_or_fallback() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".config")
        })
        .join("sandlock")
}

/// Parse a TOML profile string into a Sandbox + ProgramSpec.
pub fn parse_profile(content: &str) -> Result<(Sandbox, ProgramSpec), SandlockError> {
    let input: ProfileInput = toml::from_str(content)
        .map_err(|e| SandlockError::Sandbox(crate::error::SandboxError::Invalid(
            format!("TOML parse error: {e}"),
        )))?;
    parse_input(input)
}

/// Load a profile by name.
pub fn load_profile(name: &str) -> Result<(Sandbox, ProgramSpec), SandlockError> {
    let path = profile_dir().join(format!("{}.toml", name));
    let content = std::fs::read_to_string(&path)
        .map_err(|e| SandlockError::Sandbox(crate::error::SandboxError::Invalid(
            format!("profile '{}': {}", name, e),
        )))?;
    parse_profile(&content)
}

/// List available profile names.
pub fn list_profiles() -> Result<Vec<String>, SandlockError> {
    let dir = profile_dir();
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
    fn list_profiles_empty_dir() {
        // With no profile dir, list_profiles() should return an empty vec.
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/sandlock-test-nonexistent");
        let profiles = list_profiles().unwrap();
        assert!(profiles.is_empty());
        std::env::remove_var("XDG_CONFIG_HOME");
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
        // 1 user rule (tcp://cache.internal:6379) + at least 1 http-port-derived
        // rule that the builder auto-merges (api.internal on http.ports). The
        // merge is the contract being verified here.
        assert!(policy.net_allow.len() >= 2);
        // allow_bind mixes a bare int port and a quoted range string.
        assert_eq!(policy.net_allow_bind, vec![8080, 9000, 9001, 9002]);
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
        assert!(policy.net_allow_bind.is_empty());
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
