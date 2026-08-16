//! Canonical profile form: the TOML schema with every string micro-grammar
//! already resolved.
//!
//! [`ProfileInput`] is the raw schema: it mirrors the TOML file, so a mount is
//! still the string `"/data:/srv:ro"`, a size is still `"512M"` and a start
//! time is still an RFC 3339 stamp. Every consumer that wants the actual values
//! has to re-implement those grammars, and each re-implementation drifts.
//!
//! [`CanonicalProfile`] is the same section layout with the leaves resolved:
//! mounts are `{virt, host, ro}` objects, sizes are integer bytes, `time_start`
//! is epoch seconds, bind ports are expanded integer lists, net and HTTP rules
//! are structured records. A binding that consumes it only has to do structural
//! field mapping, and because both this type and [`ProfileInput`] reject unknown
//! keys, a schema change fails loudly at load time instead of being silently
//! mis-parsed.
//!
//! What this is not: it is not the *effective* policy. The builder derives extra
//! state at `build()` time (HTTP rules append host entries to the net allowlist,
//! `http.ports` materializes to `[80]`, `max_processes` defaults to 64). Those
//! derivations are deliberately absent here, because a consumer that maps this
//! form back into a builder would otherwise apply them a second time. Use
//! [`super::sandbox_to_json`] when the effective policy is what you want.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{SandboxError, SandlockError};
use crate::http::HttpRule;
use crate::network::{NetRule, NetTarget, Protocol};
use crate::sandbox::{BindPorts, BranchAction, ByteSize};

use super::{PortSpec, ProfileInput};

// ============================================================
// Canonical types
// ============================================================

/// A profile with every micro-grammar resolved. Section layout matches
/// [`ProfileInput`] one to one; only the leaf types differ.
///
/// Unlike [`ProfileInput`], which omits defaulted fields to keep a serialized
/// profile minimal, every field is always emitted. A consumer maps the shape
/// unconditionally, and a key that goes missing is a schema break rather than
/// an ambiguous "unset or absent".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanonicalProfile {
    pub config: CanonicalConfig,
    pub determinism: CanonicalDeterminism,
    pub program: CanonicalProgram,
    pub filesystem: CanonicalFilesystem,
    pub network: CanonicalNetwork,
    pub http: CanonicalHttp,
    pub syscalls: CanonicalSyscalls,
    pub limits: CanonicalLimits,
}

/// `[config]`: paths only, no grammar to resolve.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanonicalConfig {
    pub http_ca: Option<PathBuf>,
    pub http_key: Option<PathBuf>,
    pub http_inject_ca: Vec<PathBuf>,
    pub http_ca_out: Option<PathBuf>,
    pub fs_storage: Option<PathBuf>,
    pub workdir: Option<PathBuf>,
}

/// `[determinism]`, with `time_start` resolved from RFC 3339 to epoch time.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanonicalDeterminism {
    pub random_seed: Option<u64>,
    pub time_start: Option<CanonicalTimestamp>,
    pub deterministic_dirs: bool,
    pub no_randomize_memory: bool,
}

/// An epoch timestamp split into whole seconds and a non-negative
/// sub-second remainder.
///
/// `seconds` is signed because the profile grammar accepts pre-1970 stamps
/// (`"1969-01-01T00:00:00Z"` parses today). `nanoseconds` is carried
/// separately rather than truncated because the grammar also accepts
/// fractional seconds (`"...T00:00:00.5Z"`); dropping them here would make a
/// profile mean one thing through the CLI and another through a binding,
/// which is the exact class of drift this form exists to remove.
///
/// Normalization: `nanoseconds` is always in `[0, 1_000_000_000)`, so
/// `seconds` floors rather than truncating towards zero. Half a second before
/// the epoch is `{seconds: -1, nanoseconds: 500000000}`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

/// `[program]`: process knobs plus the program identity (`exec`/`args`),
/// which the effective-policy serializer drops but a profile consumer needs.
///
/// `env` is a sorted map: a hash map would give a different key order on every
/// run, and a canonical form has to be byte-stable.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanonicalProgram {
    pub exec: Option<PathBuf>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub clean_env: bool,
    pub no_coredump: bool,
    pub no_huge_pages: bool,
}

/// `[filesystem]`, with mount specs resolved and branch actions made explicit.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanonicalFilesystem {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub deny: Vec<PathBuf>,
    pub chroot: Option<PathBuf>,
    pub mount: Vec<CanonicalMount>,
    /// Always present. The profile grammar lets both branch actions default,
    /// and a consumer that supplies its own default for an absent key is free
    /// to pick a different one, which changes what happens to a COW branch
    /// without any error being raised. Resolving the default here means the
    /// contract lives in one place.
    pub on_exit: CanonicalBranchAction,
    pub on_error: CanonicalBranchAction,
}

/// One resolved `VIRTUAL:HOST[:ro|:rw]` mount spec.
///
/// `ro` is the effective read-only setting for `virt`, not the flag written on
/// this particular spec. The core keys read-only mounts by virtual path
/// (`Sandbox::fs_mount_ro` is a list of virtual paths), so two specs that share
/// a virtual path share one verdict: if any of them says `:ro`, writes through
/// that virtual path are denied for all of them. This form reports what the
/// sandbox will do rather than what the text said, which is also what
/// [`super::sandbox_to_profile`] prints when it re-emits the same policy as
/// specs.
///
/// Not modelled: read-only is enforced by virtual-path prefix, so a mount
/// nested under a read-only one is also write-denied at run time while its `ro`
/// here stays false. Distinguishing the two would need read-only to be keyed by
/// `(virt, host)` in the core, which this form cannot do on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalMount {
    pub virt: PathBuf,
    pub host: PathBuf,
    pub ro: bool,
}

/// `[filesystem].on_exit` / `on_error`, resolved from the three string literals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CanonicalBranchAction {
    #[default]
    Commit,
    Abort,
    Keep,
}

impl From<BranchAction> for CanonicalBranchAction {
    fn from(a: BranchAction) -> Self {
        match a {
            BranchAction::Commit => CanonicalBranchAction::Commit,
            BranchAction::Abort => CanonicalBranchAction::Abort,
            BranchAction::Keep => CanonicalBranchAction::Keep,
        }
    }
}

/// `[network]`, with bind ports expanded and rules structured.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanonicalNetwork {
    pub allow_bind: CanonicalBindPorts,
    /// `any` is always false here: the wildcard is an allow-only token and the
    /// grammar rejects it for deny. The shape is shared with `allow_bind` so a
    /// consumer needs one mapper, not two.
    pub deny_bind: CanonicalBindPorts,
    pub allow: Vec<CanonicalNetRule>,
    pub deny: Vec<CanonicalNetRule>,
    pub port_remap: bool,
}

/// A resolved bind-port list: either the `*` wildcard or an expanded,
/// sorted, deduplicated set of ports. Ranges (`"9000-9002"`) and comma
/// lists are already flattened.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanonicalBindPorts {
    /// The `*` wildcard: any port may be bound. `ports` is empty when set.
    pub any: bool,
    pub ports: Vec<u16>,
}

/// One resolved `--net-allow` / `--net-deny` rule.
///
/// A scheme-less profile entry names two protocols, so it resolves to two
/// rules here; the array length is not the profile array length.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalNetRule {
    pub protocol: Protocol,
    pub target: CanonicalNetTarget,
    /// Empty when `all_ports` is set, and always empty for ICMP.
    pub ports: Vec<u16>,
    pub all_ports: bool,
    /// The single-protocol spec string this rule round-trips through, rendered
    /// by the core formatter.
    ///
    /// The builder ABI takes net rules as spec strings, so a consumer that
    /// feeds a profile back into a builder needs one. Emitting it here keeps
    /// the grammar (including the IPv6 bracket rule) on this side: the
    /// consumer forwards an opaque string, it never composes one.
    pub spec: String,
}

/// What a net rule targets at the IP layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CanonicalNetTarget {
    /// Any destination IP (`*`, or a bare `:port`).
    Any,
    /// A hostname, resolved at sandbox start. Allow-only: the deny grammar
    /// rejects hostnames, so a deny rule never carries this variant.
    Host { host: String },
    /// A literal IP or a CIDR range. A bare IP arrives as a host route
    /// (`prefix_len` 32 or 128).
    Cidr { address: String, prefix_len: u8 },
}

/// `[http]`, with rules structured.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanonicalHttp {
    /// Ports exactly as written in the profile. The builder substitutes
    /// `[80]` (or `[80, 443]` with a CA) when this is empty; that derivation
    /// belongs to the effective policy, not to the profile.
    pub ports: Vec<u16>,
    pub allow: Vec<CanonicalHttpRule>,
    pub deny: Vec<CanonicalHttpRule>,
}

/// One resolved `"METHOD host[/path]"` rule: the method is already
/// upper-cased and the path already normalized (percent-decoded, `//`
/// collapsed, `.`/`..` resolved, trailing `*` preserved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalHttpRule {
    pub method: String,
    pub host: String,
    pub path: String,
    /// The rule re-rendered as a spec string, for the same reason as
    /// [`CanonicalNetRule::spec`]: the builder ABI takes HTTP rules as strings.
    pub spec: String,
}

/// `[syscalls]`.
///
/// Names are not expanded: `extra_allow` accepts group names only, so
/// substituting a group's members would produce a list the builder rejects.
/// `extra_deny` accepts both a group name and a bare syscall name, and its
/// validity is architecture dependent (the name table is per-target), which
/// is why this form resolves nothing here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanonicalSyscalls {
    pub extra_allow: Vec<String>,
    pub extra_deny: Vec<String>,
}

/// `[limits]`, with byte sizes resolved to integer bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanonicalLimits {
    pub memory: Option<u64>,
    pub disk: Option<u64>,
    pub processes: Option<u32>,
    pub open_files: Option<u32>,
    pub cpu: Option<u8>,
    pub gpu_devices: Option<Vec<u32>>,
    pub cpu_cores: Option<Vec<u32>>,
    pub num_cpus: Option<u32>,
}

// ============================================================
// Resolution
// ============================================================

/// Parse a TOML profile into its canonical form.
///
/// The profile goes through exactly the same pipeline a CLI user hits
/// (`super::parse_input`, including the builder's cross-section checks), so a
/// profile that fails to load here fails with the identical message the CLI
/// prints; the resolved form is then emitted from the profile input rather than
/// from the built policy, so none of the builder's derived state leaks in.
pub fn parse(content: &str) -> Result<CanonicalProfile, SandlockError> {
    let input = super::deserialize_profile(content)?;
    // Validation only: the policy is discarded. Resolving from `input` below
    // cannot fail once this call has succeeded, because both walk the same
    // grammar functions over the same strings.
    let _validated = super::parse_input(input.clone())?;
    resolve(&input)
}

/// Parse a TOML profile into canonical JSON.
pub fn parse_to_json(content: &str) -> Result<String, SandlockError> {
    let canonical = parse(content)?;
    serde_json::to_string_pretty(&canonical).map_err(|e| {
        SandlockError::Sandbox(SandboxError::Invalid(format!("JSON serialize error: {e}")))
    })
}

/// Resolve every micro-grammar in a deserialized profile.
///
/// Private, and deliberately so: it resolves grammars but runs none of the
/// cross-section checks (a uid without a gid, `net.allow` together with
/// `net.deny`, an HTTP CA without its key). [`parse`] is the entry point
/// because it runs `super::parse_input` first.
fn resolve(input: &ProfileInput) -> Result<CanonicalProfile, SandlockError> {
    let mut mount = Vec::with_capacity(input.filesystem.mount.len());
    for spec in &input.filesystem.mount {
        let (virt, host, ro) = super::parse_mount_spec(spec)?;
        mount.push(CanonicalMount { virt, host, ro });
    }
    // Read-only is keyed by virtual path in the core, so specs that share one
    // share its verdict. Emit the effective flag rather than the written one.
    let read_only: Vec<PathBuf> = mount
        .iter()
        .filter(|m| m.ro)
        .map(|m| m.virt.clone())
        .collect();
    for m in mount.iter_mut() {
        m.ro = read_only.contains(&m.virt);
    }

    let time_start = match input.determinism.time_start.as_deref() {
        Some(s) => Some(CanonicalTimestamp::from(super::parse_timestamp(s)?)),
        None => None,
    };

    let on_exit = match input.filesystem.on_exit.as_deref() {
        Some(s) => super::parse_branch_action(s)?,
        None => BranchAction::default(),
    };
    let on_error = match input.filesystem.on_error.as_deref() {
        Some(s) => super::parse_branch_action(s)?,
        None => BranchAction::default(),
    };

    Ok(CanonicalProfile {
        config: CanonicalConfig {
            http_ca: input.config.http_ca.clone(),
            http_key: input.config.http_key.clone(),
            http_inject_ca: input.config.http_inject_ca.clone(),
            http_ca_out: input.config.http_ca_out.clone(),
            fs_storage: input.config.fs_storage.clone(),
            workdir: input.config.workdir.clone(),
        },
        determinism: CanonicalDeterminism {
            random_seed: input.determinism.random_seed,
            time_start,
            deterministic_dirs: input.determinism.deterministic_dirs,
            no_randomize_memory: input.determinism.no_randomize_memory,
        },
        program: CanonicalProgram {
            exec: input.program.exec.clone(),
            args: input.program.args.clone(),
            env: input
                .program
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            cwd: input.program.cwd.clone(),
            uid: input.program.uid,
            gid: input.program.gid,
            clean_env: input.program.clean_env,
            no_coredump: input.program.no_coredump,
            no_huge_pages: input.program.no_huge_pages,
        },
        filesystem: CanonicalFilesystem {
            read: input.filesystem.read.clone(),
            write: input.filesystem.write.clone(),
            deny: input.filesystem.deny.clone(),
            chroot: input.filesystem.chroot.clone(),
            mount,
            on_exit: on_exit.into(),
            on_error: on_error.into(),
        },
        network: CanonicalNetwork {
            allow_bind: resolve_allow_bind(&input.network.allow_bind)?,
            deny_bind: resolve_deny_bind(&input.network.deny_bind)?,
            allow: resolve_net_rules(&input.network.allow, NetRule::parse_allow)?,
            deny: resolve_net_rules(&input.network.deny, NetRule::parse_deny)?,
            port_remap: input.network.port_remap,
        },
        http: CanonicalHttp {
            ports: input.http.ports.clone(),
            allow: resolve_http_rules(&input.http.allow)?,
            deny: resolve_http_rules(&input.http.deny)?,
        },
        syscalls: CanonicalSyscalls {
            extra_allow: input.syscalls.extra_allow.clone(),
            extra_deny: input.syscalls.extra_deny.clone(),
        },
        limits: CanonicalLimits {
            memory: resolve_byte_size(input.limits.memory.as_deref())?,
            disk: resolve_byte_size(input.limits.disk.as_deref())?,
            processes: input.limits.processes,
            open_files: input.limits.open_files,
            cpu: input.limits.cpu,
            gpu_devices: input.limits.gpu_devices.clone(),
            cpu_cores: input.limits.cpu_cores.clone(),
            num_cpus: input.limits.num_cpus,
        },
    })
}

impl From<jiff::Timestamp> for CanonicalTimestamp {
    fn from(ts: jiff::Timestamp) -> Self {
        // jiff signs the sub-second part to match the seconds part, so a
        // pre-epoch stamp arrives as e.g. (0, -500_000_000). Carry the borrow
        // so the emitted remainder is always non-negative.
        let mut seconds = ts.as_second();
        let mut nanoseconds = i64::from(ts.subsec_nanosecond());
        if nanoseconds < 0 {
            seconds -= 1;
            nanoseconds += 1_000_000_000;
        }
        CanonicalTimestamp {
            seconds,
            nanoseconds: nanoseconds as u32,
        }
    }
}

/// `PortSpec` is what the TOML array holds: a bare integer or a string
/// holding a comma list and/or a range. The builder stringifies the integer
/// form and runs one grammar over both, so do the same here.
fn port_specs_to_strings(specs: &[PortSpec]) -> Vec<String> {
    specs
        .iter()
        .map(|s| match s {
            PortSpec::Port(p) => p.to_string(),
            PortSpec::Spec(s) => s.clone(),
        })
        .collect()
}

fn resolve_allow_bind(specs: &[PortSpec]) -> Result<CanonicalBindPorts, SandlockError> {
    let strings = port_specs_to_strings(specs);
    let ports = crate::sandbox::parse_allow_bind_ports(&strings, "--net-allow-bind")
        .map_err(SandlockError::Sandbox)?;
    Ok(match ports {
        BindPorts::All => CanonicalBindPorts {
            any: true,
            ports: Vec::new(),
        },
        BindPorts::Ports(ports) => CanonicalBindPorts { any: false, ports },
    })
}

fn resolve_deny_bind(specs: &[PortSpec]) -> Result<CanonicalBindPorts, SandlockError> {
    let strings = port_specs_to_strings(specs);
    let ports = crate::sandbox::parse_bind_ports(&strings, "--net-deny-bind")
        .map_err(SandlockError::Sandbox)?;
    Ok(CanonicalBindPorts { any: false, ports })
}

fn resolve_net_rules(
    specs: &[String],
    parse_one: fn(&str) -> Result<Vec<NetRule>, SandboxError>,
) -> Result<Vec<CanonicalNetRule>, SandlockError> {
    let mut out = Vec::new();
    for spec in specs {
        for rule in parse_one(spec).map_err(SandlockError::Sandbox)? {
            let spec = super::format_net_rule(&rule);
            let target = match rule.target {
                NetTarget::AnyIp => CanonicalNetTarget::Any,
                NetTarget::Host(host) => CanonicalNetTarget::Host { host },
                NetTarget::Cidr(cidr) => CanonicalNetTarget::Cidr {
                    address: cidr.addr.to_string(),
                    prefix_len: cidr.prefix_len,
                },
            };
            out.push(CanonicalNetRule {
                protocol: rule.protocol,
                target,
                ports: rule.ports,
                all_ports: rule.all_ports,
                spec,
            });
        }
    }
    Ok(out)
}

fn resolve_http_rules(specs: &[String]) -> Result<Vec<CanonicalHttpRule>, SandlockError> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let rule = HttpRule::parse(spec).map_err(SandlockError::Sandbox)?;
        out.push(CanonicalHttpRule {
            spec: super::format_http_rule(&rule),
            method: rule.method,
            host: rule.host,
            path: rule.path,
        });
    }
    Ok(out)
}

fn resolve_byte_size(s: Option<&str>) -> Result<Option<u64>, SandlockError> {
    match s {
        Some(s) => Ok(Some(
            ByteSize::parse(s).map_err(SandlockError::Sandbox)?.0,
        )),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(toml: &str) -> serde_json::Value {
        let s = parse_to_json(toml).unwrap_or_else(|e| panic!("parse failed: {e}"));
        serde_json::from_str(&s).unwrap()
    }

    fn err(toml: &str) -> String {
        format!("{}", parse_to_json(toml).unwrap_err())
    }

    // ---- mounts ----

    #[test]
    fn mounts_resolve_to_structured_objects() {
        let v = json(
            r#"
            [filesystem]
            mount = ["/data:/srv/data", "/work:/srv/work:ro", "/tmpdir:/srv/tmp:rw"]
        "#,
        );
        assert_eq!(
            v["filesystem"]["mount"],
            serde_json::json!([
                {"virt": "/data", "host": "/srv/data", "ro": false},
                {"virt": "/work", "host": "/srv/work", "ro": true},
                {"virt": "/tmpdir", "host": "/srv/tmp", "ro": false},
            ])
        );
    }

    #[test]
    fn mount_host_path_may_contain_colons() {
        // Only a trailing :ro/:rw is an option; the split takes the first colon.
        let v = json(
            r#"
            [filesystem]
            mount = ["/v:/a:b:ro"]
        "#,
        );
        assert_eq!(
            v["filesystem"]["mount"][0],
            serde_json::json!({"virt": "/v", "host": "/a:b", "ro": true})
        );
    }

    #[test]
    fn duplicate_virtual_mounts_report_one_effective_read_only_flag() {
        // Read-only is keyed by virtual path in the core, so `:ro` on one spec
        // denies writes through `/w` for both. Reporting the written flag here
        // would describe a policy no layer applies.
        const TOML: &str = r#"
            [filesystem]
            mount = ["/w:/h1", "/w:/h2:ro"]
            [program]
            exec = "/bin/true"
        "#;
        assert_eq!(
            json(TOML)["filesystem"]["mount"],
            serde_json::json!([
                {"virt": "/w", "host": "/h1", "ro": true},
                {"virt": "/w", "host": "/h2", "ro": true},
            ])
        );

        // What the built policy actually enforces, from the same text.
        let (sandbox, _) = super::super::parse_profile(TOML).unwrap();
        assert_eq!(sandbox.fs_mount.len(), 2);
        for (virt, _) in &sandbox.fs_mount {
            assert!(
                sandbox.fs_mount_ro.iter().any(|d| d == virt),
                "{virt:?} is write-denied by the built policy"
            );
        }
        // And what the core prints when it re-emits that policy as specs.
        let back = super::super::sandbox_to_profile(&sandbox, &[]);
        assert_eq!(back.filesystem.mount, vec!["/w:/h1:ro", "/w:/h2:ro"]);
    }

    #[test]
    fn invalid_mount_specs_are_errors() {
        assert!(err("[filesystem]\nmount = [\"nocolon\"]").contains("VIRTUAL:HOST"));
        assert!(err("[filesystem]\nmount = [\":/host\"]").contains("non-empty"));
        assert!(err("[filesystem]\nmount = [\"/virt:\"]").contains("non-empty"));
    }

    // ---- byte sizes ----

    #[test]
    fn sizes_resolve_to_integer_bytes() {
        let v = json(
            r#"
            [limits]
            memory = "512M"
            disk = "1G"
        "#,
        );
        assert_eq!(v["limits"]["memory"], serde_json::json!(536870912u64));
        assert_eq!(v["limits"]["disk"], serde_json::json!(1073741824u64));
    }

    #[test]
    fn size_without_suffix_is_bytes_and_zero_is_kept() {
        let v = json("[limits]\nmemory = \"512\"\ndisk = \"0\"");
        assert_eq!(v["limits"]["memory"], serde_json::json!(512));
        assert_eq!(v["limits"]["disk"], serde_json::json!(0));
    }

    #[test]
    fn absent_sizes_are_null_not_zero() {
        let v = json("[limits]\ncpu = 50");
        assert!(v["limits"]["memory"].is_null());
        assert!(v["limits"]["disk"].is_null());
        assert_eq!(v["limits"]["cpu"], serde_json::json!(50));
    }

    #[test]
    fn fractional_and_terabyte_sizes_are_rejected() {
        // The core grammar takes integers with a K/M/G suffix. These two forms
        // are the ones a lenient re-implementation tends to accept.
        assert!(err("[limits]\nmemory = \"1.5G\"").contains("invalid byte size: 1.5G"));
        assert!(err("[limits]\nmemory = \"1T\"").contains("unknown byte size suffix: T"));
    }

    #[test]
    fn overflowing_size_is_an_error_not_a_silent_zero() {
        let msg = err("[limits]\nmemory = \"17179869184G\"");
        assert!(msg.contains("out of range"), "got: {msg}");
    }

    // ---- time_start ----

    #[test]
    fn time_start_resolves_to_epoch_seconds() {
        let v = json("[determinism]\ntime_start = \"2026-01-01T00:00:00Z\"");
        assert_eq!(
            v["determinism"]["time_start"],
            serde_json::json!({"seconds": 1767225600i64, "nanoseconds": 0})
        );
    }

    #[test]
    fn time_start_honours_the_offset() {
        let v = json("[determinism]\ntime_start = \"2026-01-01T00:00:00+03:00\"");
        assert_eq!(
            v["determinism"]["time_start"]["seconds"],
            serde_json::json!(1767225600i64 - 3 * 3600)
        );
    }

    #[test]
    fn time_start_keeps_sub_second_precision() {
        let v = json("[determinism]\ntime_start = \"2026-01-01T00:00:00.25Z\"");
        assert_eq!(
            v["determinism"]["time_start"],
            serde_json::json!({"seconds": 1767225600i64, "nanoseconds": 250000000u32})
        );
    }

    #[test]
    fn pre_epoch_time_start_stays_signed_with_a_non_negative_remainder() {
        let v = json("[determinism]\ntime_start = \"1969-12-31T23:59:59.5Z\"");
        assert_eq!(
            v["determinism"]["time_start"],
            serde_json::json!({"seconds": -1i64, "nanoseconds": 500000000u32})
        );
    }

    #[test]
    fn naive_time_start_is_rejected() {
        // The grammar requires an offset; a consumer that treats a naive stamp
        // as UTC would disagree with the CLI on what the profile means.
        let msg = err("[determinism]\ntime_start = \"2026-01-01T00:00:00\"");
        assert!(msg.contains("time_start"), "got: {msg}");
        assert!(msg.contains("offset"), "got: {msg}");
    }

    #[test]
    fn bare_unix_seconds_in_time_start_are_rejected() {
        assert!(err("[determinism]\ntime_start = \"1767225600\"").contains("time_start"));
    }

    // ---- branch actions ----

    #[test]
    fn branch_actions_resolve_and_default_explicitly() {
        let v = json("[filesystem]\nread = [\"/usr\"]");
        assert_eq!(v["filesystem"]["on_exit"], serde_json::json!("commit"));
        assert_eq!(v["filesystem"]["on_error"], serde_json::json!("commit"));

        let v = json("[filesystem]\non_exit = \"keep\"\non_error = \"abort\"");
        assert_eq!(v["filesystem"]["on_exit"], serde_json::json!("keep"));
        assert_eq!(v["filesystem"]["on_error"], serde_json::json!("abort"));
    }

    #[test]
    fn branch_action_is_case_sensitive() {
        let msg = err("[filesystem]\non_exit = \"COMMIT\"");
        assert!(msg.contains("invalid branch action"), "got: {msg}");
    }

    // ---- bind ports ----

    #[test]
    fn bind_ports_expand_sort_and_deduplicate() {
        let v = json("[network]\nallow_bind = [9001, \"9000-9002\", \"8080,8080\"]");
        assert_eq!(
            v["network"]["allow_bind"],
            serde_json::json!({"any": false, "ports": [8080, 9000, 9001, 9002]})
        );
    }

    #[test]
    fn bind_port_wildcard_becomes_any() {
        let v = json("[network]\nallow_bind = [\"*\"]");
        assert_eq!(
            v["network"]["allow_bind"],
            serde_json::json!({"any": true, "ports": []})
        );
    }

    #[test]
    fn bind_port_zero_is_accepted() {
        // Unlike net rules, where port 0 is rejected.
        let v = json("[network]\nallow_bind = [0]");
        assert_eq!(
            v["network"]["allow_bind"],
            serde_json::json!({"any": false, "ports": [0]})
        );
    }

    #[test]
    fn deny_bind_resolves_and_never_reports_any() {
        let v = json("[network]\ndeny_bind = [8080, \"9000-9001\"]");
        assert_eq!(
            v["network"]["deny_bind"],
            serde_json::json!({"any": false, "ports": [8080, 9000, 9001]})
        );
    }

    #[test]
    fn bind_port_grammar_errors_surface() {
        assert!(err("[network]\nallow_bind = [\"90-80\"]").contains("reversed port range"));
        assert!(err("[network]\nallow_bind = [\"8080,\"]").contains("empty port"));
        assert!(err("[network]\ndeny_bind = [\"*\"]").contains("only supported for"));
        assert!(
            err("[network]\nallow_bind = [\"*\", \"8080\"]").contains("cannot be combined")
        );
    }

    // ---- net rules ----

    #[test]
    fn scheme_less_net_rule_expands_to_tcp_and_udp() {
        let v = json("[network]\nallow = [\"example.com:443\"]");
        assert_eq!(
            v["network"]["allow"],
            serde_json::json!([
                {
                    "protocol": "tcp",
                    "target": {"kind": "host", "host": "example.com"},
                    "ports": [443],
                    "all_ports": false,
                    "spec": "tcp://example.com:443",
                },
                {
                    "protocol": "udp",
                    "target": {"kind": "host", "host": "example.com"},
                    "ports": [443],
                    "all_ports": false,
                    "spec": "udp://example.com:443",
                },
            ])
        );
    }

    #[test]
    fn net_rule_cidr_and_wildcard_targets_resolve() {
        let v = json("[network]\nallow = [\"tcp://10.0.0.0/8:80,443\", \"udp://*\"]");
        assert_eq!(
            v["network"]["allow"][0],
            serde_json::json!({
                "protocol": "tcp",
                "target": {"kind": "cidr", "address": "10.0.0.0", "prefix_len": 8},
                "ports": [80, 443],
                "all_ports": false,
                "spec": "tcp://10.0.0.0/8:80,443",
            })
        );
        assert_eq!(
            v["network"]["allow"][1],
            serde_json::json!({
                "protocol": "udp",
                "target": {"kind": "any"},
                "ports": [],
                "all_ports": true,
                "spec": "udp://*",
            })
        );
    }

    #[test]
    fn bare_ip_net_rule_becomes_a_host_route() {
        let v = json("[network]\ndeny = [\"tcp://192.168.1.1:22\"]");
        assert_eq!(
            v["network"]["deny"][0]["target"],
            serde_json::json!({"kind": "cidr", "address": "192.168.1.1", "prefix_len": 32})
        );
    }

    #[test]
    fn ipv6_net_rule_spec_keeps_the_bracket_form() {
        let v = json("[network]\nallow = [\"tcp://[fc00::/7]:443\"]");
        let rule = &v["network"]["allow"][0];
        assert_eq!(
            rule["target"],
            serde_json::json!({"kind": "cidr", "address": "fc00::", "prefix_len": 7})
        );
        // The spec has to round-trip: an unbracketed addr:port is itself a
        // valid IPv6 literal.
        assert_eq!(rule["spec"], serde_json::json!("tcp://[fc00::/7]:443"));
    }

    #[test]
    fn icmp_net_rule_carries_no_ports() {
        let v = json("[network]\nallow = [\"icmp://*\"]");
        assert_eq!(
            v["network"]["allow"],
            serde_json::json!([{
                "protocol": "icmp",
                "target": {"kind": "any"},
                "ports": [],
                "all_ports": true,
                "spec": "icmp://*",
            }])
        );
    }

    #[test]
    fn net_rule_grammar_errors_surface() {
        assert!(err("[network]\nallow = [\"example.com:0\"]").contains("port 0 is not valid"));
        assert!(err("[network]\nallow = [\"ftp://example.com\"]").contains("unknown scheme"));
        assert!(err("[network]\nallow = [\"icmp://example.com:1\"]").contains("takes no port"));
        // Hostnames are allow-only.
        assert!(err("[network]\ndeny = [\"example.com\"]").contains("hostnames are not allowed"));
    }

    #[test]
    fn net_allow_and_net_deny_are_mutually_exclusive() {
        let msg = err("[network]\nallow = [\"1.2.3.4\"]\ndeny = [\"5.6.7.8\"]");
        assert!(msg.contains("mutually exclusive"), "got: {msg}");
    }

    // ---- http rules ----

    #[test]
    fn http_rules_resolve_with_uppercased_method_and_normalized_path() {
        let v = json("[http]\nallow = [\"get Example.COM/v1//a/../b/\"]");
        assert_eq!(
            v["http"]["allow"][0],
            serde_json::json!({
                "method": "GET",
                "host": "Example.COM",
                "path": "/v1/b",
                "spec": "GET Example.COM/v1/b",
            })
        );
    }

    #[test]
    fn http_rule_without_a_path_gets_the_wildcard_path() {
        let v = json("[http]\ndeny = [\"* admin.internal\"]");
        assert_eq!(
            v["http"]["deny"][0],
            serde_json::json!({
                "method": "*",
                "host": "admin.internal",
                "path": "/*",
                "spec": "* admin.internal/*",
            })
        );
    }

    #[test]
    fn http_rules_do_not_leak_into_the_net_allowlist() {
        // The builder appends a net rule per HTTP host at build time. That is
        // effective-policy state; a consumer that mapped it back into a builder
        // would apply it twice.
        let v = json("[http]\nallow = [\"GET api.example.com/v1/*\"]");
        assert_eq!(v["network"]["allow"], serde_json::json!([]));
        // Same for the port default: the builder substitutes [80], the profile
        // said nothing.
        assert_eq!(v["http"]["ports"], serde_json::json!([]));
    }

    #[test]
    fn http_rule_grammar_errors_surface() {
        assert!(err("[http]\nallow = [\"GET\"]").contains("invalid http rule"));
    }

    // ---- unknown keys / invalid TOML ----

    #[test]
    fn unknown_section_is_an_error() {
        let msg = err("[bogus]\nx = 1");
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("bogus"), "got: {msg}");
    }

    #[test]
    fn unknown_field_in_a_known_section_is_an_error() {
        let msg = err("[program]\nexec = \"/bin/true\"\nbogus = 1");
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("bogus"), "got: {msg}");
    }

    #[test]
    fn old_flat_format_is_an_error() {
        assert!(err("fs_readable = [\"/usr\"]").contains("unknown field"));
    }

    #[test]
    fn invalid_toml_is_an_error() {
        let msg = err("[program");
        assert!(msg.contains("TOML parse error"), "got: {msg}");
    }

    #[test]
    fn wrong_scalar_type_is_an_error() {
        let msg = err("[limits]\ncpu = 300");
        assert!(msg.contains("TOML parse error"), "got: {msg}");
        assert!(msg.contains("expected u8"), "got: {msg}");
    }

    #[test]
    fn time_start_must_be_a_string_not_an_integer() {
        let msg = err("[determinism]\ntime_start = 1767225600");
        assert!(msg.contains("invalid type: integer"), "got: {msg}");
    }

    // ---- cross-section validation ----

    #[test]
    fn cross_section_checks_run_at_parse_time() {
        // These live in the builder, not in the schema. Running them here is
        // the point: a broken profile fails when it is loaded.
        assert!(err("[limits]\ncpu = 0").contains("max_cpu must be 1-100"));
        assert!(err("[limits]\nopen_files = 0").contains("greater than 0"));
        assert!(err("[program]\nuid = 1000").contains("must both be set"));
        assert!(
            err("[syscalls]\nextra_allow = [\"read\"]").contains("unknown syscall group name")
        );
    }

    // ---- whole-profile shape ----

    #[test]
    fn every_section_is_always_present() {
        let v = json("");
        for section in [
            "config",
            "determinism",
            "program",
            "filesystem",
            "network",
            "http",
            "syscalls",
            "limits",
        ] {
            assert!(v.get(section).is_some(), "missing section {section}");
        }
    }

    #[test]
    fn program_identity_survives() {
        // The effective-policy serializer drops exec/args; a profile consumer
        // cannot run anything without them.
        let v = json(
            r#"
            [program]
            exec = "/usr/bin/redis-cli"
            args = ["-h", "cache.internal"]
        "#,
        );
        assert_eq!(
            v["program"]["exec"],
            serde_json::json!("/usr/bin/redis-cli")
        );
        assert_eq!(
            v["program"]["args"],
            serde_json::json!(["-h", "cache.internal"])
        );
    }

    #[test]
    fn env_is_emitted_in_a_stable_order() {
        let toml = r#"
            [program]
            env = { zulu = "1", alpha = "2", mike = "3" }
        "#;
        let first = parse_to_json(toml).unwrap();
        for _ in 0..8 {
            assert_eq!(parse_to_json(toml).unwrap(), first);
        }
        let v: serde_json::Value = serde_json::from_str(&first).unwrap();
        let keys: Vec<&str> = v["program"]["env"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["alpha", "mike", "zulu"]);
    }

    #[test]
    fn canonical_json_round_trips_through_the_canonical_type() {
        // The consumer side deserializes this shape; it has to survive the
        // trip, and an unknown key has to be rejected there too.
        let toml = r#"
            [program]
            exec = "/bin/true"
            [filesystem]
            mount = ["/data:/srv:ro"]
            [network]
            allow = ["tcp://example.com:443"]
            allow_bind = ["*"]
            [http]
            deny = ["POST admin.example.com/x"]
            [limits]
            memory = "512M"
            [determinism]
            time_start = "2026-01-01T00:00:00Z"
        "#;
        let parsed = parse(toml).unwrap();
        let text = parse_to_json(toml).unwrap();
        let back: CanonicalProfile = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, back);

        let with_extra = text.replacen('{', "{\"bogus\": 1,", 1);
        let e = serde_json::from_str::<CanonicalProfile>(&with_extra).unwrap_err();
        assert!(format!("{e}").contains("unknown field"), "got: {e}");
    }

    #[test]
    fn full_profile_resolves_every_grammar_at_once() {
        let v = json(
            r#"
            [config]
            http_ca = "/etc/sandlock/ca.pem"
            http_key = "/etc/sandlock/ca.key"

            [determinism]
            random_seed = 42
            time_start = "2026-01-01T00:00:00Z"
            deterministic_dirs = true

            [program]
            exec = "/usr/bin/redis-cli"
            args = ["-h", "cache.internal"]
            uid = 1000
            gid = 1000
            clean_env = true

            [filesystem]
            read = ["/usr"]
            mount = ["/data:/srv/redis:ro"]
            on_exit = "keep"

            [network]
            allow_bind = [8080, "9000-9001"]
            allow = ["tcp://cache.internal:6379"]
            port_remap = true

            [http]
            ports = [80, 443]
            allow = ["GET api.internal/v1/*"]

            [syscalls]
            extra_allow = ["sysv_ipc"]
            extra_deny = ["ptrace"]

            [limits]
            memory = "512M"
            disk = "1G"
            cpu = 80
        "#,
        );

        assert_eq!(v["determinism"]["time_start"]["seconds"], 1767225600i64);
        assert_eq!(
            v["filesystem"]["mount"][0],
            serde_json::json!({"virt": "/data", "host": "/srv/redis", "ro": true})
        );
        assert_eq!(v["filesystem"]["on_exit"], "keep");
        assert_eq!(v["filesystem"]["on_error"], "commit");
        assert_eq!(
            v["network"]["allow_bind"],
            serde_json::json!({"any": false, "ports": [8080, 9000, 9001]})
        );
        assert_eq!(v["network"]["allow"][0]["ports"], serde_json::json!([6379]));
        assert_eq!(v["http"]["allow"][0]["path"], "/v1/*");
        assert_eq!(v["limits"]["memory"], 536870912u64);
        assert_eq!(v["limits"]["disk"], 1073741824u64);
        assert_eq!(v["syscalls"]["extra_allow"], serde_json::json!(["sysv_ipc"]));
    }

    #[test]
    fn parse_error_text_matches_what_the_cli_prints() {
        // Same profile, same pipeline: the message a consumer surfaces is the
        // message a CLI user sees.
        for toml in [
            "[filesystem]\nmount = [\"nocolon\"]",
            "[limits]\nmemory = \"1.5G\"",
            "[determinism]\ntime_start = \"nope\"",
            "[network]\nallow = [\"example.com:0\"]",
            "[program]\nbogus = 1",
            // The last two only fail inside the builder, so they also pin the
            // fact that this path runs the builder's checks at all.
            "[limits]\ncpu = 0",
            "[program]\nuid = 1000",
        ] {
            let canonical = format!("{}", parse_to_json(toml).unwrap_err());
            let cli = format!("{}", super::super::parse_profile(toml).unwrap_err());
            assert_eq!(canonical, cli, "profile: {toml}");
        }
    }
}

