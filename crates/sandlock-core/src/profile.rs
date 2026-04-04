use crate::policy::{Policy, ByteSize};
use crate::error::SandlockError;
use std::path::PathBuf;

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

/// Load a profile by name.
pub fn load_profile(name: &str) -> Result<Policy, SandlockError> {
    let path = profile_dir().join(format!("{}.toml", name));
    let content = std::fs::read_to_string(&path)
        .map_err(|e| SandlockError::Policy(crate::error::PolicyError::Invalid(
            format!("profile '{}': {}", name, e)
        )))?;
    parse_profile(&content)
}

/// Parse a TOML profile string into a Policy.
pub fn parse_profile(content: &str) -> Result<Policy, SandlockError> {
    let table: toml::Table = content.parse()
        .map_err(|e| SandlockError::Policy(crate::error::PolicyError::Invalid(
            format!("TOML parse error: {}", e)
        )))?;

    // Accept both [sandbox] section and flat format (Python-compatible)
    let sandbox = table.get("sandbox")
        .and_then(|v| v.as_table())
        .unwrap_or(&table);

    let mut builder = Policy::builder();

    // Parse string arrays
    if let Some(paths) = sandbox.get("fs_readable").and_then(|v| v.as_array()) {
        for p in paths { if let Some(s) = p.as_str() { builder = builder.fs_read(s); } }
    }
    if let Some(paths) = sandbox.get("fs_writable").and_then(|v| v.as_array()) {
        for p in paths { if let Some(s) = p.as_str() { builder = builder.fs_write(s); } }
    }
    if let Some(paths) = sandbox.get("fs_denied").and_then(|v| v.as_array()) {
        for p in paths { if let Some(s) = p.as_str() { builder = builder.fs_deny(s); } }
    }
    if let Some(hosts) = sandbox.get("net_allow_hosts").and_then(|v| v.as_array()) {
        for h in hosts { if let Some(s) = h.as_str() { builder = builder.net_allow_host(s); } }
    }
    if let Some(rules) = sandbox.get("http_allow").and_then(|v| v.as_array()) {
        for r in rules { if let Some(s) = r.as_str() { builder = builder.http_allow(s); } }
    }
    if let Some(rules) = sandbox.get("http_deny").and_then(|v| v.as_array()) {
        for r in rules { if let Some(s) = r.as_str() { builder = builder.http_deny(s); } }
    }

    // Parse integers
    if let Some(v) = sandbox.get("max_processes").and_then(|v| v.as_integer()) {
        builder = builder.max_processes(v as u32);
    }
    if let Some(v) = sandbox.get("max_cpu").and_then(|v| v.as_integer()) {
        builder = builder.max_cpu(v as u8);
    }
    if let Some(v) = sandbox.get("num_cpus").and_then(|v| v.as_integer()) {
        builder = builder.num_cpus(v as u32);
    }
    if let Some(v) = sandbox.get("random_seed").and_then(|v| v.as_integer()) {
        builder = builder.random_seed(v as u64);
    }

    // Parse string values
    if let Some(v) = sandbox.get("max_memory").and_then(|v| v.as_str()) {
        builder = builder.max_memory(ByteSize::parse(v)?);
    }

    // Parse booleans
    if let Some(v) = sandbox.get("no_raw_sockets").and_then(|v| v.as_bool()) {
        builder = builder.no_raw_sockets(v);
    }
    if let Some(v) = sandbox.get("no_udp").and_then(|v| v.as_bool()) {
        builder = builder.no_udp(v);
    }
    if let Some(v) = sandbox.get("isolate_ipc").and_then(|v| v.as_bool()) {
        builder = builder.isolate_ipc(v);
    }
    if let Some(v) = sandbox.get("isolate_signals").and_then(|v| v.as_bool()) {
        builder = builder.isolate_signals(v);
    }
    if let Some(v) = sandbox.get("clean_env").and_then(|v| v.as_bool()) {
        builder = builder.clean_env(v);
    }
    if let Some(v) = sandbox.get("deterministic_dirs").and_then(|v| v.as_bool()) {
        builder = builder.deterministic_dirs(v);
    }
    if let Some(v) = sandbox.get("hostname").and_then(|v| v.as_str()) {
        builder = builder.hostname(v);
    }
    if let Some(v) = sandbox.get("workdir").and_then(|v| v.as_str()) {
        builder = builder.workdir(v);
    }
    if let Some(v) = sandbox.get("cwd").and_then(|v| v.as_str()) {
        builder = builder.cwd(v);
    }
    // Parse port arrays
    if let Some(ports) = sandbox.get("net_bind").and_then(|v| v.as_array()) {
        for p in ports { if let Some(n) = p.as_integer() { builder = builder.net_bind_port(n as u16); } }
    }
    if let Some(ports) = sandbox.get("net_connect").and_then(|v| v.as_array()) {
        for p in ports { if let Some(n) = p.as_integer() { builder = builder.net_connect_port(n as u16); } }
    }

    // Parse syscall lists
    if let Some(syscalls) = sandbox.get("deny_syscalls").and_then(|v| v.as_array()) {
        let names: Vec<String> = syscalls.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        builder = builder.deny_syscalls(names);
    }

    builder.build().map_err(|e| SandlockError::Policy(e))
}

/// List available profile names.
pub fn list_profiles() -> Result<Vec<String>, SandlockError> {
    let dir = profile_dir();
    if !dir.exists() { return Ok(Vec::new()); }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .map_err(|e| SandlockError::Policy(crate::error::PolicyError::Invalid(format!("read dir: {}", e))))? {
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
    fn parse_basic_profile() {
        let toml = r#"
[sandbox]
fs_readable = ["/usr", "/lib", "/bin"]
fs_writable = ["/tmp"]
max_memory = "2G"
max_processes = 64
"#;
        let policy = parse_profile(toml).unwrap();
        assert_eq!(policy.fs_readable.len(), 3);
        assert_eq!(policy.fs_writable.len(), 1);
        assert_eq!(policy.max_memory, Some(ByteSize::gib(2)));
        assert_eq!(policy.max_processes, 64);
    }

    #[test]
    fn parse_flat_format() {
        // Flat format (no [sandbox] section) should work
        let toml = r#"
fs_readable = ["/usr", "/lib"]
clean_env = true
"#;
        let policy = parse_profile(toml).unwrap();
        assert_eq!(policy.fs_readable.len(), 2);
        assert!(policy.clean_env);
    }

    #[test]
    fn parse_sandbox_section_format() {
        // [sandbox] section format should also work
        let toml = r#"
[sandbox]
fs_readable = ["/usr"]
max_processes = 10
"#;
        let policy = parse_profile(toml).unwrap();
        assert_eq!(policy.fs_readable.len(), 1);
        assert_eq!(policy.max_processes, 10);
    }

    #[test]
    fn parse_invalid_toml() {
        let err = parse_profile("not valid toml {{{").unwrap_err();
        assert!(err.to_string().contains("TOML parse error"));
    }

    #[test]
    fn list_profiles_empty_dir() {
        // With no profile dir, should return empty vec
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/sandlock-test-nonexistent");
        let profiles = list_profiles().unwrap();
        assert!(profiles.is_empty());
        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
