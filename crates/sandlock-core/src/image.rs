//! Extract local Docker/OCI images into rootfs directories for sandboxing.
//!
//! Uses `docker create` + `docker export` to extract the image. If the
//! image is present in local Docker storage it is used as-is; otherwise
//! `docker create` pulls it from the configured registry first.
//!
//! ```ignore
//! let rootfs = image::extract("python:3.12-slim", None)?;
//! let cmd = image::inspect_cmd("python:3.12-slim")?;
//! // Use rootfs as chroot, cmd as default command
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{SandboxRuntimeError, SandlockError};

/// Default cache directory for extracted images.
fn default_cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".cache/sandlock/images")
}

/// Compute a short cache key from the image name.
fn cache_key(image: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    image.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Extract a local Docker image into a cached rootfs directory.
///
/// Creates a temporary container, exports its filesystem, and extracts
/// it. Returns the cached path on subsequent calls.
///
/// If the image is not in local Docker storage, `docker create` pulls it
/// from the registry first.
pub fn extract(image: &str, cache_dir: Option<&Path>) -> Result<PathBuf, SandlockError> {
    let cache = cache_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_cache_dir);
    let key = cache_key(image);
    let rootfs = cache.join(&key).join("rootfs");

    // Return cached rootfs if it exists and has content
    if rootfs.is_dir() {
        if let Ok(mut entries) = std::fs::read_dir(&rootfs) {
            if entries.next().is_some() {
                return Ok(rootfs);
            }
        }
    }

    // Create container (does not start it)
    let output = Command::new("docker")
        .args(["create", image, "/bin/true"])
        .output()
        .map_err(|e| SandboxRuntimeError::Child(format!("docker not found: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxRuntimeError::Child(
            format!("docker create failed: {}", stderr.trim()),
        ).into());
    }

    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Export and extract
    let result = extract_container(&container_id, &rootfs);

    // Always remove the temporary container
    let _ = Command::new("docker")
        .args(["rm", &container_id])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    result?;
    Ok(rootfs)
}

/// Export a container's filesystem and extract it to rootfs.
fn extract_container(container_id: &str, rootfs: &Path) -> Result<(), SandlockError> {
    std::fs::create_dir_all(rootfs)
        .map_err(|e| SandboxRuntimeError::Io(e))?;

    // docker export → tar stream → extract
    let mut child = Command::new("docker")
        .args(["export", container_id])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| SandboxRuntimeError::Child(format!("docker export: {}", e)))?;

    let stdout = child.stdout.take().unwrap();

    // Use tar crate or shell tar to extract
    let tar_status = Command::new("tar")
        .args(["xf", "-", "-C"])
        .arg(rootfs)
        .stdin(stdout)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .map_err(|e| SandboxRuntimeError::Child(format!("tar extract: {}", e)))?;

    let docker_status = child.wait()
        .map_err(|e| SandboxRuntimeError::Child(format!("docker export wait: {}", e)))?;

    if !docker_status.success() {
        // Clean up partial extraction
        let _ = std::fs::remove_dir_all(rootfs);
        return Err(SandboxRuntimeError::Child("docker export failed".into()).into());
    }

    if !tar_status.success() {
        let _ = std::fs::remove_dir_all(rootfs);
        return Err(SandboxRuntimeError::Child("tar extraction failed".into()).into());
    }

    Ok(())
}

/// Get the default command (ENTRYPOINT + CMD) for a local Docker image.
///
/// Returns the combined entrypoint and cmd, or `["/bin/sh"]` if none configured.
pub fn inspect_cmd(image: &str) -> Result<Vec<String>, SandlockError> {
    Ok(inspect_config(image)?.default_command())
}

/// The subset of an image's `Config` that sandlock applies when running it,
/// mirroring how `docker run` derives defaults from the image.
#[derive(Debug, Default, Clone)]
pub struct ImageConfig {
    /// `Config.Entrypoint` — prepended to the command.
    pub entrypoint: Option<Vec<String>>,
    /// `Config.Cmd` — the default command (overridden by a CLI command).
    pub cmd: Option<Vec<String>>,
    /// `Config.WorkingDir` — the default working directory.
    pub workdir: Option<String>,
    /// `Config.Env` — baked-in environment as `KEY=VALUE` pairs.
    pub env: Vec<String>,
    /// `Config.User` — default user (name or uid[:gid]).
    pub user: Option<String>,
}

impl ImageConfig {
    /// Combined ENTRYPOINT + CMD, falling back to `/bin/sh` when neither is set.
    pub fn default_command(&self) -> Vec<String> {
        match (&self.entrypoint, &self.cmd) {
            (Some(ep), Some(c)) => [ep.clone(), c.clone()].concat(),
            (Some(ep), None) => ep.clone(),
            (None, Some(c)) => c.clone(),
            (None, None) => vec!["/bin/sh".into()],
        }
    }
}

/// Inspect a local Docker image's `Config`, returning the fields sandlock maps
/// onto its sandbox (entrypoint, cmd, working dir, env, user).
///
/// On any inspection failure this returns a default config so callers can fall
/// back to running `/bin/sh`.
pub fn inspect_config(image: &str) -> Result<ImageConfig, SandlockError> {
    // One field per line keeps parsing simple and avoids delimiter clashes with
    // values that may themselves contain `|`.
    let output = Command::new("docker")
        .args([
            "inspect", "--format",
            "{{json .Config.Entrypoint}}\n{{json .Config.Cmd}}\n\
             {{json .Config.WorkingDir}}\n{{json .Config.Env}}\n{{json .Config.User}}",
            image,
        ])
        .output()
        .map_err(|_| SandboxRuntimeError::Child("docker inspect failed".into()))?;

    if !output.status.success() {
        return Ok(ImageConfig::default());
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let mut lines = raw.lines();

    let entrypoint = lines.next().and_then(parse_json_string_array);
    let cmd = lines.next().and_then(parse_json_string_array);
    let workdir = lines.next().and_then(parse_json_string).filter(|s| !s.is_empty());
    let env = lines.next().and_then(parse_json_string_array).unwrap_or_default();
    let user = lines.next().and_then(parse_json_string).filter(|s| !s.is_empty());

    Ok(ImageConfig { entrypoint, cmd, workdir, env, user })
}

/// Parse a JSON string literal like `"abc"` (or `null`) into its value.
fn parse_json_string(s: &str) -> Option<String> {
    let s = s.trim();
    if s == "null" || s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
        return None;
    }
    Some(s[1..s.len() - 1].replace("\\\"", "\"").replace("\\\\", "\\"))
}

/// Parse a JSON string array like `["a","b"]` or return None for `null`.
fn parse_json_string_array(s: &str) -> Option<Vec<String>> {
    let s = s.trim();
    if s == "null" || s.is_empty() {
        return None;
    }
    if !s.starts_with('[') || !s.ends_with(']') {
        return None;
    }
    let inner = &s[1..s.len() - 1];
    if inner.trim().is_empty() {
        return Some(Vec::new());
    }
    let mut result = Vec::new();
    for item in inner.split(',') {
        let item = item.trim();
        if item.starts_with('"') && item.ends_with('"') && item.len() >= 2 {
            result.push(item[1..item.len() - 1].replace("\\\"", "\"").replace("\\\\", "\\"));
        }
    }
    if result.is_empty() { None } else { Some(result) }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_deterministic() {
        let k1 = cache_key("python:3.12-slim");
        let k2 = cache_key("python:3.12-slim");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_cache_key_different() {
        let k1 = cache_key("python:3.12-slim");
        let k2 = cache_key("alpine:latest");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_default_cache_dir() {
        let dir = default_cache_dir();
        assert!(dir.to_str().unwrap().contains("sandlock/images"));
    }

    #[test]
    fn test_parse_json_array() {
        assert_eq!(
            parse_json_string_array(r#"["python3","-c","print(1)"]"#),
            Some(vec!["python3".into(), "-c".into(), "print(1)".into()])
        );
    }

    #[test]
    fn test_parse_json_null() {
        assert_eq!(parse_json_string_array("null"), None);
    }

    #[test]
    fn test_parse_json_empty_array() {
        assert_eq!(parse_json_string_array("[]"), Some(vec![]));
    }

    #[test]
    fn test_parse_json_single() {
        assert_eq!(
            parse_json_string_array(r#"["/bin/sh"]"#),
            Some(vec!["/bin/sh".into()])
        );
    }

    #[test]
    fn test_parse_json_string() {
        assert_eq!(parse_json_string(r#""/app""#), Some("/app".into()));
        assert_eq!(parse_json_string("null"), None);
        assert_eq!(parse_json_string(r#""""#), Some(String::new()));
        assert_eq!(parse_json_string(r#""a\"b""#), Some("a\"b".into()));
    }

    #[test]
    fn test_default_command_precedence() {
        let cfg = ImageConfig {
            entrypoint: Some(vec!["/entry".into()]),
            cmd: Some(vec!["arg".into()]),
            ..Default::default()
        };
        assert_eq!(cfg.default_command(), vec!["/entry".to_string(), "arg".into()]);

        let cmd_only = ImageConfig { cmd: Some(vec!["bash".into()]), ..Default::default() };
        assert_eq!(cmd_only.default_command(), vec!["bash".to_string()]);

        let empty = ImageConfig::default();
        assert_eq!(empty.default_command(), vec!["/bin/sh".to_string()]);
    }
}
