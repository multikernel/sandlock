//! Extract local Docker/OCI images into rootfs directories for sandboxing.
//!
//! Uses `docker create` + `docker export` to extract a locally available
//! image. No registry pulling — the image must already be present in
//! local Docker storage.
//!
//! ```ignore
//! let rootfs = image::extract("python:3.12-slim", None)?;
//! let cmd = image::inspect_cmd("python:3.12-slim")?;
//! // Use rootfs as chroot, cmd as default command
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{SandboxError, SandlockError};

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
/// The image must already be pulled locally (`docker pull` beforehand).
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
        .map_err(|e| SandboxError::Child(format!("docker not found: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Child(
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
        .map_err(|e| SandboxError::Io(e))?;

    // docker export → tar stream → extract
    let mut child = Command::new("docker")
        .args(["export", container_id])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| SandboxError::Child(format!("docker export: {}", e)))?;

    let stdout = child.stdout.take().unwrap();

    // Use tar crate or shell tar to extract
    let tar_status = Command::new("tar")
        .args(["xf", "-", "-C"])
        .arg(rootfs)
        .stdin(stdout)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .map_err(|e| SandboxError::Child(format!("tar extract: {}", e)))?;

    let docker_status = child.wait()
        .map_err(|e| SandboxError::Child(format!("docker export wait: {}", e)))?;

    if !docker_status.success() {
        // Clean up partial extraction
        let _ = std::fs::remove_dir_all(rootfs);
        return Err(SandboxError::Child("docker export failed".into()).into());
    }

    if !tar_status.success() {
        let _ = std::fs::remove_dir_all(rootfs);
        return Err(SandboxError::Child("tar extraction failed".into()).into());
    }

    Ok(())
}

/// Get the default command (ENTRYPOINT + CMD) for a local Docker image.
///
/// Returns the combined entrypoint and cmd, or `["/bin/sh"]` if none configured.
pub fn inspect_cmd(image: &str) -> Result<Vec<String>, SandlockError> {
    let output = Command::new("docker")
        .args([
            "inspect", "--format",
            "{{json .Config.Entrypoint}}|{{json .Config.Cmd}}",
            image,
        ])
        .output()
        .map_err(|_| SandboxError::Child("docker inspect failed".into()))?;

    if !output.status.success() {
        return Ok(vec!["/bin/sh".into()]);
    }

    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parts: Vec<&str> = raw.splitn(2, '|').collect();

    let entrypoint = parts.first().and_then(|s| parse_json_string_array(s));
    let cmd = parts.get(1).and_then(|s| parse_json_string_array(s));

    match (entrypoint, cmd) {
        (Some(ep), Some(c)) => Ok([ep, c].concat()),
        (Some(ep), None) => Ok(ep),
        (None, Some(c)) => Ok(c),
        (None, None) => Ok(vec!["/bin/sh".into()]),
    }
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
}
