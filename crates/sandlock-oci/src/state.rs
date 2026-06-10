//! Persistent state management for OCI container lifecycle.
//!
//! Implements Phase 2: state JSON stored at `/run/sandlock-oci/<id>/state.json`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default state directory root — matches the OCI runtime spec.
///
/// Can be overridden at runtime with the `SANDLOCK_OCI_STATE_DIR` environment
/// variable (useful for integration tests that don't run as root).
pub const STATE_DIR: &str = "/run/sandlock-oci";

/// Return the effective state directory, respecting the env override.
pub fn state_dir() -> String {
    std::env::var("SANDLOCK_OCI_STATE_DIR").unwrap_or_else(|_| STATE_DIR.to_string())
}

/// OCI container status as defined by the runtime spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Transient state while the supervisor is setting up the container.
    Creating,
    /// Container has been created (child parked) but not yet started.
    Created,
    /// Container is currently running.
    Running,
    /// Container process has exited.
    Stopped,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Creating => write!(f, "creating"),
            Status::Created => write!(f, "created"),
            Status::Running => write!(f, "running"),
            Status::Stopped => write!(f, "stopped"),
        }
    }
}

/// The on-disk state blob for a sandlock-oci container.
///
/// Fields match the OCI Runtime State specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerState {
    /// OCI spec version.
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    /// Container identifier (unique on this host).
    pub id: String,
    /// Current lifecycle status.
    pub status: Status,
    /// PID of the container's init process (0 = not yet started).
    pub pid: i32,
    /// Absolute path to the bundle directory.
    pub bundle: PathBuf,
    /// Unix timestamp (seconds) when the container was created.
    pub created: u64,
    /// Optional annotations from the OCI spec.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub annotations: std::collections::HashMap<String, String>,
    /// Exit code or signal that terminated the container.
    /// `None` while the container is Created or Running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_info: Option<ExitInfo>,
}

/// Captures how the container's init process exited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitInfo {
    /// Exit code if the process exited normally.
    pub code: Option<i32>,
    /// Signal number if the process was killed by a signal.
    pub signal: Option<i32>,
}

impl ExitInfo {
    /// Create from a raw waitpid status value.
    pub fn from_status(status: i32) -> Self {
        if libc::WIFEXITED(status) {
            ExitInfo {
                code: Some(unsafe { libc::WEXITSTATUS(status) }),
                signal: None,
            }
        } else if libc::WIFSIGNALED(status) {
            ExitInfo {
                code: None,
                signal: Some(unsafe { libc::WTERMSIG(status) }),
            }
        } else {
            ExitInfo {
                code: None,
                signal: None,
            }
        }
    }
}

impl ContainerState {
    /// Create a new state in the `Created` status.
    pub fn new(id: &str, bundle: &Path, oci_version: &str) -> Self {
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        ContainerState {
            oci_version: oci_version.to_string(),
            id: id.to_string(),
            status: Status::Creating,
            pid: 0,
            bundle: bundle.to_path_buf(),
            created,
            annotations: Default::default(),
            exit_info: None,
        }
    }

    /// Path to the state directory for this container.
    pub fn state_dir(&self) -> PathBuf {
        Path::new(&state_dir()).join(&self.id)
    }

    /// Path to the state JSON file.
    pub fn state_file(&self) -> PathBuf {
        self.state_dir().join("state.json")
    }

    /// Persist state to disk. Creates the directory if needed.
    pub fn save(&self) -> Result<()> {
        let dir = self.state_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create state dir {:?}", dir))?;
        let data = serde_json::to_string_pretty(self)
            .context("serialize container state")?;
        std::fs::write(self.state_file(), data)
            .with_context(|| format!("write state to {:?}", self.state_file()))
    }

    /// Load state from disk.
    pub fn load(id: &str) -> Result<Self> {
        let path = Path::new(&state_dir()).join(id).join("state.json");
        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("read state from {:?}", path))?;
        serde_json::from_str(&data)
            .with_context(|| format!("parse state JSON from {:?}", path))
    }

    /// Remove the state directory from disk.
    pub fn delete(&self) -> Result<()> {
        let dir = self.state_dir();
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("remove state dir {:?}", dir))?;
        }
        Ok(())
    }

    /// Record the PID in Created state (SIGSTOP'd child).
    pub fn set_created(&mut self, pid: i32) {
        self.status = Status::Created;
        self.pid = pid;
    }

    /// Mark the container as running.
    pub fn set_running(&mut self) {
        self.status = Status::Running;
    }

    /// Transition to Stopped status with exit information.
    pub fn set_stopped(&mut self, exit_info: Option<ExitInfo>) {
        self.status = Status::Stopped;
        self.exit_info = exit_info;
    }

    /// Returns true if the container process is still alive.
    pub fn is_alive(&self) -> bool {
        if self.pid <= 0 {
            return false;
        }
        // Send signal 0 to probe process existence.
        unsafe { libc::kill(self.pid, 0) == 0 }
    }
}

/// List all container IDs currently tracked in STATE_DIR.
pub fn list_containers() -> Result<Vec<String>> {
    let dir_str = state_dir();
    let dir = Path::new(&dir_str);
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut ids = vec![];
    for entry in std::fs::read_dir(dir).context("read state dir")? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Only include dirs that actually have a state.json
            if entry.path().join("state.json").exists() {
                ids.push(name);
            }
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn _make_state(id: &str) -> ContainerState {
        ContainerState::new(id, Path::new("/tmp"), "1.0.2")
    }

    #[test]
    fn status_display() {
        assert_eq!(Status::Created.to_string(), "created");
        assert_eq!(Status::Running.to_string(), "running");
        assert_eq!(Status::Stopped.to_string(), "stopped");
    }

    #[test]
    fn state_roundtrip_json() {
        let state = ContainerState::new("test-ctr", Path::new("/tmp"), "1.0.2");
        let json = serde_json::to_string(&state).unwrap();
        let loaded: ContainerState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.id, "test-ctr");
        // new() begins in Creating; set_created() transitions to Created.
        assert_eq!(loaded.status, Status::Creating);
    }

    #[test]
    fn is_alive_returns_false_for_zero_pid() {
        let state = ContainerState::new("dead-ctr", Path::new("/tmp"), "1.0.2");
        assert!(!state.is_alive());
    }

    #[test]
    fn set_created_sets_pid() {
        let mut state = _make_state("test");
        state.set_created(12345);
        assert_eq!(state.status, Status::Created);
        assert_eq!(state.pid, 12345);
    }

    #[test]
    fn set_running_updates_status() {
        let mut state = _make_state("run-ctr");
        state.set_created(9999);
        state.set_running();
        assert_eq!(state.status, Status::Running);
        assert_eq!(state.pid, 9999);
    }

    #[test]
    fn set_stopped_with_exit_info() {
        let mut state = _make_state("stop-ctr");
        state.set_created(1);
        state.set_running();
        let info = ExitInfo {
            code: Some(0),
            signal: None,
        };
        state.set_stopped(Some(info));
        assert_eq!(state.status, Status::Stopped);
        assert_eq!(state.exit_info.as_ref().unwrap().code, Some(0));
    }

    #[test]
    fn exit_info_from_status_exited() {
        let info = ExitInfo::from_status(0 << 8); // exit code 0
        assert_eq!(info.code, Some(0));
        assert!(info.signal.is_none());
    }

    #[test]
    fn exit_info_from_status_signaled() {
        let info = ExitInfo::from_status(libc::SIGKILL); // killed by SIGKILL
        assert!(info.code.is_none());
        assert_eq!(info.signal, Some(libc::SIGKILL));
    }

    #[test]
    fn state_dir_respects_env_override() {
        env::set_var("SANDLOCK_OCI_STATE_DIR", "/tmp/sandlock-test-dir");
        assert_eq!(state_dir(), "/tmp/sandlock-test-dir");
        env::remove_var("SANDLOCK_OCI_STATE_DIR");
    }
}