//! Persistent state management for OCI container lifecycle.
//!
//! Implements Phase 2: state JSON stored at `/run/sandlock-oci/<id>/state.json`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default state directory root — matches the OCI runtime spec.
pub const STATE_DIR: &str = "/run/sandlock-oci";

/// OCI container status as defined by the runtime spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Container has been created but not yet started.
    Created,
    /// Container is currently running.
    Running,
    /// Container process has exited.
    Stopped,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
            status: Status::Created,
            pid: 0,
            bundle: bundle.to_path_buf(),
            created,
            annotations: Default::default(),
        }
    }

    /// Path to the state directory for this container.
    pub fn state_dir(&self) -> PathBuf {
        Path::new(STATE_DIR).join(&self.id)
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
        let path = Path::new(STATE_DIR).join(id).join("state.json");
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

    /// Transition to Running status with the given PID.
    pub fn set_created(&mut self, pid: i32) {
        self.status = Status::Created;
        self.pid = pid;
    }

    pub fn set_running(&mut self) {
        self.status = Status::Running;
    }

    /// Transition to Stopped status.
    pub fn set_stopped(&mut self) {
        self.status = Status::Stopped;
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

/// Return a JSON string suitable for `sandlock-oci state` output.
pub fn state_json(state: &ContainerState) -> Result<String> {
    serde_json::to_string_pretty(state).context("serialize state")
}

/// List all container IDs currently tracked in STATE_DIR.
pub fn list_containers() -> Result<Vec<String>> {
    let dir = Path::new(STATE_DIR);
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
    use tempfile::tempdir;

    /// Override STATE_DIR for unit tests via the state_dir helper.
    fn _make_state(id: &str, bundle: &Path, _tmp: &Path) -> ContainerState {
        let s = ContainerState::new(id, bundle, "1.0.2");
        // Redirect state_dir to a temp location for tests
        let _ = s; // just verify construction
        ContainerState {
            oci_version: "1.0.2".into(),
            id: id.to_string(),
            status: Status::Created,
            pid: 0,
            bundle: bundle.to_path_buf(),
            created: 0,
            annotations: Default::default(),
        }
    }

    #[test]
    fn status_display() {
        assert_eq!(Status::Created.to_string(), "created");
        assert_eq!(Status::Running.to_string(), "running");
        assert_eq!(Status::Stopped.to_string(), "stopped");
    }

    #[test]
    fn state_roundtrip_json() {
        let dir = tempdir().unwrap();
        let state = ContainerState::new("test-ctr", dir.path(), "1.0.2");
        let json = serde_json::to_string(&state).unwrap();
        let loaded: ContainerState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.id, "test-ctr");
        assert_eq!(loaded.status, Status::Created);
    }

    #[test]
    fn is_alive_returns_false_for_zero_pid() {
        let dir = tempdir().unwrap();
        let state = ContainerState::new("dead-ctr", dir.path(), "1.0.2");
        assert!(!state.is_alive());
    }

    #[test]
    fn set_running_updates_status() {
        let dir = tempdir().unwrap();
        let mut state = ContainerState::new("run-ctr", dir.path(), "1.0.2");
        state.set_running(12345);
        assert_eq!(state.status, Status::Running);
        assert_eq!(state.pid, 12345);
    }

    #[test]
    fn set_stopped_updates_status() {
        let dir = tempdir().unwrap();
        let mut state = ContainerState::new("stop-ctr", dir.path(), "1.0.2");
        state.set_running(1);
        state.set_stopped();
        assert_eq!(state.status, Status::Stopped);
    }
}
