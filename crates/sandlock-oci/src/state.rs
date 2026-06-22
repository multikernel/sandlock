//! Persistent state management for the OCI container lifecycle.
//!
//! State JSON is stored at `<root>/<id>/state.json`, where `<root>` is the
//! `--root` directory (when given), `$XDG_RUNTIME_DIR/sandlock-oci` for
//! unprivileged users, or `/run/sandlock-oci` for root. See [`state_dir`].

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// System-wide state directory root, used when running as root.
///
/// Matches the runc/containerd convention. Unprivileged users default to a
/// per-user runtime directory instead (see [`resolve_state_dir`]), keeping
/// sandlock usable without root.
pub const STATE_DIR: &str = "/run/sandlock-oci";

/// Process-wide state-dir root, resolved once in `main` via [`init_state_dir`].
///
/// Set before any `fork`, so the supervisor child inherits the same value.
static STATE_DIR_ROOT: OnceLock<String> = OnceLock::new();

/// Resolve and cache the state directory root for this process.
///
/// Precedence (highest first):
/// 1. the explicit `--root` CLI flag (`root_flag`), the OCI-standard knob
///    that containerd/CRI-O pass,
/// 2. `$XDG_RUNTIME_DIR/sandlock-oci` for unprivileged users,
/// 3. `/run/sandlock-oci` for root (or when no per-user runtime dir exists).
///
/// Call once, early in `main`, before any state I/O or `fork`.
pub fn init_state_dir(root_flag: Option<&str>) {
    let _ = STATE_DIR_ROOT.set(resolve_state_dir(root_flag));
}

/// Compute the state directory root without caching. See [`init_state_dir`]
/// for the precedence rules.
fn resolve_state_dir(root_flag: Option<&str>) -> String {
    if let Some(root) = root_flag {
        return root.to_string();
    }
    // Unprivileged default: a per-user, user-owned runtime dir, mirroring
    // rootless runc/crun/podman. This is what keeps sandlock-oci runnable
    // without root, which is the project's core design goal.
    if unsafe { libc::geteuid() } != 0 {
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            if !xdg.is_empty() {
                return format!("{}/sandlock-oci", xdg);
            }
        }
    }
    STATE_DIR.to_string()
}

/// Return the effective state directory root.
///
/// Returns the value cached by [`init_state_dir`] when set; otherwise resolves
/// the default (library and test callers that never call `init_state_dir`).
pub fn state_dir() -> String {
    if let Some(dir) = STATE_DIR_ROOT.get() {
        return dir.clone();
    }
    resolve_state_dir(None)
}

/// OCI container status as defined by the runtime spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Transient state while the supervisor is setting up the sandbox.
    Creating,
    /// Sandbox has been created (child parked) but not yet started.
    Created,
    /// Sandbox is currently running.
    Running,
    /// Sandbox process has exited.
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

/// The on-disk state blob for a sandlock-oci sandbox.
///
/// Fields match the OCI Runtime State specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxState {
    /// OCI spec version.
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    /// Sandbox identifier (unique on this host).
    pub id: String,
    /// Current lifecycle status.
    pub status: Status,
    /// PID of the sandbox's init process (0 = not yet started).
    pub pid: i32,
    /// Absolute path to the bundle directory.
    pub bundle: PathBuf,
    /// Unix timestamp (seconds) when the sandbox was created.
    pub created: u64,
    /// Optional annotations from the OCI spec.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub annotations: std::collections::HashMap<String, String>,
    /// Exit code or signal that terminated the sandbox.
    /// `None` while the sandbox is Created or Running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_info: Option<ExitInfo>,
}

/// Captures how the sandbox's init process exited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitInfo {
    /// Exit code if the process exited normally.
    pub code: Option<i32>,
    /// Signal number if the process was killed by a signal.
    pub signal: Option<i32>,
}

impl SandboxState {
    /// Create a new state in the `Created` status.
    pub fn new(id: &str, bundle: &Path, oci_version: &str) -> Self {
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        SandboxState {
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

    /// Path to the state directory for this sandbox.
    pub fn state_dir(&self) -> PathBuf {
        Path::new(&state_dir()).join(&self.id)
    }

    /// Path to the state JSON file.
    pub fn state_file(&self) -> PathBuf {
        self.state_dir().join("state.json")
    }

    /// Persist state to disk. Creates the directory if needed.
    ///
    /// The write is atomic: serialize to a per-writer temp file, then `rename`
    /// it over `state.json`. During `create`/`restore` the CLI and the detached
    /// supervisor write `state.json` concurrently; a plain `write` (truncate then
    /// write) would let the other process `load` a torn or empty file and fail to
    /// parse it. `rename(2)` is atomic on the same filesystem, so a concurrent
    /// reader always sees a complete file (the previous one or the new one).
    pub fn save(&self) -> Result<()> {
        let dir = self.state_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create state dir {:?}", dir))?;
        let data = serde_json::to_string_pretty(self)
            .context("serialize sandbox state")?;
        // Temp and target share `dir` (same filesystem, so rename is atomic) and
        // the temp name carries the writer's PID so concurrent writers in
        // different processes never collide on it.
        let tmp = dir.join(format!("state.json.{}.tmp", std::process::id()));
        std::fs::write(&tmp, data)
            .with_context(|| format!("write state to {:?}", tmp))?;
        std::fs::rename(&tmp, self.state_file())
            .with_context(|| format!("rename {:?} -> {:?}", tmp, self.state_file()))
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

    /// Transition `Creating` -> `Created`, recording the parked child's init PID.
    pub fn set_created(&mut self, pid: i32) {
        self.status = Status::Created;
        self.pid = pid;
    }

    /// Mark the sandbox as running.
    pub fn set_running(&mut self) {
        self.status = Status::Running;
    }

    /// Transition to Stopped status with exit information.
    pub fn set_stopped(&mut self, exit_info: Option<ExitInfo>) {
        self.status = Status::Stopped;
        self.exit_info = exit_info;
    }

    /// Returns true if the sandbox process is still alive.
    pub fn is_alive(&self) -> bool {
        if self.pid <= 0 {
            return false;
        }
        // Send signal 0 to probe process existence.
        unsafe { libc::kill(self.pid, 0) == 0 }
    }
}

/// List all sandbox IDs currently tracked in STATE_DIR.
pub fn list_sandboxes() -> Result<Vec<String>> {
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

    fn _make_state(id: &str) -> SandboxState {
        SandboxState::new(id, Path::new("/tmp"), "1.0.2")
    }

    #[test]
    fn status_display() {
        assert_eq!(Status::Created.to_string(), "created");
        assert_eq!(Status::Running.to_string(), "running");
        assert_eq!(Status::Stopped.to_string(), "stopped");
    }

    #[test]
    fn state_roundtrip_json() {
        let state = SandboxState::new("test-ctr", Path::new("/tmp"), "1.0.2");
        let json = serde_json::to_string(&state).unwrap();
        let loaded: SandboxState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.id, "test-ctr");
        // new() begins in Creating; set_created() transitions to Created.
        assert_eq!(loaded.status, Status::Creating);
    }

    #[test]
    fn is_alive_returns_false_for_zero_pid() {
        let state = SandboxState::new("dead-ctr", Path::new("/tmp"), "1.0.2");
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
    fn state_dir_resolution_precedence() {
        // The --root flag takes precedence over the computed default.
        assert_eq!(resolve_state_dir(Some("/custom/root")), "/custom/root");

        // Unprivileged users default to a per-user runtime dir; root falls
        // back to the system-wide STATE_DIR.
        if unsafe { libc::geteuid() } != 0 {
            env::set_var("XDG_RUNTIME_DIR", "/run/user/4242");
            assert_eq!(resolve_state_dir(None), "/run/user/4242/sandlock-oci");
            env::remove_var("XDG_RUNTIME_DIR");
        }
    }
}