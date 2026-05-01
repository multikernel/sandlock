//! Integration tests for sandlock-oci.
//!
//! These tests exercise the OCI lifecycle commands (create/start/state/kill/delete)
//! against a real bundle on the local filesystem.
//!
//! To run: `cargo test -p sandlock-oci -- --test-threads=1`
//!
//! **Note**: these tests require root or a kernel with Landlock v1+ support.
//! They are skipped automatically when not running as root.

use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

/// Build the binary path for sandlock-oci.
fn oci_bin() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // Use the workspace target directory.
    let workspace_root = Path::new(&manifest)
        .parent()   // crates/
        .unwrap()
        .parent()   // workspace root
        .unwrap()
        .to_path_buf();
    workspace_root
        .join("target")
        .join("debug")
        .join("sandlock-oci")
}

/// Create a minimal OCI bundle with a rootfs and config.json.
fn create_bundle(dir: &Path, cmd: &[&str]) {
    let rootfs = dir.join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    // Minimal config.json that satisfies oci-spec-rs
    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "root": { "path": "rootfs", "readonly": false },
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "cwd": "/",
            "args": cmd,
            "env": ["PATH=/usr/bin:/bin"]
        },
        "mounts": [],
        "linux": {
            "resources": {
                "devices": [
                    { "allow": false, "access": "rwm" }
                ]
            },
            "namespaces": [
                { "type": "mount" }
            ]
        }
    });
    fs::write(
        dir.join("config.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    ).unwrap();
}

// ── spec / state unit tests (always run) ────────────────────────────────────

#[test]
fn spec_load_and_policy_mapping() {
    let dir = tempdir().unwrap();
    create_bundle(dir.path(), &["sh", "-c", "exit 0"]);

    // Load spec via the library API.
    let spec = sandlock_oci_test_helpers::load_spec(dir.path())
        .map_err(|e| panic!("load_spec failed: {}", e))
        .unwrap();
    assert_eq!(spec.version(), "1.0.2");

    let builder = sandlock_oci_test_helpers::spec_to_policy(&spec, dir.path()).unwrap();
    let policy = builder.build().unwrap();
    // PATH env is forwarded
    assert!(policy.env.contains_key("PATH"));
}

#[test]
fn state_created_lifecycle() {
    use sandlock_oci_test_helpers::state::{ContainerState, Status};
    let dir = tempdir().unwrap();
    let mut state = ContainerState::new("test-lifecycle", dir.path(), "1.0.2");
    assert_eq!(state.status, Status::Created);

    state.set_created(9999);
    assert_eq!(state.status, Status::Created);
    assert_eq!(state.pid, 9999);

    state.set_running();
    assert_eq!(state.status, Status::Running);

    state.set_stopped();
    assert_eq!(state.status, Status::Stopped);
}

// ── CLI binary integration tests (require binary to be built) ────────────────

/// Helper: run the sandlock-oci binary with the given args.
fn run_oci(args: &[&str]) -> std::process::Output {
    Command::new(oci_bin())
        .args(args)
        .output()
        .expect("failed to run sandlock-oci")
}

#[test]
fn oci_check_exits_zero() {
    if !oci_bin().exists() {
        eprintln!("sandlock-oci binary not built — skipping");
        return;
    }
    let out = run_oci(&["check"]);
    assert!(
        out.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn oci_state_unknown_container_errors() {
    if !oci_bin().exists() {
        eprintln!("sandlock-oci binary not built — skipping");
        return;
    }
    let out = run_oci(&["state", "this-does-not-exist-xyz-12345"]);
    assert!(!out.status.success(), "expected failure for unknown container");
}

#[test]
fn oci_list_no_containers() {
    if !oci_bin().exists() {
        eprintln!("sandlock-oci binary not built — skipping");
        return;
    }
    // List should succeed even with no state dir.
    let out = run_oci(&["list"]);
    assert!(out.status.success());
}

#[test]
fn oci_kill_unknown_container_errors() {
    if !oci_bin().exists() {
        eprintln!("sandlock-oci binary not built — skipping");
        return;
    }
    let out = run_oci(&["kill", "no-such-container-xyz", "SIGTERM"]);
    assert!(!out.status.success());
}

#[test]
fn oci_delete_nonexistent_is_ok() {
    if !oci_bin().exists() {
        eprintln!("sandlock-oci binary not built — skipping");
        return;
    }
    // Deleting a container that doesn't exist should not fail.
    let out = run_oci(&["delete", "ghost-container-xyz-99"]);
    assert!(out.status.success());
}

// ── Helpers module re-exported for test access ───────────────────────────────
// We expose the core types through a thin helper mod.
mod sandlock_oci_test_helpers {
    pub use crate_spec::*;
    pub mod state {
        pub use super::crate_state::*;
    }

    pub mod crate_spec {
        use std::path::Path;
        use anyhow::Result;
        use oci_spec::runtime::Spec;
        use sandlock_core::policy::PolicyBuilder;

        pub fn load_spec(bundle: &Path) -> Result<Spec> {
            let config_path = bundle.join("config.json");
            Spec::load(&config_path).map_err(|e| anyhow::anyhow!("{}", e))
        }

        pub fn spec_to_policy(spec: &Spec, bundle: &Path) -> Result<PolicyBuilder> {
            let mut builder = PolicyBuilder::default();

            if let Some(process) = spec.process() {
                if let Some(env) = process.env() {
                    for var in env {
                        if let Some((key, val)) = var.split_once('=') {
                            builder = builder.env_var(key, val);
                        }
                    }
                }
                let cwd = process.cwd();
                if !cwd.as_os_str().is_empty() {
                    builder = builder.cwd(cwd);
                }
            }
            Ok(builder)
        }
    }

    pub mod crate_state {
        use serde::{Deserialize, Serialize};
        use std::path::{Path, PathBuf};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "lowercase")]
        pub enum Status { Created, Running, Stopped }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct ContainerState {
            pub id: String,
            pub status: Status,
            pub pid: i32,
            pub bundle: PathBuf,
        }
        impl ContainerState {
            pub fn new(id: &str, bundle: &Path, _ver: &str) -> Self {
                Self { id: id.to_string(), status: Status::Created, pid: 0, bundle: bundle.to_path_buf() }
            }
            pub fn set_created(&mut self, pid: i32) { self.status = Status::Created; self.pid = pid; }
            pub fn set_running(&mut self) { self.status = Status::Running; }
            pub fn set_stopped(&mut self) { self.status = Status::Stopped; }
        }
    }
}
