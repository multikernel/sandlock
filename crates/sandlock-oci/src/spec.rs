//! OCI `config.json` → `OciPolicy` translation.
//!
//! This module implements Phase 1 of the plan: parse the OCI runtime spec and
//! map its fields to an [`OciPolicy`] which can then be converted into a
//! `sandlock_core::Policy` / `Sandbox` or applied directly to confine a process.

use anyhow::{Context, Result};
use oci_spec::runtime::Spec;
use std::path::Path;

use crate::policy::OciPolicy;

/// Parse an OCI `config.json` from the given bundle directory.
pub fn load_spec(bundle: &Path) -> Result<Spec> {
    let config_path = bundle.join("config.json");
    Spec::load(&config_path)
        .with_context(|| format!("failed to load OCI spec from {:?}", config_path))
}

/// Map an OCI [`Spec`] to an [`OciPolicy`].
///
/// The mapping strategy (per the Plan):
/// - **Filesystem**: OCI mounts → `fs_read`/`fs_write`/`fs_mount`.
///   `rootfs` becomes the chroot path.
/// - **Resources**: `linux.resources.memory` → `max_memory`,
///   `pids.limit` → `max_processes`.
/// - **Process**: `process.cwd` → `cwd`, environment forwarded.
/// - **Namespaces**: Ignored — sandlock avoids namespaces by design.
pub fn spec_to_policy(spec: &Spec, bundle: &Path) -> Result<OciPolicy> {
    let policy = OciPolicy::from_spec(spec, bundle)
        .with_context(|| "failed to map OCI spec to sandlock policy")?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{ProcessBuilder, RootBuilder, SpecBuilder};
    use std::fs;
    use tempfile::tempdir;

    fn minimal_spec() -> Spec {
        SpecBuilder::default()
            .version("1.0.2")
            .root(RootBuilder::default().path("rootfs").readonly(false).build().unwrap())
            .process(
                ProcessBuilder::default()
                    .cwd("/app")
                    .args(vec!["sh".to_string()])
                    .env(vec!["PATH=/usr/bin:/bin".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    #[test]
    fn load_spec_roundtrip() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        let rootfs = bundle.join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        let spec = minimal_spec();
        spec.save(bundle.join("config.json")).unwrap();

        let loaded = load_spec(bundle).unwrap();
        assert_eq!(loaded.version(), spec.version());
    }

    #[test]
    fn spec_to_policy_sets_cwd() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let spec = minimal_spec();
        let policy = spec_to_policy(&spec, bundle).unwrap();
        assert_eq!(policy.cwd.as_deref(), Some(std::path::Path::new("/app")));
    }

    #[test]
    fn spec_to_policy_env() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let spec = minimal_spec();
        let policy = spec_to_policy(&spec, bundle).unwrap();
        assert!(policy.env.contains_key("PATH"));
    }

    #[test]
    fn spec_to_policy_rootfs_sets_chroot() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let spec = minimal_spec();
        let policy = spec_to_policy(&spec, bundle).unwrap();
        assert!(policy.rootfs.is_some());
        assert!(policy.rootfs.as_ref().unwrap().ends_with("rootfs"));
    }

    #[test]
    fn load_spec_missing_file_errors() {
        let dir = tempdir().unwrap();
        let result = load_spec(dir.path());
        assert!(result.is_err());
    }
}