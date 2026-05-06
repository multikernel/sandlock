//! OCI `config.json` → `sandlock::Policy` translation.
//!
//! This module implements Phase 1 of the plan: parse the OCI runtime spec and
//! map its fields to a `sandlock_core::Policy`.

use anyhow::{bail, Context, Result};
use oci_spec::runtime::{LinuxResources, Mount, Process, Spec};
use sandlock_core::policy::{ByteSize, FsIsolation, PolicyBuilder};
use std::path::{Path, PathBuf};

/// Parse an OCI `config.json` from the given bundle directory.
pub fn load_spec(bundle: &Path) -> Result<Spec> {
    let config_path = bundle.join("config.json");
    Spec::load(&config_path)
        .with_context(|| format!("failed to load OCI spec from {:?}", config_path))
}

/// Map an OCI [`Spec`] to a [`sandlock_core::Policy`].
///
/// The mapping strategy (per the Plan):
/// - **Filesystem**: OCI mounts → `fs_readable`/`fs_writable`/`fs_mount`.
///   `rootfs` becomes the chroot path.
/// - **Resources**: `linux.resources.memory` → `max_memory`,
///   `pids.limit` → `max_processes`.
/// - **Process**: `process.cwd` → `cwd`, environment forwarded.
/// - **Namespaces**: Ignored — sandlock avoids namespaces by design.
pub fn spec_to_policy(spec: &Spec, bundle: &Path) -> Result<PolicyBuilder> {
    let mut builder = PolicyBuilder::default();

    // ── Rootfs (chroot) ──────────────────────────────────────────────────────
    let rootfs_path = {
        let raw = spec
            .root()
            .as_ref()
            .map(|r| r.path().clone())
            .unwrap_or_else(|| PathBuf::from("rootfs"));
        if raw.is_absolute() {
            raw
        } else {
            bundle.join(raw)
        }
    };
    if rootfs_path.exists() {
        builder = builder.chroot(&rootfs_path);
        // Standard read-only paths inside the chroot
        for ro_path in &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev"] {
            builder = builder.fs_read(ro_path);
        }
        builder = builder.fs_write("/tmp");
    }

    // ── Process ──────────────────────────────────────────────────────────────
    if let Some(process) = spec.process() {
        builder = map_process(builder, process);
    }

    // ── Mounts ───────────────────────────────────────────────────────────────
    if let Some(mounts) = spec.mounts() {
        builder = map_mounts(builder, mounts, bundle);
    }

    // ── Linux resources ──────────────────────────────────────────────────────
    if let Some(linux) = spec.linux() {
        if let Some(resources) = linux.resources() {
            builder = map_resources(builder, resources)?;
        }
    }

    Ok(builder)
}

// ── Private helpers ──────────────────────────────────────────────────────────

fn map_process(mut builder: PolicyBuilder, process: &Process) -> PolicyBuilder {
    // Working directory
    let cwd = process.cwd();
    if !cwd.as_os_str().is_empty() {
        builder = builder.cwd(cwd);
    }

    // Environment variables
    if let Some(env) = process.env() {
        for var in env {
            if let Some((key, val)) = var.split_once('=') {
                builder = builder.env_var(key, val);
            }
        }
    }

    builder
}

fn map_mounts(mut builder: PolicyBuilder, mounts: &[Mount], bundle: &Path) -> PolicyBuilder {
    for mount in mounts {
        let dest = mount.destination();

        // Detect read-only option
        let read_only = mount
            .options()
            .as_ref()
            .map(|opts| opts.iter().any(|o| o == "ro"))
            .unwrap_or(false);

        // Resolve source — relative paths are relative to the bundle
        let source: Option<PathBuf> = mount.source().as_ref().map(|s| {
            if s.is_absolute() {
                s.clone()
            } else {
                bundle.join(s)
            }
        });

        // Skip special kernel filesystems that sandlock doesn't need to mount
        let mount_type = mount.typ().as_deref().unwrap_or("bind");
        match mount_type {
            "proc" | "sysfs" | "devpts" | "tmpfs" | "mqueue" | "cgroup" | "cgroup2" => {
                // These are kernel-provided; skip for sandlock's namespace-less model
                continue;
            }
            _ => {}
        }

        // Bind mounts: map to fs_mount + readable/writable
        if let Some(src) = source {
            if src.exists() {
                builder = builder.fs_mount(dest, &src);
                if read_only {
                    builder = builder.fs_read(dest);
                } else {
                    builder = builder.fs_write(dest);
                }
            }
        }
    }
    builder
}

fn map_resources(mut builder: PolicyBuilder, resources: &LinuxResources) -> Result<PolicyBuilder> {
    // Memory limit
    if let Some(memory) = resources.memory() {
        if let Some(limit) = memory.limit() {
            if limit > 0 {
                builder = builder.max_memory(ByteSize::bytes(limit as u64));
            }
        }
    }

    // PID limit → max_processes
    if let Some(pids) = resources.pids() {
        if pids.limit() > 0 {
            builder = builder.max_processes(pids.limit() as u32);
        }
    }

    // CPU quota → max_cpu (approximate: quota/period * 100)
    if let Some(cpu) = resources.cpu() {
        if let (Some(quota), Some(period)) = (cpu.quota(), cpu.period()) {
            if quota > 0 && period > 0 {
                let pct = ((quota as f64 / period as f64) * 100.0).min(100.0) as u8;
                if pct > 0 {
                    builder = builder.max_cpu(pct);
                }
            }
        }
    }

    Ok(builder)
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
        let builder = spec_to_policy(&spec, bundle).unwrap();
        let policy = builder.build().unwrap();
        assert_eq!(policy.cwd.as_deref(), Some(std::path::Path::new("/app")));
    }

    #[test]
    fn spec_to_policy_env() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let spec = minimal_spec();
        let builder = spec_to_policy(&spec, bundle).unwrap();
        let policy = builder.build().unwrap();
        assert!(policy.env.contains_key("PATH"));
    }

    #[test]
    fn load_spec_missing_file_errors() {
        let dir = tempdir().unwrap();
        let result = load_spec(dir.path());
        assert!(result.is_err());
    }
}
