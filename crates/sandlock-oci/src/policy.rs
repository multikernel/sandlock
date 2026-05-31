//! OCI policy — in-memory representation of OCI spec → sandlock mapping.
//!
//! `OciPolicy` captures the translated OCI configuration (rootfs, mounts,
//! resources, process settings) and provides methods to:
//!
//! - Build a `Sandbox` for the supervisor's seccomp/notif pipeline
//! - Apply filesystem confinement, chroot, cwd, and env to a child process
//!   before execve

use anyhow::Result;
use oci_spec::runtime::Spec;
use sandlock_core::sandbox::{ByteSize, Sandbox, SandboxBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};

/// Serializable OCI-to-sandlock policy representation.
///
/// Stored alongside state.json in the container's state directory so that
/// the supervisor (or any recovery tool) can reconstruct the confinement
/// parameters without re-parsing the OCI bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciPolicy {
    /// Absolute path to the container rootfs (chroot target).
    pub rootfs: Option<PathBuf>,

    /// Paths readable inside the container (relative to rootfs if set).
    pub fs_read: Vec<PathBuf>,

    /// Paths writable inside the container (relative to rootfs if set).
    pub fs_write: Vec<PathBuf>,

    /// Explicit bind mounts: (dest_inside_rootfs, host_source_path).
    pub fs_mount: Vec<(PathBuf, PathBuf)>,

    /// Initial working directory (relative to rootfs if set).
    pub cwd: Option<PathBuf>,

    /// Environment variables to set in the container.
    pub env: HashMap<String, String>,

    /// Memory limit (optional).
    pub max_memory: Option<ByteSize>,

    /// PID limit (optional).
    pub max_processes: Option<u32>,

    /// CPU percentage limit, 1-100 (optional).
    pub max_cpu: Option<u8>,
}

impl OciPolicy {
    /// Build an OciPolicy from a parsed OCI Spec and its bundle directory.
    pub fn from_spec(spec: &Spec, bundle: &Path) -> Result<Self> {
        let rootfs = rootfs_path(spec, bundle);

        let mut fs_read = Vec::new();
        let mut fs_write = Vec::new();
        let mut fs_mount = Vec::new();

        if rootfs.is_some() {
            // Standard read-only paths inside the chroot
            for p in &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev"] {
                fs_read.push(PathBuf::from(*p));
            }
            // /tmp is writable by default
            fs_write.push(PathBuf::from("/tmp"));
        }

        // Process mounts — populate fs_mount, fs_read, fs_write
        if let Some(mounts) = spec.mounts() {
            map_mounts(mounts, bundle, &rootfs, &mut fs_mount, &mut fs_read, &mut fs_write);
        }

        // oci-spec 0.7: sub-struct getters (via #[getset]) return &T / &Option<T>.
        // Use .clone() on those to get owned values so closures return owned types
        // (avoids E0515 "returns a value referencing closure parameter").

        // spec.process() / spec.linux() return &Option<T>; .as_ref() converts to Option<&T>
        // so and_then/map can work without moving out of the spec reference (E0507).
        // Closures return owned values (.clone()) so no "reference to closure param" errors.

        let cwd = spec.process().as_ref()
            .and_then(|p| {
                let c = p.cwd().clone();
                if c.as_os_str().is_empty() { None } else { Some(c) }
            });

        let env: HashMap<String, String> = spec.process().as_ref()
            .and_then(|p| p.env().clone())
            .map(|env| {
                env.iter()
                    .filter_map(|v| v.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let max_memory = spec.linux().as_ref()
            .and_then(|l| l.resources().clone())
            .and_then(|res| res.memory().clone())
            .and_then(|mem| {
                mem.limit().filter(|&l| l > 0).map(|l| ByteSize::bytes(l as u64))
            });

        let max_processes = spec.linux().as_ref()
            .and_then(|l| l.resources().clone())
            .and_then(|res| res.pids().clone())
            .and_then(|pids| {
                let limit = pids.limit();
                if limit > 0 { Some(limit as u32) } else { None }
            });

        let max_cpu = spec.linux().as_ref()
            .and_then(|l| l.resources().clone())
            .and_then(|res| res.cpu().clone())
            .and_then(|cpu| {
                let quota = cpu.quota()?;
                let period = cpu.period()?;
                if quota > 0 && period > 0 {
                    let pct = ((quota as f64 / period as f64) * 100.0).min(100.0) as u8;
                    if pct > 0 { Some(pct) } else { None }
                } else {
                    None
                }
            });

        Ok(OciPolicy {
            rootfs,
            fs_read,
            fs_write,
            fs_mount,
            cwd,
            env,
            max_memory,
            max_processes,
            max_cpu,
        })
    }

    /// Convert this OCI policy into a `Sandbox` for the supervisor's use.
    ///
    /// The supervisor uses this to configure the seccomp notifier, resource
    /// tracking, and network policy.  The returned Sandbox is not started —
    /// it is only used for its configuration fields.
    pub fn to_sandbox(&self) -> Result<Sandbox> {
        let mut builder = SandboxBuilder::default();

        if let Some(ref rootfs) = self.rootfs {
            builder = builder.chroot(rootfs);
        }

        for path in &self.fs_read {
            builder = builder.fs_read(path);
        }
        for path in &self.fs_write {
            builder = builder.fs_write(path);
        }
        for (virt, host) in &self.fs_mount {
            builder = builder.fs_mount(virt, host);
        }

        if let Some(ref cwd) = self.cwd {
            builder = builder.cwd(cwd);
        }

        for (k, v) in &self.env {
            builder = builder.env_var(k, v);
        }

        if let Some(mem) = self.max_memory {
            builder = builder.max_memory(mem);
        }
        if let Some(procs) = self.max_processes {
            builder = builder.max_processes(procs);
        }
        if let Some(cpu) = self.max_cpu {
            builder = builder.max_cpu(cpu);
        }

        // Build without cross-section validation since we're constructing from
        // a spec that may omit some fields that the builder requires.
        builder.build_unchecked().map_err(Into::into)
    }

    /// Apply filesystem confinement (Landlock rules) to the current process.
    ///
    /// This sets NO_NEW_PRIVS and installs the Landlock filesystem filter.
    /// It must be called in the child process after SIGCONT and before execve.
    pub fn confine(&self) -> Result<()> {
        let confinement = self.to_confinement();
        sandlock_core::confine(&confinement).map_err(Into::into)
    }

    /// Convert the OCI policy into a `Confinement` for Landlock application.
    fn to_confinement(&self) -> sandlock_core::Confinement {
        let mut builder = sandlock_core::ConfinementBuilder::default();
        for path in &self.fs_read {
            builder = builder.fs_read(path);
        }
        for path in &self.fs_write {
            builder = builder.fs_write(path);
        }
        builder.build()
    }

    /// Apply namespace-like setup and exec the command.
    ///
    /// This is called in the SIGSTOP'd child process after SIGCONT:
    ///   1. chroot (if rootfs is configured)
    ///   2. chdir to the spec's cwd (or chroot root)
    ///   3. Set environment variables from the spec
    ///   4. Apply Landlock confinement
    ///   5. execvp the command
    ///
    /// This function never returns on success.  On failure it prints to
    /// stderr and calls `_exit(127)`.
    pub fn apply_and_exec(&self, cmd: &[String]) -> ! {
        // 1. chroot into rootfs if configured
        if let Some(ref rootfs) = self.rootfs {
            let rootfs_cstr = match CString::new(rootfs.to_string_lossy().as_ref()) {
                Ok(c) => c,
                Err(_) => {
                    eprintln!("sandlock-oci: rootfs path contains NUL byte");
                    unsafe { libc::_exit(127) };
                }
            };
            if unsafe { libc::chroot(rootfs_cstr.as_ptr()) } != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("sandlock-oci: chroot({:?}) failed: {}", rootfs, err);
                unsafe { libc::_exit(127) };
            }
            // After chroot, ensure we're inside the new root
            if unsafe { libc::chdir(b"/\0".as_ptr() as *const libc::c_char) } != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("sandlock-oci: chdir(/) after chroot failed: {}", err);
                unsafe { libc::_exit(127) };
            }
        }

        // 2. Change working directory
        if let Some(ref cwd) = self.cwd {
            let target = if self.rootfs.is_some() {
                // cwd is already relative to the chroot
                cwd.strip_prefix("/").unwrap_or(cwd)
            } else {
                cwd
            };
            let target_cstr = match CString::new(target.to_string_lossy().as_ref()) {
                Ok(c) => c,
                Err(_) => {
                    eprintln!("sandlock-oci: cwd path contains NUL byte");
                    unsafe { libc::_exit(127) };
                }
            };
            if unsafe { libc::chdir(target_cstr.as_ptr()) } != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("sandlock-oci: chdir({:?}) failed: {}", cwd, err);
                unsafe { libc::_exit(127) };
            }
        }

        // 3. Set environment variables
        // Clear existing environment first if any env vars are specified
        if !self.env.is_empty() {
            // Remove all existing env vars that aren't in the spec
            for (key, _) in std::env::vars_os() {
                // Keep PATH if the spec doesn't provide one (fallback safety)
                if key == "PATH" && !self.env.contains_key("PATH") {
                    continue;
                }
                std::env::remove_var(&key);
            }
        }
        for (key, value) in &self.env {
            std::env::set_var(key, value);
        }

        // 4. Apply Landlock confinement
        if let Err(e) = self.confine() {
            eprintln!("sandlock-oci: failed to confine process: {}", e);
            unsafe { libc::_exit(127) };
        }

        // 5. execvp
        let c_args: Vec<CString> = cmd
            .iter()
            .map(|a| {
                CString::new(a.as_str()).unwrap_or_else(|_| {
                    eprintln!("sandlock-oci: invalid argument string");
                    unsafe { libc::_exit(127) };
                })
            })
            .collect();
        let mut ptrs: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
        ptrs.push(std::ptr::null());

        eprintln!(
            "sandlock-oci: execvp({:?})",
            c_args.first().map(|c| c.to_string_lossy())
        );
        unsafe { libc::execvp(c_args[0].as_ptr(), ptrs.as_ptr()) };

        // execvp failed
        let err = std::io::Error::last_os_error();
        eprintln!("sandlock-oci: execvp failed: {}", err);
        unsafe { libc::_exit(127) };
    }
}

/// Resolve the rootfs path from the OCI spec.
/// Returns `None` when the spec has no root, an empty path, or a path that
/// doesn't exist on disk (allows rootfs-less invocations and tests without a
/// real bundle).
fn rootfs_path(spec: &Spec, bundle: &Path) -> Option<PathBuf> {
    let raw = spec.root().as_ref()
        .and_then(|r| {
            let p = r.path().clone();
            if p.as_os_str().is_empty() { None } else { Some(p) }
        })?;
    if raw.is_absolute() {
        if raw.exists() { Some(raw) } else { None }
    } else {
        let joined = bundle.join(&raw);
        if joined.exists() { Some(joined) } else { None }
    }
}

/// Process OCI mounts into fs_mount, fs_read, and fs_write lists.
///
/// Skips kernel-only mount types (proc, sysfs, etc.) and applies
/// read/write permissions from mount options to the fs_read/fs_write
/// vectors rather than hardcoding paths.
fn map_mounts(
    mounts: &[oci_spec::runtime::Mount],
    bundle: &Path,
    rootfs: &Option<PathBuf>,
    fs_mount: &mut Vec<(PathBuf, PathBuf)>,
    fs_read: &mut Vec<PathBuf>,
    fs_write: &mut Vec<PathBuf>,
) {
    for mount in mounts {
        let dest = mount.destination();

        // Detect read-only option from mount options.
        let read_only = mount
            .options()
            .as_ref()
            .map(|opts| opts.iter().any(|o| o == "ro"))
            .unwrap_or(false);

        // Resolve source — relative paths are relative to the bundle.
        let source: Option<PathBuf> = mount.source().as_ref().map(|s| {
            if s.is_absolute() {
                s.clone()
            } else {
                bundle.join(s)
            }
        });

        // Skip kernel-provided virtual filesystems.
        // These don't need Landlock rules and can't be bind-mounted.
        let mount_type = mount.typ().as_deref().unwrap_or("bind");
        match mount_type {
            "proc" | "sysfs" | "devpts" | "tmpfs" | "mqueue" | "cgroup" | "cgroup2" => {
                continue;
            }
            _ => {}
        }

        // Bind mounts: record the mapping and set read/write permissions.
        if let Some(src) = source {
            if let Some(ref rootfs_path) = rootfs {
                // Resolve the destination relative to the chroot.
                let chroot_dest = rootfs_path.join(dest.strip_prefix("/").unwrap_or(dest));
                if chroot_dest.exists() || src.exists() {
                    fs_mount.push((dest.to_path_buf(), src));
                }
            } else {
                if src.exists() {
                    fs_mount.push((dest.to_path_buf(), src));
                }
            }

            if read_only {
                fs_read.push(dest.clone());
            } else {
                fs_write.push(dest.clone());
            }
        }
    }
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
                    .args(vec!["sh".to_string(), "-c".to_string(), "echo hello".to_string()])
                    .env(vec!["PATH=/usr/bin:/bin".to_string(), "FOO=bar".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    #[test]
    fn from_spec_parses_rootfs_and_cwd() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let spec = minimal_spec();
        let policy = OciPolicy::from_spec(&spec, bundle).unwrap();

        assert!(policy.rootfs.is_some());
        assert!(policy.rootfs.as_ref().unwrap().ends_with("rootfs"));
        assert_eq!(policy.cwd, Some(PathBuf::from("/app")));
    }

    #[test]
    fn from_spec_parses_env() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let spec = minimal_spec();
        let policy = OciPolicy::from_spec(&spec, bundle).unwrap();

        assert!(policy.env.contains_key("PATH"));
        assert_eq!(policy.env.get("FOO"), Some(&"bar".to_string()));
    }

    #[test]
    fn from_spec_parses_resources() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let policy = OciPolicy::from_spec(&minimal_spec(), bundle).unwrap();
        // No resources set in minimal_spec, so these should be None
        assert!(policy.max_memory.is_none());
        assert!(policy.max_processes.is_none());
        assert!(policy.max_cpu.is_none());
    }

    #[test]
    fn to_sandbox_builds_valid_sandbox() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let spec = minimal_spec();
        let policy = OciPolicy::from_spec(&spec, bundle).unwrap();
        let sandbox = policy.to_sandbox().unwrap();

        assert!(sandbox.chroot.is_some());
        assert!(sandbox.cwd.is_some());
        assert!(!sandbox.env.is_empty());
    }

    #[test]
    fn default_stdin_paths_without_rootfs() {
        let spec = SpecBuilder::default()
            .version("1.0.2")
            .process(
                ProcessBuilder::default()
                    .args(vec!["echo".to_string(), "hello".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let policy = OciPolicy::from_spec(&spec, Path::new("/tmp")).unwrap();
        assert!(policy.rootfs.is_none());
    }
}