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
use sandlock_core::sandbox::{ByteSize, RunAs, Sandbox, SandboxBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Serializable OCI-to-sandlock policy representation.
///
/// Stored alongside state.json in the sandbox's state directory so that
/// the supervisor (or any recovery tool) can reconstruct the confinement
/// parameters without re-parsing the OCI bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciPolicy {
    /// Absolute path to the sandbox rootfs (chroot target).
    pub rootfs: Option<PathBuf>,

    /// Paths readable inside the sandbox (relative to rootfs if set).
    pub fs_read: Vec<PathBuf>,

    /// Paths writable inside the sandbox (relative to rootfs if set).
    pub fs_write: Vec<PathBuf>,

    /// Explicit bind mounts: (dest_inside_rootfs, host_source_path).
    pub fs_mount: Vec<(PathBuf, PathBuf)>,

    /// Destinations (subset of `fs_mount`) mounted read-only: the host procfs
    /// mount and `ro` bind mounts. Writes are denied even with a writable root.
    pub fs_mount_ro: Vec<PathBuf>,

    /// Initial working directory (relative to rootfs if set).
    pub cwd: Option<PathBuf>,

    /// Environment variables to set in the sandbox.
    pub env: HashMap<String, String>,

    /// Memory limit (optional).
    pub max_memory: Option<ByteSize>,

    /// PID limit (optional).
    pub max_processes: Option<u32>,

    /// CPU percentage limit, 1-100 (optional).
    pub max_cpu: Option<u8>,

    /// CPU affinity from OCI `cpu.cpus` (cpuset): the exact cores the sandbox
    /// may run on, applied via sched_setaffinity in core.  An empty/malformed
    /// cpuset maps to None (no pinning) rather than a partial set.
    #[serde(default)]
    pub cpu_cores: Option<Vec<u32>>,

    /// Host directories backing emulated tmpfs mounts.  Created before launch
    /// and removed with the sandbox state dir on `delete`.
    #[serde(default)]
    pub scratch_dirs: Vec<PathBuf>,

    /// Run-as identity from OCI `process.user` (uid/gid). Passed straight to
    /// `builder.user(...)`; core decides whether a user namespace is actually
    /// needed (it self-skips when the identity already matches the runtime).
    pub run_user: Option<RunAs>,
}

impl OciPolicy {
    /// Build an OciPolicy from a parsed OCI Spec and its bundle directory.
    pub fn from_spec(spec: &Spec, bundle: &Path, id: &str) -> Result<Self> {
        let rootfs = rootfs_path(spec, bundle)?;

        // OCI `root.readonly`: when set, the sandbox rootfs must be read-only,
        // so the whole chroot is granted read access rather than read-write.
        let root_readonly = spec
            .root()
            .as_ref()
            .and_then(|r| r.readonly())
            .unwrap_or(false);

        let mut fs_read = Vec::new();
        let mut fs_write = Vec::new();
        let mut fs_mount = Vec::new();
        let mut fs_mount_ro = Vec::new();
        let mut scratch_dirs = Vec::new();

        if rootfs.is_some() {
            // The sandbox owns its rootfs, so grant the whole chroot rather
            // than guessing a fixed set of system directories.  `root.readonly`
            // selects read-only vs. read-write for the entire tree (fs_write's
            // Landlock mask already includes read access).  Individual mounts,
            // with their ro/rw options, layer on top via map_mounts.
            if root_readonly {
                fs_read.push(PathBuf::from("/"));
            } else {
                fs_write.push(PathBuf::from("/"));
            }
        }

        // Process mounts — populate fs_mount, fs_read, fs_write, scratch_dirs
        if let Some(mounts) = spec.mounts() {
            map_mounts(
                mounts, bundle, &rootfs, id,
                &mut fs_mount, &mut fs_mount_ro, &mut fs_read, &mut fs_write, &mut scratch_dirs,
            );
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

        // OCI `cpu.quota`/`cpu.period` express a CPU allowance in *cores*
        // (quota/period can exceed 1.0 for a multi-core cap).  sandlock-core's
        // `max_cpu` is a coarse global SIGSTOP/SIGCONT wall-clock duty cycle,
        // not a bandwidth controller: it gates how much wall-clock time the
        // whole process group may run, as a 1-100 value where 100 means "no
        // limit".  A >= 1-core allowance can't be expressed as such a value, so
        // map only a strict sub-core request (quota < period) here; a multi-core
        // cap belongs on affinity (`cpu_cores`), not on this throttle.  Don't
        // fake it by clamping to 100, which core reads as unlimited anyway.
        let max_cpu = spec.linux().as_ref()
            .and_then(|l| l.resources().clone())
            .and_then(|res| res.cpu().clone())
            .and_then(|cpu| {
                let quota = cpu.quota()?;
                let period = cpu.period()?;
                if quota <= 0 || period == 0 {
                    return None;
                }
                let ratio = quota as f64 / period as f64;
                if ratio >= 1.0 {
                    // Multi-core / full-core caps are not enforceable by the
                    // single-core throttle; don't pretend by emitting 100.
                    return None;
                }
                // Floor to 1% so a tiny but non-zero request isn't truncated to
                // 0 (which would drop to None == "no limit").
                Some(((ratio * 100.0) as u8).max(1))
            });

        // OCI `cpu.cpus` is a cpuset string ("0-3,7") naming the exact cores
        // the workload may run on.  It maps directly to core's `cpu_cores`
        // (sched_setaffinity), an exact, non-approximate mapping, so unlike a
        // multi-core quota it is genuine enforcement.
        let cpu_cores = spec.linux().as_ref()
            .and_then(|l| l.resources().clone())
            .and_then(|res| res.cpu().clone())
            .and_then(|cpu| cpu.cpus().clone())
            .and_then(|cpus| parse_cpuset(&cpus));

        // OCI process.user → run-as identity (uid/gid, both required by the spec).
        let run_user = spec.process().as_ref().map(|p| {
            let u = p.user();
            RunAs { uid: u.uid(), gid: u.gid() }
        });

        Ok(OciPolicy {
            rootfs,
            fs_read,
            fs_write,
            fs_mount,
            fs_mount_ro,
            cwd,
            env,
            max_memory,
            max_processes,
            max_cpu,
            cpu_cores,
            scratch_dirs,
            run_user,
        })
    }

    /// Convert this OCI policy into a [`Sandbox`] ready to be driven by
    /// `create_interactive()` + `start()` + `wait()`.
    ///
    /// The resulting `Sandbox` carries: chroot, filesystem rules (read/write/
    /// mount), working directory, environment (clean), resource limits (memory,
    /// CPU, process count), and bind-mount mappings.  The caller is responsible
    /// for calling `sandbox.set_name(id)` and then `create_interactive`.
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
            if self.fs_mount_ro.iter().any(|d| d == virt) {
                builder = builder.fs_mount_ro(virt, host);
            } else {
                builder = builder.fs_mount(virt, host);
            }
        }

        if let Some(ref cwd) = self.cwd {
            builder = builder.cwd(cwd);
        }

        // Start from a clean environment so the sandbox sees exactly the
        // vars declared in the OCI spec, not the supervisor's inherited env.
        builder = builder.clean_env(true);
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
        if let Some(ref cores) = self.cpu_cores {
            builder = builder.cpu_cores(cores.clone());
        }

        // OCI process.user: hand the requested identity to core unconditionally.
        // Core engages a user namespace only when it differs from the runtime's
        // own uid/gid, so we don't reimplement that decision here.
        if let Some(ru) = self.run_user {
            builder = builder.user(ru.uid, ru.gid);
        }

        // Container workloads legitimately run servers (nginx, etc.). sandlock
        // gates bind() by default-deny (Landlock BIND_TCP), so without this an
        // in-container server fails bind() with EACCES and the container exits,
        // which in turn hangs any readiness/verification exec that waits on it.
        // Enable port remapping: binds are emulated on-behalf and succeed,
        // using the requested port when free and a fresh host port only on
        // conflict, so co-located sandboxes never collide on a host port.
        builder = builder.port_remap(true);

        builder.build_unchecked().map_err(Into::into)
    }
}

/// Parse an OCI cpuset string into a sorted, de-duplicated list of CPU indices.
///
/// Accepts comma-separated indices and inclusive ranges, e.g. `"0-3,5,7-8"` →
/// `[0,1,2,3,5,7,8]`.  Whitespace around tokens is ignored.  Returns `None` for
/// an empty cpuset or on any malformed token (bad number, reversed range), so a
/// broken cpuset drops to "no pinning" rather than applying a partial affinity.
fn parse_cpuset(s: &str) -> Option<Vec<u32>> {
    let mut cores = std::collections::BTreeSet::new();
    for token in s.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match token.split_once('-') {
            Some((a, b)) => {
                let start: u32 = a.trim().parse().ok()?;
                let end: u32 = b.trim().parse().ok()?;
                if end < start {
                    return None;
                }
                for c in start..=end {
                    cores.insert(c);
                }
            }
            None => {
                cores.insert(token.parse().ok()?);
            }
        }
    }
    if cores.is_empty() {
        None
    } else {
        Some(cores.into_iter().collect())
    }
}

/// Resolve the rootfs path from the OCI spec.
///
/// Returns `Ok(None)` when the spec declares no root (or an empty path): a
/// legitimately rootfs-less invocation. Returns an error when a root path *is*
/// declared but does not resolve to an existing directory, so a broken bundle
/// fails fast at `create` rather than launching chroot-less and failing
/// obscurely at execve.
fn rootfs_path(spec: &Spec, bundle: &Path) -> Result<Option<PathBuf>> {
    let raw = match spec.root().as_ref().and_then(|r| {
        let p = r.path().clone();
        if p.as_os_str().is_empty() { None } else { Some(p) }
    }) {
        Some(p) => p,
        None => return Ok(None),
    };
    let resolved = if raw.is_absolute() { raw } else { bundle.join(&raw) };
    if resolved.exists() {
        Ok(Some(resolved))
    } else {
        anyhow::bail!(
            "rootfs path {:?} declared in config.json does not exist",
            resolved
        )
    }
}

/// Translate OCI mounts into sandlock primitives by intent:
///
/// - **bind** (real source): `fs_mount(dest, source)`, ro/rw from options.
/// - **tmpfs** writable scratch (`/tmp`, `/run`, `/dev/shm`, …): backed by a
///   host directory under the sandbox state dir and bind-mounted read-write,
///   so it works on a read-only root and stays isolated from the rootfs.
/// - **proc**: `fs_mount(dest, /proc)` read-only — the host procfs, so the
///   sandbox gets a full `/proc` like a container; the seccomp `/proc` handler
///   synthesizes the limit-aware files on top and blocks foreign PIDs /
///   sensitive paths. Read-only blocks host-global writes (`/proc/sys/*`).
/// - **sysfs**: `fs_mount(dest, /sys)` read-only — the host sysfs, so the
///   sandbox sees a populated `/sys`. Read-only blocks host-global writes
///   (`/sys/power/state`, …); there is no per-path filter, so reads are full
///   host sysfs (as in a container's ro `/sys`).
/// - **tmpfs at `/dev`**: passed through read-only so sandlock's `/dev`
///   interception services it; an empty backing dir would shadow `/dev/null`.
/// - **devpts/mqueue/cgroup**: skipped (no safe namespace-less equivalent).
fn map_mounts(
    mounts: &[oci_spec::runtime::Mount],
    bundle: &Path,
    rootfs: &Option<PathBuf>,
    id: &str,
    fs_mount: &mut Vec<(PathBuf, PathBuf)>,
    fs_mount_ro: &mut Vec<PathBuf>,
    fs_read: &mut Vec<PathBuf>,
    fs_write: &mut Vec<PathBuf>,
    scratch_dirs: &mut Vec<PathBuf>,
) {
    for mount in mounts {
        let dest = mount.destination();
        let mount_type = mount.typ().as_deref().unwrap_or("bind");

        match mount_type {
            // /proc: mount the host procfs READ-ONLY at the requested
            // destination so the sandbox gets a full /proc (version, stat,
            // self/*, <pid>/*, the directory listing, …) like a real container;
            // an empty rootfs /proc would otherwise leave it bare.  The seccomp
            // /proc handler runs before this chroot mount, so it still (a)
            // synthesizes the cgroup/limit-aware files (meminfo, loadavg,
            // mounts, net/*) on top, and (b) blocks foreign PIDs and sensitive
            // paths.  Read-only is essential: a writable host procfs would let
            // the sandbox write host-global controls like /proc/sys/* and
            // /proc/sysrq-trigger (a host-escape vector).
            "proc" => {
                fs_mount.push((dest.to_path_buf(), PathBuf::from("/proc")));
                fs_mount_ro.push(dest.to_path_buf());
            }
            // sysfs: mount the host /sys READ-ONLY at the requested destination
            // so the sandbox sees a populated /sys like a container (an empty
            // rootfs /sys is otherwise bare).  Read-only is mandatory: writable
            // sysfs exposes host-global controls (/sys/power/state,
            // /sys/kernel/*, device controls).  Unlike /proc there is no
            // per-path sandlock filter for sysfs, so this is full read-only host
            // sysfs exposure (consistent with a container's ro /sys mount).
            "sysfs" => {
                fs_mount.push((dest.to_path_buf(), PathBuf::from("/sys")));
                fs_mount_ro.push(dest.to_path_buf());
            }

            "tmpfs" => {
                if dest.to_str() == Some("/dev") {
                    // The device filesystem — pass through; nodes are served by
                    // interception, an empty backing dir would hide them.
                    fs_read.push(PathBuf::from("/dev"));
                } else {
                    // Writable scratch (e.g. /tmp, /run, /dev/shm).  Back it with
                    // a host dir under the state dir so writes are isolated from a
                    // read-only rootfs and cleaned up with the state dir on delete.
                    let backing = Path::new(&crate::state::state_dir())
                        .join(id)
                        .join("tmpfs")
                        .join(dest.strip_prefix("/").unwrap_or(dest));
                    fs_mount.push((dest.to_path_buf(), backing.clone()));
                    fs_write.push(dest.to_path_buf());
                    scratch_dirs.push(backing);
                }
            }

            // No safe namespace-less equivalent.
            "devpts" | "mqueue" | "cgroup" | "cgroup2" => {}

            // Bind mounts (and any other type carrying a real source).
            _ => {
                let read_only = mount
                    .options()
                    .as_ref()
                    .map(|opts| opts.iter().any(|o| o == "ro"))
                    .unwrap_or(false);
                let source: Option<PathBuf> = mount.source().as_ref().map(|s| {
                    if s.is_absolute() { s.clone() } else { bundle.join(s) }
                });
                if let Some(src) = source {
                    let keep = match rootfs {
                        Some(rootfs_path) => {
                            let chroot_dest =
                                rootfs_path.join(dest.strip_prefix("/").unwrap_or(dest));
                            chroot_dest.exists() || src.exists()
                        }
                        None => src.exists(),
                    };
                    if keep {
                        fs_mount.push((dest.to_path_buf(), src));
                        if read_only {
                            fs_read.push(dest.to_path_buf());
                            fs_mount_ro.push(dest.to_path_buf());
                        } else {
                            fs_write.push(dest.to_path_buf());
                        }
                    }
                }
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
        let policy = OciPolicy::from_spec(&spec, bundle, "test").unwrap();

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
        let policy = OciPolicy::from_spec(&spec, bundle, "test").unwrap();

        assert!(policy.env.contains_key("PATH"));
        assert_eq!(policy.env.get("FOO"), Some(&"bar".to_string()));
    }

    #[test]
    fn from_spec_parses_resources() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let policy = OciPolicy::from_spec(&minimal_spec(), bundle, "test").unwrap();
        // No resources set in minimal_spec, so these should be None
        assert!(policy.max_memory.is_none());
        assert!(policy.max_processes.is_none());
        assert!(policy.max_cpu.is_none());
    }

    /// Build a spec carrying `linux.resources.cpu.{quota,period}`.
    fn spec_with_cpu(quota: i64, period: u64) -> Spec {
        let json = serde_json::json!({
            "ociVersion": "1.0.2",
            "root": { "path": "rootfs", "readonly": false },
            "process": { "user": { "uid": 0, "gid": 0 }, "cwd": "/", "args": ["sh"] },
            "linux": { "resources": { "cpu": { "quota": quota, "period": period } } }
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn cpu_sub_core_maps_to_percentage() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();
        // Half a core → 50%.
        let policy = OciPolicy::from_spec(&spec_with_cpu(50_000, 100_000), bundle, "t").unwrap();
        assert_eq!(policy.max_cpu, Some(50));
    }

    #[test]
    fn cpu_one_full_core_not_mapped_to_max_cpu() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();
        // Exactly one core is not a sub-core request; max_cpu's 1-100 value
        // can't express it (100 reads as "no limit"), so it doesn't belong on
        // this throttle. None here; a real cap would go on affinity.
        let policy = OciPolicy::from_spec(&spec_with_cpu(100_000, 100_000), bundle, "t").unwrap();
        assert_eq!(policy.max_cpu, None);
    }

    #[test]
    fn cpu_multi_core_request_not_clamped_to_100() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();
        // A 2-core (200%) allowance must NOT silently collapse to max_cpu=100;
        // it can't be expressed as a 1-100 value, so it stays off this knob.
        let policy = OciPolicy::from_spec(&spec_with_cpu(200_000, 100_000), bundle, "t").unwrap();
        assert_eq!(policy.max_cpu, None);
    }

    #[test]
    fn cpu_tiny_fraction_floors_to_one() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();
        // 0.5% would truncate to 0; floor to 1 so the limit isn't dropped.
        let policy = OciPolicy::from_spec(&spec_with_cpu(500, 100_000), bundle, "t").unwrap();
        assert_eq!(policy.max_cpu, Some(1));
    }

    /// Build a spec carrying `linux.resources.cpu.cpus` (cpuset).
    fn spec_with_cpuset(cpus: &str) -> Spec {
        let json = serde_json::json!({
            "ociVersion": "1.0.2",
            "root": { "path": "rootfs", "readonly": false },
            "process": { "user": { "uid": 0, "gid": 0 }, "cwd": "/", "args": ["sh"] },
            "linux": { "resources": { "cpu": { "cpus": cpus } } }
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn parse_cpuset_indices_and_ranges() {
        assert_eq!(parse_cpuset("0-3"), Some(vec![0, 1, 2, 3]));
        assert_eq!(parse_cpuset("0,2,4"), Some(vec![0, 2, 4]));
        assert_eq!(parse_cpuset("0-3,7"), Some(vec![0, 1, 2, 3, 7]));
        assert_eq!(parse_cpuset("3-3"), Some(vec![3]));
        // Whitespace tolerated; overlaps de-duplicated and sorted.
        assert_eq!(parse_cpuset(" 1 , 0 , 0-1 "), Some(vec![0, 1]));
    }

    #[test]
    fn parse_cpuset_rejects_malformed() {
        assert_eq!(parse_cpuset(""), None);
        assert_eq!(parse_cpuset("   "), None);
        assert_eq!(parse_cpuset("x"), None);
        assert_eq!(parse_cpuset("1-"), None);
        assert_eq!(parse_cpuset("3-1"), None); // reversed range
    }

    #[test]
    fn cpuset_maps_to_cpu_cores() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let policy = OciPolicy::from_spec(&spec_with_cpuset("0-3,7"), bundle, "t").unwrap();
        assert_eq!(policy.cpu_cores, Some(vec![0, 1, 2, 3, 7]));

        // And it reaches the sandbox as a real affinity list.
        let sandbox = policy.to_sandbox().unwrap();
        assert_eq!(sandbox.cpu_cores, Some(vec![0, 1, 2, 3, 7]));
    }

    #[test]
    fn no_cpuset_yields_no_cpu_cores() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();
        // minimal_spec sets no cpu.cpus.
        let policy = OciPolicy::from_spec(&minimal_spec(), bundle, "t").unwrap();
        assert_eq!(policy.cpu_cores, None);
    }

    #[test]
    fn readonly_root_grants_rootfs_read_only() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let spec = SpecBuilder::default()
            .version("1.0.2")
            .root(RootBuilder::default().path("rootfs").readonly(true).build().unwrap())
            .process(
                ProcessBuilder::default()
                    .args(vec!["sh".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let policy = OciPolicy::from_spec(&spec, bundle, "test").unwrap();
        assert!(policy.fs_read.contains(&PathBuf::from("/")));
        assert!(!policy.fs_write.contains(&PathBuf::from("/")));
    }

    #[test]
    fn writable_root_grants_rootfs_writable() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        // minimal_spec() sets readonly(false).
        let policy = OciPolicy::from_spec(&minimal_spec(), bundle, "test").unwrap();
        assert!(policy.fs_write.contains(&PathBuf::from("/")));
        assert!(!policy.fs_read.contains(&PathBuf::from("/")));
    }

    #[test]
    fn tmpfs_scratch_backed_proc_dev_passthrough() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let json = serde_json::json!({
            "ociVersion": "1.0.2",
            "root": { "path": "rootfs", "readonly": true },
            "process": { "user": { "uid": 0, "gid": 0 }, "cwd": "/", "args": ["sh"] },
            "mounts": [
                { "destination": "/tmp",  "type": "tmpfs", "source": "tmpfs" },
                { "destination": "/proc", "type": "proc",  "source": "proc" },
                { "destination": "/sys",  "type": "sysfs", "source": "sysfs" },
                { "destination": "/dev",  "type": "tmpfs", "source": "tmpfs" }
            ]
        });
        let spec: Spec = serde_json::from_value(json).unwrap();

        let policy = OciPolicy::from_spec(&spec, bundle, "ctr1").unwrap();

        // /tmp is writable scratch: bind-mounted to a backing dir under the
        // state dir, recorded for creation, and marked writable.
        assert!(policy
            .fs_mount
            .iter()
            .any(|(d, h)| d == Path::new("/tmp") && h.ends_with("ctr1/tmpfs/tmp")));
        assert!(policy.scratch_dirs.iter().any(|d| d.ends_with("ctr1/tmpfs/tmp")));
        assert!(policy.fs_write.contains(&PathBuf::from("/tmp")));

        // /proc mounts the host procfs so the sandbox gets a full /proc; the
        // seccomp /proc handler synthesizes the limit-aware files on top.
        assert!(policy
            .fs_mount
            .iter()
            .any(|(d, h)| d == Path::new("/proc") && h == Path::new("/proc")));
        // ...and it is read-only, so the sandbox can't write host-global
        // controls like /proc/sys/* through the mount.
        assert!(policy.fs_mount_ro.contains(&PathBuf::from("/proc")));
        // /sys mounts the host sysfs read-only, same as /proc.
        assert!(policy
            .fs_mount
            .iter()
            .any(|(d, h)| d == Path::new("/sys") && h == Path::new("/sys")));
        assert!(policy.fs_mount_ro.contains(&PathBuf::from("/sys")));
        // /dev is passed through read-only, not emulated.
        assert!(policy.fs_read.contains(&PathBuf::from("/dev")));
        assert!(!policy.fs_mount.iter().any(|(d, _)| d == Path::new("/dev")));
    }

    #[test]
    fn to_sandbox_builds_valid_sandbox() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let spec = minimal_spec();
        let policy = OciPolicy::from_spec(&spec, bundle, "test").unwrap();
        let sandbox = policy.to_sandbox().unwrap();

        assert!(sandbox.chroot.is_some());
        assert!(sandbox.cwd.is_some());
        assert!(!sandbox.env.is_empty());
        // Container workloads must be able to bind ports (servers); port
        // remapping is enabled so bind() succeeds instead of EACCES-exiting.
        assert!(sandbox.port_remap, "OCI containers must allow port binding");
    }

    #[test]
    fn rootfs_less_spec_yields_no_chroot() {
        // An explicitly empty root path is a legitimately rootfs-less
        // invocation: no chroot, confined against host paths only.
        let spec = SpecBuilder::default()
            .version("1.0.2")
            .root(RootBuilder::default().path("").build().unwrap())
            .process(
                ProcessBuilder::default()
                    .args(vec!["echo".to_string(), "hello".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let policy = OciPolicy::from_spec(&spec, Path::new("/tmp"), "test").unwrap();
        assert!(policy.rootfs.is_none());
    }

    #[test]
    fn declared_but_missing_rootfs_errors() {
        // A root path that is declared but does not exist must fail fast at
        // policy build rather than silently launching without a chroot.
        let spec = SpecBuilder::default()
            .version("1.0.2")
            .root(RootBuilder::default().path("rootfs").build().unwrap())
            .process(
                ProcessBuilder::default()
                    .args(vec!["sh".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let bundle = tempdir().unwrap();
        // Note: no rootfs dir created under the bundle.
        let err = OciPolicy::from_spec(&spec, bundle.path(), "test").unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn process_user_populates_run_as() {
        let dir = tempdir().unwrap();
        let bundle = dir.path();
        fs::create_dir_all(bundle.join("rootfs")).unwrap();

        let json = serde_json::json!({
            "ociVersion": "1.0.2",
            "root": { "path": "rootfs", "readonly": false },
            "process": { "user": { "uid": 1000, "gid": 2000 }, "cwd": "/", "args": ["sh"] },
        });
        let spec: Spec = serde_json::from_value(json).unwrap();
        let policy = OciPolicy::from_spec(&spec, bundle, "test").unwrap();
        // process.user flows into run_user; the userns skip decision is core's.
        assert_eq!(policy.run_user, Some(RunAs { uid: 1000, gid: 2000 }));

        let sandbox = policy.to_sandbox().unwrap();
        assert_eq!(sandbox.user, Some(RunAs { uid: 1000, gid: 2000 }));
    }
}