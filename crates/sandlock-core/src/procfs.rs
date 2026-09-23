// /proc file virtualization and PID filtering via seccomp notification.
//
// Intercepts openat syscalls that target sensitive /proc paths or virtual
// files (/proc/cpuinfo, /proc/meminfo). For virtual files, creates a memfd
// with fake content and injects it into the child's fd table.
//
// Continue safety (issue #27):
//   - Sensitive-path denials use Errno(EACCES) — TOCTOU-safe: the seccomp
//     response *is* the answer; the kernel does not re-read user memory.
//   - Virtualized paths (cpuinfo, meminfo, mounts, /proc/net/*, hostname,
//     etc.) use InjectFdSend with a sealed memfd — the child's fd table
//     ends up with our memfd, and the kernel never re-resolves the path
//     string after injection.
//   - Continue is reserved for fall-through cases: read_path failed (kernel
//     will re-read and EFAULT identically), the path doesn't match any
//     virtualized entry, or supervisor-side I/O on /proc/<pid>/fd/<n>
//     read_link returned an error. None of these cases involve the
//     supervisor approving a syscall based on user-controlled string
//     contents, so the seccomp_unotify TOCTOU class doesn't apply.
//   - A task's own /proc/self opens use InjectFdSend with an fd the
//     supervisor opened from its own copy of the path, so a later swap of
//     the string in child memory changes nothing.

use std::collections::HashSet;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::seccomp::notif::{
    content_memfd, inject_open_result, openat2_at, write_child_mem, NotifAction, NotifPolicy,
    OpenArgs, OpenRequest,
};
use crate::seccomp::state::{NetworkState, ProcessIndex};
use crate::sys::structs::{SeccompNotif, EACCES};

// ============================================================
// Sensitive path detection
// ============================================================

/// Paths that should be denied with EACCES.
const SENSITIVE_PATHS: &[&str] = &[
    "/proc/kcore",
    "/proc/kmsg",
    "/proc/kallsyms",
    "/proc/keys",
    "/proc/key-users",
    "/proc/sysrq-trigger",
    "/sys/class/net",
    "/sys/firmware",
    "/sys/kernel/security",
];

/// Returns true for paths that should be denied access.
pub(crate) fn is_sensitive_proc(path: &str) -> bool {
    SENSITIVE_PATHS
        .iter()
        .any(|&sensitive| path == sensitive || path.starts_with(&format!("{}/", sensitive)))
}

/// True for a /proc path the sandbox must never be handed: a sensitive
/// kernel file, or the directory of a process outside the sandbox.
///
/// Directory listings already hide foreign PIDs, but a process could still
/// open /proc/{ppid}/cmdline (or any guessed PID) directly.
pub(crate) fn is_hidden_proc_path(path: &str, processes: &ProcessIndex) -> bool {
    is_sensitive_proc(path) || extract_proc_pid(path).is_some_and(|pid| !processes.contains(pid))
}

/// Extract a numeric PID from a `/proc/{pid}/...` path.
///
/// Returns `None` for non-numeric components like `/proc/self/...`,
/// `/proc/cpuinfo`, etc.  Those are handled elsewhere or are safe.
pub(crate) fn extract_proc_pid(path: &str) -> Option<i32> {
    let rest = path.strip_prefix("/proc/")?;
    // Take the next path component (up to '/' or end of string).
    let component = rest.split('/').next()?;
    component.parse::<i32>().ok()
}

const PROC_SELF: &str = "/proc/self";
const PROC_THREAD_SELF: &str = "/proc/thread-self";

/// Per-task entries that show a namespace of the host, not the task.
const NAMESPACE_ENTRIES: &[&str] = &["net", "mounts", "mountinfo", "mountstats", "cgroup"];

/// Split `/proc/<task>[/task/<tid>]/<entry><tail>` for a namespace entry.
pub(crate) fn proc_namespace_entry(path: &str) -> Option<(&'static str, &str)> {
    let (task, rest) = path.strip_prefix("/proc/")?.split_once('/')?;
    if task != "self" && task != "thread-self" && task.parse::<i32>().is_err() {
        return None;
    }
    let rest = match rest.strip_prefix("task/") {
        Some(thread) => {
            let (tid, rest) = thread.split_once('/')?;
            tid.parse::<i32>().ok()?;
            rest
        }
        None => rest,
    };
    NAMESPACE_ENTRIES.iter().find_map(|&entry| {
        let tail = rest.strip_prefix(entry)?;
        (tail.is_empty() || tail.starts_with('/')).then_some((entry, tail))
    })
}

/// Give every per-task spelling of a namespace entry the one name the
/// virtualization matches.
///
/// `/proc/net` and `/proc/mounts` are links into `self`, and every task
/// directory carries the same files, so any of those spellings would
/// otherwise reach the host's tables.
pub(crate) fn canon_proc_namespace(path: &str) -> std::borrow::Cow<'_, str> {
    match proc_namespace_entry(path) {
        Some(("net", tail)) => format!("/proc/net{}", tail).into(),
        Some((entry, tail)) => format!("{}/{}{}", PROC_SELF, entry, tail).into(),
        None => path.into(),
    }
}

/// Files under /etc whose open is answered with generated content.
pub(crate) const SHADOWED_ETC_FILES: &[&str] = &["/etc/hostname", "/etc/hosts"];

/// A file whose open is answered with generated content.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum VirtualFile {
    CpuInfo,
    MemInfo,
    Uptime,
    LoadAvg,
    NetDev,
    NetIfInet6,
    NetTcp { v6: bool },
    Mounts,
    MountInfo,
    MountStats,
    Cgroup,
    Hostname,
    EtcHosts,
}

/// The virtual file `path` names under `policy`, with every per-task
/// spelling of a namespace entry collapsed first. The real file behind it
/// must never be handed out in its place.
pub(crate) fn virtual_file(path: &str, policy: &NotifPolicy) -> Option<VirtualFile> {
    Some(match canon_proc_namespace(path).as_ref() {
        "/proc/cpuinfo" if policy.num_cpus.is_some() => VirtualFile::CpuInfo,
        "/proc/meminfo" if policy.max_memory_bytes > 0 => VirtualFile::MemInfo,
        "/proc/uptime" if policy.has_time_start => VirtualFile::Uptime,
        "/proc/loadavg" => VirtualFile::LoadAvg,
        "/proc/net/dev" => VirtualFile::NetDev,
        "/proc/net/if_inet6" => VirtualFile::NetIfInet6,
        "/proc/net/tcp" if policy.port_remap => VirtualFile::NetTcp { v6: false },
        "/proc/net/tcp6" if policy.port_remap => VirtualFile::NetTcp { v6: true },
        "/proc/mounts" | "/proc/self/mounts" => VirtualFile::Mounts,
        "/proc/self/mountinfo" => VirtualFile::MountInfo,
        "/proc/self/mountstats" => VirtualFile::MountStats,
        "/proc/self/cgroup" => VirtualFile::Cgroup,
        "/etc/hostname" if policy.virtual_hostname.is_some() => VirtualFile::Hostname,
        "/etc/hosts" if !policy.virtual_etc_hosts.is_empty() => VirtualFile::EtcHosts,
        _ => return None,
    })
}

/// The content of a virtual file at this moment.
pub(crate) async fn render_virtual_file(
    file: VirtualFile,
    processes: &ProcessIndex,
    resource: &Mutex<crate::seccomp::state::ResourceState>,
    network: &Mutex<NetworkState>,
    policy: &NotifPolicy,
) -> Vec<u8> {
    let mounts_args = || {
        (
            policy.chroot_root.as_deref(),
            &policy.chroot_mounts,
            &policy.chroot_mount_ro,
            root_is_read_only(policy),
        )
    };
    match file {
        VirtualFile::CpuInfo => generate_cpuinfo(policy.num_cpus.unwrap_or(1)),
        VirtualFile::MemInfo => {
            let rs = resource.lock().await;
            generate_meminfo(policy.max_memory_bytes, rs.mem_used)
        }
        VirtualFile::Uptime => {
            let rs = resource.lock().await;
            generate_uptime(rs.start_instant.elapsed().as_secs_f64())
        }
        VirtualFile::LoadAvg => {
            let total = processes.len() as u32;
            let last_pid = processes.max_pid().unwrap_or(0);
            let rs = resource.lock().await;
            generate_loadavg(&rs.load_avg, rs.proc_count, total, last_pid)
        }
        VirtualFile::NetDev => generate_proc_net_dev(),
        VirtualFile::NetIfInet6 => generate_proc_net_if_inet6(),
        VirtualFile::NetTcp { v6 } => {
            let ns = network.lock().await;
            generate_proc_net_tcp(&ns.port_map.bound_ports, v6)
        }
        VirtualFile::Mounts => {
            let (root, mounts, ro, root_ro) = mounts_args();
            generate_proc_mounts(root, mounts, ro, root_ro)
        }
        VirtualFile::MountInfo => {
            let (root, mounts, ro, root_ro) = mounts_args();
            generate_proc_mountinfo(root, mounts, ro, root_ro)
        }
        VirtualFile::MountStats => {
            generate_proc_mountstats(policy.chroot_root.as_deref(), &policy.chroot_mounts)
        }
        // The real file names the host's slice and scope. This is what a
        // task sees from inside a cgroup namespace of its own.
        VirtualFile::Cgroup => b"0::/\n".to_vec(),
        VirtualFile::Hostname => {
            format!("{}\n", policy.virtual_hostname.as_deref().unwrap_or_default()).into_bytes()
        }
        VirtualFile::EtcHosts => policy.virtual_etc_hosts.clone().into_bytes(),
    }
}

// ============================================================
// /proc/cpuinfo generator
// ============================================================

/// Generate a minimal /proc/cpuinfo with N processor entries.
pub(crate) fn generate_cpuinfo(num_cpus: u32) -> Vec<u8> {
    let mut buf = String::new();
    for i in 0..num_cpus {
        if i > 0 {
            buf.push('\n');
        }
        buf.push_str(&format!(
            "processor\t: {}\nmodel name\t: Virtual CPU\ncpu MHz\t\t: 2400.000\n",
            i
        ));
    }
    buf.into_bytes()
}

// ============================================================
// /proc/uptime generator

/// Generate /proc/uptime showing virtual uptime since sandbox start.
/// Format: "<uptime_secs> <idle_secs>\n"
/// When time_start is set, uptime starts at 0 and ticks forward from sandbox creation.
pub(crate) fn generate_uptime(elapsed_secs: f64) -> Vec<u8> {
    // idle time is reported as 0 — the sandbox has no meaningful idle metric.
    format!("{:.2} 0.00\n", elapsed_secs.max(0.0)).into_bytes()
}

// ============================================================
// /proc/loadavg generator + EWMA tracker
// ============================================================

/// Exponential weighted moving average load tracker, matching the Linux kernel's
/// algorithm (kernel/sched/loadavg.c). Sampled every 5 seconds.
#[derive(Debug, Clone)]
pub struct LoadAvg {
    pub avg_1: f64,
    pub avg_5: f64,
    pub avg_15: f64,
}

// Decay factors: e^(-5/60), e^(-5/300), e^(-5/900)
const EXP_1: f64 = 0.9200444146293232; // e^(-1/12)
const EXP_5: f64 = 0.9834714538216174; // e^(-1/60)
const EXP_15: f64 = 0.9944598480048967; // e^(-1/180)

impl LoadAvg {
    pub fn new() -> Self {
        Self { avg_1: 0.0, avg_5: 0.0, avg_15: 0.0 }
    }

    /// Update averages with current runnable process count.
    /// Called every 5 seconds by the sampling task.
    pub fn sample(&mut self, running: u32) {
        let r = running as f64;
        self.avg_1 = self.avg_1 * EXP_1 + r * (1.0 - EXP_1);
        self.avg_5 = self.avg_5 * EXP_5 + r * (1.0 - EXP_5);
        self.avg_15 = self.avg_15 * EXP_15 + r * (1.0 - EXP_15);
    }
}

/// Generate /proc/loadavg from tracked EWMA values.
/// Format: "avg1 avg5 avg15 running/total last_pid\n"
pub(crate) fn generate_loadavg(load: &LoadAvg, running: u32, total: u32, last_pid: i32) -> Vec<u8> {
    format!(
        "{:.2} {:.2} {:.2} {}/{} {}\n",
        load.avg_1, load.avg_5, load.avg_15,
        running.max(1).min(total), total,
        last_pid.max(0),
    )
    .into_bytes()
}

// /proc/meminfo generator
// ============================================================

/// Generate /proc/meminfo showing virtual memory limits.
pub(crate) fn generate_meminfo(total_bytes: u64, used_bytes: u64) -> Vec<u8> {
    let total_kb = total_bytes / 1024;
    let used_kb = used_bytes.min(total_bytes) / 1024;
    let free_kb = total_kb.saturating_sub(used_kb);
    // Available is typically slightly more than free (includes reclaimable)
    let avail_kb = free_kb;

    format!(
        "MemTotal:       {} kB\n\
         MemFree:        {} kB\n\
         MemAvailable:   {} kB\n",
        total_kb, free_kb, avail_kb,
    )
    .into_bytes()
}

// ============================================================
// /proc/mounts and /proc/self/mountinfo virtualization
// ============================================================

/// Detect the filesystem type of a host path via statfs(2).
fn detect_fstype(path: &std::path::Path) -> &'static str {
    let c_path = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
        Ok(p) => p,
        Err(_) => return "unknown",
    };
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut buf) } != 0 {
        return "unknown";
    }
    // Map f_type magic to filesystem name.
    // Values from linux/magic.h and statfs(2).
    match buf.f_type {
        0xEF53 => "ext4",            // EXT2/3/4_SUPER_MAGIC
        0x9123683E => "btrfs",        // BTRFS_SUPER_MAGIC
        0x58465342 => "xfs",          // XFS_SUPER_MAGIC
        0x01021994 => "tmpfs",        // TMPFS_MAGIC
        0x6969 => "nfs",              // NFS_SUPER_MAGIC
        0x5346544E => "ntfs",         // NTFS_SB_MAGIC
        0x65735546 => "fuse",         // FUSE_SUPER_MAGIC
        0x28cd3d45 => "cramfs",       // CRAMFS_MAGIC
        0x3153464A => "jfs",          // JFS_SUPER_MAGIC
        0x52654973 => "reiserfs",     // REISERFS_SUPER_MAGIC
        0xF2F52010 => "f2fs",         // F2FS_SUPER_MAGIC
        0x4244 => "hfs",              // HFS_SUPER_MAGIC
        0x482B => "hfsplus",          // HFSPLUS_SUPER_MAGIC
        0x1021997 => "v9fs",          // V9FS_MAGIC
        0xFF534D42 => "cifs",         // CIFS_SUPER_MAGIC
        0x73717368 => "squashfs",     // SQUASHFS_MAGIC
        0x62656572 => "sysfs",        // SYSFS_MAGIC
        0x9FA0 => "proc",            // PROC_SUPER_MAGIC
        0x61756673 => "aufs",         // AUFS_SUPER_MAGIC
        0x794C7630 => "overlayfs",    // OVERLAYFS_SUPER_MAGIC
        0x01161970 => "gfs2",         // GFS2_MAGIC
        0x5A4F4653 => "zonefs",       // ZONEFS_MAGIC
        0xCAFE001 => "bcachefs",      // BCACHEFS_SUPER_MAGIC (approximation)
        _ => "unknown",
    }
}

/// Whether the chroot rootfs should be reported read-only in the synthesized
/// mount tables. Only meaningful under a chroot, where the rootfs is presented
/// as its own mount: it is read-only unless `/` was granted write (a read-write
/// OCI rootfs or `--fs-write /`). Without a chroot, the root is the host's real
/// (read-write) `/`, restricted by Landlock rather than a read-only mount.
fn root_is_read_only(policy: &NotifPolicy) -> bool {
    policy.chroot_root.is_some()
        && !policy
            .chroot_writable
            .iter()
            .any(|p| p.as_path() == std::path::Path::new("/"))
}

/// Generate a virtual /proc/mounts showing only the sandbox's own mounts.
///
/// Produces standard `/proc/mounts` format: `device mountpoint type options dump pass`
/// Shows the root entry and each fs_mount entry. Filesystem types are detected
/// from the actual host paths via statfs(2).
pub(crate) fn generate_proc_mounts(
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    chroot_mount_ro: &[std::path::PathBuf],
    root_ro: bool,
) -> Vec<u8> {
    let mut buf = String::new();

    if let Some(root) = chroot_root {
        let fstype = detect_fstype(root);
        let opts = if root_ro { "ro,relatime" } else { "rw,relatime" };
        buf.push_str(&format!("sandlock / {} {} 0 0\n", fstype, opts));
    } else {
        buf.push_str(&format!("rootfs / rootfs {} 0 0\n", if root_ro { "ro" } else { "rw" }));
    }

    for (virtual_path, host_path) in chroot_mounts {
        let vp = virtual_path.to_string_lossy();
        let fstype = detect_fstype(host_path);
        let opts = if chroot_mount_ro.iter().any(|d| d == virtual_path) {
            "ro,relatime"
        } else {
            "rw,relatime"
        };
        buf.push_str(&format!("sandlock {} {} {} 0 0\n", vp, fstype, opts));
    }

    buf.into_bytes()
}

/// Generate a virtual /proc/self/mountinfo showing only the sandbox's own mounts.
///
/// Format (per mount_namespaces(7)):
/// `mount_id parent_id major:minor root mount_point options optional_fields - fs_type source super_options`
pub(crate) fn generate_proc_mountinfo(
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    chroot_mount_ro: &[std::path::PathBuf],
    root_ro: bool,
) -> Vec<u8> {
    let mut buf = String::new();
    let mut mount_id: u32 = 20;
    let (root_opts, root_super) = if root_ro { ("ro,relatime", "ro") } else { ("rw,relatime", "rw") };

    if let Some(root) = chroot_root {
        let fstype = detect_fstype(root);
        buf.push_str(&format!(
            "{} 1 8:1 / / {} - {} sandlock {}\n", mount_id, root_opts, fstype, root_super
        ));
    } else {
        buf.push_str(&format!(
            "{} 1 0:1 / / {} - rootfs rootfs {}\n", mount_id, root_super, root_super
        ));
    }
    mount_id += 1;

    for (virtual_path, host_path) in chroot_mounts {
        let vp = virtual_path.to_string_lossy();
        let fstype = detect_fstype(host_path);
        let (opts, sup) = if chroot_mount_ro.iter().any(|d| d == virtual_path) {
            ("ro,relatime", "ro")
        } else {
            ("rw,relatime", "rw")
        };
        buf.push_str(&format!(
            "{} 20 8:1 / {} {} - {} sandlock {}\n", mount_id, vp, opts, fstype, sup
        ));
        mount_id += 1;
    }

    buf.into_bytes()
}

/// Generate a virtual /proc/self/mountstats naming the same mounts as
/// [`generate_proc_mounts`]. Read-only state is not part of this format.
pub(crate) fn generate_proc_mountstats(
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
) -> Vec<u8> {
    let mut buf = String::new();

    match chroot_root {
        Some(root) => buf.push_str(&format!(
            "device sandlock mounted on / with fstype {}\n", detect_fstype(root)
        )),
        None => buf.push_str("device rootfs mounted on / with fstype rootfs\n"),
    }

    for (virtual_path, host_path) in chroot_mounts {
        buf.push_str(&format!(
            "device sandlock mounted on {} with fstype {}\n",
            virtual_path.to_string_lossy(),
            detect_fstype(host_path),
        ));
    }

    buf.into_bytes()
}

// ============================================================
// /proc/net/dev and /proc/net/if_inet6 virtualization
// ============================================================

/// Generate a synthetic /proc/net/dev showing only the loopback interface.
pub(crate) fn generate_proc_net_dev() -> Vec<u8> {
    concat!(
        "Inter-|   Receive                                                |  Transmit\n",
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
        "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n",
    ).as_bytes().to_vec()
}

/// Generate a synthetic /proc/net/if_inet6 showing only loopback (::1).
pub(crate) fn generate_proc_net_if_inet6() -> Vec<u8> {
    // Format: address ifindex prefix_len scope flags ifname
    b"00000000000000000000000000000001 01 80 10 80       lo\n".to_vec()
}

// ============================================================
// /proc/net/tcp filtering
// ============================================================

/// Generate a filtered /proc/net/tcp (or tcp6) showing only the sandbox's own ports.
///
/// Reads the real /proc/net/tcp, parses each line's local port, and keeps only
/// lines whose port is in `bound_ports`. The header line is always included.
pub(crate) fn generate_proc_net_tcp(bound_ports: &HashSet<u16>, is_v6: bool) -> Vec<u8> {
    let path = if is_v6 { "/proc/net/tcp6" } else { "/proc/net/tcp" };
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut result = String::new();
    for (i, line) in content.lines().enumerate() {
        if i == 0 {
            // Header line — always include
            result.push_str(line);
            result.push('\n');
            continue;
        }
        // Each line looks like:
        //   sl  local_address rem_address   st ...
        //    0: 0100007F:1F90 00000000:0000 0A ...
        // The local port is the hex after the colon in field 1 (0-indexed).
        if let Some(local_port) = parse_proc_net_tcp_port(line) {
            if bound_ports.contains(&local_port) {
                result.push_str(line);
                result.push('\n');
            }
        }
    }
    result.into_bytes()
}

/// Parse the local port from a /proc/net/tcp line.
/// Format: "  sl  local_addr:PORT remote_addr:PORT ..."
fn parse_proc_net_tcp_port(line: &str) -> Option<u16> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 2 {
        return None;
    }
    // fields[1] is "ADDR:PORT" in hex
    let local = fields[1];
    let colon = local.rfind(':')?;
    let port_hex = &local[colon + 1..];
    u16::from_str_radix(port_hex, 16).ok()
}

// ============================================================
// memfd injection
// ============================================================

/// Create a sealed memfd of `content` and inject it as the child's openat
/// result. The memfd is created in the supervisor, sealed read-only, and
/// handed to the child via NOTIF_ADDFD, so the kernel never re-resolves the
/// virtualized /proc path string after injection.
///
/// On memfd allocation failure we fall through to `Continue` (let the real
/// open proceed) rather than `Errno`, preserving this module's long-standing
/// behavior: a failure to synthesise /proc content is not a denial.
fn inject_memfd(content: &[u8]) -> NotifAction {
    match content_memfd(content, true) {
        Ok(fd) => NotifAction::InjectFdSend { srcfd: fd, newfd_flags: libc::O_CLOEXEC as u32 },
        Err(_) => NotifAction::Continue, // fallback: let real open proceed
    }
}

// ============================================================
// handle_proc_open — intercept openat for /proc virtualization
// ============================================================

/// Handle openat syscalls targeting /proc files.
///
/// - Denies access to sensitive kernel files.
/// - Virtualizes /proc/cpuinfo and /proc/meminfo with fake content.
/// - Serves the caller's own /proc/self entries covered by the grant lists.
/// - Lets everything else through.
pub(crate) async fn handle_proc_open(
    notif: &SeccompNotif,
    open: &OpenRequest,
    processes: &Arc<ProcessIndex>,
    resource: &Arc<Mutex<crate::seccomp::state::ResourceState>>,
    network: &Arc<Mutex<NetworkState>>,
    policy: &NotifPolicy,
) -> NotifAction {
    let Some(path) = open.target_str() else { return NotifAction::Continue };

    if is_hidden_proc_path(path, processes) {
        return NotifAction::Errno(EACCES);
    }

    // The /etc shims are handlers of their own, ordered around the chroot
    // handler so that its grant check comes first.
    if path.starts_with("/proc/") {
        if let Some(file) = virtual_file(path, policy) {
            let content = render_virtual_file(file, processes, resource, network, policy).await;
            return inject_memfd(&content);
        }
    }

    let path = canon_proc_namespace(path);
    let path = path.as_ref();

    if let Some(action) = open_own_proc_on_behalf(notif, &open.args, path, processes, policy) {
        return action;
    }

    NotifAction::Continue
}

// ============================================================
// A task's own /proc/self
// ============================================================

const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

const WRITE_SIDE_FLAGS: i32 = libc::O_WRONLY
    | libc::O_RDWR
    | libc::O_CREAT
    | libc::O_TRUNC
    | (libc::O_TMPFILE & !libc::O_DIRECTORY);

// openat2 rejects an O_PATH open that carries any flag outside this set.
const PATH_OPEN_FLAGS: i32 = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW;
const READ_OPEN_FLAGS: i32 =
    libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_LARGEFILE;

/// What these show depends on the capabilities of whoever opened them, and
/// the supervisor may hold more than the task it would be opening them for.
const OPENER_PRIVILEGED_FILES: &[&str] = &["pagemap", "stack", "seccomp_cache"];

pub(crate) fn proc_open_is_write(flags: u64) -> bool {
    flags as i32 & WRITE_SIDE_FLAGS != 0
}

/// These opens cannot safely borrow the supervisor's credentials.
pub(crate) fn is_opener_sensitive_proc(path: &std::path::Path, flags: u64) -> bool {
    let Ok(relative) = path.strip_prefix("/proc") else { return false };
    if path.file_name().and_then(|name| name.to_str()).is_some_and(|name| OPENER_PRIVILEGED_FILES.contains(&name)) {
        return true;
    }
    if !proc_open_is_write(flags) {
        return false;
    }
    let mut parts = relative.iter().filter_map(|part| part.to_str());
    let Some(task) = parts.next() else { return false };
    if task != "self" && task != "thread-self" && task.parse::<u32>().is_err() {
        return false;
    }
    let mut entry = parts.next();
    if entry == Some("task") {
        if parts.next().and_then(|tid| tid.parse::<u32>().ok()).is_none() {
            return false;
        }
        entry = parts.next();
    }
    matches!(entry, Some("mem" | "attr" | "uid_map" | "gid_map" | "setgroups" | "projid_map"))
}

/// True for a grant the supervisor serves instead of Landlock. A rule
/// on procfs would let any link reach the entries the handlers hide by name
/// (issue #236), and one on /proc/self binds to a single pid (issues #218, #232).
pub(crate) fn is_supervised_proc_grant(path: &std::path::Path) -> bool {
    path.starts_with("/proc")
}

/// A path inside the caller's own /proc directory.
#[derive(Debug, PartialEq)]
struct OwnProcTarget<'a> {
    base: String,
    rest: &'a str,
    /// The pid-free spellings, which are what a policy entry can name.
    self_forms: Vec<String>,
}

impl OwnProcTarget<'_> {
    fn is_under_any(&self, list: &[std::path::PathBuf]) -> bool {
        self.self_forms
            .iter()
            .any(|form| list.iter().any(|entry| std::path::Path::new(form).starts_with(entry)))
    }
}

fn strip_dir_prefix<'a>(path: &'a str, dir: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(dir)?;
    (rest.is_empty() || rest.starts_with('/')).then_some(rest)
}

fn own_proc_target(path: &str, tid: i32, tgid: i32) -> Option<OwnProcTarget<'_>> {
    let own = format!("/proc/{}", tgid);
    if let Some(rest) = strip_dir_prefix(path, PROC_THREAD_SELF) {
        return Some(OwnProcTarget {
            base: format!("{}/task/{}", own, tid),
            rest,
            // Landlock would let a grant on /proc/self reach a thread's
            // directory, so the same grant has to cover it here.
            self_forms: vec![
                format!("{}{}", PROC_THREAD_SELF, rest),
                format!("{}/task/{}{}", PROC_SELF, tid, rest),
            ],
        });
    }
    // A dirfd on /proc/self reads back as /proc/<tgid>, so the numeric
    // spelling of the caller's own directory has to match too.
    let rest = strip_dir_prefix(path, PROC_SELF).or_else(|| strip_dir_prefix(path, &own))?;
    let mut self_forms = vec![format!("{}{}", PROC_SELF, rest)];
    if let Some(thread_rest) = strip_dir_prefix(rest, &format!("/task/{}", tid)) {
        self_forms.push(format!("{}{}", PROC_THREAD_SELF, thread_rest));
    }
    Some(OwnProcTarget { base: own, rest, self_forms })
}

/// The pid-free spellings of a path inside the caller's own /proc directory,
/// which are the only ones a grant or a deny can name. Empty for any other path.
pub(crate) fn own_proc_self_forms(path: &str, tid: i32, tgid: i32) -> Vec<String> {
    let mut forms = own_proc_target(path, tid, tgid).map(|target| target.self_forms).unwrap_or_default();
    // /proc/net is a link into the caller's directory, and a policy may name it.
    if let Some(("net", tail)) = proc_namespace_entry(path) {
        forms.push(format!("/proc/net{}", tail));
    }
    forms
}

/// Whether `grant` reaches `form`, a pid-free spelling of the caller's own
/// entry. The net subtree is the host's network namespace, not the task's
/// own data, so through this spelling only a grant naming net reaches it.
pub(crate) fn own_grant_covers(form: &str, grant: &std::path::Path) -> bool {
    if !std::path::Path::new(form).starts_with(grant) {
        return false;
    }
    match proc_namespace_entry(form) {
        Some(("net", tail)) => grant.starts_with(&form[..form.len() - tail.len()]),
        _ => true,
    }
}

/// The /dev names that are links into the caller's fd directory on this host.
fn dev_fd_aliases() -> &'static [(&'static str, &'static str)] {
    static ALIASES: std::sync::OnceLock<Vec<(&str, &str)>> = std::sync::OnceLock::new();
    ALIASES.get_or_init(|| {
        [
            ("/dev/stdin", "/proc/self/fd/0"),
            ("/dev/stdout", "/proc/self/fd/1"),
            ("/dev/stderr", "/proc/self/fd/2"),
            ("/dev/fd", "/proc/self/fd"),
        ]
        .into_iter()
        .filter(|(alias, target)| {
            std::fs::read_link(alias).is_ok_and(|link| link == std::path::Path::new(target))
        })
        .collect()
    })
}

/// The caller's own fd, when `path` is a request to reopen one: /proc/self/fd/N
/// under any spelling of the caller's directory, or /dev/stdin and its kin.
pub(crate) fn own_fd_request(path: &str, tid: i32, tgid: i32) -> Option<i32> {
    let aliased = dev_fd_aliases().iter().find_map(|(alias, target)| {
        strip_dir_prefix(path, alias).map(|rest| format!("{}{}", target, rest))
    });
    let target = own_proc_target(aliased.as_deref().unwrap_or(path), tid, tgid)?;
    let rest = match target.rest.strip_prefix("/task/") {
        Some(thread) => {
            let (thread, rest) = thread.split_once('/')?;
            thread.parse::<i32>().ok()?;
            rest
        }
        None => target.rest.strip_prefix('/')?,
    };
    let fd = rest.strip_prefix("fd/")?;
    fd.bytes().all(|b| b.is_ascii_digit()).then(|| fd.parse().ok()).flatten()
}

/// Serve a policy-listed open inside the caller's own /proc directory.
///
/// A Landlock rule for /proc/self names one pid, so only the supervisor can
/// give each task its own entry. Links fall through to the general open
/// handler, which checks the pinned target before serving procfs opens.
fn open_own_proc_on_behalf(
    notif: &SeccompNotif,
    args: &OpenArgs,
    path: &str,
    processes: &ProcessIndex,
    policy: &NotifPolicy,
) -> Option<NotifAction> {
    // Chroot mode already services /proc on behalf of the child.
    if policy.chroot_root.is_some() {
        return None;
    }
    // Caller resolution constraints need the original dirfd in the general handler.
    if args.resolve != 0 {
        return None;
    }
    // A namespace entry that has no virtual form must not reach the real file.
    if proc_namespace_entry(path).is_some() {
        return None;
    }
    let tid = notif.pid as i32;
    let target = own_proc_target(path, tid, processes.tgid_of(tid)?)?;
    // The deny precheck matches the string the child wrote, which the
    // numeric spelling of its own directory would slip past.
    let is_write = proc_open_is_write(args.flags);
    let granted = target.is_under_any(&policy.chroot_writable)
        || (!is_write && target.is_under_any(&policy.chroot_readable));
    if !granted || target.is_under_any(&policy.chroot_denied) {
        return None;
    }
    if is_opener_sensitive_proc(std::path::Path::new(path), args.flags) {
        return None;
    }

    let flags = args.flags as i32;
    let open_flags = if is_write {
        flags
    } else if flags & libc::O_PATH != 0 {
        flags & PATH_OPEN_FLAGS
    } else {
        flags & READ_OPEN_FLAGS
    };

    let base = CString::new(target.base).ok()?;
    let base_fd = unsafe {
        libc::open(base.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
    };
    if base_fd < 0 {
        return None;
    }
    let base_fd = unsafe { OwnedFd::from_raw_fd(base_fd) };

    let rel = target.rest.trim_start_matches('/');
    let rel = CString::new(if rel.is_empty() { "." } else { rel }).ok()?;
    let creates = flags & libc::O_CREAT != 0 || flags & libc::O_TMPFILE == libc::O_TMPFILE;
    let mode = if is_write && (creates || notif.data.nr as i64 == crate::arch::SYS_OPENAT2) {
        args.mode
    } else {
        0
    };
    let fd = match openat2_at(
        base_fd.as_raw_fd(),
        &rel,
        (open_flags | libc::O_CLOEXEC) as u64,
        mode,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
    ) {
        Ok(fd) => fd,
        Err(errno) if is_write && errno != libc::ELOOP => return Some(NotifAction::Errno(errno)),
        Err(_) => return None,
    };
    Some(inject_open_result(fd.into_raw_fd(), args.flags))
}

// ============================================================
// sched_getaffinity virtualization
// ============================================================

/// Handle sched_getaffinity(pid, cpusetsize, mask) — return a fake mask
/// with only `num_cpus` bits set, so nproc/sysconf report the virtual count
/// without actually pinning the process to specific cores.
pub(crate) fn handle_sched_getaffinity(
    notif: &SeccompNotif,
    num_cpus: u32,
    notif_fd: RawFd,
) -> NotifAction {
    let cpusetsize = notif.data.args[1] as usize;
    let mask_addr = notif.data.args[2];

    if mask_addr == 0 || cpusetsize == 0 {
        return NotifAction::Continue;
    }

    // Build a cpu_set with the first N bits set.
    let mut mask = vec![0u8; cpusetsize];
    for i in 0..num_cpus as usize {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < mask.len() {
            mask[byte_idx] |= 1 << bit_idx;
        }
    }

    match write_child_mem(notif_fd, notif.id, notif.pid, mask_addr, &mask) {
        Ok(()) => NotifAction::ReturnValue(cpusetsize as i64),
        Err(_) => NotifAction::Continue,
    }
}

// ============================================================
// uname virtualization
// ============================================================

/// Handle uname() — override the nodename (hostname) field.
///
/// uname(buf) writes a `struct utsname` to buf. We call the real uname()
/// in the supervisor, patch the nodename field, and write the result to
/// the child's buffer.
pub(crate) fn handle_uname(
    notif: &SeccompNotif,
    hostname: &str,
    notif_fd: RawFd,
) -> NotifAction {
    let buf_addr = notif.data.args[0];
    if buf_addr == 0 {
        return NotifAction::Continue;
    }

    // Call real uname() in the supervisor to get current kernel info.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return NotifAction::Continue;
    }

    // Overwrite nodename with the virtual hostname.
    let name_bytes = hostname.as_bytes();
    let len = name_bytes.len().min(uts.nodename.len() - 1);
    for (i, &b) in name_bytes[..len].iter().enumerate() {
        uts.nodename[i] = b as libc::c_char;
    }
    uts.nodename[len] = 0;

    // Write the patched utsname to child memory.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &uts as *const _ as *const u8,
            std::mem::size_of::<libc::utsname>(),
        )
    };

    match write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, bytes) {
        Ok(()) => NotifAction::ReturnValue(0),
        Err(_) => NotifAction::Continue,
    }
}

/// Answer an open of /etc/hostname with the virtual hostname.
pub(crate) fn handle_hostname_open(open: &OpenRequest, hostname: &str) -> Option<NotifAction> {
    if open.target.as_deref() != Some(std::path::Path::new("/etc/hostname")) {
        return None;
    }
    Some(inject_memfd(format!("{}\n", hostname).as_bytes()))
}

/// Answer an open of /etc/hosts with the virtual file: a fixed loopback view
/// plus the hostnames pre-resolved from `net_allow`, so the host's own file
/// never leaks in and glibc's `files` backend resolves allowed names.
pub(crate) fn handle_etc_hosts_open(open: &OpenRequest, etc_hosts_content: &str) -> Option<NotifAction> {
    if open.target.as_deref() != Some(std::path::Path::new("/etc/hosts")) {
        return None;
    }
    Some(inject_memfd(etc_hosts_content.as_bytes()))
}

/// Lexical normalization of `(pid, dirfd, path)`:
///
/// - Absolute `path`: used as-is.
/// - Relative `path` with `dirfd == AT_FDCWD`: prefixed with the child's
///   cwd from `/proc/<pid>/cwd`.
/// - Relative `path` with explicit `dirfd`: prefixed with the symlink
///   target of `/proc/<pid>/fd/<dirfd>` (the host kernel's view of the
///   directory the dirfd points to).
///
/// Then collapses `.`, `..`, and redundant `/` components. Returns
/// `None` if the dirfd cannot be resolved or the path walks above `/`.
pub(crate) fn resolve_to_normalized_absolute(
    pid: u32,
    dirfd: i64,
    path: &str,
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
    processes: &ProcessIndex,
) -> Option<std::path::PathBuf> {
    use std::path::{Component, Path, PathBuf};

    // The dirfd/cwd symlink target is the *real* host directory. Under
    // chroot, sandlock services /proc, /etc and /dev via on-behalf opens,
    // so that target is e.g. `<chroot>/proc` while the child's absolute
    // spelling of the same file is `/proc/...`. Map the base back into the
    // sandbox's virtual namespace so relative and absolute spellings
    // resolve identically and the open-family shims (proc synthesis,
    // /etc/hosts, /etc/hostname, random seed, CA inject) match either way.
    let to_virtual = |host: PathBuf| match chroot_root {
        Some(root) => {
            crate::chroot::resolve::host_to_virtual(root, chroot_mounts, &host).unwrap_or(host)
        }
        None => host,
    };

    let joined: PathBuf = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else if dirfd as i32 == libc::AT_FDCWD {
        // Under chroot the supervisor services chdir itself and the child's
        // real cwd never moves, so its own notion is the only current one,
        // and it is already virtual. Falling back to the kernel's is right
        // only for a task that has never moved, which is when nothing is
        // tracked.
        let base = match i32::try_from(pid).ok().and_then(|p| processes.virtual_cwd(p)) {
            Some(tracked) => tracked,
            None => to_virtual(std::fs::read_link(format!("/proc/{}/cwd", pid)).ok()?),
        };
        base.join(path)
    } else {
        let base = std::fs::read_link(format!("/proc/{}/fd/{}", pid, dirfd as i32)).ok()?;
        to_virtual(base).join(path)
    };

    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                // pop the last regular component; refuse to walk above
                // the root (out becomes empty after popping "/").
                if !out.pop() {
                    return None;
                }
                if out.as_os_str().is_empty() {
                    return None;
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    Some(match chroot_root {
        None => through_task_root_and_cwd(out, pid, processes),
        Some(_) => out,
    })
}

/// A sandbox task's root link is / when there is no chroot, and its cwd link
/// is wherever it is. Spell a path through them the way the caller could
/// spell it directly, so a virtual or hidden file is recognized under it.
fn through_task_root_and_cwd(
    mut path: std::path::PathBuf,
    caller: u32,
    processes: &ProcessIndex,
) -> std::path::PathBuf {
    for _ in 0..8 {
        let Some((task, rest)) = path.to_str().and_then(|p| p.strip_prefix("/proc/")?.split_once('/')) else {
            break;
        };
        let pid = match task {
            "self" | "thread-self" => caller as i32,
            numeric => match numeric.parse::<i32>() {
                Ok(pid) if processes.contains(pid) => pid,
                _ => break,
            },
        };
        let (link, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let base = match link {
            "root" => std::path::PathBuf::from("/"),
            "cwd" => match processes.virtual_cwd(pid) {
                Some(cwd) => cwd,
                None => match std::fs::read_link(format!("/proc/{}/cwd", pid)) {
                    Ok(cwd) => cwd,
                    Err(_) => break,
                },
            },
            _ => break,
        };
        path = base.join(tail);
    }
    path
}

// ============================================================
// Deterministic directory listing
// ============================================================

/// Handle getdents64/getdents for deterministic directory listing.
///
/// Reads the directory entries via `/proc/{pid}/fd/{fd}`, sorts them
/// lexicographically by name, and returns them to the child in sorted order.
/// This ensures `readdir()`, `ls`, `glob()` etc. produce the same order
/// regardless of filesystem internals.
pub(crate) async fn handle_sorted_getdents(
    notif: &SeccompNotif,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let pid = notif.pid;
    let child_fd = (notif.data.args[0] & 0xFFFF_FFFF) as u32;
    let buf_addr = notif.data.args[1];
    let buf_size = (notif.data.args[2] & 0xFFFF_FFFF) as usize;

    let link_path = format!("/proc/{}/fd/{}", pid, child_fd);
    let dir_path = match std::fs::read_link(&link_path) {
        Ok(t) => t,
        Err(_) => return NotifAction::Continue,
    };

    let entry = match processes.entry_for(pid as i32) {
        Some(e) => e,
        None => return NotifAction::Continue,
    };
    let cache_key = (child_fd, dir_path.to_string_lossy().into_owned());
    let mut perproc = entry.1.lock().await;

    // Build and cache sorted entries on first call for this open directory.
    // Remove an empty cache on EOF so later fd reuse can rebuild entries.
    if !perproc.procfs_dir_cache.contains_key(&cache_key) {
        let dir = match std::fs::read_dir(&dir_path) {
            Ok(d) => d,
            Err(_) => return NotifAction::Continue,
        };

        let mut names: Vec<_> = Vec::new();
        {
            use std::os::unix::fs::MetadataExt;
            let dot_ino = std::fs::symlink_metadata(&dir_path).map(|m| m.ino()).unwrap_or(0);
            let dotdot_ino = dir_path
                .parent()
                .and_then(|p| std::fs::symlink_metadata(p).ok())
                .map(|m| m.ino())
                .unwrap_or(dot_ino);
            names.push((".".to_string(), DT_DIR, dot_ino));
            names.push(("..".to_string(), DT_DIR, dotdot_ino));
        }

        names.extend(dir
            .filter_map(|e| e.ok())
            .map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let d_type = match e.file_type() {
                    Ok(ft) if ft.is_dir() => DT_DIR,
                    Ok(ft) if ft.is_symlink() => DT_LNK,
                    _ => DT_REG,
                };
                let d_ino = {
                    use std::os::linux::fs::MetadataExt;
                    e.metadata().map(|m| m.st_ino()).unwrap_or(0)
                };
                (name, d_type, d_ino)
            }));

        names.sort_by(|a, b| a.0.cmp(&b.0));

        let entries: Vec<Vec<u8>> = names
            .iter()
            .enumerate()
            .filter_map(|(i, (name, d_type, d_ino))| {
                build_dirent64(*d_ino, (i + 1) as i64, *d_type, name)
            })
            .collect();

        perproc.procfs_dir_cache.insert(cache_key.clone(), entries);
    }

    let entries = match perproc.procfs_dir_cache.get_mut(&cache_key) {
        Some(e) => e,
        None => return NotifAction::Continue,
    };

    // Empty cache = already fully drained on a prior call → return 0 (EOF).
    if entries.is_empty() {
        perproc.procfs_dir_cache.remove(&cache_key);
        return NotifAction::ReturnValue(0);
    }

    // Pack as many entries as fit into the child's buffer.
    let mut result = Vec::new();
    let mut consumed = 0;
    for entry in entries.iter() {
        if result.len() + entry.len() > buf_size {
            break;
        }
        result.extend_from_slice(entry);
        consumed += 1;
    }

    if consumed > 0 {
        entries.drain(..consumed);
    }

    drop(perproc);

    if !result.is_empty() {
        if write_child_mem(notif_fd, notif.id, pid, buf_addr, &result).is_err() {
            return NotifAction::Continue;
        }
    }

    NotifAction::ReturnValue(result.len() as i64)
}

// ============================================================
// dirent64 construction helpers
// ============================================================

pub(crate) const DT_DIR: u8 = 4;
pub(crate) const DT_REG: u8 = 8;
pub(crate) const DT_LNK: u8 = 10;

/// Build a single linux_dirent64 entry.
/// struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }
/// d_reclen is 8-byte aligned.
///
/// Returns `None` if `name` exceeds the Linux NAME_MAX limit (255 bytes) —
/// such names can't appear in a real dirent stream, and accepting them would
/// produce a record whose `d_reclen` overflows the u16 field.
pub(crate) fn build_dirent64(d_ino: u64, d_off: i64, d_type: u8, name: &str) -> Option<Vec<u8>> {
    const NAME_MAX: usize = 255;
    let name_bytes = name.as_bytes();
    if name_bytes.len() > NAME_MAX {
        return None;
    }
    let reclen = ((19 + name_bytes.len() + 1) + 7) & !7; // +1 NUL, align to 8
    let mut buf = vec![0u8; reclen];
    buf[0..8].copy_from_slice(&d_ino.to_ne_bytes());
    buf[8..16].copy_from_slice(&d_off.to_ne_bytes());
    buf[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
    buf[18] = d_type;
    buf[19..19 + name_bytes.len()].copy_from_slice(name_bytes);
    Some(buf)
}

/// Build a filtered list of dirent64 entries for /proc, hiding PIDs not in the sandbox.
fn build_filtered_dirents(sandbox_pids: &HashSet<i32>) -> Vec<Vec<u8>> {
    let mut entries = Vec::new();
    let mut d_off: i64 = 0;

    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return entries,
    };

    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Filter out foreign PID directories.
        if let Ok(pid) = name_str.parse::<i32>() {
            if !sandbox_pids.contains(&pid) {
                continue;
            }
        }

        d_off += 1;

        let d_type = match entry.file_type() {
            Ok(ft) if ft.is_dir() => DT_DIR,
            Ok(ft) if ft.is_symlink() => DT_LNK,
            _ => DT_REG,
        };

        let d_ino = {
            use std::os::linux::fs::MetadataExt;
            entry.metadata().map(|m| m.st_ino()).unwrap_or(0)
        };

        if let Some(rec) = build_dirent64(d_ino, d_off, d_type, &name_str) {
            entries.push(rec);
        }
    }
    entries
}

// ============================================================
// handle_getdents — PID filtering
// ============================================================

/// Handle getdents64 for PID filtering when `isolate_pids` is true.
///
/// Intercepts getdents64 calls on /proc directory fds and returns a filtered
/// set of entries that hides PIDs not belonging to the sandbox.
pub(crate) async fn handle_getdents(
    notif: &SeccompNotif,
    processes: &Arc<ProcessIndex>,
    _policy: &NotifPolicy,
    notif_fd: RawFd,
) -> NotifAction {
    let pid = notif.pid; // u32
    let child_fd = (notif.data.args[0] & 0xFFFF_FFFF) as u32;
    let buf_addr = notif.data.args[1];
    let buf_size = (notif.data.args[2] & 0xFFFF_FFFF) as usize;

    // Check if the child's fd points to /proc.
    let link_path = format!("/proc/{}/fd/{}", pid, child_fd);
    let target = match std::fs::read_link(&link_path) {
        Ok(t) => t,
        Err(_) => return NotifAction::Continue,
    };
    if target.to_str() != Some("/proc") {
        return NotifAction::Continue;
    }

    let entry = match processes.entry_for(pid as i32) {
        Some(e) => e,
        None => return NotifAction::Continue,
    };
    let cache_key = (child_fd, target.to_string_lossy().into_owned());
    let mut perproc = entry.1.lock().await;

    // Build and cache entries on first call for this (fd, target) pair.
    if !perproc.procfs_dir_cache.contains_key(&cache_key) {
        // Snapshot sandbox PIDs without holding the per-process lock
        // any longer than needed — pids_snapshot only takes the
        // ProcessIndex read lock briefly.
        let snapshot = processes.pids_snapshot();
        let entries = build_filtered_dirents(&snapshot);
        perproc.procfs_dir_cache.insert(cache_key.clone(), entries);
    }

    let entries = match perproc.procfs_dir_cache.get_mut(&cache_key) {
        Some(e) => e,
        None => return NotifAction::Continue,
    };

    // Pack as many entries as fit into the child's buffer.
    let mut result = Vec::new();
    let mut consumed = 0;
    for entry in entries.iter() {
        if result.len() + entry.len() > buf_size {
            break;
        }
        result.extend_from_slice(entry);
        consumed += 1;
    }

    // Empty cache = already fully drained on a prior call → return 0 (EOF).
    if entries.is_empty() {
        perproc.procfs_dir_cache.remove(&cache_key);
        return NotifAction::ReturnValue(0);
    }

    if consumed > 0 {
        entries.drain(..consumed);
    }

    drop(perproc);

    // Write the result into the child's buffer and return the byte count.
    if !result.is_empty() {
        if write_child_mem(notif_fd, notif.id, pid, buf_addr, &result).is_err() {
            return NotifAction::Continue;
        }
    }

    NotifAction::ReturnValue(result.len() as i64)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sensitive_proc() {
        assert!(is_sensitive_proc("/proc/kcore"));
        assert!(is_sensitive_proc("/proc/kmsg"));
        assert!(is_sensitive_proc("/proc/kallsyms"));
        assert!(is_sensitive_proc("/proc/keys"));
        assert!(is_sensitive_proc("/proc/key-users"));
        assert!(is_sensitive_proc("/proc/sysrq-trigger"));
        assert!(is_sensitive_proc("/sys/firmware"));
        assert!(is_sensitive_proc("/sys/firmware/efi"));
        assert!(is_sensitive_proc("/sys/kernel/security"));
        assert!(is_sensitive_proc("/sys/kernel/security/apparmor"));

        assert!(!is_sensitive_proc("/proc/cpuinfo"));
        assert!(!is_sensitive_proc("/proc/meminfo"));
        assert!(!is_sensitive_proc("/proc/1/status"));
        assert!(is_sensitive_proc("/sys/class/net"));
        assert!(is_sensitive_proc("/sys/class/net/eth0"));
    }

    #[test]
    fn test_extract_proc_pid() {
        assert_eq!(extract_proc_pid("/proc/123/cmdline"), Some(123));
        assert_eq!(extract_proc_pid("/proc/1/status"), Some(1));
        assert_eq!(extract_proc_pid("/proc/99999/fd"), Some(99999));
        assert_eq!(extract_proc_pid("/proc/self/status"), None);
        assert_eq!(extract_proc_pid("/proc/cpuinfo"), None);
        assert_eq!(extract_proc_pid("/proc/meminfo"), None);
        assert_eq!(extract_proc_pid("/proc/net/tcp"), None);
        assert_eq!(extract_proc_pid("/etc/group"), None);
        assert_eq!(extract_proc_pid("/proc/"), None);
    }

    #[test]
    fn test_own_proc_target() {
        let target = own_proc_target("/proc/self/maps", 12, 10).unwrap();
        assert_eq!((target.base.as_str(), target.rest), ("/proc/10", "/maps"));
        assert_eq!(target.self_forms, ["/proc/self/maps"]);

        let target = own_proc_target("/proc/thread-self/stat", 12, 10).unwrap();
        assert_eq!((target.base.as_str(), target.rest), ("/proc/10/task/12", "/stat"));
        assert_eq!(target.self_forms, ["/proc/thread-self/stat", "/proc/self/task/12/stat"]);

        // What a dirfd on /proc/self reads back as.
        let target = own_proc_target("/proc/10/maps", 12, 10).unwrap();
        assert_eq!(target.self_forms, ["/proc/self/maps"]);

        let target = own_proc_target("/proc/self", 10, 10).unwrap();
        assert_eq!((target.rest, target.self_forms[0].as_str()), ("", "/proc/self"));

        assert_eq!(own_proc_target("/proc/11/maps", 12, 10), None);
        assert_eq!(own_proc_target("/proc/100/maps", 12, 10), None);
        assert_eq!(own_proc_target("/proc/selfish", 12, 10), None);
        assert_eq!(own_proc_target("/proc/cpuinfo", 12, 10), None);
    }

    #[test]
    fn test_own_proc_target_is_under_any() {
        use std::path::PathBuf;
        let thread = own_proc_target("/proc/thread-self/stat", 12, 10).unwrap();
        assert!(thread.is_under_any(&[PathBuf::from("/proc/thread-self/stat")]));
        assert!(thread.is_under_any(&[PathBuf::from("/proc/self")]));
        assert!(thread.is_under_any(&[PathBuf::from("/proc")]));
        assert!(!thread.is_under_any(&[PathBuf::from("/proc/self/stat")]));

        let maps = own_proc_target("/proc/10/maps", 12, 10).unwrap();
        assert!(maps.is_under_any(&[PathBuf::from("/usr"), PathBuf::from("/proc/self/maps")]));
        assert!(!maps.is_under_any(&[PathBuf::from("/proc/self/map")]));
        assert!(!maps.is_under_any(&[]));
    }

    #[test]
    fn test_own_fd_request() {
        assert_eq!(own_fd_request("/proc/self/fd/0", 12, 10), Some(0));
        assert_eq!(own_fd_request("/proc/thread-self/fd/7", 12, 10), Some(7));
        assert_eq!(own_fd_request("/proc/10/fd/63", 12, 10), Some(63));
        assert_eq!(own_fd_request("/proc/self/task/12/fd/3", 12, 10), Some(3));
        assert_eq!(own_fd_request("/proc/11/fd/0", 12, 10), None);
        assert_eq!(own_fd_request("/proc/self/fd", 12, 10), None);
        assert_eq!(own_fd_request("/proc/self/fd/0/x", 12, 10), None);
        assert_eq!(own_fd_request("/proc/self/fd/-1", 12, 10), None);
        assert_eq!(own_fd_request("/proc/self/fdinfo/0", 12, 10), None);
        assert_eq!(own_fd_request("/tmp/fd/0", 12, 10), None);
        if std::fs::read_link("/dev/stdin").is_ok_and(|l| l == std::path::Path::new("/proc/self/fd/0")) {
            assert_eq!(own_fd_request("/dev/stdin", 12, 10), Some(0));
        }
        if std::fs::read_link("/dev/fd").is_ok_and(|l| l == std::path::Path::new("/proc/self/fd")) {
            assert_eq!(own_fd_request("/dev/fd/5", 12, 10), Some(5));
            assert_eq!(own_fd_request("/dev/fdx/5", 12, 10), None);
        }
    }

    #[test]
    fn test_own_grant_covers() {
        use std::path::Path;
        assert!(own_grant_covers("/proc/self/status", Path::new("/proc/self")));
        assert!(own_grant_covers("/proc/self/status", Path::new("/proc")));
        assert!(!own_grant_covers("/proc/self/net/arp", Path::new("/proc/self")));
        assert!(!own_grant_covers("/proc/thread-self/net/arp", Path::new("/proc/thread-self")));
        assert!(!own_grant_covers("/proc/self/task/7/net/arp", Path::new("/proc/self")));
        assert!(own_grant_covers("/proc/self/net/arp", Path::new("/proc/self/net")));
        assert!(own_grant_covers("/proc/self/net/arp", Path::new("/proc/self/net/arp")));
        assert!(!own_grant_covers("/proc/self/net/arp", Path::new("/proc")));
        assert!(own_grant_covers("/proc/net/arp", Path::new("/proc")));
        assert!(own_grant_covers("/proc/net/arp", Path::new("/proc/net")));
        assert!(!own_grant_covers("/proc/self/status", Path::new("/proc/self/status/x")));
    }

    #[test]
    fn test_own_proc_self_forms() {
        assert_eq!(own_proc_self_forms("/proc/10/maps", 12, 10), ["/proc/self/maps"]);
        assert!(own_proc_self_forms("/proc/11/maps", 12, 10).is_empty());
        assert!(own_proc_self_forms("/etc/passwd", 12, 10).is_empty());
    }

    #[test]
    fn test_is_supervised_proc_grant() {
        use std::path::Path;
        assert!(is_supervised_proc_grant(Path::new("/proc")));
        assert!(is_supervised_proc_grant(Path::new("/proc/self/maps")));
        assert!(is_supervised_proc_grant(Path::new("/proc/thread-self/net/arp")));
        assert!(is_supervised_proc_grant(Path::new("/proc/1/maps")));
        assert!(!is_supervised_proc_grant(Path::new("/procfs")));
        assert!(!is_supervised_proc_grant(Path::new("/etc")));
    }

    #[test]
    fn test_canon_proc_namespace() {
        assert_eq!(canon_proc_namespace("/proc/self/net/dev"), "/proc/net/dev");
        assert_eq!(canon_proc_namespace("/proc/thread-self/net/tcp6"), "/proc/net/tcp6");
        assert_eq!(canon_proc_namespace("/proc/42/net"), "/proc/net");
        assert_eq!(canon_proc_namespace("/proc/42/task/43/net/dev"), "/proc/net/dev");
        assert_eq!(canon_proc_namespace("/proc/net/dev"), "/proc/net/dev");
        assert_eq!(canon_proc_namespace("/proc/self/network"), "/proc/self/network");
        assert_eq!(canon_proc_namespace("/proc/self/task/net/dev"), "/proc/self/task/net/dev");
        assert_eq!(canon_proc_namespace("/proc/sys/net/core"), "/proc/sys/net/core");

        assert_eq!(canon_proc_namespace("/proc/thread-self/mounts"), "/proc/self/mounts");
        assert_eq!(canon_proc_namespace("/proc/42/mountinfo"), "/proc/self/mountinfo");
        assert_eq!(canon_proc_namespace("/proc/self/task/43/mounts"), "/proc/self/mounts");
        assert_eq!(canon_proc_namespace("/proc/42/mountstats"), "/proc/self/mountstats");
        assert_eq!(canon_proc_namespace("/proc/self/mountinfo"), "/proc/self/mountinfo");
        assert_eq!(canon_proc_namespace("/proc/mounts"), "/proc/mounts");
        assert_eq!(canon_proc_namespace("/proc/thread-self/cgroup"), "/proc/self/cgroup");
        assert_eq!(canon_proc_namespace("/proc/42/task/43/cgroup"), "/proc/self/cgroup");
        assert_eq!(canon_proc_namespace("/proc/cgroups"), "/proc/cgroups");
        assert_eq!(canon_proc_namespace("/proc/self/mountsx"), "/proc/self/mountsx");
    }

    #[test]
    fn test_generate_cpuinfo_single() {
        let info = generate_cpuinfo(1);
        let text = String::from_utf8(info).unwrap();
        assert!(text.contains("processor\t: 0"));
        assert!(text.contains("model name\t: Virtual CPU"));
        assert!(text.contains("cpu MHz\t\t: 2400.000"));
        assert!(!text.contains("processor\t: 1"));
    }

    #[test]
    fn test_generate_cpuinfo_multiple() {
        let info = generate_cpuinfo(4);
        let text = String::from_utf8(info).unwrap();
        assert!(text.contains("processor\t: 0"));
        assert!(text.contains("processor\t: 1"));
        assert!(text.contains("processor\t: 2"));
        assert!(text.contains("processor\t: 3"));
        assert!(!text.contains("processor\t: 4"));
    }

    #[test]
    fn test_generate_meminfo() {
        // 1 GiB total, 256 MiB used
        let total = 1024 * 1024 * 1024u64;
        let used = 256 * 1024 * 1024u64;
        let info = generate_meminfo(total, used);
        let text = String::from_utf8(info).unwrap();

        let total_kb = total / 1024;
        let used_kb = used / 1024;
        let free_kb = total_kb - used_kb;

        assert!(text.contains(&format!("MemTotal:       {} kB", total_kb)));
        assert!(text.contains(&format!("MemFree:        {} kB", free_kb)));
        assert!(text.contains(&format!("MemAvailable:   {} kB", free_kb)));
    }

    #[test]
    fn test_generate_meminfo_zero_used() {
        let total = 512 * 1024 * 1024u64;
        let info = generate_meminfo(total, 0);
        let text = String::from_utf8(info).unwrap();
        let total_kb = total / 1024;
        assert!(text.contains(&format!("MemTotal:       {} kB", total_kb)));
        assert!(text.contains(&format!("MemFree:        {} kB", total_kb)));
    }

    #[test]
    fn test_generate_meminfo_over_used() {
        // used > total should clamp
        let total = 100 * 1024u64;
        let used = 200 * 1024u64;
        let info = generate_meminfo(total, used);
        let text = String::from_utf8(info).unwrap();
        // Free should be 0 (saturating sub)
        assert!(text.contains("MemFree:        0 kB"));
    }

    #[test]
    fn test_generate_uptime() {
        let info = generate_uptime(123.456);
        let text = String::from_utf8(info).unwrap();
        assert!(text.starts_with("123.46"));
        assert!(text.contains("0.00"));
    }

    #[test]
    fn test_generate_uptime_zero() {
        let info = generate_uptime(0.0);
        let text = String::from_utf8(info).unwrap();
        assert!(text.starts_with("0.00"));
    }

    #[test]
    fn test_generate_uptime_negative_clamped() {
        let info = generate_uptime(-5.0);
        let text = String::from_utf8(info).unwrap();
        assert!(text.starts_with("0.00"));
    }

    #[test]
    fn test_loadavg_ewma() {
        let mut la = LoadAvg::new();
        assert_eq!(la.avg_1, 0.0);
        assert_eq!(la.avg_5, 0.0);
        assert_eq!(la.avg_15, 0.0);

        // After sampling with 4 running processes, averages should rise
        for _ in 0..12 {
            la.sample(4);
        }
        // 1-min average should converge faster than 5 and 15
        assert!(la.avg_1 > la.avg_5);
        assert!(la.avg_5 > la.avg_15);
        assert!(la.avg_1 > 2.0); // should be well above 0 after 60s of load=4
    }

    #[test]
    fn test_loadavg_ewma_decay() {
        let mut la = LoadAvg::new();
        // Load up
        for _ in 0..60 {
            la.sample(10);
        }
        let peak = la.avg_1;
        // Load drops to 0
        for _ in 0..60 {
            la.sample(0);
        }
        assert!(la.avg_1 < peak * 0.1, "1-min avg should decay quickly");
    }

    #[test]
    fn test_generate_loadavg() {
        let la = LoadAvg { avg_1: 1.23, avg_5: 0.45, avg_15: 0.12 };
        let info = generate_loadavg(&la, 3, 10, 42);
        let text = String::from_utf8(info).unwrap();
        assert!(text.contains("1.23"));
        assert!(text.contains("0.45"));
        assert!(text.contains("0.12"));
        assert!(text.contains("3/10"));
        assert!(text.contains("42"));
    }

    #[test]
    fn test_generate_loadavg_zero_procs() {
        let la = LoadAvg::new();
        let info = generate_loadavg(&la, 0, 0, 0);
        let text = String::from_utf8(info).unwrap();
        // running should be clamped: max(0,1).min(0) = 0
        assert!(text.contains("0/0"));
    }

    #[test]
    fn test_detect_fstype_root() {
        // / should always return a known fstype
        let fstype = detect_fstype(std::path::Path::new("/"));
        assert_ne!(fstype, "unknown", "root fs should have a known type");
    }

    #[test]
    fn test_detect_fstype_nonexistent() {
        let fstype = detect_fstype(std::path::Path::new("/no/such/path"));
        assert_eq!(fstype, "unknown");
    }

    #[test]
    fn test_generate_proc_mounts_chroot() {
        // Use real paths so detect_fstype works
        let tmp = std::env::temp_dir();
        let mounts = vec![
            (std::path::PathBuf::from("/work"), tmp.clone()),
            (std::path::PathBuf::from("/data"), tmp.clone()),
        ];
        let ro = vec![std::path::PathBuf::from("/data")];
        let content = generate_proc_mounts(Some(tmp.as_path()), &mounts, &ro, false);
        let text = String::from_utf8(content).unwrap();
        // Root entry with detected fstype (not hardcoded ext4)
        assert!(text.starts_with("sandlock / "), "Should start with root entry, got: {}", text);
        assert!(text.contains("sandlock /work "));
        assert!(text.contains("sandlock /data "));
        // Should NOT contain host paths
        assert!(!text.contains(tmp.to_str().unwrap()));
        // Fstype should be detected, not "unknown" (tmp is on a real fs)
        let root_line = text.lines().next().unwrap();
        assert!(!root_line.contains("unknown"), "root fstype should be detected, got: {}", root_line);
        // Options reflect read-only: /data is ro, /work and root are rw.
        assert!(text.lines().any(|l| l.starts_with("sandlock / ") && l.contains(" rw,relatime ")));
        assert!(text.lines().any(|l| l.starts_with("sandlock /work ") && l.contains(" rw,relatime ")));
        assert!(text.lines().any(|l| l.starts_with("sandlock /data ") && l.contains(" ro,relatime ")));
    }

    #[test]
    fn test_generate_proc_mounts_read_only_root() {
        let tmp = std::env::temp_dir();
        let content = generate_proc_mounts(Some(tmp.as_path()), &[], &[], true);
        let text = String::from_utf8(content).unwrap();
        assert!(text.lines().next().unwrap().contains(" ro,relatime "), "got: {}", text);
    }

    #[test]
    fn test_generate_proc_mounts_no_chroot() {
        let mounts: Vec<(std::path::PathBuf, std::path::PathBuf)> = vec![];
        let content = generate_proc_mounts(None, &mounts, &[], false);
        let text = String::from_utf8(content).unwrap();
        assert!(text.contains("rootfs / rootfs rw 0 0"));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn test_generate_proc_mountstats() {
        let text = String::from_utf8(generate_proc_mountstats(None, &[])).unwrap();
        assert_eq!(text, "device rootfs mounted on / with fstype rootfs\n");

        let tmp = std::env::temp_dir();
        let mounts = vec![(std::path::PathBuf::from("/work"), tmp.clone())];
        let text = String::from_utf8(generate_proc_mountstats(Some(tmp.as_path()), &mounts)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("device sandlock mounted on / with fstype "), "got: {}", text);
        assert!(lines[1].starts_with("device sandlock mounted on /work with fstype "), "got: {}", text);
        assert!(!text.contains(tmp.to_str().unwrap()));
    }

    #[test]
    fn test_generate_proc_mountinfo_chroot() {
        let tmp = std::env::temp_dir();
        let mounts = vec![
            (std::path::PathBuf::from("/work"), tmp.clone()),
        ];
        let content = generate_proc_mountinfo(Some(tmp.as_path()), &mounts, &[], false);
        let text = String::from_utf8(content).unwrap();
        assert!(text.contains("/ / rw,relatime -"));
        assert!(text.contains("/ /work rw,relatime -"));
        assert!(!text.contains(tmp.to_str().unwrap()));
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn test_generate_proc_mountinfo_no_chroot() {
        let mounts: Vec<(std::path::PathBuf, std::path::PathBuf)> = vec![];
        let content = generate_proc_mountinfo(None, &mounts, &[], false);
        let text = String::from_utf8(content).unwrap();
        assert!(text.contains("/ / rw - rootfs rootfs rw"));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn test_build_dirent64() {
        let entry = build_dirent64(12345, 1, DT_DIR, "1234").unwrap();
        assert_eq!(entry.len(), 24); // 19 + 5 = 24, already aligned
        let d_ino = u64::from_ne_bytes(entry[0..8].try_into().unwrap());
        assert_eq!(d_ino, 12345);
        let d_reclen = u16::from_ne_bytes(entry[16..18].try_into().unwrap());
        assert_eq!(d_reclen, 24);
        assert_eq!(entry[18], DT_DIR);
        assert_eq!(&entry[19..23], b"1234");
        assert_eq!(entry[23], 0);
    }

    #[test]
    fn test_build_dirent64_alignment() {
        let entry = build_dirent64(1, 1, DT_REG, "ab").unwrap();
        // 19 + 3 = 22, padded to 24
        assert_eq!(entry.len(), 24);
    }

    #[test]
    fn test_build_dirent64_rejects_oversize_name() {
        let name = "x".repeat(256);
        assert!(build_dirent64(1, 1, DT_REG, &name).is_none());
    }

    #[test]
    fn test_build_filtered_dirents() {
        use std::collections::HashSet;
        let mut sandbox_pids = HashSet::new();
        sandbox_pids.insert(1_i32);
        let entries = build_filtered_dirents(&sandbox_pids);
        assert!(!entries.is_empty());
    }
}
