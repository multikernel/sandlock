// /proc file virtualization and PID filtering via seccomp notification.
//
// Intercepts openat syscalls that target sensitive /proc paths or virtual
// files (/proc/cpuinfo, /proc/meminfo). For virtual files, creates a memfd
// with fake content and injects it into the child's fd table.

use std::collections::HashSet;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction, NotifPolicy, SupervisorState};
use crate::sys::structs::{SeccompNotif, EACCES};
use crate::sys::syscall;

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
    "/sys/firmware",
    "/sys/kernel/security",
];

/// Returns true for paths that should be denied access.
pub(crate) fn is_sensitive_proc(path: &str) -> bool {
    SENSITIVE_PATHS
        .iter()
        .any(|&sensitive| path == sensitive || path.starts_with(&format!("{}/", sensitive)))
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

/// Generate a virtual /proc/mounts showing only the sandbox's own mounts.
///
/// Produces standard `/proc/mounts` format: `device mountpoint type options dump pass`
/// Shows the root entry and each fs_mount entry. Filesystem types are detected
/// from the actual host paths via statfs(2).
pub(crate) fn generate_proc_mounts(
    chroot_root: Option<&std::path::Path>,
    chroot_mounts: &[(std::path::PathBuf, std::path::PathBuf)],
) -> Vec<u8> {
    let mut buf = String::new();

    if let Some(root) = chroot_root {
        let fstype = detect_fstype(root);
        buf.push_str(&format!("sandlock / {} rw,relatime 0 0\n", fstype));
    } else {
        buf.push_str("rootfs / rootfs rw 0 0\n");
    }

    for (virtual_path, host_path) in chroot_mounts {
        let vp = virtual_path.to_string_lossy();
        let fstype = detect_fstype(host_path);
        buf.push_str(&format!("sandlock {} {} rw,relatime 0 0\n", vp, fstype));
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
) -> Vec<u8> {
    let mut buf = String::new();
    let mut mount_id: u32 = 20;

    if let Some(root) = chroot_root {
        let fstype = detect_fstype(root);
        buf.push_str(&format!(
            "{} 1 8:1 / / rw,relatime - {} sandlock rw\n", mount_id, fstype
        ));
    } else {
        buf.push_str(&format!(
            "{} 1 0:1 / / rw - rootfs rootfs rw\n", mount_id
        ));
    }
    mount_id += 1;

    for (virtual_path, host_path) in chroot_mounts {
        let vp = virtual_path.to_string_lossy();
        let fstype = detect_fstype(host_path);
        buf.push_str(&format!(
            "{} 20 8:1 / {} rw,relatime - {} sandlock rw\n", mount_id, vp, fstype
        ));
        mount_id += 1;
    }

    buf.into_bytes()
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

/// Create a memfd with the given content and return an InjectFd action.
///
/// The memfd is created in the supervisor process, written with content,
/// seeked to the beginning, then injected into the child via NOTIF_ADDFD.
/// The child sees it as the fd returned by their openat call.
///
/// IMPORTANT: The returned OwnedFd must stay alive until after the ioctl
/// in send_response completes. We leak it intentionally here because the
/// supervisor loop calls inject_fd immediately after this returns. A more
/// robust design would store it in an arena, but leaking is acceptable for
/// the supervisor's lifetime.
fn inject_memfd(content: &[u8]) -> NotifAction {
    let memfd = match syscall::memfd_create("sandlock", 0) {
        Ok(fd) => fd,
        Err(_) => return NotifAction::Continue, // fallback: let real open proceed
    };

    // Write content and seek to start.
    // Borrow the raw fd for File I/O without transferring ownership.
    let raw = memfd.as_raw_fd();
    {
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        if file.write_all(content).is_err() || file.seek(SeekFrom::Start(0)).is_err() {
            std::mem::forget(file);
            return NotifAction::Continue;
        }
        // Forget the File so it doesn't close the fd — memfd (OwnedFd) still owns it.
        std::mem::forget(file);
    }

    // Move the OwnedFd into InjectFdSend — send_response will close it after the ioctl.
    NotifAction::InjectFdSend { srcfd: memfd, newfd_flags: libc::O_CLOEXEC as u32 }
}

// ============================================================
// Read path from child memory
// ============================================================

/// Read a NUL-terminated path string from child memory.
fn read_path(notif: &SeccompNotif, addr: u64, notif_fd: RawFd) -> Option<String> {
    if addr == 0 {
        return None;
    }
    // Read up to 256 bytes — enough for any /proc path we care about.
    let bytes = read_child_mem(notif_fd, notif.id, notif.pid, addr, 256).ok()?;
    let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..nul_pos].to_vec()).ok()
}

// ============================================================
// handle_proc_open — intercept openat for /proc virtualization
// ============================================================

/// Handle openat syscalls targeting /proc files.
///
/// - Denies access to sensitive kernel files.
/// - Virtualizes /proc/cpuinfo and /proc/meminfo with fake content.
/// - Lets everything else through.
pub(crate) async fn handle_proc_open(
    notif: &SeccompNotif,
    state: &Arc<Mutex<SupervisorState>>,
    resource: &Arc<Mutex<crate::seccomp::state::ResourceState>>,
    policy: &NotifPolicy,
    notif_fd: RawFd,
) -> NotifAction {
    // openat(dirfd, pathname, flags, mode)
    // args[0] = dirfd, args[1] = pathname pointer
    let path_ptr = notif.data.args[1];
    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    // Block sensitive paths.
    if is_sensitive_proc(&path) {
        return NotifAction::Errno(EACCES);
    }

    // Virtualize /proc/cpuinfo.
    if path == "/proc/cpuinfo" {
        if let Some(num_cpus) = policy.num_cpus {
            let content = generate_cpuinfo(num_cpus);
            return inject_memfd(&content);
        }
    }

    // Virtualize /proc/meminfo.
    if path == "/proc/meminfo" && policy.max_memory_bytes > 0 {
        let rs = resource.lock().await;
        let content = generate_meminfo(policy.max_memory_bytes, rs.mem_used);
        return inject_memfd(&content);
    }

    // Virtualize /proc/uptime when time_start is set.
    if path == "/proc/uptime" && policy.has_time_start {
        let rs = resource.lock().await;
        let elapsed = rs.start_instant.elapsed().as_secs_f64();
        let content = generate_uptime(elapsed);
        return inject_memfd(&content);
    }

    // Virtualize /proc/loadavg when proc virtualization is active.
    if path == "/proc/loadavg" {
        let st = state.lock().await;
        let rs = resource.lock().await;
        let total = st.proc_pids.len() as u32;
        let running = rs.proc_count;
        let last_pid = st.proc_pids.iter().max().copied().unwrap_or(0);
        let content = generate_loadavg(&rs.load_avg, running, total, last_pid);
        return inject_memfd(&content);
    }

    // Virtualize /proc/net/tcp and /proc/net/tcp6 when port_remap is active.
    if policy.port_remap && (path == "/proc/net/tcp" || path == "/proc/net/tcp6") {
        let is_v6 = path.ends_with('6');
        let st = state.lock().await;
        let content = generate_proc_net_tcp(&st.port_map.bound_ports, is_v6);
        return inject_memfd(&content);
    }

    // Virtualize /proc/mounts and /proc/self/mounts.
    if path == "/proc/mounts" || path == "/proc/self/mounts" {
        let content = generate_proc_mounts(
            policy.chroot_root.as_deref(),
            &policy.chroot_mounts,
        );
        return inject_memfd(&content);
    }

    // Virtualize /proc/self/mountinfo.
    if path == "/proc/self/mountinfo" {
        let content = generate_proc_mountinfo(
            policy.chroot_root.as_deref(),
            &policy.chroot_mounts,
        );
        return inject_memfd(&content);
    }

    NotifAction::Continue
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

/// Handle openat targeting /etc/hostname — return a memfd with the virtual hostname.
pub(crate) fn handle_hostname_open(
    notif: &SeccompNotif,
    hostname: &str,
    notif_fd: RawFd,
) -> Option<NotifAction> {
    let path_ptr = notif.data.args[1];
    let path = read_path(notif, path_ptr, notif_fd)?;

    if path != "/etc/hostname" {
        return None;
    }

    let content = format!("{}\n", hostname);
    Some(inject_memfd(content.as_bytes()))
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
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
) -> NotifAction {
    let pid = notif.pid;
    let child_fd = (notif.data.args[0] & 0xFFFF_FFFF) as u32;
    let buf_addr = notif.data.args[1];
    let buf_size = (notif.data.args[2] & 0xFFFF_FFFF) as usize;

    let cache_key = (pid as i32, child_fd);
    let mut st = state.lock().await;

    // Build and cache sorted entries on first call for this (pid, fd) pair.
    // An empty Vec means "already fully consumed" — return 0 (EOF).
    if !st.getdents_cache.contains_key(&cache_key) {
        let link_path = format!("/proc/{}/fd/{}", pid, child_fd);
        let dir_path = match std::fs::read_link(&link_path) {
            Ok(t) => t,
            Err(_) => return NotifAction::Continue,
        };

        let dir = match std::fs::read_dir(&dir_path) {
            Ok(d) => d,
            Err(_) => return NotifAction::Continue,
        };

        let mut names: Vec<_> = dir
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
            })
            .collect();

        names.sort_by(|a, b| a.0.cmp(&b.0));

        let entries: Vec<Vec<u8>> = names
            .iter()
            .enumerate()
            .map(|(i, (name, d_type, d_ino))| {
                build_dirent64(*d_ino, (i + 1) as i64, *d_type, name)
            })
            .collect();

        st.getdents_cache.insert(cache_key, entries);
    }

    let entries = match st.getdents_cache.get_mut(&cache_key) {
        Some(e) => e,
        None => return NotifAction::Continue,
    };

    // Empty cache = already fully drained on a prior call → return 0 (EOF).
    if entries.is_empty() {
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

    drop(st);

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
pub(crate) fn build_dirent64(d_ino: u64, d_off: i64, d_type: u8, name: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let reclen = ((19 + name_bytes.len() + 1) + 7) & !7; // +1 NUL, align to 8
    let mut buf = vec![0u8; reclen];
    buf[0..8].copy_from_slice(&d_ino.to_ne_bytes());
    buf[8..16].copy_from_slice(&d_off.to_ne_bytes());
    buf[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
    buf[18] = d_type;
    buf[19..19 + name_bytes.len()].copy_from_slice(name_bytes);
    buf
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

        entries.push(build_dirent64(d_ino, d_off, d_type, &name_str));
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
    state: &Arc<Mutex<SupervisorState>>,
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

    let cache_key = (pid as i32, child_fd);
    let mut st = state.lock().await;

    // Build and cache entries on first call for this (pid, fd) pair.
    if !st.getdents_cache.contains_key(&cache_key) {
        let entries = build_filtered_dirents(&st.proc_pids);
        st.getdents_cache.insert(cache_key, entries);
    }

    let entries = match st.getdents_cache.get_mut(&cache_key) {
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
        return NotifAction::ReturnValue(0);
    }

    if consumed > 0 {
        entries.drain(..consumed);
    }

    drop(st);

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
        assert!(!is_sensitive_proc("/sys/class/net"));
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
        let content = generate_proc_mounts(Some(tmp.as_path()), &mounts);
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
    }

    #[test]
    fn test_generate_proc_mounts_no_chroot() {
        let mounts: Vec<(std::path::PathBuf, std::path::PathBuf)> = vec![];
        let content = generate_proc_mounts(None, &mounts);
        let text = String::from_utf8(content).unwrap();
        assert!(text.contains("rootfs / rootfs rw 0 0"));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn test_generate_proc_mountinfo_chroot() {
        let tmp = std::env::temp_dir();
        let mounts = vec![
            (std::path::PathBuf::from("/work"), tmp.clone()),
        ];
        let content = generate_proc_mountinfo(Some(tmp.as_path()), &mounts);
        let text = String::from_utf8(content).unwrap();
        assert!(text.contains("/ / rw,relatime -"));
        assert!(text.contains("/ /work rw,relatime -"));
        assert!(!text.contains(tmp.to_str().unwrap()));
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn test_generate_proc_mountinfo_no_chroot() {
        let mounts: Vec<(std::path::PathBuf, std::path::PathBuf)> = vec![];
        let content = generate_proc_mountinfo(None, &mounts);
        let text = String::from_utf8(content).unwrap();
        assert!(text.contains("/ / rw - rootfs rootfs rw"));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn test_build_dirent64() {
        let entry = build_dirent64(12345, 1, DT_DIR, "1234");
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
        let entry = build_dirent64(1, 1, DT_REG, "ab");
        // 19 + 3 = 22, padded to 24
        assert_eq!(entry.len(), 24);
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
