// /proc file virtualization and PID filtering via seccomp notification.
//
// Intercepts openat syscalls that target sensitive /proc paths or virtual
// files (/proc/cpuinfo, /proc/meminfo). For virtual files, creates a memfd
// with fake content and injects it into the child's fd table.

use std::collections::HashSet;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, RawFd};
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
    let raw = memfd.as_raw_fd();
    {
        // Use raw fd to write — OwnedFd doesn't impl Write.
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        if file.write_all(content).is_err() || file.seek(SeekFrom::Start(0)).is_err() {
            // Don't drop the OwnedFd via file — we took ownership with from_raw_fd
            std::mem::forget(file);
            return NotifAction::Continue;
        }
        // Forget the File so it doesn't close the fd — OwnedFd still owns it.
        std::mem::forget(file);
    }

    // Leak the OwnedFd so it stays alive through the ioctl in send_response.
    // SECCOMP_ADDFD_FLAG_SEND atomically injects the fd and responds to the syscall,
    // so the child sees the memfd as the return value from openat (not the real file).
    let leaked_fd = raw;
    std::mem::forget(memfd);

    NotifAction::InjectFdSend {
        srcfd: leaked_fd,
    }
}

use std::os::unix::io::FromRawFd;

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
        let st = state.lock().await;
        let content = generate_meminfo(policy.max_memory_bytes, st.mem_used);
        return inject_memfd(&content);
    }

    // Virtualize /proc/net/tcp and /proc/net/tcp6 when port_remap is active.
    if policy.port_remap && (path == "/proc/net/tcp" || path == "/proc/net/tcp6") {
        let is_v6 = path.ends_with('6');
        let st = state.lock().await;
        let content = generate_proc_net_tcp(&st.port_map.bound_ports, is_v6);
        return inject_memfd(&content);
    }

    NotifAction::Continue
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

    if consumed > 0 {
        entries.drain(..consumed);
    }
    if entries.is_empty() {
        st.getdents_cache.remove(&cache_key);
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
