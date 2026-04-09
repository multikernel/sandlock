// Seccomp user notification supervisor — async event loop that receives
// notifications from the kernel, dispatches them to handler functions, and
// sends responses.

use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use crate::error::NotifError;
use crate::sys::structs::{
    SeccompNotif, SeccompNotifAddfd, SeccompNotifResp,
    SECCOMP_ADDFD_FLAG_SEND, SECCOMP_IOCTL_NOTIF_ADDFD, SECCOMP_IOCTL_NOTIF_ID_VALID, SECCOMP_IOCTL_NOTIF_RECV,
    SECCOMP_IOCTL_NOTIF_SEND, SECCOMP_IOCTL_NOTIF_SET_FLAGS,
    SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP, SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    ENOMEM,
};

// ============================================================
// NotifAction — how the supervisor should respond
// ============================================================

/// How the supervisor should respond to a notification.
#[derive(Debug)]
pub enum NotifAction {
    /// SECCOMP_USER_NOTIF_FLAG_CONTINUE — let the syscall proceed.
    Continue,
    /// Return -1 with the given errno.
    Errno(i32),
    /// Inject a file descriptor into the child, then continue.
    InjectFd { srcfd: RawFd, targetfd: i32 },
    /// Inject a file descriptor using SECCOMP_ADDFD_FLAG_SEND (atomically responds).
    /// The child sees the injected fd as the return value of the syscall.
    /// The `OwnedFd` is closed automatically after the ioctl completes.
    /// `newfd_flags` controls flags on the injected fd (e.g. O_CLOEXEC).
    InjectFdSend { srcfd: OwnedFd, newfd_flags: u32 },
    /// Synthetic return value (the child sees this as the syscall result).
    ReturnValue(i64),
    /// Don't respond — used for checkpoint/freeze.
    Hold,
    /// Kill the child process group (OOM-kill semantics).
    /// Fields: signal, process group leader pid.
    Kill { sig: i32, pgid: i32 },
}

// ============================================================
// NetworkPolicy — network access policy enum
// ============================================================

/// Global network policy for the sandbox.
#[derive(Debug, Clone)]
pub enum NetworkPolicy {
    /// All IPs allowed (no net_allow_hosts configured).
    Unrestricted,
    /// Only these IPs are allowed (from resolved net_allow_hosts).
    AllowList(HashSet<IpAddr>),
}

/// Check if a path-bearing notification targets a denied path.
///
/// For two-path syscalls (renameat2, linkat), checks both source and
/// destination paths — a denied file must not be linked, renamed, or
/// overwritten.
///
/// Each resolved path is checked both as-is (lexical normalization) and
/// after following symlinks via `canonicalize`.  This prevents bypass via
/// pre-existing symlinks, relative symlinks, or symlink chains that
/// ultimately resolve to a denied path.
pub(crate) fn is_path_denied_for_notif(
    policy_fn_state: &super::state::PolicyFnState,
    notif: &SeccompNotif,
    notif_fd: RawFd,
) -> bool {
    if let Some(path) = resolve_path_for_notif(notif, notif_fd) {
        if is_denied_with_symlink_resolve(policy_fn_state, &path) {
            return true;
        }
    }
    // For two-path syscalls, also check the second (destination) path.
    if let Some(path) = resolve_second_path_for_notif(notif, notif_fd) {
        if is_denied_with_symlink_resolve(policy_fn_state, &path) {
            return true;
        }
    }
    false
}

/// Check a path against denied entries, also resolving symlinks.
///
/// First checks the lexical path, then `canonicalize`s to follow symlinks
/// and checks the real path.  This catches pre-existing symlinks, relative
/// symlinks, and symlink chains that resolve to a denied file.
fn is_denied_with_symlink_resolve(
    policy_fn_state: &super::state::PolicyFnState,
    path: &str,
) -> bool {
    // Check the literal (lexically normalized) path first.
    if policy_fn_state.is_path_denied(path) {
        return true;
    }
    // Follow symlinks and re-check against denied entries.
    if let Ok(real) = std::fs::canonicalize(path) {
        if policy_fn_state.is_path_denied(&real.to_string_lossy()) {
            return true;
        }
    }
    false
}

/// Duplicate a file descriptor from an arbitrary process (by PID/TID) into the supervisor.
/// Uses PIDFD_THREAD so pidfd_open works for any thread, not just the group leader.
pub(crate) fn dup_fd_from_pid(pid: u32, target_fd: i32) -> Result<OwnedFd, io::Error> {
    const SYS_PIDFD_OPEN: i64 = 434;
    const SYS_PIDFD_GETFD: i64 = 438;
    const PIDFD_THREAD: i64 = libc::O_EXCL as i64; // Linux 6.9+
    let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid as i64, PIDFD_THREAD) };
    if pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    let pidfd_owned = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };
    let ret = unsafe {
        libc::syscall(SYS_PIDFD_GETFD, pidfd_owned.as_raw_fd() as i64, target_fd as i64, 0i64)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
    }
}

// ============================================================
// NotifPolicy — policy for the notification supervisor
// ============================================================

/// Policy for the notification supervisor.
pub struct NotifPolicy {
    pub max_memory_bytes: u64,
    pub max_processes: u32,
    pub has_memory_limit: bool,
    pub has_net_allowlist: bool,
    pub has_random_seed: bool,
    pub has_time_start: bool,
    pub time_offset: i64,
    pub num_cpus: Option<u32>,
    pub port_remap: bool,
    pub cow_enabled: bool,
    pub chroot_root: Option<std::path::PathBuf>,
    /// Virtual paths allowed for reading under chroot (original user-specified paths).
    pub chroot_readable: Vec<std::path::PathBuf>,
    /// Virtual paths allowed for writing under chroot (original user-specified paths).
    pub chroot_writable: Vec<std::path::PathBuf>,
    /// Virtual paths explicitly denied under chroot.
    pub chroot_denied: Vec<std::path::PathBuf>,
    /// Mount mappings: (virtual_path, host_path) pairs.
    pub chroot_mounts: Vec<(std::path::PathBuf, std::path::PathBuf)>,
    pub deterministic_dirs: bool,
    pub hostname: Option<String>,
    pub has_http_acl: bool,
}

// ============================================================
// Low-level ioctl helpers
// ============================================================

/// Receive a seccomp notification from the kernel.
/// ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &notif)
fn recv_notif(fd: RawFd) -> io::Result<SeccompNotif> {
    let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV as libc::c_ulong, &mut notif as *mut _)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(notif)
    }
}

/// Send a response with SECCOMP_USER_NOTIF_FLAG_CONTINUE.
fn respond_continue(fd: RawFd, id: u64) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    send_resp_raw(fd, &resp)
}

/// Send a response that returns -1 with the given errno.
fn respond_errno(fd: RawFd, id: u64, errno: i32) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    send_resp_raw(fd, &resp)
}

/// Send a response with a synthetic return value.
fn respond_value(fd: RawFd, id: u64, val: i64) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val,
        error: 0,
        flags: 0,
    };
    send_resp_raw(fd, &resp)
}

/// Inject a file descriptor into the child process using SECCOMP_ADDFD_FLAG_SEND.
///
/// Uses the SEND flag to atomically inject the fd and respond to the syscall.
/// The ioctl return value is the fd number assigned in the child process.
/// After this call, no additional SECCOMP_IOCTL_NOTIF_SEND is needed.
fn inject_fd_and_send(fd: RawFd, id: u64, srcfd: RawFd, newfd_flags: u32) -> io::Result<i32> {
    let addfd = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: srcfd as u32,
        newfd: 0,   // ignored when SECCOMP_ADDFD_FLAG_SETFD is not set
        newfd_flags,
    };
    let ret = unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong, &addfd as *const _)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as i32)
    }
}

/// Inject a file descriptor into the child process (without responding).
/// ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd)
fn inject_fd(fd: RawFd, id: u64, srcfd: RawFd, targetfd: i32) -> io::Result<()> {
    let addfd = SeccompNotifAddfd {
        id,
        flags: 0,
        srcfd: srcfd as u32,
        newfd: targetfd as u32,
        newfd_flags: 0,
    };
    let ret = unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD as libc::c_ulong, &addfd as *const _)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Raw ioctl to send a notification response.
fn send_resp_raw(fd: RawFd, resp: &SeccompNotifResp) -> io::Result<()> {
    let ret = unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND as libc::c_ulong, resp as *const _)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Check whether a notification ID is still valid (TOCTOU guard).
/// ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id)
pub(crate) fn id_valid(fd: RawFd, id: u64) -> io::Result<()> {
    let ret = unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID as libc::c_ulong, &id as *const _)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Try to enable sync wakeup (Linux 6.7+). Ignores errors.
fn try_set_sync_wakeup(fd: RawFd) {
    let flags: u64 = SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP as u64;
    unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SET_FLAGS as libc::c_ulong, &flags as *const _);
    }
}

// ============================================================
// Child memory access helpers
// ============================================================

/// Read bytes from a child process via process_vm_readv (single syscall).
fn read_child_mem_vm(pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, NotifError> {
    let mut buf = vec![0u8; len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    let ret = unsafe {
        libc::process_vm_readv(pid as i32, &local_iov, 1, &remote_iov, 1, 0)
    };
    if ret < 0 {
        Err(NotifError::ChildMemoryRead(io::Error::last_os_error()))
    } else {
        buf.truncate(ret as usize);
        Ok(buf)
    }
}

/// Write bytes to a child process via process_vm_writev (single syscall).
fn write_child_mem_vm(pid: u32, addr: u64, data: &[u8]) -> Result<(), NotifError> {
    let local_iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: data.len(),
    };
    let ret = unsafe {
        libc::process_vm_writev(pid as i32, &local_iov, 1, &remote_iov, 1, 0)
    };
    if ret < 0 {
        Err(NotifError::ChildMemoryRead(io::Error::last_os_error()))
    } else if (ret as usize) < data.len() {
        Err(NotifError::ChildMemoryRead(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short write: {} of {} bytes", ret, data.len()),
        )))
    } else {
        Ok(())
    }
}

/// Read bytes from a child process via process_vm_readv.
///
/// Performs TOCTOU validation by calling `id_valid` before and after
/// the read to ensure the notification is still live.
pub(crate) fn read_child_mem(
    notif_fd: RawFd,
    id: u64,
    pid: u32,
    addr: u64,
    len: usize,
) -> Result<Vec<u8>, NotifError> {
    id_valid(notif_fd, id).map_err(NotifError::Ioctl)?;
    let result = read_child_mem_vm(pid, addr, len)?;
    id_valid(notif_fd, id).map_err(NotifError::Ioctl)?;
    Ok(result)
}

/// Write bytes to a child process via process_vm_writev.
///
/// Performs TOCTOU validation by calling `id_valid` before and after
/// the write to ensure the notification is still live.
pub(crate) fn write_child_mem(
    notif_fd: RawFd,
    id: u64,
    pid: u32,
    addr: u64,
    data: &[u8],
) -> Result<(), NotifError> {
    id_valid(notif_fd, id).map_err(NotifError::Ioctl)?;
    write_child_mem_vm(pid, addr, data)?;
    id_valid(notif_fd, id).map_err(NotifError::Ioctl)?;
    Ok(())
}

// ============================================================
// Response dispatch
// ============================================================

/// Dispatch a `NotifAction` to the appropriate low-level response function.
fn send_response(fd: RawFd, id: u64, action: NotifAction) -> io::Result<()> {
    match action {
        NotifAction::Continue => respond_continue(fd, id),
        NotifAction::Errno(errno) => respond_errno(fd, id, errno),
        NotifAction::InjectFd { srcfd, targetfd } => {
            inject_fd(fd, id, srcfd, targetfd)?;
            respond_continue(fd, id)
        }
        NotifAction::InjectFdSend { srcfd, newfd_flags } => {
            // SECCOMP_ADDFD_FLAG_SEND atomically injects the fd and responds.
            // No separate NOTIF_SEND needed after this.
            // Fall back to Continue if ADDFD_SEND fails (e.g., old kernel).
            // srcfd (OwnedFd) is dropped at end of this arm, closing the fd.
            match inject_fd_and_send(fd, id, srcfd.as_raw_fd(), newfd_flags) {
                Ok(_new_fd) => Ok(()),
                Err(_) => respond_continue(fd, id),
            }
        }
        NotifAction::ReturnValue(val) => respond_value(fd, id, val),
        NotifAction::Hold => Ok(()), // Don't send a response.
        NotifAction::Kill { sig, pgid } => {
            // Kill the entire process group, then return ENOMEM so the
            // seccomp notification is resolved (avoids a kernel warning).
            unsafe { libc::killpg(pgid, sig) };
            respond_errno(fd, id, ENOMEM)
        }
    }
}

// ============================================================
// vDSO re-patching after exec
// ============================================================

/// Re-patch the vDSO if the base address changed (e.g. after exec replaces it).
fn maybe_patch_vdso(pid: i32, procfs: &mut super::state::ProcfsState, policy: &NotifPolicy) {
    let base = match crate::vdso::find_vdso_base(pid) {
        Ok(addr) => addr,
        Err(_) => return,
    };
    if base == procfs.vdso_patched_addr {
        return; // already patched this vDSO
    }
    let time_offset = if policy.has_time_start { Some(policy.time_offset) } else { None };
    if crate::vdso::patch(pid, time_offset, policy.has_random_seed).is_ok() {
        procfs.vdso_patched_addr = base;
    }
}

// ============================================================
// Policy event emission
// ============================================================

/// Map a syscall number to a human-readable name for the policy callback.
fn syscall_name(nr: i64) -> &'static str {
    match nr {
        n if n == libc::SYS_openat => "openat",
        n if n == libc::SYS_connect => "connect",
        n if n == libc::SYS_sendto => "sendto",
        n if n == libc::SYS_sendmsg => "sendmsg",
        n if n == libc::SYS_bind => "bind",
        n if n == libc::SYS_clone => "clone",
        n if n == libc::SYS_clone3 => "clone3",
        n if n == libc::SYS_vfork => "vfork",
        n if n == libc::SYS_execve => "execve",
        n if n == libc::SYS_execveat => "execveat",
        n if n == libc::SYS_mmap => "mmap",
        n if n == libc::SYS_munmap => "munmap",
        n if n == libc::SYS_brk => "brk",
        n if n == libc::SYS_getrandom => "getrandom",
        n if n == libc::SYS_unlinkat => "unlinkat",
        n if n == libc::SYS_mkdirat => "mkdirat",
        _ => "unknown",
    }
}

/// Map a syscall number to a high-level category.
fn syscall_category(nr: i64) -> crate::policy_fn::SyscallCategory {
    use crate::policy_fn::SyscallCategory;
    match nr {
        n if n == libc::SYS_openat || n == libc::SYS_unlinkat
            || n == libc::SYS_mkdirat || n == libc::SYS_renameat2
            || n == libc::SYS_symlinkat || n == libc::SYS_linkat
            || n == libc::SYS_fchmodat || n == libc::SYS_fchownat
            || n == libc::SYS_truncate || n == libc::SYS_readlinkat
            || n == libc::SYS_newfstatat || n == libc::SYS_statx
            || n == libc::SYS_faccessat || n == libc::SYS_getdents64
            || n == libc::SYS_getdents => SyscallCategory::File,
        n if n == libc::SYS_connect || n == libc::SYS_sendto
            || n == libc::SYS_sendmsg || n == libc::SYS_bind
            || n == libc::SYS_getsockname => SyscallCategory::Network,
        n if n == libc::SYS_clone || n == libc::SYS_clone3
            || n == libc::SYS_vfork || n == libc::SYS_execve
            || n == libc::SYS_execveat => SyscallCategory::Process,
        n if n == libc::SYS_mmap || n == libc::SYS_munmap
            || n == libc::SYS_brk || n == libc::SYS_mremap
            => SyscallCategory::Memory,
        _ => SyscallCategory::File, // default
    }
}

/// Read the parent PID from /proc/{pid}/stat.
fn read_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Format: "pid (comm) state ppid ..."
    // Find the closing ')' then split the rest
    let close_paren = stat.rfind(')')?;
    let rest = &stat[close_paren + 2..]; // skip ") "
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] = state, fields[1] = ppid
    fields.get(1)?.parse().ok()
}

/// Read a NUL-terminated path from child memory (up to 256 bytes).
fn read_path_for_event(notif: &SeccompNotif, addr: u64, notif_fd: RawFd) -> Option<String> {
    if addr == 0 { return None; }
    let bytes = read_child_mem(notif_fd, notif.id, notif.pid, addr, 256).ok()?;
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..nul].to_vec()).ok()
}

fn normalize_path(path: &std::path::Path) -> String {
    use std::path::{Component, PathBuf};

    let mut normalized = PathBuf::new();
    let absolute = path.is_absolute();
    if absolute {
        normalized.push("/");
    }

    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(_) => {}
        }
    }

    if normalized.as_os_str().is_empty() {
        if absolute { "/".into() } else { ".".into() }
    } else {
        normalized.to_string_lossy().into_owned()
    }
}

fn resolve_at_path_for_event(notif: &SeccompNotif, dirfd: i64, path: &str) -> Option<String> {
    use std::path::Path;

    if Path::new(path).is_absolute() {
        return Some(normalize_path(Path::new(path)));
    }

    let dirfd32 = dirfd as i32;
    let base = if dirfd32 == libc::AT_FDCWD {
        std::fs::read_link(format!("/proc/{}/cwd", notif.pid)).ok()?
    } else {
        std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd32)).ok()?
    };

    Some(normalize_path(&base.join(path)))
}

fn resolve_path_for_notif(notif: &SeccompNotif, notif_fd: RawFd) -> Option<String> {
    let nr = notif.data.nr as i64;
    match nr {
        n if n == libc::SYS_openat => {
            // openat(dirfd, pathname, flags, mode)
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[0] as i64, &path)
        }
        n if n == libc::SYS_open || n == libc::SYS_execve => {
            let path = read_path_for_event(notif, notif.data.args[0], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &path)
        }
        n if n == libc::SYS_execveat => {
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[0] as i64, &path)
        }
        // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        // Check the source (old) path — deny if it's a denied file being linked away.
        n if n == libc::SYS_linkat => {
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[0] as i64, &path)
        }
        // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        // Check the source (old) path — deny if a denied file is being renamed away.
        n if n == libc::SYS_renameat2 => {
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[0] as i64, &path)
        }
        // symlinkat(target, newdirfd, linkpath)
        // The target string is what the symlink points to; deny if it names a denied path.
        n if n == libc::SYS_symlinkat => {
            let target = read_path_for_event(notif, notif.data.args[0], notif_fd)?;
            // target may be absolute or relative to the process cwd
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &target)
        }
        // link(oldpath, newpath) — legacy, AT_FDCWD implied for both
        n if n == libc::SYS_link => {
            let path = read_path_for_event(notif, notif.data.args[0], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &path)
        }
        // rename(oldpath, newpath) — legacy, AT_FDCWD implied for both
        n if n == libc::SYS_rename => {
            let path = read_path_for_event(notif, notif.data.args[0], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &path)
        }
        // symlink(target, linkpath) — legacy
        n if n == libc::SYS_symlink => {
            let target = read_path_for_event(notif, notif.data.args[0], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &target)
        }
        _ => None,
    }
}

/// Resolve the second (destination) path for two-path syscalls.
///
/// Returns `None` for syscalls that only have a single path argument.
fn resolve_second_path_for_notif(notif: &SeccompNotif, notif_fd: RawFd) -> Option<String> {
    let nr = notif.data.nr as i64;
    match nr {
        // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        n if n == libc::SYS_renameat2 => {
            let path = read_path_for_event(notif, notif.data.args[3], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[2] as i64, &path)
        }
        // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        // Destination of a hardlink to a denied file should also be denied
        // (prevents overwriting a denied file via linkat).
        n if n == libc::SYS_linkat => {
            let path = read_path_for_event(notif, notif.data.args[3], notif_fd)?;
            resolve_at_path_for_event(notif, notif.data.args[2] as i64, &path)
        }
        // rename(oldpath, newpath) — legacy
        n if n == libc::SYS_rename => {
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &path)
        }
        // link(oldpath, newpath) — legacy
        n if n == libc::SYS_link => {
            let path = read_path_for_event(notif, notif.data.args[1], notif_fd)?;
            resolve_at_path_for_event(notif, libc::AT_FDCWD as i64, &path)
        }
        _ => None,
    }
}

/// Extract IP and port from a sockaddr in child memory.
fn read_sockaddr_for_event(notif: &SeccompNotif, addr: u64, len: usize, notif_fd: RawFd)
    -> (Option<std::net::IpAddr>, Option<u16>)
{
    if addr == 0 || len < 4 { return (None, None); }
    let bytes = match read_child_mem(notif_fd, notif.id, notif.pid, addr, len.min(128)) {
        Ok(b) => b,
        Err(_) => return (None, None),
    };
    if bytes.len() < 4 { return (None, None); }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let ip = match family as u32 {
        f if f == crate::sys::structs::AF_INET && bytes.len() >= 8 => {
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[4], bytes[5], bytes[6], bytes[7],
            )))
        }
        f if f == crate::sys::structs::AF_INET6 && bytes.len() >= 24 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[8..24]);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)))
        }
        _ => None,
    };
    (ip, if port > 0 { Some(port) } else { None })
}

/// Read argv (array of string pointers) from child memory for execve.
/// execve(path, argv, envp): argv is a NULL-terminated array of char* pointers.
fn read_argv_for_event(notif: &SeccompNotif, argv_ptr: u64, notif_fd: RawFd) -> Option<Vec<String>> {
    if argv_ptr == 0 { return None; }
    let mut args = Vec::new();
    let ptr_size = std::mem::size_of::<u64>();

    for i in 0..64 { // safety limit
        let ptr_addr = argv_ptr + (i * ptr_size) as u64;
        let ptr_bytes = read_child_mem(notif_fd, notif.id, notif.pid, ptr_addr, ptr_size).ok()?;
        let str_ptr = u64::from_ne_bytes(ptr_bytes[..8].try_into().ok()?);
        if str_ptr == 0 { break; } // NULL terminator

        if let Some(s) = read_path_for_event(notif, str_ptr, notif_fd) {
            args.push(s);
        } else {
            break;
        }
    }

    if args.is_empty() { None } else { Some(args) }
}

/// Emit a syscall event to the policy_fn callback thread (if active).
/// Returns the callback's verdict for held syscalls.
async fn emit_policy_event(
    notif: &SeccompNotif,
    action: &NotifAction,
    policy_fn_state: &Arc<tokio::sync::Mutex<super::state::PolicyFnState>>,
    notif_fd: RawFd,
) -> Option<crate::policy_fn::Verdict> {
    let pfs = policy_fn_state.lock().await;
    let tx = match pfs.event_tx.as_ref() {
        Some(tx) => tx.clone(),
        None => return None,
    };
    drop(pfs);

    let nr = notif.data.nr as i64;
    let denied = matches!(action, NotifAction::Errno(_));
    let name = syscall_name(nr);
    let category = syscall_category(nr);
    let parent_pid = read_ppid(notif.pid);

    // Extract metadata based on syscall type
    let mut path = None;
    let mut host = None;
    let mut port = None;
    let mut size = None;
    let mut argv = None;

    if nr == libc::SYS_openat || nr == libc::SYS_execve || nr == libc::SYS_execveat {
        // openat(dirfd, pathname, ...): args[1] = path ptr
        // execve(pathname, argv, envp): args[0] = path ptr, args[1] = argv ptr
        let path_ptr = if nr == libc::SYS_openat {
            notif.data.args[1]
        } else {
            notif.data.args[0]
        };
        path = read_path_for_event(notif, path_ptr, notif_fd);

        // Extract argv for execve/execveat
        if nr == libc::SYS_execve || nr == libc::SYS_execveat {
            argv = read_argv_for_event(notif, notif.data.args[1], notif_fd);
        }
    }

    if nr == libc::SYS_connect || nr == libc::SYS_sendto || nr == libc::SYS_bind {
        // connect(fd, addr, addrlen): args[1]=addr, args[2]=len
        let addr_ptr = notif.data.args[1];
        let addr_len = notif.data.args[2] as usize;
        let (h, p) = read_sockaddr_for_event(notif, addr_ptr, addr_len, notif_fd);
        host = h;
        port = p;
    }

    if nr == libc::SYS_mmap {
        // mmap(addr, length, ...): args[1] = length
        size = Some(notif.data.args[1]);
    }

    let event = crate::policy_fn::SyscallEvent {
        syscall: name.to_string(),
        category,
        pid: notif.pid,
        parent_pid,
        path,
        host,
        port,
        size,
        argv,
        denied,
    };

    // Hold syscalls where the callback's verdict matters.
    // The child is blocked until the callback returns.
    let is_held = nr == libc::SYS_execve || nr == libc::SYS_execveat
        || nr == libc::SYS_connect || nr == libc::SYS_sendto
        || nr == libc::SYS_bind || nr == libc::SYS_openat;

    if is_held {
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel();
        let _ = tx.send(crate::policy_fn::PolicyEvent {
            event,
            gate: Some(gate_tx),
        });
        match tokio::time::timeout(std::time::Duration::from_secs(5), gate_rx).await {
            Ok(Ok(verdict)) => Some(verdict),
            _ => None, // timeout or channel closed — allow
        }
    } else {
        let _ = tx.send(crate::policy_fn::PolicyEvent {
            event,
            gate: None,
        });
        None
    }
}

// ============================================================
// Per-notification handler (runs in a spawned task)
// ============================================================

/// Process a single seccomp notification: vDSO re-patch, path denial check,
/// dispatch, policy event emission, and response.
async fn handle_notification(
    notif: SeccompNotif,
    ctx: &Arc<super::ctx::SupervisorCtx>,
    dispatch_table: &super::dispatch::DispatchTable,
    fd: RawFd,
) {
    let policy = &ctx.policy;

    // Re-patch vDSO if needed (exec replaces it with a fresh copy).
    if policy.has_time_start || policy.has_random_seed {
        let mut pfs = ctx.procfs.lock().await;
        maybe_patch_vdso(notif.pid as i32, &mut pfs, policy);
    }

    // Check dynamic path denials before dispatch
    let mut action = {
        let nr = notif.data.nr as i64;
        let should_precheck_denied = policy.chroot_root.is_none()
            && [
                libc::SYS_openat, libc::SYS_open, libc::SYS_execve, libc::SYS_execveat,
                libc::SYS_linkat, libc::SYS_link,
                libc::SYS_renameat2, libc::SYS_rename,
                libc::SYS_symlinkat, libc::SYS_symlink,
            ].contains(&nr);
        if should_precheck_denied {
            let pfs = ctx.policy_fn.lock().await;
            if is_path_denied_for_notif(&pfs, &notif, fd) {
                NotifAction::Errno(libc::EACCES)
            } else {
                drop(pfs);
                dispatch_table.dispatch(notif, ctx, fd).await
            }
        } else {
            dispatch_table.dispatch(notif, ctx, fd).await
        }
    };

    // Emit event to policy_fn callback if active
    if let Some(verdict) = emit_policy_event(&notif, &action, &ctx.policy_fn, fd).await {
        use crate::policy_fn::Verdict;
        match verdict {
            Verdict::Deny => { action = NotifAction::Errno(libc::EPERM); }
            Verdict::DenyWith(errno) => { action = NotifAction::Errno(errno); }
            Verdict::Audit => { /* allow, but could log here */ }
            Verdict::Allow => {}
        }
    }

    // Ignore error — child may have exited between recv and response.
    let _ = send_response(fd, notif.id, action);
}

// ============================================================
// Main supervisor loop
// ============================================================

/// Async event loop that processes seccomp notifications.
///
/// Runs until the notification fd is closed (child exits or filter is removed).
pub async fn supervisor(
    notif_fd: OwnedFd,
    ctx: Arc<super::ctx::SupervisorCtx>,
) {
    let fd = notif_fd.as_raw_fd();

    // Build the dispatch table once at startup.
    let dispatch_table = Arc::new(super::dispatch::build_dispatch_table(&ctx.policy, &ctx.resource));

    // Try to enable sync wakeup (Linux 6.7+, ignore error on older kernels).
    try_set_sync_wakeup(fd);

    // SECCOMP_IOCTL_NOTIF_RECV blocks regardless of O_NONBLOCK, so we
    // receive notifications in a blocking thread and send them to the
    // async handler via a channel.  This guarantees we never miss a
    // notification — the thread is always blocked in recv_notif ready
    // for the next one.
    //
    // Notifications are processed sequentially (not spawned) to avoid
    // mutex contention between concurrent handlers.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SeccompNotif>();

    std::thread::spawn(move || {
        loop {
            match recv_notif(fd) {
                Ok(notif) => {
                    if tx.send(notif).is_err() {
                        break; // receiver dropped — supervisor shutting down
                    }
                }
                Err(_) => break, // fd closed — child exited
            }
        }
    });

    while let Some(notif) = rx.recv().await {
        handle_notification(notif, &ctx, &dispatch_table, fd).await;
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notif_action_debug() {
        // Ensure all variants implement Debug.
        let _ = format!("{:?}", NotifAction::Continue);
        let _ = format!("{:?}", NotifAction::Errno(1));
        let _ = format!("{:?}", NotifAction::InjectFd { srcfd: 3, targetfd: 4 });
        // Use a real fd (dup'd from stderr) so OwnedFd can safely close it.
        let test_fd = unsafe { OwnedFd::from_raw_fd(libc::dup(2)) };
        let _ = format!("{:?}", NotifAction::InjectFdSend { srcfd: test_fd, newfd_flags: 0 });
        let _ = format!("{:?}", NotifAction::ReturnValue(42));
        let _ = format!("{:?}", NotifAction::Hold);
        let _ = format!("{:?}", NotifAction::Kill { sig: 9, pgid: 1 });
    }

    #[test]
    fn test_network_state_new() {
        let ns = super::super::state::NetworkState::new();
        assert!(matches!(ns.network_policy, NetworkPolicy::Unrestricted));
        assert!(ns.port_map.bound_ports.is_empty());
    }

    #[test]
    fn test_time_random_state_new() {
        let tr = super::super::state::TimeRandomState::new(None, None);
        assert!(tr.time_offset.is_none());
        assert!(tr.random_state.is_none());
    }

    #[test]
    fn test_resource_state_new() {
        let rs = super::super::state::ResourceState::new(1024 * 1024, 10);
        assert_eq!(rs.mem_used, 0);
        assert_eq!(rs.max_memory_bytes, 1024 * 1024);
        assert_eq!(rs.max_processes, 10);
        assert!(rs.brk_bases.is_empty());
        assert!(!rs.hold_forks);
        assert!(rs.held_notif_ids.is_empty());
    }

    #[test]
    fn test_process_vm_readv_self() {
        let data: u64 = 0xDEADBEEF_CAFEBABE;
        let addr = &data as *const u64 as u64;
        let pid = std::process::id();
        let result = read_child_mem_vm(pid, addr, 8);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        let read_val = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(read_val, 0xDEADBEEF_CAFEBABE);
    }

    #[test]
    fn test_process_vm_writev_self() {
        let mut data: u64 = 0;
        let addr = &mut data as *mut u64 as u64;
        let pid = std::process::id();
        let payload = 0x1234567890ABCDEFu64.to_ne_bytes();
        let result = write_child_mem_vm(pid, addr, &payload);
        assert!(result.is_ok());
        assert_eq!(data, 0x1234567890ABCDEF);
    }
}
