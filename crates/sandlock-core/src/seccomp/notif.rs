// Seccomp user notification supervisor — async event loop that receives
// notifications from the kernel, dispatches them to handler functions, and
// sends responses.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use rand_chacha::ChaCha8Rng;
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;

use crate::error::NotifError;
use crate::port_remap::PortMap;
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
    InjectFdSend { srcfd: RawFd },
    /// Synthetic return value (the child sees this as the syscall result).
    ReturnValue(i64),
    /// Don't respond — used for checkpoint/freeze.
    Hold,
    /// Kill the child process group (OOM-kill semantics).
    /// Fields: signal, process group leader pid.
    Kill { sig: i32, pgid: i32 },
}

// ============================================================
// SupervisorState — runtime state shared across handlers
// ============================================================

/// Global network policy for the sandbox.
#[derive(Debug, Clone)]
pub enum NetworkPolicy {
    /// All IPs allowed (no net_allow_hosts configured).
    Unrestricted,
    /// Only these IPs are allowed (from resolved net_allow_hosts).
    AllowList(HashSet<IpAddr>),
}

/// Runtime state shared across notification handlers.
pub struct SupervisorState {
    pub mem_used: u64,
    pub brk_bases: HashMap<i32, u64>,
    pub proc_count: u32,
    pub proc_pids: HashSet<i32>,
    pub hold_forks: bool,
    pub held_notif_ids: Vec<u64>,
    /// Global network policy: unrestricted or limited to a set of IPs.
    pub network_policy: NetworkPolicy,
    pub max_memory_bytes: u64,
    pub max_processes: u32,
    pub time_offset: Option<i64>,
    pub random_state: Option<ChaCha8Rng>,
    pub port_map: PortMap,
    /// Cache of filtered dirent entries keyed by (pid, fd).
    /// Populated on first getdents64 call for a /proc directory, drained on subsequent calls.
    pub getdents_cache: HashMap<(i32, u32), Vec<Vec<u8>>>,
    /// Base address of the last vDSO we patched (0 = not yet patched).
    pub vdso_patched_addr: u64,
    /// Seccomp-based COW branch (None if COW disabled).
    pub cow_branch: Option<crate::cow::seccomp::SeccompCowBranch>,
    /// Getdents cache for COW directories.
    pub cow_dir_cache: HashMap<(i32, u32), Vec<Vec<u8>>>,
    /// Getdents cache for chroot directories.
    pub chroot_dir_cache: HashMap<(i32, u32), Vec<Vec<u8>>>,
    /// pidfd for the child process (for pidfd_getfd on-behalf syscalls).
    pub child_pidfd: Option<RawFd>,
    /// Event sender for dynamic policy callback (None if no policy_fn).
    pub policy_event_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::policy_fn::PolicyEvent>>,
    /// Per-PID network overrides from policy_fn.
    pub pid_ip_overrides: std::sync::Arc<std::sync::RwLock<HashMap<u32, HashSet<IpAddr>>>>,
    /// Shared live policy for dynamic updates (None if no policy_fn).
    pub live_policy: Option<std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    /// Dynamically denied paths from policy_fn.
    pub denied_paths: std::sync::Arc<std::sync::RwLock<HashSet<String>>>,
}

impl SupervisorState {
    /// Create a new supervisor state with the given limits.
    pub fn new(
        max_memory_bytes: u64,
        max_processes: u32,
        time_offset: Option<i64>,
        random_state: Option<ChaCha8Rng>,
    ) -> Self {
        Self {
            mem_used: 0,
            brk_bases: HashMap::new(),
            proc_count: 0,
            proc_pids: HashSet::new(),
            hold_forks: false,
            held_notif_ids: Vec::new(),
            network_policy: NetworkPolicy::Unrestricted,
            max_memory_bytes,
            max_processes,
            time_offset,
            random_state,
            port_map: PortMap::new(),
            getdents_cache: HashMap::new(),
            vdso_patched_addr: 0,
            cow_branch: None,
            cow_dir_cache: HashMap::new(),
            chroot_dir_cache: HashMap::new(),
            child_pidfd: None,
            policy_event_tx: None,
            pid_ip_overrides: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            live_policy: None,
            denied_paths: std::sync::Arc::new(std::sync::RwLock::new(HashSet::new())),
        }
    }
}

impl SupervisorState {
    /// Get the effective network policy for a PID.
    ///
    /// Priority: per-PID override > live policy > global network_policy.
    /// Returns `NetworkPolicy::Unrestricted` if no restrictions apply.
    pub fn effective_network_policy(&self, pid: u32) -> NetworkPolicy {
        // Per-PID override takes priority
        if let Ok(overrides) = self.pid_ip_overrides.read() {
            if let Some(ips) = overrides.get(&pid) {
                return NetworkPolicy::AllowList(ips.clone());
            }
        }
        // Live policy (dynamic updates from policy_fn)
        if let Some(ref lp) = self.live_policy {
            if let Ok(live) = lp.read() {
                if !live.allowed_ips.is_empty() {
                    return NetworkPolicy::AllowList(live.allowed_ips.clone());
                }
            }
        }
        // Global policy
        self.network_policy.clone()
    }

    /// Check if a path is dynamically denied.
    pub fn is_path_denied(&self, path: &str) -> bool {
        if let Ok(denied) = self.denied_paths.read() {
            denied.iter().any(|d| path == d || path.starts_with(&format!("{}/", d)))
        } else {
            false
        }
    }

    /// Check if an openat notification targets a denied path.
    pub fn is_path_denied_for_notif(&self, notif: &SeccompNotif, notif_fd: RawFd) -> bool {
        let path_ptr = notif.data.args[1];
        if path_ptr == 0 { return false; }
        if let Some(path) = read_path_for_event(notif, path_ptr, notif_fd) {
            self.is_path_denied(&path)
        } else {
            false
        }
    }
}

/// Duplicate a file descriptor from the child process into the supervisor.
/// Uses pidfd_getfd (syscall 438, Linux 5.6+).
pub(crate) fn dup_child_fd(child_pidfd: RawFd, target_fd: i32) -> Result<OwnedFd, io::Error> {
    const SYS_PIDFD_GETFD: i64 = 438;
    let ret = unsafe {
        libc::syscall(SYS_PIDFD_GETFD, child_pidfd as i64, target_fd as i64, 0i64)
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
    pub has_proc_virt: bool,
    pub isolate_pids: bool,
    pub port_remap: bool,
    pub cow_enabled: bool,
    pub chroot_root: Option<std::path::PathBuf>,
    /// Virtual paths allowed for reading under chroot (original user-specified paths).
    pub chroot_readable: Vec<std::path::PathBuf>,
    /// Virtual paths allowed for writing under chroot (original user-specified paths).
    pub chroot_writable: Vec<std::path::PathBuf>,
    pub deterministic_dirs: bool,
    pub hostname: Option<String>,
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
fn inject_fd_and_send(fd: RawFd, id: u64, srcfd: RawFd) -> io::Result<i32> {
    let addfd = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: srcfd as u32,
        newfd: 0,   // ignored when SECCOMP_ADDFD_FLAG_SETFD is not set
        newfd_flags: libc::O_CLOEXEC as u32,
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
        NotifAction::InjectFdSend { srcfd } => {
            // SECCOMP_ADDFD_FLAG_SEND atomically injects the fd and responds.
            // No separate NOTIF_SEND needed after this.
            // Fall back to Continue if ADDFD_SEND fails (e.g., old kernel).
            match inject_fd_and_send(fd, id, srcfd) {
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
// Dispatch table — routes syscalls to handlers
// ============================================================

/// Route a syscall notification to the appropriate handler.
async fn dispatch(
    notif: &SeccompNotif,
    policy: &NotifPolicy,
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    // Fork/clone family
    if nr == libc::SYS_clone || nr == libc::SYS_clone3 || nr == libc::SYS_vfork {
        return crate::resource::handle_fork(notif, state, policy).await;
    }

    // Memory management syscalls
    if policy.has_memory_limit
        && (nr == libc::SYS_mmap
            || nr == libc::SYS_munmap
            || nr == libc::SYS_brk
            || nr == libc::SYS_mremap
            || nr == libc::SYS_shmget)
    {
        return crate::resource::handle_memory(notif, state, policy).await;
    }

    // Network syscalls
    if policy.has_net_allowlist
        && (nr == libc::SYS_connect || nr == libc::SYS_sendto || nr == libc::SYS_sendmsg)
    {
        return crate::network::handle_net(notif, state, notif_fd).await;
    }

    // Deterministic random — getrandom() syscall
    if policy.has_random_seed && nr == libc::SYS_getrandom as i64 {
        let mut st = state.lock().await;
        if let Some(ref mut rng) = st.random_state {
            return crate::random::handle_getrandom(notif, rng, notif_fd);
        }
    }

    // Deterministic random — /dev/urandom and /dev/random opens
    if policy.has_random_seed && nr == libc::SYS_openat as i64 {
        let mut st = state.lock().await;
        if let Some(ref mut rng) = st.random_state {
            if let Some(action) = crate::random::handle_random_open(notif, rng, notif_fd) {
                return action;
            }
        }
    }

    // Timer adjustment for frozen time
    if policy.has_time_start {
        if nr == libc::SYS_clock_nanosleep as i64
            || nr == libc::SYS_timerfd_settime as i64
            || nr == libc::SYS_timer_settime as i64
        {
            return crate::time::handle_timer(notif, policy.time_offset, notif_fd);
        }
    }

    // Chroot path interception (runs before COW)
    if let Some(ref chroot_root) = policy.chroot_root {
        use crate::chroot::dispatch::ChrootCtx;
        let ctx = ChrootCtx {
            root: chroot_root,
            readable: &policy.chroot_readable,
            writable: &policy.chroot_writable,
        };
        if nr == libc::SYS_openat {
            let action = crate::chroot::dispatch::handle_chroot_open(notif, state, notif_fd, &ctx).await;
            if !matches!(action, NotifAction::Continue) {
                return action;
            }
        }
        if nr == libc::SYS_open as i64 {
            let action = crate::chroot::dispatch::handle_chroot_legacy_open(notif, state, notif_fd, &ctx).await;
            if !matches!(action, NotifAction::Continue) {
                return action;
            }
        }
        if nr == libc::SYS_execve || nr == libc::SYS_execveat {
            return crate::chroot::dispatch::handle_chroot_exec(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_unlinkat || nr == libc::SYS_mkdirat
            || nr == libc::SYS_renameat2 || nr == libc::SYS_symlinkat
            || nr == libc::SYS_linkat || nr == libc::SYS_fchmodat
            || nr == libc::SYS_fchownat || nr == libc::SYS_truncate
        {
            return crate::chroot::dispatch::handle_chroot_write(notif, state, notif_fd, &ctx).await;
        }
        // Legacy write syscalls (musl)
        if nr == libc::SYS_unlink as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_unlink(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_rmdir as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_rmdir(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_mkdir as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_mkdir(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_rename as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_rename(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_symlink as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_symlink(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_link as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_link(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_chmod as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_chmod(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_chown as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_chown(notif, state, notif_fd, &ctx, false).await;
        }
        if nr == libc::SYS_lchown as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_chown(notif, state, notif_fd, &ctx, true).await;
        }
        if nr == libc::SYS_newfstatat || nr == libc::SYS_faccessat
            || nr == crate::chroot::dispatch::SYS_FACCESSAT2
        {
            return crate::chroot::dispatch::handle_chroot_stat(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_stat as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_stat(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_lstat as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_lstat(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_access as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_access(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_statx {
            return crate::chroot::dispatch::handle_chroot_statx(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_readlinkat {
            return crate::chroot::dispatch::handle_chroot_readlink(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_readlink as i64 {
            return crate::chroot::dispatch::handle_chroot_legacy_readlink(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_getdents64 as i64 || nr == libc::SYS_getdents as i64 {
            return crate::chroot::dispatch::handle_chroot_getdents(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_chdir as i64 {
            return crate::chroot::dispatch::handle_chroot_chdir(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_getcwd as i64 {
            return crate::chroot::dispatch::handle_chroot_getcwd(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_statfs as i64 {
            return crate::chroot::dispatch::handle_chroot_statfs(notif, state, notif_fd, &ctx).await;
        }
        if nr == libc::SYS_utimensat as i64 {
            return crate::chroot::dispatch::handle_chroot_utimensat(notif, state, notif_fd, &ctx).await;
        }
    }

    // COW filesystem interception
    if policy.cow_enabled {
        // Write syscalls — always intercept when under COW workdir
        if nr == libc::SYS_unlinkat || nr == libc::SYS_mkdirat
            || nr == libc::SYS_renameat2 || nr == libc::SYS_symlinkat
            || nr == libc::SYS_linkat || nr == libc::SYS_fchmodat
            || nr == libc::SYS_fchownat || nr == libc::SYS_truncate
        {
            return crate::cow::dispatch::handle_cow_write(notif, state, notif_fd).await;
        }

        // openat — try COW first, fall through to proc virt if not COW path
        if nr == libc::SYS_openat {
            let action = crate::cow::dispatch::handle_cow_open(notif, state, notif_fd).await;
            if !matches!(action, NotifAction::Continue) {
                return action;
            }
            // Fall through to proc virt / other handlers
        }

        // Read syscalls — only intercept when COW has changes (optimization)
        let has_changes = {
            let st = state.lock().await;
            st.cow_branch.as_ref().map_or(false, |c| c.has_changes())
        };
        if has_changes {
            if nr == libc::SYS_newfstatat || nr == libc::SYS_faccessat {
                return crate::cow::dispatch::handle_cow_stat(notif, state, notif_fd).await;
            }
            if nr == libc::SYS_statx {
                return crate::cow::dispatch::handle_cow_statx(notif, state, notif_fd).await;
            }
            if nr == libc::SYS_readlinkat {
                return crate::cow::dispatch::handle_cow_readlink(notif, state, notif_fd).await;
            }
            if nr == libc::SYS_getdents64 as i64 || nr == libc::SYS_getdents as i64 {
                return crate::cow::dispatch::handle_cow_getdents(notif, state, notif_fd).await;
            }
        }
    }

    // /proc virtualization
    if policy.has_proc_virt {
        if nr == libc::SYS_openat as i64 {
            return crate::procfs::handle_proc_open(notif, state, policy, notif_fd).await;
        }
        if policy.isolate_pids && (nr == libc::SYS_getdents64 as i64 || nr == libc::SYS_getdents as i64) {
            return crate::procfs::handle_getdents(notif, state, policy, notif_fd).await;
        }
    }

    // Virtual CPU count — fake sched_getaffinity result
    if let Some(n) = policy.num_cpus {
        if nr == libc::SYS_sched_getaffinity as i64 {
            return crate::procfs::handle_sched_getaffinity(notif, n, notif_fd);
        }
    }

    // Hostname virtualization — fake uname() nodename and /etc/hostname
    if let Some(ref hostname) = policy.hostname {
        if nr == libc::SYS_uname as i64 {
            return crate::procfs::handle_uname(notif, hostname, notif_fd);
        }
        if nr == libc::SYS_openat as i64 {
            if let Some(action) = crate::procfs::handle_hostname_open(notif, hostname, notif_fd) {
                return action;
            }
        }
    }

    // Deterministic directory listing — sort getdents entries
    // Placed after chroot/COW/procfs handlers so those take priority for their own dirs.
    if policy.deterministic_dirs && (nr == libc::SYS_getdents64 as i64 || nr == libc::SYS_getdents as i64) {
        return crate::procfs::handle_sorted_getdents(notif, state, notif_fd).await;
    }

    // Bind — on-behalf (for TOCTOU safety when port_remap or net allowlist active)
    if (policy.port_remap || policy.has_net_allowlist) && nr == libc::SYS_bind as i64 {
        return crate::port_remap::handle_bind(notif, state, notif_fd).await;
    }
    // getsockname — port remap only
    if policy.port_remap && nr == libc::SYS_getsockname as i64 {
        return crate::port_remap::handle_getsockname(notif, state, notif_fd).await;
    }

    NotifAction::Continue
}

// ============================================================
// vDSO re-patching after exec
// ============================================================

/// Re-patch the vDSO if the base address changed (e.g. after exec replaces it).
fn maybe_patch_vdso(pid: i32, state: &mut SupervisorState, policy: &NotifPolicy) {
    let base = match crate::vdso::find_vdso_base(pid) {
        Ok(addr) => addr,
        Err(_) => return,
    };
    if base == state.vdso_patched_addr {
        return; // already patched this vDSO
    }
    let time_offset = if policy.has_time_start { Some(policy.time_offset) } else { None };
    if crate::vdso::patch(pid, time_offset, policy.has_random_seed).is_ok() {
        state.vdso_patched_addr = base;
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
    state: &Arc<Mutex<SupervisorState>>,
    notif_fd: RawFd,
) -> Option<crate::policy_fn::Verdict> {
    let st = state.lock().await;
    let tx = match st.policy_event_tx.as_ref() {
        Some(tx) => tx.clone(),
        None => return None,
    };
    drop(st);

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
// Main supervisor loop
// ============================================================

/// Async event loop that processes seccomp notifications.
///
/// Runs until the notification fd is closed (child exits or filter is removed).
pub async fn supervisor(
    notif_fd: OwnedFd,
    policy: NotifPolicy,
    state: Arc<Mutex<SupervisorState>>,
) {
    let fd = notif_fd.as_raw_fd();

    // Try to enable sync wakeup (Linux 6.7+, ignore error on older kernels).
    try_set_sync_wakeup(fd);

    // Set the fd non-blocking for use with tokio's AsyncFd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }

    let async_fd = match AsyncFd::new(notif_fd) {
        Ok(afd) => afd,
        Err(_) => return,
    };

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(_) => break,
        };

        match recv_notif(fd) {
            Ok(notif) => {
                // Re-patch vDSO if needed (exec replaces it with a fresh copy).
                if policy.has_time_start || policy.has_random_seed {
                    let mut st = state.lock().await;
                    maybe_patch_vdso(notif.pid as i32, &mut st, &policy);
                }
                // Check dynamic path denials before dispatch
                let mut action = {
                    let st = state.lock().await;
                    let nr = notif.data.nr as i64;
                    if nr == libc::SYS_openat && st.is_path_denied_for_notif(&notif, fd) {
                        NotifAction::Errno(libc::EACCES)
                    } else {
                        drop(st);
                        dispatch(&notif, &policy, &state, fd).await
                    }
                };

                // Emit event to policy_fn callback if active
                if let Some(verdict) = emit_policy_event(&notif, &action, &state, fd).await {
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
            Err(ref e) if e.raw_os_error() == Some(libc::EAGAIN) || e.raw_os_error() == Some(libc::EWOULDBLOCK) => {
                guard.clear_ready();
                continue;
            }
            Err(_) => break, // Listener fd closed or fatal error.
        }

        guard.clear_ready();
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
        let _ = format!("{:?}", NotifAction::InjectFdSend { srcfd: 5 });
        let _ = format!("{:?}", NotifAction::ReturnValue(42));
        let _ = format!("{:?}", NotifAction::Hold);
        let _ = format!("{:?}", NotifAction::Kill { sig: 9, pgid: 1 });
    }

    #[test]
    fn test_supervisor_state_new() {
        let state = SupervisorState::new(1024 * 1024, 10, None, None);
        assert_eq!(state.mem_used, 0);
        assert_eq!(state.proc_count, 0);
        assert_eq!(state.max_memory_bytes, 1024 * 1024);
        assert_eq!(state.max_processes, 10);
        assert!(state.brk_bases.is_empty());
        assert!(state.proc_pids.is_empty());
        assert!(!state.hold_forks);
        assert!(state.held_notif_ids.is_empty());
        assert!(matches!(state.network_policy, NetworkPolicy::Unrestricted));
        assert!(state.time_offset.is_none());
        assert!(state.random_state.is_none());
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
