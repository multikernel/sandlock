// Fork + confinement sequence: child-side Landlock + seccomp application
// and parent-child pipe synchronization.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::resolved::ResolvedSandbox;
use crate::sandbox::Sandbox;
use crate::seccomp::bpf;

#[cfg(test)]
use crate::arch;
#[cfg(test)]
use crate::sys::structs::{
    AF_INET, AF_INET6, CLONE_NS_FLAGS, DEFAULT_BLOCKLIST_SYSCALLS, PR_SET_DUMPABLE,
    SIOCGIFCONF, SIOCETHTOOL, SOCK_DGRAM, SOCK_RAW, SOCK_TYPE_MASK, TIOCLINUX, TIOCSTI,
};

// ============================================================
// Pipe pair for parent-child synchronization
// ============================================================

/// Pipes for parent-child communication after fork().
pub struct PipePair {
    /// Parent reads the notif fd number written by the child.
    pub notif_r: OwnedFd,
    /// Child writes the notif fd number to the parent.
    pub notif_w: OwnedFd,
    /// Child reads the "supervisor ready" signal from the parent.
    pub ready_r: OwnedFd,
    /// Parent writes the "supervisor ready" signal to the child.
    pub ready_w: OwnedFd,
}

impl PipePair {
    /// Create two pipe pairs using `pipe2(O_CLOEXEC)`.
    pub fn new() -> io::Result<Self> {
        let mut notif_fds = [0i32; 2];
        let mut ready_fds = [0i32; 2];

        // SAFETY: pipe2 with valid pointers and O_CLOEXEC
        let ret = unsafe { libc::pipe2(notif_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let ret = unsafe { libc::pipe2(ready_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret < 0 {
            // Close the first pair on failure
            unsafe {
                libc::close(notif_fds[0]);
                libc::close(notif_fds[1]);
            }
            return Err(io::Error::last_os_error());
        }

        // SAFETY: pipe2 returned valid fds
        Ok(PipePair {
            notif_r: unsafe { OwnedFd::from_raw_fd(notif_fds[0]) },
            notif_w: unsafe { OwnedFd::from_raw_fd(notif_fds[1]) },
            ready_r: unsafe { OwnedFd::from_raw_fd(ready_fds[0]) },
            ready_w: unsafe { OwnedFd::from_raw_fd(ready_fds[1]) },
        })
    }
}

// ============================================================
// Pipe I/O helpers
// ============================================================

/// Write a `u32` as 4 little-endian bytes to a raw fd.
pub(crate) fn write_u32_fd(fd: RawFd, val: u32) -> io::Result<()> {
    let buf = val.to_le_bytes();
    let mut written = 0usize;
    while written < 4 {
        let ret = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr() as *const libc::c_void,
                4 - written,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        written += ret as usize;
    }
    Ok(())
}

/// Read a `u32` (4 little-endian bytes, blocking) from a raw fd.
pub(crate) fn read_u32_fd(fd: RawFd) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    let mut total = 0usize;
    while total < 4 {
        let ret = unsafe {
            libc::read(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                4 - total,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "pipe closed before 4 bytes read",
            ));
        }
        total += ret as usize;
    }
    Ok(u32::from_le_bytes(buf))
}

#[cfg(test)]
use crate::seccomp::syscall::syscall_name_to_nr;

// ============================================================
// Sandbox -> seccomp plan
// ============================================================

pub(crate) use crate::seccomp_plan::{arg_filters_resolved, notif_syscalls_resolved};

pub fn notif_syscalls(policy: &Sandbox, sandbox_name: Option<&str>) -> Vec<u32> {
    crate::seccomp_plan::notif_syscalls(policy, sandbox_name)
}

pub fn no_supervisor_blocklist_syscall_numbers(policy: &Sandbox) -> Vec<u32> {
    crate::seccomp_plan::no_supervisor_blocklist_syscall_numbers(policy)
}

pub fn blocklist_syscall_numbers(policy: &Sandbox) -> Vec<u32> {
    crate::seccomp_plan::blocklist_syscall_numbers(policy)
}

pub fn arg_filters(policy: &Sandbox) -> Vec<crate::sys::structs::SockFilter> {
    crate::seccomp_plan::arg_filters(policy)
}

// ============================================================
// Close fds above threshold
// ============================================================

/// Close all file descriptors above `min_fd`, except those in `keep`.
fn close_fds_above(min_fd: RawFd, keep: &[RawFd]) {
    // Read /proc/self/fd to enumerate open fds.
    // Collect all fd numbers first, then close them after dropping the directory
    // iterator. This avoids closing the directory fd during iteration.
    let fds_to_close: Vec<RawFd> = {
        let dir = match std::fs::read_dir("/proc/self/fd") {
            Ok(d) => d,
            Err(_) => return,
        };
        dir.flatten()
            .filter_map(|entry| {
                entry.file_name().into_string().ok()
                    .and_then(|name| name.parse::<RawFd>().ok())
            })
            .filter(|&fd| fd > min_fd && !keep.contains(&fd))
            .collect()
    };
    // The directory is now closed; safe to close the collected fds.
    for fd in fds_to_close {
        unsafe { libc::close(fd) };
    }
}

// ============================================================
// User-namespace uid/gid mapping helpers
// ============================================================

/// Write uid/gid maps for an unprivileged user namespace.
/// `real_uid`/`real_gid` must be captured *before* unshare(CLONE_NEWUSER),
/// since getuid()/getgid() return the overflow id (65534) after unshare.
/// `target_uid`/`target_gid` are the UIDs visible inside the namespace.
fn write_id_maps(real_uid: u32, real_gid: u32, target_uid: u32, target_gid: u32) {
    let _ = std::fs::write("/proc/self/uid_map", format!("{} {} 1\n", target_uid, real_uid));
    let _ = std::fs::write("/proc/self/setgroups", "deny\n");
    let _ = std::fs::write("/proc/self/gid_map", format!("{} {} 1\n", target_gid, real_gid));
}

// ============================================================
// Child-side confinement (never returns)
// ============================================================

/// Arguments threaded from the parent's `do_spawn` into the child-side
/// `confine_child`.  Packed into a struct because `confine_child` historically
/// grew to seven positional parameters and a struct keeps the call site
/// readable when new flags get added (e.g. `extra_syscalls` for user
/// handlers).  Lifetimes tie everything to the parent's stack frame — the
/// child never outlives the fork point because `confine_child` either execs
/// or exits.
/// The terminal action `confine_child` performs after confinement is installed.
/// Exactly one of the two: there is no longer a "command plus optional override".
pub(crate) enum ChildEntry<'a> {
    /// `execve` this command (the normal path). argv[0] becomes the process name.
    Exec(&'a [CString]),
    /// Run this function in-process, with the process named `name`. Used for the
    /// OCI in-sandbox PID-1: the child is a fork of the supervisor so the code is
    /// already mapped, nothing is exec'd, and Landlock has no execve to
    /// authorize. `run` must not return; `confine_child` `_exit(0)`s if it does.
    InProcess { name: &'a CStr, run: fn() },
}

pub(crate) struct ChildSpawnArgs<'a> {
    pub sandbox: &'a Sandbox,
    /// Terminal action after confinement: `execve` a command or run a fn
    /// in-process. See [`ChildEntry`].
    pub entry: ChildEntry<'a>,
    pub pipes: &'a PipePair,
    /// Skip the user-notification supervisor: child installs a kernel-only
    /// deny filter, parent reads `notif_fd_num = 0` and never starts a
    /// supervisor. Mirrors `Sandbox::no_supervisor`.
    pub no_supervisor: bool,
    pub keep_fds: &'a [RawFd],
    /// Sandbox instance name. When set, it is also exposed as the
    /// sandbox's virtual hostname.
    pub sandbox_name: Option<&'a str>,
    /// Syscall numbers for which the parent registered user `Handler`s.
    /// Merged into the child's BPF notif list so the kernel actually
    /// raises USER_NOTIF for them.
    pub extra_syscalls: &'a [u32],
    /// PID of the parent process captured before fork. Used to detect
    /// parent death in the child without assuming PID 1 is always init
    /// (incorrect in containers where the entrypoint runs as PID 1).
    pub parent_pid: libc::pid_t,
}

/// Set the calling thread/process name (`/proc/<pid>/comm`, shown by `ps`). The
/// kernel truncates to 15 bytes + NUL. Used for the in-process PID-1, which has
/// no `execve` to set its name from argv[0].
fn set_proc_name(name: &CStr) {
    unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0) };
}

/// Apply irreversible confinement (Landlock + seccomp), then either `execve` the
/// command or run an in-process entrypoint, per [`ChildEntry`].
///
/// This function **never returns**: on success it execs or runs the entrypoint
/// (which `_exit`s); on any error it `_exit(127)`s.
pub(crate) fn confine_child(args: ChildSpawnArgs<'_>) -> ! {
    let ChildSpawnArgs {
        sandbox,
        entry,
        pipes,
        no_supervisor,
        keep_fds,
        sandbox_name,
        extra_syscalls,
        parent_pid,
    } = args;
    // Helper: abort child on error. Includes the OS error automatically.
    macro_rules! fail {
        ($msg:expr) => {{
            let err = std::io::Error::last_os_error();
            let _ = write!(std::io::stderr(), "sandlock child: {}: {}\n", $msg, err);
            unsafe { libc::_exit(127) };
        }};
    }

    use std::io::Write;

    // 1. New process group
    if unsafe { libc::setpgid(0, 0) } != 0 {
        fail!("setpgid");
    }

    // 1b. If stdin is a terminal, become the foreground process group
    //     so interactive shells can read from the TTY.
    //     Must ignore SIGTTOU first — a background pgrp calling tcsetpgrp
    //     gets stopped by SIGTTOU otherwise.
    if unsafe { libc::isatty(0) } == 1 {
        unsafe {
            libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            libc::tcsetpgrp(0, libc::getpgrp());
            libc::signal(libc::SIGTTOU, libc::SIG_DFL);
        }
    }

    // 2. Die if parent exits
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        fail!("prctl(PR_SET_PDEATHSIG)");
    }

    // 3. Check parent didn't die between fork and prctl.
    // Compare against the actual parent PID captured before fork rather than
    // hardcoding 1, since containers often run the entrypoint as PID 1 and a
    // child forked from it legitimately has getppid() == 1.
    if unsafe { libc::getppid() } != parent_pid {
        fail!("parent died before confinement");
    }

    // 4. Optional: disable ASLR
    if sandbox.no_randomize_memory {
        const ADDR_NO_RANDOMIZE: libc::c_ulong = 0x0040000;
        // Read current personality first (0xffffffff = query), then OR in the flag.
        let current = unsafe { libc::personality(0xffffffff) };
        if current == -1 {
            fail!("personality(query)");
        }
        if unsafe { libc::personality(current as libc::c_ulong | ADDR_NO_RANDOMIZE) } == -1 {
            fail!("personality(ADDR_NO_RANDOMIZE)");
        }
    }

    // 4b. Optional: CPU core binding
    if let Some(ref cores) = sandbox.cpu_cores {
        if !cores.is_empty() {
            let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
            unsafe { libc::CPU_ZERO(&mut set) };
            for &core in cores {
                unsafe { libc::CPU_SET(core as usize, &mut set) };
            }
            if unsafe {
                libc::sched_setaffinity(
                    0,
                    std::mem::size_of::<libc::cpu_set_t>(),
                    &set,
                )
            } != 0
            {
                fail!("sched_setaffinity");
            }
        }
    }

    // 5. Optional: disable THP
    if sandbox.no_huge_pages {
        if unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0) } != 0 {
            fail!("prctl(PR_SET_THP_DISABLE)");
        }
    }

    // 5c. Optional: disable core dumps
    if sandbox.no_coredump {
        // Set RLIMIT_CORE to 0 — the kernel will not write a core file.
        // We intentionally do NOT call prctl(PR_SET_DUMPABLE, 0) because
        // that would break pidfd_getfd which the supervisor needs.
        // The seccomp filter already blocks the child from calling
        // prctl(PR_SET_DUMPABLE, ...) so it can't re-enable it.
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) } != 0 {
            fail!("setrlimit(RLIMIT_CORE, 0)");
        }
    }

    // Capture real uid/gid before any unshare (after unshare they become 65534)
    let real_uid = unsafe { libc::getuid() };
    let real_gid = unsafe { libc::getgid() };

    // 5b. User namespace for --user (run-as uid/gid) mapping.
    //
    // Skip entirely when the requested identity already matches the current
    // uid/gid: there's no point unsharing a user namespace to map an identity
    // the process already has, and skipping avoids imposing an
    // unprivileged-userns requirement on callers that don't need a remap.
    if let Some(run_as) = sandbox.user {
        if run_as.uid != real_uid || run_as.gid != real_gid {
            if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
                fail!("unshare(CLONE_NEWUSER)");
            }
            write_id_maps(real_uid, real_gid, run_as.uid, run_as.gid);
        }
    }

    // 6. Optional: change working directory
    // cwd controls where the child starts; workdir is only for COW
    let effective_cwd = if let Some(ref cwd) = sandbox.cwd {
        if let Some(ref chroot_root) = sandbox.chroot {
            Some(chroot_root.join(cwd.strip_prefix("/").unwrap_or(cwd)))
        } else {
            Some(cwd.clone())
        }
    } else if let Some(ref chroot_root) = sandbox.chroot {
        // Default to chroot root
        Some(chroot_root.to_path_buf())
    } else if let Some(ref workdir) = sandbox.workdir {
        // Default to workdir when set (COW working directory)
        Some(workdir.clone())
    } else {
        None
    };

    if let Some(ref cwd) = effective_cwd {
        let c_path = match CString::new(cwd.as_os_str().as_encoded_bytes()) {
            Ok(c) => c,
            Err(_) => fail!("invalid cwd path"),
        };
        if unsafe { libc::chdir(c_path.as_ptr()) } != 0 {
            fail!("chdir");
        }
    }

    // 7. Set NO_NEW_PRIVS (required for both Landlock and seccomp without CAP_SYS_ADMIN)
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        fail!("prctl(PR_SET_NO_NEW_PRIVS)");
    }

    // 8. Apply Landlock confinement (IRREVERSIBLE)
    if let Err(e) = crate::landlock::confine(sandbox) {
        fail!(format!("landlock: {}", e));
    }

    // 9. Assemble and install seccomp filter (IRREVERSIBLE)
    let handler_syscalls: Vec<i64> = extra_syscalls.iter().map(|&nr| nr as i64).collect();
    let resolved = ResolvedSandbox::from_sandbox(sandbox, sandbox_name, &handler_syscalls);
    let args = arg_filters_resolved(&resolved);
    let mut keep_fd: i32 = -1;

    if no_supervisor {
        // No-supervisor mode: deny-only kernel filter, no NEW_LISTENER.
        // BPF filters are ANDed by the kernel, so an outer filter (from a
        // wrapping sandbox) keeps tightening this layer too.
        //
        // Uses the relaxed `no_supervisor_blocklist_syscall_numbers` deny
        // list (which leaves `ptrace`, `unshare`, `process_vm_*`, etc.
        // alone) so an inner full-supervisor sandlock nested under this
        // one still has the syscalls its supervisor needs.
        let deny = no_supervisor_blocklist_syscall_numbers(sandbox);
        let filter = match bpf::assemble_filter(&[], &deny, &args) {
            Ok(f) => f,
            Err(e) => fail!(format!("seccomp assemble: {}", e)),
        };
        if let Err(e) = bpf::install_deny_filter(&filter) {
            fail!(format!("seccomp deny filter: {}", e));
        }
        // fd=0 tells the parent there's no supervisor to attach to.
        if let Err(e) = write_u32_fd(pipes.notif_w.as_raw_fd(), 0) {
            fail!(format!("write no-supervisor signal: {}", e));
        }
    } else {
        let deny = blocklist_syscall_numbers(sandbox);
        // First-level sandbox: notif + deny filter with NEW_LISTENER.
        //
        // Caller-supplied handlers must have their syscalls registered in
        // the BPF filter, otherwise the kernel never raises a notification for
        // them and the handler silently never fires.  We merge `extra_syscalls`
        // into the notif list and dedup so each syscall produces exactly one
        // JEQ in the assembled program.
        let mut notif = notif_syscalls_resolved(&resolved);
        if !extra_syscalls.is_empty() {
            notif.extend_from_slice(extra_syscalls);
        }
        notif.sort_unstable();
        notif.dedup();
        let filter = match bpf::assemble_filter(&notif, &deny, &args) {
            Ok(f) => f,
            Err(e) => fail!(format!("seccomp assemble: {}", e)),
        };
        let notif_fd = match bpf::install_filter(&filter) {
            Ok(fd) => fd,
            Err(e) => {
                // EBUSY here means another seccomp filter on this task already
                // owns the SECCOMP_FILTER_FLAG_NEW_LISTENER slot. The kernel
                // permits at most one listener per task — to nest, opt this
                // sandbox out of the supervisor via `Sandbox::no_supervisor`
                // (or the CLI's `--no-supervisor` flag).
                if e.raw_os_error() == Some(libc::EBUSY) {
                    let _ = write!(
                        std::io::stderr(),
                        "sandlock child: seccomp install: {} (an outer sandbox already owns the \
                         seccomp listener; pass --no-supervisor or Sandbox::no_supervisor(true) \
                         on this sandbox to nest)\n",
                        e,
                    );
                    unsafe { libc::_exit(127) };
                }
                fail!(format!("seccomp install: {}", e));
            }
        };
        keep_fd = notif_fd.as_raw_fd();
        if let Err(e) = write_u32_fd(pipes.notif_w.as_raw_fd(), keep_fd as u32) {
            fail!(format!("write notif fd: {}", e));
        }
        std::mem::forget(notif_fd);
    }

    // 10. Wait for parent to signal ready
    match read_u32_fd(pipes.ready_r.as_raw_fd()) {
        Ok(_) => {}
        Err(e) => fail!(format!("read ready signal: {}", e)),
    }

    // 12. Close all fds above stderr (always on for isolation)
    let mut fds_to_keep: Vec<RawFd> = keep_fds.to_vec();
    if keep_fd >= 0 {
        fds_to_keep.push(keep_fd);
    }
    close_fds_above(2, &fds_to_keep);

    // 13. Apply environment
    if sandbox.clean_env {
        // Clear all env vars first
        for (key, _) in std::env::vars_os() {
            std::env::remove_var(&key);
        }
    }
    for (key, value) in &sandbox.env {
        std::env::set_var(key, value);
    }

    // 13b. GPU device visibility
    if let Some(ref devices) = sandbox.gpu_devices {
        if !devices.is_empty() {
            let vis = devices.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(",");
            std::env::set_var("CUDA_VISIBLE_DEVICES", &vis);
            std::env::set_var("ROCR_VISIBLE_DEVICES", &vis);
        }
        // Empty list = all GPUs visible, don't set env vars
    }

    // 14. Terminal action: run the in-process entrypoint, or fall through to
    // execve the command. The in-process arm diverges (`_exit`), so the match
    // yields the command slice only on the `Exec` path.
    let cmd: &[CString] = match entry {
        ChildEntry::InProcess { name, run } => {
            // Name the PID-1 so ps / /proc/<pid>/comm read correctly: there is
            // no execve here to set argv[0]. The child is a fork of the
            // supervisor, so `run`'s code is already mapped; running it directly
            // avoids an execve that Landlock would otherwise have to authorize.
            set_proc_name(name);
            run();
            unsafe { libc::_exit(0) };
        }
        ChildEntry::Exec(cmd) => cmd,
    };

    // 14. exec
    debug_assert!(!cmd.is_empty(), "cmd must not be empty");
    let argv_ptrs: Vec<*const libc::c_char> = cmd
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    if sandbox.chroot.is_some() {
        // With chroot the seccomp handler rewrites the filename to a host path
        // (or /proc/self/fd/N).  Pass a separate PATH_MAX buffer as the `file`
        // argument so the rewrite does not corrupt argv[0] — which must stay as
        // the original command name (e.g. busybox uses argv[0] for applet
        // detection).  execvp still handles PATH lookup for bare command names.
        let mut exec_path = vec![0u8; libc::PATH_MAX as usize];
        let orig = cmd[0].as_bytes_with_nul();
        exec_path[..orig.len()].copy_from_slice(orig);

        unsafe {
            libc::execvp(
                exec_path.as_ptr() as *const libc::c_char,
                argv_ptrs.as_ptr(),
            )
        };
    } else {
        unsafe { libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr()) };
    }

    // If we get here, exec failed
    fail!(format!("execvp '{}'", cmd[0].to_string_lossy()));
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;
