// Sandbox orchestrator — public API that coordinates fork, confinement,
// and async supervision of sandboxed child processes.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use std::sync::atomic::{AtomicBool, Ordering};

use crate::context::{self, CowConfig, PipePair, read_u32_fd, write_u32_fd};
use crate::cow::{CowBranch, overlayfs::OverlayBranch, branchfs::BranchFsBranch};
use crate::error::{SandboxError, SandlockError};
use crate::network;
use crate::policy::{BranchAction, FsIsolation, Policy};
use crate::result::{ExitStatus, RunResult};
use crate::seccomp::notif::{self, NotifPolicy, SupervisorState};
use crate::sys::syscall;

// ============================================================
// Nesting detection
// ============================================================

/// Set after seccomp confinement in the child process.
/// Any subsequent Sandbox in this process is nested.
pub(crate) static CONFINED: AtomicBool = AtomicBool::new(false);

/// Detect if this process is already inside a sandbox.
///
/// Checks both the in-process flag and /proc/self/status (Seccomp: 2)
/// to catch cross-process nesting (e.g. `sandlock run -- python agent.py`
/// where agent.py creates inner sandboxes).
pub fn is_nested() -> bool {
    if CONFINED.load(Ordering::Relaxed) {
        return true;
    }
    // Check /proc/self/status for active seccomp filter
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Seccomp:") {
                return line.trim().ends_with('2');
            }
        }
    }
    false
}

// ============================================================
// SandboxState
// ============================================================

enum SandboxState {
    Created,
    Running,
    Paused,
    Stopped(ExitStatus),
}

// ============================================================
// Sandbox
// ============================================================

/// The main user-facing sandbox API.
///
/// Orchestrates fork, confinement (Landlock + seccomp), and async
/// notification-based supervision of the sandboxed child process.
pub struct Sandbox {
    policy: Policy,
    state: SandboxState,
    child_pid: Option<i32>,
    pidfd: Option<OwnedFd>,
    notif_handle: Option<JoinHandle<()>>,
    throttle_handle: Option<JoinHandle<()>>,
    /// Capture pipe read ends — kept alive so the child doesn't get SIGPIPE.
    _stdout_read: Option<OwnedFd>,
    _stderr_read: Option<OwnedFd>,
    /// COW filesystem branch (OverlayFS or BranchFS).
    cow_branch: Option<Box<dyn CowBranch>>,
    /// Shared supervisor state for freeze/thaw support.
    supervisor_state: Option<Arc<Mutex<SupervisorState>>>,
    /// Optional fd overrides for stdin/stdout/stderr (used by Pipeline).
    io_overrides: Option<(Option<i32>, Option<i32>, Option<i32>)>,
}

impl Sandbox {
    /// Create a new sandbox in the `Created` state.
    pub fn new(policy: &Policy) -> Result<Self, SandlockError> {
        Ok(Self {
            policy: policy.clone(),
            state: SandboxState::Created,
            child_pid: None,
            pidfd: None,
            notif_handle: None,
            throttle_handle: None,
            _stdout_read: None,
            _stderr_read: None,
            cow_branch: None,
            supervisor_state: None,
            io_overrides: None,
        })
    }

    /// One-shot: spawn a sandboxed process, wait for it to exit, and return
    /// the result. Stdout and stderr are captured.
    pub async fn run(policy: &Policy, cmd: &[&str]) -> Result<RunResult, SandlockError> {
        let mut sb = Self::new(policy)?;
        sb.do_spawn(cmd, true).await?;
        sb.wait().await
    }

    /// Run a sandboxed process with inherited stdio (interactive mode).
    pub async fn run_interactive(policy: &Policy, cmd: &[&str]) -> Result<RunResult, SandlockError> {
        let mut sb = Self::new(policy)?;
        sb.do_spawn(cmd, false).await?;
        sb.wait().await
    }

    /// Wait for the child process to exit.
    pub async fn wait(&mut self) -> Result<RunResult, SandlockError> {
        let pid = self.child_pid.ok_or(SandboxError::NotRunning)?;

        if let SandboxState::Stopped(ref es) = self.state {
            return Ok(RunResult {
                exit_status: es.clone(),
                stdout: None,
                stderr: None,
            });
        }

        // Blocking waitpid in a blocking thread so we don't block the tokio runtime.
        let exit_status = tokio::task::spawn_blocking(move || -> ExitStatus {
            let mut status: i32 = 0;
            loop {
                let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    // Child already reaped or invalid pid
                    return ExitStatus::Killed;
                }
                break;
            }
            wait_status_to_exit(status)
        })
        .await
        .unwrap_or(ExitStatus::Killed);

        self.state = SandboxState::Stopped(exit_status.clone());

        // Abort supervisor tasks now that the child is gone.
        if let Some(h) = self.notif_handle.take() {
            h.abort();
        }
        if let Some(h) = self.throttle_handle.take() {
            h.abort();
        }

        // Drain captured stdout/stderr if available
        let stdout = self._stdout_read.take().map(|fd| read_fd_to_end(fd));
        let stderr = self._stderr_read.take().map(|fd| read_fd_to_end(fd));

        Ok(RunResult {
            exit_status,
            stdout,
            stderr,
        })
    }

    /// Send SIGSTOP to the child's process group.
    pub fn pause(&mut self) -> Result<(), SandlockError> {
        let pid = self.child_pid.ok_or(SandboxError::NotRunning)?;
        let ret = unsafe { libc::killpg(pid, libc::SIGSTOP) };
        if ret < 0 {
            return Err(SandboxError::Io(std::io::Error::last_os_error()).into());
        }
        self.state = SandboxState::Paused;
        Ok(())
    }

    /// Send SIGCONT to the child's process group.
    pub fn resume(&mut self) -> Result<(), SandlockError> {
        let pid = self.child_pid.ok_or(SandboxError::NotRunning)?;
        let ret = unsafe { libc::killpg(pid, libc::SIGCONT) };
        if ret < 0 {
            return Err(SandboxError::Io(std::io::Error::last_os_error()).into());
        }
        self.state = SandboxState::Running;
        Ok(())
    }

    /// Send SIGKILL to the child's process group.
    pub fn kill(&mut self) -> Result<(), SandlockError> {
        let pid = self.child_pid.ok_or(SandboxError::NotRunning)?;
        let ret = unsafe { libc::killpg(pid, libc::SIGKILL) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // ESRCH means the process is already gone — not an error.
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(SandboxError::Io(err).into());
            }
        }
        Ok(())
    }

    /// Return the child PID, if spawned.
    pub fn pid(&self) -> Option<i32> {
        self.child_pid
    }

    /// Return whether the child is currently running.
    pub fn is_running(&self) -> bool {
        matches!(self.state, SandboxState::Running | SandboxState::Paused)
    }

    /// Return a reference to the policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Commit COW writes to the original directory.
    pub async fn commit(&mut self) -> Result<(), SandlockError> {
        if let Some(branch) = self.cow_branch.take() {
            branch.commit().map_err(|e| SandlockError::Sandbox(SandboxError::Branch(e)))?;
        }
        Ok(())
    }

    /// Discard COW writes.
    pub async fn abort_branch(&mut self) -> Result<(), SandlockError> {
        if let Some(branch) = self.cow_branch.take() {
            branch.abort().map_err(|e| SandlockError::Sandbox(SandboxError::Branch(e)))?;
        }
        Ok(())
    }

    /// Freeze the sandbox: hold all fork notifications + SIGSTOP the process group.
    pub(crate) async fn freeze(&self) -> Result<(), SandlockError> {
        let pid = self.child_pid.ok_or(SandlockError::Sandbox(SandboxError::NotRunning))?;

        // Set hold_forks in supervisor state
        if let Some(ref state) = self.supervisor_state {
            let mut st = state.lock().await;
            st.hold_forks = true;
        }

        // SIGSTOP the process group
        unsafe { libc::killpg(pid, libc::SIGSTOP); }
        Ok(())
    }

    /// Thaw the sandbox: release held fork notifications + SIGCONT.
    pub(crate) async fn thaw(&self) -> Result<(), SandlockError> {
        let pid = self.child_pid.ok_or(SandlockError::Sandbox(SandboxError::NotRunning))?;

        // Release held forks
        if let Some(ref state) = self.supervisor_state {
            let mut st = state.lock().await;
            st.hold_forks = false;
            st.held_notif_ids.clear();
        }

        // SIGCONT the process group
        unsafe { libc::killpg(pid, libc::SIGCONT); }
        Ok(())
    }

    /// Spawn a sandboxed process without waiting for it to exit.
    /// Use `wait()` to collect the exit status when done.
    pub async fn spawn(&mut self, cmd: &[&str]) -> Result<(), SandlockError> {
        self.do_spawn(cmd, false).await
    }

    /// Spawn with explicit stdin/stdout/stderr fd redirection.
    ///
    /// Each `Option<RawFd>` overrides the corresponding fd in the child:
    /// - `stdin_fd`: dup2'd to fd 0
    /// - `stdout_fd`: dup2'd to fd 1
    /// - `stderr_fd`: dup2'd to fd 2
    ///
    /// The caller is responsible for closing the fds after this call.
    pub async fn spawn_with_io(
        &mut self,
        cmd: &[&str],
        stdin_fd: Option<std::os::unix::io::RawFd>,
        stdout_fd: Option<std::os::unix::io::RawFd>,
        stderr_fd: Option<std::os::unix::io::RawFd>,
    ) -> Result<(), SandlockError> {
        self.io_overrides = Some((stdin_fd, stdout_fd, stderr_fd));
        self.do_spawn(cmd, false).await
    }

    /// Capture a checkpoint of the running sandbox.
    pub async fn checkpoint(&self) -> Result<crate::checkpoint::Checkpoint, SandlockError> {
        let pid = self.child_pid.ok_or(SandlockError::Sandbox(SandboxError::NotRunning))?;

        // Freeze
        self.freeze().await?;

        // Capture state
        let cp = crate::checkpoint::capture(pid, &self.policy);

        // Thaw regardless of capture result
        self.thaw().await?;

        cp
    }

    // ============================================================
    // Internal: do_spawn
    // ============================================================

    /// Fork a child, apply confinement, and start the supervisor.
    async fn do_spawn(&mut self, cmd: &[&str], capture: bool) -> Result<(), SandlockError> {
        // 1. Validate state
        if !matches!(self.state, SandboxState::Created) {
            return Err(SandboxError::Child("sandbox already spawned".into()).into());
        }

        if cmd.is_empty() {
            return Err(SandboxError::Child("empty command".into()).into());
        }

        // 2. Convert cmd to Vec<CString>
        let c_cmd: Vec<CString> = cmd
            .iter()
            .map(|s| CString::new(*s).map_err(|_| SandboxError::Child("invalid command string".into())))
            .collect::<Result<Vec<_>, _>>()?;

        // 3. Detect nesting (before fork, in parent)
        let nested = is_nested();

        // 4. Create synchronization pipes
        let pipes = PipePair::new().map_err(SandboxError::Io)?;

        // 4. Resolve net_allow_hosts to IPs (async, before fork)
        let resolved_ips = if !self.policy.net_allow_hosts.is_empty() {
            network::resolve_hosts(&self.policy.net_allow_hosts)
                .await
                .map_err(SandboxError::Io)?
        } else {
            std::collections::HashSet::new()
        };

        // 5. Create COW branch if requested
        let cow_branch: Option<Box<dyn CowBranch>> = match self.policy.fs_isolation {
            FsIsolation::OverlayFs => {
                let workdir = self.policy.workdir.as_ref()
                    .ok_or_else(|| SandlockError::Sandbox(SandboxError::Child("OverlayFs requires workdir".into())))?;
                let storage = self.policy.fs_storage.as_ref()
                    .cloned()
                    .unwrap_or_else(|| std::env::temp_dir().join("sandlock-overlay"));
                std::fs::create_dir_all(&storage)
                    .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
                let branch = OverlayBranch::create(workdir, &storage)
                    .map_err(|e| SandlockError::Sandbox(SandboxError::Branch(e)))?;
                Some(Box::new(branch))
            }
            FsIsolation::BranchFs => {
                let workdir = self.policy.workdir.as_ref()
                    .ok_or_else(|| SandlockError::Sandbox(SandboxError::Child("BranchFs requires workdir".into())))?;
                let branch = BranchFsBranch::create(workdir)
                    .map_err(|e| SandlockError::Sandbox(SandboxError::Branch(e)))?;
                Some(Box::new(branch))
            }
            FsIsolation::None => None,
        };

        // Build CowConfig for child if OverlayFS
        let cow_config = if let Some(ref branch) = cow_branch {
            if self.policy.fs_isolation == FsIsolation::OverlayFs {
                // Downcast to get overlay-specific paths
                // The branch_path is the merged dir; we need upper/work/lowers too.
                // We stored this info in the OverlayBranch; extract via CowConfig.
                // Since we can't downcast easily, we'll build CowConfig from policy info.
                let workdir = self.policy.workdir.as_ref().unwrap();
                let merged = branch.branch_path().to_path_buf();
                // Derive upper/work from merged's parent (storage/uuid/)
                let branch_dir = merged.parent().unwrap();
                let upper = branch_dir.join("upper");
                let work = branch_dir.join("work");
                Some(CowConfig {
                    merged,
                    upper,
                    work,
                    lowers: vec![workdir.clone()],
                })
            } else {
                None
            }
        } else {
            None
        };

        // 6. Create stdout/stderr capture pipes (if capture mode)
        let (stdout_r, stderr_r) = if capture {
            let mut stdout_fds = [0i32; 2];
            let mut stderr_fds = [0i32; 2];
            if unsafe { libc::pipe2(stdout_fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
                return Err(SandboxError::Io(std::io::Error::last_os_error()).into());
            }
            if unsafe { libc::pipe2(stderr_fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
                unsafe {
                    libc::close(stdout_fds[0]);
                    libc::close(stdout_fds[1]);
                }
                return Err(SandboxError::Io(std::io::Error::last_os_error()).into());
            }
            (
                Some((
                    unsafe { OwnedFd::from_raw_fd(stdout_fds[0]) },
                    unsafe { OwnedFd::from_raw_fd(stdout_fds[1]) },
                )),
                Some((
                    unsafe { OwnedFd::from_raw_fd(stderr_fds[0]) },
                    unsafe { OwnedFd::from_raw_fd(stderr_fds[1]) },
                )),
            )
        } else {
            (None, None)
        };

        // 6. Fork
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(SandboxError::Fork(std::io::Error::last_os_error()).into());
        }

        if pid == 0 {
            // ===== CHILD PROCESS =====
            // Drop parent's pipe ends by leaking them (they are OwnedFd and would
            // close the fd on drop, but we only want to close OUR ends).
            // The child does not use notif_r or ready_w.
            // We must forget them so that Drop doesn't close the raw fds that
            // confine_child may still use.
            //
            // We use std::mem::forget on the read end of notif and write end of ready
            // because confine_child uses notif_w and ready_r (via the PipePair reference).
            // The parent's ends (notif_r, ready_w) need to be closed in the child.
            // However, since PipePair owns all four fds and confine_child takes
            // a reference to it, we pass the whole PipePair and let confine_child
            // handle it. confine_child never returns.

            // Apply io_overrides (from spawn_with_io / pipeline)
            if let Some((stdin_fd, stdout_fd, stderr_fd)) = self.io_overrides {
                if let Some(fd) = stdin_fd {
                    unsafe { libc::dup2(fd, 0) };
                }
                if let Some(fd) = stdout_fd {
                    unsafe { libc::dup2(fd, 1) };
                }
                if let Some(fd) = stderr_fd {
                    unsafe { libc::dup2(fd, 2) };
                }
            }

            // Redirect stdout/stderr if capturing
            if let Some((_, ref stdout_w)) = stdout_r {
                unsafe { libc::dup2(stdout_w.as_raw_fd(), 1) };
            }
            if let Some((_, ref stderr_w)) = stderr_r {
                unsafe { libc::dup2(stderr_w.as_raw_fd(), 2) };
            }
            // Drop capture pipe read ends in child (they belong to parent).
            // The write ends will be closed by O_CLOEXEC on exec.
            drop(stdout_r);
            drop(stderr_r);

            // This never returns.
            context::confine_child(&self.policy, &c_cmd, &pipes, cow_config.as_ref(), nested);
        }

        // ===== PARENT PROCESS =====

        // Store COW branch in parent
        self.cow_branch = cow_branch;

        // 7. Close child's pipe ends
        drop(pipes.notif_w);
        drop(pipes.ready_r);

        // Drop capture pipe write ends in parent (they belong to child).
        // Store the read ends so the child doesn't get SIGPIPE.
        self._stdout_read = stdout_r.map(|(r, _w)| r);
        self._stderr_read = stderr_r.map(|(r, _w)| r);

        // 8. Set child_pid, state=Running
        self.child_pid = Some(pid);
        self.state = SandboxState::Running;

        // 9. Open pidfd via syscall::pidfd_open
        let pidfd = match syscall::pidfd_open(pid as u32, 0) {
            Ok(fd) => Some(fd),
            Err(_) => None, // pidfd not available on older kernels — proceed without
        };

        // 10. Read notif fd number from pipe (what child wrote)
        //     0 = nested mode (no supervisor needed)
        let notif_fd_num = read_u32_fd(pipes.notif_r.as_raw_fd())
            .map_err(|e| SandboxError::Child(format!("read notif fd from child: {}", e)))?;

        let is_nested = notif_fd_num == 0;

        // 11. Copy notif fd from child (skip if nested)
        let notif_fd = if is_nested {
            None
        } else if let Some(ref pfd) = pidfd {
            Some(syscall::pidfd_getfd(pfd, notif_fd_num as i32, 0)
                .map_err(|e| SandboxError::Child(format!("pidfd_getfd: {}", e)))?)
        } else {
            let path = format!("/proc/{}/fd/{}", pid, notif_fd_num);
            let cpath = CString::new(path).unwrap();
            let raw = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
            if raw < 0 {
                return Err(
                    SandboxError::Child("failed to open notif fd from /proc".into()).into(),
                );
            }
            Some(unsafe { OwnedFd::from_raw_fd(raw) })
        };

        // 11b–14. Supervisor setup (skip in nested mode)
        if let Some(notif_fd) = notif_fd {
            // vDSO patching for determinism
            if self.policy.time_start.is_some() || self.policy.random_seed.is_some() {
                let time_offset = self.policy.time_start.map(|t| crate::time::calculate_time_offset(t));
                if let Err(e) = crate::vdso::patch(pid, time_offset, self.policy.random_seed.is_some()) {
                    eprintln!("sandlock: pre-exec vDSO patching failed (will retry after exec): {}", e);
                }
            }

            // Build NotifPolicy
            let time_offset_val = self.policy.time_start
                .map(|t| crate::time::calculate_time_offset(t))
                .unwrap_or(0);

            let notif_policy = NotifPolicy {
                max_memory_bytes: self.policy.max_memory.map(|m| m.0).unwrap_or(0),
                max_processes: self.policy.max_processes,
                has_memory_limit: self.policy.max_memory.is_some(),
                has_net_allowlist: !self.policy.net_allow_hosts.is_empty(),
                has_random_seed: self.policy.random_seed.is_some(),
                has_time_start: self.policy.time_start.is_some(),
                time_offset: time_offset_val,
                num_cpus: self.policy.num_cpus,
                has_proc_virt: self.policy.num_cpus.is_some() || self.policy.max_memory.is_some() || self.policy.isolate_pids || self.policy.port_remap,
                isolate_pids: self.policy.isolate_pids,
                port_remap: self.policy.port_remap,
                cow_enabled: self.policy.workdir.is_some() && self.policy.fs_isolation == FsIsolation::None,
            };

            // Create SupervisorState
            use rand::SeedableRng;
            use rand_chacha::ChaCha8Rng;

            let random_state = self.policy.random_seed.map(|seed| ChaCha8Rng::seed_from_u64(seed));
            let time_offset = self.policy.time_start.map(|t| crate::time::calculate_time_offset(t));

            let mut sup_state = SupervisorState::new(
                notif_policy.max_memory_bytes,
                notif_policy.max_processes,
                time_offset,
                random_state,
            );
            sup_state.allowed_ips = resolved_ips;

            if let Some(ref pfd) = pidfd {
                use std::os::unix::io::AsRawFd;
                sup_state.child_pidfd = Some(pfd.as_raw_fd());
            }

            // Seccomp COW branch
            if self.policy.workdir.is_some() && self.policy.fs_isolation == FsIsolation::None {
                let workdir = self.policy.workdir.as_ref().unwrap();
                let storage = self.policy.fs_storage.as_deref();
                match crate::cow::seccomp::SeccompCowBranch::create(workdir, storage) {
                    Ok(branch) => { sup_state.cow_branch = Some(branch); }
                    Err(e) => { eprintln!("sandlock: seccomp COW branch creation failed: {}", e); }
                }
            }

            // Policy callback thread
            if let Some(ref callback) = self.policy.policy_fn {
                let live = crate::policy_fn::LivePolicy {
                    allowed_ips: sup_state.allowed_ips.clone(),
                    max_memory_bytes: notif_policy.max_memory_bytes,
                    max_processes: notif_policy.max_processes,
                };
                let ceiling = live.clone();
                let live = std::sync::Arc::new(std::sync::RwLock::new(live));
                let denied_paths = sup_state.denied_paths.clone();
                let pid_overrides = sup_state.pid_ip_overrides.clone();
                // Store live_policy reference so supervisor reads dynamic updates
                sup_state.live_policy = Some(live.clone());
                let tx = crate::policy_fn::spawn_policy_fn(
                    callback.clone(), live, ceiling, pid_overrides, denied_paths,
                );
                sup_state.policy_event_tx = Some(tx);
            }

            let sup_state = Arc::new(Mutex::new(sup_state));
            self.supervisor_state = Some(Arc::clone(&sup_state));

            // Spawn notif supervisor
            self.notif_handle = Some(tokio::spawn(
                notif::supervisor(notif_fd, notif_policy, sup_state),
            ));
        }

        // 15. Optionally spawn CPU throttle task
        if let Some(cpu_pct) = self.policy.max_cpu {
            if cpu_pct < 100 {
                let child_pid = pid;
                self.throttle_handle = Some(tokio::spawn(throttle_cpu(child_pid, cpu_pct)));
            }
        }

        // 16. Signal child "ready" via pipe
        write_u32_fd(pipes.ready_w.as_raw_fd(), 1)
            .map_err(|e| SandboxError::Child(format!("write ready signal: {}", e)))?;

        // 17. Store pidfd
        self.pidfd = pidfd;

        Ok(())
    }
}

// ============================================================
// Drop — kill and reap child if still running
// ============================================================

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Some(pid) = self.child_pid {
            if matches!(self.state, SandboxState::Running | SandboxState::Paused) {
                // Kill the entire process group
                unsafe { libc::killpg(pid, libc::SIGKILL) };
                // Reap the zombie
                let mut status: i32 = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
            }
        }

        if let Some(h) = self.notif_handle.take() {
            h.abort();
        }
        if let Some(h) = self.throttle_handle.take() {
            h.abort();
        }

        // COW cleanup based on exit status
        if let Some(ref branch) = self.cow_branch {
            let is_error = matches!(
                self.state,
                SandboxState::Stopped(ref s) if !matches!(s, ExitStatus::Code(0))
            );
            let action = if is_error {
                &self.policy.on_error
            } else {
                &self.policy.on_exit
            };
            match action {
                BranchAction::Commit => { let _ = branch.commit(); }
                BranchAction::Abort => { let _ = branch.abort(); }
                BranchAction::Keep => {} // leave COW layer in place
            }
        }

        // Seccomp-based COW cleanup
        if let Some(ref state) = self.supervisor_state {
            let Ok(mut st) = state.try_lock() else { return; };
            if let Some(ref mut cow) = st.cow_branch {
                let is_error = matches!(
                    self.state,
                    SandboxState::Stopped(ref s) if !matches!(s, ExitStatus::Code(0))
                );
                let action = if is_error {
                    &self.policy.on_error
                } else {
                    &self.policy.on_exit
                };
                match action {
                    BranchAction::Commit => { let _ = cow.commit(); }
                    BranchAction::Abort => { let _ = cow.abort(); }
                    BranchAction::Keep => {}
                }
            }
        }
    }
}

// ============================================================
// CPU throttle
// ============================================================

/// Periodically SIGSTOP/SIGCONT the child process group to throttle CPU usage.
async fn throttle_cpu(pid: i32, cpu_pct: u8) {
    let period = Duration::from_millis(100);
    let run_time = period * cpu_pct as u32 / 100;
    let stop_time = period - run_time;

    loop {
        tokio::time::sleep(run_time).await;
        if unsafe { libc::killpg(pid, libc::SIGSTOP) } < 0 {
            break;
        }
        tokio::time::sleep(stop_time).await;
        if unsafe { libc::killpg(pid, libc::SIGCONT) } < 0 {
            break;
        }
    }
}

// ============================================================
// Helpers
// ============================================================

/// Convert a raw waitpid status to our ExitStatus enum.
/// Read all bytes from a file descriptor until EOF.
fn read_fd_to_end(fd: OwnedFd) -> Vec<u8> {
    use std::io::Read;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) };
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf);
    buf
}

fn wait_status_to_exit(status: i32) -> ExitStatus {
    if libc::WIFEXITED(status) {
        ExitStatus::Code(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        if sig == libc::SIGKILL {
            ExitStatus::Killed
        } else {
            ExitStatus::Signal(sig)
        }
    } else {
        ExitStatus::Killed
    }
}
