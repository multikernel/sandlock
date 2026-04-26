// Sandbox orchestrator — public API that coordinates fork, confinement,
// and async supervision of sandboxed child processes.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use std::sync::atomic::{AtomicBool, Ordering};

use crate::context::{self, PipePair, read_u32_fd, write_u32_fd};
use crate::cow::{CowBranch, overlayfs::OverlayBranch, branchfs::BranchFsBranch};
use crate::error::{SandboxError, SandlockError};
use crate::network;
use crate::policy::{BranchAction, FsIsolation, Policy};
use crate::result::{ExitStatus, RunResult};
use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{self, NotifPolicy};
use crate::seccomp::state::{ChrootState, CowState, NetworkState, PolicyFnState, ProcfsState, ResourceState, TimeRandomState};
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
    loadavg_handle: Option<JoinHandle<()>>,
    /// Capture pipe read ends — kept alive so the child doesn't get SIGPIPE.
    _stdout_read: Option<OwnedFd>,
    _stderr_read: Option<OwnedFd>,
    /// COW filesystem branch (OverlayFS or BranchFS).
    cow_branch: Option<Box<dyn CowBranch>>,
    /// Seccomp COW branch extracted from supervisor state after child exits.
    seccomp_cow: Option<crate::cow::seccomp::SeccompCowBranch>,
    /// Shared resource state for freeze/thaw and loadavg support.
    supervisor_resource: Option<Arc<Mutex<ResourceState>>>,
    /// Shared COW state for post-wait extraction.
    supervisor_cow: Option<Arc<Mutex<CowState>>>,
    /// Shared network state for port mapping queries.
    supervisor_network: Option<Arc<Mutex<NetworkState>>>,
    /// Control pipe for fork commands (parent end).
    ctrl_fd: Option<OwnedFd>,
    /// Stdout pipe read end (for fork clones — used by reduce).
    stdout_pipe: Option<OwnedFd>,
    /// Init function (runs once in child before fork).
    init_fn: Option<Box<dyn FnOnce() + Send + 'static>>,
    /// Work function (runs in each fork clone).
    work_fn: Option<Arc<dyn Fn(u32) + Send + Sync + 'static>>,
    /// Optional fd overrides for stdin/stdout/stderr (used by Pipeline).
    io_overrides: Option<(Option<i32>, Option<i32>, Option<i32>)>,
    /// Extra fd mappings for the child: (target_fd, source_fd).
    /// Each pair dup2's source_fd to target_fd in the child before exec.
    extra_fds: Vec<(i32, i32)>,
    /// HTTP ACL proxy handle — kept alive so the proxy runs while the child is alive.
    http_acl_handle: Option<crate::http_acl::HttpAclProxyHandle>,
    /// Optional callback invoked when a port bind is recorded.
    #[allow(clippy::type_complexity)]
    on_bind: Option<Box<dyn Fn(&std::collections::HashMap<u16, u16>) + Send + Sync>>,
}

impl Sandbox {
    /// Create a new sandbox in the `Created` state.
    pub fn new(policy: &Policy) -> Result<Self, SandlockError> {
        Ok(Self::create(policy))
    }

    /// Create a sandbox with init and work functions for COW forking.
    ///
    /// `init_fn` runs once in the child to load expensive state.
    /// `work_fn` runs in each COW clone created by `fork(N)`.
    ///
    /// ```ignore
    /// let mut sb = Sandbox::new_with_fns(&policy,
    ///     || { load_model(); },
    ///     |clone_id| { rollout(clone_id); },
    /// )?;
    /// let clones = sb.fork(1000).await?;
    /// ```
    pub fn new_with_fns(
        policy: &Policy,
        init_fn: impl FnOnce() + Send + 'static,
        work_fn: impl Fn(u32) + Send + Sync + 'static,
    ) -> Result<Self, SandlockError> {
        let mut sb = Self::create(policy);
        sb.init_fn = Some(Box::new(init_fn));
        sb.work_fn = Some(Arc::new(work_fn));
        Ok(sb)
    }

    fn create(policy: &Policy) -> Self {
        Self {
            policy: policy.clone(),
            state: SandboxState::Created,
            child_pid: None,
            pidfd: None,
            notif_handle: None,
            throttle_handle: None,
            loadavg_handle: None,
            _stdout_read: None,
            _stderr_read: None,
            cow_branch: None,
            seccomp_cow: None,
            supervisor_resource: None,
            supervisor_cow: None,
            supervisor_network: None,
            ctrl_fd: None,
            stdout_pipe: None,
            init_fn: None,
            work_fn: None,
            io_overrides: None,
            extra_fds: Vec::new(),
            http_acl_handle: None,
            on_bind: None,
        }
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

    /// Dry-run: spawn, wait, collect filesystem changes, then abort.
    /// Returns the run result plus a list of changes that would have been
    /// committed. The workdir is left unchanged.
    pub async fn dry_run(policy: &Policy, cmd: &[&str]) -> Result<crate::dry_run::DryRunResult, SandlockError> {
        let mut policy = policy.clone();
        policy.on_exit = BranchAction::Keep;
        policy.on_error = BranchAction::Keep;

        let mut sb = Self::new(&policy)?;
        sb.do_spawn(cmd, true).await?;
        let run_result = sb.wait().await?;
        let changes = sb.collect_changes().await;
        sb.do_abort().await;
        Ok(crate::dry_run::DryRunResult { run_result, changes })
    }

    /// Dry-run with inherited stdio (interactive mode).
    pub async fn dry_run_interactive(policy: &Policy, cmd: &[&str]) -> Result<crate::dry_run::DryRunResult, SandlockError> {
        let mut policy = policy.clone();
        policy.on_exit = BranchAction::Keep;
        policy.on_error = BranchAction::Keep;

        let mut sb = Self::new(&policy)?;
        sb.do_spawn(cmd, false).await?;
        let run_result = sb.wait().await?;
        let changes = sb.collect_changes().await;
        sb.do_abort().await;
        Ok(crate::dry_run::DryRunResult { run_result, changes })
    }

    /// Collect changes from whichever COW branch exists.
    async fn collect_changes(&self) -> Vec<crate::dry_run::Change> {
        if let Some(ref branch) = self.cow_branch {
            return branch.changes().unwrap_or_default();
        }
        if let Some(ref cow) = self.seccomp_cow {
            return cow.changes().unwrap_or_default();
        }
        Vec::new()
    }

    /// Abort both COW branch types (used by dry_run to discard changes).
    async fn do_abort(&mut self) {
        if let Some(branch) = self.cow_branch.take() {
            let _ = branch.abort();
        }
        if let Some(ref mut cow) = self.seccomp_cow {
            let _ = cow.abort();
        }
    }

    /// Create N COW clones of this sandbox.
    ///
    /// Requires `new_with_fns()`. Forks a confined child, runs `init_fn`,
    /// then forks N times using raw `fork()` (bypasses seccomp). Each
    /// clone gets `CLONE_ID=0..N-1` and runs `work_fn(clone_id)`.
    ///
    /// Memory pages from `init_fn` are shared copy-on-write across all
    /// clones — 1000 clones of a 50MB process use ~50MB total.
    ///
    /// Returns PIDs of all clones. Use `waitpid` to collect them.
    /// Create N COW clones, each runs `work_fn(clone_id)`.
    ///
    /// Returns a Vec of Sandbox handles — one per clone. Each clone is
    /// a live process that can be waited on, killed, or paused.
    ///
    /// ```ignore
    /// let clones = sb.fork(4).await?;
    /// for mut c in clones { c.wait().await?; }
    /// ```
    pub async fn fork(&mut self, n: u32) -> Result<Vec<Sandbox>, SandlockError> {
        let init_fn = self.init_fn.take()
            .ok_or_else(|| SandboxError::Child("fork() requires new_with_fns()".into()))?;
        let work_fn = self.work_fn.take()
            .ok_or_else(|| SandboxError::Child("fork() requires new_with_fns()".into()))?;

        let policy = self.policy.clone();


        // Create control pipe
        let mut ctrl_fds = [0i32; 2];
        if unsafe { libc::pipe2(ctrl_fds.as_mut_ptr(), 0) } < 0 {
            return Err(SandboxError::Io(std::io::Error::last_os_error()).into());
        }
        let ctrl_parent = unsafe { OwnedFd::from_raw_fd(ctrl_fds[0]) };
        let ctrl_child_fd = ctrl_fds[1];

        // Create per-clone stdout pipes (parent keeps read ends)
        let mut pipe_read_ends: Vec<OwnedFd> = Vec::with_capacity(n as usize);
        let mut pipe_write_fds: Vec<i32> = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let mut pfds = [0i32; 2];
            if unsafe { libc::pipe(pfds.as_mut_ptr()) } >= 0 {
                pipe_read_ends.push(unsafe { OwnedFd::from_raw_fd(pfds[0]) });
                pipe_write_fds.push(pfds[1]);
            } else {
                pipe_write_fds.push(-1);
            }
        }

        // Fork the template child
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe { libc::close(ctrl_child_fd) };
            return Err(SandboxError::Fork(std::io::Error::last_os_error()).into());
        }

        if pid == 0 {
            // ===== CHILD (template) =====
            drop(ctrl_parent);

            unsafe { libc::setpgid(0, 0) };
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

            let _ = crate::landlock::confine(&policy);

            let deny = crate::context::deny_syscall_numbers(&policy);
            let args = crate::context::arg_filters(&policy);
            let filter = crate::seccomp::bpf::assemble_filter(&[], &deny, &args);
            let _ = crate::seccomp::bpf::install_deny_filter(&filter);

            CONFINED.store(true, std::sync::atomic::Ordering::Relaxed);

            // Run init (loads expensive state, shared via COW)
            init_fn();

            // Close read ends in template (parent owns them)
            drop(pipe_read_ends);

            // Fork N clones, send PIDs, wait for all
            crate::fork::fork_ready_loop_fn(ctrl_child_fd, n, &*work_fn, &pipe_write_fds);
            unsafe { libc::_exit(0) };
        }

        // ===== PARENT =====
        unsafe { libc::close(ctrl_child_fd) };
        // Close write ends in parent (template/clones own them)
        for wfd in &pipe_write_fds {
            if *wfd >= 0 { unsafe { libc::close(*wfd) }; }
        }
        self.child_pid = Some(pid);
        self.state = SandboxState::Running;

        // Read N clone PIDs
        let ctrl_fd = ctrl_parent.as_raw_fd();
        let mut pid_buf = vec![0u8; n as usize * 4];
        read_exact(ctrl_fd, &mut pid_buf);

        let clone_pids: Vec<i32> = pid_buf.chunks(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap_or([0; 4])) as i32)
            .collect();
        let live_count = clone_pids.iter().filter(|&&p| p > 0).count();

        // Read exit codes (template waits for all clones first)
        let mut code_buf = vec![0u8; live_count * 4];
        read_exact(ctrl_fd, &mut code_buf);
        self.ctrl_fd = Some(ctrl_parent);

        // Wait for template to exit
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        // Create clone handles with stdout pipe read ends
        let mut code_idx = 0;
        let mut clones = Vec::with_capacity(live_count);
        let mut pipe_iter = pipe_read_ends.into_iter();

        for &clone_pid in &clone_pids {
            let pipe = pipe_iter.next();
            if clone_pid <= 0 { continue; }

            let code = i32::from_be_bytes(
                code_buf[code_idx * 4..(code_idx + 1) * 4].try_into().unwrap_or([0; 4])
            );
            code_idx += 1;

            let mut sb = Sandbox::create(&policy);
            sb.child_pid = Some(clone_pid);
            sb.state = SandboxState::Stopped(if code == 0 {
                ExitStatus::Code(0)
            } else if code > 0 {
                ExitStatus::Code(code)
            } else {
                ExitStatus::Killed
            });
            sb.stdout_pipe = pipe;
            clones.push(sb);
        }

        Ok(clones)
    }

    /// Reduce: wait for all clones, then run a reducer command.
    ///
    /// Waits for every clone to finish, then runs `cmd` in this sandbox.
    /// The reducer can read clone results from shared files, tmpdir, etc.
    ///
    /// ```ignore
    /// let clones = mapper.fork(4).await?;
    /// let result = reducer.reduce(&["python3", "sum.py"], &mut clones).await?;
    /// ```
    pub async fn reduce(
        &self,
        cmd: &[&str],
        clones: &mut [Sandbox],
    ) -> Result<RunResult, SandlockError> {
        // Read each clone's stdout pipe and concatenate
        let mut combined = Vec::new();
        for clone in clones.iter_mut() {
            if let Some(pipe) = clone.stdout_pipe.take() {
                combined.extend_from_slice(&read_fd_to_end(pipe));
            }
        }

        // Create a pipe to feed combined data to reducer's stdin
        let mut stdin_fds = [0i32; 2];
        if unsafe { libc::pipe2(stdin_fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(SandboxError::Io(std::io::Error::last_os_error()).into());
        }

        // Write combined data in a blocking thread (avoid deadlock with large data)
        let write_fd = stdin_fds[1];
        let write_handle = tokio::task::spawn_blocking(move || {
            unsafe {
                libc::write(write_fd, combined.as_ptr() as *const _, combined.len());
                libc::close(write_fd);
            }
        });

        // Spawn reducer with stdin from pipe, capture stdout
        let mut reducer = Sandbox::new(&self.policy)?;
        reducer.io_overrides = Some((Some(stdin_fds[0]), None, None));
        reducer.do_spawn(cmd, true).await?;
        unsafe { libc::close(stdin_fds[0]) };

        let _ = write_handle.await;
        reducer.wait().await
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
        if let Some(h) = self.loadavg_handle.take() {
            h.abort();
        }

        // Extract seccomp COW branch while we're still in async context
        // (can properly .lock().await the tokio Mutex).  This avoids the
        // try_lock() race in sync drop() that could skip cleanup entirely.
        if let Some(ref cow_state) = self.supervisor_cow {
            let mut cow = cow_state.lock().await;
            self.seccomp_cow = cow.branch.take();
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

    /// Set a callback invoked whenever a port bind is recorded.
    pub fn set_on_bind(&mut self, cb: impl Fn(&std::collections::HashMap<u16, u16>) + Send + Sync + 'static) {
        self.on_bind = Some(Box::new(cb));
    }

    /// Return the current virtual-to-real port mappings.
    ///
    /// Returns a snapshot of all ports where the real (host) port differs from
    /// the virtual port the sandbox requested. Empty if port_remap is disabled
    /// or no ports have been remapped.
    pub async fn port_mappings(&self) -> std::collections::HashMap<u16, u16> {
        if let Some(ref net) = self.supervisor_network {
            let ns = net.lock().await;
            ns.port_map.virtual_to_real.clone()
        } else {
            std::collections::HashMap::new()
        }
    }

    /// Return whether the child is currently running.
    #[doc(hidden)]
    pub fn is_running(&self) -> bool {
        matches!(self.state, SandboxState::Running | SandboxState::Paused)
    }

    /// Return a reference to the policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Commit COW writes to the original directory.
    #[doc(hidden)]
    pub async fn commit(&mut self) -> Result<(), SandlockError> {
        if let Some(branch) = self.cow_branch.take() {
            branch.commit().map_err(|e| SandlockError::Sandbox(SandboxError::Branch(e)))?;
        }
        Ok(())
    }

    /// Discard COW writes.
    #[doc(hidden)]
    pub async fn abort_branch(&mut self) -> Result<(), SandlockError> {
        if let Some(branch) = self.cow_branch.take() {
            branch.abort().map_err(|e| SandlockError::Sandbox(SandboxError::Branch(e)))?;
        }
        Ok(())
    }

    /// Freeze the sandbox: hold all fork notifications + SIGSTOP the process group.
    pub(crate) async fn freeze(&self) -> Result<(), SandlockError> {
        let pid = self.child_pid.ok_or(SandlockError::Sandbox(SandboxError::NotRunning))?;

        // Set hold_forks in resource state
        if let Some(ref resource) = self.supervisor_resource {
            let mut rs = resource.lock().await;
            rs.hold_forks = true;
        }

        // SIGSTOP the process group
        unsafe { libc::killpg(pid, libc::SIGSTOP); }
        Ok(())
    }

    /// Thaw the sandbox: release held fork notifications + SIGCONT.
    pub(crate) async fn thaw(&self) -> Result<(), SandlockError> {
        let pid = self.child_pid.ok_or(SandlockError::Sandbox(SandboxError::NotRunning))?;

        // Release held forks
        if let Some(ref resource) = self.supervisor_resource {
            let mut rs = resource.lock().await;
            rs.hold_forks = false;
            rs.held_notif_ids.clear();
        }

        // SIGCONT the process group
        unsafe { libc::killpg(pid, libc::SIGCONT); }
        Ok(())
    }

    /// Spawn a sandboxed process without waiting for it to exit.
    /// Use `wait()` to collect the exit status when done.
    #[doc(hidden)]
    pub async fn spawn(&mut self, cmd: &[&str]) -> Result<(), SandlockError> {
        self.do_spawn(cmd, false).await
    }

    /// Like `spawn` but captures stdout and stderr (available via `wait()`).
    /// Not part of the public API — used by the FFI crate.
    #[doc(hidden)]
    pub async fn spawn_captured(&mut self, cmd: &[&str]) -> Result<(), SandlockError> {
        self.do_spawn(cmd, true).await
    }

    /// Spawn with explicit stdin/stdout/stderr fd redirection.
    ///
    /// Each `Option<RawFd>` overrides the corresponding fd in the child:
    /// - `stdin_fd`: dup2'd to fd 0
    /// - `stdout_fd`: dup2'd to fd 1
    /// - `stderr_fd`: dup2'd to fd 2
    ///
    /// The caller is responsible for closing the fds after this call.
    #[doc(hidden)]
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

    /// Like `spawn_with_io` but also maps extra fds into the child.
    /// `extra_fds` is a list of (target_fd, source_fd) pairs.
    #[doc(hidden)]
    pub async fn spawn_with_gather_io(
        &mut self,
        cmd: &[&str],
        stdin_fd: Option<std::os::unix::io::RawFd>,
        stdout_fd: Option<std::os::unix::io::RawFd>,
        stderr_fd: Option<std::os::unix::io::RawFd>,
        extra_fds: Vec<(i32, i32)>,
    ) -> Result<(), SandlockError> {
        self.io_overrides = Some((stdin_fd, stdout_fd, stderr_fd));
        self.extra_fds = extra_fds;
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

        // 4. Resolve net_allow_hosts to IPs + build virtual /etc/hosts
        //
        // Semantics:
        //   None               -> unrestricted (no virtualization, no IP allowlist)
        //   Some(empty)        -> deny all (empty virtual /etc/hosts, empty allowlist)
        //   Some(nonempty)     -> resolve and allowlist
        let (resolved_ips, virtual_etc_hosts) = match self.policy.net_allow_hosts.as_deref() {
            None => (std::collections::HashSet::new(), None),
            Some([]) => (
                std::collections::HashSet::new(),
                Some(String::new()),
            ),
            Some(hosts) => {
                let resolved = network::resolve_hosts(hosts)
                    .await
                    .map_err(SandboxError::Io)?;
                (resolved.ips, Some(resolved.etc_hosts))
            }
        };

        // 5. Spawn HTTP ACL proxy if rules are configured
        if !self.policy.http_allow.is_empty() || !self.policy.http_deny.is_empty() {
            let handle = crate::http_acl::spawn_http_acl_proxy(
                self.policy.http_allow.clone(),
                self.policy.http_deny.clone(),
                self.policy.https_ca.as_deref(),
                self.policy.https_key.as_deref(),
            ).await.map_err(SandboxError::Io)?;
            self.http_acl_handle = Some(handle);
        }

        // 6. Create COW branch if requested
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

        // Ask the backend for mount config (only OverlayFS needs one).
        let cow_config = cow_branch.as_ref().and_then(|b| b.child_mount_config());

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

            // Apply extra fd mappings (from gather)
            for &(target_fd, source_fd) in &self.extra_fds {
                unsafe { libc::dup2(source_fd, target_fd) };
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

            // Collect target fds from gather that must survive close_fds_above
            let gather_keep_fds: Vec<i32> = self.extra_fds.iter().map(|&(target, _)| target).collect();

            // This never returns.
            context::confine_child(&self.policy, &c_cmd, &pipes, cow_config.as_ref(), nested, &gather_keep_fds);
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
                has_net_allowlist: self.policy.net_allow_hosts.is_some()
                    || self.policy.policy_fn.is_some()
                    || !self.policy.http_allow.is_empty()
                    || !self.policy.http_deny.is_empty(),
                has_random_seed: self.policy.random_seed.is_some(),
                has_time_start: self.policy.time_start.is_some(),
                time_offset: time_offset_val,
                num_cpus: self.policy.num_cpus,
                port_remap: self.policy.port_remap,
                cow_enabled: self.policy.workdir.is_some() && self.policy.fs_isolation == FsIsolation::None,
                chroot_root: self.policy.chroot.as_ref().and_then(|p| std::fs::canonicalize(p).ok()),
                chroot_readable: self.policy.fs_readable.clone(),
                chroot_writable: self.policy.fs_writable.clone(),
                chroot_denied: self.policy.fs_denied.clone(),
                chroot_mounts: self.policy.fs_mount.iter().map(|(vp, hp)| {
                    (vp.clone(), std::fs::canonicalize(hp).unwrap_or_else(|_| hp.clone()))
                }).collect(),
                deterministic_dirs: self.policy.deterministic_dirs,
                hostname: self.policy.hostname.clone(),
                has_http_acl: !self.policy.http_allow.is_empty() || !self.policy.http_deny.is_empty(),
                virtual_etc_hosts,
            };

            // Create domain states
            use rand::SeedableRng;
            use rand_chacha::ChaCha8Rng;

            let random_state = self.policy.random_seed.map(|seed| ChaCha8Rng::seed_from_u64(seed));
            let time_offset = self.policy.time_start.map(|t| crate::time::calculate_time_offset(t));

            // TimeRandomState
            let time_random_state = TimeRandomState::new(time_offset, random_state);

            // NetworkState
            let mut net_state = NetworkState::new();
            net_state.network_policy = if self.policy.net_allow_hosts.is_some() {
                crate::seccomp::notif::NetworkPolicy::AllowList(resolved_ips)
            } else {
                crate::seccomp::notif::NetworkPolicy::Unrestricted
            };
            net_state.http_acl_addr = self.http_acl_handle.as_ref().map(|h| h.addr);
            net_state.http_acl_ports = self.policy.http_ports.iter().copied().collect();
            net_state.http_acl_orig_dest = self.http_acl_handle.as_ref().map(|h| h.orig_dest.clone());
            if let Some(cb) = self.on_bind.take() {
                net_state.port_map.on_bind = Some(cb);
            }

            // ProcfsState (sandbox membership lives in ProcessIndex now).
            let procfs_state = ProcfsState::new();

            // ResourceState
            let mut res_state = ResourceState::new(
                notif_policy.max_memory_bytes,
                notif_policy.max_processes,
            );
            res_state.proc_count = 1;

            // CowState
            let mut cow_state = CowState::new();
            if self.policy.workdir.is_some() && self.policy.fs_isolation == FsIsolation::None {
                let workdir = self.policy.workdir.as_ref().unwrap();
                let storage = self.policy.fs_storage.as_deref();
                let max_disk = self.policy.max_disk.map(|b| b.0).unwrap_or(0);
                match crate::cow::seccomp::SeccompCowBranch::create(workdir, storage, max_disk) {
                    Ok(branch) => { cow_state.branch = Some(branch); }
                    Err(e) => { eprintln!("sandlock: seccomp COW branch creation failed: {}", e); }
                }
            }

            // PolicyFnState
            let mut policy_fn_state = PolicyFnState::new();

            if let Ok(mut denied) = policy_fn_state.denied_paths.write() {
                for path in &self.policy.fs_denied {
                    denied.insert(path.to_string_lossy().into_owned());
                }
            }

            if let Some(ref callback) = self.policy.policy_fn {
                let live = crate::policy_fn::LivePolicy {
                    allowed_ips: match &net_state.network_policy {
                        crate::seccomp::notif::NetworkPolicy::AllowList(ips) => ips.clone(),
                        crate::seccomp::notif::NetworkPolicy::Unrestricted => std::collections::HashSet::new(),
                    },
                    max_memory_bytes: notif_policy.max_memory_bytes,
                    max_processes: notif_policy.max_processes,
                };
                let ceiling = live.clone();
                let live = std::sync::Arc::new(std::sync::RwLock::new(live));
                let denied_paths = policy_fn_state.denied_paths.clone();
                let pid_overrides = net_state.pid_ip_overrides.clone();
                policy_fn_state.live_policy = Some(live.clone());
                let tx = crate::policy_fn::spawn_policy_fn(
                    callback.clone(), live, ceiling, pid_overrides, denied_paths,
                );
                policy_fn_state.event_tx = Some(tx);
            }

            // ChrootState
            let chroot_state = ChrootState::new();

            use std::os::unix::io::AsRawFd;
            let notif_raw_fd = notif_fd.as_raw_fd();
            let child_pidfd_raw = pidfd.as_ref().map(|pfd| pfd.as_raw_fd());

            let res_state = Arc::new(Mutex::new(res_state));
            self.supervisor_resource = Some(Arc::clone(&res_state));

            let cow_state = Arc::new(Mutex::new(cow_state));
            self.supervisor_cow = Some(Arc::clone(&cow_state));

            let net_state = Arc::new(Mutex::new(net_state));
            self.supervisor_network = Some(Arc::clone(&net_state));

            let procfs_state = Arc::new(Mutex::new(procfs_state));
            let time_random_state = Arc::new(Mutex::new(time_random_state));
            let policy_fn_state = Arc::new(Mutex::new(policy_fn_state));
            let chroot_state = Arc::new(Mutex::new(chroot_state));
            // Root child is registered (with watcher) on its first
            // notification, the same path grandchildren take.
            let processes = Arc::new(crate::seccomp::state::ProcessIndex::new());

            let ctx = Arc::new(SupervisorCtx {
                resource: Arc::clone(&res_state),
                cow: Arc::clone(&cow_state),
                procfs: Arc::clone(&procfs_state),
                network: Arc::clone(&net_state),
                time_random: Arc::clone(&time_random_state),
                policy_fn: Arc::clone(&policy_fn_state),
                chroot: Arc::clone(&chroot_state),
                netlink: Arc::new(crate::netlink::NetlinkState::new()),
                processes: Arc::clone(&processes),
                policy: Arc::new(notif_policy),
                child_pidfd: child_pidfd_raw,
                notif_fd: notif_raw_fd,
            });

            // Spawn notif supervisor
            self.notif_handle = Some(tokio::spawn(
                notif::supervisor(notif_fd, ctx),
            ));

            // Spawn load average sampling task (every 5s, like the kernel)
            let la_resource = Arc::clone(&res_state);
            self.loadavg_handle = Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                interval.tick().await; // skip immediate first tick
                loop {
                    interval.tick().await;
                    let mut rs = la_resource.lock().await;
                    let running = rs.proc_count;
                    rs.load_avg.sample(running);
                }
            }));
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
        if let Some(h) = self.loadavg_handle.take() {
            h.abort();
        }

        // COW cleanup based on exit status.
        // Determine action once, then apply to whichever branch exists.
        let is_error = matches!(
            self.state,
            SandboxState::Stopped(ref s) if !matches!(s, ExitStatus::Code(0))
        );
        let action = if is_error {
            &self.policy.on_error
        } else {
            &self.policy.on_exit
        };

        // OverlayFS / BranchFS COW branch
        if let Some(ref branch) = self.cow_branch {
            match action {
                BranchAction::Commit => { let _ = branch.commit(); }
                BranchAction::Abort => { let _ = branch.abort(); }
                BranchAction::Keep => {}
            }
        }

        // Seccomp COW branch (extracted from supervisor state in wait())
        if let Some(ref mut cow) = self.seccomp_cow {
            match action {
                BranchAction::Commit => { let _ = cow.commit(); }
                BranchAction::Abort => { let _ = cow.abort(); }
                BranchAction::Keep => {}
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
/// Read exactly `buf.len()` bytes from a raw fd.
fn read_exact(fd: i32, buf: &mut [u8]) {
    let mut off = 0;
    while off < buf.len() {
        let r = unsafe { libc::read(fd, buf[off..].as_mut_ptr() as *mut _, buf.len() - off) };
        if r <= 0 { break; }
        off += r as usize;
    }
}

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
