//! Sandbox pipeline — chain multiple sandboxed stages connected by pipes.
//!
//! Each stage runs in its own forked sandbox process with an independent policy.
//! Data flows through kernel pipe buffers between stages; the parent process
//! never reads inter-stage data.
//!
//! ```ignore
//! let result = (
//!     Stage::new(&policy_a, &["echo", "hello"])
//!     | Stage::new(&policy_b, &["tr", "a-z", "A-Z"])
//!     | Stage::new(&policy_c, &["cat"])
//! ).run(None).await?;
//! ```

use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::time::Duration;

use crate::error::{SandboxRuntimeError, SandlockError};
use crate::sandbox::Sandbox;
use crate::result::{ExitStatus, RunResult};

// ============================================================
// Stage
// ============================================================

/// A lazy command bound to a sandbox policy.
///
/// Not executed until `.run()` is called or the stage is part of a pipeline.
pub struct Stage {
    pub sandbox: Sandbox,
    pub args: Vec<String>,
}

impl Stage {
    /// Create a new stage with the given policy and command.
    pub fn new(sandbox: &Sandbox, args: &[&str]) -> Self {
        Self {
            sandbox: sandbox.clone(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Run this single stage and return the result.
    pub async fn run(self, timeout: Option<Duration>) -> Result<RunResult, SandlockError> {
        let cmd_refs: Vec<&str> = self.args.iter().map(|s| s.as_str()).collect();
        let mut sb = self.sandbox.with_name("stage");
        if let Some(dur) = timeout {
            match tokio::time::timeout(dur, sb.run_interactive(&cmd_refs)).await {
                Ok(result) => result,
                Err(_) => Ok(RunResult {
                    exit_status: ExitStatus::Timeout,
                    stdout: None,
                    stderr: None,
                }),
            }
        } else {
            sb.run_interactive(&cmd_refs).await
        }
    }
}

impl std::ops::BitOr<Stage> for Stage {
    type Output = Pipeline;
    fn bitor(self, rhs: Stage) -> Pipeline {
        Pipeline {
            stages: vec![self, rhs],
        }
    }
}

// ============================================================
// Pipeline
// ============================================================

/// A chain of stages connected by pipes.
///
/// Minimum 2 stages. Each stage runs concurrently in its own sandbox.
/// Only the last stage's stdout and stderr are captured.
pub struct Pipeline {
    pub stages: Vec<Stage>,
}

impl Pipeline {
    /// Create a pipeline from a list of stages (must have >= 2).
    pub fn new(stages: Vec<Stage>) -> Result<Self, SandlockError> {
        if stages.len() < 2 {
            return Err(SandlockError::Runtime(SandboxRuntimeError::Child(
                "Pipeline requires at least 2 stages".into(),
            )));
        }
        Ok(Self { stages })
    }

    /// Run the pipeline. Returns the last stage's exit status and captured output.
    ///
    /// `timeout` applies to the entire pipeline.
    pub async fn run(self, timeout: Option<Duration>) -> Result<RunResult, SandlockError> {
        if let Some(dur) = timeout {
            match tokio::time::timeout(dur, run_pipeline(self.stages)).await {
                Ok(result) => result,
                Err(_) => Ok(RunResult {
                    exit_status: ExitStatus::Timeout,
                    stdout: None,
                    stderr: None,
                }),
            }
        } else {
            run_pipeline(self.stages).await
        }
    }

    /// Run the pipeline as a filesystem transaction over a shared COW workdir.
    ///
    /// Unlike [`run`](Self::run) (concurrent stages streaming bytes stdout→stdin),
    /// stages run **sequentially** and share **one** COW upper over a common
    /// workdir: stage N+1 sees stage N's writes (read-committed), the real
    /// workdir is untouched during the run, and at the end either every stage's
    /// writes commit together (all stages exited 0) or none do (any stage failed
    /// → the shared upper is discarded, the workdir is byte-identical). Data is
    /// exchanged through the shared workspace, not inter-stage pipes.
    ///
    /// Every stage must set the same `workdir`, run with the supervisor
    /// (`no_supervisor == false`), leave `on_exit`/`on_error` at their defaults,
    /// and set no `chroot` and the same `fs_storage`/`max_disk` — the pipeline
    /// owns the single shared upper and its commit/abort, so a per-stage override
    /// would conflict and is rejected.
    ///
    /// `timeout` applies to the whole pipeline; on timeout the transaction aborts.
    ///
    /// The final commit is **not crash-atomic**: it merges the shared upper into
    /// the workdir file-by-file, so a crash (or `ENOSPC`) *mid-commit* can leave
    /// the workdir partially merged. The all-or-nothing guarantee holds for a
    /// clean stage failure or timeout (nothing is written until the commit
    /// starts); durable crash-atomic commit is a later phase.
    pub async fn run_transactional(
        self,
        timeout: Option<Duration>,
    ) -> Result<TxnOutcome, SandlockError> {
        validate_txn_stages(&self.stages)?;
        run_pipeline_txn(self.stages, timeout).await
    }
}

impl std::ops::BitOr<Stage> for Pipeline {
    type Output = Pipeline;
    fn bitor(mut self, rhs: Stage) -> Pipeline {
        self.stages.push(rhs);
        self
    }
}

// ============================================================
// Transactional pipeline
// ============================================================

/// Outcome of [`Pipeline::run_transactional`].
#[derive(Debug, Clone)]
pub struct TxnOutcome {
    /// True if every stage exited 0 and the shared upper was committed to the
    /// workdir. False if any stage failed (or the pipeline timed out) and the
    /// upper was discarded, leaving the workdir byte-identical.
    pub committed: bool,
    /// Per-stage results in execution order. On a stage-failure abort this holds
    /// the stages that ran, up to and including the one that failed. On a timeout
    /// or driver-error abort it is empty: the in-flight stage-driver future is
    /// cancelled and its accumulated results are dropped (`committed` and
    /// `abort_reason` still report the outcome).
    pub stages: Vec<RunResult>,
    /// Human-readable reason the transaction aborted; `None` when committed.
    pub abort_reason: Option<String>,
}

/// Reject stage configurations that can't participate in a transaction. The
/// pipeline owns the single shared upper and the single commit/abort, so each
/// stage must set the same workdir, keep the supervisor, and not carry its own
/// branch action.
fn validate_txn_stages(stages: &[Stage]) -> Result<(), SandlockError> {
    fn reject(msg: impl Into<String>) -> SandlockError {
        SandlockError::Runtime(SandboxRuntimeError::Child(msg.into()))
    }

    // `Pipeline::new` enforces >= 2, but the struct is constructible directly;
    // check here so `run_transactional` never indexes `stages[0]` out of bounds.
    if stages.len() < 2 {
        return Err(reject("transactional pipeline requires at least 2 stages"));
    }

    let base = &stages[0].sandbox;
    let base_wd = base.workdir.as_ref().ok_or_else(|| {
        reject("transactional pipeline: stage 0 has no workdir; every stage must set the shared transaction workdir")
    })?;
    let base_max_disk = base.max_disk.map(|b| b.0).unwrap_or(0);

    for (i, stage) in stages.iter().enumerate() {
        let sb = &stage.sandbox;
        let wd = sb.workdir.as_ref().ok_or_else(|| {
            reject(format!("transactional pipeline: stage {i} has no workdir; every stage must set the shared transaction workdir"))
        })?;
        if wd != base_wd {
            return Err(reject(format!(
                "transactional pipeline: stages must share one workdir (stage 0 = {}, stage {i} = {})",
                base_wd.display(),
                wd.display()
            )));
        }
        if sb.no_supervisor {
            return Err(reject(format!(
                "transactional pipeline: stage {i} has no_supervisor=true; transactions require the COW supervisor"
            )));
        }
        // All stages overlay ONE shared upper, so per-stage COW storage/quota and
        // chroot can't each take effect — reject a stage that sets them differently
        // (or at all, for chroot) rather than silently using only stage 0's.
        if sb.chroot.is_some() {
            return Err(reject(format!(
                "transactional pipeline: stage {i} sets chroot, which is unsupported with a shared COW workdir"
            )));
        }
        if sb.fs_storage != base.fs_storage || sb.max_disk.map(|b| b.0).unwrap_or(0) != base_max_disk {
            return Err(reject(format!(
                "transactional pipeline: stage {i} sets a different fs_storage/max_disk; all stages share one COW upper, so these must match stage 0"
            )));
        }
        // The builder leaves both actions at `BranchAction::Commit` by default
        // (`unwrap_or_default()`); anything else is an explicit per-stage choice
        // that conflicts with the pipeline owning commit/abort.
        if sb.on_exit != crate::sandbox::BranchAction::Commit
            || sb.on_error != crate::sandbox::BranchAction::Commit
        {
            return Err(reject(format!(
                "transactional pipeline: stage {i} sets on_exit/on_error, which conflicts with a transactional pipeline (the pipeline owns commit/abort) — leave them at their defaults"
            )));
        }
    }
    Ok(())
}

/// Create the shared COW branch, drive the stages sequentially over it, then
/// commit-all or abort-all. The branch lives here (outside the driven future)
/// so a timeout that cancels the stage loop can still abort cleanly.
async fn run_pipeline_txn(
    stages: Vec<Stage>,
    timeout: Option<Duration>,
) -> Result<TxnOutcome, SandlockError> {
    fn child_err(msg: String) -> SandlockError {
        SandlockError::Runtime(SandboxRuntimeError::Child(msg))
    }

    // All stages share the validated workdir; take COW storage/quota from the
    // first stage (they overlay the same lower).
    let base = &stages[0].sandbox;
    let workdir = base.workdir.clone().expect("validated: stage 0 has a workdir");
    let storage = base.fs_storage.clone();
    let max_disk = base.max_disk.map(|b| b.0).unwrap_or(0);

    let branch = crate::cow::seccomp::SeccompCowBranch::create(&workdir, storage.as_deref(), max_disk)
        .map_err(|e| child_err(format!("transactional pipeline: failed to create COW branch: {e}")))?;
    let upper_dir = branch.upper_dir().to_path_buf();

    let mut cow_state = crate::seccomp::state::CowState::new();
    cow_state.branch = Some(branch);
    let state = std::sync::Arc::new(tokio::sync::Mutex::new(cow_state));
    let shared = crate::sandbox::SharedCow { state: std::sync::Arc::clone(&state), upper_dir };

    let drive = drive_txn_stages(stages, shared);
    let driven: Result<(bool, Vec<RunResult>, Option<String>), SandlockError> = match timeout {
        Some(dur) => match tokio::time::timeout(dur, drive).await {
            Ok(r) => r,
            Err(_) => Ok((false, Vec::new(), Some("transactional pipeline timed out".to_string()))),
        },
        None => drive.await,
    };

    // Finalize the shared upper in EVERY case — commit only on a clean full run,
    // otherwise discard — before propagating any driver error, so a mid-loop
    // failure never leaves the upper dangling. (`SeccompCowBranch`'s Drop is a
    // further backstop for panics/cancellation; this is the deterministic path.)
    // Take the branch out from under the async mutex first, then commit/abort the
    // owned value so the sync merge doesn't run while holding the guard.
    let taken = { state.lock().await.branch.take() };
    let (all_ok, results, reason, drive_err) = match driven {
        Ok((ok, res, rsn)) => (ok, res, rsn, None),
        Err(e) => (false, Vec::new(), Some(format!("{e}")), Some(e)),
    };
    let committed = match taken {
        Some(mut branch) if all_ok => {
            branch
                .commit()
                .map_err(|e| child_err(format!("transactional pipeline: commit failed: {e}")))?;
            true
        }
        Some(mut branch) => {
            let _ = branch.abort();
            false
        }
        None => all_ok,
    };
    if let Some(e) = drive_err {
        return Err(e);
    }

    Ok(TxnOutcome {
        committed,
        stages: results,
        abort_reason: if committed { None } else { reason },
    })
}

/// Run each stage to completion in order over the shared upper, with no
/// inter-stage pipes (all stdio inherited). Stops at the first non-zero exit.
async fn drive_txn_stages(
    stages: Vec<Stage>,
    shared: crate::sandbox::SharedCow,
) -> Result<(bool, Vec<RunResult>, Option<String>), SandlockError> {
    let mut results: Vec<RunResult> = Vec::with_capacity(stages.len());
    for (i, stage) in stages.into_iter().enumerate() {
        let cmd_refs: Vec<&str> = stage.args.iter().map(|s| s.as_str()).collect();
        let mut sb = stage.sandbox.with_name(format!("txn-stage-{i}"));
        sb.set_shared_cow(shared.clone())?;
        sb.create_with_io(&cmd_refs, None, None, None).await?;
        sb.start()?;
        let result = sb.wait().await?;

        let status = result.exit_status.clone();
        results.push(result);
        if !matches!(status, ExitStatus::Code(0)) {
            return Ok((
                false,
                results,
                Some(format!("stage {i} did not exit cleanly: {status:?}")),
            ));
        }
    }
    Ok((true, results, None))
}

// ============================================================
// Internal: run_pipeline
// ============================================================

/// Helper to create a pipe and return (read_end, write_end) as OwnedFd.
fn make_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(fds[0]),
            OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

/// Fork and run all stages concurrently with inter-stage pipes.
async fn run_pipeline(stages: Vec<Stage>) -> Result<RunResult, SandlockError> {
    let n = stages.len();

    // Create inter-stage pipes: pipe[i] connects stage[i] stdout → stage[i+1] stdin
    let mut inter_pipes: Vec<(OwnedFd, OwnedFd)> = Vec::with_capacity(n - 1);
    for _ in 0..n - 1 {
        inter_pipes.push(make_pipe().map_err(SandboxRuntimeError::Io)?);
    }

    // Create capture pipes for last stage's stdout and stderr
    let (cap_stdout_r, cap_stdout_w) = make_pipe().map_err(SandboxRuntimeError::Io)?;
    let (cap_stderr_r, cap_stderr_w) = make_pipe().map_err(SandboxRuntimeError::Io)?;

    // Spawn each stage
    let mut sandboxes: Vec<Sandbox> = Vec::with_capacity(n);

    for (i, stage) in stages.into_iter().enumerate() {
        let name = format!("pipeline-stage-{}", i);
        let mut sb = stage.sandbox.clone().with_name(name);

        // Determine stdin for this stage
        let stdin_fd: Option<RawFd> = if i == 0 {
            None // First stage: inherit parent's stdin
        } else {
            Some(inter_pipes[i - 1].0.as_raw_fd()) // Read end of previous pipe
        };

        // Determine stdout for this stage
        let stdout_fd: Option<RawFd> = if i == n - 1 {
            Some(cap_stdout_w.as_raw_fd()) // Last stage: capture
        } else {
            Some(inter_pipes[i].1.as_raw_fd()) // Write end of next pipe
        };

        // Determine stderr for this stage
        let stderr_fd: Option<RawFd> = if i == n - 1 {
            Some(cap_stderr_w.as_raw_fd()) // Last stage: capture
        } else {
            None // Intermediate stages: inherit parent's stderr
        };

        let cmd_refs: Vec<&str> = stage.args.iter().map(|s| s.as_str()).collect();
        sb.create_with_io(&cmd_refs, stdin_fd, stdout_fd, stderr_fd)
            .await?;
        sb.start()?;

        sandboxes.push(sb);
    }

    // Close all pipe write ends in the parent so stages get EOF
    drop(inter_pipes);
    drop(cap_stdout_w);
    drop(cap_stderr_w);

    // Wait for all stages (last stage's exit status is the result)
    let mut last_result = RunResult {
        exit_status: ExitStatus::Killed,
        stdout: None,
        stderr: None,
    };

    for (i, mut sb) in sandboxes.into_iter().enumerate() {
        let result = sb.wait().await?;
        if i == n - 1 {
            last_result.exit_status = result.exit_status;
        }
    }

    // Read captured stdout/stderr from last stage
    last_result.stdout = Some(read_fd_to_end(cap_stdout_r));
    last_result.stderr = Some(read_fd_to_end(cap_stderr_r));

    Ok(last_result)
}

/// Read all bytes from a file descriptor until EOF.
fn read_fd_to_end(fd: OwnedFd) -> Vec<u8> {
    use std::io::Read;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) };
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf);
    buf
}

// ============================================================
// Gather — fan-in from multiple producers to one consumer
// ============================================================

/// A named producer stage.
pub struct NamedStage {
    pub name: String,
    pub stage: Stage,
}

/// Fan-in pattern: multiple named producers pipe into one consumer.
///
/// Each producer runs in its own sandbox. Their stdout is connected to the
/// consumer via Unix pipes. The last source maps to stdin (fd 0), others
/// to fd 3, 4, 5, ... The consumer reads them via `sandlock.inputs` in
/// Python or `os.fdopen(N)` directly.
///
/// The `_SANDLOCK_GATHER` env var is injected into the consumer with
/// a comma-separated list of `name:fd` pairs.
///
/// ```ignore
/// let result = Gather::new()
///     .source("data", Stage::new(&search_policy, &["python3", "search.py"]))
///     .source("code", Stage::new(&planner_policy, &["python3", "plan.py"]))
///     .consumer(Stage::new(&executor_policy, &["python3", "run.py"]))
///     .run(None)
///     .await?;
/// ```
pub struct Gather {
    sources: Vec<NamedStage>,
    consumer: Option<Stage>,
}

impl Gather {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            consumer: None,
        }
    }

    pub fn source(mut self, name: &str, stage: Stage) -> Self {
        self.sources.push(NamedStage {
            name: name.to_string(),
            stage,
        });
        self
    }

    pub fn consumer(mut self, stage: Stage) -> Self {
        self.consumer = Some(stage);
        self
    }

    pub async fn run(self, timeout: Option<Duration>) -> Result<RunResult, SandlockError> {
        let consumer = self.consumer.ok_or_else(|| {
            SandlockError::Runtime(SandboxRuntimeError::Child("Gather requires a consumer".into()))
        })?;
        if self.sources.is_empty() {
            return Err(SandlockError::Runtime(SandboxRuntimeError::Child(
                "Gather requires at least one source".into(),
            )));
        }

        if let Some(dur) = timeout {
            match tokio::time::timeout(dur, run_gather(self.sources, consumer)).await {
                Ok(result) => result,
                Err(_) => Ok(RunResult {
                    exit_status: ExitStatus::Timeout,
                    stdout: None,
                    stderr: None,
                }),
            }
        } else {
            run_gather(self.sources, consumer).await
        }
    }
}

/// Run the gather: spawn all producers and the consumer concurrently.
async fn run_gather(
    sources: Vec<NamedStage>,
    consumer: Stage,
) -> Result<RunResult, SandlockError> {
    let n = sources.len();

    // Create a pipe for each source: source stdout → consumer fd
    // Last source → consumer stdin (fd 0), others → fd 3, 4, 5, ...
    let mut source_pipes: Vec<(OwnedFd, OwnedFd)> = Vec::with_capacity(n);
    for _ in 0..n {
        source_pipes.push(make_pipe().map_err(SandboxRuntimeError::Io)?);
    }

    // Assign consumer fds: last source → fd 0, others → fd 3, 4, ...
    let mut fd_assignments: Vec<(String, i32)> = Vec::with_capacity(n);
    let mut next_fd = 3i32;
    for (i, ns) in sources.iter().enumerate() {
        let target_fd = if i == n - 1 { 0 } else { let fd = next_fd; next_fd += 1; fd };
        fd_assignments.push((ns.name.clone(), target_fd));
    }

    // Build _SANDLOCK_GATHER env var: "name1:3,name2:0"
    let gather_env: String = fd_assignments
        .iter()
        .map(|(name, fd)| format!("{}:{}", name, fd))
        .collect::<Vec<_>>()
        .join(",");

    // Capture pipes for consumer stdout/stderr
    let (cap_stdout_r, cap_stdout_w) = make_pipe().map_err(SandboxRuntimeError::Io)?;
    let (cap_stderr_r, cap_stderr_w) = make_pipe().map_err(SandboxRuntimeError::Io)?;

    // Spawn producers: each writes stdout to its pipe
    let mut sandboxes: Vec<Sandbox> = Vec::with_capacity(n + 1);
    for (i, ns) in sources.into_iter().enumerate() {
        let name = format!("gather-source-{}", ns.name);
        let mut sb = ns.stage.sandbox.clone().with_name(name);
        let stdout_fd = source_pipes[i].1.as_raw_fd();
        let cmd_refs: Vec<&str> = ns.stage.args.iter().map(|s| s.as_str()).collect();
        sb.create_with_io(&cmd_refs, None, Some(stdout_fd), None).await?;
        sb.start()?;
        sandboxes.push(sb);
    }

    // Spawn consumer with extra fds from source pipes
    let mut consumer_sandbox = consumer.sandbox.clone();
    // Inject _SANDLOCK_GATHER env var
    consumer_sandbox.env.insert("_SANDLOCK_GATHER".to_string(), gather_env);

    let mut consumer_sb = consumer_sandbox.clone().with_name("gather-consumer");
    let stdin_fd = source_pipes[n - 1].0.as_raw_fd();

    // Build extra fd mappings for non-stdin sources
    let mut extra_fds = Vec::new();
    for (i, (_, target_fd)) in fd_assignments.iter().enumerate() {
        if i < n - 1 {
            let read_fd = source_pipes[i].0.as_raw_fd();
            // Clear O_CLOEXEC so these fds survive exec
            unsafe {
                let flags = libc::fcntl(read_fd, libc::F_GETFD);
                libc::fcntl(read_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
            extra_fds.push((*target_fd, read_fd));
        }
    }

    let cmd_refs: Vec<&str> = consumer.args.iter().map(|s| s.as_str()).collect();
    consumer_sb.create_with_gather_io(
        &cmd_refs,
        Some(stdin_fd),
        Some(cap_stdout_w.as_raw_fd()),
        Some(cap_stderr_w.as_raw_fd()),
        extra_fds,
    ).await?;
    consumer_sb.start()?;
    sandboxes.push(consumer_sb);

    // Close pipe ends in parent
    drop(source_pipes);
    drop(cap_stdout_w);
    drop(cap_stderr_w);

    // Wait for all
    let total = sandboxes.len();
    let mut last_result = RunResult {
        exit_status: ExitStatus::Killed,
        stdout: None,
        stderr: None,
    };
    for (i, mut sb) in sandboxes.into_iter().enumerate() {
        let result = sb.wait().await?;
        if i == total - 1 {
            last_result.exit_status = result.exit_status;
        }
    }

    last_result.stdout = Some(read_fd_to_end(cap_stdout_r));
    last_result.stderr = Some(read_fd_to_end(cap_stderr_r));

    Ok(last_result)
}
