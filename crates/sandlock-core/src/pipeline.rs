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

use crate::error::{SandboxError, SandlockError};
use crate::policy::Policy;
use crate::result::{ExitStatus, RunResult};
use crate::sandbox::Sandbox;

// ============================================================
// Stage
// ============================================================

/// A lazy command bound to a sandbox policy.
///
/// Not executed until `.run()` is called or the stage is part of a pipeline.
pub struct Stage {
    pub policy: Policy,
    pub args: Vec<String>,
}

impl Stage {
    /// Create a new stage with the given policy and command.
    pub fn new(policy: &Policy, args: &[&str]) -> Self {
        Self {
            policy: policy.clone(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Run this single stage and return the result.
    pub async fn run(self, timeout: Option<Duration>) -> Result<RunResult, SandlockError> {
        let cmd_refs: Vec<&str> = self.args.iter().map(|s| s.as_str()).collect();
        if let Some(dur) = timeout {
            match tokio::time::timeout(dur, Sandbox::run_interactive(&self.policy, &cmd_refs)).await
            {
                Ok(result) => result,
                Err(_) => Ok(RunResult {
                    exit_status: ExitStatus::Timeout,
                    stdout: None,
                    stderr: None,
                }),
            }
        } else {
            Sandbox::run_interactive(&self.policy, &cmd_refs).await
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
            return Err(SandlockError::Sandbox(SandboxError::Child(
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
}

impl std::ops::BitOr<Stage> for Pipeline {
    type Output = Pipeline;
    fn bitor(mut self, rhs: Stage) -> Pipeline {
        self.stages.push(rhs);
        self
    }
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
        inter_pipes.push(make_pipe().map_err(SandboxError::Io)?);
    }

    // Create capture pipes for last stage's stdout and stderr
    let (cap_stdout_r, cap_stdout_w) = make_pipe().map_err(SandboxError::Io)?;
    let (cap_stderr_r, cap_stderr_w) = make_pipe().map_err(SandboxError::Io)?;

    // Spawn each stage
    let mut sandboxes: Vec<Sandbox> = Vec::with_capacity(n);

    for (i, stage) in stages.into_iter().enumerate() {
        let mut sb = Sandbox::new(&stage.policy)?;

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
        sb.spawn_with_io(&cmd_refs, stdin_fd, stdout_fd, stderr_fd)
            .await?;

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
            SandlockError::Sandbox(SandboxError::Child("Gather requires a consumer".into()))
        })?;
        if self.sources.is_empty() {
            return Err(SandlockError::Sandbox(SandboxError::Child(
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
        source_pipes.push(make_pipe().map_err(SandboxError::Io)?);
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
    let (cap_stdout_r, cap_stdout_w) = make_pipe().map_err(SandboxError::Io)?;
    let (cap_stderr_r, cap_stderr_w) = make_pipe().map_err(SandboxError::Io)?;

    // Spawn producers: each writes stdout to its pipe
    let mut sandboxes: Vec<Sandbox> = Vec::with_capacity(n + 1);
    for (i, ns) in sources.into_iter().enumerate() {
        let mut sb = Sandbox::new(&ns.stage.policy)?;
        let stdout_fd = source_pipes[i].1.as_raw_fd();
        let cmd_refs: Vec<&str> = ns.stage.args.iter().map(|s| s.as_str()).collect();
        sb.spawn_with_io(&cmd_refs, None, Some(stdout_fd), None).await?;
        sandboxes.push(sb);
    }

    // Spawn consumer with extra fds from source pipes
    let mut consumer_policy = consumer.policy.clone();
    // Inject _SANDLOCK_GATHER env var
    consumer_policy.env.insert("_SANDLOCK_GATHER".to_string(), gather_env);

    let mut consumer_sb = Sandbox::new(&consumer_policy)?;
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
    consumer_sb.spawn_with_gather_io(
        &cmd_refs,
        Some(stdin_fd),
        Some(cap_stdout_w.as_raw_fd()),
        Some(cap_stderr_w.as_raw_fd()),
        extra_fds,
    ).await?;
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
