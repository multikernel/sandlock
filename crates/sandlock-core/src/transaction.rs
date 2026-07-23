//! Filesystem transactions — sequential sandboxed stages over one shared COW
//! workdir, committed all-or-nothing (RFC #65).
//!
//! A transaction is **not** a pipeline. [`Pipeline`](crate::pipeline::Pipeline)
//! is the `|` operator: N stages running *concurrently*, each stage's stdout
//! wired to the next stage's stdin through a kernel pipe. A [`Transaction`]
//! runs its stages *sequentially* with **no inter-stage pipes and all stdio
//! inherited from the parent**; stages exchange data by reading and writing a
//! shared workspace, not by streaming bytes. The two are separate types
//! precisely so a `|`-built chain cannot be handed to the sequential runner and
//! silently lose its pipes: there is no `From<Pipeline>` and no `BitOr` for
//! `Transaction`, and a `Pipeline`'s stages are private. Taking them out is
//! [`Pipeline::into_stages`](crate::pipeline::Pipeline::into_stages) — still
//! possible, and deliberately so, but a caller has to name it.
//!
//! ```ignore
//! let outcome = Transaction::new([
//!     Stage::new(&policy, &["sh", "-c", "echo plan > a.txt"]),
//!     Stage::new(&policy, &["sh", "-c", "cat a.txt && echo built > b.txt"]),
//! ]).run(None).await?;
//! assert!(outcome.committed);
//! ```

use std::os::unix::io::AsRawFd;
use std::time::Duration;

use crate::error::{SandboxError, SandboxRuntimeError, SandlockError};
use crate::pipeline::Stage;
use crate::result::{ExitStatus, RunResult};

/// Default for [`Transaction::commit_lock_wait`]: how long to wait for another
/// transaction's commit merge to finish before giving up. Merges are short (a
/// file-by-file copy of one upper), so a wait this long only expires when
/// something is genuinely wrong.
const COMMIT_LOCK_WAIT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for the commit lock. `flock` has no timed
/// variant, so the wait is a bounded retry over the non-blocking form.
const COMMIT_LOCK_POLL: Duration = Duration::from_millis(20);

// ============================================================
// Transaction
// ============================================================

/// A set of stages run sequentially over one shared COW workdir, committed
/// all-or-nothing.
///
/// Stages run **in declaration order, one at a time**, sharing a single COW
/// upper layered over their common workdir: stage N+1 sees stage N's writes
/// (read-committed) while the real workdir stays untouched for the duration of
/// the run. If every stage exits 0 the shared upper is merged into the workdir
/// in one step; if any stage fails, or the transaction times out, the upper is
/// discarded and the workdir is byte-identical to before the run. The two cases
/// where the upper is neither merged nor discarded — the commit could not be
/// performed — are the `Err` contract of [`run`](Self::run).
///
/// **Stages are not connected by pipes.** Each stage inherits the parent's
/// stdin, stdout and stderr; data moves between stages through the shared
/// workspace. This is why a `Transaction` cannot be built with `|` — see the
/// [module docs](self).
///
/// Every stage must set the same `workdir`, run with the supervisor
/// (`no_supervisor == false`), leave `on_exit`/`on_error` at their defaults, set
/// no `chroot`, and set the same `fs_storage`/`max_disk`. The transaction owns
/// the single shared upper and its commit/abort, so a per-stage override would
/// conflict and is rejected before anything runs.
pub struct Transaction {
    stages: Vec<Stage>,
    commit_lock_wait: Duration,
}

impl Transaction {
    /// Build a transaction from an explicit list of stages.
    ///
    /// This accepts any list and validates nothing. The two-stage minimum and
    /// every cross-stage rule (see [`Transaction`]) are checked by
    /// [`run`](Self::run)/[`dry_run`](Self::dry_run) and reported as
    /// [`TxnError::Invalid`], so a caller has one place to handle a
    /// misconfigured transaction. That is deliberately unlike
    /// [`Pipeline::new`](crate::pipeline::Pipeline::new), which returns
    /// `Result` for the stage count alone.
    ///
    /// There is deliberately no `From<Pipeline>` and no `BitOr` impl: a
    /// `|`-built chain means "connect these by pipes", which a transaction does
    /// not do.
    pub fn new(stages: impl IntoIterator<Item = Stage>) -> Self {
        Self { stages: stages.into_iter().collect(), commit_lock_wait: COMMIT_LOCK_WAIT }
    }

    /// How long the commit may wait for another transaction to release the
    /// workdir lock before giving up. Defaults to 30s.
    ///
    /// Giving up does not discard the run: the shared upper is preserved and
    /// named in the error (see [`Transaction::run`]). Neither does dropping the
    /// `run()` future during the wait — the commit phase runs on a blocking
    /// thread that a cancellation detaches rather than stops, so this wait is
    /// also the bound on how long that thread outlives an abandoned `run()`.
    pub fn commit_lock_wait(mut self, wait: Duration) -> Self {
        self.commit_lock_wait = wait;
        self
    }

    /// Run every stage, then commit the shared upper if all of them exited 0.
    ///
    /// `timeout` applies to the stage phase as a whole; on expiry the
    /// transaction aborts and the workdir is untouched.
    ///
    /// Returns `Err` when the transaction could not be carried out at all: an
    /// invalid stage configuration, a failure to start a stage, or a commit that
    /// could not be performed.
    ///
    /// Once every stage has succeeded the run's work is never thrown away
    /// silently. If the commit cannot take the workdir lock, or the merge itself
    /// fails partway, the shared upper is **preserved** and its path is named in
    /// the error.
    ///
    /// That holds when this future is **cancelled** too, which is the case a
    /// caller reaches by wrapping `run()` in a `tokio::time::timeout` (the
    /// `timeout` argument bounds the stage phase only) or by racing it in a
    /// `select!`. Cancelling during the stage phase aborts and leaves the workdir
    /// untouched; cancelling once the commit phase has begun does not stop it —
    /// it runs on a blocking thread that a dropped future detaches — so the
    /// change set still lands in the workdir or is preserved. What a cancelled
    /// run gives up is the *report*: no `TxnOutcome`, no `TxnError`, and the
    /// preserved upper has to be found through
    /// [`list_preserved`](crate::cow::seccomp::list_preserved).
    pub async fn run(self, timeout: Option<Duration>) -> Result<TxnOutcome, TxnError> {
        validate_txn_stages(&self.stages)?;
        run_txn(self.stages, timeout, Disposition::Commit, self.commit_lock_wait).await
    }

    /// Run every stage and report what the transaction *would* change, then
    /// discard it. Nothing is ever merged into the workdir.
    ///
    /// The stages really execute — this predicts the filesystem effect on the
    /// workdir, not the effect of running the commands. Same contract as
    /// [`Sandbox::dry_run`](crate::sandbox::Sandbox::dry_run) for one sandbox.
    /// The outcome always has `committed == false` and
    /// `abort_reason == Some(`[`AbortReason::DryRun`]`)` unless a stage failed
    /// or the transaction timed out first.
    pub async fn dry_run(self, timeout: Option<Duration>) -> Result<TxnOutcome, TxnError> {
        validate_txn_stages(&self.stages)?;
        run_txn(self.stages, timeout, Disposition::DryRun, self.commit_lock_wait).await
    }
}

/// What to do with the shared upper once every stage has succeeded.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Commit,
    DryRun,
}

// ============================================================
// Errors
// ============================================================

/// Why a transaction could not be carried out at all.
///
/// A transaction has two failure channels and this type is the second one. The
/// **abort** channel — a stage exited non-zero, the run timed out — is an
/// `Ok(TxnOutcome)` with an [`AbortReason`]: the transaction did its job and
/// the workdir is untouched. The **commit** channel is this type: the
/// transaction could not be carried out, and each way that can happen is its
/// own variant so a caller never has to match on a message.
///
/// `#[non_exhaustive]`: match with a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TxnError {
    /// The stage set is not a valid transaction. Checked before anything runs,
    /// so nothing was executed and no branch was created.
    #[error("invalid transaction: {0}")]
    Invalid(String),

    /// The shared COW branch could not be created. No stage ran.
    #[error("transaction: failed to create the shared COW branch over {workdir}: {source}")]
    Branch {
        workdir: std::path::PathBuf,
        #[source]
        source: crate::error::BranchError,
    },

    /// Stage `index` could not be started or driven to completion. This is not a
    /// stage that *failed* — that is [`AbortReason::StageFailed`] — it is a
    /// stage that never produced an exit status.
    #[error("transaction: stage {index} could not be run: {source}")]
    Stage {
        index: usize,
        #[source]
        source: SandlockError,
    },

    /// Conflict: another transaction held the workdir commit lock for longer
    /// than [`Transaction::commit_lock_wait`]. Every stage had succeeded, so the
    /// workdir is untouched and the whole change set is preserved — additions
    /// and modifications under `preserved_upper`, deletions in the `PRESERVED`
    /// marker beside it (see
    /// [`read_preserved`](crate::cow::seccomp::read_preserved)). Retrying is the
    /// expected response.
    #[error(
        "transaction: gave up after {waited:?} waiting for another commit to release the workdir \
         lock on {workdir}. The workdir is untouched and this transaction's changes were \
         preserved at {preserved_upper}"
    )]
    Conflict {
        workdir: std::path::PathBuf,
        waited: Duration,
        preserved_upper: std::path::PathBuf,
    },

    /// The workdir commit lock could not be taken for a reason other than
    /// contention (the workdir could not be opened, or `flock` failed). As with
    /// [`Self::Conflict`] the workdir is untouched and the change set is
    /// preserved.
    #[error(
        "transaction: could not take the commit lock on {workdir}: {source}. The workdir is \
         untouched and this transaction's changes were preserved at {preserved_upper}"
    )]
    CommitLock {
        workdir: std::path::PathBuf,
        preserved_upper: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The commit merge failed. The change set that did not land is preserved —
    /// additions and modifications under `preserved_upper`, deletions in the
    /// `PRESERVED` marker beside it (see
    /// [`read_preserved`](crate::cow::seccomp::read_preserved)).
    ///
    /// The merge is not rolled back, so the workdir may be partially merged and
    /// re-running the stages is not the same thing as finishing this
    /// transaction; recovering that storage is what completes it. How much
    /// landed is not carried here — it is the difference between the workdir and
    /// what the preserved storage still holds.
    #[error(
        "transaction: the commit merge into {workdir} failed: {source}. The workdir may be \
         partially merged; what did not land was preserved at {preserved_upper}, with any \
         outstanding deletions listed in the PRESERVED marker beside it"
    )]
    Merge {
        workdir: std::path::PathBuf,
        preserved_upper: std::path::PathBuf,
        #[source]
        source: crate::error::BranchError,
    },

    /// The commit phase never ran to completion because the runtime was shut
    /// down under it. Unlike every other variant this one cannot say what state
    /// the workdir and the upper are in: the phase may not have started at all,
    /// in which case the change set was reclaimed with the branch.
    #[error("transaction: the commit did not run to completion: {0}")]
    CommitAbandoned(String),
}

impl TxnError {
    /// Process exit code for this failure, keeping the RFC's channels apart:
    /// configuration (78), stage driver (70), commit (74), conflict (75).
    ///
    /// The values are the conventional `sysexits.h` names — `EX_CONFIG`,
    /// `EX_SOFTWARE`, `EX_IOERR`, `EX_TEMPFAIL`. `EX_TEMPFAIL` for a conflict is
    /// the one that carries meaning beyond "distinct": it says retry.
    ///
    /// These do NOT distinguish themselves from a stage's own exit code — a
    /// child is free to exit 75 — so a caller that needs to tell a commit
    /// failure from a stage failure takes it from the `Result`, not the number.
    pub fn exit_code(&self) -> i32 {
        match self {
            TxnError::Invalid(_) => 78,
            TxnError::Stage { .. } => 70,
            TxnError::Branch { .. }
            | TxnError::CommitLock { .. }
            | TxnError::Merge { .. }
            | TxnError::CommitAbandoned(_) => 74,
            TxnError::Conflict { .. } => 75,
        }
    }
}

impl From<TxnError> for SandlockError {
    /// Flatten into the crate-wide error for callers that do not care about the
    /// channel — but not into one that says something false. A misconfigured
    /// transaction stays a `Sandbox` error; a stage that could not be driven
    /// keeps its own `SandlockError` verbatim; and the commit channel becomes a
    /// `Branch` error, because that is what it is — a disposition of the shared
    /// COW branch that could not be carried out. `Child` would claim a child
    /// process failed, which is the abort channel and never reaches here.
    ///
    /// The commit channel keeps its rendered message rather than only its
    /// `BranchError` source (which `Conflict` does not even have): the message
    /// names the preserved upper, and that path is the one thing a caller cannot
    /// reconstruct from anything else.
    fn from(e: TxnError) -> Self {
        match e {
            TxnError::Invalid(m) => SandlockError::Sandbox(SandboxError::Invalid(m)),
            TxnError::Stage { source, .. } => source,
            other => SandlockError::Runtime(SandboxRuntimeError::Branch(
                crate::error::BranchError::Operation(other.to_string()),
            )),
        }
    }
}

/// Why [`acquire_commit_lock`] gave up, so the caller can tell contention (a
/// conflict, worth retrying) from a broken workdir.
#[derive(Debug)]
enum LockFailure {
    /// The lock was held by someone else for the whole wait.
    Contended(Duration),
    /// The workdir could not be opened, or `flock` failed for a reason other
    /// than contention.
    Io(std::io::Error),
}

// ============================================================
// Outcome
// ============================================================

/// Why a transaction did not commit, having run and left the workdir untouched.
/// A transaction that could not be carried out at all is a [`TxnError`] instead.
///
/// `#[non_exhaustive]`: these are the reasons RFC #65 Phase 1 can produce and
/// later phases add to them. Match with a `_` arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AbortReason {
    /// Stage `index` (0-based, in declaration order) did not exit 0. Later
    /// stages were not run.
    StageFailed { index: usize, status: ExitStatus },
    /// The stage phase exceeded the transaction's timeout. The in-flight stage
    /// was killed; `TxnOutcome::stages` holds the stages that had completed.
    TimedOut,
    /// [`Transaction::dry_run`] completed: every stage succeeded and the upper
    /// was discarded on purpose rather than merged.
    DryRun,
}

impl std::fmt::Display for AbortReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbortReason::StageFailed { index, status } => {
                write!(f, "stage {index} did not exit cleanly: {status:?}")
            }
            AbortReason::TimedOut => write!(f, "the transaction timed out"),
            AbortReason::DryRun => write!(f, "dry run: changes were reported, not committed"),
        }
    }
}

/// Outcome of [`Transaction::run`] / [`Transaction::dry_run`].
#[derive(Debug, Clone)]
#[must_use = "a transaction can finish without committing; inspect `committed`"]
pub struct TxnOutcome {
    /// True if every stage exited 0 and the shared upper was merged into the
    /// workdir. False if any stage failed, the transaction timed out, or this
    /// was a dry run — in all of which the workdir is byte-identical to before.
    pub committed: bool,
    /// Per-stage results in execution order, holding every stage that ran —
    /// including on an abort, and including the partial run recorded before a
    /// timeout cancelled the in-flight stage.
    ///
    /// **`stdout` and `stderr` are always `None` here, by construction.** Stages
    /// inherit the parent's stdio (see the [module docs](self)), so their output
    /// has already gone to the parent's own fd 1/2 and there is nothing to
    /// capture. This is asymmetric with `Pipeline::run`, which pipes the last
    /// stage and returns its bytes. A caller that needs a failing stage's output
    /// has to arrange for it — redirect inside the stage command, or read the
    /// parent's stream — because [`AbortReason::StageFailed`] carries an index
    /// and a status and nothing else.
    pub stages: Vec<RunResult>,
    /// The filesystem changes the shared upper held at the end of the run, i.e.
    /// what the commit merged (or, when not committed, what was discarded).
    /// Captured from the branch before it is disposed of.
    pub changes: Vec<crate::dry_run::Change>,
    /// Why the transaction did not commit; `None` when it did.
    pub abort_reason: Option<AbortReason>,
}

impl TxnOutcome {
    /// Process exit code for this outcome, for a caller that fronts a
    /// transaction with a command-line tool.
    ///
    /// A committed transaction and a completed dry run are 0 — both did what
    /// was asked. A stage failure reports that stage's own status, under the
    /// shell convention (a signalled child is `128 + signal`), so the code a
    /// caller sees is the code the failing command produced. A timeout is 124,
    /// as `timeout(1)` reports it.
    ///
    /// The commit channel is not represented here at all: it is
    /// [`TxnError::exit_code`].
    pub fn exit_code(&self) -> i32 {
        match &self.abort_reason {
            None | Some(AbortReason::DryRun) => 0,
            Some(AbortReason::TimedOut) => 124,
            Some(AbortReason::StageFailed { status, .. }) => match status {
                ExitStatus::Code(c) => *c,
                ExitStatus::Signal(s) => 128 + *s,
                ExitStatus::Killed => 128 + libc::SIGKILL,
                ExitStatus::Timeout => 124,
            },
        }
    }
}

// ============================================================
// Validation
// ============================================================

/// Reject stage configurations that can't participate in a transaction. The
/// transaction owns the single shared upper and the single commit/abort, so each
/// stage must set the same workdir, keep the supervisor, and not carry its own
/// branch action.
///
/// These are configuration errors, reported as [`TxnError::Invalid`] so a
/// misconfigured transaction is distinguishable from a child-process failure.
fn validate_txn_stages(stages: &[Stage]) -> Result<(), TxnError> {
    fn reject(msg: impl Into<String>) -> TxnError {
        TxnError::Invalid(msg.into())
    }

    if stages.len() < 2 {
        return Err(reject("transaction requires at least 2 stages"));
    }

    let base = &stages[0].sandbox;
    let base_wd = base.workdir.as_ref().ok_or_else(|| {
        reject("transaction: stage 0 has no workdir; every stage must set the shared transaction workdir")
    })?;
    let base_max_disk = base.max_disk.map(|b| b.0).unwrap_or(0);

    for (i, stage) in stages.iter().enumerate() {
        let sb = &stage.sandbox;
        let wd = sb.workdir.as_ref().ok_or_else(|| {
            reject(format!("transaction: stage {i} has no workdir; every stage must set the shared transaction workdir"))
        })?;
        if wd != base_wd {
            return Err(reject(format!(
                "transaction: stages must share one workdir (stage 0 = {}, stage {i} = {})",
                base_wd.display(),
                wd.display()
            )));
        }
        if sb.no_supervisor {
            return Err(reject(format!(
                "transaction: stage {i} has no_supervisor=true; transactions require the COW supervisor"
            )));
        }
        // All stages overlay ONE shared upper, so per-stage COW storage/quota and
        // chroot can't each take effect — reject a stage that sets them differently
        // (or at all, for chroot) rather than silently using only stage 0's.
        if sb.chroot.is_some() {
            return Err(reject(format!(
                "transaction: stage {i} sets chroot, which is unsupported with a shared COW workdir"
            )));
        }
        if sb.fs_storage != base.fs_storage || sb.max_disk.map(|b| b.0).unwrap_or(0) != base_max_disk {
            return Err(reject(format!(
                "transaction: stage {i} sets a different fs_storage/max_disk; all stages share one COW upper, so these must match stage 0"
            )));
        }
        // The builder leaves both actions at `BranchAction::Commit` by default
        // (`unwrap_or_default()`); anything else is an explicit per-stage choice
        // that conflicts with the transaction owning commit/abort.
        if sb.on_exit != crate::sandbox::BranchAction::Commit
            || sb.on_error != crate::sandbox::BranchAction::Commit
        {
            return Err(reject(format!(
                "transaction: stage {i} sets on_exit/on_error, which conflicts with a transaction (the transaction owns commit/abort) — leave them at their defaults"
            )));
        }
    }
    Ok(())
}

// ============================================================
// Coordinator
// ============================================================

/// Create the shared COW branch, drive the stages sequentially over it, then
/// commit-all or abort-all. The branch lives here (outside the driven future)
/// so a timeout that cancels the stage loop can still abort cleanly.
async fn run_txn(
    stages: Vec<Stage>,
    timeout: Option<Duration>,
    disposition: Disposition,
    commit_lock_wait: Duration,
) -> Result<TxnOutcome, TxnError> {
    // All stages share the validated workdir; take COW storage/quota from the
    // first stage (they overlay the same lower).
    let base = &stages[0].sandbox;
    let workdir = base.workdir.clone().expect("validated: stage 0 has a workdir");
    let storage = base.fs_storage.clone();
    let max_disk = base.max_disk.map(|b| b.0).unwrap_or(0);

    let branch = crate::cow::seccomp::SeccompCowBranch::create(&workdir, storage.as_deref(), max_disk)
        .map_err(|source| TxnError::Branch { workdir: workdir.clone(), source })?;
    let upper_dir = branch.upper_dir().to_path_buf();

    let mut cow_state = crate::seccomp::state::CowState::new();
    cow_state.branch = Some(branch);
    let state = std::sync::Arc::new(tokio::sync::Mutex::new(cow_state));
    let shared = crate::sandbox::SharedCow { state: std::sync::Arc::clone(&state), upper_dir: upper_dir.clone() };

    // Stage results are accumulated through a handle the coordinator also holds,
    // so a timeout that cancels the driver future does not take the completed
    // stages' results down with it.
    let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::<RunResult>::new()));
    let drive = drive_txn_stages(stages, shared, std::sync::Arc::clone(&results));
    let driven: Result<Option<AbortReason>, TxnError> = match timeout {
        Some(dur) => match tokio::time::timeout(dur, drive).await {
            Ok(r) => r,
            Err(_) => Ok(Some(AbortReason::TimedOut)),
        },
        None => drive.await,
    };

    // Finalize the shared upper in EVERY case — commit only on a clean full run,
    // otherwise discard — before propagating any driver error, so a mid-loop
    // failure never leaves the upper dangling. (`SeccompCowBranch`'s Drop is a
    // further backstop for a panic between here and the disposition.)
    // Take the branch out from under the async mutex first, then move the owned
    // value onto a blocking thread: the merge must not run while holding the
    // guard, must not run on an executor worker, and must not be droppable by a
    // cancellation (see `finish_branch`).
    let taken = { state.lock().await.branch.take() };
    let (mut reason, drive_err) = match driven {
        Ok(rsn) => (rsn, None),
        Err(e) => (None, Some(e)),
    };
    let all_ok = reason.is_none() && drive_err.is_none();

    let mut changes = Vec::new();
    let committed = match taken {
        Some(branch) => {
            let want_commit = all_ok && disposition == Disposition::Commit;
            let wd = workdir.clone();
            let handle = tokio::task::spawn_blocking(move || {
                finish_branch(branch, &wd, commit_lock_wait, want_commit)
            });
            let finished = match handle.await {
                Ok(f) => f,
                Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
                Err(join) => return Err(TxnError::CommitAbandoned(join.to_string())),
            };
            changes = finished.changes;
            match finished.commit {
                Some(Ok(())) => true,
                Some(Err(CommitFailure::Lock(LockFailure::Contended(waited)))) => {
                    return Err(TxnError::Conflict { workdir, waited, preserved_upper: upper_dir })
                }
                Some(Err(CommitFailure::Lock(LockFailure::Io(source)))) => {
                    return Err(TxnError::CommitLock {
                        workdir,
                        preserved_upper: upper_dir,
                        source,
                    })
                }
                Some(Err(CommitFailure::Merge(source))) => {
                    return Err(TxnError::Merge { workdir, preserved_upper: upper_dir, source })
                }
                // The upper was discarded rather than merged: a dry run, or a
                // run that aborted.
                None => {
                    if all_ok {
                        reason = Some(AbortReason::DryRun);
                    }
                    false
                }
            }
        }
        // Unreachable: `create` above always yields a branch and a transactional
        // stage never takes it out of the shared state. Treat a future violation
        // of that invariant as "nothing was committed" rather than reporting a
        // commit that did not happen.
        None => false,
    };
    if let Some(e) = drive_err {
        return Err(e);
    }

    let stages = std::sync::Arc::try_unwrap(results)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_else(|arc| arc.lock().map(|g| g.clone()).unwrap_or_default());

    Ok(TxnOutcome {
        committed,
        stages,
        changes,
        abort_reason: if committed { None } else { reason },
    })
}

/// Why the commit phase could not publish the change set. Turned into a
/// [`TxnError`] by the caller, which holds the workdir and upper paths the
/// message names.
enum CommitFailure {
    Lock(LockFailure),
    Merge(crate::error::BranchError),
}

/// What the commit phase did with the shared upper.
struct Finished {
    /// The change set the upper held, read before it was disposed of.
    changes: Vec<crate::dry_run::Change>,
    /// `None` when the upper was discarded rather than merged (a dry run, or an
    /// aborted run); otherwise the result of the commit.
    commit: Option<Result<(), CommitFailure>>,
}

/// Read the shared upper's change set and dispose of it — the entire blocking
/// half of a transaction, run on a blocking thread.
///
/// Both halves are unbounded in the caller's data: `changes()` walks the whole
/// upper, and `commit()` walks it again copying file-by-file and fsyncing
/// directories. Neither may run on an executor worker, and the commit half holds
/// a cross-process `flock` while it does.
///
/// The branch is **moved in**, and that is what makes the commit phase
/// uncancellable. Dropping the `run()` future — a `tokio::time::timeout` around
/// it, a `select!` on shutdown — drops the `JoinHandle`, which detaches this task
/// rather than stopping it, so the owned branch is never dropped in
/// `BranchState::Open` by a cancellation and the change set of a run whose stages
/// all succeeded is always either published or preserved. Dropping the branch at
/// the end of this function is right in every case: `commit()` leaves it
/// `Finished` on success and `Preserved` on failure, and the lock path preserves
/// it explicitly.
fn finish_branch(
    mut branch: crate::cow::seccomp::SeccompCowBranch,
    workdir: &std::path::Path,
    commit_lock_wait: Duration,
    commit: bool,
) -> Finished {
    // The branch is about to be disposed of, so read the change set first: after
    // a commit or an abort the upper is gone and there is nothing left to report.
    let changes = branch.changes().unwrap_or_default();
    if !commit {
        let _ = branch.abort();
        return Finished { changes, commit: None };
    }

    // Serialize the merge against any other transaction committing into this
    // workdir. commit() rewrites the workdir file-by-file, so two merges
    // interleaving would tear it. This is mutual exclusion between merges, NOT
    // serializable isolation: a transaction that snapshotted before another one
    // committed still merges over that result (last writer wins per file). The
    // lock is also scoped to transactions — a plain Sandbox committing its own
    // branch into the same workdir does not take it.
    let lock = match acquire_commit_lock(workdir, commit_lock_wait) {
        Ok(l) => l,
        Err(f) => {
            // Every stage exited 0, so the upper holds a full, mergeable change
            // set that only failed to be published. Returning here would
            // otherwise drop an `Open` branch and reclaim it — losing the work of
            // a run that did nothing wrong. Hand the storage over instead, for
            // the caller to name in the error.
            branch.preserve(crate::cow::seccomp::PreserveReason::CommitDeferred);
            return Finished { changes, commit: Some(Err(CommitFailure::Lock(f))) };
        }
    };
    // `commit()` preserves the upper itself when it fails partway — it marks the
    // branch before touching the workdir.
    let merged = branch.commit().map_err(CommitFailure::Merge);
    drop(lock); // release the workdir lock after the merge
    Finished { changes, commit: Some(merged) }
}

/// Take an exclusive lock on the workdir, waiting up to `deadline_after` for a
/// concurrent commit merge to release it. `flock` has no timed variant, so this
/// is a bounded poll over the non-blocking form.
///
/// Waiting rather than failing fast is deliberate: a transaction that has run
/// every stage successfully should publish its work, not discard it because
/// another merge happened to be in flight for a few milliseconds. Expiring the
/// wait does not discard it either — the caller preserves the upper.
///
/// Blocking, and only ever called from [`finish_branch`] on a blocking thread:
/// the merge it guards is blocking too, so making the wait cancellable would buy
/// nothing and would put the branch back on a droppable await.
fn acquire_commit_lock(
    workdir: &std::path::Path,
    deadline_after: Duration,
) -> Result<std::fs::File, LockFailure> {
    acquire_commit_lock_polling(workdir, deadline_after, std::thread::sleep)
}

/// [`acquire_commit_lock`] with the poll sleep injected, so a test can observe
/// how many times — if at all — the loop actually waited.
fn acquire_commit_lock_polling(
    workdir: &std::path::Path,
    deadline_after: Duration,
    mut sleep: impl FnMut(Duration),
) -> Result<std::fs::File, LockFailure> {
    let lock = std::fs::File::open(workdir).map_err(LockFailure::Io)?;
    let deadline = std::time::Instant::now() + deadline_after;
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(lock);
        }
        let err = std::io::Error::last_os_error();
        // EWOULDBLOCK (== EAGAIN on Linux) means another commit holds the lock.
        // Any other errno is a real failure and must not be retried.
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(LockFailure::Io(err));
        }
        if std::time::Instant::now() >= deadline {
            return Err(LockFailure::Contended(deadline_after));
        }
        sleep(COMMIT_LOCK_POLL);
    }
}

/// Run each stage to completion in order over the shared upper, with no
/// inter-stage pipes (all stdio inherited). Stops at the first non-zero exit:
/// under a sequential shared-workspace model stage N+1's inputs do not exist if
/// stage N failed, and the transaction is going to abort regardless.
///
/// Each result is published to `results` as soon as its stage finishes, so the
/// coordinator still has them if this future is cancelled by a timeout.
async fn drive_txn_stages(
    stages: Vec<Stage>,
    shared: crate::sandbox::SharedCow,
    results: std::sync::Arc<std::sync::Mutex<Vec<RunResult>>>,
) -> Result<Option<AbortReason>, TxnError> {
    for (i, stage) in stages.into_iter().enumerate() {
        let at = |source: SandlockError| TxnError::Stage { index: i, source };
        let cmd_refs: Vec<&str> = stage.args.iter().map(|s| s.as_str()).collect();
        let mut sb = stage.sandbox.with_name(format!("txn-stage-{i}"));
        sb.set_shared_cow(shared.clone()).map_err(at)?;
        sb.create_with_io(&cmd_refs, None, None, None).await.map_err(at)?;
        sb.start().map_err(at)?;
        let result = sb.wait().await.map_err(at)?;

        let status = result.exit_status.clone();
        if let Ok(mut guard) = results.lock() {
            guard.push(result);
        }
        if !matches!(status, ExitStatus::Code(0)) {
            return Ok(Some(AbortReason::StageFailed { index: i, status }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{BranchAction, ByteSize, Sandbox};
    use std::os::unix::io::AsRawFd;

    // ------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------

    /// A stage that satisfies every cross-stage rule: it sets the shared
    /// workdir and nothing else the transaction owns. The command is never run —
    /// every validation test below is rejected (or accepted) before `run_txn`
    /// touches a cage.
    fn ok_stage(workdir: &std::path::Path) -> Stage {
        Stage::new(&Sandbox::builder().workdir(workdir).build().unwrap(), &["true"])
    }

    /// The rejection message of a stage set, or `None` if it validates.
    fn rejection(stages: &[Stage]) -> Option<String> {
        match validate_txn_stages(stages) {
            Ok(()) => None,
            Err(TxnError::Invalid(m)) => Some(m),
            Err(other) => panic!("validation must only ever produce Invalid, got: {other:?}"),
        }
    }

    /// Both per-stage branch actions must be left at `Commit`, and the check is
    /// on the VALUE, not on whether the builder was called: a stage that spells
    /// out `on_exit = commit` — what a TOML profile writing the default looks
    /// like — is accepted, while every other combination of the two fields is
    /// rejected.
    ///
    /// This walks all nine cells because the two halves of the check are
    /// separately deletable. Narrowing it to `on_exit` alone leaves the
    /// pre-existing `test_txn_rejects_branch_action` green, so nothing has been
    /// guarding `on_error` — and `on_error(Keep)` is exactly what a caller who
    /// wants forensics on a failed stage reaches for, which would preserve the
    /// SHARED upper behind the coordinator's back.
    ///
    /// The rejection message is pinned too. It says "leave them at their
    /// defaults" without naming the default, which is `Commit`.
    #[test]
    fn per_stage_branch_actions_are_rejected_unless_both_are_the_default() {
        let wd = tempfile::tempdir().unwrap();
        let actions = [BranchAction::Commit, BranchAction::Abort, BranchAction::Keep];

        for on_exit in &actions {
            for on_error in &actions {
                let sb = Sandbox::builder()
                    .workdir(wd.path())
                    .on_exit(on_exit.clone())
                    .on_error(on_error.clone())
                    .build()
                    .unwrap();
                let stages = vec![Stage::new(&sb, &["true"]), ok_stage(wd.path())];
                let got = rejection(&stages);

                if *on_exit == BranchAction::Commit && *on_error == BranchAction::Commit {
                    assert_eq!(
                        got, None,
                        "the default pair must be accepted even when set explicitly, \
                         but on_exit={on_exit:?}/on_error={on_error:?} was rejected"
                    );
                    continue;
                }
                let msg = got.unwrap_or_else(|| {
                    panic!(
                        "on_exit={on_exit:?}/on_error={on_error:?} is a per-stage branch action \
                         and must be rejected, but the transaction validated"
                    )
                });
                assert!(
                    msg.contains("stage 0 sets on_exit/on_error")
                        && msg.contains("leave them at their defaults"),
                    "on_exit={on_exit:?}/on_error={on_error:?} must be rejected as a branch-action \
                     conflict naming the stage, got: {msg}"
                );
            }
        }
    }

    /// Every guardrail that can fire at all must fire when the offending stage
    /// is stage 0.
    ///
    /// Stage 0 is the baseline the other stages are compared against, so it is
    /// the index a refactor is most likely to special-case. Making the loop
    /// `continue` on `i == 0` leaves every pre-existing `test_txn_rejects_*`
    /// integration test green, because each one puts its violation on the
    /// second stage.
    ///
    /// The workdir and fs_storage/max_disk rules are absent here on purpose:
    /// they compare a stage against stage 0, so they cannot fire AT stage 0.
    #[test]
    fn every_guardrail_that_can_fire_at_stage_zero_does() {
        let wd = tempfile::tempdir().unwrap();
        let chroot = tempfile::tempdir().unwrap();
        let cases: [(&str, Sandbox); 4] = [
            (
                "has no_supervisor=true",
                Sandbox::builder().workdir(wd.path()).no_supervisor(true).build().unwrap(),
            ),
            (
                "sets chroot",
                Sandbox::builder().workdir(wd.path()).chroot(chroot.path()).build().unwrap(),
            ),
            (
                "sets on_exit/on_error",
                Sandbox::builder()
                    .workdir(wd.path())
                    .on_exit(BranchAction::Abort)
                    .build()
                    .unwrap(),
            ),
            (
                "sets on_exit/on_error",
                Sandbox::builder()
                    .workdir(wd.path())
                    .on_error(BranchAction::Keep)
                    .build()
                    .unwrap(),
            ),
        ];

        for (fragment, offender) in cases {
            let stages = vec![Stage::new(&offender, &["true"]), ok_stage(wd.path())];
            let msg = rejection(&stages).unwrap_or_else(|| {
                panic!("a stage 0 that {fragment} must be rejected, but the transaction validated")
            });
            assert!(
                msg.contains(&format!("stage 0 {fragment}")),
                "the violation is at stage 0 and must be reported there, got: {msg}"
            );
        }
    }

    /// A transaction whose stages set no workdir at all is an `Invalid` error,
    /// not a panic — through both entry points.
    ///
    /// `run_txn` reads stage 0's workdir with `.expect("validated: stage 0 has a
    /// workdir")`, so the validator is the only thing standing between a
    /// misconfigured caller and a panic inside a supervisor. Both `run` and
    /// `dry_run` must validate before anything runs.
    #[tokio::test]
    async fn a_transaction_with_no_workdir_is_an_error_from_both_entry_points_not_a_panic() {
        let stageless = || {
            let sb = Sandbox::builder().build().unwrap();
            vec![Stage::new(&sb, &["true"]), Stage::new(&sb, &["true"])]
        };

        for (entry, err) in [
            ("run", Transaction::new(stageless()).run(None).await.unwrap_err()),
            ("dry_run", Transaction::new(stageless()).dry_run(None).await.unwrap_err()),
        ] {
            assert!(
                matches!(&err, TxnError::Invalid(m) if m.contains("stage 0 has no workdir")),
                "{entry} must reject a workdir-less transaction as a configuration error, got: {err:?}"
            );
        }
    }

    /// An unset `max_disk` and `max_disk = 0` are the SAME quota (both mean
    /// unlimited), so mixing them across stages is accepted — while a stage that
    /// really asks for a different quota is rejected.
    ///
    /// The whole quota half of that check is deletable on its own: dropping the
    /// `max_disk` comparison and keeping only `fs_storage` leaves every other
    /// test green, and the transaction would then silently run every stage under
    /// stage 0's quota while a stage's own limit was ignored.
    #[test]
    fn an_unset_max_disk_equals_a_zero_max_disk_but_a_real_one_must_match() {
        let wd = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let with = |disk: Option<u64>| {
            let mut b = Sandbox::builder().workdir(wd.path()).fs_storage(storage.path());
            if let Some(d) = disk {
                b = b.max_disk(ByteSize(d));
            }
            Stage::new(&b.build().unwrap(), &["true"])
        };

        assert_eq!(
            rejection(&[with(None), with(Some(0))]),
            None,
            "an unset quota and a zero quota both mean unlimited and must be interchangeable"
        );
        let msg = rejection(&[with(Some(4096)), with(Some(8192))])
            .expect("two stages asking for different quotas over one shared upper must be rejected");
        assert!(
            msg.contains("stage 1 sets a different fs_storage/max_disk"),
            "a differing quota must be reported as the fs_storage/max_disk conflict, got: {msg}"
        );
        let msg = rejection(&[with(None), with(Some(4096))])
            .expect("a real quota does not match an unset one and must be rejected");
        assert!(
            msg.contains("stage 1 sets a different fs_storage/max_disk"),
            "a quota against an unset one must be reported the same way, got: {msg}"
        );
    }

    /// The shared workdir is compared LEXICALLY, by path components: spellings
    /// that differ only in redundant separators or a `.` component are the same
    /// workdir, while a `..` component or a symlink naming the same real
    /// directory are not.
    ///
    /// The symlink case is the one that matters, and it is an asymmetry rather
    /// than a bug to fix here: `SeccompCowBranch::create` canonicalizes, so the
    /// branch would treat the two spellings as one workdir while the validator
    /// does not. Rejecting is the safe side of that disagreement — the stages
    /// would otherwise disagree with each other about which paths the COW layer
    /// intercepts.
    #[test]
    fn the_shared_workdir_is_compared_by_path_components_not_by_target() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("wd");
        std::fs::create_dir(&real).unwrap();
        let alias = base.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        let named = |p: std::path::PathBuf| {
            Stage::new(&Sandbox::builder().workdir(p).build().unwrap(), &["true"])
        };
        let same = [
            std::path::PathBuf::from(format!("{}/", real.display())),
            real.join("."),
        ];
        for spelling in same {
            assert_eq!(
                rejection(&[named(real.clone()), named(spelling.clone())]),
                None,
                "{} names the same workdir as {} and must be accepted",
                spelling.display(),
                real.display()
            );
        }
        for spelling in [alias.clone(), real.join("..").join("wd")] {
            let msg = rejection(&[named(real.clone()), named(spelling.clone())]).unwrap_or_else(
                || {
                    panic!(
                        "{} is not the same path as {} and must be rejected",
                        spelling.display(),
                        real.display()
                    )
                },
            );
            assert!(
                msg.contains("stages must share one workdir"),
                "a differing workdir spelling must be reported as the shared-workdir conflict, \
                 got: {msg}"
            );
        }
    }

    /// `chroot` and `no_supervisor` are rejected ABSOLUTELY — even when every
    /// stage sets them identically — while `workdir` and `fs_storage`/`max_disk`
    /// are only required to AGREE, so a value shared by every stage is accepted.
    ///
    /// The two kinds of rule sit three lines apart in the same loop and either
    /// could be "simplified" into the other without a test noticing: comparing
    /// `chroot` against stage 0's would let a fully-chrooted transaction run,
    /// and rejecting any `fs_storage` at all would break the ordinary case of
    /// pointing every stage at one storage dir.
    #[test]
    fn chroot_and_no_supervisor_are_absolute_while_workdir_and_storage_only_have_to_agree() {
        let wd = tempfile::tempdir().unwrap();
        let chroot = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();

        let chrooted =
            Sandbox::builder().workdir(wd.path()).chroot(chroot.path()).build().unwrap();
        let msg = rejection(&[
            Stage::new(&chrooted, &["true"]),
            Stage::new(&chrooted, &["true"]),
        ])
        .expect("chroot is unsupported with a shared COW workdir even when every stage sets it");
        assert!(
            msg.contains("stage 0 sets chroot"),
            "a chroot every stage sets must still be rejected, at the first stage, got: {msg}"
        );

        let unsupervised =
            Sandbox::builder().workdir(wd.path()).no_supervisor(true).build().unwrap();
        let msg = rejection(&[
            Stage::new(&unsupervised, &["true"]),
            Stage::new(&unsupervised, &["true"]),
        ])
        .expect("a transaction cannot run without the COW supervisor, however many stages agree");
        assert!(
            msg.contains("stage 0 has no_supervisor=true"),
            "no_supervisor must be rejected even when shared, at the first stage, got: {msg}"
        );

        let shared = Sandbox::builder()
            .workdir(wd.path())
            .fs_storage(storage.path())
            .max_disk(ByteSize(4096))
            .build()
            .unwrap();
        assert_eq!(
            rejection(&[Stage::new(&shared, &["true"]), Stage::new(&shared, &["true"])]),
            None,
            "one storage dir and one quota named by every stage is the ordinary configuration \
             and must be accepted"
        );
    }

    /// Which problem a caller is told about is fixed: the LOWEST offending stage
    /// wins across stages, and within one stage the order is workdir →
    /// no_supervisor → chroot → fs_storage/max_disk → on_exit/on_error.
    ///
    /// This is user-visible: the message is what a caller shows, so reordering
    /// the checks silently changes which of several real problems gets reported
    /// and which stays hidden until the first one is fixed.
    #[test]
    fn the_first_offending_stage_and_the_first_broken_rule_within_it_are_what_get_reported() {
        let wd = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let chroot = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();

        // Across stages: stage 1 breaks chroot, stage 2 breaks no_supervisor.
        // Stage 1 is reported even though the rule it breaks is checked later.
        let s1 = Sandbox::builder().workdir(wd.path()).chroot(chroot.path()).build().unwrap();
        let s2 = Sandbox::builder().workdir(wd.path()).no_supervisor(true).build().unwrap();
        let msg = rejection(&[ok_stage(wd.path()), Stage::new(&s1, &["true"]), Stage::new(&s2, &["true"])])
            .expect("two offending stages must still be rejected");
        assert!(
            msg.contains("stage 1 sets chroot"),
            "the lowest offending stage index wins, got: {msg}"
        );

        // Within one stage: peel the violations off in check order and assert
        // each successive rule is the one reported.
        let all = Sandbox::builder()
            .workdir(other.path())
            .no_supervisor(true)
            .chroot(chroot.path())
            .fs_storage(storage.path())
            .on_exit(BranchAction::Keep)
            .build()
            .unwrap();
        let peeled = [
            ("stages must share one workdir", all.clone()),
            ("stage 1 has no_supervisor=true", {
                let mut s = all.clone();
                s.workdir = Some(wd.path().to_path_buf());
                s
            }),
            ("stage 1 sets chroot", {
                let mut s = all.clone();
                s.workdir = Some(wd.path().to_path_buf());
                s.no_supervisor = false;
                s
            }),
            ("stage 1 sets a different fs_storage/max_disk", {
                let mut s = all.clone();
                s.workdir = Some(wd.path().to_path_buf());
                s.no_supervisor = false;
                s.chroot = None;
                s
            }),
            ("stage 1 sets on_exit/on_error", {
                let mut s = all.clone();
                s.workdir = Some(wd.path().to_path_buf());
                s.no_supervisor = false;
                s.chroot = None;
                s.fs_storage = None;
                s
            }),
        ];
        for (expected, offender) in peeled {
            let msg = rejection(&[ok_stage(wd.path()), Stage::new(&offender, &["true"])])
                .unwrap_or_else(|| panic!("expected a rejection naming {expected:?}"));
            assert!(
                msg.contains(expected),
                "checks must run in a fixed order; expected {expected:?}, got: {msg}"
            );
        }
    }

    // ------------------------------------------------------------
    // Error channels
    // ------------------------------------------------------------

    /// Which of the RFC's channels a failure belongs to.
    #[derive(Debug, PartialEq, Eq)]
    enum Channel {
        Config,
        StageDriver,
        Commit,
        Conflict,
    }

    /// Classify a failure by matching EXHAUSTIVELY, so that the table-driven
    /// tests below cannot drift into asserting over a subset of the type.
    ///
    /// `#[non_exhaustive]` has no effect inside the defining crate, so adding a
    /// `TxnError` variant stops this file compiling. `TxnError::exit_code` is
    /// exhaustive too and would already have caught that; what this adds is the
    /// channel itself, which `From<TxnError> for SandlockError` decides in a
    /// catch-all `other` arm that would absorb a new variant silently.
    fn channel_of(e: &TxnError) -> Channel {
        match e {
            TxnError::Invalid(_) => Channel::Config,
            TxnError::Stage { .. } => Channel::StageDriver,
            TxnError::Branch { .. }
            | TxnError::CommitLock { .. }
            | TxnError::Merge { .. }
            | TxnError::CommitAbandoned(_) => Channel::Commit,
            TxnError::Conflict { .. } => Channel::Conflict,
        }
    }

    /// One of every `TxnError` variant, for table-driven tests over the whole
    /// error type.
    fn one_of_every_txn_error() -> Vec<TxnError> {
        vec![
            TxnError::Invalid("bad stages".into()),
            TxnError::Stage {
                index: 0,
                source: SandlockError::Runtime(SandboxRuntimeError::NotRunning),
            },
            TxnError::Branch {
                workdir: "/wd".into(),
                source: crate::error::BranchError::Operation("create upper".into()),
            },
            TxnError::Conflict {
                workdir: "/wd".into(),
                waited: Duration::from_secs(1),
                preserved_upper: "/st/upper".into(),
            },
            TxnError::CommitLock {
                workdir: "/wd".into(),
                preserved_upper: "/st/upper".into(),
                source: std::io::Error::other("flock"),
            },
            TxnError::Merge {
                workdir: "/wd".into(),
                preserved_upper: "/st/upper".into(),
                source: crate::error::BranchError::Operation("copy".into()),
            },
            TxnError::CommitAbandoned("runtime shutting down".into()),
        ]
    }

    /// Every variant reports the EXACT `sysexits.h` code its channel is
    /// documented to use: 78 config, 70 stage driver, 74 commit, 75 conflict.
    ///
    /// The sibling test pins the four codes apart and this one pins their
    /// values, which is a different property: renumbering config from 78 to 64
    /// keeps every code distinct and every existing assertion green, while a
    /// caller's `case 78)` stops matching.
    #[test]
    fn every_txn_error_variant_reports_the_exact_exit_code_of_its_channel() {
        for e in one_of_every_txn_error() {
            let want = match channel_of(&e) {
                Channel::Config => 78,
                Channel::StageDriver => 70,
                Channel::Commit => 74,
                Channel::Conflict => 75,
            };
            assert_eq!(
                e.exit_code(),
                want,
                "{e:?} is in channel {:?} and must report {want}",
                channel_of(&e)
            );
        }
    }

    /// Flattening into `SandlockError` keeps, for every commit-channel variant,
    /// the phrase that says what state the workdir and the change set are in.
    ///
    /// The rendered message is the ONLY thing that survives the flatten — the
    /// typed fields do not — so a variant whose text is dropped or replaced
    /// leaves a caller unable to tell "nothing ran" from "the workdir may be
    /// half merged". The sibling flatten test asserts the preserved upper is
    /// kept, which the two variants that have no preserved upper cannot carry.
    #[test]
    fn flattening_a_commit_channel_failure_keeps_the_phrase_that_names_the_workdir_state() {
        let tokens = [
            ("failed to create the shared COW branch over /wd", "nothing ran"),
            ("gave up after", "contended, retry"),
            ("could not take the commit lock on /wd", "lock broken"),
            ("may be partially merged", "torn workdir"),
            ("did not run to completion", "unknown"),
        ];
        let commit_channel: Vec<TxnError> = one_of_every_txn_error()
            .into_iter()
            .filter(|e| matches!(channel_of(e), Channel::Commit | Channel::Conflict))
            .collect();
        assert_eq!(
            commit_channel.len(),
            tokens.len(),
            "every commit-channel variant needs a phrase pinned here"
        );

        for (e, (token, meaning)) in commit_channel.into_iter().zip(tokens) {
            let debug = format!("{e:?}");
            let flat: SandlockError = e.into();
            let rendered = flat.to_string();
            assert!(
                rendered.contains(token),
                "{debug} means {meaning:?}, so flattening must keep {token:?}, got: {rendered}"
            );
        }
    }

    /// A stage that exits with one of the transaction channel's own numbers has
    /// that number reported back verbatim.
    ///
    /// The numbers deliberately collide — a child is free to exit 75 — and the
    /// documented way to tell the channels apart is the `Result`, not the code.
    /// "Fixing" the collision by remapping a child's code would make the outcome
    /// report a number the command never produced.
    #[test]
    fn a_stage_exit_code_that_collides_with_the_commit_channel_is_reported_verbatim() {
        for code in [70, 74, 75, 78] {
            let outcome = aborted(AbortReason::StageFailed {
                index: 0,
                status: ExitStatus::Code(code),
            });
            assert_eq!(
                outcome.exit_code(),
                code,
                "a stage that exited {code} must report {code}, not a remapped transaction code"
            );
        }
    }

    /// Each `AbortReason` renders its own sentence, and a stage failure names
    /// the stage and its status.
    ///
    /// `Display` is the only human-readable form of the abort channel and
    /// nothing else in the workspace calls it, so its arms can be reordered,
    /// swapped or deleted without a single test noticing.
    #[test]
    fn abort_reason_renders_each_of_its_arms_distinctly() {
        let stage_failed = AbortReason::StageFailed {
            index: 2,
            status: ExitStatus::Code(3),
        }
        .to_string();
        assert!(
            stage_failed.contains("stage 2") && stage_failed.contains("Code(3)"),
            "a stage failure must name the stage and its status, got: {stage_failed}"
        );
        assert!(
            AbortReason::TimedOut.to_string().contains("timed out"),
            "a timeout must say so, got: {}",
            AbortReason::TimedOut
        );
        let dry = AbortReason::DryRun.to_string();
        assert!(
            dry.contains("dry run") && dry.contains("not committed"),
            "a dry run must say the changes were reported rather than committed, got: {dry}"
        );

        let rendered: std::collections::HashSet<String> =
            [stage_failed, AbortReason::TimedOut.to_string(), dry].into_iter().collect();
        assert_eq!(rendered.len(), 3, "each abort reason must render differently: {rendered:?}");
    }

    // ------------------------------------------------------------
    // Commit lock
    // ------------------------------------------------------------

    /// A zero wait still ACQUIRES an uncontended lock. The loop attempts the
    /// lock first and only then checks the deadline, so "no budget to wait" is
    /// not "no budget to succeed".
    ///
    /// The sibling zero-wait test covers the contended half. Together they pin
    /// the loop order: hoisting the deadline check above the `flock` attempt
    /// keeps the contended case correct — it still reports `Contended` without
    /// sleeping — while making every uncontended zero-wait commit fail on a
    /// workdir nobody is touching.
    #[test]
    fn commit_lock_with_a_zero_wait_still_takes_an_uncontended_lock() {
        let dir = tempfile::tempdir().unwrap();
        let mut polls = 0usize;
        let lock = acquire_commit_lock_polling(dir.path(), Duration::ZERO, |_| polls += 1)
            .expect("a lock nobody holds must be taken even with no budget to wait for it");
        assert_eq!(polls, 0, "taking a free lock must not sleep");
        drop(lock);
    }

    /// A commit lock that fails for a reason OTHER than contention preserves the
    /// upper too.
    ///
    /// Every stage exited 0 either way, so the change set is complete and
    /// mergeable whether the lock was busy or the workdir had vanished — and it
    /// is `CommitDeferred` in both cases, because in neither was the workdir
    /// touched. The sibling test covers the contended route only, so a change
    /// that preserved just that one — "a broken workdir means these changes are
    /// useless" — would silently reclaim a complete change set.
    #[test]
    fn finish_branch_preserves_the_upper_when_the_workdir_cannot_be_locked_at_all() {
        let (workdir, _storage, branch) = branch_holding_one_added_file();
        let branch_dir = branch.upper_dir().parent().unwrap().to_path_buf();
        let gone = workdir.path().join("no-such-workdir");

        let finished = finish_branch(branch, &gone, Duration::from_millis(50), true);

        assert!(
            matches!(finished.commit, Some(Err(CommitFailure::Lock(LockFailure::Io(_))))),
            "a workdir that cannot be opened is an I/O failure, not contention"
        );
        let survived = std::fs::read_to_string(branch_dir.join("upper").join("a.txt"))
            .unwrap_or_else(|e| {
                panic!("the unpublished change set must survive on disk, but reading it gave {e}")
            });
        assert_eq!(survived, "plan\n", "the preserved upper must still hold the stage's bytes");
        let preserved = crate::cow::seccomp::read_preserved(&branch_dir)
            .expect("a preserved upper must be findable through its marker");
        assert_eq!(
            preserved.reason,
            crate::cow::seccomp::PreserveReason::CommitDeferred,
            "the lock was never taken, so the workdir is untouched: that is CommitDeferred"
        );
    }

    // ------------------------------------------------------------
    // The type a transaction is deliberately NOT
    // ------------------------------------------------------------

    /// `Pipeline::is_empty` is documented "always false"; this is the constructor
    /// invariant that makes that true.
    ///
    /// It lives here because the transaction module's docs lean on `Pipeline`
    /// being a distinct, always-populated type — `into_stages` is the only way
    /// to move stages between the two runners, and it is documented as handing
    /// over a chain, not a possibly-empty list.
    #[test]
    fn a_pipeline_can_never_be_empty() {
        crate::pipeline::Pipeline::new(Vec::new())
            .err()
            .expect("a pipeline of no stages must be rejected at construction");
        let sb = Sandbox::builder().build().unwrap();
        let chain = crate::pipeline::Pipeline::new(vec![
            Stage::new(&sb, &["true"]),
            Stage::new(&sb, &["true"]),
        ])
        .expect("two stages are a valid chain");
        assert!(!chain.is_empty(), "a constructed pipeline always has stages");
        assert_eq!(chain.len(), 2, "and reports how many");
    }

    /// The commit lock WAITS for a concurrent merge instead of failing fast:
    /// a transaction that ran every stage successfully must publish its work,
    /// not lose it because another merge was in flight for a moment.
    #[test]
    fn commit_lock_waits_for_a_held_lock_to_be_released() {
        let dir = tempfile::tempdir().unwrap();
        let held = std::fs::File::open(dir.path()).unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );

        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            drop(held);
        });

        let mut polls = 0usize;
        let lock = acquire_commit_lock_polling(dir.path(), Duration::from_secs(10), |d| {
            polls += 1;
            std::thread::sleep(d);
        })
        .expect("must acquire the lock once the holder releases it");
        releaser.join().unwrap();
        drop(lock);

        assert!(
            polls > 0,
            "must actually have gone round the poll loop waiting for the holder"
        );
    }

    /// The wait is bounded, and expiring it is reported as CONTENTION rather
    /// than as a broken workdir: that distinction is what makes the failure a
    /// retryable `TxnError::Conflict` instead of an I/O error.
    #[test]
    fn commit_lock_wait_is_bounded_and_reports_contention() {
        let dir = tempfile::tempdir().unwrap();
        let held = std::fs::File::open(dir.path()).unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );

        let started = std::time::Instant::now();
        let err = acquire_commit_lock(dir.path(), Duration::from_millis(200))
            .expect_err("a lock that is never released must time out");
        let waited = started.elapsed();
        drop(held);

        assert!(
            matches!(err, LockFailure::Contended(d) if d == Duration::from_millis(200)),
            "a held lock must be reported as contention carrying the wait, got: {err:?}"
        );
        assert!(
            waited >= Duration::from_millis(200),
            "must have waited out the whole deadline, waited {waited:?}"
        );
    }

    /// A workdir that cannot be opened at all is NOT contention: it must not be
    /// reported as a retryable conflict.
    #[test]
    fn commit_lock_reports_a_missing_workdir_as_io() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("no-such-workdir");
        let err = acquire_commit_lock(&gone, Duration::from_millis(200))
            .expect_err("a workdir that does not exist cannot be locked");
        assert!(
            matches!(err, LockFailure::Io(_)),
            "a missing workdir is an I/O failure, not contention, got: {err:?}"
        );
    }

    /// The three failure channels stay apart, and stay honest, when flattened
    /// into the crate-wide error. Each arm is pinned to its exact variant: a
    /// commit failure reported as `Runtime(Child(..))` would claim a child
    /// process failed, which is the abort channel and cannot reach here, and
    /// `Runtime(_)` alone does not notice that.
    #[test]
    fn txn_errors_flatten_without_losing_the_channel() {
        let invalid: SandlockError = TxnError::Invalid("bad stages".into()).into();
        assert!(
            matches!(invalid, SandlockError::Sandbox(SandboxError::Invalid(_))),
            "a configuration error must stay a sandbox error, got: {invalid:?}"
        );

        // A stage that could not be driven keeps its own error verbatim.
        let stage: SandlockError = TxnError::Stage {
            index: 0,
            source: SandlockError::Runtime(SandboxRuntimeError::NotRunning),
        }
        .into();
        assert!(
            matches!(stage, SandlockError::Runtime(SandboxRuntimeError::NotRunning)),
            "a stage driver failure must flatten to the stage's own error, got: {stage:?}"
        );

        for original in [
            TxnError::Conflict {
                workdir: "/wd".into(),
                waited: Duration::from_secs(1),
                preserved_upper: "/st/upper".into(),
            },
            TxnError::Merge {
                workdir: "/wd".into(),
                preserved_upper: "/st/upper".into(),
                source: crate::error::BranchError::Operation("copy".into()),
            },
            TxnError::CommitLock {
                workdir: "/wd".into(),
                preserved_upper: "/st/upper".into(),
                source: std::io::Error::other("flock"),
            },
        ] {
            let rendered = original.to_string();
            let flat: SandlockError = original.into();
            assert!(
                matches!(flat, SandlockError::Runtime(SandboxRuntimeError::Branch(_))),
                "a commit-channel failure is a branch failure, not a child failure, got: {flat:?}"
            );
            assert!(
                flat.to_string().contains("/st/upper"),
                "flattening must not lose the preserved upper of {rendered:?}, got: {flat}"
            );
        }
    }

    /// Each commit-channel failure the RFC names gets its own exit code, and a
    /// conflict specifically reports EX_TEMPFAIL: "retry me".
    #[test]
    fn commit_channel_failures_have_distinct_exit_codes() {
        let stage = TxnError::Stage {
            index: 0,
            source: SandlockError::Runtime(SandboxRuntimeError::NotRunning),
        };
        let merge = TxnError::Merge {
            workdir: "/wd".into(),
            preserved_upper: "/st/upper".into(),
            source: crate::error::BranchError::Operation("copy".into()),
        };
        let conflict = TxnError::Conflict {
            workdir: "/wd".into(),
            waited: Duration::from_secs(1),
            preserved_upper: "/st/upper".into(),
        };
        let invalid = TxnError::Invalid("bad stages".into());

        let codes = [stage.exit_code(), merge.exit_code(), conflict.exit_code(), invalid.exit_code()];
        let unique: std::collections::HashSet<i32> = codes.iter().copied().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "stage/commit/conflict/config must not share an exit code, got {codes:?}"
        );
        assert_eq!(conflict.exit_code(), 75, "a conflict is EX_TEMPFAIL: retry it");
    }

    /// A zero wait must give up on a held lock immediately, without sleeping
    /// once: the deadline is checked before the poll sleeps, not after it.
    ///
    /// Asserted by counting sleeps. Timing it cannot carry this — the whole
    /// difference between checking the deadline before and after the sleep is
    /// one `COMMIT_LOCK_POLL`, and it still returns the same `Contended`.
    #[test]
    fn commit_lock_with_a_zero_wait_gives_up_without_sleeping() {
        let dir = tempfile::tempdir().unwrap();
        let held = std::fs::File::open(dir.path()).unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );

        let mut polls = 0usize;
        let err = acquire_commit_lock_polling(dir.path(), Duration::ZERO, |_| polls += 1)
            .expect_err("a held lock with no wait budget cannot be taken");
        drop(held);

        assert_eq!(polls, 0, "a zero wait must not sleep before giving up");
        assert!(
            matches!(err, LockFailure::Contended(d) if d == Duration::ZERO),
            "giving up on a held lock is contention even with no wait, got: {err:?}"
        );
    }

    /// An uncontended lock must not go through the poll loop's wait at all —
    /// the common case is every commit that is not racing another one.
    ///
    /// Asserted by counting the poll loop's sleeps, not by timing it. A
    /// wall-clock bound cannot carry this property: a 100ms budget does not
    /// notice a 20ms regression, and it flakes on a loaded runner.
    #[test]
    fn commit_lock_uncontended_does_not_wait_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let mut polls = 0usize;
        let lock = acquire_commit_lock_polling(dir.path(), Duration::from_secs(10), |d| {
            polls += 1;
            std::thread::sleep(d);
        })
        .unwrap();
        assert_eq!(polls, 0, "taking an uncontended lock must not sleep");
        drop(lock);
    }

    /// The whole commit channel — every way the shared upper's disposition can
    /// fail other than contention — reports one exit code, EX_IOERR.
    ///
    /// The sibling test above pins the channels apart; this one pins them
    /// together: a caller that keys "the change set is on disk, go recover it"
    /// off 74 must get it from the merge failure, the lock failure, the branch
    /// that could never be created and the commit that was abandoned alike.
    #[test]
    fn every_commit_channel_failure_reports_ex_ioerr() {
        let failures = [
            TxnError::Branch {
                workdir: "/wd".into(),
                source: crate::error::BranchError::Operation("create upper".into()),
            },
            TxnError::CommitLock {
                workdir: "/wd".into(),
                preserved_upper: "/st/upper".into(),
                source: std::io::Error::other("flock"),
            },
            TxnError::Merge {
                workdir: "/wd".into(),
                preserved_upper: "/st/upper".into(),
                source: crate::error::BranchError::Operation("copy".into()),
            },
            TxnError::CommitAbandoned("runtime shutting down".into()),
        ];
        for failure in failures {
            assert_eq!(
                failure.exit_code(),
                74,
                "the commit channel is EX_IOERR, but {failure:?} reported {}",
                failure.exit_code()
            );
        }
    }

    fn aborted(reason: AbortReason) -> TxnOutcome {
        TxnOutcome {
            committed: false,
            stages: Vec::new(),
            changes: Vec::new(),
            abort_reason: Some(reason),
        }
    }

    /// An aborted transaction reports the number a caller fronting it with a
    /// command-line tool would have got from the command itself: the failing
    /// stage's own code, `128 + signal` for a signalled one, and 124 for a
    /// timeout as `timeout(1)` reports it.
    ///
    /// Only `Code` is exercised end to end (a stage exiting 1); the signalled
    /// and killed stages are what this pins, because collapsing them onto the
    /// signal number — 9 instead of 137 — is both easy to write and
    /// indistinguishable from a command that really exited 9.
    #[test]
    fn an_aborted_outcome_reports_the_failing_stage_status_as_a_shell_would() {
        for (status, want) in [
            (ExitStatus::Code(3), 3),
            (ExitStatus::Signal(libc::SIGTERM), 128 + libc::SIGTERM),
            (ExitStatus::Killed, 128 + libc::SIGKILL),
            (ExitStatus::Timeout, 124),
        ] {
            let outcome = aborted(AbortReason::StageFailed { index: 1, status: status.clone() });
            assert_eq!(
                outcome.exit_code(),
                want,
                "a stage that ended as {status:?} must report {want}"
            );
        }
        assert_eq!(
            aborted(AbortReason::TimedOut).exit_code(),
            124,
            "a transaction timeout reports 124, as timeout(1) does"
        );
    }

    /// A transaction that did what was asked reports success — including a dry
    /// run, which does not commit but did not fail either.
    #[test]
    fn a_committed_transaction_and_a_completed_dry_run_both_report_success() {
        let committed = TxnOutcome {
            committed: true,
            stages: Vec::new(),
            changes: Vec::new(),
            abort_reason: None,
        };
        assert_eq!(committed.exit_code(), 0, "a committed transaction succeeded");
        assert_eq!(
            aborted(AbortReason::DryRun).exit_code(),
            0,
            "a dry run reported its changes as asked; not committing is not a failure"
        );
    }

    /// A branch over a fresh workdir whose upper already holds `a.txt`, as a
    /// run whose stages all succeeded would have left it. The tempdirs are
    /// returned because dropping them removes the workdir and the storage.
    fn branch_holding_one_added_file(
    ) -> (tempfile::TempDir, tempfile::TempDir, crate::cow::seccomp::SeccompCowBranch) {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let branch = crate::cow::seccomp::SeccompCowBranch::create(
            workdir.path(),
            Some(storage.path()),
            0,
        )
        .unwrap();
        std::fs::write(branch.upper_dir().join("a.txt"), "plan\n").unwrap();
        (workdir, storage, branch)
    }

    /// Discarding the upper still reports what it held: the change set is read
    /// off the branch BEFORE it is disposed of, because after the abort there
    /// is nothing left on disk to read. This is what fills `TxnOutcome::changes`
    /// on the abort and dry-run paths.
    #[test]
    fn finish_branch_discarding_the_upper_still_reports_what_it_held() {
        let (workdir, _storage, branch) = branch_holding_one_added_file();
        let branch_dir = branch.upper_dir().parent().unwrap().to_path_buf();

        let finished = finish_branch(branch, workdir.path(), Duration::from_secs(30), false);

        assert!(
            finished.commit.is_none(),
            "an upper that was discarded rather than merged reports no commit result"
        );
        let paths: Vec<_> = finished
            .changes
            .iter()
            .map(|c| (c.kind.clone(), c.path.clone()))
            .collect();
        assert_eq!(
            paths,
            vec![(crate::dry_run::ChangeKind::Added, std::path::PathBuf::from("a.txt"))],
            "the discarded change set must still be reported"
        );
        assert!(
            !workdir.path().join("a.txt").exists(),
            "a discarded upper must not reach the workdir"
        );
        assert!(!branch_dir.exists(), "a discarded upper must be reclaimed from disk");
    }

    /// The commit merges the upper into the workdir and does not keep the
    /// workdir lock afterwards: the lock is mutual exclusion between merges, so
    /// holding it past the merge would stall every later transaction for the
    /// life of this process.
    #[test]
    fn finish_branch_merges_the_upper_and_leaves_the_workdir_unlocked() {
        let (workdir, _storage, branch) = branch_holding_one_added_file();
        let branch_dir = branch.upper_dir().parent().unwrap().to_path_buf();

        let finished = finish_branch(branch, workdir.path(), Duration::from_secs(30), true);

        assert!(
            matches!(finished.commit, Some(Ok(()))),
            "an uncontended commit of a mergeable upper must succeed"
        );
        assert_eq!(
            std::fs::read_to_string(workdir.path().join("a.txt")).unwrap(),
            "plan\n",
            "the committed change set must be in the workdir, with its bytes"
        );
        assert!(!branch_dir.exists(), "a merged upper must be reclaimed from disk");

        let after = std::fs::File::open(workdir.path()).unwrap();
        assert_eq!(
            unsafe { libc::flock(after.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "the commit must release the workdir lock, not hold it past the merge"
        );
    }

    /// Giving up on the commit lock hands the storage over instead of dropping
    /// it: every stage exited 0, so the upper holds a complete change set that
    /// only failed to be published.
    ///
    /// The marker says `CommitDeferred`, which is the part a recovery acts on —
    /// it means the workdir was never touched and the whole change set is here,
    /// unlike `MergeInterrupted`, where the workdir may already be half merged.
    #[test]
    fn finish_branch_preserves_the_upper_as_commit_deferred_when_the_lock_is_contended() {
        let (workdir, _storage, branch) = branch_holding_one_added_file();
        let branch_dir = branch.upper_dir().parent().unwrap().to_path_buf();

        // Stand in for another transaction whose merge never finishes.
        let held = std::fs::File::open(workdir.path()).unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "test setup: could not take the workdir lock"
        );

        let finished = finish_branch(branch, workdir.path(), Duration::from_millis(50), true);
        drop(held);

        assert!(
            matches!(
                finished.commit,
                Some(Err(CommitFailure::Lock(LockFailure::Contended(d)))) if d == Duration::from_millis(50)
            ),
            "a lock held for the whole wait must be reported as contention"
        );
        assert!(
            !workdir.path().join("a.txt").exists(),
            "nothing may be merged when the lock was never taken"
        );
        let survived = std::fs::read_to_string(branch_dir.join("upper").join("a.txt"))
            .unwrap_or_else(|e| {
                panic!("the unpublished change set must survive on disk, but reading it gave {e}")
            });
        assert_eq!(survived, "plan\n", "the preserved upper must still hold the stage's bytes");
        let preserved = crate::cow::seccomp::read_preserved(&branch_dir)
            .expect("a preserved upper must be findable through its marker");
        assert_eq!(
            preserved.reason,
            crate::cow::seccomp::PreserveReason::CommitDeferred,
            "the workdir is untouched and the whole change set is here: that is CommitDeferred"
        );
    }

    /// A merge that fails partway leaves the remainder on disk rather than
    /// reclaiming it, and marks it as an interrupted merge — the workdir may
    /// hold part of the change set, so recovery cannot assume it is untouched.
    ///
    /// The merge is made to fail without any privilege trick: the upper holds a
    /// regular file where the workdir already has a directory of the same name,
    /// so the merge's `open(O_WRONLY|O_CREAT)` on it fails with `EISDIR`.
    #[test]
    fn finish_branch_preserves_the_remainder_when_the_merge_fails() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        std::fs::create_dir(workdir.path().join("x")).unwrap();
        let branch = crate::cow::seccomp::SeccompCowBranch::create(
            workdir.path(),
            Some(storage.path()),
            0,
        )
        .unwrap();
        let branch_dir = branch.upper_dir().parent().unwrap().to_path_buf();
        std::fs::write(branch.upper_dir().join("x"), "built\n").unwrap();

        let finished = finish_branch(branch, workdir.path(), Duration::from_secs(30), true);

        assert!(
            matches!(finished.commit, Some(Err(CommitFailure::Merge(_)))),
            "a merge that cannot write an entry into the workdir must report a merge failure"
        );
        let remainder = std::fs::read_to_string(branch_dir.join("upper").join("x"))
            .unwrap_or_else(|e| {
                panic!("the change that did not land must survive on disk, but reading it gave {e}")
            });
        assert_eq!(remainder, "built\n", "the preserved remainder must still hold its bytes");
        let preserved = crate::cow::seccomp::read_preserved(&branch_dir)
            .expect("a preserved remainder must be findable through its marker");
        assert_eq!(
            preserved.reason,
            crate::cow::seccomp::PreserveReason::MergeInterrupted,
            "the workdir may be partially merged, so this is not CommitDeferred"
        );
    }
}
