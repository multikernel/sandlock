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
    // Take the branch out from under the async mutex first, then commit/abort the
    // owned value so the sync merge doesn't run while holding the guard.
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
    use std::os::unix::io::AsRawFd;

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
}
