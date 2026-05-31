//! Thread-local Tokio runtime for FFI entry points.
//!
//! Each FFI thread lazily builds a single `current_thread` runtime on
//! first use and reuses it for all subsequent calls on that thread. We
//! prefer `current_thread` over `multi_thread` so the runtime does not
//! eagerly spawn worker threads at construction: that path fails when
//! the FFI is invoked from a multi-threaded host whose seccomp profile
//! blocks `clone3` (Kubernetes `RuntimeDefault` + multi-threaded
//! Python/uvicorn was the original report, issue #47).
//!
//! Live handles are the exception: once `sandlock_start` returns, their
//! supervisor tasks still need to progress between FFI calls, so they use
//! a small multi-thread runtime built by `build_live_runtime`.

use std::cell::OnceCell;
use std::future::Future;
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use tokio::runtime::{Builder, Runtime};

thread_local! {
    static RT: OnceCell<Runtime> = const { OnceCell::new() };
}

/// Build a fresh `current_thread` Tokio runtime. Logs the error to
/// stderr on failure so environment-incompatibility cases (e.g. seccomp
/// blocking a syscall the runtime needs at startup) surface to the
/// caller instead of being swallowed into a NULL pointer return.
pub(crate) fn build_runtime() -> Option<Runtime> {
    match Builder::new_current_thread().enable_all().build() {
        Ok(rt) => Some(rt),
        Err(e) => {
            log_build_error(&e);
            None
        }
    }
}

/// Build a runtime for live handles returned by `sandlock_create`.
///
/// Unlike the shared `current_thread` runtime, this must keep spawned
/// supervisor tasks running after an FFI call returns; Tokio suspends
/// `current_thread` tasks whenever `block_on` exits.
pub(crate) fn build_live_runtime() -> Option<Runtime> {
    match Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    {
        Ok(rt) => Some(rt),
        Err(e) => {
            log_build_error(&e);
            None
        }
    }
}

/// Drive `future` on a runtime, converting runtime panics into FFI-level
/// failure. This keeps panics such as Tokio blocking-pool startup
/// failures from unwinding across `extern "C"` entry points.
pub(crate) fn block_on_runtime<R>(rt: &Runtime, future: impl Future<Output = R>) -> Option<R> {
    match catch_unwind(AssertUnwindSafe(|| rt.block_on(future))) {
        Ok(result) => Some(result),
        Err(_) => {
            log_runtime_panic();
            None
        }
    }
}

/// Run `f` with this thread's shared runtime. Returns `None` if the
/// runtime could not be built on first use. Panics are converted to
/// `None`, so this helper is suitable for `extern "C"` entry points.
pub(crate) fn with_runtime<R>(f: impl FnOnce(&Runtime) -> R) -> Option<R> {
    match catch_unwind(AssertUnwindSafe(|| with_runtime_unwind(f))) {
        Ok(result) => result,
        Err(_) => {
            log_runtime_panic();
            None
        }
    }
}

/// Run `f` with this thread's shared runtime without catching panics.
/// Use this only from `extern "C-unwind"` entry points that intentionally
/// allow user callback panics to propagate.
pub(crate) fn with_runtime_unwind<R>(f: impl FnOnce(&Runtime) -> R) -> Option<R> {
    RT.with(|cell| {
        if cell.get().is_none() {
            let rt = build_runtime()?;
            let _ = cell.set(rt);
        }
        Some(f(cell.get().expect("runtime initialised above")))
    })
}

fn log_build_error(e: &io::Error) {
    eprintln!("sandlock: failed to build tokio runtime: {e}");
}

fn log_runtime_panic() {
    eprintln!("sandlock: tokio runtime panicked while driving an FFI call");
}
