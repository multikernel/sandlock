//! `sandlock_run_with_handlers` entry points and their plumbing helpers.
//!
//! This module owns the FFI surface that takes an array of
//! `sandlock_handler_registration_t`, converts them into `FfiHandler`
//! instances, and drives the supervisor runtime.

use std::ffi::CStr;
use std::slice;

use sandlock_core::{RunResult, Sandbox, SandlockError};

use super::abi::sandlock_handler_registration_t;
use super::adapter::FfiHandler;

/// Defensive upper bound on `argc`. Linux's `ARG_MAX` is typically
/// 128 KiB-2 MiB of *characters* across all argv+envp; an argv with
/// 4096 entries is already preposterous in practice. Bounding here
/// turns a malicious or buggy caller passing `argc = u32::MAX` (which
/// would otherwise drive an unbounded deref loop) into a fast NULL
/// return at the FFI boundary.
const MAX_ARGV: u32 = 4096;

/// Defensive upper bound on `nregistrations`. The kernel exposes
/// ~400-500 syscalls on Linux; registering even all of them is well
/// under this cap. Bounding here closes the same unbounded-deref vector
/// for the registration array.
const MAX_REGISTRATIONS: usize = 4096;

fn argv_from_c(argv: *const *const std::os::raw::c_char, argc: u32) -> Option<Vec<String>> {
    if argv.is_null() {
        return None;
    }
    // Reject argc == 0 here: an empty argv would have us hand the
    // sandbox an empty command vector, which the supervisor cannot
    // execute. Failing fast keeps the error surfacing at the FFI
    // boundary where the C caller can react.
    if argc == 0 {
        return None;
    }
    // Reject implausible `argc` values before we start dereferencing
    // `argv`. Without this cap, a caller passing `argc = u32::MAX`
    // would have us walk 4 billion pointer slots looking for nulls.
    if argc > MAX_ARGV {
        return None;
    }
    let mut out = Vec::with_capacity(argc as usize);
    for i in 0..(argc as isize) {
        let p = unsafe { *argv.offset(i) };
        if p.is_null() {
            return None;
        }
        let s = unsafe { CStr::from_ptr(p) }.to_str().ok()?.to_owned();
        out.push(s);
    }
    Some(out)
}

fn collect_registrations(
    regs: *const sandlock_handler_registration_t,
    nregs: usize,
) -> Option<Vec<(i64, FfiHandler)>> {
    if regs.is_null() && nregs > 0 {
        return None;
    }
    if nregs == 0 {
        return Some(Vec::new());
    }
    // Bound `nregs` before we materialise the slice. An attacker-supplied
    // `nregs = usize::MAX` would otherwise hand `slice::from_raw_parts`
    // a length larger than the underlying allocation — UB. The cap is
    // generous enough for any legitimate caller.
    if nregs > MAX_REGISTRATIONS {
        return None;
    }
    let slice = unsafe { slice::from_raw_parts(regs, nregs) };
    // First pass: validate all entries before taking ownership of any.
    // Without this, a null pointer at index k+1 would leave us having
    // already consumed handlers [0..k] via `Box::from_raw`; dropping the
    // partial `out` would free them while the C caller still believes it
    // owns the originals — a latent double-free via
    // `sandlock_handler_free`.
    for r in slice {
        if r.handler.is_null() {
            return None;
        }
    }
    // Second pass: ownership transfer. Every pointer is non-null per the
    // pass above.
    let mut out = Vec::with_capacity(nregs);
    for r in slice {
        // SAFETY: validated non-null above; caller provided pointer from
        // `sandlock_handler_new` and must not reuse after this call (the
        // public C ABI doc states ownership transfers in).
        let h = unsafe { FfiHandler::from_raw(r.handler) };
        out.push((r.syscall_nr, h));
    }
    Some(out)
}

fn block_on_run(
    sandbox: &Sandbox,
    name: Option<String>,
    cmd: Vec<String>,
    handlers: Vec<(i64, FfiHandler)>,
    interactive: bool,
) -> Option<Result<RunResult, SandlockError>> {
    let cmd_refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
    // Apply `name` via the builder method on a clone — mirrors the
    // pattern used by `sandlock_run` in lib.rs. A `None` here means
    // "auto-generate `sandbox-{pid}`", matching the C ABI contract.
    let mut sb = match name {
        Some(n) => sandbox.clone().with_name(n),
        None => sandbox.clone(),
    };
    // Drives the supervisor on the shared per-thread runtime; see
    // `crate::runtime` for why this is `current_thread`. This path is
    // reached from `extern "C-unwind"` entry points, so user callback
    // panics are intentionally allowed to propagate.
    crate::runtime::with_runtime_unwind(|rt| {
        rt.block_on(async move {
            if interactive {
                sb.run_interactive_with_handlers(&cmd_refs, handlers).await
            } else {
                sb.run_with_handlers(&cmd_refs, handlers).await
            }
        })
    })
}

/// Run the policy with C handlers. Returns NULL on failure.
///
/// `name` may be NULL to auto-generate `sandbox-{pid}`, or a valid
/// NUL-terminated UTF-8 C string; the placement mirrors the existing
/// `sandlock_run` entry point in `lib.rs`.
///
/// Declared `extern "C-unwind"` because the handler containers reach
/// this entry point as part of the registration array and their
/// user-supplied `ud_drop` may panic when the supervisor frees them
/// (either during a normal Box-drop or on the early-return cleanup in
/// `release_registrations`). Unwinding across an `extern "C"` boundary
/// is undefined behaviour and aborts the process under modern
/// rustc — `extern "C-unwind"` is the only legal way to let such a
/// panic propagate to the caller, who can then decide whether to
/// catch it.
///
/// # Safety
/// All pointer arguments must be valid for their documented lifetimes:
/// `policy` must come from `sandlock_sandbox_build`, `argv` must be a
/// readable array of `argc` NUL-terminated strings, and each handler
/// pointer must come from `sandlock_handler_new` and must not be reused
/// after this call (ownership transfers in).
#[no_mangle]
pub unsafe extern "C-unwind" fn sandlock_run_with_handlers(
    policy: *const crate::sandlock_sandbox_t,
    name: *const std::os::raw::c_char,
    argv: *const *const std::os::raw::c_char,
    argc: u32,
    registrations: *const sandlock_handler_registration_t,
    nregistrations: usize,
) -> *mut crate::sandlock_result_t {
    run_with_handlers_inner(
        policy,
        name,
        argv,
        argc,
        registrations,
        nregistrations,
        false,
    )
}

/// Interactive-stdio variant of `sandlock_run_with_handlers`.
///
/// `name` follows the same convention as `sandlock_run_with_handlers`.
/// The `extern "C-unwind"` declaration carries the same rationale: a
/// panicking `ud_drop` must be able to unwind out of this entry point
/// without process abort.
///
/// # Safety
/// Same constraints as `sandlock_run_with_handlers`.
#[no_mangle]
pub unsafe extern "C-unwind" fn sandlock_run_interactive_with_handlers(
    policy: *const crate::sandlock_sandbox_t,
    name: *const std::os::raw::c_char,
    argv: *const *const std::os::raw::c_char,
    argc: u32,
    registrations: *const sandlock_handler_registration_t,
    nregistrations: usize,
) -> *mut crate::sandlock_result_t {
    run_with_handlers_inner(
        policy,
        name,
        argv,
        argc,
        registrations,
        nregistrations,
        true,
    )
}

/// Drops every non-null handler pointer in the registration array.
/// Used by [`run_with_handlers_inner`] on early-return paths where
/// `collect_registrations` was not reached — guarantees the C ABI
/// contract "all handler pointers are consumed by this call".
///
/// Each per-element drop runs an arbitrary, user-supplied `ud_drop`
/// that may panic. Without protection, a panic mid-loop would unwind
/// past the remaining handlers — leaving them allocated and violating
/// the "array consumed as a whole" contract (partial-consume leak).
/// We wrap each drop in `catch_unwind`, remember the first panic, and
/// re-raise it after the loop completes via `resume_unwind`. The
/// caller is `extern "C-unwind"` so the propagated panic is legal at
/// the FFI boundary, while every handler container is still released.
///
/// # Safety
/// `regs` is either null (no-op) or points to `nregs` valid
/// `sandlock_handler_registration_t` slots whose `handler` pointer is
/// either null or comes from `sandlock_handler_new` and has not been
/// freed by anyone else.
unsafe fn release_registrations(regs: *const sandlock_handler_registration_t, nregs: usize) {
    if regs.is_null() || nregs == 0 {
        return;
    }
    // Apply the same defensive cap as `collect_registrations`. Reach
    // here from early-return paths in `run_with_handlers_inner` where
    // `collect_registrations` may not have validated yet — without the
    // cap, an attacker-supplied `nregs = usize::MAX` would feed
    // `slice::from_raw_parts` a bogus length. Out-of-range counts
    // can't have come from a valid registration array; refuse the
    // walk entirely. The C-ABI "always consume" contract is then
    // moot because no legitimate caller can hit this branch.
    if nregs > MAX_REGISTRATIONS {
        return;
    }
    let slice = slice::from_raw_parts(regs, nregs);
    let mut first_panic: Option<Box<dyn std::any::Any + Send>> = None;
    for r in slice {
        if !r.handler.is_null() {
            let h = r.handler;
            // SAFETY: `h` is non-null and came from `sandlock_handler_new`
            // per the type contract. The closure is `AssertUnwindSafe`
            // because the only state crossing the unwind boundary is the
            // raw pointer (consumed by `Box::from_raw`) — no shared
            // references with broken invariants.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(Box::from_raw(h));
            }));
            if let Err(payload) = result {
                if first_panic.is_none() {
                    first_panic = Some(payload);
                }
                // Subsequent panics are dropped: they would compose
                // into "panic during panic" → abort. Keeping only the
                // first preserves the original failure context for the
                // outer caller while still finishing the loop.
            }
        }
    }
    if let Some(payload) = first_panic {
        // Re-raise the first captured panic. The outer entry point is
        // `extern "C-unwind"` so this propagates legally to the C
        // caller, who can decide whether to catch it.
        std::panic::resume_unwind(payload);
    }
}

unsafe fn run_with_handlers_inner(
    policy: *const crate::sandlock_sandbox_t,
    name: *const std::os::raw::c_char,
    argv: *const *const std::os::raw::c_char,
    argc: u32,
    registrations: *const sandlock_handler_registration_t,
    nregistrations: usize,
    interactive: bool,
) -> *mut crate::sandlock_result_t {
    if policy.is_null() {
        // Honour the documented contract: ownership of every handler
        // pointer transfers in on entry, regardless of return value.
        release_registrations(registrations, nregistrations);
        return std::ptr::null_mut();
    }
    // Decode the optional name eagerly so a malformed (non-UTF-8) C
    // string fails the call fast, before we take ownership of any
    // handler containers via `collect_registrations`. Matches the
    // contract used by `sandlock_run`.
    let name_opt: Option<String> = if name.is_null() {
        None
    } else {
        match CStr::from_ptr(name).to_str() {
            Ok(s) => Some(s.to_owned()),
            Err(_) => {
                release_registrations(registrations, nregistrations);
                return std::ptr::null_mut();
            }
        }
    };
    let cmd = match argv_from_c(argv, argc) {
        Some(v) => v,
        None => {
            release_registrations(registrations, nregistrations);
            return std::ptr::null_mut();
        }
    };
    let handlers = match collect_registrations(registrations, nregistrations) {
        Some(v) => v,
        None => {
            // Validation failed (null handler in the array). The
            // non-null handlers in the array have not been taken into
            // FfiHandler ownership by `collect_registrations` (it is
            // validate-first), but the public C-ABI contract guarantees
            // "array consumed as a whole" — release them here so the C
            // caller is never responsible for any registered pointer
            // after this call returns.
            release_registrations(registrations, nregistrations);
            return std::ptr::null_mut();
        }
    };
    let sandbox_ref: &Sandbox = (*policy).inner();
    match block_on_run(sandbox_ref, name_opt, cmd, handlers, interactive) {
        Some(Ok(rr)) => {
            let boxed = Box::new(crate::sandlock_result_t::from_run_result(rr));
            Box::into_raw(boxed)
        }
        _ => std::ptr::null_mut(),
    }
}
