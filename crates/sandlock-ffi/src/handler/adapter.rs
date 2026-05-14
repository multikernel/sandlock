//! Rust-side adapter wiring the C ABI to the `Handler` trait.
//!
//! `FfiHandler` owns the `sandlock_handler_t` container produced by
//! `sandlock_handler_new` and implements `Handler` so the supervisor's
//! dispatch loop can invoke C callbacks transparently.

use std::future::Future;
use std::os::unix::io::FromRawFd;
use std::pin::Pin;

use sandlock_core::seccomp::dispatch::{Handler, HandlerCtx};
use sandlock_core::seccomp::notif::NotifAction;

use super::abi::{
    sandlock_action_kind_t, sandlock_action_out_t, sandlock_exception_policy_t,
    sandlock_handler_t, sandlock_mem_handle_t,
};

/// Rust adapter wrapping an owned `sandlock_handler_t` and implementing
/// `Handler`. Constructed when the supervisor accepts handlers passed
/// through `sandlock_run_with_handlers`.
pub struct FfiHandler {
    inner: Box<sandlock_handler_t>,
}

impl FfiHandler {
    /// Take ownership of a raw `sandlock_handler_t*` produced by
    /// `sandlock_handler_new`.
    ///
    /// # Safety
    /// `raw` must be a non-null pointer returned by `sandlock_handler_new`
    /// and never freed via `sandlock_handler_free`. After this call the
    /// supervisor owns the container.
    pub unsafe fn from_raw(raw: *mut sandlock_handler_t) -> Self {
        assert!(!raw.is_null(), "FfiHandler::from_raw on null pointer");
        Self { inner: Box::from_raw(raw) }
    }

    fn exception_action(&self, child_pgid: i32) -> NotifAction {
        match self.inner.on_exception {
            sandlock_exception_policy_t::Kill => {
                NotifAction::Kill { sig: libc::SIGKILL, pgid: child_pgid }
            }
            sandlock_exception_policy_t::DenyEperm => NotifAction::Errno(libc::EPERM),
            sandlock_exception_policy_t::Continue => NotifAction::Continue,
        }
    }
}

/// `Send`-only wrapper around the C user-data pointer so it can travel
/// into `spawn_blocking`. Only the move (not sharing across threads) is
/// required; the deeper Send/Sync rationale for the underlying handler
/// container lives on `sandlock_handler_t`.
struct UdPtr(*mut std::ffi::c_void);
// Safety: ud is opaque to Rust; the spawn_blocking pipeline only moves
// (not shares) the wrapper. See `sandlock_handler_t` for the deeper
// Send/Sync rationale that justifies the underlying handler container.
unsafe impl Send for UdPtr {}

impl Handler for FfiHandler {
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> Pin<Box<dyn Future<Output = NotifAction> + Send + 'a>> {
        // Capture the pieces we need by value so spawn_blocking can run
        // the C callback on a worker thread without &self lifetime games.
        let notif_snap = crate::notif_repr::sandlock_notif_data_t::from(&cx.notif);
        let notif_fd = cx.notif_fd;
        let notif_id = cx.notif.id;
        let pid = cx.notif.pid;
        // Resolve the trapped child's process group id for use as a fallback
        // pgid in Kill actions where the caller passed pgid == 0. Three guard
        // rails:
        //
        //   1. `notif.pid == 0` can occur in nested PID namespaces (e.g.,
        //      Kubernetes pod-in-pod, KubeVirt, DinD). `getpgid(0)` returns
        //      the supervisor's own pgid — substituting that into a Kill
        //      action would be a supervisor-suicide vector.
        //
        //   2. `getpgid(pid) <= 0` indicates ESRCH (child exited between
        //      notif and our query) or another kernel-side failure.
        //
        //   3. Even on success, the resolved pgid must differ from the
        //      supervisor's own pgid. If sandlock-core does not call
        //      `setpgid(0, 0)` after fork, the child inherits the parent's
        //      pgid — sending `killpg(supervisor_pgid)` would kill the
        //      supervisor along with the child.
        //
        // In all three failure cases, fall back to the bare pid. A `killpg(pid)`
        // when `pid` does not name a valid process group will fail with ESRCH
        // inside the supervisor's response path — safer than killing the
        // supervisor.
        let child_pgid = {
            let pid = cx.notif.pid as i32;
            // SAFETY: `getpgid(0)` is signal-safe and has no preconditions.
            let supervisor_pgid = unsafe { libc::getpgid(0) };
            if pid <= 0 {
                pid
            } else {
                // SAFETY: `getpgid` is signal-safe; positive pid is the only
                // documented precondition.
                let pgid = unsafe { libc::getpgid(pid) };
                if pgid <= 0 || pgid == supervisor_pgid {
                    pid
                } else {
                    pgid
                }
            }
        };
        let handler_fn = self.inner.handler_fn;
        let ud = UdPtr(self.inner.ud);
        let on_exception_fallback = self.exception_action(child_pgid);

        Box::pin(async move {
            let join = tokio::task::spawn_blocking(move || {
                // Rust 2021 disjoint closure captures (RFC 2229) would
                // otherwise capture `ud.0` (a bare `*mut c_void`, not
                // `Send`) rather than the whole `UdPtr`. Binding `ud` to
                // a fresh local at the top of the closure forces a
                // whole-struct capture so the `Send` impl on `UdPtr`
                // applies to the outer closure.
                let ud = ud;
                let UdPtr(ud_raw) = ud;
                let mut mem = sandlock_mem_handle_t::new(notif_fd, notif_id, pid);
                let mut out = sandlock_action_out_t::zeroed();
                let rc = match handler_fn {
                    Some(f) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                        || f(ud_raw, &notif_snap, &mut mem, &mut out),
                    )),
                    None => Ok(-1),
                };
                (rc, out)
            }).await;

            let (rc_or_panic, out) = match join {
                Ok(pair) => pair,
                Err(_join_err) => return on_exception_fallback,
            };

            match rc_or_panic {
                Ok(0) => match translate_action(&out, child_pgid) {
                    Some(action) => action,
                    None => {
                        // Action kind ended up Unset, unknown, or the
                        // reserved InjectFdSendTracked discriminant.
                        // Drain any inject-fd payload before falling
                        // back to the exception policy — otherwise the
                        // supervisor leaks the srcfd that was armed by
                        // the (failed) callback.
                        // SAFETY: `drain_pending_inject_fd` inspects
                        // `out.kind` itself before touching the union,
                        // and `out.kind` matches the union variant per
                        // the action setters' contract.
                        unsafe { drain_pending_inject_fd(&out) };
                        on_exception_fallback
                    }
                },
                _ => {
                    // Either the callback returned a non-zero rc OR
                    // `catch_unwind` caught a panic. The callback may
                    // have armed an InjectFdSend{,Tracked} payload
                    // before failing; drain it so its srcfd doesn't
                    // leak in the supervisor.
                    // SAFETY: see the `Ok(0) -> None` branch above.
                    unsafe { drain_pending_inject_fd(&out) };
                    on_exception_fallback
                }
            }
        })
    }
}

/// Drains a still-pending `InjectFdSend` or `InjectFdSendTracked`
/// payload by consuming the contained `srcfd` into an `OwnedFd` and
/// dropping it (which closes the fd). Called from error paths in
/// [`FfiHandler::handle`] that fall back to the exception policy
/// without dispatching the action — without this, the supervisor
/// silently leaks fds armed by a C handler that subsequently panicked
/// or returned a non-zero rc.
///
/// No-op for any other action kind (including `Unset`).
///
/// # Safety
/// `out` must point at a fully-initialised `sandlock_action_out_t`.
/// The function inspects only `out.kind` and the union arm matching
/// that kind, which is sound because the action setters establish the
/// invariant "the `kind` tag selects the union arm".
unsafe fn drain_pending_inject_fd(out: &sandlock_action_out_t) {
    use sandlock_action_kind_t as K;
    if out.kind == K::InjectFdSend as u32 {
        // SAFETY: `kind == InjectFdSend` selects the `inject_send`
        // arm per the setter contract. Wrapping the raw fd in an
        // `OwnedFd` and dropping it closes the fd.
        drop(std::os::unix::io::OwnedFd::from_raw_fd(
            out.payload.inject_send.srcfd,
        ));
    } else if out.kind == K::InjectFdSendTracked as u32 {
        // The C header exposes the discriminant value publicly even
        // though we don't ship a setter for it. A C caller can still
        // assign `out->kind = 5; out->payload.inject_send_tracked.srcfd = X;`
        // by hand. Treat it like `InjectFdSend` for cleanup purposes:
        // the srcfd was armed and must be released.
        // SAFETY: see `InjectFdSend` arm above.
        drop(std::os::unix::io::OwnedFd::from_raw_fd(
            out.payload.inject_send_tracked.srcfd,
        ));
    }
}

/// Convert the C-side decision into a `NotifAction`. Returns `None` if
/// the kind is `Unset`, unknown, or `InjectFdSendTracked` (no setter
/// exposed; treated as fallback). The caller then falls back to the
/// exception policy, and is responsible for invoking
/// [`drain_pending_inject_fd`] to release any armed inject-fd payload.
///
/// Note: this function takes `&sandlock_action_out_t` rather than
/// consuming the struct so that the caller can still inspect `out.kind`
/// on the `None` branch and drain any pending fd payload. The
/// `InjectFdSend` arm uses `OwnedFd::from_raw_fd` on the union field,
/// which is what materialises the ownership transfer from the C caller
/// to the supervisor when this branch is taken.
fn translate_action(out: &sandlock_action_out_t, child_pgid: i32) -> Option<NotifAction> {
    use sandlock_action_kind_t as K;
    let kind = match out.kind {
        x if x == K::Continue as u32 => K::Continue,
        x if x == K::Errno as u32 => K::Errno,
        x if x == K::ReturnValue as u32 => K::ReturnValue,
        x if x == K::InjectFdSend as u32 => K::InjectFdSend,
        // Discriminant reserved for a future tracker-injection ABI; no
        // setter is exposed in this release. A C caller can still set
        // it by hand (the value is public in the C header). Return
        // `None` so the caller drains the srcfd and falls back to the
        // exception policy.
        x if x == K::InjectFdSendTracked as u32 => return None,
        x if x == K::Hold as u32 => K::Hold,
        x if x == K::Kill as u32 => K::Kill,
        _ => return None, // Unset or unknown
    };

    // Safety: the `out.payload` union variant matched here was just
    // selected by the `kind` discriminant above. The C action setters
    // documented in this module pair each `kind` value with exactly one
    // payload variant, so reading that variant is the only legal access.
    // For `InjectFdSend` the documented contract on
    // `sandlock_action_set_inject_fd_send` transfers ownership of
    // `srcfd` to the supervisor; wrapping it in an `OwnedFd` here is
    // what materialises that transfer.
    let action = unsafe {
        match kind {
            K::Continue => NotifAction::Continue,
            K::Errno => NotifAction::Errno(out.payload.errno),
            K::ReturnValue => NotifAction::ReturnValue(out.payload.return_value),
            K::Hold => NotifAction::Hold,
            K::Kill => {
                let pgid = if out.payload.kill.pgid == 0 {
                    child_pgid
                } else {
                    out.payload.kill.pgid
                };
                NotifAction::Kill { sig: out.payload.kill.sig, pgid }
            }
            K::InjectFdSend => NotifAction::InjectFdSend {
                srcfd: std::os::unix::io::OwnedFd::from_raw_fd(out.payload.inject_send.srcfd),
                newfd_flags: out.payload.inject_send.newfd_flags,
            },
            K::InjectFdSendTracked | K::Unset => unreachable!(),
        }
    };
    Some(action)
}
