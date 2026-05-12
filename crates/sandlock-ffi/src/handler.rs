//! FFI surface for the sandlock `Handler` trait. See `docs/extension-handlers.md`.

use std::os::unix::io::RawFd;
use std::slice;

use sandlock_core::seccomp::notif::{read_child_cstr, read_child_mem, write_child_mem};

pub const SANDLOCK_HANDLER_MODULE_BUILT: bool = true;

/// Opaque child-memory accessor handed to a C handler callback.
///
/// Constructed on the stack inside the Rust adapter just before the
/// callback fires, invalidated when the callback returns. C handlers
/// must not store the pointer beyond the callback's return.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sandlock_mem_handle_t {
    notif_fd: RawFd,
    notif_id: u64,
    pid: u32,
}

impl sandlock_mem_handle_t {
    pub(crate) fn new(notif_fd: RawFd, notif_id: u64, pid: u32) -> Self {
        Self { notif_fd, notif_id, pid }
    }
}

/// Read up to `max_len-1` bytes of a NUL-terminated string at `addr` from the
/// traced child. On success the destination buffer is NUL-terminated and
/// `*out_len` holds the byte count copied (excluding the NUL); returns 0.
/// On failure returns -1 and leaves `*out_len` untouched. `max_len` must be
/// at least 1 to fit the NUL terminator.
///
/// # Safety
/// `handle` must point to a live `sandlock_mem_handle_t` provided by the
/// supervisor; `buf` must be writable for `max_len` bytes; `out_len` must
/// be a valid `size_t*`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_mem_read_cstr(
    handle: *const sandlock_mem_handle_t,
    addr: u64,
    buf: *mut u8,
    max_len: usize,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || buf.is_null() || out_len.is_null() || max_len == 0 {
        return -1;
    }
    let h = &*handle;
    // `max_len` is the caller-supplied buffer size including space for the
    // trailing NUL; reserve one byte so we can always terminate the string.
    let cap = max_len - 1;
    let s = match read_child_cstr(h.notif_fd, h.notif_id, h.pid, addr, cap) {
        Some(s) => s,
        None => return -1,
    };
    let bytes = s.as_bytes();
    let n = bytes.len().min(cap);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n);
    *buf.add(n) = 0;
    *out_len = n;
    0
}

/// Raw byte read at `addr` of exactly `len` bytes. Writes byte count
/// actually read to `*out_len`. Returns 0 on success, -1 on failure.
///
/// # Safety
/// Same constraints as `sandlock_mem_read_cstr`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_mem_read(
    handle: *const sandlock_mem_handle_t,
    addr: u64,
    buf: *mut u8,
    len: usize,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || buf.is_null() || out_len.is_null() {
        return -1;
    }
    let h = &*handle;
    let v = match read_child_mem(h.notif_fd, h.notif_id, h.pid, addr, len) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let n = v.len();
    std::ptr::copy_nonoverlapping(v.as_ptr(), buf, n);
    *out_len = n;
    0
}

/// Write `len` bytes from `buf` into the child at `addr`. Returns 0 on
/// success, -1 on failure.
///
/// # Safety
/// Same constraints as `sandlock_mem_read_cstr`; `buf` must be readable
/// for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn sandlock_mem_write(
    handle: *const sandlock_mem_handle_t,
    addr: u64,
    buf: *const u8,
    len: usize,
) -> i32 {
    if handle.is_null() || buf.is_null() {
        return -1;
    }
    let h = &*handle;
    let data = slice::from_raw_parts(buf, len);
    match write_child_mem(h.notif_fd, h.notif_id, h.pid, addr, data) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Tag distinguishing payload variants of `sandlock_action_out_t`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum sandlock_action_kind_t {
    /// No action set yet; the supervisor treats this as "fall through to
    /// the handler's on_exception policy" (Task 6 wires this up).
    Unset = 0,
    Continue = 1,
    Errno = 2,
    ReturnValue = 3,
    InjectFdSend = 4,
    InjectFdSendTracked = 5,
    Hold = 6,
    Kill = 7,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct sandlock_action_kill_t {
    pub sig: i32,
    pub pgid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct sandlock_action_inject_t {
    /// Owned by the C caller; ownership transfers to the supervisor on
    /// successful invocation of the corresponding setter.
    pub srcfd: i32,
    pub newfd_flags: u32,
}

/// Token used by `InjectFdSendTracked` so the C side can correlate the
/// callback that fires after `SECCOMP_IOCTL_NOTIF_ADDFD` returns the
/// child-side fd number. Wired through to a Rust `OnInjectSuccess`
/// closure built in Task 6.
#[allow(non_camel_case_types)]
pub type sandlock_inject_tracker_t = u64;

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct sandlock_action_inject_tracked_t {
    pub srcfd: i32,
    pub newfd_flags: u32,
    pub tracker: sandlock_inject_tracker_t,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub union sandlock_action_payload_t {
    pub none: u64,
    pub errno: i32,
    pub return_value: i64,
    pub inject_send: sandlock_action_inject_t,
    pub inject_send_tracked: sandlock_action_inject_tracked_t,
    pub kill: sandlock_action_kill_t,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sandlock_action_out_t {
    pub kind: u32,
    pub payload: sandlock_action_payload_t,
}

impl sandlock_action_out_t {
    /// Construct an `Unset` action with all payload bytes zero. The payload
    /// union has variants up to 16 bytes; this ensures all bytes are
    /// initialised before the C handler writes its decision.
    pub fn zeroed() -> Self {
        // Safety: `sandlock_action_payload_t` is `#[repr(C)]` with only
        // integer-and-integer-aggregate variants; the zero bit-pattern is
        // valid for all of them.
        Self {
            kind: sandlock_action_kind_t::Unset as u32,
            payload: unsafe { std::mem::MaybeUninit::zeroed().assume_init() },
        }
    }
}

/// Mark the action as `Continue` (let the syscall proceed unchanged).
///
/// # Safety
/// `out` must be a valid pointer to a `sandlock_action_out_t` writable
/// for the duration of the call, or null (in which case the call is a
/// no-op).
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_continue(out: *mut sandlock_action_out_t) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::Continue as u32;
}

/// Fail the syscall with `errno`.
///
/// # Safety
/// Same constraints as `sandlock_action_set_continue`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_errno(out: *mut sandlock_action_out_t, errno: i32) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::Errno as u32;
    (*out).payload.errno = errno;
}

/// Return a specific value from the syscall without entering the kernel.
///
/// # Safety
/// Same constraints as `sandlock_action_set_continue`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_return_value(
    out: *mut sandlock_action_out_t,
    value: i64,
) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::ReturnValue as u32;
    (*out).payload.return_value = value;
}

/// Inject the supervisor-side fd `srcfd` into the traced child as a new
/// fd (number chosen by the kernel via `SECCOMP_IOCTL_NOTIF_ADDFD`).
///
/// # Safety
/// Same constraints as `sandlock_action_set_continue`; `srcfd` must be
/// a valid open fd in the supervisor process at the moment of the
/// supervisor's dispatch.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_inject_fd_send(
    out: *mut sandlock_action_out_t,
    srcfd: RawFd,
    newfd_flags: u32,
) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::InjectFdSend as u32;
    (*out).payload.inject_send = sandlock_action_inject_t { srcfd, newfd_flags };
}

/// Tracked variant of `sandlock_action_set_inject_fd_send` — the
/// supervisor will fire a Rust-side callback identified by `tracker`
/// once the kernel reports the child-side fd number.
///
/// # Safety
/// Same constraints as `sandlock_action_set_inject_fd_send`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_inject_fd_send_tracked(
    out: *mut sandlock_action_out_t,
    srcfd: RawFd,
    newfd_flags: u32,
    tracker: sandlock_inject_tracker_t,
) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::InjectFdSendTracked as u32;
    (*out).payload.inject_send_tracked = sandlock_action_inject_tracked_t {
        srcfd, newfd_flags, tracker,
    };
}

/// Hold the syscall pending until the supervisor explicitly releases it.
///
/// # Safety
/// Same constraints as `sandlock_action_set_continue`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_hold(out: *mut sandlock_action_out_t) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::Hold as u32;
}

/// Kill the target (`pgid > 0` for the whole process group, or the pid
/// the supervisor records for the notification) with signal `sig`.
///
/// # Safety
/// Same constraints as `sandlock_action_set_continue`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_action_set_kill(
    out: *mut sandlock_action_out_t,
    sig: i32,
    pgid: i32,
) {
    if out.is_null() { return; }
    (*out).kind = sandlock_action_kind_t::Kill as u32;
    (*out).payload.kill = sandlock_action_kill_t { sig, pgid };
}

/// Exception policy applied when the handler callback fails to set a
/// valid action (returns non-zero rc, leaves `kind == Unset`, or panics
/// across the FFI boundary).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum sandlock_exception_policy_t {
    /// Treat the failure as `NotifAction::Kill { sig: SIGKILL, pgid: child_pgid }`.
    /// Default; "fail-closed" — the safe option.
    Kill = 0,
    /// Treat the failure as `NotifAction::Errno(EPERM)`. Useful for
    /// audit-style handlers where the syscall is what failed rather than
    /// the supervisor.
    DenyEperm = 1,
    /// Treat the failure as `NotifAction::Continue`. Explicit fail-open;
    /// only safe when the syscall is *also* allowed by the BPF filter and
    /// Landlock layer (e.g. observability handlers).
    Continue = 2,
}

/// C-callable handler entry point.
///
/// Returns 0 on success (and must have called exactly one setter on
/// `out`). Returns non-zero to signal a handler-internal error; the
/// supervisor then applies the configured exception policy.
#[allow(non_camel_case_types)]
pub type sandlock_handler_fn_t = extern "C" fn(
    ud: *mut std::ffi::c_void,
    notif: *const crate::notif_repr::sandlock_notif_data_t,
    mem: *mut sandlock_mem_handle_t,
    out: *mut sandlock_action_out_t,
) -> i32;

/// Optional destructor invoked when the container is freed.
#[allow(non_camel_case_types)]
pub type sandlock_handler_ud_drop_t = extern "C" fn(ud: *mut std::ffi::c_void);

/// Opaque handler container (B4 — opaque box).
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sandlock_handler_t {
    pub(crate) handler_fn: Option<sandlock_handler_fn_t>,
    pub(crate) ud: *mut std::ffi::c_void,
    pub(crate) ud_drop: Option<sandlock_handler_ud_drop_t>,
    pub(crate) on_exception: sandlock_exception_policy_t,
}

// Safety:
//
// `Send`: required so the supervisor can move the handler container into a
// `tokio::task::spawn_blocking` closure. The struct contains only pointers
// (function pointer + `void*` user-data) and a `#[repr(u32)]` enum, all of
// which are `Send`-safe to move across threads.
//
// `Sync`: required so `sandlock_handler_t` can live inside the
// `Arc<dyn Handler>` storage that the dispatch table uses. This is a
// stronger claim than `Send` — the supervisor may dispatch concurrent
// notifications for the same syscall on different worker threads, meaning
// the same `&sandlock_handler_t` (and the same `ud` pointer) may be read
// from multiple threads at the same time. The C caller is responsible for
// ensuring `ud` is either immutable or guarded by thread-safe state of its
// own (atomics, mutex, etc.) — Rust offers no synchronization for opaque
// `void*` user-data.
unsafe impl Send for sandlock_handler_t {}
unsafe impl Sync for sandlock_handler_t {}

impl Drop for sandlock_handler_t {
    fn drop(&mut self) {
        if let Some(drop_fn) = self.ud_drop.take() {
            if !self.ud.is_null() {
                (drop_fn)(self.ud);
                self.ud = std::ptr::null_mut();
            }
        }
    }
}

/// Allocate a handler container. `handler_fn` must be non-null; passing
/// `ud_drop = None` is legal when `ud` does not require cleanup.
///
/// # Safety
/// `ud` is opaque to Rust — the caller guarantees that the pointer
/// remains valid until either (a) `sandlock_handler_free` is called or
/// (b) the supervisor takes ownership via `sandlock_run_with_handlers`
/// and the run completes.
/// If `on_exception` does not match a defined `sandlock_exception_policy_t`
/// discriminant (0, 1, or 2), the call returns null and no allocation occurs.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handler_new(
    handler_fn: Option<sandlock_handler_fn_t>,
    ud: *mut std::ffi::c_void,
    ud_drop: Option<sandlock_handler_ud_drop_t>,
    on_exception: u32,
) -> *mut sandlock_handler_t {
    if handler_fn.is_none() {
        return std::ptr::null_mut();
    }
    let on_exception = match on_exception {
        0 => sandlock_exception_policy_t::Kill,
        1 => sandlock_exception_policy_t::DenyEperm,
        2 => sandlock_exception_policy_t::Continue,
        // Reject out-of-range discriminants at the FFI boundary so we never
        // store an invalid enum value into the struct — reading one later
        // via `match` would be undefined behaviour.
        _ => return std::ptr::null_mut(),
    };
    let h = Box::new(sandlock_handler_t {
        handler_fn,
        ud,
        ud_drop,
        on_exception,
    });
    Box::into_raw(h)
}

/// Free a handler container that has *not* been registered with a
/// sandbox. After successful registration the supervisor owns the
/// handler; calling this on a registered handler is undefined behaviour
/// (the supervisor's later free would double-free).
///
/// # Safety
/// `h` must be either null or a pointer previously returned by
/// `sandlock_handler_new` that has not yet been registered with the
/// supervisor and has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handler_free(h: *mut sandlock_handler_t) {
    if h.is_null() { return; }
    drop(Box::from_raw(h));
}
