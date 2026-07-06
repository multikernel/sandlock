//! C ABI bindings for sandlock-core.
//!
//! This crate exposes sandlock functionality through a C-compatible interface
//! using opaque handle patterns.  Each `*mut` / `*const` pointer returned by
//! these functions must be freed with its corresponding `_free` function.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::ptr;
use std::time::Duration;

use sandlock_core::pipeline::Stage;
use sandlock_core::sandbox::{BranchAction, ByteSize, SandboxBuilder};
use sandlock_core::{Protection, RunResult, Sandbox, StdioMode};

pub mod handler;
pub mod notif_repr;
mod runtime;

use runtime::{block_on_runtime, build_live_runtime, build_runtime, with_runtime};

// ----------------------------------------------------------------
// Opaque wrapper types
// ----------------------------------------------------------------

/// Opaque handle wrapping a [`Sandbox`].
#[repr(C)]
pub struct sandlock_sandbox_t {
    _private: Sandbox,
}

impl sandlock_sandbox_t {
    /// Crate-private accessor used by `handler.rs` to reach the inner
    /// `Sandbox` when wiring `sandlock_run_with_handlers`. Public-API
    /// callers still go through the opaque-pointer functions in this
    /// module.
    pub(crate) fn inner(&self) -> &Sandbox {
        &self._private
    }
}

impl sandlock_result_t {
    /// Crate-private constructor used by `handler.rs` to wrap a
    /// freshly-produced [`RunResult`] in the opaque public type.
    pub(crate) fn from_run_result(rr: RunResult) -> Self {
        Self { _private: rr }
    }
}

/// Opaque handle wrapping a [`RunResult`].
#[repr(C)]
pub struct sandlock_result_t {
    _private: RunResult,
}

/// Opaque handle wrapping a [`Pipeline`].
#[allow(non_camel_case_types)]
pub struct sandlock_pipeline_t {
    stages: Vec<(Sandbox, Vec<String>)>,
}

// ----------------------------------------------------------------
// Sandbox Builder — filesystem
// ----------------------------------------------------------------

#[no_mangle]
pub extern "C" fn sandlock_sandbox_builder_new() -> *mut SandboxBuilder {
    Box::into_raw(Box::new(Sandbox::builder()))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_fs_read(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.fs_read(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_fs_write(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.fs_write(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_fs_deny(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.fs_deny(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_fs_storage(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.fs_storage(path)))
}

/// # Safety
/// `b` must be a valid pointer. `devices` must point to `len` u32 values (or be null when len == 0).
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_gpu_devices(
    b: *mut SandboxBuilder,
    devices: *const u32,
    len: u32,
) -> *mut SandboxBuilder {
    if b.is_null() || (len > 0 && devices.is_null()) {
        return b;
    }
    let slice = if len > 0 {
        std::slice::from_raw_parts(devices, len as usize)
    } else {
        &[]
    };
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.gpu_devices(slice.to_vec())))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_workdir(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.workdir(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_cwd(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.cwd(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_chroot(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.chroot(path)))
}

/// Add a filesystem mount mapping (virtual_path -> host_path).
///
/// # Safety
/// `b`, `virtual_path`, and `host_path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_fs_mount(
    b: *mut SandboxBuilder,
    virtual_path: *const c_char,
    host_path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || virtual_path.is_null() || host_path.is_null() {
        return b;
    }
    let vp = CStr::from_ptr(virtual_path).to_str().unwrap_or("");
    let hp = CStr::from_ptr(host_path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.fs_mount(vp, hp)))
}

/// Set the COW branch action on successful exit.
/// `action`: 0 = Commit, 1 = Abort, 2 = Keep.
///
/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_on_exit(
    b: *mut SandboxBuilder,
    action: u8,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    let action = match action {
        1 => BranchAction::Abort,
        2 => BranchAction::Keep,
        _ => BranchAction::Commit,
    };
    Box::into_raw(Box::new(builder.on_exit(action)))
}

/// Set the COW branch action on error exit.
/// `action`: 0 = Commit, 1 = Abort, 2 = Keep.
///
/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_on_error(
    b: *mut SandboxBuilder,
    action: u8,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    let action = match action {
        1 => BranchAction::Abort,
        2 => BranchAction::Keep,
        _ => BranchAction::Commit,
    };
    Box::into_raw(Box::new(builder.on_error(action)))
}

// ----------------------------------------------------------------
// Sandbox Builder — resource limits
// ----------------------------------------------------------------

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_max_memory(
    b: *mut SandboxBuilder,
    bytes: u64,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.max_memory(ByteSize(bytes))))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_max_disk(
    b: *mut SandboxBuilder,
    bytes: u64,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.max_disk(ByteSize(bytes))))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_max_processes(
    b: *mut SandboxBuilder,
    n: u32,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.max_processes(n)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_max_cpu(
    b: *mut SandboxBuilder,
    pct: u8,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.max_cpu(pct)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_num_cpus(
    b: *mut SandboxBuilder,
    n: u32,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.num_cpus(n)))
}

/// # Safety
/// `b` must be a valid builder pointer.  `cores` must point to `len` u32 values.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_cpu_cores(
    b: *mut SandboxBuilder,
    cores: *const u32,
    len: u32,
) -> *mut SandboxBuilder {
    if b.is_null() || (len > 0 && cores.is_null()) {
        return b;
    }
    let slice = if len > 0 {
        std::slice::from_raw_parts(cores, len as usize)
    } else {
        &[]
    };
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.cpu_cores(slice.to_vec())))
}

// ----------------------------------------------------------------
// Sandbox Builder — network
// ----------------------------------------------------------------

/// Append a `--net-allow` endpoint rule. `spec` is `host:port[,port,...]`,
/// `:port`, or `*:port`. Spec is validated when the policy is built;
/// invalid specs surface as a build error.
///
/// # Safety
/// `b` and `spec` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_net_allow(
    b: *mut SandboxBuilder,
    spec: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || spec.is_null() {
        return b;
    }
    let spec = CStr::from_ptr(spec).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.net_allow(spec)))
}

/// # Safety
/// `b` and `spec` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_net_deny(
    b: *mut SandboxBuilder,
    spec: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || spec.is_null() {
        return b;
    }
    let spec = CStr::from_ptr(spec).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.net_deny(spec)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_net_allow_bind_port(
    b: *mut SandboxBuilder,
    port: u16,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.net_allow_bind_port(port)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_net_deny_bind_port(
    b: *mut SandboxBuilder,
    port: u16,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.net_deny_bind_port(port)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_port_remap(
    b: *mut SandboxBuilder,
    v: bool,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.port_remap(v)))
}

// Protocol gating (UDP, kernel ping socket) is expressed via
// `net_allow` rule schemes (`udp://`, `icmp://`) rather than separate
// FFI booleans. There is no `allow_udp` / `allow_icmp` setter.
// Sandlock does not expose raw ICMP — SOCK_RAW is unconditionally
// denied at the seccomp layer.

/// Run the sandboxed process as `uid`/`gid` via a single-entry user namespace
/// map (no host privilege required).
///
/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_user(
    b: *mut SandboxBuilder,
    uid: u32,
    gid: u32,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.user(uid, gid)))
}

// ----------------------------------------------------------------
// Sandbox Builder — HTTP ACL
// ----------------------------------------------------------------

/// # Safety
/// `b` and `rule` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_http_allow(
    b: *mut SandboxBuilder,
    rule: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || rule.is_null() {
        return b;
    }
    let rule = CStr::from_ptr(rule).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.http_allow(rule)))
}

/// # Safety
/// `b` and `rule` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_http_deny(
    b: *mut SandboxBuilder,
    rule: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || rule.is_null() {
        return b;
    }
    let rule = CStr::from_ptr(rule).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.http_deny(rule)))
}

/// # Safety
/// `b` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_http_port(
    b: *mut SandboxBuilder,
    port: u16,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.http_port(port)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_http_ca(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.http_ca(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_http_key(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.http_key(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_http_inject_ca(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.http_inject_ca(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_http_ca_out(
    b: *mut SandboxBuilder,
    path: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || path.is_null() {
        return b;
    }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.http_ca_out(path)))
}

// ----------------------------------------------------------------
// Sandbox Builder — isolation & determinism
// ----------------------------------------------------------------

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_random_seed(
    b: *mut SandboxBuilder,
    seed: u64,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.random_seed(seed)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_clean_env(
    b: *mut SandboxBuilder,
    v: bool,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.clean_env(v)))
}

/// # Safety
/// `b`, `key`, and `value` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_env_var(
    b: *mut SandboxBuilder,
    key: *const c_char,
    value: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || key.is_null() || value.is_null() {
        return b;
    }
    let key = CStr::from_ptr(key).to_str().unwrap_or("");
    let value = CStr::from_ptr(value).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.env_var(key, value)))
}

/// # Safety
/// `b` must be a valid builder pointer. `epoch_secs` is seconds since UNIX epoch.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_time_start(
    b: *mut SandboxBuilder,
    epoch_secs: u64,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    let t = std::time::UNIX_EPOCH + Duration::from_secs(epoch_secs);
    Box::into_raw(Box::new(builder.time_start(t)))
}

/// # Safety
/// `b` must be a valid builder pointer. `names` is a comma-separated NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_extra_deny_syscalls(
    b: *mut SandboxBuilder,
    names: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || names.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    let s = CStr::from_ptr(names).to_str().unwrap_or("");
    let calls: Vec<String> = s
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Box::into_raw(Box::new(builder.extra_deny_syscalls(calls)))
}

/// # Safety
/// `b` must be a valid builder pointer. `names` is a comma-separated NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_extra_allow_syscalls(
    b: *mut SandboxBuilder,
    names: *const c_char,
) -> *mut SandboxBuilder {
    if b.is_null() || names.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    let s = CStr::from_ptr(names).to_str().unwrap_or("");
    let names: Vec<String> = s
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Box::into_raw(Box::new(builder.extra_allow_syscalls(names)))
}

/// Resolve a syscall name (e.g. `"openat"`) to its kernel syscall
/// number for the host architecture.
///
/// Intended for filling a `sandlock_handler_registration_t`'s
/// `syscall_nr` without hard-coding architecture-specific numbers.
///
/// Returns the syscall number on success, or `-1` if `name` is NULL,
/// is not valid UTF-8, or names a syscall sandlock does not know. The
/// resolvable set covers the syscalls sandlock filters or supervises;
/// syscalls outside that set (e.g. `getpid`) return `-1` and must be
/// registered by raw number.
///
/// # Safety
/// `name` must be NULL or a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_syscall_nr(name: *const c_char) -> i64 {
    if name.is_null() {
        return -1;
    }
    let name = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match sandlock_core::seccomp::syscall::syscall_name_to_nr(name) {
        Some(nr) => i64::from(nr),
        None => -1,
    }
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_max_open_files(
    b: *mut SandboxBuilder,
    n: c_uint,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.max_open_files(n)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_no_randomize_memory(
    b: *mut SandboxBuilder,
    v: bool,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.no_randomize_memory(v)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_no_huge_pages(
    b: *mut SandboxBuilder,
    v: bool,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.no_huge_pages(v)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_no_coredump(
    b: *mut SandboxBuilder,
    v: bool,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.no_coredump(v)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_deterministic_dirs(
    b: *mut SandboxBuilder,
    v: bool,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.deterministic_dirs(v)))
}

// ----------------------------------------------------------------
// Sandbox Builder — Landlock protections
// ----------------------------------------------------------------

/// C ABI discriminants mirroring [`sandlock_core::Protection`].
///
/// The Rust entry-points below accept the discriminant as a `u32`
/// (rather than a `#[repr(C)]` enum) so that an out-of-range value
/// from a C or Python caller is rejected at the boundary instead of
/// reaching a Rust `match` over an enum and producing undefined
/// behaviour.
///
/// New protections are appended at higher values; old discriminants
/// are never reused.
const PROT_FS_REFER: u32 = 0;
const PROT_FS_TRUNCATE: u32 = 1;
const PROT_NET_TCP: u32 = 2;
const PROT_FS_IOCTL_DEV: u32 = 3;
const PROT_SIGNAL_SCOPE: u32 = 4;
const PROT_ABSTRACT_UNIX_SOCKET_SCOPE: u32 = 5;

/// Convert a raw discriminant into a `Protection`, returning `None`
/// for values not in the known range. Centralises the validation that
/// guards every C-ABI entry-point.
fn try_protection_from_raw(raw: u32) -> Option<Protection> {
    match raw {
        PROT_FS_REFER => Some(Protection::FsRefer),
        PROT_FS_TRUNCATE => Some(Protection::FsTruncate),
        PROT_NET_TCP => Some(Protection::NetTcp),
        PROT_FS_IOCTL_DEV => Some(Protection::FsIoctlDev),
        PROT_SIGNAL_SCOPE => Some(Protection::SignalScope),
        PROT_ABSTRACT_UNIX_SOCKET_SCOPE => Some(Protection::AbstractUnixSocketScope),
        _ => None,
    }
}

/// Per-protection minimum Landlock ABI version required by the host
/// kernel for this protection to be available.
///
/// Returns `0` for any `protection` value that is not a known
/// discriminant — `0` is below every real `min_abi()` (which start at
/// `2`), so callers can use it as an "unknown protection" sentinel
/// without colliding with a valid version number.
#[no_mangle]
pub extern "C" fn sandlock_protection_min_abi(protection: u32) -> u32 {
    match try_protection_from_raw(protection) {
        Some(p) => p.min_abi(),
        None => 0,
    }
}

/// Mark `protection` as degradable on the builder: enforced when the
/// host kernel supports it, silently skipped otherwise.
///
/// Returns the (possibly relocated) builder pointer, mirroring the
/// move-semantics convention used by every other
/// `sandlock_sandbox_builder_*` setter. A null `b` is returned
/// unchanged. An unknown `protection` discriminant is treated as a
/// no-op: the builder is returned untouched.
///
/// # Safety
/// `b` must be a valid builder pointer returned by
/// `sandlock_sandbox_builder_new` (or a previous builder setter) and
/// not freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_allow_degraded(
    b: *mut SandboxBuilder,
    protection: u32,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let p = match try_protection_from_raw(protection) {
        Some(p) => p,
        None => return b,
    };
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.allow_degraded(p)))
}

/// Mark `protection` as disabled on the builder: never enforced, even
/// on a host kernel that supports it.
///
/// Returns the (possibly relocated) builder pointer, mirroring the
/// move-semantics convention used by every other
/// `sandlock_sandbox_builder_*` setter. A null `b` is returned
/// unchanged. An unknown `protection` discriminant is treated as a
/// no-op: the builder is returned untouched.
///
/// # Safety
/// `b` must be a valid builder pointer returned by
/// `sandlock_sandbox_builder_new` (or a previous builder setter) and
/// not freed.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_disable(
    b: *mut SandboxBuilder,
    protection: u32,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let p = match try_protection_from_raw(protection) {
        Some(p) => p,
        None => return b,
    };
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.disable(p)))
}

// ----------------------------------------------------------------
// Sandbox Builder — build & free
// ----------------------------------------------------------------

/// Consume the builder and produce a policy.
/// On success, `*err` is 0 and a non-null policy pointer is returned.
/// On failure, `*err` is -1, null is returned, and `*err_msg` (if
/// non-null) is set to a heap-allocated C string describing the
/// error. The caller must release that string with
/// [`sandlock_string_free`]. Pass `null` for `err_msg` to discard.
///
/// # Safety
/// `b` must be a valid builder pointer. `err` and `err_msg` may both
/// be null. When `err_msg` is non-null, it must point to writable
/// storage for one `*mut c_char`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_build(
    b: *mut SandboxBuilder,
    err: *mut c_int,
    err_msg: *mut *mut c_char,
) -> *mut sandlock_sandbox_t {
    if !err_msg.is_null() {
        *err_msg = ptr::null_mut();
    }
    if b.is_null() {
        // Null-builder is a programmer error in the binding layer,
        // not a policy-validation failure. We surface the err code
        // but deliberately leave err_msg null — there is no
        // user-actionable message and inventing one here would
        // require a hard-coded literal living in the wrong layer.
        if !err.is_null() {
            *err = -1;
        }
        return ptr::null_mut();
    }
    let builder = *Box::from_raw(b);
    match builder.build() {
        Ok(policy) => {
            if !err.is_null() {
                *err = 0;
            }
            Box::into_raw(Box::new(sandlock_sandbox_t { _private: policy }))
        }
        Err(e) => {
            if !err.is_null() {
                *err = -1;
            }
            if !err_msg.is_null() {
                // CString::new fails only on embedded NULs; thiserror
                // Display impls don't produce NULs in this codebase,
                // so on the impossible failure we leave err_msg null
                // rather than substituting an invented string.
                if let Ok(c) = CString::new(format!("{}", e)) {
                    *err_msg = c.into_raw();
                }
            }
            ptr::null_mut()
        }
    }
}

/// # Safety
/// `p` must be null or a valid pointer from `sandlock_sandbox_build`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_free(p: *mut sandlock_sandbox_t) {
    if !p.is_null() {
        drop(Box::from_raw(p));
    }
}

// ----------------------------------------------------------------
// Confine current process
// ----------------------------------------------------------------

/// Confine the calling process with Landlock filesystem rules.
/// This is irreversible. Returns 0 on success, -1 on error.
///
/// # Safety
/// `policy` must be a valid policy pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_confine(policy: *const sandlock_sandbox_t) -> c_int {
    if policy.is_null() {
        return -1;
    }
    let policy = &(*policy)._private;
    let confinement = match sandlock_core::sandbox::Confinement::try_from(policy) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    match sandlock_core::confine(&confinement) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

// ----------------------------------------------------------------
// Run
// ----------------------------------------------------------------

/// Run a command with captured stdout/stderr. Returns a result handle.
///
/// # Safety
/// `policy` must be a valid policy pointer. `name` may be NULL to
/// auto-generate a sandbox name, or a valid NUL-terminated string.
/// `argv` must point to `argc` C strings.
#[no_mangle]
pub unsafe extern "C" fn sandlock_run(
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    argv: *const *const c_char,
    argc: c_uint,
) -> *mut sandlock_result_t {
    if policy.is_null() || argv.is_null() {
        return ptr::null_mut();
    }
    let policy = &(*policy)._private;
    let name = match optional_name(name) {
        Ok(name) => name,
        Err(_) => return ptr::null_mut(),
    };
    let args = read_argv(argv, argc);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let mut sb = match name {
        Some(ref n) => policy.clone().with_name(n.clone()),
        None => policy.clone(),
    };
    match with_runtime(|rt| rt.block_on(sb.run(&arg_refs))) {
        Some(Ok(result)) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        _ => ptr::null_mut(),
    }
}

// ----------------------------------------------------------------
// Sandbox handle (create / start / wait — for pause/resume via PID)
// ----------------------------------------------------------------

/// Opaque handle for a live sandbox.
///
/// Owns both the Sandbox and a small Tokio runtime that drives its
/// supervisor. Live handles need a runtime whose spawned tasks keep
/// progressing after `sandlock_start` returns.
#[allow(non_camel_case_types)]
pub struct sandlock_handle_t {
    sandbox: Sandbox,
    runtime: tokio::runtime::Runtime,
}

/// Shared entry-point prologue for the create/popen family: validate the
/// pointers, parse the optional name and argv, build the requested runtime,
/// and apply the name to a cloned policy. Returns the owned
/// `(Sandbox, Runtime, args)` triple, or `None` on any invalid input or
/// runtime-build failure (callers map `None` to a null handle).
///
/// The tail stays with each caller: `sandlock_create*` drive `sb.create()`,
/// `sandlock_popen` drives `sb.popen()` + fd hand-off. Factoring the prologue
/// here keeps null/name/argv/runtime handling from drifting between them.
///
/// # Safety
/// `policy` must be a valid policy pointer. `name` may be NULL to
/// auto-generate a sandbox name, or a valid NUL-terminated string.
/// `argv` must point to `argc` C strings.
unsafe fn prepare(
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    argv: *const *const c_char,
    argc: c_uint,
    build_rt: fn() -> Option<tokio::runtime::Runtime>,
) -> Option<(Sandbox, tokio::runtime::Runtime, Vec<String>)> {
    if policy.is_null() || argv.is_null() {
        return None;
    }
    let policy = &(*policy)._private;
    let name = optional_name(name).ok()?;
    let args = read_argv(argv, argc);
    let rt = build_rt()?;
    let sb = match name {
        Some(ref n) => policy.clone().with_name(n.clone()),
        None => policy.clone(),
    };
    Some((sb, rt, args))
}

/// Fork the child and install policy; the child is parked between policy
/// install and execve. Returns a live handle. Call `sandlock_start` to
/// release the child to execve.
///
/// # Safety
/// `policy` must be a valid policy pointer. `name` may be NULL to
/// auto-generate a sandbox name, or a valid NUL-terminated string.
/// `argv` must point to `argc` C strings.
unsafe fn sandlock_create_with_runtime(
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    argv: *const *const c_char,
    argc: c_uint,
    build_rt: fn() -> Option<tokio::runtime::Runtime>,
) -> *mut sandlock_handle_t {
    let (mut sb, rt, args) = match prepare(policy, name, argv, argc, build_rt) {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    if !matches!(block_on_runtime(&rt, sb.create(&arg_refs)), Some(Ok(()))) {
        return ptr::null_mut();
    }

    Box::into_raw(Box::new(sandlock_handle_t {
        sandbox: sb,
        runtime: rt,
    }))
}

#[no_mangle]
pub unsafe extern "C" fn sandlock_create(
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    argv: *const *const c_char,
    argc: c_uint,
) -> *mut sandlock_handle_t {
    sandlock_create_with_runtime(policy, name, argv, argc, build_live_runtime)
}

/// Create a sandbox handle for immediate start+wait use on the calling
/// FFI thread. Unlike `sandlock_create`, this uses the thread-local
/// `current_thread` runtime and does not create Tokio worker threads.
///
/// This is intended for blocking one-shot wrappers that call
/// `sandlock_start` and `sandlock_handle_wait*` immediately from the
/// same thread. Long-lived handles should use `sandlock_create` so the
/// supervisor keeps progressing between FFI calls.
///
/// # Safety
/// Same constraints as `sandlock_create`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_create_for_run(
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    argv: *const *const c_char,
    argc: c_uint,
) -> *mut sandlock_handle_t {
    sandlock_create_with_runtime(policy, name, argv, argc, build_runtime)
}

/// Map a raw `StdioMode` discriminant (0=inherit, 1=piped, 2=null) to the enum.
/// Returns `None` for any other value so callers can reject it loudly.
fn stdio_mode_from_raw(v: u32) -> Option<StdioMode> {
    match v {
        0 => Some(StdioMode::Inherit),
        1 => Some(StdioMode::Piped),
        2 => Some(StdioMode::Null),
        _ => None,
    }
}

/// Write `fd` through `out` if non-null; otherwise close it (a piped stream
/// whose fd the caller did not ask for must not leak).
unsafe fn write_or_close_fd(out: *mut c_int, fd: c_int) {
    if out.is_null() {
        if fd >= 0 {
            libc::close(fd);
        }
    } else {
        *out = fd;
    }
}

/// Spawn a confined process with per-stream stdio wiring and return a live
/// handle (the streaming counterpart of `sandlock_create` + `sandlock_start`).
///
/// `stdin_mode`/`stdout_mode`/`stderr_mode` are `StdioMode` discriminants
/// (0=inherit, 1=piped, 2=null). For each stream set to *piped*, the matching
/// `out_*_fd` receives an owned fd the caller must `close()`; for inherit/null
/// it receives -1. Pass null for an `out_*_fd` to discard that fd (it is closed
/// rather than leaked). Returns null on error (unknown mode, build/fork
/// failure) with every `out_*_fd` left -1.
///
/// The handle uses a multi-threaded runtime so the seccomp supervisor keeps
/// pumping while the caller does blocking IO on the returned fds. Wait for the
/// process with `sandlock_handle_wait`, terminate with `sandlock_handle_kill`,
/// and release with `sandlock_handle_free`.
///
/// Deadlock warning: a piped fd is yours once returned — `close()` a piped
/// `out_stdin_fd` *before* `sandlock_handle_wait`, or a child that reads to EOF
/// (e.g. `cat`) never exits and the wait blocks forever. Likewise drain a piped
/// `out_stdout_fd`/`out_stderr_fd` before waiting: a child that fills the pipe
/// buffer blocks on write and never reaches exit.
///
/// # Safety
/// As `sandlock_create`; `out_*_fd` must each be null or a valid `*mut c_int`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_popen(
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    argv: *const *const c_char,
    argc: c_uint,
    stdin_mode: u32,
    stdout_mode: u32,
    stderr_mode: u32,
    out_stdin_fd: *mut c_int,
    out_stdout_fd: *mut c_int,
    out_stderr_fd: *mut c_int,
) -> *mut sandlock_handle_t {
    use std::os::fd::IntoRawFd;

    if !out_stdin_fd.is_null() {
        *out_stdin_fd = -1;
    }
    if !out_stdout_fd.is_null() {
        *out_stdout_fd = -1;
    }
    if !out_stderr_fd.is_null() {
        *out_stderr_fd = -1;
    }

    let (stdin, stdout, stderr) = match (
        stdio_mode_from_raw(stdin_mode),
        stdio_mode_from_raw(stdout_mode),
        stdio_mode_from_raw(stderr_mode),
    ) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => {
            // Fail loud, not into an indistinguishable NULL: name the offending
            // discriminant(s) so the binding author sees why the handle is null.
            eprintln!(
                "sandlock: sandlock_popen rejected an unknown StdioMode \
                 (stdin={stdin_mode}, stdout={stdout_mode}, stderr={stderr_mode}); \
                 valid values are 0=inherit, 1=piped, 2=null"
            );
            return ptr::null_mut();
        }
    };
    // Shared prologue (null/name/argv/runtime) via `prepare`; popen keeps its own
    // `sb.popen()` + fd-handoff tail. build_live_runtime: the multi-threaded
    // runtime keeps the seccomp supervisor pumping during the caller's blocking IO.
    let (mut sb, rt, args) = match prepare(policy, name, argv, argc, build_live_runtime) {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    // popen returns a Process borrowing `sb`; take the owned fds and let it drop
    // so `sb` can move into the handle. The process keeps running (owned by `sb`).
    // Return OwnedFds (not raw ints) from the future: on the Err/None branch
    // below they drop-close themselves instead of leaking a dangling raw fd.
    let owned = block_on_runtime(&rt, async {
        let mut proc = sb.popen(&arg_refs, stdin, stdout, stderr).await?;
        Ok::<_, sandlock_core::SandlockError>((
            proc.take_stdin(),
            proc.take_stdout(),
            proc.take_stderr(),
        ))
    });
    let (in_fd, out_fd, err_fd) = match owned {
        Some(Ok(t)) => t,
        _ => return ptr::null_mut(),
    };
    // Convert to raw only on the infallible side of the match.
    write_or_close_fd(out_stdin_fd, in_fd.map(|f| f.into_raw_fd()).unwrap_or(-1));
    write_or_close_fd(out_stdout_fd, out_fd.map(|f| f.into_raw_fd()).unwrap_or(-1));
    write_or_close_fd(out_stderr_fd, err_fd.map(|f| f.into_raw_fd()).unwrap_or(-1));

    Box::into_raw(Box::new(sandlock_handle_t {
        sandbox: sb,
        runtime: rt,
    }))
}

/// Release a previously `sandlock_create`d child to execve. Returns 0 on
/// success, -1 on error.
///
/// # Safety
/// `h` must be a valid handle from `sandlock_create`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_start(h: *mut sandlock_handle_t) -> c_int {
    if h.is_null() {
        return -1;
    }
    let h = &mut *h;
    if h.sandbox.start().is_err() {
        return -1;
    }
    0
}

/// Get the child PID. Returns 0 if not available.
///
/// # Safety
/// `h` must be a valid handle from `sandlock_create`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_pid(h: *const sandlock_handle_t) -> i32 {
    if h.is_null() {
        return 0;
    }
    (*h).sandbox.pid().unwrap_or(0)
}

/// Send SIGKILL to the handle's entire process group. Idempotent: a process
/// that already exited is not an error. Returns 0 on success, -1 on error.
/// The handle remains valid; call `sandlock_handle_wait` to collect the exit
/// status and `sandlock_handle_free` to release it.
///
/// # Safety
/// `h` must be a valid handle from `sandlock_create` / `sandlock_popen`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_kill(h: *mut sandlock_handle_t) -> c_int {
    if h.is_null() {
        return -1;
    }
    let h = &mut *h;
    if h.sandbox.kill().is_err() {
        return -1;
    }
    0
}

/// Wait for the sandbox to exit. Returns a result handle with stdout/stderr.
///
/// For a `sandlock_popen` handle, close a piped `out_stdin_fd` and drain any
/// piped `out_stdout_fd`/`out_stderr_fd` *before* calling this, or a child that
/// reads to EOF or fills a pipe buffer never exits and this blocks forever.
///
/// # Safety
/// `h` must be a valid handle from `sandlock_create` / `sandlock_popen`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_wait(h: *mut sandlock_handle_t) -> *mut sandlock_result_t {
    if h.is_null() {
        return ptr::null_mut();
    }
    let h = &mut *h;
    match block_on_runtime(&h.runtime, h.sandbox.wait()) {
        Some(Ok(result)) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        _ => ptr::null_mut(),
    }
}

/// Wait for the sandbox to exit with a timeout in milliseconds.
/// Returns a result handle, or null on error. On timeout the sandbox is
/// killed and a result with `ExitStatus::Timeout` is returned.
///
/// # Safety
/// `h` must be a valid handle from `sandlock_create`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_wait_timeout(
    h: *mut sandlock_handle_t,
    timeout_ms: u64,
) -> *mut sandlock_result_t {
    if h.is_null() {
        return ptr::null_mut();
    }
    let h = &mut *h;

    if timeout_ms == 0 {
        // No timeout -- same as sandlock_handle_wait.
        return match block_on_runtime(&h.runtime, h.sandbox.wait()) {
            Some(Ok(result)) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
            _ => ptr::null_mut(),
        };
    }

    let dur = Duration::from_millis(timeout_ms);
    match block_on_runtime(&h.runtime, async {
        tokio::time::timeout(dur, h.sandbox.wait()).await
    }) {
        Some(Ok(Ok(result))) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        Some(Ok(Err(_))) | None => ptr::null_mut(),
        Some(Err(_)) => {
            // Timeout -- kill the process and return a timeout result.
            let _ = h.sandbox.kill();
            let result = RunResult::timeout();
            Box::into_raw(Box::new(sandlock_result_t { _private: result }))
        }
    }
}

/// Get port mappings as a JSON string (e.g. `{"80":9001,"443":9002}`).
/// Returns a C string that must be freed with `sandlock_string_free`.
/// Returns null if port_remap is not active or no ports are mapped.
///
/// # Safety
/// `h` must be a valid handle from `sandlock_create`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_port_mappings(h: *const sandlock_handle_t) -> *mut c_char {
    if h.is_null() {
        return ptr::null_mut();
    }
    let h = &*h;
    let map = match block_on_runtime(&h.runtime, h.sandbox.port_mappings()) {
        Some(map) => map,
        None => return ptr::null_mut(),
    };
    if map.is_empty() {
        return ptr::null_mut();
    }
    let json = serde_json::to_string(&map).unwrap_or_default();
    match CString::new(json) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a sandbox handle. Kills the process if still running.
///
/// # Safety
/// `h` must be null or a valid handle from `sandlock_create` / `sandlock_popen`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_free(h: *mut sandlock_handle_t) {
    if !h.is_null() {
        let mut handle = *Box::from_raw(h);
        let _ = handle.sandbox.kill();
    }
}

/// Run a command with inherited stdio (interactive). Returns exit code.
///
/// # Safety
/// `policy` must be a valid policy pointer. `name` may be NULL to
/// auto-generate a sandbox name, or a valid NUL-terminated string.
/// `argv` must point to `argc` C strings.
#[no_mangle]
pub unsafe extern "C" fn sandlock_run_interactive(
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    argv: *const *const c_char,
    argc: c_uint,
) -> c_int {
    if policy.is_null() || argv.is_null() {
        return -1;
    }
    let policy = &(*policy)._private;
    let name = match optional_name(name) {
        Ok(name) => name,
        Err(_) => return -1,
    };
    let args = read_argv(argv, argc);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let mut sb = match name {
        Some(ref n) => policy.clone().with_name(n.clone()),
        None => policy.clone(),
    };
    match with_runtime(|rt| rt.block_on(sb.run_interactive(&arg_refs))) {
        Some(Ok(result)) => result.code().unwrap_or(-1),
        _ => -1,
    }
}

// ----------------------------------------------------------------
// Result accessors
// ----------------------------------------------------------------

/// # Safety
/// `r` must be null or a valid result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_exit_code(r: *const sandlock_result_t) -> c_int {
    if r.is_null() {
        return -1;
    }
    (*r)._private.code().unwrap_or(-1)
}

/// # Safety
/// `r` must be null or a valid result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_success(r: *const sandlock_result_t) -> bool {
    if r.is_null() {
        return false;
    }
    (*r)._private.success()
}

/// Get captured stdout. Returns a malloc'd NUL-terminated string.
/// Caller must free with `sandlock_string_free`. Returns null if no capture.
///
/// # Safety
/// `r` must be null or a valid result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_stdout(r: *const sandlock_result_t) -> *mut c_char {
    if r.is_null() {
        return ptr::null_mut();
    }
    match (*r)._private.stdout.as_ref() {
        Some(bytes) => {
            let s = String::from_utf8_lossy(bytes);
            match CString::new(s.as_ref()) {
                Ok(cs) => cs.into_raw(),
                Err(_) => ptr::null_mut(),
            }
        }
        None => ptr::null_mut(),
    }
}

/// Get captured stderr. Same semantics as `sandlock_result_stdout`.
///
/// # Safety
/// `r` must be null or a valid result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_stderr(r: *const sandlock_result_t) -> *mut c_char {
    if r.is_null() {
        return ptr::null_mut();
    }
    match (*r)._private.stderr.as_ref() {
        Some(bytes) => {
            let s = String::from_utf8_lossy(bytes);
            match CString::new(s.as_ref()) {
                Ok(cs) => cs.into_raw(),
                Err(_) => ptr::null_mut(),
            }
        }
        None => ptr::null_mut(),
    }
}

/// Get captured stdout as raw bytes. Writes length to `*len`.
/// Returns pointer to internal buffer (valid until result is freed). Null if no capture.
///
/// # Safety
/// `r` must be a valid result pointer. `len` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_stdout_bytes(
    r: *const sandlock_result_t,
    len: *mut usize,
) -> *const u8 {
    if r.is_null() || len.is_null() {
        return ptr::null();
    }
    match (*r)._private.stdout.as_ref() {
        Some(bytes) => {
            *len = bytes.len();
            bytes.as_ptr()
        }
        None => {
            *len = 0;
            ptr::null()
        }
    }
}

/// Get captured stderr as raw bytes.
///
/// # Safety
/// `r` must be a valid result pointer. `len` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_stderr_bytes(
    r: *const sandlock_result_t,
    len: *mut usize,
) -> *const u8 {
    if r.is_null() || len.is_null() {
        return ptr::null();
    }
    match (*r)._private.stderr.as_ref() {
        Some(bytes) => {
            *len = bytes.len();
            bytes.as_ptr()
        }
        None => {
            *len = 0;
            ptr::null()
        }
    }
}

/// # Safety
/// `r` must be null or a valid pointer from `sandlock_run`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_free(r: *mut sandlock_result_t) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}

/// Free a string returned by `sandlock_result_stdout` or `sandlock_result_stderr`.
///
/// # Safety
/// `s` must be null or a pointer from a `sandlock_result_std*` function.
#[no_mangle]
pub unsafe extern "C" fn sandlock_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

// ----------------------------------------------------------------
// Dry-run
// ----------------------------------------------------------------

/// Opaque dry-run result.
#[allow(non_camel_case_types)]
pub struct sandlock_dry_run_result_t {
    _private: sandlock_core::DryRunResult,
}

/// Run a command in dry-run mode with captured stdout/stderr.
///
/// # Safety
/// `policy` must be a valid policy pointer. `name` may be NULL to
/// auto-generate a sandbox name, or a valid NUL-terminated string.
/// `argv` must point to `argc` C strings.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run(
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    argv: *const *const c_char,
    argc: c_uint,
) -> *mut sandlock_dry_run_result_t {
    if policy.is_null() || argv.is_null() {
        return ptr::null_mut();
    }
    let policy = &(*policy)._private;
    let name = match optional_name(name) {
        Ok(name) => name,
        Err(_) => return ptr::null_mut(),
    };
    let args = read_argv(argv, argc);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let mut sb = match name {
        Some(ref n) => policy.clone().with_name(n.clone()),
        None => policy.clone(),
    };
    match with_runtime(|rt| rt.block_on(sb.dry_run(&arg_refs))) {
        Some(Ok(result)) => Box::into_raw(Box::new(sandlock_dry_run_result_t { _private: result })),
        _ => ptr::null_mut(),
    }
}

/// Get the exit code from a dry-run result.
///
/// # Safety
/// `r` must be a valid dry-run result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_exit_code(
    r: *const sandlock_dry_run_result_t,
) -> c_int {
    if r.is_null() {
        return -1;
    }
    (*r)._private.run_result.code().unwrap_or(-1) as c_int
}

/// Check if the dry-run result indicates success.
///
/// # Safety
/// `r` must be a valid dry-run result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_success(
    r: *const sandlock_dry_run_result_t,
) -> bool {
    if r.is_null() {
        return false;
    }
    (*r)._private.run_result.success()
}

/// Get captured stdout bytes from a dry-run result.
///
/// # Safety
/// `r` must be a valid dry-run result pointer. `len` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_stdout_bytes(
    r: *const sandlock_dry_run_result_t,
    len: *mut usize,
) -> *const u8 {
    if r.is_null() {
        if !len.is_null() {
            *len = 0;
        }
        return ptr::null();
    }
    match &(*r)._private.run_result.stdout {
        Some(v) => {
            *len = v.len();
            v.as_ptr()
        }
        None => {
            *len = 0;
            ptr::null()
        }
    }
}

/// Get captured stderr bytes from a dry-run result.
///
/// # Safety
/// `r` must be a valid dry-run result pointer. `len` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_stderr_bytes(
    r: *const sandlock_dry_run_result_t,
    len: *mut usize,
) -> *const u8 {
    if r.is_null() {
        if !len.is_null() {
            *len = 0;
        }
        return ptr::null();
    }
    match &(*r)._private.run_result.stderr {
        Some(v) => {
            *len = v.len();
            v.as_ptr()
        }
        None => {
            *len = 0;
            ptr::null()
        }
    }
}

/// Get the number of filesystem changes in a dry-run result.
///
/// # Safety
/// `r` must be a valid dry-run result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_changes_len(
    r: *const sandlock_dry_run_result_t,
) -> usize {
    if r.is_null() {
        return 0;
    }
    (*r)._private.changes.len()
}

/// Get the kind of the i-th change: 'A' (added), 'M' (modified), 'D' (deleted).
///
/// # Safety
/// `r` must be a valid dry-run result pointer. `i` must be < changes_len.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_change_kind(
    r: *const sandlock_dry_run_result_t,
    i: usize,
) -> c_char {
    if r.is_null() {
        return 0;
    }
    let changes = &(*r)._private.changes;
    if i >= changes.len() {
        return 0;
    }
    use sandlock_core::ChangeKind;
    match changes[i].kind {
        ChangeKind::Added => b'A' as c_char,
        ChangeKind::Modified => b'M' as c_char,
        ChangeKind::Deleted => b'D' as c_char,
    }
}

/// Get the path of the i-th change as a C string. Caller must free with `sandlock_string_free`.
///
/// # Safety
/// `r` must be a valid dry-run result pointer. `i` must be < changes_len.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_change_path(
    r: *const sandlock_dry_run_result_t,
    i: usize,
) -> *mut c_char {
    if r.is_null() {
        return ptr::null_mut();
    }
    let changes = &(*r)._private.changes;
    if i >= changes.len() {
        return ptr::null_mut();
    }
    let path = changes[i].path.to_string_lossy();
    match CString::new(path.as_bytes()) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a dry-run result.
///
/// # Safety
/// `r` must be null or a valid dry-run result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_free(r: *mut sandlock_dry_run_result_t) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}

// ----------------------------------------------------------------
// Pipeline
// ----------------------------------------------------------------

/// Create a new empty pipeline.
#[no_mangle]
pub extern "C" fn sandlock_pipeline_new() -> *mut sandlock_pipeline_t {
    Box::into_raw(Box::new(sandlock_pipeline_t { stages: Vec::new() }))
}

/// Add a stage to the pipeline. The policy is cloned; the caller retains ownership.
///
/// # Safety
/// `pipe` must be a valid pipeline pointer. `policy` must be a valid policy pointer.
/// `argv` must point to `argc` C strings.
#[no_mangle]
pub unsafe extern "C" fn sandlock_pipeline_add_stage(
    pipe: *mut sandlock_pipeline_t,
    policy: *const sandlock_sandbox_t,
    argv: *const *const c_char,
    argc: c_uint,
) {
    if pipe.is_null() || policy.is_null() || argv.is_null() {
        return;
    }
    let policy = (*policy)._private.clone();
    let args = read_argv(argv, argc);
    (*pipe).stages.push((policy, args));
}

/// Run the pipeline. Returns a result handle (last stage's output).
/// `timeout_ms` is the total timeout in milliseconds (0 = no timeout).
///
/// # Safety
/// `pipe` is consumed and freed by this call. Do not use it after.
#[no_mangle]
pub unsafe extern "C" fn sandlock_pipeline_run(
    pipe: *mut sandlock_pipeline_t,
    timeout_ms: u64,
) -> *mut sandlock_result_t {
    if pipe.is_null() {
        return ptr::null_mut();
    }
    let pipe = *Box::from_raw(pipe);

    if pipe.stages.len() < 2 {
        return ptr::null_mut();
    }

    let mut stages: Vec<Stage> = pipe
        .stages
        .into_iter()
        .map(|(policy, args)| {
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            Stage::new(&policy, &arg_refs)
        })
        .collect();

    // Build pipeline using BitOr
    let first = stages.remove(0);
    let second = stages.remove(0);
    let mut pipeline = first | second;
    for stage in stages {
        pipeline = pipeline | stage;
    }

    let timeout = if timeout_ms > 0 {
        Some(Duration::from_millis(timeout_ms))
    } else {
        None
    };

    match with_runtime(|rt| rt.block_on(pipeline.run(timeout))) {
        Some(Ok(result)) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        _ => ptr::null_mut(),
    }
}

/// Free a pipeline without running it.
///
/// # Safety
/// `pipe` must be null or a valid pipeline pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_pipeline_free(pipe: *mut sandlock_pipeline_t) {
    if !pipe.is_null() {
        drop(Box::from_raw(pipe));
    }
}

// ----------------------------------------------------------------
// Gather (fan-in)
// ----------------------------------------------------------------

#[allow(non_camel_case_types)]
pub struct sandlock_gather_t {
    sources: Vec<(String, sandlock_core::Sandbox, Vec<String>)>,
    consumer: Option<(sandlock_core::Sandbox, Vec<String>)>,
}

/// Create a new empty gather.
#[no_mangle]
pub extern "C" fn sandlock_gather_new() -> *mut sandlock_gather_t {
    Box::into_raw(Box::new(sandlock_gather_t {
        sources: Vec::new(),
        consumer: None,
    }))
}

/// Add a named source to the gather.
///
/// # Safety
/// All pointers must be valid. `name` must be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_gather_add_source(
    g: *mut sandlock_gather_t,
    name: *const c_char,
    policy: *const sandlock_sandbox_t,
    argv: *const *const c_char,
    argc: c_uint,
) {
    if g.is_null() || name.is_null() || policy.is_null() || argv.is_null() {
        return;
    }
    let name = CStr::from_ptr(name).to_str().unwrap_or("").to_string();
    let policy = (*policy)._private.clone();
    let args = read_argv(argv, argc);
    (*g).sources.push((name, policy, args));
}

/// Set the consumer stage for the gather.
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn sandlock_gather_set_consumer(
    g: *mut sandlock_gather_t,
    policy: *const sandlock_sandbox_t,
    argv: *const *const c_char,
    argc: c_uint,
) {
    if g.is_null() || policy.is_null() || argv.is_null() {
        return;
    }
    let policy = (*policy)._private.clone();
    let args = read_argv(argv, argc);
    (*g).consumer = Some((policy, args));
}

/// Run the gather. Consumes the gather handle.
///
/// # Safety
/// `g` must be a valid gather pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_gather_run(
    g: *mut sandlock_gather_t,
    timeout_ms: u64,
) -> *mut sandlock_result_t {
    if g.is_null() {
        return ptr::null_mut();
    }
    let g = *Box::from_raw(g);

    let (consumer_policy, consumer_args) = match g.consumer {
        Some(c) => c,
        None => return ptr::null_mut(),
    };

    let mut gather = sandlock_core::Gather::new();
    for (name, policy, args) in g.sources {
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        gather = gather.source(&name, sandlock_core::Stage::new(&policy, &arg_refs));
    }
    let consumer_refs: Vec<&str> = consumer_args.iter().map(|s| s.as_str()).collect();
    gather = gather.consumer(sandlock_core::Stage::new(&consumer_policy, &consumer_refs));

    let timeout = if timeout_ms > 0 {
        Some(Duration::from_millis(timeout_ms))
    } else {
        None
    };

    match with_runtime(|rt| rt.block_on(gather.run(timeout))) {
        Some(Ok(result)) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        _ => ptr::null_mut(),
    }
}

/// Free a gather without running it.
///
/// # Safety
/// `g` must be null or a valid gather pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_gather_free(g: *mut sandlock_gather_t) {
    if !g.is_null() {
        drop(Box::from_raw(g));
    }
}

// ----------------------------------------------------------------
// Sandbox callback (policy_fn)
// ----------------------------------------------------------------

/// C-compatible syscall event passed to the policy callback.
///
/// Path strings are intentionally absent (issue #27); use static Landlock
/// rules for path-based access control. argv is exposed for execve only
/// and is TOCTOU-safe via sibling-thread freeze before Continue.
#[repr(C)]
pub struct sandlock_event_t {
    pub syscall: *const c_char,
    /// Category: 0=File, 1=Network, 2=Process, 3=Memory
    pub category: u8,
    pub pid: u32,
    pub parent_pid: u32,     // 0 if unknown
    pub host: *const c_char, // NULL if not applicable
    pub port: u16,
    pub denied: bool,
    pub argv: *const *const c_char, // NULL-terminated array, or NULL
    pub argc: u32,
}

/// C-compatible policy context handle.
#[allow(non_camel_case_types)]
pub struct sandlock_ctx_t {
    ctx: *mut sandlock_core::policy_fn::PolicyContext,
}

/// C callback type for policy_fn.
/// Return value: 0 = allow, -1 = deny (EPERM), -2 = audit (allow + flag),
/// positive = deny with that errno (e.g. 13 = EACCES). Any other value fails
/// closed (deny); do not return `-errno`, which is reserved and not allowed.
#[allow(non_camel_case_types)]
pub type sandlock_policy_fn_t = unsafe extern "C" fn(
    event: *const sandlock_event_t,
    ctx: *mut sandlock_ctx_t,
    user_data: *mut c_void,
) -> i32;

/// C destructor type for policy_fn user data.
///
/// Called when the native policy callback is dropped. This may be later than a
/// single run when the policy has been cloned; it fires once for the final
/// callback reference.
#[allow(non_camel_case_types)]
pub type sandlock_policy_ud_drop_t = unsafe extern "C" fn(user_data: *mut c_void);

struct PolicyCallbackState {
    cb: sandlock_policy_fn_t,
    user_data: *mut c_void,
    user_data_drop: Option<sandlock_policy_ud_drop_t>,
}

// SAFETY: `user_data` is opaque to Rust. The FFI caller promises it remains
// valid for the callback lifetime and is safe to access from sandlock's
// policy-fn worker thread. The function pointers are immutable.
unsafe impl Send for PolicyCallbackState {}
unsafe impl Sync for PolicyCallbackState {}

impl PolicyCallbackState {
    unsafe fn call(&self, event: *const sandlock_event_t, ctx: *mut sandlock_ctx_t) -> i32 {
        (self.cb)(event, ctx, self.user_data)
    }
}

impl Drop for PolicyCallbackState {
    fn drop(&mut self) {
        if let Some(drop_fn) = self.user_data_drop {
            unsafe { drop_fn(self.user_data) };
        }
    }
}

/// Translate a C policy callback's return value into a core `Verdict`.
///
/// `0` allows, `-1` denies (EPERM), `-2` audits, and any positive value denies
/// with that errno. Every other value fails closed (`Deny`): a negative other
/// than -1/-2 is reserved and a likely `-errno` mistake by a caller used to
/// kernel convention, so denying keeps a typo'd verdict from silently disabling
/// the policy.
fn policy_ret_to_verdict(ret: i32) -> sandlock_core::policy_fn::Verdict {
    use sandlock_core::policy_fn::Verdict;
    match ret {
        0 => Verdict::Allow,
        -1 => Verdict::Deny,
        -2 => Verdict::Audit,
        errno if errno > 0 => Verdict::DenyWith(errno),
        _ => Verdict::Deny,
    }
}

/// Set a policy callback on the builder.
///
/// # Safety
/// `b` must be a valid builder pointer. `cb` must be a valid function pointer
/// that remains valid for the lifetime of the sandbox callback.
/// `user_data` is opaque to Rust and is passed back to every callback
/// invocation. It must remain valid and be safe to access from the policy-fn
/// worker thread until `user_data_drop` is invoked. `user_data_drop = None` is
/// legal when no cleanup is needed; if provided, it must not unwind.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_builder_policy_fn(
    b: *mut SandboxBuilder,
    cb: sandlock_policy_fn_t,
    user_data: *mut c_void,
    user_data_drop: Option<unsafe extern "C" fn(user_data: *mut c_void)>,
) -> *mut SandboxBuilder {
    if b.is_null() {
        return b;
    }
    let builder = *Box::from_raw(b);
    let state = PolicyCallbackState {
        cb,
        user_data,
        user_data_drop,
    };

    // Wrap the C callback in a Rust closure
    let cb_fn = move |event: sandlock_core::policy_fn::SyscallEvent,
                      ctx: &mut sandlock_core::policy_fn::PolicyContext| {
        let syscall_c = CString::new(event.syscall.as_str()).unwrap_or_default();
        let host_c = event
            .host
            .map(|ip| CString::new(ip.to_string()).unwrap_or_default());

        // Convert argv to C string array. CStrings live until end of closure.
        let argv_c: Vec<CString> = event
            .argv
            .as_ref()
            .map(|args| {
                args.iter()
                    .filter_map(|s| CString::new(s.as_str()).ok())
                    .collect()
            })
            .unwrap_or_default();
        let argv_ptrs: Vec<*const c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
        let argc = argv_ptrs.len() as u32;

        let category = match event.category {
            sandlock_core::policy_fn::SyscallCategory::File => 0u8,
            sandlock_core::policy_fn::SyscallCategory::Network => 1,
            sandlock_core::policy_fn::SyscallCategory::Process => 2,
            sandlock_core::policy_fn::SyscallCategory::Memory => 3,
        };

        let c_event = sandlock_event_t {
            syscall: syscall_c.as_ptr(),
            category,
            pid: event.pid,
            parent_pid: event.parent_pid.unwrap_or(0),
            host: host_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            port: event.port.unwrap_or(0),
            denied: event.denied,
            argv: if argv_ptrs.is_empty() {
                ptr::null()
            } else {
                argv_ptrs.as_ptr()
            },
            argc,
        };

        let mut c_ctx = sandlock_ctx_t { ctx: ctx as *mut _ };

        let ret = unsafe { state.call(&c_event, &mut c_ctx) };
        policy_ret_to_verdict(ret)
    };

    Box::into_raw(Box::new(builder.policy_fn(cb_fn)))
}

/// Restrict network to the given IPs. Permanent — cannot grant back.
///
/// # Safety
/// `ctx` must be a valid context pointer from inside a policy callback.
/// `ips` must point to `count` valid C strings.
#[no_mangle]
pub unsafe extern "C" fn sandlock_ctx_restrict_network(
    ctx: *mut sandlock_ctx_t,
    ips: *const *const c_char,
    count: u32,
) {
    if ctx.is_null() {
        return;
    }
    let ctx = &mut *(*ctx).ctx;
    let parsed: Vec<std::net::IpAddr> = (0..count as usize)
        .filter_map(|i| {
            let s = CStr::from_ptr(*ips.add(i)).to_str().ok()?;
            s.parse().ok()
        })
        .collect();
    ctx.restrict_network(&parsed);
}

/// Grant network IPs (within ceiling). Fails silently if restricted.
///
/// # Safety
/// Same as `sandlock_ctx_restrict_network`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_ctx_grant_network(
    ctx: *mut sandlock_ctx_t,
    ips: *const *const c_char,
    count: u32,
) {
    if ctx.is_null() {
        return;
    }
    let ctx = &mut *(*ctx).ctx;
    let parsed: Vec<std::net::IpAddr> = (0..count as usize)
        .filter_map(|i| {
            let s = CStr::from_ptr(*ips.add(i)).to_str().ok()?;
            s.parse().ok()
        })
        .collect();
    let _ = ctx.grant_network(&parsed);
}

/// Restrict max memory. Permanent.
///
/// # Safety
/// `ctx` must be a valid context pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_ctx_restrict_max_memory(ctx: *mut sandlock_ctx_t, bytes: u64) {
    if ctx.is_null() {
        return;
    }
    let ctx = &mut *(*ctx).ctx;
    ctx.restrict_max_memory(bytes);
}

/// Restrict max processes. Permanent.
///
/// # Safety
/// `ctx` must be a valid context pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_ctx_restrict_max_processes(ctx: *mut sandlock_ctx_t, n: u32) {
    if ctx.is_null() {
        return;
    }
    let ctx = &mut *(*ctx).ctx;
    ctx.restrict_max_processes(n);
}

/// Restrict network for a specific PID.
///
/// # Safety
/// `ctx` must be a valid context pointer. `ips` must point to `count` C strings.
#[no_mangle]
pub unsafe extern "C" fn sandlock_ctx_restrict_pid_network(
    ctx: *mut sandlock_ctx_t,
    pid: u32,
    ips: *const *const c_char,
    count: u32,
) {
    if ctx.is_null() {
        return;
    }
    let ctx = &mut *(*ctx).ctx;
    let parsed: Vec<std::net::IpAddr> = (0..count as usize)
        .filter_map(|i| {
            let s = CStr::from_ptr(*ips.add(i)).to_str().ok()?;
            s.parse().ok()
        })
        .collect();
    ctx.restrict_pid_network(pid, &parsed);
}

/// Deny access to a path dynamically (checked on openat).
///
/// # Safety
/// `ctx` must be a valid context pointer. `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_ctx_deny_path(ctx: *mut sandlock_ctx_t, path: *const c_char) {
    if ctx.is_null() || path.is_null() {
        return;
    }
    let ctx = &*(*ctx).ctx;
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    ctx.deny_path(path);
}

/// Remove a previously denied path.
///
/// # Safety
/// `ctx` must be a valid context pointer. `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_ctx_allow_path(ctx: *mut sandlock_ctx_t, path: *const c_char) {
    if ctx.is_null() || path.is_null() {
        return;
    }
    let ctx = &*(*ctx).ctx;
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    ctx.allow_path(path);
}

// ----------------------------------------------------------------
// COW Fork
// ----------------------------------------------------------------

/// C callback types for fork init and work functions.
#[allow(non_camel_case_types)]
pub type sandlock_init_fn_t = unsafe extern "C" fn();
#[allow(non_camel_case_types)]
pub type sandlock_work_fn_t = unsafe extern "C" fn(clone_id: u32);

/// Create a sandbox with init/work functions for COW forking.
///
/// # Safety
/// `policy` must be valid. `name` may be NULL to auto-generate a sandbox
/// name, or a valid NUL-terminated string. `init_fn` and `work_fn` must
/// be valid function pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_new_with_fns(
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    init_fn: sandlock_init_fn_t,
    work_fn: sandlock_work_fn_t,
) -> *mut Sandbox {
    if policy.is_null() {
        return ptr::null_mut();
    }
    let policy = &(*policy)._private;
    let name = match optional_name(name) {
        Ok(name) => name,
        Err(_) => return ptr::null_mut(),
    };

    let init = move || unsafe { init_fn() };
    let work = move |id: u32| unsafe { work_fn(id) };

    let sb = match name {
        Some(ref n) => policy.clone().with_name(n.clone()),
        None => policy.clone(),
    };
    let sb = sb.with_init_fn(init).with_work_fn(work);
    Box::into_raw(Box::new(sb))
}

/// Opaque handle for fork result (holds clone handles with pipes).
#[allow(non_camel_case_types)]
pub struct sandlock_fork_result_t {
    clones: Vec<Sandbox>,
}

/// Fork N COW clones. Returns a fork result handle (NULL on error).
///
/// # Safety
/// `sb` must be a valid sandbox pointer from `sandlock_new_with_fns`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_fork(sb: *mut Sandbox, n: u32) -> *mut sandlock_fork_result_t {
    if sb.is_null() {
        return ptr::null_mut();
    }
    let sb = &mut *sb;

    match with_runtime(|rt| rt.block_on(sb.fork(n))) {
        Some(Ok(clones)) => Box::into_raw(Box::new(sandlock_fork_result_t { clones })),
        _ => ptr::null_mut(),
    }
}

/// Get the number of clones.
#[no_mangle]
pub unsafe extern "C" fn sandlock_fork_result_count(r: *const sandlock_fork_result_t) -> u32 {
    if r.is_null() {
        return 0;
    }
    (*r).clones.len() as u32
}

/// Get a clone's PID.
#[no_mangle]
pub unsafe extern "C" fn sandlock_fork_result_pid(
    r: *const sandlock_fork_result_t,
    index: u32,
) -> i32 {
    if r.is_null() {
        return 0;
    }
    (&(*r).clones)
        .get(index as usize)
        .and_then(|c| c.pid())
        .unwrap_or(0)
}

/// Reduce: read all clone stdout pipes, feed to reducer stdin, return result.
///
/// # Safety
/// `fork_result` is consumed. `policy` and `argv` must be valid. `name`
/// may be NULL to auto-generate a sandbox name, or a valid
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_reduce(
    fork_result: *mut sandlock_fork_result_t,
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    argv: *const *const c_char,
    argc: c_uint,
) -> *mut sandlock_result_t {
    if fork_result.is_null() || policy.is_null() || argv.is_null() {
        return ptr::null_mut();
    }
    let mut fr = *Box::from_raw(fork_result);
    let policy = &(*policy)._private;
    let name = match optional_name(name) {
        Ok(name) => name,
        Err(_) => return ptr::null_mut(),
    };
    let args = read_argv(argv, argc);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let reducer = match name {
        Some(ref n) => policy.clone().with_name(n.clone()),
        None => policy.clone(),
    };

    match with_runtime(|rt| rt.block_on(reducer.reduce(&arg_refs, &mut fr.clones.as_mut_slice()))) {
        Some(Ok(result)) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        _ => ptr::null_mut(),
    }
}

/// Free a fork result without reducing.
#[no_mangle]
pub unsafe extern "C" fn sandlock_fork_result_free(r: *mut sandlock_fork_result_t) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}

/// Wait for the sandbox template to exit. Returns exit code.
///
/// # Safety
/// `sb` must be a valid sandbox pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_wait(sb: *mut Sandbox) -> c_int {
    if sb.is_null() {
        return -1;
    }
    let sb = &mut *sb;

    match with_runtime(|rt| rt.block_on(sb.wait())) {
        Some(Ok(r)) => r.code().unwrap_or(-1),
        _ => -1,
    }
}

/// Free a Sandbox handle created by `sandlock_new_with_fns`.
///
/// # Safety
/// `sb` must be null or a valid Sandbox pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_fns_free(sb: *mut Sandbox) {
    if !sb.is_null() {
        drop(Box::from_raw(sb));
    }
}

// ----------------------------------------------------------------
// Checkpoint
// ----------------------------------------------------------------

/// Opaque handle wrapping a [`Checkpoint`].
#[allow(non_camel_case_types)]
pub struct sandlock_checkpoint_t {
    _private: sandlock_core::Checkpoint,
}

/// Capture a checkpoint from a live sandbox handle.
/// The sandbox is frozen (SIGSTOP + fork-hold), state is captured via ptrace,
/// then thawed. Returns NULL on error.
///
/// # Safety
/// `h` must be a valid handle from `sandlock_create`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_checkpoint(
    h: *mut sandlock_handle_t,
) -> *mut sandlock_checkpoint_t {
    if h.is_null() {
        return ptr::null_mut();
    }
    let h = &mut *h;
    match block_on_runtime(&h.runtime, h.sandbox.checkpoint()) {
        Some(Ok(cp)) => Box::into_raw(Box::new(sandlock_checkpoint_t { _private: cp })),
        _ => ptr::null_mut(),
    }
}

/// Save a checkpoint to a directory (human-readable JSON + binary layout).
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `cp` must be a valid checkpoint pointer. `dir` must be a valid C string path.
#[no_mangle]
pub unsafe extern "C" fn sandlock_checkpoint_save(
    cp: *const sandlock_checkpoint_t,
    dir: *const c_char,
) -> c_int {
    if cp.is_null() || dir.is_null() {
        return -1;
    }
    let dir = CStr::from_ptr(dir).to_str().unwrap_or("");
    match (*cp)._private.save(std::path::Path::new(dir)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Load a checkpoint from a directory.
/// Returns NULL on error.
///
/// # Safety
/// `dir` must be a valid C string path to a checkpoint directory.
#[no_mangle]
pub unsafe extern "C" fn sandlock_checkpoint_load(
    dir: *const c_char,
) -> *mut sandlock_checkpoint_t {
    if dir.is_null() {
        return ptr::null_mut();
    }
    let dir = CStr::from_ptr(dir).to_str().unwrap_or("");
    match sandlock_core::Checkpoint::load(std::path::Path::new(dir)) {
        Ok(cp) => Box::into_raw(Box::new(sandlock_checkpoint_t { _private: cp })),
        Err(_) => ptr::null_mut(),
    }
}

/// Set the checkpoint name.
///
/// # Safety
/// `cp` must be a valid checkpoint pointer. `name` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_checkpoint_set_name(
    cp: *mut sandlock_checkpoint_t,
    name: *const c_char,
) {
    if cp.is_null() || name.is_null() {
        return;
    }
    (*cp)._private.name = CStr::from_ptr(name).to_str().unwrap_or("").to_string();
}

/// Get the checkpoint name. Returns a malloc'd C string; free with `sandlock_string_free`.
///
/// # Safety
/// `cp` must be a valid checkpoint pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_checkpoint_name(cp: *const sandlock_checkpoint_t) -> *mut c_char {
    if cp.is_null() {
        return ptr::null_mut();
    }
    match CString::new((*cp)._private.name.as_str()) {
        Ok(cs) => cs.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Set optional app-level state bytes on the checkpoint.
///
/// # Safety
/// `cp` must be valid. `data` must point to `len` bytes, or be NULL to clear.
#[no_mangle]
pub unsafe extern "C" fn sandlock_checkpoint_set_app_state(
    cp: *mut sandlock_checkpoint_t,
    data: *const u8,
    len: usize,
) {
    if cp.is_null() {
        return;
    }
    if data.is_null() || len == 0 {
        (*cp)._private.app_state = None;
    } else {
        (*cp)._private.app_state = Some(std::slice::from_raw_parts(data, len).to_vec());
    }
}

/// Get app-level state bytes. Returns pointer to internal buffer (valid until
/// checkpoint is freed). Writes length to `*len`. Returns NULL if no app state.
///
/// # Safety
/// `cp` must be a valid checkpoint pointer. `len` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_checkpoint_app_state(
    cp: *const sandlock_checkpoint_t,
    len: *mut usize,
) -> *const u8 {
    if cp.is_null() || len.is_null() {
        return ptr::null();
    }
    match (*cp)._private.app_state.as_ref() {
        Some(data) => {
            *len = data.len();
            data.as_ptr()
        }
        None => {
            *len = 0;
            ptr::null()
        }
    }
}

/// Free a checkpoint handle.
///
/// # Safety
/// `cp` must be null or a valid checkpoint pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_checkpoint_free(cp: *mut sandlock_checkpoint_t) {
    if !cp.is_null() {
        drop(Box::from_raw(cp));
    }
}

/// Restore a checkpoint into a fresh, fully-sandboxed process.
///
/// Builds a new sandbox from `policy` (with the optional `name`, as in
/// `sandlock_create`) and injects the checkpoint image over a parked child,
/// which resumes at the saved program counter under the full confinement.
/// Returns a live handle: the process is already running, so do NOT call
/// `sandlock_start` on it; manage it with `sandlock_handle_kill` /
/// `sandlock_handle_wait` / `sandlock_handle_free` as usual. Returns NULL on
/// error (any half-built child is reaped before returning).
///
/// Fds that could not be transparently restored (sockets, pipes, memfds,
/// pseudo-filesystem paths) are recorded on the handle; enumerate them with
/// `sandlock_handle_restore_skipped_len` / `_fd` / `_path`.
///
/// x86_64 restore engine only. Transparent restore currently holds for
/// vDSO-free programs; see `Sandbox::restore_interactive` in sandlock-core.
///
/// # Safety
/// `policy` must be a valid policy pointer and `cp` a valid checkpoint
/// pointer. `name` may be NULL to auto-generate a sandbox name, or a valid
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_restore_interactive(
    policy: *const sandlock_sandbox_t,
    name: *const c_char,
    cp: *const sandlock_checkpoint_t,
) -> *mut sandlock_handle_t {
    if policy.is_null() || cp.is_null() {
        return ptr::null_mut();
    }
    let policy = &(*policy)._private;
    let name = match optional_name(name) {
        Ok(n) => n,
        Err(_) => return ptr::null_mut(),
    };
    // Live (multi-threaded) runtime: the restored process is a long-lived
    // handle whose seccomp supervisor must keep pumping between FFI calls.
    let rt = match build_live_runtime() {
        Some(rt) => rt,
        None => return ptr::null_mut(),
    };
    let mut sb = match name {
        Some(ref n) => policy.clone().with_name(n.clone()),
        None => policy.clone(),
    };
    // Core returns a Process borrowing `sb`; it carries nothing the handle
    // does not, so let it drop and move `sb` into the handle (the process
    // keeps running; the Sandbox owns it). Skipped fds live on the Sandbox.
    let cp_ref = &(*cp)._private;
    let restored = matches!(
        block_on_runtime(&rt, async { sb.restore_interactive(cp_ref).await.map(|_| ()) }),
        Some(Ok(()))
    );
    if !restored {
        // Dropping `sb` reaps any half-built child left by a failed restore.
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(sandlock_handle_t {
        sandbox: sb,
        runtime: rt,
    }))
}

/// Number of fds the restore that produced this handle could not
/// transparently recreate. 0 for a NULL handle or a handle not produced by
/// `sandlock_restore_interactive`.
///
/// # Safety
/// `h` must be null or a valid handle.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_restore_skipped_len(
    h: *const sandlock_handle_t,
) -> usize {
    if h.is_null() {
        return 0;
    }
    (*h).sandbox.restore_skipped().len()
}

/// The fd number of the i-th skipped entry (its fd in the checkpointed
/// process). Returns -1 if `h` is NULL or `i` is out of range.
///
/// # Safety
/// `h` must be null or a valid handle.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_restore_skipped_fd(
    h: *const sandlock_handle_t,
    i: usize,
) -> c_int {
    if h.is_null() {
        return -1;
    }
    match (*h).sandbox.restore_skipped().get(i) {
        Some(f) => f.fd,
        None => -1,
    }
}

/// The resource path of the i-th skipped entry (e.g. `pipe:[12345]`).
/// Returns a malloc'd C string to free with `sandlock_string_free`, or NULL
/// if `h` is NULL or `i` is out of range.
///
/// # Safety
/// `h` must be null or a valid handle.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_restore_skipped_path(
    h: *const sandlock_handle_t,
    i: usize,
) -> *mut c_char {
    if h.is_null() {
        return ptr::null_mut();
    }
    match (*h).sandbox.restore_skipped().get(i) {
        Some(f) => match CString::new(f.path.as_str()) {
            Ok(cs) => cs.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

// ----------------------------------------------------------------
// Platform query
// ----------------------------------------------------------------

/// Query the Landlock ABI version supported by the running kernel.
/// Returns the ABI version (>= 1), or -1 if Landlock is unavailable.
#[no_mangle]
pub extern "C" fn sandlock_landlock_abi_version() -> c_int {
    match sandlock_core::landlock_abi_version() {
        Ok(v) => v as c_int,
        Err(_) => -1,
    }
}

/// Return the minimum Landlock ABI version required by this build of sandlock.
#[no_mangle]
pub extern "C" fn sandlock_min_landlock_abi() -> c_int {
    sandlock_core::MIN_LANDLOCK_ABI as c_int
}

// ----------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------

unsafe fn optional_name(name: *const c_char) -> Result<Option<String>, std::str::Utf8Error> {
    if name.is_null() {
        Ok(None)
    } else {
        CStr::from_ptr(name).to_str().map(|s| Some(s.to_string()))
    }
}

unsafe fn read_argv(argv: *const *const c_char, argc: c_uint) -> Vec<String> {
    let mut args = Vec::new();
    for i in 0..argc as usize {
        let arg = CStr::from_ptr(*argv.add(i))
            .to_str()
            .unwrap_or("")
            .to_string();
        args.push(arg);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::policy_ret_to_verdict;
    use sandlock_core::policy_fn::Verdict;

    #[test]
    fn policy_ret_maps_documented_values() {
        assert_eq!(policy_ret_to_verdict(0), Verdict::Allow);
        assert_eq!(policy_ret_to_verdict(-1), Verdict::Deny);
        assert_eq!(policy_ret_to_verdict(-2), Verdict::Audit);
        assert_eq!(policy_ret_to_verdict(13), Verdict::DenyWith(13));
    }

    #[test]
    fn policy_ret_unrecognized_values_fail_closed() {
        // A negative other than -1/-2 is the classic `-errno` mistake; it must
        // deny, not silently allow.
        assert_eq!(policy_ret_to_verdict(-13), Verdict::Deny);
        assert_eq!(policy_ret_to_verdict(-3), Verdict::Deny);
        assert_eq!(policy_ret_to_verdict(i32::MIN), Verdict::Deny);
    }
}
