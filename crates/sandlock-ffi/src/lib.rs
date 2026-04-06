//! C ABI bindings for sandlock-core.
//!
//! This crate exposes sandlock functionality through a C-compatible interface
//! using opaque handle patterns.  Each `*mut` / `*const` pointer returned by
//! these functions must be freed with its corresponding `_free` function.

use std::ffi::{c_char, c_int, c_uint, CStr, CString};
use std::ptr;
use std::time::Duration;

use sandlock_core::pipeline::Stage;
use sandlock_core::policy::{ByteSize, PolicyBuilder};
use sandlock_core::{Policy, RunResult, Sandbox};

// ----------------------------------------------------------------
// Opaque wrapper types
// ----------------------------------------------------------------

/// Opaque handle wrapping a [`Policy`].
#[repr(C)]
pub struct sandlock_policy_t {
    _private: Policy,
}

/// Opaque handle wrapping a [`RunResult`].
#[repr(C)]
pub struct sandlock_result_t {
    _private: RunResult,
}

/// Opaque handle wrapping a [`Pipeline`].
#[allow(non_camel_case_types)]
pub struct sandlock_pipeline_t {
    stages: Vec<(Policy, Vec<String>)>,
}

// ----------------------------------------------------------------
// Policy Builder — filesystem
// ----------------------------------------------------------------

#[no_mangle]
pub extern "C" fn sandlock_policy_builder_new() -> *mut PolicyBuilder {
    Box::into_raw(Box::new(Policy::builder()))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_fs_read(
    b: *mut PolicyBuilder,
    path: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || path.is_null() { return b; }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.fs_read(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_fs_write(
    b: *mut PolicyBuilder,
    path: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || path.is_null() { return b; }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.fs_write(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_fs_deny(
    b: *mut PolicyBuilder,
    path: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || path.is_null() { return b; }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.fs_deny(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_fs_storage(
    b: *mut PolicyBuilder,
    path: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || path.is_null() { return b; }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.fs_storage(path)))
}

/// Set filesystem isolation mode.
/// `mode`: 0 = None, 1 = OverlayFs, 2 = BranchFs.
///
/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_fs_isolation(
    b: *mut PolicyBuilder,
    mode: u8,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    let iso = match mode {
        1 => sandlock_core::policy::FsIsolation::OverlayFs,
        2 => sandlock_core::policy::FsIsolation::BranchFs,
        _ => sandlock_core::policy::FsIsolation::None,
    };
    Box::into_raw(Box::new(builder.fs_isolation(iso)))
}

/// # Safety
/// `b` must be a valid pointer. `devices` must point to `len` u32 values (or be null when len == 0).
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_gpu_devices(
    b: *mut PolicyBuilder, devices: *const u32, len: u32,
) -> *mut PolicyBuilder {
    if b.is_null() || (len > 0 && devices.is_null()) { return b; }
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
pub unsafe extern "C" fn sandlock_policy_builder_workdir(
    b: *mut PolicyBuilder,
    path: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || path.is_null() { return b; }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.workdir(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_cwd(
    b: *mut PolicyBuilder,
    path: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || path.is_null() { return b; }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.cwd(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_chroot(
    b: *mut PolicyBuilder,
    path: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || path.is_null() { return b; }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.chroot(path)))
}

/// Add a filesystem mount mapping (virtual_path -> host_path).
///
/// # Safety
/// `b`, `virtual_path`, and `host_path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_fs_mount(
    b: *mut PolicyBuilder,
    virtual_path: *const c_char,
    host_path: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || virtual_path.is_null() || host_path.is_null() { return b; }
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
pub unsafe extern "C" fn sandlock_policy_builder_on_exit(
    b: *mut PolicyBuilder,
    action: u8,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    let action = match action {
        1 => sandlock_core::policy::BranchAction::Abort,
        2 => sandlock_core::policy::BranchAction::Keep,
        _ => sandlock_core::policy::BranchAction::Commit,
    };
    Box::into_raw(Box::new(builder.on_exit(action)))
}

/// Set the COW branch action on error exit.
/// `action`: 0 = Commit, 1 = Abort, 2 = Keep.
///
/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_on_error(
    b: *mut PolicyBuilder,
    action: u8,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    let action = match action {
        1 => sandlock_core::policy::BranchAction::Abort,
        2 => sandlock_core::policy::BranchAction::Keep,
        _ => sandlock_core::policy::BranchAction::Commit,
    };
    Box::into_raw(Box::new(builder.on_error(action)))
}

// ----------------------------------------------------------------
// Policy Builder — resource limits
// ----------------------------------------------------------------

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_max_memory(
    b: *mut PolicyBuilder, bytes: u64,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.max_memory(ByteSize(bytes))))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_max_disk(
    b: *mut PolicyBuilder, bytes: u64,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.max_disk(ByteSize(bytes))))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_max_processes(
    b: *mut PolicyBuilder, n: u32,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.max_processes(n)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_max_cpu(
    b: *mut PolicyBuilder, pct: u8,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.max_cpu(pct)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_num_cpus(
    b: *mut PolicyBuilder, n: u32,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.num_cpus(n)))
}

/// # Safety
/// `b` must be a valid builder pointer.  `cores` must point to `len` u32 values.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_cpu_cores(
    b: *mut PolicyBuilder, cores: *const u32, len: u32,
) -> *mut PolicyBuilder {
    if b.is_null() || (len > 0 && cores.is_null()) { return b; }
    let slice = if len > 0 {
        std::slice::from_raw_parts(cores, len as usize)
    } else {
        &[]
    };
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.cpu_cores(slice.to_vec())))
}

// ----------------------------------------------------------------
// Policy Builder — network
// ----------------------------------------------------------------

/// # Safety
/// `b` and `host` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_net_allow_host(
    b: *mut PolicyBuilder, host: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || host.is_null() { return b; }
    let host = CStr::from_ptr(host).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.net_allow_host(host)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_net_bind_port(
    b: *mut PolicyBuilder, port: u16,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.net_bind_port(port)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_net_connect_port(
    b: *mut PolicyBuilder, port: u16,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.net_connect_port(port)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_port_remap(
    b: *mut PolicyBuilder, v: bool,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.port_remap(v)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_no_raw_sockets(
    b: *mut PolicyBuilder, v: bool,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.no_raw_sockets(v)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_no_udp(
    b: *mut PolicyBuilder, v: bool,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.no_udp(v)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_uid(
    b: *mut PolicyBuilder, id: u32,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.uid(id)))
}

// ----------------------------------------------------------------
// Policy Builder — HTTP ACL
// ----------------------------------------------------------------

/// # Safety
/// `b` and `rule` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_http_allow(
    b: *mut PolicyBuilder,
    rule: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || rule.is_null() { return b; }
    let rule = CStr::from_ptr(rule).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.http_allow(rule)))
}

/// # Safety
/// `b` and `rule` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_http_deny(
    b: *mut PolicyBuilder,
    rule: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || rule.is_null() { return b; }
    let rule = CStr::from_ptr(rule).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.http_deny(rule)))
}

/// # Safety
/// `b` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_http_port(
    b: *mut PolicyBuilder,
    port: u16,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.http_port(port)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_https_ca(
    b: *mut PolicyBuilder,
    path: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || path.is_null() { return b; }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.https_ca(path)))
}

/// # Safety
/// `b` and `path` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_https_key(
    b: *mut PolicyBuilder,
    path: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || path.is_null() { return b; }
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.https_key(path)))
}

// ----------------------------------------------------------------
// Policy Builder — isolation & determinism
// ----------------------------------------------------------------

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_random_seed(
    b: *mut PolicyBuilder, seed: u64,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.random_seed(seed)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_clean_env(
    b: *mut PolicyBuilder, v: bool,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.clean_env(v)))
}

/// # Safety
/// `b`, `key`, and `value` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_env_var(
    b: *mut PolicyBuilder, key: *const c_char, value: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || key.is_null() || value.is_null() { return b; }
    let key = CStr::from_ptr(key).to_str().unwrap_or("");
    let value = CStr::from_ptr(value).to_str().unwrap_or("");
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.env_var(key, value)))
}

/// # Safety
/// `b` must be a valid builder pointer. `epoch_secs` is seconds since UNIX epoch.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_time_start(
    b: *mut PolicyBuilder, epoch_secs: u64,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    let t = std::time::UNIX_EPOCH + Duration::from_secs(epoch_secs);
    Box::into_raw(Box::new(builder.time_start(t)))
}

/// # Safety
/// `b` must be a valid builder pointer. `names` is a comma-separated NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_deny_syscalls(
    b: *mut PolicyBuilder, names: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || names.is_null() { return b; }
    let builder = *Box::from_raw(b);
    let s = CStr::from_ptr(names).to_str().unwrap_or("");
    let calls: Vec<String> = s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    Box::into_raw(Box::new(builder.deny_syscalls(calls)))
}

/// # Safety
/// `b` must be a valid builder pointer. `names` is a comma-separated NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_allow_syscalls(
    b: *mut PolicyBuilder, names: *const c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || names.is_null() { return b; }
    let builder = *Box::from_raw(b);
    let s = CStr::from_ptr(names).to_str().unwrap_or("");
    let calls: Vec<String> = s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    Box::into_raw(Box::new(builder.allow_syscalls(calls)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_max_open_files(
    b: *mut PolicyBuilder, n: c_uint,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.max_open_files(n)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_no_randomize_memory(
    b: *mut PolicyBuilder, v: bool,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.no_randomize_memory(v)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_no_huge_pages(
    b: *mut PolicyBuilder, v: bool,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.no_huge_pages(v)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_no_coredump(
    b: *mut PolicyBuilder, v: bool,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.no_coredump(v)))
}

/// # Safety
/// `b` must be a valid builder pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_deterministic_dirs(
    b: *mut PolicyBuilder, v: bool,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);
    Box::into_raw(Box::new(builder.deterministic_dirs(v)))
}

/// # Safety
/// `b` must be a valid builder pointer. `name` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_hostname(
    b: *mut PolicyBuilder, name: *const std::os::raw::c_char,
) -> *mut PolicyBuilder {
    if b.is_null() || name.is_null() { return b; }
    let builder = *Box::from_raw(b);
    let s = std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned();
    Box::into_raw(Box::new(builder.hostname(s)))
}

// ----------------------------------------------------------------
// Policy Builder — build & free
// ----------------------------------------------------------------

/// Consume the builder and produce a policy.
/// On success, `*err` is 0 and a non-null policy pointer is returned.
/// On failure, `*err` is -1 and null is returned.
///
/// # Safety
/// `b` must be a valid builder pointer. `err` may be null.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_build(
    b: *mut PolicyBuilder, err: *mut c_int,
) -> *mut sandlock_policy_t {
    if b.is_null() {
        if !err.is_null() { *err = -1; }
        return ptr::null_mut();
    }
    let builder = *Box::from_raw(b);
    match builder.build() {
        Ok(policy) => {
            if !err.is_null() { *err = 0; }
            Box::into_raw(Box::new(sandlock_policy_t { _private: policy }))
        }
        Err(_) => {
            if !err.is_null() { *err = -1; }
            ptr::null_mut()
        }
    }
}

/// # Safety
/// `p` must be null or a valid pointer from `sandlock_policy_build`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_free(p: *mut sandlock_policy_t) {
    if !p.is_null() { drop(Box::from_raw(p)); }
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
pub unsafe extern "C" fn sandlock_confine(
    policy: *const sandlock_policy_t,
) -> c_int {
    if policy.is_null() { return -1; }
    let policy = &(*policy)._private;
    match sandlock_core::confine_current_process(policy) {
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
/// `policy` must be a valid policy pointer. `argv` must point to `argc` C strings.
#[no_mangle]
pub unsafe extern "C" fn sandlock_run(
    policy: *const sandlock_policy_t,
    argv: *const *const c_char,
    argc: c_uint,
) -> *mut sandlock_result_t {
    if policy.is_null() || argv.is_null() { return ptr::null_mut(); }
    let policy = &(*policy)._private;
    let args = read_argv(argv, argc);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };
    match rt.block_on(Sandbox::run(policy, &arg_refs)) {
        Ok(result) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        Err(_) => ptr::null_mut(),
    }
}

// ----------------------------------------------------------------
// Sandbox handle (spawn / wait — for pause/resume via PID)
// ----------------------------------------------------------------

/// Opaque handle for a live (spawned) sandbox.
/// Owns both the Sandbox and the tokio Runtime that drives its supervisor.
#[allow(non_camel_case_types)]
pub struct sandlock_handle_t {
    sandbox: Sandbox,
    runtime: tokio::runtime::Runtime,
}

/// Spawn a sandboxed process without waiting. Returns a live handle.
/// Use `sandlock_handle_pid` to get the PID, then `sandlock_handle_wait`
/// to collect the result when done.
///
/// # Safety
/// `policy` must be a valid policy pointer. `argv` must point to `argc` C strings.
#[no_mangle]
pub unsafe extern "C" fn sandlock_spawn(
    policy: *const sandlock_policy_t,
    argv: *const *const c_char,
    argc: c_uint,
) -> *mut sandlock_handle_t {
    if policy.is_null() || argv.is_null() { return ptr::null_mut(); }
    let policy = &(*policy)._private;
    let args = read_argv(argv, argc);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    let mut sb = match Sandbox::new(policy) {
        Ok(sb) => sb,
        Err(_) => return ptr::null_mut(),
    };

    if rt.block_on(sb.spawn_captured(&arg_refs)).is_err() {
        return ptr::null_mut();
    }

    Box::into_raw(Box::new(sandlock_handle_t { sandbox: sb, runtime: rt }))
}

/// Get the child PID. Returns 0 if not available.
///
/// # Safety
/// `h` must be a valid handle from `sandlock_spawn`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_pid(h: *const sandlock_handle_t) -> i32 {
    if h.is_null() { return 0; }
    (*h).sandbox.pid().unwrap_or(0)
}

/// Wait for the sandbox to exit. Returns a result handle with stdout/stderr.
///
/// # Safety
/// `h` must be a valid handle from `sandlock_spawn`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_wait(h: *mut sandlock_handle_t) -> *mut sandlock_result_t {
    if h.is_null() { return ptr::null_mut(); }
    let h = &mut *h;
    match h.runtime.block_on(h.sandbox.wait()) {
        Ok(result) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        Err(_) => ptr::null_mut(),
    }
}

/// Wait for the sandbox to exit with a timeout in milliseconds.
/// Returns a result handle, or null on error. On timeout the sandbox is
/// killed and a result with `ExitStatus::Timeout` is returned.
///
/// # Safety
/// `h` must be a valid handle from `sandlock_spawn`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_wait_timeout(
    h: *mut sandlock_handle_t,
    timeout_ms: u64,
) -> *mut sandlock_result_t {
    if h.is_null() { return ptr::null_mut(); }
    let h = &mut *h;

    if timeout_ms == 0 {
        // No timeout -- same as sandlock_handle_wait.
        return match h.runtime.block_on(h.sandbox.wait()) {
            Ok(result) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
            Err(_) => ptr::null_mut(),
        };
    }

    let dur = Duration::from_millis(timeout_ms);
    match h.runtime.block_on(async {
        tokio::time::timeout(dur, h.sandbox.wait()).await
    }) {
        Ok(Ok(result)) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        Ok(Err(_)) => ptr::null_mut(),
        Err(_) => {
            // Timeout -- kill the process and return a timeout result.
            let _ = h.sandbox.kill();
            let result = RunResult::timeout();
            Box::into_raw(Box::new(sandlock_result_t { _private: result }))
        }
    }
}

/// Free a sandbox handle. Kills the process if still running.
///
/// # Safety
/// `h` must be null or a valid handle from `sandlock_spawn`.
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
/// `policy` must be a valid policy pointer. `argv` must point to `argc` C strings.
#[no_mangle]
pub unsafe extern "C" fn sandlock_run_interactive(
    policy: *const sandlock_policy_t,
    argv: *const *const c_char,
    argc: c_uint,
) -> c_int {
    if policy.is_null() || argv.is_null() { return -1; }
    let policy = &(*policy)._private;
    let args = read_argv(argv, argc);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return -1,
    };
    match rt.block_on(Sandbox::run_interactive(policy, &arg_refs)) {
        Ok(result) => result.code().unwrap_or(-1),
        Err(_) => -1,
    }
}

// ----------------------------------------------------------------
// Result accessors
// ----------------------------------------------------------------

/// # Safety
/// `r` must be null or a valid result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_exit_code(r: *const sandlock_result_t) -> c_int {
    if r.is_null() { return -1; }
    (*r)._private.code().unwrap_or(-1)
}

/// # Safety
/// `r` must be null or a valid result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_success(r: *const sandlock_result_t) -> bool {
    if r.is_null() { return false; }
    (*r)._private.success()
}

/// Get captured stdout. Returns a malloc'd NUL-terminated string.
/// Caller must free with `sandlock_string_free`. Returns null if no capture.
///
/// # Safety
/// `r` must be null or a valid result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_stdout(r: *const sandlock_result_t) -> *mut c_char {
    if r.is_null() { return ptr::null_mut(); }
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
    if r.is_null() { return ptr::null_mut(); }
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
    r: *const sandlock_result_t, len: *mut usize,
) -> *const u8 {
    if r.is_null() || len.is_null() { return ptr::null(); }
    match (*r)._private.stdout.as_ref() {
        Some(bytes) => { *len = bytes.len(); bytes.as_ptr() }
        None => { *len = 0; ptr::null() }
    }
}

/// Get captured stderr as raw bytes.
///
/// # Safety
/// `r` must be a valid result pointer. `len` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_stderr_bytes(
    r: *const sandlock_result_t, len: *mut usize,
) -> *const u8 {
    if r.is_null() || len.is_null() { return ptr::null(); }
    match (*r)._private.stderr.as_ref() {
        Some(bytes) => { *len = bytes.len(); bytes.as_ptr() }
        None => { *len = 0; ptr::null() }
    }
}

/// # Safety
/// `r` must be null or a valid pointer from `sandlock_run`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_result_free(r: *mut sandlock_result_t) {
    if !r.is_null() { drop(Box::from_raw(r)); }
}

/// Free a string returned by `sandlock_result_stdout` or `sandlock_result_stderr`.
///
/// # Safety
/// `s` must be null or a pointer from a `sandlock_result_std*` function.
#[no_mangle]
pub unsafe extern "C" fn sandlock_string_free(s: *mut c_char) {
    if !s.is_null() { drop(CString::from_raw(s)); }
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
/// `policy` must be a valid policy pointer. `argv` must point to `argc` C strings.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run(
    policy: *const sandlock_policy_t,
    argv: *const *const c_char,
    argc: c_uint,
) -> *mut sandlock_dry_run_result_t {
    if policy.is_null() || argv.is_null() { return ptr::null_mut(); }
    let policy = &(*policy)._private;
    let args = read_argv(argv, argc);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };
    match rt.block_on(Sandbox::dry_run(policy, &arg_refs)) {
        Ok(result) => Box::into_raw(Box::new(sandlock_dry_run_result_t { _private: result })),
        Err(_) => ptr::null_mut(),
    }
}

/// Get the exit code from a dry-run result.
///
/// # Safety
/// `r` must be a valid dry-run result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_exit_code(r: *const sandlock_dry_run_result_t) -> c_int {
    if r.is_null() { return -1; }
    (*r)._private.run_result.code().unwrap_or(-1) as c_int
}

/// Check if the dry-run result indicates success.
///
/// # Safety
/// `r` must be a valid dry-run result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_success(r: *const sandlock_dry_run_result_t) -> bool {
    if r.is_null() { return false; }
    (*r)._private.run_result.success()
}

/// Get captured stdout bytes from a dry-run result.
///
/// # Safety
/// `r` must be a valid dry-run result pointer. `len` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_stdout_bytes(
    r: *const sandlock_dry_run_result_t, len: *mut usize,
) -> *const u8 {
    if r.is_null() { if !len.is_null() { *len = 0; } return ptr::null(); }
    match &(*r)._private.run_result.stdout {
        Some(v) => { *len = v.len(); v.as_ptr() }
        None => { *len = 0; ptr::null() }
    }
}

/// Get captured stderr bytes from a dry-run result.
///
/// # Safety
/// `r` must be a valid dry-run result pointer. `len` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_stderr_bytes(
    r: *const sandlock_dry_run_result_t, len: *mut usize,
) -> *const u8 {
    if r.is_null() { if !len.is_null() { *len = 0; } return ptr::null(); }
    match &(*r)._private.run_result.stderr {
        Some(v) => { *len = v.len(); v.as_ptr() }
        None => { *len = 0; ptr::null() }
    }
}

/// Get the number of filesystem changes in a dry-run result.
///
/// # Safety
/// `r` must be a valid dry-run result pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_changes_len(r: *const sandlock_dry_run_result_t) -> usize {
    if r.is_null() { return 0; }
    (*r)._private.changes.len()
}

/// Get the kind of the i-th change: 'A' (added), 'M' (modified), 'D' (deleted).
///
/// # Safety
/// `r` must be a valid dry-run result pointer. `i` must be < changes_len.
#[no_mangle]
pub unsafe extern "C" fn sandlock_dry_run_result_change_kind(
    r: *const sandlock_dry_run_result_t, i: usize,
) -> c_char {
    if r.is_null() { return 0; }
    let changes = &(*r)._private.changes;
    if i >= changes.len() { return 0; }
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
    r: *const sandlock_dry_run_result_t, i: usize,
) -> *mut c_char {
    if r.is_null() { return ptr::null_mut(); }
    let changes = &(*r)._private.changes;
    if i >= changes.len() { return ptr::null_mut(); }
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
    if !r.is_null() { drop(Box::from_raw(r)); }
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
    policy: *const sandlock_policy_t,
    argv: *const *const c_char,
    argc: c_uint,
) {
    if pipe.is_null() || policy.is_null() || argv.is_null() { return; }
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
    if pipe.is_null() { return ptr::null_mut(); }
    let pipe = *Box::from_raw(pipe);

    if pipe.stages.len() < 2 { return ptr::null_mut(); }

    let mut stages: Vec<Stage> = pipe.stages.into_iter().map(|(policy, args)| {
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        Stage::new(&policy, &arg_refs)
    }).collect();

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

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    match rt.block_on(pipeline.run(timeout)) {
        Ok(result) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a pipeline without running it.
///
/// # Safety
/// `pipe` must be null or a valid pipeline pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_pipeline_free(pipe: *mut sandlock_pipeline_t) {
    if !pipe.is_null() { drop(Box::from_raw(pipe)); }
}

// ----------------------------------------------------------------
// Policy callback (policy_fn)
// ----------------------------------------------------------------

/// C-compatible syscall event passed to the policy callback.
#[repr(C)]
pub struct sandlock_event_t {
    pub syscall: *const c_char,
    /// Category: 0=File, 1=Network, 2=Process, 3=Memory
    pub category: u8,
    pub pid: u32,
    pub parent_pid: u32, // 0 if unknown
    pub path: *const c_char,   // NULL if not applicable
    pub host: *const c_char,   // NULL if not applicable
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
/// positive = deny with that errno (e.g. 13 = EACCES).
#[allow(non_camel_case_types)]
pub type sandlock_policy_fn_t = unsafe extern "C" fn(
    event: *const sandlock_event_t,
    ctx: *mut sandlock_ctx_t,
) -> i32;

/// Set a policy callback on the builder.
///
/// # Safety
/// `b` must be a valid builder pointer. `cb` must be a valid function pointer
/// that remains valid for the lifetime of the sandbox.
#[no_mangle]
pub unsafe extern "C" fn sandlock_policy_builder_policy_fn(
    b: *mut PolicyBuilder,
    cb: sandlock_policy_fn_t,
) -> *mut PolicyBuilder {
    if b.is_null() { return b; }
    let builder = *Box::from_raw(b);

    // Wrap the C callback in a Rust closure
    let cb_fn = move |event: sandlock_core::policy_fn::SyscallEvent,
                      ctx: &mut sandlock_core::policy_fn::PolicyContext| {
        let syscall_c = CString::new(event.syscall.as_str()).unwrap_or_default();
        let path_c = event.path.as_deref().and_then(|s| CString::new(s).ok());
        let host_c = event.host.map(|ip| CString::new(ip.to_string()).unwrap_or_default());

        // Convert argv to C string array
        let argv_c: Vec<CString> = event.argv.as_ref()
            .map(|args| args.iter().filter_map(|s| CString::new(s.as_str()).ok()).collect())
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
            path: path_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            host: host_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            port: event.port.unwrap_or(0),
            denied: event.denied,
            argv: if argv_ptrs.is_empty() { ptr::null() } else { argv_ptrs.as_ptr() },
            argc,
        };

        let mut c_ctx = sandlock_ctx_t {
            ctx: ctx as *mut _,
        };

        let ret = unsafe { cb(&c_event, &mut c_ctx) };
        match ret {
            0 => sandlock_core::policy_fn::Verdict::Allow,
            -1 => sandlock_core::policy_fn::Verdict::Deny,
            -2 => sandlock_core::policy_fn::Verdict::Audit,
            errno if errno > 0 => sandlock_core::policy_fn::Verdict::DenyWith(errno),
            _ => sandlock_core::policy_fn::Verdict::Allow,
        }
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
    if ctx.is_null() { return; }
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
    if ctx.is_null() { return; }
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
pub unsafe extern "C" fn sandlock_ctx_restrict_max_memory(
    ctx: *mut sandlock_ctx_t, bytes: u64,
) {
    if ctx.is_null() { return; }
    let ctx = &mut *(*ctx).ctx;
    ctx.restrict_max_memory(bytes);
}

/// Restrict max processes. Permanent.
///
/// # Safety
/// `ctx` must be a valid context pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_ctx_restrict_max_processes(
    ctx: *mut sandlock_ctx_t, n: u32,
) {
    if ctx.is_null() { return; }
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
    if ctx.is_null() { return; }
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
pub unsafe extern "C" fn sandlock_ctx_deny_path(
    ctx: *mut sandlock_ctx_t, path: *const c_char,
) {
    if ctx.is_null() || path.is_null() { return; }
    let ctx = &*(*ctx).ctx;
    let path = CStr::from_ptr(path).to_str().unwrap_or("");
    ctx.deny_path(path);
}

/// Remove a previously denied path.
///
/// # Safety
/// `ctx` must be a valid context pointer. `path` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn sandlock_ctx_allow_path(
    ctx: *mut sandlock_ctx_t, path: *const c_char,
) {
    if ctx.is_null() || path.is_null() { return; }
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
/// `policy` must be valid. `init_fn` and `work_fn` must be valid function pointers.
#[no_mangle]
pub unsafe extern "C" fn sandlock_new_with_fns(
    policy: *const sandlock_policy_t,
    init_fn: sandlock_init_fn_t,
    work_fn: sandlock_work_fn_t,
) -> *mut Sandbox {
    if policy.is_null() { return ptr::null_mut(); }
    let policy = &(*policy)._private;

    let init = move || { unsafe { init_fn() } };
    let work = move |id: u32| { unsafe { work_fn(id) } };

    match Sandbox::new_with_fns(policy, init, work) {
        Ok(sb) => Box::into_raw(Box::new(sb)),
        Err(_) => ptr::null_mut(),
    }
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
pub unsafe extern "C" fn sandlock_fork(
    sb: *mut Sandbox,
    n: u32,
) -> *mut sandlock_fork_result_t {
    if sb.is_null() { return ptr::null_mut(); }
    let sb = &mut *sb;

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    match rt.block_on(sb.fork(n)) {
        Ok(clones) => Box::into_raw(Box::new(sandlock_fork_result_t { clones })),
        Err(_) => ptr::null_mut(),
    }
}

/// Get the number of clones.
#[no_mangle]
pub unsafe extern "C" fn sandlock_fork_result_count(r: *const sandlock_fork_result_t) -> u32 {
    if r.is_null() { return 0; }
    (*r).clones.len() as u32
}

/// Get a clone's PID.
#[no_mangle]
pub unsafe extern "C" fn sandlock_fork_result_pid(r: *const sandlock_fork_result_t, index: u32) -> i32 {
    if r.is_null() { return 0; }
    (&(*r).clones).get(index as usize).and_then(|c| c.pid()).unwrap_or(0)
}

/// Reduce: read all clone stdout pipes, feed to reducer stdin, return result.
///
/// # Safety
/// `fork_result` is consumed. `policy` and `argv` must be valid.
#[no_mangle]
pub unsafe extern "C" fn sandlock_reduce(
    fork_result: *mut sandlock_fork_result_t,
    policy: *const sandlock_policy_t,
    argv: *const *const c_char,
    argc: c_uint,
) -> *mut sandlock_result_t {
    if fork_result.is_null() || policy.is_null() || argv.is_null() {
        return ptr::null_mut();
    }
    let mut fr = *Box::from_raw(fork_result);
    let policy = &(*policy)._private;
    let args = read_argv(argv, argc);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };

    let reducer = match Sandbox::new(policy) {
        Ok(r) => r,
        Err(_) => return ptr::null_mut(),
    };

    match rt.block_on(reducer.reduce(&arg_refs, &mut fr.clones)) {
        Ok(result) => Box::into_raw(Box::new(sandlock_result_t { _private: result })),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a fork result without reducing.
#[no_mangle]
pub unsafe extern "C" fn sandlock_fork_result_free(r: *mut sandlock_fork_result_t) {
    if !r.is_null() { drop(Box::from_raw(r)); }
}

/// Wait for the sandbox template to exit. Returns exit code.
///
/// # Safety
/// `sb` must be a valid sandbox pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_wait(sb: *mut Sandbox) -> c_int {
    if sb.is_null() { return -1; }
    let sb = &mut *sb;

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return -1,
    };

    match rt.block_on(sb.wait()) {
        Ok(r) => r.code().unwrap_or(-1),
        Err(_) => -1,
    }
}

/// Free a sandbox handle.
///
/// # Safety
/// `sb` must be null or a valid sandbox pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_sandbox_free(sb: *mut Sandbox) {
    if !sb.is_null() { drop(Box::from_raw(sb)); }
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
/// `h` must be a valid handle from `sandlock_spawn`.
#[no_mangle]
pub unsafe extern "C" fn sandlock_handle_checkpoint(
    h: *mut sandlock_handle_t,
) -> *mut sandlock_checkpoint_t {
    if h.is_null() { return ptr::null_mut(); }
    let h = &mut *h;
    match h.runtime.block_on(h.sandbox.checkpoint()) {
        Ok(cp) => Box::into_raw(Box::new(sandlock_checkpoint_t { _private: cp })),
        Err(_) => ptr::null_mut(),
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
    if cp.is_null() || dir.is_null() { return -1; }
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
    if dir.is_null() { return ptr::null_mut(); }
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
    if cp.is_null() || name.is_null() { return; }
    (*cp)._private.name = CStr::from_ptr(name).to_str().unwrap_or("").to_string();
}

/// Get the checkpoint name. Returns a malloc'd C string; free with `sandlock_string_free`.
///
/// # Safety
/// `cp` must be a valid checkpoint pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_checkpoint_name(
    cp: *const sandlock_checkpoint_t,
) -> *mut c_char {
    if cp.is_null() { return ptr::null_mut(); }
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
    if cp.is_null() { return; }
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
    if cp.is_null() || len.is_null() { return ptr::null(); }
    match (*cp)._private.app_state.as_ref() {
        Some(data) => { *len = data.len(); data.as_ptr() }
        None => { *len = 0; ptr::null() }
    }
}

/// Free a checkpoint handle.
///
/// # Safety
/// `cp` must be null or a valid checkpoint pointer.
#[no_mangle]
pub unsafe extern "C" fn sandlock_checkpoint_free(cp: *mut sandlock_checkpoint_t) {
    if !cp.is_null() { drop(Box::from_raw(cp)); }
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

unsafe fn read_argv(argv: *const *const c_char, argc: c_uint) -> Vec<String> {
    let mut args = Vec::new();
    for i in 0..argc as usize {
        let arg = CStr::from_ptr(*argv.add(i)).to_str().unwrap_or("").to_string();
        args.push(arg);
    }
    args
}
