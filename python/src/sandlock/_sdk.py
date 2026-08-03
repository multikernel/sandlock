"""Python SDK for sandlock — ctypes bindings to libsandlock_ffi.so."""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import math
import os
import signal
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, NamedTuple, Sequence

from .sandbox import Sandbox as PolicyDataclass

# ----------------------------------------------------------------
# Load the shared library
# ----------------------------------------------------------------

def _find_lib() -> str:
    """Find libsandlock_ffi.so."""
    pkg_dir = Path(__file__).parent

    # 1. Dev build from cargo — pick the most recently built profile.
    target_dir = pkg_dir / ".." / ".." / ".." / "target"
    candidates = [target_dir / p / "libsandlock_ffi.so" for p in ("debug", "release")]
    candidates = [c for c in candidates if c.exists()]
    if candidates:
        return str(max(candidates, key=lambda c: c.stat().st_mtime).resolve())

    # 2. Next to this file (installed via pip/setuptools-rust)
    for candidate in sorted(pkg_dir.glob("libsandlock_ffi*.so"), reverse=True):
        return str(candidate.resolve())

    # 3. System library path
    found = ctypes.util.find_library("sandlock_ffi")
    if found:
        return found

    # 4. LD_LIBRARY_PATH
    for d in os.environ.get("LD_LIBRARY_PATH", "").split(":"):
        p = os.path.join(d, "libsandlock_ffi.so")
        if os.path.isfile(p):
            return p

    raise RuntimeError(
        "libsandlock_ffi.so not found. Build with: "
        "cd sandlock-rs && cargo build --release"
    )

_lib = ctypes.CDLL(_find_lib())

# ----------------------------------------------------------------
# C function signatures
# ----------------------------------------------------------------

# Types
_c_policy_p = ctypes.c_void_p
_c_builder_p = ctypes.c_void_p
_c_result_p = ctypes.c_void_p
_c_pipeline_p = ctypes.c_void_p

# Sandbox builder
_lib.sandlock_sandbox_builder_new.restype = _c_builder_p
_lib.sandlock_sandbox_builder_new.argtypes = []

def _builder_fn(name, *extra_args):
    fn = getattr(_lib, name)
    fn.restype = _c_builder_p
    fn.argtypes = [_c_builder_p] + list(extra_args)
    return fn

_b_fs_read = _builder_fn("sandlock_sandbox_builder_fs_read", ctypes.c_char_p)
_b_fs_write = _builder_fn("sandlock_sandbox_builder_fs_write", ctypes.c_char_p)
_b_fs_deny = _builder_fn("sandlock_sandbox_builder_fs_deny", ctypes.c_char_p)
_b_fs_storage = _builder_fn("sandlock_sandbox_builder_fs_storage", ctypes.c_char_p)
_b_gpu_devices = _builder_fn("sandlock_sandbox_builder_gpu_devices", ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32)
_b_workdir = _builder_fn("sandlock_sandbox_builder_workdir", ctypes.c_char_p)
_b_cwd = _builder_fn("sandlock_sandbox_builder_cwd", ctypes.c_char_p)
_b_chroot = _builder_fn("sandlock_sandbox_builder_chroot", ctypes.c_char_p)
_b_fs_mount = _builder_fn("sandlock_sandbox_builder_fs_mount", ctypes.c_char_p, ctypes.c_char_p)
_b_fs_mount_ro = _builder_fn("sandlock_sandbox_builder_fs_mount_ro", ctypes.c_char_p, ctypes.c_char_p)
_b_on_exit = _builder_fn("sandlock_sandbox_builder_on_exit", ctypes.c_uint8)
_b_on_error = _builder_fn("sandlock_sandbox_builder_on_error", ctypes.c_uint8)
_b_max_memory = _builder_fn("sandlock_sandbox_builder_max_memory", ctypes.c_char_p)
_b_max_disk = _builder_fn("sandlock_sandbox_builder_max_disk", ctypes.c_char_p)
_b_max_processes = _builder_fn("sandlock_sandbox_builder_max_processes", ctypes.c_uint32)
_b_max_cpu = _builder_fn("sandlock_sandbox_builder_max_cpu", ctypes.c_uint8)
_b_num_cpus = _builder_fn("sandlock_sandbox_builder_num_cpus", ctypes.c_uint32)
_b_net_allow = _builder_fn("sandlock_sandbox_builder_net_allow", ctypes.c_char_p)
_b_net_deny = _builder_fn("sandlock_sandbox_builder_net_deny", ctypes.c_char_p)
_b_net_allow_bind = _builder_fn("sandlock_sandbox_builder_net_allow_bind", ctypes.c_char_p)
_b_net_deny_bind = _builder_fn("sandlock_sandbox_builder_net_deny_bind", ctypes.c_char_p)
_b_port_remap = _builder_fn("sandlock_sandbox_builder_port_remap", ctypes.c_bool)
_b_http_allow = _builder_fn("sandlock_sandbox_builder_http_allow", ctypes.c_char_p)
_b_http_deny = _builder_fn("sandlock_sandbox_builder_http_deny", ctypes.c_char_p)
_b_http_port = _builder_fn("sandlock_sandbox_builder_http_port", ctypes.c_uint16)
_b_http_ca = _builder_fn("sandlock_sandbox_builder_http_ca", ctypes.c_char_p)
_b_http_key = _builder_fn("sandlock_sandbox_builder_http_key", ctypes.c_char_p)
_b_http_inject_ca = _builder_fn("sandlock_sandbox_builder_http_inject_ca", ctypes.c_char_p)
_b_http_ca_out = _builder_fn("sandlock_sandbox_builder_http_ca_out", ctypes.c_char_p)
_b_user = _builder_fn("sandlock_sandbox_builder_user", ctypes.c_uint32, ctypes.c_uint32)
_b_random_seed = _builder_fn("sandlock_sandbox_builder_random_seed", ctypes.c_uint64)
_b_clean_env = _builder_fn("sandlock_sandbox_builder_clean_env", ctypes.c_bool)
_b_env_var = _builder_fn("sandlock_sandbox_builder_env_var", ctypes.c_char_p, ctypes.c_char_p)
_b_time_start = _builder_fn("sandlock_sandbox_builder_time_start", ctypes.c_char_p)
_b_time_start_epoch = _builder_fn(
    "sandlock_sandbox_builder_time_start_epoch", ctypes.c_int64, ctypes.c_uint32
)
_b_extra_deny_syscalls = _builder_fn("sandlock_sandbox_builder_extra_deny_syscalls", ctypes.c_char_p)
_b_extra_allow_syscalls = _builder_fn("sandlock_sandbox_builder_extra_allow_syscalls", ctypes.c_char_p)
_b_max_open_files = _builder_fn("sandlock_sandbox_builder_max_open_files", ctypes.c_uint32)
_b_no_randomize_memory = _builder_fn("sandlock_sandbox_builder_no_randomize_memory", ctypes.c_bool)
_b_no_huge_pages = _builder_fn("sandlock_sandbox_builder_no_huge_pages", ctypes.c_bool)
_b_no_coredump = _builder_fn("sandlock_sandbox_builder_no_coredump", ctypes.c_bool)
_b_deterministic_dirs = _builder_fn("sandlock_sandbox_builder_deterministic_dirs", ctypes.c_bool)
_b_cpu_cores = _builder_fn("sandlock_sandbox_builder_cpu_cores", ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32)

# Protection opt-out — mirror of the C ABI `sandlock_protection_t`.
# Discriminant values must stay in sync with `sandlock_core::Protection`
# and `sandlock_protection_t` in `crates/sandlock-ffi/include/sandlock.h`.
class Protection(IntEnum):
    """Per-protection Landlock feature identifier.

    Pass values from this enum to ``Sandbox(allow_degraded=...)`` or
    ``Sandbox(disable=...)`` to opt out of strict enforcement for the
    named protection. See the C header for kernel ABI requirements.
    """

    FS_REFER = 0
    FS_TRUNCATE = 1
    NET_TCP = 2
    FS_IOCTL_DEV = 3
    SIGNAL_SCOPE = 4
    ABSTRACT_UNIX_SOCKET_SCOPE = 5


_lib.sandlock_protection_min_abi.restype = ctypes.c_uint32
_lib.sandlock_protection_min_abi.argtypes = [ctypes.c_uint32]

# Move-semantics setters: each returns the (possibly relocated) builder
# pointer, mirroring the convention of the other `_builder_fn` setters.
# The C ABI accepts the protection as a `uint32_t` so an out-of-range
# value is rejected at the FFI boundary (no `#[repr(C)]` enum cast).
_b_allow_degraded = _builder_fn(
    "sandlock_sandbox_builder_allow_degraded", ctypes.c_uint32
)
_b_disable = _builder_fn(
    "sandlock_sandbox_builder_disable", ctypes.c_uint32
)


# Policy callback (policy_fn).
# Path strings absent (issue #27 — path-based control belongs in Landlock).
# argv is populated for execve only; TOCTOU-safe via sibling freeze.
class _CEvent(ctypes.Structure):
    _fields_ = [
        ("syscall", ctypes.c_char_p),
        ("category", ctypes.c_uint8),
        ("pid", ctypes.c_uint32),
        ("parent_pid", ctypes.c_uint32),
        ("host", ctypes.c_char_p),
        ("port", ctypes.c_uint16),
        ("denied", ctypes.c_bool),
        ("argv", ctypes.POINTER(ctypes.c_char_p)),
        ("argc", ctypes.c_uint32),
    ]

_c_ctx_p = ctypes.c_void_p
_POLICY_FN_TYPE = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.POINTER(_CEvent),
    _c_ctx_p,
    ctypes.c_void_p,
)

_lib.sandlock_sandbox_builder_policy_fn.restype = _c_builder_p
_lib.sandlock_sandbox_builder_policy_fn.argtypes = [
    _c_builder_p,
    _POLICY_FN_TYPE,
    ctypes.c_void_p,
    ctypes.c_void_p,
]

_lib.sandlock_ctx_restrict_network.restype = None
_lib.sandlock_ctx_restrict_network.argtypes = [_c_ctx_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint32]

_lib.sandlock_ctx_grant_network.restype = None
_lib.sandlock_ctx_grant_network.argtypes = [_c_ctx_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint32]

_lib.sandlock_ctx_restrict_max_memory.restype = None
_lib.sandlock_ctx_restrict_max_memory.argtypes = [_c_ctx_p, ctypes.c_uint64]

_lib.sandlock_ctx_restrict_max_processes.restype = None
_lib.sandlock_ctx_restrict_max_processes.argtypes = [_c_ctx_p, ctypes.c_uint32]

_lib.sandlock_ctx_restrict_pid_network.restype = None
_lib.sandlock_ctx_restrict_pid_network.argtypes = [_c_ctx_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint32]

_lib.sandlock_ctx_deny_path.restype = None
_lib.sandlock_ctx_deny_path.argtypes = [_c_ctx_p, ctypes.c_char_p]

_lib.sandlock_ctx_allow_path.restype = None
_lib.sandlock_ctx_allow_path.argtypes = [_c_ctx_p, ctypes.c_char_p]

# Platform query
_lib.sandlock_landlock_abi_version.restype = ctypes.c_int
_lib.sandlock_landlock_abi_version.argtypes = []

_lib.sandlock_min_landlock_abi.restype = ctypes.c_int
_lib.sandlock_min_landlock_abi.argtypes = []

# Confine current process
_lib.sandlock_confine.restype = ctypes.c_int
_lib.sandlock_confine.argtypes = [ctypes.c_void_p]


def landlock_abi_version() -> int:
    """Return the Landlock ABI version supported by the running kernel.

    Returns -1 if Landlock is unavailable.
    """
    return _lib.sandlock_landlock_abi_version()


def min_landlock_abi() -> int:
    """Return the minimum Landlock ABI version required by sandlock."""
    return _lib.sandlock_min_landlock_abi()


def confine(policy: "PolicyDataclass") -> None:
    """Confine the calling process with Landlock restrictions.

    Applies PR_SET_NO_NEW_PRIVS and Landlock rules from the policy's
    filesystem fields. IPC and signal isolation are always enabled. The
    confinement is **irreversible**.

    Only filesystem paths are accepted. Policies containing supervisor,
    seccomp, network, resource, environment, or COW settings are rejected
    rather than silently ignored.

    This does NOT fork or exec — it confines the current process in-place.

    Args:
        policy: Policy with Landlock rules to apply.

    Raises:
        SandlockError: If confinement fails.
    """
    native = _NativePolicy.from_dataclass(policy)
    ret = _lib.sandlock_confine(native.ptr)
    if ret != 0:
        from .exceptions import ConfinementError
        raise ConfinementError("confine failed")


_lib.sandlock_sandbox_build.restype = _c_policy_p
_lib.sandlock_sandbox_build.argtypes = [
    _c_builder_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_char_p),
]

_lib.sandlock_sandbox_free.restype = None
_lib.sandlock_sandbox_free.argtypes = [_c_policy_p]

# String-out-param release. The FFI returns CString::into_raw pointers
# for error messages from sandlock_sandbox_build; we must free them via
# this function rather than ctypes' own deallocator.
_lib.sandlock_string_free.restype = None
_lib.sandlock_string_free.argtypes = [ctypes.c_char_p]


def _free_builder(b) -> None:
    """Release a builder that will never be built.

    The C ABI has no `sandlock_sandbox_builder_free`; `sandlock_sandbox_build`
    is the only entry point that consumes a builder, so an abandoned one is
    released by building it and throwing the result away. Whatever verdict the
    build reaches is irrelevant here: the caller is already unwinding with the
    reason it stopped. The Go SDK carried the same helper for the same reason.
    """
    if not b:
        return
    err = ctypes.c_int(0)
    err_msg = ctypes.c_char_p()
    ptr = _lib.sandlock_sandbox_build(b, ctypes.byref(err), ctypes.byref(err_msg))
    if err_msg.value:
        _lib.sandlock_string_free(err_msg)
    if ptr:
        _lib.sandlock_sandbox_free(ptr)

# Profile parsing. The return type is c_void_p rather than c_char_p on
# purpose: ctypes converts a c_char_p result to `bytes` and drops the
# pointer, leaving nothing to hand back to sandlock_string_free.
_lib.sandlock_profile_parse.restype = ctypes.c_void_p
_lib.sandlock_profile_parse.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_char_p),
]


def profile_parse(toml_text: str) -> dict:
    """Parse a TOML profile with the core parser, returning its canonical form.

    Every micro-grammar in the profile (mount specs, byte sizes, timestamps,
    port specs, net/HTTP rules, branch actions) is resolved by the same code
    path the CLI runs, so a profile either loads identically in both or fails
    in both with the same message.

    Raises:
        PolicyError: With the core parser's own message.
    """
    from .exceptions import PolicyError

    encoded = toml_text.encode("utf-8")
    if b"\0" in encoded:
        # The C ABI takes a NUL-terminated string, so a NUL inside the profile
        # would truncate it and parse a prefix as if it were the whole file.
        raise PolicyError("profile contains a NUL byte")

    err = ctypes.c_int(0)
    err_msg = ctypes.c_char_p()
    ptr = _lib.sandlock_profile_parse(encoded, ctypes.byref(err), ctypes.byref(err_msg))
    if not ptr or err.value != 0:
        # err_msg.value copies the bytes; the allocation itself still has to
        # be released. When the FFI leaves it null (an internal binding bug,
        # not a profile problem) there is no diagnosis to report, so raise
        # without one rather than inventing a message.
        msg = err_msg.value.decode("utf-8", "replace") if err_msg.value else None
        if err_msg.value:
            _lib.sandlock_string_free(err_msg)
        raise PolicyError(msg) if msg else PolicyError()
    try:
        return json.loads(ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8"))
    finally:
        _lib.sandlock_string_free(ctypes.cast(ptr, ctypes.c_char_p))


# Run
_lib.sandlock_run.restype = _c_result_p
_lib.sandlock_run.argtypes = [_c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_run_interactive.restype = ctypes.c_int
_lib.sandlock_run_interactive.argtypes = [_c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

# Sandbox handle (create / start / wait)
_c_handle_p = ctypes.c_void_p

_lib.sandlock_create.restype = _c_handle_p
_lib.sandlock_create.argtypes = [_c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_create_for_run.restype = _c_handle_p
_lib.sandlock_create_for_run.argtypes = [_c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_start.restype = ctypes.c_int
_lib.sandlock_start.argtypes = [_c_handle_p]

_lib.sandlock_handle_pid.restype = ctypes.c_int
_lib.sandlock_handle_pid.argtypes = [_c_handle_p]

_lib.sandlock_handle_wait.restype = _c_result_p
_lib.sandlock_handle_wait.argtypes = [_c_handle_p]

_lib.sandlock_handle_wait_timeout.restype = _c_result_p
_lib.sandlock_handle_wait_timeout.argtypes = [_c_handle_p, ctypes.c_uint64]

_lib.sandlock_handle_free.restype = None
_lib.sandlock_handle_free.argtypes = [_c_handle_p]

_lib.sandlock_handle_port_mappings.restype = ctypes.c_char_p
_lib.sandlock_handle_port_mappings.argtypes = [_c_handle_p]

# Streaming-stdio popen (RFC #67): create+start a live handle with per-stream
# StdioMode; each piped stream's owned fd is returned through its out pointer.
_lib.sandlock_popen.restype = _c_handle_p
_lib.sandlock_popen.argtypes = [
    _c_policy_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_uint,
    ctypes.c_uint32,  # stdin_mode
    ctypes.c_uint32,  # stdout_mode
    ctypes.c_uint32,  # stderr_mode
    ctypes.POINTER(ctypes.c_int),  # out_stdin_fd
    ctypes.POINTER(ctypes.c_int),  # out_stdout_fd
    ctypes.POINTER(ctypes.c_int),  # out_stderr_fd
]

# Result
_lib.sandlock_result_exit_code.restype = ctypes.c_int
_lib.sandlock_result_exit_code.argtypes = [_c_result_p]

_lib.sandlock_result_success.restype = ctypes.c_bool
_lib.sandlock_result_success.argtypes = [_c_result_p]

_lib.sandlock_result_reason.restype = ctypes.c_uint  # sandlock_exit_reason (repr u32)
_lib.sandlock_result_reason.argtypes = [_c_result_p]

_lib.sandlock_result_signal.restype = ctypes.c_int
_lib.sandlock_result_signal.argtypes = [_c_result_p]

_lib.sandlock_result_stdout_bytes.restype = ctypes.c_void_p
_lib.sandlock_result_stdout_bytes.argtypes = [_c_result_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_result_stderr_bytes.restype = ctypes.c_void_p
_lib.sandlock_result_stderr_bytes.argtypes = [_c_result_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_result_free.restype = None
_lib.sandlock_result_free.argtypes = [_c_result_p]

# Dry-run
_c_dry_run_p = ctypes.c_void_p

_lib.sandlock_dry_run.restype = _c_dry_run_p
_lib.sandlock_dry_run.argtypes = [_c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_dry_run_result_exit_code.restype = ctypes.c_int
_lib.sandlock_dry_run_result_exit_code.argtypes = [_c_dry_run_p]

_lib.sandlock_dry_run_result_reason.restype = ctypes.c_uint
_lib.sandlock_dry_run_result_reason.argtypes = [_c_dry_run_p]

_lib.sandlock_dry_run_result_signal.restype = ctypes.c_int
_lib.sandlock_dry_run_result_signal.argtypes = [_c_dry_run_p]

_lib.sandlock_dry_run_result_success.restype = ctypes.c_bool
_lib.sandlock_dry_run_result_success.argtypes = [_c_dry_run_p]

_lib.sandlock_dry_run_result_stdout_bytes.restype = ctypes.c_void_p
_lib.sandlock_dry_run_result_stdout_bytes.argtypes = [_c_dry_run_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_dry_run_result_stderr_bytes.restype = ctypes.c_void_p
_lib.sandlock_dry_run_result_stderr_bytes.argtypes = [_c_dry_run_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_dry_run_result_changes_len.restype = ctypes.c_size_t
_lib.sandlock_dry_run_result_changes_len.argtypes = [_c_dry_run_p]

_lib.sandlock_dry_run_result_change_kind.restype = ctypes.c_char
_lib.sandlock_dry_run_result_change_kind.argtypes = [_c_dry_run_p, ctypes.c_size_t]

_lib.sandlock_dry_run_result_change_path.restype = ctypes.c_void_p
_lib.sandlock_dry_run_result_change_path.argtypes = [_c_dry_run_p, ctypes.c_size_t]

_lib.sandlock_dry_run_result_free.restype = None
_lib.sandlock_dry_run_result_free.argtypes = [_c_dry_run_p]

# Pipeline
_lib.sandlock_pipeline_new.restype = _c_pipeline_p
_lib.sandlock_pipeline_new.argtypes = []

_lib.sandlock_pipeline_add_stage.restype = None
_lib.sandlock_pipeline_add_stage.argtypes = [
    _c_pipeline_p, _c_policy_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint,
]

_lib.sandlock_pipeline_run.restype = _c_result_p
_lib.sandlock_pipeline_run.argtypes = [_c_pipeline_p, ctypes.c_uint64]

_lib.sandlock_pipeline_free.restype = None
_lib.sandlock_pipeline_free.argtypes = [_c_pipeline_p]

# Gather
_c_gather_p = ctypes.c_void_p

_lib.sandlock_gather_new.restype = _c_gather_p
_lib.sandlock_gather_new.argtypes = []

_lib.sandlock_gather_add_source.restype = None
_lib.sandlock_gather_add_source.argtypes = [
    _c_gather_p, ctypes.c_char_p, _c_policy_p,
    ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint,
]

_lib.sandlock_gather_set_consumer.restype = None
_lib.sandlock_gather_set_consumer.argtypes = [
    _c_gather_p, _c_policy_p,
    ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint,
]

_lib.sandlock_gather_run.restype = _c_result_p
_lib.sandlock_gather_run.argtypes = [_c_gather_p, ctypes.c_uint64]

_lib.sandlock_gather_free.restype = None
_lib.sandlock_gather_free.argtypes = [_c_gather_p]

_lib.sandlock_string_free.restype = None
_lib.sandlock_string_free.argtypes = [ctypes.c_char_p]

# Fork
_INIT_FN_TYPE = ctypes.CFUNCTYPE(None)
_WORK_FN_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_uint32)

_c_sandbox_p = ctypes.c_void_p

_lib.sandlock_new_with_fns.restype = _c_sandbox_p
_lib.sandlock_new_with_fns.argtypes = [_c_policy_p, ctypes.c_char_p, _INIT_FN_TYPE, _WORK_FN_TYPE]

_c_fork_result_p = ctypes.c_void_p

_lib.sandlock_fork.restype = _c_fork_result_p
_lib.sandlock_fork.argtypes = [_c_sandbox_p, ctypes.c_uint32]

_lib.sandlock_fork_result_count.restype = ctypes.c_uint32
_lib.sandlock_fork_result_count.argtypes = [_c_fork_result_p]

_lib.sandlock_fork_result_pid.restype = ctypes.c_int32
_lib.sandlock_fork_result_pid.argtypes = [_c_fork_result_p, ctypes.c_uint32]

_lib.sandlock_reduce.restype = _c_result_p
_lib.sandlock_reduce.argtypes = [_c_fork_result_p, _c_policy_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_fork_result_free.restype = None
_lib.sandlock_fork_result_free.argtypes = [_c_fork_result_p]

_lib.sandlock_wait.restype = ctypes.c_int
_lib.sandlock_wait.argtypes = [_c_sandbox_p]

_lib.sandlock_sandbox_free.restype = None
_lib.sandlock_sandbox_free.argtypes = [_c_sandbox_p]

# Checkpoint
_c_checkpoint_p = ctypes.c_void_p

_lib.sandlock_handle_checkpoint.restype = _c_checkpoint_p
_lib.sandlock_handle_checkpoint.argtypes = [_c_handle_p]

_lib.sandlock_checkpoint_save.restype = ctypes.c_int
_lib.sandlock_checkpoint_save.argtypes = [_c_checkpoint_p, ctypes.c_char_p]

_lib.sandlock_checkpoint_load.restype = _c_checkpoint_p
_lib.sandlock_checkpoint_load.argtypes = [ctypes.c_char_p]

_lib.sandlock_checkpoint_set_name.restype = None
_lib.sandlock_checkpoint_set_name.argtypes = [_c_checkpoint_p, ctypes.c_char_p]

_lib.sandlock_checkpoint_name.restype = ctypes.c_void_p
_lib.sandlock_checkpoint_name.argtypes = [_c_checkpoint_p]

_lib.sandlock_checkpoint_set_app_state.restype = None
_lib.sandlock_checkpoint_set_app_state.argtypes = [_c_checkpoint_p, ctypes.c_void_p, ctypes.c_size_t]

_lib.sandlock_checkpoint_app_state.restype = ctypes.c_void_p
_lib.sandlock_checkpoint_app_state.argtypes = [_c_checkpoint_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_checkpoint_free.restype = None
_lib.sandlock_checkpoint_free.argtypes = [_c_checkpoint_p]

_lib.sandlock_restore_interactive.restype = _c_handle_p
_lib.sandlock_restore_interactive.argtypes = [_c_policy_p, ctypes.c_char_p, _c_checkpoint_p]

_lib.sandlock_handle_restore_skipped_len.restype = ctypes.c_size_t
_lib.sandlock_handle_restore_skipped_len.argtypes = [_c_handle_p]

_lib.sandlock_handle_restore_skipped_fd.restype = ctypes.c_int
_lib.sandlock_handle_restore_skipped_fd.argtypes = [_c_handle_p, ctypes.c_size_t]

_lib.sandlock_handle_restore_skipped_path.restype = ctypes.c_void_p
_lib.sandlock_handle_restore_skipped_path.argtypes = [_c_handle_p, ctypes.c_size_t]


# ----------------------------------------------------------------
# Handler ABI — extension handlers for seccomp-notif syscalls.
#
# Structures mirror the C ABI in crates/sandlock-ffi/include/sandlock.h;
# the trampoline that drives these bindings lives in _handler_ffi.py.
# ----------------------------------------------------------------

# sandlock_notif_data_t — kernel seccomp-notification snapshot. The
# `args` array is fixed at 6 entries (the syscall ABI maximum).
class _SandlockNotifData(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("syscall_nr", ctypes.c_int32),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]


# sandlock_action_payload_t — the tagged union the setters fill in. The
# trampoline never reads these fields directly (it only ever calls the
# setters), but the layout must match so the struct is sized correctly.
class _SandlockActionPayload(ctypes.Union):
    _fields_ = [
        ("none", ctypes.c_uint64),
        ("errno_value", ctypes.c_int32),
        ("return_value", ctypes.c_int64),
        # inject_send: { int32 srcfd; uint32 newfd_flags; }
        ("inject_send", ctypes.c_uint32 * 2),
        # inject_send_tracked: { int32; uint32; uint64; } — reserved.
        ("inject_send_tracked", ctypes.c_uint64 * 2),
        # kill: { int32 sig; int32 pgid; }
        ("kill", ctypes.c_int32 * 2),
    ]


# sandlock_action_out_t — the slot a handler writes its decision into.
class _SandlockActionOut(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint32),
        ("payload", _SandlockActionPayload),
    ]


# sandlock_handler_registration_t — one (syscall_nr, handler) pair.
class _SandlockHandlerRegistration(ctypes.Structure):
    _fields_ = [
        ("syscall_nr", ctypes.c_int64),
        ("handler", ctypes.c_void_p),
    ]


_c_mem_handle_p = ctypes.c_void_p

# C handler signature:
#   int (*)(void *ud, const sandlock_notif_data_t *notif,
#           sandlock_mem_handle_t *mem, sandlock_action_out_t *out)
_HANDLER_FN_TYPE = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_void_p,                          # ud
    ctypes.POINTER(_SandlockNotifData),       # notif
    _c_mem_handle_p,                          # mem
    ctypes.POINTER(_SandlockActionOut),       # out
)

# void (*)(void *ud)
_UD_DROP_FN_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_void_p)

_c_handler_p = ctypes.c_void_p

_lib.sandlock_handler_new.restype = _c_handler_p
_lib.sandlock_handler_new.argtypes = [
    _HANDLER_FN_TYPE, ctypes.c_void_p, _UD_DROP_FN_TYPE, ctypes.c_uint32,
]

_lib.sandlock_handler_free.restype = None
_lib.sandlock_handler_free.argtypes = [_c_handler_p]

_lib.sandlock_handler_set_deferred.restype = None
_lib.sandlock_handler_set_deferred.argtypes = [_c_handler_p, ctypes.c_bool]

_lib.sandlock_run_with_handlers.restype = _c_result_p
_lib.sandlock_run_with_handlers.argtypes = [
    _c_policy_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint,
    ctypes.POINTER(_SandlockHandlerRegistration), ctypes.c_size_t,
]

_lib.sandlock_run_interactive_with_handlers.restype = _c_result_p
_lib.sandlock_run_interactive_with_handlers.argtypes = [
    _c_policy_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint,
    ctypes.POINTER(_SandlockHandlerRegistration), ctypes.c_size_t,
]

# Resolve a syscall name to its host-arch number; -1 on unknown/NULL.
_lib.sandlock_syscall_nr.restype = ctypes.c_int64
_lib.sandlock_syscall_nr.argtypes = [ctypes.c_char_p]

# Action setters — exactly one per action, called from the trampoline.
_lib.sandlock_action_set_continue.restype = None
_lib.sandlock_action_set_continue.argtypes = [ctypes.POINTER(_SandlockActionOut)]

_lib.sandlock_action_set_errno.restype = None
_lib.sandlock_action_set_errno.argtypes = [
    ctypes.POINTER(_SandlockActionOut), ctypes.c_int32,
]

_lib.sandlock_action_set_return_value.restype = None
_lib.sandlock_action_set_return_value.argtypes = [
    ctypes.POINTER(_SandlockActionOut), ctypes.c_int64,
]

_lib.sandlock_action_set_inject_fd_send.restype = None
_lib.sandlock_action_set_inject_fd_send.argtypes = [
    ctypes.POINTER(_SandlockActionOut), ctypes.c_int32, ctypes.c_uint32,
]

_lib.sandlock_action_set_hold.restype = None
_lib.sandlock_action_set_hold.argtypes = [ctypes.POINTER(_SandlockActionOut)]

_lib.sandlock_action_set_kill.restype = None
_lib.sandlock_action_set_kill.argtypes = [
    ctypes.POINTER(_SandlockActionOut), ctypes.c_int32, ctypes.c_int32,
]

# Child-memory accessors — valid only for the duration of a callback.
_lib.sandlock_mem_read_cstr.restype = ctypes.c_int
_lib.sandlock_mem_read_cstr.argtypes = [
    _c_mem_handle_p, ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

_lib.sandlock_mem_read.restype = ctypes.c_int
_lib.sandlock_mem_read.argtypes = [
    _c_mem_handle_p, ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

_lib.sandlock_mem_write.restype = ctypes.c_int
_lib.sandlock_mem_write.argtypes = [
    _c_mem_handle_p, ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
]


# ----------------------------------------------------------------
# SyscallEvent & PolicyContext (Python wrappers for policy_fn)
# ----------------------------------------------------------------

@dataclass(frozen=True)
class SyscallEvent:
    """An intercepted syscall event.

    Path strings are intentionally absent: the kernel re-reads user-memory
    pointers after a Continue response, so any path-string-based decision
    is racy (issue #27). Path-based access control belongs in static
    Landlock rules (``fs_readable``, ``fs_writable``, ``fs_denied``).

    ``argv`` *is* exposed for execve/execveat events and is TOCTOU-safe:
    the supervisor freezes the calling process's sibling threads via
    PTRACE_INTERRUPT before returning Continue, so the kernel's re-read
    sees the same memory the supervisor inspected. Siblings die during
    execve's de_thread step regardless, so the freeze has no observable
    cost.
    """
    syscall: str
    category: str | int
    """``"file"``, ``"network"``, ``"process"`` or ``"memory"``; a category
    this SDK has no name for is the raw discriminant the core sent, rather
    than one of the four names it is not."""
    pid: int
    parent_pid: int = 0
    host: str | None = None
    port: int = 0
    argv: tuple[str, ...] | None = None
    denied: bool = False

    def argv_contains(self, s: str) -> bool:
        """Returns True if any argv element contains ``s``.

        Only meaningful for execve/execveat events.
        """
        return self.argv is not None and any(s in a for a in self.argv)


class PolicyContext:
    """Context for modifying sandbox policy from a callback."""

    def __init__(self, ctx_ptr):
        self._ptr = ctx_ptr

    def restrict_network(self, ips: list[str]) -> None:
        arr = (ctypes.c_char_p * len(ips))(*[_encode(ip) for ip in ips])
        _lib.sandlock_ctx_restrict_network(self._ptr, arr, len(ips))

    def grant_network(self, ips: list[str]) -> None:
        arr = (ctypes.c_char_p * len(ips))(*[_encode(ip) for ip in ips])
        _lib.sandlock_ctx_grant_network(self._ptr, arr, len(ips))

    def restrict_max_memory(self, bytes: int) -> None:
        _lib.sandlock_ctx_restrict_max_memory(self._ptr, bytes)

    def restrict_max_processes(self, n: int) -> None:
        _lib.sandlock_ctx_restrict_max_processes(self._ptr, n)

    def restrict_pid_network(self, pid: int, ips: list[str]) -> None:
        arr = (ctypes.c_char_p * len(ips))(*[_encode(ip) for ip in ips])
        _lib.sandlock_ctx_restrict_pid_network(self._ptr, pid, arr, len(ips))

    def deny_path(self, path: str) -> None:
        """Deny access to a path (checked on openat)."""
        _lib.sandlock_ctx_deny_path(self._ptr, _encode(path))

    def allow_path(self, path: str) -> None:
        """Remove a previously denied path."""
        _lib.sandlock_ctx_allow_path(self._ptr, _encode(path))


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _encode(s: str) -> bytes:
    if isinstance(s, str):
        result = s.encode("utf-8")
    elif isinstance(s, bytes):
        result = s
    else:
        result = str(s).encode("utf-8")
    if b'\x00' in result:
        raise ValueError(f"NUL byte in string argument: {result!r}")
    return result


def _fits(value, field: str, *, bits: int, signed: bool = False) -> int:
    """Check that an integer survives the C ABI parameter that carries it.

    A representation check, and the one kind the core cannot make for us: the
    setter's parameter is a fixed-width integer, Python's is not, and ctypes
    converts by masking rather than by failing. Without this, ``max_cpu=300``
    arrives as 44 and is accepted as a perfectly ordinary throttle, and
    ``uid=-1`` arrives as 4294967295. The value the core would have judged is
    gone before it gets there, so refusing here is what keeps its verdict
    reachable, not a second opinion on the policy.

    ``bool`` is rejected outright: it is an ``int`` subclass, so ``True``
    would otherwise pass silently as 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer, got {value!r}")
    lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    if not lo <= value <= hi:
        raise ValueError(
            f"{field}={value} does not fit the {'int' if signed else 'uint'}{bits} "
            f"parameter of its C ABI setter (permitted: {lo}..{hi})"
        )
    return value


def _branch_action(value, field: str) -> int:
    """Render a branch action as the discriminant its C ABI setter takes.

    A :class:`~sandlock.BranchAction`, or one of the three spellings it is
    built from, becomes its own discriminant. A number is passed through
    untouched, so an action this SDK does not know still reaches the core and
    is refused there by value, where it used to be replaced by Commit or Abort
    through a ``.get(value, default)``: a typo became a decision about the
    caller's writes.

    A word the enum does not know cannot be forwarded at all, because the
    setter's parameter is a ``uint8_t``. That is a limit of the ABI, not a
    second opinion on the policy, and it is the only case answered here.
    """
    from .sandbox import BranchAction

    if isinstance(value, BranchAction):
        return value.abi
    if isinstance(value, int) and not isinstance(value, bool):
        return _fits(value, field, bits=8)
    try:
        return BranchAction(value).abi
    except ValueError:
        raise ValueError(
            f"{field}: {value!r} is not a branch action; "
            f"the C ABI setter carries a discriminant, so a word it does not "
            f"name ({', '.join(a.value for a in BranchAction)}) cannot be "
            f"forwarded to the core to be judged there"
        ) from None


def _epoch_split(value: float) -> tuple[int, int]:
    """Split epoch seconds into the ``(seconds, nanoseconds)`` pair the ABI takes.

    Not a grammar: the unit is fixed on both sides, so this only moves the
    sub-second part into its own field, flooring the way
    ``sandlock_profile_parse`` does so the remainder is never negative. A
    string is never routed through here; it goes to the core verbatim.
    """
    seconds = math.floor(value)
    nanoseconds = round((value - seconds) * 1_000_000_000)
    if nanoseconds == 1_000_000_000:  # the remainder rounded up to a full second
        seconds += 1
        nanoseconds = 0
    return seconds, nanoseconds


def _b_time_start_from(b, value):
    """Send ``time_start`` through whichever of its two setters fits the value.

    Text goes to ``sandlock_sandbox_builder_time_start`` untouched, so the RFC
    3339 grammar is read once, by the core, exactly as it is for a profile key
    and a command-line flag. A number is an instant that has already been
    resolved (it is what ``sandlock_profile_parse`` reports) and goes to
    ``..._time_start_epoch``, which takes the resolved form directly; rendering
    it back into a stamp here would be this SDK writing the grammar it just
    stopped reading.
    """
    if isinstance(value, str):
        return _b_time_start(b, _encode(value))
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            "time_start must be an RFC 3339 string or epoch seconds, got "
            f"{value!r}"
        )
    seconds, nanoseconds = _epoch_split(value)
    return _b_time_start_epoch(
        b, _fits(seconds, "time_start seconds", bits=64, signed=True), nanoseconds
    )


def _make_argv(cmd: Sequence[str]):
    """Create a (c_char_p array, argc) pair from a list of strings."""
    argc = len(cmd)
    argv_type = ctypes.c_char_p * argc
    argv = argv_type(*[_encode(a) for a in cmd])
    return argv, ctypes.c_uint(argc)

def _read_result_bytes(result_p, fn) -> bytes:
    """Read stdout or stderr bytes from a result pointer."""
    length = ctypes.c_size_t(0)
    ptr = fn(result_p, ctypes.byref(length))
    if not ptr or length.value == 0:
        return b""
    return ctypes.string_at(ptr, length.value)


# ----------------------------------------------------------------
# Result
# ----------------------------------------------------------------

class ExitReason(IntEnum):
    """Why a sandboxed process terminated (mirrors the C ``sandlock_exit_reason``).

    Linux bottoms both a timeout and an OOM kill out in ``SIGKILL``, so there is
    no distinct OOM reason: a timeout sandlock enforced is ``TIMEOUT``, any other
    kill is ``KILLED``.
    """
    EXITED = 0
    """Exited normally with a code (see ``Result.exit_code``)."""
    SIGNALED = 1
    """Terminated by a signal (see ``Result.signal``)."""
    KILLED = 2
    """Killed with no recoverable signal number."""
    TIMEOUT = 3
    """Killed by sandlock because it exceeded its timeout."""


@dataclass
class Result:
    """Result of a sandboxed command."""
    success: bool
    exit_code: int = 0
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)
    error: str | None = None
    # Appended after the original fields so positional construction is unchanged.
    reason: ExitReason | None = None
    """Why the process terminated (timeout / signal / kill / normal exit);
    ``None`` on an error raised before a native result was produced."""
    signal: int = -1
    """Signal number for a ``SIGNALED`` result, else ``-1``."""


# ----------------------------------------------------------------
# Checkpoint
# ----------------------------------------------------------------

_DEFAULT_STORE = Path.home() / ".sandlock" / "checkpoints"


class SkippedFd(NamedTuple):
    """An fd that ``Sandbox.restore_interactive`` could not transparently
    recreate (socket, pipe, memfd, deleted or pseudo-filesystem path). The
    restored process runs without it; such resources fall to the
    ``app_state`` hatch."""

    fd: int
    """The fd number in the checkpointed process."""
    path: str
    """The resource the fd pointed at (e.g. ``pipe:[12345]``)."""


class Checkpoint:
    """A frozen snapshot of sandbox state (registers, memory, fds).

    Wraps a native checkpoint captured via ptrace + /proc.

    Usage::

        sb = Sandbox(fs_readable=["/usr", "/lib"])
        sb.spawn(["sleep", "60"])
        cp = sb.checkpoint()
        cp.save("my-checkpoint")

        # Later:
        cp2 = Checkpoint.load("my-checkpoint")
    """

    @staticmethod
    def _validate_name(name: str) -> None:
        """Reject checkpoint names that could escape the storage directory."""
        if not name or '/' in name or os.sep in name or name.startswith('.'):
            raise ValueError(
                f"Invalid checkpoint name: {name!r}. "
                "Use a simple name without path separators."
            )

    def __init__(self, ptr: int):
        self._ptr = ptr

    @property
    def name(self) -> str:
        """Checkpoint name."""
        raw = _lib.sandlock_checkpoint_name(self._ptr)
        if not raw:
            return ""
        # raw is a void pointer to a malloc'd C string
        c_str = ctypes.cast(raw, ctypes.c_char_p)
        name = c_str.value.decode("utf-8", errors="replace") if c_str.value else ""
        _lib.sandlock_string_free(c_str)
        return name

    @name.setter
    def name(self, value: str) -> None:
        _lib.sandlock_checkpoint_set_name(self._ptr, _encode(value))

    @property
    def app_state(self) -> bytes | None:
        """Optional application-level state bytes."""
        length = ctypes.c_size_t(0)
        ptr = _lib.sandlock_checkpoint_app_state(self._ptr, ctypes.byref(length))
        if not ptr or length.value == 0:
            return None
        return ctypes.string_at(ptr, length.value)

    @app_state.setter
    def app_state(self, data: bytes | None) -> None:
        if data is None:
            _lib.sandlock_checkpoint_set_app_state(self._ptr, None, 0)
        else:
            buf = ctypes.create_string_buffer(data)
            _lib.sandlock_checkpoint_set_app_state(
                self._ptr, ctypes.cast(buf, ctypes.c_void_p), len(data),
            )

    def save(self, name: str, *, store: Path | str | None = None) -> Path:
        """Persist this checkpoint under a named store.

        Storage layout::

            <store>/<name>/
            ├── meta.json
            ├── policy.dat
            ├── app_state.bin      (optional)
            └── process/
                ├── info.json
                ├── fds.json
                ├── memory_map.json
                ├── threads/0.bin
                └── memory/<i>.bin

        Args:
            name: Checkpoint name (used as directory name).
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Returns:
            Path to the checkpoint directory.
        """
        self._validate_name(name)
        root = Path(store) if store is not None else _DEFAULT_STORE
        root.mkdir(parents=True, exist_ok=True)
        cp_dir = root / name
        self.name = name
        rc = _lib.sandlock_checkpoint_save(self._ptr, _encode(str(cp_dir)))
        if rc != 0:
            raise RuntimeError(f"Failed to save checkpoint to {cp_dir}")
        return cp_dir

    @classmethod
    def load(
        cls,
        name: str,
        *,
        store: Path | str | None = None,
        restore_fn: "Callable[[bytes], None] | None" = None,
    ) -> "Checkpoint":
        """Load a named checkpoint from disk.

        ``restore_fn`` mirrors ``save_fn`` on ``Sandbox.checkpoint``: use it
        to rebuild application-level state that ptrace cannot capture (caches,
        session data, etc.). Neither is mandatory, and they need not be
        paired: ``restore_fn`` is called with ``cp.app_state`` only when the
        checkpoint carries app state, and app state left unconsumed here
        remains readable via ``cp.app_state``. Restoring the OS-level process
        image is separate: see ``Sandbox.restore_interactive``.

        Args:
            name: Checkpoint name.
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.
            restore_fn: Optional callback receiving the saved
                application-level state bytes; not called if the checkpoint
                has no app state.

        Returns:
            The loaded Checkpoint.

        Raises:
            FileNotFoundError: If the checkpoint does not exist.
        """
        cls._validate_name(name)
        root = Path(store) if store is not None else _DEFAULT_STORE
        cp_dir = root / name
        if not cp_dir.is_dir():
            raise FileNotFoundError(f"Checkpoint not found: {cp_dir}")
        ptr = _lib.sandlock_checkpoint_load(_encode(str(cp_dir)))
        if not ptr:
            raise RuntimeError(f"Failed to load checkpoint from {cp_dir}")
        cp = cls(ptr)
        if restore_fn is not None:
            state = cp.app_state
            if state is not None:
                restore_fn(state)
        return cp

    @classmethod
    def list(cls, *, store: Path | str | None = None) -> list[str]:
        """List all named checkpoints.

        Args:
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Returns:
            Sorted list of checkpoint names.
        """
        root = Path(store) if store is not None else _DEFAULT_STORE
        if not root.is_dir():
            return []
        return sorted(
            d.name for d in root.iterdir()
            if d.is_dir() and (d / "meta.json").exists()
        )

    @classmethod
    def delete(cls, name: str, *, store: Path | str | None = None) -> None:
        """Delete a named checkpoint.

        Args:
            name: Checkpoint name.
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Raises:
            FileNotFoundError: If the checkpoint does not exist.
        """
        import shutil
        cls._validate_name(name)
        root = Path(store) if store is not None else _DEFAULT_STORE
        cp_dir = root / name
        if not cp_dir.is_dir():
            raise FileNotFoundError(f"Checkpoint not found: {cp_dir}")
        shutil.rmtree(cp_dir)

    def __del__(self):
        if getattr(self, "_ptr", None):
            _lib.sandlock_checkpoint_free(self._ptr)
            self._ptr = None


# ----------------------------------------------------------------
# Policy (native handle)
# ----------------------------------------------------------------

class _NativePolicy:
    """Wraps a native sandlock_policy_t (Sandbox config) pointer."""

    def __init__(self, ptr: int):
        self._ptr = ptr

    @property
    def ptr(self):
        return self._ptr

    def __del__(self):
        if self._ptr:
            _lib.sandlock_sandbox_free(self._ptr)
            self._ptr = None

    # Fields handled by _build_from_policy (sent to FFI) or intentionally
    # managed outside it (policy_fn is wired in from_dataclass; notif_policy
    # is Python-side only; no_coredump is a Python convenience alias).
    _HANDLED_FIELDS: set[str] = {
        "fs_writable", "fs_readable", "fs_denied", "fs_storage",
        "workdir", "cwd", "chroot", "fs_mount", "on_exit", "on_error",
        "max_memory", "max_disk", "max_processes", "max_cpu", "num_cpus",
        "cpu_cores", "gpu_devices",
        "net_allow", "net_deny", "net_allow_bind", "net_deny_bind",
        "port_remap",
        "http_allow", "http_deny", "http_ports", "http_ca", "http_key",
        "http_inject_ca", "http_ca_out",
        "user",
        "random_seed", "time_start", "clean_env", "env",
        "extra_deny_syscalls", "extra_allow_syscalls", "max_open_files",
        "no_randomize_memory", "no_huge_pages", "no_coredump", "deterministic_dirs",
        # Landlock protection opt-out (see Protection IntEnum):
        "allow_degraded", "disable",
        # Managed outside _build_from_policy:
        "notif_policy",
        # Runtime-only kwargs — not sent to FFI:
        "name", "policy_fn", "init_fn", "work_fn",
    }

    @staticmethod
    def _build_from_policy(policy: PolicyDataclass):
        """Build a native builder from a Python Sandbox dataclass. Returns builder pointer."""
        b = _lib.sandlock_sandbox_builder_new()
        try:

            # Every requested grant is forwarded, including one whose path is
            # not there. This used to drop `/lib64` and only `/lib64`, which
            # answered a portability question for the caller, silently, for one
            # hardcoded path. It is the caller who knows whether a missing
            # /lib64 is a portability detail or a typo.
            #
            # What the caller gets instead is late and thin: `build()` does not
            # check existence, so the policy builds, and the rule is installed
            # in the child, where Landlock has to open the path. A missing one
            # comes back as `Result(success=False, error='sandlock_create
            # failed')` with the path nowhere in it, and under `chroot` it is
            # skipped without a word. Filter system paths on the way in if the
            # set varies by host, the way `sandlock.mcp` does for its default
            # policy.
            for p in (policy.fs_readable or []):
                b = _b_fs_read(b, _encode(str(p)))
            for p in (policy.fs_writable or []):
                b = _b_fs_write(b, _encode(str(p)))
            for p in (policy.fs_denied or []):
                b = _b_fs_deny(b, _encode(str(p)))

            if policy.fs_storage:
                b = _b_fs_storage(b, _encode(str(policy.fs_storage)))

            if policy.gpu_devices is not None:
                devices = [_fits(d, "gpu_devices entry", bits=32) for d in policy.gpu_devices]
                arr = (ctypes.c_uint32 * len(devices))(*devices)
                b = _b_gpu_devices(b, arr, len(devices))

            if policy.workdir:
                b = _b_workdir(b, _encode(str(policy.workdir)))
            if policy.cwd:
                b = _b_cwd(b, _encode(str(policy.cwd)))
            if policy.chroot:
                b = _b_chroot(b, _encode(str(policy.chroot)))
            for mount in (policy.fs_mount or []):
                setter = _b_fs_mount_ro if mount.ro else _b_fs_mount
                b = setter(b, _encode(str(mount.virt)), _encode(str(mount.host)))

            # COW branch actions. An unknown value is forwarded as the number the
            # ABI carries, so the core answers it by name ("unrecognized branch
            # action 7"). It used to be mapped to Commit or Abort by `.get(v, 0)`,
            # which turned a typo into a decision about the caller's writes.
            if policy.on_exit is not None:
                b = _b_on_exit(b, _branch_action(policy.on_exit, "on_exit"))
            if policy.on_error is not None:
                b = _b_on_error(b, _branch_action(policy.on_error, "on_error"))

            # Byte sizes go to the core as text, whichever way they were written.
            # `'512M'` is the grammar's own spelling and a bare number is the same
            # grammar's count of bytes, which is what a loaded profile resolves to,
            # so both spellings meet at the one parser instead of being judged here.
            if policy.max_memory is not None:
                b = _b_max_memory(b, _encode(policy.max_memory))

            if policy.max_disk is not None:
                b = _b_max_disk(b, _encode(policy.max_disk))

            if policy.max_processes is not None:
                b = _b_max_processes(b, _fits(policy.max_processes, "max_processes", bits=32))
            if policy.max_cpu is not None:
                b = _b_max_cpu(b, _fits(policy.max_cpu, "max_cpu", bits=8))
            if policy.num_cpus is not None:
                b = _b_num_cpus(b, _fits(policy.num_cpus, "num_cpus", bits=32))
            if policy.cpu_cores is not None:
                cores = [_fits(c, "cpu_cores", bits=32) for c in policy.cpu_cores]
                arr = (ctypes.c_uint32 * len(cores))(*cores)
                b = _b_cpu_cores(b, arr, len(cores))

            # net_allow: list of endpoint specs. Bare `host:port` means TCP
            # and UDP; `tcp://`/`udp://`/`icmp://` schemes pin one protocol.
            # Empty = deny all outbound. net_deny is the inverse (default-allow
            # denylist of IP/CIDR/port specs); the two are mutually exclusive.
            # Validation of each spec happens in the native build().
            for spec in (policy.net_allow or []):
                b = _b_net_allow(b, _encode(str(spec)))
            for spec in (policy.net_deny or []):
                b = _b_net_deny(b, _encode(str(spec)))
            for spec in (policy.net_allow_bind or []):
                b = _b_net_allow_bind(b, _encode(str(spec)))
            for spec in (policy.net_deny_bind or []):
                b = _b_net_deny_bind(b, _encode(str(spec)))

            for rule in (policy.http_allow or []):
                b = _b_http_allow(b, _encode(str(rule)))
            for rule in (policy.http_deny or []):
                b = _b_http_deny(b, _encode(str(rule)))
            for port in (policy.http_ports or []):
                b = _b_http_port(b, _fits(port, "http_ports entry", bits=16))
            if policy.http_ca:
                b = _b_http_ca(b, _encode(str(policy.http_ca)))
            if policy.http_key:
                b = _b_http_key(b, _encode(str(policy.http_key)))
            for path in (policy.http_inject_ca or []):
                b = _b_http_inject_ca(b, _encode(str(path)))
            if policy.http_ca_out:
                b = _b_http_ca_out(b, _encode(str(policy.http_ca_out)))

            if policy.port_remap:
                b = _b_port_remap(b, True)

            # One setter call, one value: `User` carries both ids, so there is no
            # half-set state left for this SDK to have an opinion about.
            if policy.user is not None:
                b = _b_user(
                    b,
                    _fits(policy.user.uid, "user.uid", bits=32),
                    _fits(policy.user.gid, "user.gid", bits=32),
                )

            if policy.random_seed is not None:
                b = _b_random_seed(b, _fits(policy.random_seed, "random_seed", bits=64))
            if policy.time_start is not None:
                b = _b_time_start_from(b, policy.time_start)
            if policy.clean_env:
                b = _b_clean_env(b, True)
            for k, v in (policy.env or {}).items():
                b = _b_env_var(b, _encode(k), _encode(v))

            if policy.extra_deny_syscalls:
                b = _b_extra_deny_syscalls(b, _encode(",".join(policy.extra_deny_syscalls or [])))
            if policy.extra_allow_syscalls:
                b = _b_extra_allow_syscalls(b, _encode(",".join(policy.extra_allow_syscalls or [])))
            if policy.max_open_files is not None:
                b = _b_max_open_files(b, _fits(policy.max_open_files, "max_open_files", bits=32))

            if policy.no_randomize_memory:
                b = _b_no_randomize_memory(b, True)
            if policy.no_huge_pages:
                b = _b_no_huge_pages(b, True)
            if policy.no_coredump:
                b = _b_no_coredump(b, True)
            if policy.deterministic_dirs:
                b = _b_deterministic_dirs(b, True)

            # Landlock protection opt-out. The C ABI setters use move-semantics
            # and return the (possibly relocated) builder pointer, so mirror that
            # by rebinding `b` on each call. Idempotent / last-wins: if the
            # same Protection appears in both lists, the later call wins
            # (matching the underlying `ProtectionPolicy::set` semantics).
            # A discriminant this SDK does not know is the core's to refuse,
            # by value, exactly as an unknown branch action is. Only the width
            # is checked here: ctypes converts to uint32 by masking, so a value
            # that does not fit would arrive as a different, plausible one and
            # the core would never see what the caller wrote.
            for p in (policy.allow_degraded or ()):
                b = _b_allow_degraded(b, _fits(p, "allow_degraded", bits=32))
            for p in (policy.disable or ()):
                b = _b_disable(b, _fits(p, "disable", bits=32))

            # Guard: warn if any dataclass field was set to a non-default value
            # but is not in _HANDLED_FIELDS (i.e. silently dropped).
            import dataclasses as _dc
            import warnings as _w
            from .sandbox import Sandbox as _Sandbox
            _defaults = _Sandbox()
            for f in _dc.fields(policy):
                if f.name in _NativePolicy._HANDLED_FIELDS:
                    continue
                val = getattr(policy, f.name)
                default_val = getattr(_defaults, f.name)
                if val != default_val:
                    _w.warn(
                        f"Policy field {f.name!r} is set but not wired through "
                        f"FFI, so it will have no effect (value: {val!r})",
                        stacklevel=3,
                    )

            return b
        except BaseException:
            # Every setter consumes the pointer it is given and returns a new
            # one, so the only builder that still exists is the one `b` holds
            # right now. There is no `sandlock_sandbox_builder_free` in the C
            # ABI, and `sandlock_sandbox_build` is the only entry point that
            # consumes a builder, so the release runs through it. Without
            # this, a caller that validates policies it did not write leaks a
            # fully loaded builder for every one it rejects.
            _free_builder(b)
            raise

    @classmethod
    def from_dataclass(cls, policy: PolicyDataclass, policy_fn=None) -> _NativePolicy:
        """Build a native policy from a Python Policy dataclass."""
        b = _NativePolicy._build_from_policy(policy)

        # Store callback reference to prevent GC
        c_callback = None
        if policy_fn is not None:
            def _c_callback(event_p, ctx_p, _user_data):
                ev = event_p.contents
                py_argv = None
                if ev.argv and ev.argc > 0:
                    py_argv = tuple(
                        ev.argv[i].decode("utf-8", errors="replace")
                        for i in range(ev.argc)
                        if ev.argv[i]
                    )
                # A category this SDK does not know is reported as the number
                # the core sent. Naming it "file" instead would hand the
                # callback a category the syscall does not belong to, and a
                # policy that keys on "file" would then act on it.
                _CATEGORIES = {0: "file", 1: "network", 2: "process", 3: "memory"}
                py_event = SyscallEvent(
                    syscall=ev.syscall.decode("utf-8") if ev.syscall else "",
                    category=_CATEGORIES.get(ev.category, ev.category),
                    pid=ev.pid,
                    parent_pid=ev.parent_pid,
                    host=ev.host.decode("utf-8") if ev.host else None,
                    port=ev.port,
                    argv=py_argv,
                    denied=ev.denied,
                )
                py_ctx = PolicyContext(ctx_p)
                result = policy_fn(py_event, py_ctx)
                # Return: 0=allow, -1=deny, -2=audit, positive=deny with errno
                # Python callback can return:
                #   None/False/0  → allow
                #   True/-1       → deny (EPERM)
                #   positive int  → deny with that errno
                #   "audit"/-2    → audit (allow + flag)
                if result is None or result is False or result == 0:
                    return 0
                if result is True or result == -1:
                    return -1
                if result == "audit" or result == -2:
                    return -2
                if isinstance(result, int) and result > 0:
                    return result
                # Unrecognized return values fail closed (deny) rather than
                # silently allowing the syscall.
                return -1

            c_callback = _POLICY_FN_TYPE(_c_callback)
            b = _lib.sandlock_sandbox_builder_policy_fn(b, c_callback, None, None)

        err = ctypes.c_int(0)
        err_msg = ctypes.c_char_p()
        ptr = _lib.sandlock_sandbox_build(b, ctypes.byref(err), ctypes.byref(err_msg))
        if not ptr or err.value != 0:
            # err_msg.value is a copy of the C string's bytes; the
            # underlying allocation still needs releasing afterwards.
            # When the FFI leaves err_msg null (e.g. internal binding
            # bug), raise without a message rather than inventing one.
            msg = err_msg.value.decode("utf-8", "replace") if err_msg.value else None
            if err_msg.value:
                _lib.sandlock_string_free(err_msg)
            raise RuntimeError(msg) if msg else RuntimeError()
        native = _NativePolicy(ptr)
        native._c_callback = c_callback  # prevent GC
        return native


# ----------------------------------------------------------------
# ForkResult (holds clone handles with pipes for reduce)
# ----------------------------------------------------------------

class ForkResult:
    """Result of fork() — holds clone handles and stdout pipes.

    Pass to reducer.reduce() to pipe clone output to the reducer.
    Can also iterate clones via indexing or len().
    """

    def __init__(self, ptr, pids: list[int], native_policy):
        self._ptr = ptr  # sandlock_fork_result_t (owns pipes)
        self.pids = pids
        self._native_policy = native_policy

    def __len__(self):
        return len(self.pids)

    def __getitem__(self, i):
        return self.pids[i]

    def __del__(self):
        if self._ptr is not None:
            _lib.sandlock_fork_result_free(self._ptr)
            self._ptr = None


# ----------------------------------------------------------------
# Stage & Pipeline
# ----------------------------------------------------------------

class Stage:
    """A lazy command bound to a Sandbox. Not executed until .run()."""

    def __init__(self, sandbox: PolicyDataclass, args: list[str]):
        self.sandbox = sandbox
        self.args = args

    def as_(self, name: str) -> NamedStage:
        """Label this stage's output for use in a gather pattern."""
        return NamedStage(self, name)

    def run(self, timeout: float | None = None) -> Result:
        """Run this single stage."""
        return self.sandbox.run(self.args)

    def __or__(self, other: Stage | Pipeline) -> Pipeline:
        if isinstance(other, Pipeline):
            return Pipeline([self] + other.stages)
        return Pipeline([self, other])


class NamedStage:
    """A Stage with a named output for gather patterns."""

    def __init__(self, stage: Stage, name: str):
        self.stage = stage
        self.name = name

    def __add__(self, other: NamedStage | Gather) -> Gather:
        if isinstance(other, Gather):
            return Gather([(self.name, self.stage)] + other.sources)
        return Gather([(self.name, self.stage), (other.name, other.stage)])


class Gather:
    """A set of named stages to be gathered into a consumer.

    Usage::

        result = (
            Sandbox(...).cmd(["produce_code"]).as_("code")
            + Sandbox(...).cmd(["produce_data"]).as_("data")
            | Sandbox(...).cmd(["python3", "consume.py"])
        ).run()

    The consumer script imports ``from sandlock import inputs`` to read
    producer outputs by name.
    """

    def __init__(self, sources: list[tuple[str, Stage]]):
        self.sources = sources

    def __add__(self, other: NamedStage | Gather) -> Gather:
        if isinstance(other, Gather):
            return Gather(self.sources + other.sources)
        return Gather(self.sources + [(other.name, other.stage)])

    def __or__(self, other: Stage) -> GatherPipeline:
        return GatherPipeline(self.sources, other)


class GatherPipeline:
    """Fan-in pipeline: multiple producers → one consumer via pipes.

    Producer outputs are available in the consumer via
    ``from sandlock import inputs``.
    """

    def __init__(self, sources: list[tuple[str, Stage]], consumer: Stage):
        self.sources = sources
        self.consumer = consumer

    def run(self, timeout: float | None = None) -> Result:
        """Run all producers in parallel, pipe outputs to consumer.

        Each producer's stdout is connected to the consumer via a Unix pipe.
        The last source maps to stdin (fd 0), others to fd 3, 4, 5, ...
        The consumer reads them via ``from sandlock import inputs``.
        """
        # Build the gather via FFI
        gather_p = _lib.sandlock_gather_new()

        for name, stage in self.sources:
            name_b = name.encode("utf-8") + b"\x00"
            argv, argc = _make_argv(stage.args)
            _lib.sandlock_gather_add_source(
                gather_p,
                ctypes.c_char_p(name_b),
                stage.sandbox._ensure_native().ptr,
                argv, argc,
            )

        consumer_argv, consumer_argc = _make_argv(self.consumer.args)
        _lib.sandlock_gather_set_consumer(
            gather_p,
            self.consumer.sandbox._ensure_native().ptr,
            consumer_argv, consumer_argc,
        )

        timeout_ms = int(timeout * 1000) if timeout else 0
        result_p = _lib.sandlock_gather_run(gather_p, timeout_ms)

        if not result_p:
            error = "Gather timed out" if timeout else "Gather failed"
            return Result(success=False, exit_code=-1, error=error)

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        reason = ExitReason(_lib.sandlock_result_reason(result_p))
        signal = _lib.sandlock_result_signal(result_p)
        out_bytes = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        error = None
        if reason == ExitReason.TIMEOUT:
            error = "Gather timed out"

        return Result(
            success=bool(success),
            exit_code=exit_code,
            reason=reason,
            signal=signal,
            stdout=out_bytes,
            stderr=stderr,
            error=error,
        )


class Pipeline:
    """A chain of stages connected by pipes.

    Usage::

        result = (
            Sandbox(...).cmd(["echo", "hello"])
            | Sandbox(...).cmd(["tr", "a-z", "A-Z"])
        ).run()
        assert b"HELLO" in result.stdout
    """

    def __init__(self, stages: list[Stage]):
        if len(stages) < 2:
            raise ValueError("Pipeline requires at least 2 stages")
        self.stages = stages

    def __or__(self, other: Stage | Pipeline) -> Pipeline:
        if isinstance(other, Pipeline):
            return Pipeline(self.stages + other.stages)
        return Pipeline(self.stages + [other])

    def run(
        self,
        stdout: int | None = None,
        timeout: float | None = None,
    ) -> Result:
        """Run the pipeline. Returns the last stage's result.

        If ``stdout`` is a file descriptor, the last stage's stdout is
        redirected there and ``result.stdout`` will be empty.
        """
        pipe_p = _lib.sandlock_pipeline_new()

        for stage in self.stages:
            argv, argc = _make_argv(stage.args)
            _lib.sandlock_pipeline_add_stage(
                pipe_p, stage.sandbox._ensure_native().ptr, argv, argc,
            )

        timeout_ms = int(timeout * 1000) if timeout else 0
        # pipeline_run consumes pipe_p
        result_p = _lib.sandlock_pipeline_run(pipe_p, timeout_ms)

        if not result_p:
            error = "Pipeline timed out" if timeout else "Pipeline failed"
            return Result(success=False, exit_code=-1, error=error)

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        reason = ExitReason(_lib.sandlock_result_reason(result_p))
        signal = _lib.sandlock_result_signal(result_p)
        out_bytes = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        # Handle stdout fd redirection
        if stdout is not None and out_bytes:
            os.write(stdout, out_bytes)
            out_bytes = b""

        error = None
        if reason == ExitReason.TIMEOUT:
            error = "Pipeline timed out"

        return Result(
            success=bool(success),
            exit_code=exit_code,
            reason=reason,
            signal=signal,
            stdout=out_bytes,
            stderr=stderr,
            error=error,
        )
