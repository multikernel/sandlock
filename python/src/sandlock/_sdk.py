"""Python SDK for sandlock — ctypes bindings to libsandlock_ffi.so."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import signal
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    from .policy import Policy as PolicyDataclass

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

# Policy builder
_lib.sandlock_policy_builder_new.restype = _c_builder_p
_lib.sandlock_policy_builder_new.argtypes = []

def _builder_fn(name, *extra_args):
    fn = getattr(_lib, name)
    fn.restype = _c_builder_p
    fn.argtypes = [_c_builder_p] + list(extra_args)
    return fn

_b_fs_read = _builder_fn("sandlock_policy_builder_fs_read", ctypes.c_char_p)
_b_fs_write = _builder_fn("sandlock_policy_builder_fs_write", ctypes.c_char_p)
_b_fs_deny = _builder_fn("sandlock_policy_builder_fs_deny", ctypes.c_char_p)
_b_fs_storage = _builder_fn("sandlock_policy_builder_fs_storage", ctypes.c_char_p)
_b_fs_isolation = _builder_fn("sandlock_policy_builder_fs_isolation", ctypes.c_uint8)
_b_gpu_devices = _builder_fn("sandlock_policy_builder_gpu_devices", ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32)
_b_workdir = _builder_fn("sandlock_policy_builder_workdir", ctypes.c_char_p)
_b_cwd = _builder_fn("sandlock_policy_builder_cwd", ctypes.c_char_p)
_b_chroot = _builder_fn("sandlock_policy_builder_chroot", ctypes.c_char_p)
_b_fs_mount = _builder_fn("sandlock_policy_builder_fs_mount", ctypes.c_char_p, ctypes.c_char_p)
_b_on_exit = _builder_fn("sandlock_policy_builder_on_exit", ctypes.c_uint8)
_b_on_error = _builder_fn("sandlock_policy_builder_on_error", ctypes.c_uint8)
_b_max_memory = _builder_fn("sandlock_policy_builder_max_memory", ctypes.c_uint64)
_b_max_disk = _builder_fn("sandlock_policy_builder_max_disk", ctypes.c_uint64)
_b_max_processes = _builder_fn("sandlock_policy_builder_max_processes", ctypes.c_uint32)
_b_max_cpu = _builder_fn("sandlock_policy_builder_max_cpu", ctypes.c_uint8)
_b_num_cpus = _builder_fn("sandlock_policy_builder_num_cpus", ctypes.c_uint32)
_b_net_allow = _builder_fn("sandlock_policy_builder_net_allow", ctypes.c_char_p)
_b_net_bind_port = _builder_fn("sandlock_policy_builder_net_bind_port", ctypes.c_uint16)
_b_port_remap = _builder_fn("sandlock_policy_builder_port_remap", ctypes.c_bool)
_b_allow_udp = _builder_fn("sandlock_policy_builder_allow_udp", ctypes.c_bool)
_b_allow_icmp = _builder_fn("sandlock_policy_builder_allow_icmp", ctypes.c_bool)
_b_http_allow = _builder_fn("sandlock_policy_builder_http_allow", ctypes.c_char_p)
_b_http_deny = _builder_fn("sandlock_policy_builder_http_deny", ctypes.c_char_p)
_b_http_port = _builder_fn("sandlock_policy_builder_http_port", ctypes.c_uint16)
_b_https_ca = _builder_fn("sandlock_policy_builder_https_ca", ctypes.c_char_p)
_b_https_key = _builder_fn("sandlock_policy_builder_https_key", ctypes.c_char_p)
_b_uid = _builder_fn("sandlock_policy_builder_uid", ctypes.c_uint32)
_b_random_seed = _builder_fn("sandlock_policy_builder_random_seed", ctypes.c_uint64)
_b_clean_env = _builder_fn("sandlock_policy_builder_clean_env", ctypes.c_bool)
_b_env_var = _builder_fn("sandlock_policy_builder_env_var", ctypes.c_char_p, ctypes.c_char_p)
_b_time_start = _builder_fn("sandlock_policy_builder_time_start", ctypes.c_uint64)
_b_deny_syscalls = _builder_fn("sandlock_policy_builder_deny_syscalls", ctypes.c_char_p)
_b_allow_syscalls = _builder_fn("sandlock_policy_builder_allow_syscalls", ctypes.c_char_p)
_b_max_open_files = _builder_fn("sandlock_policy_builder_max_open_files", ctypes.c_uint32)
_b_no_randomize_memory = _builder_fn("sandlock_policy_builder_no_randomize_memory", ctypes.c_bool)
_b_no_huge_pages = _builder_fn("sandlock_policy_builder_no_huge_pages", ctypes.c_bool)
_b_no_coredump = _builder_fn("sandlock_policy_builder_no_coredump", ctypes.c_bool)
_b_deterministic_dirs = _builder_fn("sandlock_policy_builder_deterministic_dirs", ctypes.c_bool)
_b_hostname = _builder_fn("sandlock_policy_builder_hostname", ctypes.c_char_p)
_b_cpu_cores = _builder_fn("sandlock_policy_builder_cpu_cores", ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32)

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
_POLICY_FN_TYPE = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.POINTER(_CEvent), _c_ctx_p)

_lib.sandlock_policy_builder_policy_fn.restype = _c_builder_p
_lib.sandlock_policy_builder_policy_fn.argtypes = [_c_builder_p, _POLICY_FN_TYPE]

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
    filesystem, IPC, and signal isolation fields. The confinement is
    **irreversible**.

    Only filesystem paths are used (IPC and signal isolation are always enabled).
    Network, resource limits, and other policy fields are ignored.

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
        raise ConfinementError("confine_current_process failed")


_lib.sandlock_policy_build.restype = _c_policy_p
_lib.sandlock_policy_build.argtypes = [_c_builder_p, ctypes.POINTER(ctypes.c_int)]

_lib.sandlock_policy_free.restype = None
_lib.sandlock_policy_free.argtypes = [_c_policy_p]

# Run
_lib.sandlock_run.restype = _c_result_p
_lib.sandlock_run.argtypes = [_c_policy_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_run_interactive.restype = ctypes.c_int
_lib.sandlock_run_interactive.argtypes = [_c_policy_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

# Spawn handle
_c_handle_p = ctypes.c_void_p

_lib.sandlock_spawn.restype = _c_handle_p
_lib.sandlock_spawn.argtypes = [_c_policy_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

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

# Result
_lib.sandlock_result_exit_code.restype = ctypes.c_int
_lib.sandlock_result_exit_code.argtypes = [_c_result_p]

_lib.sandlock_result_success.restype = ctypes.c_bool
_lib.sandlock_result_success.argtypes = [_c_result_p]

_lib.sandlock_result_stdout_bytes.restype = ctypes.c_void_p
_lib.sandlock_result_stdout_bytes.argtypes = [_c_result_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_result_stderr_bytes.restype = ctypes.c_void_p
_lib.sandlock_result_stderr_bytes.argtypes = [_c_result_p, ctypes.POINTER(ctypes.c_size_t)]

_lib.sandlock_result_free.restype = None
_lib.sandlock_result_free.argtypes = [_c_result_p]

# Dry-run
_c_dry_run_p = ctypes.c_void_p

_lib.sandlock_dry_run.restype = _c_dry_run_p
_lib.sandlock_dry_run.argtypes = [_c_policy_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

_lib.sandlock_dry_run_result_exit_code.restype = ctypes.c_int
_lib.sandlock_dry_run_result_exit_code.argtypes = [_c_dry_run_p]

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
_lib.sandlock_new_with_fns.argtypes = [_c_policy_p, _INIT_FN_TYPE, _WORK_FN_TYPE]

_c_fork_result_p = ctypes.c_void_p

_lib.sandlock_fork.restype = _c_fork_result_p
_lib.sandlock_fork.argtypes = [_c_sandbox_p, ctypes.c_uint32]

_lib.sandlock_fork_result_count.restype = ctypes.c_uint32
_lib.sandlock_fork_result_count.argtypes = [_c_fork_result_p]

_lib.sandlock_fork_result_pid.restype = ctypes.c_int32
_lib.sandlock_fork_result_pid.argtypes = [_c_fork_result_p, ctypes.c_uint32]

_lib.sandlock_reduce.restype = _c_result_p
_lib.sandlock_reduce.argtypes = [_c_fork_result_p, _c_policy_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]

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
    category: str  # "file", "network", "process", "memory"
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

@dataclass
class Result:
    """Result of a sandboxed command."""
    success: bool
    exit_code: int = 0
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)
    error: str | None = None


# ----------------------------------------------------------------
# Checkpoint
# ----------------------------------------------------------------

_DEFAULT_STORE = Path.home() / ".sandlock" / "checkpoints"


class Checkpoint:
    """A frozen snapshot of sandbox state (registers, memory, fds).

    Wraps a native checkpoint captured via ptrace + /proc.

    Usage::

        sb = Sandbox(policy)
        sb.run_bg(["sleep", "60"])  # or use spawn via handle
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
    def load(cls, name: str, *, store: Path | str | None = None) -> "Checkpoint":
        """Load a named checkpoint from disk.

        Args:
            name: Checkpoint name.
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Returns:
            Checkpoint with all state restored.

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
        return cls(ptr)

    @classmethod
    def restore(
        cls,
        name: str,
        restore_fn: "Callable[[bytes], None]",
        *,
        store: "Path | str | None" = None,
    ) -> "Checkpoint":
        """Load a checkpoint and pass its app state to restore_fn.

        Convenience for ``load()`` + calling ``restore_fn(cp.app_state)``.

        Args:
            name: Checkpoint name.
            restore_fn: Callback that receives the saved application-level
                state bytes. Use this to rebuild state that ptrace can't
                capture (caches, session data, etc.).
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Returns:
            The loaded Checkpoint.

        Raises:
            FileNotFoundError: If the checkpoint does not exist.
            ValueError: If the checkpoint has no app_state.
        """
        cp = cls.load(name, store=store)
        state = cp.app_state
        if state is None:
            raise ValueError(
                f"Checkpoint {name!r} has no app_state — "
                "was it created with save_fn?"
            )
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
    """Wraps a native sandlock_policy_t pointer."""

    def __init__(self, ptr: int):
        self._ptr = ptr

    @property
    def ptr(self):
        return self._ptr

    def __del__(self):
        if self._ptr:
            _lib.sandlock_policy_free(self._ptr)
            self._ptr = None

    # Fields handled by _build_from_policy (sent to FFI) or intentionally
    # managed outside it (policy_fn is wired in from_dataclass; notif_policy
    # is Python-side only; no_coredump is a Python convenience alias).
    _HANDLED_FIELDS: set[str] = {
        "fs_writable", "fs_readable", "fs_denied", "fs_storage", "fs_isolation",
        "workdir", "cwd", "chroot", "fs_mount", "on_exit", "on_error",
        "max_memory", "max_disk", "max_processes", "max_cpu", "num_cpus",
        "cpu_cores", "gpu_devices",
        "net_allow", "net_bind",
        "port_remap", "allow_udp", "allow_icmp",
        "http_allow", "http_deny", "http_ports", "https_ca", "https_key",
        "uid",
        "random_seed", "time_start", "clean_env", "env",
        "deny_syscalls", "allow_syscalls", "max_open_files",
        "no_randomize_memory", "no_huge_pages", "no_coredump", "deterministic_dirs",
        # Managed outside _build_from_policy:
        "notif_policy",
    }

    @staticmethod
    def _build_from_policy(policy: PolicyDataclass, override_hostname=None):
        """Build a native builder from a Python Policy dataclass. Returns builder pointer."""
        from .policy import parse_memory_size, parse_ports

        b = _lib.sandlock_policy_builder_new()

        for p in (policy.fs_readable or []):
            if str(p) == "/lib64" and not os.path.exists("/lib64"):
                continue
            b = _b_fs_read(b, _encode(str(p)))
        for p in (policy.fs_writable or []):
            b = _b_fs_write(b, _encode(str(p)))
        for p in (policy.fs_denied or []):
            b = _b_fs_deny(b, _encode(str(p)))

        if policy.fs_storage:
            b = _b_fs_storage(b, _encode(str(policy.fs_storage)))

        from .policy import FsIsolation
        _iso_map = {
            FsIsolation.NONE: 0,
            FsIsolation.OVERLAYFS: 1,
            FsIsolation.BRANCHFS: 2,
        }
        if policy.fs_isolation != FsIsolation.NONE:
            b = _b_fs_isolation(b, _iso_map[policy.fs_isolation])

        if policy.gpu_devices is not None:
            arr = (ctypes.c_uint32 * len(policy.gpu_devices))(*policy.gpu_devices)
            b = _b_gpu_devices(b, arr, len(policy.gpu_devices))

        if policy.workdir:
            b = _b_workdir(b, _encode(str(policy.workdir)))
        if policy.cwd:
            b = _b_cwd(b, _encode(str(policy.cwd)))
        if policy.chroot:
            b = _b_chroot(b, _encode(str(policy.chroot)))
        for vp, hp in (policy.fs_mount or {}).items():
            b = _b_fs_mount(b, _encode(str(vp)), _encode(str(hp)))

        # COW branch actions (0=Commit, 1=Abort, 2=Keep)
        _action_map = {"commit": 0, "abort": 1, "keep": 2}
        on_exit_val = policy.on_exit.value if hasattr(policy.on_exit, 'value') else str(policy.on_exit)
        on_error_val = policy.on_error.value if hasattr(policy.on_error, 'value') else str(policy.on_error)
        b = _b_on_exit(b, _action_map.get(on_exit_val, 0))
        b = _b_on_error(b, _action_map.get(on_error_val, 1))

        if policy.max_memory is not None:
            if isinstance(policy.max_memory, str):
                mem_bytes = parse_memory_size(policy.max_memory)
            else:
                mem_bytes = int(policy.max_memory)
            b = _b_max_memory(b, mem_bytes)

        if policy.max_disk is not None:
            if isinstance(policy.max_disk, str):
                disk_bytes = parse_memory_size(policy.max_disk)
            else:
                disk_bytes = int(policy.max_disk)
            b = _b_max_disk(b, disk_bytes)

        if policy.max_processes != 64:
            b = _b_max_processes(b, policy.max_processes)
        if policy.max_cpu is not None:
            b = _b_max_cpu(b, policy.max_cpu)
        if policy.num_cpus is not None:
            b = _b_num_cpus(b, policy.num_cpus)
        if policy.cpu_cores is not None:
            arr = (ctypes.c_uint32 * len(policy.cpu_cores))(*policy.cpu_cores)
            b = _b_cpu_cores(b, arr, len(policy.cpu_cores))

        # net_allow: list of endpoint specs (`host:port[,port,...]`,
        # `:port`, `*:port`). Empty = deny all outbound. Applies to TCP
        # and to UDP (when allow_udp is set). Validation of each spec
        # happens in the native build().
        for spec in (policy.net_allow or []):
            b = _b_net_allow(b, _encode(str(spec)))
        for port in parse_ports(policy.net_bind) if policy.net_bind else []:
            b = _b_net_bind_port(b, port)

        for rule in (policy.http_allow or []):
            b = _b_http_allow(b, _encode(str(rule)))
        for rule in (policy.http_deny or []):
            b = _b_http_deny(b, _encode(str(rule)))
        for port in (policy.http_ports or []):
            b = _b_http_port(b, int(port))
        if policy.https_ca:
            b = _b_https_ca(b, _encode(str(policy.https_ca)))
        if policy.https_key:
            b = _b_https_key(b, _encode(str(policy.https_key)))

        if policy.port_remap:
            b = _b_port_remap(b, True)
        if policy.allow_udp:
            b = _b_allow_udp(b, True)
        if policy.allow_icmp:
            b = _b_allow_icmp(b, True)

        if policy.uid is not None:
            b = _b_uid(b, policy.uid)

        if policy.random_seed is not None:
            b = _b_random_seed(b, policy.random_seed)
        if policy.time_start is not None:
            epoch_secs = int(policy.time_start.timestamp()) if hasattr(policy.time_start, 'timestamp') else int(policy.time_start)
            b = _b_time_start(b, epoch_secs)
        if policy.clean_env:
            b = _b_clean_env(b, True)
        for k, v in (policy.env or {}).items():
            b = _b_env_var(b, _encode(k), _encode(v))

        if policy.deny_syscalls:
            b = _b_deny_syscalls(b, _encode(",".join(policy.deny_syscalls)))
        if policy.allow_syscalls:
            b = _b_allow_syscalls(b, _encode(",".join(policy.allow_syscalls)))
        if policy.max_open_files is not None:
            b = _b_max_open_files(b, policy.max_open_files)

        if policy.no_randomize_memory:
            b = _b_no_randomize_memory(b, True)
        if policy.no_huge_pages:
            b = _b_no_huge_pages(b, True)
        if policy.no_coredump:
            b = _b_no_coredump(b, True)
        if policy.deterministic_dirs:
            b = _b_deterministic_dirs(b, True)
        if override_hostname is not None:
            b = _b_hostname(b, override_hostname.encode())

        # Guard: warn if any dataclass field was set to a non-default value
        # but is not in _HANDLED_FIELDS (i.e. silently dropped).
        import dataclasses as _dc
        import warnings as _w
        from .policy import Policy as _Policy
        _defaults = _Policy()
        for f in _dc.fields(policy):
            if f.name in _NativePolicy._HANDLED_FIELDS:
                continue
            val = getattr(policy, f.name)
            default_val = getattr(_defaults, f.name)
            if val != default_val:
                _w.warn(
                    f"Policy field {f.name!r} is set but not wired through "
                    f"FFI — it will have no effect (value: {val!r})",
                    stacklevel=3,
                )

        return b

    @classmethod
    def from_dataclass(cls, policy: PolicyDataclass, policy_fn=None, override_hostname=None) -> _NativePolicy:
        """Build a native policy from a Python Policy dataclass."""
        b = _NativePolicy._build_from_policy(policy, override_hostname=override_hostname)

        # Store callback reference to prevent GC
        c_callback = None
        if policy_fn is not None:
            def _c_callback(event_p, ctx_p):
                ev = event_p.contents
                py_argv = None
                if ev.argv and ev.argc > 0:
                    py_argv = tuple(
                        ev.argv[i].decode("utf-8", errors="replace")
                        for i in range(ev.argc)
                        if ev.argv[i]
                    )
                _CATEGORIES = {0: "file", 1: "network", 2: "process", 3: "memory"}
                py_event = SyscallEvent(
                    syscall=ev.syscall.decode("utf-8") if ev.syscall else "",
                    category=_CATEGORIES.get(ev.category, "file"),
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
                return 0

            c_callback = _POLICY_FN_TYPE(_c_callback)
            b = _lib.sandlock_policy_builder_policy_fn(b, c_callback)

        err = ctypes.c_int(0)
        ptr = _lib.sandlock_policy_build(b, ctypes.byref(err))
        if not ptr or err.value != 0:
            raise RuntimeError("Failed to build policy")
        native = _NativePolicy(ptr)
        native._c_callback = c_callback  # prevent GC
        return native


# ----------------------------------------------------------------
# Sandbox
# ----------------------------------------------------------------

class Sandbox:
    """Run commands in a sandlock sandbox.

    Usage::

        from sandlock import Sandbox, Policy
        sb = Sandbox(Policy(fs_readable=["/usr", "/lib"], fs_writable=["/tmp"]))
        result = sb.run(["echo", "hello"])
        assert result.success
        assert b"hello" in result.stdout
    """

    def __init__(self, policy: PolicyDataclass, policy_fn=None,
                 init_fn=None, work_fn=None, name: str | None = None):
        self._policy_dc = policy
        self._policy_fn = policy_fn
        self._init_fn = init_fn
        self._work_fn = work_fn
        self._name = name
        self._native = _NativePolicy.from_dataclass(policy, policy_fn=policy_fn)
        self._handle = None  # live sandbox handle during run()

    def _resolve_name(self):
        """Resolve sandbox name: explicit > auto-generated."""
        if self._name is not None:
            return self._name
        return f"sandbox-{os.getpid()}"

    @property
    def name(self) -> str | None:
        """Sandbox name."""
        return self._name

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._handle is not None:
            _lib.sandlock_handle_free(self._handle)
            self._handle = None
        return False

    @property
    def pid(self) -> int | None:
        """Child PID while running, None otherwise."""
        if self._handle is None:
            return None
        return _lib.sandlock_handle_pid(self._handle) or None

    def ports(self) -> dict[int, int]:
        """Return current port mappings {virtual_port: real_port}.

        Only contains entries where the real port differs from the virtual
        port (i.e., where a remap occurred). Empty if port_remap is disabled
        or no ports have been remapped. Requires the sandbox to be running.
        """
        if self._handle is None:
            return {}
        c_str = _lib.sandlock_handle_port_mappings(self._handle)
        if not c_str:
            return {}
        try:
            import json
            raw = json.loads(c_str.decode())
            return {int(k): v for k, v in raw.items()}
        finally:
            _lib.sandlock_string_free(c_str)

    def pause(self) -> None:
        """Send SIGSTOP to the sandbox process group."""
        pid = self.pid
        if pid is None:
            raise RuntimeError("sandbox is not running")
        os.killpg(pid, signal.SIGSTOP)

    def resume(self) -> None:
        """Send SIGCONT to the sandbox process group."""
        pid = self.pid
        if pid is None:
            raise RuntimeError("sandbox is not running")
        os.killpg(pid, signal.SIGCONT)

    def checkpoint(
        self,
        save_fn: "Callable[[], bytes] | None" = None,
    ) -> Checkpoint:
        """Capture a checkpoint of the running sandbox.

        The sandbox is frozen (SIGSTOP + fork-hold), state is captured
        via ptrace + /proc, then thawed.

        Args:
            save_fn: Optional callback that returns application-level
                state bytes. Called after OS-level capture; the result
                is stored in ``checkpoint.app_state``. Use this for
                state that ptrace can't see (caches, session data, etc.).

        Returns:
            Checkpoint with process state, memory, fds, and optional app state.

        Raises:
            RuntimeError: If the sandbox is not running or capture fails.
        """
        if self._handle is None:
            raise RuntimeError("sandbox is not running (use spawn first)")
        ptr = _lib.sandlock_handle_checkpoint(self._handle)
        if not ptr:
            raise RuntimeError("checkpoint capture failed")
        cp = Checkpoint(ptr)
        if save_fn is not None:
            cp.app_state = save_fn()
        return cp

    def run(self, cmd: list[str], timeout: float | None = None) -> Result:
        """Run a command in the sandbox, capturing stdout and stderr.

        Args:
            cmd: Command and arguments to execute.
            timeout: Maximum execution time in seconds. The process is
                killed and a timeout result is returned if exceeded.
                None means no timeout.
        """
        argv, argc = _make_argv(cmd)

        # Resolve sandbox name and rebuild native policy with it
        resolved_name = self._resolve_name()
        self._native = _NativePolicy.from_dataclass(
            self._policy_dc, policy_fn=self._policy_fn,
            override_hostname=resolved_name,
        )

        # Spawn (non-blocking) so PID is available for pause/resume
        self._handle = _lib.sandlock_spawn(self._native.ptr, argv, argc)
        if not self._handle:
            return Result(success=False, exit_code=-1, error="sandlock_spawn failed")

        try:
            timeout_ms = int(timeout * 1000) if timeout else 0
            result_p = _lib.sandlock_handle_wait_timeout(self._handle, timeout_ms)
        finally:
            _lib.sandlock_handle_free(self._handle)
            self._handle = None

        if not result_p:
            return Result(success=False, exit_code=-1, error="sandlock_handle_wait failed")

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        stdout = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        return Result(
            success=bool(success),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )

    def dry_run(self, cmd: list[str], timeout: float | None = None) -> "DryRunResult":
        """Dry-run: run a command, collect filesystem changes, then discard.

        Args:
            cmd: Command and arguments to execute.
            timeout: Maximum execution time in seconds. None means no timeout.

        Returns:
            DryRunResult with exit info and list of filesystem changes.
        """
        from .policy import Change, DryRunResult

        argv, argc = _make_argv(cmd)
        result_p = _lib.sandlock_dry_run(self._native.ptr, argv, argc)

        if not result_p:
            return DryRunResult(success=False, exit_code=-1, error="sandlock_dry_run failed")

        try:
            exit_code = _lib.sandlock_dry_run_result_exit_code(result_p)
            success = _lib.sandlock_dry_run_result_success(result_p)
            stdout = _read_result_bytes(result_p, _lib.sandlock_dry_run_result_stdout_bytes)
            stderr = _read_result_bytes(result_p, _lib.sandlock_dry_run_result_stderr_bytes)

            n = _lib.sandlock_dry_run_result_changes_len(result_p)
            changes = []
            for i in range(n):
                kind_byte = _lib.sandlock_dry_run_result_change_kind(result_p, i)
                kind = kind_byte.decode("ascii")
                path_p = _lib.sandlock_dry_run_result_change_path(result_p, i)
                if path_p:
                    path = ctypes.c_char_p(path_p).value.decode("utf-8")
                    _lib.sandlock_string_free(ctypes.cast(path_p, ctypes.c_char_p))
                else:
                    path = ""
                changes.append(Change(kind=kind, path=path))
        finally:
            _lib.sandlock_dry_run_result_free(result_p)

        return DryRunResult(
            success=bool(success),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            changes=changes,
        )

    def run_interactive(self, cmd: list[str]) -> int:
        """Run with inherited stdio. Returns exit code."""
        argv, argc = _make_argv(cmd)
        return _lib.sandlock_run_interactive(self._native.ptr, argv, argc)

    def cmd(self, args: list[str]) -> Stage:
        """Bind a command to this sandbox, returning a lazy Stage."""
        return Stage(self, args)

    def fork(self, n: int) -> list[int]:
        """Create N COW clones. init_fn runs once, work_fn in each clone.

        Requires init_fn and work_fn passed to Sandbox().

        Returns list of clone PIDs.

        Example::

            sb = Sandbox(policy,
                init_fn=lambda: load_model(),
                work_fn=lambda clone_id: rollout(clone_id),
            )
            pids = sb.fork(1000)
        """
        if self._init_fn is None or self._work_fn is None:
            raise RuntimeError("fork() requires init_fn and work_fn in Sandbox()")

        c_init = _INIT_FN_TYPE(self._init_fn)
        _user_work = self._work_fn
        def _flushing_work(clone_id):
            import sys, os, io
            # After dup2, Python's sys.stdout still points to old fd.
            # Replace it with a fresh wrapper on fd 1.
            sys.stdout = io.TextIOWrapper(io.FileIO(1, 'w', closefd=False), line_buffering=True)
            _user_work(clone_id)
            sys.stdout.flush()
        c_work = _WORK_FN_TYPE(_flushing_work)
        self._c_init = c_init  # prevent GC
        self._c_work = c_work

        sb_ptr = _lib.sandlock_new_with_fns(self._native.ptr, c_init, c_work)
        if not sb_ptr:
            raise RuntimeError("sandlock_new_with_fns failed")

        # Fork N clones — returns opaque handle with pipes
        fork_result = _lib.sandlock_fork(sb_ptr, n)

        # Wait for template
        _lib.sandlock_wait(sb_ptr)
        _lib.sandlock_sandbox_free(sb_ptr)

        if not fork_result:
            return ForkResult(None, [], self._native)

        count = _lib.sandlock_fork_result_count(fork_result)
        pids = [_lib.sandlock_fork_result_pid(fork_result, i) for i in range(count)]

        return ForkResult(fork_result, pids, self._native)

    def reduce(self, cmd: list[str], fork_result: "ForkResult") -> Result:
        """Reduce: read clone stdout pipes, feed to reducer stdin.

        Args:
            cmd: Reducer command (receives combined clone output on stdin).
            fork_result: ForkResult from fork().

        Returns:
            Result with reducer's stdout/stderr.

        Example::

            clones = mapper.fork(4)
            result = reducer.reduce(["python3", "sum.py"], clones)
        """
        if fork_result._ptr is None:
            return Result(success=False, exit_code=-1, error="no fork result")

        argv, argc = _make_argv(cmd)
        result_p = _lib.sandlock_reduce(
            fork_result._ptr, self._native.ptr, argv, argc,
        )
        fork_result._ptr = None  # consumed by reduce

        if not result_p:
            return Result(success=False, exit_code=-1, error="reduce failed")

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        stdout = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        return Result(
            success=bool(success),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )


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

    def __init__(self, sandbox: Sandbox, args: list[str]):
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
            Sandbox(policy_a).cmd(["produce_code"]).as_("code")
            + Sandbox(policy_b).cmd(["produce_data"]).as_("data")
            | Sandbox(policy_c).cmd(["python3", "consume.py"])
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
                stage.sandbox._native.ptr,
                argv, argc,
            )

        consumer_argv, consumer_argc = _make_argv(self.consumer.args)
        _lib.sandlock_gather_set_consumer(
            gather_p,
            self.consumer.sandbox._native.ptr,
            consumer_argv, consumer_argc,
        )

        timeout_ms = int(timeout * 1000) if timeout else 0
        result_p = _lib.sandlock_gather_run(gather_p, timeout_ms)

        if not result_p:
            error = "Gather timed out" if timeout else "Gather failed"
            return Result(success=False, exit_code=-1, error=error)

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        out_bytes = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        error = None
        if exit_code == -1 and not success and timeout:
            error = "Gather timed out"

        return Result(
            success=bool(success),
            exit_code=exit_code,
            stdout=out_bytes,
            stderr=stderr,
            error=error,
        )


class Pipeline:
    """A chain of stages connected by pipes.

    Usage::

        result = (
            Sandbox(policy_a).cmd(["echo", "hello"])
            | Sandbox(policy_b).cmd(["tr", "a-z", "A-Z"])
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
                pipe_p, stage.sandbox._native.ptr, argv, argc,
            )

        timeout_ms = int(timeout * 1000) if timeout else 0
        # pipeline_run consumes pipe_p
        result_p = _lib.sandlock_pipeline_run(pipe_p, timeout_ms)

        if not result_p:
            error = "Pipeline timed out" if timeout else "Pipeline failed"
            return Result(success=False, exit_code=-1, error=error)

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        out_bytes = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        # Handle stdout fd redirection
        if stdout is not None and out_bytes:
            os.write(stdout, out_bytes)
            out_bytes = b""

        # Detect timeout (exit_code == -1 from ExitStatus::Timeout)
        error = None
        if exit_code == -1 and not success and timeout:
            error = "Pipeline timed out"

        return Result(
            success=bool(success),
            exit_code=exit_code,
            stdout=out_bytes,
            stderr=stderr,
            error=error,
        )

