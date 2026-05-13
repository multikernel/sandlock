# SPDX-License-Identifier: Apache-2.0
"""Sandbox dataclass for Sandlock sandbox configuration and runtime.

A Sandbox holds both the configuration (policy fields) and the runtime
state for executing commands. Configuration fields are set at construction
time; runtime state (``_native``, ``_handle``) is initialized lazily.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Callable, Mapping, Sequence

if TYPE_CHECKING:
    from ._notif_policy import NotifPolicy


# --- Memory size parsing (from branching/process/limits.py) ---

_UNITS = {
    "K": 1024,
    "M": 1024 ** 2,
    "G": 1024 ** 3,
    "T": 1024 ** 4,
}

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([KMGT])?\s*$", re.IGNORECASE)


def parse_memory_size(s: str) -> int:
    """Parse a human-friendly memory size string to bytes.

    Accepts plain integers (bytes) or suffixed values: ``'512M'``, ``'1G'``,
    ``'100K'``.  The suffix is case-insensitive.

    Returns:
        Size in bytes (integer).

    Raises:
        ValueError: If the string cannot be parsed.
    """
    m = _SIZE_RE.match(s)
    if m is None:
        raise ValueError(f"invalid memory size: {s!r}")
    value = float(m.group(1))
    suffix = m.group(2)
    if suffix is not None:
        value *= _UNITS[suffix.upper()]
    return int(value)


_PORT_RANGE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def parse_ports(specs: Sequence[int | str]) -> list[int]:
    """Parse port specifications into a sorted list of unique port numbers.

    Each spec is an int (single port) or a string like ``"80"``,
    ``"8000-9000"``.  Raises ValueError on out-of-range or bad format.
    """
    ports: set[int] = set()
    for spec in specs:
        if isinstance(spec, int):
            if not 0 <= spec <= 65535:
                raise ValueError(f"port out of range: {spec}")
            ports.add(spec)
            continue
        m = _PORT_RANGE_RE.match(spec.strip())
        if m is None:
            raise ValueError(f"invalid port spec: {spec!r}")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if lo > hi or not 0 <= lo <= 65535 or not 0 <= hi <= 65535:
            raise ValueError(f"invalid port range: {spec!r}")
        ports.update(range(lo, hi + 1))
    return sorted(ports)


class FsIsolation(Enum):
    """Filesystem mutation isolation mode."""

    NONE = "none"        # Direct host writes (default)
    BRANCHFS = "branchfs"  # BranchFS COW isolation
    OVERLAYFS = "overlayfs"  # OverlayFS COW (kernel built-in, no dependencies)


class BranchAction(Enum):
    """Action to take on a BranchFS branch when sandbox exits."""

    COMMIT = "commit"    # Merge writes into parent branch
    ABORT = "abort"      # Discard all writes
    KEEP = "keep"        # Leave branch as-is (caller decides)


@dataclass(frozen=True)
class Change:
    """A single filesystem change detected by dry-run."""

    kind: str
    """Change kind: A=added, M=modified, D=deleted."""

    path: str
    """Path relative to workdir."""


@dataclass
class DryRunResult:
    """Result of a dry-run execution."""

    success: bool
    exit_code: int = 0
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)
    changes: list = field(default_factory=list)
    error: str | None = None


@dataclass
class Sandbox:
    """Sandbox configuration and runtime handle.

    Holds both the policy configuration (filesystem, network, resource limits,
    etc.) and the runtime state for executing commands. Construct once,
    call ``run()``, ``start()`` + lifecycle methods, or use as a context manager.

    A single ``Sandbox`` instance holds at most one running process at a time.
    For concurrent execution, create multiple ``Sandbox`` instances.

    Most config fields are optional — unset fields mean "no restriction".
    Sandlock's default syscall blocklist is always applied.

    Runtime kwargs (``name``, ``policy_fn``, ``init_fn``, ``work_fn``) have
    ``metadata={"runtime": True}`` so serializers can skip them.
    """

    # Filesystem (Landlock)
    fs_writable: Sequence[str] = field(default_factory=list)
    """Paths the sandbox can write to."""

    fs_readable: Sequence[str] = field(default_factory=list)
    """Paths the sandbox can read (in addition to writable paths)."""

    fs_denied: Sequence[str] = field(default_factory=list)
    """Paths explicitly denied (neither read nor write)."""

    extra_deny_syscalls: Sequence[str] = field(default_factory=list)
    """Additional syscall names to block on top of Sandlock's default blocklist."""

    extra_allow_syscalls: Sequence[str] = field(default_factory=list)
    """Syscall group names to allow (e.g. ``'sysv_ipc'``)."""

    # Network — endpoint allowlist (protocol × IP × port via seccomp on-behalf path)
    net_allow: Sequence[str] = field(default_factory=list)
    """Outbound endpoint rules. Each entry is a string. The bare form is
    TCP; other protocols use a scheme prefix:

    * ``"host:port"`` — TCP to one host on one port (e.g. ``"api.openai.com:443"``)
    * ``"host:port,port,..."`` — TCP, multiple ports (e.g. ``"github.com:22,443"``)
    * ``":port"`` / ``"*:port"`` — TCP on any IP (e.g. ``":53"``)
    * ``"tcp://host:port"`` — explicit TCP (same suffix grammar as bare form)
    * ``"udp://host:port"`` — UDP to a host
    * ``"udp://*:*"`` — any UDP (matches the previous ``allow_udp=True`` behavior)
    * ``"icmp://host"`` — kernel ping socket (SOCK_DGRAM + IPPROTO_ICMP) to a host
    * ``"icmp://*"`` — any ICMP echo destination

    Sandlock does not expose raw ICMP (SOCK_RAW). Workloads that need
    ping should rely on the host's ``net.ipv4.ping_group_range`` and
    use the dgram path above.

    Protocol gating falls out of rule presence: with no UDP/ICMP rules,
    UDP and ICMP socket creation are denied at the seccomp layer.
    Hostnames are resolved at sandbox-creation time and pinned via a
    synthetic ``/etc/hosts``. Empty = deny all outbound. HTTP rules with
    concrete hosts auto-add a matching TCP entry on :attr:`http_ports`.
    See README "Network Model" for details."""

    no_coredump: bool = False
    """Disable core dumps and restrict /proc/pid access from other
    processes.  Applied via prctl(PR_SET_DUMPABLE, 0).  Prevents
    leaking sandbox memory contents but breaks gdb/strace/perf."""

    # Network — bind allowlist (Landlock ABI v4+, TCP only)
    net_bind: Sequence[int | str] = field(default_factory=list)
    """TCP ports the sandbox may bind. Empty = deny all. Each entry is
    a port number or a ``"lo-hi"`` range string. Landlock's port hooks
    are TCP-only — UDP bind is not separately gated."""

    # HTTP ACL
    http_allow: Sequence[str] = field(default_factory=list)
    """HTTP allow rules. Format: "METHOD host/path" with glob matching.
    When non-empty, all other HTTP requests are denied by default.
    A transparent MITM proxy is spawned in the supervisor."""

    http_deny: Sequence[str] = field(default_factory=list)
    """HTTP block rules. Checked before allow rules. Format: "METHOD host/path"."""

    http_ports: Sequence[int] = field(default_factory=list)
    """TCP ports to intercept for HTTP ACL. Defaults to [80] (plus 443 with
    http_ca). Override to intercept custom ports like 8080."""

    http_ca: str | None = None
    """PEM CA certificate path for HTTPS MITM. When set, port 443 is also
    intercepted by the HTTP ACL proxy."""

    http_key: str | None = None
    """PEM CA private key path for HTTPS MITM. Required with http_ca."""

    # Resource limits
    max_memory: str | int | None = None
    """Memory limit. String like '512M' or int bytes."""

    max_processes: int = 64
    """Maximum total forks allowed in the sandbox (lifetime count,
    not concurrent).  Enforced by the seccomp notif supervisor.
    Also enables fork interception needed for checkpoint freeze."""

    max_open_files: int | None = None
    """Maximum number of open file descriptors.  Enforced via
    RLIMIT_NOFILE — kernel-enforced, survives exec.  Prevents fd
    exhaustion attacks.  None = inherit system default."""

    max_cpu: int | None = None
    """CPU throttle as a percentage of one core (1–100).  E.g. ``50``
    means the sandbox process group gets at most 50% of one core.
    Enforced by the parent via SIGSTOP/SIGCONT cycling on the process
    group — applies to all processes in the sandbox collectively."""

    cpu_cores: Sequence[int] | None = None
    """CPU cores to pin the sandbox to.  When set, sched_setaffinity()
    is called in the child to restrict it to the specified cores.
    None = inherit parent affinity (unrestricted)."""

    num_cpus: int | None = None
    """Visible CPU count in /proc/cpuinfo.  When set, the sandbox sees
    a synthetic /proc/cpuinfo with only this many processor entries
    (renumbered 0..N-1).  Also virtualizes /proc/meminfo when
    max_memory is set.  Requires seccomp user notification (automatic)."""

    port_remap: bool = False
    """Enable transparent TCP port virtualization.  Each sandbox gets a
    full virtual port space — bind(3000) is silently remapped to a unique
    real port.  Inbound traffic to the virtual port is proxied to the
    real port automatically.  No network namespaces or root required."""

    # Deterministic execution
    random_seed: int | None = None
    """Seed for deterministic randomness. When set, getrandom() returns
    deterministic bytes from a seeded PRNG. Same seed = same output."""

    time_start: float | str | None = None
    """Start timestamp for time virtualization. When set, clock_gettime()
    and gettimeofday() return shifted time starting from this epoch.
    Accepts a Unix timestamp (float) or ISO 8601 string.
    Time ticks at real speed from the given start point."""

    no_randomize_memory: bool = False
    """Disable Address Space Layout Randomization (ASLR) inside the sandbox.
    When set, stack, heap, mmap, and shared library addresses are
    deterministic across runs.  Useful for reproducible builds and tests.
    Applied via personality(ADDR_NO_RANDOMIZE) — per-process, no root."""

    no_huge_pages: bool = False
    """Disable Transparent Huge Pages (THP) inside the sandbox.
    Prevents the kernel from silently promoting 4KB pages to 2MB huge
    pages, which causes nondeterministic memory layout, RSS measurements,
    and page fault timing.  Applied via prctl(PR_SET_THP_DISABLE)."""

    deterministic_dirs: bool = False
    """Sort directory entries lexicographically for deterministic readdir().
    Ensures ls, glob, os.listdir etc. return the same order regardless of
    filesystem internals."""

    # GPU access
    gpu_devices: Sequence[int] | None = None
    """GPU device indices visible to the sandbox.  When set, Landlock
    rules are added for GPU device files (/dev/nvidia*, /dev/dri/*) and
    driver paths (/proc/driver/nvidia, /sys/bus/pci/devices), and
    ``CUDA_VISIBLE_DEVICES`` / ``ROCR_VISIBLE_DEVICES`` are set.
    ``None`` = no GPU access.  ``[]`` (empty list) = all GPUs visible."""

    # Optional chroot
    chroot: str | None = None
    """Path to chroot into before applying other confinement."""

    fs_mount: Mapping[str, str] = field(default_factory=dict)
    """Map virtual paths to host directories inside chroot.
    Example: {"/work": "/host/sandbox/work"} makes /work inside the
    chroot resolve to /host/sandbox/work on the host."""

    # Environment
    clean_env: bool = False
    """If True, start with a minimal environment (PATH, HOME, USER, TERM, LANG).
    If False (default), inherit the parent's full environment."""

    env: Mapping[str, str] = field(default_factory=dict)
    """Variables to set or override in the child.  Applied after clean_env."""


    uid: int | None = None
    """Map to the given UID inside a user namespace.  For example,
    ``uid=0`` gives fake root, ``uid=1000`` maps to UID 1000.
    The child has no real host privileges regardless of the mapped UID.
    Only effective when user namespaces are available."""

    # Seccomp user notification (filesystem virtualization)
    notif_policy: NotifPolicy | None = None
    """If set, enables a seccomp user notification supervisor that
    intercepts open/openat syscalls and applies path-based rules
    for /proc and /sys virtualization.  Requires Linux 5.6+."""

    # Working directory
    workdir: str | None = None
    """COW root directory.  Only controls which directory COW tracks —
    does NOT set the child's working directory.  Use ``cwd`` for that."""

    cwd: str | None = None
    """Child working directory (chdir target).  The child process starts
    in this directory.  Independent of ``workdir`` (COW root)."""

    # COW filesystem isolation
    fs_isolation: FsIsolation = FsIsolation.NONE
    """Filesystem isolation mode.  Auto-set to OVERLAYFS when workdir is set."""

    fs_storage: str | None = None
    """Separate storage directory for BranchFS COW deltas.
    If set, passed as ``--storage`` to ``branchfs mount``."""

    max_disk: str | None = None
    """Disk quota for BranchFS storage (e.g. ``'1G'``).
    Passed as ``--max-storage`` to ``branchfs mount``.
    Enforced by BranchFS FUSE layer (returns ENOSPC)."""

    on_exit: BranchAction = BranchAction.COMMIT
    """Branch action on normal sandbox exit."""

    on_error: BranchAction = BranchAction.ABORT
    """Branch action on sandbox error/exception."""

    # Runtime kwargs — not part of policy serialization.
    name: str | None = field(default=None, repr=False, metadata={"runtime": True})
    """Sandbox name (also exposed as the virtual hostname inside the sandbox).
    Auto-generated as ``sandbox-{pid}`` when omitted."""

    policy_fn: Callable | None = field(default=None, repr=False, metadata={"runtime": True})
    """Optional callback for dynamic per-event policy decisions."""

    init_fn: Callable | None = field(default=None, repr=False, metadata={"runtime": True})
    """Callback run once in the template process before COW fork."""

    work_fn: Callable | None = field(default=None, repr=False, metadata={"runtime": True})
    """Callback run in each COW clone, receives clone_id as argument."""

    def __post_init__(self):
        # Validate name
        if self.name is not None:
            if not self.name:
                raise ValueError("sandbox name must not be empty")
            if "\0" in self.name:
                raise ValueError("sandbox name must not contain NUL bytes")
            if len(self.name.encode()) > 64:
                raise ValueError("sandbox name must be at most 64 bytes")
        # Runtime state — not dataclass fields, not serialized
        self._native = None   # _NativePolicy created lazily on first use
        self._handle = None   # live sandbox handle during start()/run()

    def _resolve_name(self) -> str:
        """Resolve sandbox name: explicit > auto-generated."""
        import os
        if self.name is not None:
            return self.name
        return f"sandbox-{os.getpid()}"

    def _ensure_native(self):
        """Build a fresh native policy from this dataclass.

        Rebuilds on every call so that mutations to config fields
        between lifecycle invocations (e.g. ``run()`` → mutate
        ``fs_readable`` → ``run()`` again) take effect on the next
        run. The Sandbox class is not frozen; a stale native cache
        would silently apply outdated config.
        """
        from ._sdk import _NativePolicy
        self._native = _NativePolicy.from_dataclass(self, policy_fn=self.policy_fn)
        return self._native

    # ------------------------------------------------------------------
    # Config helper methods
    # ------------------------------------------------------------------

    def bind_ports(self) -> list[int]:
        """Return parsed bind port list, or empty if unrestricted."""
        return parse_ports(self.net_bind) if self.net_bind else []

    def memory_bytes(self) -> int | None:
        """Return max_memory as bytes, or None if unset."""
        if self.max_memory is None:
            return None
        if isinstance(self.max_memory, int):
            return self.max_memory
        return parse_memory_size(self.max_memory)

    def time_start_timestamp(self) -> float | None:
        """Return time_start as a Unix timestamp float, or None if unset."""
        if self.time_start is None:
            return None
        if isinstance(self.time_start, (int, float)):
            return float(self.time_start)
        from datetime import datetime, timezone
        s = self.time_start
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()

    def cpu_pct(self) -> int | None:
        """Return max_cpu as a clamped percentage (1–100), or None."""
        if self.max_cpu is None:
            return None
        return max(1, min(100, self.max_cpu))

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._handle is not None:
            from ._sdk import _lib
            try:
                _lib.sandlock_handle_free(self._handle)
            except Exception:
                pass
            self._handle = None
        return False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def pid(self) -> int | None:
        """Child PID while running, None otherwise."""
        if self._handle is None:
            return None
        from ._sdk import _lib
        return _lib.sandlock_handle_pid(self._handle) or None

    @property
    def is_running(self) -> bool:
        """True if a process is currently running in this sandbox."""
        return self._handle is not None

    # ------------------------------------------------------------------
    # Execution methods
    # ------------------------------------------------------------------

    def run(self, cmd: Sequence[str], timeout: float | None = None):
        """Run ``cmd`` in this sandbox and return a ``Result``.

        Spawns the command, waits for it to complete (optionally with a
        timeout), and returns the result.  This is the common one-shot case.

        For explicit lifecycle control (``pause`` / ``resume`` / ``kill``),
        use ``start()`` then the lifecycle methods.

        Args:
            cmd: Command and arguments to execute.
            timeout: Maximum execution time in seconds. The process is
                killed and a timeout result is returned if exceeded.
                None means no timeout.
        """
        from ._sdk import _lib, _make_argv, _read_result_bytes, Result

        if self._handle is not None:
            raise RuntimeError("sandbox is already running")

        native = self._ensure_native()
        argv, argc = _make_argv(list(cmd))
        resolved_name = self._resolve_name()

        # Spawn (non-blocking) so PID is available for pause/resume
        self._handle = _lib.sandlock_spawn(
            native.ptr, _encode(resolved_name), argv, argc,
        )
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

    def start(self, cmd: Sequence[str]) -> None:
        """Spawn ``cmd`` in the sandbox without waiting for it to finish.

        After calling ``start()``, use ``pid``, ``pause()``, ``resume()``,
        ``kill()``, and ``wait()`` to manage the process lifecycle.

        Raises:
            RuntimeError: If a process is already running.
        """
        from ._sdk import _lib, _make_argv

        if self._handle is not None:
            raise RuntimeError("sandbox is already running")

        native = self._ensure_native()
        argv, argc = _make_argv(list(cmd))
        resolved_name = self._resolve_name()

        self._handle = _lib.sandlock_spawn(
            native.ptr, _encode(resolved_name), argv, argc,
        )
        if not self._handle:
            raise RuntimeError("sandlock_spawn failed")

    def wait(self):
        """Wait for the running process to finish and return its Result.

        Raises:
            RuntimeError: If the sandbox is not running.
        """
        from ._sdk import _lib, _read_result_bytes, Result

        if self._handle is None:
            raise RuntimeError("sandbox is not running")

        try:
            result_p = _lib.sandlock_handle_wait_timeout(self._handle, 0)
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

    def dry_run(self, cmd: Sequence[str], timeout: float | None = None) -> "DryRunResult":
        """Dry-run: run a command, collect filesystem changes, then discard.

        Args:
            cmd: Command and arguments to execute.
            timeout: Maximum execution time in seconds. None means no timeout.

        Returns:
            DryRunResult with exit info and list of filesystem changes.
        """
        from ._sdk import _lib, _make_argv, _read_result_bytes

        native = self._ensure_native()
        argv, argc = _make_argv(list(cmd))
        result_p = _lib.sandlock_dry_run(
            native.ptr, _encode(self._resolve_name()), argv, argc,
        )

        if not result_p:
            return DryRunResult(success=False, exit_code=-1, error="sandlock_dry_run failed")

        try:
            exit_code = _lib.sandlock_dry_run_result_exit_code(result_p)
            success = _lib.sandlock_dry_run_result_success(result_p)
            stdout = _read_result_bytes(result_p, _lib.sandlock_dry_run_result_stdout_bytes)
            stderr = _read_result_bytes(result_p, _lib.sandlock_dry_run_result_stderr_bytes)

            import ctypes
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

    def run_interactive(self, cmd: Sequence[str]) -> int:
        """Run with inherited stdio. Returns exit code."""
        from ._sdk import _lib, _make_argv

        native = self._ensure_native()
        argv, argc = _make_argv(list(cmd))
        return _lib.sandlock_run_interactive(
            native.ptr, _encode(self._resolve_name()), argv, argc,
        )

    def cmd(self, args: list[str]) -> "Stage":
        """Bind a command to this sandbox, returning a lazy Stage."""
        from ._sdk import Stage
        return Stage(self, args)

    def fork(self, n: int) -> "ForkResult":
        """Create N COW clones. init_fn runs once, work_fn in each clone.

        Requires ``init_fn`` and ``work_fn`` passed to ``Sandbox()``.

        Returns ForkResult with clone PIDs.

        Example::

            sb = Sandbox(
                fs_readable=[...],
                init_fn=lambda: load_model(),
                work_fn=lambda clone_id: rollout(clone_id),
            )
            clones = sb.fork(1000)
        """
        from ._sdk import _lib, _INIT_FN_TYPE, _WORK_FN_TYPE, ForkResult, _make_argv, _encode as _sdk_encode

        if self.init_fn is None or self.work_fn is None:
            raise RuntimeError("fork() requires init_fn and work_fn in Sandbox()")

        native = self._ensure_native()

        c_init = _INIT_FN_TYPE(self.init_fn)
        _user_work = self.work_fn
        def _flushing_work(clone_id):
            import sys, os, io
            sys.stdout = io.TextIOWrapper(io.FileIO(1, 'w', closefd=False), line_buffering=True)
            _user_work(clone_id)
            sys.stdout.flush()
        c_work = _WORK_FN_TYPE(_flushing_work)
        self._c_init = c_init  # prevent GC
        self._c_work = c_work

        sb_ptr = _lib.sandlock_new_with_fns(
            native.ptr, _encode(self._resolve_name()), c_init, c_work,
        )
        if not sb_ptr:
            raise RuntimeError("sandlock_new_with_fns failed")

        fork_result = _lib.sandlock_fork(sb_ptr, n)

        _lib.sandlock_wait(sb_ptr)
        _lib.sandlock_sandbox_free(sb_ptr)

        if not fork_result:
            return ForkResult(None, [], native)

        count = _lib.sandlock_fork_result_count(fork_result)
        pids = [_lib.sandlock_fork_result_pid(fork_result, i) for i in range(count)]

        return ForkResult(fork_result, pids, native)

    def reduce(self, cmd: list[str], fork_result: "ForkResult") -> "Result":
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
        from ._sdk import _lib, _make_argv, _read_result_bytes, Result

        if fork_result._ptr is None:
            return Result(success=False, exit_code=-1, error="no fork result")

        native = self._ensure_native()
        argv, argc = _make_argv(cmd)
        result_p = _lib.sandlock_reduce(
            fork_result._ptr, native.ptr, _encode(self._resolve_name()), argv, argc,
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

    # ------------------------------------------------------------------
    # Lifecycle methods
    # ------------------------------------------------------------------

    def pause(self) -> None:
        """Send SIGSTOP to the sandbox process group."""
        import signal
        pid = self.pid
        if pid is None:
            raise RuntimeError("sandbox is not running")
        import os
        os.killpg(pid, signal.SIGSTOP)

    def resume(self) -> None:
        """Send SIGCONT to the sandbox process group."""
        import signal
        pid = self.pid
        if pid is None:
            raise RuntimeError("sandbox is not running")
        import os
        os.killpg(pid, signal.SIGCONT)

    def kill(self) -> None:
        """Send SIGKILL to the sandbox process group."""
        import signal
        pid = self.pid
        if pid is None:
            raise RuntimeError("sandbox is not running")
        import os
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def ports(self) -> dict[int, int]:
        """Return current port mappings {virtual_port: real_port}.

        Only contains entries where the real port differs from the virtual
        port (i.e., where a remap occurred). Empty if port_remap is disabled
        or no ports have been remapped. Requires the sandbox to be running.
        """
        if self._handle is None:
            return {}
        from ._sdk import _lib
        c_str = _lib.sandlock_handle_port_mappings(self._handle)
        if not c_str:
            return {}
        try:
            import json
            raw = json.loads(c_str.decode())
            return {int(k): v for k, v in raw.items()}
        finally:
            _lib.sandlock_string_free(c_str)

    def checkpoint(
        self,
        save_fn: "Callable[[], bytes] | None" = None,
    ) -> "Checkpoint":
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
        from ._sdk import _lib, Checkpoint

        if self._handle is None:
            raise RuntimeError("sandbox is not running (use start() or run() first)")
        ptr = _lib.sandlock_handle_checkpoint(self._handle)
        if not ptr:
            raise RuntimeError("checkpoint capture failed")
        cp = Checkpoint(ptr)
        if save_fn is not None:
            cp.app_state = save_fn()
        return cp


def _encode(s: str) -> bytes:
    """Encode a string to UTF-8 bytes, rejecting NUL bytes."""
    if isinstance(s, str):
        result = s.encode("utf-8")
    elif isinstance(s, bytes):
        result = s
    else:
        result = str(s).encode("utf-8")
    if b'\x00' in result:
        raise ValueError(f"NUL byte in string argument: {result!r}")
    return result
