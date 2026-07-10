# SPDX-License-Identifier: Apache-2.0
"""Sandbox dataclass for Sandlock sandbox configuration and runtime.

A Sandbox holds both the configuration (policy fields) and the runtime
state for executing commands. Configuration fields are set at construction
time; runtime state (``_native``, ``_handle``) is initialized lazily.
"""

from __future__ import annotations

import inspect
import re
import weakref
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Callable, Mapping, Sequence

if TYPE_CHECKING:
    from ._notif_policy import NotifPolicy
    from ._sdk import ExitReason  # DryRunResult.reason annotation (runtime import is circular)


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

    Each spec is an int (single port) or a string holding a comma-separated
    list of single ports / inclusive ``"lo-hi"`` ranges, e.g. ``"80"``,
    ``"8000-9000"``, or ``"8080,9000-9005"`` (matching the CLI's
    ``--net-allow-bind`` grammar).  Raises ValueError on out-of-range or bad
    format.
    """
    ports: set[int] = set()
    for spec in specs:
        if isinstance(spec, int):
            if not 0 <= spec <= 65535:
                raise ValueError(f"port out of range: {spec}")
            ports.add(spec)
            continue
        for part in spec.split(","):
            part = part.strip()
            m = _PORT_RANGE_RE.match(part)
            if m is None:
                raise ValueError(f"invalid port spec: {part!r}")
            lo = int(m.group(1))
            hi = int(m.group(2)) if m.group(2) else lo
            if lo > hi or not 0 <= lo <= 65535 or not 0 <= hi <= 65535:
                raise ValueError(f"invalid port range: {part!r}")
            ports.update(range(lo, hi + 1))
    return sorted(ports)


class BranchAction(Enum):
    """Action to take on the COW branch when sandbox exits."""

    COMMIT = "commit"    # Merge writes into parent branch
    ABORT = "abort"      # Discard all writes
    KEEP = "keep"        # Leave branch as-is (caller decides)


class StdioMode(IntEnum):
    """Per-stream stdio wiring for :meth:`Sandbox.popen`.

    The values are the stable ABI discriminants shared with the C/Rust core.
    """

    INHERIT = 0
    """Share the supervisor's own fd (child writes to the same terminal/file)."""
    PIPED = 1
    """Connect to a pipe; the caller owns the returned end via :class:`Process`."""
    NULL = 2
    """Connect the stream to ``/dev/null``."""


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
    # Appended after the original fields so positional construction is unchanged.
    reason: "ExitReason | None" = None
    """Why the process terminated (parity with ``Result.reason``); ``None`` on an
    error raised before a native result was produced."""
    signal: int = -1
    """Signal number for a ``SIGNALED`` result, else ``-1``."""


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
    A target may also be an IP, a CIDR range, or an IPv6 literal
    (``"10.0.0.0/8:443"``, ``"[2606:4700::/32]:443"``), matched by
    containment with no DNS. Hostnames are resolved at sandbox-creation
    time and pinned via a synthetic ``/etc/hosts``. Empty = deny all
    outbound. HTTP rules with concrete hosts auto-add a matching TCP entry
    on :attr:`http_ports`. See README "Network Model" for details."""

    net_deny: Sequence[str] = field(default_factory=list)
    """Outbound endpoint denylist: default-allow networking, block these
    targets. The inverse of :attr:`net_allow` and **mutually exclusive**
    with it. Same grammar as ``net_allow`` except targets must be a literal
    IP/CIDR or ``"*"`` (hostnames are rejected; use :attr:`http_deny` for
    domains), e.g. ``["10.0.0.0/8", "169.254.169.254:80", "udp://*"]``.
    Empty = no denylist. See README "Network Model" for details."""

    no_coredump: bool = False
    """Disable core dumps and restrict /proc/pid access from other
    processes.  Applied via prctl(PR_SET_DUMPABLE, 0).  Prevents
    leaking sandbox memory contents but breaks gdb/strace/perf."""

    # Network — bind allowlist (Landlock ABI v4+, TCP only)
    net_allow_bind: Sequence[int | str] = field(default_factory=list)
    """TCP ports the sandbox may bind (default-deny allowlist). Empty = deny
    all. Each entry is a port number or a ``"lo-hi"`` range string (or a
    comma-separated list). Landlock's port hooks are TCP-only — UDP bind is
    not separately gated. Mutually exclusive with :attr:`net_deny_bind`."""

    net_deny_bind: Sequence[int | str] = field(default_factory=list)
    """TCP ports the sandbox may NOT bind (default-allow denylist; the
    inverse of :attr:`net_allow_bind`, enforced on the on-behalf ``bind()``
    path). Same port syntax. Empty = no bind denylist. Mutually exclusive
    with :attr:`net_allow_bind`."""

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

    http_inject_ca: Sequence[str] = field(default_factory=list)
    """Trust bundle paths to splice the MITM CA into. Without http_ca this
    generates an ephemeral CA and intercepts port 443."""

    http_ca_out: str | None = None
    """Path to write the active MITM CA public certificate (PEM). Never the
    private key. Useful for NODE_EXTRA_CA_CERTS and similar."""

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

    gid: int | None = None
    """Map to the given GID inside the user namespace.  Must be set together
    with ``uid`` (both or neither).  An unprivileged user namespace maps a
    single id, so supplementary groups are not available."""

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
    fs_storage: str | None = None
    """Separate storage directory for the seccomp COW upper layer / deltas."""

    max_disk: str | None = None
    """Disk quota for COW storage (e.g. ``'1G'``).
    Enforced by the COW layer (returns ENOSPC)."""

    on_exit: BranchAction = BranchAction.COMMIT
    """Branch action on normal sandbox exit."""

    on_error: BranchAction = BranchAction.ABORT
    """Branch action on sandbox error/exception."""

    # Landlock protection opt-out — relax strict enforcement for the
    # named protections. See ``sandlock.Protection`` (the IntEnum mirror
    # of the C ABI ``sandlock_protection_t``).
    allow_degraded: Sequence[int] = field(default_factory=list)
    """Protections that may degrade silently on kernels that don't
    support them. Each entry is a :class:`sandlock.Protection` value.
    On a capable kernel the protection is still enforced strictly; on
    an older kernel it is skipped instead of failing the build.
    Idempotent / last-wins with :attr:`disable` (the later assignment
    for a given protection wins)."""

    disable: Sequence[int] = field(default_factory=list)
    """Protections that are never enforced, even on a host kernel that
    supports them. Each entry is a :class:`sandlock.Protection` value.
    Use this for a deliberate opt-out (e.g. to allow a workload to use
    a protection-incompatible feature). Idempotent / last-wins with
    :attr:`allow_degraded`."""

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
        self._process = None  # weakref to the live popen() Process; it OWNS its
                              # own handle (see `_popen_process`), this is only a
                              # non-owning busy marker
        self._restore_skipped = []  # SkippedFd entries from the last restore

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
        """Return parsed allow-bind port list, or empty if unrestricted."""
        return parse_ports(self.net_allow_bind) if self.net_allow_bind else []

    def deny_bind_ports(self) -> list[int]:
        """Return parsed deny-bind port list, or empty if none."""
        return parse_ports(self.net_deny_bind) if self.net_deny_bind else []

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

    def _popen_process(self):
        """The live :meth:`popen` :class:`Process`, or ``None``. Held *weakly*:
        this is only a busy marker, so abandoning the ``Process`` still lets its
        ``__del__`` reap the child rather than the sandbox pinning it alive."""
        ref = self._process
        return ref() if ref is not None else None

    def _live_handle(self):
        """The handle owning the currently running child, from either source:
        the ``create``/``start``/``run``/``spawn`` lifecycle (``self._handle``) or
        a :meth:`popen` :class:`Process` (which owns its handle). Returns ``None``
        when nothing is running. This is the single source of truth for "busy"."""
        if self._handle is not None:
            return self._handle
        proc = self._popen_process()
        if proc is not None and proc._handle is not None:
            return proc._handle
        return None

    def _check_not_running(self) -> None:
        """Raise if any child is live, so a second lifecycle call can't leak the
        first handle or alias a running popen() child."""
        if self._live_handle() is not None:
            raise RuntimeError("sandbox is already running")

    def _reject_if_popen(self) -> None:
        """Raise if the live child is driven by a :meth:`popen` :class:`Process`.
        The sandbox's own lifecycle methods (``wait``/``pause``/``resume``/``kill``)
        must not touch a handle the ``Process`` owns — freeing or signalling it
        behind the ``Process``'s back is exactly the aliasing this split avoids."""
        proc = self._popen_process()
        if proc is not None and proc._handle is not None:
            raise RuntimeError(
                "this sandbox is running a process started with popen(); manage it "
                "through the returned Process (proc.wait() / proc.kill()), not the "
                "sandbox"
            )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Reap a still-running popen() Process (it owns its own handle) so leaving
        # the sandbox context never strands a confined child.
        proc = self._popen_process()
        if proc is not None and proc._handle is not None:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait()
            except Exception:
                pass
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
        """Child PID while running, None otherwise. Reflects a running child from
        either the sandbox lifecycle or a live :meth:`popen` :class:`Process`."""
        proc = self._popen_process()
        if proc is not None:
            # The Process owns the handle; its pid is lock-guarded and cached, so
            # reading it can't race a concurrent wait() freeing the handle.
            return proc.pid
        if self._handle is None:
            return None
        from ._sdk import _lib
        return _lib.sandlock_handle_pid(self._handle) or None

    @property
    def is_running(self) -> bool:
        """True if a process is currently running in this sandbox (lifecycle or
        a live :meth:`popen` :class:`Process`)."""
        return self._live_handle() is not None

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
        from ._sdk import _lib, _make_argv, _read_result_bytes, Result, ExitReason

        self._check_not_running()

        native = self._ensure_native()
        argv, argc = _make_argv(list(cmd))
        resolved_name = self._resolve_name()

        # Create (parked) so PID is available for pause/resume, then start.
        # The one-shot run path immediately drives wait on this same Python
        # thread, so it can use the FFI current-thread runtime and avoid
        # eager Tokio worker-thread creation.
        self._handle = _lib.sandlock_create_for_run(
            native.ptr, _encode(resolved_name), argv, argc,
        )
        if not self._handle:
            return Result(success=False, exit_code=-1, error="sandlock_create failed")
        if _lib.sandlock_start(self._handle) != 0:
            _lib.sandlock_handle_free(self._handle)
            self._handle = None
            return Result(success=False, exit_code=-1, error="sandlock_start failed")

        try:
            # None -> wait forever (0). A finite timeout clamps up to 1ms so
            # timeout=0 / sub-ms don't collapse to 0 (= wait forever).
            timeout_ms = max(1, int(timeout * 1000)) if timeout is not None else 0
            result_p = _lib.sandlock_handle_wait_timeout(self._handle, timeout_ms)
        finally:
            _lib.sandlock_handle_free(self._handle)
            self._handle = None

        if not result_p:
            return Result(success=False, exit_code=-1, error="sandlock_handle_wait failed")

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        reason = ExitReason(_lib.sandlock_result_reason(result_p))
        signal = _lib.sandlock_result_signal(result_p)
        stdout = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        return Result(
            success=bool(success),
            exit_code=exit_code,
            reason=reason,
            signal=signal,
            stdout=stdout,
            stderr=stderr,
        )

    def run_with_handlers(
        self,
        cmd: Sequence[str],
        handlers: Sequence,
        name: str | None = None,
    ):
        """Run ``cmd`` under this sandbox with extra seccomp-notif handlers.

        ``handlers`` is a sequence of ``(syscall, Handler)`` pairs.
        ``syscall`` is either a syscall name (``str``, e.g. ``"openat"``)
        resolved for the host architecture, or a raw kernel syscall
        number (``int``). Prefer the name — raw numbers are
        architecture-specific. A name sandlock cannot resolve raises
        ``ValueError``; syscalls sandlock does not filter (e.g.
        ``getpid``) are not name-resolvable and must be passed as an
        ``int``. ``Handler`` is an instance of
        :class:`sandlock.handler.Handler`; see that class for handler
        semantics.

        Ownership of every ``Handler`` is held by the sandlock supervisor
        for the duration of the run; the Python-side reference is held in
        an internal registry and released when the run completes (success
        or failure).

        The underlying C ABI builds and drives its own runtime for each
        call. Do not invoke this method from a thread that already runs a
        Tokio runtime — the FFI panics in that case, and the panic
        propagates as a Python exception via ``extern "C-unwind"``.

        Args:
            cmd: Command and arguments to execute.
            handlers: Sequence of ``(syscall, Handler)`` pairs, where
                ``syscall`` is a name (``str``) or raw number (``int``).
            name: Optional sandbox name. ``None`` resolves to the same
                auto-generated name as :meth:`run`.

        Returns:
            A :class:`Result` describing the run.
        """
        import ctypes

        from . import _handler_ffi
        from ._sdk import (
            _SandlockHandlerRegistration,
            _encode,
            _lib,
            _make_argv,
            _read_result_bytes,
            Result,
            ExitReason,
        )

        self._check_not_running()

        # Resolve syscall keys (str name -> host-arch number, int as is)
        # up front: an unknown name fails loudly here, before any native
        # policy is built or any handler container is allocated.
        handlers = [(_resolve_syscall(key), h) for key, h in list(handlers)]
        native = self._ensure_native()
        argv, argc = _make_argv(list(cmd))
        resolved_name = name if name is not None else self._resolve_name()

        trampoline = _handler_ffi._make_trampoline()
        ud_drop = _handler_ffi._make_ud_drop()

        # Build the registration array. Handler containers allocated here
        # are consumed by sandlock_run_with_handlers — on a successful or
        # failed call the supervisor frees them (and fires ud_drop). We
        # must NOT call sandlock_handler_free on any container handed in.
        regs = (_SandlockHandlerRegistration * len(handlers))()
        registered_ids: list[int] = []
        # ``i`` is referenced in the rollback path; keep it bound even if
        # ``handlers`` is empty and the loop never runs.
        i = 0
        # A container produced by sandlock_handler_new but not yet stored
        # into ``regs`` is owned by neither the regs array nor the
        # supervisor. Track it here so the rollback path can free it;
        # clear it back to None the instant ownership moves into regs.
        container = None
        try:
            for i, (syscall_nr, handler) in enumerate(handlers):
                hid = _handler_ffi._register_handler(handler)
                registered_ids.append(hid)
                container = _lib.sandlock_handler_new(
                    trampoline,
                    ctypes.c_void_p(hid),
                    ud_drop,
                    int(handler.on_exception),
                )
                if not container:
                    raise RuntimeError(
                        "sandlock_handler_new returned NULL for syscall "
                        f"{syscall_nr}"
                    )
                # An async `handle` runs off the supervisor loop. Flag the
                # container before it is handed to the run.
                if _is_deferred_handler(handler):
                    _lib.sandlock_handler_set_deferred(container, True)
                regs[i].syscall_nr = int(syscall_nr)
                regs[i].handler = container
                # Ownership now lives in regs[i]; clear the pending ref so
                # the rollback path does not double-free it (regs[i] is
                # already covered by the range(i) loop below).
                container = None
        except BaseException:
            # Roll back: free every handler container already allocated
            # in this loop. sandlock_handler_free fires the container's
            # ud_drop, which removes that handler from the registry — so
            # we must NOT also call _unregister_handler for those.
            #
            # BaseException (not Exception) so a KeyboardInterrupt or
            # SystemExit raised mid-loop still triggers cleanup before it
            # propagates.
            for j in range(i):
                if regs[j].handler:
                    _lib.sandlock_handler_free(regs[j].handler)
            # A container created by sandlock_handler_new in the failing
            # iteration but not yet stored into regs[i]. With syscall
            # numbers resolved up front, no step currently sits between
            # the alloc and the store that can raise — but this stays as
            # forward defense (a future fallible step there would leak
            # the container otherwise). It is owned by nothing else, so
            # free it here. After a successful store ``container`` is
            # None, so this branch never double-frees a container
            # already covered above.
            if container:
                _lib.sandlock_handler_free(container)
            # The current slot `i` registered a handler id but its
            # container's ud_drop will never fire (either no container
            # was created, or the one created above is freed by hand and
            # its ud_drop only clears that same id) — drop it by hand.
            if i < len(registered_ids):
                _handler_ffi._unregister_handler(registered_ids[i])
            raise

        name_b = _encode(resolved_name)
        try:
            result_p = _lib.sandlock_run_with_handlers(
                native.ptr,
                name_b,
                argv,
                argc,
                regs,
                len(handlers),
            )
        finally:
            # The registry exists only to route dispatch DURING the run;
            # once sandlock_run_with_handlers returns, no handler can be
            # invoked again. On the normal and early-return paths the
            # supervisor has already fired every ud_drop, emptying these
            # slots. On a panic — the entry point is extern "C-unwind",
            # so a panic (e.g. called from within an existing Tokio
            # runtime) propagates here as a Python exception — it may
            # not have. Sweep unconditionally so a panic cannot orphan
            # entries in the process-global registry;
            # _unregister_handler is idempotent (pop(.., None)), so this
            # is a no-op on the paths where ud_drop already ran.
            for hid in registered_ids:
                _handler_ffi._unregister_handler(hid)
        # Ownership of every container has transferred to the supervisor.

        if not result_p:
            return Result(
                success=False,
                exit_code=-1,
                error="sandlock_run_with_handlers failed",
            )

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        reason = ExitReason(_lib.sandlock_result_reason(result_p))
        signal = _lib.sandlock_result_signal(result_p)
        stdout = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        return Result(
            success=bool(success),
            exit_code=exit_code,
            reason=reason,
            signal=signal,
            stdout=stdout,
            stderr=stderr,
        )

    def create(self, cmd: Sequence[str]) -> None:
        """Fork the sandboxed child and install policy. The child is
        parked between policy install and ``execve``; call ``start()``
        to release it.

        ``pid`` is available after this call. The child is not running
        user code yet -- it is blocked inside the sandlock supervisor
        waiting for ``start()``.

        Raises:
            RuntimeError: If a process is already running.
        """
        from ._sdk import _lib, _make_argv

        self._check_not_running()

        native = self._ensure_native()
        argv, argc = _make_argv(list(cmd))
        resolved_name = self._resolve_name()

        self._handle = _lib.sandlock_create(
            native.ptr, _encode(resolved_name), argv, argc,
        )
        if not self._handle:
            raise RuntimeError("sandlock_create failed")

    def start(self) -> None:
        """Release a previously ``create()``d child to ``execve`` the
        configured command.

        Raises:
            RuntimeError: If no child has been created.
        """
        from ._sdk import _lib

        if self._handle is None:
            raise RuntimeError("sandbox has not been created")
        if _lib.sandlock_start(self._handle) != 0:
            _lib.sandlock_handle_free(self._handle)
            self._handle = None
            raise RuntimeError("sandlock_start failed")

    def spawn(self, cmd: Sequence[str]) -> None:
        """Spawn ``cmd`` in the sandbox without waiting for it to finish.

        Sugar for ``create(cmd) + start()``. After calling ``spawn()``,
        use ``pid``, ``pause()``, ``resume()``, ``kill()``, and ``wait()``
        to manage the process lifecycle.

        Raises:
            RuntimeError: If a process is already running.
        """
        self.create(cmd)
        self.start()

    def wait(self):
        """Wait for the running process to finish and return its Result.

        Raises:
            RuntimeError: If the sandbox is not running, or if it is running a
                :meth:`popen` :class:`Process` (wait on that Process instead —
                freeing its handle here would break it).
        """
        from ._sdk import _lib, _read_result_bytes, Result, ExitReason

        self._reject_if_popen()
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
        reason = ExitReason(_lib.sandlock_result_reason(result_p))
        signal = _lib.sandlock_result_signal(result_p)
        stdout = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        return Result(
            success=bool(success),
            exit_code=exit_code,
            reason=reason,
            signal=signal,
            stdout=stdout,
            stderr=stderr,
        )

    def popen(
        self,
        cmd: Sequence[str],
        stdin: StdioMode = StdioMode.INHERIT,
        stdout: StdioMode = StdioMode.INHERIT,
        stderr: StdioMode = StdioMode.INHERIT,
    ) -> "Process":
        """Spawn a confined process with per-stream stdio and return a live
        :class:`Process` whose piped streams the caller reads/writes while it runs.

        The streaming counterpart of :meth:`run`: instead of buffering output
        until the child exits, each stream set to :attr:`StdioMode.PIPED` is
        handed back as a file object on the returned ``Process`` (``.stdin`` /
        ``.stdout`` / ``.stderr``); ``INHERIT``/``NULL`` streams are ``None``.
        Use it to drive a request/response protocol over stdio while the process
        is alive (an MCP or LSP server, a REPL, JSON-RPC).

        All streams default to :attr:`StdioMode.INHERIT` (parity with
        :class:`subprocess.Popen`); pass :attr:`StdioMode.PIPED` for exactly the
        streams you want to drive.

        Deadlock warning (as with :class:`subprocess.Popen`): if you write to a
        piped ``stdin`` you own it -- close it before :meth:`Process.wait` or a
        child that reads to EOF (e.g. ``cat``) never exits and the wait blocks
        forever; likewise drain a piped ``stdout``/``stderr`` before waiting or a
        child that fills the pipe buffer blocks on write. ``Process`` is a
        context manager that closes the streams and reaps the child on exit.

        The ``Result`` returned by :meth:`Process.wait` carries *no* captured
        ``stdout``/``stderr`` (they were streamed to you as fds) — read the output
        off ``proc.stdout``/``proc.stderr``, not off the result.

        Raises:
            RuntimeError: If a process is already running, or the spawn failed.
            ValueError: If a stdio argument is not a valid :class:`StdioMode`.
        """
        import ctypes
        from ._sdk import _lib, _make_argv

        self._check_not_running()

        # Normalize/validate up front: StdioMode(x) accepts a StdioMode or its int
        # discriminant and raises ValueError on anything else, so a bad mode fails
        # clearly in Python instead of as an opaque null handle across the FFI.
        stdin, stdout, stderr = StdioMode(stdin), StdioMode(stdout), StdioMode(stderr)

        native = self._ensure_native()
        argv, argc = _make_argv(list(cmd))
        resolved_name = self._resolve_name()

        fd_in = ctypes.c_int(-1)
        fd_out = ctypes.c_int(-1)
        fd_err = ctypes.c_int(-1)
        # The handle is owned by the returned Process, not the Sandbox: it is
        # never stored in self._handle. self._process (set below) is the busy
        # marker (`_live_handle`), so a stale Process can never alias a later
        # child through the sandbox.
        handle = _lib.sandlock_popen(
            native.ptr,
            _encode(resolved_name),
            argv,
            argc,
            int(stdin),
            int(stdout),
            int(stderr),
            ctypes.byref(fd_in),
            ctypes.byref(fd_out),
            ctypes.byref(fd_err),
        )
        if not handle:
            raise RuntimeError("sandlock_popen failed")

        try:
            proc = Process(self, handle, fd_in.value, fd_out.value, fd_err.value)
        except BaseException:
            # Wrapping the fds failed after the child was spawned. Process.__init__
            # already closed any fds it opened; free the handle (which reaps the
            # child) so the Sandbox is left clean and reusable.
            _lib.sandlock_handle_free(handle)
            raise
        self._process = weakref.ref(proc)
        return proc

    def dry_run(self, cmd: Sequence[str], timeout: float | None = None) -> "DryRunResult":
        """Dry-run: run a command, collect filesystem changes, then discard.

        Args:
            cmd: Command and arguments to execute.
            timeout: Maximum execution time in seconds. None means no timeout.

        Returns:
            DryRunResult with exit info and list of filesystem changes.
        """
        from ._sdk import _lib, _make_argv, _read_result_bytes, ExitReason

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
            reason = ExitReason(_lib.sandlock_dry_run_result_reason(result_p))
            signal = _lib.sandlock_dry_run_result_signal(result_p)
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
            reason=reason,
            signal=signal,
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
        from ._sdk import _lib, _make_argv, _read_result_bytes, Result, ExitReason

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
        reason = ExitReason(_lib.sandlock_result_reason(result_p))
        signal = _lib.sandlock_result_signal(result_p)
        stdout = _read_result_bytes(result_p, _lib.sandlock_result_stdout_bytes)
        stderr = _read_result_bytes(result_p, _lib.sandlock_result_stderr_bytes)
        _lib.sandlock_result_free(result_p)

        return Result(
            success=bool(success),
            exit_code=exit_code,
            reason=reason,
            signal=signal,
            stdout=stdout,
            stderr=stderr,
        )

    # ------------------------------------------------------------------
    # Lifecycle methods
    # ------------------------------------------------------------------

    def pause(self) -> None:
        """Send SIGSTOP to the sandbox process group.

        Raises RuntimeError if a :meth:`popen` Process owns the child (manage it
        through the Process)."""
        import signal
        self._reject_if_popen()
        pid = self.pid
        if pid is None:
            raise RuntimeError("sandbox is not running")
        import os
        os.killpg(pid, signal.SIGSTOP)

    def resume(self) -> None:
        """Send SIGCONT to the sandbox process group.

        Raises RuntimeError if a :meth:`popen` Process owns the child."""
        import signal
        self._reject_if_popen()
        pid = self.pid
        if pid is None:
            raise RuntimeError("sandbox is not running")
        import os
        os.killpg(pid, signal.SIGCONT)

    def kill(self) -> None:
        """Send SIGKILL to the sandbox process group.

        Raises RuntimeError if a :meth:`popen` Process owns the child (call
        ``proc.kill()`` instead)."""
        import signal
        self._reject_if_popen()
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
        or no ports have been remapped. Works for a running child from either
        the lifecycle or a live :meth:`popen` :class:`Process`.
        """
        proc = self._popen_process()
        if proc is not None:
            # The Process owns the handle; its ports() reads it under the lock so
            # this can't race a concurrent wait() freeing it.
            return proc.ports()
        if self._handle is None:
            return {}
        return _read_port_mappings(self._handle)

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

        # A popen() Process owns its handle; checkpoint (SIGSTOP + ptrace freeze)
        # would fight the streaming Process for it, so reject rather than reach
        # past it — consistent with wait/pause/resume/kill.
        self._reject_if_popen()
        if self._handle is None:
            raise RuntimeError("sandbox is not running (use start() or run() first)")
        ptr = _lib.sandlock_handle_checkpoint(self._handle)
        if not ptr:
            raise RuntimeError("checkpoint capture failed")
        cp = Checkpoint(ptr)
        if save_fn is not None:
            cp.app_state = save_fn()
        return cp

    def restore_interactive(self, cp: "Checkpoint") -> None:
        """Restore a checkpoint into a fresh, fully-sandboxed process.

        The checkpoint image is injected over a parked child, which resumes
        at the saved program counter under the full confinement. The sandbox
        is running when this returns (no ``start()`` needed); manage it with
        ``pid`` / ``pause()`` / ``resume()`` / ``kill()`` / ``wait()`` as
        usual. This restores the OS-level process image; for application
        state carried in ``app_state``, see ``Checkpoint.load``'s
        ``restore_fn``. Fds that
        could not be transparently restored are reported by
        :attr:`restore_skipped`.

        x86_64 only. Transparent restore currently works for vDSO-free
        programs: a glibc program resumes but crashes on its first vDSO call
        (known limitation of the injection-based restore engine).

        Args:
            cp: Checkpoint to restore, from :meth:`checkpoint` or
                ``Checkpoint.load``.

        Raises:
            RuntimeError: If a process is already running in this sandbox,
                or the restore fails.
        """
        import ctypes

        from ._sdk import _lib, SkippedFd

        self._check_not_running()
        native = self._ensure_native()
        handle = _lib.sandlock_restore_interactive(
            native.ptr, _encode(self._resolve_name()), cp._ptr,
        )
        if not handle:
            raise RuntimeError("checkpoint restore failed")
        self._handle = handle
        # Copy the skipped-fd diagnostics out eagerly: the native entries live
        # on the handle, which wait() frees.
        skipped = []
        for i in range(_lib.sandlock_handle_restore_skipped_len(handle)):
            fd = _lib.sandlock_handle_restore_skipped_fd(handle, i)
            raw = _lib.sandlock_handle_restore_skipped_path(handle, i)
            path = ""
            if raw:
                c_str = ctypes.cast(raw, ctypes.c_char_p)
                if c_str.value:
                    path = c_str.value.decode("utf-8", errors="replace")
                _lib.sandlock_string_free(c_str)
            skipped.append(SkippedFd(fd=fd, path=path))
        self._restore_skipped = skipped

    @property
    def restore_skipped(self) -> "list[SkippedFd]":
        """Fds the last :meth:`restore_interactive` could not transparently
        recreate (sockets, pipes, memfds, pseudo-filesystem paths); the
        restored process runs without them. Empty if this sandbox never
        restored a checkpoint or every fd was restored."""
        return list(self._restore_skipped)


def _read_port_mappings(handle) -> dict[int, int]:
    """Decode {virtual: real} port mappings for a live handle. Shared by
    ``Sandbox.ports`` and ``Process.ports``; the caller must hold whatever lock
    guards ``handle`` while invoking this."""
    from ._sdk import _lib
    c_str = _lib.sandlock_handle_port_mappings(handle)
    if not c_str:
        return {}
    try:
        import json
        raw = json.loads(c_str.decode())
        return {int(k): v for k, v in raw.items()}
    finally:
        _lib.sandlock_string_free(c_str)


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


def _is_deferred_handler(handler) -> bool:
    """Whether a handler runs off the supervisor loop.

    True when its ``handle`` is an ``async def`` (a coroutine function): the
    coroutine is driven to completion on a worker thread, which would block
    the supervisor loop if run inline, so it must be deferred.
    """
    return inspect.iscoroutinefunction(getattr(handler, "handle", None))


def _resolve_syscall(key) -> int:
    """Resolve a handler-registration key to a kernel syscall number.

    ``key`` is either:

    * an ``int`` — a raw kernel syscall number, used as is; or
    * a ``str`` — a syscall name (e.g. ``"openat"``), resolved for the
      host architecture so callers need not hard-code arch-specific
      numbers.

    A numeric string (e.g. ``"257"``) is treated as a name, not a
    number — it will not resolve; pass an ``int`` for a raw number.

    Raises ``ValueError`` for a name sandlock cannot resolve (syscalls
    sandlock does not filter, e.g. ``getpid``, are not name-resolvable
    and must be passed as an ``int``), and ``TypeError`` for any other
    key type.
    """
    # bool is an int subclass: True/False would otherwise slip through
    # the int branch and resolve to syscalls 1/0 (write/read) — a silent
    # wrong registration. Reject before the int check.
    if isinstance(key, bool):
        raise TypeError(
            "syscall key must be a name (str) or number (int), not bool"
        )
    if isinstance(key, str):
        from ._sdk import _lib
        nr = _lib.sandlock_syscall_nr(_encode(key))
        if nr < 0:
            raise ValueError(
                f"unknown syscall name {key!r}: sandlock cannot resolve it "
                f"— pass the raw kernel syscall number as an int instead"
            )
        return nr
    if isinstance(key, int):
        return key
    raise TypeError(
        f"syscall key must be a name (str) or number (int), "
        f"got {type(key).__name__}"
    )


class Process:
    """A live confined process with caller-owned stdio, returned by
    :meth:`Sandbox.popen`.

    ``.stdin`` / ``.stdout`` / ``.stderr`` are unbuffered binary file objects
    for streams opened with :attr:`StdioMode.PIPED`, else ``None``. The process
    keeps running until :meth:`wait` (or :meth:`kill`) is called, or the
    ``Process`` context manager exits. Prefer the context manager, which closes
    the streams and reaps the child even on error::

        with sandbox.popen(["cat"], stdin=StdioMode.PIPED,
                           stdout=StdioMode.PIPED) as proc:
            proc.stdin.write(b"hi\\n")
            proc.stdin.close()          # EOF so cat exits
            data = proc.stdout.read()
            result = proc.wait()
    """

    def __init__(self, sandbox: "Sandbox", handle, stdin_fd: int, stdout_fd: int, stderr_fd: int):
        import os
        import threading
        from ._sdk import _lib

        self._sandbox = sandbox
        # _lock guards _handle (and the _waiting reservation) so kill()/pid on
        # one thread can't observe or act on a handle wait() is freeing on
        # another — the "kill from another thread while wait() blocks" pattern.
        self._lock = threading.Lock()
        self._waiting = False
        # The handle and pid are set only AFTER the fds are wrapped below: if an
        # fdopen raises, this Process never takes ownership, so popen()'s caller
        # frees the handle exactly once (no double free via __del__).
        self._handle = None
        self._pid = -1
        self._result = None
        self.stdin = self.stdout = self.stderr = None
        # os.fdopen takes ownership of each fd: closing the stream closes the fd,
        # so a Process that is closed/exited never leaks the pipe ends. Wrap the
        # three fds so that if a later fdopen raises, the streams already opened
        # are closed and the not-yet-wrapped raw fds are closed too — no fd is
        # leaked on the error path.
        specs = ((stdin_fd, "wb"), (stdout_fd, "rb"), (stderr_fd, "rb"))
        opened: list = []
        try:
            for fd, mode in specs:
                opened.append(os.fdopen(fd, mode, buffering=0) if fd >= 0 else None)
        except BaseException:
            for stream in opened:
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            for fd, _mode in specs[len(opened):]:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            raise
        self.stdin, self.stdout, self.stderr = opened
        # Take ownership now that construction can no longer fail. Cache the pid
        # so kill()/pid never dereference the handle (avoiding a race with a
        # concurrent wait() free) — they signal by pid, like the sandbox and the
        # Go binding.
        self._pid = _lib.sandlock_handle_pid(handle) or -1
        self._handle = handle

    @property
    def pid(self) -> int | None:
        """The child PID while running, else ``None`` (after :meth:`wait`)."""
        with self._lock:
            return self._pid if self._handle is not None and self._pid > 0 else None

    def ports(self) -> dict[int, int]:
        """Current virtual→real port mappings while running, else ``{}`` (needs
        ``port_remap``). Reads the handle under the lock, and reports ``{}``
        while a :meth:`wait` holds it, so it can't race the wait's free."""
        with self._lock:
            if self._handle is None or self._waiting:
                return {}
            return _read_port_mappings(self._handle)

    def kill(self) -> None:
        """SIGKILL the child's entire process group by pid (like the sandbox and
        the Go binding), so a kill from another thread is safe while :meth:`wait`
        blocks on the handle. Idempotent: a child that already exited is not an
        error, and after :meth:`wait` has reaped it this is a no-op.

        Raises:
            RuntimeError: If the process has no pid (never a valid popen child).
            OSError: If the kill genuinely fails (e.g. EPERM) — a
                ``ProcessLookupError`` (already-exited group) is swallowed.
        """
        import os
        import signal

        with self._lock:
            if self._handle is None:
                return  # already reaped by wait() — no-op
            if self._pid <= 0:
                raise RuntimeError("process has no pid")
            pid = self._pid
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # the group already exited — idempotent no-op

    def wait(self, timeout: float | None = None) -> "Result":
        """Wait for the child to exit and return its :class:`Result`.

        A still-open piped ``stdin`` is closed first so a child that reads to EOF
        can exit; piped ``stdout``/``stderr`` stay open for the caller to finish
        reading. Frees the underlying handle; a second call returns the cached
        result.

        The returned ``Result`` carries no ``stdout``/``stderr`` (those were
        streamed to you as fds — read them off ``.stdout``/``.stderr``).

        Args:
            timeout: Maximum seconds to wait. On timeout the child is killed and
                a non-success ``Result`` is returned (same semantics as
                :meth:`Sandbox.run`'s ``timeout``) — the wait never hangs. ``None``
                (default) waits indefinitely. Note: without a ``timeout``, a piped
                ``stdout``/``stderr`` you have not drained can block the child on a
                full pipe and hang the wait forever; pass a ``timeout`` or drain first.
        """
        from ._sdk import _lib, Result, ExitReason

        # Reserve the handle under the lock so a concurrent kill()/pid sees a
        # consistent state, then run the blocking wait WITHOUT the lock so kill()
        # (which signals by pid, not through the handle) can interrupt it.
        with self._lock:
            handle = self._handle
            if handle is None:
                if self._result is not None:
                    return self._result
                raise RuntimeError("process is not running")
            if self._waiting:
                raise RuntimeError("wait already in progress")
            self._waiting = True

        # Deliver EOF to a still-open piped stdin so a reader child can exit and
        # the wait below does not block forever.
        if self.stdin is not None and not self.stdin.closed:
            try:
                self.stdin.close()
            except OSError:
                pass

        try:
            # None -> wait forever (the FFI treats 0 as "no timeout"). A finite
            # timeout maps to milliseconds, clamped up to 1ms so timeout=0 and
            # sub-millisecond values don't collapse to 0 and wait forever — the
            # opposite of the caller's intent.
            timeout_ms = max(1, int(timeout * 1000)) if timeout is not None else 0
            result_p = _lib.sandlock_handle_wait_timeout(handle, timeout_ms)
        finally:
            with self._lock:
                _lib.sandlock_handle_free(handle)
                self._handle = None
                self._waiting = False
            # Release the sandbox's busy marker so it can be reused. Guard that it
            # still points at us (the weakref may already be dead during __del__).
            if self._sandbox._popen_process() is self:
                self._sandbox._process = None

        if not result_p:
            self._result = Result(
                success=False, exit_code=-1, error="sandlock_handle_wait failed"
            )
            return self._result

        exit_code = _lib.sandlock_result_exit_code(result_p)
        success = _lib.sandlock_result_success(result_p)
        reason = ExitReason(_lib.sandlock_result_reason(result_p))
        signal = _lib.sandlock_result_signal(result_p)
        # stdout/stderr were handed to the caller as fds, so the RunResult holds
        # none — read them off the streams, not the Result.
        _lib.sandlock_result_free(result_p)
        self._result = Result(
            success=bool(success), exit_code=exit_code, reason=reason, signal=signal,
        )
        return self._result

    def __enter__(self) -> "Process":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # Terminate and reap a still-running child so no confined process is left
        # behind, then close every stream we own.
        if self._handle is not None:
            try:
                self.kill()
            except Exception:
                pass
            try:
                self.wait()
            except Exception:
                pass
        for stream in (self.stdin, self.stdout, self.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass

    def __del__(self):
        # Safety net for a Process dropped without wait()/context: a live handle
        # would otherwise leak the confined child + its runtime and wedge the
        # Sandbox in "already running". Reap it, warning like subprocess.Popen so
        # the missing wait()/`with` is visible. __del__ must never raise, and may
        # run during interpreter shutdown when imports/globals are gone — so this
        # is strictly best-effort inside a broad guard.
        try:
            if getattr(self, "_handle", None) is None:
                return
            import warnings

            warnings.warn(
                "Process was not waited on or used as a context manager; "
                "reaping the confined child. Use `with sandbox.popen(...)` or "
                "call wait().",
                ResourceWarning,
                stacklevel=2,
            )
            self.kill()
            self.wait()
        except Exception:
            pass
