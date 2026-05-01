# SPDX-License-Identifier: Apache-2.0
"""Policy dataclasses for Sandlock sandbox configuration.

A Policy is frozen after creation — live updates go through
BPF maps + seccomp notif, not Policy mutation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Mapping, Sequence

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


@dataclass(frozen=True)
class Policy:
    """Immutable sandbox policy.

    All fields are optional — unset fields mean "no restriction"
    (except ``deny_syscalls`` which defaults to a safe blocklist).
    """

    # Filesystem (Landlock)
    fs_writable: Sequence[str] = field(default_factory=list)
    """Paths the sandbox can write to."""

    fs_readable: Sequence[str] = field(default_factory=list)
    """Paths the sandbox can read (in addition to writable paths)."""

    fs_denied: Sequence[str] = field(default_factory=list)
    """Paths explicitly denied (neither read nor write)."""

    # Syscall filtering (seccomp) — set one or neither, not both
    deny_syscalls: Sequence[str] | None = None
    """Syscall names to block (blocklist mode). None = default blocklist."""

    allow_syscalls: Sequence[str] | None = None
    """Syscall names to allow (allowlist mode). Everything else is blocked.
    Stricter than deny_syscalls — unknown/new syscalls are denied by default."""

    # Network — endpoint allowlist (IP × port via seccomp on-behalf path)
    net_allow: Sequence[str] = field(default_factory=list)
    """Outbound TCP endpoint rules. Each entry is a string of the form:

    * ``"host:port"`` — restrict to one host on one port (e.g. ``"api.openai.com:443"``)
    * ``"host:port,port,..."`` — multiple ports for one host (e.g. ``"github.com:22,443"``)
    * ``":port"`` or ``"*:port"`` — any IP on this port

    Hostnames are resolved at sandbox-creation time and pinned via a
    synthetic ``/etc/hosts``. Empty = deny all outbound TCP (Landlock
    rejects on the direct path; no on-behalf path is enabled). HTTP
    rules with concrete hosts auto-add a matching entry on
    :attr:`http_ports`. See README "Network Model" for details."""

    no_coredump: bool = False
    """Disable core dumps and restrict /proc/pid access from other
    processes.  Applied via prctl(PR_SET_DUMPABLE, 0).  Prevents
    leaking sandbox memory contents but breaks gdb/strace/perf."""

    # Network (Landlock ABI v4+, TCP only)
    net_bind: Sequence[int | str] = field(default_factory=list)
    """TCP ports the sandbox may bind.  Empty = deny all.
    Each entry is a port number or a ``"lo-hi"`` range string."""

    # Socket type restrictions (seccomp-enforced)
    no_raw_sockets: bool = True
    """Block raw IP sockets (SOCK_RAW on AF_INET/AF_INET6).  Raw sockets
    allow packet sniffing and ICMP crafting — almost never needed by
    sandboxed programs.  Enforced via seccomp BPF."""

    no_udp: bool = True
    """Block UDP sockets (SOCK_DGRAM on AF_INET/AF_INET6). Default deny
    matches the deny-by-default posture of every other protocol; flip
    to ``False`` (CLI: ``--allow-udp``) to enable UDP. Outbound UDP
    destinations are still gated by :attr:`net_allow` — same endpoint
    allowlist used for TCP. AF_UNIX datagrams are unaffected.
    Enforced via seccomp BPF."""

    # HTTP ACL
    http_allow: Sequence[str] = field(default_factory=list)
    """HTTP allow rules. Format: "METHOD host/path" with glob matching.
    When non-empty, all other HTTP requests are denied by default.
    A transparent MITM proxy is spawned in the supervisor."""

    http_deny: Sequence[str] = field(default_factory=list)
    """HTTP deny rules. Checked before allow rules. Format: "METHOD host/path"."""

    http_ports: Sequence[int] = field(default_factory=list)
    """TCP ports to intercept for HTTP ACL. Defaults to [80] (plus 443 with
    https_ca). Override to intercept custom ports like 8080."""

    https_ca: str | None = None
    """PEM CA certificate path for HTTPS MITM. When set, port 443 is also
    intercepted by the HTTP ACL proxy."""

    https_key: str | None = None
    """PEM CA private key path for HTTPS MITM. Required with https_ca."""

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
