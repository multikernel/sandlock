# SPDX-License-Identifier: Apache-2.0
"""Sandlock: Lightweight process sandbox.

Uses Landlock, seccomp, and cgroup v2 for process confinement
without root or namespaces.
"""

from ._version import __version__
from .policy import Policy, FsIsolation, BranchAction, parse_ports
from .sandbox import Sandbox
from ._runner import Result
from ._checkpoint import Checkpoint
from ._notif_policy import NotifPolicy, NotifAction, PathRule
from ._seccomp import DEFAULT_ALLOW_SYSCALLS, DEFAULT_DENY_SYSCALLS
from .exceptions import (
    SandlockError,
    PolicyError,
    SandboxError,
    ForkError,
    ConfinementError,
    LandlockUnavailableError,
    SeccompError,
    CgroupError,
    ChildError,
    MemoryProtectError,
    NotifError,
    BranchError,
    BranchConflictError,
)

__all__ = [
    "__version__",
    # Core API
    "Sandbox",
    "Policy",
    "FsIsolation",
    "BranchAction",
    "Result",
    "Checkpoint",
    "parse_ports",
    # Seccomp syscall lists
    "DEFAULT_ALLOW_SYSCALLS",
    "DEFAULT_DENY_SYSCALLS",
    # Notification / virtualization
    "NotifPolicy",
    "NotifAction",
    "PathRule",
    # Exceptions
    "SandlockError",
    "PolicyError",
    "SandboxError",
    "ForkError",
    "ConfinementError",
    "LandlockUnavailableError",
    "SeccompError",
    "ChildError",
    "MemoryProtectError",
    "NotifError",
    "BranchError",
    "BranchConflictError",
]
