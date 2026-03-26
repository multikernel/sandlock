# SPDX-License-Identifier: Apache-2.0
"""Sandlock: Lightweight process sandbox.

Uses Landlock and seccomp for process confinement
without root or namespaces.
"""

from ._version import __version__
from .policy import Policy, FsIsolation, BranchAction, parse_ports
from .sandbox import Sandbox
from ._runner import Result, Stage, Pipeline
from ._checkpoint import Checkpoint
from ._notif_policy import NotifPolicy, NotifAction, PathRule
from ._profile import load_profile, list_profiles
from ._seccomp import DEFAULT_ALLOW_SYSCALLS, DEFAULT_DENY_SYSCALLS
from .exceptions import (
    SandlockError,
    PolicyError,
    SandboxError,
    ForkError,
    ConfinementError,
    LandlockUnavailableError,
    SeccompError,
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
    "Stage",
    "Pipeline",
    "Policy",
    "FsIsolation",
    "BranchAction",
    "Result",
    "Checkpoint",
    "parse_ports",
    # Profiles
    "load_profile",
    "list_profiles",
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
