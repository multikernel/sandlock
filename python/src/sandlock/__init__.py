# SPDX-License-Identifier: Apache-2.0
"""Sandlock: Lightweight process sandbox.

Uses Landlock and seccomp for process confinement
without root or namespaces.
"""

from ._version import __version__
from ._sdk import (
    Sandbox, Stage, Pipeline, Result, SyscallEvent, PolicyContext, Checkpoint,
    NamedStage, Gather, GatherPipeline,
    landlock_abi_version, min_landlock_abi, confine,
)
from .inputs import inputs
from .policy import Policy, FsIsolation, BranchAction, parse_ports, Change, DryRunResult
from ._profile import load_profile, list_profiles
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
    "Result",
    "SyscallEvent",
    "PolicyContext",
    "Checkpoint",
    "NamedStage",
    "Gather",
    "GatherPipeline",
    "inputs",
    "Policy",
    "FsIsolation",
    "BranchAction",
    "parse_ports",
    "Change",
    "DryRunResult",
    # Platform
    "landlock_abi_version",
    "min_landlock_abi",
    "confine",
    # Profiles
    "load_profile",
    "list_profiles",
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
