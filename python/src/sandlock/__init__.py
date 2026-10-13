# SPDX-License-Identifier: Apache-2.0
"""Sandlock: Lightweight process sandbox.

Uses Landlock and seccomp for process confinement
without root or namespaces.
"""

from ._version import __version__
from ._sdk import (
    Stage, Pipeline, Result, ExitReason, SyscallEvent, PolicyContext, Approval, Checkpoint, SkippedFd,
    NamedStage, Gather, GatherPipeline,
    Protection,
    landlock_abi_version, min_landlock_abi, confine, pull_image,
)
from .inputs import inputs
from .handler import Handler, NotifAction, HandlerCtx, ExceptionPolicy
from .sandbox import (
    Sandbox, PolicyFn, BranchAction, parse_ports, Change, Entry, renames, StdioMode, Process,
    Image, ImageConfig,
)
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
    "PolicyFn",
    "Image",
    "ImageConfig",
    "pull_image",
    "Stage",
    "Pipeline",
    "Result",
    "ExitReason",
    "SyscallEvent",
    "PolicyContext",
    "Approval",
    "Checkpoint",
    "SkippedFd",
    "NamedStage",
    "Gather",
    "GatherPipeline",
    "inputs",
    "BranchAction",
    "parse_ports",
    "Change",
    "Entry",
    "renames",
    "StdioMode",
    "Process",
    "Protection",
    # Handler ABI
    "Handler",
    "NotifAction",
    "HandlerCtx",
    "ExceptionPolicy",
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
