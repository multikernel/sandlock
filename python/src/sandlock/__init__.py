# SPDX-License-Identifier: Apache-2.0
"""Sandlock: Lightweight process sandbox.

Uses Landlock and seccomp for process confinement
without root or namespaces.
"""

from ._version import __version__
from ._sdk import Sandbox, Stage, Pipeline, Result, SyscallEvent, PolicyContext, Checkpoint
from .policy import Policy, FsIsolation, BranchAction, parse_ports
from ._profile import load_profile, list_profiles
from .exceptions import (
    SandlockError,
    PolicyError,
    SandboxError,
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
    "Policy",
    "FsIsolation",
    "BranchAction",
    "parse_ports",
    # Profiles
    "load_profile",
    "list_profiles",
    # Exceptions
    "SandlockError",
    "PolicyError",
    "SandboxError",
]
