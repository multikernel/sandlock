# SPDX-License-Identifier: Apache-2.0
"""Exception hierarchy for Sandlock sandbox operations."""


class SandlockError(Exception):
    """Base exception for all Sandlock errors."""

    pass


class PolicyError(SandlockError):
    """Invalid policy configuration."""

    pass


class SandboxError(SandlockError):
    """Sandbox lifecycle errors."""

    pass


class ForkError(SandboxError):
    """os.fork() failed."""

    pass


class ConfinementError(SandboxError):
    """Landlock/seccomp/chroot confinement failed."""

    pass


class LandlockUnavailableError(ConfinementError):
    """Landlock LSM not available on this kernel."""

    pass


class SeccompError(ConfinementError):
    """seccomp-bpf filter installation failed."""

    pass


class NotifError(SeccompError):
    """Seccomp user notification supervisor error."""

    pass


class CgroupError(SandboxError):
    """cgroup creation/configuration failed."""

    pass



class ChildError(SandboxError):
    """Child process exited abnormally."""

    pass


class BranchError(SandboxError):
    """BranchFS branch operation failed."""

    pass


class BranchConflictError(BranchError):
    """Commit rejected — a sibling branch already committed (ESTALE)."""

    pass


class MemoryProtectError(SandlockError):
    """mprotect(2) failed."""

    pass
