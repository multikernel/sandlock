# SPDX-License-Identifier: Apache-2.0
"""Abstract base class for Copy-on-Write filesystem isolation.

Three backends implement this interface:

- ``CowBranch`` (seccomp notif): no namespaces, no dependencies
- ``OverlayBranch`` (kernel overlayfs): user+mount namespace, no dependencies
- ``SandboxBranch`` (BranchFS FUSE): no namespaces, requires branchfs binary

All three provide the same lifecycle: create → use → commit/abort.
"""

from __future__ import annotations

import os
import shutil
from abc import ABC, abstractmethod
from pathlib import Path


class CowBranchBase(ABC):
    """Abstract COW branch interface.

    A branch isolates filesystem writes. The sandbox operates on
    ``path``, writes are captured, and on exit either committed
    (merged back to the original) or aborted (discarded).

    Implementations must be idempotent: calling commit() or abort()
    multiple times after the first is a no-op.
    """

    @abstractmethod
    def create(self) -> Path:
        """Create the branch. Returns the path the sandbox should use."""

    @abstractmethod
    def commit(self) -> None:
        """Merge captured writes back to the original directory."""

    @abstractmethod
    def abort(self) -> None:
        """Discard all captured writes."""

    @property
    @abstractmethod
    def path(self) -> Path:
        """Path the sandbox operates on.

        - Seccomp COW: the original workdir (writes intercepted)
        - OverlayFS: the merged overlay view
        - BranchFS: the virtual branch path
        """

    @property
    @abstractmethod
    def branch_id(self) -> str | None:
        """Unique identifier for this branch. None before create()."""

    @property
    @abstractmethod
    def finished(self) -> bool:
        """Whether commit() or abort() has been called."""

    @property
    @abstractmethod
    def upper_dir(self) -> Path:
        """Directory containing captured writes (COW deltas).

        Used by the parent for disk quota enforcement.
        Raises BranchError if not created yet.
        """


def merge_upper_to_target(upper: Path, target: Path) -> None:
    """Copy all files from upper directory to target directory.

    Shared by CowBranch and OverlayBranch commit().
    """
    for root, dirs, files in os.walk(upper):
        rel = os.path.relpath(root, upper)
        for d in dirs:
            dest = target / rel / d
            dest.mkdir(parents=True, exist_ok=True)
        for f in files:
            src = Path(root) / f
            dest = target / rel / f
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))


def cleanup_branch_dir(storage: Path, branch_id: str) -> None:
    """Remove a branch's storage directory."""
    branch_dir = storage / branch_id
    shutil.rmtree(str(branch_dir), ignore_errors=True)


def dir_size(path: Path) -> int:
    """Calculate total size of files in a directory tree (bytes).

    Used for disk quota enforcement across all COW backends.
    """
    total = 0
    try:
        for entry in os.scandir(path):
            if entry.is_file(follow_symlinks=False):
                total += entry.stat(follow_symlinks=False).st_size
            elif entry.is_dir(follow_symlinks=False):
                total += dir_size(Path(entry.path))
    except OSError:
        pass
    return total
