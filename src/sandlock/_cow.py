# SPDX-License-Identifier: Apache-2.0
"""Seccomp notif-based Copy-on-Write filesystem isolation.

No mount namespace, no FUSE, no dependencies. Uses seccomp user
notification to intercept openat() and redirect writes to a COW
upper directory. The original workdir is never modified.

Flow::

    child calls open("file.txt", O_WRONLY)
        ↓
    seccomp notif intercepts
        ↓
    is path under workdir?
        no  → allow (continue)
        yes → is file in upper?
            yes → open upper copy, inject fd
            no  → copy lower→upper (COW), open upper, inject fd

This handles mmap correctly: the fd the child receives points to the
upper copy, so mmap writes go to the copy, not the original.

Usage::

    branch = CowBranch(workdir=Path("/opt/project"))
    branch.create()

    # Pass to NotifSupervisor — it calls handle_open() for each openat
    handler = CowHandler(branch)

    # After sandbox exits:
    branch.commit()   # merge writes to workdir
    # or
    branch.abort()    # discard all writes
"""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from .exceptions import BranchError
from ._cow_base import CowBranchBase, merge_upper_to_target, cleanup_branch_dir

# O_* flags for detecting writes
O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100
O_TRUNC = 0o1000
O_APPEND = 0o2000

_WRITE_FLAGS = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND


class CowBranch(CowBranchBase):
    """Seccomp notif-based COW. No namespaces, no dependencies."""

    def __init__(self, workdir: Path, storage: Path | None = None):
        self._workdir = Path(workdir)
        self._storage = storage or Path(f"/tmp/sandlock-cow-{os.getpid()}")
        self._branch_id: str | None = None
        self._finished = False

    @property
    def workdir(self) -> Path:
        return self._workdir

    @property
    def path(self) -> Path:
        """For CowBranch, path is the original workdir (no merged view)."""
        return self._workdir

    @property
    def branch_id(self) -> str | None:
        return self._branch_id

    @property
    def upper_dir(self) -> Path:
        if self._branch_id is None:
            raise BranchError("Branch not created yet")
        return self._storage / self._branch_id / "upper"

    @property
    def finished(self) -> bool:
        return self._finished

    def create(self) -> Path:
        """Create the COW upper directory."""
        self._branch_id = uuid.uuid4().hex[:12]
        branch_dir = self._storage / self._branch_id
        branch_dir.mkdir(parents=True, exist_ok=True)
        (branch_dir / "upper").mkdir(exist_ok=True)
        return self._workdir

    def ensure_cow_copy(self, rel_path: str) -> Path:
        """Ensure a COW copy exists in upper. Returns the upper path.

        If the file exists in lower (workdir) but not in upper, copies it.
        If it exists in neither, returns the upper path (for new files).
        """
        upper_file = self.upper_dir / rel_path
        lower_file = self._workdir / rel_path

        if upper_file.exists():
            return upper_file

        upper_file.parent.mkdir(parents=True, exist_ok=True)

        if lower_file.exists():
            shutil.copy2(str(lower_file), str(upper_file))

        return upper_file

    def resolve_read(self, rel_path: str) -> Path:
        """Resolve a read path: upper if modified, else lower."""
        upper_file = self.upper_dir / rel_path
        if upper_file.exists():
            return upper_file
        return self._workdir / rel_path

    def commit(self) -> None:
        """Merge upper dir writes into workdir."""
        if self._finished:
            return
        if self._branch_id is None:
            raise BranchError("Branch not created yet")
        merge_upper_to_target(self.upper_dir, self._workdir)
        cleanup_branch_dir(self._storage, self._branch_id)
        self._finished = True

    def abort(self) -> None:
        """Discard all writes."""
        if self._finished:
            return
        if self._branch_id is None:
            raise BranchError("Branch not created yet")
        cleanup_branch_dir(self._storage, self._branch_id)
        self._finished = True


class CowHandler:
    """Handles seccomp notif openat() interception for COW.

    Stateless — all state lives in the CowBranch. This class
    provides the decision logic for the notif supervisor.

    Can be extracted into a standalone module in the future.
    """

    def __init__(self, branch: CowBranch):
        self._branch = branch
        self._workdir_str = str(branch.workdir)

    @property
    def workdir(self) -> str:
        return self._workdir_str

    def matches(self, path: str) -> bool:
        """Check if a path is under the COW workdir."""
        return path.startswith(self._workdir_str + "/") or path == self._workdir_str

    def handle_open(self, path: str, flags: int) -> str | None:
        """Determine the real path to open for a COW-intercepted openat.

        Args:
            path: Absolute path the child is trying to open.
            flags: Open flags (O_WRONLY, O_RDWR, O_CREAT, etc.)

        Returns:
            Path to open (in upper or lower dir), or None to let
            the kernel handle it (path not found in either).
        """
        rel_path = os.path.relpath(path, self._workdir_str)
        is_write = bool(flags & _WRITE_FLAGS)

        if is_write:
            try:
                upper_file = self._branch.ensure_cow_copy(rel_path)
                return str(upper_file)
            except OSError:
                return None
        else:
            resolved = self._branch.resolve_read(rel_path)
            if resolved.exists():
                return str(resolved)
            return None

    @property
    def upper_dir(self) -> Path:
        return self._branch.upper_dir
