# SPDX-License-Identifier: Apache-2.0
"""CowBranch: manages COW upper directory for seccomp-based isolation."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from ..exceptions import BranchError
from .._cow_base import CowBranchBase, cleanup_branch_dir


class CowBranch(CowBranchBase):
    """Seccomp notif-based COW. No namespaces, no dependencies.

    Tracks deletions in memory (no whiteout files on disk).
    """

    def __init__(self, workdir: Path, storage: Path | None = None):
        self._workdir = Path(workdir)
        self._storage = storage or Path(f"/tmp/sandlock-cow-{os.getpid()}")
        self._branch_id: str | None = None
        self._finished = False
        self._deleted: set[str] = set()  # relative paths deleted by sandbox
        self._has_changes = False  # True after first write or delete

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
        """Create the COW upper directory.

        Also cleans up any orphaned storage dirs from killed processes.
        """
        # Clean stale dirs from previous crashed runs
        if self._storage.exists():
            for entry in self._storage.iterdir():
                if entry.is_dir():
                    try:
                        # Check if the owning process is still alive
                        # Storage parent is /tmp/sandlock-cow-<pid>
                        parts = self._storage.name.split("-")
                        if len(parts) >= 3 and parts[-1].isdigit():
                            pid = int(parts[-1])
                            os.kill(pid, 0)  # check if alive
                    except (ProcessLookupError, ValueError):
                        shutil.rmtree(str(entry), ignore_errors=True)

        self._branch_id = uuid.uuid4().hex[:12]
        branch_dir = self._storage / self._branch_id
        branch_dir.mkdir(parents=True, exist_ok=True)
        (branch_dir / "upper").mkdir(exist_ok=True)
        return self._workdir

    def is_deleted(self, rel_path: str) -> bool:
        """Check if a path has been deleted in this branch."""
        return rel_path in self._deleted

    @property
    def has_changes(self) -> bool:
        """True after any write, delete, or metadata change."""
        return self._has_changes

    def mark_deleted(self, rel_path: str) -> None:
        """Mark a path as deleted."""
        self._deleted.add(rel_path)
        self._has_changes = True

    def ensure_cow_copy(self, rel_path: str) -> Path:
        """Ensure a COW copy exists in upper. Returns the upper path.

        If the file exists in lower (workdir) but not in upper, copies it.
        If it exists in neither, returns the upper path (for new files).
        Clears any deletion mark for this path.
        """
        self._deleted.discard(rel_path)
        self._has_changes = True

        upper_file = self.upper_dir / rel_path
        lower_file = self._workdir / rel_path

        if upper_file.exists():
            return upper_file

        upper_file.parent.mkdir(parents=True, exist_ok=True)

        if lower_file.exists() and not lower_file.is_symlink():
            shutil.copy2(str(lower_file), str(upper_file),
                         follow_symlinks=False)
        elif lower_file.is_symlink():
            # Copy symlink itself, not its target
            link_target = os.readlink(str(lower_file))
            os.symlink(link_target, str(upper_file))

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

        upper = self.upper_dir
        target = self._workdir

        # Delete files marked as deleted
        for rel_path in self._deleted:
            dest = target / rel_path
            if dest.is_dir():
                shutil.rmtree(str(dest), ignore_errors=True)
            elif dest.exists() or dest.is_symlink():
                dest.unlink()

        # Copy files from upper to target
        synced_dirs = set()
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
                synced_dirs.add(str(dest.parent))

        # fsync all modified directories to ensure data is on disk
        # before removing the upper dir
        for d in synced_dirs:
            try:
                fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
                os.fsync(fd)
                os.close(fd)
            except OSError:
                pass

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
