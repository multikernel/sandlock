# SPDX-License-Identifier: Apache-2.0
"""OverlayFS-based COW filesystem isolation.

Uses kernel overlayfs in a user namespace (Linux 5.11+) for copy-on-write
isolation without any external dependencies. Supports nesting via chained
lowerdir.

Directory layout per branch::

    {storage}/{branch_id}/
        upper/    ← COW writes go here
        work/     ← overlayfs internal
        merged/   ← union view (what the sandbox sees)

For nesting, the parent's merged dir becomes an additional lowerdir.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import shutil
import uuid
from pathlib import Path

from .exceptions import BranchError, SandboxError

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


class OverlayBranch:
    """Manages an overlayfs branch for a single sandbox.

    Same interface as SandboxBranch for API compatibility.
    """

    def __init__(
        self,
        lower: Path,
        storage: Path,
        parent_branch: "OverlayBranch | None" = None,
    ):
        self._lower = Path(lower)
        self._storage = Path(storage)
        self._parent_branch = parent_branch
        self._branch_id: str | None = None
        self._path: Path | None = None
        self._finished = False

    @property
    def path(self) -> Path:
        """Path to the merged view (what the sandbox sees)."""
        if self._path is None:
            raise BranchError("Branch not created yet")
        return self._path

    @property
    def branch_id(self) -> str | None:
        return self._branch_id

    @property
    def mount_root(self) -> Path:
        return self._lower

    @property
    def finished(self) -> bool:
        return self._finished

    @property
    def upper_dir(self) -> Path:
        """Path to the upper (writable) directory."""
        if self._branch_id is None:
            raise BranchError("Branch not created yet")
        return self._storage / self._branch_id / "upper"

    @property
    def work_dir(self) -> Path:
        """Path to the overlayfs work directory."""
        if self._branch_id is None:
            raise BranchError("Branch not created yet")
        return self._storage / self._branch_id / "work"

    @property
    def lower_dirs(self) -> list[Path]:
        """Chained lower directories for overlayfs mount.

        For nested branches, includes parent's merged dir.
        """
        dirs = []
        if self._parent_branch is not None:
            # Parent's upper has the latest writes, then parent's lowers
            dirs.append(self._parent_branch.upper_dir)
            dirs.extend(self._parent_branch.lower_dirs)
        else:
            dirs.append(self._lower)
        return dirs

    def create(self) -> Path:
        """Create the branch directory structure.

        Returns the merged path. The actual overlayfs mount happens
        in the child process (requires user + mount namespace).
        """
        self._branch_id = uuid.uuid4().hex[:12]
        branch_dir = self._storage / self._branch_id

        branch_dir.mkdir(parents=True, exist_ok=True)
        (branch_dir / "upper").mkdir(exist_ok=True)
        (branch_dir / "work").mkdir(exist_ok=True)
        (branch_dir / "merged").mkdir(exist_ok=True)

        self._path = branch_dir / "merged"
        return self._path

    def mount_options(self) -> str:
        """Build the mount options string for overlayfs."""
        if self._branch_id is None:
            raise BranchError("Branch not created yet")

        lowers = ":".join(str(d) for d in self.lower_dirs)
        return (
            f"lowerdir={lowers},"
            f"upperdir={self.upper_dir},"
            f"workdir={self.work_dir}"
        )

    def commit(self) -> None:
        """Commit: merge upper dir writes into the lower dir."""
        if self._finished:
            return
        if self._branch_id is None:
            raise BranchError("Branch not created yet")

        upper = self.upper_dir
        target = self._lower

        # Copy files from upper to lower, overwriting
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

        # Handle whiteouts (overlayfs marks deletions as char devices)
        for root, dirs, files in os.walk(upper):
            rel = os.path.relpath(root, upper)
            for f in files:
                src = Path(root) / f
                if _is_whiteout(src):
                    dest = target / rel / f
                    if dest.exists():
                        dest.unlink()

        self._cleanup()
        self._finished = True

    def abort(self) -> None:
        """Abort: discard all writes."""
        if self._finished:
            return
        if self._branch_id is None:
            raise BranchError("Branch not created yet")

        self._cleanup()
        self._finished = True

    def _cleanup(self) -> None:
        """Remove the branch directory."""
        if self._branch_id is None:
            return
        branch_dir = self._storage / self._branch_id
        shutil.rmtree(str(branch_dir), ignore_errors=True)


def mount_overlay(branch: OverlayBranch) -> None:
    """Mount overlayfs for a branch.

    Must be called inside a user namespace (child process).
    Requires Linux 5.11+ for unprivileged overlayfs.
    No mount namespace needed — user namespace restricts mount visibility.
    """
    merged = str(branch.path)
    opts = branch.mount_options()

    ret = _libc.mount(
        b"overlay",
        merged.encode(),
        b"overlay",
        0,
        opts.encode(),
    )
    if ret < 0:
        err = ctypes.get_errno()
        raise SandboxError(
            f"overlayfs mount failed: {os.strerror(err)} "
            f"(requires Linux 5.11+ with user namespace)"
        )


def dir_size(path: Path) -> int:
    """Calculate total size of files in a directory tree (bytes)."""
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


def _is_whiteout(path: Path) -> bool:
    """Check if a file is an overlayfs whiteout (char device 0/0)."""
    try:
        st = path.lstat()
        import stat
        return stat.S_ISCHR(st.st_mode) and st.st_rdev == 0
    except OSError:
        return False
