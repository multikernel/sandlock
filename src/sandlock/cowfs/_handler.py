# SPDX-License-Identifier: Apache-2.0
"""CowHandler: seccomp notif decision logic for COW interception.

Stateless — all state lives in CowBranch (including the deleted set).
This class provides the decision logic that the seccomp notif supervisor
calls for each intercepted filesystem syscall.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from ._branch import CowBranch

# O_* flags for detecting writes
O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100
O_TRUNC = 0o1000
O_APPEND = 0o2000
O_DIRECTORY = 0o200000

_WRITE_FLAGS = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND


class CowHandler:
    """Handles seccomp notif syscall interception for COW."""

    def __init__(self, branch: CowBranch):
        self._branch = branch
        self._workdir_str = str(branch.workdir)

    @property
    def workdir(self) -> str:
        return self._workdir_str

    @property
    def upper_dir(self) -> Path:
        return self._branch.upper_dir

    def matches(self, path: str) -> bool:
        """Check if a path is under the COW workdir."""
        return path.startswith(self._workdir_str + "/") or path == self._workdir_str

    def _safe_rel(self, path: str) -> str | None:
        """Compute relative path and reject traversal escapes.

        Returns the relative path, or None if it escapes the workdir.
        """
        rel = os.path.relpath(path, self._workdir_str)
        if rel == ".." or rel.startswith("../"):
            return None
        return rel

    def handle_open(self, path: str, flags: int) -> str | None:
        """Determine the real path to open for a COW-intercepted openat.

        Returns path to open, or None to let the kernel handle it.
        """
        if flags & O_DIRECTORY:
            return None

        rel_path = self._safe_rel(path)
        if rel_path is None:
            return None

        # Deleted file — new create or ENOENT
        if self._branch.is_deleted(rel_path):
            if flags & O_CREAT:
                return str(self._branch.ensure_cow_copy(rel_path))
            return None

        is_write = bool(flags & _WRITE_FLAGS)

        if is_write:
            try:
                return str(self._branch.ensure_cow_copy(rel_path))
            except OSError:
                return None
        else:
            resolved = self._branch.resolve_read(rel_path)
            if resolved.exists():
                return str(resolved)
            return None

    def handle_unlink(self, path: str, is_dir: bool = False) -> bool:
        """Handle unlink/rmdir: delete from upper, mark as deleted.

        Returns True if handled, False to let kernel handle.
        """
        rel_path = self._safe_rel(path)
        if rel_path is None:
            return False
        upper_file = self._branch.upper_dir / rel_path
        lower_file = Path(self._workdir_str) / rel_path

        # Delete from upper if exists
        if upper_file.exists():
            if is_dir and upper_file.is_dir():
                shutil.rmtree(str(upper_file), ignore_errors=True)
            elif not is_dir:
                upper_file.unlink()

        # Mark as deleted if it exists in lower
        if lower_file.exists() or lower_file.is_symlink():
            self._branch.mark_deleted(rel_path)
            return True

        # Existed only in upper (already deleted above)
        if not lower_file.exists():
            return True

        return False

    def handle_mkdir(self, path: str, mode: int) -> bool:
        """Handle mkdirat: create directory in upper."""
        rel_path = self._safe_rel(path)
        if rel_path is None:
            return False
        self._branch._deleted.discard(rel_path)
        upper_dir = self._branch.upper_dir / rel_path
        upper_dir.mkdir(parents=True, exist_ok=True)
        return True

    def handle_stat(self, path: str) -> str | None:
        """Handle stat: resolve to upper or lower path.

        Returns the real path to stat, or None if deleted/nonexistent.
        """
        rel_path = self._safe_rel(path)
        if rel_path is None:
            return None

        if self._branch.is_deleted(rel_path):
            return None

        resolved = self._branch.resolve_read(rel_path)
        if resolved.exists():
            return str(resolved)
        return None

    def handle_rename(self, old_path: str, new_path: str) -> bool:
        """Handle rename: rename in upper dir."""
        old_rel = self._safe_rel(old_path)
        new_rel = self._safe_rel(new_path)
        if old_rel is None or new_rel is None:
            return False

        old_upper = self._branch.ensure_cow_copy(old_rel)
        new_upper = self._branch.upper_dir / new_rel
        new_upper.parent.mkdir(parents=True, exist_ok=True)
        old_upper.rename(new_upper)

        # Old path is effectively deleted from lower
        lower_old = Path(self._workdir_str) / old_rel
        if lower_old.exists():
            self._branch.mark_deleted(old_rel)

        return True

    def list_merged_dir(self, rel_path: str) -> list[str]:
        """List directory entries merging upper + lower, minus deletions."""
        lower_dir = Path(self._workdir_str) / rel_path
        upper_dir = self._branch.upper_dir / rel_path

        entries = set()

        # Upper entries
        if upper_dir.is_dir():
            for e in upper_dir.iterdir():
                entries.add(e.name)

        # Lower entries (not deleted)
        if lower_dir.is_dir():
            for e in lower_dir.iterdir():
                child_rel = os.path.join(rel_path, e.name) if rel_path != "." else e.name
                if not self._branch.is_deleted(child_rel):
                    entries.add(e.name)

        return sorted(entries)

    def handle_symlink(self, target: str, linkpath: str) -> bool:
        """Handle symlink: create symlink in upper.

        Rejects absolute or traversal symlink targets to prevent
        escaping the COW layer on commit.
        """
        rel_path = self._safe_rel(linkpath)
        if rel_path is None:
            return False
        # Reject symlink targets that escape the workdir
        if os.path.isabs(target) or ".." in target.split("/"):
            return False
        self._branch._deleted.discard(rel_path)
        upper_link = self._branch.upper_dir / rel_path
        upper_link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, str(upper_link))
        return True

    def handle_link(self, oldpath: str, newpath: str) -> bool:
        """Handle link: create hard link in upper."""
        old_rel = self._safe_rel(oldpath)
        new_rel = self._safe_rel(newpath)
        if old_rel is None or new_rel is None:
            return False
        old_upper = self._branch.ensure_cow_copy(old_rel)
        new_upper = self._branch.upper_dir / new_rel
        new_upper.parent.mkdir(parents=True, exist_ok=True)
        os.link(str(old_upper), str(new_upper))
        return True

    def handle_chmod(self, path: str, mode: int) -> bool:
        """Handle chmod: chmod in upper (COW copy if needed)."""
        rel_path = self._safe_rel(path)
        if rel_path is None:
            return False
        upper_file = self._branch.ensure_cow_copy(rel_path)
        os.chmod(str(upper_file), mode)
        return True

    def handle_readlink(self, path: str) -> str | None:
        """Handle readlink: resolve symlink from upper or lower."""
        rel_path = self._safe_rel(path)
        if rel_path is None:
            return None

        if self._branch.is_deleted(rel_path):
            return None

        upper_file = self._branch.upper_dir / rel_path
        lower_file = Path(self._workdir_str) / rel_path

        if upper_file.is_symlink():
            return os.readlink(str(upper_file))
        if lower_file.is_symlink():
            return os.readlink(str(lower_file))
        return None

    def handle_truncate(self, path: str, length: int) -> bool:
        """Handle truncate: truncate in upper (COW copy if needed)."""
        rel_path = self._safe_rel(path)
        if rel_path is None:
            return False
        upper_file = self._branch.ensure_cow_copy(rel_path)
        os.truncate(str(upper_file), length)
        return True

    def handle_chown(self, path: str, uid: int, gid: int,
                     follow_symlinks: bool = True) -> bool:
        """Handle chown/fchownat: chown in upper (COW copy if needed)."""
        rel_path = self._safe_rel(path)
        if rel_path is None:
            return False
        upper_file = self._branch.ensure_cow_copy(rel_path)
        os.chown(str(upper_file), uid, gid,
                 follow_symlinks=follow_symlinks)
        return True

    def handle_utimens(self, path: str,
                       times: tuple[float, float] | None,
                       follow_symlinks: bool = True) -> bool:
        """Handle utimensat: set timestamps in upper (COW copy if needed).

        times is (atime, mtime) as floats, or None for current time.
        """
        rel_path = self._safe_rel(path)
        if rel_path is None:
            return False
        upper_file = self._branch.ensure_cow_copy(rel_path)
        os.utime(str(upper_file), times=times,
                 follow_symlinks=follow_symlinks)
        return True
