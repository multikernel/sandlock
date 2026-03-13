# SPDX-License-Identifier: Apache-2.0
"""BranchFS integration for copy-on-write filesystem isolation.

Talks to a BranchFS FUSE daemon via ioctls on ``.branchfs_ctl`` files.
Each sandbox gets its own branch; writes are isolated in a COW delta
layer until explicitly committed or aborted.

If the mount point is not already a BranchFS mount, sandlock will
auto-mount it via the ``branchfs`` CLI (optional runtime dependency).
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import shutil
import subprocess
from pathlib import Path

from .exceptions import BranchError, BranchConflictError

# ioctl numbers — must match branchfs daemon (fs.rs)
FS_IOC_BRANCH_CREATE = 0x8080_6200  # _IOR('b', 0, [u8; 128])
FS_IOC_BRANCH_COMMIT = 0x0000_6201  # _IO ('b', 1)
FS_IOC_BRANCH_ABORT = 0x0000_6202   # _IO ('b', 2)

CTL_FILE = ".branchfs_ctl"


def _ctl_create(ctl_path: Path) -> str:
    """Issue CREATE ioctl and return the new branch UUID."""
    fd = os.open(str(ctl_path), os.O_RDWR)
    try:
        buf = ctypes.create_string_buffer(128)
        fcntl.ioctl(fd, FS_IOC_BRANCH_CREATE, buf)
        return buf.value.decode()
    except OSError as e:
        raise BranchError(f"CREATE failed at {ctl_path}: {e}") from e
    finally:
        os.close(fd)


def _ctl_ioctl(ctl_path: Path, cmd: int, op_name: str) -> None:
    """Open a ctl file and issue a simple ioctl (no output buffer)."""
    fd = os.open(str(ctl_path), os.O_RDWR)
    try:
        fcntl.ioctl(fd, cmd, 0)
    except OSError as e:
        if e.errno == errno.ESTALE:
            raise BranchConflictError(
                f"{op_name} conflict at {ctl_path} (sibling already committed)"
            ) from e
        raise BranchError(f"{op_name} failed at {ctl_path}: {e}") from e
    finally:
        os.close(fd)


def is_branchfs_mount(mount_point: Path) -> bool:
    """Check if a path is already a BranchFS mount."""
    return (mount_point / CTL_FILE).exists()


def ensure_mount(
    mount_point: Path,
    *,
    base: Path | None = None,
    storage: Path | None = None,
    max_disk: str | None = None,
) -> None:
    """Ensure a BranchFS mount exists at the given path.

    If already mounted, this is a no-op.  Otherwise, auto-mounts via
    the ``branchfs`` CLI command (optional runtime dependency).

    Args:
        mount_point: Where to mount BranchFS.
        base: Base directory for the workspace.  Defaults to mount_point.
        storage: Separate storage directory for COW deltas.
            Auto-created temp dir if not specified.
        max_disk: Storage quota (e.g. ``"1G"``), passed as ``--max-storage``.

    Raises:
        BranchError: If ``branchfs`` is not installed or mount fails.
    """
    if is_branchfs_mount(mount_point):
        return

    branchfs_bin = shutil.which("branchfs")
    if branchfs_bin is None:
        raise BranchError(
            "fs_isolation=BRANCHFS requires the 'branchfs' command. "
            "Install it with: cargo install branchfs"
        )

    import tempfile
    import time

    mount_point.mkdir(parents=True, exist_ok=True)
    if storage is None:
        storage = Path(tempfile.mkdtemp(prefix="sandlock_storage_"))
    else:
        storage.mkdir(parents=True, exist_ok=True)

    cmd = [branchfs_bin, "mount"]
    cmd.extend(["--base", str(base or mount_point)])
    cmd.extend(["--storage", str(storage)])
    if max_disk:
        cmd.extend(["--max-storage", max_disk])
    cmd.append(str(mount_point))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as e:
        raise BranchError(f"branchfs not found: {e}") from e

    if result.returncode != 0:
        raise BranchError(
            f"branchfs mount failed: {result.stderr.strip() or result.stdout.strip()}"
        )

    # Wait for FUSE to be ready (daemon starts asynchronously)
    ctl = mount_point / CTL_FILE
    for _ in range(50):
        if ctl.exists():
            return
        time.sleep(0.1)

    raise BranchError("branchfs mount timed out waiting for FUSE")


def unmount(mount_point: Path) -> None:
    """Unmount a BranchFS mount that was auto-mounted by ensure_mount()."""
    branchfs_bin = shutil.which("branchfs")
    if branchfs_bin is None:
        return
    subprocess.run(
        [branchfs_bin, "unmount", str(mount_point)],
        capture_output=True,
    )


class SandboxBranch:
    """Manages a BranchFS branch for a single sandbox.

    Created by Sandbox when ``policy.fs_isolation == FsIsolation.BRANCHFS``.
    The branch is created under the parent's ctl (mount root for top-level,
    or parent branch's ``@path`` for nested sandboxes).

    Attributes:
        path: The ``@{uuid}`` virtual path where this branch is accessible.
    """

    def __init__(
        self,
        mount_root: Path,
        parent_path: Path | None = None,
    ):
        self._mount_root = Path(mount_root)
        self._parent_path = Path(parent_path) if parent_path else self._mount_root
        self._branch_id: str | None = None
        self._path: Path | None = None
        self._finished = False

    @property
    def path(self) -> Path:
        """Virtual path to this branch (mount_root/@{uuid})."""
        if self._path is None:
            raise BranchError("Branch not created yet")
        return self._path

    @property
    def branch_id(self) -> str | None:
        """Branch UUID assigned by the daemon."""
        return self._branch_id

    @property
    def mount_root(self) -> Path:
        return self._mount_root

    def create(self) -> Path:
        """Create the branch via CREATE ioctl on parent's ctl file.

        Returns:
            The virtual path (mount_root/@{uuid}).
        """
        ctl_path = self._parent_path / CTL_FILE
        self._branch_id = _ctl_create(ctl_path)
        self._path = self._mount_root / f"@{self._branch_id}"
        return self._path

    def commit(self) -> None:
        """Commit the branch (merge writes into parent).

        Raises:
            BranchConflictError: If a sibling already committed (ESTALE).
            BranchError: If the commit fails.
        """
        if self._finished:
            return
        if self._path is None:
            raise BranchError("Branch not created")
        _ctl_ioctl(self._path / CTL_FILE, FS_IOC_BRANCH_COMMIT, "commit")
        self._finished = True

    def abort(self) -> None:
        """Abort the branch (discard all writes).

        Raises:
            BranchError: If the abort fails.
        """
        if self._finished:
            return
        if self._path is None:
            raise BranchError("Branch not created")
        _ctl_ioctl(self._path / CTL_FILE, FS_IOC_BRANCH_ABORT, "abort")
        self._finished = True

    @property
    def finished(self) -> bool:
        return self._finished
