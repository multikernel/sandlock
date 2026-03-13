# SPDX-License-Identifier: Apache-2.0
"""cgroup v2 delegated management for sandbox resource limits.

On systemd systems each user gets a delegated cgroup subtree.
Sandlock creates a sub-cgroup per sandbox for memory/pids/cpu
limits and atomic freeze/resume.  No root required.
"""

from __future__ import annotations

import os
from pathlib import Path

from .exceptions import CgroupError


def _find_user_cgroup() -> Path:
    """Find the user's delegated cgroup root.

    Reads /proc/self/cgroup to find the current cgroup, then checks
    that we have write access.  Falls back to $CAPSULE_CGROUP_ROOT
    env var if set.

    Returns:
        Path to the user's cgroup directory.

    Raises:
        CgroupError: If no writable cgroup directory is found.
    """
    override = os.environ.get("CAPSULE_CGROUP_ROOT")
    if override:
        p = Path(override)
        if p.is_dir() and os.access(p, os.W_OK):
            return p
        raise CgroupError(f"CAPSULE_CGROUP_ROOT={override} is not a writable directory")

    try:
        cgroup_data = Path("/proc/self/cgroup").read_text()
    except OSError as e:
        raise CgroupError(f"Cannot read /proc/self/cgroup: {e}") from e

    # cgroup v2: single line "0::/path"
    for line in cgroup_data.strip().splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0":
            rel_path = parts[2]
            cgroup_path = Path("/sys/fs/cgroup") / rel_path.lstrip("/")
            if cgroup_path.is_dir() and os.access(cgroup_path, os.W_OK):
                return cgroup_path

    raise CgroupError(
        "No writable cgroup v2 directory found. "
        "Set CAPSULE_CGROUP_ROOT or ensure systemd cgroup delegation is enabled."
    )


class SandboxCgroup:
    """Manage a cgroup v2 scope for a sandbox."""

    def __init__(self, sandbox_id: str, *, parent: "SandboxCgroup | None" = None):
        self._sandbox_id = sandbox_id
        self._root = parent.path if parent is not None else _find_user_cgroup()
        self._path = self._root / f"sandlock-{sandbox_id}"

    @property
    def path(self) -> Path:
        return self._path

    def create(self) -> None:
        """Create the cgroup directory (mkdir)."""
        try:
            self._path.mkdir(exist_ok=True)
        except OSError as e:
            raise CgroupError(f"Cannot create cgroup {self._path}: {e}") from e

        # Enable controllers in the parent if needed
        self._enable_controllers()

    def _enable_controllers(self) -> None:
        """Enable memory, pids, cpu controllers in the parent subtree_control."""
        control_file = self._root / "cgroup.subtree_control"
        if not control_file.exists():
            return

        try:
            current = control_file.read_text().split()
        except OSError:
            return

        for controller in ("memory", "pids", "cpu"):
            if controller not in current:
                try:
                    control_file.write_text(f"+{controller}\n")
                except OSError:
                    pass  # May not have permission or controller unavailable

    def add_pid(self, pid: int) -> None:
        """Write pid to cgroup.procs."""
        try:
            (self._path / "cgroup.procs").write_text(str(pid))
        except OSError as e:
            raise CgroupError(f"Cannot add pid {pid} to cgroup: {e}") from e

    def set_memory_max(self, nbytes: int) -> None:
        """Write to memory.max."""
        try:
            (self._path / "memory.max").write_text(str(nbytes))
        except OSError as e:
            raise CgroupError(f"Cannot set memory.max: {e}") from e

    def set_pids_max(self, n: int) -> None:
        """Write to pids.max."""
        try:
            (self._path / "pids.max").write_text(str(n))
        except OSError as e:
            raise CgroupError(f"Cannot set pids.max: {e}") from e

    def set_cpu_max(self, quota_us: int, period_us: int = 100_000) -> None:
        """Write '$quota $period' to cpu.max."""
        try:
            (self._path / "cpu.max").write_text(f"{quota_us} {period_us}")
        except OSError as e:
            raise CgroupError(f"Cannot set cpu.max: {e}") from e

    def set_oom_group(self, enabled: bool = True) -> None:
        """Write to memory.oom.group."""
        try:
            (self._path / "memory.oom.group").write_text("1" if enabled else "0")
        except OSError as e:
            raise CgroupError(f"Cannot set memory.oom.group: {e}") from e

    def freeze(self) -> None:
        """Write 1 to cgroup.freeze. Atomic freeze of all processes."""
        try:
            (self._path / "cgroup.freeze").write_text("1")
        except OSError as e:
            raise CgroupError(f"Cannot freeze cgroup: {e}") from e

    def unfreeze(self) -> None:
        """Write 0 to cgroup.freeze."""
        try:
            (self._path / "cgroup.freeze").write_text("0")
        except OSError as e:
            raise CgroupError(f"Cannot unfreeze cgroup: {e}") from e

    def memory_current(self) -> int:
        """Read memory.current."""
        try:
            return int((self._path / "memory.current").read_text().strip())
        except (OSError, ValueError) as e:
            raise CgroupError(f"Cannot read memory.current: {e}") from e

    def is_frozen(self) -> bool:
        """Read cgroup.freeze status."""
        try:
            return (self._path / "cgroup.freeze").read_text().strip() == "1"
        except OSError:
            return False

    def pids(self) -> list[int]:
        """Read cgroup.procs and return list of PIDs."""
        try:
            text = (self._path / "cgroup.procs").read_text().strip()
            if not text:
                return []
            return [int(p) for p in text.splitlines()]
        except (OSError, ValueError):
            return []

    def destroy(self) -> None:
        """Remove the cgroup directory (must be empty — all processes exited/killed)."""
        try:
            if self._path.exists():
                self._path.rmdir()
        except OSError:
            pass  # Best-effort — may still have zombie processes
