# SPDX-License-Identifier: Apache-2.0
"""Checkpoint and restore for sandboxed processes.

Two layers of state capture:

1. **OS-level** (automatic, transparent): Sandlock uses ptrace +
   /proc to dump registers, memory, and file descriptors from the
   frozen child.  The child does not need to cooperate.

2. **App-level** (optional, cooperative): If the child registered
   a save_fn, Sandlock triggers it via a 1-byte write on the control
   socket.  The child runs save_fn and sends raw bytes back.
   This covers state that ptrace can't see (open sockets, epoll, etc.).

Combined with BranchFS (O(1) filesystem snapshot) and SIGSTOP,
this provides full checkpoint/restore without CRIU or root.

Control socket protocol (for app-level state only):

    Parent → Child:  1 byte (0x01 = checkpoint trigger)
    Child → Parent:  4-byte big-endian length + raw state bytes
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from ._ptrace import ProcessState

_DEFAULT_STORE = Path.home() / ".sandlock" / "checkpoints"

# Trigger byte
TRIGGER_CHECKPOINT = b"\x01"

# Response status
_STATUS_OK = 0
_STATUS_ERR = 1


@dataclass
class Checkpoint:
    """Complete checkpoint: OS state + filesystem + optional app state.

    All data is raw bytes — no Python-specific serialization imposed
    on the application.
    """

    # OS-level (captured automatically via ptrace)
    process_state: ProcessState | None = None
    """Registers, memory, fds — captured transparently."""

    # Filesystem (captured via BranchFS)
    branch_id: str | None = None
    """BranchFS branch UUID (O(1) COW snapshot)."""

    fs_mount: str | None = None
    """BranchFS mount point."""

    # App-level (optional, from save_fn)
    app_state: bytes | None = None
    """Raw bytes from save_fn. None if no save_fn registered."""

    # Metadata
    policy_data: bytes = b""
    """Serialized Policy (for re-applying confinement on restore)."""

    sandbox_id: str | None = None

    # --- Named checkpoint persistence ---

    def save(self, name: str, *, store: Path | str | None = None) -> Path:
        """Persist this checkpoint to disk under the given name.

        Storage layout::

            <store>/<name>/
            ├── meta.json          # branch_id, fs_mount, sandbox_id
            ├── policy.dat         # serialized Policy bytes
            ├── app_state.bin      # raw app state (optional)
            └── process/           # OS-level state (optional)
                ├── info.json      # pid, cwd, exe
                ├── fds.json       # file descriptor table
                ├── memory_map.json# region metadata
                ├── threads/
                │   └── <tid>.bin  # raw register bytes
                └── memory/
                    └── <index>.bin# raw memory contents

        Args:
            name: Checkpoint name (used as directory name).
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Returns:
            Path to the checkpoint directory.
        """
        root = Path(store) if store is not None else _DEFAULT_STORE
        cp_dir = root / name

        # Atomic-ish: write to temp, rename
        tmp_dir = cp_dir.with_suffix(".tmp")
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)
        tmp_dir.mkdir(parents=True)

        try:
            # meta.json
            meta = {
                "branch_id": self.branch_id,
                "fs_mount": self.fs_mount,
                "sandbox_id": self.sandbox_id,
            }
            (tmp_dir / "meta.json").write_text(json.dumps(meta))

            # policy.dat
            (tmp_dir / "policy.dat").write_bytes(self.policy_data)

            # app_state.bin
            if self.app_state is not None:
                (tmp_dir / "app_state.bin").write_bytes(self.app_state)

            # process state
            if self.process_state is not None:
                self._save_process_state(tmp_dir / "process")

            # Rename into place
            if cp_dir.exists():
                shutil.rmtree(cp_dir)
            tmp_dir.rename(cp_dir)

        except BaseException:
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir)
            raise

        return cp_dir

    def _save_process_state(self, proc_dir: Path) -> None:
        """Write ProcessState to a directory of files."""
        ps = self.process_state
        proc_dir.mkdir()

        # info.json
        info = {"pid": ps.pid, "cwd": ps.cwd, "exe": ps.exe}
        (proc_dir / "info.json").write_text(json.dumps(info))

        # fds.json
        fds = [
            {
                "fd": fd.fd,
                "path": fd.path,
                "flags": fd.flags,
                "offset": fd.offset,
                "restorable": fd.restorable,
            }
            for fd in ps.fds
        ]
        (proc_dir / "fds.json").write_text(json.dumps(fds))

        # threads/<tid>.bin — raw register bytes
        threads_dir = proc_dir / "threads"
        threads_dir.mkdir()
        thread_meta = []
        for ts in ps.threads:
            (threads_dir / f"{ts.tid}.bin").write_bytes(ts.registers.data)
            thread_meta.append({
                "tid": ts.tid,
                "arch": ts.registers.arch,
            })
        (proc_dir / "threads.json").write_text(json.dumps(thread_meta))

        # memory/<index>.bin — raw memory contents
        mem_dir = proc_dir / "memory"
        mem_dir.mkdir()
        mem_map = []
        for i, region in enumerate(ps.memory):
            (mem_dir / f"{i}.bin").write_bytes(region.contents)
            mem_map.append({
                "start": region.start,
                "end": region.end,
                "perms": region.perms,
                "offset": region.offset,
                "path": region.path,
            })
        (proc_dir / "memory_map.json").write_text(json.dumps(mem_map))

    @classmethod
    def load(cls, name: str, *, store: Path | str | None = None) -> "Checkpoint":
        """Load a named checkpoint from disk.

        Args:
            name: Checkpoint name.
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Returns:
            Checkpoint with all state restored.

        Raises:
            FileNotFoundError: If the checkpoint does not exist.
        """
        root = Path(store) if store is not None else _DEFAULT_STORE
        cp_dir = root / name
        if not cp_dir.is_dir():
            raise FileNotFoundError(f"Checkpoint not found: {cp_dir}")

        # meta.json
        meta = json.loads((cp_dir / "meta.json").read_text())

        # policy.dat
        policy_data = (cp_dir / "policy.dat").read_bytes()

        # app_state.bin
        app_path = cp_dir / "app_state.bin"
        app_state = app_path.read_bytes() if app_path.exists() else None

        # process state
        proc_dir = cp_dir / "process"
        process_state = cls._load_process_state(proc_dir) if proc_dir.is_dir() else None

        return cls(
            process_state=process_state,
            branch_id=meta.get("branch_id"),
            fs_mount=meta.get("fs_mount"),
            app_state=app_state,
            policy_data=policy_data,
            sandbox_id=meta.get("sandbox_id"),
        )

    @staticmethod
    def _load_process_state(proc_dir: Path) -> "ProcessState":
        """Read ProcessState from a directory of files."""
        from ._ptrace import (
            ProcessState, ThreadState, RegisterState,
            MemoryRegion, FileDescriptor,
        )

        info = json.loads((proc_dir / "info.json").read_text())

        # Threads
        thread_meta = json.loads((proc_dir / "threads.json").read_text())
        threads = []
        for tm in thread_meta:
            reg_data = (proc_dir / "threads" / f"{tm['tid']}.bin").read_bytes()
            threads.append(ThreadState(
                tid=tm["tid"],
                registers=RegisterState(arch=tm["arch"], data=reg_data),
            ))

        # Memory
        mem_map = json.loads((proc_dir / "memory_map.json").read_text())
        memory = []
        for i, mm in enumerate(mem_map):
            contents = (proc_dir / "memory" / f"{i}.bin").read_bytes()
            memory.append(MemoryRegion(
                start=mm["start"],
                end=mm["end"],
                perms=mm["perms"],
                offset=mm["offset"],
                path=mm["path"],
                contents=contents,
            ))

        # File descriptors
        fds_data = json.loads((proc_dir / "fds.json").read_text())
        fds = [
            FileDescriptor(
                fd=fd["fd"],
                path=fd["path"],
                flags=fd["flags"],
                offset=fd["offset"],
                restorable=fd["restorable"],
            )
            for fd in fds_data
        ]

        return ProcessState(
            pid=info["pid"],
            threads=threads,
            memory=memory,
            fds=fds,
            cwd=info.get("cwd", ""),
            exe=info.get("exe", ""),
        )

    @classmethod
    def list(cls, *, store: Path | str | None = None) -> list[str]:
        """List all named checkpoints.

        Args:
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Returns:
            Sorted list of checkpoint names.
        """
        root = Path(store) if store is not None else _DEFAULT_STORE
        if not root.is_dir():
            return []
        return sorted(
            d.name for d in root.iterdir()
            if d.is_dir() and (d / "meta.json").exists()
        )

    @classmethod
    def delete(cls, name: str, *, store: Path | str | None = None) -> None:
        """Delete a named checkpoint.

        Args:
            name: Checkpoint name.
            store: Storage root. Defaults to ``~/.sandlock/checkpoints/``.

        Raises:
            FileNotFoundError: If the checkpoint does not exist.
        """
        root = Path(store) if store is not None else _DEFAULT_STORE
        cp_dir = root / name
        if not cp_dir.is_dir():
            raise FileNotFoundError(f"Checkpoint not found: {cp_dir}")
        shutil.rmtree(cp_dir)


# --- Control socket protocol (for app-level state) ---

def _send_bytes(fd: int, data: bytes) -> None:
    """Send length-prefixed bytes."""
    header = struct.pack(">I", len(data))
    payload = header + data
    view = memoryview(payload)
    while len(view) > 0:
        written = os.write(fd, view)
        view = view[written:]


def _recv_bytes(fd: int) -> bytes:
    """Receive length-prefixed bytes."""
    header = b""
    while len(header) < 4:
        chunk = os.read(fd, 4 - len(header))
        if not chunk:
            raise EOFError("Control socket closed")
        header += chunk
    length = struct.unpack(">I", header)[0]
    if length == 0:
        return b""
    data = b""
    while len(data) < length:
        chunk = os.read(fd, min(length - len(data), 65536))
        if not chunk:
            raise EOFError("Control socket closed mid-read")
        data += chunk
    return data


# --- Child side ---

class _CheckpointListener:
    """Listens for checkpoint triggers in the child process.

    save_fn is registered at construction in the child's address space.
    The parent triggers it by writing a single byte to the control socket.
    """

    def __init__(self, control_fd: int, save_fn: Callable[[], bytes]):
        self._fd = control_fd
        self._save_fn = save_fn

    def start(self) -> None:
        t = threading.Thread(target=self._run, name="sandlock-ckpt", daemon=True)
        t.start()

    def _run(self) -> None:
        try:
            while True:
                trigger = os.read(self._fd, 1)
                if not trigger:
                    break
                if trigger == TRIGGER_CHECKPOINT:
                    self._do_checkpoint()
        except OSError:
            pass
        finally:
            try:
                os.close(self._fd)
            except OSError:
                pass

    def _do_checkpoint(self) -> None:
        try:
            state = self._save_fn()
            _send_bytes(self._fd, bytes([_STATUS_OK]) + state)
        except Exception as e:
            msg = f"{type(e).__name__}: {e}".encode("utf-8", errors="replace")
            _send_bytes(self._fd, bytes([_STATUS_ERR]) + msg)


def start_child_listener(
    control_fd: int,
    save_fn: Callable[[], bytes],
) -> None:
    """Start the checkpoint listener in the child process."""
    _CheckpointListener(control_fd, save_fn).start()


# --- Parent side ---

def request_app_state(control_fd: int) -> bytes:
    """Trigger save_fn in the child and receive app state bytes.

    Args:
        control_fd: Parent's end of the control socket.

    Returns:
        Raw bytes from the child's save_fn.

    Raises:
        RuntimeError: If save_fn failed in the child.
    """
    os.write(control_fd, TRIGGER_CHECKPOINT)
    response = _recv_bytes(control_fd)
    if len(response) == 0:
        raise RuntimeError("Empty checkpoint response")
    status = response[0]
    payload = response[1:]
    if status == _STATUS_OK:
        return payload
    elif status == _STATUS_ERR:
        raise RuntimeError(
            f"save_fn failed in child: {payload.decode('utf-8', errors='replace')}"
        )
    else:
        raise RuntimeError(f"Unknown response status: {status}")
