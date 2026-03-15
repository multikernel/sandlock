# SPDX-License-Identifier: Apache-2.0
"""Transparent process state capture via ptrace and /proc.

Dumps registers, memory layout, memory contents, and file descriptors
from a **frozen** child process.  The child does not need to cooperate
or even know it's being checkpointed.

Used by ``Sandbox.checkpoint()`` to capture OS-level state.
App-level state (open sockets, epoll, etc.) is optionally captured
by a user-provided save_fn via the control socket.

Requires:
- The target process must be a direct child (or ptrace-attachable).
- The process should be stopped (SIGSTOP) before dumping to
  guarantee a consistent snapshot.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import re
import struct
from dataclasses import dataclass, field
from typing import Optional

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# ptrace constants
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207
PTRACE_DETACH = 17
PTRACE_GETREGSET = 0x4204

# NT_PRSTATUS — general-purpose registers
NT_PRSTATUS = 1

# iovec for PTRACE_GETREGSET
class _Iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


def _ptrace(request: int, pid: int, addr: int = 0, data: int = 0) -> int:
    """Raw ptrace(2) syscall wrapper."""
    ret = _libc.ptrace(
        ctypes.c_long(request),
        ctypes.c_long(pid),
        ctypes.c_long(addr),
        ctypes.c_long(data),
    )
    if ret == -1:
        err = ctypes.get_errno()
        if err != 0:
            raise OSError(err, f"ptrace({request}, {pid}): {os.strerror(err)}")
    return ret


# --- Register buffer sizes per architecture ---

_MACHINE = platform.machine()

if _MACHINE == "x86_64":
    _REGSET_SIZE = 27 * 8  # struct user_regs_struct: 27 u64 fields = 216 bytes
elif _MACHINE == "aarch64":
    _REGSET_SIZE = 34 * 8  # 31 GPRs + SP + PC + PSTATE = 272 bytes
else:
    _REGSET_SIZE = 256  # Conservative fallback


# --- Data classes for process state ---

@dataclass
class RegisterState:
    """Raw register contents as bytes (architecture-dependent)."""
    arch: str
    data: bytes


@dataclass
class MemoryRegion:
    """One contiguous virtual memory mapping."""
    start: int
    end: int
    perms: str        # "rwxp" or "r--s" etc.
    offset: int       # File offset
    path: str         # Mapped file path, or "" for anonymous
    contents: bytes   # Raw memory contents

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class FileDescriptor:
    """An open file descriptor."""
    fd: int
    path: str         # Symlink target of /proc/<pid>/fd/<n>
    flags: int        # O_RDONLY, O_WRONLY, etc.
    offset: int       # File position
    restorable: bool  # True if this is a regular file or device


@dataclass
class ThreadState:
    """State of one thread."""
    tid: int
    registers: RegisterState


@dataclass
class ProcessState:
    """Complete capturable state of a process."""
    pid: int
    threads: list[ThreadState] = field(default_factory=list)
    memory: list[MemoryRegion] = field(default_factory=list)
    fds: list[FileDescriptor] = field(default_factory=list)
    cwd: str = ""
    exe: str = ""


# --- Dumping ---

def _get_registers(pid: int) -> bytes:
    """Read general-purpose registers via PTRACE_GETREGSET."""
    buf = ctypes.create_string_buffer(_REGSET_SIZE)
    iov = _Iovec()
    iov.iov_base = ctypes.addressof(buf)
    iov.iov_len = _REGSET_SIZE

    _ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, ctypes.addressof(iov))
    return buf.raw[:iov.iov_len]


def _read_memory_region(pid: int, start: int, size: int) -> bytes:
    """Read a memory region from /proc/<pid>/mem."""
    try:
        fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        try:
            return os.pread(fd, size, start)
        finally:
            os.close(fd)
    except OSError:
        return b""  # Unreadable region (e.g., [vvar], guard pages)


_MAPS_RE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+"  # start-end
    r"([rwxsp-]+)\s+"                # perms
    r"([0-9a-f]+)\s+"               # offset
    r"[0-9a-f]+:[0-9a-f]+\s+"       # dev
    r"\d+\s*"                        # inode
    r"(.*)$"                         # pathname
)


def _parse_maps(pid: int) -> list[tuple[int, int, str, int, str]]:
    """Parse /proc/<pid>/maps into (start, end, perms, offset, path) tuples."""
    regions = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                m = _MAPS_RE.match(line.strip())
                if m:
                    start = int(m.group(1), 16)
                    end = int(m.group(2), 16)
                    perms = m.group(3)
                    offset = int(m.group(4), 16)
                    path = m.group(5).strip()
                    regions.append((start, end, perms, offset, path))
    except OSError:
        pass
    return regions


def _dump_fds(pid: int) -> list[FileDescriptor]:
    """Read open file descriptors from /proc/<pid>/fd/."""
    fds = []
    fd_dir = f"/proc/{pid}/fd"
    try:
        entries = os.listdir(fd_dir)
    except OSError:
        return fds

    for entry in sorted(entries, key=lambda x: int(x) if x.isdigit() else 0):
        if not entry.isdigit():
            continue
        fd_num = int(entry)
        try:
            path = os.readlink(f"{fd_dir}/{fd_num}")
        except OSError:
            continue

        # Read fdinfo for flags and offset
        flags = 0
        offset = 0
        try:
            with open(f"/proc/{pid}/fdinfo/{fd_num}") as f:
                for line in f:
                    if line.startswith("pos:"):
                        offset = int(line.split(":", 1)[1].strip())
                    elif line.startswith("flags:"):
                        flags = int(line.split(":", 1)[1].strip(), 8)
        except OSError:
            pass

        # Regular files and some devices are restorable
        restorable = (
            not path.startswith("pipe:")
            and not path.startswith("socket:")
            and not path.startswith("anon_inode:")
        )

        fds.append(FileDescriptor(
            fd=fd_num, path=path, flags=flags,
            offset=offset, restorable=restorable,
        ))

    return fds


def _list_threads(pid: int) -> list[int]:
    """List thread IDs from /proc/<pid>/task/."""
    try:
        return [int(t) for t in os.listdir(f"/proc/{pid}/task") if t.isdigit()]
    except OSError:
        return [pid]


# Regions to skip during memory dump (kernel-managed, not restorable)
_SKIP_REGIONS = {"[vvar]", "[vdso]", "[vsyscall]"}


def dump_process_state(pid: int) -> ProcessState:
    """Capture the full OS-level state of a frozen process.

    The process must be stopped (SIGSTOP or ptrace-stopped)
    before calling this.  Does NOT freeze/unfreeze — caller manages that.

    Steps:
        1. ptrace SEIZE + INTERRUPT (stop all threads)
        2. Read registers for each thread
        3. Read /proc/<pid>/maps + memory contents
        4. Read /proc/<pid>/fd/ + fdinfo/
        5. ptrace DETACH

    Args:
        pid: Process ID to dump.

    Returns:
        ProcessState with all captured state.
    """
    state = ProcessState(pid=pid)

    # Read cwd and exe before ptrace (doesn't require stop)
    try:
        state.cwd = os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        pass
    try:
        state.exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass

    # Attach via SEIZE (doesn't stop the process)
    _ptrace(PTRACE_SEIZE, pid)
    try:
        # INTERRUPT to stop all threads for consistent reads
        _ptrace(PTRACE_INTERRUPT, pid)
        os.waitpid(pid, 0)  # Wait for stop

        # Dump registers for each thread
        tids = _list_threads(pid)
        for tid in tids:
            try:
                regs = _get_registers(tid)
                state.threads.append(ThreadState(
                    tid=tid,
                    registers=RegisterState(arch=_MACHINE, data=regs),
                ))
            except OSError:
                pass  # Thread may have exited

        # Dump memory
        for start, end, perms, offset, path in _parse_maps(pid):
            if path in _SKIP_REGIONS:
                continue
            # Only dump readable regions
            if "r" not in perms:
                continue
            contents = _read_memory_region(pid, start, end - start)
            state.memory.append(MemoryRegion(
                start=start, end=end, perms=perms,
                offset=offset, path=path, contents=contents,
            ))

        # Dump file descriptors
        state.fds = _dump_fds(pid)

    finally:
        try:
            _ptrace(PTRACE_DETACH, pid)
        except OSError:
            pass

    return state
