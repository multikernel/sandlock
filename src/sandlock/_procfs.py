# SPDX-License-Identifier: Apache-2.0
"""Helpers for reading child process memory and resolving syscall paths.

Used by the seccomp notification supervisor to read string arguments
(e.g., file paths) from the child's address space via /proc/<pid>/mem.
"""

from __future__ import annotations

import os


def read_cstring(pid: int, addr: int, max_len: int = 4096) -> str:
    """Read a NUL-terminated C string from a child process's memory.

    Args:
        pid: Target process ID.
        addr: Virtual address of the string in the target's address space.
        max_len: Maximum bytes to read.

    Returns:
        The decoded string (UTF-8, replacing errors).

    Raises:
        OSError: If /proc/<pid>/mem cannot be read.
    """
    fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        data = os.pread(fd, max_len, addr)
    finally:
        os.close(fd)
    nul = data.find(b"\0")
    if nul >= 0:
        data = data[:nul]
    return data.decode("utf-8", errors="replace")


def read_argv(pid: int, argv_addr: int, max_args: int = 32) -> tuple[str, ...]:
    """Read a NULL-terminated argv array from a child process's memory.

    Args:
        pid: Target process ID.
        argv_addr: Virtual address of the char** argv pointer array.
        max_args: Maximum number of arguments to read.

    Returns:
        Tuple of decoded argument strings.
    """
    import struct
    fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        args = []
        for i in range(max_args):
            ptr_bytes = os.pread(fd, 8, argv_addr + i * 8)
            if len(ptr_bytes) < 8:
                break
            ptr = struct.unpack("Q", ptr_bytes)[0]
            if ptr == 0:
                break
            data = os.pread(fd, 4096, ptr)
            nul = data.find(b"\0")
            if nul >= 0:
                data = data[:nul]
            args.append(data.decode("utf-8", errors="replace"))
        return tuple(args)
    finally:
        os.close(fd)


def read_bytes(pid: int, addr: int, length: int) -> bytes:
    """Read raw bytes from a child process's memory.

    Args:
        pid: Target process ID.
        addr: Virtual address in the target's address space.
        length: Number of bytes to read.

    Returns:
        The raw bytes.

    Raises:
        OSError: If /proc/<pid>/mem cannot be read.
    """
    fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        return os.pread(fd, length, addr)
    finally:
        os.close(fd)


def write_bytes(pid: int, addr: int, data: bytes) -> None:
    """Write raw bytes to a child process's memory.

    Args:
        pid: Target process ID.
        addr: Virtual address in the target's address space.
        data: Bytes to write.

    Raises:
        OSError: If /proc/<pid>/mem cannot be written.
    """
    fd = os.open(f"/proc/{pid}/mem", os.O_WRONLY)
    try:
        os.pwrite(fd, data, addr)
    finally:
        os.close(fd)


def resolve_openat_path(pid: int, dirfd: int, pathname_addr: int) -> str:
    """Resolve the full path for an openat(dirfd, pathname, ...) call.

    If the pathname is absolute, returns it directly.
    If relative and dirfd == AT_FDCWD (-100), resolves against /proc/<pid>/cwd.
    If relative and dirfd is a real fd, resolves against /proc/<pid>/fd/<dirfd>.

    Args:
        pid: Child process ID.
        dirfd: The dirfd argument from openat().
        pathname_addr: Address of the pathname string in child memory.

    Returns:
        The resolved absolute path.
    """
    AT_FDCWD = -100

    path = read_cstring(pid, pathname_addr)

    if os.path.isabs(path):
        return os.path.normpath(path)

    # Resolve the base directory
    if dirfd == AT_FDCWD or dirfd == AT_FDCWD & 0xFFFFFFFF:
        try:
            base = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            base = "/"
    else:
        try:
            base = os.readlink(f"/proc/{pid}/fd/{dirfd}")
        except OSError:
            base = "/"

    return os.path.normpath(os.path.join(base, path))
