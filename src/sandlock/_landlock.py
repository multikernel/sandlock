# SPDX-License-Identifier: Apache-2.0
"""Landlock LSM bindings for filesystem confinement.

Provides unprivileged, per-process filesystem confinement using
Linux Landlock (5.13+).  No namespaces or capabilities required — any
process can self-confine.

Generalized from branching's ``confine_to_branch()`` to support
explicit path lists: writable, readable, and denied paths.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
from pathlib import Path

from .exceptions import ConfinementError, LandlockUnavailableError

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# Landlock syscall numbers (asm-generic, same on all architectures)
__NR_landlock_create_ruleset = 444
__NR_landlock_add_rule = 445
__NR_landlock_restrict_self = 446

# --- Access flags (ABI v1–v5) ---

LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13        # ABI v2
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14     # ABI v3
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15    # ABI v5

# All write-like operations (anything that mutates the filesystem).
_WRITE_ACCESS = (
    LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE
)

LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_RULE_NET_PORT = 2          # ABI v4
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

# --- Network access flags (ABI v4, Linux 6.7+) ---

LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1

# --- IPC scoping flags (ABI v6, Linux 6.12+) ---

LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
LANDLOCK_SCOPE_SIGNAL = 1 << 1

# Read access flags
_READ_ACCESS = (
    LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
)

# Full access (read + write)
_FULL_ACCESS = _READ_ACCESS | _WRITE_ACCESS


# --- Structs ---

class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _LandlockNetPortAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    ]


# --- Low-level wrappers ---

def _create_ruleset(
    handled_access_fs: int,
    handled_access_net: int = 0,
    scoped: int = 0,
) -> int:
    """Create a Landlock ruleset and return its fd."""
    attr = _LandlockRulesetAttr(
        handled_access_fs=handled_access_fs,
        handled_access_net=handled_access_net,
        scoped=scoped,
    )
    fd = _libc.syscall(
        __NR_landlock_create_ruleset,
        ctypes.byref(attr),
        ctypes.c_size_t(ctypes.sizeof(attr)),
        ctypes.c_uint32(0),
    )
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"landlock_create_ruleset: {os.strerror(err)}")
    return fd


def _add_path_rule(ruleset_fd: int, allowed_access: int, path: Path) -> None:
    """Add a path-beneath rule to a Landlock ruleset."""
    fd_flags = os.O_PATH
    if path.is_dir():
        fd_flags |= os.O_DIRECTORY
    dir_fd = os.open(str(path), fd_flags)
    try:
        rule = _LandlockPathBeneathAttr(
            allowed_access=allowed_access,
            parent_fd=dir_fd,
        )
        ret = _libc.syscall(
            __NR_landlock_add_rule,
            ctypes.c_int(ruleset_fd),
            ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH),
            ctypes.byref(rule),
            ctypes.c_uint32(0),
        )
        if ret < 0:
            err = ctypes.get_errno()
            raise OSError(err, f"landlock_add_rule({path}): {os.strerror(err)}")
    finally:
        os.close(dir_fd)


def _add_net_port_rule(ruleset_fd: int, allowed_access: int, port: int) -> None:
    """Add a net-port rule to a Landlock ruleset (ABI v4+)."""
    rule = _LandlockNetPortAttr(allowed_access=allowed_access, port=port)
    ret = _libc.syscall(
        __NR_landlock_add_rule,
        ctypes.c_int(ruleset_fd),
        ctypes.c_int(LANDLOCK_RULE_NET_PORT),
        ctypes.byref(rule),
        ctypes.c_uint32(0),
    )
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"landlock_add_rule(net_port={port}): {os.strerror(err)}")


def _restrict_self(ruleset_fd: int) -> None:
    """Apply a Landlock ruleset to the current process."""
    ret = _libc.syscall(
        __NR_landlock_restrict_self,
        ctypes.c_int(ruleset_fd),
        ctypes.c_uint32(0),
    )
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"landlock_restrict_self: {os.strerror(err)}")


def _set_no_new_privs() -> None:
    """Set PR_SET_NO_NEW_PRIVS — required before landlock_restrict_self."""
    PR_SET_NO_NEW_PRIVS = 38
    ret = _libc.prctl(
        ctypes.c_int(PR_SET_NO_NEW_PRIVS),
        ctypes.c_ulong(1),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"prctl(PR_SET_NO_NEW_PRIVS): {os.strerror(err)}")


def landlock_abi_version() -> int:
    """Return the highest Landlock ABI version supported by the kernel.

    Returns 0 if Landlock is not supported.
    """
    ver = _libc.syscall(
        __NR_landlock_create_ruleset,
        ctypes.c_void_p(None),
        ctypes.c_size_t(0),
        ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
    )
    if ver < 0:
        return 0
    return ver


# --- Public API ---

def confine(
    *,
    writable: list[str] | None = None,
    readable: list[str] | None = None,
    denied: list[str] | None = None,
    bind_ports: list[int] | None = None,
    connect_ports: list[int] | None = None,
    isolate_ipc: bool = False,
    isolate_signals: bool = False,
) -> None:
    """Confine the current process using Landlock.

    After this call the process (and any children it forks) is restricted
    to the specified paths and network ports.  This is irreversible.

    Args:
        writable: Paths with full read+write access.
        readable: Paths with read-only access (execute + read).
        denied: Paths explicitly denied.
        bind_ports: TCP ports the process may bind.  ``None`` means
            unrestricted; an empty list blocks all binds.
        connect_ports: TCP ports the process may connect to.  ``None``
            means unrestricted; an empty list blocks all connects.
        isolate_ipc: Block connections to abstract UNIX sockets
            outside the sandbox domain (ABI v6+, Linux 6.12+).
        isolate_signals: Block sending signals to processes
            outside the sandbox domain (ABI v6+, Linux 6.12+).

    Raises:
        LandlockUnavailableError: If Landlock is not supported.
        ConfinementError: If confinement setup fails, or if network/IPC
            features are requested but the kernel's Landlock ABI is too old.
    """
    abi = landlock_abi_version()
    if abi < 1:
        raise LandlockUnavailableError(
            "Landlock not available. Requires Linux 5.13+ with "
            "CONFIG_SECURITY_LANDLOCK=y and lsm=...,landlock,..."
        )

    # Build ABI-aware filesystem access masks
    write = _WRITE_ACCESS
    if abi < 2:
        write &= ~LANDLOCK_ACCESS_FS_REFER
    if abi < 3:
        write &= ~LANDLOCK_ACCESS_FS_TRUNCATE

    read = _READ_ACCESS
    full = read | write
    handled_fs = full

    # Network handled mask (ABI v4+)
    handled_net = 0
    if bind_ports is not None or connect_ports is not None:
        if abi < 4:
            raise ConfinementError(
                f"Network port restrictions require Landlock ABI >= 4 "
                f"(Linux >= 6.7), but this kernel only supports ABI v{abi}"
            )
        if bind_ports is not None:
            handled_net |= LANDLOCK_ACCESS_NET_BIND_TCP
        if connect_ports is not None:
            handled_net |= LANDLOCK_ACCESS_NET_CONNECT_TCP

    # IPC scoping mask (ABI v6+)
    scoped = 0
    if isolate_ipc or isolate_signals:
        if abi < 6:
            raise ConfinementError(
                f"IPC/signal isolation requires Landlock ABI >= 6 "
                f"(Linux >= 6.12), but this kernel only supports ABI v{abi}"
            )
        if isolate_ipc:
            scoped |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
        if isolate_signals:
            scoped |= LANDLOCK_SCOPE_SIGNAL

    writable = writable or []
    readable = readable or []
    has_fs = bool(writable or readable or denied)
    has_net = handled_net != 0
    has_scope = scoped != 0

    if not has_fs and not has_net and not has_scope:
        return  # Nothing to confine

    denied_set = set(os.path.realpath(p) for p in (denied or []))

    ruleset_fd = _create_ruleset(handled_fs if has_fs else 0, handled_net, scoped)
    try:
        # Filesystem rules
        if has_fs:
            for p in writable:
                rp = os.path.realpath(p)
                if rp in denied_set:
                    continue
                path = Path(rp)
                if path.exists():
                    _add_path_rule(ruleset_fd, full, path)

            for p in readable:
                rp = os.path.realpath(p)
                if rp in denied_set:
                    continue
                path = Path(rp)
                if path.exists():
                    _add_path_rule(ruleset_fd, read, path)

        # Network port rules (ABI v4+)
        if has_net:
            for port in (bind_ports or []):
                _add_net_port_rule(
                    ruleset_fd, LANDLOCK_ACCESS_NET_BIND_TCP, port,
                )
            for port in (connect_ports or []):
                _add_net_port_rule(
                    ruleset_fd, LANDLOCK_ACCESS_NET_CONNECT_TCP, port,
                )

        _set_no_new_privs()
        _restrict_self(ruleset_fd)
    except LandlockUnavailableError:
        raise
    except OSError as e:
        raise ConfinementError(f"Landlock confinement failed: {e}") from e
    finally:
        os.close(ruleset_fd)
