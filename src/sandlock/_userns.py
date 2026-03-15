# SPDX-License-Identifier: Apache-2.0
"""User namespace helpers for privileged mode.

Sandlock uses CLONE_NEWUSER to create a new user namespace for
privileged mode (UID 0 mapping inside the sandbox).

This module only creates user namespaces — no PID, network, or mount
namespaces are created.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

CLONE_NEWUSER = 0x10000000


def setup_userns_in_parent(child_pid: int, privileged: bool = False) -> None:
    """Write UID/GID maps for a child that has unshared CLONE_NEWUSER.

    Must be called from the parent process — writing uid_map/gid_map
    requires CAP_SETUID/CAP_SETGID in the parent user namespace.

    Args:
        child_pid: PID of the child that called unshare(CLONE_NEWUSER).
        privileged: If True, map UID 0 inside. If False, identity map.
    """
    uid = os.getuid()
    gid = os.getgid()
    inner_uid = 0 if privileged else uid
    inner_gid = 0 if privileged else gid

    _write_setgroups_deny_for(child_pid)
    _write_id_map(f"/proc/{child_pid}/uid_map", inner_uid, uid, 1)
    _write_id_map(f"/proc/{child_pid}/gid_map", inner_gid, gid, 1)


def unshare_user() -> None:
    """Create a new user namespace via unshare(2).

    After this call (and after the parent writes uid/gid maps),
    the process has CAP_SYS_ADMIN in the new user namespace.

    Raises:
        OSError: If unshare fails (e.g. kernel.unprivileged_userns_clone=0).
    """
    ret = _libc.unshare(ctypes.c_int(CLONE_NEWUSER))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"unshare(NEWUSER): {os.strerror(err)}")


def userns_available() -> bool:
    """Check if unprivileged user namespaces are available."""
    try:
        # Check sysctl
        try:
            val = open("/proc/sys/kernel/unprivileged_userns_clone").read().strip()
            if val == "0":
                return False
        except FileNotFoundError:
            pass  # Sysctl doesn't exist — namespaces are allowed

        # Try a real unshare in a forked child to be sure
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            try:
                ret = _libc.unshare(ctypes.c_int(CLONE_NEWUSER))
                os.write(w, b"1" if ret == 0 else b"0")
            except Exception:
                os.write(w, b"0")
            finally:
                os.close(w)
                os._exit(0)
        else:
            os.close(w)
            data = os.read(r, 1)
            os.close(r)
            os.waitpid(pid, 0)
            return data == b"1"
    except Exception:
        return False


def _write_id_map(path: str, inner: int, outer: int, count: int) -> None:
    """Write a UID/GID mapping."""
    with open(path, "w") as f:
        f.write(f"{inner} {outer} {count}\n")


def _write_setgroups_deny() -> None:
    """Deny setgroups — required before writing gid_map."""
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny\n")


def _write_setgroups_deny_for(pid: int) -> None:
    """Deny setgroups for another process."""
    with open(f"/proc/{pid}/setgroups", "w") as f:
        f.write("deny\n")
