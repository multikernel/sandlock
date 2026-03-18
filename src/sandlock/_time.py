# SPDX-License-Identifier: Apache-2.0
"""Deterministic time via clock offset.

Intercepts clock_gettime() and gettimeofday() and shifts wall/monotonic
clocks by a fixed offset so the sandbox sees time starting from a
user-specified epoch. Process CPU time clocks are not affected.
"""

from __future__ import annotations

import struct
import time

from ._seccomp import _SYSCALL_NR
from ._procfs import write_bytes

NR_CLOCK_GETTIME = _SYSCALL_NR.get("clock_gettime")
NR_GETTIMEOFDAY = _SYSCALL_NR.get("gettimeofday")

# Clocks that should be shifted (wall time and monotonic)
_SHIFTED_CLOCKS = {
    0,   # CLOCK_REALTIME
    1,   # CLOCK_MONOTONIC
    4,   # CLOCK_MONOTONIC_RAW
    5,   # CLOCK_REALTIME_COARSE
    6,   # CLOCK_MONOTONIC_COARSE
    7,   # CLOCK_BOOTTIME
}

TIME_NRS = {NR_CLOCK_GETTIME, NR_GETTIMEOFDAY} - {None}


class TimeOffset:
    """Fixed time offset computed at sandbox start."""

    def __init__(self, start_timestamp: float):
        now = time.time()
        self._offset_s = start_timestamp - now

    @property
    def offset_ns(self) -> int:
        """Offset in nanoseconds."""
        return int(self._offset_s * 1_000_000_000)


def handle_time(notif, nr: int, offset: TimeOffset,
                id_valid, respond_val, respond_continue) -> None:
    """Handle clock_gettime/gettimeofday — shift time by fixed offset."""
    if nr == NR_CLOCK_GETTIME:
        clockid = notif.data.args[0] & 0xFFFFFFFF
        tp_addr = notif.data.args[1]

        if clockid not in _SHIFTED_CLOCKS:
            respond_continue(notif.id)
            return

        # Get real time from the appropriate clock
        if clockid in (0, 5):  # CLOCK_REALTIME variants
            now = time.time()
        else:
            now = time.monotonic()

        fake = now + offset._offset_s
        sec = int(fake)
        nsec = int((fake - sec) * 1_000_000_000)
        if nsec < 0:
            sec -= 1
            nsec += 1_000_000_000

        packed = struct.pack("<qQ", sec, nsec)

        if not id_valid(notif.id):
            return

        try:
            write_bytes(notif.pid, tp_addr, packed)
            respond_val(notif.id, 0)
        except OSError:
            respond_continue(notif.id)

    elif nr == NR_GETTIMEOFDAY:
        tv_addr = notif.data.args[0]

        if tv_addr == 0:
            respond_continue(notif.id)
            return

        now = time.time()
        fake = now + offset._offset_s
        sec = int(fake)
        usec = int((fake - sec) * 1_000_000)
        if usec < 0:
            sec -= 1
            usec += 1_000_000

        packed = struct.pack("<qQ", sec, usec)

        if not id_valid(notif.id):
            return

        try:
            write_bytes(notif.pid, tv_addr, packed)
            respond_val(notif.id, 0)
        except OSError:
            respond_continue(notif.id)

    else:
        respond_continue(notif.id)
