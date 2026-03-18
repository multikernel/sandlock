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
NR_TIME = _SYSCALL_NR.get("time")
NR_CLOCK_NANOSLEEP = _SYSCALL_NR.get("clock_nanosleep")
NR_TIMERFD_SETTIME = _SYSCALL_NR.get("timerfd_settime")
NR_TIMER_SETTIME = _SYSCALL_NR.get("timer_settime")

# Clocks that should be shifted (wall time only).
_SHIFTED_CLOCKS = {
    0,   # CLOCK_REALTIME
    5,   # CLOCK_REALTIME_COARSE
}

# Clocks whose monotonic offset is applied in the vDSO stub.
# clock_nanosleep with TIMER_ABSTIME needs the deadline un-shifted.
_MONO_SHIFTED_CLOCKS = {
    1,   # CLOCK_MONOTONIC
    4,   # CLOCK_MONOTONIC_RAW
    6,   # CLOCK_MONOTONIC_COARSE
    7,   # CLOCK_BOOTTIME
}

TIMER_ABSTIME = 1

TIME_NRS = {NR_CLOCK_GETTIME, NR_GETTIMEOFDAY, NR_TIME,
            NR_CLOCK_NANOSLEEP, NR_TIMERFD_SETTIME,
            NR_TIMER_SETTIME} - {None}


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
                id_valid, respond_val, respond_continue,
                mono_offset_s: int = 0) -> None:
    """Handle clock_gettime/gettimeofday/time/clock_nanosleep."""
    if nr == NR_CLOCK_GETTIME:
        clockid = notif.data.args[0] & 0xFFFFFFFF
        tp_addr = notif.data.args[1]

        if clockid not in _SHIFTED_CLOCKS:
            respond_continue(notif.id)
            return

        # Get real wall time (only REALTIME clocks reach here)
        now = time.time()

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

    elif nr == NR_TIME:
        tloc_addr = notif.data.args[0]
        now = time.time()
        fake = int(now + offset._offset_s)

        if not id_valid(notif.id):
            return

        if tloc_addr != 0:
            try:
                write_bytes(notif.pid, tloc_addr, struct.pack("<q", fake))
            except OSError:
                respond_continue(notif.id)
                return

        respond_val(notif.id, fake)

    elif nr == NR_CLOCK_NANOSLEEP:
        # clock_nanosleep(clockid, flags, request, remain)
        # When TIMER_ABSTIME is set and clockid is a vDSO-shifted
        # monotonic clock, the process computed the deadline using
        # the shifted clock.  Un-shift it before the kernel sees it.
        clockid = notif.data.args[0] & 0xFFFFFFFF
        flags = notif.data.args[1]
        req_addr = notif.data.args[2]

        if not (flags & TIMER_ABSTIME) or clockid not in _MONO_SHIFTED_CLOCKS:
            respond_continue(notif.id)
            return

        # Read the shifted deadline, un-shift, write back
        from ._procfs import read_bytes as _read_bytes
        try:
            data = _read_bytes(notif.pid, req_addr, 16)
            sec, nsec = struct.unpack("<qQ", data)
            sec -= mono_offset_s
            write_bytes(notif.pid, req_addr, struct.pack("<qQ", sec, nsec))
        except OSError:
            pass

        respond_continue(notif.id)

    elif nr == NR_TIMERFD_SETTIME:
        # timerfd_settime(fd, flags, new_value, old_value)
        # new_value is struct itimerspec: {it_interval(16), it_value(16)}
        # When TFD_TIMER_ABSTIME (1) is set, un-shift it_value.
        flags = notif.data.args[1]
        new_value_addr = notif.data.args[2]

        if not (flags & TIMER_ABSTIME):
            respond_continue(notif.id)
            return

        from ._procfs import read_bytes as _read_bytes
        try:
            # it_value starts at offset 16 in itimerspec
            val_addr = new_value_addr + 16
            data = _read_bytes(notif.pid, val_addr, 16)
            sec, nsec = struct.unpack("<qQ", data)
            sec -= mono_offset_s
            write_bytes(notif.pid, val_addr, struct.pack("<qQ", sec, nsec))
        except OSError:
            pass

        respond_continue(notif.id)

    elif nr == NR_TIMER_SETTIME:
        # timer_settime(timerid, flags, new_value, old_value)
        # Same itimerspec layout as timerfd_settime.
        flags = notif.data.args[1]
        new_value_addr = notif.data.args[2]

        if not (flags & TIMER_ABSTIME):
            respond_continue(notif.id)
            return

        from ._procfs import read_bytes as _read_bytes
        try:
            val_addr = new_value_addr + 16
            data = _read_bytes(notif.pid, val_addr, 16)
            sec, nsec = struct.unpack("<qQ", data)
            sec -= mono_offset_s
            write_bytes(notif.pid, val_addr, struct.pack("<qQ", sec, nsec))
        except OSError:
            pass

        respond_continue(notif.id)

    else:
        respond_continue(notif.id)
