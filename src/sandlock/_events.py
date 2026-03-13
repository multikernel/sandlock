# SPDX-License-Identifier: Apache-2.0
"""BPF ring buffer reader (Phase 4+).

Placeholder for BPF event stream.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EventType(Enum):
    """Types of sandbox events."""

    PROCESS_FORK = "process_fork"
    PROCESS_EXIT = "process_exit"
    SIGNAL_BLOCKED = "signal_blocked"
    PTRACE_BLOCKED = "ptrace_blocked"
    SOCKET_BLOCKED = "socket_blocked"
    CAPABILITY_BLOCKED = "capability_blocked"
    MEMORY_EXCEEDED = "memory_exceeded"
    CPU_EXCEEDED = "cpu_exceeded"
    PIDS_EXCEEDED = "pids_exceeded"


@dataclass
class Event:
    """A sandbox event."""

    type: EventType
    sandbox_id: str
    pid: int
    detail: str = ""
