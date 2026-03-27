# SPDX-License-Identifier: Apache-2.0
"""Syscall events emitted by the seccomp notification supervisor.

When a policy coroutine (``policy_fn``) is attached to a sandbox, the
supervisor pushes a :class:`SyscallEvent` for every intercepted syscall.
The coroutine consumes these events and calls ``ctx.grant()`` /
``ctx.restrict()`` to adjust the live policy.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SyscallEvent:
    """An intercepted syscall observed by the notification supervisor.

    Fields are populated based on the syscall type — irrelevant fields
    are ``None``.  Events are immutable facts, never modified after
    creation.
    """

    syscall: str
    """Syscall name (e.g. ``"connect"``, ``"openat"``, ``"clone"``)."""

    pid: int
    """PID of the process that made the syscall."""

    timestamp: float
    """Monotonic timestamp (``time.monotonic()``) when the event was created."""

    path: str | None = None
    """Resolved filesystem path (for ``openat``, ``execve``, etc.)."""

    host: str | None = None
    """Destination IP address (for ``connect``, ``sendto``, ``sendmsg``)."""

    port: int | None = None
    """Destination port (for ``connect``, ``bind``)."""

    size: int | None = None
    """Size argument (for ``mmap``, ``write``, etc.)."""

    argv: tuple[str, ...] | None = None
    """Command arguments (for ``execve`` / ``execveat``)."""

    flags: int = 0
    """Raw syscall flags (e.g. ``O_WRONLY`` for ``openat``)."""

    denied: bool = False
    """Whether the supervisor denied this syscall."""
