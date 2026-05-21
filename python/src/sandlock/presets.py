# SPDX-License-Identifier: Apache-2.0
"""Preset Handler classes for common interception patterns.

Imported explicitly:

    from sandlock.presets import AuditPathsHandler, PathDenyHandler, \
        PathAllowListHandler, LogSyscallsHandler, COMMON_PATH_SYSCALLS

The root ``sandlock`` package deliberately does not re-export these — the
root surface stays minimal; callers reach for presets when they want them.
"""

from __future__ import annotations

import errno as _errno
import fnmatch
import logging
from typing import Callable

from .handler import ExceptionPolicy, Handler, HandlerCtx, NotifAction


# Modern path-bearing syscalls a generic file-operation handler is typically
# registered against. Used with a list comprehension:
#
#     sb.run_with_handlers(cmd, [(s, handler) for s in COMMON_PATH_SYSCALLS])
COMMON_PATH_SYSCALLS: list[str] = [
    "openat", "unlinkat", "newfstatat", "statx", "faccessat",
    "readlinkat", "mkdirat", "execveat", "execve",
]


class AuditPathsHandler(Handler):
    """Call ``callback(path, ctx)`` on every intercepted path syscall.

    ``on_exception=CONTINUE`` — audit must never block the child. ``path``
    is whatever :meth:`HandlerCtx.read_path` returns for the syscall; the
    callback is invoked even when it is ``None`` so the caller sees
    "couldn't read".
    """

    on_exception = ExceptionPolicy.CONTINUE

    def __init__(
        self,
        callback: Callable[[str | None, HandlerCtx], None],
        max_len: int = 4096,
    ) -> None:
        self.callback = callback
        self.max_len = max_len

    def handle(self, ctx: HandlerCtx) -> NotifAction:
        path = ctx.read_path(max_len=self.max_len)
        self.callback(path, ctx)
        return NotifAction.continue_()


class PathDenyHandler(Handler):
    """Deny syscalls whose path matches any ``fnmatch`` pattern in ``deny``.

    ``on_exception=KILL`` — security handler, fail-closed if it itself errors.

    The ``path is None`` case is deliberately permissive: a deny-list does
    not claim "everything else is allowed", only "these patterns are
    denied". When the path cannot be classified we defer to Landlock and
    any other handlers in the chain (``continue_()``).

    Patterns are tested in the order given; the first match wins.
    """

    on_exception = ExceptionPolicy.KILL

    def __init__(
        self,
        deny: list[str],
        errno: int = _errno.EPERM,
        max_len: int = 4096,
    ) -> None:
        if not isinstance(deny, list):
            raise TypeError(
                f"deny must be a list of str patterns, got {type(deny).__name__}"
            )
        self.deny = deny
        self.errno = errno
        self.max_len = max_len

    def handle(self, ctx: HandlerCtx) -> NotifAction:
        path = ctx.read_path(max_len=self.max_len)
        if path is None:
            return NotifAction.continue_()
        for pattern in self.deny:
            if fnmatch.fnmatchcase(path, pattern):
                return NotifAction.errno(self.errno)
        return NotifAction.continue_()
