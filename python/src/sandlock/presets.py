# SPDX-License-Identifier: Apache-2.0
"""Preset Handler classes for common interception patterns.

Imported explicitly:

    from sandlock.presets import AuditPathsHandler, PathDenyHandler, \
        PathAllowHandler, LogSyscallsHandler, COMMON_PATH_SYSCALLS

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

    ``callback`` may be invoked concurrently on the same handler instance
    from different supervisor worker threads — if it mutates shared state,
    the caller must provide its own synchronization.
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


class PathAllowHandler(Handler):
    """Allow only syscalls whose path matches a pattern in ``allow``; deny others.

    ``on_exception=KILL`` — security handler, fail-closed if it itself errors.

    The ``path is None`` case is deliberately restrictive: an allow-list
    claims "everything except the listed paths is denied", so failing to
    verify the path means failing closed (deny).

    Patterns are tested in the order given; the first match wins.
    """

    on_exception = ExceptionPolicy.KILL

    def __init__(
        self,
        allow: list[str],
        errno: int = _errno.EACCES,
        max_len: int = 4096,
    ) -> None:
        if not isinstance(allow, list):
            raise TypeError(
                f"allow must be a list of str patterns, got {type(allow).__name__}"
            )
        self.allow = allow
        self.errno = errno
        self.max_len = max_len

    def handle(self, ctx: HandlerCtx) -> NotifAction:
        path = ctx.read_path(max_len=self.max_len)
        if path is None:
            return NotifAction.errno(self.errno)
        for pattern in self.allow:
            if fnmatch.fnmatchcase(path, pattern):
                return NotifAction.continue_()
        return NotifAction.errno(self.errno)


class LogSyscallsHandler(Handler):
    """Log each intercepted syscall as one line; never modify behaviour.

    ``on_exception=CONTINUE`` — observational handler. The default logger
    is ``logging.getLogger("sandlock.audit").info``; pass any
    ``Callable[[str], None]`` to redirect (e.g. a list's ``append`` for
    tests).

    If ``logger`` raises, the exception is absorbed by
    ``on_exception=CONTINUE`` — the child proceeds but the log line is
    silently lost.
    """

    on_exception = ExceptionPolicy.CONTINUE

    def __init__(self, logger: Callable[[str], None] | None = None) -> None:
        self.logger = logger or logging.getLogger("sandlock.audit").info

    def handle(self, ctx: HandlerCtx) -> NotifAction:
        self.logger(
            f"syscall={ctx.syscall_nr} pid={ctx.pid} args={ctx.args}"
        )
        return NotifAction.continue_()
