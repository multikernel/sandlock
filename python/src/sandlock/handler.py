# SPDX-License-Identifier: Apache-2.0
"""Python wrapper for the sandlock Handler ABI.

The C ABI (see ``crates/sandlock-ffi/include/sandlock.h``) is mapped via
ctypes; this module exposes a pythonic Handler base class and a
NotifAction value-object.

The wrapper is strictly minimal — ergonomic helpers (path readers,
preset handlers, asyncio adapters) are deferred to a follow-up.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


# Discriminant values mirror SANDLOCK_ACTION_* in sandlock.h.
class _ActionKind(enum.IntEnum):
    UNSET = 0
    CONTINUE = 1
    ERRNO = 2
    RETURN_VALUE = 3
    INJECT_FD_SEND = 4
    INJECT_FD_SEND_TRACKED = 5  # reserved; setter not exposed
    HOLD = 6
    KILL = 7


@dataclass(frozen=True)
class NotifAction:
    """Decision returned from a Python ``Handler.handle`` call.

    Construct via the factory classmethods (``NotifAction.continue_()``,
    ``NotifAction.errno(13)``, etc.); do not instantiate directly.

    Field semantics depend on ``kind``:

    - CONTINUE: no payload fields used.
    - ERRNO: ``errno_value`` set.
    - RETURN_VALUE: ``return_value`` set (factory: ``return_value_``).
    - INJECT_FD_SEND: ``srcfd``, ``newfd_flags`` set; the supervisor
      takes ownership of the fd on dispatch.
    - HOLD: no payload fields used.
    - KILL: ``sig``, ``pgid`` set. ``pgid == 0`` substitutes the
      supervisor-resolved child pgid; if the supervisor cannot safely
      resolve one, the action is refused and the exception policy
      applies.

    ``srcfd`` defaults to ``-1`` (not a valid fd) for every action
    kind other than INJECT_FD_SEND.
    """

    kind: int  # discriminant; values from _ActionKind / sandlock_action_kind_t
    errno_value: int = 0
    return_value: int = 0
    srcfd: int = -1
    newfd_flags: int = 0
    sig: int = 0
    pgid: int = 0

    @classmethod
    def continue_(cls) -> NotifAction:
        return cls(kind=int(_ActionKind.CONTINUE))

    @classmethod
    def errno(cls, value: int) -> NotifAction:
        return cls(kind=int(_ActionKind.ERRNO), errno_value=value)

    @classmethod
    def return_value_(cls, value: int) -> NotifAction:
        return cls(kind=int(_ActionKind.RETURN_VALUE), return_value=value)

    @classmethod
    def hold(cls) -> NotifAction:
        return cls(kind=int(_ActionKind.HOLD))

    @classmethod
    def kill(cls, sig: int, pgid: int = 0) -> NotifAction:
        return cls(kind=int(_ActionKind.KILL), sig=sig, pgid=pgid)

    @classmethod
    def inject_fd_send(cls, srcfd: int, newfd_flags: int = 0) -> NotifAction:
        """Inject a file descriptor into the child.

        Ownership of ``srcfd`` transfers to the supervisor on successful
        dispatch. The Python caller must NOT close ``srcfd`` after
        returning this action, regardless of whether the dispatch
        actually fires (the supervisor handles cleanup on all paths).
        """
        if not isinstance(srcfd, int) or srcfd < 0:
            raise ValueError(
                f"inject_fd_send: srcfd must be a non-negative int, "
                f"got {srcfd!r}"
            )
        return cls(
            kind=int(_ActionKind.INJECT_FD_SEND),
            srcfd=srcfd,
            newfd_flags=newfd_flags,
        )


class ExceptionPolicy(enum.IntEnum):
    """Maps to sandlock_exception_policy_t in the C ABI.

    Applied when a handler's ``handle()`` raises, returns an invalid
    value, or the trampoline cannot reach the Python interpreter
    (e.g. ``Py_FinalizeEx``). See ``crates/sandlock-ffi/include/sandlock.h``
    for the supervisor's exact behaviour per policy.
    """
    KILL = 0
    DENY_EPERM = 1
    CONTINUE = 2
    DENY_EIO = 3


class Handler:
    """Base class for Python sandlock handlers.

    Subclass and override ``handle()``. Optionally override
    ``on_exception`` to choose what the supervisor does when this
    handler errors. Default is ``ExceptionPolicy.KILL`` (fail-closed).

    Lifetime: a Handler instance must outlive any Sandbox run it is
    registered with. The Sandbox holds a Python-side reference for the
    duration of the run; the underlying C container's ``ud_drop``
    releases that reference when the run completes (or fails).

    Concurrency: the supervisor MAY invoke ``handle()`` concurrently for
    the same Handler instance, on different worker threads, for
    different notifications. If ``handle()`` mutates instance state,
    guard it with your own synchronization — the wrapper does not
    serialize handler dispatch.

    Promptness: ``handle()`` must return quickly. It runs synchronously
    inside the supervisor's dispatch path while holding the GIL; a
    handler that blocks (a long sleep, a blocking I/O call, an infinite
    loop) stalls the supervisor and can wedge the entire run.
    """

    on_exception: ExceptionPolicy = ExceptionPolicy.KILL

    def handle(self, ctx: HandlerCtx) -> NotifAction:
        """Override in a subclass to inspect ``ctx`` and return a NotifAction.

        Raising an exception triggers the configured ``on_exception``
        policy. Returning a non-NotifAction value is treated as an
        exception. The default implementation raises NotImplementedError.
        """
        raise NotImplementedError(
            "Handler subclasses must override handle(ctx) -> NotifAction"
        )


class _MemHandle:
    """Mutable wrapper around the opaque child-memory handle.

    The raw ``sandlock_mem_handle_t*`` is valid only for the duration
    of a single ``Handler.handle`` call — it points at a stack local
    in the supervisor. The trampoline invalidates this cell when the
    callback returns, so a HandlerCtx that escapes its ``handle()``
    call fails fast on the next memory access instead of dereferencing
    a dangling pointer.
    """

    __slots__ = ("_ptr", "_live")

    def __init__(self, ptr: object) -> None:
        self._ptr = ptr
        self._live = True

    def invalidate(self) -> None:
        self._live = False
        self._ptr = None

    @property
    def live(self) -> bool:
        return self._live

    @property
    def ptr(self) -> object:
        return self._ptr


@dataclass(frozen=True)
class HandlerCtx:
    """Read-only snapshot of the seccomp notification the supervisor
    received, plus an opaque handle for child-memory access.

    Field names match ``sandlock_notif_data_t`` in the C header. The
    ``_mem_handle`` field is an implementation detail (a ``_MemHandle``
    liveness cell); use ``read_cstr``, ``read``, ``write`` to access
    child memory.

    Do not retain a HandlerCtx beyond the ``handle()`` call — the mem
    handle is valid only for the duration of the callback. The wrapper
    now ENFORCES this: the trampoline invalidates the underlying
    ``_MemHandle`` cell once the callback returns, so a retained
    HandlerCtx fails safe — its memory accessors return ``None`` /
    ``False`` rather than dereferencing a dangling pointer (a
    use-after-free in C).
    """
    id: int
    pid: int
    flags: int
    syscall_nr: int
    arch: int
    instruction_pointer: int
    args: tuple[int, int, int, int, int, int]  # the six syscall args

    # Set by the trampoline to a ``_MemHandle`` liveness cell; opaque to
    # user code. Defaults to None — a HandlerCtx built without one (the
    # trampoline always supplies it) has inert child-memory accessors.
    _mem_handle: object = None

    def read_cstr(self, addr: int, max_len: int) -> str | None:
        """Read a NUL-terminated string from the child at ``addr``.

        Returns the decoded string on success, or None on failure
        (invalid address, target string longer than max_len, race with
        child exit, or no mem handle). ``max_len`` must be at least 1
        to fit the NUL terminator.
        """
        cell = self._mem_handle
        if cell is None or not cell.live:
            return None
        from . import _handler_ffi
        return _handler_ffi.mem_read_cstr(cell.ptr, addr, max_len)

    def read(self, addr: int, length: int) -> bytes | None:
        """Read ``length`` raw bytes from the child at ``addr``.

        Returns bytes on success, or None on failure.
        """
        cell = self._mem_handle
        if cell is None or not cell.live:
            return None
        from . import _handler_ffi
        return _handler_ffi.mem_read(cell.ptr, addr, length)

    def write(self, addr: int, data: bytes) -> bool:
        """Write ``data`` into the child at ``addr``.

        Returns True on success, False on failure.
        """
        cell = self._mem_handle
        if cell is None or not cell.live:
            return False
        from . import _handler_ffi
        return _handler_ffi.mem_write(cell.ptr, addr, data)
