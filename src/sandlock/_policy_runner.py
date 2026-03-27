# SPDX-License-Identifier: Apache-2.0
"""Policy coroutine runner.

Runs the user's ``policy_fn`` async generator on a daemon thread,
feeding it :class:`SyscallEvent` objects from the supervisor's event
queue and applying ``ctx.grant()`` / ``ctx.restrict()`` calls.

For syscalls in ``NotifSupervisor._HOLD_SYSCALLS``, the supervisor
blocks until the policy_fn has processed the event.  This is done
via a ``threading.Event`` (gate) attached to each queued item.  The
runner sets the gate after the policy_fn's ``async for`` body runs,
so any ``grant()`` / ``restrict()`` call takes effect before the
child resumes.
"""

from __future__ import annotations

import asyncio
import logging
import queue as _queue_mod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._events import SyscallEvent
    from ._policy_ctx import PolicyContext

logger = logging.getLogger(__name__)


def run_policy_fn(
    policy_fn,
    event_queue: _queue_mod.SimpleQueue,
    ctx: PolicyContext,
) -> None:
    """Run the user's async policy function (target for daemon thread).

    The function receives an async event stream and the policy context.
    It runs until the event stream is exhausted (sandbox exited) or
    the coroutine returns/raises.
    """

    async def _run() -> None:
        async def event_stream():
            loop = asyncio.get_event_loop()
            while True:
                try:
                    event, gate = await loop.run_in_executor(
                        None, _blocking_get, event_queue, ctx,
                    )
                except (_StreamDone, RuntimeError):
                    # RuntimeError: executor shutdown during asyncio teardown
                    return
                try:
                    yield event
                finally:
                    # Release the gate AFTER the policy_fn's async-for body
                    # has run — any grant/restrict calls have taken effect.
                    if gate is not None:
                        gate.set()

        try:
            await policy_fn(event_stream(), ctx)
        except Exception:
            logger.exception("policy_fn raised an exception")
        finally:
            # The policy_fn has returned — stop holding future events
            # and release any gates already queued.
            ctx._supervisor._policy_fn_done = True
            _drain_gates(event_queue)

    asyncio.run(_run())


def _drain_gates(q: _queue_mod.SimpleQueue) -> None:
    """Release all pending gates in the queue."""
    while True:
        try:
            item = q.get_nowait()
        except _queue_mod.Empty:
            return
        if item is None:
            return
        _, gate = item
        if gate is not None:
            gate.set()


class _StreamDone(Exception):
    """Sentinel: the supervisor has stopped and the queue is drained."""


def _blocking_get(q, ctx):
    """Blocking get that handles poison pill and liveness checks.

    Returns ``(SyscallEvent, gate)`` or raises ``_StreamDone``.
    """
    while True:
        try:
            item = q.get_nowait()
        except _queue_mod.Empty:
            pass
        else:
            if item is None:  # poison pill from supervisor.stop()
                raise _StreamDone
            return item  # (event, gate) tuple

        if not ctx._supervisor.alive:
            raise _StreamDone

        import time
        time.sleep(0.05)
