# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for the sandlock Python handler wrapper."""

from sandlock.handler import ExceptionPolicy, Handler, NotifAction


def test_notif_action_continue_has_continue_kind():
    a = NotifAction.continue_()
    assert a.kind == 1  # SANDLOCK_ACTION_CONTINUE


def test_notif_action_errno_carries_value():
    a = NotifAction.errno(13)
    assert a.kind == 2
    assert a.errno_value == 13


def test_notif_action_kill_carries_sig_and_pgid():
    a = NotifAction.kill(9, 0)
    assert a.kind == 7
    assert a.sig == 9
    assert a.pgid == 0


def test_notif_action_return_value_carries_value():
    a = NotifAction.return_value_(42)
    assert a.kind == 3
    assert a.return_value == 42  # field, not the classmethod


def test_notif_action_inject_fd_send_carries_srcfd():
    a = NotifAction.inject_fd_send(7)
    assert a.kind == 4
    assert a.srcfd == 7
    assert a.newfd_flags == 0


def test_notif_action_inject_fd_send_with_flags():
    a = NotifAction.inject_fd_send(7, newfd_flags=0o2000000)  # O_CLOEXEC
    assert a.srcfd == 7
    assert a.newfd_flags == 0o2000000


def test_notif_action_is_frozen():
    import dataclasses
    a = NotifAction.continue_()
    try:
        a.kind = 999  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("NotifAction must be frozen (immutable)")


def test_exception_policy_enum_values_match_c_header():
    # Must match include/sandlock.h SANDLOCK_EXCEPTION_* discriminants.
    assert ExceptionPolicy.KILL == 0
    assert ExceptionPolicy.DENY_EPERM == 1
    assert ExceptionPolicy.CONTINUE == 2
    assert ExceptionPolicy.DENY_EIO == 3


def test_handler_subclass_has_default_kill_policy():
    class MyHandler(Handler):
        def handle(self, ctx):
            return NotifAction.continue_()

    h = MyHandler()
    assert h.on_exception == ExceptionPolicy.KILL  # fail-closed default


def test_handler_subclass_can_override_exception_policy():
    class AuditHandler(Handler):
        on_exception = ExceptionPolicy.CONTINUE

        def handle(self, ctx):
            return NotifAction.continue_()

    h = AuditHandler()
    assert h.on_exception == ExceptionPolicy.CONTINUE


def test_base_handler_handle_raises_not_implemented():
    h = Handler()
    try:
        h.handle(None)
    except NotImplementedError:
        pass
    else:
        raise AssertionError("base Handler.handle must raise NotImplementedError")


def test_action_kind_enum_values_match_c_header():
    # Must match SANDLOCK_ACTION_* in crates/sandlock-ffi/include/sandlock.h.
    from sandlock.handler import _ActionKind

    assert _ActionKind.UNSET == 0
    assert _ActionKind.CONTINUE == 1
    assert _ActionKind.ERRNO == 2
    assert _ActionKind.RETURN_VALUE == 3
    assert _ActionKind.INJECT_FD_SEND == 4
    assert _ActionKind.INJECT_FD_SEND_TRACKED == 5
    assert _ActionKind.HOLD == 6
    assert _ActionKind.KILL == 7


def test_handler_ctx_exposes_notif_fields():
    from sandlock.handler import HandlerCtx

    # Construct via the test helper; the production constructor is
    # called only from the trampoline.
    ctx = HandlerCtx._for_test(
        id=42, pid=1234, flags=0,
        syscall_nr=39, arch=0xC000003E,
        instruction_pointer=0xDEADBEEF,
        args=(1, 2, 3, 4, 5, 6),
    )
    assert ctx.id == 42
    assert ctx.pid == 1234
    assert ctx.flags == 0
    assert ctx.syscall_nr == 39
    assert ctx.arch == 0xC000003E
    assert ctx.instruction_pointer == 0xDEADBEEF
    assert ctx.args == (1, 2, 3, 4, 5, 6)


def test_handler_ctx_mem_methods_return_falsy_without_handle():
    from sandlock.handler import HandlerCtx

    # _for_test ctx has no mem handle — accessors must degrade safely,
    # not crash.
    ctx = HandlerCtx._for_test(
        id=1, pid=1, flags=0, syscall_nr=0, arch=0,
        instruction_pointer=0, args=(0, 0, 0, 0, 0, 0),
    )
    assert ctx.read_cstr(0x1000, 64) is None
    assert ctx.read(0x1000, 16) is None
    assert ctx.write(0x1000, b"x") is False


def test_handler_ctx_is_frozen():
    import dataclasses

    from sandlock.handler import HandlerCtx

    ctx = HandlerCtx._for_test(
        id=1, pid=1, flags=0, syscall_nr=0, arch=0,
        instruction_pointer=0, args=(0, 0, 0, 0, 0, 0),
    )
    try:
        ctx.pid = 999  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("HandlerCtx must be frozen (immutable)")


# ----------------------------------------------------------------
# End-to-end audit smoke test (RFC #43 §Phasing item 2).
# ----------------------------------------------------------------

import os

import pytest

import sandlock


# Standard readable paths for a sandboxed python3 child, mirroring
# tests/test_sandbox.py's _PYTHON_READABLE helper.
_PYTHON_READABLE = ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"]

# Use a system interpreter that lives inside the readable tree above.
# sys.executable may point at a venv outside the sandbox (e.g. under
# the developer's home directory), which the child cannot exec.
_SYSTEM_PYTHON = "/usr/bin/python3"


class _OpenatCounter(Handler):
    on_exception = ExceptionPolicy.CONTINUE  # audit-only — never block

    def __init__(self):
        self.count = 0

    def handle(self, ctx):
        self.count += 1
        return NotifAction.continue_()


def test_smoke_audit_openat():
    """RFC #43 phasing item 2: audit handler counting SYS_openat."""
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257  # x86_64

    sb = sandlock.Sandbox(fs_readable=_PYTHON_READABLE)
    counter = _OpenatCounter()

    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c",
             "import os\n"
             "for _ in range(3):\n"
             "    fd = os.open('/etc/hostname', os.O_RDONLY)\n"
             "    os.close(fd)\n"],
        handlers=[(SYS_openat, counter)],
    )

    assert result.success, result
    assert counter.count >= 3, (
        f"expected >=3 openat intercepts, got {counter.count}"
    )


# ----------------------------------------------------------------
# End-to-end failure-path tests: a handler that raises exercises the
# trampoline's exception path (handler raises -> rc -1 -> the
# supervisor applies the configured on_exception policy).
# ----------------------------------------------------------------


def test_handler_ctx_mem_handle_invalidated_after_handle():
    """A HandlerCtx that escapes its handle() call must have its mem
    accessors fail safe (return None/False) rather than dereference a
    dangling C pointer."""
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257  # x86_64

    captured = {}

    class _EscapingHandler(Handler):
        on_exception = ExceptionPolicy.CONTINUE

        def handle(self, ctx):
            captured["ctx"] = ctx          # escape the HandlerCtx
            # While inside handle(), the handle is live — a read may
            # succeed or fail depending on the address, but it must not
            # be inert yet:
            captured["live_during"] = (
                ctx._mem_handle is not None and ctx._mem_handle.live
            )
            return NotifAction.continue_()

    sb = sandlock.Sandbox(fs_readable=_PYTHON_READABLE)
    handler = _EscapingHandler()
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c",
             "import os\nfd = os.open('/etc/hostname', os.O_RDONLY)\nos.close(fd)\n"],
        handlers=[(SYS_openat, handler)],
    )
    assert result.success, result

    escaped = captured["ctx"]
    assert captured["live_during"] is True, "mem handle should be live during handle()"
    # After the run, the escaped ctx must be INERT — the trampoline's
    # finally must have invalidated the cell. This is the load-bearing
    # assertion: if the cell is still 'live' the accessors would
    # dereference a dangling supervisor pointer (use-after-free).
    assert escaped._mem_handle is not None
    assert escaped._mem_handle.live is False, (
        "trampoline must invalidate the mem handle once handle() returns; "
        "a live cell here means accessors deref freed memory (UAF)"
    )
    assert escaped._mem_handle.ptr is None
    # And the accessors must fail safe rather than deref a dangling ptr.
    assert escaped.read_cstr(0x1000, 64) is None
    assert escaped.read(0x1000, 16) is None
    assert escaped.write(0x1000, b"x") is False


class _RaisingHandler(Handler):
    """Handler that always raises — exercises the trampoline's
    exception path. on_exception is set per-test."""

    def __init__(self, on_exception):
        self.on_exception = on_exception

    def handle(self, ctx):
        raise RuntimeError("intentional handler failure")


def test_handler_exception_continue_policy_lets_child_run():
    """A handler that raises, with on_exception=CONTINUE, must let the
    child run to completion — the trampoline catches the exception and
    the supervisor applies the Continue policy."""
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257  # x86_64
    sb = sandlock.Sandbox(fs_readable=_PYTHON_READABLE)
    handler = _RaisingHandler(ExceptionPolicy.CONTINUE)
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c",
             "import os\nfd = os.open('/etc/hostname', os.O_RDONLY)\nos.close(fd)\n"],
        handlers=[(SYS_openat, handler)],
    )
    # Continue policy: the openat proceeds despite the handler raising,
    # so the child completes normally.
    assert result.success, result


def test_handler_exception_kill_policy_terminates_child():
    """A handler that raises, with on_exception=KILL, must terminate the
    child — the trampoline catches the exception and the supervisor
    applies the Kill policy."""
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257
    sb = sandlock.Sandbox(fs_readable=_PYTHON_READABLE)
    handler = _RaisingHandler(ExceptionPolicy.KILL)
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c",
             "import os\nfd = os.open('/etc/hostname', os.O_RDONLY)\nos.close(fd)\n"],
        handlers=[(SYS_openat, handler)],
    )
    # Kill policy: the first intercepted openat that the raising handler
    # touches kills the child's process group, so the run does not
    # succeed.
    assert not result.success, (
        f"expected child terminated by Kill policy, got success: {result}"
    )
