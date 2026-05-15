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


def test_inject_fd_send_rejects_negative_srcfd():
    import pytest
    with pytest.raises(ValueError):
        NotifAction.inject_fd_send(-1)


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
    """ExceptionPolicy discriminants must match SANDLOCK_EXCEPTION_* in
    the C header. Parse the real header so an ABI drift is caught."""
    import re
    from pathlib import Path

    header = (
        Path(__file__).resolve().parents[2]
        / "crates" / "sandlock-ffi" / "include" / "sandlock.h"
    )
    text = header.read_text()
    pairs = dict(
        (m.group(1), int(m.group(2)))
        for m in re.finditer(r"SANDLOCK_EXCEPTION_(\w+)\s*=\s*(\d+)", text)
    )
    assert pairs, "no SANDLOCK_EXCEPTION_* discriminants found in sandlock.h"
    for c_name, c_val in pairs.items():
        py_member = getattr(ExceptionPolicy, c_name)
        assert int(py_member) == c_val, (
            f"ExceptionPolicy.{c_name}={int(py_member)} != C header {c_val}"
        )
    for member in ExceptionPolicy:
        assert member.name in pairs, f"ExceptionPolicy.{member.name} not in C header"


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
    """_ActionKind discriminants must match SANDLOCK_ACTION_* in the C
    header. Parse the real header so an ABI drift is caught."""
    import re
    from pathlib import Path

    from sandlock.handler import _ActionKind

    header = (
        Path(__file__).resolve().parents[2]
        / "crates" / "sandlock-ffi" / "include" / "sandlock.h"
    )
    text = header.read_text()
    # Extract `SANDLOCK_ACTION_<NAME> = <N>` pairs.
    pairs = dict(
        (m.group(1), int(m.group(2)))
        for m in re.finditer(r"SANDLOCK_ACTION_(\w+)\s*=\s*(\d+)", text)
    )
    assert pairs, "no SANDLOCK_ACTION_* discriminants found in sandlock.h"
    # Map C name -> Python _ActionKind member.
    for c_name, c_val in pairs.items():
        py_member = getattr(_ActionKind, c_name)
        assert int(py_member) == c_val, (
            f"_ActionKind.{c_name}={int(py_member)} != C header {c_val}"
        )
    # And every _ActionKind member must exist in the header.
    for member in _ActionKind:
        assert member.name in pairs, f"_ActionKind.{member.name} not in C header"


def test_handler_ctx_dataclass_stores_fields():
    """Pure unit test of HandlerCtx as a dataclass: _for_test stores the
    kwargs 1:1. This covers storage only — the trampoline's notification
    unpacking is covered by
    test_handler_ctx_notif_fields_populated_from_real_notification."""
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


def test_smoke_audit_openat(tmp_dir):
    """RFC #43 phasing item 2: an audit handler counts the child's
    SYS_openat calls. Counts only opens of a unique probe file so the
    assertion is not satisfiable by interpreter-startup openat noise.

    The probe is a plain file under tmp_dir, mirroring
    test_handler_mem_read_cstr_reads_child_path: /etc/hostname is
    virtualized by a builtin supervisor handler that intercepts the
    notification before any user handler runs.
    """
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257  # x86_64

    probe = tmp_dir / "audit-probe-file"
    probe.write_text("x")
    probe_path = str(probe)

    class _OpenatCounter(Handler):
        on_exception = ExceptionPolicy.CONTINUE  # audit-only — never block

        def __init__(self, target):
            self.target = target
            self.count = 0

        def handle(self, ctx):
            # openat(dirfd, pathname, flags, ...) -> pathname is args[1].
            path = ctx.read_cstr(ctx.args[1], max_len=4096)
            if path == self.target:
                self.count += 1
            return NotifAction.continue_()

    sb = sandlock.Sandbox(fs_readable=[*_PYTHON_READABLE, str(tmp_dir)])
    counter = _OpenatCounter(probe_path)
    script = (
        "import os\n"
        "for _ in range(3):\n"
        "    fd = os.open(%r, os.O_RDONLY)\n"
        "    os.close(fd)\n" % probe_path
    )
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c", script],
        handlers=[(SYS_openat, counter)],
    )

    assert result.success, result
    # Counts only opens of the unique probe path — interpreter-startup
    # openat noise targets other paths and is excluded.
    assert counter.count == 3, (
        f"expected exactly 3 opens of the probe file, got {counter.count}"
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


def test_handler_exception_continue_policy_lets_child_run(tmp_dir):
    """A handler that RAISES, with on_exception=CONTINUE, lets the child
    complete — and we verify the exception path was actually exercised,
    not just that the child happened to succeed.

    The handler targets a probe file under tmp_dir, not /etc/hostname:
    that path is virtualized by a builtin supervisor handler that
    intercepts the notification before any user handler runs.
    """
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257  # x86_64

    probe = tmp_dir / "probe.txt"
    probe.write_text("payload\n")
    probe_path = str(probe)

    class _RaisingHandler(Handler):
        on_exception = ExceptionPolicy.CONTINUE

        def __init__(self, target):
            self.target = target
            self.raised = 0

        def handle(self, ctx):
            # Only act on the probe path; the loader's own openat calls
            # hit other paths and must not be raised on.
            path = ctx.read_cstr(ctx.args[1], max_len=4096)
            if path == self.target:
                self.raised += 1
                raise RuntimeError("intentional handler failure")
            return NotifAction.continue_()

    sb = sandlock.Sandbox(fs_readable=[*_PYTHON_READABLE, str(tmp_dir)])
    handler = _RaisingHandler(probe_path)
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c",
             "import os; fd = os.open(%r, os.O_RDONLY); os.close(fd)" % probe_path],
        handlers=[(SYS_openat, handler)],
    )
    # The handler must have been called and must have raised — proving
    # the trampoline's except-path + CONTINUE policy were exercised.
    assert handler.raised >= 1, "handler.handle was never invoked / never raised"
    # And with CONTINUE the raised exception did not block the child.
    assert result.success, result


def test_handler_exception_kill_policy_terminates_child(tmp_dir):
    """A raising handler with on_exception=KILL terminates the child AT
    the intercepted syscall — not merely 'the run failed somehow'.

    The handler targets a probe file under tmp_dir, not /etc/hostname:
    that path is virtualized by a builtin supervisor handler that
    intercepts the notification before any user handler runs.
    """
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257  # x86_64

    probe = tmp_dir / "probe.txt"
    probe.write_text("payload\n")
    probe_path = str(probe)

    class _RaisingHandler(Handler):
        on_exception = ExceptionPolicy.KILL

        def __init__(self, target):
            self.target = target

        def handle(self, ctx):
            path = ctx.read_cstr(ctx.args[1], max_len=4096)
            if path == self.target:
                raise RuntimeError("intentional handler failure")
            return NotifAction.continue_()

    sb = sandlock.Sandbox(fs_readable=[*_PYTHON_READABLE, str(tmp_dir)])
    # BEFORE proves the child reached the open; AFTER proves it did NOT
    # proceed past it. A run that crashes before the child starts shows
    # neither marker -> the test fails, as it should.
    script = (
        "import os, sys\n"
        "sys.stdout.write('BEFORE\\n'); sys.stdout.flush()\n"
        "os.open(%r, os.O_RDONLY)\n"
        "sys.stdout.write('AFTER\\n'); sys.stdout.flush()\n" % probe_path
    )
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c", script],
        handlers=[(SYS_openat, _RaisingHandler(probe_path))],
    )
    stdout = result.stdout
    assert b"BEFORE" in stdout, f"child never reached the syscall: {stdout!r}"
    assert b"AFTER" not in stdout, f"child proceeded past the kill point: {stdout!r}"
    assert not result.success, result


# ----------------------------------------------------------------
# End-to-end coverage for the trampoline's NotifAction kind-dispatch.
#
# The tests above only ever return NotifAction.continue_() or exercise
# the exception-POLICY path. The branch in _handler_ffi.py that
# translates a RETURNED non-Continue action (errno / return_value /
# kill / inject_fd) into the matching sandlock_action_set_* call had no
# end-to-end coverage — a trampoline reduced to "always Continue" passed
# the whole suite. The tests below make a handler RETURN a non-Continue
# action and observe the child behave accordingly, so a neutered
# kind-dispatch fails them.
# ----------------------------------------------------------------


def test_handler_errno_action_makes_child_observe_eperm(tmp_dir):
    """A handler returning NotifAction.errno(EPERM) must make the child's
    openat fail with errno EPERM — only reachable if the trampoline
    translates the Errno action into sandlock_action_set_errno.

    The handler targets one probe file by path: denying *every* openat
    would kill the dynamic loader before the child runs (the test would
    then observe EPERM from ld.so, not from the child's own open). It
    also avoids /etc/hostname and other supervisor-virtualized paths,
    which a builtin handler intercepts before any user handler runs.
    """
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257  # x86_64
    import errno as _errno

    probe = tmp_dir / "probe.txt"
    probe.write_text("payload\n")

    class _DenyProbe(Handler):
        on_exception = ExceptionPolicy.KILL  # handler is correct; policy unused

        def handle(self, ctx):
            # openat(dirfd, pathname, flags, ...) -> pathname is args[1].
            path = ctx.read_cstr(ctx.args[1], max_len=4096)
            if path == str(probe):
                return NotifAction.errno(_errno.EPERM)
            return NotifAction.continue_()

    sb = sandlock.Sandbox(fs_readable=[*_PYTHON_READABLE, str(tmp_dir)])
    # Child opens the probe file and reports the errno it gets.
    script = (
        "import os, sys\n"
        "try:\n"
        "    os.open(%r, os.O_RDONLY)\n"
        "    sys.exit(0)\n"
        "except OSError as e:\n"
        "    sys.stderr.write('errno=%%d' %% e.errno)\n"
        "    sys.exit(3)\n" % str(probe)
    )
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c", script],
        handlers=[(SYS_openat, _DenyProbe())],
    )
    # Child caught OSError(EPERM) -> exit 3, stderr 'errno=1'.
    assert not result.success, result
    assert b"errno=%d" % _errno.EPERM in result.stderr, result.stderr


def test_handler_return_value_action_overrides_getpid():
    """A handler returning NotifAction.return_value_(777) must make the
    child's os.getpid() return the synthetic 777 — only reachable if the
    trampoline translates the ReturnValue action into
    sandlock_action_set_return_value."""
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_getpid = 39  # x86_64

    class _FakePid(Handler):
        on_exception = ExceptionPolicy.KILL

        def handle(self, ctx):
            return NotifAction.return_value_(777)

    sb = sandlock.Sandbox(fs_readable=_PYTHON_READABLE)
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c", "import os; print(os.getpid())"],
        handlers=[(SYS_getpid, _FakePid())],
    )
    assert result.success, result
    assert result.stdout.strip() == b"777", result.stdout


def test_handler_kill_action_terminates_child():
    """A handler returning NotifAction.kill(SIGKILL, 0) directly must
    terminate the child. on_exception is CONTINUE here deliberately: if
    the trampoline failed to translate the Kill action, the action would
    be Unset, the exception policy CONTINUE would let the child survive,
    and this test would fail — which makes it discriminating."""
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257
    import signal

    class _KillOnOpen(Handler):
        on_exception = ExceptionPolicy.CONTINUE  # NOT used — handler returns cleanly

        def handle(self, ctx):
            return NotifAction.kill(signal.SIGKILL, 0)  # pgid 0 -> supervisor resolves

    sb = sandlock.Sandbox(fs_readable=_PYTHON_READABLE)
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c",
             "import os; os.open('/etc/hostname', os.O_RDONLY)"],
        handlers=[(SYS_openat, _KillOnOpen())],
    )
    assert not result.success, (
        f"child must be killed by the handler's Kill action; got {result}"
    )


def test_handler_mem_read_cstr_reads_child_path(tmp_dir):
    """A handler reads the openat path argument from child memory via
    ctx.read_cstr and denies a specific file. This exercises the real
    sandlock_mem_read_cstr ctypes round-trip (the other tests only cover
    read_cstr with _mem_handle=None).

    The probe is a plain file under tmp_dir, not /etc/hostname: the
    supervisor virtualizes /etc/hostname with a builtin openat handler
    that intercepts the notification before any user handler runs, so a
    user handler never observes that path.
    """
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257
    import errno as _errno

    probe = tmp_dir / "probe.txt"
    probe.write_text("payload\n")

    seen_paths = []

    class _PathReader(Handler):
        on_exception = ExceptionPolicy.CONTINUE

        def handle(self, ctx):
            # openat(dirfd, pathname, flags, ...) -> pathname is args[1].
            path = ctx.read_cstr(ctx.args[1], max_len=4096)
            seen_paths.append(path)
            if path == str(probe):
                return NotifAction.errno(_errno.EACCES)
            return NotifAction.continue_()

    sb = sandlock.Sandbox(fs_readable=[*_PYTHON_READABLE, str(tmp_dir)])
    script = (
        "import os, sys\n"
        "try:\n"
        "    os.open(%r, os.O_RDONLY)\n"
        "    sys.exit(0)\n"
        "except OSError as e:\n"
        "    sys.exit(7 if e.errno == %d else 8)\n" % (str(probe), _errno.EACCES)
    )
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c", script],
        handlers=[(SYS_openat, _PathReader())],
    )
    # Handler read the real probe path from child memory and denied it.
    assert str(probe) in seen_paths, seen_paths
    assert not result.success, result


def test_handler_ctx_notif_fields_populated_from_real_notification(tmp_dir):
    """HandlerCtx fields must be unpacked correctly from the C
    notification by the trampoline — not just stored by the dataclass.
    Exercise the real run_with_handlers -> trampoline path.

    The child opens a probe file under tmp_dir, not /etc/hostname:
    that path is virtualized by a builtin supervisor handler that
    intercepts the notification before any user handler runs.
    """
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    SYS_openat = 257  # x86_64

    probe = tmp_dir / "probe.txt"
    probe.write_text("payload\n")
    probe_path = str(probe)

    seen = {}

    class _FieldInspector(Handler):
        on_exception = ExceptionPolicy.CONTINUE

        def __init__(self, target):
            self.target = target

        def handle(self, ctx):
            # Record the notification the trampoline built — but only for
            # the probe open, so the loader's own openat calls (other
            # paths) do not overwrite the recorded fields.
            path = ctx.read_cstr(ctx.args[1], max_len=4096)
            if path == self.target:
                seen["syscall_nr"] = ctx.syscall_nr
                seen["pid"] = ctx.pid
                seen["args_len"] = len(ctx.args)
                seen["arg1_is_ptr"] = ctx.args[1]  # openat pathname pointer
            return NotifAction.continue_()

    sb = sandlock.Sandbox(fs_readable=[*_PYTHON_READABLE, str(tmp_dir)])
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c",
             "import os; fd = os.open(%r, os.O_RDONLY); os.close(fd)" % probe_path],
        handlers=[(SYS_openat, _FieldInspector(probe_path))],
    )
    assert result.success, result
    # The handler ran for the probe's SYS_openat: syscall_nr must equal
    # the registered number — a field-swap in the trampoline (e.g.
    # syscall_nr <- arch) would make this fail.
    assert seen.get("syscall_nr") == SYS_openat, seen
    # pid must be a real, positive child pid.
    assert isinstance(seen.get("pid"), int) and seen["pid"] > 0, seen
    # openat takes 6 syscall args; args[1] (pathname pointer) must be a
    # non-zero userspace address.
    assert seen.get("args_len") == 6, seen
    assert isinstance(seen.get("arg1_is_ptr"), int) and seen["arg1_is_ptr"] > 0, seen


def test_run_with_handlers_empty_handler_list():
    """An empty handler list should run cleanly (degenerate but valid)."""
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    sb = sandlock.Sandbox(fs_readable=_PYTHON_READABLE)
    result = sb.run_with_handlers(
        cmd=[_SYSTEM_PYTHON, "-c", "pass"],
        handlers=[],
    )
    assert result.success, result


def test_run_with_handlers_rejects_non_handler():
    """A non-Handler object in the list must raise a clear error, not
    crash deep in ctypes."""
    if not os.path.exists(_SYSTEM_PYTHON):
        pytest.skip(f"{_SYSTEM_PYTHON} not available")

    sb = sandlock.Sandbox(fs_readable=_PYTHON_READABLE)
    with pytest.raises((TypeError, AttributeError, ValueError)):
        sb.run_with_handlers(
            cmd=[_SYSTEM_PYTHON, "-c", "pass"],
            handlers=[(257, "not a handler")],
        )
