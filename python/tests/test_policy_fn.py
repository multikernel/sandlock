# SPDX-License-Identifier: Apache-2.0
"""Tests for the dynamic policy callback (policy_fn) feature."""

from __future__ import annotations

import contextlib
import os
import socket
import sys
import threading

import pytest

from sandlock import Sandbox, PolicyFn, Permissions, Allow, Audit, Deny, Grant, SyscallEvent, PolicyContext


_PYTHON_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev",
    sys.prefix,
]))


def _policy(**overrides):
    defaults = {"fs_readable": _PYTHON_READABLE, "fs_writable": ["/tmp"]}
    defaults.update(overrides)
    return Sandbox(**defaults)


@contextlib.contextmanager
def _loopback_listener(host="127.0.0.1"):
    """Yield ``(host, port)`` for a live TCP listener on an ephemeral port.

    A *live* listener is the baseline that makes a network deny-test
    meaningful: a connect to it succeeds when allowed, so a failure can only
    mean the sandbox denied it — as opposed to connecting to a dead port,
    which fails with ``ECONNREFUSED`` regardless of any enforcement.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, 0))
    s.listen(8)
    try:
        yield host, s.getsockname()[1]
    finally:
        s.close()


# ---------------------------------------------------------------------------
# SyscallEvent
# ---------------------------------------------------------------------------

class TestSyscallEvent:
    def test_basic_construction(self):
        e = SyscallEvent(syscall="connect", category="network", pid=123, host="1.2.3.4", port=443)
        assert e.syscall == "connect"
        assert e.category == "network"
        assert e.pid == 123
        assert e.host == "1.2.3.4"
        assert e.port == 443
        assert e.denied is False

    def test_frozen(self):
        e = SyscallEvent(syscall="openat", category="filesystem", pid=1)
        with pytest.raises(AttributeError):
            e.syscall = "other"

    def test_defaults(self):
        e = SyscallEvent(syscall="clone", category="process", pid=1)
        assert e.host is None
        assert e.port == 0
        assert e.parent_pid == 0
        assert e.argv is None
        assert e.denied is False

    def test_argv_contains(self):
        e = SyscallEvent(
            syscall="execve", category="process", pid=1,
            argv=("python3", "-c", "print(1)"),
        )
        assert e.argv_contains("python3")
        assert e.argv_contains("-c")
        assert not e.argv_contains("ruby")

    def test_argv_contains_none(self):
        e = SyscallEvent(syscall="openat", category="filesystem", pid=1)
        assert not e.argv_contains("anything")


# ---------------------------------------------------------------------------
# Integration: policy_fn receives events
# ---------------------------------------------------------------------------

class TestPolicyFnEvents:
    def test_receives_events(self):
        events = []

        def on_event(event, ctx):
            events.append(event.syscall)

        result = _policy(policy_fn=PolicyFn(on_event)).run(
            ["python3", "-c", "print('hello')"]
        )
        assert result.success
        assert len(events) > 0, "should have received syscall events"
        assert "openat" in events or "execve" in events

    def test_receives_execve(self):
        exec_events = []

        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                exec_events.append(event)

        result = _policy(policy_fn=PolicyFn(on_event)).run(
            ["python3", "-c", "print('hello')"]
        )
        assert result.success
        assert len(exec_events) > 0, "should have received execve events"

    def test_passthrough_no_modification(self):
        """policy_fn that does nothing should not affect execution."""
        count = {"n": 0}

        def on_event(event, ctx):
            count["n"] += 1

        result = _policy(policy_fn=PolicyFn(on_event)).run(
            ["python3", "-c", "print(6 * 7)"]
        )
        assert result.success
        assert result.stdout.strip() == b"42"
        assert count["n"] > 0

    def test_multiple_runs_isolated(self):
        """Each run gets its own event stream."""
        counts = []

        def on_event(event, ctx):
            pass  # just needs to not crash

        sb = _policy(policy_fn=PolicyFn(on_event))
        r1 = sb.run(["echo", "a"])
        r2 = sb.run(["echo", "b"])
        assert r1.success
        assert r2.success


# ---------------------------------------------------------------------------
# Integration: policy_fn restricts permissions
# ---------------------------------------------------------------------------

class TestPolicyFnRestrict:
    def test_restrict_on_execve(self):
        """restrict narrows outbound to the listed rules after execve.

        Two live loopback listeners are both allowlisted up front, so either
        would connect; restricting to 127.0.0.1 must permit the first and
        refuse the second (ECONNREFUSED, errno 111).
        """
        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.restrict(net_allow=["127.0.0.1:*"])

        with _loopback_listener("127.0.0.1") as (h1, p1), \
                _loopback_listener("127.0.0.2") as (h2, p2):
            script = (
                "import socket\n"
                "def probe(ip, port):\n"
                "    s = socket.socket(); s.settimeout(2)\n"
                "    try:\n"
                "        s.connect((ip, port)); return 'OK'\n"
                "    except OSError as e: return 'ERR%d' % e.errno\n"
                "    finally: s.close()\n"
                f"print('allowed=' + probe('{h1}', {p1}), 'denied=' + probe('{h2}', {p2}))\n"
            )
            result = _policy(
                net_allow=[f"{h1}:{p1}", f"{h2}:{p2}"], policy_fn=PolicyFn(on_event)
            ).run([sys.executable, "-c", script])

        out = result.stdout.decode()
        assert result.success, result.error
        assert "allowed=OK" in out, out          # listed IP still reachable
        assert "denied=ERR111" in out, out        # non-listed IP refused

    def test_restrict_max_memory(self):
        """restrict_max_memory tightens the static ceiling and is enforced.

        The old version restricted memory then ran ``echo`` and asserted
        nothing, so it never exercised the limit. dynamic restriction works by
        tightening a static ``max_memory`` ceiling: set a 256 MiB ceiling,
        restrict to 64 MiB, then allocate 128 MiB. With enforcement the process
        is killed; the un-restricted ceiling (control) allows the same 128 MiB,
        proving the kill is due to the dynamic restriction, not the ceiling.
        """
        alloc_128mb = (
            "print('STARTED', flush=True)\n"
            "b = bytearray(128 * 1024 * 1024)\n"
            "b[::4096] = b'\\x01' * (len(b) // 4096)\n"   # commit the pages
            "print('ALLOC_OK')\n"
        )

        def restrict_to_64mb(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.restrict_max_memory(64 * 1024 * 1024)
            return Allow()

        # Restricted: 128 MiB exceeds the tightened 64 MiB limit -> killed.
        restricted = _policy(max_memory="256M", policy_fn=PolicyFn(restrict_to_64mb)).run(
            [sys.executable, "-c", alloc_128mb], timeout=15
        )
        assert b"STARTED" in restricted.stdout, restricted.stdout
        assert b"ALLOC_OK" not in restricted.stdout, restricted.stdout
        assert not restricted.success, "128 MiB must exceed the 64 MiB dynamic limit"

        # Control: same 128 MiB under the un-restricted 256 MiB ceiling -> OK.
        baseline = _policy(max_memory="256M").run(
            [sys.executable, "-c", alloc_128mb], timeout=15
        )
        assert b"ALLOC_OK" in baseline.stdout, baseline.stdout
        assert baseline.success, baseline.error

    def test_restrict_max_processes(self):
        """restrict_max_processes tightens the concurrent-process limit, enforced.

        The old version restricted the limit then ran ``echo`` and asserted
        nothing. Restrict to 1 (only the running process), then fork: the fork
        must be denied with EAGAIN (errno 11). The control run (no restriction)
        forks successfully, proving the denial is due to the dynamic limit, not
        the fork itself.
        """
        fork_once = (
            "import os\n"
            "print('STARTED', flush=True)\n"
            "try:\n"
            "    pid = os.fork()\n"
            "    if pid == 0: os._exit(0)\n"
            "    os.waitpid(pid, 0); print('FORK_OK')\n"
            "except OSError as e: print('FORK_DENIED', e.errno)\n"
        )

        def restrict_to_1(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.restrict_max_processes(1)
            return Allow()

        restricted = _policy(policy_fn=PolicyFn(restrict_to_1)).run(
            [sys.executable, "-c", fork_once], timeout=15
        )
        out = restricted.stdout.decode()
        assert restricted.success, restricted.error
        assert "STARTED" in out, out
        assert "FORK_OK" not in out, out
        assert "FORK_DENIED 11" in out, out          # EAGAIN from the limit

        # Control: no restriction -> the same fork succeeds.
        baseline = _policy(policy_fn=PolicyFn(lambda e, ctx: Allow())).run(
            [sys.executable, "-c", fork_once], timeout=15
        )
        assert baseline.success, baseline.error
        assert "FORK_OK" in baseline.stdout.decode(), baseline.stdout


# ---------------------------------------------------------------------------
# Integration: per-PID restriction
# ---------------------------------------------------------------------------

class TestPolicyFnVerdict:
    def test_deny_with_errno(self):
        """Deny(errno) denies with *that* errno — attributable to policy_fn.

        The previous version connected to 127.0.0.1:1, which is outside the
        ``net_allow`` allowlist, so Landlock denies it with the same errno 13 —
        the test passed even if the policy_fn errno path were broken. Target a
        live listener on an *allowlisted* port instead: Landlock permits it and
        the listener accepts it, so errno 13 can only come from the policy_fn.
        """
        import errno

        def on_event(event, ctx):
            if event.syscall == "connect":
                return Deny(errno.EACCES)
            return Allow()

        with _loopback_listener() as (host, port):
            script = (
                "import socket\n"
                "s = socket.socket(); s.settimeout(2)\n"
                "try:\n"
                f"    s.connect(('{host}', {port})); print('CONNECTED')\n"
                "except OSError as e: print('ERR:%d' % e.errno)\n"
                "s.close()\n"
            )
            result = _policy(
                net_allow=[f"{host}:{port}"], policy_fn=PolicyFn(on_event)
            ).run([sys.executable, "-c", script])

        out = result.stdout.decode().strip()
        assert result.success, result.error
        assert out == "ERR:13", f"expected policy_fn EACCES (13), got: {out!r}"

    def test_audit_allows(self):
        """Audit() allows but flags."""
        def on_event(event, ctx):
            if event.category == "filesystem":
                return Audit()
            return Allow()

        result = _policy(policy_fn=PolicyFn(on_event)).run(
            ["cat", "/etc/hostname"]
        )
        assert result.success, "audit should allow the syscall"

    @pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
    @pytest.mark.parametrize("bogus", ["bogus", 0, False, True, -1, -2, 13, "audit"])
    def test_unrecognized_return_fails_closed(self, bogus):
        """Anything but a verdict or None denies rather than being guessed at."""
        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                return bogus
            return Allow()

        result = _policy(policy_fn=PolicyFn(on_event)).run(["echo", "should-not-run"])
        assert not result.success, "unrecognized verdict must fail closed (deny)"

    def test_deny_returns_true(self):
        """Deny() denies connect with EPERM — and the process keeps running.

        The target is a live listener on an allowlisted port, so without the
        policy_fn deny the connect would *succeed*. EPERM (errno 1) therefore
        proves the deny fired, and the trailing marker proves the deny did not
        kill the process (the backward-compat contract).
        """
        def on_event(event, ctx):
            return Deny() if event.syscall == "connect" else Allow()

        with _loopback_listener() as (host, port):
            script = (
                "import socket\n"
                "s = socket.socket(); s.settimeout(2)\n"
                "try:\n"
                f"    s.connect(('{host}', {port})); print('ALLOWED')\n"
                "except OSError as e: print('ERR', e.errno)\n"
                "s.close(); print('SURVIVED')\n"
            )
            result = _policy(
                net_allow=[f"{host}:{port}"], policy_fn=PolicyFn(on_event)
            ).run([sys.executable, "-c", script])

        out = result.stdout.decode()
        assert "ALLOWED" not in out, out
        assert "ERR 1" in out, out          # EPERM from the policy_fn deny
        assert "SURVIVED" in out, out        # deny must not kill the process
        assert result.success, result.error

    def test_deny_path_dynamic(self):
        """ctx.deny_path blocks file access."""
        import tempfile, os

        out = os.path.join(tempfile.gettempdir(), f"sandlock-test-denypath-{os.getpid()}")

        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.deny_path("/etc/hostname")
            return Allow()

        result = _policy(policy_fn=PolicyFn(on_event)).run(
            ["python3", "-c",
             f"try:\n"
             f"  open('/etc/hostname').read()\n"
             f"  open('{out}', 'w').write('READ')\n"
             f"except (PermissionError, OSError):\n"
             f"  open('{out}', 'w').write('BLOCKED')\n"
            ]
        )
        assert result.success
        with open(out) as f:
            content = f.read()
        assert content == "BLOCKED", f"expected BLOCKED, got: {content}"
        os.unlink(out)


class TestPolicyFnPerPid:
    def test_restrict_pid(self):
        """restrict_pid narrows a specific pid's outbound to the listed rules.

        Mirrors test_restrict_on_execve: restricting the exec'd pid to
        127.0.0.1 must permit the first listener and refuse the second.
        """
        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.restrict_pid(event.pid, net_allow=["127.0.0.1:*"])

        with _loopback_listener("127.0.0.1") as (h1, p1), \
                _loopback_listener("127.0.0.2") as (h2, p2):
            script = (
                "import socket\n"
                "def probe(ip, port):\n"
                "    s = socket.socket(); s.settimeout(2)\n"
                "    try:\n"
                "        s.connect((ip, port)); return 'OK'\n"
                "    except OSError as e: return 'ERR%d' % e.errno\n"
                "    finally: s.close()\n"
                f"print('allowed=' + probe('{h1}', {p1}), 'denied=' + probe('{h2}', {p2}))\n"
            )
            result = _policy(
                net_allow=[f"{h1}:{p1}", f"{h2}:{p2}"], policy_fn=PolicyFn(on_event)
            ).run([sys.executable, "-c", script])

        out = result.stdout.decode()
        assert result.success, result.error
        assert "allowed=OK" in out, out
        assert "denied=ERR111" in out, out


@pytest.mark.parametrize("verdict_timeout", [-1, float("inf"), float("nan"), 1e30])
def test_invalid_verdict_timeout(verdict_timeout):
    with pytest.raises(ValueError, match="verdict_timeout"):
        PolicyFn(lambda event, ctx: Allow(), verdict_timeout=verdict_timeout)


@pytest.mark.parametrize("events", [set(), {"bogus"}, {"network", "dns"}])
def test_invalid_events(events):
    with pytest.raises(ValueError, match="events"):
        PolicyFn(lambda event, ctx: Allow(), events=events)


def test_events_rejects_bare_string():
    with pytest.raises(TypeError, match="events"):
        PolicyFn(lambda event, ctx: Allow(), events="network")


def test_events_default_to_all_categories():
    assert PolicyFn(lambda event, ctx: Allow()).events == {"filesystem", "network", "process"}


def test_network_events_only():
    seen = []
    deny_errors = []

    def on_event(event, ctx):
        seen.append((event.syscall, event.category))
        try:
            ctx.deny_path("/etc/hostname")
        except RuntimeError as e:
            deny_errors.append(e)
        return Allow()

    with _loopback_listener() as (host, port):
        result = _policy(
            net_allow=[f"{host}:{port}"], policy_fn=PolicyFn(on_event, events=["network"])
        ).run(
            ["python3", "-c",
             "import socket, subprocess\n"
             "open('/etc/hostname').read()\n"
             "subprocess.run(['/bin/true'], check=True)\n"
             f"socket.create_connection(('{host}', {port})).close()\n"]
        )
    assert result.success, result.error
    assert any(name == "connect" for name, _ in seen), seen
    assert all(category == "network" for _, category in seen), seen
    assert len(deny_errors) == len(seen)


def test_verdict_timeout_denies_late_allow():
    import time

    def on_event(event, ctx):
        if event.syscall == "execve":
            time.sleep(0.15)
        return Allow()

    result = _policy(policy_fn=PolicyFn(on_event, verdict_timeout=0.02)).run(["/bin/true"])
    assert not result.success


def test_shutdown_cancels_unlimited_approval():
    import time

    entered = threading.Event()
    cancelled = threading.Event()

    def on_event(event, ctx):
        if event.syscall == "execve":
            entered.set()
            deadline = time.monotonic() + 2
            while not ctx.is_cancelled() and time.monotonic() < deadline:
                time.sleep(0.001)
            if ctx.is_cancelled():
                cancelled.set()
        return Allow()

    result = _policy(policy_fn=PolicyFn(on_event, verdict_timeout=None)).run(
        ["/bin/true"], timeout=0.2,
    )
    assert entered.is_set()
    assert cancelled.is_set()
    assert not result.success


def test_policy_fn_requires_callable():
    with pytest.raises(TypeError, match="callback"):
        PolicyFn(None)


def test_sandbox_requires_policy_fn_configuration():
    with pytest.raises(TypeError, match="PolicyFn"):
        Sandbox(policy_fn=lambda event, ctx: Allow())


@pytest.mark.parametrize("bad", [0, -1, True, 1.5])
def test_deny_rejects_bad_errno(bad):
    with pytest.raises(ValueError):
        Deny(bad)


def _approve_from_thread(verdict):
    import queue

    approvals = queue.Queue()

    def answer():
        while (approval := approvals.get()) is not None:
            assert not approval.cancelled
            approval.resolve(verdict)

    worker = threading.Thread(target=answer)
    worker.start()
    return approvals, worker


@pytest.mark.parametrize("verdict, success", [(None, True), (Allow(), True), (Deny(13), False), (Deny(), False)])
def test_deferred_approval_resolved_from_another_thread(verdict, success):
    approvals, worker = _approve_from_thread(verdict)

    def on_event(event, ctx, approval):
        if approval is not None:
            approvals.put(approval)

    try:
        result = _policy(policy_fn=PolicyFn(on_event, deferred=True)).run(["/bin/true"])
    finally:
        approvals.put(None)
        worker.join()
    assert result.success is success


def test_deferred_unanswered_approval_denies():
    result = _policy(policy_fn=PolicyFn(lambda event, ctx, approval: None, deferred=True)).run(
        ["/bin/true"],
    )
    assert not result.success


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_deferred_callback_exception_denies():
    def on_event(event, ctx, approval):
        if approval is not None:
            raise RuntimeError("approver failed")

    result = _policy(policy_fn=PolicyFn(on_event, deferred=True)).run(["/bin/true"])
    assert not result.success


def test_deferred_approval_cancelled_by_timeout():
    kept = []

    def on_event(event, ctx, approval):
        if approval is not None:
            kept.append(approval)

    result = _policy(policy_fn=PolicyFn(on_event, deferred=True, verdict_timeout=0.05)).run(
        ["/bin/true"],
    )
    assert not result.success
    assert kept and kept[0].cancelled
    kept[0].allow()
    with pytest.raises(RuntimeError, match="already answered"):
        kept[0].allow()


def test_deferred_approval_answered_by_later_event():
    with _loopback_listener() as (host, first), _loopback_listener() as (_, second):
        held = []

        def on_event(event, ctx, approval):
            if event.syscall == "connect" and event.port == first:
                held.append(approval)
                return
            if event.syscall == "connect" and event.port == second:
                held.pop().allow()
            if approval is not None:
                approval.allow()

        script = (
            "import socket, threading, time\n"
            f"t = threading.Thread(target=socket.create_connection, args=(('{host}', {first}),), kwargs={{'timeout': 10}})\n"
            "t.start()\n"
            "time.sleep(0.2)\n"
            f"socket.create_connection(('{host}', {second}), timeout=10)\n"
            "t.join()\n"
        )
        policy = _policy(
            net_allow=[f"{host}:{first}", f"{host}:{second}"],
            policy_fn=PolicyFn(on_event, deferred=True),
        )
        result = policy.run([sys.executable, "-c", script])
    assert result.success, result.stderr


# ---------------------------------------------------------------------------
# Approvable network grants
# ---------------------------------------------------------------------------

_CONNECT_TWICE = (
    "import socket, sys\n"
    "res = []\n"
    "for _ in range(2):\n"
    "    s = socket.socket(); s.settimeout(5)\n"
    "    try:\n"
    "        s.connect(('127.0.0.1', int(sys.argv[1]))); res.append('OK')\n"
    "    except OSError as e: res.append('ERR%d' % e.errno)\n"
    "    finally: s.close()\n"
    "print(' '.join(res))\n"
)


def _network_approver(answer):
    """Hand each held network operation to ``answer`` on another thread."""
    import queue

    approvals = queue.Queue()

    def worker():
        while (approval := approvals.get()) is not None:
            answer(approval)

    thread = threading.Thread(target=worker)
    thread.start()

    def on_event(event, ctx, approval):
        if approval is None:
            return
        if event.syscall == "connect":
            approvals.put(approval)
        else:
            approval.allow()

    def stop():
        approvals.put(None)
        thread.join()

    return on_event, stop


def _run_approvable(answer, approvable=("127.0.0.1:*",)):
    on_event, stop = _network_approver(answer)
    with _loopback_listener("127.0.0.1") as (_, port):
        try:
            result = _policy(policy_fn=PolicyFn(
                on_event, deferred=True, events={"network"},
                approvable=Permissions(net_allow=list(approvable)),
            )).run([sys.executable, "-c", _CONNECT_TWICE, str(port)])
        finally:
            stop()
    assert result.success, result.error
    return result.stdout.decode().strip()


def test_approval_grants_network_from_thread():
    assert _run_approvable(lambda a: a.resolve(Grant(net_allow=["127.0.0.1:*"]))) == "OK OK"


def _refused_grant(grant, error):
    errors = []

    def answer(approval):
        try:
            approval.resolve(grant)
        except error as e:
            errors.append(e)

    assert _run_approvable(answer) == "ERR111 ERR111"
    assert len(errors) == 2


def test_grant_outside_approvable_denies_and_raises():
    _refused_grant(Grant(net_allow=["10.0.0.0/8:*"]), PermissionError)


def test_grant_hostname_denies_and_raises():
    _refused_grant(Grant(net_allow=["example.com:443"]), ValueError)


def test_sync_callback_returns_grant():
    def on_event(event, ctx):
        if event.syscall == "connect":
            return Grant(net_allow=["127.0.0.1:*"])
        return Allow()

    with _loopback_listener("127.0.0.1") as (_, port):
        result = _policy(policy_fn=PolicyFn(
            on_event, events={"network"},
            approvable=Permissions(net_allow=["127.0.0.1:*"]),
        )).run([sys.executable, "-c", _CONNECT_TWICE, str(port)])
    assert result.success, result.error
    assert result.stdout.decode().strip() == "OK OK"


def test_policy_fn_without_net_allow_denies_connect():
    with _loopback_listener("127.0.0.1") as (_, port):
        result = _policy(policy_fn=PolicyFn(lambda event, ctx: None)).run(
            [sys.executable, "-c", _CONNECT_TWICE, str(port)]
        )
    assert result.success, result.error
    assert result.stdout.decode().strip() == "ERR111 ERR111"


def test_restrict_requires_keyword():
    errors = []

    def on_event(event, ctx):
        if event.syscall in ("execve", "execveat"):
            try:
                ctx.restrict()
            except TypeError as e:
                errors.append(e)

    assert _policy(policy_fn=PolicyFn(on_event)).run(["/bin/true"]).success
    assert errors


def test_permissions_rejects_bare_string():
    with pytest.raises(TypeError):
        Permissions(net_allow="*:*")
