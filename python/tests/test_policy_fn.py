# SPDX-License-Identifier: Apache-2.0
"""Tests for the dynamic policy callback (policy_fn) feature."""

from __future__ import annotations

import contextlib
import os
import socket
import sys
import threading

import pytest

from sandlock import Sandbox, SyscallEvent, PolicyContext


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
        e = SyscallEvent(syscall="openat", category="file", pid=1)
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
        e = SyscallEvent(syscall="openat", category="file", pid=1)
        assert not e.argv_contains("anything")


# ---------------------------------------------------------------------------
# Integration: policy_fn receives events
# ---------------------------------------------------------------------------

class TestPolicyFnEvents:
    def test_receives_events(self):
        events = []

        def on_event(event, ctx):
            events.append(event.syscall)

        result = _policy(policy_fn=on_event).run(
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

        result = _policy(policy_fn=on_event).run(
            ["python3", "-c", "print('hello')"]
        )
        assert result.success
        assert len(exec_events) > 0, "should have received execve events"

    def test_passthrough_no_modification(self):
        """policy_fn that does nothing should not affect execution."""
        count = {"n": 0}

        def on_event(event, ctx):
            count["n"] += 1

        result = _policy(policy_fn=on_event).run(
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

        sb = _policy(policy_fn=on_event)
        r1 = sb.run(["echo", "a"])
        r2 = sb.run(["echo", "b"])
        assert r1.success
        assert r2.success


# ---------------------------------------------------------------------------
# Integration: policy_fn restricts permissions
# ---------------------------------------------------------------------------

class TestPolicyFnRestrict:
    def test_restrict_network_on_execve(self):
        """restrict_network narrows outbound to the listed IPs after execve.

        The old version called ``restrict_network([])`` — an empty list is a
        no-op (the override is skipped when it lists no IPs) — and asserted only
        that the program printed, so it verified nothing about the restriction.

        Use two live loopback listeners on 127.0.0.1 and 127.0.0.2, both
        allowlisted up front so either would connect. Restricting to
        ``["127.0.0.1"]`` must then permit the first and deny the second
        (ECONNREFUSED, errno 111). Without enforcement both would connect.
        """
        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.restrict_network(["127.0.0.1"])

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
                net_allow=[f"{h1}:{p1}", f"{h2}:{p2}"], policy_fn=on_event
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
            return 0

        # Restricted: 128 MiB exceeds the tightened 64 MiB limit -> killed.
        restricted = _policy(max_memory="256M", policy_fn=restrict_to_64mb).run(
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
            return 0

        restricted = _policy(policy_fn=restrict_to_1).run(
            [sys.executable, "-c", fork_once], timeout=15
        )
        out = restricted.stdout.decode()
        assert restricted.success, restricted.error
        assert "STARTED" in out, out
        assert "FORK_OK" not in out, out
        assert "FORK_DENIED 11" in out, out          # EAGAIN from the limit

        # Control: no restriction -> the same fork succeeds.
        baseline = _policy(policy_fn=lambda e, ctx: 0).run(
            [sys.executable, "-c", fork_once], timeout=15
        )
        assert baseline.success, baseline.error
        assert "FORK_OK" in baseline.stdout.decode(), baseline.stdout


# ---------------------------------------------------------------------------
# Integration: per-PID restriction
# ---------------------------------------------------------------------------

class TestPolicyFnVerdict:
    def test_deny_with_errno(self):
        """Returning a positive int denies with *that* errno — attributable to policy_fn.

        The previous version connected to 127.0.0.1:1, which is outside the
        ``net_allow`` allowlist, so Landlock denies it with the same errno 13 —
        the test passed even if the policy_fn errno path were broken. Target a
        live listener on an *allowlisted* port instead: Landlock permits it and
        the listener accepts it, so errno 13 can only come from the policy_fn.
        """
        import errno

        def on_event(event, ctx):
            if event.syscall == "connect":
                return errno.EACCES  # 13
            return 0

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
                net_allow=[f"{host}:{port}"], policy_fn=on_event
            ).run([sys.executable, "-c", script])

        out = result.stdout.decode().strip()
        assert result.success, result.error
        assert out == "ERR:13", f"expected policy_fn EACCES (13), got: {out!r}"

    def test_audit_allows(self):
        """Return 'audit' or -2 to allow but flag."""
        def on_event(event, ctx):
            if event.category == "file":
                return "audit"
            return 0

        result = _policy(policy_fn=on_event).run(
            ["cat", "/etc/hostname"]
        )
        assert result.success, "audit should allow the syscall"

    def test_unrecognized_return_fails_closed(self):
        """An unrecognized return value denies rather than silently allowing."""
        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                return "bogus"  # not a recognized verdict
            return 0

        result = _policy(policy_fn=on_event).run(["echo", "should-not-run"])
        assert not result.success, "unrecognized verdict must fail closed (deny)"

    def test_deny_returns_true(self):
        """Returning True denies connect with EPERM — and the process keeps running.

        The target is a live listener on an allowlisted port, so without the
        policy_fn deny the connect would *succeed*. EPERM (errno 1) therefore
        proves the deny fired, and the trailing marker proves the deny did not
        kill the process (the backward-compat contract).
        """
        def on_event(event, ctx):
            # True only for connect (deny); allow everything else.
            return event.syscall == "connect"

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
                net_allow=[f"{host}:{port}"], policy_fn=on_event
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
            return 0

        result = _policy(policy_fn=on_event).run(
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
    def test_restrict_pid_network(self):
        """restrict_pid_network narrows a specific pid's outbound to the listed IPs.

        The old version restricted the pid then ran ``echo ok`` — it never made
        a network call, so it could not observe any restriction. Mirror
        test_restrict_network_on_execve with two live loopback listeners, both
        allowlisted: restricting the exec'd pid to ["127.0.0.1"] must permit the
        first and refuse the second (errno 111).
        """
        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.restrict_pid_network(event.pid, ["127.0.0.1"])

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
                net_allow=[f"{h1}:{p1}", f"{h2}:{p2}"], policy_fn=on_event
            ).run([sys.executable, "-c", script])

        out = result.stdout.decode()
        assert result.success, result.error
        assert "allowed=OK" in out, out
        assert "denied=ERR111" in out, out
