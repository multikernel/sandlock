# SPDX-License-Identifier: Apache-2.0
"""Tests for the dynamic policy callback (policy_fn) feature."""

import os
import sys
import threading

import pytest

from sandlock import Sandbox, Policy, SyscallEvent, PolicyContext


_PYTHON_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev",
    sys.prefix,
]))


def _policy(**overrides):
    defaults = {"fs_readable": _PYTHON_READABLE, "fs_writable": ["/tmp"]}
    defaults.update(overrides)
    return Policy(**defaults)


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

        result = Sandbox(_policy(), policy_fn=on_event).run(
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

        result = Sandbox(_policy(), policy_fn=on_event).run(
            ["python3", "-c", "print('hello')"]
        )
        assert result.success
        assert len(exec_events) > 0, "should have received execve events"

    def test_passthrough_no_modification(self):
        """policy_fn that does nothing should not affect execution."""
        count = {"n": 0}

        def on_event(event, ctx):
            count["n"] += 1

        result = Sandbox(_policy(), policy_fn=on_event).run(
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

        sb = Sandbox(_policy(), policy_fn=on_event)
        r1 = sb.run(["echo", "a"])
        r2 = sb.run(["echo", "b"])
        assert r1.success
        assert r2.success


# ---------------------------------------------------------------------------
# Integration: policy_fn restricts permissions
# ---------------------------------------------------------------------------

class TestPolicyFnRestrict:
    def test_restrict_network_on_execve(self):
        """Restrict network after seeing execve."""
        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.restrict_network([])

        result = Sandbox(
            _policy(net_allow=["127.0.0.1:443"]),
            policy_fn=on_event,
        ).run(["python3", "-c", "print('restricted')"])
        assert result.success
        assert b"restricted" in result.stdout

    def test_restrict_max_memory(self):
        """Restrict memory limit dynamically."""
        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.restrict_max_memory(32 * 1024 * 1024)

        result = Sandbox(_policy(), policy_fn=on_event).run(
            ["echo", "ok"]
        )
        # Should still run (echo uses very little memory)

    def test_restrict_max_processes(self):
        """Restrict process limit dynamically."""
        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.restrict_max_processes(1)

        result = Sandbox(_policy(), policy_fn=on_event).run(
            ["echo", "ok"]
        )


# ---------------------------------------------------------------------------
# Integration: per-PID restriction
# ---------------------------------------------------------------------------

class TestPolicyFnVerdict:
    def test_deny_with_errno(self):
        """Return a positive int to deny with that errno."""
        import errno
        import tempfile, os

        out = os.path.join(tempfile.gettempdir(), f"sandlock-test-denywith-{os.getpid()}")

        def on_event(event, ctx):
            if event.syscall == "connect":
                return errno.EACCES  # 13
            return 0

        result = Sandbox(
            _policy(net_allow=["127.0.0.1:443"]),
            policy_fn=on_event,
        ).run(["python3", "-c",
            f"import socket\n"
            f"s = socket.socket(); s.settimeout(0.5)\n"
            f"try:\n"
            f"  s.connect(('127.0.0.1', 1))\n"
            f"  open('{out}', 'w').write('CONNECTED')\n"
            f"except OSError as e:\n"
            f"  open('{out}', 'w').write(f'ERR:{{e.errno}}')\n"
            f"s.close()\n"
        ])
        assert result.success
        with open(out) as f:
            content = f.read()
        assert content == "ERR:13", f"expected EACCES (13), got: {content}"
        os.unlink(out)

    def test_audit_allows(self):
        """Return 'audit' or -2 to allow but flag."""
        def on_event(event, ctx):
            if event.category == "file":
                return "audit"
            return 0

        result = Sandbox(_policy(), policy_fn=on_event).run(
            ["cat", "/etc/hostname"]
        )
        assert result.success, "audit should allow the syscall"

    def test_deny_returns_true(self):
        """Return True to deny with EPERM (backward compat)."""
        def on_event(event, ctx):
            if event.syscall == "connect":
                return True
            return False

        result = Sandbox(
            _policy(net_allow=["127.0.0.1:443"]),
            policy_fn=on_event,
        ).run(["python3", "-c",
            "import socket; s=socket.socket(); s.settimeout(0.5); "
            "s.connect_ex(('127.0.0.1', 1)); s.close(); print('ok')"
        ])
        # connect was denied but process should still run
        assert result.success

    def test_deny_path_dynamic(self):
        """ctx.deny_path blocks file access."""
        import tempfile, os

        out = os.path.join(tempfile.gettempdir(), f"sandlock-test-denypath-{os.getpid()}")

        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.deny_path("/etc/hostname")
            return 0

        result = Sandbox(_policy(), policy_fn=on_event).run(
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
        """Per-PID network restriction."""
        def on_event(event, ctx):
            if event.syscall in ("execve", "execveat"):
                ctx.restrict_pid_network(event.pid, ["127.0.0.1"])

        result = Sandbox(
            _policy(net_allow=["127.0.0.1:443"]),
            policy_fn=on_event,
        ).run(["echo", "ok"])
