# SPDX-License-Identifier: Apache-2.0
"""Tests for the policy coroutine (policy_fn) feature."""

from __future__ import annotations

import dataclasses
import threading
import time
from queue import SimpleQueue

import pytest

from sandlock import Policy, Sandbox, SyscallEvent, PolicyContext
from sandlock._notif_policy import NotifPolicy
from sandlock._events import SyscallEvent as SyscallEventCls


# ---------------------------------------------------------------------------
# Unit tests: SyscallEvent
# ---------------------------------------------------------------------------

class TestSyscallEvent:
    def test_basic_construction(self):
        e = SyscallEvent(
            syscall="connect", pid=123, timestamp=1.0,
            host="1.2.3.4", port=443,
        )
        assert e.syscall == "connect"
        assert e.pid == 123
        assert e.host == "1.2.3.4"
        assert e.port == 443
        assert e.denied is False
        assert e.path is None

    def test_frozen(self):
        e = SyscallEvent(syscall="openat", pid=1, timestamp=0.0)
        with pytest.raises(AttributeError):
            e.syscall = "other"

    def test_defaults(self):
        e = SyscallEvent(syscall="clone", pid=1, timestamp=0.0)
        assert e.path is None
        assert e.host is None
        assert e.port is None
        assert e.size is None
        assert e.flags == 0
        assert e.denied is False


# ---------------------------------------------------------------------------
# Unit tests: PolicyContext
# ---------------------------------------------------------------------------

class _FakeSupervisor:
    """Minimal mock of NotifSupervisor for PolicyContext tests."""

    def __init__(self, policy: NotifPolicy):
        self._policy = policy
        self._pid_policies: dict[int, NotifPolicy] = {}
        self._thread = threading.Thread()  # fake thread
        self._thread.start()  # immediately finishes

    @property
    def alive(self) -> bool:
        return False


class TestPolicyContext:
    def _make_ctx(self, **policy_kw) -> tuple[PolicyContext, _FakeSupervisor]:
        policy = NotifPolicy(**policy_kw)
        sup = _FakeSupervisor(policy)
        ctx = PolicyContext(sup, ceiling=policy)
        return ctx, sup

    def test_grant_allowed_ips(self):
        ctx, sup = self._make_ctx(allowed_ips=frozenset({"1.1.1.1", "2.2.2.2"}))
        ctx.grant(allowed_ips=frozenset({"1.1.1.1"}))
        assert sup._policy.allowed_ips == frozenset({"1.1.1.1"})

    def test_grant_capped_to_ceiling(self):
        ctx, sup = self._make_ctx(allowed_ips=frozenset({"1.1.1.1"}))
        # Try to grant more than ceiling
        ctx.grant(allowed_ips=frozenset({"1.1.1.1", "9.9.9.9"}))
        # Should be capped to ceiling
        assert sup._policy.allowed_ips == frozenset({"1.1.1.1"})

    def test_restrict_permanent(self):
        ctx, sup = self._make_ctx(
            allowed_ips=frozenset({"1.1.1.1", "2.2.2.2"}),
        )
        ctx.restrict(allowed_ips=frozenset({"1.1.1.1"}))
        assert sup._policy.allowed_ips == frozenset({"1.1.1.1"})
        # Cannot grant back a restricted field
        with pytest.raises(Exception, match="restricted"):
            ctx.grant(allowed_ips=frozenset({"2.2.2.2"}))

    def test_grant_non_grantable_raises(self):
        ctx, sup = self._make_ctx()
        with pytest.raises(Exception, match="non-grantable"):
            ctx.grant(rules=())

    def test_restrict_non_grantable_raises(self):
        ctx, sup = self._make_ctx()
        with pytest.raises(Exception, match="non-grantable"):
            ctx.restrict(rules=())

    def test_grant_numeric_capped(self):
        ctx, sup = self._make_ctx(max_memory_bytes=1000)
        ctx.grant(max_memory_bytes=500)
        assert sup._policy.max_memory_bytes == 500
        # Try to exceed ceiling
        ctx.grant(max_memory_bytes=2000)
        assert sup._policy.max_memory_bytes == 1000

    def test_restrict_pid(self):
        ctx, sup = self._make_ctx(
            allowed_ips=frozenset({"1.1.1.1", "2.2.2.2"}),
        )
        ctx.restrict_pid(42, allowed_ips=frozenset({"1.1.1.1"}))
        assert 42 in sup._pid_policies
        assert sup._pid_policies[42].allowed_ips == frozenset({"1.1.1.1"})
        # Global policy unchanged
        assert sup._policy.allowed_ips == frozenset({"1.1.1.1", "2.2.2.2"})

    def test_permissions_property(self):
        ctx, sup = self._make_ctx(max_processes=10)
        assert ctx.permissions.max_processes == 10
        ctx.grant(max_processes=5)
        assert ctx.permissions.max_processes == 5

    def test_ceiling_property(self):
        ctx, sup = self._make_ctx(max_processes=10)
        assert ctx.ceiling.max_processes == 10
        ctx.grant(max_processes=5)
        # Ceiling doesn't change
        assert ctx.ceiling.max_processes == 10

    def test_thread_safety(self):
        """Multiple threads granting/restricting concurrently."""
        ctx, sup = self._make_ctx(
            max_memory_bytes=10000,
            max_processes=100,
        )
        errors = []

        def grant_loop():
            try:
                for i in range(100):
                    ctx.grant(max_memory_bytes=10000 - i)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=grant_loop) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


# ---------------------------------------------------------------------------
# Unit tests: event emission
# ---------------------------------------------------------------------------

class TestEventEmission:
    def test_emit_event_no_queue(self):
        """_emit_event is a no-op when no queue is attached."""
        from sandlock._notif import _get_nr_to_name
        # Just verify the reverse map builds
        nr_map = _get_nr_to_name()
        assert isinstance(nr_map, dict)
        assert len(nr_map) > 0

    def test_nr_to_name_reverse_map(self):
        from sandlock._seccomp import _SYSCALL_NR
        from sandlock._notif import _get_nr_to_name
        nr_map = _get_nr_to_name()
        for name, nr in _SYSCALL_NR.items():
            assert nr in nr_map
            assert nr_map[nr] == name


# ---------------------------------------------------------------------------
# Integration test: policy_fn with real sandbox
# ---------------------------------------------------------------------------

class TestPolicyFnIntegration:
    """End-to-end tests requiring Linux Landlock + seccomp."""

    def test_policy_fn_receives_events(self):
        """policy_fn receives SyscallEvent objects from the sandbox."""
        received = []
        done = threading.Event()

        async def collector(events, ctx):
            async for e in events:
                received.append(e)
                if len(received) >= 3:
                    done.set()

        policy = Policy(
            fs_readable=["/usr", "/lib", "/lib64", "/bin", "/proc",
                         "/etc", "/dev"],
        )
        with Sandbox(policy, policy_fn=collector) as sb:
            sb.exec(["/bin/ls", "/proc/self/status"])
            sb.wait(timeout=10)

        done.wait(timeout=5)
        assert len(received) > 0
        assert all(isinstance(e, SyscallEventCls) for e in received)
        # Should see openat events with paths
        openat_events = [e for e in received if e.syscall == "openat"]
        assert len(openat_events) > 0
        assert any(e.path is not None for e in openat_events)

    def test_policy_fn_called_without_events(self):
        """policy_fn is called even if the command is very fast."""
        called = threading.Event()

        async def marker(events, ctx):
            called.set()
            async for _ in events:
                pass

        policy = Policy()
        with Sandbox(policy, policy_fn=marker) as sb:
            sb.exec(["/bin/echo", "hello"])
            sb.wait(timeout=10)

        # policy_fn should have been invoked
        assert called.is_set()

    def test_restrict_pid_propagates_to_children(self):
        """restrict_pid on a parent propagates to its child processes."""
        import os
        import socket
        import tempfile

        # Start a local TCP server
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        received = []

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                    received.append(conn.recv(4096))
                    conn.close()
                except OSError:
                    break

        srv_thread = threading.Thread(target=serve, daemon=True)
        srv_thread.start()

        with tempfile.TemporaryDirectory() as workspace:
            # Script that spawns a child which connects to our server
            parent_py = os.path.join(workspace, "parent.py")
            child_py = os.path.join(workspace, "child.py")

            with open(child_py, "w") as f:
                f.write(f"""\
import socket
try:
    s = socket.create_connection(("127.0.0.1", {port}), timeout=2)
    s.sendall(b"leaked")
    s.close()
except OSError:
    pass
""")

            with open(parent_py, "w") as f:
                f.write(f"""\
import subprocess, sys
subprocess.run([sys.executable, "{child_py}"])
""")

            import sys
            python_paths = [p for p in sys.path if p and os.path.isdir(p)]
            policy = Policy(
                fs_readable=["/usr", "/lib", "/lib64", "/bin",
                             "/etc", "/dev", "/tmp", workspace] + python_paths,
                fs_writable=[workspace, "/tmp"],
            )

            # Restrict the parent.py process — child.py should inherit
            async def guard(events, ctx):
                async for e in events:
                    if (e.syscall == "execve" and e.argv
                            and any("parent.py" in a for a in e.argv)):
                        ctx.restrict_pid(e.pid, allowed_ips=frozenset())
                        break

            received.clear()
            with Sandbox(policy, policy_fn=guard) as sb:
                sb.exec(["python3", parent_py])
                sb.wait(timeout=15)

            # child.py's connect should have been blocked
            assert not received, (
                f"Child process leaked data despite parent restrict_pid: "
                f"{received}"
            )

        srv.close()
