# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.sandbox.Sandbox."""

import os
from unittest.mock import patch, MagicMock

import pytest

from sandlock.policy import Policy
from sandlock.sandbox import Sandbox
from sandlock.exceptions import SandboxError


class TestSandboxInit:
    def test_default_id(self):
        sb = Sandbox(Policy())
        assert len(sb.id) == 12

    def test_custom_id(self):
        sb = Sandbox(Policy(), sandbox_id="test-123")
        assert sb.id == "test-123"

    def test_policy_stored(self):
        p = Policy(max_memory="512M")
        sb = Sandbox(p)
        assert sb.policy is p

    def test_not_alive_initially(self):
        sb = Sandbox(Policy())
        assert not sb.alive

    def test_from_profile_name(self, tmp_path, monkeypatch):
        import sandlock._profile as mod
        monkeypatch.setattr(mod, "_PROFILES_DIR", tmp_path)
        (tmp_path / "test.toml").write_text(
            'max_memory = "256M"\nclean_env = true\n'
        )
        sb = Sandbox("test")
        assert sb.policy.max_memory == "256M"
        assert sb.policy.clean_env is True
        assert sb.pid is None


class TestSandboxCall:
    def test_simple_callable(self):
        result = Sandbox(Policy()).call(lambda: 42)
        assert result.success
        assert result.value == 42

    def test_callable_with_args(self):
        result = Sandbox(Policy()).call(lambda x, y: x + y, args=(3, 4))
        assert result.success
        assert result.value == 7

    def test_callable_exception(self):
        def bad():
            raise ValueError("boom")

        result = Sandbox(Policy()).call(bad)
        assert not result.success
        assert "ValueError" in result.error

    def test_callable_returns_string(self):
        result = Sandbox(Policy()).call(lambda: "hello")
        assert result.success
        assert result.value == "hello"

    def test_callable_returns_dict(self):
        result = Sandbox(Policy()).call(lambda: {"key": "value"})
        assert result.success
        assert result.value == {"key": "value"}

    def test_callable_returns_list(self):
        result = Sandbox(Policy()).call(lambda: [1, 2, 3])
        assert result.success
        assert result.value == [1, 2, 3]


class TestSandboxRun:
    def test_simple_command(self):
        result = Sandbox(Policy()).run(["echo", "hello"])
        assert result.success
        assert b"hello" in result.stdout

    def test_command_failure(self):
        result = Sandbox(Policy()).run(["false"])
        assert not result.success
        assert result.exit_code != 0

    def test_command_not_found(self):
        result = Sandbox(Policy()).run(["nonexistent_command_xyz"])
        assert not result.success

    def test_stderr_captured(self):
        result = Sandbox(Policy()).run(
            ["python3", "-c", "import sys; sys.stderr.write('err\\n')"]
        )
        assert b"err" in result.stderr


class TestSandboxContextManager:
    def test_enter_exit(self):
        with Sandbox(Policy()) as sb:
            assert sb.id
        assert not sb.alive

    def test_exec_requires_context(self):
        sb = Sandbox(Policy())
        with pytest.raises(SandboxError, match="context manager"):
            sb.exec(["echo", "hello"])

    def test_pause_without_running_process(self):
        with Sandbox(Policy()) as sb:
            with pytest.raises(SandboxError, match="No running process"):
                sb.pause()

    def test_resume_without_running_process(self):
        with Sandbox(Policy()) as sb:
            with pytest.raises(SandboxError, match="No running process"):
                sb.resume()


class TestSandboxNested:
    def test_nested_returns_sandbox(self):
        sb = Sandbox(Policy())
        inner = sb.sandbox(Policy(max_memory="256M"))
        assert isinstance(inner, Sandbox)
        assert inner.policy.max_memory == "256M"

    def test_nested_sandbox_runs(self):
        """Parent sandbox spawns a nested child sandbox via call()."""
        parent_policy = Policy()
        child_policy = Policy(max_processes=4)

        def outer():
            inner = Sandbox(child_policy).call(lambda: 6 * 7)
            return inner.value

        result = Sandbox(parent_policy).call(outer)
        assert result.success
        assert result.value == 42

    def test_nested_sandbox_inherits_restrictions(self):
        """Nested sandbox cannot escalate write access beyond parent."""

        def outer():
            # Parent sandbox has no writable paths.  The inner sandbox
            # claims /tmp is writable, but Landlock is cumulative --
            # the inner ruleset cannot grant more than the parent allows.
            inner_policy = Policy(
                fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"],
                fs_writable=["/tmp"],
            )
            def try_write():
                import tempfile
                try:
                    with tempfile.NamedTemporaryFile(dir="/tmp", delete=True) as f:
                        f.write(b"hacked")
                    return "WRITTEN"
                except (PermissionError, OSError):
                    return "DENIED"
            result = Sandbox(inner_policy).call(try_write)
            return result.value

        parent_policy = Policy(
            fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev", "/tmp"],
        )
        result = Sandbox(parent_policy).call(outer)
        assert result.success
        assert result.value == "DENIED"


class TestPortRemap:
    """Test transparent TCP port remapping."""

    def test_two_sandboxes_same_virtual_port(self):
        """Two sandboxes bind the same virtual port without conflict."""
        import socket as sock_mod

        def bind_port():
            s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 8080))
            # getsockname returns virtual port (8080), so check bind succeeds
            name = s.getsockname()
            s.close()
            return name[1]

        policy = Policy(net_bind=["30000-30999"], port_remap=True)

        r1 = Sandbox(policy).call(bind_port)
        r2 = Sandbox(policy).call(bind_port)

        assert r1.success
        assert r2.success
        # Both see virtual port 8080 via getsockname
        assert r1.value == 8080
        assert r2.value == 8080

    def test_multiple_ports_in_one_sandbox(self):
        """Multiple virtual ports in one sandbox all bind successfully."""
        import socket as sock_mod

        def bind_three():
            ports = {}
            for vport in [3000, 5432, 8080]:
                s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
                s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", vport))
                ports[vport] = s.getsockname()[1]
                s.close()
            return ports

        policy = Policy(net_bind=["31000-31099"], port_remap=True)
        result = Sandbox(policy).call(bind_three)

        assert result.success
        # getsockname returns virtual ports
        assert result.value == {"3000": 3000, "5432": 5432, "8080": 8080}

    def test_same_virtual_port_remapped_consistently(self):
        """Binding the same virtual port twice in one sandbox reuses the mapping."""
        import socket as sock_mod

        def bind_twice():
            results = []
            for _ in range(2):
                s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
                s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", 9090))
                results.append(s.getsockname()[1])
                s.close()
            return results

        policy = Policy(net_bind=["32000-32099"], port_remap=True)
        result = Sandbox(policy).call(bind_twice)

        assert result.success
        # Same virtual port should map to the same real port
        assert result.value[0] == result.value[1]

    def test_port_in_range_not_remapped(self):
        """A port already in the net_bind range is passed through unchanged."""
        import socket as sock_mod

        def bind_real():
            s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 33050))  # Within net_bind range
            real = s.getsockname()[1]
            s.close()
            return real

        policy = Policy(net_bind=["33000-33099"], port_remap=True)
        result = Sandbox(policy).call(bind_real)

        assert result.success
        assert result.value == 33050  # Not remapped

    def test_getsockname_returns_virtual_port(self):
        """getsockname() should return the virtual port, not the real one."""
        import socket as sock_mod

        def bind_and_check():
            s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 4000))
            name = s.getsockname()
            s.close()
            return {"ip": name[0], "port": name[1]}

        policy = Policy(net_bind=["35000-35099"], port_remap=True)
        result = Sandbox(policy).call(bind_and_check)

        assert result.success
        assert result.value["port"] == 4000  # Virtual, not real
        assert result.value["ip"] == "127.0.0.1"

    def test_port_outside_range_remapped(self):
        """A virtual port outside net_bind binds successfully and getsockname shows virtual."""
        import socket as sock_mod

        def bind_virtual():
            s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 3000))  # Outside net_bind range
            port = s.getsockname()[1]
            s.close()
            return port

        policy = Policy(net_bind=["34000-34099"], port_remap=True)
        result = Sandbox(policy).call(bind_virtual)

        assert result.success
        assert result.value == 3000  # getsockname returns virtual port

    def test_ipv6_bind_remapped(self):
        """IPv6 bind is remapped the same as IPv4."""
        import socket as sock_mod

        def bind_ipv6():
            s = sock_mod.socket(sock_mod.AF_INET6, sock_mod.SOCK_STREAM)
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            s.bind(("::1", 5000))
            port = s.getsockname()[1]
            s.close()
            return port

        policy = Policy(net_bind=["36000-36099"], port_remap=True)
        result = Sandbox(policy).call(bind_ipv6)

        assert result.success
        assert result.value == 5000  # getsockname returns virtual port

    def test_ipv6_two_sandboxes_no_conflict(self):
        """Two sandboxes bind the same IPv6 virtual port without conflict."""
        import socket as sock_mod

        def bind_ipv6():
            s = sock_mod.socket(sock_mod.AF_INET6, sock_mod.SOCK_STREAM)
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            s.bind(("::1", 8080))
            s.close()
            return True

        policy = Policy(net_bind=["37000-37999"], port_remap=True)

        r1 = Sandbox(policy).call(bind_ipv6)
        r2 = Sandbox(policy).call(bind_ipv6)

        assert r1.success and r1.value is True
        assert r2.success and r2.value is True

    def test_cross_sandbox_port_scan_blocked(self):
        """A sandbox cannot connect to another sandbox's real port."""
        import socket as sock_mod

        def try_connect_to_other():
            s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            try:
                # 38000 is in the full net_bind range but belongs
                # to another sandbox's slice
                s.connect(("127.0.0.1", 38000))
                s.close()
                return "CONNECTED"
            except ConnectionRefusedError:
                return "BLOCKED"
            except OSError:
                return "BLOCKED"

        # Use range 38000-38199, each sandbox gets 100 ports.
        # First sandbox takes 38000-38099, second gets 38100-38199.
        policy = Policy(net_bind=["38000-38199"], port_remap=True)
        _r1 = Sandbox(policy).call(lambda: True)  # Consume first slice

        r2 = Sandbox(policy).call(try_connect_to_other)
        assert r2.success
        assert r2.value == "BLOCKED"

    def test_proc_net_tcp_shows_own_port_only(self):
        """/proc/net/tcp shows only the sandbox's own ports."""
        import socket as sock_mod

        def bind_and_read_proc():
            s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 5000))
            s.listen(1)
            with open("/proc/net/tcp") as f:
                lines = f.readlines()
            s.close()
            # Parse ports from /proc/net/tcp (skip header)
            ports = []
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    port_hex = parts[1].split(":")[1]
                    ports.append(int(port_hex, 16))
            return ports

        policy = Policy(
            net_bind=["39000-39099"],
            port_remap=True,
            fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"],
        )
        result = Sandbox(policy).call(bind_and_read_proc)

        assert result.success
        # Should see exactly one port: our remapped real port
        assert len(result.value) == 1
        assert 39000 <= result.value[0] <= 39099

    def test_proc_net_tcp_hides_host_ports(self):
        """/proc/net/tcp hides host ports (e.g. sshd on port 22)."""

        def read_proc():
            with open("/proc/net/tcp") as f:
                lines = f.readlines()
            ports = []
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    port_hex = parts[1].split(":")[1]
                    ports.append(int(port_hex, 16))
            return ports

        policy = Policy(
            net_bind=["39100-39199"],
            port_remap=True,
            fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"],
        )
        result = Sandbox(policy).call(read_proc)

        assert result.success
        # Host ports (e.g. sshd on 22) should NOT be visible
        assert 22 not in result.value
        # Only ports in the sandbox's net_bind range may appear
        # (from previous tests' sockets in TIME_WAIT)
        for p in result.value:
            assert 39100 <= p <= 39199

    def test_proc_net_tcp6_filtered(self):
        """/proc/net/tcp6 is filtered the same way."""
        import socket as sock_mod

        def bind_ipv6_and_read():
            s = sock_mod.socket(sock_mod.AF_INET6, sock_mod.SOCK_STREAM)
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            s.bind(("::1", 6000))
            s.listen(1)
            with open("/proc/net/tcp6") as f:
                lines = f.readlines()
            s.close()
            ports = []
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    port_hex = parts[1].split(":")[1]
                    ports.append(int(port_hex, 16))
            return ports

        policy = Policy(
            net_bind=["39200-39299"],
            port_remap=True,
            fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"],
        )
        result = Sandbox(policy).call(bind_ipv6_and_read)

        assert result.success
        # At least our bound port should be visible in the remapped range
        in_range = [p for p in result.value if 39200 <= p <= 39299]
        assert len(in_range) >= 1


class TestCpuThrottle:
    """Test SIGSTOP/SIGCONT CPU throttling."""

    @staticmethod
    def _burn_cpu():
        """Fixed CPU workload (not wall-clock dependent)."""
        total = 0
        for _ in range(20_000_000):
            total += 1
        return total

    def test_throttle_slows_execution(self):
        """50% throttle should take roughly 2x wall time."""
        import time

        # Baseline without throttle
        t0 = time.monotonic()
        Sandbox(Policy()).call(self._burn_cpu)
        base = time.monotonic() - t0

        # 50% throttle
        t0 = time.monotonic()
        result = Sandbox(Policy(max_cpu=50)).call(self._burn_cpu)
        throttled = time.monotonic() - t0

        assert result.success
        ratio = throttled / base
        # Allow generous range: 1.5x–3.0x (signal jitter, CI variance)
        assert 1.5 <= ratio <= 3.0, f"ratio={ratio:.1f}, expected ~2.0"

    def test_throttle_100_is_noop(self):
        """max_cpu=100 should not start a throttle thread."""
        result = Sandbox(Policy(max_cpu=100)).call(self._burn_cpu)
        assert result.success

    def test_throttle_result_correct(self):
        """Throttled process should still return correct results."""
        result = Sandbox(Policy(max_cpu=50)).call(self._burn_cpu)
        assert result.success
        assert result.value == 20_000_000
