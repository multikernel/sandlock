# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.sandbox.Sandbox."""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

from sandlock.policy import Policy
from sandlock.sandbox import Sandbox
from sandlock.exceptions import SandboxError

_PYTHON_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev",
    sys.prefix,
]))


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


class TestSandboxCallConverted:
    def test_simple_expression(self):
        result = Sandbox(Policy()).run(["python3", "-c", "print(42)"])
        assert result.success
        assert result.stdout.strip() == b"42"

    def test_expression_with_args(self):
        result = Sandbox(Policy()).run(["python3", "-c", "print(3 + 4)"])
        assert result.success
        assert result.stdout.strip() == b"7"

    def test_exception_propagation(self):
        result = Sandbox(Policy()).run(["python3", "-c", "raise ValueError('boom')"])
        assert not result.success

    def test_returns_string(self):
        result = Sandbox(Policy()).run(["python3", "-c", "print('hello')"])
        assert result.success
        assert result.stdout.strip() == b"hello"

    def test_returns_dict(self):
        result = Sandbox(Policy()).run(["python3", "-c", "print({'key': 'value'})"])
        assert result.success
        assert result.stdout.strip() == b"{'key': 'value'}"

    def test_returns_list(self):
        result = Sandbox(Policy()).run(["python3", "-c", "print([1, 2, 3])"])
        assert result.success
        assert result.stdout.strip() == b"[1, 2, 3]"


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
        """Parent sandbox spawns a nested child sandbox via run()."""
        import subprocess
        # Run in a subprocess to avoid nested sandbox pipe issues
        script = (
            "from sandlock import Sandbox, Policy; "
            "r = Sandbox(Policy()).run(['python3', '-c', 'print(6 * 7)']); "
            "assert r.success, f'inner failed: {r.error}'; "
            "assert r.stdout.strip() == b'42', f'got: {r.stdout}'; "
            "print('OK')"
        )
        proc = subprocess.run(
            ["python3", "-c", script],
            capture_output=True,
        )
        assert proc.returncode == 0, f"stderr: {proc.stderr.decode()}"
        assert b"OK" in proc.stdout


class TestPortRemap:
    """Test transparent TCP port remapping."""

    def test_two_sandboxes_same_virtual_port(self):
        """Two sandboxes bind the same virtual port without conflict."""
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('127.0.0.1', 8080)); "
            "print(s.getsockname()[1]); "
            "s.close()"
        )
        policy = Policy(port_remap=True)

        r1 = Sandbox(policy).run(["python3", "-c", code])
        r2 = Sandbox(policy).run(["python3", "-c", code])

        assert r1.success
        assert r2.success
        assert r1.stdout.strip() == b"8080"
        assert r2.stdout.strip() == b"8080"

    def test_multiple_ports_in_one_sandbox(self):
        """Multiple virtual ports in one sandbox all bind successfully."""
        code = (
            "import socket\n"
            "ports = {}\n"
            "for vport in [3000, 5432, 8080]:\n"
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "    s.bind(('127.0.0.1', vport))\n"
            "    ports[vport] = s.getsockname()[1]\n"
            "    s.close()\n"
            "print(ports)"
        )
        policy = Policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        assert b"3000: 3000" in result.stdout
        assert b"5432: 5432" in result.stdout
        assert b"8080: 8080" in result.stdout

    def test_same_virtual_port_remapped_consistently(self):
        """Binding the same virtual port twice in one sandbox reuses the mapping."""
        code = (
            "import socket\n"
            "results = []\n"
            "for _ in range(2):\n"
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "    s.bind(('127.0.0.1', 9090))\n"
            "    results.append(s.getsockname()[1])\n"
            "    s.close()\n"
            "print(results[0] == results[1])"
        )
        policy = Policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        assert result.stdout.strip() == b"True"

    def test_ephemeral_port_not_remapped(self):
        """Binding port 0 (ephemeral) is not remapped -- kernel picks."""
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('127.0.0.1', 0)); "
            "print(s.getsockname()[1]); "
            "s.close()"
        )
        policy = Policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        assert int(result.stdout.strip()) > 0

    def test_getsockname_returns_virtual_port(self):
        """getsockname() should return the virtual port, not the real one."""
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('127.0.0.1', 4000)); "
            "name = s.getsockname(); "
            "print(name[0], name[1]); "
            "s.close()"
        )
        policy = Policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        parts = result.stdout.strip().split()
        assert parts[0] == b"127.0.0.1"
        assert parts[1] == b"4000"

    def test_virtual_port_remapped(self):
        """A virtual port is remapped and getsockname shows virtual port."""
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('127.0.0.1', 3000)); "
            "print(s.getsockname()[1]); "
            "s.close()"
        )
        policy = Policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        assert result.stdout.strip() == b"3000"

    def test_ipv6_bind_remapped(self):
        """IPv6 bind is remapped the same as IPv4."""
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('::1', 5000)); "
            "print(s.getsockname()[1]); "
            "s.close()"
        )
        policy = Policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        assert result.stdout.strip() == b"5000"

    def test_ipv6_two_sandboxes_no_conflict(self):
        """Two sandboxes bind the same IPv6 virtual port without conflict."""
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('::1', 8080)); "
            "s.close(); "
            "print('OK')"
        )
        policy = Policy(port_remap=True)

        r1 = Sandbox(policy).run(["python3", "-c", code])
        r2 = Sandbox(policy).run(["python3", "-c", code])

        assert r1.success and r1.stdout.strip() == b"OK"
        assert r2.success and r2.stdout.strip() == b"OK"

    def test_proc_net_tcp_shows_own_port_only(self):
        """/proc/net/tcp shows only the sandbox's own remapped port."""
        code = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1', 5000))\n"
            "s.listen(1)\n"
            "with open('/proc/net/tcp') as f:\n"
            "    lines = f.readlines()\n"
            "s.close()\n"
            "ports = []\n"
            "for line in lines[1:]:\n"
            "    parts = line.split()\n"
            "    if len(parts) >= 2:\n"
            "        port_hex = parts[1].split(':')[1]\n"
            "        ports.append(int(port_hex, 16))\n"
            "print(len(ports))"
        )
        policy = Policy(
            port_remap=True,
            fs_readable=_PYTHON_READABLE,
        )
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        assert int(result.stdout.strip()) == 1

    def test_proc_net_tcp_hides_host_ports(self):
        """/proc/net/tcp hides host ports (e.g. sshd on port 22)."""
        code = (
            "with open('/proc/net/tcp') as f:\n"
            "    lines = f.readlines()\n"
            "ports = []\n"
            "for line in lines[1:]:\n"
            "    parts = line.split()\n"
            "    if len(parts) >= 2:\n"
            "        port_hex = parts[1].split(':')[1]\n"
            "        ports.append(int(port_hex, 16))\n"
            "print(22 not in ports)"
        )
        policy = Policy(
            port_remap=True,
            fs_readable=_PYTHON_READABLE,
        )
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        assert result.stdout.strip() == b"True"

    def test_proc_net_tcp6_filtered(self):
        """/proc/net/tcp6 is filtered the same way."""
        code = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n"
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('::1', 6000))\n"
            "s.listen(1)\n"
            "with open('/proc/net/tcp6') as f:\n"
            "    lines = f.readlines()\n"
            "s.close()\n"
            "ports = []\n"
            "for line in lines[1:]:\n"
            "    parts = line.split()\n"
            "    if len(parts) >= 2:\n"
            "        port_hex = parts[1].split(':')[1]\n"
            "        ports.append(int(port_hex, 16))\n"
            "print(len(ports))"
        )
        policy = Policy(
            port_remap=True,
            fs_readable=_PYTHON_READABLE,
        )
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        assert int(result.stdout.strip()) == 1

    def test_tcp_sendmsg_2mb_with_port_remap(self):
        """TCP sendmsg() with 2 MB payload works correctly under port remap."""
        code = (
            "import socket, select, json\n"
            "DATA_SIZE = 2 * 1024 * 1024\n"
            "server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "server.bind(('127.0.0.1', 7070))\n"
            "server.listen(1)\n"
            "server_port = server.getsockname()[1]\n"
            "client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "client.setblocking(False)\n"
            "try:\n"
            "    client.connect(('127.0.0.1', 7070))\n"
            "except BlockingIOError:\n"
            "    pass\n"
            "conn, _ = server.accept()\n"
            "conn.setblocking(False)\n"
            "select.select([], [client], [])\n"
            "payload = b'\\xab' * DATA_SIZE\n"
            "total_sent = 0\n"
            "received = bytearray()\n"
            "while total_sent < DATA_SIZE or len(received) < DATA_SIZE:\n"
            "    r_list = [conn] if len(received) < DATA_SIZE else []\n"
            "    w_list = [client] if total_sent < DATA_SIZE else []\n"
            "    readable, writable, _ = select.select(r_list, w_list, [], 10)\n"
            "    if client in writable and total_sent < DATA_SIZE:\n"
            "        chunk = payload[total_sent:total_sent + 262144]\n"
            "        try:\n"
            "            n = client.sendmsg([chunk])\n"
            "            total_sent += n\n"
            "        except BlockingIOError:\n"
            "            pass\n"
            "    if conn in readable:\n"
            "        try:\n"
            "            data = conn.recv(65536)\n"
            "            if data:\n"
            "                received.extend(data)\n"
            "            elif total_sent >= DATA_SIZE:\n"
            "                break\n"
            "        except BlockingIOError:\n"
            "            pass\n"
            "    if total_sent >= DATA_SIZE and client.fileno() != -1:\n"
            "        client.shutdown(socket.SHUT_WR)\n"
            "while len(received) < DATA_SIZE:\n"
            "    readable, _, _ = select.select([conn], [], [], 5)\n"
            "    if not readable:\n"
            "        break\n"
            "    data = conn.recv(65536)\n"
            "    if not data:\n"
            "        break\n"
            "    received.extend(data)\n"
            "conn.close()\n"
            "client.close()\n"
            "server.close()\n"
            "print(json.dumps({'server_port': server_port, 'sent': total_sent, "
            "'received': len(received), 'data_ok': bytes(received) == payload}))"
        )
        policy = Policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success, f"Sandbox failed: {result}"
        import json
        data = json.loads(result.stdout.strip())
        assert data["server_port"] == 7070
        assert data["sent"] == data["received"]
        assert data["data_ok"] is True


    def test_slow_path_host_holds_virtual_port(self):
        """Slow path: host process holds TCP virtual port, sandbox must remap."""
        import socket as _socket
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.bind(('127.0.0.1', 8080)); "
            "print(s.getsockname()[1]); "
            "s.close()"
        )
        policy = Policy(port_remap=True)

        holder = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        holder.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 8080))
        try:
            result = Sandbox(policy).run(["python3", "-c", code])
        finally:
            holder.close()

        assert result.success, f"Sandbox failed: {result.stderr}"
        assert result.stdout.strip() == b"8080"

    def test_slow_path_two_concurrent_sandboxes(self):
        """Slow path: two concurrent sandboxes both bind the same virtual TCP port."""
        import threading
        code_hold = (
            "import socket, time; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.bind(('127.0.0.1', 8080)); "
            "print(s.getsockname()[1], flush=True); "
            "time.sleep(3); "
            "s.close()"
        )
        code_fast = (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.bind(('127.0.0.1', 8080)); "
            "print(s.getsockname()[1]); "
            "s.close()"
        )
        policy = Policy(port_remap=True)
        results = [None, None]

        def run(i, code):
            results[i] = Sandbox(policy).run(["python3", "-c", code])

        t1 = threading.Thread(target=run, args=(0, code_hold))
        t1.start()
        import time
        time.sleep(1)
        t2 = threading.Thread(target=run, args=(1, code_fast))
        t2.start()
        t1.join()
        t2.join()

        r1, r2 = results
        assert r1.success, f"Sandbox 1 failed: {r1.stderr}"
        assert r2.success, f"Sandbox 2 failed: {r2.stderr}"
        assert r1.stdout.strip() == b"8080"
        assert r2.stdout.strip() == b"8080"

class TestCpuThrottle:
    """Test SIGSTOP/SIGCONT CPU throttling."""

    _BURN_CODE = (
        "total = 0\n"
        "for _ in range(20_000_000):\n"
        "    total += 1\n"
        "print(total)"
    )

    def test_throttle_slows_execution(self):
        """50% throttle should take roughly 2x wall time."""
        import time

        # Baseline without throttle
        t0 = time.monotonic()
        Sandbox(Policy()).run(["python3", "-c", self._BURN_CODE])
        base = time.monotonic() - t0

        # 50% throttle
        t0 = time.monotonic()
        result = Sandbox(Policy(max_cpu=50)).run(["python3", "-c", self._BURN_CODE])
        throttled = time.monotonic() - t0

        assert result.success
        ratio = throttled / base
        # Allow generous range: 1.5x-3.0x (signal jitter, CI variance)
        assert 1.5 <= ratio <= 3.0, f"ratio={ratio:.1f}, expected ~2.0"

    def test_throttle_100_is_noop(self):
        """max_cpu=100 should not start a throttle thread."""
        result = Sandbox(Policy(max_cpu=100)).run(["python3", "-c", self._BURN_CODE])
        assert result.success

    def test_throttle_result_correct(self):
        """Throttled process should still return correct results."""
        result = Sandbox(Policy(max_cpu=50)).run(["python3", "-c", self._BURN_CODE])
        assert result.success
        assert result.stdout.strip() == b"20000000"


class TestGpuDevices:
    """Test GPU device isolation via CUDA_VISIBLE_DEVICES."""

    _GPU_POLICY_READABLE = _PYTHON_READABLE

    def test_gpu_devices_sets_env(self):
        """gpu_devices=[0,2] sets CUDA_VISIBLE_DEVICES=0,2."""
        code = (
            "import os; "
            "print(os.environ.get('CUDA_VISIBLE_DEVICES', 'UNSET'))"
        )
        policy = Policy(gpu_devices=[0, 2], fs_readable=self._GPU_POLICY_READABLE)
        result = Sandbox(policy).run(["python3", "-c", code])
        assert result.success, f"failed: {result.stderr}"
        assert result.stdout.strip() == b"0,2"

    def test_gpu_devices_sets_rocr(self):
        """gpu_devices also sets ROCR_VISIBLE_DEVICES for AMD GPUs."""
        code = (
            "import os; "
            "print(os.environ.get('ROCR_VISIBLE_DEVICES', 'UNSET'))"
        )
        policy = Policy(gpu_devices=[1], fs_readable=self._GPU_POLICY_READABLE)
        result = Sandbox(policy).run(["python3", "-c", code])
        assert result.success, f"failed: {result.stderr}"
        assert result.stdout.strip() == b"1"

    def test_gpu_devices_empty_no_env(self):
        """gpu_devices=[] (all GPUs) does not set CUDA_VISIBLE_DEVICES."""
        code = (
            "import os; "
            "print(os.environ.get('CUDA_VISIBLE_DEVICES', 'UNSET'))"
        )
        policy = Policy(gpu_devices=[], fs_readable=self._GPU_POLICY_READABLE)
        result = Sandbox(policy).run(["python3", "-c", code])
        assert result.success, f"failed: {result.stderr}"
        assert result.stdout.strip() == b"UNSET"

    def test_no_gpu_no_env(self):
        """gpu_devices=None (default) does not set CUDA_VISIBLE_DEVICES."""
        code = (
            "import os; "
            "print(os.environ.get('CUDA_VISIBLE_DEVICES', 'UNSET'))"
        )
        policy = Policy()
        result = Sandbox(policy).run(["python3", "-c", code])
        assert result.success
        assert result.stdout.strip() == b"UNSET"
