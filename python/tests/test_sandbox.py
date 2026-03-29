# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.Sandbox (ctypes FFI bindings)."""

import json
import os
import socket
import sys
import threading
import time

import pytest

from sandlock import Sandbox, Policy


_PYTHON_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev",
    sys.prefix,
]))

def _policy(**overrides):
    """Minimal policy with standard readable paths."""
    defaults = {"fs_readable": _PYTHON_READABLE}
    defaults.update(overrides)
    return Policy(**defaults)


class TestSandboxRun:
    def test_simple_command(self):
        result = Sandbox(_policy()).run(["echo", "hello"])
        assert result.success
        assert b"hello" in result.stdout

    def test_python_expression(self):
        result = Sandbox(_policy()).run(["python3", "-c", "print(42)"])
        assert result.success
        assert result.stdout.strip() == b"42"

    def test_command_failure(self):
        result = Sandbox(_policy()).run(["false"])
        assert not result.success
        assert result.exit_code != 0

    def test_command_not_found(self):
        result = Sandbox(_policy()).run(["nonexistent_command_xyz"])
        assert not result.success

    def test_stderr_captured(self):
        result = Sandbox(_policy()).run(
            ["python3", "-c", "import sys; sys.stderr.write('err\\n')"]
        )
        assert b"err" in result.stderr

    def test_exit_code_preserved(self):
        result = Sandbox(_policy()).run(["sh", "-c", "exit 42"])
        assert result.exit_code == 42


class TestPortRemap:
    """Test transparent TCP port remapping."""

    def test_two_sandboxes_same_virtual_port(self):
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('127.0.0.1', 8080)); "
            "print(s.getsockname()[1]); "
            "s.close()"
        )
        policy = _policy(port_remap=True)

        r1 = Sandbox(policy).run(["python3", "-c", code])
        r2 = Sandbox(policy).run(["python3", "-c", code])

        assert r1.success
        assert r2.success
        assert r1.stdout.strip() == b"8080"
        assert r2.stdout.strip() == b"8080"

    def test_getsockname_returns_virtual_port(self):
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('127.0.0.1', 4000)); "
            "name = s.getsockname(); "
            "print(name[0], name[1]); "
            "s.close()"
        )
        policy = _policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        parts = result.stdout.strip().split()
        assert parts[0] == b"127.0.0.1"
        assert parts[1] == b"4000"

    def test_ephemeral_port_not_remapped(self):
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('127.0.0.1', 0)); "
            "print(s.getsockname()[1]); "
            "s.close()"
        )
        policy = _policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        assert int(result.stdout.strip()) > 0

    def test_ipv6_bind_remapped(self):
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('::1', 5000)); "
            "print(s.getsockname()[1]); "
            "s.close()"
        )
        policy = _policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success
        assert result.stdout.strip() == b"5000"

    def test_slow_path_host_holds_virtual_port(self):
        code = (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
            "s.bind(('127.0.0.1', 8080)); "
            "print(s.getsockname()[1]); "
            "s.close()"
        )
        policy = _policy(port_remap=True, net_bind=[8080])

        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 8080))
        try:
            result = Sandbox(policy).run(["python3", "-c", code])
        finally:
            holder.close()

        assert result.success, f"Sandbox failed: {result.stderr}"
        assert result.stdout.strip() == b"8080"

    def test_tcp_sendmsg_2mb_with_port_remap(self):
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
        policy = _policy(port_remap=True)
        result = Sandbox(policy).run(["python3", "-c", code])

        assert result.success, f"Sandbox failed: {result}"
        data = json.loads(result.stdout.strip())
        assert data["server_port"] == 7070
        assert data["sent"] == data["received"]
        assert data["data_ok"] is True


class TestCpuThrottle:
    _BURN_CODE = (
        "total = 0\n"
        "for _ in range(20_000_000):\n"
        "    total += 1\n"
        "print(total)"
    )

    def test_throttle_slows_execution(self):
        t0 = time.monotonic()
        Sandbox(_policy()).run(["python3", "-c", self._BURN_CODE])
        base = time.monotonic() - t0

        t0 = time.monotonic()
        result = Sandbox(_policy(max_cpu=50)).run(["python3", "-c", self._BURN_CODE])
        throttled = time.monotonic() - t0

        assert result.success
        ratio = throttled / base
        assert 1.5 <= ratio <= 3.0, f"ratio={ratio:.1f}, expected ~2.0"

    def test_throttle_100_is_noop(self):
        result = Sandbox(_policy(max_cpu=100)).run(["python3", "-c", self._BURN_CODE])
        assert result.success

    def test_throttle_result_correct(self):
        result = Sandbox(_policy(max_cpu=50)).run(["python3", "-c", self._BURN_CODE])
        assert result.success
        assert result.stdout.strip() == b"20000000"
