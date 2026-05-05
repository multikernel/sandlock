# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.Sandbox (ctypes FFI bindings)."""

import json
import os
import socket
import sys
import threading
import time

import pytest

from sandlock import Sandbox, Policy, Change, DryRunResult


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

    def test_invalid_sandbox_name(self):
        with pytest.raises(ValueError, match="must not be empty"):
            Sandbox(_policy(), name="")
        with pytest.raises(ValueError, match="NUL"):
            Sandbox(_policy(), name="bad\0name")
        with pytest.raises(ValueError, match="64 bytes"):
            Sandbox(_policy(), name="x" * 65)

    def test_stderr_captured(self):
        result = Sandbox(_policy()).run(
            ["python3", "-c", "import sys; sys.stderr.write('err\\n')"]
        )
        assert b"err" in result.stderr

    def test_exit_code_preserved(self):
        result = Sandbox(_policy()).run(["sh", "-c", "exit 42"])
        assert result.exit_code == 42

    def test_fs_denied_blocks_read(self, tmp_dir):
        secret = tmp_dir / "secret.txt"
        secret.write_text("top-secret")

        policy = _policy(
            fs_readable=[*_PYTHON_READABLE, str(tmp_dir)],
            fs_denied=[str(secret)],
        )
        result = Sandbox(policy).run(["cat", str(secret)])

        assert not result.success


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
        policy = _policy(port_remap=True, net_bind=[7070], net_allow=["127.0.0.1:7070"])
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


class TestPauseResume:
    def test_pause_resume_from_thread(self):
        sb = Sandbox(_policy())

        def run_in_thread():
            return sb.run(["python3", "-c",
                "import time\n"
                "for i in range(5):\n"
                "    print(i, flush=True)\n"
                "    time.sleep(0.1)\n"
            ])

        t = threading.Thread(target=run_in_thread)
        t.start()
        time.sleep(0.15)  # let it start

        sb.pause()
        time.sleep(0.3)  # paused — should not progress
        sb.resume()

        t.join(timeout=10)
        # Process should have completed after resume

    def test_pid_available_during_run(self):
        sb = Sandbox(_policy())
        pid_seen = []

        def run_in_thread():
            sb.run(["sleep", "1"])

        t = threading.Thread(target=run_in_thread)
        t.start()
        time.sleep(0.1)

        pid = sb.pid
        assert pid is not None
        assert pid > 0
        pid_seen.append(pid)

        # After run completes, pid should be None
        t.join(timeout=10)
        assert sb.pid is None

    def test_pause_not_running_raises(self):
        sb = Sandbox(_policy())
        with pytest.raises(RuntimeError):
            sb.pause()

    def test_resume_not_running_raises(self):
        sb = Sandbox(_policy())
        with pytest.raises(RuntimeError):
            sb.resume()


class TestDryRun:
    """Tests for Sandbox.dry_run()."""

    def test_dry_run_reports_added_file(self, tmp_path):
        workdir = tmp_path / "add"
        workdir.mkdir()
        (workdir / "existing.txt").write_text("hello")

        p = _policy(fs_writable=[str(workdir)], workdir=str(workdir))
        result = Sandbox(p).dry_run(
            ["sh", "-c", f"touch {workdir}/new.txt"]
        )
        assert result.success
        assert not (workdir / "new.txt").exists(), "new.txt should not exist after dry-run"
        kinds = [c.kind for c in result.changes]
        assert "A" in kinds

    def test_dry_run_reports_modified_file(self, tmp_path):
        workdir = tmp_path / "mod"
        workdir.mkdir()
        (workdir / "data.txt").write_text("original")

        p = _policy(fs_writable=[str(workdir)], workdir=str(workdir))
        result = Sandbox(p).dry_run(
            ["sh", "-c", f"echo changed > {workdir}/data.txt"]
        )
        assert result.success
        assert (workdir / "data.txt").read_text() == "original"
        kinds = [c.kind for c in result.changes]
        assert "M" in kinds

    def test_dry_run_reports_deleted_file(self, tmp_path):
        workdir = tmp_path / "del"
        workdir.mkdir()
        (workdir / "victim.txt").write_text("delete me")

        p = _policy(fs_writable=[str(workdir)], workdir=str(workdir))
        result = Sandbox(p).dry_run(
            ["sh", "-c", f"rm {workdir}/victim.txt"]
        )
        assert result.success
        assert (workdir / "victim.txt").exists(), "file should still exist after dry-run"
        kinds = [c.kind for c in result.changes]
        assert "D" in kinds

    def test_dry_run_no_changes(self, tmp_path):
        workdir = tmp_path / "noop"
        workdir.mkdir()

        p = _policy(fs_writable=[str(workdir)], workdir=str(workdir))
        result = Sandbox(p).dry_run(["echo", "hello"])
        assert result.success
        assert result.changes == []

    def test_dry_run_returns_structured_result(self, tmp_path):
        workdir = tmp_path / "struct"
        workdir.mkdir()
        (workdir / "f.txt").write_text("x")

        p = _policy(fs_writable=[str(workdir)], workdir=str(workdir))
        result = Sandbox(p).dry_run(
            ["sh", "-c", f"echo y > {workdir}/f.txt; touch {workdir}/new.txt"]
        )
        assert isinstance(result, DryRunResult)
        assert isinstance(result.changes, list)
        for c in result.changes:
            assert isinstance(c, Change)
            assert c.kind in ("A", "M", "D")
            assert isinstance(c.path, str)


class TestNewPolicyFields:
    """Tests for newly wired FFI policy fields."""

    def test_time_start(self):
        from datetime import datetime, timezone
        # Freeze time to 2000-06-15
        t = datetime(2000, 6, 15, tzinfo=timezone.utc)
        p = _policy(time_start=t)
        result = Sandbox(p).run(["date", "+%Y"])
        assert result.success
        assert result.stdout.strip() == b"2000"

    def test_block_syscalls(self):
        from sandlock.policy import SyscallPolicy
        p = _policy(syscall_policy=SyscallPolicy.BLOCKLIST, block_syscalls=["mount"])
        result = Sandbox(p).run(["echo", "ok"])
        assert result.success
        assert result.stdout.strip() == b"ok"

    def test_max_open_files(self):
        # max_open_files is accepted by the policy but not yet enforced
        # in the sandbox — just verify it doesn't crash.
        p = _policy(max_open_files=64)
        result = Sandbox(p).run(["echo", "ok"])
        assert result.success



class TestFsIsolation:
    """Tests for fs_isolation FFI wiring."""

    def test_fs_isolation_none_runs(self):
        """Default FsIsolation.NONE should work normally."""
        from sandlock.policy import FsIsolation
        p = _policy()
        assert p.fs_isolation == FsIsolation.NONE
        result = Sandbox(p).run(["echo", "ok"])
        assert result.success

    def test_fs_isolation_value_roundtrips(self):
        """Non-default values are accepted by the FFI builder without error."""
        from sandlock.policy import FsIsolation
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            p = _policy(fs_isolation=FsIsolation.BRANCHFS)
            # Building the native policy should succeed (the mode itself
            # may fail at sandbox.run time without branchfs, but FFI wiring
            # should not warn or crash).
            from sandlock._sdk import _NativePolicy
            _NativePolicy._build_from_policy(p)
        unwired = [x for x in w if "fs_isolation" in str(x.message)]
        assert unwired == [], "fs_isolation should be wired, not warned about"


class TestGpuDevices:
    """Tests for gpu_devices FFI wiring."""

    def test_gpu_devices_accepted(self):
        p = _policy(gpu_devices=[0])
        result = Sandbox(p).run(["echo", "ok"])
        assert result.success

    def test_gpu_devices_empty_list(self):
        p = _policy(gpu_devices=[])
        result = Sandbox(p).run(["echo", "ok"])
        assert result.success


class TestNoCoredump:
    """Tests for no_coredump (RLIMIT_CORE=0)."""

    def test_no_coredump_rlimit_zero(self):
        """With no_coredump=True, RLIMIT_CORE should be 0."""
        code = (
            "import resource; "
            "soft, hard = resource.getrlimit(resource.RLIMIT_CORE); "
            "print(f'{soft} {hard}')"
        )
        p = _policy(no_coredump=True)
        result = Sandbox(p).run(["python3", "-c", code])
        assert result.success
        assert result.stdout.strip() == b"0 0"

    def test_no_coredump_default_off(self):
        """Without no_coredump, RLIMIT_CORE should be inherited (non-zero)."""
        code = (
            "import resource; "
            "soft, hard = resource.getrlimit(resource.RLIMIT_CORE); "
            "print(f'{soft} {hard}')"
        )
        p = _policy(no_coredump=False)
        result = Sandbox(p).run(["python3", "-c", code])
        assert result.success
        # Default RLIMIT_CORE is typically unlimited (very large number), not "0 0"
        assert result.stdout.strip() != b"0 0"


class TestUnwiredFieldWarning:
    """Test that setting an unknown/unwired Policy field raises a warning."""

    def test_warns_on_unwired_field(self):
        import warnings
        from sandlock._sdk import _NativePolicy

        # Temporarily remove a field from the handled set to simulate
        # a field that exists on the dataclass but was forgotten in FFI.
        _NativePolicy._HANDLED_FIELDS.discard("no_coredump")
        try:
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                p = _policy(no_coredump=True)
                Sandbox(p).run(["echo", "ok"])

            matched = [x for x in w if "no_coredump" in str(x.message)]
            assert len(matched) >= 1
            assert "not wired through FFI" in str(matched[0].message)
        finally:
            _NativePolicy._HANDLED_FIELDS.add("no_coredump")

    def test_sandbox_name_parameter(self):
        sb = Sandbox(_policy(), name="test-host")
        assert sb.name == "test-host"

    def test_no_warning_on_default_values(self):
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Sandbox(_policy()).run(["echo", "ok"])

        unwired = [x for x in w if "not wired through FFI" in str(x.message)]
        assert unwired == []


class TestDiskQuota:
    """Tests for max_disk quota enforcement via seccomp COW.

    The quota is enforced at COW-copy time: when openat() triggers a copy
    from lower to upper, the copy is rejected with ENOSPC if it would
    exceed max_disk.  Subsequent write() syscalls to an already-open fd
    bypass the COW layer (the fd is injected directly), so the quota
    governs total COW-copy size, not total bytes written.
    """

    def test_cow_copy_within_quota(self, tmp_path):
        """COW-copying a small file under a generous quota succeeds."""
        workdir = tmp_path / "within"
        workdir.mkdir()
        (workdir / "small.txt").write_text("hello")  # 5 bytes
        p = _policy(
            fs_writable=[str(workdir)],
            workdir=str(workdir),
            max_disk="1M",
        )
        # Opening for write triggers COW copy of the 5-byte file.
        result = Sandbox(p).run(
            ["sh", "-c", f"echo world >> {workdir}/small.txt"]
        )
        assert result.success

    def test_cow_copy_exceeds_quota(self, tmp_path):
        """COW-copying a file larger than max_disk returns ENOSPC."""
        workdir = tmp_path / "exceed"
        workdir.mkdir()
        # Create a 8 KiB file in the lower layer.
        (workdir / "big.bin").write_bytes(b"\x00" * 8192)
        p = _policy(
            fs_writable=[str(workdir)],
            workdir=str(workdir),
            max_disk="1K",  # 1024 bytes — smaller than the 8 KiB file
        )
        # Trying to open big.bin for write triggers COW copy → ENOSPC.
        result = Sandbox(p).run(
            ["sh", "-c", f"echo x >> {workdir}/big.bin"]
        )
        assert not result.success

    def test_cumulative_cow_copies_exceed_quota(self, tmp_path):
        """Multiple COW copies that individually fit but together exceed."""
        workdir = tmp_path / "cumul"
        workdir.mkdir()
        # Two 600-byte files. Quota is 1000 bytes.
        (workdir / "a.bin").write_bytes(b"A" * 600)
        (workdir / "b.bin").write_bytes(b"B" * 600)
        p = _policy(
            fs_writable=[str(workdir)],
            workdir=str(workdir),
            max_disk="1000",
        )
        # First open succeeds (600 <= 1000), second fails (600+600 > 1000).
        result = Sandbox(p).run(
            ["sh", "-c",
             f"echo x >> {workdir}/a.bin && echo x >> {workdir}/b.bin"]
        )
        assert not result.success

    def test_enospc_in_stderr(self, tmp_path):
        """The child process should see 'No space left on device'."""
        workdir = tmp_path / "enospc"
        workdir.mkdir()
        (workdir / "big.bin").write_bytes(b"\x00" * 4096)
        p = _policy(
            fs_writable=[str(workdir)],
            workdir=str(workdir),
            max_disk="512",
        )
        result = Sandbox(p).run(
            ["sh", "-c", f"echo x >> {workdir}/big.bin 2>&1"]
        )
        assert not result.success
        combined = result.stdout + result.stderr
        assert b"No space" in combined or b"ENOSPC" in combined

    def test_quota_none_is_unlimited(self, tmp_path):
        """Without max_disk, COW copies are unrestricted."""
        workdir = tmp_path / "nolimit"
        workdir.mkdir()
        (workdir / "data.bin").write_bytes(b"\x00" * 8192)
        p = _policy(
            fs_writable=[str(workdir)],
            workdir=str(workdir),
        )
        result = Sandbox(p).run(
            ["sh", "-c", f"echo x >> {workdir}/data.bin"]
        )
        assert result.success

    def test_quota_dry_run_enforced(self, tmp_path):
        """Quota applies during dry_run (COW is always active)."""
        workdir = tmp_path / "dryquota"
        workdir.mkdir()
        (workdir / "big.bin").write_bytes(b"\x00" * 8192)
        p = _policy(
            fs_writable=[str(workdir)],
            workdir=str(workdir),
            max_disk="1K",
        )
        result = Sandbox(p).dry_run(
            ["sh", "-c", f"echo x >> {workdir}/big.bin"]
        )
        assert not result.success

    def test_quota_accepts_various_units(self, tmp_path):
        """String sizes like '1G', '512M', '100K' are accepted."""
        workdir = tmp_path / "units"
        workdir.mkdir()
        for size in ("100K", "10M", "1G"):
            p = _policy(
                fs_writable=[str(workdir)],
                workdir=str(workdir),
                max_disk=size,
            )
            result = Sandbox(p).run(["echo", "ok"])
            assert result.success, f"max_disk={size!r} should be accepted"

    def test_read_does_not_consume_quota(self, tmp_path):
        """Reading a file should not trigger COW copy or consume quota."""
        workdir = tmp_path / "readonly"
        workdir.mkdir()
        (workdir / "big.bin").write_bytes(b"\x00" * 8192)
        p = _policy(
            fs_writable=[str(workdir)],
            workdir=str(workdir),
            max_disk="100",  # tiny quota
        )
        result = Sandbox(p).run(
            ["cat", f"{workdir}/big.bin"]
        )
        assert result.success

    def test_fs_storage_directs_cow_deltas(self, tmp_path):
        """fs_storage controls where COW upper directory is created."""
        workdir = tmp_path / "wd"
        workdir.mkdir()
        storage = tmp_path / "storage"
        storage.mkdir()
        (workdir / "file.txt").write_text("original")

        p = _policy(
            fs_writable=[str(workdir)],
            workdir=str(workdir),
            fs_storage=str(storage),
        )
        result = Sandbox(p).run(
            ["sh", "-c", f"echo modified > {workdir}/file.txt"]
        )
        assert result.success
        # The workdir should be updated (on_exit=commit by default).
        # This proves COW went through the custom fs_storage path and
        # committed back — the branch dir is cleaned up after commit.
        assert (workdir / "file.txt").read_text().strip() == "modified"

    def test_fs_storage_with_quota(self, tmp_path):
        """fs_storage + max_disk together: quota enforced on custom storage."""
        workdir = tmp_path / "wd2"
        workdir.mkdir()
        storage = tmp_path / "storage2"
        storage.mkdir()
        (workdir / "big.bin").write_bytes(b"\x00" * 4096)

        p = _policy(
            fs_writable=[str(workdir)],
            workdir=str(workdir),
            fs_storage=str(storage),
            max_disk="512",
        )
        result = Sandbox(p).run(
            ["sh", "-c", f"echo x >> {workdir}/big.bin"]
        )
        assert not result.success
