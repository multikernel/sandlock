# SPDX-License-Identifier: Apache-2.0
"""Tests for checkpoint and restore (hybrid: OS-level + optional app-level)."""

from __future__ import annotations

import os
import pickle
import socket
import struct
import time
import threading
import unittest
from pathlib import Path
from unittest import mock

from sandlock._checkpoint import (
    Checkpoint,
    TRIGGER_CHECKPOINT,
    _send_bytes,
    _recv_bytes,
    _CheckpointListener,
    start_child_listener,
    request_app_state,
)
from sandlock.policy import Policy, FsIsolation, BranchAction


class TestCheckpointDataclass(unittest.TestCase):
    def test_fields(self):
        cp = Checkpoint(
            policy_data=pickle.dumps(Policy()),
            app_state=b"hello",
            branch_id="abc123",
            fs_mount="/mnt/ws",
            sandbox_id="sb-1",
        )
        self.assertEqual(cp.app_state, b"hello")
        self.assertEqual(cp.branch_id, "abc123")
        self.assertEqual(cp.fs_mount, "/mnt/ws")
        self.assertEqual(cp.sandbox_id, "sb-1")
        self.assertIsNone(cp.process_state)

    def test_policy_roundtrip(self):
        policy = Policy(max_memory="256M", max_processes=10)
        cp = Checkpoint(
            policy_data=pickle.dumps(policy),
            app_state=b"",
        )
        restored_policy = pickle.loads(cp.policy_data)
        self.assertEqual(restored_policy.max_memory, "256M")
        self.assertEqual(restored_policy.max_processes, 10)

    def test_defaults(self):
        cp = Checkpoint()
        self.assertIsNone(cp.process_state)
        self.assertIsNone(cp.branch_id)
        self.assertIsNone(cp.fs_mount)
        self.assertIsNone(cp.app_state)
        self.assertIsNone(cp.sandbox_id)
        self.assertEqual(cp.policy_data, b"")

    def test_with_process_state(self):
        from sandlock._ptrace import ProcessState, ThreadState, RegisterState
        ps = ProcessState(
            pid=1234,
            threads=[ThreadState(tid=1234, registers=RegisterState(arch="x86_64", data=b"\x00" * 216))],
            cwd="/tmp",
            exe="/usr/bin/python3",
        )
        cp = Checkpoint(process_state=ps, policy_data=b"")
        self.assertEqual(cp.process_state.pid, 1234)
        self.assertEqual(len(cp.process_state.threads), 1)
        self.assertEqual(cp.process_state.cwd, "/tmp")


class TestWireProtocol(unittest.TestCase):
    """Test the length-prefixed wire protocol (_send_bytes / _recv_bytes)."""

    def test_send_recv_roundtrip(self):
        r, w = os.pipe()
        try:
            _send_bytes(w, b"hello world")
            result = _recv_bytes(r)
            self.assertEqual(result, b"hello world")
        finally:
            os.close(r)
            os.close(w)

    def test_empty_message(self):
        r, w = os.pipe()
        try:
            _send_bytes(w, b"")
            result = _recv_bytes(r)
            self.assertEqual(result, b"")
        finally:
            os.close(r)
            os.close(w)

    def test_large_message(self):
        """Use socketpair to avoid pipe buffer deadlock on large messages."""
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        data = b"x" * 100_000
        try:
            _send_bytes(a.fileno(), data)
            result = _recv_bytes(b.fileno())
            self.assertEqual(result, data)
        finally:
            a.close()
            b.close()

    def test_recv_closed_pipe_raises(self):
        r, w = os.pipe()
        os.close(w)
        with self.assertRaises(EOFError):
            _recv_bytes(r)
        os.close(r)

    def test_multiple_messages(self):
        r, w = os.pipe()
        try:
            _send_bytes(w, b"first")
            _send_bytes(w, b"second")
            self.assertEqual(_recv_bytes(r), b"first")
            self.assertEqual(_recv_bytes(r), b"second")
        finally:
            os.close(r)
            os.close(w)

    def test_binary_data(self):
        """Ensure binary data with null bytes survives roundtrip."""
        r, w = os.pipe()
        data = bytes(range(256))
        try:
            _send_bytes(w, data)
            result = _recv_bytes(r)
            self.assertEqual(result, data)
        finally:
            os.close(r)
            os.close(w)


class TestCheckpointListener(unittest.TestCase):
    """Test the child-side checkpoint listener + parent-side request_app_state."""

    def test_save_fn_triggered(self):
        """Parent sends trigger byte, child runs save_fn, parent gets result."""
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            child_fd = child.detach()

            def save_fn():
                return b"my_state_data"

            start_child_listener(child_fd, save_fn)

            # Give listener thread time to start
            time.sleep(0.05)

            result = request_app_state(parent.fileno())
            self.assertEqual(result, b"my_state_data")
        finally:
            parent.close()

    def test_save_fn_exception(self):
        """If save_fn raises, parent gets RuntimeError."""
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            child_fd = child.detach()

            def bad_save_fn():
                raise ValueError("oops")

            start_child_listener(child_fd, bad_save_fn)
            time.sleep(0.05)

            with self.assertRaises(RuntimeError) as cm:
                request_app_state(parent.fileno())
            self.assertIn("oops", str(cm.exception))
        finally:
            parent.close()

    def test_multiple_checkpoints(self):
        """Listener handles multiple checkpoint triggers sequentially."""
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            counter = [0]
            child_fd = child.detach()

            def counting_save():
                counter[0] += 1
                return f"state_{counter[0]}".encode()

            start_child_listener(child_fd, counting_save)
            time.sleep(0.05)

            r1 = request_app_state(parent.fileno())
            r2 = request_app_state(parent.fileno())
            self.assertEqual(r1, b"state_1")
            self.assertEqual(r2, b"state_2")
        finally:
            parent.close()

    def test_trigger_byte_value(self):
        """TRIGGER_CHECKPOINT is 0x01."""
        self.assertEqual(TRIGGER_CHECKPOINT, b"\x01")

    def test_listener_stops_on_close(self):
        """Listener exits cleanly when socket is closed."""
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        child_fd = child.detach()

        start_child_listener(child_fd, lambda: b"x")
        time.sleep(0.05)

        # Close parent — listener should exit without error
        parent.close()
        time.sleep(0.1)
        # No assertion needed — just verify no crash/hang


class TestSandboxCheckpointIntegration(unittest.TestCase):
    def test_checkpoint_requires_running_process(self):
        from sandlock.sandbox import Sandbox
        from sandlock.exceptions import SandboxError
        sb = Sandbox(Policy(max_memory="512M"))
        with self.assertRaises(SandboxError):
            sb.checkpoint()

    def test_from_checkpoint_restores_policy(self):
        """from_checkpoint creates a sandbox with the checkpointed policy."""
        policy = Policy(max_memory="256M", max_processes=5)
        cp = Checkpoint(
            policy_data=pickle.dumps(policy),
            app_state=b"test_state",
        )

        with mock.patch("sandlock.sandbox.Sandbox.call") as mock_call:
            mock_call.return_value = mock.MagicMock(success=True)
            from sandlock.sandbox import Sandbox
            result = Sandbox.from_checkpoint(cp, lambda state: None)
            mock_call.assert_called_once()

    def test_from_checkpoint_with_branch(self):
        """from_checkpoint sets parent_branch_path when branch_id is present."""
        policy = Policy(
            fs_isolation=FsIsolation.BRANCHFS,
            fs_mount="/mnt/ws",
        )
        cp = Checkpoint(
            policy_data=pickle.dumps(policy),
            app_state=b"state",
            branch_id="snap-abc",
            fs_mount="/mnt/ws",
        )

        with mock.patch("sandlock.sandbox.Sandbox.call") as mock_call:
            mock_call.return_value = mock.MagicMock(success=True)
            from sandlock.sandbox import Sandbox
            Sandbox.from_checkpoint(cp, lambda state: None)
            mock_call.assert_called_once()

    def test_from_checkpoint_without_branch(self):
        """from_checkpoint works without branch info."""
        policy = Policy()
        cp = Checkpoint(
            policy_data=pickle.dumps(policy),
            app_state=b"data",
        )

        with mock.patch("sandlock.sandbox.Sandbox.call") as mock_call:
            mock_call.return_value = mock.MagicMock(success=True)
            from sandlock.sandbox import Sandbox
            Sandbox.from_checkpoint(cp, lambda state: None)
            mock_call.assert_called_once()


class TestPtraceDataClasses(unittest.TestCase):
    """Test _ptrace.py data classes."""

    def test_register_state(self):
        from sandlock._ptrace import RegisterState
        rs = RegisterState(arch="x86_64", data=b"\x00" * 216)
        self.assertEqual(rs.arch, "x86_64")
        self.assertEqual(len(rs.data), 216)

    def test_memory_region_size(self):
        from sandlock._ptrace import MemoryRegion
        mr = MemoryRegion(
            start=0x400000, end=0x401000,
            perms="r-xp", offset=0, path="/bin/ls",
            contents=b"\x00" * 0x1000,
        )
        self.assertEqual(mr.size, 0x1000)

    def test_file_descriptor(self):
        from sandlock._ptrace import FileDescriptor
        fd = FileDescriptor(fd=3, path="/tmp/foo", flags=0, offset=100, restorable=True)
        self.assertTrue(fd.restorable)

        pipe_fd = FileDescriptor(fd=4, path="pipe:[12345]", flags=0, offset=0, restorable=False)
        self.assertFalse(pipe_fd.restorable)

    def test_process_state_defaults(self):
        from sandlock._ptrace import ProcessState
        ps = ProcessState(pid=1)
        self.assertEqual(ps.pid, 1)
        self.assertEqual(ps.threads, [])
        self.assertEqual(ps.memory, [])
        self.assertEqual(ps.fds, [])
        self.assertEqual(ps.cwd, "")
        self.assertEqual(ps.exe, "")

    def test_thread_state(self):
        from sandlock._ptrace import ThreadState, RegisterState
        ts = ThreadState(
            tid=42,
            registers=RegisterState(arch="aarch64", data=b"\x01" * 272),
        )
        self.assertEqual(ts.tid, 42)
        self.assertEqual(ts.registers.arch, "aarch64")


class TestNamedCheckpoints(unittest.TestCase):
    """Test save/load/list/delete for named checkpoints."""

    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.mkdtemp(prefix="sandlock_test_ckpt_")
        self.store = Path(self._tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_checkpoint(self, **kwargs):
        defaults = dict(
            policy_data=pickle.dumps(Policy()),
            app_state=b"test_app_state",
            branch_id="br-001",
            fs_mount="/mnt/ws",
            sandbox_id="sb-42",
        )
        defaults.update(kwargs)
        return Checkpoint(**defaults)

    def _make_checkpoint_with_process_state(self):
        from sandlock._ptrace import (
            ProcessState, ThreadState, RegisterState,
            MemoryRegion, FileDescriptor,
        )
        ps = ProcessState(
            pid=9999,
            threads=[
                ThreadState(tid=9999, registers=RegisterState(arch="x86_64", data=b"\xab" * 216)),
                ThreadState(tid=10000, registers=RegisterState(arch="x86_64", data=b"\xcd" * 216)),
            ],
            memory=[
                MemoryRegion(start=0x400000, end=0x401000, perms="r-xp",
                             offset=0, path="/bin/test", contents=b"\x90" * 0x1000),
                MemoryRegion(start=0x7fff0000, end=0x7fff2000, perms="rw-p",
                             offset=0, path="[stack]", contents=b"\x00" * 0x2000),
            ],
            fds=[
                FileDescriptor(fd=0, path="/dev/null", flags=0, offset=0, restorable=True),
                FileDescriptor(fd=3, path="pipe:[12345]", flags=0, offset=0, restorable=False),
            ],
            cwd="/home/user",
            exe="/usr/bin/python3",
        )
        return self._make_checkpoint(process_state=ps)

    def test_save_and_load(self):
        cp = self._make_checkpoint()
        path = cp.save("env1", store=self.store)
        self.assertTrue(path.is_dir())
        self.assertTrue((path / "meta.json").exists())
        self.assertTrue((path / "policy.dat").exists())
        self.assertTrue((path / "app_state.bin").exists())

        loaded = Checkpoint.load("env1", store=self.store)
        self.assertEqual(loaded.branch_id, "br-001")
        self.assertEqual(loaded.fs_mount, "/mnt/ws")
        self.assertEqual(loaded.sandbox_id, "sb-42")
        self.assertEqual(loaded.app_state, b"test_app_state")
        self.assertEqual(loaded.policy_data, cp.policy_data)

    def test_save_and_load_with_process_state(self):
        cp = self._make_checkpoint_with_process_state()
        cp.save("with-proc", store=self.store)

        loaded = Checkpoint.load("with-proc", store=self.store)
        ps = loaded.process_state
        self.assertIsNotNone(ps)
        self.assertEqual(ps.pid, 9999)
        self.assertEqual(ps.cwd, "/home/user")
        self.assertEqual(ps.exe, "/usr/bin/python3")

        # Threads
        self.assertEqual(len(ps.threads), 2)
        self.assertEqual(ps.threads[0].tid, 9999)
        self.assertEqual(ps.threads[0].registers.arch, "x86_64")
        self.assertEqual(ps.threads[0].registers.data, b"\xab" * 216)
        self.assertEqual(ps.threads[1].tid, 10000)
        self.assertEqual(ps.threads[1].registers.data, b"\xcd" * 216)

        # Memory
        self.assertEqual(len(ps.memory), 2)
        self.assertEqual(ps.memory[0].start, 0x400000)
        self.assertEqual(ps.memory[0].end, 0x401000)
        self.assertEqual(ps.memory[0].perms, "r-xp")
        self.assertEqual(ps.memory[0].path, "/bin/test")
        self.assertEqual(len(ps.memory[0].contents), 0x1000)
        self.assertEqual(ps.memory[1].path, "[stack]")
        self.assertEqual(len(ps.memory[1].contents), 0x2000)

        # FDs
        self.assertEqual(len(ps.fds), 2)
        self.assertEqual(ps.fds[0].path, "/dev/null")
        self.assertTrue(ps.fds[0].restorable)
        self.assertFalse(ps.fds[1].restorable)

    def test_save_without_app_state(self):
        cp = self._make_checkpoint(app_state=None)
        cp.save("no-app", store=self.store)

        loaded = Checkpoint.load("no-app", store=self.store)
        self.assertIsNone(loaded.app_state)

    def test_save_without_process_state(self):
        cp = self._make_checkpoint()
        cp.save("no-proc", store=self.store)

        loaded = Checkpoint.load("no-proc", store=self.store)
        self.assertIsNone(loaded.process_state)

    def test_save_overwrites_existing(self):
        cp1 = self._make_checkpoint(app_state=b"first")
        cp1.save("env", store=self.store)

        cp2 = self._make_checkpoint(app_state=b"second")
        cp2.save("env", store=self.store)

        loaded = Checkpoint.load("env", store=self.store)
        self.assertEqual(loaded.app_state, b"second")

    def test_load_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            Checkpoint.load("does-not-exist", store=self.store)

    def test_list_empty(self):
        names = Checkpoint.list(store=self.store)
        self.assertEqual(names, [])

    def test_list_multiple(self):
        self._make_checkpoint().save("beta", store=self.store)
        self._make_checkpoint().save("alpha", store=self.store)
        self._make_checkpoint().save("gamma", store=self.store)

        names = Checkpoint.list(store=self.store)
        self.assertEqual(names, ["alpha", "beta", "gamma"])

    def test_delete(self):
        self._make_checkpoint().save("doomed", store=self.store)
        self.assertIn("doomed", Checkpoint.list(store=self.store))

        Checkpoint.delete("doomed", store=self.store)
        self.assertNotIn("doomed", Checkpoint.list(store=self.store))

    def test_delete_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            Checkpoint.delete("ghost", store=self.store)

    def test_policy_survives_roundtrip(self):
        policy = Policy(max_memory="1G", max_processes=100, max_cpu=75)
        cp = self._make_checkpoint(policy_data=pickle.dumps(policy))
        cp.save("pol", store=self.store)

        loaded = Checkpoint.load("pol", store=self.store)
        restored = pickle.loads(loaded.policy_data)
        self.assertEqual(restored.max_memory, "1G")
        self.assertEqual(restored.max_processes, 100)
        self.assertEqual(restored.max_cpu, 75)

    def test_list_ignores_non_checkpoint_dirs(self):
        """Directories without meta.json are not listed."""
        (self.store / "not-a-checkpoint").mkdir()
        (self.store / "random-file.txt").write_text("hello")
        self._make_checkpoint().save("real", store=self.store)

        names = Checkpoint.list(store=self.store)
        self.assertEqual(names, ["real"])


class TestEndToEndCheckpoint(unittest.TestCase):
    """End-to-end checkpoint: start sandbox, checkpoint, restore, verify."""

    def test_app_state_roundtrip(self):
        """Checkpoint captures app state via save_fn and restores it."""
        import tempfile
        import time
        from sandlock.sandbox import Sandbox
        from sandlock._context import SandboxContext

        store = Path(tempfile.mkdtemp(prefix="sandlock_e2e_ckpt_"))

        try:
            policy = Policy()

            def save_fn():
                return b"counter=42"

            # Use a Python target (not exec) so the checkpoint listener
            # thread survives -- exec replaces the process image and
            # kills the listener.
            def _target():
                time.sleep(60)

            ctx = SandboxContext(_target, policy, "e2e-test", save_fn=save_fn)
            with ctx:
                time.sleep(0.2)
                pid = ctx.pid

                # SIGSTOP + ptrace dump + app state
                import signal
                os.killpg(pid, signal.SIGSTOP)

                from sandlock._ptrace import dump_process_state
                process_state = dump_process_state(pid)

                os.killpg(pid, signal.SIGCONT)

                from sandlock._checkpoint import request_app_state
                app_state = request_app_state(ctx.control_fd)

                self.assertEqual(app_state, b"counter=42")
                self.assertIsNotNone(process_state)

                cp = Checkpoint(
                    process_state=process_state,
                    app_state=app_state,
                    policy_data=pickle.dumps(policy),
                    sandbox_id="e2e-test",
                )

                cp.save("e2e", store=store)
                loaded = Checkpoint.load("e2e", store=store)
                self.assertEqual(loaded.app_state, b"counter=42")
                self.assertIsNotNone(loaded.process_state)

            # Restore
            def restore_fn(state):
                assert state == b"counter=42"

            result = Sandbox.from_checkpoint(
                loaded, restore_fn, timeout=5,
            )
            self.assertTrue(result.success, f"restore failed: {result.error}")
        finally:
            import shutil
            shutil.rmtree(store, ignore_errors=True)

    def test_app_state_via_call(self):
        """Checkpoint save/load/restore roundtrip using call() API."""
        import tempfile
        from sandlock.sandbox import Sandbox

        store = Path(tempfile.mkdtemp(prefix="sandlock_e2e_call_"))

        try:
            # Manually build a checkpoint with app state (no ptrace needed)
            policy = Policy(max_memory="256M")
            cp = Checkpoint(
                app_state=b"state:hello",
                policy_data=pickle.dumps(policy),
                sandbox_id="e2e-call",
            )

            cp.save("call-test", store=store)
            loaded = Checkpoint.load("call-test", store=store)
            self.assertEqual(loaded.app_state, b"state:hello")

            # restore_fn runs in a forked child; assert inside it
            # so a mismatch causes the child to exit non-zero
            def restore_fn(state):
                assert state == b"state:hello", f"got {state!r}"

            result = Sandbox.from_checkpoint(
                loaded, restore_fn, timeout=5,
            )
            self.assertTrue(result.success, f"restore failed: {result.error}")

            # Verify restored policy
            restored_policy = pickle.loads(loaded.policy_data)
            self.assertEqual(restored_policy.max_memory, "256M")
        finally:
            import shutil
            shutil.rmtree(store, ignore_errors=True)


class TestExports(unittest.TestCase):
    def test_checkpoint_importable(self):
        from sandlock import Checkpoint
        self.assertIsNotNone(Checkpoint)

    def test_in_all(self):
        import sandlock
        self.assertIn("Checkpoint", sandlock.__all__)


if __name__ == "__main__":
    unittest.main()
