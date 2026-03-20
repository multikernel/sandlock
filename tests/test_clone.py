# SPDX-License-Identifier: Apache-2.0
"""Tests for Sandbox(policy, init, work) / Sandbox.fork() — COW cloning."""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
import unittest

from sandlock._checkpoint import (
    TRIGGER_FORK,
    _send_bytes,
    _recv_bytes,
    request_fork,
)
from sandlock.policy import Policy
from sandlock.sandbox import Sandbox
from sandlock.exceptions import SandboxError


class TestForkRequiresInitWork(unittest.TestCase):
    def test_fork_without_init_work_raises(self):
        sb = Sandbox(Policy())
        with self.assertRaises(SandboxError):
            sb.fork(1)

    def test_constructor_stores_init_work(self):
        init = lambda: None
        work = lambda: None
        sb = Sandbox(Policy(), init, work)
        self.assertIs(sb._init_fn, init)
        self.assertIs(sb._work_fn, work)


class TestRequestForkProtocol(unittest.TestCase):
    def test_sends_trigger_and_env(self):
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            def child_side():
                fd = child.fileno()
                trigger = os.read(fd, 1)
                assert trigger == TRIGGER_FORK
                env_data = _recv_bytes(fd)
                env = json.loads(env_data)
                assert env.get("SEED") == "42"
                os.write(fd, struct.pack(">I", 256))

            t = threading.Thread(target=child_side)
            t.start()
            pid = request_fork(parent.fileno(), env={"SEED": "42"})
            self.assertEqual(pid, 256)
            t.join(timeout=2)
        finally:
            parent.close()
            child.close()

    def test_fork_failure_raises(self):
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            def child_side():
                fd = child.fileno()
                os.read(fd, 1)
                _recv_bytes(fd)
                os.write(fd, struct.pack(">I", 0))

            t = threading.Thread(target=child_side)
            t.start()
            with self.assertRaises(RuntimeError):
                request_fork(parent.fileno())
            t.join(timeout=2)
        finally:
            parent.close()
            child.close()

    def test_no_env_sends_empty(self):
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            def child_side():
                fd = child.fileno()
                os.read(fd, 1)
                env_data = _recv_bytes(fd)
                assert json.loads(env_data) == {}
                os.write(fd, struct.pack(">I", 100))

            t = threading.Thread(target=child_side)
            t.start()
            pid = request_fork(parent.fileno())
            self.assertEqual(pid, 100)
            t.join(timeout=2)
        finally:
            parent.close()
            child.close()


class TestMaxProcessesInClone(unittest.TestCase):
    """Verify that max_processes is enforced inside COW clones.

    The template uses raw fork(2) to bypass seccomp USER_NOTIF, but
    clones inherit the seccomp filter that intercepts clone (os.fork).
    Process limits must still be enforced in work().
    """

    def test_clone_inherits_process_limit(self):
        """work() cannot fork more than max_processes allows."""
        import sys
        import tempfile

        marker = tempfile.mktemp(prefix="sandlock_test_maxproc_")

        def init():
            pass

        def work():
            count = 0
            for _ in range(20):
                try:
                    pid = os.fork()
                    if pid == 0:
                        os._exit(0)
                    os.waitpid(pid, 0)
                    count += 1
                except OSError:
                    break
            with open(marker, "w") as f:
                f.write(str(count))

        policy = Policy(
            fs_writable=["/tmp"],
            fs_readable=[sys.prefix, "/usr", "/lib", "/etc", "/proc", "/dev"],
            max_processes=5,
        )

        with Sandbox(policy, init, work) as sb:
            sb.fork(1)[0].wait(timeout=10)

        self.assertTrue(os.path.exists(marker))
        count = int(open(marker).read())
        os.unlink(marker)

        # max_processes=5: the template's raw fork counts as 1 (via
        # the supervisor tracking clone3/vfork), so the clone can
        # fork at most 4 more times.  The exact count depends on
        # how the supervisor counts, but it must be less than 20.
        self.assertLess(count, 20, "max_processes not enforced in clone")
        self.assertGreater(count, 0, "clone couldn't fork at all")


class TestForkEnvAndCloneId(unittest.TestCase):
    """Verify that fork() sets CLONE_ID and passes extra env."""

    def test_clone_id_and_env(self):
        import sys
        import tempfile

        marker = tempfile.mktemp(prefix="sandlock_test_env_")

        def init():
            pass

        def work():
            clone_id = os.environ.get("CLONE_ID", "missing")
            mode = os.environ.get("MODE", "missing")
            with open(f"{marker}_{clone_id}", "w") as f:
                f.write(f"{clone_id}:{mode}")

        policy = Policy(
            fs_writable=["/tmp"],
            fs_readable=[sys.prefix, "/usr", "/lib", "/etc", "/proc", "/dev"],
        )

        with Sandbox(policy, init, work) as sb:
            clones = sb.fork(3, env={"MODE": "test"})
            for c in clones:
                c.wait(timeout=10)

        for i in range(3):
            path = f"{marker}_{i}"
            self.assertTrue(os.path.exists(path), f"Clone {i} didn't write output")
            content = open(path).read()
            self.assertEqual(content, f"{i}:test")
            os.unlink(path)


class TestClonePauseResume(unittest.TestCase):
    """Verify that pause()/resume() works on COW clones."""

    def test_pause_resume_clone(self):
        """A paused clone resumes and completes after SIGCONT."""
        import sys
        import tempfile
        import time

        marker = tempfile.mktemp(prefix="sandlock_test_pause_")

        def init():
            pass

        def work():
            # Write marker after a brief moment to prove we ran
            with open(marker, "w") as f:
                f.write("done")

        policy = Policy(
            fs_writable=["/tmp"],
            fs_readable=[sys.prefix, "/usr", "/lib", "/etc", "/proc", "/dev"],
        )

        with Sandbox(policy, init, work) as sb:
            clones = sb.fork(1)
            clone = clones[0]
            # Give the clone a moment to start
            time.sleep(0.1)
            clone.pause()
            self.assertTrue(clone.is_paused)
            # Resume and wait for completion
            clone.resume()
            clone.wait(timeout=10)

        self.assertTrue(os.path.exists(marker))
        self.assertEqual(open(marker).read(), "done")
        os.unlink(marker)

    def test_resume_without_pause_is_harmless(self):
        """Calling resume() on a running clone should not error."""
        import sys
        import tempfile

        marker = tempfile.mktemp(prefix="sandlock_test_resume_noop_")

        def init():
            pass

        def work():
            with open(marker, "w") as f:
                f.write("ok")

        policy = Policy(
            fs_writable=["/tmp"],
            fs_readable=[sys.prefix, "/usr", "/lib", "/etc", "/proc", "/dev"],
        )

        with Sandbox(policy, init, work) as sb:
            clones = sb.fork(1)
            clone = clones[0]
            # resume a non-paused clone — should be harmless
            clone.resume()
            clone.wait(timeout=10)

        self.assertTrue(os.path.exists(marker))
        os.unlink(marker)


if __name__ == "__main__":
    unittest.main()
