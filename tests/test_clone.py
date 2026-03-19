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
            sb.fork()

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


if __name__ == "__main__":
    unittest.main()
