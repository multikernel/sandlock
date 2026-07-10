# SPDX-License-Identifier: Apache-2.0
"""Tests for the Python Sandbox lifecycle methods: spawn, create, start, wait."""

from __future__ import annotations

import os
import time

import pytest

from sandlock import Sandbox, ExitReason
from sandlock._sdk import _lib


_BIN_READABLE = ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc"]


def _policy(**overrides):
    defaults = {"fs_readable": _BIN_READABLE}
    defaults.update(overrides)
    return Sandbox(**defaults)


def _proc_state(pid: int) -> str | None:
    """Return the single-letter process state from /proc/<pid>/status, or
    None if the entry no longer exists."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("State:"):
                    return line.split()[1]
    except FileNotFoundError:
        return None
    return None


class TestExitReason:
    """The terminating reason (issue #131) is surfaced on Result."""

    def test_normal_exit_is_exited(self):
        result = _policy().run(["sh", "-c", "exit 7"])
        assert result.reason is ExitReason.EXITED
        assert result.exit_code == 7
        assert result.signal == -1

    def test_timeout_is_timeout(self):
        # sandlock kills the process when it exceeds the timeout; the reason must
        # be TIMEOUT, distinct from a plain signal kill, and never a success.
        result = _policy().run(["sleep", "60"], timeout=1)
        assert result.reason is ExitReason.TIMEOUT
        assert not result.success

    def test_signal_is_signaled_with_number(self):
        # A catchable signal (SIGTERM=15) is SIGNALED and carries the signal
        # number — not TIMEOUT (sandlock did not initiate the kill).
        result = _policy().run(["sh", "-c", "kill -TERM $$"])
        assert result.reason is ExitReason.SIGNALED
        assert result.signal == 15

    def test_sigkill_is_killed_without_number(self):
        # SIGKILL folds into KILLED (core sandbox.rs: `sig == SIGKILL => Killed`),
        # distinct from SIGNALED, so no signal number is recoverable. This pins
        # the "systemd-style minus oom-kill" boundary the C ABI promises.
        result = _policy().run(["sh", "-c", "kill -KILL $$"])
        assert result.reason is ExitReason.KILLED
        assert result.signal == -1


class TestSpawn:
    def test_spawn_then_wait_returns_result(self):
        with _policy() as sb:
            sb.spawn(["sh", "-c", "echo hello; exit 0"])
            result = sb.wait()
            assert result.exit_code == 0
            assert b"hello" in result.stdout

    def test_spawn_raises_when_already_running(self):
        with _policy() as sb:
            sb.spawn(["sleep", "60"])
            try:
                with pytest.raises(RuntimeError, match="already running"):
                    sb.spawn(["sleep", "60"])
            finally:
                sb.kill()
                sb.wait()


class TestCreateStart:
    def test_create_sets_pid_and_parks_child(self):
        with _policy() as sb:
            sb.create(["sh", "-c", "echo from-child"])
            pid = sb.pid
            assert pid is not None and pid > 0
            # The child is blocked inside the sandlock supervisor (read on
            # the ready pipe) before execve — kernel reports interruptible
            # sleep ('S').
            assert _proc_state(pid) == "S"
            sb.start()
            sb.wait()

    def test_create_then_start_runs_command(self):
        with _policy() as sb:
            sb.create(["sh", "-c", "echo two-step"])
            sb.start()
            result = sb.wait()
            assert result.exit_code == 0
            assert b"two-step" in result.stdout

    def test_start_raises_without_create(self):
        with _policy() as sb:
            with pytest.raises(RuntimeError, match="has not been created"):
                sb.start()


class TestDropReapsParkedChild:
    def test_create_then_discard_reaps_child(self):
        """Created-but-not-started child must be reaped on handle_free,
        not left as a zombie."""
        sb = _policy()
        sb.create(["sleep", "60"])
        pid = sb.pid
        assert pid is not None and pid > 0
        assert _proc_state(pid) == "S"

        # Free the handle without start() — Rust Drop should SIGKILL + waitpid.
        _lib.sandlock_handle_free(sb._handle)
        sb._handle = None

        # After Drop, /proc/<pid> must be gone. If it's still there as 'Z',
        # the reap is missing.
        state = _proc_state(pid)
        assert state is None, f"child {pid} not reaped: state={state!r}"
