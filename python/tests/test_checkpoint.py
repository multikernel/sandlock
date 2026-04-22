# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.Checkpoint (save_fn / restore_fn / persistence)."""

import json
import platform
import sys

import pytest

from sandlock import Sandbox, Policy, Checkpoint
from sandlock._sdk import _lib, _make_argv


pytestmark = pytest.mark.skipif(
    platform.machine() == "aarch64",
    reason="ARM64 checkpoint register capture is planned for stage 4",
)


_PYTHON_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev",
    sys.prefix,
]))


def _policy(**overrides):
    defaults = {"fs_readable": _PYTHON_READABLE}
    defaults.update(overrides)
    return Policy(**defaults)


@pytest.fixture
def running_sandbox():
    """A sandbox with a long-running process for checkpoint tests."""
    sb = Sandbox(_policy())
    argv, argc = _make_argv(["sleep", "60"])
    sb._handle = _lib.sandlock_spawn(sb._native.ptr, argv, argc)
    assert sb._handle, "spawn failed"
    yield sb
    if sb._handle:
        _lib.sandlock_handle_free(sb._handle)
        sb._handle = None


class TestCheckpointCapture:
    def test_basic_checkpoint(self, running_sandbox):
        cp = running_sandbox.checkpoint()
        assert cp.name == ""
        assert cp.app_state is None

    def test_checkpoint_with_save_fn(self, running_sandbox):
        data = {"key": "value", "count": 42}
        cp = running_sandbox.checkpoint(
            save_fn=lambda: json.dumps(data).encode(),
        )
        assert cp.app_state == json.dumps(data).encode()

    def test_checkpoint_save_fn_none_by_default(self, running_sandbox):
        cp = running_sandbox.checkpoint()
        assert cp.app_state is None

    def test_checkpoint_not_running_raises(self):
        sb = Sandbox(_policy())
        with pytest.raises(RuntimeError, match="not running"):
            sb.checkpoint()


class TestCheckpointPersistence:
    def test_save_load_roundtrip(self, running_sandbox, tmp_dir):
        cp = running_sandbox.checkpoint()
        path = cp.save("test-ckpt", store=tmp_dir)
        assert path.is_dir()
        assert (path / "meta.json").exists()
        assert (path / "process" / "info.json").exists()

        loaded = Checkpoint.load("test-ckpt", store=tmp_dir)
        assert loaded.name == "test-ckpt"

    def test_save_with_app_state(self, running_sandbox, tmp_dir):
        state = b"binary app state \x00\xff"
        cp = running_sandbox.checkpoint(
            save_fn=lambda: state,
        )
        cp.save("with-state", store=tmp_dir)
        assert (tmp_dir / "with-state" / "app_state.bin").exists()

        loaded = Checkpoint.load("with-state", store=tmp_dir)
        assert loaded.app_state == state

    def test_save_without_app_state_no_file(self, running_sandbox, tmp_dir):
        cp = running_sandbox.checkpoint()
        cp.save("no-state", store=tmp_dir)
        assert not (tmp_dir / "no-state" / "app_state.bin").exists()

    def test_list(self, running_sandbox, tmp_dir):
        assert Checkpoint.list(store=tmp_dir) == []

        cp = running_sandbox.checkpoint()
        cp.save("alpha", store=tmp_dir)
        cp.save("beta", store=tmp_dir)

        assert Checkpoint.list(store=tmp_dir) == ["alpha", "beta"]

    def test_delete(self, running_sandbox, tmp_dir):
        cp = running_sandbox.checkpoint()
        cp.save("to-delete", store=tmp_dir)
        assert Checkpoint.list(store=tmp_dir) == ["to-delete"]

        Checkpoint.delete("to-delete", store=tmp_dir)
        assert Checkpoint.list(store=tmp_dir) == []

    def test_load_nonexistent_raises(self, tmp_dir):
        with pytest.raises(FileNotFoundError):
            Checkpoint.load("nope", store=tmp_dir)

    def test_delete_nonexistent_raises(self, tmp_dir):
        with pytest.raises(FileNotFoundError):
            Checkpoint.delete("nope", store=tmp_dir)


class TestCheckpointRestore:
    def test_restore_calls_restore_fn(self, running_sandbox, tmp_dir):
        original = {"model": "gpt-4", "tokens": 99}
        cp = running_sandbox.checkpoint(
            save_fn=lambda: json.dumps(original).encode(),
        )
        cp.save("restorable", store=tmp_dir)

        restored = {}
        Checkpoint.restore(
            "restorable",
            restore_fn=lambda data: restored.update(json.loads(data)),
            store=tmp_dir,
        )
        assert restored == original

    def test_restore_returns_checkpoint(self, running_sandbox, tmp_dir):
        cp = running_sandbox.checkpoint(
            save_fn=lambda: b"state",
        )
        cp.save("ret-test", store=tmp_dir)

        result = Checkpoint.restore("ret-test", lambda d: None, store=tmp_dir)
        assert isinstance(result, Checkpoint)
        assert result.name == "ret-test"

    def test_restore_no_app_state_raises(self, running_sandbox, tmp_dir):
        cp = running_sandbox.checkpoint()
        cp.save("no-app", store=tmp_dir)

        with pytest.raises(ValueError, match="no app_state"):
            Checkpoint.restore("no-app", lambda d: None, store=tmp_dir)

    def test_restore_nonexistent_raises(self, tmp_dir):
        with pytest.raises(FileNotFoundError):
            Checkpoint.restore("nope", lambda d: None, store=tmp_dir)
