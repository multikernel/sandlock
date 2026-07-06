# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.Checkpoint (save_fn / restore_fn / persistence)."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
import time

import pytest

from sandlock import Sandbox, Checkpoint, SkippedFd
from sandlock._sdk import _encode, _lib, _make_argv


_PYTHON_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev",
    sys.prefix,
]))


def _policy(**overrides):
    defaults = {"fs_readable": _PYTHON_READABLE}
    defaults.update(overrides)
    return Sandbox(**defaults)


@pytest.fixture
def running_sandbox():
    """A sandbox with a long-running process for checkpoint tests."""
    sb = _policy()
    argv, argc = _make_argv(["sleep", "60"])
    native = sb._ensure_native()
    sb._handle = _lib.sandlock_create(
        native.ptr,
        _encode(sb._resolve_name()),
        argv,
        argc,
    )
    assert sb._handle, "create failed"
    assert _lib.sandlock_start(sb._handle) == 0, "start failed"
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
        sb = _policy()
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


class TestCheckpointLoadRestoreFn:
    """load(restore_fn=...) semantics. app_state is auxiliary to the real
    process-image restore, so save_fn/restore_fn pairing is NOT mandatory:
    restore_fn runs only when both it and app_state are present."""

    def test_restore_classmethod_is_gone(self):
        # Folded into load(); "restore" now means process-image restore only.
        assert not hasattr(Checkpoint, "restore")

    def test_load_calls_restore_fn_with_app_state(self, running_sandbox, tmp_dir):
        original = {"model": "gpt-4", "tokens": 99}
        cp = running_sandbox.checkpoint(
            save_fn=lambda: json.dumps(original).encode(),
        )
        cp.save("restorable", store=tmp_dir)

        restored = {}
        result = Checkpoint.load(
            "restorable",
            store=tmp_dir,
            restore_fn=lambda data: restored.update(json.loads(data)),
        )
        assert restored == original
        assert isinstance(result, Checkpoint)
        assert result.name == "restorable"

    def test_load_without_restore_fn_keeps_app_state(self, running_sandbox, tmp_dir):
        # app_state present, restore_fn omitted: no error, state stays readable.
        cp = running_sandbox.checkpoint(save_fn=lambda: b"state")
        cp.save("app-no-fn", store=tmp_dir)

        loaded = Checkpoint.load("app-no-fn", store=tmp_dir)
        assert loaded.app_state == b"state"

    def test_load_restore_fn_without_app_state_not_called(
        self, running_sandbox, tmp_dir
    ):
        # restore_fn given, checkpoint has no app_state: fn is simply not
        # called; no error.
        cp = running_sandbox.checkpoint()
        cp.save("no-app-fn", store=tmp_dir)

        calls = []
        loaded = Checkpoint.load("no-app-fn", store=tmp_dir, restore_fn=calls.append)
        assert calls == []
        assert loaded.app_state is None


# Freestanding x86_64 program (no libc, no vDSO; raw syscalls only) that opens
# an output file once, then loops forever rewriting an incrementing counter
# through that kept-open fd. Mirrors the core restore integration test: the
# injection-based restore engine does not relocate the vDSO, so the guest must
# be vDSO-free for transparent restore to hold.
_COUNTER_TEMPLATE = r"""
#define SYS_write 1
#define SYS_open 2
#define SYS_nanosleep 35
#define SYS_lseek 8
#define SYS_ftruncate 77
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
static long sys3(long n, long a, long b, long c){
  long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory"); return r;
}
struct ts { long sec; long nsec; };
void _start(void){
  const char *path = "@OUT_PATH@";
  long fd = sys3(SYS_open, (long)path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
  unsigned long i = 0;
  char buf[24];
  struct ts t; t.sec = 0; t.nsec = 20000000;
  for(;;){
    i++;
    int p = 0; unsigned long v = i; char tmp[24]; int k=0;
    if(v==0){ tmp[k++]='0'; } while(v){ tmp[k++]='0'+(v%10); v/=10; }
    while(k>0){ buf[p++]=tmp[--k]; } buf[p++]='\n';
    sys3(SYS_lseek, fd, 0, 0);
    sys3(SYS_ftruncate, fd, 0, 0);
    sys3(SYS_write, fd, (long)buf, p);
    sys3(SYS_nanosleep, (long)&t, 0, 0);
  }
}
"""


def _build_counter(tmp_dir):
    """Compile the vDSO-free counter program, or skip if this host can't."""
    if platform.machine() != "x86_64":
        pytest.skip("injection-based restore is x86_64-only")
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler (cc/gcc) available")
    counter = tmp_dir / "counter.cnt"
    src = tmp_dir / "counter.c"
    binary = tmp_dir / "counter"
    src.write_text(_COUNTER_TEMPLATE.replace("@OUT_PATH@", str(counter)))
    build = subprocess.run(
        [cc, "-static", "-nostdlib", "-no-pie", "-O0", "-o", str(binary), str(src)],
        capture_output=True,
    )
    if build.returncode != 0:
        pytest.skip(f"counter build failed: {build.stderr.decode()}")
    return binary, counter


def _read_counter(path) -> int:
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0  # absent or torn read mid-rewrite


class TestRestoreInteractive:
    def test_restore_resumes_counter(self, tmp_dir):
        binary, counter = _build_counter(tmp_dir)
        policy_kw = dict(
            fs_readable=_PYTHON_READABLE + [str(tmp_dir)],
            fs_writable=[str(tmp_dir)],
        )

        sb = _policy(**policy_kw)
        sb.spawn([str(binary)])
        try:
            time.sleep(0.4)
            cp = sb.checkpoint()
            baseline = _read_counter(counter)
            assert baseline > 2, f"counter should have advanced, got {baseline}"
        finally:
            sb.kill()
            sb.wait()

        # Sentinel: only the restored process can advance the file past baseline.
        counter.write_text("0\n")

        sb2 = _policy(**policy_kw)
        assert sb2.restore_skipped == []
        ret = sb2.restore_interactive(cp)
        assert ret is None
        skipped = sb2.restore_skipped
        assert isinstance(skipped, list)
        for s in skipped:
            assert isinstance(s, SkippedFd)
            assert isinstance(s.fd, int) and s.fd >= 0
            assert isinstance(s.path, str) and s.path
        try:
            assert sb2.is_running
            assert sb2.pid
            deadline = time.monotonic() + 3
            last = 0
            advanced = False
            while time.monotonic() < deadline:
                last = _read_counter(counter)
                if last > baseline:
                    advanced = True
                    break
                time.sleep(0.05)
        finally:
            sb2.kill()
            sb2.wait()
        assert advanced, (
            f"restored process must resume and advance past {baseline}, last {last}"
        )

    def test_restore_while_running_raises(self, running_sandbox):
        cp = running_sandbox.checkpoint()
        with pytest.raises(RuntimeError, match="already"):
            running_sandbox.restore_interactive(cp)
