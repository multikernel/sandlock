"""Session lifetime is independent of the main process's exit."""
import os

import pytest

from sandlock import Sandbox, ExitStatus, ExitReason, StdioMode, BranchAction


def policy(**kwargs):
    return Sandbox(fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"], **kwargs)


def test_wait_retains_jobs_and_shutdown_collects_output():
    with policy() as sb:
        sb.spawn(["sh", "-c", "sleep 60 & echo retained; exit 7"])
        status = sb.wait(timeout=5)
        assert isinstance(status, ExitStatus)
        assert status.exit_code == 7
        assert sb.wait() == status
        assert sb.is_running
        assert sb.process_groups()
        with pytest.raises(RuntimeError, match="already running"):
            sb.spawn(["true"])
        result = sb.shutdown()
        assert result.exit_code == 7
        assert result.stdout == b"retained\n"
        assert not sb.is_running
        assert sb.run(["true"]).success


def test_wait_timeout_retains_main_for_retry():
    with policy() as sb:
        sb.spawn(["sh", "-c", "sleep 0.2; exit 9"])
        with pytest.raises(TimeoutError):
            sb.wait(timeout=0)
        assert sb.process_groups()
        assert sb.wait(timeout=5).exit_code == 9
        assert sb.shutdown().exit_code == 9


def test_handle_stays_usable_while_another_thread_waits():
    import threading
    import time
    with policy() as sb:
        sb.spawn(["sleep", "60"])
        statuses = []
        waiter = threading.Thread(target=lambda: statuses.append(sb.wait()))
        waiter.start()
        time.sleep(0.1)
        assert sb.process_groups()
        sb.kill()
        waiter.join(timeout=5)
        assert not waiter.is_alive()
        assert statuses[0].reason == ExitReason.KILLED
        sb.shutdown()


def test_popen_context_cleans_background_jobs_after_wait():
    with policy().popen(["sh", "-c", "sleep 60 & echo $!"], stdout=StdioMode.PIPED) as proc:
        child = int(proc.stdout.readline())
        assert proc.wait(timeout=5).success
        assert proc.process_groups()
        os.kill(child, 0)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)


def test_shutdown_defers_cow_until_jobs_finish(tmp_path):
    with policy(fs_writable=[str(tmp_path)], workdir=str(tmp_path), on_exit=BranchAction.DEFER) as sb:
        sb.spawn(["sh", "-c", f"echo data > {tmp_path}/out"])
        assert sb.wait(timeout=5).success
        assert not sb.pending
        assert not (tmp_path / "out").exists()
        result = sb.shutdown()
        assert result.changes
        assert sb.pending
        sb.commit()
        assert (tmp_path / "out").read_text() == "data\n"


def test_run_timeout_terminates_session():
    with policy() as sb:
        result = sb.run(["sleep", "60"], timeout=0.01)
        assert result.reason == ExitReason.TIMEOUT
        assert not result.success
        assert not sb.is_running

@pytest.mark.parametrize("streaming", [False, True])
def test_context_exit_interrupts_wait_and_releases_session(streaming):
    import threading
    import time
    sb = policy()
    if streaming:
        owner = sb.popen(["sleep", "60"])
    else:
        sb.spawn(["sleep", "60"])
        owner = sb
    outcomes = []
    worker = threading.Thread(target=lambda: outcomes.append(owner.wait()), daemon=True)
    worker.start()
    time.sleep(0.1)
    owner.__exit__(None, None, None)
    worker.join(5)
    assert not worker.is_alive()
    assert outcomes and not outcomes[0].success
    assert not sb.is_running
    assert sb.run(["true"]).success


def test_wait_rejects_conflicting_start_and_checkpoint():
    import threading
    import time
    with policy() as sb:
        sb.spawn(["sleep", "60"])
        worker = threading.Thread(target=sb.wait, daemon=True)
        worker.start()
        time.sleep(0.1)
        try:
            for op in (sb.start, sb.checkpoint):
                with pytest.raises(RuntimeError, match="already in progress"):
                    op()
        finally:
            sb.kill()
            worker.join(5)
        assert not worker.is_alive()


def test_kill_in_fresh_interpreter():
    import ctypes
    from sandlock._sdk import _lib
    assert _lib.sandlock_handle_kill.argtypes == [ctypes.c_void_p]
    import subprocess
    import sys
    result = subprocess.run(
        [sys.executable, "-c", """
from sandlock import Sandbox
with Sandbox(fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc"]) as sb:
    sb.spawn(["sleep", "60"])
    sb.kill()
    assert not sb.wait().success
    sb.shutdown()
"""],
        capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr.decode()
