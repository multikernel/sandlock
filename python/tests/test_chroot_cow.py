# SPDX-License-Identifier: Apache-2.0
"""Tests for chroot + COW filesystem isolation.

Verifies that on_exit/on_error branch actions work correctly and that
concurrent sandboxes with separate fs_storage directories get isolated
upper layers.  Parametrized across all COW backends (seccomp, overlayfs).
"""

import os
import shutil
import threading
import tempfile
from pathlib import Path

import pytest

from sandlock import Policy, Sandbox


_HELPER_BIN = Path(__file__).resolve().parent.parent.parent / "tests" / "rootfs-helper"

_FS_READABLE = ["/usr", "/usr/bin", "/bin", "/sbin", "/etc", "/proc", "/dev"]


# ---------------------------------------------------------------------------
# Backend parametrization
# ---------------------------------------------------------------------------

def _overlayfs_available():
    """Check if unprivileged overlayfs is usable (needs user+mount ns)."""
    try:
        p = Policy(
            chroot=None,
            workdir="/tmp",
            cwd="/tmp",
            fs_readable=["/"],
            fs_writable=["/tmp"],
            fs_isolation="overlayfs",
            on_exit="abort",
            clean_env=True,
            env={"PATH": "/bin:/usr/bin"},
        )
        r = Sandbox(p).run(["true"])
        return r.success
    except Exception:
        return False


_BACKENDS = ["seccomp"]  # always available
if _overlayfs_available():
    _BACKENDS.append("overlayfs")


@pytest.fixture(params=_BACKENDS)
def backend(request):
    return request.param


@pytest.fixture
def rootfs(tmp_path):
    """Build a minimal self-contained chroot rootfs with the helper binary."""
    # Real directories
    for d in ("usr/bin", "usr/sbin", "etc", "proc", "dev", "tmp", "work"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)

    # Copy helper binary
    helper_dst = tmp_path / "usr" / "bin" / "rootfs-helper"
    try:
        os.link(_HELPER_BIN, helper_dst)  # hard-link: atomic, avoids ETXTBSY
    except OSError:
        shutil.copy2(_HELPER_BIN, helper_dst)

    # Busybox-style symlinks
    for name in ("sh", "cat", "echo", "ls", "pwd", "readlink", "stat",
                  "mkdir", "rmdir", "chmod", "ln", "rm", "mv", "true",
                  "false", "write", "access"):
        link = tmp_path / "usr" / "bin" / name
        if not link.exists():
            os.symlink("rootfs-helper", link)

    # Merged-usr symlinks (relative)
    for name in ("bin", "sbin"):
        link = tmp_path / name
        if not link.exists():
            os.symlink(f"usr/{name}", link)

    # Set tmp permissions
    os.chmod(tmp_path / "tmp", 0o1777)

    return tmp_path


def _cow_policy(rootfs, on_exit="abort", fs_storage=None, backend="seccomp"):
    """Build a COW policy for the given backend."""
    # seccomp backend: fs_isolation left as default (None) -- workdir triggers
    # the seccomp COW path.  overlayfs: explicit.
    fs_isolation = "overlayfs" if backend == "overlayfs" else None
    return Policy(
        chroot=str(rootfs),
        workdir=str(rootfs),
        cwd="/",
        fs_readable=_FS_READABLE + ["/"],
        fs_writable=["/tmp"],
        on_exit=on_exit,
        fs_storage=fs_storage,
        fs_isolation=fs_isolation,
        clean_env=True,
        env={"PATH": "/usr/bin:/bin"},
    )


# ---------------------------------------------------------------------------
# Abort
# ---------------------------------------------------------------------------

class TestCowAbort:
    """on_exit=abort should discard all writes."""

    def test_abort_no_leak(self, rootfs, backend):
        p = _cow_policy(rootfs, on_exit="abort", backend=backend)
        r = Sandbox(p).run(["sh", "-c", "echo marker > /tmp/marker.txt"])
        assert r.success, f"[{backend}] failed: {r.stderr}"
        assert not (rootfs / "tmp" / "marker.txt").exists(), \
            f"[{backend}] file should not leak to rootfs with on_exit=abort"

    def test_abort_cleans_storage(self, rootfs, backend):
        """Abort must actually remove the upper dir, not just skip cleanup."""
        storage = tempfile.mkdtemp()
        p = _cow_policy(rootfs, on_exit="abort", fs_storage=storage, backend=backend)
        r = Sandbox(p).run(["sh", "-c", "echo data > /tmp/data.txt"])
        assert r.success, f"[{backend}] failed: {r.stderr}"
        # The storage dir should be empty (UUID subdir removed by abort).
        remaining = os.listdir(storage)
        assert remaining == [], \
            f"[{backend}] abort should clean up storage, but found: {remaining}"

    def test_abort_write_visible_during_run(self, rootfs, backend):
        """Writes should be visible to the child during execution."""
        p = _cow_policy(rootfs, on_exit="abort", backend=backend)
        r = Sandbox(p).run([
            "sh", "-c", "echo hello > /tmp/test.txt && cat /tmp/test.txt"
        ])
        assert r.success, f"[{backend}] failed: {r.stderr}"
        assert b"hello" in r.stdout

    def test_abort_multiple_files(self, rootfs, backend):
        p = _cow_policy(rootfs, on_exit="abort", backend=backend)
        r = Sandbox(p).run([
            "sh", "-c",
            "echo a > /tmp/a.txt && echo b > /tmp/b.txt && cat /tmp/a.txt /tmp/b.txt"
        ])
        assert r.success, f"[{backend}] failed: {r.stderr}"
        assert b"a" in r.stdout
        assert b"b" in r.stdout
        assert not (rootfs / "tmp" / "a.txt").exists()
        assert not (rootfs / "tmp" / "b.txt").exists()


# ---------------------------------------------------------------------------
# Commit
# ---------------------------------------------------------------------------

class TestCowCommit:
    """on_exit=commit should merge writes to rootfs."""

    def test_commit_persists(self, rootfs, backend):
        p = _cow_policy(rootfs, on_exit="commit", backend=backend)
        r = Sandbox(p).run(["sh", "-c", "echo persisted > /tmp/persist.txt"])
        assert r.success, f"[{backend}] failed: {r.stderr}"
        assert (rootfs / "tmp" / "persist.txt").exists(), \
            f"[{backend}] file should persist to rootfs with on_exit=commit"
        assert (rootfs / "tmp" / "persist.txt").read_text().strip() == "persisted"
        # Clean up
        (rootfs / "tmp" / "persist.txt").unlink()

    def test_commit_cleans_storage(self, rootfs, backend):
        """Commit must copy to rootfs AND remove the upper dir afterward."""
        storage = tempfile.mkdtemp()
        p = _cow_policy(rootfs, on_exit="commit", fs_storage=storage, backend=backend)
        r = Sandbox(p).run(["sh", "-c", "echo committed > /tmp/committed.txt"])
        assert r.success, f"[{backend}] failed: {r.stderr}"
        # File must be in rootfs (commit actually ran)
        assert (rootfs / "tmp" / "committed.txt").exists(), \
            f"[{backend}] commit should copy file to rootfs"
        assert (rootfs / "tmp" / "committed.txt").read_text().strip() == "committed"
        # Storage should be cleaned up after commit
        remaining = os.listdir(storage)
        assert remaining == [], \
            f"[{backend}] commit should clean up storage, but found: {remaining}"
        # Clean up rootfs
        (rootfs / "tmp" / "committed.txt").unlink()


# ---------------------------------------------------------------------------
# Keep
# ---------------------------------------------------------------------------

class TestCowKeep:
    """on_exit=keep should leave upper layer, not merge to rootfs."""

    def test_keep_not_in_rootfs(self, rootfs, backend):
        storage = tempfile.mkdtemp()
        p = _cow_policy(rootfs, on_exit="keep", fs_storage=storage, backend=backend)
        r = Sandbox(p).run(["sh", "-c", "echo kept > /tmp/kept.txt"])
        assert r.success, f"[{backend}] failed: {r.stderr}"
        assert not (rootfs / "tmp" / "kept.txt").exists(), \
            f"[{backend}] file should not be in rootfs with on_exit=keep"

    def test_keep_write_visible_during_run(self, rootfs, backend):
        """With keep, writes should be visible during execution."""
        storage = tempfile.mkdtemp()
        p = _cow_policy(rootfs, on_exit="keep", fs_storage=storage, backend=backend)
        r = Sandbox(p).run([
            "sh", "-c", "echo kept > /tmp/kept.txt && cat /tmp/kept.txt"
        ])
        assert r.success, f"[{backend}] failed: {r.stderr}"
        assert b"kept" in r.stdout


# ---------------------------------------------------------------------------
# Concurrent isolation
# ---------------------------------------------------------------------------

class TestCowIsolation:
    """Concurrent sandboxes must see isolated filesystems."""

    def test_concurrent_writes_isolated(self, rootfs, backend):
        """Two sandboxes writing to the same virtual path should each see
        only their own writes, not each other's."""
        results = {}
        errors = {}

        def run_sandbox(name):
            try:
                storage = tempfile.mkdtemp()
                p = _cow_policy(rootfs, on_exit="abort", fs_storage=storage, backend=backend)
                r = Sandbox(p).run([
                    "sh", "-c",
                    f"echo {name} > /tmp/id.txt && cat /tmp/id.txt"
                ])
                results[name] = r.stdout.strip() if r.success else None
                if not r.success:
                    errors[name] = r.stderr
            except Exception as e:
                errors[name] = str(e)

        t1 = threading.Thread(target=run_sandbox, args=("SANDBOX_A",))
        t2 = threading.Thread(target=run_sandbox, args=("SANDBOX_B",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not errors, f"[{backend}] sandbox errors: {errors}"
        assert results["SANDBOX_A"] == b"SANDBOX_A", \
            f"[{backend}] A should see SANDBOX_A, got {results['SANDBOX_A']}"
        assert results["SANDBOX_B"] == b"SANDBOX_B", \
            f"[{backend}] B should see SANDBOX_B, got {results['SANDBOX_B']}"

    def test_concurrent_no_rootfs_leak(self, rootfs, backend):
        """Neither sandbox should leak to the shared rootfs."""
        def run_sandbox(name):
            storage = tempfile.mkdtemp()
            p = _cow_policy(rootfs, on_exit="abort", fs_storage=storage, backend=backend)
            Sandbox(p).run([
                "sh", "-c", f"echo {name} > /tmp/{name}.txt"
            ])

        threads = [
            threading.Thread(target=run_sandbox, args=(f"sb{i}",))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for i in range(4):
            assert not (rootfs / "tmp" / f"sb{i}.txt").exists(), \
                f"[{backend}] sb{i}.txt leaked to rootfs"
