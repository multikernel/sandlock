# SPDX-License-Identifier: Apache-2.0
"""Tests for chroot + COW filesystem isolation.

Verifies that on_exit/on_error branch actions work correctly and that
concurrent sandboxes with separate fs_storage directories get isolated
upper layers.
"""

import os
import sys
import threading
import tempfile

import pytest

from sandlock import Policy, Sandbox


_PYTHON_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev",
    sys.prefix,
]))


@pytest.fixture
def rootfs(tmp_path):
    """Build a minimal chroot rootfs using symlinks to host dirs."""
    for d in ("usr", "lib", "lib64", "bin", "sbin", "etc", "proc", "dev"):
        host = os.path.join("/", d)
        target = tmp_path / d
        if os.path.exists(host) and not target.exists():
            os.symlink(host, target)
    (tmp_path / "tmp").mkdir(exist_ok=True)
    return tmp_path


def _cow_policy(rootfs, on_exit="abort", fs_storage=None):
    return Policy(
        chroot=str(rootfs),
        workdir=str(rootfs),
        cwd="/",
        fs_readable=_PYTHON_READABLE + ["/"],
        fs_writable=["/tmp"],
        on_exit=on_exit,
        fs_storage=fs_storage,
        clean_env=True,
        env={"PATH": "/bin:/usr/bin"},
    )


class TestCowAbort:
    """on_exit=abort should discard all writes."""

    def test_abort_no_leak(self, rootfs):
        p = _cow_policy(rootfs, on_exit="abort")
        r = Sandbox(p).run(["sh", "-c", "echo marker > /tmp/marker.txt"])
        assert r.success, f"failed: {r.stderr}"
        assert not (rootfs / "tmp" / "marker.txt").exists(), \
            "file should not leak to rootfs with on_exit=abort"

    def test_abort_write_visible_during_run(self, rootfs):
        """Writes should be visible to the child during execution."""
        p = _cow_policy(rootfs, on_exit="abort")
        r = Sandbox(p).run([
            "sh", "-c", "echo hello > /tmp/test.txt && cat /tmp/test.txt"
        ])
        assert r.success, f"failed: {r.stderr}"
        assert b"hello" in r.stdout

    def test_abort_multiple_files(self, rootfs):
        p = _cow_policy(rootfs, on_exit="abort")
        r = Sandbox(p).run([
            "sh", "-c",
            "echo a > /tmp/a.txt && echo b > /tmp/b.txt && cat /tmp/a.txt /tmp/b.txt"
        ])
        assert r.success, f"failed: {r.stderr}"
        assert b"a" in r.stdout
        assert b"b" in r.stdout
        assert not (rootfs / "tmp" / "a.txt").exists()
        assert not (rootfs / "tmp" / "b.txt").exists()


class TestCowCommit:
    """on_exit=commit should merge writes to rootfs."""

    def test_commit_persists(self, rootfs):
        p = _cow_policy(rootfs, on_exit="commit")
        r = Sandbox(p).run(["sh", "-c", "echo persisted > /tmp/persist.txt"])
        assert r.success, f"failed: {r.stderr}"
        assert (rootfs / "tmp" / "persist.txt").exists(), \
            "file should persist to rootfs with on_exit=commit"
        assert (rootfs / "tmp" / "persist.txt").read_text().strip() == "persisted"
        # Clean up
        (rootfs / "tmp" / "persist.txt").unlink()


class TestCowKeep:
    """on_exit=keep should leave upper layer, not merge to rootfs."""

    def test_keep_not_in_rootfs(self, rootfs):
        storage = tempfile.mkdtemp()
        p = _cow_policy(rootfs, on_exit="keep", fs_storage=storage)
        r = Sandbox(p).run(["sh", "-c", "echo kept > /tmp/kept.txt"])
        assert r.success, f"failed: {r.stderr}"
        assert not (rootfs / "tmp" / "kept.txt").exists(), \
            "file should not be in rootfs with on_exit=keep"

    def test_keep_write_visible_during_run(self, rootfs):
        """With keep, writes should be visible during execution."""
        storage = tempfile.mkdtemp()
        p = _cow_policy(rootfs, on_exit="keep", fs_storage=storage)
        r = Sandbox(p).run([
            "sh", "-c", "echo kept > /tmp/kept.txt && cat /tmp/kept.txt"
        ])
        assert r.success, f"failed: {r.stderr}"
        assert b"kept" in r.stdout


class TestCowIsolation:
    """Concurrent sandboxes must see isolated filesystems."""

    def test_concurrent_writes_isolated(self, rootfs):
        """Two sandboxes writing to the same virtual path should each see
        only their own writes, not each other's."""
        results = {}
        errors = {}

        def run_sandbox(name):
            try:
                storage = tempfile.mkdtemp()
                p = _cow_policy(rootfs, on_exit="abort", fs_storage=storage)
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

        assert not errors, f"sandbox errors: {errors}"
        assert results["SANDBOX_A"] == b"SANDBOX_A", \
            f"A should see SANDBOX_A, got {results['SANDBOX_A']}"
        assert results["SANDBOX_B"] == b"SANDBOX_B", \
            f"B should see SANDBOX_B, got {results['SANDBOX_B']}"

    def test_concurrent_no_rootfs_leak(self, rootfs):
        """Neither sandbox should leak to the shared rootfs."""
        def run_sandbox(name):
            storage = tempfile.mkdtemp()
            p = _cow_policy(rootfs, on_exit="abort", fs_storage=storage)
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
                f"sb{i}.txt leaked to rootfs"
