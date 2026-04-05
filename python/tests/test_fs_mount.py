# SPDX-License-Identifier: Apache-2.0
"""Tests for fs_mount: mapping virtual paths inside a chroot to host directories."""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from sandlock import Policy, Sandbox
from sandlock.policy import FsIsolation


_HELPER_BIN = Path(__file__).resolve().parent.parent.parent / "tests" / "rootfs-helper"

_FS_READABLE = ["/usr", "/usr/bin", "/bin", "/sbin", "/etc", "/proc", "/dev"]


@pytest.fixture
def rootfs(tmp_path):
    """Build a minimal chroot rootfs (without /work)."""
    for d in ("usr/bin", "usr/sbin", "etc", "proc", "dev", "tmp"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)

    helper_dst = tmp_path / "usr" / "bin" / "rootfs-helper"
    try:
        os.link(_HELPER_BIN, helper_dst)
    except OSError:
        shutil.copy2(_HELPER_BIN, helper_dst)

    for name in ("sh", "cat", "echo", "ls", "pwd", "readlink", "stat",
                  "mkdir", "rmdir", "chmod", "ln", "rm", "mv", "true",
                  "false", "write", "access"):
        link = tmp_path / "usr" / "bin" / name
        if not link.exists():
            os.symlink("rootfs-helper", link)

    for name in ("bin", "sbin"):
        link = tmp_path / name
        if not link.exists():
            os.symlink(f"usr/{name}", link)

    os.chmod(tmp_path / "tmp", 0o1777)
    return tmp_path


def _mount_policy(rootfs, work_dir, cwd="/", extra_fs_readable=None):
    """Build a policy with fs_mount mapping /work to a host directory."""
    readable = list(_FS_READABLE)
    if extra_fs_readable:
        readable.extend(extra_fs_readable)
    return Policy(
        chroot=str(rootfs),
        fs_mount={"/work": str(work_dir)},
        fs_readable=readable,
        clean_env=True,
        cwd=cwd,
        env={"PATH": "/bin:/usr/bin"},
    )


class TestFsMount:

    def test_fs_mount_read_file(self, rootfs, tmp_path):
        """Write a file on host, verify sandbox can read it via cat."""
        work_dir = tmp_path / "hostwork"
        work_dir.mkdir()
        (work_dir / "hello.txt").write_text("hello from host\n")

        policy = _mount_policy(rootfs, work_dir)
        result = Sandbox(policy).run(["cat", "/work/hello.txt"])
        assert result.success, f"failed: {result.stderr}"
        assert b"hello from host" in result.stdout

    def test_fs_mount_write_file(self, rootfs, tmp_path):
        """Sandbox writes via write applet, verify file appears on host."""
        work_dir = tmp_path / "hostwork"
        work_dir.mkdir()

        policy = _mount_policy(rootfs, work_dir)
        result = Sandbox(policy).run(["write", "/work/output.txt", "sandbox wrote this"])
        assert result.success, f"failed: {result.stderr}"
        assert (work_dir / "output.txt").exists()
        assert "sandbox wrote this" in (work_dir / "output.txt").read_text()

    def test_fs_mount_ls_directory(self, rootfs, tmp_path):
        """Create files in mount target, verify ls /work lists them."""
        work_dir = tmp_path / "hostwork"
        work_dir.mkdir()
        (work_dir / "aaa.txt").write_text("a")
        (work_dir / "bbb.txt").write_text("b")

        policy = _mount_policy(rootfs, work_dir)
        result = Sandbox(policy).run(["ls", "/work"])
        assert result.success, f"failed: {result.stderr}"
        assert b"aaa.txt" in result.stdout
        assert b"bbb.txt" in result.stdout

    def test_fs_mount_cwd(self, rootfs, tmp_path):
        """Set cwd=/work, verify cat with relative path works."""
        work_dir = tmp_path / "hostwork"
        work_dir.mkdir()
        (work_dir / "file.txt").write_text("relative access\n")
        # cwd resolution needs the directory to exist in rootfs
        (rootfs / "work").mkdir(exist_ok=True)

        policy = _mount_policy(rootfs, work_dir, cwd="/work")
        result = Sandbox(policy).run(["cat", "file.txt"])
        assert result.success, f"failed: {result.stderr}"
        assert b"relative access" in result.stdout

    def test_fs_mount_survives_across_runs(self, rootfs, tmp_path):
        """Write in run 1, read in run 2 -- persistence via shared host dir."""
        work_dir = tmp_path / "hostwork"
        work_dir.mkdir()

        policy = _mount_policy(rootfs, work_dir)

        # Run 1: write
        r1 = Sandbox(policy).run(["write", "/work/persist.txt", "persisted data"])
        assert r1.success, f"run 1 failed: {r1.stderr}"

        # Run 2: read
        r2 = Sandbox(policy).run(["cat", "/work/persist.txt"])
        assert r2.success, f"run 2 failed: {r2.stderr}"
        assert b"persisted data" in r2.stdout

    def test_fs_mount_isolation(self, rootfs, tmp_path):
        """Two sandboxes with different mounts at /work are isolated."""
        work_a = tmp_path / "work_a"
        work_b = tmp_path / "work_b"
        work_a.mkdir()
        work_b.mkdir()

        policy_a = _mount_policy(rootfs, work_a)
        policy_b = _mount_policy(rootfs, work_b)

        ra = Sandbox(policy_a).run(["write", "/work/id.txt", "sandbox_a"])
        assert ra.success, f"sandbox A failed: {ra.stderr}"

        rb = Sandbox(policy_b).run(["write", "/work/id.txt", "sandbox_b"])
        assert rb.success, f"sandbox B failed: {rb.stderr}"

        assert (work_a / "id.txt").read_text().strip() == "sandbox_a"
        assert (work_b / "id.txt").read_text().strip() == "sandbox_b"

    def test_fs_mount_rootfs_untouched(self, rootfs, tmp_path):
        """Mount at /work should not affect a /work directory in rootfs."""
        # Create /work in rootfs with a sentinel file
        rootfs_work = rootfs / "work"
        rootfs_work.mkdir(exist_ok=True)
        (rootfs_work / "sentinel.txt").write_text("original")

        work_dir = tmp_path / "hostwork"
        work_dir.mkdir()

        policy = _mount_policy(rootfs, work_dir)
        result = Sandbox(policy).run(["write", "/work/new.txt", "from sandbox"])
        assert result.success, f"failed: {result.stderr}"

        # The write should go to work_dir, not rootfs /work
        assert (work_dir / "new.txt").exists()
        assert not (rootfs_work / "new.txt").exists(), \
            "write should go to mount target, not rootfs /work"
        assert (rootfs_work / "sentinel.txt").read_text() == "original", \
            "rootfs /work/sentinel.txt should be untouched"


class TestFsMountCow:
    """Tests for fs_mount combined with COW (copy-on-write) workdir."""

    def _cow_mount_policy(self, rootfs, work_dir, storage_dir,
                          on_exit="commit", max_disk=None):
        """Build a policy combining fs_mount with COW."""
        kwargs = dict(
            chroot=str(rootfs),
            fs_mount={"/work": str(work_dir)},
            workdir=str(work_dir),
            fs_storage=str(storage_dir),
            fs_writable=[str(work_dir)],
            fs_readable=list(_FS_READABLE),
            fs_isolation=FsIsolation.NONE,
            on_exit=on_exit,
            on_error="abort",
            clean_env=True,
            env={"PATH": "/bin:/usr/bin"},
        )
        if max_disk is not None:
            kwargs["max_disk"] = max_disk
        return Policy(**kwargs)

    def test_fs_mount_cow_commit(self, rootfs, tmp_path):
        """Write via fs_mount + COW with on_exit=commit, verify file persists."""
        work_dir = tmp_path / "hostwork"
        work_dir.mkdir()
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()

        policy = self._cow_mount_policy(rootfs, work_dir, storage_dir,
                                        on_exit="commit")
        result = Sandbox(policy).run(["write", "/work/committed.txt",
                                      "cow commit data"])
        assert result.success, f"failed: {result.stderr}"
        assert (work_dir / "committed.txt").exists(), \
            "committed file should persist in host directory"
        assert "cow commit data" in (work_dir / "committed.txt").read_text()

    def test_fs_mount_cow_abort(self, rootfs, tmp_path):
        """Write via fs_mount + COW with on_exit=abort, verify host unchanged."""
        work_dir = tmp_path / "hostwork"
        work_dir.mkdir()
        (work_dir / "existing.txt").write_text("original")
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()

        policy = self._cow_mount_policy(rootfs, work_dir, storage_dir,
                                        on_exit="abort")
        result = Sandbox(policy).run(["write", "/work/new_file.txt",
                                      "should be discarded"])
        assert result.success, f"failed: {result.stderr}"
        assert not (work_dir / "new_file.txt").exists(), \
            "aborted file should not appear in host directory"
        assert (work_dir / "existing.txt").read_text() == "original", \
            "existing file should be unchanged after abort"

    def test_fs_mount_cow_quota(self, rootfs, tmp_path):
        """Set a small max_disk, try to COW-copy a file that exceeds it."""
        work_dir = tmp_path / "hostwork"
        work_dir.mkdir()
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()

        # Pre-create a file larger than the quota in the lower layer.
        # Opening it for write inside the sandbox triggers a COW copy
        # which should be rejected with ENOSPC.
        (work_dir / "big.bin").write_bytes(b"\x00" * 8192)

        policy = self._cow_mount_policy(rootfs, work_dir, storage_dir,
                                        on_exit="abort", max_disk="1K")
        # The write applet opens the file with O_WRONLY|O_CREAT|O_TRUNC,
        # triggering a COW copy of the 8 KiB file against a 1 KiB quota.
        result = Sandbox(policy).run(["write", "/work/big.bin", "overwrite"])
        assert not result.success, \
            "Writing to a file exceeding COW quota should fail"
