# SPDX-License-Identifier: Apache-2.0
"""Tests for chroot interception of legacy (non-*at) syscalls.

musl libc uses stat/lstat/open/access/readlink instead of their *at
variants (newfstatat/openat/etc.).  These tests invoke the legacy
syscalls via the rootfs-helper binary to verify the chroot dispatcher
handles them correctly.
"""

import os
import platform
import shutil
from pathlib import Path

import pytest

from sandlock import Policy, Sandbox


pytestmark = pytest.mark.skipif(
    platform.machine() == "aarch64",
    reason="ARM64 Linux does not provide legacy non-*at path syscalls",
)


# ── helpers ──────────────────────────────────────────────────────

_HELPER_BIN = Path(__file__).resolve().parent.parent.parent / "tests" / "rootfs-helper"

_FS_READABLE = ["/usr", "/usr/bin", "/bin", "/sbin", "/etc", "/proc", "/dev"]


def _chroot_policy(rootfs, **overrides):
    defaults = dict(
        chroot=str(rootfs),
        cwd="/",
        fs_readable=_FS_READABLE + ["/"],
        clean_env=True,
        env={"PATH": "/usr/bin:/bin"},
    )
    defaults.update(overrides)
    return Policy(**defaults)


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
                  "false", "write", "access", "fstat-fd"):
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

    # Test data
    (tmp_path / "work" / "hello.txt").write_text("hello-from-chroot")
    return tmp_path


def _run_helper(rootfs, args, *, fs_writable=None):
    """Run rootfs-helper with the given arguments inside the chroot."""
    policy = _chroot_policy(
        rootfs,
        fs_readable=_FS_READABLE + ["/", "/work"],
        fs_writable=fs_writable or [],
    )
    return Sandbox(policy).run(["rootfs-helper"] + args)


# ── SYS_stat (nr 4) ─────────────────────────────────────────────

class TestLegacyStat:
    def test_stat_existing_file(self, rootfs):
        r = _run_helper(rootfs, ["legacy-stat", "/work/hello.txt"])
        assert r.success, f"stat failed: {r.stderr}"
        assert b"OK" in r.stdout

    def test_stat_nonexistent(self, rootfs):
        r = _run_helper(rootfs, ["legacy-stat", "/work/nope"])
        assert not r.success
        assert b"ERR" in r.stdout


# ── SYS_lstat (nr 6) ────────────────────────────────────────────

class TestLegacyLstat:
    def test_lstat_directory(self, rootfs):
        r = _run_helper(rootfs, ["legacy-lstat", "/work"])
        assert r.success, f"lstat failed: {r.stderr}"
        assert b"OK" in r.stdout


# ── SYS_open (nr 2) ─────────────────────────────────────────────

class TestLegacyOpen:
    def test_open_read(self, rootfs):
        r = _run_helper(rootfs, ["legacy-open", "/work/hello.txt"])
        assert r.success, f"open failed: {r.stderr}"
        assert b"OK" in r.stdout


# ── SYS_access (nr 21) ──────────────────────────────────────────

class TestLegacyAccess:
    def test_access_existing(self, rootfs):
        r = _run_helper(rootfs, ["legacy-access", "/work/hello.txt"])
        assert r.success, f"access failed: {r.stderr}"
        assert b"OK" in r.stdout

    def test_access_nonexistent(self, rootfs):
        r = _run_helper(rootfs, ["legacy-access", "/work/nope"])
        assert not r.success
        assert b"ERR" in r.stdout


# ── SYS_readlink (nr 89) ────────────────────────────────────────

class TestLegacyReadlink:
    def test_readlink(self, rootfs):
        # Create a symlink inside chroot
        os.symlink("hello.txt", rootfs / "work" / "mylink")
        r = _run_helper(rootfs, ["legacy-readlink", "/work/mylink"])
        assert r.success, f"readlink failed: {r.stderr}"
        assert b"OK" in r.stdout


# ── SYS_mkdir (nr 83) / SYS_rmdir (nr 84) ───────────────────────

class TestLegacyMkdirRmdir:
    def test_mkdir_rmdir(self, rootfs):
        r = _run_helper(rootfs, ["legacy-mkdir", "/tmp/testdir"],
                        fs_writable=["/tmp"])
        assert r.success, f"mkdir failed: {r.stderr}"
        assert b"OK" in r.stdout

        r = _run_helper(rootfs, ["legacy-rmdir", "/tmp/testdir"],
                        fs_writable=["/tmp"])
        assert r.success, f"rmdir failed: {r.stderr}"
        assert b"OK" in r.stdout


# ── SYS_unlink (nr 87) ──────────────────────────────────────────

class TestLegacyUnlink:
    def test_unlink(self, rootfs):
        (rootfs / "tmp" / "deleteme").write_text("bye")
        r = _run_helper(rootfs, ["legacy-unlink", "/tmp/deleteme"],
                        fs_writable=["/tmp"])
        assert r.success, f"unlink failed: {r.stderr}"
        assert b"OK" in r.stdout
        assert not (rootfs / "tmp" / "deleteme").exists()


# ── SYS_rename (nr 82) ──────────────────────────────────────────

class TestLegacyRename:
    def test_rename(self, rootfs):
        (rootfs / "tmp" / "before.txt").write_text("data")
        r = _run_helper(rootfs, ["legacy-rename", "/tmp/before.txt", "/tmp/after.txt"],
                        fs_writable=["/tmp"])
        assert r.success, f"rename failed: {r.stderr}"
        assert b"OK" in r.stdout
        assert (rootfs / "tmp" / "after.txt").exists()
        assert not (rootfs / "tmp" / "before.txt").exists()


# ── SYS_symlink (nr 88) ─────────────────────────────────────────

class TestLegacySymlink:
    def test_symlink(self, rootfs):
        r = _run_helper(rootfs, ["legacy-symlink", "target.txt", "/tmp/mylink"],
                        fs_writable=["/tmp"])
        assert r.success, f"symlink failed: {r.stderr}"
        assert b"OK" in r.stdout
        assert (rootfs / "tmp" / "mylink").is_symlink()


# ── SYS_chmod (nr 90) ───────────────────────────────────────────

class TestLegacyChmod:
    def test_chmod(self, rootfs):
        (rootfs / "tmp" / "chmodme").write_text("x")
        r = _run_helper(rootfs, ["legacy-chmod", "0755", "/tmp/chmodme"],
                        fs_writable=["/tmp"])
        assert r.success, f"chmod failed: {r.stderr}"
        assert b"OK" in r.stdout


# ── fstat via AT_EMPTY_PATH ─────────────────────────────────────

class TestFstatFd:
    """fstat(fd) uses newfstatat(fd, "", buf, AT_EMPTY_PATH) internally.

    The chroot handler must pass this through to the kernel (the fd
    already points to the correct file), not attempt chroot path
    resolution on the empty string.
    """

    def test_fstat_fd_on_chroot_file(self, rootfs):
        """Open a file inside the chroot, then fstat the fd."""
        r = _run_helper(rootfs, ["fstat-fd", "/work/hello.txt"])
        assert r.success, f"fstat-fd failed: {r.stderr}"
        out = r.stdout.decode()
        assert "OK" in out
        # Verify the size matches the file we created in the rootfs
        assert "size=17" in out  # "hello-from-chroot" is 17 bytes
