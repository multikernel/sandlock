# SPDX-License-Identifier: Apache-2.0
"""Tests for chroot interception of legacy (non-*at) syscalls.

musl libc uses stat/lstat/open/access/readlink instead of their *at
variants (newfstatat/openat/etc.).  These tests invoke the legacy
syscalls directly via ctypes to verify the chroot dispatcher handles
them — independent of which libc the test runner uses.
"""

import os
import sys
import textwrap

import pytest

from sandlock import Policy, Sandbox


# ── helpers ──────────────────────────────────────────────────────

_PYTHON_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev",
    sys.prefix,
]))


def _chroot_policy(rootfs, **overrides):
    defaults = dict(
        chroot=str(rootfs),
        cwd="/",
        fs_readable=_PYTHON_READABLE + ["/"],
    )
    defaults.update(overrides)
    return Policy(**defaults)


@pytest.fixture
def rootfs(tmp_path):
    """Build a minimal chroot rootfs using symlinks to host dirs."""
    for d in ("usr", "lib", "lib64", "bin", "sbin", "etc", "proc", "dev"):
        host = os.path.join("/", d)
        target = tmp_path / d
        if os.path.exists(host) and not target.exists():
            os.symlink(host, target)
    (tmp_path / "tmp").mkdir(exist_ok=True)
    (tmp_path / "work").mkdir(exist_ok=True)
    (tmp_path / "work" / "hello.txt").write_text("hello-from-chroot")
    return tmp_path


def _run_python(rootfs, code, *, fs_writable=None):
    """Run a Python snippet inside the chroot and return the result."""
    policy = _chroot_policy(
        rootfs,
        fs_readable=_PYTHON_READABLE + ["/", "/work"],
        fs_writable=fs_writable or [],
    )
    # Dedent so callers can use indented triple-quoted strings.
    code = textwrap.dedent(code).strip()
    return Sandbox(policy).run(["python3", "-c", code])


# ── SYS_stat (nr 4) ─────────────────────────────────────────────

class TestLegacyStat:
    def test_stat_existing_file(self, rootfs):
        r = _run_python(rootfs, """
            import ctypes, sys
            buf = ctypes.create_string_buffer(144)
            ret = ctypes.CDLL(None).syscall(4, b"/work/hello.txt\\0", buf)
            print(ret)
        """)
        assert r.success, f"stat failed: {r.stderr}"
        assert r.stdout.strip() == b"0"

    def test_stat_nonexistent(self, rootfs):
        r = _run_python(rootfs, """
            import ctypes
            buf = ctypes.create_string_buffer(144)
            ret = ctypes.CDLL(None).syscall(4, b"/work/nope\\0", buf)
            print(ret)
        """)
        assert r.success
        assert r.stdout.strip() == b"-1"


# ── SYS_lstat (nr 6) ────────────────────────────────────────────

class TestLegacyLstat:
    def test_lstat_directory(self, rootfs):
        r = _run_python(rootfs, """
            import ctypes
            buf = ctypes.create_string_buffer(144)
            ret = ctypes.CDLL(None).syscall(6, b"/work\\0", buf)
            print(ret)
        """)
        assert r.success, f"lstat failed: {r.stderr}"
        assert r.stdout.strip() == b"0"


# ── SYS_open (nr 2) ─────────────────────────────────────────────

class TestLegacyOpen:
    def test_open_read(self, rootfs):
        r = _run_python(rootfs, """
            import ctypes, os
            fd = ctypes.CDLL(None).syscall(2, b"/work/hello.txt\\0", 0, 0)
            if fd >= 0:
                data = os.read(fd, 100)
                os.close(fd)
                print(data.decode())
            else:
                print("FAIL", fd)
        """)
        assert r.success, f"open failed: {r.stderr}"
        assert b"hello-from-chroot" in r.stdout


# ── SYS_access (nr 21) ──────────────────────────────────────────

class TestLegacyAccess:
    def test_access_existing(self, rootfs):
        r = _run_python(rootfs, """
            import ctypes
            ret = ctypes.CDLL(None).syscall(21, b"/work/hello.txt\\0", 0)
            print(ret)
        """)
        assert r.success, f"access failed: {r.stderr}"
        assert r.stdout.strip() == b"0"

    def test_access_nonexistent(self, rootfs):
        r = _run_python(rootfs, """
            import ctypes
            ret = ctypes.CDLL(None).syscall(21, b"/work/nope\\0", 0)
            print(ret)
        """)
        assert r.success
        assert r.stdout.strip() == b"-1"


# ── SYS_readlink (nr 89) ────────────────────────────────────────

class TestLegacyReadlink:
    def test_readlink(self, rootfs):
        # Create a symlink inside chroot
        link = rootfs / "work" / "mylink"
        os.symlink("hello.txt", link)
        r = _run_python(rootfs, """
            import ctypes
            buf = ctypes.create_string_buffer(256)
            ret = ctypes.CDLL(None).syscall(89, b"/work/mylink\\0", buf, 256)
            if ret > 0:
                print(buf.value.decode())
            else:
                print("FAIL", ret)
        """)
        assert r.success, f"readlink failed: {r.stderr}"
        assert b"hello.txt" in r.stdout


# ── SYS_mkdir (nr 83) / SYS_rmdir (nr 84) ───────────────────────

class TestLegacyMkdirRmdir:
    def test_mkdir_rmdir(self, rootfs):
        r = _run_python(rootfs, """
            import ctypes
            libc = ctypes.CDLL(None)
            ret = libc.syscall(83, b"/tmp/testdir\\0", 0o755)
            print("mkdir", ret)
            ret = libc.syscall(84, b"/tmp/testdir\\0")
            print("rmdir", ret)
        """, fs_writable=["/tmp"])
        assert r.success, f"mkdir/rmdir failed: {r.stderr}"
        assert b"mkdir 0" in r.stdout
        assert b"rmdir 0" in r.stdout


# ── SYS_unlink (nr 87) ──────────────────────────────────────────

class TestLegacyUnlink:
    def test_unlink(self, rootfs):
        (rootfs / "tmp" / "deleteme").write_text("bye")
        r = _run_python(rootfs, """
            import ctypes
            ret = ctypes.CDLL(None).syscall(87, b"/tmp/deleteme\\0")
            print(ret)
        """, fs_writable=["/tmp"])
        assert r.success, f"unlink failed: {r.stderr}"
        assert r.stdout.strip() == b"0"
        assert not (rootfs / "tmp" / "deleteme").exists()


# ── SYS_rename (nr 82) ──────────────────────────────────────────

class TestLegacyRename:
    def test_rename(self, rootfs):
        (rootfs / "tmp" / "before.txt").write_text("data")
        r = _run_python(rootfs, """
            import ctypes
            ret = ctypes.CDLL(None).syscall(82, b"/tmp/before.txt\\0", b"/tmp/after.txt\\0")
            print(ret)
        """, fs_writable=["/tmp"])
        assert r.success, f"rename failed: {r.stderr}"
        assert r.stdout.strip() == b"0"
        assert (rootfs / "tmp" / "after.txt").exists()
        assert not (rootfs / "tmp" / "before.txt").exists()


# ── SYS_symlink (nr 88) ─────────────────────────────────────────

class TestLegacySymlink:
    def test_symlink(self, rootfs):
        r = _run_python(rootfs, """
            import ctypes
            ret = ctypes.CDLL(None).syscall(88, b"target.txt\\0", b"/tmp/mylink\\0")
            print(ret)
        """, fs_writable=["/tmp"])
        assert r.success, f"symlink failed: {r.stderr}"
        assert r.stdout.strip() == b"0"
        assert (rootfs / "tmp" / "mylink").is_symlink()


# ── SYS_chmod (nr 90) ───────────────────────────────────────────

class TestLegacyChmod:
    def test_chmod(self, rootfs):
        (rootfs / "tmp" / "chmodme").write_text("x")
        r = _run_python(rootfs, """
            import ctypes
            ret = ctypes.CDLL(None).syscall(90, b"/tmp/chmodme\\0", 0o644)
            print(ret)
        """, fs_writable=["/tmp"])
        assert r.success, f"chmod failed: {r.stderr}"
        assert r.stdout.strip() == b"0"
