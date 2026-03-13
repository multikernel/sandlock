# SPDX-License-Identifier: Apache-2.0
"""Tests for seccomp user notification modules."""

from __future__ import annotations

import ctypes
import errno
import struct
import unittest
from unittest import mock

from sandlock._notif_policy import (
    NotifAction,
    NotifPolicy,
    PathRule,
    default_proc_rules,
)
from sandlock._procfs import resolve_openat_path
from sandlock._notif import (
    _ioc,
    _IOC_READ,
    _IOC_WRITE,
    _SECCOMP_NOTIF_SIZE,
    _SECCOMP_NOTIF_RESP_SIZE,
    _SECCOMP_NOTIF_ADDFD_SIZE,
    SECCOMP_IOCTL_NOTIF_RECV,
    SECCOMP_IOCTL_NOTIF_SEND,
    SECCOMP_IOCTL_NOTIF_ID_VALID,
    SECCOMP_IOCTL_NOTIF_ADDFD,
    SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    SeccompNotif,
    SeccompNotifResp,
    SeccompNotifAddfd,
    _SeccompData,
    _build_combined_filter,
)
from sandlock._seccomp import (
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_USER_NOTIF,
    _SYSCALL_NR,
    BPF_LD,
    BPF_W,
    BPF_ABS,
    BPF_JMP,
    BPF_JEQ,
    BPF_K,
    BPF_RET,
)


# ===== NotifPolicy tests =====


class TestNotifAction(unittest.TestCase):
    def test_values(self):
        self.assertEqual(NotifAction.ALLOW.value, "allow")
        self.assertEqual(NotifAction.DENY.value, "deny")
        self.assertEqual(NotifAction.VIRTUALIZE.value, "virtualize")


class TestPathRule(unittest.TestCase):
    def test_defaults(self):
        r = PathRule("/proc/kcore", NotifAction.DENY)
        self.assertEqual(r.pattern, "/proc/kcore")
        self.assertEqual(r.action, NotifAction.DENY)
        self.assertEqual(r.errno_code, errno.EACCES)
        self.assertEqual(r.virtual_content, b"")

    def test_custom_errno(self):
        r = PathRule("/x", NotifAction.DENY, errno_code=errno.EPERM)
        self.assertEqual(r.errno_code, errno.EPERM)

    def test_virtual_content(self):
        r = PathRule("/proc/self/mounts", NotifAction.VIRTUALIZE,
                     virtual_content=b"rootfs / rootfs rw 0 0\n")
        self.assertEqual(r.virtual_content, b"rootfs / rootfs rw 0 0\n")

    def test_frozen(self):
        r = PathRule("/x", NotifAction.ALLOW)
        with self.assertRaises(AttributeError):
            r.pattern = "/y"


class TestNotifPolicy(unittest.TestCase):
    def test_empty_policy_allows_all(self):
        p = NotifPolicy()
        action, err, content = p.decide("/anything")
        self.assertEqual(action, NotifAction.ALLOW)
        self.assertEqual(err, 0)
        self.assertEqual(content, b"")

    def test_exact_deny(self):
        p = NotifPolicy(rules=(
            PathRule("/proc/kcore", NotifAction.DENY, errno.EACCES),
        ))
        action, err, _ = p.decide("/proc/kcore")
        self.assertEqual(action, NotifAction.DENY)
        self.assertEqual(err, errno.EACCES)

    def test_exact_deny_no_false_positive(self):
        p = NotifPolicy(rules=(
            PathRule("/proc/kcore", NotifAction.DENY, errno.EACCES),
        ))
        action, _, _ = p.decide("/proc/kcorex")
        self.assertEqual(action, NotifAction.ALLOW)

    def test_prefix_match(self):
        p = NotifPolicy(rules=(
            PathRule("/sys/firmware/", NotifAction.DENY, errno.EACCES),
        ))
        action, _, _ = p.decide("/sys/firmware/efi/vars")
        self.assertEqual(action, NotifAction.DENY)

    def test_prefix_exact_dir(self):
        """Prefix rule matches the dir itself (without trailing slash)."""
        p = NotifPolicy(rules=(
            PathRule("/sys/firmware/", NotifAction.DENY, errno.EACCES),
        ))
        action, _, _ = p.decide("/sys/firmware")
        self.assertEqual(action, NotifAction.DENY)

    def test_prefix_no_partial(self):
        """Prefix /sys/firmware/ should not match /sys/firmwarex."""
        p = NotifPolicy(rules=(
            PathRule("/sys/firmware/", NotifAction.DENY, errno.EACCES),
        ))
        action, _, _ = p.decide("/sys/firmwarex")
        self.assertEqual(action, NotifAction.ALLOW)

    def test_fnmatch_glob(self):
        p = NotifPolicy(rules=(
            PathRule("/proc/*/status", NotifAction.ALLOW),
        ))
        action, _, _ = p.decide("/proc/1234/status")
        self.assertEqual(action, NotifAction.ALLOW)

    def test_first_match_wins(self):
        p = NotifPolicy(rules=(
            PathRule("/proc/kcore", NotifAction.DENY, errno.EACCES),
            PathRule("/proc/*", NotifAction.ALLOW),
        ))
        action, _, _ = p.decide("/proc/kcore")
        self.assertEqual(action, NotifAction.DENY)

    def test_virtualize(self):
        content = b"fake mounts"
        p = NotifPolicy(rules=(
            PathRule("/proc/self/mounts", NotifAction.VIRTUALIZE,
                     virtual_content=content),
        ))
        action, _, virt = p.decide("/proc/self/mounts")
        self.assertEqual(action, NotifAction.VIRTUALIZE)
        self.assertEqual(virt, content)


class TestPidIsolation(unittest.TestCase):
    """Tests for isolate_pids: deny /proc/<foreign_pid>/ access."""

    def _policy(self, **kwargs):
        return NotifPolicy(
            rules=(PathRule("*", NotifAction.ALLOW),),
            isolate_pids=True,
            **kwargs,
        )

    def test_foreign_pid_denied(self):
        p = self._policy()
        action, err, _ = p.decide("/proc/999/status", sandbox_pids={100, 101})
        self.assertEqual(action, NotifAction.DENY)
        self.assertEqual(err, errno.ESRCH)

    def test_own_pid_allowed(self):
        p = self._policy()
        action, _, _ = p.decide("/proc/100/status", sandbox_pids={100, 101})
        self.assertEqual(action, NotifAction.ALLOW)

    def test_foreign_pid_cmdline(self):
        p = self._policy()
        action, _, _ = p.decide("/proc/500/cmdline", sandbox_pids={100})
        self.assertEqual(action, NotifAction.DENY)

    def test_foreign_pid_root_dir(self):
        """Accessing /proc/<pid> (no trailing component) is also denied."""
        p = self._policy()
        action, _, _ = p.decide("/proc/500", sandbox_pids={100})
        self.assertEqual(action, NotifAction.DENY)

    def test_non_proc_path_unaffected(self):
        p = self._policy()
        action, _, _ = p.decide("/etc/passwd", sandbox_pids={100})
        self.assertEqual(action, NotifAction.ALLOW)

    def test_proc_self_unaffected(self):
        """Paths like /proc/self/... don't match the numeric PID regex."""
        p = self._policy()
        action, _, _ = p.decide("/proc/self/status", sandbox_pids={100})
        self.assertEqual(action, NotifAction.ALLOW)

    def test_proc_global_files_unaffected(self):
        """/proc/kcore, /proc/cpuinfo etc. don't match /proc/<pid>/."""
        p = self._policy()
        action, _, _ = p.decide("/proc/cpuinfo", sandbox_pids={100})
        self.assertEqual(action, NotifAction.ALLOW)

    def test_disabled_by_default(self):
        p = NotifPolicy(rules=(PathRule("*", NotifAction.ALLOW),))
        action, _, _ = p.decide("/proc/999/status", sandbox_pids={100})
        self.assertEqual(action, NotifAction.ALLOW)

    def test_no_sandbox_pids_skips_check(self):
        """If sandbox_pids is None, isolation is skipped."""
        p = self._policy()
        action, _, _ = p.decide("/proc/999/status", sandbox_pids=None)
        self.assertEqual(action, NotifAction.ALLOW)

    def test_custom_errno(self):
        p = self._policy(foreign_pid_error=errno.ENOENT)
        action, err, _ = p.decide("/proc/999/status", sandbox_pids={100})
        self.assertEqual(err, errno.ENOENT)

    def test_pid_check_before_rules(self):
        """PID isolation fires before normal rules, so even a wildcard ALLOW
        doesn't override it."""
        p = NotifPolicy(
            rules=(PathRule("/proc/*/status", NotifAction.ALLOW),),
            isolate_pids=True,
        )
        action, _, _ = p.decide("/proc/999/status", sandbox_pids={100})
        self.assertEqual(action, NotifAction.DENY)


class TestDefaultProcRules(unittest.TestCase):
    def test_returns_tuple(self):
        rules = default_proc_rules()
        self.assertIsInstance(rules, tuple)
        self.assertTrue(len(rules) > 0)

    def test_denies_kcore(self):
        p = NotifPolicy(rules=default_proc_rules())
        action, _, _ = p.decide("/proc/kcore")
        self.assertEqual(action, NotifAction.DENY)

    def test_denies_kallsyms(self):
        p = NotifPolicy(rules=default_proc_rules())
        action, _, _ = p.decide("/proc/kallsyms")
        self.assertEqual(action, NotifAction.DENY)

    def test_denies_sys_kernel(self):
        p = NotifPolicy(rules=default_proc_rules())
        action, _, _ = p.decide("/sys/kernel/debug/something")
        self.assertEqual(action, NotifAction.DENY)

    def test_denies_sys_firmware(self):
        p = NotifPolicy(rules=default_proc_rules())
        action, _, _ = p.decide("/sys/firmware/efi/vars")
        self.assertEqual(action, NotifAction.DENY)

    def test_denies_sys_cgroup(self):
        p = NotifPolicy(rules=default_proc_rules())
        action, _, _ = p.decide("/sys/fs/cgroup/user.slice")
        self.assertEqual(action, NotifAction.DENY)

    def test_virtualizes_mountinfo(self):
        p = NotifPolicy(rules=default_proc_rules())
        action, _, content = p.decide("/proc/self/mountinfo")
        self.assertEqual(action, NotifAction.VIRTUALIZE)
        self.assertEqual(content, b"")

    def test_virtualizes_mounts(self):
        p = NotifPolicy(rules=default_proc_rules())
        action, _, _ = p.decide("/proc/self/mounts")
        self.assertEqual(action, NotifAction.VIRTUALIZE)

    def test_allows_normal_proc(self):
        p = NotifPolicy(rules=default_proc_rules())
        action, _, _ = p.decide("/proc/self/status")
        self.assertEqual(action, NotifAction.ALLOW)

    def test_allows_non_proc(self):
        p = NotifPolicy(rules=default_proc_rules())
        action, _, _ = p.decide("/etc/passwd")
        self.assertEqual(action, NotifAction.ALLOW)


# ===== _notif module tests =====


class TestIocConstants(unittest.TestCase):
    def test_ioc_formula(self):
        """Verify _ioc matches manual computation."""
        val = _ioc(_IOC_WRITE | _IOC_READ, 0, _SECCOMP_NOTIF_SIZE)
        # dir=3 (W|R), size=80, type=0x21, nr=0
        expected = (3 << 30) | (80 << 16) | (0x21 << 8) | 0
        self.assertEqual(val, expected)

    def test_recv_ioctl(self):
        expected = (3 << 30) | (_SECCOMP_NOTIF_SIZE << 16) | (0x21 << 8) | 0
        self.assertEqual(SECCOMP_IOCTL_NOTIF_RECV, expected)

    def test_send_ioctl(self):
        expected = (3 << 30) | (_SECCOMP_NOTIF_RESP_SIZE << 16) | (0x21 << 8) | 1
        self.assertEqual(SECCOMP_IOCTL_NOTIF_SEND, expected)

    def test_id_valid_ioctl(self):
        # direction = _IOC_WRITE only = 1
        expected = (1 << 30) | (8 << 16) | (0x21 << 8) | 2
        self.assertEqual(SECCOMP_IOCTL_NOTIF_ID_VALID, expected)

    def test_addfd_ioctl(self):
        expected = (3 << 30) | (_SECCOMP_NOTIF_ADDFD_SIZE << 16) | (0x21 << 8) | 3
        self.assertEqual(SECCOMP_IOCTL_NOTIF_ADDFD, expected)


class TestCtypesStructs(unittest.TestCase):
    def test_seccomp_notif_size(self):
        self.assertEqual(ctypes.sizeof(SeccompNotif), _SECCOMP_NOTIF_SIZE)

    def test_seccomp_notif_resp_size(self):
        self.assertEqual(ctypes.sizeof(SeccompNotifResp), _SECCOMP_NOTIF_RESP_SIZE)

    def test_seccomp_notif_addfd_size(self):
        self.assertEqual(ctypes.sizeof(SeccompNotifAddfd), _SECCOMP_NOTIF_ADDFD_SIZE)

    def test_seccomp_data_size(self):
        self.assertEqual(ctypes.sizeof(_SeccompData), 64)

    def test_notif_resp_fields(self):
        resp = SeccompNotifResp()
        resp.id = 42
        resp.val = -1
        resp.error = -errno.EACCES
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
        self.assertEqual(resp.id, 42)
        self.assertEqual(resp.error, -errno.EACCES)
        self.assertEqual(resp.flags, 1)

    def test_addfd_fields(self):
        addfd = SeccompNotifAddfd()
        addfd.id = 99
        addfd.srcfd = 7
        addfd.newfd = 0
        self.assertEqual(addfd.id, 99)
        self.assertEqual(addfd.srcfd, 7)


class TestBuildNotifFilter(unittest.TestCase):
    def _decode_insns(self, prog_bytes):
        """Decode BPF bytecode into list of (code, jt, jf, k) tuples."""
        insns = []
        for i in range(0, len(prog_bytes), 8):
            code, jt, jf, k = struct.unpack("<HBBi", prog_bytes[i:i+8])
            insns.append((code, jt, jf, k))
        return insns

    def test_single_syscall(self):
        prog = _build_combined_filter([257], [])  # openat notif, no deny
        insns = self._decode_insns(prog)
        # Last three instructions: ALLOW, USER_NOTIF, ERRNO
        self.assertGreaterEqual(len(insns), 7)
        code_allow, _, _, k_allow = insns[-3]
        code_notif, _, _, k_notif = insns[-2]
        code_errno, _, _, k_errno = insns[-1]
        self.assertEqual(code_allow & 0xFF, BPF_RET | BPF_K)
        self.assertEqual(k_allow, SECCOMP_RET_ALLOW)
        self.assertEqual(code_notif & 0xFF, BPF_RET | BPF_K)
        self.assertEqual(k_notif & 0xFFFFFFFF, SECCOMP_RET_USER_NOTIF & 0xFFFFFFFF)
        self.assertEqual(code_errno & 0xFF, BPF_RET | BPF_K)

    def test_multiple_syscalls(self):
        prog = _build_combined_filter([2, 257], [])
        insns = self._decode_insns(prog)
        # Should have JEQ instructions for arch check + arg filters + 2 notif syscalls
        jeq_count = sum(1 for code, _, _, _ in insns
                        if (code & 0xFF) == (BPF_JMP | BPF_JEQ | BPF_K))
        # At least: 1 arch + 2 notif syscalls = 3 (plus arg filter JEQs)
        self.assertGreaterEqual(jeq_count, 3)

    def test_starts_with_arch_check(self):
        prog = _build_combined_filter([257], [])
        insns = self._decode_insns(prog)
        # First insn: load arch
        code0, _, _, _ = insns[0]
        self.assertEqual(code0, BPF_LD | BPF_W | BPF_ABS)
        # Second: JEQ arch
        code1 = insns[1][0] & 0xFF
        self.assertEqual(code1, BPF_JMP | BPF_JEQ | BPF_K)
        # Third: RET KILL on arch mismatch
        code2, _, _, k2 = insns[2]
        self.assertEqual(code2 & 0xFF, BPF_RET | BPF_K)
        self.assertEqual(k2 & 0xFFFFFFFF, SECCOMP_RET_KILL_PROCESS & 0xFFFFFFFF)

    def test_filter_size_grows_with_syscalls(self):
        """More syscalls should produce a larger filter."""
        prog1 = _build_combined_filter([100], [])
        prog5 = _build_combined_filter(list(range(100, 105)), [])
        self.assertGreater(len(prog5), len(prog1))


# ===== _procfs tests =====


class TestResolveOpenatPath(unittest.TestCase):
    @mock.patch("sandlock._procfs.read_cstring")
    def test_absolute_path(self, mock_read):
        mock_read.return_value = "/etc/passwd"
        result = resolve_openat_path(123, -100, 0xDEAD)
        self.assertEqual(result, "/etc/passwd")

    @mock.patch("sandlock._procfs.read_cstring")
    @mock.patch("os.readlink")
    def test_relative_at_fdcwd(self, mock_readlink, mock_read):
        mock_read.return_value = "file.txt"
        mock_readlink.return_value = "/home/user"
        result = resolve_openat_path(123, -100, 0xDEAD)
        self.assertEqual(result, "/home/user/file.txt")
        mock_readlink.assert_called_with("/proc/123/cwd")

    @mock.patch("sandlock._procfs.read_cstring")
    @mock.patch("os.readlink")
    def test_relative_with_dirfd(self, mock_readlink, mock_read):
        mock_read.return_value = "sub/file.txt"
        mock_readlink.return_value = "/tmp/dir"
        result = resolve_openat_path(123, 5, 0xDEAD)
        self.assertEqual(result, "/tmp/dir/sub/file.txt")
        mock_readlink.assert_called_with("/proc/123/fd/5")

    @mock.patch("sandlock._procfs.read_cstring")
    def test_absolute_normpath(self, mock_read):
        mock_read.return_value = "/proc/../etc/passwd"
        result = resolve_openat_path(123, -100, 0xDEAD)
        self.assertEqual(result, "/etc/passwd")

    @mock.patch("sandlock._procfs.read_cstring")
    @mock.patch("os.readlink", side_effect=OSError)
    def test_cwd_readlink_fails(self, mock_readlink, mock_read):
        mock_read.return_value = "file.txt"
        result = resolve_openat_path(123, -100, 0xDEAD)
        self.assertEqual(result, "/file.txt")

    @mock.patch("sandlock._procfs.read_cstring")
    def test_at_fdcwd_unsigned(self, mock_read):
        """AT_FDCWD as unsigned 32-bit (0xFFFFFF9C)."""
        mock_read.return_value = "/etc/hosts"
        result = resolve_openat_path(123, 0xFFFFFF9C, 0xDEAD)
        self.assertEqual(result, "/etc/hosts")


# ===== Export tests =====


class TestExports(unittest.TestCase):
    def test_notif_policy_importable(self):
        from sandlock import NotifPolicy, NotifAction, PathRule
        self.assertIsNotNone(NotifPolicy)
        self.assertIsNotNone(NotifAction)
        self.assertIsNotNone(PathRule)

    def test_notif_error_importable(self):
        from sandlock import NotifError
        self.assertIsNotNone(NotifError)

    def test_notif_policy_in_all(self):
        import sandlock
        for name in ("NotifPolicy", "NotifAction", "PathRule", "NotifError"):
            self.assertIn(name, sandlock.__all__)


if __name__ == "__main__":
    unittest.main()
