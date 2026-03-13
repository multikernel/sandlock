# SPDX-License-Identifier: Apache-2.0
"""Tests for BranchFS integration."""

from __future__ import annotations

import errno
import unittest
from pathlib import Path
from unittest import mock

from sandlock._branchfs import (
    SandboxBranch,
    CTL_FILE,
    FS_IOC_BRANCH_CREATE,
    FS_IOC_BRANCH_COMMIT,
    FS_IOC_BRANCH_ABORT,
)
from sandlock.exceptions import BranchError, BranchConflictError
from sandlock.policy import Policy, FsIsolation, BranchAction


class TestIoctlConstants(unittest.TestCase):
    def test_create_ioctl(self):
        self.assertEqual(FS_IOC_BRANCH_CREATE, 0x8080_6200)

    def test_commit_ioctl(self):
        self.assertEqual(FS_IOC_BRANCH_COMMIT, 0x0000_6201)

    def test_abort_ioctl(self):
        self.assertEqual(FS_IOC_BRANCH_ABORT, 0x0000_6202)

    def test_ctl_file(self):
        self.assertEqual(CTL_FILE, ".branchfs_ctl")


class TestSandboxBranch(unittest.TestCase):
    def test_path_before_create_raises(self):
        b = SandboxBranch(Path("/mnt/ws"))
        with self.assertRaises(BranchError):
            _ = b.path

    def test_mount_root(self):
        b = SandboxBranch(Path("/mnt/ws"))
        self.assertEqual(b.mount_root, Path("/mnt/ws"))

    def test_branch_id_none_before_create(self):
        b = SandboxBranch(Path("/mnt/ws"))
        self.assertIsNone(b.branch_id)

    def test_not_finished_initially(self):
        b = SandboxBranch(Path("/mnt/ws"))
        self.assertFalse(b.finished)

    @mock.patch("sandlock._branchfs._ctl_create", return_value="abc123")
    def test_create(self, mock_create):
        b = SandboxBranch(Path("/mnt/ws"))
        path = b.create()
        self.assertEqual(path, Path("/mnt/ws/@abc123"))
        self.assertEqual(b.branch_id, "abc123")
        self.assertEqual(b.path, Path("/mnt/ws/@abc123"))
        mock_create.assert_called_once_with(Path("/mnt/ws/.branchfs_ctl"))

    @mock.patch("sandlock._branchfs._ctl_create", return_value="child456")
    def test_create_nested(self, mock_create):
        """Nested branch: parent_path is the parent branch's @-path."""
        b = SandboxBranch(Path("/mnt/ws"), parent_path=Path("/mnt/ws/@parent123"))
        path = b.create()
        self.assertEqual(path, Path("/mnt/ws/@child456"))
        mock_create.assert_called_once_with(
            Path("/mnt/ws/@parent123/.branchfs_ctl")
        )

    @mock.patch("sandlock._branchfs._ctl_ioctl")
    @mock.patch("sandlock._branchfs._ctl_create", return_value="abc")
    def test_commit(self, mock_create, mock_ioctl):
        b = SandboxBranch(Path("/mnt/ws"))
        b.create()
        b.commit()
        mock_ioctl.assert_called_once_with(
            Path("/mnt/ws/@abc/.branchfs_ctl"),
            FS_IOC_BRANCH_COMMIT,
            "commit",
        )
        self.assertTrue(b.finished)

    @mock.patch("sandlock._branchfs._ctl_ioctl")
    @mock.patch("sandlock._branchfs._ctl_create", return_value="abc")
    def test_abort(self, mock_create, mock_ioctl):
        b = SandboxBranch(Path("/mnt/ws"))
        b.create()
        b.abort()
        mock_ioctl.assert_called_once_with(
            Path("/mnt/ws/@abc/.branchfs_ctl"),
            FS_IOC_BRANCH_ABORT,
            "abort",
        )
        self.assertTrue(b.finished)

    @mock.patch("sandlock._branchfs._ctl_ioctl")
    @mock.patch("sandlock._branchfs._ctl_create", return_value="abc")
    def test_double_commit_is_noop(self, mock_create, mock_ioctl):
        b = SandboxBranch(Path("/mnt/ws"))
        b.create()
        b.commit()
        b.commit()  # Second call is no-op
        self.assertEqual(mock_ioctl.call_count, 1)

    @mock.patch("sandlock._branchfs._ctl_ioctl")
    @mock.patch("sandlock._branchfs._ctl_create", return_value="abc")
    def test_double_abort_is_noop(self, mock_create, mock_ioctl):
        b = SandboxBranch(Path("/mnt/ws"))
        b.create()
        b.abort()
        b.abort()  # Second call is no-op
        self.assertEqual(mock_ioctl.call_count, 1)

    def test_commit_before_create_raises(self):
        b = SandboxBranch(Path("/mnt/ws"))
        with self.assertRaises(BranchError):
            b.commit()

    def test_abort_before_create_raises(self):
        b = SandboxBranch(Path("/mnt/ws"))
        with self.assertRaises(BranchError):
            b.abort()


class TestCtlIoctlConflict(unittest.TestCase):
    @mock.patch("sandlock._branchfs.os.open", return_value=3)
    @mock.patch("sandlock._branchfs.os.close")
    @mock.patch(
        "sandlock._branchfs.fcntl.ioctl",
        side_effect=OSError(errno.ESTALE, "Stale file handle"),
    )
    def test_estale_raises_conflict(self, mock_ioctl, mock_close, mock_open):
        from sandlock._branchfs import _ctl_ioctl

        with self.assertRaises(BranchConflictError):
            _ctl_ioctl(Path("/mnt/ws/@abc/.branchfs_ctl"), FS_IOC_BRANCH_COMMIT, "commit")

    @mock.patch("sandlock._branchfs.os.open", return_value=3)
    @mock.patch("sandlock._branchfs.os.close")
    @mock.patch(
        "sandlock._branchfs.fcntl.ioctl",
        side_effect=OSError(errno.EIO, "I/O error"),
    )
    def test_other_oserror_raises_branch_error(self, mock_ioctl, mock_close, mock_open):
        from sandlock._branchfs import _ctl_ioctl

        with self.assertRaises(BranchError):
            _ctl_ioctl(Path("/mnt/ws/@abc/.branchfs_ctl"), FS_IOC_BRANCH_COMMIT, "commit")


class TestPolicyFields(unittest.TestCase):
    def test_default_isolation_none(self):
        p = Policy()
        self.assertEqual(p.fs_isolation, FsIsolation.NONE)
        self.assertIsNone(p.fs_mount)

    def test_branch_isolation(self):
        p = Policy(
            fs_isolation=FsIsolation.BRANCHFS,
            fs_mount="/mnt/workspace",
        )
        self.assertEqual(p.fs_isolation, FsIsolation.BRANCHFS)
        self.assertEqual(p.fs_mount, "/mnt/workspace")

    def test_default_branch_actions(self):
        p = Policy()
        self.assertEqual(p.on_exit, BranchAction.COMMIT)
        self.assertEqual(p.on_error, BranchAction.ABORT)

    def test_custom_branch_actions(self):
        p = Policy(
            on_exit=BranchAction.KEEP,
            on_error=BranchAction.KEEP,
        )
        self.assertEqual(p.on_exit, BranchAction.KEEP)
        self.assertEqual(p.on_error, BranchAction.KEEP)


class TestSandboxBranchIntegration(unittest.TestCase):
    """Test Sandbox._setup_branch, _effective_policy, _finish_branch."""

    def _make_sandbox(self, **policy_kwargs):
        from sandlock.sandbox import Sandbox
        return Sandbox(Policy(**policy_kwargs))

    def test_no_branch_when_isolation_none(self):
        sb = self._make_sandbox()
        self.assertIsNone(sb._setup_branch())
        self.assertIsNone(sb._branch)

    def test_branch_requires_fs_mount(self):
        from sandlock.sandbox import Sandbox
        from sandlock.exceptions import SandboxError
        sb = Sandbox(Policy(fs_isolation=FsIsolation.BRANCHFS))
        with self.assertRaises(SandboxError):
            sb._setup_branch()

    @mock.patch("sandlock._branchfs.ensure_mount")
    @mock.patch("sandlock._branchfs.SandboxBranch.create", return_value=Path("/mnt/ws/@uuid"))
    def test_setup_branch_creates(self, mock_create, mock_mount):
        sb = self._make_sandbox(
            fs_isolation=FsIsolation.BRANCHFS,
            fs_mount="/mnt/ws",
        )
        result = sb._setup_branch()
        self.assertIsNotNone(result)
        mock_create.assert_called_once()

    @mock.patch("sandlock._branchfs.ensure_mount")
    @mock.patch("sandlock._branchfs.SandboxBranch.create", return_value=Path("/mnt/ws/@uuid"))
    @mock.patch("sandlock._branchfs.SandboxBranch.path", new_callable=mock.PropertyMock, return_value=Path("/mnt/ws/@uuid"))
    def test_effective_policy_rewrites_paths(self, mock_path, mock_create, mock_mount):
        sb = self._make_sandbox(
            fs_isolation=FsIsolation.BRANCHFS,
            fs_mount="/mnt/ws",
            fs_writable=["/mnt/ws"],
            fs_readable=["/mnt/ws/data", "/usr"],
        )
        sb._setup_branch()
        eff = sb._effective_policy()
        self.assertEqual(list(eff.fs_writable), ["/mnt/ws/@uuid"])
        self.assertEqual(list(eff.fs_readable), ["/mnt/ws/@uuid/data", "/usr"])

    def test_effective_policy_no_branch_returns_original(self):
        sb = self._make_sandbox(fs_writable=["/tmp"])
        eff = sb._effective_policy()
        self.assertIs(eff, sb._policy)

    @mock.patch("sandlock._branchfs.ensure_mount")
    @mock.patch("sandlock._branchfs.SandboxBranch.commit")
    @mock.patch("sandlock._branchfs.SandboxBranch.create", return_value=Path("/mnt/ws/@uuid"))
    def test_finish_branch_commit_on_success(self, mock_create, mock_commit, mock_mount):
        sb = self._make_sandbox(
            fs_isolation=FsIsolation.BRANCHFS,
            fs_mount="/mnt/ws",
            on_exit=BranchAction.COMMIT,
        )
        sb._setup_branch()
        sb._finish_branch(error=False)
        mock_commit.assert_called_once()

    @mock.patch("sandlock._branchfs.ensure_mount")
    @mock.patch("sandlock._branchfs.SandboxBranch.abort")
    @mock.patch("sandlock._branchfs.SandboxBranch.create", return_value=Path("/mnt/ws/@uuid"))
    def test_finish_branch_abort_on_error(self, mock_create, mock_abort, mock_mount):
        sb = self._make_sandbox(
            fs_isolation=FsIsolation.BRANCHFS,
            fs_mount="/mnt/ws",
            on_error=BranchAction.ABORT,
        )
        sb._setup_branch()
        sb._finish_branch(error=True)
        mock_abort.assert_called_once()

    @mock.patch("sandlock._branchfs.ensure_mount")
    @mock.patch("sandlock._branchfs.SandboxBranch.commit")
    @mock.patch("sandlock._branchfs.SandboxBranch.abort")
    @mock.patch("sandlock._branchfs.SandboxBranch.create", return_value=Path("/mnt/ws/@uuid"))
    def test_finish_branch_keep_does_nothing(self, mock_create, mock_abort, mock_commit, mock_mount):
        sb = self._make_sandbox(
            fs_isolation=FsIsolation.BRANCHFS,
            fs_mount="/mnt/ws",
            on_exit=BranchAction.KEEP,
        )
        sb._setup_branch()
        sb._finish_branch(error=False)
        mock_commit.assert_not_called()
        mock_abort.assert_not_called()

    def test_finish_branch_noop_when_no_branch(self):
        sb = self._make_sandbox()
        sb._finish_branch(error=False)  # Should not raise

    @mock.patch("sandlock._branchfs.ensure_mount")
    @mock.patch("sandlock._branchfs._ctl_create", return_value="child")
    def test_nested_sandbox_inherits_parent_branch(self, mock_create, mock_mount):
        from sandlock.sandbox import Sandbox

        parent = Sandbox(Policy(
            fs_isolation=FsIsolation.BRANCHFS,
            fs_mount="/mnt/ws",
        ))
        parent._setup_branch()

        child_sb = parent.sandbox(Policy(
            fs_isolation=FsIsolation.BRANCHFS,
            fs_mount="/mnt/ws",
        ))
        self.assertEqual(
            child_sb._parent_branch_path,
            Path("/mnt/ws/@child"),
        )


class TestExports(unittest.TestCase):
    def test_enums_importable(self):
        from sandlock import FsIsolation, BranchAction
        self.assertEqual(FsIsolation.BRANCHFS.value, "branchfs")
        self.assertEqual(BranchAction.COMMIT.value, "commit")

    def test_exceptions_importable(self):
        from sandlock import BranchError, BranchConflictError
        self.assertTrue(issubclass(BranchConflictError, BranchError))

    def test_in_all(self):
        import sandlock
        for name in ("FsIsolation", "BranchAction", "BranchError", "BranchConflictError"):
            self.assertIn(name, sandlock.__all__)


if __name__ == "__main__":
    unittest.main()
