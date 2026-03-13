# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock._landlock."""

import pytest

from sandlock._landlock import (
    LANDLOCK_ACCESS_FS_EXECUTE,
    LANDLOCK_ACCESS_FS_READ_DIR,
    LANDLOCK_ACCESS_FS_READ_FILE,
    LANDLOCK_ACCESS_FS_WRITE_FILE,
    LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
    LANDLOCK_SCOPE_SIGNAL,
    _FULL_ACCESS,
    _READ_ACCESS,
    _WRITE_ACCESS,
    landlock_abi_version,
)


class TestAccessFlags:
    def test_read_access_includes_execute(self):
        assert _READ_ACCESS & LANDLOCK_ACCESS_FS_EXECUTE

    def test_read_access_includes_read_file(self):
        assert _READ_ACCESS & LANDLOCK_ACCESS_FS_READ_FILE

    def test_read_access_includes_read_dir(self):
        assert _READ_ACCESS & LANDLOCK_ACCESS_FS_READ_DIR

    def test_write_access_includes_write_file(self):
        assert _WRITE_ACCESS & LANDLOCK_ACCESS_FS_WRITE_FILE

    def test_full_access_is_union(self):
        assert _FULL_ACCESS == _READ_ACCESS | _WRITE_ACCESS

    def test_read_and_write_disjoint(self):
        assert _READ_ACCESS & _WRITE_ACCESS == 0


class TestScopeFlags:
    def test_scope_flags_are_distinct(self):
        assert LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET != LANDLOCK_SCOPE_SIGNAL

    def test_scope_flags_are_single_bits(self):
        assert LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET & (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET - 1) == 0
        assert LANDLOCK_SCOPE_SIGNAL & (LANDLOCK_SCOPE_SIGNAL - 1) == 0

    def test_scope_flags_no_overlap(self):
        assert LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET & LANDLOCK_SCOPE_SIGNAL == 0


class TestLandlockAbiVersion:
    def test_returns_int(self):
        ver = landlock_abi_version()
        assert isinstance(ver, int)
        assert ver >= 0

    def test_version_reasonable(self):
        ver = landlock_abi_version()
        # If Landlock is available, version should be 1-10 range
        if ver > 0:
            assert ver <= 10
