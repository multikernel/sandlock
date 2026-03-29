# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock._profile."""

import textwrap

import pytest

from sandlock._profile import (
    load_profile_path,
    policy_from_dict,
    list_profiles,
    profiles_dir,
)
from sandlock.exceptions import PolicyError
from sandlock.policy import Policy, FsIsolation, BranchAction


class TestPolicyFromDict:
    def test_empty_dict(self):
        p = policy_from_dict({})
        assert p == Policy()

    def test_simple_fields(self):
        p = policy_from_dict({
            "fs_writable": ["/tmp"],
            "fs_readable": ["/usr", "/lib"],
            "clean_env": True,
            "max_memory": "512M",
            "max_processes": 10,
        })
        assert p.fs_writable == ["/tmp"]
        assert p.fs_readable == ["/usr", "/lib"]
        assert p.clean_env is True
        assert p.max_memory == "512M"
        assert p.max_processes == 10

    def test_env_dict(self):
        p = policy_from_dict({"env": {"FOO": "bar", "BAZ": "qux"}})
        assert p.env == {"FOO": "bar", "BAZ": "qux"}

    def test_boolean_fields(self):
        p = policy_from_dict({
            "isolate_ipc": True,
            "isolate_signals": True,
            "strict": False,
            "privileged": True,
            "close_fds": False,
        })
        assert p.isolate_ipc is True
        assert p.isolate_signals is True
        assert p.strict is False
        assert p.privileged is True
        assert p.close_fds is False

    def test_net_ports(self):
        p = policy_from_dict({
            "net_bind": ["8080"],
            "net_connect": [80, 443],
        })
        assert p.net_bind == ["8080"]
        # Integers in port lists get coerced to strings
        assert p.net_connect == ["80", "443"]

    def test_fs_isolation_enum(self):
        p = policy_from_dict({"fs_isolation": "branchfs"})
        assert p.fs_isolation == FsIsolation.BRANCHFS

    def test_branch_action_enums(self):
        p = policy_from_dict({"on_exit": "abort", "on_error": "keep"})
        assert p.on_exit == BranchAction.ABORT
        assert p.on_error == BranchAction.KEEP

    def test_unknown_field_raises(self):
        with pytest.raises(PolicyError, match="unknown fields.*bogus"):
            policy_from_dict({"bogus": True})

    def test_type_mismatch_raises(self):
        with pytest.raises(PolicyError, match="expected bool.*got str"):
            policy_from_dict({"clean_env": "yes"})

    def test_invalid_fs_isolation_raises(self):
        with pytest.raises(PolicyError, match="fs_isolation"):
            policy_from_dict({"fs_isolation": "invalid"})

    def test_invalid_branch_action_raises(self):
        with pytest.raises(PolicyError, match="on_exit"):
            policy_from_dict({"on_exit": "invalid"})


class TestLoadProfilePath:
    def test_load_valid_toml(self, tmp_path):
        profile = tmp_path / "test.toml"
        profile.write_text(textwrap.dedent("""\
            fs_writable = ["/tmp/work"]
            fs_readable = ["/usr", "/lib"]
            clean_env = true
            max_memory = "256M"

            [env]
            CC = "gcc"
        """))
        p = load_profile_path(profile)
        assert p.fs_writable == ["/tmp/work"]
        assert p.fs_readable == ["/usr", "/lib"]
        assert p.clean_env is True
        assert p.max_memory == "256M"
        assert p.env == {"CC": "gcc"}

    def test_invalid_toml_raises(self, tmp_path):
        profile = tmp_path / "bad.toml"
        profile.write_text("not valid [[[toml")
        with pytest.raises(PolicyError, match="invalid TOML"):
            load_profile_path(profile)

    def test_unknown_field_in_file_raises(self, tmp_path):
        profile = tmp_path / "bad.toml"
        profile.write_text('typo_field = true\n')
        with pytest.raises(PolicyError, match="unknown fields"):
            load_profile_path(profile)


class TestListProfiles:
    def test_list_profiles(self, tmp_path, monkeypatch):
        import sandlock._profile as mod
        monkeypatch.setattr(mod, "_PROFILES_DIR", tmp_path)

        (tmp_path / "build.toml").write_text('strict = true\n')
        (tmp_path / "dev.toml").write_text('strict = false\n')
        (tmp_path / "not-toml.txt").write_text('ignored')

        assert list_profiles() == ["build", "dev"]

    def test_list_profiles_empty(self, tmp_path, monkeypatch):
        import sandlock._profile as mod
        monkeypatch.setattr(mod, "_PROFILES_DIR", tmp_path)
        assert list_profiles() == []

    def test_list_profiles_no_dir(self, tmp_path, monkeypatch):
        import sandlock._profile as mod
        monkeypatch.setattr(mod, "_PROFILES_DIR", tmp_path / "nonexistent")
        assert list_profiles() == []


class TestMergeCliOverrides:
    def test_scalar_override(self):
        from sandlock._profile import merge_cli_overrides
        base = Policy(max_memory="256M", strict=True)
        result = merge_cli_overrides(base, {"max_memory": "1G"})
        assert result.max_memory == "1G"
        assert result.strict is True  # unchanged

    def test_list_append(self):
        from sandlock._profile import merge_cli_overrides
        base = Policy(fs_readable=["/usr", "/lib"])
        result = merge_cli_overrides(base, {"fs_readable": ["/etc"]})
        assert result.fs_readable == ["/usr", "/lib", "/etc"]

    def test_bool_override(self):
        from sandlock._profile import merge_cli_overrides
        base = Policy(clean_env=False)
        result = merge_cli_overrides(base, {"clean_env": True})
        assert result.clean_env is True
