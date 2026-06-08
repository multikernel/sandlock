# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock._profile (sectioned schema)."""

from __future__ import annotations

import textwrap

import pytest

from sandlock._profile import (
    list_profiles,
    load_profile_path,
    merge_cli_overrides,
    policy_from_dict,
    profiles_dir,
)
from sandlock.exceptions import PolicyError
from sandlock.sandbox import BranchAction, Sandbox


class TestPolicyFromDict:
    def test_empty_dict(self):
        p = policy_from_dict({})
        assert p == Sandbox()

    def test_filesystem_section(self):
        p = policy_from_dict({
            "filesystem": {
                "read": ["/usr", "/lib"],
                "write": ["/tmp"],
                "deny": ["/proc/sys"],
            },
        })
        assert p.fs_readable == ["/usr", "/lib"]
        assert p.fs_writable == ["/tmp"]
        assert p.fs_denied == ["/proc/sys"]

    def test_program_section(self):
        p = policy_from_dict({
            "program": {
                "env": {"FOO": "bar", "BAZ": "qux"},
                "uid": 0,
                "clean_env": True,
                "no_coredump": True,
            },
        })
        assert p.env == {"FOO": "bar", "BAZ": "qux"}
        assert p.uid == 0
        assert p.clean_env is True
        assert p.no_coredump is True

    def test_program_exec_and_args_are_silently_ignored(self):
        # exec/args are runtime program identity, not Sandbox config.
        # Loading a profile with them should succeed but not place them
        # anywhere on the resulting Sandbox.
        p = policy_from_dict({
            "program": {
                "exec": "/bin/true",
                "args": ["--flag"],
                "uid": 1000,
            },
        })
        assert p.uid == 1000
        # No side-effect on Sandbox itself; we just need the load to succeed.
        assert isinstance(p, Sandbox)

    def test_limits_section(self):
        p = policy_from_dict({
            "limits": {
                "memory": "512M",
                "processes": 10,
                "open_files": 256,
                "cpu": 80,
                "disk": "256M",
                "cpu_cores": [0, 1],
            },
        })
        assert p.max_memory == "512M"
        assert p.max_processes == 10
        assert p.max_open_files == 256
        assert p.max_cpu == 80
        assert p.max_disk == "256M"
        assert list(p.cpu_cores) == [0, 1]

    def test_network_section(self):
        p = policy_from_dict({
            "network": {
                "allow_bind": [8080],
                "allow": ["api.example.com:443", ":8080"],
                "port_remap": True,
            },
        })
        assert p.net_allow_bind == ["8080"]  # ints coerced to strings
        assert list(p.net_allow) == ["api.example.com:443", ":8080"]
        assert p.port_remap is True

    def test_network_deny_section(self):
        p = policy_from_dict({
            "network": {"deny": ["10.0.0.0/8", "169.254.169.254:80"]},
        })
        assert list(p.net_deny) == ["10.0.0.0/8", "169.254.169.254:80"]

    def test_network_deny_bind_section(self):
        p = policy_from_dict({
            "network": {"deny_bind": [8080, "9000-9002"]},
        })
        assert p.deny_bind_ports() == [8080, 9000, 9001, 9002]

    def test_http_section(self):
        p = policy_from_dict({
            "http": {
                "ports": [80, 443],
                "allow": ["GET api.internal/v1/*"],
                "deny": ["* */admin/*"],
            },
        })
        assert list(p.http_ports) == [80, 443]
        assert list(p.http_allow) == ["GET api.internal/v1/*"]
        assert list(p.http_deny) == ["* */admin/*"]

    def test_syscalls_section(self):
        p = policy_from_dict({
            "syscalls": {
                "extra_allow": ["sysv_ipc"],
                "extra_deny": ["ptrace"],
            },
        })
        assert list(p.extra_allow_syscalls) == ["sysv_ipc"]
        assert list(p.extra_deny_syscalls) == ["ptrace"]

    def test_config_section(self):
        p = policy_from_dict({
            "config": {
                "http_ca": "/etc/sandlock/ca.pem",
                "http_key": "/etc/sandlock/ca.key",
                "fs_storage": "/var/sandlock/store",
                "workdir": "/var/sandlock/work",
            },
        })
        assert p.http_ca == "/etc/sandlock/ca.pem"
        assert p.http_key == "/etc/sandlock/ca.key"
        assert p.fs_storage == "/var/sandlock/store"
        assert p.workdir == "/var/sandlock/work"

    def test_determinism_section(self):
        p = policy_from_dict({
            "determinism": {
                "random_seed": 42,
                "deterministic_dirs": True,
                "no_randomize_memory": True,
            },
        })
        assert p.random_seed == 42
        assert p.deterministic_dirs is True
        assert p.no_randomize_memory is True

    def test_filesystem_isolation_key_rejected(self):
        with pytest.raises(PolicyError, match=r"unknown field\(s\) in \[filesystem\]"):
            policy_from_dict({"filesystem": {"isolation": "none"}})

    def test_filesystem_branch_actions(self):
        p = policy_from_dict({
            "filesystem": {"on_exit": "abort", "on_error": "keep"},
        })
        assert p.on_exit == BranchAction.ABORT
        assert p.on_error == BranchAction.KEEP

    def test_filesystem_mount_strings_to_dict(self):
        p = policy_from_dict({
            "filesystem": {"mount": ["/data:/srv/redis-data", "/cache:/srv/cache"]},
        })
        assert p.fs_mount == {"/data": "/srv/redis-data", "/cache": "/srv/cache"}

    def test_unknown_section_raises(self):
        with pytest.raises(PolicyError, match="unknown section"):
            policy_from_dict({"bogus": {}})

    def test_unknown_field_in_section_raises(self):
        with pytest.raises(PolicyError, match=r"unknown field\(s\) in \[filesystem\]"):
            policy_from_dict({"filesystem": {"bogus": True}})

    def test_section_must_be_table(self):
        with pytest.raises(PolicyError, match=r"\[filesystem\] must be a TOML table"):
            policy_from_dict({"filesystem": "not-a-table"})

    def test_type_mismatch_raises(self):
        with pytest.raises(PolicyError, match=r"\[program\]\.clean_env expected bool"):
            policy_from_dict({"program": {"clean_env": "yes"}})

    def test_invalid_branch_action_raises(self):
        with pytest.raises(PolicyError, match=r"\[filesystem\]\.on_exit must be"):
            policy_from_dict({"filesystem": {"on_exit": "invalid"}})

    def test_mount_missing_colon_raises(self):
        with pytest.raises(PolicyError, match=r"must be 'VIRTUAL:HOST'"):
            policy_from_dict({"filesystem": {"mount": ["nocolon"]}})

    def test_mount_empty_half_raises(self):
        with pytest.raises(PolicyError, match=r"both VIRTUAL and HOST"):
            policy_from_dict({"filesystem": {"mount": [":/host"]}})


class TestLoadProfilePath:
    def test_load_valid_toml(self, tmp_path):
        profile = tmp_path / "test.toml"
        profile.write_text(textwrap.dedent("""\
            [filesystem]
            read = ["/usr", "/lib"]
            write = ["/tmp/work"]

            [program]
            clean_env = true
            env = { CC = "gcc" }

            [limits]
            memory = "256M"
        """))
        p = load_profile_path(profile)
        assert p.fs_readable == ["/usr", "/lib"]
        assert p.fs_writable == ["/tmp/work"]
        assert p.clean_env is True
        assert p.env == {"CC": "gcc"}
        assert p.max_memory == "256M"

    def test_invalid_toml_raises(self, tmp_path):
        profile = tmp_path / "bad.toml"
        profile.write_text("not valid [[[toml")
        with pytest.raises(PolicyError, match="invalid TOML"):
            load_profile_path(profile)

    def test_unknown_section_in_file_raises(self, tmp_path):
        profile = tmp_path / "bad.toml"
        profile.write_text("[typo]\n")
        with pytest.raises(PolicyError, match="unknown section"):
            load_profile_path(profile)

    def test_old_flat_format_rejected(self, tmp_path):
        # Pre-Phase-3 profiles used flat top-level keys. They are now
        # rejected (sectioned schema only). Pre-1.0 hard break.
        profile = tmp_path / "old.toml"
        profile.write_text('fs_readable = ["/usr"]\n')
        with pytest.raises(PolicyError, match="unknown section"):
            load_profile_path(profile)


class TestListProfiles:
    def test_list_profiles(self, tmp_path, monkeypatch):
        import sandlock._profile as mod
        monkeypatch.setattr(mod, "_PROFILES_DIR", tmp_path)

        (tmp_path / "build.toml").write_text("[program]\nuid = 0\n")
        (tmp_path / "dev.toml").write_text("[program]\nclean_env = true\n")
        (tmp_path / "not-toml.txt").write_text("ignored")

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
        base = Sandbox(max_memory="256M", uid=0)
        result = merge_cli_overrides(base, {"max_memory": "1G"})
        assert result.max_memory == "1G"
        assert result.uid == 0  # unchanged

    def test_list_append(self):
        base = Sandbox(fs_readable=["/usr", "/lib"])
        result = merge_cli_overrides(base, {"fs_readable": ["/etc"]})
        assert result.fs_readable == ["/usr", "/lib", "/etc"]

    def test_bool_override(self):
        base = Sandbox(clean_env=False)
        result = merge_cli_overrides(base, {"clean_env": True})
        assert result.clean_env is True


def test_profiles_dir_is_a_path():
    assert profiles_dir().is_absolute() or str(profiles_dir()).startswith("~")
