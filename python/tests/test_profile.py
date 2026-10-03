# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock._profile (sectioned schema, parsed by the core)."""

from __future__ import annotations

import textwrap

import pytest

from sandlock._profile import (
    list_profiles,
    load_profile,
    load_profile_path,
    merge_cli_overrides,
    policy_from_toml,
    profiles_dir,
)
from sandlock.exceptions import PolicyError
from sandlock.sandbox import BranchAction, Sandbox


def load(text: str) -> Sandbox:
    return policy_from_toml(textwrap.dedent(text))


class TestPolicyFromToml:
    def test_empty_profile(self):
        assert load("") == Sandbox()

    def test_filesystem_section(self):
        p = load("""
            [filesystem]
            read = ["/usr", "/lib"]
            write = ["/tmp"]
            deny = ["/proc/sys"]
        """)
        assert p.fs_readable == ["/usr", "/lib"]
        assert p.fs_writable == ["/tmp"]
        assert p.fs_denied == ["/proc/sys"]

    def test_program_section(self):
        p = load("""
            [program]
            env = { FOO = "bar", BAZ = "qux" }
            uid = 0
            gid = 0
            clean_env = true
            no_coredump = true
        """)
        assert p.env == {"FOO": "bar", "BAZ": "qux"}
        assert (p.uid, p.gid) == (0, 0)
        assert p.clean_env is True
        assert p.no_coredump is True

    def test_uid_without_gid_raises(self):
        with pytest.raises(PolicyError, match="uid and program.gid must both be set"):
            load("[program]\nuid = 1000\n")

    def test_program_exec_and_args_are_not_returned(self):
        p = load("""
            [program]
            exec = "/bin/true"
            args = ["--flag"]
            clean_env = true
        """)
        assert p.clean_env is True

    def test_limits_section(self):
        p = load("""
            [limits]
            memory = "512M"
            processes = 10
            open_files = 256
            cpu = 80
            disk = "256M"
            cpu_cores = [0, 1]
        """)
        assert p.max_memory == "512M"
        assert p.max_processes == 10
        assert p.max_open_files == 256
        assert p.max_cpu == 80
        assert p.max_disk == "256M"
        assert list(p.cpu_cores) == [0, 1]

    def test_network_section(self):
        p = load("""
            [network]
            allow_bind = [8080, "9000-9002"]
            deny_bind = [22]
            allow = ["api.example.com:443", ":8080"]
            deny = ["10.0.0.0/8"]
            port_remap = true
        """)
        assert list(p.net_allow_bind) == [8080, "9000-9002"]
        assert list(p.net_deny_bind) == [22]
        assert list(p.net_allow) == ["api.example.com:443", ":8080"]
        assert list(p.net_deny) == ["10.0.0.0/8"]
        assert p.port_remap is True

    def test_bind_wildcard_with_ports_raises(self):
        # The old Python parser let this through until run time.
        with pytest.raises(PolicyError, match="wildcard"):
            load('[network]\nallow_bind = [8080, "*"]\n')

    def test_http_section(self):
        p = load("""
            [http]
            ports = [80, 443]
            allow = ["GET api.internal/v1/*"]
            deny = ["* */admin/*"]
        """)
        assert list(p.http_ports) == [80, 443]
        assert list(p.http_allow) == ["GET api.internal/v1/*"]
        assert list(p.http_deny) == ["* */admin/*"]

    def test_syscalls_section(self):
        p = load("""
            [syscalls]
            extra_allow = ["sysv_ipc"]
            extra_deny = ["ptrace"]
        """)
        assert list(p.extra_allow_syscalls) == ["sysv_ipc"]
        assert list(p.extra_deny_syscalls) == ["ptrace"]

    def test_config_section(self):
        p = load("""
            [config]
            fs_storage = "/var/sandlock/store"
            workdir = "/var/sandlock/work"
        """)
        assert p.fs_storage == "/var/sandlock/store"
        assert p.workdir == "/var/sandlock/work"

    def test_determinism_section(self):
        p = load("""
            [determinism]
            random_seed = 42
            deterministic_dirs = true
            no_randomize_memory = true
        """)
        assert p.random_seed == 42
        assert p.deterministic_dirs is True
        assert p.no_randomize_memory is True

    def test_filesystem_branch_actions(self):
        p = load("""
            [filesystem]
            on_exit = "abort"
            on_error = "keep"
        """)
        assert p.on_exit == BranchAction.ABORT
        assert p.on_error == BranchAction.KEEP

    def test_invalid_branch_action_raises(self):
        with pytest.raises(PolicyError, match=r"\[filesystem\]\.on_exit"):
            load('[filesystem]\non_exit = "invalid"\n')

    def test_invalid_memory_size_raises(self):
        with pytest.raises(PolicyError):
            load('[limits]\nmemory = "lots"\n')

    def test_unknown_section_raises(self):
        with pytest.raises(PolicyError, match="unknown field `bogus`"):
            load("[bogus]\n")

    def test_unknown_field_in_section_raises(self):
        with pytest.raises(PolicyError, match="unknown field `isolation`"):
            load('[filesystem]\nisolation = "none"\n')

    def test_type_mismatch_raises(self):
        with pytest.raises(PolicyError, match="clean_env"):
            load('[program]\nclean_env = "yes"\n')

    def test_old_flat_format_rejected(self):
        with pytest.raises(PolicyError, match="unknown field `fs_readable`"):
            load('fs_readable = ["/usr"]\n')

    def test_error_names_the_source(self):
        with pytest.raises(PolicyError, match="^my.toml: "):
            policy_from_toml("[bogus]\n", source="my.toml")


class TestMount:
    def test_mount_strings_to_dict(self):
        p = load('[filesystem]\nmount = ["/data:/srv/redis-data", "/cache:/srv/cache"]\n')
        assert p.fs_mount == {"/data": "/srv/redis-data", "/cache": "/srv/cache"}
        assert p.fs_mount_ro == {}

    def test_ro_suffix_selects_read_only(self):
        p = load('[filesystem]\nmount = ["/work:/host:ro"]\n')
        assert p.fs_mount == {}
        assert p.fs_mount_ro == {"/work": "/host"}

    def test_rw_suffix_is_the_default(self):
        p = load('[filesystem]\nmount = ["/work:/host:rw"]\n')
        assert p.fs_mount == {"/work": "/host"}

    def test_suffix_does_not_leak_into_host(self):
        p = load('[filesystem]\nmount = ["/v:/a:b:ro", "/v2:/c:d:rw", "/v3:/host:root"]\n')
        assert p.fs_mount_ro == {"/v": "/a:b"}
        assert p.fs_mount == {"/v2": "/c:d", "/v3": "/host:root"}

    @pytest.mark.parametrize("spec", ["nocolon", "/work:ro", ":/host"])
    def test_malformed_spec_raises(self, spec):
        with pytest.raises(PolicyError, match="invalid mount spec"):
            load(f'[filesystem]\nmount = ["{spec}"]\n')

    def test_same_virtual_path_twice_raises(self):
        with pytest.raises(PolicyError, match="mounted more than once"):
            load('[filesystem]\nmount = ["/work:/a", "/work:/b:ro"]\n')


class TestExpansion:
    # Expansion itself is tested in the core against the shared fixture;
    # these only check that the SDK receives the expanded values.
    def test_path_fields_expand(self, monkeypatch):
        monkeypatch.setenv("HOME", "/home/alice")
        p = load("""
            [filesystem]
            read = ["${HOME}/src"]
            mount = ["/work:${HOME}/host:ro"]
            [program]
            cwd = "${HOME}/src"
        """)
        assert p.fs_readable == ["/home/alice/src"]
        assert p.cwd == "/home/alice/src"
        assert p.fs_mount_ro == {"/work": "/home/alice/host"}

    def test_error_names_the_field(self, monkeypatch):
        monkeypatch.setenv("HOME", "/home/alice")
        with pytest.raises(PolicyError, match=r"\[filesystem\]\.read"):
            load('[filesystem]\nread = ["${NOPE}"]\n')

    def test_home_under_chroot_is_an_error(self, monkeypatch):
        monkeypatch.setenv("HOME", "/env/home")
        with pytest.raises(PolicyError, match="chroot"):
            load('[filesystem]\nchroot = "/jail"\nread = ["${HOME}/src"]\n')


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
        with pytest.raises(PolicyError, match="TOML parse error"):
            load_profile_path(profile)

    def test_error_names_the_file(self, tmp_path):
        profile = tmp_path / "bad.toml"
        profile.write_text("[typo]\n")
        with pytest.raises(PolicyError, match=str(profile)):
            load_profile_path(profile)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(PolicyError):
            load_profile_path(tmp_path / "absent.toml")


class TestProfilesDir:
    @pytest.fixture
    def config_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        directory = tmp_path / ".config" / "sandlock" / "profiles"
        directory.mkdir(parents=True)
        return directory

    def test_lives_under_home(self, config_home):
        # The CLI resolves the directory this way, so both must agree.
        assert profiles_dir() == config_home

    def test_xdg_config_home_is_not_consulted(self, config_home, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "elsewhere"))
        assert profiles_dir() == config_home

    def test_list_profiles(self, config_home):
        (config_home / "build.toml").write_text("[program]\nclean_env = true\n")
        (config_home / "dev.toml").write_text("[program]\nclean_env = true\n")
        (config_home / "not-toml.txt").write_text("ignored")
        assert list_profiles() == ["build", "dev"]

    def test_list_profiles_empty(self, config_home):
        assert list_profiles() == []

    def test_list_profiles_no_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        assert list_profiles() == []

    def test_load_profile_by_name(self, config_home):
        (config_home / "dev.toml").write_text('[filesystem]\nmount = ["/w:/h:ro"]\n')
        assert load_profile("dev").fs_mount_ro == {"/w": "/h"}

    def test_load_missing_profile_raises(self, config_home):
        with pytest.raises(PolicyError, match="profile not found"):
            load_profile("absent")


class TestMergeCliOverrides:
    def test_scalar_override(self):
        base = Sandbox(max_memory="256M", uid=0)
        result = merge_cli_overrides(base, {"max_memory": "1G"})
        assert result.max_memory == "1G"
        assert result.uid == 0

    def test_list_append(self):
        base = Sandbox(fs_readable=["/usr", "/lib"])
        result = merge_cli_overrides(base, {"fs_readable": ["/etc"]})
        assert result.fs_readable == ["/usr", "/lib", "/etc"]

    def test_bool_override(self):
        base = Sandbox(clean_env=False)
        result = merge_cli_overrides(base, {"clean_env": True})
        assert result.clean_env is True


def test_explicit_read_write_profile_normalizes_both_grants():
    p = load('[filesystem]\nread_write = ["/tmp"]')
    assert p.fs_readable == ["/tmp"]
    assert p.fs_writable == ["/tmp"]


def test_explicit_read_write_sdk_runs(tmp_path):
    sb = Sandbox(fs_readable=["/usr", "/lib", "/bin"], fs_read_write=[str(tmp_path)])
    result = sb.run(["sh", "-c", 'printf rw > "$1/out"; cat "$1/out"', "sh", str(tmp_path)])
    assert result.exit_code == 0
    assert result.stdout == b"rw"
