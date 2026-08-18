# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock._profile.

Profile text is parsed by the core parser and returned in canonical form;
this module only maps that form onto a Sandbox. The tests therefore fall
into two groups: field mapping, and parity with the core grammar (the SDK
must accept exactly what the CLI accepts, reject exactly what it rejects,
and say what the core says when it rejects).
"""

from __future__ import annotations

import textwrap

import pytest

from sandlock._profile import (
    _from_canonical,
    list_profiles,
    load_profile_path,
    merge_cli_overrides,
    policy_from_toml,
    profiles_dir,
)
from sandlock._sdk import profile_parse
from sandlock.exceptions import PolicyError
from sandlock.sandbox import BranchAction, Mount, Sandbox


class TestSectionMapping:
    def test_empty_profile_is_defaults_with_core_branch_actions(self):
        # A profile always carries both branch actions: core resolves the
        # default so that an absent key cannot mean one thing to the CLI and
        # another to a binding. Core's default is commit for both.
        p = policy_from_toml("")
        assert p == Sandbox(on_error=BranchAction.COMMIT)

    def test_filesystem_section(self):
        p = policy_from_toml(textwrap.dedent("""\
            [filesystem]
            read = ["/usr", "/lib"]
            write = ["/tmp"]
            deny = ["/proc/sys"]
            chroot = "/srv/root"
        """))
        assert p.fs_readable == ["/usr", "/lib"]
        assert p.fs_writable == ["/tmp"]
        assert p.fs_denied == ["/proc/sys"]
        assert p.chroot == "/srv/root"

    def test_program_section(self):
        p = policy_from_toml(textwrap.dedent("""\
            [program]
            env = { FOO = "bar", BAZ = "qux" }
            uid = 1000
            gid = 1000
            cwd = "/work"
            clean_env = true
            no_coredump = true
            no_huge_pages = true
        """))
        assert p.env == {"FOO": "bar", "BAZ": "qux"}
        assert p.uid == 1000
        assert p.gid == 1000
        assert p.cwd == "/work"
        assert p.clean_env is True
        assert p.no_coredump is True
        assert p.no_huge_pages is True

    def test_program_exec_and_args_are_dropped(self):
        # exec/args are runtime program identity, not Sandbox config. They
        # must not block the load, and they must not land anywhere.
        p = policy_from_toml(textwrap.dedent("""\
            [program]
            exec = "/bin/true"
            args = ["--flag"]
            uid = 1000
            gid = 1000
        """))
        assert p == Sandbox(uid=1000, gid=1000, on_error=BranchAction.COMMIT)

    def test_limits_section(self):
        p = policy_from_toml(textwrap.dedent("""\
            [limits]
            memory = "512M"
            disk = "256M"
            processes = 10
            open_files = 256
            cpu = 80
            cpu_cores = [0, 1]
            num_cpus = 2
            gpu_devices = [0]
        """))
        assert p.max_memory == 512 * 1024 ** 2
        assert p.max_disk == 256 * 1024 ** 2
        assert p.max_processes == 10
        assert p.max_open_files == 256
        assert p.max_cpu == 80
        assert list(p.cpu_cores) == [0, 1]
        assert p.num_cpus == 2
        assert list(p.gpu_devices) == [0]

    def test_absent_limits_keep_sandbox_defaults(self):
        # `processes` is null in the canonical form when unset, and the
        # Sandbox default for it is 64, not None: a null must be skipped
        # rather than assigned.
        p = policy_from_toml("[limits]\ncpu = 50\n")
        assert p.max_processes == 64
        assert p.max_memory is None
        assert p.gpu_devices is None

    def test_network_section(self):
        p = policy_from_toml(textwrap.dedent("""\
            [network]
            allow_bind = [8080, "9000-9001"]
            allow = ["tcp://api.example.com:443"]
            port_remap = true
        """))
        assert list(p.net_allow_bind) == [8080, 9000, 9001]
        assert list(p.net_allow) == ["tcp://api.example.com:443"]
        assert p.port_remap is True

    def test_network_deny_section(self):
        p = policy_from_toml(textwrap.dedent("""\
            [network]
            deny = ["tcp://10.0.0.0/8"]
            deny_bind = [8080, "9000-9001"]
        """))
        assert list(p.net_deny) == ["tcp://10.0.0.0/8"]
        assert list(p.net_deny_bind) == [8080, 9000, 9001]

    def test_http_section(self):
        p = policy_from_toml(textwrap.dedent("""\
            [http]
            ports = [80, 443]
            allow = ["GET api.internal/v1/*"]
        """))
        assert list(p.http_ports) == [80, 443]
        assert list(p.http_allow) == ["GET api.internal/v1/*"]

    def test_syscalls_section(self):
        p = policy_from_toml(textwrap.dedent("""\
            [syscalls]
            extra_allow = ["sysv_ipc"]
            extra_deny = ["ptrace"]
        """))
        assert list(p.extra_allow_syscalls) == ["sysv_ipc"]
        assert list(p.extra_deny_syscalls) == ["ptrace"]

    def test_config_section(self):
        p = policy_from_toml(textwrap.dedent("""\
            [config]
            http_ca = "/etc/sandlock/ca.pem"
            http_key = "/etc/sandlock/ca.key"
            http_ca_out = "/tmp/ca-out.pem"
            http_inject_ca = ["/etc/ssl/certs/ca-bundle.crt"]
            fs_storage = "/var/sandlock/store"
            workdir = "/var/sandlock/work"

            [http]
            allow = ["GET api.internal/v1/*"]
        """))
        assert p.http_ca == "/etc/sandlock/ca.pem"
        assert p.http_key == "/etc/sandlock/ca.key"
        assert p.http_ca_out == "/tmp/ca-out.pem"
        assert list(p.http_inject_ca) == ["/etc/ssl/certs/ca-bundle.crt"]
        assert p.fs_storage == "/var/sandlock/store"
        assert p.workdir == "/var/sandlock/work"

    def test_determinism_section(self):
        p = policy_from_toml(textwrap.dedent("""\
            [determinism]
            random_seed = 42
            deterministic_dirs = true
            no_randomize_memory = true
        """))
        assert p.random_seed == 42
        assert p.deterministic_dirs is True
        assert p.no_randomize_memory is True

    def test_branch_actions(self):
        p = policy_from_toml('[filesystem]\non_exit = "abort"\non_error = "keep"\n')
        assert p.on_exit == BranchAction.ABORT
        assert p.on_error == BranchAction.KEEP

    def test_loaded_profile_is_still_a_plain_dataclass(self):
        import dataclasses

        p = policy_from_toml('[limits]\nmemory = "512M"\n')
        assert dataclasses.is_dataclass(p)
        assert dataclasses.replace(p, max_cpu=50).max_cpu == 50
        assert dataclasses.asdict(p)["max_memory"] == 512 * 1024 ** 2


class TestMounts:
    def test_mount_maps_to_mount_entries(self):
        p = policy_from_toml(
            '[filesystem]\nmount = ["/data:/srv/data", "/cache:/srv/cache"]\n'
        )
        assert list(p.fs_mount) == [
            Mount("/data", "/srv/data"),
            Mount("/cache", "/srv/cache"),
        ]

    def test_read_only_suffix_is_applied_not_refused(self):
        # Before the core parser was adopted, the SDK could not express a
        # read-only mount and refused the ':ro' suffix outright.
        p = policy_from_toml('[filesystem]\nmount = ["/work:/host:ro"]\n')
        assert list(p.fs_mount) == [Mount("/work", "/host", ro=True)]

    def test_read_write_suffix_is_accepted(self):
        p = policy_from_toml('[filesystem]\nmount = ["/work:/host:rw"]\n')
        assert list(p.fs_mount) == [Mount("/work", "/host", ro=False)]

    def test_host_path_may_contain_colons(self):
        p = policy_from_toml(
            '[filesystem]\nmount = ["/v:/a:b", "/v2:/host:root"]\n'
        )
        assert list(p.fs_mount) == [
            Mount("/v", "/a:b"),
            Mount("/v2", "/host:root"),
        ]

    def test_same_virtual_path_twice_keeps_both_entries(self):
        # A mapping keyed by virtual path would collapse these two and lose a
        # host path; a sequence keeps both. The read-only flag does collapse,
        # because the core keys it by virtual path: ':ro' on either spec denies
        # writes through '/w' for both, and that is what the loaded policy says
        # rather than the flag each spec was written with.
        p = policy_from_toml('[filesystem]\nmount = ["/w:/h1", "/w:/h2:ro"]\n')
        assert list(p.fs_mount) == [
            Mount("/w", "/h1", ro=True),
            Mount("/w", "/h2", ro=True),
        ]

    @pytest.mark.parametrize(
        "spec,fragment",
        [
            ("nocolon", 'expected "VIRTUAL:HOST[:ro]"'),
            (":/host", "non-empty"),
            ("/virt:", "non-empty"),
        ],
    )
    def test_invalid_mount_specs_report_the_core_message(self, spec, fragment):
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml(f'[filesystem]\nmount = ["{spec}"]\n')
        assert fragment in str(excinfo.value)


class TestCoreParity:
    """The SDK must not have a second opinion about the profile grammar."""

    @pytest.mark.parametrize(
        "size,expected",
        [("512M", 512 * 1024 ** 2), ("1G", 1024 ** 3), ("512", 512), ("0", 0)],
    )
    def test_sizes_resolve_the_way_core_resolves_them(self, size, expected):
        p = policy_from_toml(f'[limits]\nmemory = "{size}"\n')
        assert p.max_memory == expected

    @pytest.mark.parametrize(
        "size,fragment",
        [
            # The SDK's own size parser used to accept both of these, so a
            # profile could load through the SDK and fail in the CLI.
            ("1.5G", "invalid byte size: 1.5G"),
            ("1T", "unknown byte size suffix: T"),
            ("17179869184G", "out of range"),
            ("512B", "unknown byte size suffix: B"),
        ],
    )
    def test_sizes_core_rejects_are_rejected_here(self, size, fragment):
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml(f'[limits]\nmemory = "{size}"\n')
        assert fragment in str(excinfo.value)

    def test_disk_size_uses_the_same_grammar(self):
        assert policy_from_toml('[limits]\ndisk = "1G"\n').max_disk == 1024 ** 3
        with pytest.raises(PolicyError):
            policy_from_toml('[limits]\ndisk = "1.5G"\n')

    def test_rfc3339_time_start_resolves_to_epoch_seconds(self):
        # The SDK used to call int() on the raw string here, so an RFC 3339
        # stamp (the only form the CLI accepts) raised ValueError.
        p = policy_from_toml('[determinism]\ntime_start = "2026-01-01T00:00:00Z"\n')
        assert p.time_start == 1767225600

    def test_time_start_honours_the_offset(self):
        p = policy_from_toml(
            '[determinism]\ntime_start = "2026-01-01T00:00:00+03:00"\n'
        )
        assert p.time_start == 1767225600 - 3 * 3600

    def test_time_start_keeps_sub_second_precision(self):
        p = policy_from_toml(
            '[determinism]\ntime_start = "2026-01-01T00:00:00.25Z"\n'
        )
        assert p.time_start == 1767225600.25

    def test_pre_epoch_time_start_stays_negative(self):
        p = policy_from_toml(
            '[determinism]\ntime_start = "1969-12-31T23:59:59.5Z"\n'
        )
        assert p.time_start == -0.5

    def test_naive_time_start_is_rejected(self):
        # A binding that assumed UTC here would disagree with the CLI about
        # what the profile means.
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml('[determinism]\ntime_start = "2026-01-01T00:00:00"\n')
        assert "offset" in str(excinfo.value)

    def test_bare_unix_seconds_in_time_start_are_rejected(self):
        with pytest.raises(PolicyError):
            policy_from_toml('[determinism]\ntime_start = "1767225600"\n')

    def test_scheme_less_net_rule_expands_to_both_protocols(self):
        # Core turns one profile entry into one rule per protocol; the SDK
        # forwards what core produced instead of the original string.
        p = policy_from_toml('[network]\nallow = ["example.com:443"]\n')
        assert list(p.net_allow) == [
            "tcp://example.com:443",
            "udp://example.com:443",
        ]

    def test_ipv6_net_rule_keeps_the_bracket_form(self):
        p = policy_from_toml('[network]\nallow = ["tcp://[fc00::/7]:443"]\n')
        assert list(p.net_allow) == ["tcp://[fc00::/7]:443"]

    def test_http_rule_is_normalized_by_core(self):
        p = policy_from_toml('[http]\nallow = ["get Example.COM/v1//a/../b/"]\n')
        assert list(p.http_allow) == ["GET Example.COM/v1/b"]

    def test_bind_port_ranges_are_expanded_sorted_and_deduplicated(self):
        p = policy_from_toml(
            '[network]\nallow_bind = [9001, "9000-9002", "8080,8080"]\n'
        )
        assert list(p.net_allow_bind) == [8080, 9000, 9001, 9002]

    def test_bind_port_wildcard_survives(self):
        p = policy_from_toml('[network]\nallow_bind = ["*"]\n')
        assert list(p.net_allow_bind) == ["*"]

    @pytest.mark.parametrize(
        "profile,fragment",
        [
            ('[network]\nallow_bind = ["90-80"]\n', "reversed port range"),
            ('[network]\ndeny_bind = ["*"]\n', "only supported for"),
            ('[network]\nallow = ["example.com:0"]\n', "port 0 is not valid"),
            ('[network]\ndeny = ["example.com"]\n', "hostnames are not allowed"),
            ('[filesystem]\non_exit = "COMMIT"\n', "invalid branch action"),
            ('[syscalls]\nextra_allow = ["read"]\n', "unknown syscall group name"),
        ],
    )
    def test_other_grammars_report_the_core_message(self, profile, fragment):
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml(profile)
        assert fragment in str(excinfo.value)

    @pytest.mark.parametrize(
        "profile,fragment",
        [
            # Cross-section checks live in the builder, not in the schema.
            # They still have to fire when a profile is loaded.
            ("[limits]\ncpu = 0\n", "max_cpu must be 1-100"),
            ("[limits]\nopen_files = 0\n", "greater than 0"),
            ("[program]\nuid = 1000\n", "must both be set"),
            (
                '[network]\nallow = ["1.2.3.4"]\ndeny = ["5.6.7.8"]\n',
                "mutually exclusive",
            ),
        ],
    )
    def test_cross_section_checks_run_at_load_time(self, profile, fragment):
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml(profile)
        assert fragment in str(excinfo.value)

    @pytest.mark.parametrize(
        "profile,message",
        [
            (
                '[limits]\nmemory = "1.5G"\n',
                "sandbox error: invalid sandbox: invalid byte size: 1.5G",
            ),
            (
                '[filesystem]\nmount = ["nocolon"]\n',
                "sandbox error: invalid sandbox: invalid mount spec "
                '"nocolon"; expected "VIRTUAL:HOST[:ro]"',
            ),
            (
                "[limits]\ncpu = 0\n",
                "sandbox error: max_cpu must be 1-100, got 0",
            ),
        ],
    )
    def test_the_message_is_the_core_message_and_nothing_else(
        self, profile, message
    ):
        # Whole-string equality on purpose: an SDK-side prefix, suffix or
        # reword is exactly what this pins down. The core message is what a
        # CLI user sees for the same profile.
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml(profile)
        assert str(excinfo.value) == message

    @pytest.mark.parametrize(
        "profile",
        [
            "[bogus]\nx = 1\n",
            "[program]\nbogus = 1\n",
            'fs_readable = ["/usr"]\n',
            "[limits]\ncpu = 300\n",
            "[determinism]\ntime_start = 1767225600\n",
            "[filesystem]\nmount = 1\n",
        ],
    )
    def test_schema_errors_reach_the_caller_unchanged(self, profile):
        # The mapping layer must not swallow, reclassify or re-wrap what the
        # export raised on its way out.
        with pytest.raises(PolicyError) as from_core:
            profile_parse(profile)
        with pytest.raises(PolicyError) as from_sdk:
            policy_from_toml(profile)
        assert str(from_sdk.value) == str(from_core.value)

    def test_invalid_toml_is_reported_by_the_core_parser(self):
        # Wording specific to core's TOML reader: a Python-side reader would
        # phrase this differently, and there is no longer one.
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml("not valid [[[toml")
        assert "TOML parse error" in str(excinfo.value)

    def test_profile_text_with_a_nul_byte_is_refused(self):
        # The C ABI takes a NUL-terminated string; truncating at the NUL
        # would parse a prefix of the profile and call it valid.
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml('[limits]\ncpu = 50\n\x00[network]\n')
        assert "NUL" in str(excinfo.value)


class TestCanonicalDrift:
    """Unknown-key checking on the SDK side, so a schema change is loud."""

    def _canonical(self) -> dict:
        return profile_parse('[limits]\nmemory = "512M"\n')

    def test_unknown_section_in_the_canonical_form_is_an_error(self):
        canonical = self._canonical()
        canonical["bogus"] = {}
        with pytest.raises(PolicyError, match="out of sync"):
            _from_canonical(canonical)

    def test_unknown_field_in_a_section_is_an_error(self):
        canonical = self._canonical()
        canonical["limits"]["bogus"] = 1
        with pytest.raises(PolicyError, match="out of sync"):
            _from_canonical(canonical)

    def test_a_field_that_disappears_is_an_error(self):
        canonical = self._canonical()
        del canonical["limits"]["memory"]
        with pytest.raises(PolicyError, match="out of sync"):
            _from_canonical(canonical)

    def test_a_mount_that_loses_its_read_only_flag_is_an_error(self):
        canonical = profile_parse('[filesystem]\nmount = ["/w:/h:ro"]\n')
        del canonical["filesystem"]["mount"][0]["ro"]
        with pytest.raises(PolicyError, match="out of sync"):
            _from_canonical(canonical)

    def test_a_rule_without_a_spec_is_an_error(self):
        canonical = profile_parse('[network]\nallow = ["tcp://example.com:443"]\n')
        del canonical["network"]["allow"][0]["spec"]
        with pytest.raises(PolicyError, match="out of sync"):
            _from_canonical(canonical)


class TestLoadProfilePath:
    def test_load_valid_toml(self, tmp_path):
        profile = tmp_path / "test.toml"
        profile.write_text(textwrap.dedent("""\
            [filesystem]
            read = ["/usr", "/lib"]
            write = ["/tmp/work"]
            mount = ["/work:/srv/work:ro"]

            [program]
            clean_env = true
            env = { CC = "gcc" }

            [limits]
            memory = "256M"
        """))
        p = load_profile_path(profile)
        assert p.fs_readable == ["/usr", "/lib"]
        assert p.fs_writable == ["/tmp/work"]
        assert list(p.fs_mount) == [Mount("/work", "/srv/work", ro=True)]
        assert p.clean_env is True
        assert p.env == {"CC": "gcc"}
        assert p.max_memory == 256 * 1024 ** 2

    def test_missing_file_names_the_path(self, tmp_path):
        with pytest.raises(PolicyError, match="nope.toml"):
            load_profile_path(tmp_path / "nope.toml")

    def test_parse_error_names_the_file_and_keeps_the_core_message(self, tmp_path):
        profile = tmp_path / "bad.toml"
        profile.write_text('[limits]\nmemory = "1.5G"\n')
        with pytest.raises(PolicyError) as excinfo:
            load_profile_path(profile)
        message = str(excinfo.value)
        assert str(profile) in message
        assert "invalid byte size: 1.5G" in message

    def test_unknown_section_in_file_raises(self, tmp_path):
        profile = tmp_path / "bad.toml"
        profile.write_text("[typo]\n")
        with pytest.raises(PolicyError, match="unknown field"):
            load_profile_path(profile)

    def test_old_flat_format_rejected(self, tmp_path):
        # Pre-Phase-3 profiles used flat top-level keys. They are now
        # rejected (sectioned schema only). Pre-1.0 hard break.
        profile = tmp_path / "old.toml"
        profile.write_text('fs_readable = ["/usr"]\n')
        with pytest.raises(PolicyError, match="unknown field"):
            load_profile_path(profile)


class TestListProfiles:
    def test_list_profiles(self, tmp_path, monkeypatch):
        import sandlock._profile as mod
        monkeypatch.setattr(mod, "_PROFILES_DIR", tmp_path)

        (tmp_path / "build.toml").write_text("[program]\nuid = 0\ngid = 0\n")
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
        base = Sandbox(max_memory=256 * 1024 ** 2, uid=0, gid=0)
        result = merge_cli_overrides(base, {"max_memory": 1024 ** 3})
        assert result.max_memory == 1024 ** 3
        assert result.uid == 0  # unchanged

    def test_list_append(self):
        base = Sandbox(fs_readable=["/usr", "/lib"])
        result = merge_cli_overrides(base, {"fs_readable": ["/etc"]})
        assert result.fs_readable == ["/usr", "/lib", "/etc"]

    def test_bool_override(self):
        base = Sandbox(clean_env=False)
        result = merge_cli_overrides(base, {"clean_env": True})
        assert result.clean_env is True

    def test_overrides_compose_with_a_loaded_profile(self):
        base = policy_from_toml('[filesystem]\nread = ["/usr"]\n')
        result = merge_cli_overrides(base, {"fs_readable": ["/etc"]})
        assert result.fs_readable == ["/usr", "/etc"]


def test_profiles_dir_is_a_path():
    assert profiles_dir().is_absolute() or str(profiles_dir()).startswith("~")
