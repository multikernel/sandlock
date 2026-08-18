# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.sandbox."""

from __future__ import annotations

import pytest

import sandlock.sandbox as sandbox_module
from sandlock._sdk import _bytes_limit, _epoch_seconds
from sandlock.sandbox import (
    Mount,
    Sandbox,
    parse_ports,
)


class TestNoSecondGrammar:
    """The profile grammars live in the core parser, and only there.

    Every helper named here used to be a second implementation of a grammar
    the core already owns, and each one disagreed with it somewhere: sizes
    accepted ``'1.5G'``/``'1T'`` that the core rejects, and the timestamp
    helper read a naive stamp as UTC while the core requires an offset.
    """

    def test_size_grammar_is_gone(self):
        assert not hasattr(sandbox_module, "parse_memory_size")
        assert not hasattr(Sandbox, "memory_bytes")

    def test_timestamp_grammar_is_gone(self):
        assert not hasattr(Sandbox, "time_start_timestamp")

    @pytest.mark.parametrize("field", ["max_memory", "max_disk"])
    def test_size_strings_are_refused_at_construction(self, field):
        with pytest.raises(TypeError, match="integer number of bytes"):
            Sandbox(**{field: "512M"})

    def test_time_start_strings_are_refused_at_construction(self):
        with pytest.raises(TypeError, match="epoch seconds"):
            Sandbox(time_start="2026-01-01T00:00:00Z")


class TestFsMountField:
    def test_mount_entries(self):
        p = Sandbox(fs_mount=[Mount("/work", "/host"), Mount("/ro", "/h", ro=True)])
        assert p.fs_mount[0].ro is False
        assert p.fs_mount[1].ro is True

    def test_mapping_is_refused(self):
        # The old representation was dict[virt, host], which had no channel
        # for the read-only flag at all.
        with pytest.raises(TypeError, match="not a mapping"):
            Sandbox(fs_mount={"/work": "/host"})

    def test_non_mount_entries_are_refused(self):
        with pytest.raises(TypeError, match="must be Mount"):
            Sandbox(fs_mount=[("/work", "/host")])


class TestEnsureNative:
    """``_ensure_native`` rebuilds on every call so that mutations to
    config fields between lifecycle invocations are not silently
    masked by a stale native cache."""

    def test_rebuilds_on_each_call(self):
        sb = Sandbox(fs_readable=["/usr"])
        first = sb._ensure_native()
        second = sb._ensure_native()
        # Two distinct native objects (rebuild, not cache hit).
        assert first is not second

    def test_picks_up_post_construction_mutation(self):
        sb = Sandbox(fs_readable=["/usr"])
        sb._ensure_native()                 # first build
        sb.fs_readable = ["/usr", "/etc"]   # user mutates after first run
        rebuilt = sb._ensure_native()       # second build sees mutation
        # The rebuilt native is a fresh object; the cached self._native
        # was replaced, not retained from the pre-mutation state.
        assert rebuilt is sb._native


class TestPolicy:
    def test_defaults(self):
        p = Sandbox()
        assert p.fs_writable == []
        assert p.fs_readable == []
        assert p.fs_denied == []
        assert p.extra_deny_syscalls == []
        assert p.extra_allow_syscalls == []
        assert p.net_allow_bind == []
        assert p.net_allow == []
        assert p.max_memory is None
        assert p.max_processes == 64
        assert p.max_cpu is None

    def test_mutable_config(self):
        # Sandbox is no longer frozen — it holds runtime state too.
        p = Sandbox(max_memory=512 * 1024 ** 2)
        p.max_memory = 1024 ** 3
        assert p.max_memory == 1024 ** 3

    def test_cpu_pct(self):
        p = Sandbox(max_cpu=50)
        assert p.cpu_pct() == 50

    def test_cpu_pct_none(self):
        p = Sandbox()
        assert p.cpu_pct() is None

    def test_cpu_pct_clamped(self):
        assert Sandbox(max_cpu=0).cpu_pct() == 1
        assert Sandbox(max_cpu=200).cpu_pct() == 100


class TestDiskQuotaPolicy:
    def test_default_none(self):
        p = Sandbox()
        assert p.max_disk is None

    def test_byte_value(self):
        p = Sandbox(max_disk=1024 ** 3)
        assert p.max_disk == 1024 ** 3

    def test_mutable_config(self):
        # Sandbox is no longer frozen — it holds runtime state too.
        p = Sandbox(max_disk=512 * 1024 ** 2)
        p.max_disk = 1024 ** 3
        assert p.max_disk == 1024 ** 3


class TestParsePorts:
    def test_single_int(self):
        assert parse_ports([80]) == [80]

    def test_single_string(self):
        assert parse_ports(["443"]) == [443]

    def test_range(self):
        assert parse_ports(["8000-8003"]) == [8000, 8001, 8002, 8003]

    def test_mixed(self):
        assert parse_ports([80, "443", "8000-8002"]) == [80, 443, 8000, 8001, 8002]

    def test_comma_in_string(self):
        # A string element may hold a comma list / ranges, matching the CLI's
        # --net-allow-bind grammar.
        assert parse_ports(["8080,9090"]) == [8080, 9090]
        assert parse_ports(["8080,9000-9002", 443]) == [443, 8080, 9000, 9001, 9002]

    def test_comma_empty_part_rejected(self):
        with pytest.raises(ValueError):
            parse_ports(["8080,"])

    def test_dedup(self):
        assert parse_ports([80, "80", "79-81"]) == [79, 80, 81]

    def test_invalid_range(self):
        with pytest.raises(ValueError):
            parse_ports(["9000-8000"])

    def test_out_of_range(self):
        with pytest.raises(ValueError):
            parse_ports([70000])

    def test_bad_format(self):
        with pytest.raises(ValueError):
            parse_ports(["abc"])

    def test_empty(self):
        assert parse_ports([]) == []


class TestNetPolicy:
    def test_unrestricted_by_default(self):
        p = Sandbox()
        assert p.net_allow_bind == []
        assert p.net_allow == []


class TestEnvControl:
    def test_clean_env_default_off(self):
        p = Sandbox()
        assert p.clean_env is False

    def test_env_default_empty(self):
        p = Sandbox()
        assert p.env == {}

    def test_clean_env_on(self):
        p = Sandbox(clean_env=True)
        assert p.clean_env is True

    def test_env_set(self):
        p = Sandbox(env={"FOO": "bar", "BAZ": "qux"})
        assert p.env == {"FOO": "bar", "BAZ": "qux"}


class TestGpuDevices:
    def test_default_none(self):
        p = Sandbox()
        assert p.gpu_devices is None

    def test_specific_devices(self):
        p = Sandbox(gpu_devices=[0, 2])
        assert p.gpu_devices == [0, 2]

    def test_all_gpus(self):
        p = Sandbox(gpu_devices=[])
        assert p.gpu_devices == []


class TestCpuCores:
    def test_default_none(self):
        p = Sandbox()
        assert p.cpu_cores is None

    def test_specific_cores(self):
        p = Sandbox(cpu_cores=[0, 2, 3])
        assert p.cpu_cores == [0, 2, 3]


class TestNetAllow:
    """Endpoint allowlist semantics for `net_allow`.

    Each entry is a string spec parsed by the native build:
    `host:port[,port,...]`, `:port`, or `*:port`. Empty list = deny all.
    """

    def test_default_is_empty(self):
        p = Sandbox()
        assert p.net_allow == []

    def test_specs_preserved_as_strings(self):
        p = Sandbox(net_allow=["api.example.com:443", "github.com:22,443", ":8080"])
        assert list(p.net_allow) == [
            "api.example.com:443",
            "github.com:22,443",
            ":8080",
        ]


class TestNetDeny:
    """Endpoint denylist semantics for `net_deny` (default-allow, inverse of
    `net_allow`, mutually exclusive with it). Targets are literal IP/CIDR."""

    def test_default_is_empty(self):
        assert Sandbox().net_deny == []

    def test_specs_preserved_as_strings(self):
        p = Sandbox(net_deny=["10.0.0.0/8", "169.254.169.254:80", "udp://*"])
        assert list(p.net_deny) == ["10.0.0.0/8", "169.254.169.254:80", "udp://*"]



class TestBuilderBoundary:
    """Values the C ABI setters cannot carry are refused, not truncated.

    ``sandlock_sandbox_builder_time_start`` takes whole non-negative epoch
    seconds while the profile grammar accepts pre-epoch and fractional
    stamps, so those two cases have to fail loudly: passing them on would
    make the same profile mean one thing through the CLI and another here,
    and a negative value would wrap to a date in the far future.
    """

    def test_whole_epoch_seconds_pass(self):
        assert _epoch_seconds(1767225600) == 1767225600
        assert _epoch_seconds(1767225600.0) == 1767225600

    def test_pre_epoch_time_start_is_refused(self):
        with pytest.raises(ValueError, match="before the Unix epoch"):
            _epoch_seconds(-0.5)

    def test_sub_second_time_start_is_refused(self):
        with pytest.raises(ValueError, match="sub-second"):
            _epoch_seconds(1767225600.25)

    def test_non_numeric_time_start_is_refused(self):
        with pytest.raises(TypeError, match="epoch seconds"):
            _epoch_seconds("1767225600")

    def test_byte_limits_must_be_integers(self):
        assert _bytes_limit(512, "max_memory") == 512
        with pytest.raises(TypeError, match="integer number of bytes"):
            _bytes_limit(1.5, "max_memory")

    def test_byte_limits_must_fit_the_abi(self):
        with pytest.raises(ValueError, match="out of range"):
            _bytes_limit(2 ** 64, "max_memory")
        with pytest.raises(ValueError, match="out of range"):
            _bytes_limit(-1, "max_disk")
