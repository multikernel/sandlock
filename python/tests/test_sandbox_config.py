# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.sandbox."""

from __future__ import annotations

import pytest

from sandlock.sandbox import (
    Sandbox,
    parse_ports,
)


class TestCoreOwnsSizeAndTimeGrammar:
    """Size and timestamp fields are forwarded verbatim; the core decides."""

    @pytest.mark.parametrize("field,value", [
        ("max_memory", "512M"),
        ("max_memory", 1024),
        ("max_disk", "1G"),
        ("time_start", "1969-07-20T20:17:00Z"),
        ("time_start", "2026-01-01T00:00:00.5+08:00"),
    ])
    def test_accepted(self, field, value):
        Sandbox(**{field: value})._ensure_native()

    @pytest.mark.parametrize("field,value", [
        ("max_memory", "1.5G"),
        ("max_memory", "1T"),
        ("max_disk", "lots"),
        ("time_start", "1767225600"),
        ("time_start", 1767225600.5),
    ])
    def test_refused_with_core_reason(self, field, value):
        with pytest.raises(RuntimeError, match=field):
            Sandbox(**{field: value})._ensure_native()

    def test_aware_datetime_is_forwarded(self):
        from datetime import datetime, timezone
        Sandbox(time_start=datetime(1969, 7, 20, tzinfo=timezone.utc))._ensure_native()

    def test_naive_datetime_is_refused(self):
        from datetime import datetime
        with pytest.raises(RuntimeError, match="time_start"):
            Sandbox(time_start=datetime(2000, 1, 1))._ensure_native()


class TestHttpPorts:
    @pytest.mark.parametrize("port", [-1, 70000])
    def test_out_of_range_port_is_refused(self, port):
        with pytest.raises(ValueError, match="http_ports"):
            Sandbox(http_ports=[port])._ensure_native()


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
        assert p.max_processes is None
        assert p.max_cpu is None

    def test_mutable_config(self):
        # Sandbox is no longer frozen — it holds runtime state too.
        p = Sandbox(max_memory="512M")
        p.max_memory = "1G"
        assert p.max_memory == "1G"

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

    def test_string_value(self):
        p = Sandbox(max_disk="1G")
        assert p.max_disk == "1G"

    def test_mutable_config(self):
        # Sandbox is no longer frozen — it holds runtime state too.
        p = Sandbox(max_disk="512M")
        p.max_disk = "1G"
        assert p.max_disk == "1G"


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
    `net_allow`, with denied destinations taking precedence). Targets are
    literal IP/CIDR."""

    def test_default_is_empty(self):
        assert Sandbox().net_deny == []

    def test_specs_preserved_as_strings(self):
        p = Sandbox(net_deny=["10.0.0.0/8", "169.254.169.254:80", "udp://*"])
        assert list(p.net_deny) == ["10.0.0.0/8", "169.254.169.254:80", "udp://*"]

