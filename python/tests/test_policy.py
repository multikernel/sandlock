# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.policy."""

import pytest

from sandlock.policy import (
    Policy,
    parse_memory_size,
    parse_ports,
)


class TestParseMemorySize:
    def test_plain_bytes(self):
        assert parse_memory_size("1024") == 1024

    def test_kilobytes(self):
        assert parse_memory_size("100K") == 100 * 1024

    def test_megabytes(self):
        assert parse_memory_size("512M") == 512 * 1024 ** 2

    def test_gigabytes(self):
        assert parse_memory_size("1G") == 1024 ** 3

    def test_terabytes(self):
        assert parse_memory_size("2T") == 2 * 1024 ** 4

    def test_case_insensitive(self):
        assert parse_memory_size("512m") == 512 * 1024 ** 2

    def test_fractional(self):
        assert parse_memory_size("1.5G") == int(1.5 * 1024 ** 3)

    def test_whitespace(self):
        assert parse_memory_size("  512M  ") == 512 * 1024 ** 2

    def test_invalid(self):
        with pytest.raises(ValueError):
            parse_memory_size("not_a_size")

    def test_empty(self):
        with pytest.raises(ValueError):
            parse_memory_size("")


class TestPolicy:
    def test_defaults(self):
        p = Policy()
        assert p.fs_writable == []
        assert p.fs_readable == []
        assert p.fs_denied == []
        assert p.deny_syscalls is None
        assert p.net_bind == []
        assert p.net_connect == []
        assert p.max_memory is None
        assert p.max_processes == 64
        assert p.max_cpu is None
        assert p.close_fds is True

    def test_frozen(self):
        p = Policy(max_memory="512M")
        with pytest.raises(AttributeError):
            p.max_memory = "1G"  # type: ignore

    def test_memory_bytes_string(self):
        p = Policy(max_memory="512M")
        assert p.memory_bytes() == 512 * 1024 ** 2

    def test_memory_bytes_int(self):
        p = Policy(max_memory=1024)
        assert p.memory_bytes() == 1024

    def test_memory_bytes_none(self):
        p = Policy()
        assert p.memory_bytes() is None

    def test_cpu_pct(self):
        p = Policy(max_cpu=50)
        assert p.cpu_pct() == 50

    def test_cpu_pct_none(self):
        p = Policy()
        assert p.cpu_pct() is None

    def test_cpu_pct_clamped(self):
        assert Policy(max_cpu=0).cpu_pct() == 1
        assert Policy(max_cpu=200).cpu_pct() == 100


class TestParsePorts:
    def test_single_int(self):
        assert parse_ports([80]) == [80]

    def test_single_string(self):
        assert parse_ports(["443"]) == [443]

    def test_range(self):
        assert parse_ports(["8000-8003"]) == [8000, 8001, 8002, 8003]

    def test_mixed(self):
        assert parse_ports([80, "443", "8000-8002"]) == [80, 443, 8000, 8001, 8002]

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
    def test_bind_ports(self):
        p = Policy(net_bind=[80, "443", "8000-8002"])
        assert p.bind_ports() == [80, 443, 8000, 8001, 8002]

    def test_connect_ports(self):
        p = Policy(net_connect=["1-1024"])
        assert p.connect_ports() == list(range(1, 1025))

    def test_unrestricted_by_default(self):
        p = Policy()
        assert p.bind_ports() == []
        assert p.connect_ports() == []


class TestEnvControl:
    def test_clean_env_default_off(self):
        p = Policy()
        assert p.clean_env is False

    def test_env_default_empty(self):
        p = Policy()
        assert p.env == {}

    def test_clean_env_on(self):
        p = Policy(clean_env=True)
        assert p.clean_env is True

    def test_env_set(self):
        p = Policy(env={"FOO": "bar", "BAZ": "qux"})
        assert p.env == {"FOO": "bar", "BAZ": "qux"}


class TestGpuDevices:
    def test_default_none(self):
        p = Policy()
        assert p.gpu_devices is None

    def test_specific_devices(self):
        p = Policy(gpu_devices=[0, 2])
        assert p.gpu_devices == [0, 2]

    def test_all_gpus(self):
        p = Policy(gpu_devices=[])
        assert p.gpu_devices == []


class TestIpcScoping:
    def test_defaults_to_off(self):
        p = Policy()
        assert p.isolate_ipc is False
        assert p.isolate_signals is False

    def test_enable_ipc(self):
        p = Policy(isolate_ipc=True)
        assert p.isolate_ipc is True

    def test_enable_signals(self):
        p = Policy(isolate_signals=True)
        assert p.isolate_signals is True

    def test_enable_both(self):
        p = Policy(isolate_ipc=True, isolate_signals=True)
        assert p.isolate_ipc is True
        assert p.isolate_signals is True


