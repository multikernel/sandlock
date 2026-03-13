# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock._seccomp."""

import struct

import pytest

from sandlock._seccomp import (
    AUDIT_ARCH,
    DEFAULT_DENY_SYSCALLS,
    TIOCSTI,
    _ARCH_AARCH64,
    _ARCH_X86_64,
    _CLONE_NS_FLAGS,
    _MACHINE_TO_ARCH,
    _SYSCALL_NR,
    _arch,
    _bpf_jump,
    _bpf_stmt,
    _build_arg_filters,
    _build_deny_filter,
    syscall_number,
)


class TestArchDetection:
    def test_detected_arch_is_valid(self):
        assert _arch.name in ("x86_64", "aarch64")

    def test_audit_arch_matches(self):
        assert AUDIT_ARCH == _arch.audit_arch

    def test_syscall_nrs_matches(self):
        assert _SYSCALL_NR is _arch.syscall_nrs

    def test_both_archs_have_common_syscalls(self):
        common = ["mount", "ptrace", "bpf", "clone", "clone3", "ioctl"]
        for name in common:
            assert name in _ARCH_X86_64.syscall_nrs, f"{name} missing from x86_64"
            assert name in _ARCH_AARCH64.syscall_nrs, f"{name} missing from aarch64"

    def test_x86_only_syscalls_not_on_aarch64(self):
        assert "ioperm" in _ARCH_X86_64.syscall_nrs
        assert "ioperm" not in _ARCH_AARCH64.syscall_nrs
        assert "iopl" in _ARCH_X86_64.syscall_nrs
        assert "iopl" not in _ARCH_AARCH64.syscall_nrs

    def test_supported_architectures(self):
        assert "x86_64" in _MACHINE_TO_ARCH
        assert "aarch64" in _MACHINE_TO_ARCH


class TestSyscallNumber:
    def test_known_syscall(self):
        assert syscall_number("mount") is not None

    def test_unknown_syscall(self):
        assert syscall_number("nonexistent_syscall") is None

    def test_ptrace(self):
        assert syscall_number("ptrace") is not None

    def test_bpf(self):
        assert syscall_number("bpf") is not None


class TestBpfInstructions:
    def test_stmt_size(self):
        insn = _bpf_stmt(0, 0)
        assert len(insn) == 8

    def test_jump_size(self):
        insn = _bpf_jump(0, 0, 0, 0)
        assert len(insn) == 8

    def test_stmt_encoding(self):
        insn = _bpf_stmt(0x20, 4)  # BPF_LD | BPF_ABS, offset 4
        code, jt, jf, k = struct.unpack("HBBI", insn)
        assert code == 0x20
        assert jt == 0
        assert jf == 0
        assert k == 4


class TestBuildArgFilters:
    def test_returns_valid_bpf(self):
        filt = _build_arg_filters()
        assert len(filt) > 0
        assert len(filt) % 8 == 0

    def test_clone_and_ioctl_in_syscall_map(self):
        assert "clone" in _SYSCALL_NR
        assert "clone3" in _SYSCALL_NR
        assert "ioctl" in _SYSCALL_NR

    def test_clone_ns_flags_defined(self):
        assert _CLONE_NS_FLAGS & 0x10000000  # CLONE_NEWUSER
        assert _CLONE_NS_FLAGS & 0x00020000  # CLONE_NEWNS

    def test_tiocsti_defined(self):
        assert TIOCSTI == 0x5412


class TestBuildFilter:
    def test_empty_deny_list(self):
        filt = _build_deny_filter([])
        # Should have: arch preamble + arg filters + load nr + allow + deny
        assert len(filt) > 0
        assert len(filt) % 8 == 0  # Each instruction is 8 bytes

    def test_single_deny(self):
        filt = _build_deny_filter([165])  # mount
        n_insns = len(filt) // 8
        n_arg_insns = len(_build_arg_filters()) // 8
        # arch load + arch check + kill + arg_filters + nr load + 1 check + allow + deny
        assert n_insns == 4 + n_arg_insns + 1 + 1 + 1

    def test_multiple_deny(self):
        filt = _build_deny_filter([165, 166, 167])
        n_insns = len(filt) // 8
        n_arg_insns = len(_build_arg_filters()) // 8
        # 3 base + arg_filters + 1 load_nr + 3 checks + allow + deny
        assert n_insns == 3 + n_arg_insns + 1 + 3 + 1 + 1


class TestDefaultDenySyscalls:
    def test_all_have_numbers(self):
        for name in DEFAULT_DENY_SYSCALLS:
            assert name in _SYSCALL_NR, f"'{name}' not in syscall number map"

    def test_dangerous_syscalls_blocked(self):
        assert "mount" in DEFAULT_DENY_SYSCALLS
        assert "reboot" in DEFAULT_DENY_SYSCALLS
        assert "ptrace" in DEFAULT_DENY_SYSCALLS
        assert "kexec_load" in DEFAULT_DENY_SYSCALLS
