# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock._seccomp."""

import struct

import pytest

from sandlock._seccomp import (
    AUDIT_ARCH,
    BPF_ALU,
    BPF_AND,
    BPF_JMP,
    BPF_JEQ,
    BPF_K,
    BPF_RET,
    DEFAULT_DENY_SYSCALLS,
    ERRNO_EPERM,
    SECCOMP_RET_ERRNO,
    TIOCLINUX,
    TIOCSTI,
    _AF_INET,
    _AF_INET6,
    _ARCH_AARCH64,
    _ARCH_X86_64,
    _CLONE_NS_FLAGS,
    _DANGEROUS_IOCTLS,
    _DANGEROUS_PRCTL_OPS,
    _MACHINE_TO_ARCH,
    _SOCK_DGRAM,
    _SOCK_RAW,
    _SOCK_TYPE_MASK,
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

    def test_tioclinux_defined(self):
        assert TIOCLINUX == 0x541C

    def test_dangerous_ioctls_defined(self):
        assert TIOCSTI in _DANGEROUS_IOCTLS
        assert TIOCLINUX in _DANGEROUS_IOCTLS

    def test_prctl_in_syscall_map(self):
        assert "prctl" in _SYSCALL_NR

    def test_dangerous_prctl_ops_defined(self):
        assert len(_DANGEROUS_PRCTL_OPS) == 3
        assert 4 in _DANGEROUS_PRCTL_OPS           # PR_SET_DUMPABLE
        assert 28 in _DANGEROUS_PRCTL_OPS          # PR_SET_SECUREBITS
        assert 0x59616d61 in _DANGEROUS_PRCTL_OPS  # PR_SET_PTRACER
        assert 22 not in _DANGEROUS_PRCTL_OPS      # PR_SET_SECCOMP — safe under NO_NEW_PRIVS


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

    def test_deny_filter_passes_socket_type_params(self):
        """_build_deny_filter should forward no_raw_sockets/no_udp."""
        filt_default = _build_deny_filter([165])
        filt_no_raw = _build_deny_filter([165], no_raw_sockets=False, no_udp=False)
        # Default has raw socket block, no_raw=False does not
        assert len(filt_default) > len(filt_no_raw)


class TestDefaultDenySyscalls:
    def test_all_have_numbers(self):
        for name in DEFAULT_DENY_SYSCALLS:
            assert name in _SYSCALL_NR, f"'{name}' not in syscall number map"

    def test_dangerous_syscalls_blocked(self):
        assert "mount" in DEFAULT_DENY_SYSCALLS
        assert "reboot" in DEFAULT_DENY_SYSCALLS
        assert "ptrace" in DEFAULT_DENY_SYSCALLS
        assert "kexec_load" in DEFAULT_DENY_SYSCALLS
        assert "io_uring_setup" in DEFAULT_DENY_SYSCALLS
        assert "io_uring_enter" in DEFAULT_DENY_SYSCALLS
        assert "io_uring_register" in DEFAULT_DENY_SYSCALLS


class TestSocketTypeConstants:
    def test_af_inet_values(self):
        assert _AF_INET == 2
        assert _AF_INET6 == 10

    def test_sock_type_values(self):
        assert _SOCK_DGRAM == 2
        assert _SOCK_RAW == 3

    def test_type_mask_strips_flags(self):
        SOCK_NONBLOCK = 0x800
        SOCK_CLOEXEC = 0x80000
        assert (_SOCK_RAW | SOCK_NONBLOCK) & _SOCK_TYPE_MASK == _SOCK_RAW
        assert (_SOCK_DGRAM | SOCK_CLOEXEC) & _SOCK_TYPE_MASK == _SOCK_DGRAM
        assert (_SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC) & _SOCK_TYPE_MASK == _SOCK_RAW


class TestSocketTypeFiltering:
    """Unit tests for socket type BPF filtering (no_raw_sockets, no_udp)."""

    def test_default_includes_raw_block(self):
        """Default _build_arg_filters() includes SOCK_RAW block."""
        filt_default = _build_arg_filters()
        filt_none = _build_arg_filters(no_raw_sockets=False, no_udp=False)
        assert len(filt_default) > len(filt_none)

    def test_no_raw_adds_instructions(self):
        baseline = _build_arg_filters(no_raw_sockets=False, no_udp=False)
        with_raw = _build_arg_filters(no_raw_sockets=True, no_udp=False)
        added = (len(with_raw) - len(baseline)) // 8
        # Should add: LOAD NR + JEQ socket + LOAD arg0 + JEQ AF_INET +
        #   JEQ AF_INET6 + LOAD arg1 + AND mask + JEQ SOCK_RAW + RET ERRNO
        assert added == 9

    def test_no_udp_adds_instructions(self):
        baseline = _build_arg_filters(no_raw_sockets=False, no_udp=False)
        with_udp = _build_arg_filters(no_raw_sockets=False, no_udp=True)
        added = (len(with_udp) - len(baseline)) // 8
        assert added == 9  # same structure as raw block

    def test_both_share_structure(self):
        """Blocking both types shares the domain check, adding only 1 JEQ."""
        baseline = _build_arg_filters(no_raw_sockets=False, no_udp=False)
        with_raw = _build_arg_filters(no_raw_sockets=True, no_udp=False)
        with_both = _build_arg_filters(no_raw_sockets=True, no_udp=True)
        raw_insns = (len(with_raw) - len(baseline)) // 8
        both_insns = (len(with_both) - len(baseline)) // 8
        # Both adds one extra JEQ for the second type
        assert both_insns == raw_insns + 1

    def test_filter_contains_deny_return(self):
        """Filter with socket blocks must contain RET ERRNO(EPERM)."""
        filt = _build_arg_filters(no_raw_sockets=True)
        deny_ret = struct.pack("HBBI", BPF_RET | BPF_K, 0, 0,
                               SECCOMP_RET_ERRNO | ERRNO_EPERM)
        assert deny_ret in filt

    def test_filter_contains_and_mask(self):
        """Filter must AND arg1 with 0xFF to strip SOCK_NONBLOCK|SOCK_CLOEXEC."""
        filt = _build_arg_filters(no_raw_sockets=True)
        and_insn = struct.pack("HBBI", BPF_ALU | BPF_AND | BPF_K, 0, 0,
                               _SOCK_TYPE_MASK)
        assert and_insn in filt

    def test_no_socket_block_when_disabled(self):
        """No AND mask instruction when both socket blocks are disabled."""
        filt = _build_arg_filters(no_raw_sockets=False, no_udp=False)
        and_insn = struct.pack("HBBI", BPF_ALU | BPF_AND | BPF_K, 0, 0,
                               _SOCK_TYPE_MASK)
        assert and_insn not in filt

    def _decode_insns(self, data):
        """Decode BPF bytecode into list of (code, jt, jf, k) tuples."""
        insns = []
        for i in range(0, len(data), 8):
            insns.append(struct.unpack("HBBI", data[i:i + 8]))
        return insns

    def test_raw_block_jump_targets_valid(self):
        """All jump targets in the raw socket block must land within bounds."""
        filt = _build_arg_filters(no_raw_sockets=True, no_udp=False)
        insns = self._decode_insns(filt)
        n = len(insns)
        for i, (code, jt, jf, k) in enumerate(insns):
            if code & 0x07 == 0x05:  # BPF_JMP
                assert i + 1 + jt <= n, f"insn[{i}] jt={jt} overflows (n={n})"
                assert i + 1 + jf <= n, f"insn[{i}] jf={jf} overflows (n={n})"

    def test_both_block_jump_targets_valid(self):
        """All jump targets valid when both raw and udp are blocked."""
        filt = _build_arg_filters(no_raw_sockets=True, no_udp=True)
        insns = self._decode_insns(filt)
        n = len(insns)
        for i, (code, jt, jf, k) in enumerate(insns):
            if code & 0x07 == 0x05:  # BPF_JMP
                assert i + 1 + jt <= n, f"insn[{i}] jt={jt} overflows (n={n})"
                assert i + 1 + jf <= n, f"insn[{i}] jf={jf} overflows (n={n})"
