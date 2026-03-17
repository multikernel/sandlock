# SPDX-License-Identifier: Apache-2.0
"""seccomp-bpf filter generation and installation.

Generates a classic BPF (cBPF) sock_filter program that blocks
specified syscalls.  Installed via prctl(PR_SET_SECCOMP).

Supports x86_64 and aarch64.  The architecture is detected at
import time via ``platform.machine()``.

This provides defense-in-depth even without BPF LSM — seccomp
runs at syscall entry before the kernel does any work.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import struct
from dataclasses import dataclass

from .exceptions import SeccompError

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# prctl constants
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# BPF instruction constants (cBPF)
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_JSET = 0x40
BPF_K = 0x00
BPF_RET = 0x06
BPF_ALU = 0x04
BPF_AND = 0x50

# seccomp return values
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_USER_NOTIF = 0x7FC00000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_KILL_PROCESS = 0x80000000

# seccomp() syscall constants (not prctl — needed for USER_NOTIF)
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3
SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV = 1 << 5  # Linux 5.19+

# seccomp_data offsets (architecture-independent layout)
# struct seccomp_data { u32 nr, u32 arch, u64 instruction_pointer, u64 args[6] }
OFFSET_NR = 0
OFFSET_ARCH = 4
OFFSET_ARGS0_LO = 16   # args[0] low 32 bits
OFFSET_ARGS0_HI = 20   # args[0] high 32 bits
OFFSET_ARGS1_LO = 24   # args[1] low 32 bits
OFFSET_ARGS1_HI = 28   # args[1] high 32 bits
OFFSET_ARGS2_LO = 32   # args[2] low 32 bits

# EPERM
ERRNO_EPERM = 1

# clone(2) flags that allow namespace creation — these are dangerous
# because they let sandboxed processes escape filesystem restrictions.
CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWCGROUP = 0x02000000
_CLONE_NS_FLAGS = (
    CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID
    | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP
)

# Dangerous ioctl commands — TIOCSTI allows injecting input into
# another terminal session (terminal escape attack).
TIOCSTI = 0x5412


# --- Per-architecture configuration ---

@dataclass(frozen=True)
class _ArchConfig:
    """Architecture-specific constants for seccomp."""
    name: str
    audit_arch: int
    syscall_nrs: dict[str, int]


# Shared syscalls present on both x86_64 and aarch64 (with different numbers).
# x86-only syscalls (ioperm, iopl, etc.) appear only in the x86_64 table.
# aarch64 uses asm-generic numbers for most syscalls.

from ._syscall_table import (
    X86_64_AUDIT_ARCH, X86_64_SYSCALLS,
    AARCH64_AUDIT_ARCH, AARCH64_SYSCALLS,
)

_ARCH_X86_64 = _ArchConfig(
    name="x86_64",
    audit_arch=X86_64_AUDIT_ARCH,
    syscall_nrs=X86_64_SYSCALLS,
)

_ARCH_AARCH64 = _ArchConfig(
    name="aarch64",
    audit_arch=AARCH64_AUDIT_ARCH,
    syscall_nrs=AARCH64_SYSCALLS,
)

_MACHINE_TO_ARCH: dict[str, _ArchConfig] = {
    "x86_64": _ARCH_X86_64,
    "aarch64": _ARCH_AARCH64,
}


def _detect_arch() -> _ArchConfig:
    """Detect the current architecture and return its config.

    Raises:
        SeccompError: If the architecture is not supported.
    """
    machine = platform.machine()
    arch = _MACHINE_TO_ARCH.get(machine)
    if arch is None:
        raise SeccompError(
            f"Unsupported architecture for seccomp: {machine!r}. "
            f"Supported: {', '.join(sorted(_MACHINE_TO_ARCH))}"
        )
    return arch


_arch = _detect_arch()

# Public aliases for the resolved architecture
AUDIT_ARCH = _arch.audit_arch


_SYSCALL_NR = _arch.syscall_nrs

# Default blocklist: dangerous syscalls that sandboxed processes
# should almost never need.
DEFAULT_DENY_SYSCALLS = [
    "mount",
    "umount2",
    "pivot_root",
    "swapon",
    "swapoff",
    "reboot",
    "sethostname",
    "setdomainname",
    "kexec_load",
    "init_module",
    "finit_module",
    "delete_module",
    "unshare",
    "setns",
    "perf_event_open",
    "bpf",
    "userfaultfd",
    "keyctl",
    "add_key",
    "request_key",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "open_by_handle_at",
    "name_to_handle_at",
    "ioperm",
    "iopl",
    "quotactl",
    "acct",
    "lookup_dcookie",
    "nfsservctl",
]


# --- cBPF instruction helpers ---

def _bpf_stmt(code: int, k: int) -> bytes:
    """Encode a BPF_STMT (no jump targets)."""
    return struct.pack("HBBI", code, 0, 0, k)


def _bpf_jump(code: int, k: int, jt: int, jf: int) -> bytes:
    """Encode a BPF_JUMP."""
    return struct.pack("HBBI", code, jt, jf, k)


class _SockFprog(ctypes.Structure):
    """struct sock_fprog for seccomp."""
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.c_void_p),
    ]


# Default allowlist: syscalls that typical programs (Python, Node, Go,
# shell utilities) need.  Everything else is blocked.  This is the
# strict alternative to DEFAULT_DENY_SYSCALLS.
#
# Maintained as architecture-neutral names — resolved to numbers at
# runtime.  Unknown names on a given arch are silently skipped.
DEFAULT_ALLOW_SYSCALLS = [
    # --- I/O ---
    "read", "write", "readv", "writev", "pread64", "pwrite64",
    "preadv", "pwritev", "preadv2", "pwritev2",
    # --- File operations ---
    "open", "openat", "openat2", "close", "close_range",
    "stat", "fstat", "lstat", "newfstatat",
    "lseek", "access", "faccessat", "faccessat2",
    "readlink", "readlinkat",
    "fcntl", "dup", "dup2", "dup3",
    "flock", "ftruncate", "fallocate",
    "statx", "statfs", "fstatfs",
    "getdents", "getdents64",
    "getcwd", "chdir", "fchdir",
    "rename", "renameat", "renameat2",
    "mkdir", "mkdirat", "rmdir",
    "link", "linkat", "symlink", "symlinkat",
    "unlink", "unlinkat",
    "chmod", "fchmod", "fchmodat",
    "chown", "fchown", "fchownat", "lchown",
    "utimensat", "futimesat",
    # --- Memory ---
    "brk", "mmap", "munmap", "mremap", "mprotect", "madvise",
    "msync", "mincore", "membarrier",
    # --- Process ---
    "exit", "exit_group",
    "clone", "fork", "vfork",  # clone arg-filtered for NS flags
    "execve", "execveat",
    "wait4", "waitid",
    "getpid", "getppid", "gettid",
    "getuid", "geteuid", "getgid", "getegid",
    "getresuid", "getresgid", "getgroups",
    "setsid", "getpgid", "setpgid", "getpgrp",
    "prctl", "arch_prctl",
    "set_tid_address", "set_robust_list", "get_robust_list",
    "futex", "futex_waitv",
    "sched_yield", "sched_getaffinity", "sched_setaffinity",
    "sched_getparam", "sched_setparam",
    "sched_getscheduler", "sched_setscheduler",
    "nanosleep", "clock_nanosleep",
    # --- Signals ---
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "rt_sigpending", "rt_sigtimedwait", "rt_sigsuspend",
    "sigaltstack", "kill", "tgkill", "tkill",
    # --- Networking (TCP/UDP/Unix) ---
    "socket", "bind", "listen", "accept", "accept4",
    "connect", "sendto", "recvfrom", "sendmsg", "recvmsg",
    "shutdown", "getsockname", "getpeername",
    "setsockopt", "getsockopt", "socketpair",
    # --- Polling / events ---
    "poll", "ppoll", "select", "pselect6",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    "eventfd", "eventfd2", "timerfd_create", "timerfd_settime", "timerfd_gettime",
    "signalfd", "signalfd4",
    # --- Pipes ---
    "pipe", "pipe2", "splice", "tee", "sendfile",
    # --- Time ---
    "clock_gettime", "clock_getres", "gettimeofday", "time",
    # --- Resource info ---
    "getrlimit", "setrlimit", "prlimit64",
    "getrusage", "times", "sysinfo", "uname",
    # --- ioctl (arg-filtered for TIOCSTI) ---
    "ioctl",
    # --- Misc ---
    "getrandom",
    "rseq",
    "mlock", "mlock2", "munlock",
    "umask",
]


def _build_arg_filters() -> bytes:
    """Build cBPF instructions for arg-level syscall filtering.

    These filters check specific arguments rather than blocking the
    syscall entirely:

    - ioctl(2): Block TIOCSTI (terminal input injection).  Normal
      terminal I/O and isatty() still work.

    Note: clone/clone3 namespace flag checks are handled in the
    supervisor via USER_NOTIF, not here.
    """
    insns = bytearray()

    # --- clone/clone3: handled via USER_NOTIF (namespace flag checks
    #     and process tracking done in supervisor) ---

    # --- ioctl: block TIOCSTI (terminal input injection) ---
    # Load syscall number
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR)
    # if nr != ioctl, skip ahead
    insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, _SYSCALL_NR["ioctl"], 0, 3)
    # Load ioctl request (arg1, low 32 bits)
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS1_LO)
    # if request == TIOCSTI → deny
    insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, TIOCSTI, 0, 1)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ERRNO_EPERM)

    # --- socket: block NETLINK_SOCK_DIAG (hides host socket info) ---
    _AF_NETLINK = 16
    _NETLINK_SOCK_DIAG = 4
    # Load syscall number
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR)
    # if nr != socket, skip ahead (5 instructions)
    insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, _SYSCALL_NR["socket"], 0, 5)
    # Load domain (arg0)
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO)
    # if domain != AF_NETLINK, skip (3 instructions)
    insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, _AF_NETLINK, 0, 3)
    # Load protocol (arg2)
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS2_LO)
    # if protocol == NETLINK_SOCK_DIAG → deny
    insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, _NETLINK_SOCK_DIAG, 0, 1)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ERRNO_EPERM)

    return bytes(insns)


def _build_deny_filter(deny_nrs: list[int]) -> bytes:
    """Build a cBPF filter that blocks the given syscall numbers.

    Filter logic:
        1. Check arch (kill process if wrong)
        2. Arg-level filters (clone NS flags, ioctl TIOCSTI)
        3. For each denied syscall: if nr == denied → ERRNO(EPERM)
        4. Default: ALLOW
    """
    insns = bytearray()
    insns += _build_arch_check()
    insns += _build_arg_filters()
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR)

    for i, nr in enumerate(deny_nrs):
        remaining = len(deny_nrs) - i - 1
        insns += _bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K, nr,
            remaining + 1, 0,
        )

    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ERRNO_EPERM)
    return bytes(insns)


def _build_allow_filter(allow_nrs: list[int]) -> bytes:
    """Build a cBPF filter that only allows the given syscall numbers.

    Filter logic:
        1. Check arch (kill process if wrong)
        2. Arg-level filters (clone NS flags, ioctl TIOCSTI)
        3. For each allowed syscall: if nr == allowed → ALLOW
        4. Default: ERRNO(EPERM)
    """
    insns = bytearray()
    insns += _build_arch_check()
    insns += _build_arg_filters()
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR)

    for i, nr in enumerate(allow_nrs):
        remaining = len(allow_nrs) - i - 1
        insns += _bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K, nr,
            remaining + 1, 0,
        )

    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ERRNO_EPERM)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    return bytes(insns)


def _build_arch_check() -> bytes:
    """BPF instructions: load arch, kill if wrong."""
    insns = bytearray()
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH)
    insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
    return bytes(insns)


def syscall_number(name: str) -> int | None:
    """Look up a syscall number by name for the current architecture.

    Returns None if the syscall name is not in the mapping.
    """
    return _SYSCALL_NR.get(name)


def apply_seccomp_filter(
    deny_syscalls: list[str] | None = None,
    allow_syscalls: list[str] | None = None,
) -> None:
    """Install a seccomp-bpf filter.

    Exactly one mode is used:

    - **Deny mode** (default): blocks ``deny_syscalls``, allows everything
      else.  Uses ``DEFAULT_DENY_SYSCALLS`` when ``deny_syscalls`` is None
      and ``allow_syscalls`` is not set.
    - **Allow mode**: allows only ``allow_syscalls``, blocks everything
      else.  Enabled when ``allow_syscalls`` is provided.

    Args:
        deny_syscalls: Syscall names to block (blocklist mode).
        allow_syscalls: Syscall names to allow (allowlist mode).

    Raises:
        SeccompError: If filter installation fails.
        ValueError: If both deny_syscalls and allow_syscalls are provided.
    """
    if deny_syscalls is not None and allow_syscalls is not None:
        raise ValueError("Cannot set both deny_syscalls and allow_syscalls")

    if allow_syscalls is not None:
        allow_nrs = [nr for name in allow_syscalls
                     if (nr := _SYSCALL_NR.get(name)) is not None]
        if not allow_nrs:
            return
        filter_bytes = _build_allow_filter(allow_nrs)
    else:
        if deny_syscalls is None:
            deny_syscalls = DEFAULT_DENY_SYSCALLS
        deny_nrs = [nr for name in deny_syscalls
                    if (nr := _SYSCALL_NR.get(name)) is not None]
        if not deny_nrs:
            return
        filter_bytes = _build_deny_filter(deny_nrs)
    n_insns = len(filter_bytes) // 8  # Each instruction is 8 bytes

    # Create filter buffer
    buf = ctypes.create_string_buffer(filter_bytes)
    prog = _SockFprog()
    prog.len = n_insns
    prog.filter = ctypes.addressof(buf)

    # PR_SET_NO_NEW_PRIVS must already be set (Landlock sets it too)
    # Set it again in case Landlock was skipped
    ret = _libc.prctl(
        ctypes.c_int(PR_SET_NO_NEW_PRIVS),
        ctypes.c_ulong(1),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if ret < 0:
        err = ctypes.get_errno()
        raise SeccompError(f"prctl(PR_SET_NO_NEW_PRIVS): {os.strerror(err)}")

    # Install filter
    ret = _libc.prctl(
        ctypes.c_int(PR_SET_SECCOMP),
        ctypes.c_ulong(SECCOMP_MODE_FILTER),
        ctypes.cast(ctypes.byref(prog), ctypes.c_void_p),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if ret < 0:
        err = ctypes.get_errno()
        raise SeccompError(f"prctl(PR_SET_SECCOMP): {os.strerror(err)}")
