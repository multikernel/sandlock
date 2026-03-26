# SPDX-License-Identifier: Apache-2.0
"""Seccomp user notification supervisor.

Installs a SECCOMP_RET_USER_NOTIF filter for filesystem syscalls
(open/openat) and runs a supervisor thread that intercepts these
calls, reads the path argument from the child's memory, and applies
policy decisions (allow, deny, or virtualize with fake content).

Requires Linux 5.9+ for SECCOMP_IOCTL_NOTIF_ADDFD (virtualization).
ALLOW and DENY work on Linux 5.6+.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import select
import signal
import socket
from pathlib import Path
import struct
import threading
from typing import Optional

from .exceptions import NotifError
from ._notif_policy import NotifAction, NotifPolicy
from ._procfs import read_bytes, read_cstring, write_bytes, resolve_openat_path
from ._seccomp import (
    AUDIT_ARCH,
    BPF_ABS,
    BPF_JEQ,
    BPF_JMP,
    BPF_K,
    BPF_LD,
    BPF_RET,
    BPF_W,
    OFFSET_ARCH,
    OFFSET_NR,
    SECCOMP_FILTER_FLAG_NEW_LISTENER,
    SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_USER_NOTIF,
    SECCOMP_SET_MODE_FILTER,
    _SYSCALL_NR,
    _SockFprog,
    _bpf_jump,
    _bpf_stmt,
    _build_arch_check,
    _build_arg_filters,
    ERRNO_EPERM,
)


_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# ioctl commands for seccomp user notification.
# Computed from _IOC(dir, type=0x21, nr, size):
#   _IOC_WRITE=1, _IOC_READ=2  (on both x86_64 and aarch64)
#   _IOC(dir, type, nr, size) = (dir<<30) | (size<<16) | (type<<8) | nr
_IOC_WRITE = 1
_IOC_READ = 2


def _ioc(direction: int, nr: int, size: int) -> int:
    return (direction << 30) | (size << 16) | (0x21 << 8) | nr


# struct seccomp_notif: id(u64) + pid(u32) + flags(u32) + seccomp_data(64) = 80
_SECCOMP_NOTIF_SIZE = 80
# struct seccomp_notif_resp: id(u64) + val(s64) + error(s32) + flags(u32) = 24
_SECCOMP_NOTIF_RESP_SIZE = 24
# struct seccomp_notif_addfd: id(u64) + flags(u32) + srcfd(u32) + newfd(u32) + newfd_flags(u32) = 24
_SECCOMP_NOTIF_ADDFD_SIZE = 24

SECCOMP_IOCTL_NOTIF_RECV = _ioc(_IOC_WRITE | _IOC_READ, 0, _SECCOMP_NOTIF_SIZE)
SECCOMP_IOCTL_NOTIF_SEND = _ioc(_IOC_WRITE | _IOC_READ, 1, _SECCOMP_NOTIF_RESP_SIZE)
SECCOMP_IOCTL_NOTIF_ID_VALID = _ioc(_IOC_WRITE, 2, 8)  # u64
SECCOMP_IOCTL_NOTIF_ADDFD = _ioc(_IOC_WRITE | _IOC_READ, 3, _SECCOMP_NOTIF_ADDFD_SIZE)
SECCOMP_IOCTL_NOTIF_SET_FLAGS = _ioc(_IOC_WRITE, 4, 8)  # u64, Linux 6.7+

# Response flag: let the original syscall proceed in the kernel
SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1

# Notification fd flag: wake child on supervisor's CPU (4x latency reduction)
SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP = 1 << 0


# --- ctypes structs ---

class _SeccompData(ctypes.Structure):
    """struct seccomp_data (64 bytes)."""
    _fields_ = [
        ("nr", ctypes.c_int32),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]


class SeccompNotif(ctypes.Structure):
    """struct seccomp_notif (80 bytes)."""
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("data", _SeccompData),
    ]


class SeccompNotifResp(ctypes.Structure):
    """struct seccomp_notif_resp (24 bytes)."""
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("val", ctypes.c_int64),
        ("error", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
    ]


class SeccompNotifAddfd(ctypes.Structure):
    """struct seccomp_notif_addfd (24 bytes)."""
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("srcfd", ctypes.c_uint32),
        ("newfd", ctypes.c_uint32),
        ("newfd_flags", ctypes.c_uint32),
    ]


# --- Filter installation ---

def _build_combined_filter(
    notify_nrs: list[int],
    deny_nrs: list[int],
    *,
    no_raw_sockets: bool = True,
    no_udp: bool = False,
) -> bytes:
    """Build a single cBPF filter that handles notif + deny + arg checks.

    One filter eliminates the stacked-filter CONTINUE re-evaluation issue.

    Filter logic:
        1. Check arch (kill if wrong)
        2. Arg-level filters (clone NS flags → ERRNO, ioctl TIOCSTI → ERRNO)
        3. Load syscall number
        4. For each notif syscall → USER_NOTIF
        5. For each denied syscall → ERRNO
        6. Default → ALLOW
    """
    insns = bytearray()

    # 1. Arch check
    insns += _build_arch_check()

    # 2. Arg-level filters (clone namespace flags, ioctl TIOCSTI, socket types)
    insns += _build_arg_filters(no_raw_sockets=no_raw_sockets, no_udp=no_udp)

    # 3. Load syscall number
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR)

    # 4. Notif syscalls → USER_NOTIF
    # Jump targets: need to skip past both notif checks, deny checks,
    # and the ALLOW instruction to reach the USER_NOTIF return.
    n_deny = len(deny_nrs)
    for i, nr in enumerate(notify_nrs):
        remaining_notif = len(notify_nrs) - i - 1
        # jt: skip remaining notif checks + all deny checks + ALLOW
        jt = remaining_notif + n_deny + 1
        insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, jt, 0)

    # 5. Denied syscalls → ERRNO
    for i, nr in enumerate(deny_nrs):
        remaining_deny = n_deny - i - 1
        # jt: skip remaining deny checks + ALLOW + USER_NOTIF to reach ERRNO
        jt = remaining_deny + 2
        insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, jt, 0)

    # 6. Returns
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ERRNO_EPERM)

    return bytes(insns)


def install_notif_filter(
    syscall_names: list[str],
    deny_syscalls: list[str] | None = None,
    allow_syscalls: list[str] | None = None,
    *,
    no_raw_sockets: bool = True,
    no_udp: bool = False,
) -> int:
    """Install a combined seccomp filter with notif + deny in one program.

    Uses the seccomp(2) syscall with SECCOMP_FILTER_FLAG_NEW_LISTENER.
    A single filter avoids the stacked-filter CONTINUE re-evaluation issue.

    Args:
        syscall_names: Syscall names to intercept via USER_NOTIF.
        deny_syscalls: Syscall names to block with ERRNO.  Defaults to
            DEFAULT_DENY_SYSCALLS.
        allow_syscalls: If set, only these syscalls are allowed (allowlist
            mode).  Mutually exclusive with deny_syscalls.
        no_raw_sockets: Block SOCK_RAW on AF_INET/AF_INET6 (default True).
        no_udp: Block SOCK_DGRAM on AF_INET/AF_INET6 (default False).

    Returns:
        The notification file descriptor.

    Raises:
        NotifError: If installation fails.
    """
    from ._seccomp import DEFAULT_DENY_SYSCALLS

    notify_nrs = []
    for name in syscall_names:
        nr = _SYSCALL_NR.get(name)
        if nr is not None:
            notify_nrs.append(nr)

    if not notify_nrs:
        raise NotifError("No valid syscall names to intercept")

    # Build deny list (exclude syscalls already in the notif list)
    notify_nr_set = set(notify_nrs)
    if allow_syscalls is not None:
        # Allowlist mode: deny everything not in the allowlist or notif list
        allow_nrs = set()
        for name in allow_syscalls:
            nr = _SYSCALL_NR.get(name)
            if nr is not None:
                allow_nrs.add(nr)
        # In allowlist mode, we can't enumerate all syscalls to deny.
        # Use the deny filter for the allowlist separately after this.
        deny_nrs = []
    else:
        if deny_syscalls is None:
            deny_syscalls = DEFAULT_DENY_SYSCALLS
        deny_nrs = [nr for name in deny_syscalls
                     if (nr := _SYSCALL_NR.get(name)) is not None
                     and nr not in notify_nr_set]

    filter_bytes = _build_combined_filter(
        notify_nrs, deny_nrs,
        no_raw_sockets=no_raw_sockets, no_udp=no_udp,
    )
    n_insns = len(filter_bytes) // 8

    buf = ctypes.create_string_buffer(filter_bytes)
    prog = _SockFprog()
    prog.len = n_insns
    prog.filter = ctypes.addressof(buf)

    # seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog)
    # WAIT_KILLABLE_RECV (5.19+) prevents signals from aborting
    # notifications while the supervisor is handling them.
    __NR_seccomp = _SYSCALL_NR["seccomp"]
    flags = SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
    fd = _libc.syscall(
        ctypes.c_long(__NR_seccomp),
        ctypes.c_uint(SECCOMP_SET_MODE_FILTER),
        ctypes.c_uint(flags),
        ctypes.byref(prog),
    )
    if fd < 0:
        # Fall back without WAIT_KILLABLE_RECV on older kernels
        fd = _libc.syscall(
            ctypes.c_long(__NR_seccomp),
            ctypes.c_uint(SECCOMP_SET_MODE_FILTER),
            ctypes.c_uint(SECCOMP_FILTER_FLAG_NEW_LISTENER),
            ctypes.byref(prog),
        )
    if fd < 0:
        err = ctypes.get_errno()
        raise NotifError(f"seccomp(SET_MODE_FILTER, NEW_LISTENER): {os.strerror(err)}")

    return fd


# --- SCM_RIGHTS fd passing ---

def send_fd(sock: socket.socket, fd: int) -> None:
    """Send a file descriptor over a Unix socket via SCM_RIGHTS."""
    sock.sendmsg(
        [b"\x00"],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))],
    )


def recv_fd(sock: socket.socket) -> int:
    """Receive a file descriptor from a Unix socket via SCM_RIGHTS."""
    msg, ancdata, flags, addr = sock.recvmsg(
        1, socket.CMSG_SPACE(struct.calcsize("i"))
    )
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            return struct.unpack("i", cmsg_data[:struct.calcsize("i")])[0]
    raise NotifError("No fd received via SCM_RIGHTS")


# --- memfd helper ---

_NR_MEMFD_CREATE = _SYSCALL_NR.get("memfd_create", 319)


def _memfd_create(name: str) -> int:
    """Create an anonymous file via memfd_create(2)."""
    name_bytes = name.encode() + b"\0"
    buf = ctypes.create_string_buffer(name_bytes)
    fd = _libc.syscall(
        ctypes.c_long(_NR_MEMFD_CREATE),
        buf,
        ctypes.c_uint(0),
    )
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"memfd_create: {os.strerror(err)}")
    return fd


# --- sockaddr parsing ---

# struct sockaddr_in  { sa_family_t (u16), in_port_t (u16), in_addr (4 bytes), ... }
# struct sockaddr_in6 { sa_family_t (u16), in_port_t (u16), flowinfo (u32), in6_addr (16 bytes), ... }
_AF_INET = 2
_AF_INET6 = 10



# --- getdents64 helpers ---

def _build_dirent64(d_ino: int, d_off: int, d_type: int, name: str) -> bytes:
    """Build a single linux_dirent64 entry.

    struct linux_dirent64 {
        u64  d_ino;      // 0
        s64  d_off;      // 8
        u16  d_reclen;   // 16
        u8   d_type;     // 18
        char d_name[];   // 19+
    };
    d_reclen is 8-byte aligned.
    """
    name_bytes = name.encode("utf-8") + b"\0"
    # 19 bytes header + name + padding to 8-byte alignment
    reclen = 19 + len(name_bytes)
    reclen = (reclen + 7) & ~7  # align to 8
    buf = bytearray(reclen)
    struct.pack_into("QqHB", buf, 0, d_ino, d_off, reclen, d_type)
    buf[19:19 + len(name_bytes)] = name_bytes
    return bytes(buf)


def _build_filtered_dirents(sandbox_pids: set[int]) -> list[bytes]:
    """Build a list of dirent64 entries for /proc, filtering out foreign PIDs.

    Reads the real /proc directory in the supervisor process and builds
    synthetic dirent64 entries, excluding PID directories not in sandbox_pids.
    """
    DT_DIR = 4
    DT_REG = 8
    DT_LNK = 10
    entries = []
    d_off = 0
    try:
        with os.scandir("/proc") as it:
            for entry in it:
                name = entry.name
                # Filter out foreign PID directories
                if name.isdigit():
                    if int(name) not in sandbox_pids:
                        continue

                d_off += 1
                try:
                    if entry.is_dir(follow_symlinks=False):
                        d_type = DT_DIR
                    elif entry.is_symlink():
                        d_type = DT_LNK
                    else:
                        d_type = DT_REG
                except OSError:
                    d_type = DT_REG

                try:
                    d_ino = entry.inode()
                except OSError:
                    d_ino = 0

                entries.append(_build_dirent64(d_ino, d_off, d_type, name))
    except OSError:
        pass
    return entries


# --- Notification supervisor ---

class NotifSupervisor:
    """Seccomp user notification supervisor.

    Runs a background thread that receives seccomp notifications for
    intercepted syscalls, reads the file path from the child's memory,
    applies policy rules, and responds (allow, deny, or virtualize).
    """

    def __init__(
        self,
        notify_fd: int,
        child_pid: int,
        policy: NotifPolicy,
        *,
        pids_fn: Optional[callable] = None,
        disk_quota_path: str | None = None,
        disk_quota_bytes: int = 0,
    ):
        self._notify_fd = notify_fd
        self._child_pid = child_pid
        self._policy = policy
        self._pids_fn = pids_fn
        self._disk_quota_path = disk_quota_path
        self._disk_quota_bytes = disk_quota_bytes
        self._cow_handler = None  # CowHandler | None
        # Deterministic randomness
        self._det_random = None  # DeterministicRandom | None
        if policy.random_seed is not None:
            from ._random import DeterministicRandom
            self._det_random = DeterministicRandom(policy.random_seed)
        # Deterministic time
        self._time_offset = None  # TimeOffset | None
        self._mono_offset_s: int = 0  # monotonic offset for vDSO stubs
        self._vdso_patched_addr: int = 0  # vDSO base address we last patched
        self._virtual_btime: int = 0  # virtual boot time for /proc/stat
        if policy.time_start is not None:
            import time as _time
            from ._time import TimeOffset
            self._time_offset = TimeOffset(policy.time_start)
            self._mono_offset_s = -int(_time.monotonic())
            self._virtual_btime = int(policy.time_start)
        self._thread: Optional[threading.Thread] = None
        self._stop_r, self._stop_w = os.pipe()
        # Resource state (memory, process count, fork-hold)
        from ._resource import ResourceState
        self._res = ResourceState(child_pid)
        # Aliases for backward compatibility
        self._proc_pids = self._res.proc_pids
        # getdents /proc filtering: fd → list of remaining dirent entries
        self._proc_dir_cache: dict[int, list[bytes]] = {}
        # Port virtualization (on-demand allocation from kernel)
        self._port_map = None  # PortMap | None
        if policy.port_remap:
            from ._port_remap import get_port_map
            self._port_map = get_port_map(proxy=True)
        # Fast-path flag: when only /proc hardening needs openat (no COW,
        # no time/random virtualization, no port remap), skip full path
        # resolution for non-/proc paths using a cheap prefix read.
        self._openat_fast_proc = (
            (policy.isolate_pids or policy.rules)
            and not policy.cow_enabled
            and policy.random_seed is None
            and policy.time_start is None
            and not policy.port_remap
            and not policy.allowed_ips
        )
        # Cached fd for fast /proc/pid/mem prefix reads
        self._mem_fd: int = -1
        self._mem_fd_pid: int = -1

    def start(self) -> None:
        """Start the supervisor thread."""
        # Enable synchronous wake-up mode (Linux 6.7+) for ~4x lower
        # notification latency.  Silently ignored on older kernels.
        flags = ctypes.c_uint64(SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP)
        _libc.ioctl(
            ctypes.c_int(self._notify_fd),
            ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_SET_FLAGS),
            ctypes.byref(flags),
        )
        self._thread = threading.Thread(
            target=self._run, name="sandlock-notif", daemon=True,
        )
        self._thread.start()

    def hold_forks(self) -> None:
        """Enter hold mode: fork/clone notifications are not responded to."""
        with self._res.hold_lock:
            self._res.hold_forks = True

    def release_forks(self) -> None:
        """Exit hold mode: respond CONTINUE to all held fork notifications."""
        with self._res.hold_lock:
            self._res.hold_forks = False
            for notif_id in self._res.held_notif_ids:
                try:
                    self._respond_continue(notif_id)
                except OSError:
                    pass
            self._res.held_notif_ids.clear()

    def stop(self) -> None:
        """Signal the supervisor to stop and wait for it."""
        self.release_forks()  # Unblock any held processes before stopping
        try:
            os.write(self._stop_w, b"x")
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        for fd in (self._notify_fd, self._stop_r, self._stop_w):
            try:
                os.close(fd)
            except OSError:
                pass
        self._notify_fd = -1
        self._stop_r = -1
        self._stop_w = -1
        if self._mem_fd >= 0:
            try:
                os.close(self._mem_fd)
            except OSError:
                pass
            self._mem_fd = -1
            self._mem_fd_pid = -1
        if self._port_map is not None:
            self._port_map.close()
            self._port_map = None

    def _check_disk_quota(self) -> None:
        """Check if overlay upper dir exceeds disk quota."""
        if not self._disk_quota_path:
            return
        try:
            from ._cow_base import dir_size
            from pathlib import Path
            used = dir_size(Path(self._disk_quota_path))
            if used > self._disk_quota_bytes:
                os.killpg(self._child_pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass

    @property
    def port_map(self):
        """PortMap for this sandbox, or None if port_remap is disabled."""
        return self._port_map

    def _run(self) -> None:
        """Supervisor event loop."""
        import time
        poller = select.poll()
        poller.register(self._notify_fd, select.POLLIN)
        poller.register(self._stop_r, select.POLLIN)
        last_quota_check = 0.0

        while True:
            try:
                events = poller.poll(1000)
            except OSError:
                break

            if self._disk_quota_bytes > 0:
                now = time.monotonic()
                if now - last_quota_check >= 1.0:
                    self._check_disk_quota()
                    last_quota_check = now

            for fd, event in events:
                if fd == self._stop_r:
                    return
                if fd == self._notify_fd:
                    if event & (select.POLLHUP | select.POLLERR):
                        return
                    if event & select.POLLIN:
                        self._handle_one()

    def _handle_one(self) -> None:
        """Receive one notification, apply policy, respond."""
        notif = SeccompNotif()
        ret = _libc.ioctl(
            ctypes.c_int(self._notify_fd),
            ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_RECV),
            ctypes.byref(notif),
        )
        if ret < 0:
            return  # ENOENT = child died, EINTR = interrupted

        # Patch vDSO before dispatching (child is stopped in seccomp
        # notification state, so /proc/pid/mem writes are reliable).
        # Re-patch when the vDSO address changes (exec replaces the vDSO).
        if self._time_offset is not None:
            self._maybe_patch_vdso(notif.pid)

        try:
            self._dispatch(notif)
        except Exception:
            # Safety net: never leave a notification without a response,
            # otherwise the child blocks forever.
            try:
                self._respond_continue(notif.id)
            except Exception:
                pass

    @property
    def tracked_pids(self) -> set[int]:
        """All PIDs known to belong to this sandbox."""
        return set(self._proc_pids)

    def _maybe_patch_vdso(self, pid: int) -> None:
        """Patch the child's vDSO to force real syscalls, if needed.

        Called while the child is stopped in seccomp notification state,
        so /proc/pid/mem writes land reliably before the child resumes.
        Tracks the vDSO base address to detect exec (which replaces the
        vDSO at a new address) and re-patch automatically.
        """
        from ._vdso import _find_vdso, _parse_vdso_symbols, _get_stubs
        info = _find_vdso(pid)
        if not info:
            return
        addr, size = info
        if addr == self._vdso_patched_addr:
            return  # already patched this vDSO
        stubs = _get_stubs(self._mono_offset_s)
        if not stubs:
            return
        try:
            fd = os.open(f"/proc/{pid}/mem", os.O_RDWR)
            try:
                os.lseek(fd, addr, os.SEEK_SET)
                data = os.read(fd, size)
                for name, off in _parse_vdso_symbols(data):
                    stub = stubs.get(name)
                    if stub:
                        os.lseek(fd, addr + off, os.SEEK_SET)
                        os.write(fd, stub)
                self._vdso_patched_addr = addr
            finally:
                os.close(fd)
        except OSError:
            pass

    def _dispatch(self, notif: SeccompNotif) -> None:
        """Route a notification to the appropriate handler."""
        # Lazily track every PID that makes an intercepted syscall
        pid = notif.pid
        self._proc_pids.add(pid)
        nr = notif.data.nr


        # --- Deterministic randomness ---
        if self._det_random is not None:
            from ._random import NR_GETRANDOM, handle_getrandom
            if nr == NR_GETRANDOM:
                handle_getrandom(notif, self._det_random,
                                 self._id_valid, self._respond_val,
                                 self._respond_continue)
                return

        # --- Deterministic time ---
        if self._time_offset is not None:
            from ._time import TIME_NRS, handle_time
            if nr in TIME_NRS:
                handle_time(notif, nr, self._time_offset,
                            self._id_valid, self._respond_val,
                            self._respond_continue,
                            mono_offset_s=self._mono_offset_s)
                return

        # --- Resource: memory + process limits ---
        from ._resource import MEMORY_NRS, FORK_NRS, handle_memory, handle_fork

        if nr in MEMORY_NRS and self._policy.max_memory_bytes > 0:
            handle_memory(notif, nr, self._res,
                          self._policy.max_memory_bytes,
                          self._respond_continue, self._respond_errno)
            return

        if nr in FORK_NRS:
            handle_fork(notif, nr, self._res,
                        self._policy.max_processes,
                        self._respond_continue, self._respond_errno,
                        self._proc_dir_cache.clear)
            return

        # --- Port remapping: bind / connect / getsockname ---
        nr_bind = _SYSCALL_NR.get("bind")
        nr_connect = _SYSCALL_NR.get("connect")
        nr_getsockname = _SYSCALL_NR.get("getsockname")

        if self._port_map is not None and nr in (nr_bind, nr_connect):
            self._handle_port_remap(notif, nr)
            return

        if self._port_map is not None and nr == nr_getsockname:
            self._handle_getsockname(notif)
            return

        # --- Network: connect / sendto / sendmsg IP enforcement ---
        from ._network import NET_NRS, handle_net

        if nr in NET_NRS and self._policy.allowed_ips:
            handle_net(notif, nr, self._policy.allowed_ips,
                       self._id_valid, self._respond_continue,
                       self._respond_errno)
            return

        # --- /proc readdir PID filtering + COW dir merging ---
        nr_getdents64 = _SYSCALL_NR.get("getdents64")
        nr_getdents = _SYSCALL_NR.get("getdents")

        if nr in (nr_getdents64, nr_getdents) and self._cow_handler is not None:
            # Fast path: no changes yet → kernel handles readdir correctly
            if not self._cow_handler._branch.has_changes:
                self._respond_continue(notif.id)
                return
            child_fd_num = notif.data.args[0] & 0xFFFFFFFF
            try:
                target = os.readlink(f"/proc/{pid}/fd/{child_fd_num}")
            except OSError:
                target = ""
            if self._cow_handler.matches(target):
                from .cowfs._notif_handler import handle_cow_getdents
                handle_cow_getdents(notif, target, self._cow_handler,
                                    self._proc_dir_cache, self._id_valid,
                                    self._respond_val, self._respond_continue,
                                    _build_dirent64)
                return

        if nr in (nr_getdents64, nr_getdents) and self._policy.isolate_pids:
            self._handle_getdents(notif)
            return

        # --- COW: filesystem modification syscalls ---
        if self._cow_handler is not None:
            nr_unlinkat = _SYSCALL_NR.get("unlinkat")
            nr_unlink = _SYSCALL_NR.get("unlink")
            nr_rmdir = _SYSCALL_NR.get("rmdir")
            nr_mkdirat = _SYSCALL_NR.get("mkdirat")
            nr_mkdir = _SYSCALL_NR.get("mkdir")
            nr_renameat2 = _SYSCALL_NR.get("renameat2")
            nr_rename = _SYSCALL_NR.get("rename")
            nr_newfstatat = _SYSCALL_NR.get("newfstatat")
            nr_statx = _SYSCALL_NR.get("statx")
            nr_faccessat = _SYSCALL_NR.get("faccessat")
            nr_stat = _SYSCALL_NR.get("stat")
            nr_lstat = _SYSCALL_NR.get("lstat")
            nr_access = _SYSCALL_NR.get("access")
            nr_symlinkat = _SYSCALL_NR.get("symlinkat")
            nr_symlink = _SYSCALL_NR.get("symlink")
            nr_linkat = _SYSCALL_NR.get("linkat")
            nr_link = _SYSCALL_NR.get("link")
            nr_fchmodat = _SYSCALL_NR.get("fchmodat")
            nr_chmod = _SYSCALL_NR.get("chmod")
            nr_fchownat = _SYSCALL_NR.get("fchownat")
            nr_chown = _SYSCALL_NR.get("chown")
            nr_lchown = _SYSCALL_NR.get("lchown")
            nr_readlinkat = _SYSCALL_NR.get("readlinkat")
            nr_readlink = _SYSCALL_NR.get("readlink")
            nr_truncate = _SYSCALL_NR.get("truncate")
            nr_utimensat = _SYSCALL_NR.get("utimensat")
            nr_futimesat = _SYSCALL_NR.get("futimesat")

            # *at variants: dirfd=arg0, pathname=arg1
            cow_at_nrs = {nr_unlinkat, nr_mkdirat, nr_renameat2,
                          nr_newfstatat, nr_statx, nr_faccessat,
                          nr_fchmodat, nr_fchownat, nr_readlinkat,
                          nr_utimensat} - {None}
            # non-at variants: pathname=arg0
            cow_plain_nrs = {nr_unlink, nr_rmdir, nr_mkdir, nr_rename,
                             nr_stat, nr_lstat, nr_access,
                             nr_chmod, nr_chown, nr_lchown,
                             nr_readlink, nr_truncate,
                             nr_futimesat} - {None}
            # Special arg layouts
            cow_special_nrs = {nr_symlinkat, nr_symlink,
                               nr_linkat, nr_link} - {None}
            # Read-only COW syscalls — can skip when no changes yet
            cow_readonly_nrs = {nr_newfstatat, nr_statx, nr_faccessat,
                                nr_stat, nr_lstat, nr_access,
                                nr_readlinkat, nr_readlink} - {None}

            # Fast path: read-only COW syscalls with no changes → let kernel handle
            if nr in cow_readonly_nrs and not self._cow_handler._branch.has_changes:
                self._respond_continue(notif.id)
                return

            # symlink/link have special arg layouts — handle separately
            if nr in cow_special_nrs:
                try:
                    if nr == nr_symlinkat:
                        # symlinkat(target, newdirfd, linkpath)
                        # target is a raw string (not resolved), linkpath is resolved
                        target_addr = notif.data.args[0]
                        target_str = read_cstring(pid, target_addr)
                        newdirfd = ctypes.c_int32(notif.data.args[1] & 0xFFFFFFFF).value
                        linkpath_addr = notif.data.args[2]
                        linkpath = resolve_openat_path(pid, newdirfd, linkpath_addr)
                    elif nr == nr_symlink:
                        # symlink(target, linkpath)
                        target_addr = notif.data.args[0]
                        target_str = read_cstring(pid, target_addr)
                        linkpath_addr = notif.data.args[1]
                        linkpath = resolve_openat_path(pid, -100, linkpath_addr)
                    elif nr == nr_linkat:
                        # linkat(olddirfd, oldpath, newdirfd, newpath, flags)
                        olddirfd = ctypes.c_int32(notif.data.args[0] & 0xFFFFFFFF).value
                        oldpath_addr = notif.data.args[1]
                        target_str = resolve_openat_path(pid, olddirfd, oldpath_addr)
                        newdirfd = ctypes.c_int32(notif.data.args[2] & 0xFFFFFFFF).value
                        newpath_addr = notif.data.args[3]
                        linkpath = resolve_openat_path(pid, newdirfd, newpath_addr)
                    elif nr == nr_link:
                        # link(oldpath, newpath)
                        oldpath_addr = notif.data.args[0]
                        target_str = resolve_openat_path(pid, -100, oldpath_addr)
                        newpath_addr = notif.data.args[1]
                        linkpath = resolve_openat_path(pid, -100, newpath_addr)
                    else:
                        self._respond_continue(notif.id)
                        return
                except OSError:
                    self._respond_continue(notif.id)
                    return

                if not self._id_valid(notif.id):
                    return

                if self._cow_handler.matches(linkpath):
                    if nr in (nr_symlinkat, nr_symlink):
                        if self._cow_handler.handle_symlink(target_str, linkpath):
                            self._respond_val(notif.id, 0)
                        else:
                            self._respond_continue(notif.id)
                    elif nr in (nr_linkat, nr_link):
                        if self._cow_handler.handle_link(target_str, linkpath):
                            self._respond_val(notif.id, 0)
                        else:
                            self._respond_continue(notif.id)
                    return

                self._respond_continue(notif.id)
                return

            if nr in cow_at_nrs or nr in cow_plain_nrs:
                try:
                    if nr in cow_at_nrs:
                        dirfd = ctypes.c_int32(notif.data.args[0] & 0xFFFFFFFF).value
                        pathname_addr = notif.data.args[1]
                        path = resolve_openat_path(pid, dirfd, pathname_addr)
                    else:
                        pathname_addr = notif.data.args[0]
                        path = resolve_openat_path(pid, -100, pathname_addr)
                except OSError:
                    self._respond_continue(notif.id)
                    return

                if not self._id_valid(notif.id):
                    return

                if self._cow_handler.matches(path):
                    # unlink / unlinkat / rmdir
                    if nr in (nr_unlinkat, nr_unlink, nr_rmdir):
                        is_dir = (nr == nr_rmdir or
                                  (nr == nr_unlinkat and
                                   bool(notif.data.args[2] & 0x200)))
                        if self._cow_handler.handle_unlink(path, is_dir=is_dir):
                            self._respond_val(notif.id, 0)
                        else:
                            self._respond_continue(notif.id)
                        return

                    # mkdir / mkdirat
                    if nr in (nr_mkdirat, nr_mkdir):
                        mode = notif.data.args[2] if nr == nr_mkdirat else notif.data.args[1]
                        if self._cow_handler.handle_mkdir(path, mode):
                            self._respond_val(notif.id, 0)
                        else:
                            self._respond_continue(notif.id)
                        return

                    # rename / renameat2
                    if nr in (nr_renameat2, nr_rename):
                        try:
                            if nr == nr_renameat2:
                                newdirfd = ctypes.c_int32(notif.data.args[2] & 0xFFFFFFFF).value
                                newpath_addr = notif.data.args[3]
                                new_path = resolve_openat_path(pid, newdirfd, newpath_addr)
                            else:
                                newpath_addr = notif.data.args[1]
                                new_path = resolve_openat_path(pid, -100, newpath_addr)
                        except OSError:
                            self._respond_continue(notif.id)
                            return
                        if self._cow_handler.handle_rename(path, new_path):
                            self._respond_val(notif.id, 0)
                        else:
                            self._respond_continue(notif.id)
                        return

                    # access / faccessat — just check existence
                    if nr in (nr_faccessat, nr_access):
                        real_path = self._cow_handler.handle_stat(path)
                        if real_path is None:
                            self._respond_errno(notif.id, errno.ENOENT)
                        else:
                            self._respond_continue(notif.id)
                        return

                    # stat / lstat / newfstatat — do stat ourselves,
                    # write result to child's buffer
                    if nr in (nr_newfstatat, nr_stat, nr_lstat):
                        real_path = self._cow_handler.handle_stat(path)
                        if real_path is None:
                            self._respond_errno(notif.id, errno.ENOENT)
                        else:
                            from .cowfs._notif_handler import handle_cow_stat
                            handle_cow_stat(notif, nr, real_path,
                                            self._id_valid, self._respond_val,
                                            self._respond_errno, self._respond_continue)
                        return

                    # statx — complex struct, let kernel handle if possible
                    if nr == nr_statx:
                        real_path = self._cow_handler.handle_stat(path)
                        if real_path is None:
                            self._respond_errno(notif.id, errno.ENOENT)
                        else:
                            self._respond_continue(notif.id)
                        return

                    # chmod / fchmodat
                    if nr in (nr_fchmodat, nr_chmod):
                        mode = notif.data.args[2] if nr == nr_fchmodat else notif.data.args[1]
                        if self._cow_handler.handle_chmod(path, mode & 0o7777):
                            self._respond_val(notif.id, 0)
                        else:
                            self._respond_continue(notif.id)
                        return

                    # chown / fchownat / lchown
                    if nr in (nr_fchownat, nr_chown, nr_lchown):
                        if nr == nr_fchownat:
                            uid = ctypes.c_int32(notif.data.args[2] & 0xFFFFFFFF).value
                            gid = ctypes.c_int32(notif.data.args[3] & 0xFFFFFFFF).value
                            follow = not bool(notif.data.args[4] & 0x100)  # AT_SYMLINK_NOFOLLOW
                        elif nr == nr_chown:
                            uid = ctypes.c_int32(notif.data.args[1] & 0xFFFFFFFF).value
                            gid = ctypes.c_int32(notif.data.args[2] & 0xFFFFFFFF).value
                            follow = True
                        else:  # lchown
                            uid = ctypes.c_int32(notif.data.args[1] & 0xFFFFFFFF).value
                            gid = ctypes.c_int32(notif.data.args[2] & 0xFFFFFFFF).value
                            follow = False
                        if self._cow_handler.handle_chown(path, uid, gid,
                                                          follow_symlinks=follow):
                            self._respond_val(notif.id, 0)
                        else:
                            self._respond_continue(notif.id)
                        return

                    # utimensat / futimesat
                    if nr in (nr_utimensat, nr_futimesat):
                        UTIME_NOW = (1 << 30) - 1
                        UTIME_OMIT = (1 << 30) - 2
                        times = None  # default: current time
                        if nr == nr_utimensat:
                            # utimensat(dirfd, path, times[2], flags)
                            times_addr = notif.data.args[2]
                            follow = not bool(notif.data.args[3] & 0x100)
                            if times_addr != 0:
                                from ._procfs import read_bytes as _read
                                raw = _read(pid, times_addr, 32)
                                a_s, a_ns = struct.unpack_from("<qQ", raw, 0)
                                m_s, m_ns = struct.unpack_from("<qQ", raw, 16)
                                atime = None if a_ns == UTIME_OMIT else (
                                    None if a_ns == UTIME_NOW else a_s + a_ns / 1e9)
                                mtime = None if m_ns == UTIME_OMIT else (
                                    None if m_ns == UTIME_NOW else m_s + m_ns / 1e9)
                                if atime is not None or mtime is not None:
                                    # Need current stat for OMIT fields
                                    real = self._cow_handler.handle_stat(path)
                                    if real:
                                        st = os.stat(real)
                                        if atime is None:
                                            atime = st.st_atime
                                        if mtime is None:
                                            mtime = st.st_mtime
                                    times = (atime or 0, mtime or 0)
                                # both UTIME_NOW → times=None (current time)
                        else:
                            # futimesat(dirfd, path, times[2])
                            times_addr = notif.data.args[2]
                            follow = True
                            if times_addr != 0:
                                from ._procfs import read_bytes as _read
                                raw = _read(pid, times_addr, 32)
                                a_s, a_us = struct.unpack_from("<qQ", raw, 0)
                                m_s, m_us = struct.unpack_from("<qQ", raw, 16)
                                times = (a_s + a_us / 1e6,
                                         m_s + m_us / 1e6)
                        if self._cow_handler.handle_utimens(path, times,
                                                            follow_symlinks=follow):
                            self._respond_val(notif.id, 0)
                        else:
                            self._respond_continue(notif.id)
                        return

                    # truncate (path-based)
                    if nr == nr_truncate:
                        length = notif.data.args[1]
                        if self._cow_handler.handle_truncate(path, length):
                            self._respond_val(notif.id, 0)
                        else:
                            self._respond_continue(notif.id)
                        return

                    # readlink / readlinkat
                    if nr in (nr_readlinkat, nr_readlink):
                        target = self._cow_handler.handle_readlink(path)
                        if target is not None:
                            from .cowfs._notif_handler import handle_cow_readlink
                            handle_cow_readlink(notif, nr, target,
                                                self._id_valid, self._respond_val,
                                                self._respond_continue)
                        else:
                            self._respond_errno(notif.id, errno.EINVAL)
                        return

                self._respond_continue(notif.id)
                return

        # --- COW: execve / execveat path redirection ---
        if self._cow_handler is not None:
            nr_execve = _SYSCALL_NR.get("execve")
            nr_execveat = _SYSCALL_NR.get("execveat")

            if nr in (nr_execve, nr_execveat):
                try:
                    if nr == nr_execve:
                        # execve(pathname, argv, envp)
                        pathname_addr = notif.data.args[0]
                        path = resolve_openat_path(pid, -100, pathname_addr)
                    else:
                        # execveat(dirfd, pathname, argv, envp, flags)
                        dirfd = ctypes.c_int32(notif.data.args[0] & 0xFFFFFFFF).value
                        exec_flags = notif.data.args[4]
                        if exec_flags & 0x1000:  # AT_EMPTY_PATH — fd-based, no path
                            self._respond_continue(notif.id)
                            return
                        pathname_addr = notif.data.args[1]
                        path = resolve_openat_path(pid, dirfd, pathname_addr)
                except OSError:
                    self._respond_continue(notif.id)
                    return

                if not self._id_valid(notif.id):
                    return

                if not self._cow_handler.matches(path):
                    self._respond_continue(notif.id)
                    return

                # Resolve through COW layer
                real_path = self._cow_handler.handle_stat(path)
                if real_path is None:
                    # File deleted in COW
                    self._respond_errno(notif.id, errno.ENOENT)
                    return

                # If unchanged (real_path == path), let kernel handle it
                if real_path == path:
                    self._respond_continue(notif.id)
                    return

                # File is in upper layer — inject fd then rewrite path
                try:
                    src_fd = os.open(real_path, os.O_RDONLY | os.O_CLOEXEC)
                except OSError:
                    self._respond_continue(notif.id)
                    return

                try:
                    child_fd = self._inject_fd(notif.id, src_fd, cloexec=False)
                finally:
                    os.close(src_fd)

                if child_fd < 0:
                    self._respond_continue(notif.id)
                    return

                # Overwrite the pathname in child memory with /proc/self/fd/N
                proc_path = f"/proc/self/fd/{child_fd}\0".encode()
                try:
                    write_bytes(pid, pathname_addr, proc_path)
                except OSError:
                    self._respond_continue(notif.id)
                    return

                self._respond_continue(notif.id)
                return

        # --- Filesystem: open / openat virtualization + COW ---
        nr_openat = _SYSCALL_NR.get("openat")
        nr_open = _SYSCALL_NR.get("open")

        try:
            if nr == nr_openat:
                dirfd = ctypes.c_int32(notif.data.args[0] & 0xFFFFFFFF).value
                pathname_addr = notif.data.args[1]
                flags = notif.data.args[2]
                # Fast path: when only /proc hardening needs openat,
                # read a 6-byte prefix to skip non-/proc paths without
                # full path resolution.  Uses a cached fd to avoid
                # open/close overhead per call.
                if self._openat_fast_proc:
                    AT_FDCWD = -100
                    if dirfd == AT_FDCWD or dirfd == AT_FDCWD & 0xFFFFFFFF:
                        try:
                            if self._mem_fd_pid != pid:
                                if self._mem_fd >= 0:
                                    os.close(self._mem_fd)
                                self._mem_fd = os.open(
                                    f"/proc/{pid}/mem", os.O_RDONLY)
                                self._mem_fd_pid = pid
                            prefix = os.pread(self._mem_fd, 6, pathname_addr)
                        except OSError:
                            self._mem_fd = -1
                            self._mem_fd_pid = -1
                            self._respond_continue(notif.id)
                            return
                        if prefix != b"/proc/" and prefix[:5] != b"/proc":
                            self._respond_continue(notif.id)
                            return
                path = resolve_openat_path(pid, dirfd, pathname_addr)
            elif nr == nr_open:
                pathname_addr = notif.data.args[0]
                flags = notif.data.args[1]
                if self._openat_fast_proc:
                    try:
                        if self._mem_fd_pid != pid:
                            if self._mem_fd >= 0:
                                os.close(self._mem_fd)
                            self._mem_fd = os.open(
                                f"/proc/{pid}/mem", os.O_RDONLY)
                            self._mem_fd_pid = pid
                        prefix = os.pread(self._mem_fd, 6, pathname_addr)
                    except OSError:
                        self._mem_fd = -1
                        self._mem_fd_pid = -1
                        self._respond_continue(notif.id)
                        return
                    if prefix != b"/proc/" and prefix[:5] != b"/proc":
                        self._respond_continue(notif.id)
                        return
                path = resolve_openat_path(pid, -100, pathname_addr)  # AT_FDCWD
            else:
                self._respond_continue(notif.id)
                return
        except OSError:
            self._respond_continue(notif.id)
            return

        # TOCTTOU check: verify notification is still valid
        if not self._id_valid(notif.id):
            return

        # --- Deterministic /dev/urandom, /dev/random ---
        if self._det_random is not None and path in ("/dev/urandom", "/dev/random"):
            from ._random import make_dev_random_fd
            fd = make_dev_random_fd(self._policy.random_seed)
            try:
                self._respond_addfd(notif.id, fd)
            finally:
                os.close(fd)
            return

        # --- Virtualize /proc/uptime for time virtualization ---
        if self._mono_offset_s != 0 and path == "/proc/uptime":
            import time as _time
            uptime = _time.monotonic() + self._mono_offset_s
            if uptime < 0:
                uptime = 0.0
            content = f"{uptime:.2f} 0.00\n".encode()
            r, w = os.pipe()
            os.write(w, content)
            os.close(w)
            try:
                self._respond_addfd(notif.id, r)
            finally:
                os.close(r)
            return

        # --- Virtualize /proc/stat btime for time virtualization ---
        if self._time_offset is not None and path == "/proc/stat":
            virtual_btime = self._virtual_btime
            try:
                with open("/proc/stat", "rb") as f:
                    lines = f.readlines()
                out = []
                for line in lines:
                    if line.startswith(b"btime "):
                        out.append(f"btime {virtual_btime}\n".encode())
                    else:
                        out.append(line)
                content = b"".join(out)
                r, w = os.pipe()
                os.write(w, content)
                os.close(w)
                try:
                    self._respond_addfd(notif.id, r)
                finally:
                    os.close(r)
                return
            except OSError:
                pass

        # --- COW: redirect opens under workdir to upper dir ---
        if self._cow_handler is not None and self._cow_handler.matches(path):
            # Fast path: read-only open with no changes → kernel handles it
            from .cowfs._handler import _WRITE_FLAGS, O_DIRECTORY
            is_read_only = not (flags & (_WRITE_FLAGS | O_DIRECTORY))
            if is_read_only and not self._cow_handler._branch.has_changes:
                self._respond_continue(notif.id)
                return
            from .cowfs._notif_handler import handle_cow_open
            handle_cow_open(notif, path, flags, self._cow_handler,
                            self._respond_continue, self._respond_addfd)
            return

        # Virtualize /proc/net/* to hide host and other sandboxes' info
        if self._port_map is not None and (
            path.endswith("/net/tcp") or path.endswith("/net/tcp6")
        ):
            content = self._filter_proc_net_tcp(path)
            self._respond_virtualize(notif.id, content)
            return

        _NET_HIDE = ("/net/unix", "/net/udp", "/net/udp6",
                     "/net/raw", "/net/raw6")
        if self._port_map is not None and any(
            path.endswith(suffix) for suffix in _NET_HIDE
        ):
            content = self._filter_proc_net_header_only(path)
            self._respond_virtualize(notif.id, content)
            return

        # Apply policy (with sandbox pid set for isolation)
        sandbox_pids = None
        if self._policy.isolate_pids and self._pids_fn is not None:
            sandbox_pids = set(self._pids_fn())
        action, errno_code, virtual_content = self._policy.decide(
            path, sandbox_pids=sandbox_pids,
        )

        if action == NotifAction.ALLOW:
            self._respond_continue(notif.id)
        elif action == NotifAction.DENY:
            self._respond_errno(notif.id, errno_code)
        elif action == NotifAction.VIRTUALIZE:
            self._respond_virtualize(notif.id, virtual_content)

    # COW handlers moved to cowfs/_notif_handler.py

    def _respond_addfd(self, notif_id: int, src_fd: int) -> None:
        """Inject an open fd into the child and return it as the syscall result."""
        addfd = SeccompNotifAddfd()
        addfd.id = notif_id
        addfd.flags = 0
        addfd.srcfd = src_fd
        addfd.newfd = 0
        addfd.newfd_flags = 0

        ret = _libc.ioctl(
            ctypes.c_int(self._notify_fd),
            ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_ADDFD),
            ctypes.byref(addfd),
        )
        if ret < 0:
            self._respond_continue(notif_id)
            return

        child_fd = ret
        resp = SeccompNotifResp()
        resp.id = notif_id
        resp.val = child_fd
        resp.error = 0
        resp.flags = 0
        _libc.ioctl(
            ctypes.c_int(self._notify_fd),
            ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_SEND),
            ctypes.byref(resp),
        )

    def _inject_fd(self, notif_id: int, src_fd: int,
                   cloexec: bool = False) -> int:
        """Inject an fd into the child without completing the notification.

        Returns the fd number in the child's table, or -1 on failure.
        """
        addfd = SeccompNotifAddfd()
        addfd.id = notif_id
        addfd.flags = 0  # Don't auto-send response
        addfd.srcfd = src_fd
        addfd.newfd = 0
        addfd.newfd_flags = os.O_CLOEXEC if cloexec else 0

        ret = _libc.ioctl(
            ctypes.c_int(self._notify_fd),
            ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_ADDFD),
            ctypes.byref(addfd),
        )
        return ret

    # Network, memory, and fork handlers moved to _network.py and _resource.py

    def _handle_port_remap(self, notif: SeccompNotif, nr: int) -> None:
        """Handle bind/connect — rewrite port in child's sockaddr.

        For bind: remaps virtual port to a real port from the pool.
        For connect: remaps virtual port, and blocks connections to
        other sandboxes' ports (prevents port scanning).
        """
        from ._port_remap import _remap_sockaddr
        from ._seccomp import _SYSCALL_NR

        sockaddr_addr = notif.data.args[1]
        addrlen = notif.data.args[2] & 0xFFFFFFFF

        try:
            _remap_sockaddr(notif.pid, sockaddr_addr, addrlen, self._port_map)
        except OSError:
            pass

        self._respond_continue(notif.id)

    def _filter_proc_net_tcp(self, path: str) -> bytes:
        """Read /proc/net/tcp{,6} and filter to only show our ports.

        Keeps the header line and lines where the local port belongs
        to this sandbox's allocated slice.  Other sandboxes' ports and
        host ports are hidden.
        """
        # Normalize to canonical path (resolve /proc/net → /proc/self/net)
        canonical = path.replace("/proc/net/", "/proc/self/net/")
        try:
            with open(canonical) as f:
                lines = f.readlines()
        except OSError:
            return b""

        if not lines:
            return b""

        our_ports = set(self._port_map._real_to_virtual.keys())
        result = [lines[0]]  # Header

        for line in lines[1:]:
            # Format: "  sl  local_address:PORT ..."
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                local = parts[1]  # e.g. "0100007F:9C40"
                port_hex = local.split(":")[1]
                port = int(port_hex, 16)
                if port in our_ports:
                    result.append(line)
            except (IndexError, ValueError):
                continue

        return "".join(result).encode()

    def _filter_proc_net_header_only(self, path: str) -> bytes:
        """Return only the header line from a /proc/net/* file."""
        canonical = path.replace("/proc/net/", "/proc/self/net/")
        try:
            with open(canonical) as f:
                return f.readline().encode()
        except OSError:
            return b""

    def _handle_getsockname(self, notif: SeccompNotif) -> None:
        """Handle getsockname — do it in supervisor and rewrite real port to virtual.

        Can't use CONTINUE because getsockname fills the sockaddr after
        the syscall completes.  Instead, we do the call in supervisor
        space via pidfd_getfd, rewrite the port, and return the result.
        """
        from ._port_remap import fixup_getsockname

        # getsockname(fd, addr, addrlen_ptr)
        fd = notif.data.args[0] & 0xFFFFFFFF
        sockaddr_addr = notif.data.args[1]
        addrlen_addr = notif.data.args[2]

        try:
            if fixup_getsockname(notif.pid, sockaddr_addr, addrlen_addr,
                                 fd, self._port_map):
                self._respond_val(notif.id, 0)  # Success
                return
        except OSError:
            pass

        # Fallback: let the syscall proceed normally
        self._respond_continue(notif.id)

    # COW stat, readlink, getdents handlers moved to cowfs/_notif_handler.py

    def _handle_getdents(self, notif: SeccompNotif) -> None:
        """Handle getdents64/getdents — filter /proc readdir to hide foreign PIDs.

        On first call for a given fd, reads all /proc entries from the
        supervisor, filters out foreign PIDs, builds dirent64 entries,
        and caches them.  Each call returns as many cached entries as fit
        in the child's buffer, then returns 0 when exhausted.
        """
        pid = notif.pid
        child_fd_num = notif.data.args[0] & 0xFFFFFFFF
        buf_addr = notif.data.args[1]
        buf_size = notif.data.args[2] & 0xFFFFFFFF

        # Check if the fd points to /proc
        try:
            target = os.readlink(f"/proc/{pid}/fd/{child_fd_num}")
        except OSError:
            self._respond_continue(notif.id)
            return

        if target != "/proc":
            self._respond_continue(notif.id)
            return

        # Build cache on first call for this fd
        cache_key = (pid, child_fd_num)
        if cache_key not in self._proc_dir_cache:
            sandbox_pids = None
            if self._pids_fn is not None:
                sandbox_pids = set(self._pids_fn())
            if sandbox_pids is None:
                self._respond_continue(notif.id)
                return

            entries = _build_filtered_dirents(sandbox_pids)
            self._proc_dir_cache[cache_key] = entries

        entries = self._proc_dir_cache[cache_key]

        if not self._id_valid(notif.id):
            return

        # Pack as many entries as fit into buf_size
        result = bytearray()
        consumed = 0
        for entry in entries:
            if len(result) + len(entry) > buf_size:
                break
            result.extend(entry)
            consumed += 1

        # Remove consumed entries from cache
        if consumed > 0:
            self._proc_dir_cache[cache_key] = entries[consumed:]
        elif not entries:
            # All entries consumed — clean up cache
            del self._proc_dir_cache[cache_key]

        # Write to child memory and return byte count
        try:
            if result:
                write_bytes(pid, buf_addr, bytes(result))
            self._respond_val(notif.id, len(result))
        except OSError:
            self._proc_dir_cache.pop(cache_key, None)
            self._respond_continue(notif.id)

    def _id_valid(self, notif_id: int) -> bool:
        """Check if a notification ID is still valid (TOCTTOU check)."""
        id_val = ctypes.c_uint64(notif_id)
        ret = _libc.ioctl(
            ctypes.c_int(self._notify_fd),
            ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_ID_VALID),
            ctypes.byref(id_val),
        )
        return ret == 0

    def _respond_continue(self, notif_id: int) -> None:
        """Allow the syscall to proceed in the kernel."""
        resp = SeccompNotifResp()
        resp.id = notif_id
        resp.val = 0
        resp.error = 0
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
        _libc.ioctl(
            ctypes.c_int(self._notify_fd),
            ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_SEND),
            ctypes.byref(resp),
        )

    def _respond_val(self, notif_id: int, val: int) -> None:
        """Return a specific value as the syscall result."""
        resp = SeccompNotifResp()
        resp.id = notif_id
        resp.val = val
        resp.error = 0
        resp.flags = 0
        _libc.ioctl(
            ctypes.c_int(self._notify_fd),
            ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_SEND),
            ctypes.byref(resp),
        )

    def _respond_errno(self, notif_id: int, errno_code: int) -> None:
        """Deny the syscall with the given errno."""
        resp = SeccompNotifResp()
        resp.id = notif_id
        resp.val = 0
        resp.error = -errno_code
        resp.flags = 0
        _libc.ioctl(
            ctypes.c_int(self._notify_fd),
            ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_SEND),
            ctypes.byref(resp),
        )

    def _respond_virtualize(self, notif_id: int, content: bytes) -> None:
        """Inject a memfd with virtual content into the child.

        Uses SECCOMP_IOCTL_NOTIF_ADDFD (Linux 5.9+) to place a memfd
        containing the fake content into the child's fd table, then
        returns that fd number as the openat() result.
        """
        # Create memfd in supervisor, write content, seek to 0
        try:
            memfd = _memfd_create("sandlock_virt")
        except OSError:
            self._respond_errno(notif_id, errno.EACCES)
            return

        try:
            os.write(memfd, content)
            os.lseek(memfd, 0, os.SEEK_SET)

            # Inject memfd into child via ADDFD
            addfd = SeccompNotifAddfd()
            addfd.id = notif_id
            addfd.flags = 0
            addfd.srcfd = memfd
            addfd.newfd = 0
            addfd.newfd_flags = 0  # no O_CLOEXEC — child expects a normal fd

            ret = _libc.ioctl(
                ctypes.c_int(self._notify_fd),
                ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_ADDFD),
                ctypes.byref(addfd),
            )
            if ret < 0:
                # ADDFD not supported (pre-5.9) or child died — fall back to deny
                self._respond_errno(notif_id, errno.EACCES)
                return

            # ret is the fd number in the child's table
            child_fd = ret

            # Respond with the injected fd as the return value
            resp = SeccompNotifResp()
            resp.id = notif_id
            resp.val = child_fd
            resp.error = 0
            resp.flags = 0
            _libc.ioctl(
                ctypes.c_int(self._notify_fd),
                ctypes.c_ulong(SECCOMP_IOCTL_NOTIF_SEND),
                ctypes.byref(resp),
            )
        finally:
            os.close(memfd)
