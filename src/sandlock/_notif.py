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

    # 2. Arg-level filters (clone namespace flags, ioctl TIOCSTI)
    insns += _build_arg_filters()

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

    filter_bytes = _build_combined_filter(notify_nrs, deny_nrs)
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


def _parse_dest_ip(pid: int, addr: int, addrlen: int) -> str | None:
    """Read a sockaddr from child memory and extract the destination IP.

    Returns the IP string, or None if the address family is not
    AF_INET/AF_INET6 (e.g. AF_UNIX, AF_NETLINK — not filtered).
    """
    if addrlen < 4:
        return None
    data = read_bytes(pid, addr, min(addrlen, 28))
    family = struct.unpack_from("H", data, 0)[0]
    try:
        if family == _AF_INET and len(data) >= 8:
            return socket.inet_ntop(socket.AF_INET, data[4:8])
        if family == _AF_INET6 and len(data) >= 24:
            return socket.inet_ntop(socket.AF_INET6, data[8:24])
    except (ValueError, OSError):
        return None  # Malformed sockaddr — pass through
    return None  # AF_UNIX etc. — pass through


def _parse_msghdr_dest_ip(pid: int, msghdr_addr: int) -> str | None:
    """Extract the destination IP from a sendmsg() msghdr.

    struct msghdr { void *msg_name, socklen_t msg_namelen, ... }
    On x86_64/aarch64: msg_name is 8 bytes, msg_namelen is 4 bytes.
    """
    # Read msg_name (pointer) + msg_namelen (u32) = first 12 bytes
    hdr = read_bytes(pid, msghdr_addr, 12)
    name_addr = struct.unpack_from("Q", hdr, 0)[0]  # void *msg_name
    name_len = struct.unpack_from("I", hdr, 8)[0]    # socklen_t msg_namelen
    if name_addr == 0 or name_len == 0:
        return None  # No destination — connected socket, pass through
    return _parse_dest_ip(pid, name_addr, name_len)


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
        bind_ports: list[int] | None = None,
        disk_quota_path: str | None = None,
        disk_quota_bytes: int = 0,
    ):
        self._notify_fd = notify_fd
        self._child_pid = child_pid
        self._policy = policy
        self._pids_fn = pids_fn
        self._bind_ports = bind_ports
        self._disk_quota_path = disk_quota_path
        self._disk_quota_bytes = disk_quota_bytes
        self._cow_handler = None  # CowHandler | None
        self._thread: Optional[threading.Thread] = None
        self._stop_r, self._stop_w = os.pipe()
        # Resource tracking state
        self._mem_used: int = 0       # Total mapped bytes
        self._brk_base: dict[int, int] = {}  # pid → last known brk
        self._proc_count: int = 1     # Start at 1 (the initial child)
        self._proc_pids: set[int] = {child_pid}  # All known sandbox PIDs
        # getdents /proc filtering: fd → list of remaining dirent entries
        self._proc_dir_cache: dict[int, list[bytes]] = {}
        # Fork-hold state for checkpoint freeze
        self._hold_forks: bool = False
        self._hold_lock = threading.Lock()
        self._held_notif_ids: list[int] = []
        # Port remapping (sliced from net_bind via PortAllocator)
        self._port_map = None  # PortMap | None
        self._full_port_set = None  # set[int] | None — all net_bind ports
        if policy.port_remap and self._bind_ports:
            from ._port_remap import get_port_map
            self._port_map = get_port_map(self._bind_ports)
            self._full_port_set = set(self._bind_ports)

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
        """Enter hold mode: fork/clone notifications are not responded to.

        The kernel keeps the calling process blocked until we respond.
        This creates a clean freeze barrier for checkpoint.
        """
        with self._hold_lock:
            self._hold_forks = True

    def release_forks(self) -> None:
        """Exit hold mode: respond CONTINUE to all held fork notifications."""
        with self._hold_lock:
            self._hold_forks = False
            for notif_id in self._held_notif_ids:
                try:
                    self._respond_continue(notif_id)
                except OSError:
                    pass  # Process may have died while waiting
            self._held_notif_ids.clear()

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

    def _dispatch(self, notif: SeccompNotif) -> None:
        """Route a notification to the appropriate handler."""
        # Lazily track every PID that makes an intercepted syscall
        pid = notif.pid
        self._proc_pids.add(pid)
        nr = notif.data.nr

        # --- Resource: memory tracking ---
        nr_mmap = _SYSCALL_NR.get("mmap")
        nr_munmap = _SYSCALL_NR.get("munmap")
        nr_brk = _SYSCALL_NR.get("brk")
        nr_mremap = _SYSCALL_NR.get("mremap")

        if nr in (nr_mmap, nr_munmap, nr_brk, nr_mremap) and self._policy.max_memory_bytes > 0:
            self._handle_memory(notif, nr)
            return

        # --- Resource: process count ---
        nr_clone = _SYSCALL_NR.get("clone")
        nr_fork = _SYSCALL_NR.get("fork")
        nr_vfork = _SYSCALL_NR.get("vfork")

        if nr in (nr_clone, nr_fork, nr_vfork) and self._policy.max_processes > 0:
            self._handle_fork(notif, nr)
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
        nr_sendto = _SYSCALL_NR.get("sendto")
        nr_sendmsg = _SYSCALL_NR.get("sendmsg")

        if nr in (nr_connect, nr_sendto, nr_sendmsg) and self._policy.allowed_ips:
            self._handle_net(notif, nr)
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
                self._handle_cow_getdents(notif, target)
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
            nr_readlinkat = _SYSCALL_NR.get("readlinkat")
            nr_readlink = _SYSCALL_NR.get("readlink")
            nr_truncate = _SYSCALL_NR.get("truncate")

            # *at variants: dirfd=arg0, pathname=arg1
            cow_at_nrs = {nr_unlinkat, nr_mkdirat, nr_renameat2,
                          nr_newfstatat, nr_statx, nr_faccessat,
                          nr_fchmodat, nr_readlinkat} - {None}
            # non-at variants: pathname=arg0
            cow_plain_nrs = {nr_unlink, nr_rmdir, nr_mkdir, nr_rename,
                             nr_stat, nr_lstat, nr_access,
                             nr_chmod, nr_readlink, nr_truncate} - {None}
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
                            self._handle_cow_stat(notif, nr, real_path)
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
                            self._handle_cow_readlink(notif, nr, target)
                        else:
                            self._respond_errno(notif.id, errno.EINVAL)
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
                path = resolve_openat_path(pid, dirfd, pathname_addr)
            elif nr == nr_open:
                pathname_addr = notif.data.args[0]
                flags = notif.data.args[1]
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

        # --- COW: redirect opens under workdir to upper dir ---
        if self._cow_handler is not None and self._cow_handler.matches(path):
            # Fast path: read-only open with no changes → kernel handles it
            from .cowfs._handler import _WRITE_FLAGS, O_DIRECTORY
            is_read_only = not (flags & (_WRITE_FLAGS | O_DIRECTORY))
            if is_read_only and not self._cow_handler._branch.has_changes:
                self._respond_continue(notif.id)
                return
            self._handle_cow_open(notif, path, flags)
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

    def _handle_cow_open(self, notif: SeccompNotif, path: str, flags: int) -> None:
        """Handle openat under workdir: redirect to COW upper dir."""
        real_path = self._cow_handler.handle_open(path, flags)
        if real_path is None:
            self._respond_continue(notif.id)
            return

        # Open the file in the supervisor and inject fd into child
        try:
            fd = os.open(real_path, flags, 0o666)
        except OSError:
            self._respond_continue(notif.id)
            return

        try:
            self._respond_addfd(notif.id, fd)
        finally:
            os.close(fd)

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

    def _handle_net(self, notif: SeccompNotif, nr: int) -> None:
        """Handle connect/sendto/sendmsg — check destination IP against allowlist."""
        pid = notif.pid
        nr_connect = _SYSCALL_NR.get("connect")
        nr_sendmsg = _SYSCALL_NR.get("sendmsg")

        try:
            if nr == nr_connect:
                # connect(fd, addr, addrlen)
                dest_ip = _parse_dest_ip(pid, notif.data.args[1],
                                         notif.data.args[2] & 0xFFFFFFFF)
            elif nr == nr_sendmsg:
                # sendmsg(fd, msghdr*, flags)
                dest_ip = _parse_msghdr_dest_ip(pid, notif.data.args[1])
            else:
                # sendto(fd, buf, len, flags, addr, addrlen)
                addr_ptr = notif.data.args[4]
                if addr_ptr == 0:
                    # NULL addr on connected socket — allow
                    self._respond_continue(notif.id)
                    return
                dest_ip = _parse_dest_ip(pid, addr_ptr,
                                         notif.data.args[5] & 0xFFFFFFFF)
        except Exception:
            # Can't read child memory or parse sockaddr — allow through
            self._respond_continue(notif.id)
            return

        if not self._id_valid(notif.id):
            return

        # Non-IP families (AF_UNIX, AF_NETLINK) or NULL msghdr dest — pass through
        if dest_ip is None:
            self._respond_continue(notif.id)
            return

        if dest_ip in self._policy.allowed_ips:
            self._respond_continue(notif.id)
        else:
            self._respond_errno(notif.id, errno.ECONNREFUSED)

    def _handle_memory(self, notif: SeccompNotif, nr: int) -> None:
        """Handle mmap/munmap/brk/mremap — enforce memory budget."""
        nr_mmap = _SYSCALL_NR.get("mmap")
        nr_munmap = _SYSCALL_NR.get("munmap")
        nr_brk = _SYSCALL_NR.get("brk")
        nr_mremap = _SYSCALL_NR.get("mremap")
        limit = self._policy.max_memory_bytes

        if nr == nr_mmap:
            # mmap(addr, length, prot, flags, fd, offset): length=arg1
            length = notif.data.args[1]
            if self._mem_used + length > limit:
                self._respond_errno(notif.id, errno.ENOMEM)
                return
            self._mem_used += length
            self._respond_continue(notif.id)

        elif nr == nr_munmap:
            # munmap(addr, length): length=arg1
            length = notif.data.args[1]
            self._mem_used = max(0, self._mem_used - length)
            self._respond_continue(notif.id)

        elif nr == nr_brk:
            # brk(addr): if addr==0, query; else set new brk
            pid = notif.pid
            new_brk = notif.data.args[0]
            if new_brk == 0:
                # Query — just allow
                self._respond_continue(notif.id)
                return
            old_brk = self._brk_base.get(pid, new_brk)
            delta = new_brk - old_brk
            if delta > 0 and self._mem_used + delta > limit:
                self._respond_errno(notif.id, errno.ENOMEM)
                return
            self._mem_used = max(0, self._mem_used + delta)
            self._brk_base[pid] = new_brk
            self._respond_continue(notif.id)

        elif nr == nr_mremap:
            # mremap(old_addr, old_size, new_size, flags, ...):
            # old_size=arg1, new_size=arg2
            old_size = notif.data.args[1]
            new_size = notif.data.args[2]
            delta = new_size - old_size
            if delta > 0 and self._mem_used + delta > limit:
                self._respond_errno(notif.id, errno.ENOMEM)
                return
            self._mem_used += delta
            self._respond_continue(notif.id)

        else:
            self._respond_continue(notif.id)

    def _handle_fork(self, notif: SeccompNotif, nr: int) -> None:
        """Handle clone/fork/vfork — enforce process count limit.

        Only counts process-creating clones.  Thread-creating clones
        (CLONE_THREAD) are always allowed — they share the parent's
        address space and don't increase the sandbox's resource footprint.
        """
        nr_clone = _SYSCALL_NR.get("clone")
        CLONE_THREAD = 0x00010000

        # clone with CLONE_THREAD = new thread, not new process — allow
        if nr == nr_clone:
            flags = notif.data.args[0] & 0xFFFFFFFF
            if flags & CLONE_THREAD:
                self._respond_continue(notif.id)
                return

        if self._proc_count >= self._policy.max_processes:
            self._respond_errno(notif.id, errno.EAGAIN)
            return

        # In hold mode, don't respond — process stays blocked in kernel
        with self._hold_lock:
            if self._hold_forks:
                self._held_notif_ids.append(notif.id)
                return

        self._proc_count += 1
        # Record the calling PID (the parent doing the fork).
        # The new child's PID is unknown until it makes its first
        # intercepted syscall — tracked lazily via _record_pid.
        self._proc_pids.add(notif.pid)
        # Invalidate /proc readdir cache so new PIDs appear
        self._proc_dir_cache.clear()
        self._respond_continue(notif.id)

    def _handle_port_remap(self, notif: SeccompNotif, nr: int) -> None:
        """Handle bind/connect — rewrite port in child's sockaddr.

        For bind: remaps virtual port to a real port from the pool.
        For connect: remaps virtual port, and blocks connections to
        other sandboxes' ports (prevents port scanning).
        """
        from ._port_remap import _remap_sockaddr, _read_port
        from ._seccomp import _SYSCALL_NR

        sockaddr_addr = notif.data.args[1]
        addrlen = notif.data.args[2] & 0xFFFFFFFF

        nr_connect = _SYSCALL_NR.get("connect")
        if nr == nr_connect and self._full_port_set is not None:
            # Block connections to other sandboxes' real ports.
            # If target port is in the full net_bind range but not
            # in our slice, it belongs to another sandbox.
            try:
                target_port = _read_port(notif.pid, sockaddr_addr, addrlen)
                if target_port is not None:
                    if (target_port in self._full_port_set
                            and target_port not in self._port_map._pool_set):
                        self._respond_errno(notif.id, errno.ECONNREFUSED)
                        return
            except OSError:
                pass

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

        our_ports = self._port_map._pool_set
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

    def _handle_cow_stat(self, notif: SeccompNotif, nr: int, real_path: str) -> None:
        """Do stat on the resolved COW path, write result to child's buffer."""
        from ._procfs import write_bytes

        nr_newfstatat = _SYSCALL_NR.get("newfstatat")
        nr_stat = _SYSCALL_NR.get("stat")
        nr_lstat = _SYSCALL_NR.get("lstat")

        # Get the statbuf pointer from syscall args
        if nr == nr_newfstatat:
            # newfstatat(dirfd, pathname, statbuf, flags)
            statbuf_addr = notif.data.args[2]
            use_lstat = bool(notif.data.args[3] & 0x100)  # AT_SYMLINK_NOFOLLOW
        elif nr == nr_stat:
            # stat(pathname, statbuf)
            statbuf_addr = notif.data.args[1]
            use_lstat = False
        elif nr == nr_lstat:
            # lstat(pathname, statbuf)
            statbuf_addr = notif.data.args[1]
            use_lstat = True
        else:
            self._respond_continue(notif.id)
            return

        try:
            if use_lstat:
                st = os.lstat(real_path)
            else:
                st = os.stat(real_path)
        except OSError:
            self._respond_errno(notif.id, errno.ENOENT)
            return

        # Pack struct stat (x86_64: 144 bytes)
        # dev(Q) ino(Q) nlink(Q) mode(I) uid(I) gid(I) pad(I) rdev(Q)
        # size(q) blksize(q) blocks(q)
        # atime_sec(Q) atime_ns(Q) mtime_sec(Q) mtime_ns(Q)
        # ctime_sec(Q) ctime_ns(Q) unused(qqq)
        packed = struct.pack(
            "QQQIIIIQqqqQQQQQQqqq",
            st.st_dev, st.st_ino, st.st_nlink,
            st.st_mode, st.st_uid, st.st_gid, 0,  # pad
            st.st_rdev,
            st.st_size, st.st_blksize, st.st_blocks,
            int(st.st_atime), int(st.st_atime_ns % 1_000_000_000),
            int(st.st_mtime), int(st.st_mtime_ns % 1_000_000_000),
            int(st.st_ctime), int(st.st_ctime_ns % 1_000_000_000),
            0, 0, 0,  # unused
        )

        if not self._id_valid(notif.id):
            return

        try:
            write_bytes(notif.pid, statbuf_addr, packed)
            self._respond_val(notif.id, 0)
        except OSError:
            self._respond_continue(notif.id)

    def _handle_cow_readlink(self, notif: SeccompNotif, nr: int, target: str) -> None:
        """Write readlink result to child's buffer."""
        from ._procfs import write_bytes

        nr_readlinkat = _SYSCALL_NR.get("readlinkat")

        if nr == nr_readlinkat:
            # readlinkat(dirfd, pathname, buf, bufsiz)
            buf_addr = notif.data.args[2]
            bufsiz = notif.data.args[3] & 0xFFFFFFFF
        else:
            # readlink(pathname, buf, bufsiz)
            buf_addr = notif.data.args[1]
            bufsiz = notif.data.args[2] & 0xFFFFFFFF

        target_bytes = target.encode()
        write_len = min(len(target_bytes), bufsiz)

        if not self._id_valid(notif.id):
            return

        try:
            write_bytes(notif.pid, buf_addr, target_bytes[:write_len])
            self._respond_val(notif.id, write_len)
        except OSError:
            self._respond_continue(notif.id)

    def _handle_cow_getdents(self, notif: SeccompNotif, dir_path: str) -> None:
        """Handle getdents64 for COW directories — merge upper + lower entries."""
        pid = notif.pid
        child_fd_num = notif.data.args[0] & 0xFFFFFFFF
        buf_addr = notif.data.args[1]
        buf_size = notif.data.args[2] & 0xFFFFFFFF

        cache_key = ("cow", pid, child_fd_num)
        if cache_key not in self._proc_dir_cache:
            workdir = self._cow_handler.workdir
            rel_path = os.path.relpath(dir_path, workdir)
            merged_names = self._cow_handler.list_merged_dir(rel_path)

            DT_DIR = 4
            DT_REG = 8
            DT_LNK = 10
            entries = []
            d_off = 0
            for name in merged_names:
                d_off += 1
                # Determine type from upper or lower
                upper_p = self._cow_handler.upper_dir / rel_path / name
                lower_p = Path(workdir) / rel_path / name
                check = upper_p if upper_p.exists() else lower_p
                if check.is_dir():
                    d_type = DT_DIR
                elif check.is_symlink():
                    d_type = DT_LNK
                else:
                    d_type = DT_REG
                entries.append(_build_dirent64(d_off, d_off, d_type, name))

            self._proc_dir_cache[cache_key] = entries

        entries = self._proc_dir_cache[cache_key]

        if not self._id_valid(notif.id):
            return

        result = bytearray()
        consumed = 0
        for entry in entries:
            if len(result) + len(entry) > buf_size:
                break
            result.extend(entry)
            consumed += 1

        if consumed > 0:
            self._proc_dir_cache[cache_key] = entries[consumed:]
        elif not entries:
            del self._proc_dir_cache[cache_key]

        try:
            if result:
                write_bytes(pid, buf_addr, bytes(result))
            self._respond_val(notif.id, len(result))
        except OSError:
            self._proc_dir_cache.pop(cache_key, None)
            self._respond_continue(notif.id)

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
