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
import socket
import struct
import threading
from typing import Optional

from .exceptions import NotifError
from ._notif_policy import NotifAction, NotifPolicy
from ._procfs import read_bytes, resolve_openat_path
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

# Response flag: let the original syscall proceed in the kernel
SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1


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

    # seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog)
    __NR_seccomp = _SYSCALL_NR["seccomp"]
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
    ):
        self._notify_fd = notify_fd
        self._child_pid = child_pid
        self._policy = policy
        self._pids_fn = pids_fn
        self._thread: Optional[threading.Thread] = None
        self._stop_r, self._stop_w = os.pipe()
        # Resource tracking state
        self._mem_used: int = 0       # Total mapped bytes
        self._brk_base: dict[int, int] = {}  # pid → last known brk
        self._proc_count: int = 1     # Start at 1 (the initial child)
        self._proc_pids: set[int] = {child_pid}  # All known sandbox PIDs

    def start(self) -> None:
        """Start the supervisor thread."""
        self._thread = threading.Thread(
            target=self._run, name="sandlock-notif", daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the supervisor to stop and wait for it."""
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

    def _run(self) -> None:
        """Supervisor event loop."""
        poller = select.poll()
        poller.register(self._notify_fd, select.POLLIN)
        poller.register(self._stop_r, select.POLLIN)

        while True:
            try:
                events = poller.poll(1000)
            except OSError:
                break

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
        self._proc_pids.add(notif.pid)
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

        # --- Network: connect / sendto / sendmsg IP enforcement ---
        nr_connect = _SYSCALL_NR.get("connect")
        nr_sendto = _SYSCALL_NR.get("sendto")
        nr_sendmsg = _SYSCALL_NR.get("sendmsg")

        if nr in (nr_connect, nr_sendto, nr_sendmsg) and self._policy.allowed_ips:
            self._handle_net(notif, nr)
            return

        # --- Filesystem: open / openat virtualization ---
        nr_openat = _SYSCALL_NR.get("openat")
        nr_open = _SYSCALL_NR.get("open")

        try:
            if nr == nr_openat:
                dirfd = ctypes.c_int32(notif.data.args[0] & 0xFFFFFFFF).value
                pathname_addr = notif.data.args[1]
                path = resolve_openat_path(pid, dirfd, pathname_addr)
            elif nr == nr_open:
                pathname_addr = notif.data.args[0]
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
        self._proc_count += 1
        # Record the calling PID (the parent doing the fork).
        # The new child's PID is unknown until it makes its first
        # intercepted syscall — tracked lazily via _record_pid.
        self._proc_pids.add(notif.pid)
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
