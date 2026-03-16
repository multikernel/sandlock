# SPDX-License-Identifier: Apache-2.0
"""Transparent TCP port virtualization via seccomp user notification.

Each sandbox gets a full virtual port space (0-65535).  When the app
calls bind() on a virtual port, the supervisor allocates a free real
port from the kernel (bind(0)) and rewrites the sockaddr in the
child's memory.  The app thinks it bound the virtual port.

No port ranges to configure.  The kernel handles real port allocation.

Requires Linux 5.9+ (SECCOMP_USER_NOTIF_FLAG_CONTINUE + /proc/pid/mem
write access).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import socket
import struct
import threading
from dataclasses import dataclass, field

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# pidfd_getfd(2) syscall number
_NR_PIDFD_GETFD = 438  # x86_64 and aarch64 (asm-generic)

_AF_INET = 2
_AF_INET6 = 10
_PORT_OFFSET = 2  # sin_port / sin6_port at byte offset 2


@dataclass
class PortMap:
    """Bidirectional mapping between virtual and real ports.

    Allocates real ports on demand from the kernel via bind(0).
    Optionally proxies inbound traffic from virtual port to real port.
    Thread-safe.
    """

    proxy: bool = False
    """If True, listen on virtual ports and forward to real ports."""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _virtual_to_real: dict[int, int] = field(default_factory=dict, repr=False)
    _real_to_virtual: dict[int, int] = field(default_factory=dict, repr=False)
    # Sockets held open to keep real ports reserved
    _held_sockets: list[socket.socket] = field(default_factory=list, repr=False)
    # Proxy state
    _proxy_threads: list[threading.Thread] = field(default_factory=list, repr=False)
    _proxy_sockets: list[socket.socket] = field(default_factory=list, repr=False)
    _proxy_stop: threading.Event = field(default_factory=threading.Event, repr=False)

    def real_port(self, virtual: int, family: int = _AF_INET) -> int | None:
        """Get or allocate the real port for a virtual port.

        Allocates a free real port from the kernel on first use.
        If proxy=True, also starts listening on the virtual port.
        Returns None if allocation fails.
        """
        with self._lock:
            if virtual in self._virtual_to_real:
                return self._virtual_to_real[virtual]

            # Ask the kernel for a free port
            real = self._allocate_real_port(family)
            if real is None:
                return None

            self._virtual_to_real[virtual] = real
            self._real_to_virtual[real] = virtual

        # Start proxy outside the lock (may block briefly)
        if self.proxy:
            self._start_proxy(virtual, real, family)

        return real

    def virtual_port(self, real: int) -> int | None:
        """Look up the virtual port for a real port, or None."""
        with self._lock:
            return self._real_to_virtual.get(real)

    def close(self) -> None:
        """Release all held sockets, stop proxies."""
        self._proxy_stop.set()
        for s in self._proxy_sockets:
            try:
                s.close()
            except OSError:
                pass
        for t in self._proxy_threads:
            t.join(timeout=2.0)
        with self._lock:
            for s in self._held_sockets:
                try:
                    s.close()
                except OSError:
                    pass
            self._held_sockets.clear()
            self._virtual_to_real.clear()
            self._real_to_virtual.clear()
            self._proxy_sockets.clear()
            self._proxy_threads.clear()

    def _allocate_real_port(self, family: int) -> int | None:
        """Bind a socket to port 0 to get a free port from the kernel."""
        try:
            af = socket.AF_INET6 if family == _AF_INET6 else socket.AF_INET
            s = socket.socket(af, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            addr = "::1" if af == socket.AF_INET6 else "127.0.0.1"
            s.bind((addr, 0))
            real_port = s.getsockname()[1]
            self._held_sockets.append(s)
            return real_port
        except OSError:
            return None

    def _start_proxy(self, virtual: int, real: int, family: int) -> None:
        """Start a TCP proxy: listen on virtual port, forward to real port."""
        af = socket.AF_INET6 if family == _AF_INET6 else socket.AF_INET
        try:
            listener = socket.socket(af, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            addr = "" if af == socket.AF_INET6 else "0.0.0.0"
            listener.bind((addr, virtual))
            listener.listen(128)
            listener.settimeout(1.0)
        except OSError:
            return  # Can't bind virtual port (maybe already in use)

        self._proxy_sockets.append(listener)

        def _proxy_loop():
            while not self._proxy_stop.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                # Connect to the sandbox's real port
                try:
                    backend = socket.socket(af, socket.SOCK_STREAM)
                    backend_addr = "::1" if af == socket.AF_INET6 else "127.0.0.1"
                    backend.connect((backend_addr, real))
                except OSError:
                    client.close()
                    continue
                # Bidirectional forwarding in threads
                t1 = threading.Thread(
                    target=_forward, args=(client, backend, self._proxy_stop),
                    daemon=True,
                )
                t2 = threading.Thread(
                    target=_forward, args=(backend, client, self._proxy_stop),
                    daemon=True,
                )
                t1.start()
                t2.start()

            listener.close()

        t = threading.Thread(target=_proxy_loop, daemon=True)
        t.start()
        self._proxy_threads.append(t)


def _forward(src: socket.socket, dst: socket.socket,
             stop: threading.Event) -> None:
    """Forward data from src to dst until EOF or stop."""
    try:
        while not stop.is_set():
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def get_port_map(proxy: bool = False) -> PortMap:
    """Get a new PortMap for a sandbox.

    Args:
        proxy: If True, listen on virtual ports and forward inbound
            traffic to the sandbox's real ports.
    """
    return PortMap(proxy=proxy)


def _read_port(pid: int, sockaddr_addr: int, addrlen: int) -> tuple[int, int] | None:
    """Read the port and address family from a sockaddr in child memory.

    Returns (port, family) or None if not AF_INET/AF_INET6.
    """
    from ._procfs import read_bytes

    if addrlen < 4:
        return None

    data = read_bytes(pid, sockaddr_addr, min(addrlen, 28))
    family = struct.unpack_from("H", data, 0)[0]

    if family not in (_AF_INET, _AF_INET6):
        return None

    port = struct.unpack_from("!H", data, _PORT_OFFSET)[0]
    return (port, family)


def _remap_sockaddr(pid: int, sockaddr_addr: int, addrlen: int,
                    port_map: PortMap) -> bool:
    """Rewrite the port in a sockaddr to a real port.

    Returns True if remapped, False if not applicable.
    """
    from ._procfs import read_bytes, write_bytes

    info = _read_port(pid, sockaddr_addr, addrlen)
    if info is None:
        return False

    virtual_port, family = info
    if virtual_port == 0:
        return False  # Ephemeral port — let kernel pick

    real = port_map.real_port(virtual_port, family)
    if real is None:
        return False  # Allocation failed
    if real == virtual_port:
        return False  # Same port, no rewrite needed

    write_bytes(pid, sockaddr_addr + _PORT_OFFSET, struct.pack("!H", real))
    return True


def fixup_getsockname(pid: int, sockaddr_addr: int, addrlen_addr: int,
                      fd: int, port_map: PortMap) -> bool:
    """Perform getsockname() in the supervisor and rewrite real port to virtual.

    We can't use CONTINUE because getsockname() fills the sockaddr
    after the syscall, and we need to post-process it.  Instead, we
    duplicate the child's socket via pidfd_getfd, do getsockname()
    in supervisor space, rewrite real->virtual port, and write the
    result into the child's memory.

    Returns True if handled, False if not applicable.
    """
    from ._procfs import write_bytes

    # Duplicate the child's socket fd via pidfd_getfd syscall
    try:
        pidfd = os.pidfd_open(pid)
    except OSError:
        return False

    try:
        local_fd = _libc.syscall(
            ctypes.c_long(_NR_PIDFD_GETFD),
            ctypes.c_int(pidfd),
            ctypes.c_int(fd),
            ctypes.c_uint(0),
        )
        if local_fd < 0:
            return False
    finally:
        os.close(pidfd)

    try:
        s = socket.socket(fileno=local_fd)
        try:
            addr = s.getsockname()
            family = s.family
        finally:
            s.detach()
    except OSError:
        os.close(local_fd)
        return False

    if family not in (socket.AF_INET, socket.AF_INET6):
        return False

    real_port = addr[1]
    virtual = port_map.virtual_port(real_port)
    if virtual is None:
        virtual = real_port  # Not remapped, use as-is

    # Build the sockaddr to write back
    if family == socket.AF_INET:
        ip_bytes = socket.inet_aton(addr[0])
        sockaddr = struct.pack("H", family)
        sockaddr += struct.pack("!H", virtual)
        sockaddr += ip_bytes
        sockaddr += b"\x00" * 8  # sin_zero
        written_len = 16
    else:
        ip_bytes = socket.inet_pton(socket.AF_INET6, addr[0])
        flowinfo = addr[2] if len(addr) > 2 else 0
        scope_id = addr[3] if len(addr) > 3 else 0
        sockaddr = struct.pack("H", family)
        sockaddr += struct.pack("!H", virtual)
        sockaddr += struct.pack("!I", flowinfo)
        sockaddr += ip_bytes
        sockaddr += struct.pack("!I", scope_id)
        written_len = 28

    # Write sockaddr and addrlen into child's memory
    try:
        write_bytes(pid, sockaddr_addr, sockaddr)
        write_bytes(pid, addrlen_addr, struct.pack("I", written_len))
    except OSError:
        return False

    return True
