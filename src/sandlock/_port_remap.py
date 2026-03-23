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

# pidfd_open(2) / pidfd_getfd(2) syscall numbers
_NR_PIDFD_OPEN  = 434  # x86_64 and aarch64 (asm-generic)
_NR_PIDFD_GETFD = 438  # x86_64 and aarch64 (asm-generic)


def _pidfd_open(pid: int) -> int:
    """Open a pidfd for the given process.

    Raises:
        OSError: If pidfd_open fails.
    """
    fd = _libc.syscall(
        ctypes.c_long(_NR_PIDFD_OPEN),
        ctypes.c_int(pid),
        ctypes.c_uint(0),
    )
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"pidfd_open({pid}): {os.strerror(err)}")
    return fd

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

        If the virtual port is free, reserves it and returns it unchanged
        (no rewrite, no proxy — the sandbox binds the port directly).
        Only allocates a different real port + proxy when the virtual port
        is already taken by another sandbox.
        Returns None if allocation fails.
        """
        with self._lock:
            if virtual in self._virtual_to_real:
                return self._virtual_to_real[virtual]

            # Fast path: try to reserve the virtual port itself.
            # If successful, the sandbox binds directly — no proxy needed.
            real = self._try_reserve_port(virtual, family)
            if real is not None:
                # virtual == real: _remap_sockaddr sees no change, skips rewrite
                self._virtual_to_real[virtual] = real
                self._real_to_virtual[real] = virtual
                return real

            # Slow path: virtual port taken, allocate a different real port
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

    def _try_reserve_port(self, port: int, family: int) -> int | None:
        """Check if a port is available by probe-and-close.

        Returns the port if free, None if already in use.
        No holder socket is kept — the sandbox binds the port directly.
        There is a tiny race window between the probe and the sandbox's
        bind(); if another process grabs the port, the sandbox gets
        EADDRINUSE, which is a normal error applications already handle.
        """
        af = socket.AF_INET6 if family == _AF_INET6 else socket.AF_INET
        s = socket.socket(af, socket.SOCK_STREAM)
        try:
            s.bind(("::1" if af == socket.AF_INET6 else "127.0.0.1", port))
            return port
        except OSError:
            return None
        finally:
            s.close()

    def _allocate_real_port(self, family: int) -> int | None:
        """Bind a socket to port 0 to get a free port from the kernel."""
        af = socket.AF_INET6 if family == _AF_INET6 else socket.AF_INET
        addr = "::1" if af == socket.AF_INET6 else "127.0.0.1"
        s = socket.socket(af, socket.SOCK_STREAM)
        try:
            s.bind((addr, 0))
            return s.getsockname()[1]
        except OSError:
            return None
        finally:
            s.close()

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

        t = threading.Thread(
            target=_proxy_event_loop,
            args=(listener, real, af, self._proxy_stop),
            daemon=True,
        )
        t.start()
        self._proxy_threads.append(t)


def _proxy_event_loop(listener: socket.socket, real_port: int,
                      af: int, stop: threading.Event) -> None:
    """Single-thread event loop: accept connections, splice data.

    Uses poll + splice so one thread handles all connections with
    zero-copy forwarding.  No per-connection threads needed.
    """
    import select

    poller = select.poll()
    listener_fd = listener.fileno()
    poller.register(listener_fd, select.POLLIN)

    # Per-fd state: fd → (peer_fd, pipe_r, pipe_w)
    pipes: dict[int, tuple[int, int, int]] = {}
    # Track socket objects to prevent GC
    sockets: dict[int, socket.socket] = {}

    def _add_pair(client: socket.socket, backend: socket.socket) -> None:
        client.setblocking(False)
        backend.setblocking(False)
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        backend.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        c_fd = client.fileno()
        b_fd = backend.fileno()
        c2b_r, c2b_w = os.pipe()
        b2c_r, b2c_w = os.pipe()
        pipes[c_fd] = (b_fd, c2b_r, c2b_w)
        pipes[b_fd] = (c_fd, b2c_r, b2c_w)
        sockets[c_fd] = client
        sockets[b_fd] = backend
        poller.register(c_fd, select.POLLIN)
        poller.register(b_fd, select.POLLIN)

    def _remove_fd(fd: int) -> None:
        if fd not in pipes:
            return
        peer_fd, pipe_r, pipe_w = pipes.pop(fd)
        os.close(pipe_r)
        os.close(pipe_w)
        try:
            poller.unregister(fd)
        except (KeyError, OSError):
            pass
        s = sockets.pop(fd, None)
        if s:
            try:
                s.close()
            except OSError:
                pass
        # Also remove peer
        if peer_fd in pipes:
            p_peer, p_r, p_w = pipes.pop(peer_fd)
            os.close(p_r)
            os.close(p_w)
            try:
                poller.unregister(peer_fd)
            except (KeyError, OSError):
                pass
            ps = sockets.pop(peer_fd, None)
            if ps:
                try:
                    ps.close()
                except OSError:
                    pass

    backend_addr = "::1" if af == socket.AF_INET6 else "127.0.0.1"
    _SPLICE_F_NONBLOCK = 0x02

    try:
        while not stop.is_set():
            try:
                events = poller.poll(500)
            except OSError:
                break
            for fd, event in events:
                if fd == listener_fd:
                    # Accept new connection
                    try:
                        client, _ = listener.accept()
                    except OSError:
                        continue
                    try:
                        backend = socket.socket(af, socket.SOCK_STREAM)
                        backend.connect((backend_addr, real_port))
                    except OSError:
                        client.close()
                        continue
                    _add_pair(client, backend)
                    continue

                if fd not in pipes:
                    continue

                if event & (select.POLLERR | select.POLLNVAL):
                    _remove_fd(fd)
                    continue

                if event & (select.POLLIN | select.POLLHUP):
                    peer_fd, pipe_r, pipe_w = pipes[fd]
                    try:
                        n = os.splice(fd, pipe_w, 65536,
                                      flags=_SPLICE_F_NONBLOCK)
                        if n == 0:
                            _remove_fd(fd)
                            continue
                        while n > 0:
                            n -= os.splice(pipe_r, peer_fd, n)
                    except BlockingIOError:
                        pass
                    except OSError:
                        _remove_fd(fd)
    finally:
        for fd in list(pipes):
            _remove_fd(fd)
        listener.close()


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
    from ._context import _pidfd_open
    try:
        pidfd = _pidfd_open(pid)
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
            os.close(local_fd)
    except OSError:
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
