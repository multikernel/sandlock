# SPDX-License-Identifier: Apache-2.0
"""Network IP enforcement — allowed IP address filtering.

Intercepts connect/sendto/sendmsg and checks the destination IP
against an allowlist. Non-IP families (AF_UNIX, AF_NETLINK) pass
through. Called by the seccomp notif supervisor.
"""

from __future__ import annotations

import errno
import socket
import struct

from ._procfs import read_bytes
from ._seccomp import _SYSCALL_NR

_AF_INET = 2
_AF_INET6 = 10

NR_CONNECT = _SYSCALL_NR.get("connect")
NR_SENDTO = _SYSCALL_NR.get("sendto")
NR_SENDMSG = _SYSCALL_NR.get("sendmsg")
NET_NRS = {NR_CONNECT, NR_SENDTO, NR_SENDMSG} - {None}


def _parse_dest_ip(pid: int, addr: int, addrlen: int) -> str | None:
    """Read a sockaddr from child memory and extract the destination IP.

    Returns the IP string, or None if not AF_INET/AF_INET6.
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
        return None
    return None


def _parse_msghdr_dest_ip(pid: int, msghdr_addr: int) -> str | None:
    """Extract the destination IP from a sendmsg() msghdr."""
    hdr = read_bytes(pid, msghdr_addr, 12)
    name_addr = struct.unpack_from("Q", hdr, 0)[0]
    name_len = struct.unpack_from("I", hdr, 8)[0]
    if name_addr == 0 or name_len == 0:
        return None
    return _parse_dest_ip(pid, name_addr, name_len)


def extract_dest_ip(notif, nr: int) -> str | None:
    """Extract destination IP from a network syscall notification.

    Returns the IP string, or None if not an IP-family destination
    (e.g. AF_UNIX) or if the address is not provided (sendto with
    addr_ptr == 0).
    """
    pid = notif.pid
    try:
        if nr == NR_CONNECT:
            return _parse_dest_ip(pid, notif.data.args[1],
                                  notif.data.args[2] & 0xFFFFFFFF)
        elif nr == NR_SENDMSG:
            return _parse_msghdr_dest_ip(pid, notif.data.args[1])
        else:
            # sendto(fd, buf, len, flags, addr, addrlen)
            addr_ptr = notif.data.args[4]
            if addr_ptr == 0:
                return None
            return _parse_dest_ip(pid, addr_ptr,
                                  notif.data.args[5] & 0xFFFFFFFF)
    except Exception:
        return None


def handle_net(notif, nr: int, allowed_ips: frozenset[str],
               id_valid, respond_continue, respond_errno) -> None:
    """Handle connect/sendto/sendmsg — check destination IP against allowlist."""
    dest_ip = extract_dest_ip(notif, nr)

    if dest_ip is None:
        respond_continue(notif.id)
        return

    if not id_valid(notif.id):
        return

    if dest_ip in allowed_ips:
        respond_continue(notif.id)
    else:
        respond_errno(notif.id, errno.ECONNREFUSED)
