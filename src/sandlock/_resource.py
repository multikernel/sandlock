# SPDX-License-Identifier: Apache-2.0
"""Resource enforcement — memory limits and process count.

Handles mmap/munmap/brk/mremap for memory tracking and
clone/fork/vfork for process count limits. Called by the
seccomp notif supervisor.
"""

from __future__ import annotations

import errno
import threading

from ._seccomp import _SYSCALL_NR

# Syscall numbers (cached at import time)
NR_MMAP = _SYSCALL_NR.get("mmap")
NR_MUNMAP = _SYSCALL_NR.get("munmap")
NR_BRK = _SYSCALL_NR.get("brk")
NR_MREMAP = _SYSCALL_NR.get("mremap")
NR_CLONE = _SYSCALL_NR.get("clone")
NR_FORK = _SYSCALL_NR.get("fork")
NR_VFORK = _SYSCALL_NR.get("vfork")

MEMORY_NRS = {NR_MMAP, NR_MUNMAP, NR_BRK, NR_MREMAP} - {None}
FORK_NRS = {NR_CLONE, NR_FORK, NR_VFORK} - {None}

CLONE_THREAD = 0x00010000


class ResourceState:
    """Mutable state for resource tracking across the sandbox."""

    def __init__(self, child_pid: int):
        self.mem_used: int = 0
        self.brk_base: dict[int, int] = {}
        self.proc_count: int = 1
        self.proc_pids: set[int] = {child_pid}
        self.hold_forks: bool = False
        self.hold_lock = threading.Lock()
        self.held_notif_ids: list[int] = []


def handle_memory(notif, nr: int, state: ResourceState,
                   limit: int, respond_continue, respond_errno) -> None:
    """Handle mmap/munmap/brk/mremap — enforce memory budget."""
    if nr == NR_MMAP:
        length = notif.data.args[1]
        if state.mem_used + length > limit:
            respond_errno(notif.id, errno.ENOMEM)
            return
        state.mem_used += length
        respond_continue(notif.id)

    elif nr == NR_MUNMAP:
        length = notif.data.args[1]
        state.mem_used = max(0, state.mem_used - length)
        respond_continue(notif.id)

    elif nr == NR_BRK:
        pid = notif.pid
        new_brk = notif.data.args[0]
        if new_brk == 0:
            respond_continue(notif.id)
            return
        old_brk = state.brk_base.get(pid, new_brk)
        delta = new_brk - old_brk
        if delta > 0 and state.mem_used + delta > limit:
            respond_errno(notif.id, errno.ENOMEM)
            return
        state.mem_used = max(0, state.mem_used + delta)
        state.brk_base[pid] = new_brk
        respond_continue(notif.id)

    elif nr == NR_MREMAP:
        old_size = notif.data.args[1]
        new_size = notif.data.args[2]
        delta = new_size - old_size
        if delta > 0 and state.mem_used + delta > limit:
            respond_errno(notif.id, errno.ENOMEM)
            return
        state.mem_used += delta
        respond_continue(notif.id)

    else:
        respond_continue(notif.id)


def handle_fork(notif, nr: int, state: ResourceState,
                max_processes: int, respond_continue, respond_errno,
                clear_dir_cache) -> None:
    """Handle clone/fork/vfork — enforce process count limit."""
    # clone with CLONE_THREAD = new thread, not new process — allow
    if nr == NR_CLONE:
        flags = notif.data.args[0] & 0xFFFFFFFF
        if flags & CLONE_THREAD:
            respond_continue(notif.id)
            return

    if state.proc_count >= max_processes:
        respond_errno(notif.id, errno.EAGAIN)
        return

    # In hold mode, don't respond — process stays blocked in kernel
    with state.hold_lock:
        if state.hold_forks:
            state.held_notif_ids.append(notif.id)
            return

    state.proc_count += 1
    state.proc_pids.add(notif.pid)
    clear_dir_cache()
    respond_continue(notif.id)
