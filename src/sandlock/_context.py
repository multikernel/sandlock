# SPDX-License-Identifier: Apache-2.0
"""SandboxContext: fork + confinement for sandboxed execution.

Each child is confined via Landlock (filesystem + network), seccomp
(syscall blocklist + allowlist), and a seccomp user-notification
supervisor for resource limits, /proc virtualization, and network
enforcement.  No root required.

With the default ``policy.strict=True``, confinement failures (Landlock
unavailable, seccomp installation failure) abort the child process.
Set ``strict=False`` to degrade gracefully when kernel features are missing.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import select
import signal
import socket
from typing import Callable, Optional, Sequence

from .exceptions import (
    ChildError,
    ConfinementError,
    ForkError,
    NotifError,
    SandboxError,
)
from ._landlock import confine, LandlockUnavailableError
from ._seccomp import apply_seccomp_filter
from ._chroot import setup_chroot
from .policy import Policy


def _waitstatus_to_exitcode(status: int) -> int:
    """Convert a waitpid status to an exit code."""
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return -1

# Set after seccomp confinement in the child.  Any subsequent
# SandboxContext in this process is nested and must skip the
# notif filter (can't install two).
_confined = False


def _is_already_confined() -> bool:
    """Detect if this process is already inside a sandbox.

    Checks /proc/self/status for active seccomp filters (Seccomp: 2).
    This catches both in-process nesting (_confined flag) and
    cross-process nesting (e.g. ``sandlock run ... -- python agent.py``
    where agent.py creates inner sandboxes).
    """
    if _confined:
        return True
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    return line.strip().endswith("2")
    except OSError:
        pass
    return False


# --- pidfd helpers (Linux 5.3+, required by Sandlock) ---

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# pidfd_open(2) — asm-generic syscall number, same on all architectures
_NR_PIDFD_OPEN = 434


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


def _pidfd_poll(pidfd: int, timeout_s: float) -> bool:
    """Wait for a pidfd to become readable (child exited).

    Uses poll(2) which has no fd-number limit (unlike select's 1024 limit).

    Args:
        pidfd: File descriptor from pidfd_open.
        timeout_s: Timeout in seconds (negative = wait forever).

    Returns:
        True if the child exited, False on timeout.
    """
    timeout_ms = int(timeout_s * 1000) if timeout_s >= 0 else -1
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    events = poller.poll(timeout_ms)
    return bool(events)


# --- Syscalls to intercept for notification ---

def _notif_syscall_names(notif: "NotifPolicy") -> list[str]:
    """Return the list of syscalls to intercept via user notification.

    clone/fork/vfork/clone3 are always intercepted for namespace flag
    checks and process counting.  openat/open are only intercepted when
    features that need path inspection are enabled (COW, random seed,
    time virtualization, port remap, hosts virtualization, PID isolation).
    """
    from ._seccomp import _SYSCALL_NR
    names = []

    # openat/open only needed when features require path inspection
    needs_openat = (
        notif is not None and (
            notif.rules                   # path-based virtualization (e.g. /etc/hosts)
            or notif.cow_enabled          # COW filesystem redirects
            or notif.random_seed is not None  # deterministic /dev/urandom
            or notif.time_start is not None   # /proc/uptime, /proc/stat virtualization
            or notif.port_remap           # /proc/net/* filtering
            or notif.isolate_pids         # /proc/<pid> access control
        )
    )
    if needs_openat:
        names.append("openat")
        if "open" in _SYSCALL_NR:
            names.append("open")
    # Intercept clone/clone3/vfork via USER_NOTIF for namespace flag
    # checks and process counting.  Clone namespace flags are also
    # blocked by a BPF arg filter as defense in depth.
    #
    # The raw fork syscall (NR 57) is NOT intercepted.  It takes no
    # flags and cannot create namespaces.  The COW fork template uses
    # raw fork(2) via ctypes to bypass the seccomp notif round-trip.
    # User code uses os.fork() which calls clone (intercepted).
    names.extend(["clone", "clone3", "vfork"])
    if notif is not None and notif.allowed_ips:
        names.extend(["connect", "sendto"])
    if notif is not None and notif.port_remap:
        names.extend(["bind", "connect", "getsockname"])
    if notif is not None and notif.max_memory_bytes > 0:
        names.extend(["mmap", "munmap", "brk", "mremap"])
    if notif is not None and notif.isolate_pids:
        names.append("getdents64")
        if "getdents" in _SYSCALL_NR:
            names.append("getdents")
    if notif is not None and notif.cow_enabled:
        cow_syscalls = [
            "unlinkat", "mkdirat", "renameat2",
            "newfstatat", "statx", "faccessat",
            "symlinkat", "linkat", "fchmodat", "fchownat",
            "readlinkat", "truncate", "utimensat", "getdents64",
            "execve", "execveat",
            # Non-at variants (x86_64 has both, aarch64 only has *at)
            "unlink", "rmdir", "mkdir", "rename",
            "stat", "lstat", "access",
            "symlink", "link", "chmod", "chown", "lchown",
            "readlink", "futimesat",
        ]
        for name in cow_syscalls:
            if name in _SYSCALL_NR:
                names.append(name)
        if "getdents" in _SYSCALL_NR:
            names.append("getdents")
    if notif is not None and notif.random_seed is not None:
        names.append("getrandom")
    if notif is not None and notif.time_start is not None:
        names.extend(["clock_gettime", "gettimeofday", "time",
                       "clock_nanosleep", "timerfd_settime",
                       "timer_settime"])
    # Deduplicate (clone/open may already be in the list)
    return list(dict.fromkeys(names))


def _pids_by_pgid(pgid: int) -> list[int]:
    """Get PIDs in a process group by scanning /proc."""
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            stat = open(f"/proc/{entry}/stat").read()
            # comm field (field 1) is in parens and may contain spaces.
            # Parse after the last ')'.
            rest = stat[stat.rfind(")") + 2:]
            fields = rest.split()
            # fields[0]=state, [1]=ppid, [2]=pgrp
            if int(fields[2]) == pgid:
                pids.append(int(entry))
        except (OSError, IndexError, ValueError):
            continue
    return pids


class SandboxContext:
    """Fork-based sandbox context.

    Forks a child process and applies confinement (Landlock, seccomp)
    according to the given Policy.

    Child confinement sequence:
        0. setpgid(0, 0)                  — new process group
        1. PR_SET_PTRACER(ppid)           — allow parent to ptrace (checkpoint)
        2. unshare(NEWUSER)               — if privileged mode
        3. chroot(path)                   — optional root change
        4. Landlock(fs + net + IPC)       — irreversible
        5. checkpoint listener thread     — before seccomp (needs clone3)
        6. seccomp filter                 — irreversible
        7. close fds 3+                   — fd hygiene
        8. clean_env + env overrides      — environment setup
        9. exec(cmd) or target()          — run user code

    Parent side (after fork):
        - write uid/gid maps             — if privileged mode
        - receive notify fd              — start seccomp supervisor thread
        - start throttle thread           — if max_cpu is set

    Nesting: Landlock and seccomp BPF filters stack naturally (kernel
    ANDs them).  The seccomp notif supervisor and resource limits
    (max_processes, max_memory) apply only at the outermost level.
    CPU throttle works at each level (separate process groups).
    """

    def __init__(
        self,
        target: Callable[[], None],
        policy: Policy,
        sandbox_id: str,
        *,
        save_fn: Callable[[], bytes] | None = None,
        overlay_branch: "object | None" = None,
        cow_branch: "object | None" = None,
        clone_loop_fn: "Callable[[int], None] | None" = None,
    ):
        self._target = target
        self._policy = policy
        self._sandbox_id = sandbox_id
        self._save_fn = save_fn
        self._clone_loop_fn = clone_loop_fn
        self._overlay_branch = overlay_branch or getattr(policy, '_overlay_branch', None)
        self._cow_branch = cow_branch or getattr(policy, '_cow_branch', None)
        self._pid: Optional[int] = None
        self._pidfd: int = -1
        self._supervisor = None  # NotifSupervisor | None (lazy import)
        self._throttle_stop = None  # threading.Event | None
        self._throttle_thread = None  # threading.Thread | None
        self._disk_quota_stop = None  # threading.Event | None
        self._disk_quota_thread = None  # threading.Thread | None
        self._control_fd: int = -1  # Parent's end of control socket
        self._exited = False

    @property
    def pid(self) -> int:
        if self._pid is None:
            raise SandboxError("Process not started")
        return self._pid

    @property
    def alive(self) -> bool:
        if self._pid is None or self._exited:
            return False
        try:
            os.kill(self._pid, 0)
            return True
        except ProcessLookupError:
            return False

    def wait(self, timeout: Optional[float] = None) -> int:
        """Wait for the child process to exit.

        Args:
            timeout: Maximum seconds to wait (None = wait forever).

        Returns:
            Exit code of the child.

        Raises:
            TimeoutError: If the child doesn't exit within timeout.
        """
        return self._wait_raw(timeout)

    def _wait_raw(self, timeout: Optional[float] = None) -> int:
        """Wait for the child and return the raw exit code.

        Uses pidfd + poll(2) for event-driven waiting — no busy-loop.
        """
        if self._pid is None:
            return -1

        if timeout is None:
            # Blocking wait — pidfd not needed
            _, status = os.waitpid(self._pid, 0)
            self._exited = True
            return _waitstatus_to_exitcode(status)

        # Event-driven: pidfd becomes readable when child exits
        if not _pidfd_poll(self._pidfd, timeout):
            raise TimeoutError(
                f"Process {self._pid} did not exit within {timeout}s"
            )

        try:
            _, status = os.waitpid(self._pid, os.WNOHANG)
            self._exited = True
            return _waitstatus_to_exitcode(status)
        except ChildProcessError:
            self._exited = True
            return -1

    def abort(self, timeout: float = 5.0) -> None:
        """Abort the child and all its descendants.

        Kills the process group first, then kills any individually
        tracked PIDs from the seccomp notif supervisor (catches
        processes that changed their process group).
        Escalates SIGTERM → SIGKILL after timeout.
        """
        if self._pid is None or self._exited:
            return

        # Collect tracked PIDs before stopping the supervisor
        tracked = set()
        if self._supervisor is not None:
            tracked = self._supervisor.tracked_pids

        # Stop threads
        self._stop_throttle()
        self._stop_disk_quota()
        self._stop_supervisor()

        # SIGTERM the process group
        try:
            os.killpg(self._pid, signal.SIGTERM)
        except ProcessLookupError:
            self._exited = True
            self._reap()
            return

        # Wait for graceful exit via pidfd
        if _pidfd_poll(self._pidfd, timeout):
            self._reap()
            self._exited = True
            return

        # Escalate to SIGKILL — process group + all tracked PIDs
        for pid in tracked | {self._pid}:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            os.killpg(self._pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

        self._reap()
        self._exited = True

    def _start_disk_quota(self, pgid: int) -> None:
        """Start a daemon thread that checks overlay disk usage periodically."""
        import threading
        import time
        from .policy import parse_memory_size
        from ._cow_base import dir_size
        from pathlib import Path

        branch = self._overlay_branch or self._cow_branch
        upper = Path(str(branch.upper_dir))
        quota = parse_memory_size(self._policy.max_disk)
        stop_event = threading.Event()
        self._disk_quota_stop = stop_event

        def _loop():
            while not stop_event.wait(1.0):
                try:
                    used = dir_size(upper)
                    if used > quota:
                        # Graceful: SIGTERM, then SIGKILL after 3s
                        try:
                            os.killpg(pgid, signal.SIGTERM)
                        except ProcessLookupError:
                            return
                        if not stop_event.wait(3.0):
                            try:
                                os.killpg(pgid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        return
                except (OSError, ProcessLookupError):
                    return

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        self._disk_quota_thread = t

    def _stop_supervisor(self) -> None:
        """Stop the notification supervisor if running."""
        if self._supervisor is not None:
            self._supervisor.stop()
            self._supervisor = None

    def _start_throttle(self, pgid: int, pct: int) -> None:
        """Start a daemon thread that throttles CPU via SIGSTOP/SIGCONT."""
        import threading
        import time

        period = 0.1  # 100ms cycle
        run_time = period * pct / 100
        stop_time = period - run_time
        stop_event = threading.Event()
        self._throttle_stop = stop_event

        def _loop():
            while not stop_event.is_set():
                if stop_event.wait(run_time):
                    break
                try:
                    os.killpg(pgid, signal.SIGSTOP)
                except ProcessLookupError:
                    break
                if stop_event.wait(stop_time):
                    # Ensure we resume before exiting
                    try:
                        os.killpg(pgid, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
                    break
                try:
                    os.killpg(pgid, signal.SIGCONT)
                except ProcessLookupError:
                    break

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        self._throttle_thread = t

    def _stop_throttle(self) -> None:
        """Stop the throttle thread and ensure the child is resumed."""
        if self._throttle_stop is not None:
            self._throttle_stop.set()
        if self._throttle_thread is not None:
            self._throttle_thread.join(timeout=1.0)
            self._throttle_thread = None
            self._throttle_stop = None

    def _stop_disk_quota(self) -> None:
        """Stop the disk quota thread."""
        if self._disk_quota_stop is not None:
            self._disk_quota_stop.set()
        if self._disk_quota_thread is not None:
            self._disk_quota_thread.join(timeout=2.0)
            self._disk_quota_thread = None
            self._disk_quota_stop = None

    def _reap(self) -> None:
        """Reap the child process (non-blocking, best-effort)."""
        if self._pid is not None:
            try:
                os.waitpid(self._pid, os.WNOHANG)
            except ChildProcessError:
                pass
        self._close_pidfd()

    @property
    def control_fd(self) -> int:
        """Parent's end of the control socket (-1 if not available)."""
        return self._control_fd

    def _close_pidfd(self) -> None:
        """Close the pidfd and control fd if open."""
        if self._pidfd >= 0:
            try:
                os.close(self._pidfd)
            except OSError:
                pass
            self._pidfd = -1
        if self._control_fd >= 0:
            try:
                os.close(self._control_fd)
            except OSError:
                pass
            self._control_fd = -1

    # Paths that Landlock can enforce on procfs/sysfs.  Added to
    # fs_denied as defense-in-depth alongside the seccomp notification
    # rules that block the rest (kallsyms, modules, keys, mounts, etc.).
    _PROC_DENY_PATHS = [
        "/proc/kcore", "/proc/config.gz",
        "/proc/sched_debug", "/proc/timer_list",
        "/sys/kernel", "/sys/firmware", "/sys/fs/cgroup",
    ]

    def __enter__(self) -> "SandboxContext":
        global _confined
        self._notif_policy = self._policy.notif_policy
        self._has_proc = any(
            p == "/proc" or p.rstrip("/") == "/proc"
            for p in self._policy.fs_readable
        )
        # /proc hardening when /proc is readable:
        # - Always: sensitive file blocking + mount info virtualization
        #   via default_proc_rules() (enforced in seccomp notification)
        # - When isolate_pids=True: hide foreign PIDs via getdents64 +
        #   openat interception (fast prefix check skips non-/proc paths)
        if self._has_proc:
            from ._notif_policy import NotifPolicy, default_proc_rules
            import dataclasses
            proc_rules = default_proc_rules()
            isolate = self._policy.isolate_pids
            if self._notif_policy is None:
                self._notif_policy = NotifPolicy(
                    rules=proc_rules,
                    isolate_pids=isolate,
                )
            else:
                merged_rules = self._notif_policy.rules + proc_rules
                self._notif_policy = dataclasses.replace(
                    self._notif_policy,
                    rules=merged_rules,
                    isolate_pids=isolate or self._notif_policy.isolate_pids,
                )
        use_notif = self._notif_policy is not None

        # Pre-import modules used in the child BEFORE fork — the child's
        # Landlock policy won't include the sandlock source directory, so
        # lazy imports after confinement would fail.  After fork these are
        # just sys.modules lookups.
        if use_notif:
            from ._notif import install_notif_filter, send_fd  # noqa: F811
        if (self._notif_policy is not None
                and self._notif_policy.time_start is not None):
            import time as _time  # noqa: F811
            from ._vdso import disable_vdso_local  # noqa: F811
        if self._save_fn is not None:
            from ._checkpoint import start_child_listener  # noqa: F811
        # User namespace is needed for privileged mode or overlayfs
        from .policy import FsIsolation
        needs_overlay = self._policy.fs_isolation == FsIsolation.OVERLAYFS
        needs_userns = self._policy.privileged or needs_overlay
        if needs_userns:
            from ._userns import unshare_user, setup_userns_in_parent, userns_available  # noqa: F811

        # Sync pipes for user namespace setup:
        #   child_to_parent: child signals "I've unshared"
        #   parent_to_child: parent signals "maps written, proceed"
        userns_c2p_r, userns_c2p_w = (-1, -1)
        userns_p2c_r, userns_p2c_w = (-1, -1)
        if needs_userns:
            userns_c2p_r, userns_c2p_w = os.pipe()
            userns_p2c_r, userns_p2c_w = os.pipe()

        # Become a subreaper — orphaned descendants get reparented to us,
        # even if they change their process group.
        _libc.prctl(ctypes.c_int(36), ctypes.c_ulong(1),  # PR_SET_CHILD_SUBREAPER
                     ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))

        # Create socket pair for passing the notify fd from child to parent.
        # Skip in nested sandboxes — notif filter can't be stacked.
        if use_notif and not _is_already_confined():
            parent_sock, child_sock = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_STREAM,
            )
        else:
            parent_sock = child_sock = None

        # Create control socket pair for checkpoint commands (bidirectional)
        ctrl_parent, ctrl_child = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM,
        )
        ctrl_parent_fd = ctrl_parent.fileno()
        ctrl_child_fd = ctrl_child.fileno()

        try:
            pid = os.fork()
        except OSError as e:
            ctrl_parent.close()
            ctrl_child.close()
            if parent_sock is not None:
                parent_sock.close()
                child_sock.close()
            raise ForkError(f"fork() failed: {e}") from e

        if pid == 0:
            # === Child process ===
            ctrl_parent.close()
            if parent_sock is not None:
                parent_sock.close()
            try:
                os.setpgid(0, 0)

                # Allow parent to ptrace us (needed for checkpoint on
                # kernels with yama ptrace_scope=1)
                _PR_SET_PTRACER = 0x59616d61  # Yama-specific
                _libc.prctl(ctypes.c_int(_PR_SET_PTRACER),
                            ctypes.c_ulong(os.getppid()),
                            ctypes.c_ulong(0), ctypes.c_ulong(0),
                            ctypes.c_ulong(0))

                # Kill this child if the supervisor/parent dies
                _PR_SET_PDEATHSIG = 1
                _libc.prctl(ctypes.c_int(_PR_SET_PDEATHSIG),
                            ctypes.c_ulong(signal.SIGKILL),
                            ctypes.c_ulong(0), ctypes.c_ulong(0),
                            ctypes.c_ulong(0))

                # 1. User namespace for privileged mode (if needed)
                if needs_userns and userns_c2p_w >= 0:
                    os.close(userns_c2p_r)
                    os.close(userns_p2c_w)
                    try:
                        unshare_user()
                        os.write(userns_c2p_w, b"1")  # Tell parent: unshared
                        os.close(userns_c2p_w)
                        os.read(userns_p2c_r, 1)       # Wait: maps written
                        os.close(userns_p2c_r)
                    except OSError:
                        os.write(userns_c2p_w, b"0")
                        os.close(userns_c2p_w)
                        os.close(userns_p2c_r)
                        if self._policy.strict and self._policy.privileged:
                            raise ConfinementError(
                                "User namespace unavailable and policy.privileged=True"
                            )

                # 1b. Mount namespace + overlayfs (if needed)
                if needs_overlay and self._overlay_branch is not None:
                    from ._overlayfs import mount_overlay
                    CLONE_NEWNS = 0x00020000
                    ret = _libc.unshare(ctypes.c_int(CLONE_NEWNS))
                    if ret < 0:
                        err = ctypes.get_errno()
                        raise ConfinementError(
                            f"unshare(NEWNS) failed: {os.strerror(err)}"
                        )
                    mount_overlay(self._overlay_branch)

                # 2. chroot if requested
                if self._policy.chroot:
                    setup_chroot(self._policy.chroot)

                # 2b. chdir to workdir if set
                # Use the rewritten workdir path (may point to overlay merged dir)
                if self._policy.workdir:
                    # Check if overlay branch rewrote the path
                    if self._overlay_branch is not None:
                        os.chdir(str(self._overlay_branch.path))
                    else:
                        os.chdir(self._policy.workdir)

                # 3. Disable ASLR for deterministic memory layout
                if self._policy.no_randomize_memory:
                    ADDR_NO_RANDOMIZE = 0x0040000
                    _libc.personality(ctypes.c_ulong(ADDR_NO_RANDOMIZE))

                # 3a. Disable THP for deterministic page sizes
                if self._policy.no_huge_pages:
                    _PR_SET_THP_DISABLE = 41
                    _libc.prctl(ctypes.c_int(_PR_SET_THP_DISABLE),
                                ctypes.c_ulong(1),
                                ctypes.c_ulong(0), ctypes.c_ulong(0),
                                ctypes.c_ulong(0))

                # 3b. Disable core dumps and /proc/pid access
                if self._policy.no_coredump:
                    import resource
                    # PR_SET_DUMPABLE=0 restricts /proc/pid access and
                    # disables core dumps.  Effective before exec;
                    # exec() resets dumpable to 1, so for Sandbox.run()
                    # we also set RLIMIT_CORE=0 which survives exec.
                    _PR_SET_DUMPABLE = 4
                    _libc.prctl(ctypes.c_int(_PR_SET_DUMPABLE),
                                ctypes.c_ulong(0),
                                ctypes.c_ulong(0), ctypes.c_ulong(0),
                                ctypes.c_ulong(0))
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

                # 4. Landlock confinement (filesystem + network, irreversible)
                writable = list(self._policy.fs_writable)
                readable = list(self._policy.fs_readable)
                denied = list(self._policy.fs_denied)

                # Auto-deny sensitive /proc paths when /proc is readable
                if self._has_proc:
                    for p in self._PROC_DENY_PATHS:
                        if p not in denied:
                            denied.append(p)

                # GPU device access
                if self._policy.gpu_devices is not None:
                    _gpu_rw = [
                        "/dev/nvidia*", "/dev/nvidiactl",
                        "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools",
                        "/dev/dri",
                    ]
                    _gpu_ro = [
                        "/proc/driver/nvidia",
                        "/sys/bus/pci/devices",
                        "/sys/module/nvidia",
                    ]
                    for p in _gpu_rw:
                        if p not in writable:
                            writable.append(p)
                    for p in _gpu_ro:
                        if p not in readable:
                            readable.append(p)
                bind_ports = self._policy.bind_ports() or None
                connect_ports = self._policy.connect_ports() or None
                if (writable or readable or bind_ports or connect_ports
                        or self._policy.isolate_ipc
                        or self._policy.isolate_signals):
                    try:
                        confine(
                            writable=writable,
                            readable=readable,
                            denied=denied,
                            bind_ports=bind_ports,
                            connect_ports=connect_ports,
                            isolate_ipc=self._policy.isolate_ipc,
                            isolate_signals=self._policy.isolate_signals,
                        )
                    except LandlockUnavailableError:
                        if self._policy.strict:
                            raise ConfinementError(
                                "Landlock unavailable and policy.strict=True"
                            )
                    except ConfinementError:
                        if self._policy.strict:
                            raise

                # 5. Start checkpoint/clone listener thread (if save_fn provided)
                #    Must happen BEFORE seccomp — seccomp blocks clone3
                #    which Python's threading module uses.
                if self._clone_loop_fn is not None:
                    pass  # Keep ctrl_child_fd open for clone_ready_loop
                elif self._save_fn is not None:
                    try:
                        start_child_listener(ctrl_child_fd, self._save_fn)
                    except RuntimeError:
                        os.close(ctrl_child_fd)
                else:
                    os.close(ctrl_child_fd)

                # 6. seccomp filter (irreversible)
                # When notif is active, build a single combined filter
                # (notif + deny in one BPF program) to avoid stacked-filter
                # CONTINUE re-evaluation issues.
                deny = (
                    list(self._policy.deny_syscalls)
                    if self._policy.deny_syscalls is not None
                    else None
                )
                allow = (
                    list(self._policy.allow_syscalls)
                    if self._policy.allow_syscalls is not None
                    else None
                )

                _no_raw = self._policy.no_raw_sockets
                _no_udp = self._policy.no_udp

                if use_notif and child_sock is not None and not _is_already_confined():
                    # First-level sandbox: install combined notif + BPF filter
                    try:
                        from ._landlock import _set_no_new_privs
                        _set_no_new_privs()
                        notify_fd = install_notif_filter(
                            _notif_syscall_names(self._notif_policy),
                            deny_syscalls=deny,
                            allow_syscalls=allow,
                            no_raw_sockets=_no_raw,
                            no_udp=_no_udp,
                        )
                        send_fd(child_sock, notify_fd)
                        os.close(notify_fd)
                    except Exception as e:
                        if self._policy.strict:
                            raise ConfinementError(
                                f"seccomp notif filter failed: {e}"
                            )
                    finally:
                        child_sock.close()
                    if allow is not None:
                        try:
                            apply_seccomp_filter(
                                allow_syscalls=allow,
                                no_raw_sockets=_no_raw,
                                no_udp=_no_udp,
                            )
                        except Exception:
                            if self._policy.strict:
                                raise ConfinementError(
                                    "seccomp allowlist filter failed"
                                )
                else:
                    # Nested sandbox or no notif: stack a BPF deny/allow
                    # filter.  BPF filters are ANDed by the kernel, so
                    # each nesting level can only tighten.
                    if child_sock is not None:
                        child_sock.close()
                    try:
                        apply_seccomp_filter(
                            deny, allow,
                            no_raw_sockets=_no_raw,
                            no_udp=_no_udp,
                        )
                    except Exception:
                        if self._policy.strict:
                            raise ConfinementError(
                                "seccomp filter installation failed"
                            )

                # Mark this process as confined so nested SandboxContext
                # instances know to skip the notif filter.
                _confined = True

                # 7. Close inherited fds (exempt control socket)
                if self._policy.close_fds:
                    max_fd = os.sysconf("SC_OPEN_MAX")
                    os.closerange(3, ctrl_child_fd)
                    os.closerange(ctrl_child_fd + 1, max_fd)

                # 8. Environment variable control
                if self._policy.clean_env:
                    keep = {}
                    for k in ("PATH", "HOME", "USER", "TERM", "LANG", "SHELL"):
                        if k in os.environ:
                            keep[k] = os.environ[k]
                    os.environ.clear()
                    os.environ.update(keep)
                if self._policy.env:
                    os.environ.update(self._policy.env)

                # 8b. GPU device visibility
                if self._policy.gpu_devices is not None:
                    devs = self._policy.gpu_devices
                    if len(devs) > 0:
                        vis = ",".join(str(d) for d in devs)
                        os.environ["CUDA_VISIBLE_DEVICES"] = vis
                        os.environ["ROCR_VISIBLE_DEVICES"] = vis

                # 9b. Disable vDSO for time virtualization
                if (self._notif_policy is not None
                        and self._notif_policy.time_start is not None):
                    import time as _time
                    from ._vdso import disable_vdso_local
                    mono_offset = -int(_time.monotonic())
                    disable_vdso_local(mono_offset_s=mono_offset)

                # 9c. Limit open file descriptors (after all setup fds are closed)
                if self._policy.max_open_files is not None:
                    import resource
                    n = self._policy.max_open_files
                    resource.setrlimit(resource.RLIMIT_NOFILE, (n, n))

                # 10. Run target (or clone-ready loop)
                if self._clone_loop_fn is not None:
                    self._clone_loop_fn(ctrl_child_fd)
                else:
                    self._target()
                os._exit(0)
            except SystemExit as e:
                os._exit(e.code if isinstance(e.code, int) else 1)
            except BaseException:
                os._exit(1)
        else:
            # === Parent process ===
            ctrl_child.close()
            self._control_fd = ctrl_parent.detach()

            # Write UID/GID maps for the child's user namespace
            if needs_userns and userns_c2p_r >= 0:
                os.close(userns_c2p_w)
                os.close(userns_p2c_r)
                status = os.read(userns_c2p_r, 1)  # Wait: child unshared
                os.close(userns_c2p_r)
                if status == b"1":
                    try:
                        setup_userns_in_parent(
                            pid, privileged=self._policy.privileged,
                        )
                    except OSError:
                        pass  # Best-effort
                os.write(userns_p2c_w, b"1")  # Signal: maps written, proceed
                os.close(userns_p2c_w)

            if child_sock is not None:
                child_sock.close()

            self._pid = pid
            self._pidfd = _pidfd_open(pid)

            # Race-free process group setup
            try:
                os.setpgid(pid, pid)
            except OSError:
                pass  # Child may have already set it

            # Receive notify fd and start supervisor
            if use_notif and parent_sock is not None:
                try:
                    from ._notif import recv_fd, NotifSupervisor
                    notify_fd = recv_fd(parent_sock)
                    parent_sock.close()
                    pids_fn = lambda pgid=pid: _pids_by_pgid(pgid)  # noqa: E731
                    # Disk quota for overlayfs upper dir
                    dq_path = None
                    dq_bytes = 0
                    if self._overlay_branch is not None and self._policy.max_disk:
                        from .policy import parse_memory_size
                        dq_path = str(self._overlay_branch.upper_dir)
                        dq_bytes = parse_memory_size(self._policy.max_disk)
                    self._supervisor = NotifSupervisor(
                        notify_fd, pid, self._notif_policy,
                        pids_fn=pids_fn,
                        disk_quota_path=dq_path,
                        disk_quota_bytes=dq_bytes,
                    )
                    # Attach COW handler for seccomp-based COW
                    if self._cow_branch is not None:
                        from .cowfs._handler import CowHandler
                        self._supervisor._cow_handler = CowHandler(self._cow_branch)
                    self._supervisor.start()
                except Exception:
                    try:
                        parent_sock.close()
                    except OSError:
                        pass

            # Start disk quota thread if COW + max_disk
            if (self._overlay_branch or self._cow_branch) and self._policy.max_disk:
                self._start_disk_quota(pid)

            # Start CPU throttle thread if max_cpu is set
            cpu_pct = self._policy.cpu_pct()
            if cpu_pct is not None and cpu_pct < 100:
                self._start_throttle(pid, cpu_pct)

            return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.abort()
        return False
