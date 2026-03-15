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

# Set after seccomp confinement in the child.  Any subsequent
# SandboxContext in this process is nested and must skip the
# notif filter (can't install two).
_confined = False


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

    openat is always intercepted.  open is added on x86_64 (not
    present on aarch64).  connect and sendto are added when
    allowed_ips is set for network enforcement.
    """
    from ._seccomp import _SYSCALL_NR
    names = ["openat"]
    if "open" in _SYSCALL_NR:
        names.append("open")
    if notif is not None and notif.allowed_ips:
        names.extend(["connect", "sendto"])
    if notif is not None and notif.max_memory_bytes > 0:
        names.extend(["mmap", "munmap", "brk", "mremap"])
    if notif is not None and notif.max_processes > 0:
        names.extend(["clone", "fork", "vfork"])
    if notif is not None and notif.isolate_pids:
        names.append("getdents64")
        if "getdents" in _SYSCALL_NR:
            names.append("getdents")
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
    """

    def __init__(
        self,
        target: Callable[[], None],
        policy: Policy,
        sandbox_id: str,
        *,
        save_fn: Callable[[], bytes] | None = None,
    ):
        self._target = target
        self._policy = policy
        self._sandbox_id = sandbox_id
        self._save_fn = save_fn
        self._pid: Optional[int] = None
        self._pidfd: int = -1
        self._supervisor = None  # NotifSupervisor | None (lazy import)
        self._throttle_stop = None  # threading.Event | None
        self._throttle_thread = None  # threading.Thread | None
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
            return os.waitstatus_to_exitcode(status)

        # Event-driven: pidfd becomes readable when child exits
        if not _pidfd_poll(self._pidfd, timeout):
            raise TimeoutError(
                f"Process {self._pid} did not exit within {timeout}s"
            )

        try:
            _, status = os.waitpid(self._pid, os.WNOHANG)
            self._exited = True
            return os.waitstatus_to_exitcode(status)
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

        # Stop throttle first — ensure child is resumed for clean exit
        self._stop_throttle()

        # Stop supervisor — it reads from child memory
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

    def __enter__(self) -> "SandboxContext":
        # Auto-enable /proc PID isolation when /proc is readable
        self._notif_policy = self._policy.notif_policy
        has_proc = any(
            p == "/proc" or p.rstrip("/") == "/proc"
            for p in self._policy.fs_readable
        )
        if has_proc:
            from ._notif_policy import NotifPolicy, default_proc_rules
            import dataclasses
            if self._notif_policy is None:
                self._notif_policy = NotifPolicy(
                    rules=default_proc_rules(),
                    isolate_pids=True,
                )
            elif not self._notif_policy.isolate_pids:
                self._notif_policy = dataclasses.replace(
                    self._notif_policy,
                    isolate_pids=True,
                )
        use_notif = self._notif_policy is not None

        # Pre-import modules used in the child BEFORE fork — the child's
        # Landlock policy won't include the sandlock source directory, so
        # lazy imports after confinement would fail.  After fork these are
        # just sys.modules lookups.
        if use_notif:
            from ._notif import install_notif_filter, send_fd  # noqa: F811
        if self._save_fn is not None:
            from ._checkpoint import start_child_listener  # noqa: F811
        # User namespace is only needed for privileged mode (UID 0 mapping)
        needs_userns = self._policy.privileged
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

        # Create socket pair for passing the notify fd from child to parent
        if use_notif:
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
            global _confined
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

                # 2. chroot if requested
                if self._policy.chroot:
                    setup_chroot(self._policy.chroot)

                # 4. Landlock confinement (filesystem + network, irreversible)
                writable = list(self._policy.fs_writable)
                readable = list(self._policy.fs_readable)
                denied = list(self._policy.fs_denied)
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

                # 5. Start checkpoint listener thread (if save_fn provided)
                #    Must happen BEFORE seccomp — seccomp blocks clone3
                #    which Python's threading module uses.
                if self._save_fn is not None:
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

                if use_notif and child_sock is not None:
                    if _confined:
                        # Nested sandbox: parent's supervisor already
                        # intercepts our syscalls.  Skip notif filter.
                        child_sock.close()
                    else:
                        try:
                            from ._landlock import _set_no_new_privs
                            _set_no_new_privs()
                            notify_fd = install_notif_filter(
                                _notif_syscall_names(self._notif_policy),
                                deny_syscalls=deny,
                                allow_syscalls=allow,
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
                    # Combined filter handles deny — install allowlist
                    # separately only if in allowlist mode (the combined
                    # filter can't enumerate all syscalls to deny).
                    if allow is not None:
                        try:
                            apply_seccomp_filter(allow_syscalls=allow)
                        except Exception:
                            if self._policy.strict:
                                raise ConfinementError(
                                    "seccomp allowlist filter failed"
                                )
                else:
                    try:
                        apply_seccomp_filter(deny, allow)
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

                # 10. Run target
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
                    self._supervisor = NotifSupervisor(
                        notify_fd, pid, self._notif_policy,
                        pids_fn=pids_fn,
                    )
                    self._supervisor.start()
                except Exception:
                    try:
                        parent_sock.close()
                    except OSError:
                        pass

            # Start CPU throttle thread if max_cpu is set
            cpu_pct = self._policy.cpu_pct()
            if cpu_pct is not None and cpu_pct < 100:
                self._start_throttle(pid, cpu_pct)

            return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.abort()
        return False
