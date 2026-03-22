# SPDX-License-Identifier: Apache-2.0
"""Sandbox class: main user-facing API for Sandlock.

Wraps SandboxContext and result passing into a clean interface
for one-shot and long-lived sandboxing.
"""

from __future__ import annotations

import os
import signal
import time
import uuid
import warnings
from pathlib import Path
from typing import Any, Callable, Optional

from .exceptions import SandboxError, BranchError
from .policy import BranchAction, FsIsolation, Policy
from ._context import SandboxContext
from ._runner import Result, run_command_in_sandbox, run_interactive_in_sandbox

# Flags to strip when reopening files — creation-time flags that would
# fail or cause side effects on an existing file.
_FD_STRIP_FLAGS = os.O_CREAT | os.O_EXCL | os.O_TRUNC


def _restore_process_env(process_state) -> None:
    """Restore working directory and file descriptors from ProcessState.

    Called inside the forked child before restore_fn runs.  Skips
    non-restorable fds (pipes, sockets) and fds 0-2 (stdio).
    Errors on individual fds are warned, not fatal.
    """
    # Restore cwd
    if process_state.cwd:
        try:
            os.chdir(process_state.cwd)
        except OSError:
            warnings.warn(
                f"Could not restore cwd {process_state.cwd!r}",
                RuntimeWarning,
                stacklevel=2,
            )

    # Restore file descriptors (sorted by fd number to minimise dup2 conflicts)
    for fd in sorted(process_state.fds, key=lambda f: f.fd):
        if fd.fd <= 2:
            continue  # Skip stdio
        if not fd.restorable:
            continue  # Skip pipes, sockets, anon_inode, etc.
        try:
            open_flags = fd.flags & ~_FD_STRIP_FLAGS
            opened = os.open(fd.path, open_flags)
            if opened != fd.fd:
                os.dup2(opened, fd.fd)
                os.close(opened)
            if fd.offset > 0 and not (fd.flags & os.O_APPEND):
                os.lseek(fd.fd, fd.offset, os.SEEK_SET)
        except OSError:
            warnings.warn(
                f"Could not restore fd {fd.fd} ({fd.path!r})",
                RuntimeWarning,
                stacklevel=2,
            )


class Sandbox:
    """Lightweight process sandbox.

    Uses Landlock (filesystem) and seccomp (syscall filter) for
    confinement.  No root or namespaces required.

    Usage::

        # One-shot command
        result = Sandbox(policy).run(["python", "untrusted.py"])

        # Long-lived sandbox
        with Sandbox(policy) as sb:
            sb.exec(["python", "server.py"])
            sb.pause()
            sb.resume()
    """

    def __new__(cls, policy: "Policy | str", init_fn=None, work_fn=None, *, host: str | None = None, **kwargs):
        if host is not None:
            try:
                from .deploy._sandbox import RemoteSandbox
            except ImportError:
                raise ImportError(
                    "Remote sandbox requires sandlock[deploy]. "
                    "Install with: pip install sandlock[deploy]"
                ) from None
            return RemoteSandbox(policy, host=host, **kwargs)
        return super().__new__(cls)

    def __init__(
        self,
        policy: Policy | str,
        init_fn: Optional[Callable] = None,
        work_fn: Optional[Callable] = None,
        *,
        host: str | None = None,
        sandbox_id: str | None = None,
        **kwargs,
    ):
        if host is not None:
            return  # RemoteSandbox already initialized via __new__
        if isinstance(policy, str):
            from ._profile import load_profile
            policy = load_profile(policy)
        self._policy = policy
        self._init_fn = init_fn
        self._work_fn = work_fn
        self._id = sandbox_id or uuid.uuid4().hex[:12]
        self._ctx: SandboxContext | None = None
        self._branch = None  # SandboxBranch | None (lazy import)
        self._parent_branch_path = None  # Path | None (for nested sandboxes)
        self._owns_mount = False  # True if we auto-mounted BranchFS
        self._entered = False
        self._clone_pid = None  # int | None (PID for COW clones)

    @property
    def id(self) -> str:
        return self._id

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def pid(self) -> int | None:
        """PID of the sandboxed process, or None if not running."""
        if hasattr(self, '_clone_pid') and self._clone_pid is not None:
            return self._clone_pid
        if self._ctx is not None:
            try:
                return self._ctx.pid
            except SandboxError:
                return None
        return None

    @property
    def alive(self) -> bool:
        """Whether the sandboxed process is still running."""
        clone_pid = getattr(self, '_clone_pid', None)
        if clone_pid is not None:
            try:
                os.kill(clone_pid, 0)
                return True
            except ProcessLookupError:
                return False
        return self._ctx is not None and self._ctx.alive

    @property
    def is_paused(self) -> bool:
        """Whether the sandbox is paused (SIGSTOP'd)."""
        pid = self.pid
        if pid is None:
            return False
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("State:"):
                        return "T" in line or "t" in line
        except OSError:
            pass
        return False

    # --- One-shot API ---

    def run(self, cmd: list[str], *, timeout: float | None = None) -> Result:
        """Run a command in a sandbox and return the result.

        Creates a temporary sandbox, runs the command, and tears down.
        For long-lived sandboxes, use the context manager API instead.

        Args:
            cmd: Command and arguments to execute.
            timeout: Maximum seconds to wait.

        Returns:
            Result with exit_code, stdout, stderr.
        """
        branch = self._setup_branch()
        policy = self._effective_policy()
        try:
            result = run_command_in_sandbox(
                cmd, policy, self._id,
                timeout=timeout,
            )
            self._finish_branch(error=not result.success)
            return result
        except BaseException:
            self._finish_branch(error=True)
            raise
        finally:
            self._cleanup_mount()

    def run_interactive(self, cmd: list[str], *, timeout: float | None = None) -> Result:
        """Run a command interactively in a sandbox.

        Unlike run(), stdin/stdout/stderr are inherited directly from the
        parent process so the child can interact with the terminal.

        Args:
            cmd: Command and arguments to execute.
            timeout: Maximum seconds to wait.

        Returns:
            Result with exit_code (stdout/stderr are empty).
        """
        branch = self._setup_branch()
        policy = self._effective_policy()
        try:
            result = run_interactive_in_sandbox(
                cmd, policy, self._id,
                timeout=timeout,
            )
            self._finish_branch(error=not result.success)
            return result
        except BaseException:
            self._finish_branch(error=True)
            raise
        finally:
            self._cleanup_mount()

    # --- Context manager API (long-lived sandbox) ---

    def __enter__(self) -> "Sandbox":
        self._setup_branch()
        self._entered = True

        # If init_fn + work_fn were provided, start the clone-ready loop
        if self._init_fn is not None and self._work_fn is not None:
            self._start_clone_loop()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self._entered = False
        if self._ctx is not None:
            self._ctx.abort()
            self._ctx = None
        self._finish_branch(error=exc_type is not None)
        self._cleanup_mount()
        return False

    def exec(
        self,
        cmd: list[str],
        *,
        save_fn: Callable[[], bytes] | None = None,
    ) -> None:
        """Execute a command in the long-lived sandbox.

        Must be used within a ``with Sandbox(policy) as sb:`` block.

        Args:
            cmd: Command and arguments to execute.
            save_fn: Optional checkpoint function.  If provided, the child
                starts a listener thread; calling ``sandbox.checkpoint()``
                triggers save_fn in the child and returns the bytes.
                save_fn must return raw bytes. Sandlock does not impose
                any serialization format.

        Raises:
            SandboxError: If not in a context manager or already running.
        """
        if not self._entered:
            raise SandboxError("exec() requires context manager (use 'with Sandbox(...) as sb:')")
        if self._ctx is not None and self._ctx.alive:
            raise SandboxError("Sandbox already has a running process")

        def _target() -> None:
            try:
                os.execvp(cmd[0], cmd)
            except OSError as e:
                os._exit(127)

        ctx = SandboxContext(
            _target, self._effective_policy(), self._id,
            save_fn=save_fn,
        )
        try:
            ctx.__enter__()
        except BaseException:
            ctx.__exit__(None, None, None)
            raise
        self._ctx = ctx

    def wait(self, timeout: float | None = None) -> int:
        """Wait for the sandboxed process to exit.

        Returns:
            Exit code.
        """
        clone_pid = getattr(self, '_clone_pid', None)
        if clone_pid is not None:
            # Clone is not our direct child (it's the template's child),
            # so we can't use waitpid.  Use pidfd to wait for exit.
            from ._context import _pidfd_open, _pidfd_poll
            pidfd = _pidfd_open(clone_pid)
            try:
                wait_time = timeout if timeout is not None else 3600.0
                if not _pidfd_poll(pidfd, wait_time):
                    raise TimeoutError(
                        f"Process {clone_pid} did not exit within {timeout}s"
                    )
            finally:
                os.close(pidfd)
            self._clone_pid = None
            return 0  # pidfd only tells us it exited, not the code
        if self._ctx is None:
            raise SandboxError("No process running")
        return self._ctx.wait(timeout=timeout)

    # --- Pause/Resume ---

    def pause(self) -> None:
        """Pause the sandbox by sending SIGSTOP to the process group."""
        p = self.pid
        if p is None or not self.alive:
            raise SandboxError("No running process to pause")
        if self._clone_pid is not None:
            os.kill(p, signal.SIGSTOP)
        else:
            os.killpg(p, signal.SIGSTOP)

    def resume(self) -> None:
        """Resume the sandbox by sending SIGCONT.

        Uses ``kill`` for COW clones (single process) and ``killpg``
        for regular sandboxes (entire process group).
        """
        p = self.pid
        if p is None or not self.alive:
            raise SandboxError("No running process to resume")
        try:
            if self._clone_pid is not None:
                os.kill(p, signal.SIGCONT)
            else:
                os.killpg(p, signal.SIGCONT)
        except ProcessLookupError:
            raise SandboxError("Process no longer exists")

    # --- Checkpoint/Restore ---

    def checkpoint(self) -> "Checkpoint":
        """Checkpoint the running sandbox.

        Captures three layers of state:

        1. **OS-level** (always, transparent): ptrace dumps registers,
           memory contents, and file descriptors.

        2. **App-level** (optional, cooperative): If ``exec()`` was
           called with ``save_fn``, triggers it via the control socket.

        3. **Filesystem** (if BranchFS active): O(1) COW snapshot.

        Freeze sequence (cgroup-like, no root):
            1. supervisor.hold_forks()     -- block all fork/clone in kernel
            2. SIGSTOP each tracked PID    -- stop running processes
            3. branchfs snapshot           -- O(1) fs snapshot
            4. ptrace dump                 -- registers, memory, fds
            5. SIGCONT + save_fn           -- app-level state (optional)
            6. supervisor.release_forks()  -- unblock held forks
            7. SIGCONT all                 -- resume

        Returns:
            Checkpoint with OS state, optional app state, and branch ref.
        """
        import pickle
        from ._checkpoint import Checkpoint, request_app_state
        from ._ptrace import dump_process_state

        if self._ctx is None or not self._ctx.alive:
            raise SandboxError("No running process to checkpoint")

        pid = self._ctx.pid
        supervisor = self._ctx._supervisor

        # 1. Hold forks -- any in-flight fork blocks in kernel
        if supervisor is not None:
            supervisor.hold_forks()

        try:
            # 2. Stop all tracked PIDs individually
            if supervisor is not None:
                for p in supervisor.tracked_pids:
                    try:
                        os.kill(p, signal.SIGSTOP)
                    except ProcessLookupError:
                        pass
            else:
                os.killpg(pid, signal.SIGSTOP)

            # 3. Snapshot filesystem via BranchFS (O(1))
            snapshot_branch_id = None
            if self._branch is not None:
                from ._branchfs import SandboxBranch
                snapshot = SandboxBranch(
                    self._branch.mount_root,
                    parent_path=self._branch.path,
                )
                snapshot.create()
                snapshot_branch_id = snapshot.branch_id

            # 4. Transparent OS-level dump (while stopped)
            process_state = dump_process_state(pid)

            # 5. App-level state (optional -- requires save_fn + resume)
            app_state = None
            control_fd = self._ctx.control_fd
            if control_fd >= 0:
                os.kill(pid, signal.SIGCONT)
                try:
                    app_state = request_app_state(control_fd)
                except (EOFError, RuntimeError, OSError):
                    pass
                os.kill(pid, signal.SIGSTOP)

        finally:
            # 6. Release held forks
            if supervisor is not None:
                supervisor.release_forks()

            # 7. Resume all
            if supervisor is not None:
                for p in supervisor.tracked_pids:
                    try:
                        os.kill(p, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
            else:
                os.killpg(pid, signal.SIGCONT)

        return Checkpoint(
            process_state=process_state,
            branch_id=snapshot_branch_id,
            workdir=self._policy.workdir,
            app_state=app_state,
            policy_data=pickle.dumps(self._policy),
            sandbox_id=self._id,
        )

    def _start_clone_loop(self) -> None:
        """Start the clone-ready loop in the sandbox child."""
        _init = self._init_fn
        _work = self._work_fn

        def _clone_loop(ctrl_fd: int) -> None:
            from ._checkpoint import clone_ready_loop
            _init()
            clone_ready_loop(ctrl_fd, _work)

        ctx = SandboxContext(
            lambda: None, self._effective_policy(), self._id,
            clone_loop_fn=_clone_loop,
        )
        try:
            ctx.__enter__()
        except BaseException:
            ctx.__exit__(None, None, None)
            raise
        self._ctx = ctx

    def fork(
        self,
        n: int,
        *,
        env: dict[str, str] | None = None,
    ) -> "list[Sandbox]":
        """Create N COW clones of this sandbox.

        Each clone is an ``os.fork()`` of the template with full
        copy-on-write memory sharing.  Each clone receives a
        ``CLONE_ID`` environment variable (0 through N-1).

        Args:
            n: Number of clones to create.
            env: Extra environment variables applied to all clones.

        Returns:
            List of Sandbox handles.

        Example::

            with Sandbox(policy, init, work) as sb:
                for c in sb.fork(1000):
                    c.wait()
        """
        if self._ctx is None or not self._ctx.alive:
            raise SandboxError(
                "No running template — pass init_fn and work_fn "
                "to Sandbox()"
            )

        control_fd = self._ctx.control_fd
        if control_fd < 0:
            raise SandboxError("No control socket")

        base = env or {}
        envs = [{**base, "CLONE_ID": str(i)} for i in range(n)]

        from ._checkpoint import request_fork_batch
        pids = request_fork_batch(control_fd, envs)

        clones = []
        for pid in pids:
            sb = Sandbox(self._policy, sandbox_id=None)
            sb._clone_pid = pid
            sb._entered = True
            clones.append(sb)
        return clones

    @classmethod
    def restore(
        cls,
        checkpoint: "Checkpoint",
        restore_fn: Callable[[bytes], None],
        *,
        timeout: float | None = None,
    ) -> Result:
        """Restore a sandbox from a checkpoint.

        Creates a new sandbox with the checkpointed policy.  If the
        checkpoint contains OS-level process state, file descriptors
        and the working directory are restored before ``restore_fn``
        runs.  If BranchFS was used, creates a new branch forked from
        the checkpoint's snapshot.

        Args:
            checkpoint: Checkpoint to restore from.
            restore_fn: Callable that receives the app state bytes and
                rebuilds application state.
            timeout: Maximum seconds to wait for restore_fn.

        Returns:
            Result from the restored sandbox execution.
        """
        import pickle

        policy = pickle.loads(checkpoint.policy_data)

        # If checkpoint has a branch, create a child branch from it
        if checkpoint.branch_id and checkpoint.workdir:
            from ._branchfs import SandboxBranch
            from pathlib import Path

            mount = Path(checkpoint.workdir)
            checkpoint_branch_path = mount / f"@{checkpoint.branch_id}"

            # Override policy to fork from checkpoint branch
            sb = cls(policy)
            sb._parent_branch_path = checkpoint_branch_path
        else:
            sb = cls(policy)

        # The restore target: restore OS environment then run restore_fn.
        app_state = checkpoint.app_state
        process_state = checkpoint.process_state

        def _restore_target():
            if process_state is not None:
                _restore_process_env(process_state)
            restore_fn(app_state)

        branch = sb._setup_branch()
        policy = sb._effective_policy()
        try:
            import dataclasses

            inner_policy = dataclasses.replace(policy, close_fds=False)
            for attr in ('_overlay_branch', '_cow_branch'):
                val = getattr(policy, attr, None)
                if val is not None:
                    object.__setattr__(inner_policy, attr, val)

            try:
                with SandboxContext(
                    _restore_target, inner_policy, sb._id,
                ) as ctx:
                    try:
                        exit_code = ctx.wait(timeout=timeout)
                    except TimeoutError:
                        ctx.abort()
                        result = Result(
                            success=False, exit_code=-1,
                            error="Sandbox timed out",
                        )
                        sb._finish_branch(error=True)
                        return result
            except Exception as e:
                sb._finish_branch(error=True)
                return Result(success=False, exit_code=-1, error=str(e))

            result = Result(
                success=(exit_code == 0),
                exit_code=exit_code,
            )
            sb._finish_branch(error=not result.success)
            return result
        except BaseException:
            sb._finish_branch(error=True)
            raise
        finally:
            sb._cleanup_mount()


    # --- Nested sandbox ---

    def sandbox(self, policy: Policy) -> "Sandbox":
        """Create a nested sandbox with a more restrictive policy.

        If BranchFS isolation is active, the child branch is created
        under the parent's branch.

        Args:
            policy: Policy for the nested sandbox.

        Returns:
            A new Sandbox instance.
        """
        child = Sandbox(policy)
        if self._branch is not None:
            from ._overlayfs import OverlayBranch
            if isinstance(self._branch, OverlayBranch):
                child._parent_overlay_branch = self._branch
            else:
                child._parent_branch_path = self._branch.path
        return child

    # --- Branch operations ---

    def commit(self) -> None:
        """Commit the sandbox's BranchFS branch (merge writes to parent).

        Raises:
            BranchError: If no branch is active.
            BranchConflictError: If a sibling already committed.
        """
        if self._branch is None:
            raise SandboxError("No branch active (fs_isolation is not BRANCH)")
        self._branch.commit()

    def abort_branch(self) -> None:
        """Abort the sandbox's BranchFS branch (discard all writes).

        Raises:
            BranchError: If no branch is active.
        """
        if self._branch is None:
            raise SandboxError("No branch active (fs_isolation is not BRANCH)")
        self._branch.abort()

    @property
    def branch_path(self) -> Path | None:
        """Path to the sandbox's BranchFS branch, or None if not using branches."""
        return self._branch.path if self._branch is not None else None

    # --- Internal ---

    def _setup_branch(self):
        """Create a filesystem branch if policy requires COW isolation.

        Supports BranchFS (FUSE) and OverlayFS (kernel built-in).

        Returns:
            SandboxBranch, OverlayBranch, or None.
        """
        # workdir with fs_isolation=NONE → seccomp-based COW (no namespaces)
        if self._policy.workdir and self._policy.fs_isolation == FsIsolation.NONE:
            if self._branch is not None:
                return self._branch
            from .cowfs._branch import CowBranch
            from pathlib import Path
            storage = Path(self._policy.fs_storage) if self._policy.fs_storage else None
            self._branch = CowBranch(Path(self._policy.workdir), storage)
            self._branch.create()
            return self._branch

        if self._policy.fs_isolation == FsIsolation.NONE:
            return None
        if self._branch is not None:
            return self._branch

        workdir = self._policy.workdir
        if workdir is None:
            raise SandboxError(
                f"fs_isolation={self._policy.fs_isolation.value} requires workdir to be set"
            )

        from pathlib import Path

        if self._policy.fs_isolation == FsIsolation.BRANCHFS:
            from ._branchfs import SandboxBranch, ensure_mount, is_branchfs_mount

            mount_root = Path(workdir)

            # Auto-mount BranchFS if not already mounted
            if not is_branchfs_mount(mount_root):
                ensure_mount(
                    mount_root,
                    storage=Path(self._policy.fs_storage) if self._policy.fs_storage else None,
                    max_disk=self._policy.max_disk,
                )
                self._owns_mount = True

            parent_path = self._parent_branch_path  # None for top-level
            self._branch = SandboxBranch(mount_root, parent_path)
            self._branch.create()

        elif self._policy.fs_isolation == FsIsolation.OVERLAYFS:
            from ._overlayfs import OverlayBranch

            lower = Path(workdir)
            if self._policy.fs_storage:
                storage = Path(self._policy.fs_storage)
            else:
                # Storage must be outside the lowerdir so the parent
                # can see upper dir writes (same pattern as podman).
                import tempfile
                storage = Path(tempfile.mkdtemp(prefix="sandlock-overlay-"))

            parent_branch = None
            if hasattr(self, '_parent_overlay_branch'):
                parent_branch = self._parent_overlay_branch

            self._branch = OverlayBranch(lower, storage, parent_branch)
            self._branch.create()

        return self._branch

    def _effective_policy(self) -> Policy:
        """Return the policy adjusted for branch paths and net_allow_hosts.

        - BranchFS: rewrites fs_writable/fs_readable to the branch path.
        - net_allow_hosts: resolves domains, builds /etc/hosts virtualization
          rules, and merges them into the notif_policy.
        """
        import dataclasses

        policy = self._policy
        overrides: dict = {}

        # --- COW path rewriting (BranchFS and OverlayFS) ---
        if self._branch is not None:
            mount = policy.workdir
            branch_path = str(self._branch.path)

            def _rewrite(paths):
                result = []
                for p in paths:
                    if p == mount or p.rstrip("/") == mount.rstrip("/"):
                        result.append(branch_path)
                    elif p.startswith(mount.rstrip("/") + "/"):
                        result.append(branch_path + p[len(mount.rstrip("/")):])
                    else:
                        result.append(p)
                return result

            overrides["fs_writable"] = _rewrite(list(policy.fs_writable))
            overrides["fs_readable"] = _rewrite(list(policy.fs_readable))

        # --- net_allow_hosts → virtualize /etc/hosts + IP enforcement ---
        if policy.net_allow_hosts:
            from ._notif_policy import (
                NotifPolicy, hosts_rules, resolve_hosts, default_proc_rules,
            )

            hosts_content, allowed_ips = resolve_hosts(policy.net_allow_hosts)
            new_rules = hosts_rules(hosts_content)

            existing = policy.notif_policy
            if existing is not None:
                merged_rules = new_rules + existing.rules
                overrides["notif_policy"] = dataclasses.replace(
                    existing,
                    rules=merged_rules,
                    allowed_ips=allowed_ips,
                )
            else:
                overrides["notif_policy"] = NotifPolicy(
                    rules=new_rules + default_proc_rules(),
                    allowed_ips=allowed_ips,
                )

        # --- Resource limits + port remap → notif_policy ---
        mem_bytes = policy.memory_bytes() or 0
        max_procs = policy.max_processes or 0
        port_remap = policy.port_remap
        random_seed = policy.random_seed
        time_start = policy.time_start_timestamp()
        if (mem_bytes > 0 or max_procs > 0 or port_remap
                or random_seed is not None or time_start is not None):
            from ._notif_policy import NotifPolicy, default_proc_rules

            existing = overrides.get("notif_policy", policy.notif_policy)
            if existing is not None:
                overrides["notif_policy"] = dataclasses.replace(
                    existing,
                    max_memory_bytes=mem_bytes,
                    max_processes=max_procs,
                    port_remap=port_remap,
                    random_seed=random_seed,
                    time_start=time_start,
                )
            else:
                overrides["notif_policy"] = NotifPolicy(
                    max_memory_bytes=mem_bytes,
                    max_processes=max_procs,
                    port_remap=port_remap,
                    random_seed=random_seed,
                    time_start=time_start,
                )

        # --- CowBranch: ensure notif policy with cow_enabled ---
        from .cowfs._branch import CowBranch
        if isinstance(self._branch, CowBranch):
            from ._notif_policy import NotifPolicy, default_proc_rules
            existing = overrides.get("notif_policy", policy.notif_policy)
            if existing is not None:
                overrides["notif_policy"] = dataclasses.replace(
                    existing, cow_enabled=True,
                )
            else:
                overrides["notif_policy"] = NotifPolicy(
                    rules=default_proc_rules(), cow_enabled=True,
                )

        if not overrides:
            result = policy
        else:
            result = dataclasses.replace(policy, **overrides)

        # Attach overlay branch for child-side mount (not a Policy field)
        from ._overlayfs import OverlayBranch
        if isinstance(self._branch, OverlayBranch):
            object.__setattr__(result, '_overlay_branch', self._branch)

        # Attach cow branch for supervisor-side COW (not a Policy field)
        if isinstance(self._branch, CowBranch):
            object.__setattr__(result, '_cow_branch', self._branch)

        return result

    def _cleanup_mount(self) -> None:
        """Unmount BranchFS if we auto-mounted it."""
        if self._owns_mount and self._policy.workdir:
            from ._branchfs import unmount
            from pathlib import Path
            try:
                unmount(Path(self._policy.workdir))
            except Exception:
                pass
            self._owns_mount = False

    def _finish_branch(self, error: bool) -> None:
        """Commit or abort the branch based on policy and exit status."""
        if self._branch is None or self._branch.finished:
            return

        action = self._policy.on_error if error else self._policy.on_exit
        try:
            if action == BranchAction.COMMIT:
                self._branch.commit()
            elif action == BranchAction.ABORT:
                self._branch.abort()
            # BranchAction.KEEP: leave as-is
        except BranchError:
            pass  # Best-effort on cleanup

