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
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from .exceptions import SandboxError, BranchError
from .policy import BranchAction, FsIsolation, Policy
from ._context import SandboxContext
from ._runner import Result, call_in_sandbox, run_command_in_sandbox, run_interactive_in_sandbox


class Sandbox:
    """Lightweight process sandbox.

    Uses Landlock (filesystem) and seccomp (syscall filter) for
    confinement.  No root or namespaces required.

    Usage::

        # One-shot command
        result = Sandbox(policy).run(["python", "untrusted.py"])

        # One-shot callable
        result = Sandbox(policy).call(my_func, args=(arg1,))

        # Long-lived sandbox
        with Sandbox(policy) as sb:
            sb.exec(["python", "server.py"])
            sb.pause()
            sb.resume()
    """

    def __new__(cls, policy: "Policy | str", *, host: str | None = None, **kwargs):
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

    def __init__(self, policy: Policy | str, *, host: str | None = None, sandbox_id: str | None = None, **kwargs):
        if host is not None:
            return  # RemoteSandbox already initialized via __new__
        if isinstance(policy, str):
            from ._profile import load_profile
            policy = load_profile(policy)
        self._policy = policy
        self._id = sandbox_id or uuid.uuid4().hex[:12]
        self._ctx: SandboxContext | None = None
        self._branch = None  # SandboxBranch | None (lazy import)
        self._parent_branch_path = None  # Path | None (for nested sandboxes)
        self._owns_mount = False  # True if we auto-mounted BranchFS
        self._entered = False

    @property
    def id(self) -> str:
        return self._id

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def pid(self) -> int | None:
        """PID of the sandboxed process, or None if not running."""
        if self._ctx is not None:
            try:
                return self._ctx.pid
            except SandboxError:
                return None
        return None

    @property
    def alive(self) -> bool:
        """Whether the sandboxed process is still running."""
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

    def call(
        self,
        fn: Callable,
        args: tuple = (),
        *,
        timeout: float | None = None,
    ) -> Result:
        """Run a Python callable in a sandbox and return the result.

        The callable is executed in a forked child process. The return
        value is passed back via a pipe (must be JSON-serializable).

        Args:
            fn: Callable to execute.
            args: Positional arguments for fn.
            timeout: Maximum seconds to wait.

        Returns:
            Result with the return value or error.
        """
        branch = self._setup_branch()
        policy = self._effective_policy()
        try:
            result = call_in_sandbox(
                fn, args, policy, self._id,
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
        if self._ctx is None:
            raise SandboxError("No process running")
        return self._ctx.wait(timeout=timeout)

    # --- Pause/Resume ---

    def pause(self) -> None:
        """Pause the sandbox by sending SIGSTOP to the process group."""
        if self._ctx is None or not self._ctx.alive:
            raise SandboxError("No running process to pause")
        os.killpg(self._ctx.pid, signal.SIGSTOP)

    def resume(self) -> None:
        """Resume the sandbox by sending SIGCONT to the process group."""
        if self._ctx is None or not self._ctx.alive:
            raise SandboxError("No running process to resume")
        os.killpg(self._ctx.pid, signal.SIGCONT)

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
                except (EOFError, RuntimeError):
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
            fs_mount=self._policy.fs_mount,
            app_state=app_state,
            policy_data=pickle.dumps(self._policy),
            sandbox_id=self._id,
        )

    @classmethod
    def from_checkpoint(
        cls,
        checkpoint: "Checkpoint",
        restore_fn: Callable[[bytes], None],
        *,
        timeout: float | None = None,
    ) -> Result:
        """Restore a sandbox from a checkpoint and run restore_fn.

        Creates a new sandbox with the checkpointed policy. If BranchFS
        was used, creates a new branch forked from the checkpoint's
        snapshot.  Then runs restore_fn(app_state) in the sandbox.

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
        if checkpoint.branch_id and checkpoint.fs_mount:
            from ._branchfs import SandboxBranch
            from pathlib import Path

            mount = Path(checkpoint.fs_mount)
            checkpoint_branch_path = mount / f"@{checkpoint.branch_id}"

            # Override policy to fork from checkpoint branch
            sb = cls(policy)
            sb._parent_branch_path = checkpoint_branch_path
        else:
            sb = cls(policy)

        # The restore target: call restore_fn with the saved state
        app_state = checkpoint.app_state

        def _restore_target():
            restore_fn(app_state)

        return sb.call(_restore_target, timeout=timeout)

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
        """Create a BranchFS branch if policy requires it.

        Auto-mounts BranchFS if not already mounted at fs_mount.

        Returns:
            SandboxBranch or None.
        """
        if self._policy.fs_isolation != FsIsolation.BRANCHFS:
            return None
        if self._branch is not None:
            return self._branch

        fs_mount = self._policy.fs_mount
        if fs_mount is None:
            raise SandboxError(
                "fs_isolation=BRANCHFS requires fs_mount to be set"
            )

        from ._branchfs import SandboxBranch, ensure_mount, is_branchfs_mount
        from pathlib import Path

        mount_root = Path(fs_mount)

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

        # --- BranchFS path rewriting ---
        if self._branch is not None:
            mount = policy.fs_mount
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
        if mem_bytes > 0 or max_procs > 0 or port_remap:
            from ._notif_policy import NotifPolicy, default_proc_rules

            existing = overrides.get("notif_policy", policy.notif_policy)
            if existing is not None:
                overrides["notif_policy"] = dataclasses.replace(
                    existing,
                    max_memory_bytes=mem_bytes,
                    max_processes=max_procs,
                    port_remap=port_remap,
                )
            else:
                overrides["notif_policy"] = NotifPolicy(
                    rules=default_proc_rules(),
                    max_memory_bytes=mem_bytes,
                    max_processes=max_procs,
                    port_remap=port_remap,
                )

        if not overrides:
            return policy
        return dataclasses.replace(policy, **overrides)

    def _cleanup_mount(self) -> None:
        """Unmount BranchFS if we auto-mounted it."""
        if self._owns_mount and self._policy.fs_mount:
            from ._branchfs import unmount
            from pathlib import Path
            try:
                unmount(Path(self._policy.fs_mount))
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

