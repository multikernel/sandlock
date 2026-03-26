# SPDX-License-Identifier: Apache-2.0
"""Runner implementation: pipe-based result passing for fork+exec sandboxing."""

from __future__ import annotations

import dataclasses
import os
import signal
from dataclasses import dataclass, field
from typing import Any, Callable, TYPE_CHECKING

from .exceptions import SandboxError
from ._context import SandboxContext
from .policy import Policy

if TYPE_CHECKING:
    from .sandbox import Sandbox


@dataclass
class Result:
    """Result from a sandbox execution."""

    success: bool
    """Whether the sandboxed code completed without error."""

    exit_code: int = 0
    """Exit code of the child process."""

    value: Any = None
    """Reserved for future use."""

    error: str | None = None
    """Error message if the child failed."""

    stdout: bytes = field(default=b"", repr=False)
    """Captured stdout."""

    stderr: bytes = field(default=b"", repr=False)
    """Captured stderr."""


def run_interactive_in_sandbox(
    cmd: list[str],
    policy: Policy,
    sandbox_id: str,
    *,
    timeout: float | None = None,
) -> Result:
    """Run a command interactively in a sandboxed child process.

    Unlike run_command_in_sandbox(), stdin/stdout/stderr are inherited
    directly from the parent so the child can interact with the terminal.

    Args:
        cmd: Command and arguments to execute.
        policy: Sandbox policy.
        sandbox_id: Unique sandbox identifier.
        timeout: Maximum seconds to wait for the child.

    Returns:
        Result with exit code (stdout/stderr are empty since they go to terminal).
    """

    is_tty = os.isatty(0)

    def _target() -> None:
        try:
            os.execvp(cmd[0], cmd)
        except OSError as e:
            os.write(2, f"exec failed: {e}\n".encode())
            os._exit(127)

    try:
        with SandboxContext(
            _target,
            policy,
            sandbox_id,
        ) as ctx:
            # Give the child the controlling terminal so it can read stdin.
            # The child is in its own process group (setpgid(0,0) in
            # SandboxContext), making it a background group.  Without
            # tcsetpgrp the kernel sends SIGTTIN and the child hangs.
            if is_tty:
                old_handler = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
                try:
                    os.tcsetpgrp(0, ctx.pid)
                finally:
                    signal.signal(signal.SIGTTOU, old_handler)
            try:
                exit_code = ctx.wait(timeout=timeout)
            except TimeoutError:
                ctx.abort()
                return Result(
                    success=False,
                    exit_code=-1,
                    error="Sandbox timed out",
                )
            finally:
                # Reclaim the terminal for the parent.
                if is_tty:
                    old_handler = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
                    try:
                        os.tcsetpgrp(0, os.getpgrp())
                    finally:
                        signal.signal(signal.SIGTTOU, old_handler)
    except Exception as e:
        return Result(success=False, exit_code=-1, error=str(e))

    return Result(
        success=(exit_code == 0),
        exit_code=exit_code,
    )


def run_command_in_sandbox(
    cmd: list[str],
    policy: Policy,
    sandbox_id: str,
    *,
    timeout: float | None = None,
) -> Result:
    """Run a command in a forked, sandboxed child process.

    Args:
        cmd: Command and arguments to execute.
        policy: Sandbox policy.
        sandbox_id: Unique sandbox identifier.
        timeout: Maximum seconds to wait for the child.

    Returns:
        Result with exit code, stdout, and stderr.
    """
    stdout_r, stdout_w = os.pipe()
    stderr_r, stderr_w = os.pipe()

    def _target() -> None:
        os.close(stdout_r)
        os.close(stderr_r)
        # Redirect stdout/stderr to pipes
        os.dup2(stdout_w, 1)
        os.dup2(stderr_w, 2)
        os.close(stdout_w)
        os.close(stderr_w)
        try:
            os.execvp(cmd[0], cmd)
        except OSError as e:
            os.write(2, f"exec failed: {e}\n".encode())
            os._exit(127)

    inner_policy = dataclasses.replace(policy, close_fds=False)
    for attr in ('_overlay_branch', '_cow_branch'):
        val = getattr(policy, attr, None)
        if val is not None:
            object.__setattr__(inner_policy, attr, val)

    try:
        with SandboxContext(
            _target,
            inner_policy,
            sandbox_id,
        ) as ctx:
            os.close(stdout_w)
            os.close(stderr_w)
            stdout_w = -1
            stderr_w = -1
            try:
                exit_code = ctx.wait(timeout=timeout)
            except TimeoutError:
                ctx.abort()
                _drain_and_close(stdout_r)
                _drain_and_close(stderr_r)
                return Result(
                    success=False,
                    exit_code=-1,
                    error="Sandbox timed out",
                )
    except Exception as e:
        for fd in (stdout_w, stderr_w):
            if fd >= 0:
                os.close(fd)
        _drain_and_close(stdout_r)
        _drain_and_close(stderr_r)
        return Result(success=False, exit_code=-1, error=str(e))

    stdout_data = _read_all_fd(stdout_r)
    os.close(stdout_r)
    stderr_data = _read_all_fd(stderr_r)
    os.close(stderr_r)

    return Result(
        success=(exit_code == 0),
        exit_code=exit_code,
        stdout=stdout_data,
        stderr=stderr_data,
    )


# --- Pipe helpers ---

def _read_all_fd(fd: int) -> bytes:
    """Read all data from a file descriptor."""
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _drain_and_close(fd: int) -> None:
    """Read remaining data from fd and close it."""
    try:
        while os.read(fd, 65536):
            pass
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


# --- Stage / Pipeline ---


class Stage:
    """A sandbox bound to a command, not yet running.

    Created by :meth:`Sandbox.cmd`.  Stages can be chained into a
    pipeline with the ``|`` operator::

        result = (
            Sandbox(policy_a).cmd(["producer"])
            | Sandbox(policy_b).cmd(["consumer"])
        ).run()
    """

    __slots__ = ("sandbox", "args")

    def __init__(self, sandbox: Sandbox, args: list[str]):
        self.sandbox = sandbox
        self.args = args

    def __or__(self, other: Stage | Pipeline) -> Pipeline:
        if isinstance(other, Pipeline):
            return Pipeline([self] + other.stages)
        if isinstance(other, Stage):
            return Pipeline([self, other])
        return NotImplemented

    def run(self, *, timeout: float | None = None) -> Result:
        """Run this single stage.  Equivalent to ``sandbox.run(args)``."""
        return self.sandbox.run(self.args, timeout=timeout)


class Pipeline:
    """A chain of stages connected by pipes.

    Each stage's stdout is wired to the next stage's stdin.  The
    parent process never holds the inter-stage pipe data — it flows
    through kernel buffers only.

    Created by ``stage_a | stage_b``.
    """

    __slots__ = ("stages",)

    def __init__(self, stages: list[Stage]):
        if len(stages) < 2:
            raise ValueError("Pipeline requires at least 2 stages")
        self.stages = stages

    def __or__(self, other: Stage | Pipeline) -> Pipeline:
        if isinstance(other, Stage):
            return Pipeline(self.stages + [other])
        if isinstance(other, Pipeline):
            return Pipeline(self.stages + other.stages)
        return NotImplemented

    def run(
        self,
        *,
        stdout: int | None = None,
        timeout: float | None = None,
    ) -> Result:
        """Execute the pipeline.

        Each stage runs in its own sandbox.  Stdout of stage N is piped
        to stdin of stage N+1.  The parent never reads inter-stage data.

        Args:
            stdout: File descriptor for the final stage's stdout.
                When set, the last stage writes directly to this fd
                and ``result.stdout`` is empty.  Use ``sys.stdout.fileno()``
                to send output to the terminal.
            timeout: Maximum seconds to wait for the entire pipeline.

        Returns:
            Result from the last stage.  ``stdout`` contains the last
            stage's output only when the *stdout* parameter is not set.
        """
        return run_pipeline(self.stages, stdout=stdout, timeout=timeout)


def run_pipeline(
    stages: list[Stage],
    *,
    stdout: int | None = None,
    timeout: float | None = None,
) -> Result:
    """Execute a pipeline of sandboxed stages connected by pipes.

    The parent creates pipes between adjacent stages and closes its
    copies immediately after fork.  Data flows through kernel buffers;
    the parent never reads inter-stage data.

    Args:
        stages: Ordered list of stages to execute.
        stdout: File descriptor for the final stage's stdout.
        timeout: Maximum seconds to wait for the entire pipeline.

    Returns:
        Result from the last stage.
    """
    n = len(stages)
    if n == 0:
        raise ValueError("Pipeline requires at least 1 stage")
    if n == 1:
        return stages[0].run(timeout=timeout)

    # Create inter-stage pipes: pipe[i] connects stage i → stage i+1
    # Each pipe is (read_fd, write_fd)
    pipes = [os.pipe() for _ in range(n - 1)]

    # Create stderr pipe for last stage
    last_stderr_r, last_stderr_w = os.pipe()

    # Capture stdout of last stage (unless caller provided an fd)
    capture_stdout = stdout is None
    if capture_stdout:
        last_stdout_r, last_stdout_w = os.pipe()
    else:
        last_stdout_r, last_stdout_w = -1, -1

    contexts = [None] * n    # type: list
    opened_fds = []           # type: list  # track fds we need to clean up on error

    try:
        for i, stage in enumerate(stages):
            # Determine this stage's stdin/stdout fds
            stdin_fd = pipes[i - 1][0] if i > 0 else -1
            if i < n - 1:
                stdout_fd = pipes[i][1]
            elif capture_stdout:
                stdout_fd = last_stdout_w
            else:
                stdout_fd = os.dup(stdout)
                opened_fds.append(stdout_fd)
            stderr_fd = last_stderr_w if i == n - 1 else -1

            # Build the target function for this stage.  Capture fds
            # and pipe list by value to avoid closure issues.
            cmd = stage.args
            _stdin = stdin_fd
            _stdout = stdout_fd
            _stderr = stderr_fd
            _pipes = pipes
            _last_stderr_w = last_stderr_w
            _last_stdout_r = last_stdout_r
            _last_stdout_w = last_stdout_w

            def _make_target(cmd, _stdin, _stdout, _stderr,
                             _pipes, _last_stderr_w,
                             _last_stdout_r, _last_stdout_w):
                def _target():
                    # Close all pipe fds the child doesn't need
                    for r, w in _pipes:
                        if r != _stdin:
                            os.close(r)
                        if w != _stdout:
                            os.close(w)
                    if _last_stderr_w >= 0 and _last_stderr_w != _stderr:
                        os.close(_last_stderr_w)
                    if _last_stdout_r >= 0:
                        os.close(_last_stdout_r)
                    if _last_stdout_w >= 0 and _last_stdout_w != _stdout:
                        os.close(_last_stdout_w)

                    # Wire stdin
                    if _stdin >= 0:
                        os.dup2(_stdin, 0)
                        os.close(_stdin)

                    # Wire stdout
                    os.dup2(_stdout, 1)
                    if _stdout > 2:
                        os.close(_stdout)

                    # Wire stderr (last stage only)
                    if _stderr >= 0:
                        os.dup2(_stderr, 2)
                        if _stderr > 2:
                            os.close(_stderr)

                    try:
                        os.execvp(cmd[0], cmd)
                    except OSError as e:
                        os.write(2, f"exec failed: {e}\n".encode())
                        os._exit(127)

                return _target

            target = _make_target(cmd, _stdin, _stdout, _stderr,
                                  _pipes, _last_stderr_w,
                                  _last_stdout_r, _last_stdout_w)

            sb = stage.sandbox
            branch = sb._setup_branch()
            policy = sb._effective_policy()
            inner_policy = dataclasses.replace(policy, close_fds=False)
            for attr in ('_overlay_branch', '_cow_branch'):
                val = getattr(policy, attr, None)
                if val is not None:
                    object.__setattr__(inner_policy, attr, val)

            ctx = SandboxContext(target, inner_policy, sb._id)
            ctx.__enter__()
            contexts[i] = ctx

        # Parent: close ALL pipe fds.  Data flows kernel-only.
        for r, w in pipes:
            os.close(r)
            os.close(w)
        pipes = []  # prevent double-close in error path

        os.close(last_stderr_w)
        last_stderr_w = -1

        if last_stdout_w >= 0:
            os.close(last_stdout_w)
            last_stdout_w = -1

        for fd in opened_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        opened_fds = []

        # Wait for all stages.  Timeout applies to the whole pipeline.
        exit_codes = [0] * n
        timed_out = False
        for i in range(n):
            ctx = contexts[i]
            if ctx is None:
                exit_codes[i] = -1
                continue
            try:
                exit_codes[i] = ctx.wait(timeout=timeout)
            except TimeoutError:
                timed_out = True
                ctx.abort()
                exit_codes[i] = -1
                # Abort remaining stages
                for j in range(i + 1, n):
                    if contexts[j] is not None:
                        contexts[j].abort()
                        exit_codes[j] = -1
                break

        # Clean up contexts
        for i in range(n):
            if contexts[i] is not None:
                try:
                    contexts[i].__exit__(None, None, None)
                except Exception:
                    pass
                contexts[i] = None

        # Finish branches
        for i, stage in enumerate(stages):
            stage.sandbox._finish_branch(error=exit_codes[i] != 0)

        # Read last stage's captured output
        if capture_stdout and last_stdout_r >= 0:
            stdout_data = _read_all_fd(last_stdout_r)
            os.close(last_stdout_r)
            last_stdout_r = -1
        else:
            stdout_data = b""
            if last_stdout_r >= 0:
                _drain_and_close(last_stdout_r)
                last_stdout_r = -1

        stderr_data = _read_all_fd(last_stderr_r)
        os.close(last_stderr_r)
        last_stderr_r = -1

        last_exit = exit_codes[-1]
        if timed_out:
            return Result(
                success=False, exit_code=-1,
                error="Pipeline timed out",
                stderr=stderr_data,
            )

        return Result(
            success=(last_exit == 0),
            exit_code=last_exit,
            stdout=stdout_data,
            stderr=stderr_data,
        )

    except BaseException:
        # Cleanup on error: close all fds, abort all contexts
        for r, w in pipes:
            try:
                os.close(r)
            except OSError:
                pass
            try:
                os.close(w)
            except OSError:
                pass
        for fd in (last_stderr_r, last_stderr_w, last_stdout_r, last_stdout_w):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        for fd in opened_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        for ctx in contexts:
            if ctx is not None:
                try:
                    ctx.abort()
                    ctx.__exit__(None, None, None)
                except Exception:
                    pass
        for stage in stages:
            try:
                stage.sandbox._finish_branch(error=True)
            except Exception:
                pass
        raise
