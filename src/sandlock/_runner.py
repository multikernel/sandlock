# SPDX-License-Identifier: Apache-2.0
"""call() implementation: pipe-based result passing for fork+exec sandboxing."""

from __future__ import annotations

import dataclasses
import json
import os
import pickle
import signal
from dataclasses import dataclass, field
from typing import Any, Callable

from .exceptions import ChildError, SandboxError
from ._context import SandboxContext
from .policy import Policy


@dataclass
class Result:
    """Result from a sandbox execution."""

    success: bool
    """Whether the sandboxed code completed without error."""

    exit_code: int = 0
    """Exit code of the child process."""

    value: Any = None
    """Return value from call(), or None for run()."""

    error: str | None = None
    """Error message if the child failed."""

    stdout: bytes = field(default=b"", repr=False)
    """Captured stdout (for run() only)."""

    stderr: bytes = field(default=b"", repr=False)
    """Captured stderr (for run() only)."""


def call_in_sandbox(
    fn: Callable,
    args: tuple,
    policy: Policy,
    sandbox_id: str,
    *,
    timeout: float | None = None,
) -> Result:
    """Run *fn(*args)* in a forked, sandboxed child process.

    Results are passed back via an inherited pipe fd.

    Args:
        fn: Callable to execute.
        args: Positional arguments for *fn*.
        policy: Sandbox policy.
        sandbox_id: Unique sandbox identifier.
        timeout: Maximum seconds to wait for the child.

    Returns:
        Result with the return value or error.
    """
    read_fd, write_fd = os.pipe()

    def _target() -> None:
        os.close(read_fd)
        try:
            value = fn(*args)
            _write_result_fd(write_fd, {"ok": True, "value": value})
        except BaseException as exc:
            _write_result_fd(
                write_fd, {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            )
        finally:
            os.close(write_fd)

    # Use a non-closing-fds policy for the inner target since we need the pipe
    inner_policy = dataclasses.replace(policy, close_fds=False)
    # Propagate overlay branch (not a dataclass field, lost by replace)
    _ob = getattr(policy, '_overlay_branch', None)
    if _ob is not None:
        object.__setattr__(inner_policy, '_overlay_branch', _ob)

    try:
        with SandboxContext(
            _target,
            inner_policy,
            sandbox_id,
        ) as ctx:
            os.close(write_fd)
            write_fd = -1  # prevent double-close
            try:
                exit_code = ctx.wait(timeout=timeout)
            except TimeoutError:
                ctx.abort()
                _drain_and_close(read_fd)
                return Result(
                    success=False,
                    exit_code=-1,
                    error="Sandbox timed out",
                )
    except Exception as e:
        if write_fd >= 0:
            os.close(write_fd)
        _drain_and_close(read_fd)
        return Result(success=False, exit_code=-1, error=str(e))

    # Read result from pipe
    data = _read_result_fd(read_fd)
    os.close(read_fd)

    if data is None:
        return Result(
            success=False,
            exit_code=exit_code,
            error="Child process did not produce a result (possibly OOM-killed)",
        )

    if data.get("ok"):
        return Result(success=True, exit_code=0, value=data.get("value"))

    return Result(
        success=False,
        exit_code=exit_code,
        error=data.get("error", "unknown child error"),
    )


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
    _ob = getattr(policy, '_overlay_branch', None)
    if _ob is not None:
        object.__setattr__(inner_policy, '_overlay_branch', _ob)

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

def _write_result_fd(fd: int, data: dict) -> None:
    """Write a JSON result dict to a pipe fd."""
    try:
        payload = json.dumps(data).encode()
    except (TypeError, ValueError):
        fallback = dict(data)
        if "value" in fallback:
            fallback["value"] = repr(fallback["value"])
        payload = json.dumps(fallback).encode()
    os.write(fd, payload)


def _read_result_fd(fd: int) -> dict | None:
    """Read a JSON result dict from a pipe fd.  Returns None on empty read."""
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    if not chunks:
        return None
    return json.loads(b"".join(chunks))


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
