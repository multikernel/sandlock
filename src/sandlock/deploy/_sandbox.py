# SPDX-License-Identifier: Apache-2.0
"""RemoteSandbox: same API as Sandbox, executes over SSH."""

from __future__ import annotations

import shlex

from ..policy import Policy
from .._runner import Result
from ._ssh import SSHSession


def _policy_to_cli_flags(policy: Policy) -> list[str]:
    """Convert a Policy to sandlock CLI flags."""
    flags: list[str] = []

    for path in policy.fs_readable:
        flags += ["-r", path]
    for path in policy.fs_writable:
        flags += ["-w", path]
    if policy.max_memory:
        flags += ["-m", policy.max_memory]
    if policy.max_processes:
        flags += ["-P", str(policy.max_processes)]
    if policy.max_cpu:
        flags += ["-c", str(policy.max_cpu)]
    if policy.clean_env:
        flags.append("--clean-env")
    if policy.env:
        for k, v in policy.env.items():
            flags += ["--env", f"{k}={v}"]
    if policy.isolate_ipc:
        flags.append("--isolate-ipc")
    if policy.isolate_signals:
        flags.append("--isolate-signals")
    if policy.net_bind:
        for port in policy.net_bind:
            flags += ["--net-bind", port]
    if policy.net_connect:
        for port in policy.net_connect:
            flags += ["--net-connect", port]
    if policy.net_allow_hosts:
        for host in policy.net_allow_hosts:
            flags += ["--net-allow-host", host]
    if policy.port_remap:
        flags.append("--port-remap")

    return flags


class RemoteSandbox:
    """Sandbox that executes commands on a remote host via SSH.

    Provides the same ``run()`` interface as ``Sandbox``, but executes
    the command on the remote host using ``sandlock run`` over SSH.

    Usage::

        sb = RemoteSandbox(policy, host="user@host")
        result = sb.run(["python3", "task.py"])
        # result.stdout, result.stderr, result.exit_code — same as local
    """

    def __init__(
        self,
        policy: Policy | str,
        *,
        host: str,
        port: int = 22,
        key_file: str | None = None,
        sandlock_bin: str = "sandlock",
        workdir: str | None = None,
    ):
        if isinstance(policy, str):
            self._profile_name = policy
            self._policy = None
        else:
            self._profile_name = None
            self._policy = policy

        self._workdir = workdir

        # Parse user@host
        if "@" in host:
            self._user, self._host = host.split("@", 1)
        else:
            self._user, self._host = None, host

        self._port = port
        self._key_file = key_file
        self._sandlock_bin = sandlock_bin
        self._session: SSHSession | None = None

    def _ensure_connected(self) -> SSHSession:
        if self._session is None:
            self._session = SSHSession(
                host=self._host,
                user=self._user,
                port=self._port,
                key_file=self._key_file,
            )
            self._session.connect()
        return self._session

    def _build_command(self, cmd: list[str], timeout: float | None = None) -> str:
        """Build the remote sandlock command string."""
        parts = self._base_parts(timeout) + ["--"] + cmd
        return " ".join(shlex.quote(p) for p in parts)

    def run(self, cmd: list[str], *, timeout: float | None = None) -> Result:
        """Run a command in a remote sandbox.

        Args:
            cmd: Command and arguments to execute.
            timeout: Maximum seconds to wait.

        Returns:
            Result with exit_code, stdout, stderr.
        """
        ssh = self._ensure_connected()
        remote_cmd = self._build_command(cmd, timeout)
        exit_code, stdout, stderr = ssh.exec(remote_cmd)

        return Result(
            success=exit_code == 0,
            exit_code=exit_code,
            stdout=stdout.encode(),
            stderr=stderr.encode(),
        )

    def _base_parts(self, timeout: float | None = None) -> list[str]:
        """Build common sandlock run prefix."""
        parts = [self._sandlock_bin, "run"]
        if self._profile_name:
            parts += ["--profile", self._profile_name]
        elif self._policy:
            parts += _policy_to_cli_flags(self._policy)
        if self._workdir:
            parts += ["-r", self._workdir, "-w", self._workdir]
            parts += ["--workdir", self._workdir]
        if timeout is not None:
            parts += ["-t", str(timeout)]
        return parts

    def run_shell(self, command: str, *, timeout: float | None = None) -> Result:
        """Run a shell command string in a remote sandbox.

        Args:
            command: Shell command string (passed via -e).
            timeout: Maximum seconds to wait.

        Returns:
            Result with exit_code, stdout, stderr.
        """
        ssh = self._ensure_connected()
        parts = self._base_parts(timeout) + ["-e", command]
        remote_cmd = " ".join(shlex.quote(p) for p in parts)
        exit_code, stdout, stderr = ssh.exec(remote_cmd)

        return Result(
            success=exit_code == 0,
            exit_code=exit_code,
            stdout=stdout.encode(),
            stderr=stderr.encode(),
        )

    def close(self) -> None:
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self) -> RemoteSandbox:
        self._ensure_connected()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()
