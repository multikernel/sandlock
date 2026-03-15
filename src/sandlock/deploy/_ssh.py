# SPDX-License-Identifier: Apache-2.0
"""Thin paramiko wrapper for SSH operations."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

import paramiko


class SSHSession:
    """Manages an SSH connection to a remote host."""

    def __init__(
        self,
        host: str,
        user: str | None = None,
        port: int = 22,
        key_file: str | None = None,
    ):
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self._client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs: dict = {
            "hostname": self.host,
            "port": self.port,
            "allow_agent": True,
            "look_for_keys": False,
        }
        if self.user:
            kwargs["username"] = self.user
        if self.key_file:
            kwargs["key_filename"] = self.key_file

        # Load SSH config for host aliases and per-host settings
        ssh_config_path = Path.home() / ".ssh" / "config"
        if ssh_config_path.exists():
            config = paramiko.SSHConfig.from_path(str(ssh_config_path))
            host_config = config.lookup(self.host)
            if "hostname" in host_config:
                kwargs["hostname"] = host_config["hostname"]
            if "user" in host_config and not self.user:
                kwargs["username"] = host_config["user"]
            if "port" in host_config and self.port == 22:
                kwargs["port"] = int(host_config["port"])
            if "identityfile" in host_config and not self.key_file:
                kwargs["key_filename"] = host_config["identityfile"]

        client.connect(**kwargs)
        self._client = client

    def exec(self, command: str) -> tuple[int, str, str]:
        """Execute a command and return (exit_code, stdout, stderr).

        Prepends ~/.local/bin to PATH since non-interactive SSH
        sessions don't load shell profiles.
        """
        assert self._client is not None
        wrapped = f'PATH="$HOME/.local/bin:$PATH" {command}'
        _, stdout, stderr = self._client.exec_command(wrapped)
        exit_code = stdout.channel.recv_exit_status()
        return exit_code, stdout.read().decode(), stderr.read().decode()

    def upload(self, local_path: str | Path, remote_path: str) -> None:
        """Upload a file via SFTP."""
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            # Ensure remote directory exists
            remote_dir = str(PurePosixPath(remote_path).parent)
            self._mkdir_p(sftp, remote_dir)
            sftp.put(str(local_path), remote_path)
        finally:
            sftp.close()

    def read_remote(self, remote_path: str) -> str | None:
        """Read a remote file, return None if it doesn't exist."""
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            with sftp.open(remote_path, "r") as f:
                return f.read().decode()
        except FileNotFoundError:
            return None
        finally:
            sftp.close()

    def write_remote(self, remote_path: str, content: str, mode: int = 0o644) -> None:
        """Write content to a remote file."""
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            remote_dir = str(PurePosixPath(remote_path).parent)
            self._mkdir_p(sftp, remote_dir)
            with sftp.open(remote_path, "w") as f:
                f.write(content)
            sftp.chmod(remote_path, mode)
        finally:
            sftp.close()

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> SSHSession:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @staticmethod
    def _mkdir_p(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
        """Recursively create remote directories."""
        dirs_to_create = []
        current = remote_dir
        while current and current != "/":
            try:
                sftp.stat(current)
                break
            except FileNotFoundError:
                dirs_to_create.append(current)
                current = str(PurePosixPath(current).parent)

        for d in reversed(dirs_to_create):
            sftp.mkdir(d)
