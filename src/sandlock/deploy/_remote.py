# SPDX-License-Identifier: Apache-2.0
"""Remote deployment orchestration."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ._ssh import SSHSession


def _build_wheel(dest_dir: str) -> Path:
    """Build a wheel of the current sandlock package."""
    # Find the project root (where pyproject.toml lives)
    pkg_dir = Path(__file__).resolve().parent.parent.parent.parent
    pyproject = pkg_dir / "pyproject.toml"

    if pyproject.exists():
        # Build from source
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", str(pkg_dir),
             "--no-deps", "-w", dest_dir],
            check=True, capture_output=True,
        )
    else:
        # Installed package — download the wheel from cache/PyPI
        subprocess.run(
            [sys.executable, "-m", "pip", "download", "sandlock",
             "--no-deps", "-d", dest_dir],
            check=True, capture_output=True,
        )

    wheels = list(Path(dest_dir).glob("sandlock-*.whl"))
    if not wheels:
        raise RuntimeError("failed to build sandlock wheel")
    return wheels[0]


def _local_profile_path(name: str) -> Path:
    """Find a local profile TOML file."""
    from .._profile import profiles_dir
    path = profiles_dir() / f"{name}.toml"
    if not path.is_file():
        raise FileNotFoundError(f"profile not found: {path}")
    return path


def _force_command_line(profile: str | None, sandlock_bin: str) -> str:
    """Build the ForceCommand/command= string."""
    parts = [sandlock_bin, "run"]
    if profile:
        parts += ["--profile", profile]
    parts += ["-e", r'\"${SSH_ORIGINAL_COMMAND:-/bin/bash}\"']
    return " ".join(parts)


def deploy(
    ssh: SSHSession,
    *,
    profile: str | None = None,
    pubkey: str | None = None,
    force_command: bool = False,
    remote_python: str = "python3",
) -> None:
    """Deploy sandlock to a remote host.

    Steps:
      1. Build and upload sandlock wheel, pip install it
      2. Push profile if specified
      3. Configure authorized_keys or ForceCommand

    Returns the remote sandlock binary path.
    """
    print(f"Connecting to {ssh.user}@{ssh.host}:{ssh.port}...")
    ssh.connect()

    # Step 1: Install sandlock
    print("Building and uploading sandlock...")
    with tempfile.TemporaryDirectory() as tmp:
        wheel = _build_wheel(tmp)
        remote_wheel = f"/tmp/{wheel.name}"
        ssh.upload(wheel, remote_wheel)

    print("Installing sandlock on remote...")
    rc, out, err = ssh.exec(
        f"{remote_python} -m pip install --user --force-reinstall {remote_wheel}"
    )
    if rc != 0:
        raise RuntimeError(f"remote pip install failed:\n{err}")
    # Clean up remote wheel
    ssh.exec(f"rm -f {remote_wheel}")

    # Find remote sandlock binary
    rc, out, _ = ssh.exec("which sandlock")
    sandlock_bin = out.strip() or "sandlock"
    print(f"  sandlock installed at: {sandlock_bin}")

    # Step 2: Push profile
    if profile:
        print(f"Pushing profile '{profile}'...")
        local_toml = _local_profile_path(profile)
        profile_content = local_toml.read_text()
        rc, home_out, _ = ssh.exec("echo $HOME")
        remote_home = home_out.strip()
        remote_profile = f"{remote_home}/.config/sandlock/profiles/{profile}.toml"
        ssh.write_remote(remote_profile, profile_content)
        print(f"  profile uploaded to: {remote_profile}")

    # Step 3: Configure SSH
    if pubkey or force_command:
        rc, home_out, _ = ssh.exec("echo $HOME")
        remote_home = home_out.strip()
        ak_path = f"{remote_home}/.ssh/authorized_keys"

        if pubkey:
            print("Configuring authorized_keys...")
            key_content = Path(pubkey).expanduser().read_text().strip()

            if force_command:
                fc = _force_command_line(profile, sandlock_bin)
                line = f'command="{fc}" {key_content}'
            else:
                line = key_content

            # Read existing, avoid duplicates
            existing = ssh.read_remote(ak_path) or ""
            if key_content in existing:
                print("  key already present, updating...")
                # Remove old entry with this key and re-add
                lines = [l for l in existing.splitlines()
                         if key_content not in l]
                lines.append(line)
                new_content = "\n".join(lines) + "\n"
            else:
                new_content = existing.rstrip("\n") + "\n" + line + "\n" if existing else line + "\n"

            # Ensure .ssh dir exists with correct perms
            ssh.exec(f"mkdir -p {remote_home}/.ssh && chmod 700 {remote_home}/.ssh")
            ssh.write_remote(ak_path, new_content, mode=0o600)
            print(f"  authorized_keys updated: {ak_path}")

        elif force_command:
            # ForceCommand in sshd_config (needs sudo)
            fc = _force_command_line(profile, sandlock_bin)
            user = ssh.user or "unknown"
            block = (
                f"\n# sandlock deploy — {user}\n"
                f"Match User {user}\n"
                f"    ForceCommand {fc}\n"
            )
            print(f"Adding ForceCommand to sshd_config for user '{user}'...")
            rc, existing, _ = ssh.exec("sudo cat /etc/ssh/sshd_config")
            if rc != 0:
                raise RuntimeError("cannot read sshd_config (sudo required)")

            if f"# sandlock deploy — {user}" in existing:
                print("  existing config found, replacing...")
                # Remove old block
                lines = existing.splitlines()
                new_lines = []
                skip = False
                for l in lines:
                    if l.strip() == f"# sandlock deploy — {user}":
                        skip = True
                        continue
                    if skip and (l.startswith("Match ") or l.startswith("#")):
                        skip = False
                    if skip and l.startswith("    "):
                        continue
                    skip = False
                    new_lines.append(l)
                existing = "\n".join(new_lines)

            new_config = existing.rstrip("\n") + "\n" + block
            # Write via sudo
            rc, _, err = ssh.exec(
                f"echo {repr(new_config)} | sudo tee /etc/ssh/sshd_config > /dev/null"
            )
            if rc != 0:
                raise RuntimeError(f"failed to write sshd_config: {err}")
            print("  reloading sshd...")
            ssh.exec("sudo systemctl reload sshd || sudo systemctl reload ssh")
            print("  done")

    return sandlock_bin


def verify(ssh: SSHSession, sandlock_bin: str = "sandlock") -> bool:
    """Verify sandlock is working on the remote host."""
    print("Verifying remote sandlock...")
    rc, out, err = ssh.exec(f"{sandlock_bin} check")
    if rc != 0:
        print(f"  FAIL: sandlock check returned {rc}")
        if err:
            print(f"  {err.strip()}")
        return False

    print(f"  {out.strip()}")

    # Quick sandbox test
    rc, out, _ = ssh.exec(f'{sandlock_bin} run -e "echo sandlock-ok"')
    if rc != 0 or "sandlock-ok" not in out:
        print("  FAIL: sandbox test run failed")
        return False

    print("  sandbox test: OK")
    return True
