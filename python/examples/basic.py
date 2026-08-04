#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Basic Sandlock sandbox examples."""

import os

from sandlock import Sandbox

# Minimum filesystem readable to exec common binaries.
# Present system paths only: /lib64 is absent on arm64 and /sbin is a
# symlink into /usr on merged-usr hosts. A grant on a path that is not
# there fails when the child installs its Landlock rules, and the failure
# does not name the path, so filter here rather than debug it there.
_BASE_READ = [
    p for p in ("/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev")
    if os.path.exists(p)
]


def example_run_command():
    """Run a command in a sandbox."""
    print("=== Run command ===")
    result = Sandbox(fs_readable=_BASE_READ).run(
        ["echo", "Hello from sandbox!"]
    )
    print(f"  success: {result.success}")
    print(f"  stdout: {result.stdout.decode().strip()}")
    print()


def example_run_python():
    """Run a Python expression in a sandbox."""
    print("=== Run Python ===")

    result = Sandbox(fs_readable=_BASE_READ).run(
        ["python3", "-c", "print(2 ** 10)"]
    )
    print(f"  success: {result.success}")
    print(f"  stdout: {result.stdout.decode().strip()}")
    print()


def example_with_policy():
    """Run with filesystem restrictions, including a writable scratch dir."""
    print("=== With policy ===")
    sandbox = Sandbox(
        fs_readable=_BASE_READ,
        fs_writable=["/tmp"],
    )
    result = sandbox.run(["ls", "/usr"])
    print(f"  success: {result.success}")
    print(f"  files: {result.stdout.decode().strip()[:100]}...")
    print()


if __name__ == "__main__":
    example_run_command()
    example_run_python()
    example_with_policy()
