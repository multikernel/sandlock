#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Basic Sandlock sandbox examples."""

from sandlock import Sandbox

# Minimum filesystem readable to exec common binaries.
_BASE_READ = ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"]


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
