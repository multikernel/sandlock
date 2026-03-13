#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Basic Sandlock sandbox examples."""

from sandlock import Sandbox, Policy


def example_run_command():
    """Run a command in a sandbox."""
    print("=== Run command ===")
    result = Sandbox(Policy()).run(["echo", "Hello from sandbox!"])
    print(f"  success: {result.success}")
    print(f"  stdout: {result.stdout.decode().strip()}")
    print()


def example_call_function():
    """Run a Python function in a sandbox."""
    print("=== Call function ===")

    def compute(x, y):
        return x ** y

    result = Sandbox(Policy()).call(compute, args=(2, 10))
    print(f"  success: {result.success}")
    print(f"  value: {result.value}")
    print()


def example_with_policy():
    """Run with filesystem restrictions."""
    print("=== With policy ===")
    policy = Policy(
        fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"],
        fs_writable=["/tmp"],
    )
    result = Sandbox(policy).run(["ls", "/usr"])
    print(f"  success: {result.success}")
    print(f"  files: {result.stdout.decode().strip()[:100]}...")
    print()


if __name__ == "__main__":
    example_run_command()
    example_call_function()
    example_with_policy()
