#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Nested sandbox example."""

from sandlock import Sandbox


def example_nested():
    """Create nested sandboxes with progressively restrictive policies."""
    print("=== Nested sandboxes ===")

    outer = Sandbox(
        fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"],
        fs_writable=["/tmp"],
    )

    inner = Sandbox(
        fs_readable=["/usr", "/lib", "/lib64", "/bin"],
        fs_writable=[],
    )

    # Outer sandbox can write to /tmp
    result = outer.run(["python3", "-c", "print('outer ok')"])
    print(f"  outer: {result.success} — {result.stdout.decode().strip()}")

    # Inner sandbox: more restrictive (independent sandbox with tighter policy)
    result = inner.run(["echo", "inner ok"])
    print(f"  inner: {result.success} — {result.stdout.decode().strip()}")
    print()


if __name__ == "__main__":
    example_nested()
