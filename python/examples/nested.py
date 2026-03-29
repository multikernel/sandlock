#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Nested sandbox example."""

from sandlock import Sandbox, Policy


def example_nested():
    """Create nested sandboxes with progressively restrictive policies."""
    print("=== Nested sandboxes ===")

    outer_policy = Policy(
        fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"],
        fs_writable=["/tmp"],
    )

    inner_policy = Policy(
        fs_readable=["/usr", "/lib", "/lib64", "/bin"],
        fs_writable=[],
    )

    # Outer sandbox can write to /tmp
    sb = Sandbox(outer_policy)
    result = sb.run(["python3", "-c", "print('outer ok')"])
    print(f"  outer: {result.success} — {result.stdout.decode().strip()}")

    # Inner sandbox: more restrictive (independent sandbox with tighter policy)
    inner = Sandbox(inner_policy)
    result = inner.run(["echo", "inner ok"])
    print(f"  inner: {result.success} — {result.stdout.decode().strip()}")
    print()


if __name__ == "__main__":
    example_nested()
