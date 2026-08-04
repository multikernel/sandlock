#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Nested sandbox example."""

import os

from sandlock import Sandbox

def _present(*paths: str) -> list[str]:
    """Keep the system paths this host actually has.

    /lib64 is absent on arm64 and /sbin is a symlink into /usr on merged-usr
    hosts. A grant on a path that is not there fails when the child installs
    its Landlock rules, and the failure does not name the path, so filter here
    rather than debug it there.
    """
    return [p for p in paths if os.path.exists(p)]


def example_nested():
    """Create nested sandboxes with progressively restrictive policies."""
    print("=== Nested sandboxes ===")

    outer = Sandbox(
        fs_readable=_present("/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"),
        fs_writable=["/tmp"],
    )

    inner = Sandbox(
        fs_readable=_present("/usr", "/lib", "/lib64", "/bin"),
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
