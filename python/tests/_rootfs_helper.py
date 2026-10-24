# SPDX-License-Identifier: Apache-2.0
"""Locate the static rootfs-helper test fixture."""

from __future__ import annotations

from pathlib import Path

import pytest

_TARGET = Path(__file__).resolve().parents[2] / "target"


def rootfs_helper() -> Path:
    """The rootfs-helper that sandlock-core's build.rs compiles into its OUT_DIR."""
    found = [
        p
        for pattern in ("*/build/sandlock-core-*/out/rootfs-helper",
                        "*/*/build/sandlock-core-*/out/rootfs-helper")
        for p in _TARGET.glob(pattern)
    ]
    if not found:
        pytest.fail("rootfs-helper not built (sandlock-core's build.rs compiles it)")
    return max(found, key=lambda p: p.stat().st_mtime)
