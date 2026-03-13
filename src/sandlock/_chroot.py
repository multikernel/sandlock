# SPDX-License-Identifier: Apache-2.0
"""Optional chroot setup for sandbox confinement."""

from __future__ import annotations

import os

from .exceptions import ConfinementError


def setup_chroot(path: str) -> None:
    """chroot into the given path and chdir to /.

    Args:
        path: Directory to use as new root.

    Raises:
        ConfinementError: If chroot or chdir fails.
    """
    try:
        os.chroot(path)
        os.chdir("/")
    except OSError as e:
        raise ConfinementError(f"chroot({path}) failed: {e}") from e
