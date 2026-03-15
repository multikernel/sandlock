# SPDX-License-Identifier: Apache-2.0
"""SSH-based remote deployment for sandlock.

Install with: pip install sandlock[deploy]
"""

from __future__ import annotations

try:
    import paramiko  # noqa: F401
except ImportError:
    raise ImportError(
        "sandlock[deploy] requires paramiko. "
        "Install with: pip install sandlock[deploy]"
    ) from None

from ._remote import deploy, verify
from ._sandbox import RemoteSandbox
