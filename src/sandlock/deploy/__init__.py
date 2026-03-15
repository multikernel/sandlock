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
from ._target import Target, Cluster, load_target, load_targets, load_cluster
from ._scheduler import schedule, probe_cluster, NodeStatus
