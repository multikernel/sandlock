# SPDX-License-Identifier: Apache-2.0
"""Deny-by-default policy for sandboxed tool execution.

A tool with no capabilities gets a maximally restrictive sandbox:
read-only system paths, no writes, no network.  Every permission
must be explicitly granted via capabilities.

Example::

    policy = policy_for_tool(workspace="/tmp/work", capabilities={
        "fs_writable": ["/tmp/work"],
        "net_allow": ["api.google.com:443"],
    })
"""

from __future__ import annotations

import os
import site
import sys
from dataclasses import fields
from typing import Any, Mapping, Sequence

from ..sandbox import Sandbox

# Resolve the Python interpreter's installation prefix so that sandboxed
# processes can always exec the current interpreter, even when it lives
# outside the standard system paths (e.g. /opt on CI, virtualenvs, etc.).
_PYTHON_PREFIX = sys.prefix


def _interpreter_readable() -> list[str]:
    """Paths the sandboxed worker must read to launch and import a tool.

    Covers the interpreter prefixes, the site-packages directories, and the
    sandlock package root (the last so the worker script is readable even in
    an editable install).
    """
    paths = [sys.prefix, sys.base_prefix]
    try:
        paths.extend(site.getsitepackages())
    except Exception:
        pass
    try:
        paths.append(site.getusersitepackages())
    except Exception:
        pass
    # Parent of the 'sandlock' package dir, e.g. .../site-packages or the
    # editable source root .../python/src.
    paths.append(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
    return [p for p in dict.fromkeys(paths) if p and os.path.isdir(p)]


_INTERP_READABLE = _interpreter_readable()


_POLICY_FIELDS = frozenset(f.name for f in fields(Sandbox))
_SANDLOCK_PREFIX = "sandlock:"


def policy_for_tool(
    *,
    workspace: str = "/tmp/sandlock",
    capabilities: Mapping[str, Any] | None = None,
    extra_readable: Sequence[str] = (),
) -> Sandbox:
    """Build a :class:`Sandbox` from explicit capabilities.

    **Deny by default**: no capabilities = read-only access to system
    paths and the workspace.  Every permission must be granted.

    Environment is always cleared.  Use ``env`` capability to pass
    specific variables::

        capabilities={"env": {"API_KEY": "..."}}

    Args:
        workspace: Filesystem path the sandbox can read.
        capabilities: Grants keyed by Sandbox field name.  Common keys:

            - ``fs_writable: ["/tmp/workspace"]``
            - ``net_allow: ["api.example.com:443"]``
            - ``env: {"KEY": "value"}``
            - ``max_memory: "256M"``

    Returns:
        A frozen :class:`Sandbox` instance.
    """
    # Fields that users cannot override — always enforced.
    _ENFORCED = {"clean_env"}

    kwargs: dict[str, Any] = {
        "fs_writable": [],
        "fs_readable": list(dict.fromkeys([
            workspace, "/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin",
            _PYTHON_PREFIX, *_INTERP_READABLE, *extra_readable,
        ])),
        "net_bind": [],
        "net_allow": [],
        "clean_env": True,
    }

    if capabilities:
        for key, value in capabilities.items():
            if key in _POLICY_FIELDS and key not in _ENFORCED:
                kwargs[key] = value

    return Sandbox(**kwargs)


def capabilities_from_mcp_tool(tool: Any) -> dict[str, Any]:
    """Extract capabilities from an MCP tool's ``sandlock:*`` annotations.

    Reads ``sandlock:*`` keys from the tool's annotations and meta dicts.
    Standard MCP hints (readOnlyHint, openWorldHint) are ignored —
    only explicit ``sandlock:*`` keys grant permissions.

    Args:
        tool: An MCP tool object.

    Returns:
        Capabilities dict (may be empty).
    """
    caps: dict[str, Any] = {}

    # From annotations
    ann = _parse_annotations(tool)
    for key, value in ann.items():
        if key.startswith(_SANDLOCK_PREFIX):
            field_name = key[len(_SANDLOCK_PREFIX):]
            if field_name in _POLICY_FIELDS:
                caps[field_name] = value

    # From meta (MCP Tool.meta field)
    if hasattr(tool, "meta") and tool.meta:
        for key, value in tool.meta.items():
            if key.startswith(_SANDLOCK_PREFIX):
                field_name = key[len(_SANDLOCK_PREFIX):]
                if field_name in _POLICY_FIELDS:
                    caps[field_name] = value

    return caps


def _parse_annotations(tool: Any) -> dict[str, Any]:
    """Extract annotations dict from a tool object."""
    if not hasattr(tool, "annotations") or tool.annotations is None:
        return {}
    ann = tool.annotations
    if isinstance(ann, dict):
        return ann
    if hasattr(ann, "model_dump"):
        return ann.model_dump(exclude_none=True)
    if hasattr(ann, "__dict__"):
        return {k: v for k, v in vars(ann).items() if v is not None}
    return {}
