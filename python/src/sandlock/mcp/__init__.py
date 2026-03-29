# SPDX-License-Identifier: Apache-2.0
"""Sandlock MCP integration: per-tool sandboxed execution.

Deny by default.  Each tool declares capabilities explicitly.

::

    from sandlock.mcp import McpSandbox

    mcp = McpSandbox(workspace="/tmp/agent")
    mcp.add_tool("read_file", read_fn)
    mcp.add_tool("write_file", write_fn, capabilities={"fs_writable": [workspace]})
    result = await mcp.call_tool("read_file", {"path": "foo.txt"})
"""

from ._policy import policy_for_tool, capabilities_from_mcp_tool
from ._sandbox import McpSandbox
try:
    from .server import create_server
except ImportError:
    pass  # mcp not installed

__all__ = [
    "McpSandbox",
    "create_server",
    "policy_for_tool",
    "capabilities_from_mcp_tool",
]
