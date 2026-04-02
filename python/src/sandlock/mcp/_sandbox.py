# SPDX-License-Identifier: Apache-2.0
"""McpSandbox: per-tool sandboxed execution for AI agents.

Deny by default.  Each tool declares capabilities explicitly.

Usage::

    from sandlock.mcp import McpSandbox

    mcp = McpSandbox(workspace="/tmp/agent")
    mcp.add_tool("read_file", read_fn)  # no capabilities = read-only
    mcp.add_tool("write_file", write_fn, capabilities={"fs_writable": [workspace]})

    result = await mcp.call_tool("write_file", {"path": "out.txt", "content": "hi"})
"""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
import textwrap
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from ..policy import Policy
from .._sdk import Sandbox
from ._policy import policy_for_tool, capabilities_from_mcp_tool


class _LocalTool:
    __slots__ = ("name", "func", "description", "capabilities", "input_schema")

    def __init__(self, name, func, description, capabilities, input_schema):
        self.name = name
        self.func = func
        self.description = description
        self.capabilities = capabilities
        self.input_schema = input_schema


class McpSandbox:
    """Sandboxed tool execution for AI agents.

    Deny by default.  Each tool must explicitly declare capabilities
    to get permissions beyond read-only access.

    Args:
        workspace: Directory the sandbox can read.  Tools that need
            write access must declare ``fs_writable: [workspace]``.
        timeout: Default timeout (seconds) for each tool call.
    """

    def __init__(
        self,
        *,
        workspace: str = "/tmp/sandlock",
        timeout: float | None = 30.0,
    ):
        self._workspace = workspace
        self._timeout = timeout
        self._local_tools: dict[str, _LocalTool] = {}
        self._local_policies: dict[str, Policy] = {}
        self._mcp_tools: dict[str, Any] = {}
        self._mcp_tool_session: dict[str, Any] = {}
        self._mcp_policies: dict[str, Policy] = {}

    # --- Local tools ---

    def add_tool(
        self,
        name: str,
        func: Callable,
        *,
        description: str = "",
        capabilities: dict[str, Any] | None = None,
        input_schema: dict[str, Any] | None = None,
    ) -> None:
        """Register a local tool.

        The function runs in a per-call sandbox.  It must be
        self-contained (imports inside the function body).

        Args:
            name: Tool name.
            func: Python function implementing the tool.
            description: Description for the LLM.
            capabilities: Permission grants.  No capabilities = read-only.
            input_schema: JSON Schema for parameters.
        """
        self._local_tools[name] = _LocalTool(
            name=name,
            func=func,
            description=description,
            capabilities=capabilities or {},
            input_schema=input_schema or {"type": "object", "properties": {}},
        )
        self._local_policies[name] = policy_for_tool(
            workspace=self._workspace,
            capabilities=capabilities,
        )

    # --- MCP server tools ---

    async def add_mcp_session(self, session: Any) -> None:
        """Discover tools from an MCP server.

        ``sandlock:*`` keys in annotations/meta are read as capabilities.
        """
        result = await session.list_tools()
        tools = result.tools if hasattr(result, "tools") else result

        for tool in tools:
            self._mcp_tools[tool.name] = tool
            self._mcp_tool_session[tool.name] = session
            caps = capabilities_from_mcp_tool(tool)
            self._mcp_policies[tool.name] = policy_for_tool(
                workspace=self._workspace,
                capabilities=caps,
            )

    # --- Unified interface ---

    @property
    def tools(self) -> dict[str, Any]:
        all_tools: dict[str, Any] = {}
        all_tools.update(self._local_tools)
        all_tools.update(self._mcp_tools)
        return all_tools

    def tool_definitions_openai(self) -> list[dict[str, Any]]:
        """Tool definitions in OpenAI function-calling format."""
        result = []
        for name, tool in self._local_tools.items():
            result.append({"type": "function", "function": {
                "name": name,
                "description": tool.description,
                "parameters": tool.input_schema,
            }})
        for name, tool in self._mcp_tools.items():
            fn: dict[str, Any] = {"name": name}
            if hasattr(tool, "description") and tool.description:
                fn["description"] = tool.description
            if hasattr(tool, "inputSchema"):
                fn["parameters"] = tool.inputSchema
            result.append({"type": "function", "function": fn})
        return result

    def get_policy(self, tool_name: str) -> Policy:
        """Return the policy for a tool."""
        if tool_name in self._local_policies:
            return self._local_policies[tool_name]
        if tool_name in self._mcp_policies:
            return self._mcp_policies[tool_name]
        raise KeyError(f"Unknown tool: {tool_name!r}")

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> str:
        """Call a tool by name.

        Local tools run in a per-call sandbox.
        MCP tools are forwarded to the server.
        """
        args = arguments or {}
        t = timeout if timeout is not None else self._timeout

        if name in self._local_tools:
            return await self._call_local(name, args, t)
        elif name in self._mcp_tools:
            return await self._call_mcp(name, args)
        else:
            raise KeyError(f"Unknown tool: {name!r}")

    async def _call_local(self, name: str, args: dict, timeout: float | None) -> str:
        tool = self._local_tools[name]
        policy = self._local_policies[name]

        try:
            source = textwrap.dedent(inspect.getsource(tool.func))
        except (OSError, TypeError):
            raise RuntimeError(
                f"Cannot sandbox {name!r}: function source not available"
            )

        args_json = json.dumps(args)
        script = f"""\
import json, sys

{source}

_args = json.loads({args_json!r})
_result = {tool.func.__name__}(**_args)
if _result is not None:
    print(_result if isinstance(_result, str) else json.dumps(_result))
"""

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: Sandbox(policy).run(
                [sys.executable, "-c", script], timeout=timeout,
            ),
        )

        if not result.success:
            stderr = (result.stderr or b"").decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Sandboxed tool {name!r} failed "
                f"(exit {result.exit_code}): {stderr}"
            )

        return (result.stdout or b"").decode("utf-8", errors="replace")

    async def _call_mcp(self, name: str, args: dict) -> str:
        session = self._mcp_tool_session[name]
        result = await session.call_tool(name, args)
        if hasattr(result, "content") and result.content:
            return "\n".join(
                item.text for item in result.content if hasattr(item, "text")
            )
        return str(result)
