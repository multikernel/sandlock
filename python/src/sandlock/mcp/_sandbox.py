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
import os
import sys
from collections import namedtuple
from typing import Any, Callable, Mapping

from ..sandbox import Sandbox
from ._policy import policy_for_tool, capabilities_from_mcp_tool


_Entrypoint = namedtuple("_Entrypoint", "module qualname syspath")

# Absolute path to the worker, run as a plain script (not ``-m``) so it
# executes with only stdlib imports and never pulls the sandlock package
# (and its FFI cdylib) into the jail.
_WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_worker.py")


def _resolve_entrypoint(name: str, func: Callable) -> _Entrypoint:
    """Derive an importable (module, qualname, syspath) for a tool function.

    Rejects lambdas, methods, and nested/closure functions, which cannot
    be imported by name in a fresh interpreter.
    """
    qualname = getattr(func, "__qualname__", getattr(func, "__name__", ""))
    if qualname == "<lambda>":
        raise ValueError(
            f"cannot sandbox {name!r}: tool must be a top-level function, not a lambda"
        )
    if "<locals>" in qualname:
        raise ValueError(
            f"cannot sandbox {name!r}: nested function {qualname!r} is not importable; "
            f"define the tool at module top level"
        )
    if "." in qualname:
        raise ValueError(
            f"cannot sandbox {name!r}: expected a top-level function "
            f"(got qualname {qualname!r}); methods are not supported"
        )
    try:
        file = inspect.getfile(func)
    except TypeError as exc:
        raise ValueError(
            f"cannot sandbox {name!r}: source location unavailable ({exc})"
        )
    syspath = os.path.dirname(os.path.abspath(file))
    module = func.__module__
    if module == "__main__":
        module = os.path.splitext(os.path.basename(file))[0]
    return _Entrypoint(module=module, qualname=qualname, syspath=syspath)


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
        self._local_policies: dict[str, Sandbox] = {}
        self._local_entrypoints: dict[str, _Entrypoint] = {}
        self._mcp_tools: dict[str, Any] = {}
        self._mcp_tool_session: dict[str, Any] = {}
        self._mcp_policies: dict[str, Sandbox] = {}

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

        Each call runs in a fresh per-call sandbox.  The function must be
        a top-level function in an import-safe module: the worker imports
        that module by name, so module-level imports, helpers, constants,
        and state are all fine, but lambdas, methods, and nested functions
        are rejected, and any startup logic in the module must be guarded
        under ``if __name__ == "__main__":``.

        If the function declares a parameter named ``workspace``, the
        sandbox's workspace path is injected for it at call time (hidden
        from the tool schema and not overridable by the caller).

        Args:
            name: Tool name.
            func: Python function implementing the tool.
            description: Description for the LLM.
            capabilities: Permission grants.  No capabilities = read-only.
            input_schema: JSON Schema for parameters.
        """
        entry = _resolve_entrypoint(name, func)
        self._local_tools[name] = _LocalTool(
            name=name,
            func=func,
            description=description,
            capabilities=capabilities or {},
            input_schema=input_schema or {"type": "object", "properties": {}},
        )
        self._local_entrypoints[name] = entry
        self._local_policies[name] = policy_for_tool(
            workspace=self._workspace,
            capabilities=capabilities,
            extra_readable=[entry.syspath],
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

    def get_policy(self, tool_name: str) -> Sandbox:
        """Return the sandbox config for a tool."""
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
        policy = self._local_policies[name]
        entry = self._local_entrypoints[name]

        cmd = [
            sys.executable, _WORKER,
            "--syspath", entry.syspath,
            "--workspace", self._workspace,
            entry.module, entry.qualname,
            json.dumps(args),
        ]

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: policy.run(cmd, timeout=timeout),
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
