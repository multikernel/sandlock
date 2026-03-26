# SPDX-License-Identifier: Apache-2.0
"""Standalone MCP server with sandboxed tool execution.

Provides shell, Python, and file tools — each running in a per-call
Landlock + seccomp sandbox.  No Docker required.

Local (stdio) usage::

    sandlock-mcp --workspace /tmp/sandbox

Remote (SSE) usage::

    sandlock-mcp --transport sse --host 0.0.0.0 --port 8080 --workspace /tmp/sandbox

Configure in Claude Desktop / Cursor:

Local::

    {
      "mcpServers": {
        "sandlock": {
          "command": "sandlock-mcp",
          "args": ["--workspace", "/tmp/sandbox"]
        }
      }
    }

Remote::

    {
      "mcpServers": {
        "sandlock": {
          "url": "http://remote-host:8080/sse"
        }
      }
    }
"""

from __future__ import annotations

import argparse
import asyncio
import os
import tempfile

from mcp import types
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server

from ._sandbox import McpSandbox

# ---------------------------------------------------------------------------
# Built-in tool functions (self-contained — imports inside body)
# ---------------------------------------------------------------------------


def shell(command: str) -> str:
    """Run a shell command and return stdout+stderr."""
    import subprocess

    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = result.stdout
    if result.stderr:
        output += result.stderr
    if result.returncode != 0:
        output += f"\n[exit code: {result.returncode}]"
    return output


def python(code: str) -> str:
    """Execute Python code and return stdout."""
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(code)
    return buf.getvalue()


def read_file(path: str) -> str:
    """Read a file from the workspace."""
    import os

    workspace = os.environ["SANDLOCK_WORKSPACE"]
    full = os.path.join(workspace, path)
    with open(full) as f:
        return f.read()


def write_file(path: str, content: str) -> str:
    """Write content to a file in the workspace."""
    import os

    workspace = os.environ["SANDLOCK_WORKSPACE"]
    full = os.path.join(workspace, path)
    parent = os.path.dirname(full)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(full, "w") as f:
        f.write(content)
    return f"Wrote {len(content)} bytes to {path}"


def list_files(subdir: str = "") -> str:
    """List files in the workspace directory."""
    import os

    workspace = os.environ["SANDLOCK_WORKSPACE"]
    target = os.path.join(workspace, subdir) if subdir else workspace
    entries = sorted(os.listdir(target))
    lines = []
    for e in entries:
        kind = "dir" if os.path.isdir(os.path.join(target, e)) else "file"
        lines.append(f"{kind}  {e}")
    return "\n".join(lines) if lines else "(empty)"


# ---------------------------------------------------------------------------
# Tool definitions (name -> schema + sandbox registration info)
# ---------------------------------------------------------------------------

_TOOL_DEFS: list[dict] = [
    {
        "name": "shell",
        "func": shell,
        "description": (
            "Run a shell command in a sandboxed environment. "
            "No network access. Read-only filesystem except workspace."
        ),
        "capabilities_extra": lambda ws: {"fs_writable": [ws]},
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "python",
        "func": python,
        "description": (
            "Execute Python code and return stdout. "
            "No filesystem or network access."
        ),
        "capabilities_extra": lambda ws: {"max_memory": "256M"},
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python code to execute",
                },
            },
            "required": ["code"],
        },
    },
    {
        "name": "read_file",
        "func": read_file,
        "description": "Read a file from the workspace. Path is relative to workspace root.",
        "capabilities_extra": lambda ws: {},
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative file path",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "func": write_file,
        "description": "Write content to a file in the workspace. Creates parent directories.",
        "capabilities_extra": lambda ws: {"fs_writable": [ws]},
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative file path",
                },
                "content": {
                    "type": "string",
                    "description": "File content to write",
                },
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "list_files",
        "func": list_files,
        "description": "List files and directories in the workspace.",
        "capabilities_extra": lambda ws: {},
        "input_schema": {
            "type": "object",
            "properties": {
                "subdir": {
                    "type": "string",
                    "description": "Subdirectory to list (optional, default: workspace root)",
                    "default": "",
                },
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------


def _register_tools(sandbox: McpSandbox, workspace: str) -> None:
    """Register built-in tools on the McpSandbox."""
    ws_env = {"SANDLOCK_WORKSPACE": workspace}

    for td in _TOOL_DEFS:
        caps = {"env": ws_env}
        caps.update(td["capabilities_extra"](workspace))
        sandbox.add_tool(
            td["name"],
            td["func"],
            description=td["description"],
            capabilities=caps,
            input_schema=td["input_schema"],
        )


def create_server(workspace: str) -> tuple[Server, McpSandbox]:
    """Create and configure the MCP server.

    Returns:
        (server, sandbox) tuple.
    """
    os.makedirs(workspace, exist_ok=True)

    sandbox = McpSandbox(workspace=workspace)
    _register_tools(sandbox, workspace)

    server = Server(
        name="sandlock",
        instructions=(
            "Sandboxed tool execution server powered by sandlock. "
            "Each tool runs in an isolated Landlock + seccomp sandbox. "
            f"Workspace directory: {workspace}"
        ),
    )

    # -- list_tools handler --
    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        tools = []
        for td in _TOOL_DEFS:
            tools.append(
                types.Tool(
                    name=td["name"],
                    description=td["description"],
                    inputSchema=td["input_schema"],
                )
            )
        return tools

    # -- call_tool handler --
    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None,
    ) -> list[types.TextContent]:
        try:
            result = await sandbox.call_tool(name, arguments)
            return [types.TextContent(type="text", text=result)]
        except KeyError:
            return [types.TextContent(
                type="text",
                text=f"Unknown tool: {name}",
            )]
        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error: {e}",
            )]

    return server, sandbox


async def _run_stdio(server: Server) -> None:
    """Run the server over stdio transport."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream,
            server.create_initialization_options(),
        )


def _run_sse(server: Server, host: str, port: int) -> None:
    """Run the server over SSE transport (HTTP)."""
    try:
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route
        import uvicorn
    except ImportError:
        raise SystemExit(
            "SSE transport requires extra dependencies.\n"
            "Install them with:  pip install 'sandlock[mcp-remote]'"
        )

    from mcp.server.sse import SseServerTransport

    sse = SseServerTransport("/messages/")

    async def handle_sse(request):
        async with sse.connect_sse(
            request.scope, request.receive, request._send,
        ) as (read_stream, write_stream):
            await server.run(
                read_stream, write_stream,
                server.create_initialization_options(),
            )

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
    )

    uvicorn.run(app, host=host, port=port)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sandlock MCP server — sandboxed tool execution",
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help="Workspace directory (default: auto-created temp dir)",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to for SSE transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to bind to for SSE transport (default: 8080)",
    )
    args = parser.parse_args()

    def run_with_workspace(workspace: str) -> None:
        server, _ = create_server(workspace)
        if args.transport == "sse":
            _run_sse(server, args.host, args.port)
        else:
            asyncio.run(_run_stdio(server))

    if args.workspace:
        run_with_workspace(os.path.abspath(args.workspace))
    else:
        with tempfile.TemporaryDirectory(prefix="sandlock-mcp-") as workspace:
            run_with_workspace(workspace)


if __name__ == "__main__":
    main()
