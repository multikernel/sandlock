# SPDX-License-Identifier: Apache-2.0
"""Built-in tool functions for the sandlock MCP server.

Kept in a stdlib-only module (no ``mcp``, no sandlock imports) so the
per-call worker can import them in the jail cheaply: importing ``server``
would pull in the whole MCP framework on every tool call.

Tools that declare a ``workspace`` parameter receive the sandbox's
workspace path automatically (injected by McpSandbox).
"""
from __future__ import annotations


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


def read_file(path: str, *, workspace: str) -> str:
    """Read a file from the workspace."""
    import os

    full = os.path.join(workspace, path)
    with open(full) as f:
        return f.read()


def write_file(path: str, content: str, *, workspace: str) -> str:
    """Write content to a file in the workspace."""
    import os

    full = os.path.join(workspace, path)
    parent = os.path.dirname(full)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(full, "w") as f:
        f.write(content)
    return f"Wrote {len(content)} bytes to {path}"


def list_files(subdir: str = "", *, workspace: str) -> str:
    """List files in the workspace directory."""
    import os

    target = os.path.join(workspace, subdir) if subdir else workspace
    entries = sorted(os.listdir(target))
    lines = []
    for e in entries:
        kind = "dir" if os.path.isdir(os.path.join(target, e)) else "file"
        lines.append(f"{kind}  {e}")
    return "\n".join(lines) if lines else "(empty)"
