# SPDX-License-Identifier: Apache-2.0
"""Tool implementations for the mcp_agent example.

Plain stdlib-only functions in their own importable module.  McpSandbox
imports this module by name inside each per-call jail, so it must not pull
in sandlock, openai, or any other heavy dependency.  Module-level imports
are fine (and shown here): the worker imports the module normally.
"""
import contextlib
import io
import os
from urllib.request import urlopen


def read_file(path: str, *, workspace: str) -> str:
    """Read a file from the workspace."""
    with open(os.path.join(workspace, path)) as f:
        return f.read()


def write_file(path: str, content: str, *, workspace: str) -> str:
    """Write content to a file in the workspace."""
    full = os.path.join(workspace, path)
    parent = os.path.dirname(full)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(full, "w") as f:
        f.write(content)
    return f"Wrote {len(content)} bytes to {path}"


def run_python(code: str) -> str:
    """Execute Python code and return stdout."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(code)
    return buf.getvalue()


def list_files(*, workspace: str) -> str:
    """List files in the workspace."""
    entries = sorted(os.listdir(workspace))
    lines = []
    for e in entries:
        kind = "dir" if os.path.isdir(os.path.join(workspace, e)) else "file"
        lines.append(f"{kind}  {e}")
    return "\n".join(lines) if lines else "(empty)"


def web_fetch(url: str) -> str:
    """Fetch a URL and return the response body (first 4KB)."""
    resp = urlopen(url, timeout=10)
    return resp.read(4096).decode("utf-8", errors="replace")
