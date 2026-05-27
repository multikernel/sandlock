# SPDX-License-Identifier: Apache-2.0
"""Integration tests for sandlock.mcp — per-tool sandboxed execution."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from types import SimpleNamespace

import pytest

from sandlock.mcp import policy_for_tool, McpSandbox

from _tool_helpers import (
    _read_file_tool,
    _write_file_tool,
    _run_python_tool,
    _list_files_tool,
)


# -- Helpers --

def _run_in_sandbox(capabilities, script, workspace, timeout=15.0):
    """Run a script in a sandbox with given capabilities."""
    policy = policy_for_tool(workspace=workspace, capabilities=capabilities)
    return policy.run([sys.executable, "-c", script], timeout=timeout)


# -- Tests --

class TestDenyByDefault:

    def test_no_capabilities_blocks_write(self, tmp_path):
        workspace = str(tmp_path)
        script = f"""\
with open("{workspace}/bad.txt", "w") as f:
    f.write("nope")
"""
        result = _run_in_sandbox(None, script, workspace)
        assert not result.success

    def test_no_capabilities_allows_read(self, tmp_path):
        workspace = str(tmp_path)
        (tmp_path / "existing.txt").write_text("hello")

        script = f"""\
with open("{workspace}/existing.txt") as f:
    print(f.read())
"""
        result = _run_in_sandbox(None, script, workspace)
        assert result.success
        assert b"hello" in result.stdout


class TestCapabilitiesEnforcement:

    def test_fs_writable_grants_write(self, tmp_path):
        workspace = str(tmp_path)
        script = f"""\
with open("{workspace}/test.txt", "w") as f:
    f.write("ok")
print("done")
"""
        result = _run_in_sandbox({"fs_writable": [workspace]}, script, workspace)
        assert result.success

    def test_no_network_blocks_connect(self, tmp_path):
        workspace = str(tmp_path)
        script = """\
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.settimeout(2)
    s.connect(("127.0.0.1", 80))
    print("connected")
except (OSError, socket.timeout):
    print("blocked")
finally:
    s.close()
"""
        result = _run_in_sandbox(None, script, workspace)
        assert result.success
        assert b"blocked" in result.stdout


class TestWorkspaceSharing:

    def test_write_then_read(self, tmp_path):
        workspace = str(tmp_path)

        # Write
        script = f'open("{workspace}/test.txt", "w").write("hello")'
        result = _run_in_sandbox({"fs_writable": [workspace]}, script, workspace)
        assert result.success

        # Read (no capabilities)
        script = f'print(open("{workspace}/test.txt").read())'
        result = _run_in_sandbox(None, script, workspace)
        assert result.success
        assert b"hello" in result.stdout


class TestMcpSandboxLocalTools:

    def _run(self, coro):
        return asyncio.run(coro)

    def test_read_only_by_default(self, tmp_path):
        workspace = str(tmp_path)

        mcp = McpSandbox(workspace=workspace)
        mcp.add_tool("run_python", _run_python_tool)

        result = self._run(mcp.call_tool("run_python", {"code": "print(42)"}))
        assert "42" in result

    def test_clean_env_by_default(self, tmp_path):
        """Tools get clean env — can't see agent's env vars."""
        workspace = str(tmp_path)
        os.environ["SECRET_API_KEY"] = "should-not-leak"

        mcp = McpSandbox(workspace=workspace)
        mcp.add_tool("run_python", _run_python_tool)

        result = self._run(mcp.call_tool("run_python", {
            "code": "import os; print(os.environ.get('SECRET_API_KEY', 'HIDDEN'))",
        }))
        assert "HIDDEN" in result
        assert "should-not-leak" not in result

    def test_env_capability_passes_vars(self, tmp_path):
        """Only explicitly granted env vars are visible."""
        workspace = str(tmp_path)

        mcp = McpSandbox(workspace=workspace)
        mcp.add_tool("run_python", _run_python_tool,
                      capabilities={"env": {"MY_TOKEN": "granted"}})

        result = self._run(mcp.call_tool("run_python", {
            "code": "import os; print(os.environ.get('MY_TOKEN', 'MISSING'))",
        }))
        assert "granted" in result

    def test_write_requires_capability(self, tmp_path):
        workspace = str(tmp_path)

        mcp = McpSandbox(workspace=workspace)
        mcp.add_tool("write_file", _write_file_tool)  # no fs_writable

        with pytest.raises(RuntimeError, match="failed"):
            self._run(mcp.call_tool(
                "write_file", {"path": "bad.txt", "content": "nope"},
            ))

    def test_write_with_capability(self, tmp_path):
        workspace = str(tmp_path)

        mcp = McpSandbox(workspace=workspace)
        mcp.add_tool("write_file", _write_file_tool,
                      capabilities={"fs_writable": [workspace]})
        mcp.add_tool("read_file", _read_file_tool)

        self._run(mcp.call_tool(
            "write_file", {"path": "test.txt", "content": "hello"},
        ))
        result = self._run(mcp.call_tool("read_file", {"path": "test.txt"}))
        assert "hello" in result

    def test_get_policy(self, tmp_path):
        workspace = str(tmp_path)
        mcp = McpSandbox(workspace=workspace)
        mcp.add_tool("reader", _read_file_tool)
        mcp.add_tool("writer", _write_file_tool,
                      capabilities={"fs_writable": [workspace]})

        assert mcp.get_policy("reader").fs_writable == []
        assert mcp.get_policy("reader").clean_env is True
        assert workspace in mcp.get_policy("writer").fs_writable

    def test_unknown_tool_raises(self, tmp_path):
        mcp = McpSandbox(workspace=str(tmp_path))
        with pytest.raises(KeyError):
            self._run(mcp.call_tool("nope", {}))

    def test_openai_format(self, tmp_path):
        mcp = McpSandbox(workspace=str(tmp_path))
        mcp.add_tool("t", _run_python_tool, description="Test")

        defs = mcp.tool_definitions_openai()
        assert len(defs) == 1
        assert defs[0]["type"] == "function"
        assert defs[0]["function"]["name"] == "t"

    def test_full_workflow(self, tmp_path):
        workspace = str(tmp_path)

        mcp = McpSandbox(workspace=workspace)
        mcp.add_tool("write_file", _write_file_tool,
                      capabilities={"fs_writable": [workspace]})
        mcp.add_tool("read_file", _read_file_tool)
        mcp.add_tool("run_python", _run_python_tool)
        mcp.add_tool("list_files", _list_files_tool)

        async def workflow():
            await mcp.call_tool("write_file",
                                {"path": "data.txt", "content": "hello"})
            r = await mcp.call_tool("run_python",
                                    {"code": "print('hello'.upper())"})
            await mcp.call_tool("write_file",
                                {"path": "out.txt", "content": r.strip()})
            files = json.loads(await mcp.call_tool("list_files", {}))
            assert "data.txt" in files
            assert "out.txt" in files
            assert "HELLO" in await mcp.call_tool("read_file", {"path": "out.txt"})

        self._run(workflow())


# -- Import-by-entrypoint execution --

def test_policy_extra_readable_is_added():
    pol = policy_for_tool(workspace="/tmp/ws", extra_readable=["/opt/tools"])
    assert "/opt/tools" in pol.fs_readable
    assert "/tmp/ws" in pol.fs_readable  # default still present


def test_worker_invokes_module_function(capsys):
    import sandlock.mcp._worker as worker
    here = os.path.dirname(os.path.abspath(__file__))
    rc = worker.main(["--syspath", here, "_worker_fixture", "echo", '{"text": "hi"}'])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "fixture:hi"


def test_module_level_state_tool_runs(tmp_path):
    import _worker_fixture  # tests dir is on sys.path under pytest
    mcp = McpSandbox(workspace=str(tmp_path))
    mcp.add_tool("echo", _worker_fixture.echo)  # top-level import + const + helper
    out = asyncio.run(mcp.call_tool("echo", {"text": "hi"}))
    assert out.strip() == "fixture:hi"


def test_lambda_rejected():
    with pytest.raises(ValueError):
        McpSandbox().add_tool("bad", lambda x: x)


def test_method_rejected():
    class C:
        def m(self, x):
            return x
    with pytest.raises(ValueError):
        McpSandbox().add_tool("bad", C().m)


def test_nested_function_rejected():
    def outer():
        def inner(x):
            return x
        return inner
    with pytest.raises(ValueError):
        McpSandbox().add_tool("bad", outer())


def test_workspace_injected(tmp_path):
    import _worker_fixture
    mcp = McpSandbox(workspace=str(tmp_path))
    mcp.add_tool("whereami", _worker_fixture.whereami)  # no env wiring
    out = asyncio.run(mcp.call_tool("whereami", {}))
    assert out.strip() == str(tmp_path)


def test_llm_cannot_override_workspace(tmp_path):
    import _worker_fixture
    mcp = McpSandbox(workspace=str(tmp_path))
    mcp.add_tool("whereami", _worker_fixture.whereami)
    out = asyncio.run(mcp.call_tool("whereami", {"workspace": "/evil"}))
    assert out.strip() == str(tmp_path)


def test_builtins_import_does_not_pull_in_mcp():
    """The per-call worker imports the built-in tools' module; it must stay
    light, i.e. not drag in the heavy ``mcp`` framework."""
    import subprocess
    code = "import sandlock.mcp._builtins, sys; print('mcp' in sys.modules)"
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "False", out.stdout


def test_create_server_still_importable():
    """create_server is lazily importable from the package."""
    from sandlock.mcp import create_server
    assert callable(create_server)
