#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AI agent with OpenAI + sandlock per-tool sandboxing.

Demonstrates sandlock.mcp.McpSandbox with local tools.  Each tool call
runs inside its own Sandbox with a policy derived from MCP annotations.

Prerequisites::

    pip install sandlock openai
    export OPENAI_API_KEY=sk-...

Run::

    python3 examples/mcp_agent.py "Write fibonacci numbers to fib.txt, then read it back"

Architecture::

    User prompt
        |
        v
    OpenAI (gpt-4o-mini)       <-- reasons about which tool to call
        |
        v
    McpSandbox.call_tool()     <-- sandlock derives per-tool policy
        |
        v
    sandlock.Sandbox            <-- fork + Landlock + seccomp
        |
        v
    tool function               <-- runs confined
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile

from openai import OpenAI
from sandlock.mcp import McpSandbox

# Tools live in a stdlib-only module so McpSandbox can import them inside
# each per-call jail without pulling in openai or sandlock.  See agent_tools.py.
from agent_tools import read_file, write_file, run_python, list_files, web_fetch


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

async def run_agent(user_prompt: str, workspace: str):
    """Run the agent loop: OpenAI reasoning + sandboxed local tool execution."""

    # -- Set up McpSandbox with local tools --
    mcp = McpSandbox(workspace=workspace)

    # Deny by default: clean env, no writes, no network.
    # Each tool gets only the permissions it needs; the workspace path is
    # injected automatically into any tool that declares a `workspace` param.
    mcp.add_tool(
        "read_file", read_file,
        description="Read a file from the workspace. Path is relative to workspace root.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Relative file path"}},
            "required": ["path"],
        },
    )
    mcp.add_tool(
        "write_file", write_file,
        description="Write content to a file in the workspace. Creates parent directories.",
        capabilities={"fs_writable": [workspace]},
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative file path"},
                "content": {"type": "string", "description": "File content"},
            },
            "required": ["path", "content"],
        },
    )
    mcp.add_tool(
        "run_python", run_python,
        description="Run Python code and return stdout. No filesystem or network access.",
        capabilities={"max_memory": "128M"},
        input_schema={
            "type": "object",
            "properties": {"code": {"type": "string", "description": "Python code to execute"}},
            "required": ["code"],
        },
    )
    mcp.add_tool(
        "list_files", list_files,
        description="List files in the workspace directory.",
        input_schema={"type": "object", "properties": {}},
    )
    mcp.add_tool(
        "web_fetch", web_fetch,
        description="Fetch a URL and return the response body. Only httpbin.org is allowed.",
        capabilities={
            "net_allow": ["httpbin.org:80,443"],
        },
        input_schema={
            "type": "object",
            "properties": {"url": {"type": "string", "description": "URL to fetch"}},
            "required": ["url"],
        },
    )

    # -- Show per-tool policies --
    print(f"Workspace: {workspace}")
    print(f"Tools ({len(mcp.tools)}):")
    for name in mcp.tools:
        p = mcp.get_policy(name)
        rw = "read-only" if not p.fs_writable else "read-write"
        net = f"endpoints {list(p.net_allow)}" if p.net_allow else "none"
        print(f"  {name:15s}  fs={rw:10s}  net={net}")
    print()

    # -- OpenAI agent loop --
    client = OpenAI()
    messages = [
        {
            "role": "system",
            "content": (
                "You are a helpful assistant with access to file and code tools. "
                f"The workspace directory is {workspace}. "
                "File paths are relative to the workspace. "
                "When done, summarize what you did."
            ),
        },
        {"role": "user", "content": user_prompt},
    ]

    openai_tools = mcp.tool_definitions_openai()

    max_turns = 10
    for turn in range(max_turns):
        print(f"--- Turn {turn + 1} ---")

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=openai_tools,
        )

        choice = response.choices[0]
        messages.append(choice.message.model_dump())

        if choice.finish_reason == "stop":
            print(f"\n[Agent]: {choice.message.content}")
            break

        if choice.finish_reason != "tool_calls":
            print(f"Unexpected finish_reason: {choice.finish_reason}")
            break

        # Execute each tool call via McpSandbox
        for tc in choice.message.tool_calls:
            name = tc.function.name
            args = json.loads(tc.function.arguments)
            print(f"  Calling {name}({json.dumps(args, indent=None)[:80]})")

            try:
                result = await mcp.call_tool(name, args)
                print(f"    -> {result[:120]}")
            except Exception as e:
                result = f"Error: {e}"
                print(f"    -> {result}")

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })

    else:
        print(f"\n[Agent exceeded {max_turns} turns]")


def main():
    parser = argparse.ArgumentParser(
        description="AI agent with OpenAI + sandlock per-tool sandboxing",
    )
    parser.add_argument(
        "prompt",
        nargs="?",
        default=(
            "Write a Python script that prints the first 10 Fibonacci numbers "
            "to a file called fib.txt, then read fib.txt and tell me what's in it."
        ),
        help="User prompt for the agent",
    )
    parser.add_argument(
        "--workspace", default=None,
        help="Workspace directory (default: auto-created temp dir)",
    )
    args = parser.parse_args()

    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable is required.")
        print("  export OPENAI_API_KEY=sk-...")
        sys.exit(1)

    if args.workspace:
        workspace = args.workspace
        os.makedirs(workspace, exist_ok=True)
        asyncio.run(run_agent(args.prompt, workspace))
    else:
        with tempfile.TemporaryDirectory(prefix="sandlock-mcp-") as workspace:
            asyncio.run(run_agent(args.prompt, workspace))


if __name__ == "__main__":
    main()
