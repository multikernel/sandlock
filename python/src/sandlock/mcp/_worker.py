# SPDX-License-Identifier: Apache-2.0
"""Jailed entry point: import a tool module and call one function.

Invoked by McpSandbox inside a Landlock + seccomp sandbox::

    python _worker.py --syspath DIR --workspace WS MODULE QUALNAME ARGS_JSON

DIR is prepended to sys.path (clean_env strips PYTHONPATH) so that
locally-defined tool modules resolve.  MODULE is imported, the top-level
function QUALNAME is called with the JSON-decoded keyword arguments, and
its result is printed (str as-is, otherwise JSON).  A non-zero exit and a
traceback on stderr signal failure to the parent.

If the function declares a parameter named ``workspace``, the value of
``--workspace`` is injected for it (overriding anything the caller passed,
so the model cannot spoof the path).
"""
from __future__ import annotations

import argparse
import importlib
import inspect
import json
import sys


def _accepts(func, name: str) -> bool:
    """True if ``func`` declares an explicit parameter named ``name``."""
    try:
        param = inspect.signature(func).parameters.get(name)
    except (TypeError, ValueError):
        return False
    return param is not None and param.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sandlock.mcp._worker")
    parser.add_argument("--syspath", default=None)
    parser.add_argument("--workspace", default=None)
    parser.add_argument("module")
    parser.add_argument("qualname")
    parser.add_argument("args_json")
    ns = parser.parse_args(argv)

    if ns.syspath:
        sys.path.insert(0, ns.syspath)

    module = importlib.import_module(ns.module)
    func = getattr(module, ns.qualname)
    args = json.loads(ns.args_json)

    if ns.workspace is not None and _accepts(func, "workspace"):
        args["workspace"] = ns.workspace  # framework value wins

    result = func(**args)

    if result is not None:
        print(result if isinstance(result, str) else json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
