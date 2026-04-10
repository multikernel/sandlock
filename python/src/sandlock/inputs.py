# SPDX-License-Identifier: Apache-2.0
"""Gather inputs — read named producer outputs inside a gather consumer.

Usage in a consumer script::

    from sandlock import inputs

    code = inputs["code"]   # reads from the planner's pipe
    data = inputs["data"]   # reads from the searcher's pipe

The ``_SANDLOCK_GATHER`` env var maps names to fd numbers
(e.g. ``data:3,code:0``). Each fd is a pipe connected to the
corresponding producer's stdout. Values are read lazily on
first access and cached.
"""

import os


class _Inputs:
    """Lazy dict-like accessor for gather pipe inputs."""

    def __init__(self):
        self._cache: dict[str, str] = {}
        self._fd_map: dict[str, int] | None = None

    def _parse_map(self) -> dict[str, int]:
        if self._fd_map is not None:
            return self._fd_map
        raw = os.environ.get("_SANDLOCK_GATHER", "")
        self._fd_map = {}
        if raw:
            for pair in raw.split(","):
                name, fd_str = pair.split(":", 1)
                self._fd_map[name] = int(fd_str)
        return self._fd_map

    def __getitem__(self, name: str) -> str:
        if name in self._cache:
            return self._cache[name]
        fd_map = self._parse_map()
        if name not in fd_map:
            raise KeyError(
                f"No gather input named '{name}'. "
                f"Available: {list(fd_map.keys())}"
            )
        fd = fd_map[name]
        with os.fdopen(fd, "r", closefd=True) as f:
            value = f.read()
        self._cache[name] = value
        return value

    def __contains__(self, name: str) -> bool:
        return name in self._parse_map()

    def keys(self):
        return self._parse_map().keys()

    def __repr__(self):
        fd_map = self._parse_map()
        loaded = set(self._cache.keys())
        parts = []
        for name in fd_map:
            status = "loaded" if name in loaded else f"fd={fd_map[name]}"
            parts.append(f"'{name}': <{status}>")
        return "inputs({" + ", ".join(parts) + "})"


inputs = _Inputs()
