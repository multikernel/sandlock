# SPDX-License-Identifier: Apache-2.0
"""Fixture tool module for import-by-entrypoint tests.

Uses a module-level import, constant, and helper on purpose: the patterns
the old source-re-exec path could not handle.
"""
import os

PREFIX = "fixture:"


def _decorate(text: str) -> str:
    return PREFIX + text


def echo(text: str) -> str:
    return _decorate(text)


def read_env(var: str) -> str:
    return os.environ[var]


def whereami(*, workspace: str) -> str:
    return workspace
