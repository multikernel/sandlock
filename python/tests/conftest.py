# SPDX-License-Identifier: Apache-2.0
"""Shared test fixtures for Sandlock tests."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_dir():
    """Create a temporary directory for test use."""
    d = tempfile.mkdtemp(prefix="sandlock-test-")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)
