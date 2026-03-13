# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock._runner."""

import json
import os

import pytest

from sandlock._runner import (
    Result,
    _read_result_fd,
    _write_result_fd,
)


class TestResult:
    def test_success(self):
        r = Result(success=True, value=42)
        assert r.success
        assert r.value == 42
        assert r.error is None

    def test_failure(self):
        r = Result(success=False, error="boom")
        assert not r.success
        assert r.error == "boom"

    def test_with_output(self):
        r = Result(success=True, stdout=b"hello\n", stderr=b"")
        assert r.stdout == b"hello\n"


class TestPipeHelpers:
    def test_write_read_roundtrip(self):
        r, w = os.pipe()
        data = {"ok": True, "value": 42}
        _write_result_fd(w, data)
        os.close(w)
        result = _read_result_fd(r)
        os.close(r)
        assert result == data

    def test_read_empty(self):
        r, w = os.pipe()
        os.close(w)
        result = _read_result_fd(r)
        os.close(r)
        assert result is None

    def test_non_serializable_fallback(self):
        r, w = os.pipe()
        data = {"ok": True, "value": object()}
        _write_result_fd(w, data)
        os.close(w)
        result = _read_result_fd(r)
        os.close(r)
        assert result["ok"] is True
        assert "object" in result["value"]
