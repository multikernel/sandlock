# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.mcp — deny-by-default capability model."""

import pytest
from types import SimpleNamespace

from sandlock.policy import Policy
from sandlock.mcp._policy import policy_for_tool, capabilities_from_mcp_tool


class TestDenyByDefault:

    def test_no_capabilities(self):
        policy = policy_for_tool(workspace="/tmp/ws")
        assert policy.fs_writable == []
        assert "/tmp/ws" in policy.fs_readable
        assert policy.net_connect == []
        assert policy.isolate_pids is True
        assert policy.isolate_ipc is True
        assert policy.no_raw_sockets is True

    def test_empty_capabilities(self):
        policy = policy_for_tool(workspace="/tmp/ws", capabilities={})
        assert policy.fs_writable == []
        assert policy.net_connect == []


class TestCapabilities:

    def test_fs_writable(self):
        policy = policy_for_tool(
            workspace="/tmp/ws",
            capabilities={"fs_writable": ["/tmp/ws"]},
        )
        assert "/tmp/ws" in policy.fs_writable

    def test_net_connect(self):
        policy = policy_for_tool(
            workspace="/tmp/ws",
            capabilities={"net_connect": [443]},
        )
        assert 443 in policy.net_connect

    def test_net_allow_hosts(self):
        policy = policy_for_tool(
            workspace="/tmp/ws",
            capabilities={"net_allow_hosts": ["api.google.com"]},
        )
        assert "api.google.com" in policy.net_allow_hosts

    def test_max_memory(self):
        policy = policy_for_tool(
            workspace="/tmp/ws",
            capabilities={"max_memory": "512M"},
        )
        assert policy.max_memory == "512M"

    def test_multiple(self):
        policy = policy_for_tool(
            workspace="/tmp/ws",
            capabilities={
                "fs_writable": ["/data"],
                "net_connect": [443, 8080],
                "max_memory": "256M",
            },
        )
        assert policy.fs_writable == ["/data"]
        assert 443 in policy.net_connect
        assert 8080 in policy.net_connect
        assert policy.max_memory == "256M"

    def test_net_allow_hosts_implies_net_connect(self):
        policy = policy_for_tool(
            workspace="/tmp/ws",
            capabilities={"net_allow_hosts": ["example.com"]},
        )
        assert "example.com" in policy.net_allow_hosts
        assert 80 in policy.net_connect
        assert 443 in policy.net_connect

    def test_net_allow_hosts_with_explicit_net_connect(self):
        policy = policy_for_tool(
            workspace="/tmp/ws",
            capabilities={
                "net_allow_hosts": ["example.com"],
                "net_connect": [8443],
            },
        )
        assert policy.net_connect == [8443]  # explicit wins

    def test_unknown_field_ignored(self):
        policy = policy_for_tool(
            workspace="/tmp/ws",
            capabilities={"not_a_real_field": True},
        )
        assert not hasattr(policy, "not_a_real_field")


class TestCapabilitiesFromMcpTool:

    def _tool(self, annotations=None, meta=None):
        t = SimpleNamespace(name="t", annotations=annotations)
        if meta is not None:
            t.meta = meta
        return t

    def test_from_annotations(self):
        tool = self._tool({"sandlock:net_connect": [443]})
        caps = capabilities_from_mcp_tool(tool)
        assert caps == {"net_connect": [443]}

    def test_from_meta(self):
        tool = self._tool(meta={"sandlock:max_memory": "128M"})
        caps = capabilities_from_mcp_tool(tool)
        assert caps == {"max_memory": "128M"}

    def test_standard_hints_ignored(self):
        tool = self._tool({"readOnlyHint": True, "openWorldHint": True})
        caps = capabilities_from_mcp_tool(tool)
        assert caps == {}

    def test_unknown_sandlock_key_ignored(self):
        tool = self._tool({"sandlock:fake_field": True})
        caps = capabilities_from_mcp_tool(tool)
        assert caps == {}

    def test_pydantic_model_annotations(self):
        class FakeAnn:
            def model_dump(self, exclude_none=False):
                return {"sandlock:fs_writable": ["/data"]}

        tool = self._tool(FakeAnn())
        caps = capabilities_from_mcp_tool(tool)
        assert caps == {"fs_writable": ["/data"]}

    def test_none_annotations(self):
        tool = self._tool(None)
        caps = capabilities_from_mcp_tool(tool)
        assert caps == {}

    def test_meta_overrides_annotations(self):
        """meta wins over annotations for same key."""
        tool = self._tool(
            {"sandlock:net_connect": [80]},
            {"sandlock:net_connect": [443]},
        )
        caps = capabilities_from_mcp_tool(tool)
        assert caps == {"net_connect": [443]}
