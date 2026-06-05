# SPDX-License-Identifier: Apache-2.0
"""Tests for http_inject_ca / http_ca_out policy fields."""

from __future__ import annotations

from sandlock import Sandbox


def test_policy_accepts_inject_ca_fields():
    p = Sandbox(
        http_allow=["GET example.com/*"],
        http_inject_ca=["/etc/ssl/certs/ca-certificates.crt"],
        http_ca_out="/tmp/ca.pem",
    )
    assert list(p.http_inject_ca) == ["/etc/ssl/certs/ca-certificates.crt"]
    assert p.http_ca_out == "/tmp/ca.pem"
