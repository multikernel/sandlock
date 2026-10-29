# SPDX-License-Identifier: Apache-2.0

import os
import sys

import pytest

from sandlock import Sandbox


def test_registration_is_per_sandbox():
    readable = ["/usr", "/lib", "/lib64", "/bin", "/etc", sys.prefix]
    name = f"py-registration-{os.getpid()}"
    private = Sandbox(name=name, fs_readable=readable, registration=False)
    registered = Sandbox(name=name, fs_readable=readable)
    private.spawn(["sleep", "30"])
    try:
        registered.spawn(["sleep", "30"])
        try:
            result = Sandbox(
                name=name, fs_readable=readable, registration=False,
            ).run(["true"])
            assert result.success, result.error
            with pytest.raises(RuntimeError, match="sandlock_create failed"):
                Sandbox(name=name, fs_readable=readable).spawn(["true"])
        finally:
            registered.kill()
    finally:
        private.kill()
