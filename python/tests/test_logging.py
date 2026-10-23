"""Native diagnostics reach the "sandlock" logger, never stderr directly."""

from __future__ import annotations

import logging
import subprocess
import sys
import time

from sandlock import _sdk

_BAD_STDIO = 7

_TRIGGER = (
    "import time\n"
    "from sandlock import _sdk\n"
    f"_sdk._lib.sandlock_popen(None, None, None, 0, {_BAD_STDIO}, 0, 0, None, None, None)\n"
    "time.sleep(0.5)\n"
)


def _reject_stdio() -> None:
    assert not _sdk._lib.sandlock_popen(None, None, None, 0, _BAD_STDIO, 0, 0, None, None, None)


def test_native_error_reaches_the_sandlock_logger(caplog):
    caplog.set_level(logging.DEBUG, logger="sandlock")
    _reject_stdio()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        records = [r for r in caplog.records if r.name == "sandlock"]
        if records:
            break
        time.sleep(0.01)
    assert records, "no record reached the sandlock logger"
    assert records[0].levelno == logging.ERROR
    assert "unknown StdioMode" in records[0].getMessage()


def test_unconfigured_logging_keeps_stderr_clean():
    out = subprocess.run([sys.executable, "-c", _TRIGGER], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stderr == ""


def test_configured_logging_shows_native_errors():
    script = "import logging\nlogging.basicConfig()\n" + _TRIGGER
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "ERROR:sandlock:sandlock_popen rejected an unknown StdioMode" in out.stderr
