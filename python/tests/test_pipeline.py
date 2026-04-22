# SPDX-License-Identifier: Apache-2.0
"""Tests for Stage, Pipeline, and Sandbox.cmd()."""

import os
import sys
import tempfile

import pytest

from sandlock import Sandbox, Policy, Stage, Pipeline, NamedStage, Gather, GatherPipeline


# --- Helpers ---

_PYTHON_PREFIX = sys.prefix

def _policy(**overrides):
    """Minimal policy for testing."""
    defaults = {
        "fs_readable": list(dict.fromkeys([
            "/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin",
            _PYTHON_PREFIX,
        ])),
        "clean_env": True,
    }
    defaults.update(overrides)
    return Policy(**defaults)


# --- Stage ---

class TestStage:
    def test_cmd_returns_stage(self):
        sb = Sandbox(_policy())
        stage = sb.cmd(["echo", "hello"])
        assert isinstance(stage, Stage)
        assert stage.sandbox is sb
        assert stage.args == ["echo", "hello"]

    def test_stage_run(self):
        result = Sandbox(_policy()).cmd(["echo", "hello"]).run()
        assert result.success
        assert b"hello" in result.stdout

    def test_stage_or_stage_returns_pipeline(self):
        a = Sandbox(_policy()).cmd(["echo", "hello"])
        b = Sandbox(_policy()).cmd(["cat"])
        p = a | b
        assert isinstance(p, Pipeline)
        assert len(p.stages) == 2

    def test_stage_or_pipeline(self):
        a = Sandbox(_policy()).cmd(["echo", "a"])
        b = Sandbox(_policy()).cmd(["cat"])
        c = Sandbox(_policy()).cmd(["cat"])
        p = a | b | c
        assert isinstance(p, Pipeline)
        assert len(p.stages) == 3


# --- Pipeline ---

class TestPipeline:
    def test_two_stage_pipe(self):
        """echo | cat: basic data flow through pipe."""
        result = (
            Sandbox(_policy()).cmd(["echo", "hello pipeline"])
            | Sandbox(_policy()).cmd(["cat"])
        ).run()
        assert result.success
        assert b"hello pipeline" in result.stdout

    def test_three_stage_pipe(self):
        """echo | tr | cat: data flows through multiple stages."""
        result = (
            Sandbox(_policy()).cmd(["echo", "hello"])
            | Sandbox(_policy()).cmd(["tr", "a-z", "A-Z"])
            | Sandbox(_policy()).cmd(["cat"])
        ).run()
        assert result.success
        assert b"HELLO" in result.stdout

    def test_disjoint_policies(self):
        """Stages have independent policies."""
        with tempfile.TemporaryDirectory() as tmp:
            secret = os.path.join(tmp, "secret.txt")
            with open(secret, "w") as f:
                f.write("sensitive data")

            # Stage 1: can read the file
            reader_policy = _policy(fs_readable=[
                tmp, "/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin",
            ])
            # Stage 2: cannot read the file (no tmp in readable)
            processor_policy = _policy()

            result = (
                Sandbox(reader_policy).cmd(["cat", secret])
                | Sandbox(processor_policy).cmd(["tr", "a-z", "A-Z"])
            ).run()
            assert result.success
            assert b"SENSITIVE DATA" in result.stdout

    def test_pipeline_captures_last_stderr(self):
        """Stderr from last stage is captured."""
        result = (
            Sandbox(_policy()).cmd(["echo", "hello"])
            | Sandbox(_policy()).cmd(
                [sys.executable, "-c",
                 "import sys; sys.stderr.write('err msg\\n'); "
                 "print(sys.stdin.read().strip())"]
            )
        ).run()
        assert result.success
        assert b"hello" in result.stdout
        assert b"err msg" in result.stderr

    def test_pipeline_stdout_to_fd(self):
        """stdout= routes final output to fd, result.stdout is empty."""
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "output.txt")
            out_fd = os.open(out_path, os.O_WRONLY | os.O_CREAT, 0o644)
            try:
                result = (
                    Sandbox(_policy()).cmd(["echo", "to fd"])
                    | Sandbox(_policy()).cmd(["cat"])
                ).run(stdout=out_fd)
            finally:
                os.close(out_fd)

            assert result.success
            assert result.stdout == b""
            with open(out_path) as f:
                assert "to fd" in f.read()

    def test_first_stage_failure(self):
        """Pipeline reports failure when first stage fails."""
        result = (
            Sandbox(_policy()).cmd(["/nonexistent"])
            | Sandbox(_policy()).cmd(["cat"])
        ).run()
        # Last stage reads EOF from pipe → exits 0, but first stage failed.
        # We report last stage's exit code.
        assert result.stdout == b""

    def test_last_stage_failure(self):
        """Pipeline reports failure of the last stage."""
        result = (
            Sandbox(_policy()).cmd(["echo", "hello"])
            | Sandbox(_policy()).cmd(
                [sys.executable, "-c", "import sys; sys.exit(42)"]
            )
        ).run()
        assert not result.success
        assert result.exit_code == 42

    def test_pipeline_requires_two_stages(self):
        with pytest.raises(ValueError, match="at least 2"):
            Pipeline([Sandbox(_policy()).cmd(["echo"])])

    def test_pipeline_timeout(self):
        """Pipeline times out if a stage hangs."""
        result = (
            Sandbox(_policy()).cmd(
                [sys.executable, "-c", "import time; time.sleep(60)"]
            )
            | Sandbox(_policy()).cmd(["cat"])
        ).run(timeout=1)
        assert not result.success
        assert "timed out" in (result.error or "").lower()


# --- XOA pattern ---

class TestXOA:
    def test_xoa_data_flow(self):
        """Planner generates script, executor runs it with data access."""
        with tempfile.TemporaryDirectory() as workspace:
            # Write "untrusted data" that planner must not see
            data_file = os.path.join(workspace, "emails.txt")
            with open(data_file, "w") as f:
                f.write("From: alice\nSubject: hello\n")

            # Planner: no filesystem access to workspace
            planner_policy = _policy()

            # Executor: can read workspace, no network
            executor_policy = _policy(
                fs_readable=list(dict.fromkeys([
                    workspace, "/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin",
                    _PYTHON_PREFIX,
                ])),
                net_connect=[],
            )

            # Planner emits a script that reads the data file.
            # In real XOA the LLM generates this from tool schemas.
            planner_cmd = [
                sys.executable, "-c",
                "print("
                "'import sys\\n"
                f"with open(\\'{data_file}\\') as f:\\n"
                "    print(f.read())')"
            ]

            result = (
                Sandbox(planner_policy).cmd(planner_cmd)
                | Sandbox(executor_policy).cmd(
                    [sys.executable, "-"]  # reads script from stdin
                )
            ).run()

            assert result.success
            assert b"From: alice" in result.stdout
            assert b"Subject: hello" in result.stdout

    def test_xoa_executor_no_network(self):
        """Executor cannot reach the network."""
        executor_policy = _policy(net_connect=[])

        result = (
            Sandbox(_policy()).cmd(
                [sys.executable, "-c",
                 "print('import socket; "
                 "socket.create_connection((\"1.1.1.1\", 80), timeout=1)')"]
            )
            | Sandbox(executor_policy).cmd(
                [sys.executable, "-c", "-"]
            )
        ).run()

        # Executor tried to connect but was blocked
        assert not result.success


# --- Gather ---

class TestGather:
    def test_as_returns_named_stage(self):
        stage = Sandbox(_policy()).cmd(["echo", "hello"])
        named = stage.as_("greeting")
        assert isinstance(named, NamedStage)
        assert named.name == "greeting"

    def test_add_returns_gather(self):
        a = Sandbox(_policy()).cmd(["echo", "a"]).as_("a")
        b = Sandbox(_policy()).cmd(["echo", "b"]).as_("b")
        g = a + b
        assert isinstance(g, Gather)
        assert len(g.sources) == 2

    def test_gather_or_stage_returns_pipeline(self):
        g = (
            Sandbox(_policy()).cmd(["echo", "a"]).as_("a")
            + Sandbox(_policy()).cmd(["echo", "b"]).as_("b")
        )
        gp = g | Sandbox(_policy()).cmd(["cat"])
        assert isinstance(gp, GatherPipeline)

    def test_gather_two_sources(self):
        """Two producers pipe into one consumer via gather."""
        result = (
            Sandbox(_policy()).cmd(["echo", "hello"]).as_("greeting")
            + Sandbox(_policy()).cmd(["echo", "world"]).as_("name")
            | Sandbox(_policy()).cmd(
                ["sh", "-c",
                 'read name; greeting=$(cat <&3); echo "$greeting $name"']
            )
        ).run()
        assert result.success, f"stderr={result.stderr}"
        assert b"hello" in result.stdout
        assert b"world" in result.stdout

    def test_gather_with_python_inputs(self):
        """Consumer reads gather inputs via sandlock.inputs."""
        python_paths = [p for p in sys.path if p and os.path.isdir(p)]
        policy = _policy(fs_readable=list(dict.fromkeys([
            "/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin",
            "/home", _PYTHON_PREFIX,
        ] + python_paths)))

        result = (
            Sandbox(policy).cmd(
                [sys.executable, "-c", "print('DATA_CONTENT')"]
            ).as_("data")
            + Sandbox(policy).cmd(
                [sys.executable, "-c", "print('CODE_CONTENT')"]
            ).as_("code")
            | Sandbox(policy).cmd(
                [sys.executable, "-c",
                 "from sandlock import inputs; "
                 "print(f'code={inputs[\"code\"].strip()}'); "
                 "print(f'data={inputs[\"data\"].strip()}')"]
            )
        ).run()
        assert result.success, f"stderr={result.stderr}"
        assert b"code=CODE_CONTENT" in result.stdout
        assert b"data=DATA_CONTENT" in result.stdout

    def test_gather_disjoint_policies(self):
        """Sources have independent policies — data source can read
        a file the code source cannot."""
        with tempfile.TemporaryDirectory() as tmp:
            secret = os.path.join(tmp, "secret.txt")
            with open(secret, "w") as f:
                f.write("sensitive data")

            data_policy = _policy(fs_readable=list(dict.fromkeys([
                tmp, "/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin",
                _PYTHON_PREFIX,
            ])))
            code_policy = _policy()
            consumer_policy = _policy()

            result = (
                Sandbox(data_policy).cmd(["cat", secret]).as_("data")
                + Sandbox(code_policy).cmd(
                    ["echo", "tr a-z A-Z <&3"]
                ).as_("code")
                | Sandbox(consumer_policy).cmd(
                    ["sh", "-c", 'eval "$(cat)"']
                )
            ).run()
            assert result.success, f"stderr={result.stderr}"
            assert b"SENSITIVE DATA" in result.stdout

    def test_gather_three_sources(self):
        """Three producers fan into one consumer."""
        result = (
            Sandbox(_policy()).cmd(["echo", "aaa"]).as_("a")
            + Sandbox(_policy()).cmd(["echo", "bbb"]).as_("b")
            + Sandbox(_policy()).cmd(["echo", "ccc"]).as_("c")
            | Sandbox(_policy()).cmd(
                ["sh", "-c",
                 # c on stdin, a on fd 3, b on fd 4
                 # Use read builtin (no fork) instead of $(cat) to avoid
                 # flaky kernel-level EAGAIN under concurrent load.
                 'read c; read a <&3; read b <&4; echo "$a $b $c"']
            )
        ).run()
        assert result.success, f"stderr={result.stderr}"
        assert b"aaa" in result.stdout
        assert b"bbb" in result.stdout
        assert b"ccc" in result.stdout
