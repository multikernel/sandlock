# SPDX-License-Identifier: Apache-2.0
"""CLI/SDK parity on profiles.

A profile has to mean the same thing whether `sandlock run --profile-file`
loads it or the Python SDK does. Both now go through the same core parser, so
what is left to check is that nothing is lost on the way from the canonical
form to a native sandbox, and that a bad profile is refused in the same words.

The comparison point is the control plane. A running sandbox serves its
effective policy over `sandlock inspect`, serialized by the same core routine
whichever side created it, so a dropped read-only mount, a size resolved
differently, or a port range expanded differently shows up as a difference in
that document. Comparing the two documents compares the policy, not the text
of the profile.

Profiles that cannot be run that far (a chroot with no interpreter inside it,
a memory limit of zero) are compared one step earlier: both implementations
have to accept them, and the values the SDK resolved are pinned here. Profiles
both sides reject are compared on the message.

The corpus below is meant to cover every micro-grammar a profile can carry:
mount specs with and without a `:ro`/`:rw` suffix, byte sizes, RFC 3339
timestamps, net rules, bind port specs, HTTP rules, branch actions, and
syscall group names.
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sandlock._profile import policy_from_toml
from sandlock.exceptions import PolicyError
from sandlock.sandbox import BranchAction, Mount

REPO_ROOT = Path(__file__).resolve().parents[2]

# The guest command only has to stay alive long enough to be inspected.
SLEEP = shutil.which("sleep") or "/bin/sleep"

# Grants every runnable case needs, so that the guest can exec the interpreter
# it was given. Missing directories are dropped: a grant on a path that does
# not exist is an error, and the layout differs between distributions.
BASE_READ = [d for d in ("/usr", "/bin", "/lib", "/lib64", "/etc") if os.path.isdir(d)]

_names = itertools.count()


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{os.getpid()}-{next(_names)}"


@pytest.fixture(scope="session")
def cli() -> str:
    """Path to the `sandlock` binary, built if it is not there yet.

    `SANDLOCK_CLI` short-circuits the search for packaging and for running
    these tests against an installed binary.
    """
    env = os.environ.get("SANDLOCK_CLI")
    if env:
        return env
    for profile in ("debug", "release"):
        candidate = REPO_ROOT / "target" / profile / "sandlock"
        if candidate.is_file():
            return str(candidate)
    subprocess.run(
        ["cargo", "build", "-p", "sandlock-cli"],
        cwd=REPO_ROOT,
        check=True,
        # The SDK loads the shared library from <repo>/target, so the CLI has
        # to land there too and not in a redirected target directory.
        env={k: v for k, v in os.environ.items() if k != "CARGO_TARGET_DIR"},
    )
    return str(REPO_ROOT / "target" / "debug" / "sandlock")


# ============================================================
# Corpus
# ============================================================


@dataclass(frozen=True)
class Case:
    """One profile, and how far the two implementations can be compared."""

    name: str
    toml: str
    #: "run" compares the effective policy of a live sandbox; "load" only
    #: checks that both implementations accept the profile, for policies whose
    #: guest cannot reach the point of being inspected.
    compare: str = "run"
    #: Sandbox attributes the profile is expected to resolve to. This is what
    #: pins the meaning of a micro-grammar ("512M" is 536870912 bytes) rather
    #: than only pinning that both sides agree.
    expect: dict = field(default_factory=dict)


CASES: list[Case] = [
    Case(
        name="filesystem_lists_and_branch_actions",
        toml="""
            [filesystem]
            read = {base_read}
            write = ["{tmp}/w"]
            deny = ["/etc/shadow"]
            on_exit = "keep"
            on_error = "abort"
        """,
        expect={
            "fs_denied": ["/etc/shadow"],
            "on_exit": BranchAction.KEEP,
            "on_error": BranchAction.ABORT,
        },
    ),
    Case(
        name="branch_action_commit",
        toml="""
            [filesystem]
            read = {base_read}
            on_exit = "commit"
        """,
        expect={"on_exit": BranchAction.COMMIT, "on_error": BranchAction.COMMIT},
    ),
    Case(
        name="mount_specs_ro_rw_and_bare",
        toml="""
            [filesystem]
            read = {base_read}
            mount = ["/ro:{tmp}:ro", "/bare:{tmp}", "/rw:{tmp}:rw"]
        """,
        expect={
            "fs_mount": [
                Mount(virt="/ro", host="{tmp}", ro=True),
                Mount(virt="/bare", host="{tmp}", ro=False),
                Mount(virt="/rw", host="{tmp}", ro=False),
            ],
        },
    ),
    Case(
        name="byte_sizes_suffixed",
        toml="""
            [filesystem]
            read = {base_read}
            [limits]
            memory = "512M"
            disk = "1G"
        """,
        expect={"max_memory": 512 * 1024 * 1024, "max_disk": 1024 * 1024 * 1024},
    ),
    Case(
        # The spellings are what this case is about: a bare byte count and a
        # `K` suffix. The values are large because the case compares two live
        # sandboxes, and a ceiling that the guest cannot start under is a
        # portability trap rather than a stricter test: 1MiB is enough for
        # `sleep` on x86-64 and not on arm64, where the loader maps more.
        name="byte_sizes_bare_and_kilo",
        toml="""
            [filesystem]
            read = {base_read}
            [limits]
            memory = "268435456"
            disk = "1048576K"
        """,
        expect={"max_memory": 268435456, "max_disk": 1048576 * 1024},
    ),
    Case(
        name="byte_size_largest_supported",
        toml="""
            [filesystem]
            read = {base_read}
            [limits]
            disk = "16777215G"
        """,
        compare="load",
        expect={"max_disk": 16777215 * 1024 * 1024 * 1024},
    ),
    Case(
        name="byte_size_zero_disk",
        # "0" is a size the grammar reads, and the disk quota is the knob that
        # takes it: zero is its spelling of "unlimited". The memory ceiling
        # refuses the same text (see the memory_zero reject), so the grammar
        # and the policy are pinned apart rather than together.
        toml="""
            [filesystem]
            read = {base_read}
            [limits]
            disk = "0"
        """,
        expect={"max_disk": 0},
    ),
    Case(
        name="limits_scalars",
        toml="""
            [filesystem]
            read = {base_read}
            [limits]
            processes = 8
            open_files = 128
            cpu = 50
            num_cpus = 1
            cpu_cores = [0]
        """,
        expect={
            "max_processes": 8,
            "max_open_files": 128,
            "max_cpu": 50,
            "num_cpus": 1,
            "cpu_cores": [0],
        },
    ),
    Case(
        name="time_start_utc",
        toml="""
            [filesystem]
            read = {base_read}
            [determinism]
            time_start = "2026-01-01T00:00:00Z"
        """,
        expect={"time_start": 1767225600},
    ),
    Case(
        name="time_start_offset",
        # The same instant written with a non-zero offset. Both sides have to
        # land on the same epoch second, not on the wall clock digits.
        toml="""
            [filesystem]
            read = {base_read}
            [determinism]
            time_start = "2025-12-31T21:00:00-03:00"
        """,
        expect={"time_start": 1767225600},
    ),
    Case(
        name="determinism_flags",
        toml="""
            [filesystem]
            read = {base_read}
            [determinism]
            random_seed = 7
            deterministic_dirs = true
            no_randomize_memory = true
        """,
        expect={
            "random_seed": 7,
            "deterministic_dirs": True,
            "no_randomize_memory": True,
        },
    ),
    Case(
        name="program_section",
        toml="""
            [filesystem]
            read = {base_read}
            [program]
            env = { FOO = "bar", BAZ = "qux" }
            cwd = "/tmp"
            uid = {uid}
            gid = {gid}
            clean_env = true
            no_coredump = true
            no_huge_pages = true
        """,
        expect={
            "env": {"FOO": "bar", "BAZ": "qux"},
            "cwd": "/tmp",
            "clean_env": True,
            "no_coredump": True,
            "no_huge_pages": True,
        },
    ),
    Case(
        name="program_exec_is_not_policy",
        # exec/args identify a program, not a policy. The CLI takes the command
        # from argv here, so the two sandboxes still have to agree.
        toml="""
            [filesystem]
            read = {base_read}
            [program]
            exec = "/bin/true"
            args = ["--flag"]
        """,
    ),
    Case(
        name="net_rules_every_form",
        toml="""
            [filesystem]
            read = {base_read}
            [network]
            allow = [
                "127.0.0.1:8080",
                "localhost:22,443",
                "tcp://10.0.0.0/8:443",
                "udp://192.168.1.1:53",
                "udp://*:*",
                "icmp://*",
                ":53",
                "[2606:4700::/32]:443",
            ]
        """,
        expect={
            # A scheme-less rule covers TCP and UDP, so core hands back one
            # rendered rule per protocol.
            "net_allow": [
                "tcp://127.0.0.1:8080",
                "udp://127.0.0.1:8080",
                "tcp://localhost:22,443",
                "udp://localhost:22,443",
                "tcp://10.0.0.0/8:443",
                "udp://192.168.1.1:53",
                "udp://*",
                "icmp://*",
                "tcp://*:53",
                "udp://*:53",
                "tcp://[2606:4700::/32]:443",
                "udp://[2606:4700::/32]:443",
            ],
        },
    ),
    Case(
        name="net_deny_and_bind_denylist",
        toml="""
            [filesystem]
            read = {base_read}
            [network]
            deny = ["10.0.0.0/8:443", "udp://1.2.3.4:53"]
            deny_bind = [22, "8000-8002"]
        """,
        expect={
            "net_deny": ["tcp://10.0.0.0/8:443", "udp://10.0.0.0/8:443", "udp://1.2.3.4:53"],
            "net_deny_bind": [22, 8000, 8001, 8002],
        },
    ),
    Case(
        name="bind_port_specs",
        toml="""
            [filesystem]
            read = {base_read}
            [network]
            allow_bind = [8080, "9000-9002", "7000,7001"]
            port_remap = true
        """,
        expect={
            # Ranges and lists are expanded, sorted and deduplicated by core.
            "net_allow_bind": [7000, 7001, 8080, 9000, 9001, 9002],
            "port_remap": True,
        },
    ),
    Case(
        name="bind_any_port",
        toml="""
            [filesystem]
            read = {base_read}
            [network]
            allow_bind = ["*"]
        """,
        expect={"net_allow_bind": ["*"]},
    ),
    Case(
        name="http_rules",
        toml="""
            [filesystem]
            read = {base_read}
            [http]
            ports = [8080]
            allow = ["get localhost/v1/*", "POST localhost/api"]
            deny = ["* localhost/admin"]
        """,
        expect={
            # The method is uppercased and the path normalized by core.
            "http_allow": ["GET localhost/v1/*", "POST localhost/api"],
            "http_deny": ["* localhost/admin"],
            "http_ports": [8080],
        },
    ),
    Case(
        name="http_wildcard_host",
        toml="""
            [filesystem]
            read = {base_read}
            [http]
            ports = [8080]
            allow = ["GET */public/*"]
        """,
        expect={"http_allow": ["GET */public/*"]},
    ),
    Case(
        name="syscall_groups_and_names",
        toml="""
            [filesystem]
            read = {base_read}
            [syscalls]
            extra_allow = ["sysv_ipc"]
            extra_deny = ["ptrace", "keyctl"]
        """,
        expect={
            "extra_allow_syscalls": ["sysv_ipc"],
            "extra_deny_syscalls": ["ptrace", "keyctl"],
        },
    ),
    Case(
        name="config_workdir",
        toml="""
            [filesystem]
            read = {base_read}
            [config]
            workdir = "{tmp}"
        """,
        expect={"workdir": "{tmp}"},
    ),
    Case(
        name="chroot",
        # A chroot with nothing in it cannot exec the guest command, so this
        # one stops at load time.
        toml="""
            [filesystem]
            read = {base_read}
            chroot = "{tmp}"
        """,
        compare="load",
        expect={"chroot": "{tmp}"},
    ),
]


# A profile both implementations must refuse, with the same words. One entry
# per micro-grammar that can fail, plus the cross-section checks the builder
# runs after the whole profile is in.
REJECTS: list[tuple[str, str]] = [
    ("size_fractional", '[limits]\nmemory = "1.5G"\n'),
    ("size_terabyte_suffix", '[limits]\nmemory = "1T"\n'),
    ("size_out_of_range", '[limits]\nmemory = "17179869184G"\n'),
    ("size_not_a_number", '[limits]\nmemory = "abc"\n'),
    ("size_negative", '[limits]\nmemory = "-1"\n'),
    ("disk_fractional", '[limits]\ndisk = "0.5G"\n'),
    ("time_start_without_offset", '[determinism]\ntime_start = "2026-01-01T00:00:00"\n'),
    ("time_start_not_a_timestamp", '[determinism]\ntime_start = "yesterday"\n'),
    ("time_start_as_integer", "[determinism]\ntime_start = 1767225600\n"),
    ("mount_without_separator", '[filesystem]\nmount = ["novirt"]\n'),
    ("mount_empty_host", '[filesystem]\nmount = ["/v:"]\n'),
    ("mount_empty_virtual", '[filesystem]\nmount = [":/h"]\n'),
    ("mount_suffix_only", '[filesystem]\nmount = ["/v:ro"]\n'),
    ("branch_action_on_exit", '[filesystem]\non_exit = "nope"\n'),
    ("branch_action_on_error", '[filesystem]\non_error = "rollback"\n'),
    ("net_port_out_of_range", '[network]\nallow = ["example.com:99999"]\n'),
    ("net_unknown_scheme", '[network]\nallow = ["ftp://example.com:21"]\n'),
    ("net_deny_hostname", '[network]\ndeny = ["example.com:443"]\n'),
    ("net_allow_and_deny", '[network]\nallow = ["1.2.3.4:80"]\ndeny = ["5.6.7.8:80"]\n'),
    ("bind_reversed_range", '[network]\nallow_bind = ["9000-8000"]\n'),
    ("bind_not_a_port", '[network]\nallow_bind = ["http"]\n'),
    ("bind_allow_and_deny", "[network]\nallow_bind = [80]\ndeny_bind = [81]\n"),
    ("syscall_group_unknown", '[syscalls]\nextra_allow = ["not_a_group"]\n'),
    ("syscall_name_unknown", '[syscalls]\nextra_deny = ["nosuchsyscall"]\n'),
    ("uid_without_gid", "[program]\nuid = 1000\n"),
    ("cpu_zero", "[limits]\ncpu = 0\n"),
    ("cpu_above_hundred", "[limits]\ncpu = 101\n"),
    ("open_files_zero", "[limits]\nopen_files = 0\n"),
    ("processes_zero", "[limits]\nprocesses = 0\n"),
    ("num_cpus_zero", "[limits]\nnum_cpus = 0\n"),
    ("memory_zero", '[limits]\nmemory = "0"\n'),
    ("cpu_cores_empty", "[limits]\ncpu_cores = []\n"),
    ("http_rule_without_space", '[http]\nallow = ["GETexample.com"]\n'),
    ("http_port_out_of_range", "[http]\nports = [70000]\n"),
    ("unknown_key", '[limits]\nmemry = "1G"\n'),
    ("unknown_section", "[nope]\nx = 1\n"),
    ("malformed_toml", "[limits\n"),
    ("wrong_value_type", '[limits]\nprocesses = "many"\n'),
]


# ============================================================
# Harness
# ============================================================


def _render(text: str, tmp_path: Path) -> str:
    """Fill in the host-specific parts of a corpus profile."""
    return (
        text.replace("{base_read}", json.dumps(BASE_READ))
        .replace("{tmp}", str(tmp_path))
        .replace("{uid}", str(os.getuid()))
        .replace("{gid}", str(os.getgid()))
    )


def _expected(value, tmp_path: Path):
    """Fill in `{tmp}` inside an expected value."""
    if isinstance(value, str):
        return value.replace("{tmp}", str(tmp_path))
    if isinstance(value, Mount):
        return Mount(
            virt=_expected(value.virt, tmp_path),
            host=_expected(value.host, tmp_path),
            ro=value.ro,
        )
    if isinstance(value, list):
        return [_expected(v, tmp_path) for v in value]
    return value


def _without_run_local_paths(policy: dict) -> dict:
    """Blank out the parts of a policy that name this run and not the profile.

    A workdir gives the sandbox a copy-on-write upper layer under a directory
    named after a fresh UUID, which is then granted read access. The grant is
    part of the effective policy but its path is per run, so comparing the two
    documents literally would compare two UUIDs.
    """
    text = json.dumps(policy)
    text = re.sub(r"/sandlock-cow/[0-9a-f-]{36}/", "/sandlock-cow/<run>/", text)
    return json.loads(text)


def _inspect(cli: str, name: str, timeout: float = 15.0) -> dict:
    """Read a live sandbox's effective policy through the control plane."""
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        done = subprocess.run([cli, "inspect", name], capture_output=True, text=True)
        if done.returncode == 0:
            return json.loads(done.stdout)
        last = done.stderr.strip()
        time.sleep(0.05)
    raise AssertionError(f"`sandlock inspect {name}` never answered: {last}")


def _stop(proc: subprocess.Popen) -> str:
    """Shut a sandbox down and return what it reported.

    A signalled supervisor tears its guest down with it, so the polite signal
    goes first; the guest would otherwise outlive the test as an orphan.
    """
    proc.terminate()
    try:
        _, err = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        proc.kill()
        _, err = proc.communicate(timeout=10)
    return err.strip()


def _cli_effective_policy(cli: str, profile: Path) -> dict:
    """Run a profile through `sandlock run` and read back its policy."""
    name = _unique_name("parity-cli")
    proc = subprocess.Popen(
        [cli, "run", "--profile-file", str(profile), "--name", name, "--", SLEEP, "30"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        policy = _inspect(cli, name)
    except BaseException as exc:
        reported = _stop(proc)
        if isinstance(exc, AssertionError):
            raise AssertionError(f"{exc}\nsandlock run said: {reported}") from exc
        raise
    _stop(proc)
    return policy


def _sdk_effective_policy(cli: str, text: str) -> dict:
    """Load a profile through the SDK and read back the same document."""
    policy = dataclasses.replace(policy_from_toml(text), name=_unique_name("parity-sdk"))
    policy.spawn([SLEEP, "30"])
    try:
        return _inspect(cli, policy.name)
    finally:
        try:
            policy.kill()
        except Exception:  # pragma: no cover - the guest may already be gone
            pass


def _cli_load_error(cli: str, profile: Path) -> str | None:
    """Return the CLI's profile diagnosis, or None if it accepted the profile.

    A rejected profile stops `sandlock run` before it forks anything, and the
    report is the core error. Anything that goes wrong afterwards (an exec that
    the policy denies, a host that does not resolve) is a different message,
    which is what tells the two apart.
    """
    done = subprocess.run(
        [cli, "run", "--profile-file", str(profile), "--", "/bin/true"],
        capture_output=True,
        text=True,
    )
    head = done.stderr.split("\n\nCaused by:")[0].strip()
    if not head.startswith("Error: sandbox error:"):
        return None
    return head[len("Error: ") :]


def _write(tmp_path: Path, text: str) -> Path:
    profile = tmp_path / "profile.toml"
    profile.write_text(text, encoding="utf-8")
    return profile


def _ids(cases):
    return [c.name for c in cases]


RUN_CASES = [c for c in CASES if c.compare == "run"]
LOAD_CASES = [c for c in CASES if c.compare == "load"]
EXPECT_CASES = [c for c in CASES if c.expect]


# ============================================================
# Tests
# ============================================================


@pytest.mark.parametrize("case", RUN_CASES, ids=_ids(RUN_CASES))
def test_effective_policy_is_the_same_from_both_sides(cli, tmp_path, case):
    """The same profile has to produce the same live policy either way."""
    (tmp_path / "w").mkdir(exist_ok=True)
    text = _render(case.toml, tmp_path)
    from_cli = _cli_effective_policy(cli, _write(tmp_path, text))
    from_sdk = _sdk_effective_policy(cli, text)
    assert _without_run_local_paths(from_cli) == _without_run_local_paths(from_sdk)


@pytest.mark.parametrize("case", LOAD_CASES, ids=_ids(LOAD_CASES))
def test_both_accept_the_profile(cli, tmp_path, case):
    """Policies whose guest cannot run are still accepted by both sides."""
    text = _render(case.toml, tmp_path)
    assert _cli_load_error(cli, _write(tmp_path, text)) is None
    policy_from_toml(text)  # raises PolicyError if the SDK disagrees


@pytest.mark.parametrize("case", EXPECT_CASES, ids=_ids(EXPECT_CASES))
def test_profile_resolves_to_expected_values(tmp_path, case):
    """Pin what each micro-grammar means, not only that both sides agree."""
    policy = policy_from_toml(_render(case.toml, tmp_path))
    for attr, value in case.expect.items():
        assert getattr(policy, attr) == _expected(value, tmp_path), attr


@pytest.mark.parametrize("name,text", REJECTS, ids=[n for n, _ in REJECTS])
def test_rejected_by_both_with_the_same_message(cli, tmp_path, name, text):
    """A refused profile is refused on both sides, in the same words."""
    from_cli = _cli_load_error(cli, _write(tmp_path, text))
    assert from_cli is not None, "the CLI accepted a profile the SDK rejects"

    with pytest.raises(PolicyError) as excinfo:
        policy_from_toml(text)

    # The core message is passed through unchanged on both sides; the CLI's
    # error formatting is what strips the trailing newline of a TOML report.
    assert str(excinfo.value).rstrip("\n") == from_cli


def test_time_start_the_c_abi_cannot_carry_is_refused_loudly(cli, tmp_path):
    """Two timestamps the CLI accepts and the SDK cannot apply.

    `sandlock_sandbox_builder_time_start` takes a `uint64` of seconds, so a
    sub-second or pre-epoch stamp cannot be handed to it, while core keeps a
    full timestamp and the CLI runs both. That is a real parity gap, reported
    upstream. What is pinned here is that the SDK says so instead of wrapping
    a negative value through the unsigned setter (a pre-epoch stamp used to
    land in year 584942417355), and that the profile itself still loads, so
    the gap stays visible as an ABI limit rather than a parse difference.
    """
    for text in (
        '[determinism]\ntime_start = "2026-01-01T00:00:00.5Z"\n',
        '[determinism]\ntime_start = "1960-01-01T00:00:00Z"\n',
    ):
        assert _cli_load_error(cli, _write(tmp_path, text)) is None
        policy = policy_from_toml(text)
        with pytest.raises(ValueError, match="sandlock_sandbox_builder_time_start"):
            policy.create(["/bin/true"])
