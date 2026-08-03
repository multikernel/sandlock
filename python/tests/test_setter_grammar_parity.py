# SPDX-License-Identifier: Apache-2.0
"""One grammar, four surfaces: a CLI flag, a profile key, a C ABI setter, an SDK.

`sandlock_sandbox_builder_max_memory`, `_max_disk` and `_time_start` used to
take a number that somebody else had already parsed, so every binding grew a
parser of its own. The two that existed agreed with each other and both
disagreed with the core they were feeding, accepting `1.5G` and `1T` that no
profile and no CLI flag has ever accepted. The setters now take the string the
user wrote and hand it to the core, which leaves one grammar. This file is the
evidence for that claim, and the place where a second grammar would show up
again.

Every value in the corpus is driven through four surfaces:

    sandlock run --max-memory 512M ...       the flag
    [limits] memory = "512M"                 the profile
    sandlock_sandbox_builder_max_memory      the setter, called through ctypes
    sandlock.Sandbox(max_memory="512M")      the Python SDK

The fifth, the Go SDK, is driven over the same corpus by
`go/grammar_parity_linux_test.go`, which is why the corpus itself lives in
`tests/grammar-corpus.json` rather than in this file: a list of values pasted
into each language would be the failure this whole change is about, one table
per surface and nothing keeping them together.

An accepted value is compared on the effective policy of a live sandbox, read
back over `sandlock inspect`. That is the comparison point `test_cli_parity.py`
uses and for the same reason: the document is serialized by one core routine
whichever surface configured the sandbox, so comparing documents compares the
policy rather than the text that asked for it.

A rejected value is compared on the message. Each surface adds an envelope of
its own (`Error: ` from the CLI's report, `sandbox error: ` from the profile
loader's wrapper). Each envelope is asserted literally and then peeled, so what
is compared afterwards is the core's own sentence, and a surface that reworded
the diagnosis or parsed the value itself fails here.

Two things are deliberately not done here:

* The whole grammar is not walked on every surface. Each accepted entry below
  launches four sandboxes, so the corpus is one representative per equivalence
  class plus the edges. Every spelling the setter accepts is already pinned
  against the core's own parse, without launching anything, in
  `crates/sandlock-ffi/tests/builder_pending_error.rs`.
* The `setter` surface loads the library with a private `ctypes.CDLL` instead
  of through `sandlock._sdk`, so the ABI is exercised the way a foreign binding
  sees it. The `python` surface then goes through the SDK proper, and the two
  are separate on purpose: the first says the ABI is right, the second says the
  SDK forwards to it without helping.
"""

from __future__ import annotations

import ctypes
import itertools
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

import sandlock

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The corpus shared with the Go SDK's half of this proof. See its `about` key.
CORPUS_PATH = REPO_ROOT / "tests" / "grammar-corpus.json"
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))

#: The guest only has to stay alive long enough to be inspected.
SLEEP = shutil.which("sleep") or "/bin/sleep"

#: Grants every launched case needs so the guest can exec the program it was
#: given. Missing directories are dropped: a grant on a path that does not
#: exist is an error, and the layout differs between distributions.
GRANTS = [d for d in ("/usr", "/bin", "/lib", "/lib64", "/etc") if os.path.isdir(d)]

_names = itertools.count()


def _unique(prefix: str) -> str:
    return f"{prefix}-{os.getpid()}-{next(_names)}"


# ============================================================
# The four surfaces
# ============================================================

FLAG = "flag"
PROFILE = "profile"
SETTER = "setter"
PYSDK = "python"
SURFACES = (FLAG, PROFILE, SETTER, PYSDK)

#: What each surface wraps around the core's diagnosis. Asserted literally
#: before it is peeled: an envelope that changed is a surface that started
#: reporting something other than the core's verdict.
ENVELOPE = {
    # anyhow's report header, with the core error as the whole of it.
    FLAG: "Error: invalid sandbox: ",
    # The profile loader returns SandlockError, which names the layer.
    PROFILE: "Error: sandbox error: invalid sandbox: ",
    # `sandlock_sandbox_build` hands back the SandboxError it built with.
    SETTER: "invalid sandbox: ",
    # The SDK raises that same string as a RuntimeError and adds nothing.
    PYSDK: "invalid sandbox: ",
}


@dataclass(frozen=True)
class Knob:
    """One grammar, and how each surface spells the knob that carries it."""

    id: str
    flag: str
    setter: str
    python: str
    #: Where the value lands in a profile, and in the document a profile
    #: resolves to. The same pair addresses both, because the canonical
    #: document keeps the shape of the file it came from.
    doc: tuple[str, str]
    #: The knob name each surface writes into a rejection message, when the
    #: grammar's diagnosis names one at all. `None` means the core's message
    #: is knob-free, and the surfaces must then agree word for word.
    labels: dict[str, str] | None = None

    @property
    def section(self) -> str:
        return f"[{self.doc[0]}]"

    @property
    def key(self) -> str:
        return self.doc[1]


KNOBS = {
    name: Knob(
        id=name,
        flag=spec["flag"],
        setter=spec["setter"],
        python=spec["python"],
        doc=tuple(spec["profile"]),
        labels=spec.get("labels"),
    )
    for name, spec in CORPUS["knobs"].items()
}


# ============================================================
# Corpus
# ============================================================


@dataclass(frozen=True)
class Accepted:
    """A value all four surfaces must take, and what it has to mean."""

    knob: str
    value: str
    #: The exact resolution, as the canonical profile document reports it:
    #: an integer count of bytes, or `{"seconds", "nanoseconds"}` since the
    #: epoch. This is what pins the meaning of the grammar rather than only
    #: pinning that the surfaces agree on something.
    resolved: object
    #: How a live sandbox spells the value back over `sandlock inspect`, or
    #: `None` when that document cannot carry it at all.
    renders: str | None
    #: False for a policy whose guest cannot reach the point of being
    #: inspected. Such a value is still compared on all four surfaces, one
    #: step earlier: every surface has to accept it.
    live: bool = True

    @property
    def id(self) -> str:
        return f"{self.knob}-{_slug(self.value)}"


@dataclass(frozen=True)
class Rejected:
    """A value no surface may take, and the sentence it has to be refused with.

    `diagnosis` is a prefix of the core's message, with the knob label folded
    to `<knob>`. It is a prefix because the timestamp parser continues its
    sentence with wording that belongs to `jiff`, which this repository does
    not own; the surfaces are separately required to produce one identical
    full sentence, so the prefix pins the verdict and the comparison pins
    that nobody reworded the rest of it.
    """

    knob: str
    value: str
    diagnosis: str
    #: True for a value one of the deleted SDK parsers used to accept.
    sdk_only: bool = False

    @property
    def id(self) -> str:
        return f"{self.knob}-{_slug(self.value)}"


def _slug(value: str) -> str:
    """A pytest id that `-k` can select without quoting.

    Spaces become underscores rather than disappearing: whitespace is part of
    what is being tested here, and two entries that differ only in it must not
    collapse into one id.
    """
    return value.replace(" ", "_") or "empty"


ACCEPTED = [
    Accepted(
        knob=entry["knob"],
        value=entry["value"],
        resolved=entry["resolved"],
        renders=entry["renders"],
        live=entry.get("live", True),
    )
    for entry in CORPUS["accepted"]
]

REJECTED = [
    Rejected(
        knob=entry["knob"],
        value=entry["value"],
        diagnosis=entry["diagnosis"],
        sdk_only=entry.get("sdk_only", False),
    )
    for entry in CORPUS["rejected"]
]

#: The corpus lets an entry declare a surface that cannot carry it, for the one
#: reason a surface is allowed to have: the host language has no way to spell
#: the value. Go says "unset" with an empty string, so an empty `MaxMemory`
#: never reaches the core. None of the four surfaces driven here has such a
#: limit, and this is where that stops being an assumption: an entry that
#: excused one of them would otherwise be skipped in silence, which is exactly
#: how a surface stops being tested.
_EXCUSED = {
    surface
    for entry in CORPUS["accepted"] + CORPUS["rejected"]
    for surface in entry.get("unreachable", {})
}


def test_no_surface_driven_here_claims_it_cannot_carry_a_value():
    assert _EXCUSED.isdisjoint(SURFACES), (
        f"{CORPUS_PATH.name} excuses a surface this file drives: "
        f"{sorted(_EXCUSED & set(SURFACES))}"
    )


# ============================================================
# Building the artifacts under test
# ============================================================


def _cargo_build() -> None:
    subprocess.run(
        ["cargo", "build", "-p", "sandlock-cli", "-p", "sandlock-ffi"],
        cwd=REPO_ROOT,
        check=True,
        # Both artifacts have to land in <repo>/target, where this file looks
        # for them, and not in a redirected target directory.
        env={k: v for k, v in os.environ.items() if k != "CARGO_TARGET_DIR"},
    )


def _artifact(name: str, env_var: str) -> str:
    """Locate a build artifact, building it once if it is not there yet.

    `env_var` (`SANDLOCK_CLI`, `SANDLOCK_LIB`) short-circuits the search, for
    packaging and for running this file against an installed build. Both
    artifacts must come from the same tree: pointing one of them somewhere else
    compares two different implementations, which is only useful on purpose.
    """
    override = os.environ.get(env_var)
    if override:
        return override
    for attempt in (0, 1):
        candidates = [
            REPO_ROOT / "target" / profile / name for profile in ("debug", "release")
        ]
        found = [c for c in candidates if c.is_file()]
        if found:
            return str(max(found, key=lambda c: c.stat().st_mtime))
        if attempt == 0:
            _cargo_build()
    raise AssertionError(f"{name} was not built into {REPO_ROOT / 'target'}")


@pytest.fixture(scope="session")
def cli() -> str:
    return _artifact("sandlock", "SANDLOCK_CLI")


@pytest.fixture(scope="session")
def abi() -> "_Abi":
    return _Abi(_artifact("libsandlock_ffi.so", "SANDLOCK_LIB"))


class _Abi:
    """The exports this file drives, prototyped by hand.

    Everything the ABI hands back as an owned string is copied out and released
    here, so a leak in the test cannot mask one in the implementation.
    """

    def __init__(self, path: str) -> None:
        lib = ctypes.CDLL(path)
        ptr = ctypes.c_void_p
        lib.sandlock_sandbox_builder_new.restype = ptr
        lib.sandlock_sandbox_builder_new.argtypes = []
        setters = sorted({k.setter for k in KNOBS.values()})
        for name in ["sandlock_sandbox_builder_fs_read", *setters]:
            fn = getattr(lib, name)
            fn.restype = ptr
            # Every one of these takes a string. A setter that still took a
            # number would read the pointer as its value here.
            fn.argtypes = [ptr, ctypes.c_char_p]
        lib.sandlock_sandbox_build.restype = ptr
        lib.sandlock_sandbox_build.argtypes = [
            ptr,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_char_p),
        ]
        lib.sandlock_sandbox_free.restype = None
        lib.sandlock_sandbox_free.argtypes = [ptr]
        lib.sandlock_profile_parse.restype = ptr
        lib.sandlock_profile_parse.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_char_p),
        ]
        lib.sandlock_create.restype = ptr
        lib.sandlock_create.argtypes = [
            ptr,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_uint,
        ]
        lib.sandlock_start.restype = ctypes.c_int
        lib.sandlock_start.argtypes = [ptr]
        lib.sandlock_handle_kill.restype = ctypes.c_int
        lib.sandlock_handle_kill.argtypes = [ptr]
        lib.sandlock_handle_free.restype = None
        lib.sandlock_handle_free.argtypes = [ptr]
        lib.sandlock_string_free.restype = None
        lib.sandlock_string_free.argtypes = [ctypes.c_char_p]
        self.lib = lib

    def _take(self, owned: ctypes.c_char_p) -> str | None:
        # `is None` rather than a truth test: an empty string still owns an
        # allocation, and treating it as "nothing was written" would leak it
        # and report a message that was set as a message that was not.
        if owned.value is None:
            return None
        text = owned.value.decode()
        self.lib.sandlock_string_free(owned)
        return text

    def build(self, knob: Knob, value: str, grants: bool):
        """Configure one knob through its setter and build.

        Returns `(sandbox, err, message)`. The sandbox is owned by the caller
        and has to be released with `free_sandbox`.
        """
        b = self.lib.sandlock_sandbox_builder_new()
        assert b, "sandlock_sandbox_builder_new returned null"
        if grants:
            for path in GRANTS:
                b = self.lib.sandlock_sandbox_builder_fs_read(b, path.encode())
        b = getattr(self.lib, knob.setter)(b, value.encode())
        err = ctypes.c_int(7)  # poison: build has to overwrite this
        msg = ctypes.c_char_p()
        sandbox = self.lib.sandlock_sandbox_build(
            b, ctypes.byref(err), ctypes.byref(msg)
        )
        return sandbox, err.value, self._take(msg)

    def free_sandbox(self, sandbox) -> None:
        self.lib.sandlock_sandbox_free(sandbox)

    def profile_parse(self, toml: str):
        """Resolve a profile the way `sandlock_profile_parse` callers do.

        Returns `(document, err, message)`. This export runs the same core
        routine the CLI runs for `--profile-file`, which the core asserts in
        `profile::canonical`'s parse_error_text_matches_what_the_cli_prints.
        It is used here because it reports resolved values exactly, which the
        effective policy document does not.
        """
        err = ctypes.c_int(7)
        msg = ctypes.c_char_p()
        raw = self.lib.sandlock_profile_parse(
            toml.encode(), ctypes.byref(err), ctypes.byref(msg)
        )
        document = None
        if raw:
            document = json.loads(ctypes.string_at(raw).decode())
            self.lib.sandlock_string_free(ctypes.cast(raw, ctypes.c_char_p))
        return document, err.value, self._take(msg)

    def spawn(self, sandbox, name: str, cmd: list[str]):
        argv = (ctypes.c_char_p * len(cmd))(*[a.encode() for a in cmd])
        handle = self.lib.sandlock_create(sandbox, name.encode(), argv, len(cmd))
        assert handle, "sandlock_create returned null"
        assert self.lib.sandlock_start(handle) == 0, "sandlock_start failed"
        return handle

    def stop(self, handle) -> None:
        self.lib.sandlock_handle_kill(handle)
        self.lib.sandlock_handle_free(handle)


# ============================================================
# Driving the four surfaces
# ============================================================


def _profile_text(knob: Knob, value: str, grants: bool = True) -> str:
    """The profile that carries `value`, and nothing else that could fail."""
    head = ""
    if grants:
        reads = ", ".join(json.dumps(d) for d in GRANTS)
        head = f"[filesystem]\nread = [{reads}]\n\n"
    # TOML basic strings and JSON strings quote these values identically.
    return f"{head}{knob.section}\n{knob.key} = {json.dumps(value)}\n"


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


def _stop(cli: str, name: str, proc: subprocess.Popen) -> str:
    """Shut a sandbox down and return what it reported.

    `sandlock kill` first, and the signal only as a fallback: a supervisor that
    is asked to stop clears its control directory, while a supervisor that is
    signalled leaves the directory behind. `sandlock ps` filters those out, but
    a test that launches a few dozen sandboxes would leave a few dozen of them
    in /dev/shm.

    The process is then reaped either way, so a guest cannot outlive the test
    as an orphan.
    """
    subprocess.run([cli, "kill", name], capture_output=True, text=True)
    proc.terminate()
    try:
        _, err = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        proc.kill()
        _, err = proc.communicate(timeout=10)
    return (err or "").strip()


def _policy_from_cli(cli: str, argv: list[str], name: str) -> dict:
    proc = subprocess.Popen(
        [*argv, "--name", name, "--", SLEEP, "30"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        policy = _inspect(cli, name)
    except AssertionError as exc:
        reported = _stop(cli, name, proc)
        raise AssertionError(f"{exc}\nsandlock run said: {reported}") from exc
    _stop(cli, name, proc)
    return policy


def _flag_arg(knob: Knob, value: str) -> str:
    """`--knob=value`, as one argument.

    The attached form, not two arguments: a value that starts with `-` reads as
    another flag when it stands on its own, and getting turned away by the
    argument parser is not the grammar's verdict on it.
    """
    return f"{knob.flag}={value}"


def _sdk_sandbox(knob: Knob, value: str, **extra) -> sandlock.Sandbox:
    """A sandbox configured through the SDK's public field, and nothing else.

    The value is handed over as the string the corpus holds. Whatever the SDK
    does with it on the way to the setter is the thing under test, so this
    helper must not touch it.
    """
    return sandlock.Sandbox(**{knob.python: value}, **extra)


def _policy_from_sdk(cli: str, sb: sandlock.Sandbox, name: str) -> dict:
    """Launch an SDK-configured sandbox and read its effective policy back."""
    with sb:
        sb.spawn([SLEEP, "30"])
        try:
            return _inspect(cli, name)
        finally:
            # `sb.kill()`, never `sandlock kill <name>`: for a CLI-launched
            # sandbox the supervisor is the `sandlock run` process, but for an
            # SDK-launched one it is this interpreter, so asking the control
            # plane to stop the sandbox by name takes the test runner down with
            # it. This is the same signal the `setter` surface sends through
            # `sandlock_handle_kill`, which is `Sandbox::kill` underneath.
            try:
                sb.kill()
            except RuntimeError:
                pass
        # Leaving the block frees the handle.


def effective_policy(surface, cli, abi, knob: Knob, value: str, tmp_path: Path) -> dict:
    """Configure one knob through one surface and read the policy back."""
    if surface == FLAG:
        argv = [cli, "run", _flag_arg(knob, value)]
        for path in GRANTS:
            argv += ["--fs-read", path]
        return _policy_from_cli(cli, argv, _unique("parity-flag"))

    if surface == PROFILE:
        path = tmp_path / f"{knob.id}.toml"
        path.write_text(_profile_text(knob, value), encoding="utf-8")
        argv = [cli, "run", "--profile-file", str(path)]
        return _policy_from_cli(cli, argv, _unique("parity-profile"))

    if surface == PYSDK:
        name = _unique("parity-pysdk")
        sb = _sdk_sandbox(knob, value, fs_readable=GRANTS, name=name)
        return _policy_from_sdk(cli, sb, name)

    sandbox, err, msg = abi.build(knob, value, grants=True)
    assert err == 0 and sandbox, f"the setter refused {value!r}: {msg}"
    name = _unique("parity-setter")
    handle = abi.spawn(sandbox, name, [SLEEP, "30"])
    try:
        return _inspect(cli, name)
    finally:
        abi.stop(handle)
        abi.free_sandbox(sandbox)


def rejection(surface, cli, abi, knob: Knob, value: str, tmp_path: Path) -> str | None:
    """Offer one surface a value and return its refusal, or None if it took it.

    A rejected value stops each surface before anything is forked, so what
    comes back is the parse diagnosis. Anything that goes wrong later is a
    different report, which is what tells acceptance from refusal here.
    """
    if surface == SETTER:
        sandbox, err, msg = abi.build(knob, value, grants=False)
        if sandbox:
            abi.free_sandbox(sandbox)
            return None
        assert err == -1, f"a refused build must report -1, got {err}"
        return msg

    if surface == PYSDK:
        # No grants, so a value the SDK accepts produces a guest that cannot
        # exec and a `Result`, never an exception. The same shape as the two
        # command-line surfaces below, which also run the whole command and
        # tell a refusal from a failure by what came back.
        try:
            with _sdk_sandbox(knob, value) as sb:
                sb.run(["/bin/true"])
        except RuntimeError as exc:
            return str(exc)
        return None

    if surface == FLAG:
        argv = [cli, "run", _flag_arg(knob, value)]
    else:
        path = tmp_path / f"{knob.id}-reject.toml"
        path.write_text(_profile_text(knob, value, grants=False), encoding="utf-8")
        argv = [cli, "run", "--profile-file", str(path)]
    done = subprocess.run(
        [*argv, "--", "/bin/true"], capture_output=True, text=True
    )
    head = done.stderr.split("\n\nCaused by:")[0].strip()
    return head if head.startswith("Error: ") else None


# ============================================================
# Tests
# ============================================================


LIVE = [c for c in ACCEPTED if c.live]
NOT_LIVE = [c for c in ACCEPTED if not c.live]
SDK_ONLY = [c for c in REJECTED if c.sdk_only]
PLAIN_REJECTED = [c for c in REJECTED if not c.sdk_only]


@pytest.mark.parametrize("case", LIVE, ids=[c.id for c in LIVE])
def test_an_accepted_value_means_the_same_on_all_four_surfaces(cli, abi, tmp_path, case):
    """The same text has to produce the same live policy from any surface."""
    knob = KNOBS[case.knob]
    policies = {
        surface: effective_policy(surface, cli, abi, knob, case.value, tmp_path)
        for surface in SURFACES
    }

    section, key = knob.doc
    for surface, policy in policies.items():
        got = policy.get(section, {}).get(key)
        # Without this the four could agree by all dropping the value, which
        # is what a setter that ignored its argument would look like.
        assert got == case.renders, (
            f"{surface} resolved {case.value!r} to {got!r}, expected {case.renders!r}"
        )

    distinct = [policies[s] for s in SURFACES]
    assert all(p == distinct[0] for p in distinct), policies


@pytest.mark.parametrize("case", NOT_LIVE, ids=[c.id for c in NOT_LIVE])
def test_a_value_whose_guest_cannot_run_is_still_taken_by_all_four(
    cli, abi, tmp_path, case
):
    """Acceptance is the half of the claim a dead guest can still carry.

    The document comparison above needs a sandbox that stays up long enough to
    answer `sandlock inspect`, which a policy like a zero memory limit never
    does. What is left to compare is the verdict: no surface may refuse a value
    the others take. What the value resolves to is pinned by the canonical
    profile below, which needs no guest at all.
    """
    knob = KNOBS[case.knob]
    for surface in SURFACES:
        refusal = rejection(surface, cli, abi, knob, case.value, tmp_path)
        assert refusal is None, f"{surface} refused {case.value!r}: {refusal}"


@pytest.mark.parametrize("case", ACCEPTED, ids=[c.id for c in ACCEPTED])
def test_an_accepted_value_resolves_to_the_pinned_quantity(abi, case):
    """Pin what the grammar means, not only that the surfaces agree on it.

    The canonical profile document reports the resolution exactly: a count of
    bytes, or seconds and nanoseconds since the epoch. It is the only view that
    survives sub-second precision and a pre-epoch instant, both of which the
    effective policy document above rounds off or drops.
    """
    knob = KNOBS[case.knob]
    toml = _profile_text(knob, case.value, grants=False)
    document, err, msg = abi.profile_parse(toml)
    assert err == 0, f"the profile refused {case.value!r}: {msg}"
    section, key = knob.doc
    assert document[section][key] == case.resolved


@pytest.mark.parametrize(
    "case", PLAIN_REJECTED, ids=[c.id for c in PLAIN_REJECTED]
)
def test_a_rejected_value_is_refused_everywhere_with_one_diagnosis(
    cli, abi, tmp_path, case
):
    """One parser, so one verdict and one sentence to explain it."""
    _assert_one_diagnosis(cli, abi, tmp_path, case)


@pytest.mark.parametrize("case", SDK_ONLY, ids=[c.id for c in SDK_ONLY])
def test_a_value_only_an_sdk_parser_ever_accepted_is_refused_everywhere(
    cli, abi, tmp_path, case
):
    """The regression this change exists to close.

    Each of these reached a live policy through a binding while the identical
    text in a profile or on the command line was refused, because the binding
    parsed it itself. Now the string goes to the core, so all four surfaces
    give the same answer, and the answer is no. The sentence is pinned as well
    as shared, so a refusal for some unrelated reason (a null argument, a
    builder that latched something earlier) cannot stand in for the grammar's
    verdict.
    """
    _assert_one_diagnosis(cli, abi, tmp_path, case)


def _assert_one_diagnosis(cli, abi, tmp_path, case: Rejected) -> None:
    """Refuse `case` on all four surfaces and check they said the same thing."""
    knob = KNOBS[case.knob]
    raw = {
        surface: rejection(surface, cli, abi, knob, case.value, tmp_path)
        for surface in SURFACES
    }
    for surface, text in raw.items():
        assert text is not None, f"{surface} accepted {case.value!r}"
        assert text.startswith(ENVELOPE[surface]), (
            f"{surface} reported something other than the core's verdict: {text!r}"
        )

    diagnosis = {s: text[len(ENVELOPE[s]) :] for s, text in raw.items()}
    if knob.labels:
        # The knob name is the one part a surface supplies: the core is told
        # which knob carried the value so it can name it. Everything else in
        # the sentence has to match, so the name is checked and then removed.
        for surface, text in diagnosis.items():
            assert knob.labels[surface] in text, (
                f"{surface} must name its own knob in {text!r}"
            )
        diagnosis = {
            s: text.replace(knob.labels[s], "<knob>", 1)
            for s, text in diagnosis.items()
        }

    assert len(set(diagnosis.values())) == 1, diagnosis
    shared = diagnosis[SETTER]
    assert shared.startswith(case.diagnosis), (
        f"expected the grammar's verdict {case.diagnosis!r}, got {shared!r}"
    )


def test_an_epoch_number_is_the_resolved_instant_and_not_a_second_grammar(cli):
    """`time_start` takes text or a number, and they are not two spellings.

    `"1700000000"` is refused above on every surface, because a bare count of
    seconds is not an RFC 3339 stamp. The same quantity as a Python number is
    accepted, and this is why that is not the grammar creeping back in: the
    number is the *resolved* instant, the form `sandlock_profile_parse` reports
    and the form `sandlock_sandbox_builder_time_start_epoch` takes. Two doors
    into one instant, so they have to arrive at the same policy, which is what
    is compared here. The SDK reads neither of them.
    """
    stamp = "2023-11-14T22:13:20Z"
    seconds = 1700000000

    def policy(value) -> dict:
        name = _unique("parity-epoch")
        sb = sandlock.Sandbox(time_start=value, fs_readable=GRANTS, name=name)
        return _policy_from_sdk(cli, sb, name)

    from_text = policy(stamp)
    from_number = policy(seconds)
    assert from_text["determinism"]["time_start"] == stamp
    assert from_number["determinism"]["time_start"] == stamp

    # Which does not make the count a spelling of the stamp. Written as text it
    # is offered to the grammar, and the grammar has no reading for it.
    with pytest.raises(RuntimeError, match='invalid time_start "1700000000"'):
        with sandlock.Sandbox(time_start=str(seconds)) as sb:
            sb.run(["/bin/true"])
