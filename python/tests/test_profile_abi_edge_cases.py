# SPDX-License-Identifier: Apache-2.0
"""Hostile input and raw-ABI edge cases for profile parsing.

``test_profile.py`` covers what a profile means. This covers what happens when
it is malformed, or when the export is called the way a hand-written binding
might call it rather than the way :mod:`sandlock._sdk` does. Two things are at
stake once TOML parsing moves behind a C ABI: a caller must never be told
"failed" with nothing else, and no value may be quietly shortened on the way
across, because a shortened host or path is a policy nobody wrote.
"""

from __future__ import annotations

import ctypes

import pytest

from sandlock._profile import policy_from_toml
from sandlock._sdk import _NativePolicy, _lib, profile_parse
from sandlock.exceptions import PolicyError


VALID = b'[limits]\nmemory = "1G"\n'
INVALID = b"[limits]\nbogus = 1\n"
# A pointer no allocator will return, so "was this written at all?" is
# answerable rather than being confused with "was written null".
POISON = ctypes.c_char_p(b"poison-sentinel")


def _strings(node):
    """Every string anywhere in a canonical document, keys included."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _raw_call(toml, pass_err=True, pass_err_msg=True):
    """Call the export directly, bypassing the SDK's own argument handling."""
    err = ctypes.c_int(7)
    err_msg = ctypes.c_char_p(POISON.value)
    ptr = _lib.sandlock_profile_parse(
        toml,
        ctypes.byref(err) if pass_err else None,
        ctypes.byref(err_msg) if pass_err_msg else None,
    )
    result = ctypes.string_at(ptr) if ptr else None
    if ptr:
        _lib.sandlock_string_free(ctypes.cast(ptr, ctypes.c_char_p))
    msg = err_msg.value
    if pass_err_msg and msg is not None and msg != POISON.value:
        _lib.sandlock_string_free(err_msg)
    return result, err.value, msg


class TestRawAbi:
    """Called straight through ctypes, with the out-parameters varied."""

    @pytest.mark.parametrize("pass_err", [True, False])
    @pytest.mark.parametrize("pass_err_msg", [True, False])
    @pytest.mark.parametrize(
        "toml,want_json,want_msg",
        [
            # A null profile is a bug in the calling binding, not a bad
            # profile, so it reports the failure without a diagnosis to
            # attribute to the user's file.
            (None, False, False),
            (VALID, True, False),
            (INVALID, False, True),
        ],
        ids=["null", "valid", "invalid"],
    )
    def test_every_out_param_combination(
        self, toml, want_json, want_msg, pass_err, pass_err_msg
    ):
        result, err, msg = _raw_call(toml, pass_err, pass_err_msg)

        assert (result is not None) is want_json
        if pass_err:
            assert err == (0 if want_json else -1)
        else:
            assert err == 7, "err was written through a null pointer"

        if pass_err_msg:
            assert msg != POISON.value, "err_msg was never written"
            assert (msg is not None) is want_msg
        else:
            assert msg == POISON.value, "err_msg was written through a null pointer"

    def test_a_null_return_always_means_failure(self):
        # The documented contract, and the only one a caller that passed null
        # for both out-parameters can rely on.
        assert _raw_call(VALID, False, False)[0] is not None
        assert _raw_call(INVALID, False, False)[0] is None

    def test_invalid_utf8_is_reported_not_read_as_a_shorter_profile(self):
        # A lossy decode would silently drop the offending byte and hand back
        # a profile the file does not contain.
        result, err, msg = _raw_call(b'[program]\nexec = "/bin/\xff"\n')
        assert result is None
        assert err == -1
        assert b"utf-8" in msg

    def test_string_free_accepts_null(self):
        _lib.sandlock_string_free(None)


class TestNulBytes:
    """The one byte a C string cannot carry, on both the value and the
    diagnosis path."""

    def test_a_nul_in_the_profile_text_is_refused_before_the_call(self):
        # Passing it on would truncate the file at the NUL and validate a
        # prefix, reporting a policy the user never wrote as valid.
        with pytest.raises(PolicyError, match="NUL"):
            profile_parse('[limits]\nmemory = "1G"\n\x00[filesystem]\nread = ["/"]\n')

    @pytest.mark.parametrize(
        "toml,fragment",
        [
            # TOML decodes ``\u0000``, so the parser can end up quoting a NUL
            # back at the user inside its own error message. Reporting the
            # failure with no message at all leaves an SDK user with a bare
            # exception and nothing to search for.
            ('[limits]\nmemory = "1\\u0000G"\n', "1\\0G"),
            ('[syscalls]\nextra_deny = ["re\\u0000ad"]\n', "re\\0ad"),
            ('[limits]\n"bo\\u0000gus" = 1\n', "bo\\0gus"),
        ],
    )
    def test_a_nul_in_the_diagnosis_still_reaches_the_caller(self, toml, fragment):
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml(toml)
        assert fragment in str(excinfo.value)

    @pytest.mark.parametrize(
        "toml,shortened",
        [
            # Each of these is a value the CLI would use whole. If the SDK
            # forwarded it as a C string it would apply the part before the
            # NUL: a different host, a different path, a different mount.
            ('[network]\nallow = ["tcp://ex\\u0000ample.com"]\n', "tcp://ex"),
            ('[filesystem]\nchroot = "/real\\u0000/decoy"\n', "/real"),
            ('[filesystem]\nmount = ["/v:/host\\u0000/decoy"]\n', "/host"),
            ('[http]\nallow = ["GET ex\\u0000ample.com"]\n', "GET ex"),
            # Percent-decoding gets a NUL into an HTTP path with no TOML
            # escape involved.
            ('[http]\nallow = ["GET example.com/a%00b"]\n', "GET example.com/a"),
        ],
    )
    def test_a_nul_inside_a_value_fails_loudly_rather_than_shortening_it(
        self, toml, shortened
    ):
        # It survives the canonical form intact, because JSON escapes it, and
        # what follows the NUL is exactly what a silent truncation would drop.
        carriers = [s for s in _strings(profile_parse(toml)) if "\x00" in s]
        assert carriers, "the NUL did not survive into the canonical form"
        assert any(
            s.startswith(shortened) and len(s) > len(shortened) for s in carriers
        ), f"expected a value longer than {shortened!r} in {carriers!r}"

        policy = policy_from_toml(toml)
        # It is refused at the boundary that cannot represent it, and the
        # refusal quotes the value so the user can find it.
        with pytest.raises(ValueError, match="NUL"):
            _NativePolicy.from_dataclass(policy)


class TestMalformedProfiles:
    """Structure and type errors, reported with core's wording."""

    def test_an_empty_profile_is_an_unconstrained_sandbox_not_an_error(self):
        policy = policy_from_toml("")
        assert policy.max_memory is None
        assert policy.fs_readable == []
        assert policy_from_toml("# only a comment\n") == policy
        assert policy_from_toml("   \n\t\n") == policy

    @pytest.mark.parametrize(
        "toml,fragment",
        [
            ("[bogus]\nx = 1\n", "unknown field `bogus`"),
            ('memory = "1G"\n', "unknown field `memory`"),
            ("[limits]\nbogus = 1\n", "unknown field `bogus`"),
            ('[limits]\nmemory = "1G"\nmemory = "2G"\n', "duplicate key `memory`"),
            ('[limits]\nmemory = "1G"\n[limits]\ncpu = 1\n', "duplicate key"),
            ('[program.env]\nA = "1"\nA = "2"\n', "duplicate key `A`"),
            ("[program\n", "TOML parse error"),
        ],
    )
    def test_structure_errors(self, toml, fragment):
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml(toml)
        assert fragment in str(excinfo.value)

    @pytest.mark.parametrize(
        "toml,fragment",
        [
            # Wrong type in both directions. A parser that coerced would make
            # these load here and fail in the CLI.
            ('[limits]\ncpu = "1"\n', "expected u8"),
            ("[limits]\nmemory = 1024\n", "expected a string"),
            ("[determinism]\ntime_start = 1700000000\n", "expected a string"),
            ('[determinism]\nrandom_seed = "5"\n', "expected u64"),
            ('[program]\nclean_env = "true"\n', "expected a boolean"),
            ('[filesystem]\nread = "/a"\n', "invalid type: string"),
            ("[program]\nargs = [1, 2]\n", "invalid type: integer"),
        ],
    )
    def test_type_errors(self, toml, fragment):
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml(toml)
        assert fragment in str(excinfo.value)

    @pytest.mark.parametrize(
        "toml,fragment",
        [
            ('[filesystem]\nmount = [""]\n', 'invalid mount spec ""'),
            ('[limits]\nmemory = ""\n', "empty byte size string"),
            ('[determinism]\ntime_start = ""\n', "[determinism].time_start"),
            ('[filesystem]\non_exit = ""\n', "invalid branch action"),
            ('[network]\nallow = [""]\n', "--net-allow: empty rule"),
            ('[network]\nallow_bind = [""]\n', "--net-allow-bind: empty port"),
            ('[http]\nallow = [""]\n', "invalid http rule"),
            ('[syscalls]\nextra_allow = [""]\n', "unknown syscall group name"),
        ],
    )
    def test_an_empty_value_names_the_grammar_that_rejected_it(self, toml, fragment):
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml(toml)
        assert fragment in str(excinfo.value)

    @pytest.mark.parametrize(
        "toml,fragment",
        [
            # Sizes and ports are the fields with a signed spelling and an
            # unsigned destination, so they are where a silent wrap would live.
            ('[limits]\nmemory = "-1"\n', "invalid byte size: -1"),
            ('[limits]\nmemory = "18446744073709551616"\n', "invalid byte size"),
            ('[limits]\nmemory = "17179869184G"\n', "byte size out of range"),
            ("[limits]\nprocesses = -1\n", "invalid value"),
            ("[limits]\nprocesses = 4294967296\n", "invalid value"),
            ("[program]\nuid = -1\n", "invalid value"),
            ("[http]\nports = [65536]\n", "invalid value"),
            ('[network]\nallow_bind = ["65536"]\n', "invalid port `65536`"),
            ('[network]\nallow_bind = ["-1"]\n', "invalid port range `-1`"),
            ('[network]\nallow = ["tcp://example.com:65536"]\n', "invalid port `65536`"),
        ],
    )
    def test_a_number_outside_its_range_is_rejected(self, toml, fragment):
        with pytest.raises(PolicyError) as excinfo:
            policy_from_toml(toml)
        assert fragment in str(excinfo.value)

    def test_the_largest_legal_values_still_load(self):
        # The range checks above would also be satisfied by a parser that
        # rejected everything.
        assert policy_from_toml('[limits]\nmemory = "18446744073709551615"\n').max_memory == 2 ** 64 - 1
        assert policy_from_toml('[limits]\nmemory = "0"\n').max_memory == 0
        assert policy_from_toml("[limits]\ncpu = 100\n").max_cpu == 100
        assert policy_from_toml('[network]\nallow_bind = ["0-65535"]\n').net_allow_bind[-1] == 65535

    def test_a_very_long_value_is_not_clipped(self):
        path = "/" + "a" * 200_000
        policy = policy_from_toml(f'[filesystem]\nread = ["{path}"]\n')
        assert policy.fs_readable == [path]


def _rss_kb() -> int:
    with open("/proc/self/status") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise RuntimeError("VmRSS not reported")


def test_the_returned_strings_are_actually_released():
    """Both the JSON and the message are the caller's to free, so a caller that
    frees them must not grow.

    Sized so the answer is not a judgement call: each iteration hands back
    about 28 KB, and skipping the free calls grows this process by tens of
    megabytes over the same loop, which is an order of magnitude above the
    threshold below and two above what a correct run uses. The exact figures
    are host and allocator dependent; the separation is not.
    """
    # ~2048 expanded ports per call, so the result is large enough to see.
    big = '[network]\nallow_bind = ["0-2047"]\n'
    bad = '[limits]\nmemory = "1.5G"\n'

    for _ in range(20):  # let the allocator reach a steady state first
        profile_parse(big)
    before = _rss_kb()
    for _ in range(800):
        profile_parse(big)
        with pytest.raises(PolicyError):
            profile_parse(bad)
    growth = _rss_kb() - before

    assert growth < 4096, f"grew {growth} kB over 800 parses; expected roughly none"
