# SPDX-License-Identifier: Apache-2.0
"""Tests for sandlock.sandbox."""

from __future__ import annotations

import re

import pytest

import sandlock.sandbox as sandbox_module
from sandlock._sdk import _branch_action, _epoch_split, _fits
from sandlock.sandbox import (
    BranchAction,
    Mount,
    Sandbox,
    User,
    parse_ports,
)


class TestNoSecondGrammar:
    """The profile grammars live in the core parser, and only there.

    Every helper named here used to be a second implementation of a grammar
    the core already owns, and each one disagreed with it somewhere: sizes
    accepted ``'1.5G'``/``'1T'`` that the core rejects, and the timestamp
    helper read a naive stamp as UTC while the core requires an offset.
    """

    def test_size_grammar_is_gone(self):
        assert not hasattr(sandbox_module, "parse_memory_size")
        assert not hasattr(Sandbox, "memory_bytes")

    def test_timestamp_grammar_is_gone(self):
        assert not hasattr(Sandbox, "time_start_timestamp")

    @pytest.mark.parametrize("field", ["max_memory", "max_disk"])
    def test_a_size_string_is_carried_to_the_core_unchanged(self, field):
        """The field holds what the caller wrote, and the core resolves it.

        Not merely "the constructor accepts it": the value has to survive
        round-tripping through the dataclass, because an SDK that parsed it
        would store the resolved number here instead.
        """
        assert getattr(Sandbox(**{field: "512M"}), field) == "512M"
        Sandbox(**{field: "512M"})._ensure_native()

    @pytest.mark.parametrize("field", ["max_memory", "max_disk"])
    @pytest.mark.parametrize(
        "value,message",
        [
            # The two spellings the SDK parsers invented between them. Both
            # built a sandbox through this SDK while the same text in a
            # profile was refused.
            ("1.5G", "invalid byte size: 1.5G"),
            ("1T", "unknown byte size suffix: T"),
            ("", "empty byte size string"),
        ],
    )
    def test_a_size_the_core_refuses_reports_the_core_message(
        self, field, value, message
    ):
        with pytest.raises(RuntimeError, match=re.escape(message)):
            Sandbox(**{field: value})._ensure_native()

    def test_an_rfc3339_stamp_is_carried_to_the_core_unchanged(self):
        sb = Sandbox(time_start="2026-01-01T00:00:00Z")
        assert sb.time_start == "2026-01-01T00:00:00Z"
        sb._ensure_native()

    @pytest.mark.parametrize(
        "value",
        [
            # The grammar's own edges, none of which the epoch-seconds
            # parameter this setter used to take could carry.
            "2026-01-01T00:00:00.5Z",
            "2025-12-31T19:00:00-05:00",
            "1969-07-20T20:17:00Z",
        ],
    )
    def test_the_core_grammar_is_reachable_in_full(self, value):
        Sandbox(time_start=value)._ensure_native()

    @pytest.mark.parametrize(
        "value,message",
        [
            ("nope", 'invalid time_start "nope"'),
            # A bare epoch count is what the old ABI parameter took and what
            # the SDK parsers accepted. It is not the grammar.
            ("1700000000", 'invalid time_start "1700000000"'),
            ("2026-01-01T00:00:00", 'invalid time_start "2026-01-01T00:00:00"'),
        ],
    )
    def test_a_stamp_the_core_refuses_reports_the_core_message(self, value, message):
        with pytest.raises(RuntimeError, match=re.escape(message)):
            Sandbox(time_start=value)._ensure_native()

    def test_a_resolved_instant_reaches_the_core_without_being_re_rendered(self):
        """A number is the form a loaded profile carries, and it is accepted.

        Both doors have to stay open: the string one for what a caller writes,
        the numeric one for what ``sandlock_profile_parse`` hands back. A
        pre-epoch instant and a sub-second remainder are the two the old
        ``uint64`` parameter could not express at all.
        """
        for value in (1767225600, 1767225600.5, -14182980, -0.5, 0):
            Sandbox(time_start=value)._ensure_native()


class TestFsMountField:
    def test_mount_entries(self):
        p = Sandbox(fs_mount=[Mount("/work", "/host"), Mount("/ro", "/h", ro=True)])
        assert p.fs_mount[0].ro is False
        assert p.fs_mount[1].ro is True

    def test_mapping_is_refused(self):
        # The old representation was dict[virt, host], which had no channel
        # for the read-only flag at all.
        with pytest.raises(TypeError, match="not a mapping"):
            Sandbox(fs_mount={"/work": "/host"})

    def test_non_mount_entries_are_refused(self):
        with pytest.raises(TypeError, match="must be Mount"):
            Sandbox(fs_mount=[("/work", "/host")])


class TestEnsureNative:
    """``_ensure_native`` rebuilds on every call so that mutations to
    config fields between lifecycle invocations are not silently
    masked by a stale native cache."""

    def test_rebuilds_on_each_call(self):
        sb = Sandbox(fs_readable=["/usr"])
        first = sb._ensure_native()
        second = sb._ensure_native()
        # Two distinct native objects (rebuild, not cache hit).
        assert first is not second

    def test_picks_up_post_construction_mutation(self):
        sb = Sandbox(fs_readable=["/usr"])
        sb._ensure_native()                 # first build
        sb.fs_readable = ["/usr", "/etc"]   # user mutates after first run
        rebuilt = sb._ensure_native()       # second build sees mutation
        # The rebuilt native is a fresh object; the cached self._native
        # was replaced, not retained from the pre-mutation state.
        assert rebuilt is sb._native


class TestPolicy:
    def test_defaults(self):
        p = Sandbox()
        assert p.fs_writable == []
        assert p.fs_readable == []
        assert p.fs_denied == []
        assert p.extra_deny_syscalls == []
        assert p.extra_allow_syscalls == []
        assert p.net_allow_bind == []
        assert p.net_allow == []
        assert p.max_memory is None
        # Not 64: the cap's default is the core's to state, and repeating it
        # here is what let the two drift apart in the first place.
        assert p.max_processes is None
        assert p.max_cpu is None

    def test_mutable_config(self):
        # Sandbox is no longer frozen — it holds runtime state too.
        p = Sandbox(max_memory=512 * 1024 ** 2)
        p.max_memory = 1024 ** 3
        assert p.max_memory == 1024 ** 3

    def test_the_clamping_accessor_is_gone(self):
        """``cpu_pct()`` answered a question the core answers by refusing.

        It squeezed the percentage into 1..100, so ``max_cpu=0`` read back as
        1 and ``max_cpu=200`` as 100: two policies the core rejects outright,
        rewritten into two it accepts.
        """
        assert not hasattr(Sandbox, "cpu_pct")

    @pytest.mark.parametrize("value", [0, 101, 200])
    def test_a_percentage_outside_the_range_gets_the_core_verdict(self, value):
        with pytest.raises(RuntimeError, match=f"max_cpu must be 1-100, got {value}"):
            Sandbox(max_cpu=value)._ensure_native()


class TestZeroIsNotUnset:
    """``None`` and ``0`` are two different policies, and the core says so.

    Every field here is ``None`` when unset, so a zero the caller wrote is
    forwarded rather than filtered, and the core answers it by name. That is
    the half this SDK cannot get wrong quietly: a filter here would turn
    "refuse this cap" into "ignore this cap", which is what a
    ``max_processes != 64`` guard and a clamping ``cpu_pct()`` used to do.
    """

    @pytest.mark.parametrize(
        "field, message",
        [
            ("max_processes", "max_processes must be greater than 0"),
            ("num_cpus", "num_cpus must be greater than 0"),
            ("max_open_files", "max_open_files must be greater than 0"),
            ("max_cpu", "max_cpu must be 1-100, got 0"),
        ],
    )
    def test_a_zero_cap_gets_the_core_verdict(self, field, message):
        with pytest.raises(RuntimeError, match=re.escape(message)):
            Sandbox(**{field: 0})._ensure_native()

    @pytest.mark.parametrize("field", ["max_processes", "num_cpus", "max_open_files", "max_cpu"])
    def test_the_same_cap_unset_is_not_refused(self, field):
        # The other half of the pair: `None` must reach no setter at all, so
        # the core never sees the field and its own default stands.
        assert getattr(Sandbox(), field) is None
        Sandbox()._ensure_native()

    @pytest.mark.parametrize("value", [0, "0"])
    def test_a_zero_memory_ceiling_gets_the_core_verdict(self, value):
        # Zero is what the supervisor carries internally for "no ceiling",
        # but the memory handler is installed on the field being set at all,
        # so an explicit zero used to install a handler enforcing a ceiling
        # of zero: the guest was SIGKILLed on the loader's first anonymous
        # mmap, with no exit status and nothing naming the setting.
        with pytest.raises(RuntimeError, match="max_memory must be greater than 0"):
            Sandbox(max_memory=value)._ensure_native()

    def test_a_zero_disk_quota_is_left_alone(self):
        # max_disk is deliberately not the same knob: zero is its documented
        # spelling of "unlimited". An SDK that generalised the memory rule
        # would take a working policy away.
        Sandbox(max_disk=0)._ensure_native()

    def test_an_empty_core_set_gets_the_core_verdict(self):
        # An empty list asks for an affinity mask with no bits, which the
        # kernel refuses; the child setup used to skip the call for it, so
        # the pinning the caller asked for silently did not happen.
        with pytest.raises(RuntimeError, match="cpu_cores must name at least one core"):
            Sandbox(cpu_cores=[])._ensure_native()

    def test_an_empty_device_list_is_left_alone(self):
        # gpu_devices shares the shape and not the rule: an empty list there
        # is the spelling of "every GPU present".
        Sandbox(gpu_devices=[])._ensure_native()

    def test_a_zero_seed_is_a_seed(self):
        # random_seed has no reserved value, so zero is an ordinary seed and
        # must travel: `if policy.random_seed:` would have dropped it.
        Sandbox(random_seed=0)._ensure_native()


class TestOnlyAUidIsNotExpressible:
    """The half-set identity is gone from the type, not from a check.

    ``User`` carries both ids because the core's ``Option<RunAs>`` does: an
    unprivileged user namespace maps exactly one pair. There is no
    ``uid``-without-``gid`` value for this SDK to have an opinion about, so
    the "both or neither" check it used to make has nothing left to check.
    """

    def test_the_pair_cannot_be_split(self):
        with pytest.raises(TypeError):
            User(uid=1000)  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            User(gid=1000)  # type: ignore[call-arg]

    def test_the_sandbox_carries_one_identity_field(self):
        import dataclasses

        names = {f.name for f in dataclasses.fields(Sandbox)}
        assert "user" in names
        assert not names & {"uid", "gid"}, (
            "separate uid/gid fields put the half-set state back"
        )

    def test_a_zero_id_is_fake_root_and_not_unset(self):
        # uid 0 is a policy ("map me to fake root"), so it must not be
        # filtered the way a zero cap once was.
        assert Sandbox(user=User(uid=0, gid=0)).user == User(uid=0, gid=0)
        Sandbox(user=User(uid=0, gid=0))._ensure_native()


class TestDiskQuotaPolicy:
    def test_default_none(self):
        p = Sandbox()
        assert p.max_disk is None

    def test_byte_value(self):
        p = Sandbox(max_disk=1024 ** 3)
        assert p.max_disk == 1024 ** 3

    def test_mutable_config(self):
        # Sandbox is no longer frozen — it holds runtime state too.
        p = Sandbox(max_disk=512 * 1024 ** 2)
        p.max_disk = 1024 ** 3
        assert p.max_disk == 1024 ** 3


class TestParsePorts:
    def test_single_int(self):
        assert parse_ports([80]) == [80]

    def test_single_string(self):
        assert parse_ports(["443"]) == [443]

    def test_range(self):
        assert parse_ports(["8000-8003"]) == [8000, 8001, 8002, 8003]

    def test_mixed(self):
        assert parse_ports([80, "443", "8000-8002"]) == [80, 443, 8000, 8001, 8002]

    def test_comma_in_string(self):
        # A string element may hold a comma list / ranges.
        assert parse_ports(["8080,9090"]) == [8080, 9090]
        assert parse_ports(["8080,9000-9002", 443]) == [443, 8080, 9000, 9001, 9002]

    @pytest.mark.parametrize("spec", ["*", "80 - 90"])
    def test_it_is_not_the_bind_grammar_and_must_not_be_used_as_one(self, spec):
        """Both of these are accepted by the core and refused by this helper.

        ``*`` is the any-port wildcard and ``80 - 90`` is a range the core
        trims around. A caller who pre-expands a bind list through here loses
        the wildcard entirely and gets a Python-side ValueError for a spec the
        CLI takes. The pass-through path has to keep taking both, which is
        what makes the pre-expansion unnecessary in the first place.
        """
        with pytest.raises(ValueError):
            parse_ports([spec])
        Sandbox(fs_readable=["/usr"], net_allow_bind=[spec])._ensure_native()

    def test_comma_empty_part_rejected(self):
        with pytest.raises(ValueError):
            parse_ports(["8080,"])

    def test_dedup(self):
        assert parse_ports([80, "80", "79-81"]) == [79, 80, 81]

    def test_invalid_range(self):
        with pytest.raises(ValueError):
            parse_ports(["9000-8000"])

    def test_out_of_range(self):
        with pytest.raises(ValueError):
            parse_ports([70000])

    def test_bad_format(self):
        with pytest.raises(ValueError):
            parse_ports(["abc"])

    def test_empty(self):
        assert parse_ports([]) == []


class TestNetPolicy:
    def test_unrestricted_by_default(self):
        p = Sandbox()
        assert p.net_allow_bind == []
        assert p.net_allow == []


class TestEnvControl:
    def test_clean_env_default_off(self):
        p = Sandbox()
        assert p.clean_env is False

    def test_env_default_empty(self):
        p = Sandbox()
        assert p.env == {}

    def test_clean_env_on(self):
        p = Sandbox(clean_env=True)
        assert p.clean_env is True

    def test_env_set(self):
        p = Sandbox(env={"FOO": "bar", "BAZ": "qux"})
        assert p.env == {"FOO": "bar", "BAZ": "qux"}


class TestGpuDevices:
    def test_default_none(self):
        p = Sandbox()
        assert p.gpu_devices is None

    def test_specific_devices(self):
        p = Sandbox(gpu_devices=[0, 2])
        assert p.gpu_devices == [0, 2]

    def test_all_gpus(self):
        p = Sandbox(gpu_devices=[])
        assert p.gpu_devices == []


class TestCpuCores:
    def test_default_none(self):
        p = Sandbox()
        assert p.cpu_cores is None

    def test_specific_cores(self):
        p = Sandbox(cpu_cores=[0, 2, 3])
        assert p.cpu_cores == [0, 2, 3]


class TestNetAllow:
    """Endpoint allowlist semantics for `net_allow`.

    Each entry is a string spec parsed by the native build:
    `host:port[,port,...]`, `:port`, or `*:port`. Empty list = deny all.
    """

    def test_default_is_empty(self):
        p = Sandbox()
        assert p.net_allow == []

    def test_specs_preserved_as_strings(self):
        p = Sandbox(net_allow=["api.example.com:443", "github.com:22,443", ":8080"])
        assert list(p.net_allow) == [
            "api.example.com:443",
            "github.com:22,443",
            ":8080",
        ]


class TestNetDeny:
    """Endpoint denylist semantics for `net_deny` (default-allow, inverse of
    `net_allow`, mutually exclusive with it). Targets are literal IP/CIDR."""

    def test_default_is_empty(self):
        assert Sandbox().net_deny == []

    def test_specs_preserved_as_strings(self):
        p = Sandbox(net_deny=["10.0.0.0/8", "169.254.169.254:80", "udp://*"])
        assert list(p.net_deny) == ["10.0.0.0/8", "169.254.169.254:80", "udp://*"]



class TestBuilderBoundary:
    """Values the C ABI setters cannot carry are refused, not truncated.

    The setters take fixed-width integers and ctypes converts by masking, so
    a value that does not fit arrives as a different, perfectly plausible one:
    ``max_cpu=300`` becomes 44, a throttle the core has no reason to question.
    Refusing here is what keeps the core's verdict reachable, which is why
    these are the one class of check this SDK still makes for itself.
    """

    @pytest.mark.parametrize(
        "field,value,setter",
        [
            ("max_cpu", 300, "uint8"),
            ("max_cpu", -1, "uint8"),
            ("http_ports", [70000], "uint16"),
            ("http_ports", [-1], "uint16"),
            ("num_cpus", 2 ** 32, "uint32"),
            ("max_open_files", -1, "uint32"),
            ("random_seed", 2 ** 64, "uint64"),
        ],
    )
    def test_a_value_the_setter_cannot_carry_is_refused_not_masked(
        self, field, value, setter
    ):
        with pytest.raises(ValueError, match=f"{setter} parameter"):
            Sandbox(**{field: value})._ensure_native()

    def test_a_wrapped_uid_is_refused(self):
        """``User(-1, -1)`` used to arrive as uid 4294967295."""
        with pytest.raises(ValueError, match="uint32 parameter"):
            Sandbox(user=User(-1, 0))._ensure_native()

    def test_a_bool_is_not_an_integer_here(self):
        # bool is an int subclass, so True would otherwise pass as 1.
        with pytest.raises(TypeError, match="must be an integer"):
            _fits(True, "num_cpus", bits=32)

    @pytest.mark.parametrize(
        "value,expected",
        [
            (0, (0, 0)),
            (1767225600, (1767225600, 0)),
            (1767225600.5, (1767225600, 500_000_000)),
            # Floors rather than truncating towards zero, the way the
            # canonical profile form splits: the remainder is never negative.
            (-0.5, (-1, 500_000_000)),
            (-14182980, (-14182980, 0)),
        ],
    )
    def test_epoch_seconds_split_the_way_the_canonical_form_splits(
        self, value, expected
    ):
        assert _epoch_split(value) == expected

    def test_a_remainder_that_rounds_up_to_a_whole_second_carries(self):
        # Without the carry this would emit nanoseconds == 1e9, which the core
        # refuses as unnormalized.
        assert _epoch_split(0.9999999999) == (1, 0)

    def test_time_start_must_be_a_stamp_or_a_number(self):
        with pytest.raises(TypeError, match="RFC 3339 string or epoch seconds"):
            Sandbox(time_start=object())._ensure_native()

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_cpu": 300},                # _fits
            {"on_exit": "keepp"},            # _branch_action
            {"time_start": object()},        # _b_time_start_from
        ],
    )
    def test_a_refused_policy_does_not_leak_its_builder(self, monkeypatch, kwargs):
        """Refusing a value must not abandon the native builder.

        Every setter consumes the pointer it is given and hands back a new
        one, and `sandlock_sandbox_build` is the only entry point in the C ABI
        that consumes a builder without producing another. So a raise between
        `sandlock_sandbox_builder_new` and the build strands one, with all the
        paths, env and rule strings already loaded into it. A long-lived
        process that validates policies it did not write leaks one per
        rejection.

        Counted rather than measured: the two calls have to balance, which is
        exact, where a resident-set reading is a threshold.
        """
        from sandlock import _sdk

        counts = {"new": 0, "build": 0}
        real_new = _sdk._lib.sandlock_sandbox_builder_new
        real_build = _sdk._lib.sandlock_sandbox_build

        def counting_new(*a):
            counts["new"] += 1
            return real_new(*a)

        def counting_build(*a):
            counts["build"] += 1
            return real_build(*a)

        monkeypatch.setattr(_sdk._lib, "sandlock_sandbox_builder_new", counting_new)
        monkeypatch.setattr(_sdk._lib, "sandlock_sandbox_build", counting_build)

        # A policy big enough that the leak would be worth noticing, and whose
        # setters have all run by the time the bad value is reached.
        policy = Sandbox(
            fs_readable=["/usr", "/lib", "/etc"],
            env={"A": "B", "C": "D"},
            **kwargs,
        )
        with pytest.raises((ValueError, TypeError, RuntimeError)):
            policy._ensure_native()

        assert counts["new"] == 1, "the test did not reach the builder"
        assert counts["build"] == counts["new"], (
            "the builder was allocated and never consumed"
        )


class TestBranchAction:
    """An action the SDK does not know is the core's to refuse, by value."""

    def test_the_discriminants_are_the_abi_ones(self):
        assert [a.abi for a in BranchAction] == [0, 1, 2]
        assert _branch_action(BranchAction.KEEP, "on_exit") == 2

    @pytest.mark.parametrize("field,default_it_used_to_take", [("on_exit", 0), ("on_error", 1)])
    def test_an_unknown_action_is_not_quietly_replaced_by_a_default(
        self, field, default_it_used_to_take
    ):
        """``.get(value, 0)`` turned a typo into a decision about the writes.

        ``on_exit`` fell back to Commit and ``on_error`` to Abort, so a
        misspelled action silently merged or discarded a COW branch. The
        number now goes through and the core names it.
        """
        with pytest.raises(RuntimeError, match=f"{field}: unrecognized branch action 7"):
            Sandbox(**{field: 7})._ensure_native()
        assert default_it_used_to_take in (0, 1)

    def test_neither_default_is_written_down_on_this_side(self):
        """The SDK's own ``on_error`` default disagreed with the core's.

        ``BranchAction.ABORT`` here against Commit there, for the same field,
        so a policy that said nothing about the error path discarded the
        guest's writes through this SDK and kept them through the CLI, a
        profile and the Go SDK. Unset now means unset, and the setter is not
        called at all. What the core then does with it is compared against a
        profile, on a live sandbox, in ``test_cli_parity.py``.
        """
        assert Sandbox().on_exit is None
        assert Sandbox().on_error is None

    def test_the_three_spellings_still_work(self):
        for action in BranchAction:
            assert _branch_action(action.value, "on_exit") == action.abi

    @pytest.mark.parametrize("field", ["on_exit", "on_error"])
    def test_the_reference_table_agrees_with_the_dataclass(self, field):
        """docs/sandbox-reference.md is the table a reader consults.

        Its ``on_error`` row was rewritten when the default moved into the
        core; the ``on_exit`` row directly above it was not, so the same
        document said ``None`` in its synopsis and ``BranchAction.COMMIT`` in
        its table for the same field.
        """
        import dataclasses
        import pathlib

        doc = pathlib.Path(__file__).resolve().parents[2] / "docs" / "sandbox-reference.md"
        rows = [
            line for line in doc.read_text().splitlines()
            if line.startswith(f"| `{field}`")
        ]
        assert len(rows) == 1, f"expected one {field} row, got {rows}"
        # `\|` inside a cell is an escaped pipe, not a column separator.
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", rows[0].strip("|"))]
        declared_type, declared_default = cells[2], cells[3]

        spec = {f.name: f for f in dataclasses.fields(Sandbox)}[field]
        assert spec.default is None, "the dataclass default moved; update the table"
        assert declared_default == "`None`", (
            f"{field} is documented as defaulting to {declared_default}, "
            f"but the dataclass leaves it unset"
        )
        assert "None" in declared_type, (
            f"{field} is documented as {declared_type}, which cannot be unset"
        )

    def test_a_word_the_abi_cannot_carry_is_refused_here(self):
        # The setter's parameter is a uint8; there is no way to put a string
        # into it, so this one cannot be deferred to the core. What must not
        # happen is the old behaviour: 'keepp' silently meaning Commit.
        with pytest.raises(ValueError, match="is not a branch action"):
            Sandbox(on_exit="keepp")._ensure_native()
