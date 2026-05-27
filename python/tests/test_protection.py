# SPDX-License-Identifier: Apache-2.0
"""Python wrapper tests for Protection allow_degraded / disable kwargs.

Covers the Python parity for the C ABI added in sandlock-ffi (see
``crates/sandlock-ffi/include/sandlock.h`` — ``sandlock_protection_t``,
``sandlock_protection_min_abi``, ``sandlock_sandbox_builder_allow_degraded``,
``sandlock_sandbox_builder_disable``).
"""

import sandlock
from sandlock import Sandbox, Protection


def test_protection_intenum_min_abi_via_ffi():
    """`sandlock_protection_min_abi` returns the kernel ABI requirement
    for each protection — sanity-check the IntEnum discriminants match
    the C ABI by calling through the FFI."""
    from sandlock._sdk import _lib

    # SIGNAL_SCOPE — Landlock ABI v6
    assert _lib.sandlock_protection_min_abi(int(Protection.SIGNAL_SCOPE)) == 6
    # FS_TRUNCATE — Landlock ABI v3
    assert _lib.sandlock_protection_min_abi(int(Protection.FS_TRUNCATE)) == 3


def test_sandbox_allow_degraded_kwarg_default_empty():
    """Both kwargs default to an empty sequence when omitted."""
    sb = Sandbox(fs_readable=["/usr"])
    assert list(sb.allow_degraded) == []
    assert list(sb.disable) == []


def test_sandbox_allow_degraded_kwarg_accepts_protections():
    """`allow_degraded` accepts a sequence of Protection values and
    preserves the order/identity on the dataclass."""
    sb = Sandbox(
        fs_readable=["/usr"],
        allow_degraded=[
            Protection.SIGNAL_SCOPE,
            Protection.ABSTRACT_UNIX_SOCKET_SCOPE,
        ],
    )
    assert list(sb.allow_degraded) == [
        Protection.SIGNAL_SCOPE,
        Protection.ABSTRACT_UNIX_SOCKET_SCOPE,
    ]


def test_sandbox_disable_kwarg_accepts_protections():
    """`disable` accepts a sequence of Protection values and preserves
    them on the dataclass."""
    sb = Sandbox(fs_readable=["/usr"], disable=[Protection.SIGNAL_SCOPE])
    assert list(sb.disable) == [Protection.SIGNAL_SCOPE]


def test_protection_is_intenum_with_correct_values():
    """Protection discriminants mirror the C ABI ``sandlock_protection_t``
    layout exactly (stable across releases)."""
    assert Protection.FS_REFER == 0
    assert Protection.FS_TRUNCATE == 1
    assert Protection.NET_TCP == 2
    assert Protection.FS_IOCTL_DEV == 3
    assert Protection.SIGNAL_SCOPE == 4
    assert Protection.ABSTRACT_UNIX_SOCKET_SCOPE == 5
    # IntEnum: values usable as plain ints (the FFI takes c_int).
    assert int(Protection.SIGNAL_SCOPE) == 4
    assert isinstance(Protection.SIGNAL_SCOPE, int)


def test_protection_reexported_from_top_level_package():
    """`Protection` is re-exported by the top-level package so callers
    can do ``from sandlock import Protection`` without reaching into
    ``_sdk``."""
    assert sandlock.Protection is Protection
    assert "Protection" in sandlock.__all__


def test_sandbox_build_with_protection_kwargs_does_not_raise():
    """Building the native policy with non-empty Protection kwargs must
    succeed: this exercises the ctypes bindings end-to-end (the
    move-semantics `b = _b_allow_degraded(b, ...)` rebind in
    `_build_from_policy`)."""
    from sandlock._sdk import _NativePolicy

    sb = Sandbox(
        fs_readable=["/usr"],
        allow_degraded=[Protection.SIGNAL_SCOPE],
        disable=[Protection.ABSTRACT_UNIX_SOCKET_SCOPE],
    )
    # Should not raise — and the resulting native policy owns a live
    # pointer that is freed by __del__.
    native = _NativePolicy.from_dataclass(sb)
    assert native.ptr is not None and native.ptr != 0


def test_sandbox_build_with_idempotent_protection_kwargs():
    """Repeating the same Protection in `allow_degraded` (or across
    both kwargs) must not raise — the C-side `ProtectionPolicy::set`
    is last-wins, and the Python wrapper just forwards values."""
    from sandlock._sdk import _NativePolicy

    sb = Sandbox(
        fs_readable=["/usr"],
        allow_degraded=[Protection.SIGNAL_SCOPE, Protection.SIGNAL_SCOPE],
        disable=[Protection.SIGNAL_SCOPE],
    )
    native = _NativePolicy.from_dataclass(sb)
    assert native.ptr is not None and native.ptr != 0


# --------------------------------------------------------------
# Out-of-range protection int — the SDK must raise `ValueError`
# before reaching the FFI. The Rust setters tolerate unknown
# discriminants as a no-op, but the Python contract is loud failure
# (silent no-op is the wrong UX when the caller typed a wrong int).
# --------------------------------------------------------------


def test_sandbox_build_rejects_out_of_range_protection_int():
    """An integer outside the known `Protection` enum range raises
    `ValueError` at build time — before reaching the FFI."""
    import pytest

    from sandlock._sdk import _NativePolicy

    sb = Sandbox(fs_readable=["/usr"], allow_degraded=[99])
    with pytest.raises(ValueError, match="allow_degraded"):
        _NativePolicy.from_dataclass(sb)


def test_sandbox_build_rejects_out_of_range_in_disable():
    """Same guard applies to the `disable` kwarg."""
    import pytest

    from sandlock._sdk import _NativePolicy

    sb = Sandbox(fs_readable=["/usr"], disable=[100, 200])
    with pytest.raises(ValueError, match="disable"):
        _NativePolicy.from_dataclass(sb)


def test_sandbox_build_rejects_negative_protection_int():
    """Negative ints are not valid Protection discriminants — must
    raise rather than wrap to a large unsigned value at the FFI."""
    import pytest

    from sandlock._sdk import _NativePolicy

    sb = Sandbox(fs_readable=["/usr"], allow_degraded=[-1])
    with pytest.raises(ValueError):
        _NativePolicy.from_dataclass(sb)


def test_sandbox_build_accepts_plain_int_in_valid_range():
    """Callers using plain `int` (not the `Protection` IntEnum) for
    values in the valid range must still succeed — the validator
    coerces through `Protection(int)`."""
    from sandlock._sdk import _NativePolicy

    sb = Sandbox(fs_readable=["/usr"], allow_degraded=[4])  # 4 == SIGNAL_SCOPE
    native = _NativePolicy.from_dataclass(sb)
    assert native.ptr is not None and native.ptr != 0
