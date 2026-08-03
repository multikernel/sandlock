# SPDX-License-Identifier: Apache-2.0
"""TOML profile loading for Sandlock.

The profile text is handed to the core parser (``sandlock_profile_parse``),
which returns the profile in canonical form: every string micro-grammar is
already resolved (mounts are ``{virt, host, ro}`` objects, byte sizes are
integer bytes, ``time_start`` is epoch time, port specs are expanded integer
lists, net and HTTP rules are structured records with a rendered spec). This
module only maps those fields onto :class:`~sandlock.Sandbox`, so a profile
means exactly what it means to the CLI, down to the error message.

Section to field mapping::

    [config]      -> http_ca, http_key, http_inject_ca, http_ca_out,
                     fs_storage, workdir
    [determinism] -> random_seed, time_start, deterministic_dirs,
                     no_randomize_memory
    [program]     -> env, cwd, user (uid + gid), clean_env, no_coredump,
                     no_huge_pages (``exec`` and ``args`` are runtime program
                     identity and are ignored here; pass them to
                     ``sandbox.run(cmd)`` instead)
    [filesystem]  -> fs_readable (read), fs_writable (write), fs_denied
                     (deny), chroot, fs_mount (mount), on_exit, on_error
    [network]     -> net_allow_bind (allow_bind), net_deny_bind (deny_bind),
                     net_allow (allow), net_deny (deny), port_remap
    [http]        -> http_ports (ports), http_allow (allow), http_deny (deny)
    [syscalls]    -> extra_allow_syscalls (extra_allow),
                     extra_deny_syscalls (extra_deny)
    [limits]      -> max_memory (memory), max_disk (disk), max_processes
                     (processes), max_open_files (open_files), max_cpu (cpu),
                     gpu_devices, cpu_cores, num_cpus
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ._sdk import profile_parse
from .exceptions import PolicyError
from .sandbox import BranchAction, Mount, Sandbox, User


_PROFILES_DIR = Path("~/.config/sandlock/profiles").expanduser()


# Canonical-form key -> Sandbox attribute, per section. ``None`` marks a key
# the field-for-field loop does not carry: program identity, which is not
# policy, and the two ids that are joined into ``user`` afterwards.
#
# The key sets are exhaustive on purpose: the core emits every canonical field
# unconditionally, so a key that appears, disappears or is renamed on the other
# side is a schema break. Checking the whole set turns that into a load-time
# error here instead of a field that silently stops being applied.
_SECTIONS: dict[str, dict[str, str | None]] = {
    "config": {
        "http_ca": "http_ca",
        "http_key": "http_key",
        "http_inject_ca": "http_inject_ca",
        "http_ca_out": "http_ca_out",
        "fs_storage": "fs_storage",
        "workdir": "workdir",
    },
    "determinism": {
        "random_seed": "random_seed",
        "time_start": "time_start",
        "deterministic_dirs": "deterministic_dirs",
        "no_randomize_memory": "no_randomize_memory",
    },
    "program": {
        "exec": None,
        "args": None,
        "env": "env",
        "cwd": "cwd",
        # Two canonical keys, one Sandbox field: joined by `_user` below.
        "uid": None,
        "gid": None,
        "clean_env": "clean_env",
        "no_coredump": "no_coredump",
        "no_huge_pages": "no_huge_pages",
    },
    "filesystem": {
        "read": "fs_readable",
        "write": "fs_writable",
        "deny": "fs_denied",
        "chroot": "chroot",
        "mount": "fs_mount",
        "on_exit": "on_exit",
        "on_error": "on_error",
    },
    "network": {
        "allow_bind": "net_allow_bind",
        "deny_bind": "net_deny_bind",
        "allow": "net_allow",
        "deny": "net_deny",
        "port_remap": "port_remap",
    },
    "http": {
        "ports": "http_ports",
        "allow": "http_allow",
        "deny": "http_deny",
    },
    "syscalls": {
        "extra_allow": "extra_allow_syscalls",
        "extra_deny": "extra_deny_syscalls",
    },
    "limits": {
        "memory": "max_memory",
        "disk": "max_disk",
        "processes": "max_processes",
        "open_files": "max_open_files",
        "cpu": "max_cpu",
        "gpu_devices": "gpu_devices",
        "cpu_cores": "cpu_cores",
        "num_cpus": "num_cpus",
    },
}


def profiles_dir() -> Path:
    """Return the profiles directory path."""
    return _PROFILES_DIR


def list_profiles() -> list[str]:
    """Return sorted names of available profiles."""
    if not _PROFILES_DIR.is_dir():
        return []
    return sorted(
        p.stem for p in _PROFILES_DIR.glob("*.toml") if p.is_file()
    )


def load_profile(name: str) -> Sandbox:
    """Load a named profile and return a Sandbox.

    Raises:
        PolicyError: If the profile doesn't exist or the core parser rejects it.
    """
    path = _PROFILES_DIR / f"{name}.toml"
    if not path.is_file():
        raise PolicyError(f"profile not found: {path}")
    return load_profile_path(path)


def load_profile_path(path: Path) -> Sandbox:
    """Load a profile from a file path and return a Sandbox.

    Raises:
        PolicyError: If the file can't be read or the core parser rejects it.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise PolicyError(f"{path}: {e}") from e
    except UnicodeDecodeError as e:
        raise PolicyError(f"{path}: profile is not valid UTF-8: {e}") from e

    try:
        return policy_from_toml(text)
    except PolicyError as e:
        # The diagnosis stays the core parser's; only the file it came from
        # is added, since the caller passed a path and not the text.
        raise PolicyError(f"{path}: {e}") from e


def policy_from_toml(text: str) -> Sandbox:
    """Construct a Sandbox from profile TOML text.

    Raises:
        PolicyError: With the core parser's message, verbatim.
    """
    return _from_canonical(profile_parse(text))


def _from_canonical(canonical: dict) -> Sandbox:
    """Map the canonical profile form onto a Sandbox."""
    _check_keys(canonical, _SECTIONS, "profile")

    kwargs: dict[str, Any] = {}
    for section, fields in _SECTIONS.items():
        data = canonical[section]
        _check_keys(data, fields, f"[{section}]")
        for key, attr in fields.items():
            if attr is None:
                continue
            value = _convert(attr, data[key])
            # A null leaf means "not set in the profile"; leaving it out keeps
            # the Sandbox default, which is not always None (max_processes).
            if value is not None:
                kwargs[attr] = value

    user = _user(canonical["program"])
    if user is not None:
        kwargs["user"] = user

    return Sandbox(**kwargs)


def _user(program: dict) -> User | None:
    """Join the canonical ``uid``/``gid`` pair into one :class:`User`.

    The core refuses a profile that sets one without the other, and the
    canonical form is produced by that same builder, so a half-set pair here
    means the two sides disagree about the contract rather than that the
    profile was wrong. That is reported as such, the way a missing key is.
    """
    uid, gid = program["uid"], program["gid"]
    if uid is None and gid is None:
        return None
    if uid is None or gid is None:
        raise PolicyError(
            "[program]: canonical profile carries uid without gid or the "
            f"other way round (uid={uid!r}, gid={gid!r}); core and SDK are "
            "out of sync"
        )
    return User(uid=uid, gid=gid)


def _check_keys(data: Any, expected: Iterable[str], where: str) -> None:
    """Fail loudly when the canonical form is not the shape expected here."""
    if not isinstance(data, dict):
        raise PolicyError(
            f"{where}: expected an object in the canonical profile, "
            f"got {type(data).__name__}"
        )
    missing = sorted(set(expected) - set(data))
    unknown = sorted(set(data) - set(expected))
    if missing or unknown:
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if unknown:
            detail.append(f"unknown {', '.join(unknown)}")
        raise PolicyError(
            f"{where}: canonical profile does not match this SDK "
            f"({'; '.join(detail)}); core and SDK are out of sync"
        )


def _convert(attr: str, value: Any) -> Any:
    """Turn one canonical leaf into its Sandbox representation."""
    if value is None:
        return None
    if attr == "fs_mount":
        return [_mount(entry) for entry in value]
    if attr in ("on_exit", "on_error"):
        return BranchAction(value)
    if attr == "time_start":
        return _timestamp(value)
    if attr in ("net_allow_bind", "net_deny_bind"):
        return _bind_ports(value)
    if attr in ("net_allow", "net_deny", "http_allow", "http_deny"):
        # Rules are structured, but every builder entry point takes a spec
        # string, so the core-rendered `spec` is what gets forwarded. A
        # scheme-less profile entry has already been split into one rule per
        # protocol at this point.
        return [_rule_spec(rule, attr) for rule in value]
    return value


def _rule_spec(rule: Any, attr: str) -> str:
    if not isinstance(rule, dict) or "spec" not in rule:
        raise PolicyError(
            f"{attr}: canonical rule carries no 'spec' string; core and SDK "
            f"are out of sync (got {rule!r})"
        )
    return rule["spec"]


def _mount(entry: Any) -> Mount:
    _check_keys(entry, ("virt", "host", "ro"), "mount entry")
    return Mount(virt=entry["virt"], host=entry["host"], ro=entry["ro"])


def _bind_ports(value: Any) -> list:
    _check_keys(value, ("any", "ports"), "bind ports")
    return ["*"] if value["any"] else list(value["ports"])


def _timestamp(value: Any) -> str | int:
    """Take the rendered stamp, not the pair, whenever there is a remainder.

    ``seconds + nanos / 1e9`` is a double, and a double has about 238ns of
    spacing at 2026 epoch values, so it cannot hold the pair the core just
    resolved. ``"...T00:00:00.9999999Z"`` rounded up to the next whole second
    through here, and the core floors ``time_start`` to whole seconds, so the
    same profile ran one second later through this SDK than through the CLI:
    the drift the canonical form exists to remove, re-created one line after
    it arrives. The core renders the instant for us for exactly this reason,
    the way it renders net and HTTP rules back into spec strings.

    A whole second still comes back as an ``int``: it is exact, and it keeps
    the numeric door (``sandlock_sandbox_builder_time_start_epoch``) exercised
    by the common case.
    """
    _check_keys(value, ("seconds", "nanoseconds", "rfc3339"), "time_start")
    if value["nanoseconds"] == 0:
        return value["seconds"]
    return value["rfc3339"]


def merge_cli_overrides(policy: Sandbox, overrides: dict) -> Sandbox:
    """Return a new Sandbox with CLI overrides applied on top of a profile.

    List fields from the CLI are appended to profile values.
    Scalar fields from the CLI replace profile values.
    """
    import dataclasses

    merged: dict[str, Any] = {}
    for key, value in overrides.items():
        current = getattr(policy, key, None)
        if isinstance(current, (list, tuple)) and isinstance(value, list):
            merged[key] = list(current) + value
        else:
            merged[key] = value

    return dataclasses.replace(policy, **merged)
