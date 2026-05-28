# SPDX-License-Identifier: Apache-2.0
"""TOML profile loading for Sandlock.

Profiles use the sectioned policy schema (the same one parsed by the
Rust CLI). Each section maps to a subset of ``Sandbox`` fields:

    [config]      → http_ca, http_key, fs_storage, workdir
    [determinism] → random_seed, time_start, deterministic_dirs,
                    no_randomize_memory
    [program]     → env, cwd, uid, clean_env, no_coredump, no_huge_pages
                    (``exec`` and ``args`` are runtime program identity
                    and are silently ignored — pass them to
                    ``sandbox.run(cmd)`` instead)
    [filesystem]  → fs_readable (read), fs_writable (write),
                    fs_denied (deny), fs_isolation (isolation), chroot,
                    fs_mount (mount), on_exit, on_error
    [network]     → net_bind (bind), net_allow (allow), port_remap
    [http]        → http_ports (ports), http_allow (allow),
                    http_deny (deny)
    [syscalls]    → extra_allow_syscalls (extra_allow),
                    extra_deny_syscalls (extra_deny)
    [limits]      → max_memory (memory), max_processes (processes),
                    max_open_files (open_files), max_cpu (cpu),
                    max_disk (disk), gpu_devices, cpu_cores, num_cpus
"""

from __future__ import annotations

import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from pathlib import Path
from typing import Any

from .exceptions import PolicyError
from .sandbox import BranchAction, FsIsolation, Sandbox


_PROFILES_DIR = Path("~/.config/sandlock/profiles").expanduser()


# Per-section schema. Each entry maps a TOML field name to
# (sandbox-attribute name, expected python type).  A sandbox-attribute
# name of ``None`` means the field is recognised but silently ignored
# (used for [program].exec and [program].args, which are runtime
# program identity, not Sandbox config).
_SECTIONS: dict[str, dict[str, tuple[str | None, type]]] = {
    "config": {
        "http_ca":    ("http_ca",    str),
        "http_key":   ("http_key",   str),
        "fs_storage": ("fs_storage", str),
        "workdir":    ("workdir",    str),
    },
    "determinism": {
        "random_seed":         ("random_seed",         int),
        "time_start":          ("time_start",          str),
        "deterministic_dirs":  ("deterministic_dirs",  bool),
        "no_randomize_memory": ("no_randomize_memory", bool),
    },
    "program": {
        "exec":          (None,            str),
        "args":          (None,            list),
        "env":           ("env",           dict),
        "cwd":           ("cwd",           str),
        "uid":           ("uid",           int),
        "clean_env":     ("clean_env",     bool),
        "no_coredump":   ("no_coredump",   bool),
        "no_huge_pages": ("no_huge_pages", bool),
    },
    "filesystem": {
        "read":      ("fs_readable",  list),
        "write":     ("fs_writable",  list),
        "deny":      ("fs_denied",    list),
        "isolation": ("fs_isolation", str),
        "chroot":    ("chroot",       str),
        "mount":     ("fs_mount",     list),
        "on_exit":   ("on_exit",      str),
        "on_error":  ("on_error",     str),
    },
    "network": {
        "bind":       ("net_bind",   list),
        "allow":      ("net_allow",  list),
        "port_remap": ("port_remap", bool),
    },
    "http": {
        "ports": ("http_ports", list),
        "allow": ("http_allow", list),
        "deny":  ("http_deny",  list),
    },
    "syscalls": {
        "extra_allow": ("extra_allow_syscalls", list),
        "extra_deny":  ("extra_deny_syscalls",  list),
    },
    "limits": {
        "memory":      ("max_memory",     str),
        "processes":   ("max_processes",  int),
        "open_files":  ("max_open_files", int),
        "cpu":         ("max_cpu",        int),
        "disk":        ("max_disk",       str),
        "gpu_devices": ("gpu_devices",    list),
        "cpu_cores":   ("cpu_cores",      list),
        "num_cpus":    ("num_cpus",       int),
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
        PolicyError: If the profile doesn't exist or has invalid fields.
    """
    path = _PROFILES_DIR / f"{name}.toml"
    if not path.is_file():
        raise PolicyError(f"profile not found: {path}")
    return load_profile_path(path)


def load_profile_path(path: Path) -> Sandbox:
    """Load a profile from a file path and return a Sandbox.

    Raises:
        PolicyError: If the file can't be parsed or has invalid fields.
    """
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"invalid TOML in {path}: {e}") from e

    return policy_from_dict(data, source=str(path))


def policy_from_dict(data: dict, source: str = "<dict>") -> Sandbox:
    """Construct a Sandbox from a parsed sectioned-TOML dict.

    Each top-level key must be a known schema section (``config``,
    ``determinism``, ``program``, ``filesystem``, ``network``, ``http``,
    ``syscalls``, ``limits``).  Within each section, only the documented
    fields are accepted.

    Raises:
        PolicyError: If unknown section / field names appear or types mismatch.
    """
    if not isinstance(data, dict):
        raise PolicyError(
            f"{source}: expected a TOML table at the top level, "
            f"got {type(data).__name__}"
        )

    unknown_sections = set(data.keys()) - set(_SECTIONS.keys())
    if unknown_sections:
        raise PolicyError(
            f"{source}: unknown section(s): "
            f"{', '.join(sorted(unknown_sections))}"
        )

    kwargs: dict[str, Any] = {}

    for section_name, section_data in data.items():
        if not isinstance(section_data, dict):
            raise PolicyError(
                f"{source}: [{section_name}] must be a TOML table, "
                f"got {type(section_data).__name__}"
            )
        schema = _SECTIONS[section_name]
        unknown_fields = set(section_data.keys()) - set(schema.keys())
        if unknown_fields:
            raise PolicyError(
                f"{source}: unknown field(s) in [{section_name}]: "
                f"{', '.join(sorted(unknown_fields))}"
            )
        for toml_key, value in section_data.items():
            sandbox_key, expected_type = schema[toml_key]
            if sandbox_key is None:
                # [program].exec / [program].args — silently ignored.
                continue
            if not isinstance(value, expected_type):
                raise PolicyError(
                    f"{source}: [{section_name}].{toml_key} expected "
                    f"{expected_type.__name__}, got {type(value).__name__}"
                )
            value = _coerce(section_name, toml_key, sandbox_key, value, source)
            kwargs[sandbox_key] = value

    return Sandbox(**kwargs)


def _coerce(
    section: str, toml_key: str, sandbox_key: str, value: Any, source: str
) -> Any:
    """Per-field value coercion (enums, mount-spec parsing, port lists)."""
    if sandbox_key == "fs_isolation":
        try:
            return FsIsolation(value)
        except ValueError:
            raise PolicyError(
                f"{source}: [{section}].{toml_key} must be "
                f"'none' or 'branchfs', got {value!r}"
            )
    if sandbox_key in ("on_exit", "on_error"):
        try:
            return BranchAction(value)
        except ValueError:
            raise PolicyError(
                f"{source}: [{section}].{toml_key} must be "
                f"'commit', 'abort', or 'keep', got {value!r}"
            )
    if sandbox_key == "fs_mount":
        # TOML form is ``["VIRTUAL:HOST", ...]``;
        # Sandbox.fs_mount is dict[str, str].
        mount: dict[str, str] = {}
        for spec in value:
            if not isinstance(spec, str):
                raise PolicyError(
                    f"{source}: [{section}].{toml_key} entries must be "
                    f"'VIRTUAL:HOST' strings, got {type(spec).__name__}"
                )
            if ":" not in spec:
                raise PolicyError(
                    f"{source}: [{section}].{toml_key} entry {spec!r} "
                    "must be 'VIRTUAL:HOST'"
                )
            virt, host = spec.split(":", 1)
            if not virt or not host:
                raise PolicyError(
                    f"{source}: [{section}].{toml_key} entry {spec!r} "
                    "requires both VIRTUAL and HOST to be non-empty"
                )
            mount[virt] = host
        return mount
    if sandbox_key == "net_bind":
        # Coerce TOML integers to strings for port specs (existing behaviour).
        return [str(v) if isinstance(v, int) else v for v in value]
    return value


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
