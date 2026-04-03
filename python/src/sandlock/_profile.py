# SPDX-License-Identifier: Apache-2.0
"""TOML profile loading for Sandlock.

Profiles are stored as TOML files under ``~/.config/sandlock/profiles/``.
Field names match ``Policy`` exactly — no translation layer.
"""

from __future__ import annotations

import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib
from pathlib import Path

from .exceptions import PolicyError
from .policy import Policy, FsIsolation, BranchAction


_PROFILES_DIR = Path("~/.config/sandlock/profiles").expanduser()

# Policy fields settable from TOML (excludes notif_policy which needs Python objects).
_SIMPLE_FIELDS: dict[str, type] = {
    # Filesystem
    "fs_writable": list,
    "fs_readable": list,
    "fs_denied": list,
    # Syscall filtering
    "deny_syscalls": list,
    "allow_syscalls": list,
    # Network
    "net_allow_hosts": list,
    "net_bind": list,
    "net_connect": list,
    # IPC scoping
    "isolate_ipc": bool,
    "isolate_signals": bool,
    "isolate_pids": bool,
    "no_raw_sockets": bool,
    "no_udp": bool,
    # Resources
    "max_memory": str,
    "max_processes": int,
    "max_open_files": int,
    "max_cpu": int,
    "num_cpus": int,
    "cpu_cores": list,
    # Chroot
    "chroot": str,
    # Environment
    "clean_env": bool,
    "env": dict,
    # Deterministic
    "random_seed": int,
    "no_randomize_memory": bool,
    "no_huge_pages": bool,
    "deterministic_dirs": bool,
    "hostname": str,
    "no_coredump": bool,
    # Misc
    "port_remap": bool,
    "close_fds": bool,
    "uid": int,
    # Workdir
    "workdir": str,
    # COW isolation
    "fs_isolation": str,
    "fs_storage": str,
    "max_disk": str,
    "on_exit": str,
    "on_error": str,
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


def load_profile(name: str) -> Policy:
    """Load a named profile and return a Policy.

    Args:
        name: Profile name (without .toml extension).

    Raises:
        PolicyError: If the profile doesn't exist or has invalid fields.
    """
    path = _PROFILES_DIR / f"{name}.toml"
    if not path.is_file():
        raise PolicyError(f"profile not found: {path}")
    return load_profile_path(path)


def load_profile_path(path: Path) -> Policy:
    """Load a profile from a file path and return a Policy.

    Raises:
        PolicyError: If the file can't be parsed or has invalid fields.
    """
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"invalid TOML in {path}: {e}") from e

    return policy_from_dict(data, source=str(path))


def policy_from_dict(data: dict, source: str = "<dict>") -> Policy:
    """Construct a Policy from a parsed TOML dict.

    Raises:
        PolicyError: If unknown keys or type mismatches are found.
    """
    unknown = set(data.keys()) - set(_SIMPLE_FIELDS.keys())
    if unknown:
        raise PolicyError(
            f"unknown fields in {source}: {', '.join(sorted(unknown))}"
        )

    kwargs: dict = {}
    for key, value in data.items():
        expected = _SIMPLE_FIELDS[key]

        # Enum conversions
        if key == "fs_isolation":
            try:
                kwargs[key] = FsIsolation(value)
            except ValueError:
                raise PolicyError(
                    f"{source}: fs_isolation must be 'none', 'branchfs', or 'overlayfs', "
                    f"got {value!r}"
                )
            continue
        if key in ("on_exit", "on_error"):
            try:
                kwargs[key] = BranchAction(value)
            except ValueError:
                raise PolicyError(
                    f"{source}: {key} must be 'commit', 'abort', or 'keep', "
                    f"got {value!r}"
                )
            continue

        # Type checking
        if not isinstance(value, expected):
            raise PolicyError(
                f"{source}: field '{key}' expected {expected.__name__}, "
                f"got {type(value).__name__}"
            )

        # Coerce TOML integers in lists to strings for port specs
        if key in ("net_bind", "net_connect") and isinstance(value, list):
            value = [str(v) if isinstance(v, int) else v for v in value]

        kwargs[key] = value

    return Policy(**kwargs)


def merge_cli_overrides(policy: Policy, overrides: dict) -> Policy:
    """Return a new Policy with CLI overrides applied on top of a profile.

    List fields from CLI are appended to profile values.
    Scalar fields from CLI replace profile values.
    """
    import dataclasses

    merged = {}
    for key, value in overrides.items():
        current = getattr(policy, key, None)
        # Append lists, replace everything else
        if isinstance(current, (list, tuple)) and isinstance(value, list):
            merged[key] = list(current) + value
        else:
            merged[key] = value

    return dataclasses.replace(policy, **merged)
