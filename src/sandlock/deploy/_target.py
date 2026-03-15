# SPDX-License-Identifier: Apache-2.0
"""Target configuration: declarative deployment specs.

Targets are defined in ``sandlock.toml`` (project root or
``~/.config/sandlock/sandlock.toml``).  Each target describes
a remote environment: host, profile, repo, setup commands.

Example::

    [target.ci]
    host = "ci@runner-1"
    profile = "restricted"
    repo = "git@github.com:org/project.git"
    setup = "pip install -r requirements.txt"
    workdir = "~/project"

    [target.staging]
    host = "deploy@staging.example.com"
    profile = "web"
    repo = "git@github.com:org/app.git"
    branch = "main"
    workdir = "~/app"
    setup = "pip install -r requirements.txt && python manage.py migrate"
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass(frozen=True)
class Target:
    """A deployment target specification."""

    name: str
    """Target name (the key under [target.*])."""

    host: str
    """Remote host (user@host)."""

    profile: str | None = None
    """Sandbox profile name to use."""

    repo: str | None = None
    """Git repo URL to clone on remote."""

    branch: str | None = None
    """Git branch to checkout."""

    workdir: str | None = None
    """Working directory on remote for command execution."""

    setup: str | None = None
    """Shell command(s) to run after clone/pull (e.g. pip install)."""

    port: int = 22
    """SSH port."""

    key: str | None = None
    """Path to SSH private key file."""

    pubkey: str | None = None
    """Path to SSH public key for authorized_keys setup."""

    force_command: bool = False
    """Whether to configure SSH ForceCommand."""

    remote_python: str = "python3"
    """Python interpreter on remote."""


_KNOWN_FIELDS = {f.name for f in Target.__dataclass_fields__.values()} - {"name"}


def _find_config() -> Path | None:
    """Find sandlock.toml in project root or user config."""
    # Check current directory and parents
    cwd = Path.cwd()
    for d in [cwd, *cwd.parents]:
        path = d / "sandlock.toml"
        if path.is_file():
            return path
        # Stop at home directory
        if d == Path.home():
            break

    # Check user config
    user_config = Path("~/.config/sandlock/sandlock.toml").expanduser()
    if user_config.is_file():
        return user_config

    return None


def load_targets(config_path: Path | None = None) -> dict[str, Target]:
    """Load all targets from sandlock.toml.

    Args:
        config_path: Explicit config path. If None, searches for sandlock.toml.

    Returns:
        Dict mapping target names to Target objects.

    Raises:
        FileNotFoundError: If no config file found.
        ValueError: If config has invalid fields.
    """
    if config_path is None:
        config_path = _find_config()
    if config_path is None:
        raise FileNotFoundError(
            "No sandlock.toml found. Create one in the project root or "
            "~/.config/sandlock/sandlock.toml"
        )

    with open(config_path, "rb") as f:
        data = tomllib.load(f)

    targets_data = data.get("target", {})
    if not isinstance(targets_data, dict):
        raise ValueError(f"{config_path}: [target] must be a table")

    targets = {}
    for name, spec in targets_data.items():
        if not isinstance(spec, dict):
            raise ValueError(f"{config_path}: [target.{name}] must be a table")

        if "host" not in spec:
            raise ValueError(f"{config_path}: [target.{name}] requires 'host'")

        unknown = set(spec.keys()) - _KNOWN_FIELDS
        if unknown:
            raise ValueError(
                f"{config_path}: [target.{name}] unknown fields: "
                f"{', '.join(sorted(unknown))}"
            )

        targets[name] = Target(name=name, **spec)

    return targets


@dataclass(frozen=True)
class Cluster:
    """A group of targets."""

    name: str
    """Cluster name (the key under [cluster.*])."""

    nodes: list[str]
    """List of target names in this cluster."""


def load_clusters(config_path: Path | None = None) -> dict[str, Cluster]:
    """Load all clusters from sandlock.toml."""
    if config_path is None:
        config_path = _find_config()
    if config_path is None:
        raise FileNotFoundError(
            "No sandlock.toml found. Create one in the project root or "
            "~/.config/sandlock/sandlock.toml"
        )

    with open(config_path, "rb") as f:
        data = tomllib.load(f)

    clusters_data = data.get("cluster", {})
    if not isinstance(clusters_data, dict):
        raise ValueError(f"{config_path}: [cluster] must be a table")

    clusters = {}
    for name, spec in clusters_data.items():
        if not isinstance(spec, dict):
            raise ValueError(f"{config_path}: [cluster.{name}] must be a table")
        if "nodes" not in spec:
            raise ValueError(f"{config_path}: [cluster.{name}] requires 'nodes'")
        nodes = spec["nodes"]
        if not isinstance(nodes, list):
            raise ValueError(f"{config_path}: [cluster.{name}].nodes must be a list")
        clusters[name] = Cluster(name=name, nodes=nodes)

    return clusters


def load_cluster(name: str, config_path: Path | None = None) -> Cluster:
    """Load a single cluster by name."""
    clusters = load_clusters(config_path)
    if name not in clusters:
        available = ", ".join(sorted(clusters.keys())) or "(none)"
        raise KeyError(f"cluster '{name}' not found. Available: {available}")
    return clusters[name]


def load_target(name: str, config_path: Path | None = None) -> Target:
    """Load a single target by name.

    Raises:
        FileNotFoundError: If no config file found.
        KeyError: If target name doesn't exist.
    """
    targets = load_targets(config_path)
    if name not in targets:
        available = ", ".join(sorted(targets.keys())) or "(none)"
        raise KeyError(f"target '{name}' not found. Available: {available}")
    return targets[name]
