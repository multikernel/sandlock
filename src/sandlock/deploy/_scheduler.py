# SPDX-License-Identifier: Apache-2.0
"""Cluster scheduler: probe nodes, pick lightest, run.

No daemon, no state. Probes fresh every time via SSH.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from ._ssh import SSHSession
from ._target import Cluster, Target, load_cluster, load_target


@dataclass
class NodeStatus:
    """Resource snapshot from a single node."""
    name: str
    host: str
    load_1m: float
    mem_available_mb: int
    cpus: int
    reachable: bool
    error: str | None = None


def probe_node(target: Target) -> NodeStatus:
    """SSH into a node and collect load, memory, CPU count."""
    user, host = (target.host.split("@", 1) if "@" in target.host
                  else (None, target.host))
    session = SSHSession(
        host=host, user=user, port=target.port, key_file=target.key,
    )
    try:
        session.connect()

        # Single command: load, available mem, cpu count
        rc, out, _ = session.exec(
            "cat /proc/loadavg && "
            "awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo && "
            "nproc"
        )
        if rc != 0:
            return NodeStatus(
                name=target.name, host=target.host,
                load_1m=999, mem_available_mb=0, cpus=0,
                reachable=False, error="probe command failed",
            )

        lines = out.strip().splitlines()
        load_1m = float(lines[0].split()[0])
        mem_available_mb = int(lines[1])
        cpus = int(lines[2])

        return NodeStatus(
            name=target.name, host=target.host,
            load_1m=load_1m, mem_available_mb=mem_available_mb,
            cpus=cpus, reachable=True,
        )
    except Exception as e:
        return NodeStatus(
            name=target.name, host=target.host,
            load_1m=999, mem_available_mb=0, cpus=0,
            reachable=False, error=str(e),
        )
    finally:
        session.close()


def probe_cluster(cluster_name: str) -> list[NodeStatus]:
    """Probe all nodes in a cluster in parallel."""
    cluster = load_cluster(cluster_name)
    targets = [load_target(node) for node in cluster.nodes]

    with ThreadPoolExecutor(max_workers=len(targets)) as pool:
        futures = {pool.submit(probe_node, t): t for t in targets}
        results = []
        for future in as_completed(futures):
            results.append(future.result())

    return results


def pick_node(statuses: list[NodeStatus]) -> NodeStatus | None:
    """Pick the node with the lowest load (normalized by CPU count)."""
    reachable = [s for s in statuses if s.reachable]
    if not reachable:
        return None
    # Lowest load-per-cpu wins
    return min(reachable, key=lambda s: s.load_1m / max(s.cpus, 1))


def schedule(cluster_name: str) -> Target:
    """Probe a cluster and return the best target to run on.

    Raises:
        RuntimeError: If no nodes are reachable.
    """
    statuses = probe_cluster(cluster_name)
    best = pick_node(statuses)
    if best is None:
        unreachable = ", ".join(s.name for s in statuses)
        raise RuntimeError(f"no reachable nodes in cluster '{cluster_name}': {unreachable}")
    return load_target(best.name)
