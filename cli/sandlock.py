#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sandlock CLI: lightweight process sandbox."""

from __future__ import annotations

import argparse
import os
import sys

# Ensure the package is importable when running as a standalone script.
_src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

from sandlock._version import __version__


def cmd_run(args: argparse.Namespace) -> int:
    """Run a command in a sandbox."""
    from sandlock.policy import Policy
    from sandlock.sandbox import Sandbox

    policy_kwargs: dict = {}
    if args.writable:
        policy_kwargs["fs_writable"] = args.writable
    if args.readable:
        policy_kwargs["fs_readable"] = args.readable
    if args.memory:
        policy_kwargs["max_memory"] = args.memory
    if args.processes:
        policy_kwargs["max_processes"] = args.processes
    if args.cpu:
        policy_kwargs["max_cpu"] = args.cpu
    if args.net_bind:
        policy_kwargs["net_bind"] = args.net_bind
    if args.net_connect:
        policy_kwargs["net_connect"] = args.net_connect
    if args.strict:
        from sandlock._seccomp import DEFAULT_ALLOW_SYSCALLS
        policy_kwargs["allow_syscalls"] = DEFAULT_ALLOW_SYSCALLS
    if args.privileged:
        policy_kwargs["privileged"] = True
    if args.fs_isolation:
        from sandlock.policy import FsIsolation
        policy_kwargs["fs_isolation"] = FsIsolation(args.fs_isolation)
    if args.fs_mount:
        policy_kwargs["fs_mount"] = args.fs_mount
    if args.fs_storage:
        policy_kwargs["fs_storage"] = args.fs_storage
    if args.max_disk:
        policy_kwargs["max_disk"] = args.max_disk
    if args.net_allow_host:
        policy_kwargs["net_allow_hosts"] = args.net_allow_host

    # Auto-enable /proc pid isolation when /proc is readable
    if args.readable and any(
        p == "/proc" or p.rstrip("/") == "/proc" for p in args.readable
    ):
        from sandlock._notif_policy import NotifPolicy, default_proc_rules
        if "notif_policy" not in policy_kwargs:
            policy_kwargs["notif_policy"] = NotifPolicy(
                rules=default_proc_rules(),
                isolate_pids=True,
            )

    policy = Policy(**policy_kwargs)
    sb = Sandbox(policy)

    if args.interactive:
        result = sb.run_interactive(args.command, timeout=args.timeout)
    else:
        result = sb.run(args.command, timeout=args.timeout)
        if result.stdout:
            sys.stdout.buffer.write(result.stdout)
        if result.stderr:
            sys.stderr.buffer.write(result.stderr)

    return result.exit_code


def cmd_check(args: argparse.Namespace) -> int:
    """Check kernel support for sandbox features."""
    print(f"Sandlock {__version__}")
    print()

    # Landlock
    try:
        from sandlock._landlock import landlock_abi_version
        ver = landlock_abi_version()
        if ver > 0:
            print(f"  Landlock:  supported (ABI v{ver})")
        else:
            print("  Landlock:  not available")
    except Exception as e:
        print(f"  Landlock:  error ({e})")

    # seccomp
    try:
        from sandlock._seccomp import apply_seccomp_filter
        print("  seccomp:   available")
    except Exception as e:
        print(f"  seccomp:   error ({e})")

    # cgroup v2
    try:
        from sandlock._cgroup import _find_user_cgroup
        cg = _find_user_cgroup()
        print(f"  cgroup v2: available ({cg})")
    except Exception as e:
        print(f"  cgroup v2: not available ({e})")

    print()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sandlock",
        description="Lightweight process sandbox",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command_name")

    # sandlock run
    run_p = sub.add_parser("run", help="Run a command in a sandbox")
    run_p.add_argument("-i", "--interactive", action="store_true",
                       help="Interactive mode: inherit stdin/stdout/stderr")
    run_p.add_argument("command", nargs="+", help="Command to run")
    run_p.add_argument("-w", "--writable", action="append", help="Writable path")
    run_p.add_argument("-r", "--readable", action="append", help="Readable path")
    run_p.add_argument("-m", "--memory", help="Memory limit (e.g. 512M)")
    run_p.add_argument("-p", "--processes", type=int, help="Max processes")
    run_p.add_argument("-c", "--cpu", help="CPU limit (e.g. 50%%)")
    run_p.add_argument("-t", "--timeout", type=float, help="Timeout in seconds")
    run_p.add_argument("--strict", action="store_true",
                       help="Allowlist mode: only permit known-safe syscalls")
    run_p.add_argument("--privileged", action="store_true",
                       help="Run as root inside a user namespace")
    run_p.add_argument("--net-bind", action="append", metavar="PORT",
                       help="Allowed TCP bind port or range (e.g. 80, 8000-9000)")
    run_p.add_argument("--net-connect", action="append", metavar="PORT",
                       help="Allowed TCP connect port or range (e.g. 443, 1-1024)")
    run_p.add_argument("--fs-isolation", choices=["none", "branchfs"],
                       help="Filesystem isolation mode")
    run_p.add_argument("--fs-mount", metavar="PATH",
                       help="BranchFS mount point")
    run_p.add_argument("--fs-storage", metavar="PATH",
                       help="BranchFS storage directory (separate from mount)")
    run_p.add_argument("--max-disk", metavar="SIZE",
                       help="BranchFS storage quota (e.g. 1G)")
    run_p.add_argument("--net-allow-host", action="append", metavar="DOMAIN",
                       help="Allowed domain (virtualizes /etc/hosts)")
    run_p.set_defaults(func=cmd_run)

    # sandlock check
    check_p = sub.add_parser("check", help="Check kernel support")
    check_p.set_defaults(func=cmd_check)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
