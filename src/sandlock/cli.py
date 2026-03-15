# SPDX-License-Identifier: Apache-2.0
"""CLI: sandlock run, sandlock check."""

from __future__ import annotations

import argparse
import sys

from ._version import __version__


def cmd_run(args: argparse.Namespace) -> int:
    """Run a command in a sandbox."""
    from .policy import Policy
    from .sandbox import Sandbox

    # Build CLI overrides dict
    cli_kwargs: dict = {}
    if args.writable:
        cli_kwargs["fs_writable"] = args.writable
    if args.readable:
        cli_kwargs["fs_readable"] = args.readable
    if args.memory:
        cli_kwargs["max_memory"] = args.memory
    if args.processes:
        cli_kwargs["max_processes"] = args.processes
    if args.cpu:
        cli_kwargs["max_cpu"] = args.cpu
    if args.strict:
        from ._seccomp import DEFAULT_ALLOW_SYSCALLS
        cli_kwargs["allow_syscalls"] = DEFAULT_ALLOW_SYSCALLS
    if args.image:
        from ._image import extract
        try:
            rootfs = extract(args.image)
        except Exception as e:
            print(f"error: failed to pull image {args.image!r}: {e}",
                  file=sys.stderr)
            return 1
        cli_kwargs["chroot"] = rootfs
        cli_kwargs["privileged"] = True
        if not args.readable:
            cli_kwargs.setdefault("fs_readable", ["/"])
        if not args.writable:
            cli_kwargs.setdefault("fs_writable", ["/tmp"])
    if args.chroot:
        cli_kwargs["chroot"] = args.chroot
    if args.privileged:
        cli_kwargs["privileged"] = True
    if args.fs_isolation:
        from .policy import FsIsolation
        cli_kwargs["fs_isolation"] = FsIsolation(args.fs_isolation)
    if args.fs_mount:
        cli_kwargs["fs_mount"] = args.fs_mount
    if args.fs_storage:
        cli_kwargs["fs_storage"] = args.fs_storage
    if args.max_disk:
        cli_kwargs["max_disk"] = args.max_disk
    if args.net_bind:
        cli_kwargs["net_bind"] = args.net_bind
    if args.net_connect:
        cli_kwargs["net_connect"] = args.net_connect
    if args.net_allow_host:
        cli_kwargs["net_allow_hosts"] = args.net_allow_host
    if args.isolate_ipc:
        cli_kwargs["isolate_ipc"] = True
    if args.isolate_signals:
        cli_kwargs["isolate_signals"] = True
    if args.port_remap:
        cli_kwargs["port_remap"] = True
    if args.clean_env:
        cli_kwargs["clean_env"] = True
    if args.env:
        env_dict = {}
        for spec in args.env:
            if "=" not in spec:
                print(f"error: --env requires KEY=VALUE, got {spec!r}",
                      file=sys.stderr)
                return 1
            k, v = spec.split("=", 1)
            env_dict[k] = v
        cli_kwargs["env"] = env_dict

    # Load profile or start from defaults, then apply CLI overrides
    if args.profile:
        from ._profile import load_profile, merge_cli_overrides
        try:
            policy = load_profile(args.profile)
        except Exception as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if cli_kwargs:
            policy = merge_cli_overrides(policy, cli_kwargs)
    else:
        policy = Policy(**cli_kwargs)

    # Resolve command: -e string, explicit args, image default, or error
    if args.exec_shell:
        command = ["/bin/sh", "-c", args.exec_shell]
    elif args.command:
        command = args.command
    elif args.image:
        from ._image import get_default_cmd
        command = get_default_cmd(args.image)
    else:
        print("error: no command specified", file=sys.stderr)
        return 1

    # Remote execution via SSH
    if getattr(args, "host", None):
        try:
            from .deploy._sandbox import RemoteSandbox
        except ImportError:
            print(
                "error: --host requires sandlock[deploy].\n"
                "Install with: pip install sandlock[deploy]",
                file=sys.stderr,
            )
            return 1

        sb = RemoteSandbox(policy, host=args.host)
        try:
            if args.exec_shell:
                result = sb.run_shell(args.exec_shell, timeout=args.timeout)
            else:
                result = sb.run(command, timeout=args.timeout)
            if result.stdout:
                sys.stdout.buffer.write(result.stdout)
            if result.stderr:
                sys.stderr.buffer.write(result.stderr)
            return result.exit_code
        finally:
            sb.close()

    sb = Sandbox(policy)

    if args.interactive:
        result = sb.run_interactive(command, timeout=args.timeout)
    else:
        result = sb.run(command, timeout=args.timeout)
        if result.stdout:
            sys.stdout.buffer.write(result.stdout)
        if result.stderr:
            sys.stderr.buffer.write(result.stderr)

    return result.exit_code


def cmd_profile_list(args: argparse.Namespace) -> int:
    """List available profiles."""
    from ._profile import list_profiles, profiles_dir

    names = list_profiles()
    if not names:
        print(f"No profiles found in {profiles_dir()}")
        return 0
    for name in names:
        print(name)
    return 0


def cmd_profile_show(args: argparse.Namespace) -> int:
    """Show a profile's contents."""
    from ._profile import load_profile, profiles_dir
    import dataclasses

    path = profiles_dir() / f"{args.name}.toml"
    if not path.is_file():
        print(f"error: profile not found: {path}", file=sys.stderr)
        return 1

    # Show raw TOML
    print(f"# {path}")
    print(path.read_text(), end="")
    return 0


def cmd_deploy(args: argparse.Namespace) -> int:
    """Deploy sandlock to a remote host via SSH."""
    try:
        from .deploy._cli import run_deploy
    except ImportError:
        print(
            "error: sandlock[deploy] not installed.\n"
            "Install with: pip install sandlock[deploy]",
            file=sys.stderr,
        )
        return 1
    return run_deploy(args)


def cmd_check(args: argparse.Namespace) -> int:
    """Check kernel support for sandbox features."""
    print(f"Sandlock {__version__}")
    print()

    # Landlock
    try:
        from ._landlock import landlock_abi_version
        ver = landlock_abi_version()
        if ver > 0:
            print(f"  Landlock:  supported (ABI v{ver})")
            if ver >= 4:
                print("    - network TCP port restrictions")
            if ver >= 6:
                print("    - IPC scoping (abstract UNIX sockets, signals)")
        else:
            print("  Landlock:  not available")
    except Exception as e:
        print(f"  Landlock:  error ({e})")

    # seccomp
    try:
        from ._seccomp import apply_seccomp_filter
        print("  seccomp:   available")
    except Exception as e:
        print(f"  seccomp:   error ({e})")

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
    run_p.add_argument("-p", "--profile", metavar="NAME",
                       help="Use a named profile from ~/.config/sandlock/profiles/")
    run_p.add_argument("-e", "--exec-shell", metavar="CMD",
                       help="Run CMD via /bin/sh -c (e.g. for SSH ForceCommand)")
    run_p.add_argument("command", nargs="*", help="Command to run")
    run_p.add_argument("-w", "--writable", action="append", help="Writable path")
    run_p.add_argument("-r", "--readable", action="append", help="Readable path")
    run_p.add_argument("-m", "--memory", help="Memory limit (e.g. 512M)")
    run_p.add_argument("-P", "--processes", type=int, help="Max processes")
    run_p.add_argument("-c", "--cpu", type=int, help="CPU throttle percent (1-100)")
    run_p.add_argument("-t", "--timeout", type=float, help="Timeout in seconds")
    run_p.add_argument("--strict", action="store_true",
                       help="Allowlist mode: only permit known-safe syscalls")
    run_p.add_argument("--image", metavar="IMAGE",
                       help="Use a Docker/OCI image as root filesystem (e.g. python:3.12-slim)")
    run_p.add_argument("--chroot", metavar="PATH",
                       help="Use directory as root filesystem (requires --privileged)")
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
    run_p.add_argument("--isolate-ipc", action="store_true",
                       help="Block abstract UNIX sockets outside sandbox (Landlock ABI v6+)")
    run_p.add_argument("--isolate-signals", action="store_true",
                       help="Block signals to processes outside sandbox (Landlock ABI v6+)")
    run_p.add_argument("--port-remap", action="store_true",
                       help="Transparent TCP port remapping (no port conflicts between sandboxes)")
    run_p.add_argument("--clean-env", action="store_true",
                       help="Start with minimal environment (PATH, HOME, USER, TERM, LANG)")
    run_p.add_argument("--env", action="append", metavar="KEY=VALUE",
                       help="Set environment variable in the sandbox")
    run_p.add_argument("--host", metavar="USER@HOST",
                       help="Run on remote host via SSH (requires sandlock[deploy])")
    run_p.set_defaults(func=cmd_run)

    # sandlock profile
    prof_p = sub.add_parser("profile", help="Manage profiles")
    prof_sub = prof_p.add_subparsers(dest="profile_command")

    prof_list = prof_sub.add_parser("list", help="List available profiles")
    prof_list.set_defaults(func=cmd_profile_list)

    prof_show = prof_sub.add_parser("show", help="Show a profile")
    prof_show.add_argument("name", help="Profile name")
    prof_show.set_defaults(func=cmd_profile_show)

    prof_p.set_defaults(func=lambda args: (prof_p.print_help(), 1)[1])

    # sandlock deploy
    deploy_p = sub.add_parser("deploy", help="Deploy sandlock to a remote host via SSH")
    deploy_p.add_argument("host", help="Remote host (user@host)")
    deploy_p.add_argument("-p", "--port", type=int, default=22, help="SSH port")
    deploy_p.add_argument("-k", "--key", metavar="PATH", help="SSH private key file")
    deploy_p.add_argument("--profile", metavar="NAME", help="Profile to push to remote")
    deploy_p.add_argument("--pubkey", metavar="PATH",
                          help="Public key file to add to remote authorized_keys")
    deploy_p.add_argument("--force-command", action="store_true",
                          help="Configure SSH ForceCommand to sandbox all sessions")
    deploy_p.add_argument("--remote-python", default="python3",
                          help="Python interpreter on remote (default: python3)")
    deploy_p.add_argument("--no-verify", action="store_true",
                          help="Skip post-deploy verification")
    deploy_p.set_defaults(func=cmd_deploy)

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
