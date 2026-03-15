# SPDX-License-Identifier: Apache-2.0
"""CLI handler for ``sandlock deploy``."""

from __future__ import annotations

import argparse
import sys


def run_deploy(args: argparse.Namespace) -> int:
    """Entry point for the deploy subcommand."""
    from ._ssh import SSHSession
    from ._remote import deploy, verify

    # Parse user@host
    target = args.host
    if "@" in target:
        user, host = target.split("@", 1)
    else:
        user, host = None, target

    session = SSHSession(
        host=host,
        user=user,
        port=args.port,
        key_file=args.key,
    )

    try:
        sandlock_bin = deploy(
            session,
            profile=args.profile,
            pubkey=args.pubkey,
            force_command=args.force_command,
            remote_python=args.remote_python,
        )

        if not args.no_verify:
            if not verify(session, sandlock_bin):
                return 1

        print("\nDeployment complete.")
        return 0

    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        session.close()
