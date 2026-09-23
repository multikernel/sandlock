# CLI Guide

`sandlock run` confines one command. Filesystem access is default-deny:
`-r PATH` grants read access, `-w PATH` grants read and write access. Every
other option layers a further restriction on top. The full field-by-field
reference, shared with profiles and the Python SDK, is in
[`sandbox-reference.md`](sandbox-reference.md).

## Examples

```bash
# Basic confinement
sandlock run -r /usr -r /lib -w /tmp -- ls /tmp

# Interactive shell (the sandboxed command inherits the terminal)
sandlock run -r /usr -r /lib -r /lib64 -r /bin -r /etc -w /tmp -- /bin/sh

# Resource limits + timeout
sandlock run -m 512M -P 20 -t 30 -- ./compute.sh

# GPU access (NVIDIA): `--gpu all` for every GPU, or indices like `0,2`.
# Selection is a hard Landlock boundary: only the chosen /dev/nvidiaN nodes
# are openable, so a sandbox given `--gpu 0` cannot touch other GPUs. The
# NVIDIA userspace also needs the driver libraries readable and writes thread
# names under /proc/self/task.
sandlock run --gpu 0 \
  -r /usr -r /lib -r /lib64 -r /etc -r /sys -r /proc -w /proc/self/task \
  -- python3 train.py

# Outbound allowlist: restrict to one host on one port
sandlock run --net-allow api.openai.com:443 -r /usr -r /lib -r /etc -- python3 agent.py

# Multiple ports for one host, plus a separate any-IP port
sandlock run --net-allow github.com:22,443 --net-allow :8080 \
  -r /usr -r /lib -r /etc -- python3 agent.py

# Wildcard port (optional): a bare `host` (or `host:*`) permits every port
sandlock run --net-allow github.com -r /usr -r /lib -r /etc -- ssh user@github.com

# IP, CIDR range, or IPv6 literal as the target (matched by containment,
# no DNS); same grammar as --net-deny
sandlock run --net-allow 10.0.0.0/8:443 --net-allow '[2606:4700::/32]:443' \
  -r /usr -r /lib -r /etc -- python3 agent.py

# Unrestricted outbound: `*` opens any host and any port over both TCP
# and UDP (`:*` / `*:*` are equivalent). ICMP still needs `icmp://`.
sandlock run --net-allow '*' \
  -r /usr -r /lib -r /etc -- ./client

# Scheme prefix: a spec with no scheme covers TCP and UDP; `tcp://` or
# `udp://` pins one protocol (e.g. UDP DNS to 1.1.1.1 only, plus
# TCP-only HTTPS to anywhere)
sandlock run --net-allow udp://1.1.1.1:53 --net-allow tcp://:443 \
  -r /usr -r /lib -r /etc -- ./client

# Ping: kernel ping socket (SOCK_DGRAM) gated by net.ipv4.ping_group_range
sandlock run --net-allow icmp://github.com -r /usr -r /lib -r /etc -- ping github.com

# Denylist: default-allow networking, block specific IPs/CIDRs/ports.
# When combined with --net-allow, denied destinations win. Port is optional.
sandlock run --net-deny 169.254.169.254 --net-deny 10.0.0.0/8 \
  -r /usr -r /lib -r /etc -- python3 agent.py

# Combined policy: allow HTTPS generally, except for the denied CIDR.
sandlock run --net-allow ':443' --net-deny 10.0.0.0/8 \
  -r /usr -r /lib -r /etc -- python3 agent.py

# HTTP-level ACL (method + host + path rules via transparent proxy)
# HTTP rules generate host:80,443 reachability at resolution time (not stored in --net-allow)
sandlock run \
  --http-allow "GET docs.python.org/*" \
  --http-allow "POST api.openai.com/v1/chat/completions" \
  --http-deny "* */admin/*" \
  -r /usr -r /lib -r /etc -- python3 agent.py

# HTTPS MITM, zero-config: sandlock generates an ephemeral CA and splices it
# into the trust bundle(s) you name. No openssl, no manual install.
sandlock run \
  --http-allow "POST api.openai.com/v1/*" \
  --http-inject-ca /etc/ssl/certs/ca-certificates.crt \
  -r /usr -r /lib -r /etc -- python3 agent.py

# Node and other runtimes with a compiled-in CA list: export the cert and
# wire the runtime's own env var.
sandlock run \
  --http-allow "POST api.example.com/*" \
  --http-inject-ca /etc/ssl/certs/ca-certificates.crt \
  --http-ca-out /tmp/sandlock-ca.pem \
  --env NODE_EXTRA_CA_CERTS=/tmp/sandlock-ca.pem \
  -r /usr -r /lib -r /etc -- node agent.js

# HTTPS MITM with your own CA (still supported)
sandlock run \
  --http-allow "POST api.openai.com/v1/*" \
  --http-ca ca.pem --http-key ca-key.pem \
  -r /usr -r /lib -r /etc -- python3 agent.py

# Credential injection: the secret lives in the supervisor, the child never sees
# it. sandlock attaches it in the proxy AFTER the ACL check. Over HTTPS the value
# is encrypted to the upstream; over cleartext HTTP sandlock warns (the secret
# would be exposed on the wire).
sandlock run \
  --http-allow "POST api.openai.com/v1/*" \
  --http-inject-ca /etc/ssl/certs/ca-certificates.crt \
  --credential openai=env:OPENAI_API_KEY \
  --http-auth "POST api.openai.com/* bearer openai" \
  -r /usr -r /lib -r /etc -- python3 agent.py

# Server listening on ports (Landlock --net-allow-bind, separate from --net-allow;
# accepts comma-separated ports and lo-hi ranges, repeatable)
sandlock run --net-allow-bind 8080,9000-9005 -r /usr -r /lib -r /etc -- python3 server.py

# Clean environment
sandlock run --clean-env --env CC=gcc \
  -r /usr -r /lib -w /tmp -- make

# Deterministic execution (frozen time + seeded randomness)
sandlock run --time-start "2000-01-01T00:00:00Z" --random-seed 42 -- ./build.sh

# Port virtualization (multiple sandboxes can bind the same port)
sandlock run --port-remap --net-allow-bind 6379 -r /usr -r /lib -r /etc -- redis-server --port 6379

# Port virtualization with named sandboxes (enables network discovery)
sandlock run --name api.local --port-remap --net-allow-bind 8080 -r /usr -r /lib -r /etc -- python3 server.py
sandlock run --name web.local --port-remap --net-allow-bind 8080 -r /usr -r /lib -r /etc -- python3 server.py

# List all running sandboxes (with uptime and command)
sandlock ps

# Show effective policy for a running sandbox (JSON or TOML)
sandlock inspect api.local
sandlock inspect api.local --toml

# Kill a running sandbox by name
sandlock kill web.local

# Chroot with per-sandbox mount (no kernel bind mount needed)
sandlock run --chroot ./rootfs --fs-mount /work:/tmp/sandbox/work -- /bin/sh

# COW filesystem (writes captured, committed on success)
sandlock run --workdir /opt/project -r /usr -r /lib -- python3 task.py

# Dry-run (show what files would change, then discard)
sandlock run --dry-run --workdir . -w . -r /usr -r /lib -r /bin -r /etc -- make build

# Use a saved profile
sandlock run -p build -- make -j4

# No-supervisor mode (Landlock + deny-only seccomp, no supervisor process)
sandlock run --no-supervisor -r /usr -r /lib -r /lib64 -r /bin -w /tmp -- ./script.sh

# Nested sandboxing: confine sandlock's own supervisor
sandlock run --no-supervisor -r /proc -r /usr -r /lib -r /lib64 -r /bin -r /etc -w /tmp -- \
  sandlock run -r /usr -w /tmp -- untrusted-command
```

## Procfs access

With supervision enabled, grants under `/proc/self` apply to each process's
own entries, including those of forked children. `/proc/thread-self` refers
to the calling thread. Use read grants for inspecting process state and write
grants for changing it; a write grant also permits reads.

| Grant | Access |
| --- | --- |
| `-r /proc/self/maps` | Each process can read its own memory mappings. |
| `-w /proc/self/comm` | Each process can read and change its own name. |
| `-w /proc/self/task` | Threads can read and change names within their process's task directory. |
| `-w /proc/thread-self/comm` | Each thread can read and change its own name. |

Explicit filesystem denies still take precedence. Grants do not allow
following procfs links such as `cwd`, `root`, or `fd/N` to files outside the
filesystem policy.

Some entries remain restricted even with a grant. Supervised opens refuse
`pagemap`, `stack`, and `seccomp_cache`; supervised writes also refuse `mem`,
the `attr` subtree, `uid_map`, `gid_map`, `setgroups`, and `projid_map` in
process and thread directories. Opening these files as the supervisor can
change their permission checks, so these restrictions are stricter than
native procfs permissions.

Without supervision, procfs grants use native Landlock rules. A grant on
`/proc/self` then binds to the first process's entries and does not extend
to forked children.

## Profiles

Save reusable sandbox profiles as TOML files in
`~/.config/sandlock/profiles/`. Profiles use a sectioned schema; top-level
flat keys such as `fs_readable = [...]` are rejected. Pass a sandbox instance
name with `--name` when you need a stable virtual hostname.

```toml
# ~/.config/sandlock/profiles/build.toml
[program]
exec = "make"
args = ["-j4"]
clean_env = true
env = { CC = "gcc", LANG = "C.UTF-8" }

[filesystem]
read = ["/usr", "/lib", "/lib64", "/bin", "/etc", "${HOME}/.cargo"]
write = ["/tmp/work"]

[limits]
memory = "512M"
processes = 50

[syscalls]
extra_deny = []
```

Path fields expand `${HOME}`, so the same profile works on machines with
different usernames. `${HOME}` is the only variable; anything else, including
a leading `~`, is a load error. See
[`sandbox-reference.md`](sandbox-reference.md) for the full grammar.

```bash
sandlock profile list
sandlock profile show build
sandlock run -p build        # uses [program].exec + args
sandlock run -p build -- make test  # trailing command overrides [program]
```

## Managing running sandboxes

`sandlock ps` lists every running sandbox with its uptime, port mappings,
and command. `sandlock inspect NAME` prints the effective policy as JSON
(`--toml` prints it in profile syntax). `sandlock kill NAME` stops a
sandbox and its supervisor.

```
$ sandlock ps
NAME                                  PID        UPTIME  STATUS      PORTS                     CMD
api.local                           12345            5m  running     8080→41235                python3 server.py
web.local                           12346            3m  running     8080→41236                python3 server.py

$ sandlock inspect api.local --toml | head -10
[config]
http_inject_ca = []

[determinism]
...

$ sandlock kill web.local
Killed sandbox 'web.local' (child PID 12346, supervisor PID 12340)
```

Ports show as `virtual→real` when `--port-remap` is active; see
[`network.md`](network.md#port-virtualization).

## Generating a profile

`sandlock learn` runs a workload under observation and emits a profile
covering the paths, network endpoints, and resource peaks it actually
used. See [`learn.md`](learn.md).
