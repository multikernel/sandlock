# Network Model

Sandlock gates outbound traffic with Landlock TCP port rules where the
kernel can express the policy, and with a seccomp on-behalf path in the
supervisor everywhere else. This page covers the endpoint grammar shared
by `--net-allow` and `--net-deny`, protocol gating, HTTP-level access
control, server-side bind rules, and port virtualization. Field types and
defaults are in [`sandbox-reference.md`](sandbox-reference.md#network).

## Endpoint grammar

Outbound traffic is gated by an endpoint list naming
**protocol × destination**. `--net-allow` (allowlist) and `--net-deny`
(denylist) share one grammar. When both are present, a destination must pass
the allowlist and must not match the denylist (deny wins overlaps):

```
<spec>     repeatable; the port is optional (a bare target = all ports)
  target   host | <ip> | <cidr> | *           (`*` or empty target = any IP)
  forms    target[:port[,port,...]] · :port · host:* · :* · *:*
           [<ipv6|cidr>]:port                  (bracket IPv6 when a port follows)
  scheme   none = tcp + udp · tcp:// · udp:// (`udp://*` = any UDP) · icmp:// (no port)

  --net-allow  target may also be a hostname, resolved via DNS at start
  --net-deny   target must be a literal IP/CIDR (no hostnames; use --http-deny)
```

A spec with no scheme applies to both TCP and UDP (it expands to one
rule per protocol at parse time); a scheme pins the spec to that one
protocol. ICMP is never implied and always needs `icmp://`.

A comma groups ports within one spec (`host:80,443`); to pass multiple
rules, repeat the flag. IP and CIDR targets are matched by containment
with no DNS (an IP literal is a `/32` or `/128`); only hostnames resolve.

Multiple rules within each list are OR'd. With `--net-allow` alone, a
destination is permitted iff some allow rule matches the **same protocol** as
the socket plus the destination IP and port (port is N/A for ICMP). When
`--net-deny` is also present, the destination must not match any deny rule.

**Protocol gating** falls out of rule presence per scheme:

  * No UDP rule → UDP socket creation is denied at the seccomp layer
    (a scheme-less rule counts for both TCP and UDP).
  * No ICMP rule → kernel ping socket creation (SOCK_DGRAM + IPPROTO_ICMP)
    is denied at the seccomp layer.
  * Raw ICMP (SOCK_RAW + IPPROTO_ICMP) is **never exposed**; packet
    crafting is out of scope. Workloads that need ping should rely on
    the host's `net.ipv4.ping_group_range` and use the dgram path
    above (`--net-allow icmp://...`).
  * TCP is always permitted at the syscall level; destinations are
    governed by Landlock and/or the on-behalf path.

**Defaults.** With no `--net-allow` and no HTTP ACL flags, Landlock
denies every TCP `connect()`, UDP / ICMP / raw socket creation are
denied at the seccomp layer, and there is no on-behalf path active.
For unrestricted TCP and UDP egress, opt in explicitly with
`--net-allow '*'`; ICMP needs its own `--net-allow 'icmp://*'`.

**Denylist (`--net-deny`).** The inverse of the allowlist: networking is
default-allow and the listed targets are blocked. When combined with
`--net-allow`, denied destinations win. It uses the same
grammar as `--net-allow` above, the only difference being that targets
must be literal IPs/CIDRs (hostnames are rejected; use `--http-deny` for
domains). Examples:

```
--net-deny 10.0.0.0/8               # all ports on a CIDR (TCP and UDP)
--net-deny 169.254.169.254:80      # one IP, one port (TCP and UDP)
--net-deny 169.254.169.254:80,443  # comma-separated ports in one rule
--net-deny '*'                     # any IP, all ports (TCP and UDP)
--net-deny 'udp://192.168.0.0/16'  # UDP only, to a CIDR
--net-deny 'tcp://10.0.0.1:22'     # TCP only, one IP and port
```

When both lists are present the allowlist minus the denylist applies;
deny always wins an overlap:

```
--net-allow ':443' --net-deny 10.0.0.0/8   # allow HTTPS generally, except the denied CIDR
```

**Resolution.** Only hostname targets touch DNS: they are resolved once
at sandbox start and pinned in a synthetic `/etc/hosts` (across all
protocols). IP and CIDR targets are matched by containment directly, so
they never resolve and never appear in `/etc/hosts`. The synthetic file
replaces the real one only when at least one rule has a concrete
hostname; rules made purely of IPs/CIDRs, `:port`, `udp://*`, or
`icmp://*` leave the real `/etc/hosts` and DNS visible.

**Wildcards.** Hostnames are matched literally: `--net-allow
*.example.com:443` is **not** supported, list each domain you need (or
use a CIDR/IP target for an address range). The `*` token is allowed as
the target (alias for empty: `*:port` ≡ `:port`) and as the port for
TCP/UDP rules (`host:*`, `:*`, `*:*`).
The port is optional: omitting it means all ports, so `host` ≡
`host:*` and `*` ≡ `:*` ≡ `*:*` (and `udp://*` ≡ `udp://*:*`). Mixing
`*` with concrete ports (`host:80,*`) is rejected. When any TCP rule
uses the all-ports wildcard, Landlock no
longer filters TCP connect at the kernel level (it cannot express
"every port" without enumerating 65535 rules); the on-behalf path
becomes the sole enforcer, and for `:*` it short-circuits to
allow-all.

**Implementation.** Two enforcement paths:

  * **Direct path**: pure `:port` TCP policies (any IP, no concrete
    host/IP/CIDR) and no HTTP ACL. Landlock enforces the TCP port
    allowlist at the kernel level; no per-syscall overhead. UDP and ICMP
    are not covered by Landlock and always use the on-behalf path when
    allowed.
  * **On-behalf path**: any host, IP, or CIDR target, any HTTP ACL
    rule, or any UDP / ICMP rule (the destination IP must be checked,
    which Landlock cannot do). Seccomp traps `connect()`, `sendto()`,
    `sendmsg()`,
    and `sendmmsg()`; the supervisor dups the child fd, queries
    `getsockopt(SOL_SOCKET, SO_PROTOCOL)` to learn whether the socket
    is TCP / UDP / ICMP, then checks the destination against that
    protocol's resolved allow/deny layers before performing the syscall.
    The HTTP/HTTPS proxy redirect (when configured) happens here too.

**HTTP / HTTPS interception.** `--http-allow` / `--http-deny` route
matching ports through a transparent proxy. Each rule with a concrete
host generates a `host:80` reachability rule (and `host:443` when
`--http-ca` is set) at resolution time so the proxy's intercept ports
are reachable; wildcard hosts generate `:80` / `:443` (any IP). All
generated entries are TCP and are merged only at enforcement; they are
never stored in `--net-allow`. HTTPS MITM is enabled two ways: pass `--http-ca <cert>`
and `--http-key <key>` to bring your own CA, or pass `--http-inject-ca
<bundle>` to have sandlock generate an ephemeral CA (private key in
memory only) and splice its public cert into each named trust bundle at
open time, so the workload trusts the proxy with no manual install. For
runtimes with a compiled-in CA store such as Node, `--http-ca-out
<path>` writes the public cert so you can point the runtime's own env
var at it (e.g. `NODE_EXTRA_CA_CERTS`). Without any of these, port 443
is not intercepted: `--net-allow host:443` permits raw TLS to the host
with no content inspection.

**Bind.** `--net-allow-bind <ports>` is independent from `--net-allow` and
governs server-side `bind()` as a default-deny allowlist. Each value is a
comma-separated list of single ports or inclusive `lo-hi` ranges (e.g.
`--net-allow-bind 8080,9000-9005`), and the flag repeats. Only the `'*'`
wildcard allows binding any port, including an ephemeral `bind(0)`; a listed
port `0` authorizes only a `bind(0)` request. The wildcard cannot be mixed
with port lists (repeating the bare wildcard is fine). Landlock enforces the
allowlist (TCP only; the wildcard simply leaves Landlock's `BIND_TCP` hook
unhandled). When network supervision is active (`--net-allow`, `--net-deny`,
`--http-allow`, `--port-remap`, a policy function) `bind()` runs on the
supervisor's on-behalf path, which enforces the same allowlist.
`--net-deny-bind <ports>` is the inverse: default-allow binding, deny the
listed TCP ports (same port syntax). When both bind flags are present, a port
must pass the allowlist and must not match the denylist. Because Landlock is
allowlist-only, a deny-bind relaxes the Landlock `BIND_TCP` hook and enforces
the denylist on the on-behalf seccomp `bind()` path instead.

**AF_UNIX sockets** are governed by Landlock's
`LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, independent from `--net-allow`.

## HTTP ACL and credentials

```bash
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
```

Rule syntax, MITM setup, and credential injection are described in full
under [`sandbox-reference.md#config`](sandbox-reference.md#config).

## Port Virtualization

Each sandbox gets a full virtual port space. Multiple sandboxes can bind
the same port without conflicts. The supervisor performs `bind()` on behalf
of the child via `pidfd_getfd` (TOCTOU-safe). When a port conflicts, a
different real port is allocated transparently. Socket tables under `/proc/net` show only sockets held by sandbox tasks,
with remapped local ports translated back to their virtual values.

Use `sandlock ps` to see all running sandboxes and their port mappings,
and `sandlock kill` to stop them (see [`cli.md`](cli.md#managing-running-sandboxes)).

```bash
# Multiple sandboxes can bind the same port
sandlock run --port-remap --net-allow-bind 6379 -r /usr -r /lib -r /etc -- redis-server --port 6379

# Named sandboxes enable network discovery by name
sandlock run --name api.local --port-remap --net-allow-bind 8080 -r /usr -r /lib -r /etc -- python3 server.py
sandlock run --name web.local --port-remap --net-allow-bind 8080 -r /usr -r /lib -r /etc -- python3 server.py
```

This enables external reverse proxies (nginx, envoy) to route traffic
by name to the correct real port.

## Network information in procfs

With read access to `/proc`, Sandlock exposes a fixed `/proc/net` directory.
`dev`, `if_inet6`, `route`, `ipv6_route`, `fib_trie`, and `arp` describe a
loopback-only topology. `tcp`, `tcp6`, `udp`, `udp6`, and `unix` contain only
verified sockets held by sandbox tasks, whether port remapping is enabled
or disabled. `sockstat` and `sockstat6` count those sockets; untracked memory,
orphan, TIME_WAIT, and fragment counters are zero. Other entries are absent.
Per-task spellings such as `/proc/self/net` expose the same view.

Each file open produces a read-only snapshot. Sockets without a live task
file descriptor, including ownerless TIME_WAIT sockets, are omitted. Internal
virtual netlink transports and Unix socket paths that cannot be mapped into
the sandbox are omitted too. Network files do not expose host-wide traffic
counters. `O_PATH` opens return `EOPNOTSUPP` because seccomp cannot inject
that descriptor type.

The supervisor matches `NETLINK_SOCK_DIAG` records against `SO_COOKIE` values
from pinned task descriptors. Inode numbers remain in the output for procfs
compatibility, but do not authorize visibility. These read-only queries need
no additional capabilities in the supervisor's network namespace. An empty
ownership snapshot returns only the table header without a diagnostic query.
The supervisor reuses one pidfd throughout each task's descriptor scan. The sandbox
continues to deny direct socket diagnostic access. The kernel must provide
INET, TCP, UDP, and UNIX diagnostic support for their respective tables;
failed or interrupted dumps return an error without an inode-based fallback.
Reference counts and counters unavailable through diagnostics are zero. UNIX
names that cannot be represented as UTF-8 on one line are omitted.
