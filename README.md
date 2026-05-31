# Sandlock

Lightweight process sandbox for Linux. Confines untrusted code using
**Landlock** (filesystem + network + IPC), **seccomp-bpf** (syscall filtering),
and **seccomp user notification** (resource limits, IP enforcement, /proc
virtualization). No root, no cgroups, no containers.

```
sandlock run -w /tmp -r /usr -r /lib -m 512M -- python3 untrusted.py
```

## Why Sandlock?

Containers and VMs are powerful but heavy. Sandlock targets the gap: strict
confinement without image builds or root privileges. Built-in COW filesystem
protects your working directory automatically.

| Feature | Sandlock | Container | MicroVM (Firecracker) |
|---|---|---|---|
| Root required | No | Yes* | Yes (KVM) |
| Image build | No | Yes | Yes |
| Startup time | ~5 ms | ~200 ms | ~100 ms |
| Kernel | Shared | Shared | Separate guest |
| Filesystem isolation | Landlock + seccomp COW | Overlay | Block-level |
| Network isolation | Landlock + seccomp notif | Network namespace | TAP device |
| HTTP-level ACL | Method + host + path rules | N/A | N/A |
| Syscall filtering | seccomp-bpf | seccomp | N/A |
| Resource limits | seccomp notif + SIGSTOP | cgroup v2 | VM config |

\* Rootless containers exist but require user namespace support and `/etc/subuid` configuration.

## Architecture

Sandlock is implemented in **Rust** for performance and safety:

- **sandlock-core** — Rust library: Landlock, seccomp, supervisor, COW, pipeline
- **sandlock-cli** — Rust CLI binary (`sandlock run ...`)
- **sandlock-ffi** — C ABI shared library (`libsandlock_ffi.so`)
- **Python SDK** — ctypes bindings to the FFI library

```
                    ┌─────────────┐
                    │  Python SDK │  ctypes FFI
                    │  (sandlock) │──────────────┐
                    └─────────────┘              │
                                                 ▼
┌──────────────┐    ┌──────────────────────────────┐
│ sandlock CLI │───>│       libsandlock_ffi.so      │
└──────────────┘    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │        sandlock-core          │
                    │  Landlock · seccomp · COW ·   │
                    │  pipeline · policy_fn · vDSO  │
                    └──────────────────────────────┘
```

## Requirements

- **Linux 6.12+** (Landlock ABI v6), **Rust 1.70+** (to build)
- **Python 3.8+** (optional, for Python SDK)
- No root, no cgroups

| Feature | Minimum kernel |
|---|---|
| seccomp user notification | 5.6 |
| Landlock filesystem rules | 5.13 |
| Landlock TCP port rules | 6.7 (ABI v4) |
| Landlock IPC scoping | 6.12 (ABI v6) |

## Install

### From source

```bash
# Build the Rust binary and shared library
cargo build --release

# Install Python SDK (auto-builds Rust FFI library)
cd python && pip install -e .
```

### CLI only

```bash
cargo install --path crates/sandlock-cli
```

## Quick Start

### CLI

```bash
# Basic confinement
sandlock run -r /usr -r /lib -w /tmp -- ls /tmp

# Interactive shell
sandlock run -i -r /usr -r /lib -r /lib64 -r /bin -r /etc -w /tmp -- /bin/sh

# Resource limits + timeout
sandlock run -m 512M -P 20 -t 30 -- ./compute.sh

# Outbound allowlist — restrict to one host on one port
sandlock run --net-allow api.openai.com:443 -r /usr -r /lib -r /etc -- python3 agent.py

# Multiple ports for one host, plus a separate any-IP port
sandlock run --net-allow github.com:22,443 --net-allow :8080 \
  -r /usr -r /lib -r /etc -- python3 agent.py

# Wildcard port — `host:*` permits every port to the host
sandlock run --net-allow github.com:* -r /usr -r /lib -r /etc -- ssh user@github.com

# Unrestricted outbound — `:*` opens any host and any TCP port. For full
# egress add a UDP wildcard via the `udp://*:*` scheme.
sandlock run --net-allow :* --net-allow udp://*:* \
  -r /usr -r /lib -r /etc -- ./client

# UDP — scheme prefix gates the protocol and scopes the destination
# (e.g. DNS to 1.1.1.1, plus TCP HTTPS to anywhere)
sandlock run --net-allow udp://1.1.1.1:53 --net-allow :443 \
  -r /usr -r /lib -r /etc -- ./client

# Ping — kernel ping socket (SOCK_DGRAM) gated by net.ipv4.ping_group_range
sandlock run --net-allow icmp://github.com -r /usr -r /lib -r /etc -- ping github.com

# HTTP-level ACL (method + host + path rules via transparent proxy)
# HTTP rules with concrete hosts auto-extend --net-allow with host:80,443
sandlock run \
  --http-allow "GET docs.python.org/*" \
  --http-allow "POST api.openai.com/v1/chat/completions" \
  --http-deny "* */admin/*" \
  -r /usr -r /lib -r /etc -- python3 agent.py

# HTTPS MITM with user-provided CA (enables ACL on port 443)
# Generate a CA, add the cert to the sandbox's trust store
# (e.g. /etc/ssl/certs/), then pass both files here.
sandlock run \
  --http-allow "POST api.openai.com/v1/*" \
  --http-ca ca.pem --http-key ca-key.pem \
  -r /usr -r /lib -r /etc -- python3 agent.py

# Server listening on a port (Landlock --net-bind, separate from --net-allow)
sandlock run --net-bind 8080 -r /usr -r /lib -r /etc -- python3 server.py

# Clean environment
sandlock run --clean-env --env CC=gcc \
  -r /usr -r /lib -w /tmp -- make

# Deterministic execution (frozen time + seeded randomness)
sandlock run --time-start "2000-01-01T00:00:00Z" --random-seed 42 -- ./build.sh

# Port virtualization (multiple sandboxes can bind the same port)
sandlock run --port-remap --net-bind 6379 -r /usr -r /lib -r /etc -- redis-server --port 6379

# Port virtualization with named sandboxes (enables network discovery)
sandlock run --name api.local --port-remap --net-bind 8080 -r /usr -r /lib -r /etc -- python3 server.py
sandlock run --name web.local --port-remap --net-bind 8080 -r /usr -r /lib -r /etc -- python3 server.py

# List all running sandboxes
sandlock list

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

### Python API

```python
from sandlock import Sandbox, confine

sandbox = Sandbox(
    fs_writable=["/tmp/sandbox"],
    fs_readable=["/usr", "/lib", "/etc"],
    max_memory="256M",
    max_processes=10,
    clean_env=True,
)

# Run a command (with optional timeout in seconds)
result = sandbox.run(["python3", "-c", "print('hello')"], timeout=30)
assert result.success
assert b"hello" in result.stdout

# HTTP ACL: only allow specific API calls
agent = Sandbox(
    fs_readable=["/usr", "/lib", "/etc"],
    http_allow=["POST api.openai.com/v1/chat/completions"],
    http_deny=["* */admin/*"],
)
result = agent.run(["python3", "agent.py"])

# Chroot with per-sandbox mount (Docker-style -v, no root needed)
chrooted = Sandbox(
    chroot="/opt/rootfs",
    fs_mount={"/work": "/tmp/sandbox-1/work"},  # maps /work inside chroot
    fs_readable=["/usr", "/bin", "/lib", "/etc"],
    cwd="/work",
)
result = chrooted.run(["python3", "task.py"])

# Port virtualization: query port mappings while sandbox is running
sb = Sandbox(port_remap=True, fs_readable=["/usr", "/lib", "/etc"], name="api.local")
# sb.ports() returns {virtual_port: real_port} while running

# Confine the current process (Landlock filesystem only, irreversible)
confine(Sandbox(fs_readable=["/usr", "/lib"], fs_writable=["/tmp"]))

# Dry-run: see what files would change, then discard
sandbox = Sandbox(fs_writable=["."], workdir=".", fs_readable=["/usr", "/lib", "/bin", "/etc"])
result = sandbox.dry_run(["make", "build"])
for c in result.changes:
    print(f"{c.kind}  {c.path}")  # A=added, M=modified, D=deleted
```

### Pipeline

Chain sandboxed stages with the `|` operator — each stage has its own
independent sandbox config. Data flows through kernel pipes.

```python
from sandlock import Sandbox

trusted = Sandbox(fs_readable=["/usr", "/lib", "/bin", "/etc", "/opt/data"])
restricted = Sandbox(fs_readable=["/usr", "/lib", "/bin", "/etc"])

# Reader can access data, processor cannot
result = (
    trusted.cmd(["cat", "/opt/data/secret.csv"])
    | restricted.cmd(["tr", "a-z", "A-Z"])
).run()
assert b"SECRET" in result.stdout
```

**XOA pattern** (eXecute Over Architecture) — planner generates code,
executor runs it with data access but no network:

```python
planner = Sandbox(fs_readable=["/usr", "/lib", "/bin", "/etc"])
executor = Sandbox(fs_readable=["/usr", "/lib", "/bin", "/etc", "/data"])

result = (
    planner.cmd(["python3", "-c", "print('cat /data/input.txt')"])
    | executor.cmd(["sh"])
).run()
```

### Dynamic Policy (policy_fn)

Inspect syscall events at runtime and adjust permissions on the fly.
Events carry syscall name, category, PID, network destination (for
`connect`/`sendto`/`bind`), and `argv` (for `execve`). The callback
returns a verdict to allow, deny, or audit.

```python
from sandlock import Sandbox
import errno

def on_event(event, ctx):
    # Block download tools by argv
    if event.syscall == "execve" and event.argv_contains("curl"):
        return True  # deny

    # Deny connections to a specific IP
    if event.syscall == "connect" and event.host == "10.0.0.5":
        return errno.EACCES

    # Lock down once the program has finished starting up
    if event.syscall == "execve":
        ctx.restrict_network([])           # block all network
        ctx.deny_path("/etc/shadow")       # dynamic fs deny

    # Audit every file access (allow but flag)
    if event.category == "file":
        return "audit"

    return 0  # allow

sandbox = Sandbox(
    fs_readable=["/usr", "/lib", "/etc"],
    net_allow=["api.example.com:443"],
    policy_fn=on_event,
)
result = sandbox.run(["python3", "agent.py"])
```

**Verdicts:** `0`/`False` = allow, `True`/`-1` = deny (EPERM),
positive int = deny with errno, `"audit"`/`-2` = allow + flag.

**Event fields:** `syscall`, `category` (file/network/process/memory),
`pid`, `parent_pid`, `host`, `port`, `argv`, `denied`.

> **TOCTOU NOTE** Per `seccomp_unotify(2)`, the kernel
> re-reads user-memory pointers after `Continue`. Sandlock handles this
> in two places:
>
> - **Path strings are not exposed on events.** Path-based access control
>   belongs in static Landlock rules (`fs_readable` / `fs_writable` /
>   `fs_denied`) — kernel-enforced and TOCTOU-immune. Use
>   `ctx.deny_path()` for runtime additions.
> - **`event.argv` is exposed and TOCTOU-safe.** Before exposing
>   `argv` to `policy_fn` or returning `Continue` for an
>   `execve`, the supervisor freezes every task in `ProcessIndex`,
>   including peer processes that may alias argv through shared memory.
>   With `policy_fn` active, fork-like syscalls are traced for one
>   ptrace creation event, so children are registered in `ProcessIndex`
>   before they can run user code. If the freeze or creation tracking
>   cannot be established (e.g., YAMA blocks ptrace), the syscall is
>   denied with `EPERM`; the safety invariant is never silently relaxed.

**Context methods:**
- `ctx.restrict_network(ips)` / `ctx.grant_network(ips)` — network control
- `ctx.restrict_max_memory(bytes)` / `ctx.restrict_max_processes(n)` — resource limits
- `ctx.deny_path(path)` / `ctx.allow_path(path)` — dynamic filesystem restriction
- `ctx.restrict_pid_network(pid, ips)` — per-PID network override

**Held syscalls** (child blocked until callback returns): `execve`,
`connect`, `sendto`, `bind`, `openat`.

### Rust API

```rust
use sandlock_core::{confine, Confinement, Sandbox, Stage};
use sandlock_core::sandbox::ByteSize;
use sandlock_core::policy_fn::Verdict;

// Basic run
let mut sandbox = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib")
    .fs_write("/tmp")
    .max_memory(ByteSize::mib(256))
    .name("hello-box")
    .build()?;
let result = sandbox.run(&["echo", "hello"]).await?;
assert!(result.success());

// HTTP ACL: restrict API access at the HTTP level
let mut agent = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib").fs_read("/etc")
    .http_allow("POST api.openai.com/v1/chat/completions")
    .http_deny("* */admin/*")
    .name("agent-box")
    .build()?;
let result = agent.run(&["python3", "agent.py"]).await?;

// Confine the current process (Landlock filesystem only, irreversible)
let confinement = Confinement::builder()
    .fs_read("/usr").fs_read("/lib")
    .fs_write("/tmp")
    .build();
confine(&confinement)?;

// Pipeline
let producer = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib").fs_read("/bin")
    .build()?;
let consumer = producer.clone();
let result = (
    Stage::new(&producer, &["echo", "hello"])
    | Stage::new(&consumer, &["tr", "a-z", "A-Z"])
).run(None).await?;

// Dynamic policy
let mut dynamic = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib")
    .policy_fn(|event, ctx| {
        if event.argv_contains("curl") {
            return Verdict::Deny;
        }
        if event.syscall == "execve" {
            ctx.restrict_network(&[]);
            ctx.deny_path("/etc/shadow");
        }
        Verdict::Allow
    })
    .build()?;
let result = dynamic.run(&["python3", "agent.py"]).await?;
```

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
read = ["/usr", "/lib", "/lib64", "/bin", "/etc"]
write = ["/tmp/work"]

[limits]
memory = "512M"
processes = 50

[syscalls]
extra_deny = []
```

```bash
sandlock profile list
sandlock profile show build
sandlock run -p build        # uses [program].exec + args
sandlock run -p build -- make test  # trailing command overrides [program]
```

## How It Works

Sandlock applies confinement in sequence after `fork()`:

```
Parent                              Child
  │  fork()                           │
  │──────────────────────────────────>│
  │                                   ├─ 1. setpgid(0,0)
  │                                   ├─ 2. Optional: chdir(cwd)
  │                                   ├─ 3. NO_NEW_PRIVS
  │                                   ├─ 4. Landlock (fs + net + IPC)
  │                                   ├─ 5. seccomp filter (deny + notif)
  │                                   │     └─ send notif fd ──> Parent
  │  receive notif fd                 ├─ 6. Wait for "ready" signal
  │  start supervisor (tokio)         ├─ 7. Close fds 3+
  │  optional: vDSO patching          └─ 8. exec(cmd)
  │  optional: policy_fn thread
  │  optional: CPU throttle task
```

### Seccomp Supervisor

The async notification supervisor (tokio) handles intercepted syscalls:

| Syscall | Handler |
|---|---|
| `clone/fork/vfork` | Process count enforcement |
| `mmap/munmap/brk/mremap` | Memory limit tracking |
| `connect/sendto/sendmsg` | IP allowlist + on-behalf execution + HTTP ACL redirect |
| `bind` | On-behalf bind + port remapping |
| `openat` | /proc virtualization, COW interception |
| `unlinkat/mkdirat/renameat2` | COW write interception |
| `execve/execveat` | policy_fn hold + vDSO re-patching |
| `getrandom` | Deterministic PRNG injection |
| `clock_nanosleep/timer_settime` | Timer adjustment for frozen time |
| `getdents64` | PID filtering, COW directory merging |
| `getsockname` | Port remap translation |

### Custom Handlers

Downstream Rust crates can append their own seccomp-notification
handlers to the supervisor chain alongside the builtins, registering
for any syscall they care about via the `Handler` trait and
`Sandbox::run_with_handlers`. The builtin chain runs first, so
user handlers cannot subvert confinement; the registration step also
rejects handlers on syscalls in the default blocklist or
`extra_deny_syscalls`. See
[`docs/extension-handlers.md`](docs/extension-handlers.md) for the
full API, ordering semantics, and state patterns.

### COW Filesystem

Copy-on-write filesystem isolation via seccomp notification: when
`workdir` is set, sandlock intercepts filesystem syscalls and stages
writes in an upper directory; reads resolve upper-then-lower. No mount
namespace, no user namespace, no root. Committed on exit, aborted on
error.

**Dry-run mode**: `--dry-run` runs the command, inspects the COW layer
for changes (added/modified/deleted files), prints a summary, then
aborts — leaving the workdir completely untouched. Useful for previewing
what a command would do before committing.

### COW Fork & Map-Reduce

Initialize expensive state once, then fork COW clones that share memory.
Each clone uses raw `fork(2)` with shared copy-on-write pages. 1000
clones in ~530ms, ~1,900 forks/sec.

Each clone's stdout is captured via its own pipe. `reduce()` reads all
pipes and feeds combined output to a reducer's stdin — fully pipe-based
data flow with no temp files.

```python
from sandlock import Sandbox

def init():
    global model, data
    model = load_model()          # 2 GB, loaded once
    data = preprocess_dataset()

def work(clone_id):
    shard = data[clone_id::4]
    print(sum(shard))             # stdout → per-clone pipe

# Map: fork 4 clones with a separate sandbox config
mapper = Sandbox(
    fs_readable=["/usr", "/lib", "/bin", "/etc", "/data"],
    init_fn=init,
    work_fn=work,
)
clones = mapper.fork(4)

# Reduce: pipe clone outputs to reducer stdin
reducer = Sandbox(fs_readable=["/usr", "/lib", "/bin", "/etc"])
result = reducer.reduce(
    ["python3", "-c", "import sys; print(sum(int(l) for l in sys.stdin))"],
    clones,
)
print(result.stdout)  # b"total\n"
```

```rust
let mut mapper = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib").fs_read("/bin").fs_read("/etc")
    .fs_read("/data")
    .name("mapper")
    .init_fn(|| { load_data(); })
    .work_fn(|id| { println!("{}", compute(id)); })
    .build()?;
let mut clones = mapper.fork(4).await?;

let reducer = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib").fs_read("/bin").fs_read("/etc")
    .name("reducer")
    .build()?;
let result = reducer.reduce(
    &["python3", "-c", "import sys; print(sum(int(l) for l in sys.stdin))"],
    &mut clones,
).await?;
```

Map and reduce run in separate sandboxes with independent configs —
the mapper has data access, the reducer doesn't. Each clone inherits
Landlock + seccomp confinement. `CLONE_ID=0..N-1` is set automatically.

### Network Model

Outbound traffic is gated by a single endpoint allowlist that names
**protocol × destination**. Each `--net-allow` rule is one of:

```
--net-allow <spec>          repeatable; no rules = deny all outbound
  bare form  host:port[,port,...] / :port / *:port / host:* / :* / *:*   (TCP)
  tcp://     same suffix grammar — explicit TCP
  udp://     same suffix grammar — UDP (`udp://*:*` opens any UDP)
  icmp://    host or `*`, no port — kernel ping socket (SOCK_DGRAM)
```

Multiple rules are OR'd. A destination is permitted iff some rule
matches the **same protocol** as the socket plus the destination IP
and port (port is N/A for ICMP).

**Protocol gating** falls out of rule presence per scheme:

  * No UDP rule → UDP socket creation is denied at the seccomp layer.
  * No ICMP rule → kernel ping socket creation (SOCK_DGRAM + IPPROTO_ICMP)
    is denied at the seccomp layer.
  * Raw ICMP (SOCK_RAW + IPPROTO_ICMP) is **never exposed** — packet
    crafting is out of scope. Workloads that need ping should rely on
    the host's `net.ipv4.ping_group_range` and use the dgram path
    above (`--net-allow icmp://...`).
  * TCP is always permitted at the syscall level; destinations are
    governed by Landlock and/or the on-behalf path.

**Defaults.** With no `--net-allow` and no HTTP ACL flags, Landlock
denies every TCP `connect()`, UDP / ICMP / raw socket creation are
denied at the seccomp layer, and there is no on-behalf path active.
For unrestricted TCP egress, opt in explicitly with
`--net-allow :*`; for any UDP, add `--net-allow udp://*:*`.

**Resolution.** Concrete hostnames are resolved once at sandbox start
and pinned in a synthetic `/etc/hosts` (across all protocols). The
synthetic file replaces the real one only when at least one rule has
a concrete host; pure `:port` / `udp://*:*` / `icmp://*` rules leave
the real `/etc/hosts` and DNS visible.

**Wildcards.** Hostnames are matched literally — `--net-allow
*.example.com:443` is **not** supported, list each domain you need.
The `*` token is allowed as the host (alias for empty: `*:port` ≡
`:port`) and as the port for TCP/UDP rules (`host:*`, `:*`, `*:*`,
`udp://*:*`). Mixing `*` with concrete ports (`host:80,*`) is
rejected. When any TCP rule uses the all-ports wildcard, Landlock no
longer filters TCP connect at the kernel level (it cannot express
"every port" without enumerating 65535 rules); the on-behalf path
becomes the sole enforcer, and for `:*` it short-circuits to
allow-all.

**Implementation.** Two enforcement paths:

  * **Direct path** — pure `:port` TCP policies (no concrete host)
    and no HTTP ACL. Landlock enforces the TCP port allowlist at the
    kernel level; no per-syscall overhead. UDP and ICMP are not
    covered by Landlock and always use the on-behalf path when allowed.
  * **On-behalf path** — any concrete host, any HTTP ACL rule, or any
    UDP / ICMP rule. Seccomp traps `connect()`, `sendto()`, `sendmsg()`,
    and `sendmmsg()`; the supervisor dups the child fd, queries
    `getsockopt(SOL_SOCKET, SO_PROTOCOL)` to learn whether the socket
    is TCP / UDP / ICMP, then checks the destination against that
    protocol's resolved allowlist before performing the syscall.
    The HTTP/HTTPS proxy redirect (when configured) happens here too.

**HTTP / HTTPS interception.** `--http-allow` / `--http-deny` route
matching ports through a transparent proxy. Each rule with a concrete
host auto-extends `--net-allow` with `host:80` (and `host:443` when
`--http-ca` is set) so the proxy's intercept ports are reachable;
wildcard hosts auto-add `:80` / `:443` (any IP). All auto-added
entries are TCP. HTTPS MITM is opt-in: pass `--http-ca <cert>` and
`--http-key <key>` for a CA *you generate* and trust inside the
sandbox (typically install the cert into the workload's
`/etc/ssl/certs/`). Without `--http-ca`, port 443 is not intercepted
— `--net-allow host:443` permits raw TLS to the host with no content
inspection.

**Bind.** `--net-bind <port>` is independent from `--net-allow` and
governs server-side `bind()`. Landlock enforces it (TCP only);
`--port-remap` adds on-behalf virtualization for binding.

**AF_UNIX sockets** are governed by Landlock's
`LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, independent from `--net-allow`.

### Port Virtualization

Each sandbox gets a full virtual port space. Multiple sandboxes can bind
the same port without conflicts. The supervisor performs `bind()` on behalf
of the child via `pidfd_getfd` (TOCTOU-safe). When a port conflicts, a
different real port is allocated transparently. `/proc/net/tcp` is filtered
to only show the sandbox's own ports.

When `--port-remap` is enabled, the sandbox registers its state in a
shared registry (`/dev/shm`). Use `sandlock list` to see all running
sandboxes and `sandlock kill` to stop them:

```
$ sandlock list
NAME                    PID  PORTS
api.local            12345  8080
web.local            12346  8080 -> 35299

$ sandlock kill web.local
Killed sandbox 'web.local' (PID 12346)
```

This enables external reverse proxies (nginx, envoy) to route traffic
by name to the correct real port.

## Performance

Benchmarked on a typical Linux workstation:

| Workload | Bare metal | Sandlock | Docker | Sandlock overhead |
|---|---|---|---|---|
| `/bin/echo` startup | 2 ms | 7 ms | 307 ms | 5 ms (44x faster than Docker) |
| Redis SET (100K ops) | 82K rps | 80K rps | 52K rps | 97.1% of bare metal |
| Redis GET (100K ops) | 79K rps | 77K rps | 53K rps | 97.1% of bare metal |
| Redis p99 latency | 0.5 ms | 0.6 ms | 1.5 ms | ~2.5x lower than Docker |
| COW fork ×1000 | — | 530 ms | — | 530μs/fork, ~1,900 forks/sec |

## Testing

```bash
# Rust tests
cargo test --release

# Python tests
cd python && pip install -e . && pytest tests/
```

## Sandbox Reference

The full `Sandbox` configuration reference — every field, default,
and grouping — lives in [`docs/sandbox-reference.md`](docs/sandbox-reference.md).
