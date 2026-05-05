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

# Unrestricted outbound — `:*` opens any host and any port. UDP socket
# creation is still gated by --allow-udp; pair the two for full egress.
sandlock run --net-allow :* --allow-udp -r /usr -r /lib -r /etc -- ./client

# UDP — opt in to UDP and allowlist the destination (e.g. DNS)
sandlock run --allow-udp --net-allow 1.1.1.1:53 --net-allow :443 \
  -r /usr -r /lib -r /etc -- ./client

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
  --https-ca ca.pem --https-key ca-key.pem \
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
from sandlock import Sandbox, Policy, confine

policy = Policy(
    fs_writable=["/tmp/sandbox"],
    fs_readable=["/usr", "/lib", "/etc"],
    max_memory="256M",
    max_processes=10,
    clean_env=True,
)

# Run a command (with optional timeout in seconds)
result = Sandbox(policy).run(["python3", "-c", "print('hello')"], timeout=30)
assert result.success
assert b"hello" in result.stdout

# HTTP ACL: only allow specific API calls
agent_policy = Policy(
    fs_readable=["/usr", "/lib", "/etc"],
    http_allow=["POST api.openai.com/v1/chat/completions"],
    http_deny=["* */admin/*"],
)
result = Sandbox(agent_policy).run(["python3", "agent.py"])

# Chroot with per-sandbox mount (Docker-style -v, no root needed)
chroot_policy = Policy(
    chroot="/opt/rootfs",
    fs_mount={"/work": "/tmp/sandbox-1/work"},  # maps /work inside chroot
    fs_readable=["/usr", "/bin", "/lib", "/etc"],
    cwd="/work",
)
result = Sandbox(chroot_policy).run(["python3", "task.py"])

# Port virtualization: query port mappings while sandbox is running
sb = Sandbox(Policy(port_remap=True, fs_readable=["/usr", "/lib", "/etc"]), name="api.local")
# sb.ports() returns {virtual_port: real_port} while running

# Confine the current process (Landlock filesystem only, irreversible)
confine(Policy(fs_readable=["/usr", "/lib"], fs_writable=["/tmp"]))

# Dry-run: see what files would change, then discard
policy = Policy(fs_writable=["."], workdir=".", fs_readable=["/usr", "/lib", "/bin", "/etc"])
result = Sandbox(policy).dry_run(["make", "build"])
for c in result.changes:
    print(f"{c.kind}  {c.path}")  # A=added, M=modified, D=deleted
```

### Pipeline

Chain sandboxed stages with the `|` operator — each stage has its own
independent policy. Data flows through kernel pipes.

```python
from sandlock import Sandbox, Policy

trusted = Policy(fs_readable=["/usr", "/lib", "/bin", "/etc", "/opt/data"])
restricted = Policy(fs_readable=["/usr", "/lib", "/bin", "/etc"])

# Reader can access data, processor cannot
result = (
    Sandbox(trusted).cmd(["cat", "/opt/data/secret.csv"])
    | Sandbox(restricted).cmd(["tr", "a-z", "A-Z"])
).run()
assert b"SECRET" in result.stdout
```

**XOA pattern** (eXecute Over Architecture) — planner generates code,
executor runs it with data access but no network:

```python
planner = Policy(fs_readable=["/usr", "/lib", "/bin", "/etc"])
executor = Policy(fs_readable=["/usr", "/lib", "/bin", "/etc", "/data"])

result = (
    Sandbox(planner).cmd(["python3", "-c", "print('cat /data/input.txt')"])
    | Sandbox(executor).cmd(["sh"])
).run()
```

### Dynamic Policy (policy_fn)

Inspect syscall events at runtime and adjust permissions on the fly.
Events carry syscall name, category, PID, network destination (for
`connect`/`sendto`/`bind`), and `argv` (for `execve`). The callback
returns a verdict to allow, deny, or audit.

```python
from sandlock import Sandbox, Policy
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

policy = Policy(
    fs_readable=["/usr", "/lib", "/etc"],
    net_allow=["api.example.com:443"],
)
result = Sandbox(policy, policy_fn=on_event).run(["python3", "agent.py"])
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
use sandlock_core::{Policy, Sandbox, Pipeline, Stage, confine_current_process};

// Basic run
let policy = Policy::builder()
    .fs_read("/usr").fs_read("/lib")
    .fs_write("/tmp")
    .max_memory(ByteSize::mib(256))
    .build()?;
let result = Sandbox::run(&policy, &["echo", "hello"]).await?;
assert!(result.success());

// HTTP ACL: restrict API access at the HTTP level
let policy = Policy::builder()
    .fs_read("/usr").fs_read("/lib").fs_read("/etc")
    .http_allow("POST api.openai.com/v1/chat/completions")
    .http_deny("* */admin/*")
    .build()?;
let result = Sandbox::run(&policy, &["python3", "agent.py"]).await?;

// Confine the current process (Landlock filesystem only, irreversible)
let policy = Policy::builder()
    .fs_read("/usr").fs_read("/lib")
    .fs_write("/tmp")
    .build()?;
confine_current_process(&policy)?;

// Pipeline
let result = (
    Stage::new(&policy_a, &["echo", "hello"])
    | Stage::new(&policy_b, &["tr", "a-z", "A-Z"])
).run(None).await?;

// Dynamic policy
use sandlock_core::policy_fn::Verdict;
let policy = Policy::builder()
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
```

## Profiles

Save reusable policies as TOML files in `~/.config/sandlock/profiles/`:

```toml
# ~/.config/sandlock/profiles/build.toml
fs_writable = ["/tmp/work"]
fs_readable = ["/usr", "/lib", "/lib64", "/bin", "/etc"]
clean_env = true
max_memory = "512M"
max_processes = 50

[env]
CC = "gcc"
LANG = "C.UTF-8"
```

```bash
sandlock profile list
sandlock profile show build
sandlock run -p build -- make -j4
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

### COW Filesystem

Two modes of copy-on-write filesystem isolation:

**Seccomp COW** (default when `workdir` is set): Intercepts filesystem
syscalls via seccomp notification. Writes go to an upper directory;
reads resolve upper-then-lower. No mount namespace, no root. Committed
on exit, aborted on error.

**OverlayFS COW**: Uses kernel OverlayFS in a user namespace. Requires
unprivileged user namespaces to be enabled.

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
from sandlock import Sandbox, Policy

def init():
    global model, data
    model = load_model()          # 2 GB, loaded once
    data = preprocess_dataset()

def work(clone_id):
    shard = data[clone_id::4]
    print(sum(shard))             # stdout → per-clone pipe

# Map: fork 4 clones with separate policies
mapper = Sandbox(data_policy, init_fn=init, work_fn=work)
clones = mapper.fork(4)

# Reduce: pipe clone outputs to reducer stdin
result = Sandbox(reduce_policy).reduce(
    ["python3", "-c", "import sys; print(sum(int(l) for l in sys.stdin))"],
    clones,
)
print(result.stdout)  # b"total\n"
```

```rust
let mut mapper = Sandbox::new_with_fns(&map_policy,
    || { load_data(); },
    |id| { println!("{}", compute(id)); },
)?;
let mut clones = mapper.fork(4).await?;

let reducer = Sandbox::new(&reduce_policy)?;
let result = reducer.reduce(
    &["python3", "-c", "import sys; print(sum(int(l) for l in sys.stdin))"],
    &mut clones,
).await?;
```

Map and reduce run in separate sandboxes with independent policies —
the mapper has data access, the reducer doesn't. Each clone inherits
Landlock + seccomp confinement. `CLONE_ID=0..N-1` is set automatically.

### Network Model

Outbound traffic is gated by a single endpoint allowlist. Each
`--net-allow` rule names a `(host, ports)` pair, multiple rules are
OR'd, and a destination is permitted iff `(IP, port)` matches at least
one rule. The same allowlist applies to TCP `connect()` and to UDP
`sendto` / `sendmsg` destinations — the latter only relevant when
`--allow-udp` is set, since UDP socket creation is denied by default.

```
--net-allow <spec>          repeatable; no rules = deny all outbound
                            <spec> = host:port[,port,...]   (IP-restricted)
                                   | :port  | *:port        (any IP, listed port)
                                   | host:*                 (host, any port)
                                   | :*  | *:*              (any IP, any port)
```

**Defaults.** With no `--net-allow` and no HTTP ACL flags, Landlock
denies every TCP `connect()`, UDP and raw socket creation are denied
at the seccomp layer, and there is no on-behalf path active. For
unrestricted egress, opt in explicitly with `--net-allow :*` (still
UDP-gated by `--allow-udp`).

**Resolution.** Concrete hostnames are resolved once at sandbox start
and pinned in a synthetic `/etc/hosts`. The synthetic file replaces
the real one only when `--net-allow` includes at least one concrete
host; pure `:port` rules leave the real `/etc/hosts` and DNS visible.

**Wildcards.** Hostnames are matched literally — `--net-allow
*.example.com:443` is **not** supported, list each domain you need.
The `*` token is allowed in two positions: as the host (alias for
empty: `*:port` ≡ `:port`) and as the port to mean "any port"
(`host:*`, `:*`, `*:*`). Mixing `*` with concrete ports
(`host:80,*`) is rejected — use either the wildcard or an explicit
list. When any rule uses the all-ports wildcard, Landlock no longer
filters TCP connect at the kernel level (it cannot express "every
port" without enumerating 65535 rules); the on-behalf path becomes
the sole enforcer, and for `:*` it short-circuits to allow-all.

**Implementation.** Two enforcement paths:

  * **Direct path** — pure `:port` policies (no concrete host) and no
    HTTP ACL. Landlock enforces the TCP port allowlist at the kernel
    level; no per-syscall overhead. UDP is not covered by Landlock and
    therefore always uses the on-behalf path when allowed.
  * **On-behalf path** — any concrete host, any HTTP ACL rule, or
    `--allow-udp`. Seccomp traps `connect()`, `sendto()`, and
    `sendmsg()`; the supervisor checks the `(ip, port)` against the
    resolved allowlist and performs the syscall. The HTTP/HTTPS proxy
    redirect (when configured) happens here too.

**HTTP / HTTPS interception.** `--http-allow` / `--http-deny` route
matching ports through a transparent proxy. Each rule with a concrete
host auto-extends `--net-allow` with `host:80` (and `host:443` when
`--https-ca` is set) so the proxy's intercept ports are reachable;
wildcard hosts auto-add `:80` / `:443` (any IP). HTTPS MITM is opt-in:
pass `--https-ca <cert>` and `--https-key <key>` for a CA *you generate*
and trust inside the sandbox (typically install the cert into the
workload's `/etc/ssl/certs/`). Without `--https-ca`, port 443 is not
intercepted — `--net-allow host:443` permits raw TLS to the host with
no content inspection.

**Bind.** `--net-bind <port>` is independent from `--net-allow` and
governs server-side `bind()`. Landlock enforces it; `--port-remap` adds
on-behalf virtualization for binding.

**UDP, ICMP, unix.** Default-deny, opt in via dedicated flags:

  * `--allow-udp` enables UDP socket creation. Outbound UDP
    destinations are then gated by the same `--net-allow` allowlist
    used for TCP — the seccomp on-behalf path also covers `sendto` /
    `sendmsg`. Example: `--allow-udp --net-allow 1.1.1.1:53` for DNS.
  * `--allow-icmp` narrowly permits `socket(AF_INET, SOCK_RAW,
    IPPROTO_ICMP)` and the IPv6 equivalent only — enough for `ping`.
    Other raw socket types stay denied.
  * AF_UNIX sockets are governed by Landlock's
    `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`.

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

## Policy Reference

```python
Policy(
    # Filesystem (Landlock)
    fs_writable=["/tmp"],          # Read/write access
    fs_readable=["/usr", "/lib"],  # Read-only access
    fs_denied=["/proc/kcore"],     # Explicitly denied

    # Syscall filtering (seccomp)
    deny_syscalls=None,            # None = default blocklist
    allow_syscalls=None,           # Allowlist mode (stricter)

    # Network — see "Network Model" above. Each entry is `host:port[,port,...]`,
    # `:port`, `*:port`, `host:*`, or `:*` / `*:*`. Empty list = deny all
    # outbound; `:*` = unrestricted. Same allowlist gates UDP destinations
    # when allow_udp=True (e.g. `:53` for DNS).
    net_allow=["api.example.com:443", "github.com:22,443", ":8080"],
    net_bind=[8080],               # TCP bind ports (Landlock; ABI v4+)

    # HTTP ACL (transparent proxy)
    http_allow=["POST api.openai.com/v1/*"],  # Allow rules (METHOD host/path)
    http_deny=["* */admin/*"],     # Deny rules (checked first)
    http_ports=[80],               # Ports to intercept (default: [80])
    https_ca="ca.pem",             # CA cert for HTTPS MITM (adds port 443)
    https_key="ca-key.pem",        # CA key for HTTPS MITM

    # Socket restrictions (raw sockets and UDP denied by default)
    allow_udp=False,               # CLI: --allow-udp; outbound UDP still gated by net_allow
    allow_icmp=False,              # CLI: --allow-icmp; permits ICMP raw only (AF_INET/AF_INET6 + SOCK_RAW + IPPROTO_ICMP[V6])

    # Resources
    max_memory="512M",             # Memory limit
    max_processes=64,              # Peak concurrent process limit
    max_cpu=50,                    # CPU throttle (% of one core)
    max_open_files=256,            # fd limit
    port_remap=False,              # Virtual port space


    # Deterministic execution
    time_start="2000-01-01T00:00:00",  # Frozen time
    random_seed=42,                # Deterministic getrandom()
    no_randomize_memory=False,     # Disable ASLR
    no_huge_pages=False,           # Disable THP
    no_coredump=False,             # Disable core dumps

    # Environment
    clean_env=False,               # Minimal env
    env={"KEY": "value"},          # Override env vars

    # Chroot + mount mapping
    chroot=None,                   # Path to chroot into
    fs_mount={"/work": "/host/sandbox/work"},  # Map virtual paths to host dirs

    # COW isolation
    workdir=None,                  # COW root directory
    cwd=None,                      # Child working directory
    fs_isolation=FsIsolation.NONE, # NONE | OVERLAYFS | BRANCHFS
    on_exit=BranchAction.COMMIT,   # COMMIT | ABORT | KEEP
    on_error=BranchAction.ABORT,

    # Misc
    uid=None,                      # Map to given UID in user namespace (e.g. 0 for fake root)
)
```
