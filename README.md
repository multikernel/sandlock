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

- **Linux 5.13+** (Landlock ABI v1), **Rust 1.70+** (to build)
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

# Domain-based network isolation
sandlock run --net-allow-host api.openai.com -r /usr -r /lib -r /etc -- python3 agent.py

# TCP port restrictions (Landlock)
sandlock run --net-bind 8080 --net-connect 443 -r /usr -r /lib -r /etc -- python3 server.py

# IPC scoping + clean environment
sandlock run --isolate-ipc --isolate-signals --clean-env --env CC=gcc \
  -r /usr -r /lib -w /tmp -- make

# Deterministic execution (frozen time + seeded randomness)
sandlock run --time-start "2000-01-01T00:00:00" --random-seed 42 -- ./build.sh

# Port virtualization (multiple sandboxes can bind the same port)
sandlock run --port-remap --net-bind 6379 -r /usr -r /lib -r /etc -- redis-server --port 6379

# COW filesystem (writes captured, committed on success)
sandlock run --workdir /opt/project -r /usr -r /lib -- python3 task.py

# Use a saved profile
sandlock run -p build -- make -j4
```

### Python API

```python
from sandlock import Sandbox, Policy

policy = Policy(
    fs_writable=["/tmp/sandbox"],
    fs_readable=["/usr", "/lib", "/etc"],
    max_memory="256M",
    max_processes=10,
    isolate_ipc=True,
    clean_env=True,
)

# Run a command
result = Sandbox(policy).run(["python3", "-c", "print('hello')"])
assert result.success
assert b"hello" in result.stdout
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
Each event includes rich metadata: path, host, port, argv, category,
parent PID. The callback returns a verdict to allow, deny, or audit.

```python
from sandlock import Sandbox, Policy
import errno

def on_event(event, ctx):
    # Block download tools
    if event.syscall == "execve" and event.argv_contains("curl"):
        return True  # deny

    # Custom errno for sensitive files
    if event.category == "file" and event.path_contains("/secret"):
        return errno.EACCES

    # Restrict network after setup phase
    if event.syscall == "execve" and event.path_contains("untrusted"):
        ctx.restrict_network([])
        ctx.deny_path("/etc/shadow")

    # Audit file access (allow but flag)
    if event.category == "file":
        return "audit"

    return 0  # allow

policy = Policy(
    fs_readable=["/usr", "/lib", "/etc"],
    net_allow_hosts=["api.example.com"],
)
result = Sandbox(policy, policy_fn=on_event).run(["python3", "agent.py"])
```

**Verdicts:** `0`/`False` = allow, `True`/`-1` = deny (EPERM),
positive int = deny with errno, `"audit"`/`-2` = allow + flag.

**Event fields:** `syscall`, `category` (file/network/process/memory),
`pid`, `parent_pid`, `path`, `host`, `port`, `argv`, `denied`.

**Context methods:**
- `ctx.restrict_network(ips)` / `ctx.grant_network(ips)` — network control
- `ctx.restrict_max_memory(bytes)` / `ctx.restrict_max_processes(n)` — resource limits
- `ctx.deny_path(path)` / `ctx.allow_path(path)` — dynamic filesystem restriction
- `ctx.restrict_pid_network(pid, ips)` — per-PID network override

**Held syscalls** (child blocked until callback returns): `execve`,
`connect`, `sendto`, `bind`, `openat`.

### Rust API

```rust
use sandlock_core::{Policy, Sandbox, Pipeline, Stage};

// Basic run
let policy = Policy::builder()
    .fs_read("/usr").fs_read("/lib")
    .fs_write("/tmp")
    .max_memory(ByteSize::mib(256))
    .build()?;
let result = Sandbox::run(&policy, &["echo", "hello"]).await?;
assert!(result.success());

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
isolate_ipc = true
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
  │                                   ├─ 2. Optional: chdir(workdir)
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
| `connect/sendto/sendmsg` | IP allowlist + on-behalf execution |
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

### COW Fork

Initialize expensive state once, then fork COW clones that share memory.
Each fork uses raw `fork(2)` (bypasses seccomp notification) for minimal
overhead. 1000 clones in ~530ms, ~1,900 forks/sec.

```python
from sandlock import Sandbox, Policy

def init():
    global model, data
    model = load_model()          # 2 GB, loaded once
    data = preprocess_dataset()

def work(clone_id):
    result = rollout(model, data, clone_id)  # reads COW-shared globals
    save_result(result)

sb = Sandbox(policy, init_fn=init, work_fn=work)
pids = sb.fork(1000)  # 1000 clones, ~50 MB shared (not 50 GB)
```

```rust
let mut sb = Sandbox::new_with_fns(&policy,
    || { load_model(); },
    |clone_id| { rollout(clone_id); },
)?;
let pids = sb.fork(1000).await?;
```

Each clone inherits Landlock + seccomp confinement via `fork()`.
`CLONE_ID` environment variable is set to 0..N-1.

### Port Virtualization

Each sandbox gets a full virtual port space. Multiple sandboxes can bind
the same port without conflicts. The supervisor performs `bind()` on behalf
of the child via `pidfd_getfd` (TOCTOU-safe). When a port conflicts, a
different real port is allocated transparently. `/proc/net/tcp` is filtered
to only show the sandbox's own ports.

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

    # Network
    net_allow_hosts=["api.example.com"],  # Domain allowlist
    net_bind=[8080],               # TCP bind ports (Landlock ABI v4+)
    net_connect=[443],             # TCP connect ports

    # Socket restrictions
    no_raw_sockets=True,           # Block SOCK_RAW (default)
    no_udp=False,                  # Block SOCK_DGRAM

    # IPC scoping (Landlock ABI v6+)
    isolate_ipc=False,             # Block abstract UNIX sockets to host
    isolate_signals=False,         # Block signals to host processes

    # Resources
    max_memory="512M",             # Memory limit
    max_processes=64,              # Fork count limit
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

    # COW isolation
    workdir=None,                  # Working directory + COW
    fs_isolation=FsIsolation.NONE, # NONE | OVERLAYFS | BRANCHFS
    on_exit=BranchAction.COMMIT,   # COMMIT | ABORT | KEEP
    on_error=BranchAction.ABORT,

    # Misc
    chroot=None,
    close_fds=True,
    strict=True,                   # Abort on confinement failure
    privileged=False,              # UID 0 in user namespace
)
```
