# Sandlock

Lightweight process sandbox for Linux. Confines untrusted code using
**Landlock** (filesystem + network + IPC), **seccomp-bpf** (syscall filtering),
and **seccomp user notification** (resource limits, IP enforcement, /proc
virtualization). No root, no cgroups, no containers.

```
sandlock run -w /tmp -r /usr -m 512M -- python3 untrusted.py
```

## Why Sandlock?

Containers and VMs are powerful but heavy. Sandlock targets the gap: strict
confinement without image builds or root privileges. Built-in OverlayFS COW
protects your working directory automatically.

| Feature | Sandlock | Container | MicroVM (Firecracker) | gVisor |
|---|---|---|---|---|
| Root required | No | Yes* | Yes (KVM) | Yes |
| Image build | No | Yes | Yes | Yes |
| Startup time | ~1 ms (fork) | ~200 ms | ~100 ms | ~100 ms |
| Kernel | Shared | Shared | Separate guest | Shared (sentry) |
| Filesystem isolation | Landlock | Overlay | Block-level (QCOW2) | ptrace/KVM |
| Network isolation | Landlock port range + seccomp notif port virtualization | Network namespace | TAP device | Sentry kernel |
| Syscall filtering | seccomp-bpf | seccomp | N/A (full kernel) | Sentry kernel |
| Resource limits | seccomp notif + SIGSTOP/SIGCONT | cgroup v2 | VM config | cgroup v2 |
| Memory sharing | COW fork (`sb.fork()`), zero-copy | Bind-mount + re-init | Shared mem (explicit) | N/A |
| Nesting | Native (fork) | Complex (DinD/DooD) | Not supported | Supported |
| COW filesystem | OverlayFS (kernel) / BranchFS | Overlay | Block-level | N/A |
| Checkpoint/restore | ptrace + BranchFS | CRIU | VM snapshot | N/A |

\* Rootless containers exist but require user namespace support, `/etc/subuid` configuration, and `fuse-overlayfs`.

## Requirements

- **Linux 5.13+** (Landlock ABI v1), **Python 3.8+**
- No root, no cgroups, no C compiler (all kernel interfaces via ctypes)

| Feature | Minimum kernel |
|---|---|
| seccomp user notification | 5.6 |
| Landlock filesystem rules | 5.13 |
| Landlock TCP port rules | 6.7 (ABI v4) |
| Landlock IPC scoping | 6.12 (ABI v6) |

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
sandlock run --time-start "2000-01-01T00:00:00Z" --random-seed 42 -- ./build.sh

# Port virtualization (multiple sandboxes can bind the same port)
sandlock run -i --port-remap -r /usr -r /lib -r /etc -- redis-server --port 6379

# Use a saved profile (CLI flags override profile values)
sandlock run -p build -- make -j4
sandlock run -p build --max-memory 1G -- make

# Profile management
sandlock profile list
sandlock profile show build
```

### Profiles

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

Field names match `Policy` exactly. Unknown fields are rejected. CLI flags override profile values.

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
    env={"LANG": "C.UTF-8"},
)

# Run a command
result = Sandbox(policy).run(["python3", "-c", "print('hello')"])

# Use a saved TOML profile
result = Sandbox("build").run(["make", "-j4"])
```

Long-lived and nested sandboxes:

```python
with Sandbox(policy) as sb:
    sb.exec(["python3", "server.py"])
    sb.pause()       # Freeze all processes atomically
    sb.resume()
    sb.update(max_memory="128M")  # Adjust limits live
    exit_code = sb.wait(timeout=30)

# Nested: child inherits parent's constraints
with Sandbox(parent_policy) as parent:
    result = parent.sandbox(child_policy).run(["python3", "untrusted.py"])
```

## Architecture

Sandlock applies confinement in sequence after `fork()`:

```
Parent                              Child
  │  fork()                           │
  │──────────────────────────────────>│
  │                                   ├─ 1. setpgid(0,0)
  │                                   ├─ 2. unshare(NEWUSER) (if privileged)
  │                                   ├─ 3. chroot (optional)
  │                                   ├─ 4. Landlock (fs + net + IPC, irreversible)
  │                                   ├─ 5. Combined seccomp filter (irreversible)
  │                                   │     └─ send notify fd ──────> Parent
  │  receive notify fd                ├─ 7. Close fds 3+
  │  start supervisor thread          ├─ 8. Environment (clean_env + env)
  │  pidfd_open() + poll()            └─ 9. exec(cmd)
```

Each layer is **defense-in-depth**: bypassing one doesn't defeat the others.

### Landlock: Filesystem + Network + IPC

[Landlock](https://landlock.io) restricts filesystem, network, and IPC
access without root. Rules are applied via `landlock_restrict_self()` and
are **irreversible**.

```python
Policy(
    fs_writable=["/tmp/work"],
    fs_readable=["/usr", "/lib"],        # ABI v1+: filesystem
    net_bind=[8080],                      # ABI v4+: TCP ports
    net_connect=[443, "5432"],
    isolate_ipc=True,                     # ABI v6+: block abstract UNIX sockets to host
    isolate_signals=True,                 # ABI v6+: block signals to host processes
)
```

### seccomp-bpf: Syscall Filtering

A cBPF filter blocks dangerous syscalls at the kernel entry point:
`ptrace`, `mount`, `unshare`, `setns`, `kexec_load`, `bpf`, `perf_event_open`,
`ioperm`/`iopl`, and more. Argument-level filtering blocks namespace flags
in `clone`/`clone3` and `TIOCSTI` in `ioctl`. Supports **x86_64** and **aarch64**.

### Resource Limits

Enforced via **seccomp user notification** and **SIGSTOP/SIGCONT**, no cgroups or root required.

| Resource | Mechanism | Enforcement |
|---|---|---|
| Memory | seccomp notif on `mmap`/`munmap`/`brk`/`mremap` | `ENOMEM` when over budget |
| Processes | seccomp notif on `clone`/`fork`/`vfork` | `EAGAIN` when at limit |
| CPU | Parent-side SIGSTOP/SIGCONT on process group | Throttle to N% of one core |
| Open files | `RLIMIT_NOFILE` | Kernel-enforced fd limit |
| Disk | BranchFS FUSE layer (`--max-disk`) | `ENOSPC` when quota exceeded |
| Ports | seccomp notif on `bind`/`connect` | Virtualize ports outside `net_bind` range |

CPU throttling works like cgroup v2 `cpu.max` but without root: a supervisor
thread cycles SIGSTOP/SIGCONT on the sandbox process group every 100ms.
`max_cpu=50` means ~50ms running, ~50ms stopped per cycle, roughly 50% of
one core.  Applies collectively to all processes in the sandbox.

### Port Virtualization

Each sandbox gets a full virtual port space.  Multiple sandboxes can bind the
same port without conflicts — no configuration needed.

```python
policy = Policy(port_remap=True)

Sandbox(policy).run(["python3", "server.py"])   # bind(3000) -> direct bind
Sandbox(policy).run(["python3", "server.py"])   # bind(3000) -> remapped, no conflict
```

The supervisor intercepts `bind()`/`connect()` via seccomp notif.  When a port
is free, the sandbox binds it directly (zero data-path overhead).  When there is
a conflict, a different real port is allocated and traffic is forwarded via a
zero-copy splice proxy.  `getsockname()` returns the virtual port.  No port
ranges to configure, no network namespaces, no root required.

Optionally, `net_bind`/`net_connect` restrict which virtual ports the sandbox
may use (Landlock enforcement, defense-in-depth).

### Network: Domain-Based Access Control

Specify allowed hostnames -- everything else is blocked:

```python
Policy(net_allow_hosts=["api.openai.com", "github.com"])
```

Two cooperating layers: (1) `/etc/hosts` virtualization via seccomp notif
(programs see clean "host not found" for unlisted domains), and (2) `connect()`/`sendto()`
IP enforcement (blocks hardcoded IPs, raw DNS over UDP, etc.).

### /proc and /sys Virtualization

Seccomp user notification intercepts `open()`/`openat()` for path-based rules.
Three actions: **ALLOW** (continue), **DENY** (return `-EACCES`), **VIRTUALIZE**
(inject `memfd` with fake content). Auto-enabled when `-r /proc` is passed.

Denies: `/proc/kcore`, `/proc/kallsyms`, `/proc/keys`, `/sys/kernel/`, `/sys/firmware/`.
Virtualizes: `/proc/self/mounts`, `/proc/self/mountinfo`.
PID isolation: blocks access to `/proc/<foreign_pid>/`.

### Copy-on-Write Filesystem

Setting `workdir` automatically enables COW protection. Writes are committed
on success, discarded on error. The sandbox `chdir`s into the workdir.

```python
# OverlayFS (default, zero dependencies, Linux 5.11+)
Policy(workdir="/opt/project")

# BranchFS (optional, supports snapshots, requires branchfs FUSE binary)
Policy(workdir="/opt/project", fs_isolation=FsIsolation.BRANCHFS)
```

```bash
sandlock run --workdir /opt/project -- python3 task.py
```

Two backends:

| | OverlayFS | BranchFS |
|---|---|---|
| Dependencies | None (kernel built-in) | `branchfs` FUSE binary |
| Kernel | >= 5.11 | Any with FUSE |
| Nesting | Chained lowerdir | Native branches |
| Snapshots | Manual | O(1) native |

Nested sandboxes create child COW layers automatically.

### Deterministic Execution

Pin time, randomness, and memory layout for reproducible builds and tests:

```python
Policy(
    time_start="2000-01-01T00:00:00Z",  # Frozen wall clock + monotonic near zero
    random_seed=42,                      # Deterministic getrandom()
    no_randomize_memory=True,            # Disable ASLR
    no_huge_pages=True,                  # Consistent page sizes
    no_coredump=True,                    # Disable core dumps
)
```

```bash
sandlock run --time-start "2000-01-01T00:00:00Z" --random-seed 42 \
  --no-randomize-memory --no-huge-pages -- ./build.sh
```

Time virtualization intercepts `clock_gettime`/`gettimeofday`/`time` via seccomp
notification and patches the vDSO to force real syscalls.  `/proc/uptime` and
`/proc/stat` btime are also virtualized.

### Checkpoint/Restore

Two-layer checkpoint without CRIU or root:

1. **OS-level**: ptrace + `/proc` dumps registers, memory, and file descriptors (transparent to child)
2. **App-level**: optional `save_fn` callback for application state

Combined with BranchFS O(1) snapshots for full checkpoint/restore.

```python
with Sandbox(policy) as sb:
    sb.exec(["python3", "server.py"], save_fn=lambda: serialize_state())
    cp = sb.checkpoint()
    cp.save("my-env")       # persist to disk

# Later: restore
cp = Checkpoint.load("my-env")
Sandbox.restore(cp, restore_fn=lambda state: load_state(state))
```

### COW Fork

Initialize expensive state once, then fork COW clones that share memory.
Each fork is a raw `fork(2)` syscall that bypasses seccomp notification
for minimal overhead. 1000 clones of a 50 MB Python process use ~50 MB
total, not 50 GB. ~680 us per fork, over 1,300 forks/sec.

```python
def init():
    global model, data
    model = load_model()          # 2 GB, loaded once
    data = preprocess_dataset()   # stored in globals

def work():
    clone_id = int(os.environ["CLONE_ID"])  # 0..N-1, set automatically
    result = rollout(model, data, clone_id)  # reads COW-shared globals
    save_result(result)

with Sandbox(policy, init, work) as sb:
    clones = sb.fork(1000)                   # batch: 1000 clones in ~530 ms
    for c in clones:
        c.wait()
```

How it works:
1. `Sandbox(policy, init, work)` forks a child, runs `init()`, then the
   child's main thread enters a fork-ready loop on the control socket
2. `sb.fork(N)` sends a single batch command. The main thread forks N
   times in a tight loop using raw `fork(2)`, bypassing seccomp
   notification. Each clone gets `CLONE_ID=0..N-1` and runs `work()`
3. No signals, no ptrace. The main thread is in a blocking `os.read()`
   (GIL released), so it forks itself cleanly
4. Each clone inherits Landlock + seccomp confinement via `fork()`

Designed for AI agent sandboxing and RL rollouts where setup is expensive
but each run needs different parameters.

### Privileged Mode

`privileged=True` maps UID 0 inside a user namespace. The child appears as
root but Landlock + seccomp still apply — "root" cannot escape confinement.

## Policy Reference

```python
@dataclass(frozen=True)
class Policy:
    # Filesystem (Landlock)
    fs_writable: Sequence[str] = []     # Read/write access
    fs_readable: Sequence[str] = []     # Read-only access
    fs_denied: Sequence[str] = []       # Explicitly denied

    # Syscall filtering (seccomp)
    deny_syscalls: Sequence[str] | None = None   # None = default blocklist
    allow_syscalls: Sequence[str] | None = None  # Allowlist mode (stricter)

    # Network
    net_allow_hosts: Sequence[str] = []     # Domain allowlist (seccomp notif)
    net_bind: Sequence[int | str] = []      # TCP bind ports (Landlock ABI v4+)
    net_connect: Sequence[int | str] = []   # TCP connect ports (Landlock ABI v4+)

    # IPC scoping (Landlock ABI v6+)
    isolate_ipc: bool = False       # Block abstract UNIX sockets to host
    isolate_signals: bool = False   # Block signals to host processes

    # Resources (seccomp notif + SIGSTOP/SIGCONT)
    max_memory: str | int | None = None  # '512M'
    max_processes: int = 64              # per-sandbox fork count
    max_cpu: int | None = None           # 50 = 50% of one core (SIGSTOP/SIGCONT)
    max_open_files: int | None = None    # RLIMIT_NOFILE
    port_remap: bool = False             # Full virtual port space per sandbox

    # Deterministic execution
    time_start: float | str | None = None    # '2000-01-01T00:00:00Z' or Unix timestamp
    random_seed: int | None = None           # Deterministic getrandom()
    no_randomize_memory: bool = False        # Disable ASLR
    no_huge_pages: bool = False              # Disable THP
    no_coredump: bool = False                # Disable core dumps

    # Environment
    clean_env: bool = False              # Minimal env (PATH, HOME, TERM, LANG, USER, SHELL)
    env: Mapping[str, str] = {}          # Set/override env vars

    # COW isolation (auto-enabled by workdir)
    workdir: str | None = None           # Working directory + COW protection
    fs_isolation: FsIsolation = NONE     # NONE | OVERLAYFS | BRANCHFS
    on_exit: BranchAction = COMMIT       # COMMIT | ABORT | KEEP
    on_error: BranchAction = ABORT

    # Misc
    chroot: str | None = None
    close_fds: bool = True
    strict: bool = True          # Abort on confinement failure
    privileged: bool = False     # UID 0 inside user namespace
    notif_policy: NotifPolicy | None = None
```

`strict=False` degrades gracefully when Landlock or seccomp is unavailable.
