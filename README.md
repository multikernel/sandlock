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
confinement without image builds, overlay filesystems, or root privileges.

| Feature | Sandlock | Container | MicroVM (Firecracker) | gVisor |
|---|---|---|---|---|
| Root required | No | Yes* | Yes (KVM) | Yes |
| Image build | No | Yes | Yes | Yes |
| Startup time | ~1 ms (fork) | ~200 ms | ~100 ms | ~100 ms |
| Kernel | Shared | Shared | Separate guest | Shared (sentry) |
| Filesystem isolation | Landlock | Overlay | Block-level (QCOW2) | ptrace/KVM |
| Network isolation | Landlock + seccomp notif | Network namespace | TAP device | Sentry kernel |
| Syscall filtering | seccomp-bpf | seccomp | N/A (full kernel) | Sentry kernel |
| Resource limits | seccomp notif + rlimit | cgroup v2 | VM config | cgroup v2 |
| Memory sharing | COW (fork), zero-copy | Bind-mount + re-init | Shared mem (explicit) | N/A |
| Nesting | Native (fork) | Complex (DinD/DooD) | Not supported | Supported |
| Checkpoint/restore | ptrace + BranchFS | CRIU | VM snapshot | N/A |

\* Rootless containers exist but require user namespace support, `/etc/subuid` configuration, and `fuse-overlayfs`.

## Requirements

- **Linux 5.13+** (Landlock ABI v1), **Python 3.10+**
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

# Run a Python function
result = Sandbox(policy).call(lambda: sum(range(1_000_000)))
print(result.value)  # 499999500000

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
    result = parent.sandbox(child_policy).call(untrusted_fn)
```

## Architecture

Sandlock applies confinement in sequence after `fork()`:

```
Parent                              Child
  │  fork()                           │
  │──────────────────────────────────>│
  │                                   ├─ 1. setpgid(0,0)
  │                                   ├─ 2. unshare(NEWUSER) (if privileged)
  │                                   ├─ 3. RLIMIT_CPU (if cpu_time)
  │                                   ├─ 4. chroot (optional)
  │                                   ├─ 5. Landlock (fs + net + IPC, irreversible)
  │                                   ├─ 6. Combined seccomp filter (irreversible)
  │                                   │     └─ send notify fd ──────> Parent
  │  receive notify fd                ├─ 7. Close fds 3+
  │  start supervisor thread          ├─ 8. Environment (clean_env + env)
  │  pidfd_open() + poll()            └─ 9. exec(cmd) or target()
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

Enforced via **seccomp user notification** and **rlimit** — no cgroups or root required.

| Resource | Mechanism | Enforcement |
|---|---|---|
| Memory | seccomp notif on `mmap`/`munmap`/`brk`/`mremap` | `ENOMEM` when over budget |
| Processes | seccomp notif on `clone`/`fork`/`vfork` | `EAGAIN` when at limit |
| CPU | `RLIMIT_CPU` per-process | `SIGXCPU` → `SIGKILL` |

### Network: Domain-Based Access Control

Specify allowed hostnames — everything else is blocked:

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

### BranchFS: Copy-on-Write Filesystem

With `fs_isolation=BRANCHFS`, sandbox writes go to an isolated COW branch
on a [BranchFS](https://github.com/user/branchfs) FUSE mount. Writes are
committed on success, discarded on failure. Nested sandboxes create child branches.

```python
Policy(
    fs_isolation=FsIsolation.BRANCHFS,
    fs_mount="/mnt/workspace",
    on_exit=BranchAction.COMMIT,
    on_error=BranchAction.ABORT,
)
```

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
Sandbox.from_checkpoint(cp, restore_fn=lambda state: load_state(state))
```

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

    # Resources (seccomp notif + rlimit)
    max_memory: str | int | None = None  # '512M'
    max_processes: int | None = None     # per-sandbox fork count
    cpu_time: str | int | None = None    # '30s' per-process RLIMIT_CPU

    # Environment
    clean_env: bool = False              # Minimal env (PATH, HOME, TERM, LANG, USER, SHELL)
    env: Mapping[str, str] = {}          # Set/override env vars

    # BranchFS COW isolation
    fs_isolation: FsIsolation = NONE     # NONE | BRANCHFS
    fs_mount: str | None = None          # BranchFS mount point
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
