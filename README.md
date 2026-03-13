# Sandlock

Lightweight process sandbox for Linux. Confines untrusted code using
**Landlock** (filesystem + network), **seccomp-bpf** (syscall filtering),
and **seccomp user notification** (resource limits, IP enforcement, /proc
virtualization). No root, no cgroups, no containers.

```
python3 cli/sandlock.py run -w /tmp -r /usr -m 512M -- python3 untrusted.py
```

## Why Sandlock?

Containers (Docker, Podman) and VMs (gVisor, Firecracker) are powerful but
heavy. Sandlock targets the gap: you need to run a function or command with
**strict confinement** but without the overhead of image builds, overlay
filesystems, or root privileges.

| Feature | Sandlock | Container | gVisor |
|---|---|---|---|
| Root required | No | Yes* | Yes |
| Image build | No | Yes | Yes |
| Startup time | ~1 ms (fork) | ~200 ms | ~100 ms |
| Filesystem isolation | Landlock | Overlay | ptrace/KVM |
| Network isolation | Landlock + seccomp notif | Network namespace | Sentry kernel |
| Syscall filtering | seccomp-bpf | seccomp | Sentry kernel |
| /proc virtualization | seccomp notif | Mount namespace | Sentry kernel |
| Resource limits | seccomp notif + rlimit | cgroup v2 | cgroup v2 |

\* Rootless containers exist but have significant limitations.

## Requirements

- **Linux 5.13+** (Landlock ABI v1)
- **Python 3.10+**
- No root, no cgroups, no special system configuration
- No C compiler needed, all kernel interfaces via ctypes

Optional kernel versions for additional features:

| Feature | Minimum kernel |
|---|---|
| pidfd process tracking | 5.3 |
| seccomp user notification | 5.6 |
| NOTIF_ADDFD (virtualization) | 5.9 |
| Landlock filesystem rules | 5.13 |
| Landlock TCP port rules | 6.7 (ABI v4) |

Check your system:

```
python3 cli/sandlock.py check
```

## Quick Start

### CLI

```bash
# Basic confinement
python3 cli/sandlock.py run -r /usr -r /lib -w /tmp -- ls /tmp

# Interactive shell in a sandbox
python3 cli/sandlock.py run -i -r /usr -r /lib -r /lib64 -r /bin -r /etc -w /tmp -- /bin/sh

# With resource limits
python3 cli/sandlock.py run -m 512M -p 20 -t 30 -- ./compute.sh

# Network: only allow connecting to specific domains
python3 cli/sandlock.py run \
  --net-allow-host api.openai.com \
  --net-allow-host github.com \
  -r /usr -r /lib -r /lib64 -r /etc \
  -- python3 agent.py

# Network: TCP port restrictions (Landlock)
python3 cli/sandlock.py run --net-bind 8080 --net-connect 443 \
  -r /usr -r /lib -r /lib64 -r /etc \
  -- python3 server.py

# Check kernel support
python3 cli/sandlock.py check
```

### Python API

```python
from sandlock import Sandbox, Policy

# Run a shell command with filesystem restrictions
policy = Policy(
    fs_writable=["/tmp/sandbox"],
    fs_readable=["/usr", "/lib", "/etc"],
    max_memory="256M",
    max_processes=10,
)

result = Sandbox(policy).run(["python3", "-c", "print('hello')"])
print(result.stdout)  # b'hello\n'
print(result.exit_code)  # 0
```

### Run a Python function

```python
def work():
    return sum(range(1_000_000))

result = Sandbox(policy).call(work)
print(result.value)  # 499999500000
```

### Interactive mode

```python
policy = Policy(
    fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc"],
    fs_writable=["/tmp"],
)
result = Sandbox(policy).run_interactive(["/bin/sh"])
```

### Long-lived sandbox

```python
with Sandbox(policy) as sb:
    sb.exec(["python3", "server.py"])

    # Freeze / resume all processes atomically
    sb.pause()
    sb.resume()

    # Adjust limits on the fly
    sb.update(max_memory="128M")

    # Wait or abort
    exit_code = sb.wait(timeout=30)
```

### Nested sandboxes

```python
with Sandbox(parent_policy) as parent:
    child = parent.sandbox(child_policy)
    result = child.call(untrusted_fn)
    # child inherits parent's cgroup constraints
```

## Architecture

Sandlock applies confinement in a strict sequence after `fork()`:

```
Parent                              Child
  │                                   │
  │  fork()                           │
  │──────────────────────────────────>│
  │                                   ├─ 1. setpgid(0,0)
  │                                   ├─ 2. unshare(NEWUSER) (if privileged)
  │  write uid/gid maps              ├─     ... wait for maps ...
  │                                   ├─ 3. RLIMIT_CPU (if max_cpu set)
  │                                   ├─ 4. chroot (optional)
  │                                   ├─ 5. Landlock (filesystem + network, irreversible)
  │                                   ├─ 6. Combined seccomp filter (irreversible)
  │                                   │     notif + deny + resource tracking
  │                                   │     └─ send notify fd ──────> Parent
  │  receive notify fd                ├─ 7. Close fds 3+
  │  start supervisor thread          └─ 8. exec(cmd) or target()
  │                                   │
  │  pidfd_open()                     │
  │  poll() for exit                  │
```

Each layer is **defense-in-depth**: even if one layer is bypassed, the
others still constrain the process.

### Landlock: Filesystem + Network Confinement

[Landlock](https://landlock.io) is a Linux Security Module that restricts
filesystem and network access without requiring root.

**Filesystem** (ABI v1+):

```python
Policy(
    fs_writable=["/tmp/work"],
    fs_readable=["/usr", "/lib", "/etc/resolv.conf"],
)
# The child cannot access /home, /root, /var, etc.
```

**Network** (ABI v4+, TCP only):

```python
Policy(
    net_bind=[8080],              # Only bind TCP port 8080
    net_connect=[443, "5432"],    # Only connect to TCP 443 and 5432
)
```

Port specs accept integers or `"lo-hi"` range strings. Empty = unrestricted.

Landlock rules are applied via `landlock_restrict_self()` and are
**irreversible**. The child cannot remove them.

### seccomp-bpf: Syscall Filtering

A classic BPF (cBPF) filter blocks dangerous syscalls at the kernel entry
point, before any work is done. The default deny list includes:

- **Privilege escalation**: `ptrace`, `process_vm_readv/writev`, `keyctl`
- **Namespace escape**: `unshare`, `setns`, `pivot_root`, `mount/umount`
- **Kernel interfaces**: `kexec_load`, `bpf`, `perf_event_open`
- **Dangerous I/O**: `ioperm`, `iopl` (x86 only)

Argument-level filtering is applied for:
- `clone` / `clone3`: blocks namespace flags (`CLONE_NEWNS`, `CLONE_NEWUSER`, etc.) while allowing normal `fork()`
- `ioctl`: blocks `TIOCSTI` (terminal injection) while allowing normal I/O

Supports both **x86_64** and **aarch64** with per-architecture syscall tables.

### Resource Limits (No Cgroups Required)

Sandlock enforces resource limits via **seccomp user notification** and
**rlimit** — no cgroups, no root, no system configuration.  Works out
of the box on stock Ubuntu, Docker, CI, everywhere.

```python
Policy(
    max_memory="512M",      # seccomp notif tracks mmap/brk/munmap
    max_processes=10,        # seccomp notif counts clone/fork
    max_cpu="50%",           # RLIMIT_CPU (inherited by children)
)
```

How it works:

| Resource | Mechanism | Per-sandbox? | Enforcement |
|---|---|---|---|
| Memory | seccomp notif on `mmap`/`munmap`/`brk`/`mremap` | Yes — supervisor tracks total | `ENOMEM` when over budget |
| Processes | seccomp notif on `clone`/`fork`/`vfork` | Yes — supervisor counts (threads excluded) | `EAGAIN` when at limit |
| CPU | `RLIMIT_CPU` set before exec | Per-process (inherited) | Kernel sends `SIGXCPU` → `SIGKILL` |

The seccomp notif supervisor intercepts allocation syscalls
synchronously — the child blocks until the supervisor approves or
denies.  Memory and process limits are enforced per-sandbox (the
supervisor maintains counters per sandbox instance).  CPU limits are
per-process via rlimit, bounded by `max_processes × max_cpu`.

All resource tracking uses the same combined seccomp filter as network
enforcement and filesystem virtualization — one filter, no stacking
issues, zero additional overhead beyond the syscall interception.

### Network Isolation: Domain-Based Access Control

For AI agents and untrusted code, Sandlock provides domain-based network
isolation — specify allowed hostnames and everything else is blocked:

```python
Policy(
    net_allow_hosts=["api.openai.com", "github.com"],
    fs_readable=["/usr", "/lib", "/etc"],
)
```

This works through three cooperating layers:

```
resolve_hosts(["api.openai.com"])     ← before fork, in parent
       │
       ├──→ Virtual /etc/hosts         (only allowed domain→IP mappings)
       ├──→ Virtual /etc/nsswitch.conf (forces "hosts: files", no DNS fallback)
       └──→ allowed_ips set            {104.18.26.120, ..., 127.0.0.1, ::1}


Layer 1: /etc/hosts virtualization  (usability)
  resolve "api.openai.com" → 104.18.26.120  ✓
  resolve "evil.com"       → "not found"     ✓

Layer 2: connect/sendto IP check   (security)
  connect to 104.18.26.120 → allowed         ✓
  connect to 8.8.8.8       → ECONNREFUSED    ✓
  UDP sendto 8.8.8.8:53    → ECONNREFUSED    ✓
```

**Layer 1** virtualizes `/etc/hosts` via seccomp user notification. When
the child opens `/etc/hosts`, a memfd with only the allowed mappings is
injected. Programs get clean "host not found" errors for unlisted domains.

**Layer 2** intercepts `connect()` and `sendto()` syscalls via seccomp
user notification, reads the `sockaddr` from child memory, and checks the
destination IP against the allowed set. This is the security boundary —
hardcoded IPs, direct DNS over UDP, raw sockets — all go through
`connect`/`sendto` and are checked there.

Landlock TCP port rules (`net_bind` / `net_connect`) layer underneath as
a zero-overhead fast path for port-level restrictions.

### seccomp User Notification: /proc and /sys Virtualization

For deeper isolation, Sandlock can intercept `open()` and `openat()` syscalls
via `SECCOMP_RET_USER_NOTIF` and apply path-based rules:

```python
from sandlock import Policy, NotifPolicy, PathRule, NotifAction
from sandlock._notif_policy import default_proc_rules

notif = NotifPolicy(
    rules=default_proc_rules(),
    isolate_pids=True,           # Deny access to /proc/<foreign_pid>/
)

policy = Policy(
    notif_policy=notif,
    fs_readable=["/usr", "/lib", "/proc", "/sys"],
)
```

The supervisor runs in a parent thread and handles three actions:

| Action | Mechanism | Example |
|---|---|---|
| **ALLOW** | `SECCOMP_USER_NOTIF_FLAG_CONTINUE` | `/proc/self/status` |
| **DENY** | Return `-EACCES` or `-ESRCH` | `/proc/kcore`, `/sys/firmware/` |
| **VIRTUALIZE** | `memfd_create` + `SECCOMP_IOCTL_NOTIF_ADDFD` | `/proc/self/mounts`, `/etc/hosts` |

Virtualization injects a `memfd` containing fake content into the child's
fd table. The child thinks it opened the real file but reads
supervisor-controlled bytes. This requires Linux 5.9+.

**PID isolation** (`isolate_pids=True`): when enabled, any access to
`/proc/<pid>/...` where the PID is not in the sandbox's cgroup is denied
with `ESRCH` (No such process). The sandbox's own processes are unaffected.
Auto-enabled when `-r /proc` is passed on the CLI.

Default rules deny:
- `/proc/kcore`, `/proc/kallsyms`, `/proc/keys` (kernel secrets)
- `/sys/kernel/`, `/sys/firmware/`, `/sys/fs/cgroup/` (host internals)
- Virtualizes `/proc/self/mounts` and `/proc/self/mountinfo` (hide host mounts)

### BranchFS: Copy-on-Write Filesystem Isolation

When `fs_isolation=BRANCH`, Sandlock creates a COW branch on a
[BranchFS](https://github.com/user/branchfs) FUSE mount. All sandbox
writes go to an isolated `@{branch-uuid}` directory; the parent
filesystem is never modified.

```python
from sandlock import Sandbox, Policy, FsIsolation, BranchAction

policy = Policy(
    fs_isolation=FsIsolation.BRANCHFS,
    fs_mount="/mnt/workspace",
    fs_writable=["/mnt/workspace"],
    fs_readable=["/usr", "/lib"],
    on_exit=BranchAction.COMMIT,    # Merge writes on success
    on_error=BranchAction.ABORT,    # Discard writes on failure
)

result = Sandbox(policy).run(["python3", "transform.py"])
# Writes are committed only if the command succeeds
```

Nested sandboxes create child branches under the parent's branch.
Commit conflicts (sibling already committed) raise `BranchConflictError`
with `ESTALE`.

Explicit control is available in long-lived sandboxes:

```python
with Sandbox(policy) as sb:
    sb.exec(["python3", "experiment.py"])
    sb.wait()
    # Inspect results before deciding
    sb.commit()        # or sb.abort_branch()
```

### Checkpoint/Restore

Sandlock provides checkpoint and restore for sandboxed processes using
a hybrid approach with two layers of state capture:

1. **OS-level (automatic, transparent)**: ptrace + `/proc` to dump
   registers, memory layout, memory contents, and file descriptors.
   The child does not need to cooperate or know it's being checkpointed.

2. **App-level (optional, cooperative)**: If `exec()` was called with a
   `save_fn`, Sandlock triggers it via a control socket and receives raw
   bytes. This covers state that ptrace can't see (open sockets, epoll,
   application-level caches).

Combined with BranchFS (O(1) filesystem snapshot) and process group
SIGSTOP, this provides full checkpoint/restore without CRIU or root.

```python
with Sandbox(policy) as sb:
    # Start with optional app-level save function
    sb.exec(["python3", "server.py"], save_fn=lambda: serialize_state())

    # ... later ...

    # Checkpoint: freeze > fs snapshot > ptrace dump > save_fn > resume
    cp = sb.checkpoint()

# Restore from checkpoint
result = Sandbox.from_checkpoint(cp, restore_fn=lambda state: load_state(state))
```

#### Named Checkpoints (Stateful Sandboxes)

Checkpoints can be saved to disk and loaded later, turning a sandbox
into a persistent environment. Install packages, stop, resume days
later with everything intact:

```python
# First session: set up environment
with Sandbox(policy) as sb:
    sb.exec(["python3", "-m", "pip", "install", "numpy", "pandas"])
    sb.wait()
    cp = sb.checkpoint()
    cp.save("my-env")                   # persist to ~/.sandlock/checkpoints/my-env/

# Days later: resume from where we left off
cp = Checkpoint.load("my-env")
result = Sandbox.from_checkpoint(cp, restore_fn=lambda state: load_state(state))

# Management
Checkpoint.list()                       # ["my-env", "experiment-3"]
Checkpoint.delete("experiment-3")
```

On-disk layout (JSON metadata + raw binary, no pickle for user data):

```
~/.sandlock/checkpoints/my-env/
├── meta.json              # branch_id, fs_mount, sandbox_id
├── policy.dat             # serialized Policy
├── app_state.bin          # raw app state bytes (optional)
└── process/               # OS-level state (optional)
    ├── info.json          # pid, cwd, exe
    ├── threads.json       # thread metadata (tid, arch)
    ├── threads/
    │   └── <tid>.bin      # raw register bytes per thread
    ├── memory_map.json    # region metadata (start, end, perms, path)
    ├── memory/
    │   └── <index>.bin    # raw memory contents per region
    └── fds.json           # file descriptor table
```

Checkpoint sequence:

```
 1. SIGSTOP process group      pause all processes
 2. BranchFS create            O(1) COW snapshot (if active)
 3. ptrace SEIZE+INTERRUPT     stop threads for consistent read
 4. PTRACE_GETREGSET           dump registers (per thread)
 5. /proc/<pid>/maps + mem     dump memory regions
 6. /proc/<pid>/fd + fdinfo    dump file descriptors
 7. ptrace DETACH              release threads
 8. SIGCONT                    resume for save_fn (if any)
 9. trigger save_fn            1-byte write on control socket
10. receive app_state          length-prefixed raw bytes
11. resume
```

The control socket uses a simple wire protocol:

- **Parent to Child**: 1 byte (`0x01` = checkpoint trigger)
- **Child to Parent**: 4-byte big-endian length + status byte + payload

### Process Tracking

Sandlock uses `pidfd_open(2)` + `poll(2)` for event-driven process
monitoring with no busy-loop or sleep polling. Process group cleanup
escalates SIGTERM to SIGKILL via `killpg()`.

### Privileged Mode (User Namespace)

The `--privileged` flag maps UID 0 (root) inside a user namespace.
The child appears as root but has no real host privileges — Landlock
and seccomp are applied **after** the namespace is created, so the
"root" cannot escape confinement.

```bash
# Run as root inside the sandbox (e.g. for apt install)
python3 cli/sandlock.py run --privileged -r /usr -r /lib -r /etc -w /tmp \
  -- apt install -y some-package
```

```python
Policy(privileged=True)  # UID 0 inside, still confined
```

Sandlock uses `CLONE_NEWUSER` + `CLONE_NEWCGROUP` only when
`privileged=True`.  The parent writes UID/GID maps via a sync
pipe handshake.  Nested sandboxes each fork from the unsandboxed
parent, so no user namespace nesting occurs.

## Policy Reference

```python
@dataclass(frozen=True)
class Policy:
    # Filesystem (Landlock)
    fs_writable: Sequence[str] = []     # Paths with read/write access
    fs_readable: Sequence[str] = []     # Paths with read-only access
    fs_denied: Sequence[str] = []       # Explicitly denied paths

    # Syscall blocklist (seccomp)
    deny_syscalls: Sequence[str] | None = None  # None = default blocklist

    # Network — domain allowlist (seccomp notif)
    net_allow_hosts: Sequence[str] = []  # Allowed domains; empty = unrestricted
    # Resolved before fork → virtual /etc/hosts + IP enforcement on connect/sendto

    # Network — TCP port rules (Landlock ABI v4+)
    net_bind: Sequence[int | str] = []      # Allowed bind ports; empty = unrestricted
    net_connect: Sequence[int | str] = []   # Allowed connect ports; empty = unrestricted

    # Resource limits (seccomp notif + rlimit, no cgroups)
    max_memory: str | int | None = None  # '512M' — per-sandbox mmap budget
    max_processes: int | None = None      # per-sandbox fork count
    max_cpu: str | None = None           # '50%' — per-process RLIMIT_CPU

    # BranchFS COW isolation
    fs_isolation: FsIsolation = FsIsolation.NONE   # NONE | BRANCHFS
    fs_mount: str | None = None                     # BranchFS mount point
    on_exit: BranchAction = BranchAction.COMMIT     # COMMIT | ABORT | KEEP
    on_error: BranchAction = BranchAction.ABORT

    # Misc
    chroot: str | None = None
    close_fds: bool = True
    strict: bool = True          # Abort on confinement failure
    privileged: bool = False     # UID 0 inside user namespace

    # Seccomp user notification (auto-configured by resource/network/proc settings)
    notif_policy: NotifPolicy | None = None
```

## Strict vs. Permissive Mode

By default (`strict=True`), if any confinement layer fails to initialize
(e.g., Landlock unavailable on an older kernel), the child process aborts.

Set `strict=False` to degrade gracefully:

```python
Policy(strict=False)
# Landlock unavailable? Continue without filesystem isolation.
# seccomp fails? Continue without syscall filtering.
```

## Comparison with Alternatives

**vs. `subprocess` + seccomp only**: Sandlock adds filesystem isolation
(Landlock), network isolation, resource limits (cgroup), and /proc
virtualization.

**vs. bubblewrap (bwrap)**: bwrap uses namespaces (requires `CLONE_NEWUSER`).
Sandlock uses Landlock, which works on kernels/configs where user namespaces are
disabled.

**vs. nsjail**: nsjail requires root for most features. Sandlock is fully
unprivileged.

**vs. gVisor**: gVisor provides a full syscall-compatible kernel in
userspace. Sandlock is lighter: it allows most syscalls to hit the real
kernel and only interposes on specific paths via seccomp notifications.

| Feature | Sandlock | MicroVM (e.g. Firecracker) | Container |
|---|---|---|---|
| Isolation | Landlock + seccomp | KVM hardware | Namespaces |
| Kernel | Shared | Separate guest kernel | Shared |
| Root required | No | Yes (KVM access) | Yes* |
| Startup time | ~1 ms | ~100 ms | ~200 ms |
| State persistence | Named checkpoints + BranchFS | VM snapshots | Volumes |
| Checkpoint/restore | ptrace + BranchFS | VM snapshot | CRIU (complex) |
| COW filesystem | BranchFS (FUSE) | Block-level (QCOW2) | Overlay |
| Network isolation | seccomp notif + Landlock | Full (TAP device) | Full (netns) |
