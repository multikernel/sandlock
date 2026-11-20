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

- **sandlock-core**: Rust library (Landlock, seccomp, supervisor, COW, pipeline)
- **sandlock-cli**: Rust CLI binary (`sandlock run ...`)
- **sandlock-oci**: OCI runtime shim for containerd, CRI-O, and Kubernetes (namespace-less)
- **sandlock-ffi**: C ABI shared library (`libsandlock_ffi.so`)
- **Python SDK**: ctypes bindings to the FFI library
- **Go SDK**: cgo bindings to the FFI library

See [`docs/architecture.md`](docs/architecture.md) for how the pieces fit
together and how confinement is applied.

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

Protections can be selectively waived per-policy when needed; see
[`docs/sandbox-reference.md#protection-opt-out`](docs/sandbox-reference.md#protection-opt-out).

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

### Optional features

All five features (`http`, `checkpoint`, `image`, `profiles`, `cow`) are enabled
by default. Build with none or select the ones you need:

```bash
cargo build --release --no-default-features
cargo build --release --no-default-features --features http,profiles
```

See [Building Sandlock](docs/building.md) for feature dependencies and Rust
library configuration.

## Quick Start

### CLI

```bash
# Basic confinement
sandlock run -r /usr -r /lib -w /tmp -- ls /tmp

# Interactive shell (the sandboxed command inherits the terminal)
sandlock run -r /usr -r /lib -r /lib64 -r /bin -r /etc -w /tmp -- /bin/sh

# Resource limits + timeout
sandlock run -m 512M -P 20 -t 30 -- ./compute.sh

# Outbound allowlist: one host on one port
sandlock run --net-allow api.openai.com:443 -r /usr -r /lib -r /etc -- python3 agent.py

# HTTP-level ACL (method + host + path rules via transparent proxy)
sandlock run \
  --http-allow "GET docs.python.org/*" \
  --http-allow "POST api.openai.com/v1/chat/completions" \
  --http-deny "* */admin/*" \
  -r /usr -r /lib -r /etc -- python3 agent.py

# COW filesystem (writes captured, committed on success)
sandlock run --workdir /opt/project -r /usr -r /lib -- python3 task.py

# Dry-run (show what files would change, then discard)
sandlock run --dry-run --workdir . -w . -r /usr -r /lib -r /bin -r /etc -- make build

# Use a saved profile
sandlock run -p build -- make -j4
```

The full option tour (GPU, network grammar, HTTPS MITM, credential
injection, port virtualization, chroot, nesting) is in
[`docs/cli.md`](docs/cli.md).

### Python API

```python
from sandlock import Sandbox, BranchAction

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

# Dry-run: see what files would change, then discard
sandbox = Sandbox(fs_writable=["."], workdir=".", fs_readable=["/usr", "/lib", "/bin", "/etc"],
                  on_exit=BranchAction.ABORT)
result = sandbox.run(["make", "build"])
for c in result.changes:
    print(f"{c.kind}  {c.path}")  # A=added, M=modified, D=deleted
```

See [`python/README.md`](python/README.md) for the SDK guide, including
HTTP ACL, chroot mounts, port virtualization, `confine()`, and deferred
commit.

### Rust API

```rust
use sandlock_core::{confine, Confinement, Sandbox};
use sandlock_core::sandbox::ByteSize;

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
```

## Documentation

| Document | Contents |
|---|---|
| [`docs/building.md`](docs/building.md) | Build commands, optional features, and minimal Rust embedding |
| [`docs/cli.md`](docs/cli.md) | Every `sandlock run` option by example, profiles, `ps` / `inspect` / `kill` |
| [`docs/sandbox-reference.md`](docs/sandbox-reference.md) | Every `Sandbox` field, default, and TOML key; credentials; protection opt-out |
| [`docs/network.md`](docs/network.md) | Endpoint grammar, protocol gating, HTTP interception, bind rules, port virtualization |
| [`docs/policy-fn.md`](docs/policy-fn.md) | Dynamic policy callbacks: events, verdicts, context methods, TOCTOU guarantees |
| [`docs/http-observer.md`](docs/http-observer.md) | HTTP observation callbacks: requests, response status, streamed bodies |
| [`docs/pipelines.md`](docs/pipelines.md) | Pipelines, the XOA pattern, COW fork and map-reduce |
| [`docs/prompt_injection.md`](docs/prompt_injection.md) | Prompt injection defenses: isolation, permissions, credentials, and text inspection |
| [`docs/architecture.md`](docs/architecture.md) | Crate layout, confinement sequence, supervisor handlers, COW filesystem |
| [`docs/learn.md`](docs/learn.md) | `sandlock learn`: generate a profile from an observed run |
| [`docs/extension-handlers.md`](docs/extension-handlers.md) | Custom seccomp-notification handlers (Rust and C ABI) |
| [`docs/python-handlers.md`](docs/python-handlers.md) | Custom handlers from Python |
| [`python/README.md`](python/README.md) | Python SDK guide |
| [`go/README.md`](go/README.md) | Go SDK guide |
| [`crates/sandlock-oci/README.md`](crates/sandlock-oci/README.md) | OCI runtime shim |

## Performance

Benchmarked on a typical Linux workstation:

| Workload | Bare metal | Sandlock | Docker | Sandlock overhead |
|---|---|---|---|---|
| `/bin/echo` startup | 2 ms | 7 ms | 307 ms | 5 ms (44x faster than Docker) |
| Redis SET (100K ops) | 82K rps | 80K rps | 52K rps | 97.1% of bare metal |
| Redis GET (100K ops) | 79K rps | 77K rps | 53K rps | 97.1% of bare metal |
| Redis p99 latency | 0.5 ms | 0.6 ms | 1.5 ms | ~2.5x lower than Docker |
| COW fork ×1000 | n/a | 530 ms | n/a | 530μs/fork, ~1,900 forks/sec |

## Testing

```bash
# Rust tests
cargo test --release

# Python tests
cd python && pip install -e . && pytest tests/
```
