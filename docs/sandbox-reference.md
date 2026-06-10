# Sandbox Reference

The Sandlock `Sandbox` configuration follows a sectioned schema shared
by the CLI, Python SDK, and TOML profiles. Sections are named for the
concern they cover (`config`, `determinism`, `program`, `filesystem`,
`network`, `http`, `syscalls`, `limits`); the Python `Sandbox`
dataclass exposes the same fields as keyword arguments. Unless noted
otherwise, each field is optional, and omitting a field means "no
restriction" beyond Sandlock's default seccomp blocklist, which is
always applied.

Where a Python field name differs from its TOML key (mostly the
`[filesystem]` and `[limits]` sections, which drop the `fs_` and `max_`
prefixes the dataclass uses), the field tables list both.

## Synopsis

### Python

```python
from sandlock import Sandbox, BranchAction

sandbox = Sandbox(
    # [config]
    http_ca=None, http_key=None,
    fs_storage=None, workdir=None,

    # [determinism]
    random_seed=None, time_start=None,
    deterministic_dirs=False, no_randomize_memory=False,

    # [program]  (process knobs only; exec/args are arguments to .run/.cmd)
    env={}, cwd=None, uid=None, gid=None,
    clean_env=False, no_coredump=False, no_huge_pages=False,

    # [filesystem]
    fs_readable=(), fs_writable=(), fs_denied=(),
    chroot=None, fs_mount={},
    on_exit=BranchAction.COMMIT, on_error=BranchAction.ABORT,

    # [network]
    net_allow_bind=(), net_allow=(), port_remap=False,

    # [http]
    http_ports=(), http_allow=(), http_deny=(),

    # [syscalls]
    extra_allow_syscalls=(), extra_deny_syscalls=(),

    # [limits]
    max_memory=None, max_processes=64, max_open_files=None,
    max_cpu=None, max_disk=None,
    gpu_devices=None, cpu_cores=None, num_cpus=None,

    # Runtime kwargs (not serialized as policy)
    name=None, policy_fn=None, init_fn=None, work_fn=None,

    # Advanced (internal; usually configured via the fields above)
    notif_policy=None,
)
```

### TOML profile

```toml
[config]
http_ca         = "/path/to/ca.pem"
http_key        = "/path/to/ca.key"
http_inject_ca  = ["/etc/ssl/certs/ca-certificates.crt"]
http_ca_out     = "/tmp/sandlock-ca.pem"
fs_storage      = "/var/lib/sandlock"
workdir         = "/opt/project"

[determinism]
random_seed         = 42
time_start          = "2026-01-01T00:00:00Z"
deterministic_dirs  = true
no_randomize_memory = true

[program]
exec          = "/usr/bin/make"
args          = ["-j4"]
env           = { CC = "gcc" }
cwd           = "/work"
uid           = 0
gid           = 0
clean_env     = true
no_coredump   = true
no_huge_pages = true

[filesystem]
read      = ["/usr", "/lib"]
write     = ["/tmp"]
deny      = ["/proc/kcore"]
chroot    = "/opt/rootfs"
mount     = ["/work:/host/sandbox/work"]
on_exit   = "commit"                  # "commit" | "abort" | "keep"
on_error  = "abort"

[network]
allow_bind = [8080]
allow      = ["api.example.com:443", "udp://1.1.1.1:53"]
port_remap = false

[http]
ports = [80]
allow = ["POST api.openai.com/v1/*"]
deny  = ["* */admin/*"]

[syscalls]
extra_allow = ["sysv_ipc"]
extra_deny  = []

[limits]
memory      = "512M"
processes   = 64
open_files  = 256
cpu         = 50
disk        = "1G"
gpu_devices = [0]
cpu_cores   = [0, 1]
num_cpus    = 2
```

## `[config]`

Top-level configuration for the supervisor and COW workspace.

| Python       | TOML        | Type          | Default | Description                                                                              |
| ------------ | ----------- | ------------- | ------- | ---------------------------------------------------------------------------------------- |
| `http_ca`    | `http_ca`   | `str \| None` | `None`  | PEM CA certificate path for HTTPS MITM. When set, port `443` is added to `http_ports`.   |
| `http_key`   | `http_key`  | `str \| None` | `None`  | PEM CA private key path. Required whenever `http_ca` is set.                             |
| `http_inject_ca` | `http_inject_ca` | `list[str]` | `[]` | Trust bundle paths to splice the active MITM CA's public cert into at open time. Without `http_ca`, generates an ephemeral CA (private key in memory only, never on disk) and intercepts port `443`. Requires at least one `http_allow` / `http_deny` rule. |
| `http_ca_out` | `http_ca_out` | `str \| None` | `None`  | Writes the active CA's public certificate (PEM) to this path; never the private key. Requires at least one `http_allow` / `http_deny` rule. |
| `fs_storage` | `fs_storage`| `str \| None` | `None`  | Separate storage directory for the seccomp COW upper layer / deltas. |
| `workdir`    | `workdir`   | `str \| None` | `None`  | COW root directory. Controls which directory COW tracks; does **not** set the child's working directory. |

HTTPS interception is opt-in: without `http_ca` or `http_inject_ca`,
port 443 is not intercepted, and `net_allow host:443` permits raw TLS to
the host with no content inspection. When `http_ca` is set, the CA must
be one the caller has generated and installed into the sandbox's trust
store (typically `/etc/ssl/certs/`). Alternatively, `http_inject_ca`
generates an ephemeral CA (private key kept in memory, never written to
disk) and splices its public cert into each named trust bundle at open
time, so the workload trusts the proxy with no manual install. File
injection covers tools that read a trust file from disk (curl, git,
OpenSSL CLI, Go, Python stdlib ssl, and Python requests / httpx via
certifi's `cacert.pem` if you name that path). Runtimes with a
compiled-in CA list such as Node and Java are not reachable by file
injection; for those use `http_ca_out` to export the public cert and
point the runtime's own env var at it (e.g. `NODE_EXTRA_CA_CERTS`).

## `[determinism]`

Knobs that pin sources of non-determinism in the child process.

| Python                  | TOML                  | Type                  | Default | Description                                                                                                  |
| ----------------------- | --------------------- | --------------------- | ------- | ------------------------------------------------------------------------------------------------------------ |
| `random_seed`           | `random_seed`         | `int \| None`         | `None`  | Seed for deterministic `getrandom()`. Identical seeds yield identical byte streams.                          |
| `time_start`            | `time_start`          | `float \| str \| None`| `None`  | Frozen start time as a Unix timestamp or RFC 3339 / ISO 8601 string. Time advances at real speed from the given epoch. |
| `deterministic_dirs`    | `deterministic_dirs`  | `bool`                | `False` | Sort `readdir()` entries lexicographically so that `ls`, `glob`, and `os.listdir` return a stable order.     |
| `no_randomize_memory`   | `no_randomize_memory` | `bool`                | `False` | Disable ASLR via `personality(ADDR_NO_RANDOMIZE)`.                                                           |

## `[program]`

Process-level knobs applied to the child. In a TOML profile, `exec`
and `args` also live in this section; in the Python SDK those are
arguments to `sandbox.run([...])` or `sandbox.cmd([...])` and are not
fields on `Sandbox`.

| Python          | TOML            | Type                | Default | Description                                                                                                                                          |
| --------------- | --------------- | ------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `env`           | `env`           | `Mapping[str, str]` | `{}`    | Variables to set or override in the child. Applied after `clean_env`.                                                                                |
| `cwd`           | `cwd`           | `str \| None`       | `None`  | Child working directory (`chdir` target). Independent of `workdir`.                                                                                  |
| `uid`           | `uid`           | `int \| None`       | `None`  | UID to map the child to inside a user namespace (e.g. `0` for fake root). Must be set together with `gid` (both or neither). The child retains no host privileges regardless of the mapped UID. Requires user namespaces to be available. |
| `gid`           | `gid`           | `int \| None`       | `None`  | GID to map the child to inside the user namespace. Must be set together with `uid`. An unprivileged user namespace maps a single id, so supplementary groups are not available. |
| `clean_env`     | `clean_env`     | `bool`              | `False` | When `True`, start with a minimal environment (`PATH`, `HOME`, `USER`, `TERM`, `LANG`) instead of inheriting the parent's.                            |
| `no_coredump`   | `no_coredump`   | `bool`              | `False` | Apply `prctl(PR_SET_DUMPABLE, 0)`. Disables core dumps and restricts `/proc/<pid>` access from other processes. Breaks `gdb`, `strace`, and `perf`.   |
| `no_huge_pages` | `no_huge_pages` | `bool`              | `False` | Disable transparent huge pages via `prctl(PR_SET_THP_DISABLE)`.                                                                                      |

## `[filesystem]`

Landlock filesystem rules plus chroot, mount mapping, and COW
filesystem isolation.

| Python         | TOML        | Type                | Default                 | Description                                                                                                                  |
| -------------- | ----------- | ------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `fs_readable`  | `read`      | `Sequence[str]`     | `()`                    | Paths the sandbox may read (in addition to `fs_writable`).                                                                   |
| `fs_writable`  | `write`     | `Sequence[str]`     | `()`                    | Paths the sandbox may read and write.                                                                                        |
| `fs_denied`    | `deny`      | `Sequence[str]`     | `()`                    | Paths explicitly denied (neither read nor write), even if implied by a broader rule.                                         |
| `chroot`       | `chroot`    | `str \| None`       | `None`                  | Path to `chroot` into before applying other confinement.                                                                     |
| `fs_mount`     | `mount`     | `Mapping[str, str]` | `{}`                    | Map virtual paths inside the chroot to host directories. Python form: `{"/work": "/host/sandbox/work"}`. TOML form: list of `"VIRTUAL:HOST"` strings. |
| `on_exit`      | `on_exit`   | `BranchAction`      | `BranchAction.COMMIT`   | Branch action on normal sandbox exit.                                                                                        |
| `on_error`     | `on_error`  | `BranchAction`      | `BranchAction.ABORT`    | Branch action on sandbox error or exception.                                                                                 |

Landlock rules are kernel-evaluated and TOCTOU-immune.

## `[network]`

Outbound allowlist, bind allowlist, and port virtualization. Each
entry of `net_allow` is a single rule of the form **protocol, host,
port**. Rules are OR'd. An empty `net_allow` denies all outbound
traffic. Protocol gating falls out of rule presence: without a UDP
rule, UDP socket creation is denied at the seccomp layer; without an
ICMP rule, kernel ping socket creation is denied. Raw ICMP (`SOCK_RAW
+ IPPROTO_ICMP`) is never exposed. See the project README's "Network
Model" section for the full grammar.

Rule shapes:

* `host:port[,port,...]`: TCP, default scheme (no prefix).
* `tcp://host:port`: TCP, explicit scheme.
* `udp://host:port`: UDP. `udp://*:*` opens any UDP destination.
* `icmp://host`: kernel ping socket (`SOCK_DGRAM + IPPROTO_ICMP`).
  `icmp://*` opens any echo destination.

| Python       | TOML         | Type                    | Default | Description                                                                                                                                          |
| ------------ | ------------ | ----------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `net_allow`  | `allow`      | `Sequence[str]`         | `()`    | Outbound endpoint allowlist. Empty list denies all outbound.                                                                                         |
| `net_allow_bind`   | `allow_bind` | `Sequence[int \| str]`  | `()`    | TCP ports the sandbox may bind/listen on (default-deny allowlist). Each entry is a port or a `"lo-hi"` range. Landlock ABI v4+ (TCP only; UDP `bind()` is not separately gated). Mutually exclusive with `net_deny_bind`.        |
| `net_deny_bind`    | `deny_bind`  | `Sequence[int \| str]`  | `()`    | TCP ports the sandbox may NOT bind (default-allow denylist; inverse of `net_allow_bind`). Same port syntax. Enforced on the on-behalf `bind()` path (Landlock `BIND_TCP` is relaxed). Mutually exclusive with `net_allow_bind`.        |
| `port_remap` | `port_remap` | `bool`                  | `False` | Enable transparent TCP port virtualization. Each sandbox receives an independent virtual port space; conflicting binds are remapped to unique real ports via `pidfd_getfd`. |

Hostnames are resolved once at sandbox creation and pinned via a
synthetic `/etc/hosts` that is only injected when at least one rule
references a concrete host. Pure `:port`, `udp://*:*`, and `icmp://*`
rules leave the host's real DNS configuration visible.

## `[http]`

HTTP-level access control via a transparent MITM proxy.

| Python       | TOML    | Type            | Default | Description                                                                          |
| ------------ | ------- | --------------- | ------- | ------------------------------------------------------------------------------------ |
| `http_allow` | `allow` | `Sequence[str]` | `()`    | Allow rules of the form `"METHOD host/path"` with glob path matching.                |
| `http_deny`  | `deny`  | `Sequence[str]` | `()`    | Deny rules, checked before allow rules. Same format as `http_allow`.                 |
| `http_ports` | `ports` | `Sequence[int]` | `()`    | TCP ports to intercept. Defaults to `[80]`; `443` is added when `http_ca` is set.    |

When `http_allow` or `http_deny` is non-empty, the supervisor spawns
the proxy and redirects matching ports to it. HTTP rules with concrete
hosts auto-extend `net_allow` with the corresponding TCP entry on each
entry of `http_ports` (and on `443` when `http_ca` is set). Wildcard
hosts auto-add `:80` (and `:443` when `http_ca` is set). All
auto-added entries are TCP.

## `[syscalls]`

Adjustments to Sandlock's default seccomp-bpf blocklist. The default
blocklist is applied unconditionally; the fields below alter it.

| Python                 | TOML          | Type            | Default | Description                                                                          |
| ---------------------- | ------------- | --------------- | ------- | ------------------------------------------------------------------------------------ |
| `extra_allow_syscalls` | `extra_allow` | `Sequence[str]` | `()`    | Syscall group names to re-allow (e.g. `"sysv_ipc"`).                                 |
| `extra_deny_syscalls`  | `extra_deny`  | `Sequence[str]` | `()`    | Additional syscall names to block on top of the default blocklist.                   |

## `[limits]`

Resource caps and visibility limits. The TOML schema drops the `max_`
prefix that the Python field names carry, because `[limits]` makes the
prefix redundant; the GPU and CPU placement fields keep their names.

| Python           | TOML          | Type                    | Default | Description                                                                                                                  |
| ---------------- | ------------- | ----------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `max_memory`     | `memory`      | `str \| int \| None`    | `None`  | Memory limit. Accepts strings such as `"512M"`, `"1G"`, or an integer byte count.                                            |
| `max_processes`  | `processes`   | `int`                   | `64`    | Maximum **lifetime** fork count permitted in the sandbox (not concurrent). Also enables fork interception used by checkpoint freeze. |
| `max_open_files` | `open_files`  | `int \| None`           | `None`  | Maximum number of open file descriptors. Enforced via `RLIMIT_NOFILE` (kernel, survives `exec`).                              |
| `max_cpu`        | `cpu`         | `int \| None`           | `None`  | CPU throttle as a percentage of one core (1 to 100). Applied to the entire process group via `SIGSTOP`/`SIGCONT` cycling.    |
| `max_disk`       | `disk`        | `str \| None`           | `None`  | COW storage quota (e.g. `"1G"`). Returned as `ENOSPC` when the upper layer exceeds it.                                       |
| `gpu_devices`    | `gpu_devices` | `Sequence[int] \| None` | `None`  | GPU device indices to expose. `None` denies GPU access entirely; `[]` exposes every GPU; a list exposes only those devices. Adds Landlock rules for `/dev/nvidia*` and `/dev/dri/*` and sets `CUDA_VISIBLE_DEVICES` / `ROCR_VISIBLE_DEVICES`. |
| `cpu_cores`      | `cpu_cores`   | `Sequence[int] \| None` | `None`  | CPU cores to pin the sandbox to via `sched_setaffinity` in the child.                                                        |
| `num_cpus`       | `num_cpus`    | `int \| None`           | `None`  | Visible CPU count in `/proc/cpuinfo` (renumbered `0..N-1`). Also virtualizes `/proc/meminfo` when `max_memory` is set.        |

## Runtime kwargs (Python-only)

These fields are not part of the policy serialization (they are
flagged with `metadata={"runtime": True}` and skipped by serializers)
and have no TOML counterpart.

| Field       | Type              | Default | Description                                                                                                |
| ----------- | ----------------- | ------- | ---------------------------------------------------------------------------------------------------------- |
| `name`      | `str \| None`     | `None`  | Sandbox name and virtual hostname inside the sandbox. Auto-generated as `sandbox-{pid}` when omitted. Maximum 64 bytes; must not contain NUL. |
| `policy_fn` | `Callable \| None`| `None`  | Per-event dynamic policy callback. See the project README's "Dynamic Policy" section.                      |
| `init_fn`   | `Callable \| None`| `None`  | Callback invoked once in the template process prior to COW fork.                                           |
| `work_fn`   | `Callable \| None`| `None`  | Callback invoked in each COW clone; receives `clone_id` as its argument.                                   |

## Advanced

| Field          | Type                  | Default | Description                                                                                                                                       |
| -------------- | --------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `notif_policy` | `NotifPolicy \| None` | `None`  | Seccomp user-notification policy for `/proc` and `/sys` virtualization. Usually configured implicitly by the other fields; advanced use only.     |

## Protection opt-out

By default sandlock enforces every Landlock protection the host kernel
supports and refuses to start when a required protection is
unavailable. Two builder methods on `SandboxBuilder` let callers opt
out of the strict default on a per-protection basis:

- `allow_degraded(Protection::P)` — enforce `P` where the host kernel
  supports it, silently skip it where it does not. Use this when
  deploying across a mixed fleet of kernels where some lack the
  protection.
- `disable(Protection::P)` — never enforce `P`, even on a kernel that
  supports it. Use this when the workload legitimately needs the
  capability the protection blocks (for example signalling a sibling
  process when `SignalScope` would otherwise prevent it).

Calling neither method leaves the protection in its default `Strict`
state. The two methods are last-wins per protection: a later call for
the same `Protection` value supersedes the earlier one.

`sandlock check` reports each protection's availability against the
host's Landlock ABI; `Sandbox::active_protections()` returns the
per-protection resolved status (`Active`, `Degraded`, `Disabled`, or
`Unavailable`) of a constructed `Sandbox`.

Each `Protection` has a minimum Landlock ABI floor:

| `Protection`              | Landlock ABI floor |
| ------------------------- | ------------------ |
| `FsRefer`                 | v2                 |
| `FsTruncate`              | v3                 |
| `NetTcp`                  | v4                 |
| `FsIoctlDev`              | v5                 |
| `SignalScope`             | v6                 |
| `AbstractUnixSocketScope` | v6                 |

The protection policy is part of the checkpoint: a saved sandbox
restores with the exact per-protection posture it was built with.

Example:

```rust
use sandlock_core::{Protection, Sandbox};

let sb = Sandbox::builder()
    .fs_read("/data")
    .fs_write("/tmp")
    .allow_degraded(Protection::SignalScope)
    .allow_degraded(Protection::AbstractUnixSocketScope)
    .build()?;
```

The two `allow_degraded` calls let the sandbox build on Linux kernels
below 6.12, where the v6 IPC scopes are unavailable. On a kernel that
does support them, the scopes remain enforced.

## Enumerations

### `BranchAction`

```python
class BranchAction(Enum):
    COMMIT = "commit"   # Merge branch writes into the parent branch.
    ABORT  = "abort"    # Discard all branch writes.
    KEEP   = "keep"     # Leave the branch as-is; caller decides.
```

## Result types

```python
@dataclass(frozen=True)
class Change:
    kind: str   # "A" = added, "M" = modified, "D" = deleted.
    path: str   # Path relative to workdir.
```

```python
@dataclass
class DryRunResult:
    success:   bool
    exit_code: int
    stdout:    bytes
    stderr:    bytes
    changes:   list[Change]
    error:     str | None
```

## Helpers

```python
from sandlock import parse_ports

parse_ports([80, "443", "8000-8005"])
# => [80, 443, 8000, 8001, 8002, 8003, 8004, 8005]
```

## Behavioral notes

1. **Default-deny network.** `net_allow=()` (the default) denies all
   outbound traffic. Protocol gating is a function of rule presence:
   the seccomp layer denies UDP and ICMP socket creation when no rule
   of that protocol is configured.
2. **Seccomp COW with `workdir`.** When `workdir` is set, the
   seccomp-based COW path intercepts writes under `workdir` and stages
   them in an upper layer, committed or aborted on exit per `on_exit` /
   `on_error`.
3. **HTTP host auto-expansion.** HTTP rules referencing concrete hosts
   auto-add corresponding TCP entries on `http_ports` (and on `443`
   when `http_ca` is set). Wildcard hosts add the equivalent any-IP
   entries. All auto-added entries are TCP.
4. **TOCTOU and `policy_fn`.** Path strings are never exposed on
   policy events because seccomp user notification re-reads
   user-memory pointers after `Continue`. Path-based control belongs
   in static Landlock rules (`fs_readable`, `fs_writable`,
   `fs_denied`) or in `ctx.deny_path()` for runtime additions.
   `event.argv` is exposed and TOCTOU-safe; the supervisor freezes
   peer tasks before exposing it.
