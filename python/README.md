# sandlock Python SDK

Python bindings for [sandlock](https://github.com/multikernel/sandlock), a
lightweight process sandbox using Landlock and seccomp. No root, no Docker,
no namespaces required.

Requires Linux 6.7+ with Landlock ABI v6.

```
pip install sandlock
```

## Quick start

```python
from sandlock import Sandbox, Policy

policy = Policy(
    fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"],
    fs_writable=["/tmp"],
)
result = Sandbox(policy).run(["echo", "hello"], timeout=10)
assert result.success
print(result.stdout)  # b"hello\n"
```

## API reference

### Platform

#### `sandlock.landlock_abi_version() -> int`

Return the Landlock ABI version supported by the running kernel.
Returns -1 if Landlock is unavailable.

#### `sandlock.min_landlock_abi() -> int`

Return the minimum Landlock ABI version required by sandlock (currently 6).

### Policy

```python
sandlock.Policy(**kwargs)
```

An immutable (frozen dataclass) sandbox policy. All fields are optional.
Unset fields mean "no restriction" unless noted otherwise.

#### Filesystem (Landlock)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `fs_readable` | `list[str]` | `[]` | Paths the sandbox can read |
| `fs_writable` | `list[str]` | `[]` | Paths the sandbox can write |
| `fs_denied` | `list[str]` | `[]` | Paths explicitly denied |
| `workdir` | `str \| None` | `None` | Working directory; enables COW protection |
| `chroot` | `str \| None` | `None` | Path to chroot into before confinement |
| `fs_mount` | `dict[str, str]` | `{}` | Map virtual paths to host directories inside chroot |
| `cwd` | `str \| None` | `None` | Child working directory |

#### Network

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `net_allow_hosts` | `list[str]` | `[]` | Allowed domain names (empty = unrestricted) |
| `net_bind` | `list[int \| str]` | `[]` | TCP ports the sandbox may bind (empty = unrestricted) |
| `net_connect` | `list[int \| str]` | `[]` | TCP ports the sandbox may connect to (empty = unrestricted) |
| `port_remap` | `bool` | `False` | Transparent TCP port virtualization |
| `no_raw_sockets` | `bool` | `True` | Block raw IP sockets |
| `no_udp` | `bool` | `False` | Block UDP sockets |

#### HTTP ACL

Enforce method + host + path rules on HTTP traffic via a transparent
MITM proxy. When `http_allow` is set, all non-matching HTTP requests are
denied by default. Deny rules are checked first and take precedence.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `http_allow` | `list[str]` | `[]` | Allow rules in `"METHOD host/path"` format |
| `http_deny` | `list[str]` | `[]` | Deny rules in `"METHOD host/path"` format |
| `http_ports` | `list[int]` | `[80]` | TCP ports to intercept (443 added when `https_ca` is set) |
| `https_ca` | `str \| None` | `None` | CA certificate for HTTPS MITM |
| `https_key` | `str \| None` | `None` | CA private key for HTTPS MITM |

Rule format: `"METHOD host/path"` where method and host can be `*` for
wildcard, and path supports trailing `*` for prefix matching. Paths are
normalized (percent-decoding, `..` resolution, `//` collapsing) before
matching to prevent bypasses.

```python
policy = Policy(
    fs_readable=["/usr", "/lib", "/etc"],
    http_allow=[
        "GET docs.python.org/*",
        "POST api.openai.com/v1/chat/completions",
    ],
    http_deny=["* */admin/*"],
)
result = Sandbox(policy).run(["python3", "agent.py"])
```

#### Chroot with mount mapping

Map host directories into a chroot — like Docker's `-v /host:/container`
but without kernel bind mounts or root privileges. Each sandbox gets its
own persistent workspace while sharing a read-only rootfs.

```python
policy = Policy(
    chroot="/opt/rootfs",
    fs_mount={"/work": "/tmp/sandbox-1/work"},
    fs_readable=["/usr", "/bin", "/lib", "/etc"],
    cwd="/work",
)
result = Sandbox(policy).run(["python3", "task.py"])
```

Combine with `workdir` + `max_disk` for quota-enforced writes:

```python
policy = Policy(
    chroot="/opt/rootfs",
    fs_mount={"/work": "/tmp/sandbox-1/work"},
    workdir="/tmp/sandbox-1/work",
    fs_storage="/tmp/sandbox-1/cow",
    max_disk="100M",
    on_exit="commit",
    fs_readable=["/usr", "/bin", "/lib", "/etc"],
)
```

#### Resource limits

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_memory` | `str \| int \| None` | `None` | Memory limit, e.g. `"512M"` or int bytes |
| `max_processes` | `int` | `64` | Peak concurrent process limit |
| `max_open_files` | `int \| None` | `None` | Max file descriptors (RLIMIT_NOFILE) |
| `max_cpu` | `int \| None` | `None` | CPU throttle as percentage of one core (1-100) |
| `cpu_cores` | `list[int] \| None` | `None` | CPU cores to pin sandbox to |
| `num_cpus` | `int \| None` | `None` | Visible CPU count in /proc/cpuinfo |

#### Syscall filtering (seccomp)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `deny_syscalls` | `list[str] \| None` | `None` | Syscall names to block (blocklist mode) |
| `allow_syscalls` | `list[str] \| None` | `None` | Syscall names to allow (allowlist mode) |

Set one or neither, not both.

#### Deterministic execution

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `random_seed` | `int \| None` | `None` | Seed for deterministic getrandom() |
| `time_start` | `datetime \| float \| str \| None` | `None` | Start timestamp for time virtualization |
| `no_randomize_memory` | `bool` | `False` | Disable ASLR |
| `no_huge_pages` | `bool` | `False` | Disable Transparent Huge Pages |
| `deterministic_dirs` | `bool` | `False` | Sort directory entries lexicographically |

#### Environment

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `clean_env` | `bool` | `False` | Start with minimal environment |
| `env` | `dict[str, str]` | `{}` | Variables to set/override in the child |

#### GPU access

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `gpu_devices` | `list[int] \| None` | `None` | GPU device indices to expose (`[]` = all) |

#### Misc

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `uid` | `int \| None` | `None` | Map to given UID inside a user namespace (e.g. `0` for fake root) |
| `no_coredump` | `bool` | `False` | Disable core dumps |

#### COW filesystem isolation

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `fs_isolation` | `FsIsolation` | `NONE` | `NONE`, `BRANCHFS`, or `OVERLAYFS` |
| `fs_storage` | `str \| None` | `None` | Storage directory for BranchFS deltas |
| `max_disk` | `str \| None` | `None` | Disk quota for BranchFS (e.g. `"1G"`) |
| `on_exit` | `BranchAction` | `COMMIT` | `COMMIT`, `ABORT`, or `KEEP` |
| `on_error` | `BranchAction` | `ABORT` | `COMMIT`, `ABORT`, or `KEEP` |

### Sandbox

```python
sandlock.Sandbox(policy, policy_fn=None, init_fn=None, work_fn=None, name=None)
```

Create a sandbox from a `Policy`.

- `policy` -- a `Policy` instance.
- `name` -- sandbox name (also sets UTS hostname inside the sandbox).
  Auto-generated as `sandbox-{pid}` when omitted.
- `policy_fn` -- optional callback for dynamic per-event decisions (see
  [Dynamic policy](#dynamic-policy)).
- `init_fn` / `work_fn` -- callbacks for COW fork mode (see [Fork](#fork)).

Sandbox is a context manager:

```python
with Sandbox(policy) as sb:
    result = sb.run(["echo", "hello"])
```

#### `sandbox.run(cmd, timeout=None) -> Result`

Run a command, capturing stdout and stderr.

- `cmd` -- list of strings (command and arguments).
- `timeout` -- max execution time in seconds (float). `None` = no timeout.

```python
result = Sandbox(policy).run(["python3", "-c", "print(42)"], timeout=10.0)
```

#### `sandbox.dry_run(cmd, timeout=None) -> DryRunResult`

Run a command in a temporary COW layer, then discard all writes.
Returns the list of filesystem changes that would have been made.

```python
result = Sandbox(policy).dry_run(["sh", "-c", "echo hi > /tmp/out.txt"])
for change in result.changes:
    print(change.kind, change.path)  # "A /tmp/out.txt"
```

#### `sandbox.run_interactive(cmd) -> int`

Run with inherited stdio (no capture). Returns the exit code.

#### `sandbox.name -> str | None`

The sandbox name.

#### `sandbox.pid -> int | None`

The child PID while running, `None` otherwise.

#### `sandbox.ports() -> dict[int, int]`

Current port mappings `{virtual_port: real_port}` while running.
Only contains entries where port remapping occurred. Requires `port_remap=True`.

#### `sandbox.pause()` / `sandbox.resume()`

Send SIGSTOP / SIGCONT to the sandbox process group.
Raises `RuntimeError` if the sandbox is not running.

#### `sandbox.checkpoint(save_fn=None) -> Checkpoint`

Capture a checkpoint of the running sandbox. See [Checkpoint](#checkpoint).

### Result

Returned by `sandbox.run()`.

| Attribute | Type | Description |
|-----------|------|-------------|
| `success` | `bool` | True if exit code is 0 |
| `exit_code` | `int` | Process exit code |
| `stdout` | `bytes` | Captured standard output |
| `stderr` | `bytes` | Captured standard error |
| `error` | `str \| None` | Error message on failure |

### DryRunResult

Returned by `sandbox.dry_run()`.

Same attributes as `Result`, plus:

| Attribute | Type | Description |
|-----------|------|-------------|
| `changes` | `list[Change]` | Filesystem changes detected |

### Change

| Attribute | Type | Description |
|-----------|------|-------------|
| `kind` | `str` | `"A"` (added), `"M"` (modified), or `"D"` (deleted) |
| `path` | `str` | Path relative to workdir |

### Stage and Pipeline

Chain sandboxed commands with pipes using the `|` operator:

```python
result = (
    Sandbox(policy_a).cmd(["echo", "hello"])
    | Sandbox(policy_b).cmd(["tr", "a-z", "A-Z"])
).run()
assert result.stdout == b"HELLO\n"
```

#### `sandbox.cmd(args) -> Stage`

Create a lazy `Stage` bound to this sandbox.

#### `pipeline.run(stdout=None, timeout=None) -> Result`

Run the pipeline. Each stage's stdout feeds the next stage's stdin.

### Dynamic policy

Use `policy_fn` to make per-syscall decisions at runtime:

```python
from sandlock import Sandbox, Policy, SyscallEvent, PolicyContext

def my_policy(event: SyscallEvent, ctx: PolicyContext):
    if event.category == "network" and event.host == "evil.com":
        return True   # deny
    if event.category == "file" and "/secrets" in (event.path or ""):
        ctx.deny_path("/secrets")
        return True   # deny
    return False      # allow

sb = Sandbox(Policy(...), policy_fn=my_policy)
```

#### SyscallEvent

| Attribute | Type | Description |
|-----------|------|-------------|
| `syscall` | `str` | Syscall name (e.g. `"openat"`, `"connect"`) |
| `category` | `str` | `"file"`, `"network"`, `"process"`, or `"memory"` |
| `pid` | `int` | Process ID |
| `parent_pid` | `int` | Parent process ID |
| `path` | `str \| None` | File path (for file events) |
| `host` | `str \| None` | Hostname (for network events) |
| `port` | `int` | Port number (for network events) |
| `argv` | `tuple[str, ...] \| None` | Command arguments (for execve) |
| `denied` | `bool` | Whether this event was already denied by static policy |

Helper methods:

- `event.path_contains(s)` -- True if path contains substring s
- `event.argv_contains(s)` -- True if any argv element contains s

#### PolicyContext

Methods available inside `policy_fn`:

| Method | Description |
|--------|-------------|
| `ctx.restrict_network(ips)` | Restrict to given IP addresses |
| `ctx.grant_network(ips)` | Allow additional IP addresses |
| `ctx.restrict_max_memory(bytes)` | Lower memory limit |
| `ctx.restrict_max_processes(n)` | Lower process limit |
| `ctx.restrict_pid_network(pid, ips)` | Per-PID network restriction |
| `ctx.deny_path(path)` | Deny access to a path |
| `ctx.allow_path(path)` | Remove a previously denied path |

Callback return values:

| Return | Meaning |
|--------|---------|
| `None`, `False`, `0` | Allow |
| `True`, `-1` | Deny (EPERM) |
| positive `int` | Deny with that errno |
| `"audit"`, `-2` | Allow but flag for audit |

### Fork

COW fork for parallel execution with shared initialization:

```python
sb = Sandbox(policy,
    init_fn=lambda: load_model(),
    work_fn=lambda clone_id: process(clone_id),
)
clones = sb.fork(4)  # returns ForkResult with .pids
```

#### `sandbox.reduce(cmd, fork_result) -> Result`

Pipe combined clone output into a reducer command:

```python
result = Sandbox(policy).reduce(["python3", "sum.py"], clones)
```

### Checkpoint

Save and restore sandbox state:

```python
sb = Sandbox(policy)
# ... start a long-running process ...
cp = sb.checkpoint(save_fn=lambda: my_state_bytes())
cp.save("my-snapshot")

# Later:
cp2 = Checkpoint.load("my-snapshot")
Checkpoint.restore("my-snapshot", restore_fn=lambda data: rebuild(data))
```

| Method | Description |
|--------|-------------|
| `cp.save(name, store=None)` | Persist checkpoint to disk |
| `Checkpoint.load(name, store=None)` | Load from disk |
| `Checkpoint.restore(name, restore_fn, store=None)` | Load and call restore_fn with app_state |
| `Checkpoint.list(store=None)` | List saved checkpoint names |
| `Checkpoint.delete(name, store=None)` | Delete a saved checkpoint |

Properties: `cp.name` (str), `cp.app_state` (bytes or None).

Default store: `~/.sandlock/checkpoints/`.

### Profiles

Load policies from TOML files:

```python
from sandlock import load_profile, list_profiles

policy = load_profile("web-scraper")
names = list_profiles()
```

### Exceptions

```
SandlockError (base)
  +-- PolicyError          invalid policy configuration
  +-- SandboxError         sandbox lifecycle errors
        +-- ForkError          fork failed
        +-- ChildError         child exited abnormally
        +-- BranchError        BranchFS operation failed
        |     +-- BranchConflictError   sibling branch committed (ESTALE)
        +-- ConfinementError   Landlock/seccomp setup failed
              +-- LandlockUnavailableError   no Landlock support
              +-- SeccompError               seccomp filter failed
                    +-- NotifError           notif supervisor error
  +-- MemoryProtectError   mprotect failed
```

All exceptions are importable from `sandlock.exceptions` or directly from
`sandlock`:

```python
from sandlock import SandlockError, SandboxError, PolicyError
```

### Enums

#### `FsIsolation`

- `FsIsolation.NONE` -- direct host writes (default)
- `FsIsolation.BRANCHFS` -- BranchFS COW isolation
- `FsIsolation.OVERLAYFS` -- OverlayFS COW

#### `BranchAction`

- `BranchAction.COMMIT` -- merge writes on exit
- `BranchAction.ABORT` -- discard writes
- `BranchAction.KEEP` -- leave branch as-is

### MCP integration

Sandboxed tool execution for AI agents. Each tool runs in a per-call
sandbox with deny-by-default permissions.

```
pip install 'sandlock[mcp]'
```

#### McpSandbox

```python
from sandlock.mcp import McpSandbox

mcp = McpSandbox(workspace="/tmp/agent", timeout=30.0)
```

- `workspace` -- directory the sandbox can read (default: `"/tmp/sandlock"`).
- `timeout` -- default timeout in seconds per tool call (default: `30.0`).

#### `mcp.add_tool(name, func, *, description="", capabilities=None, input_schema=None)`

Register a local tool. The function must be self-contained (imports inside
the body) -- it is serialized and executed in a fresh sandbox process.

```python
def read_file(path: str) -> str:
    import os
    workspace = os.environ["SANDLOCK_WORKSPACE"]
    with open(os.path.join(workspace, path)) as f:
        return f.read()

mcp.add_tool("read_file", read_file,
    description="Read a file from the workspace",
    capabilities={"env": {"SANDLOCK_WORKSPACE": "/tmp/agent"}},
)
```

No capabilities = read-only, clean environment, no network. Grant
permissions explicitly:

| Capability | Example | Description |
|------------|---------|-------------|
| `fs_writable` | `["/tmp/agent"]` | Paths the tool can write to |
| `net_connect` | `[443]` | TCP ports the tool can connect to |
| `net_allow_hosts` | `["api.example.com"]` | Allowed domains (implies ports 80, 443) |
| `env` | `{"KEY": "val"}` | Environment variables to pass |
| `max_memory` | `"256M"` | Memory limit |

Any `Policy` field name is accepted as a capability key.

#### `await mcp.add_mcp_session(session)`

Discover tools from a remote MCP server. Capabilities are read from
`sandlock:*` keys in the tool's annotations or meta dict.

#### `await mcp.call_tool(name, arguments=None, *, timeout=None) -> str`

Call a tool by name. Local tools run in a per-call sandbox. MCP tools
are forwarded to their server session.

```python
result = await mcp.call_tool("read_file", {"path": "data.txt"})
```

#### `mcp.get_policy(tool_name) -> Policy`

Return the computed `Policy` for a registered tool.

#### `mcp.tool_definitions_openai() -> list[dict]`

Tool definitions in OpenAI function-calling format, for use with
chat completion APIs.

#### `mcp.tools -> dict[str, Any]`

All registered tools (local and MCP).

#### MCP server

A standalone MCP server with built-in sandboxed tools (shell, python,
read_file, write_file, list_files):

```bash
# stdio (for Claude Desktop / Cursor)
sandlock-mcp --workspace /tmp/sandbox

# SSE (remote)
pip install 'sandlock[mcp-remote]'
sandlock-mcp --transport sse --host 0.0.0.0 --port 8080 --workspace /tmp/sandbox
```

Claude Desktop configuration:

```json
{
  "mcpServers": {
    "sandlock": {
      "command": "sandlock-mcp",
      "args": ["--workspace", "/tmp/sandbox"]
    }
  }
}
```

#### `policy_for_tool(*, workspace, capabilities=None) -> Policy`

Build a deny-by-default `Policy` from explicit capabilities. Used
internally by `McpSandbox` but available for direct use.

#### `capabilities_from_mcp_tool(tool) -> dict`

Extract `sandlock:*` capabilities from an MCP tool's annotations/meta.

## License

Apache-2.0
