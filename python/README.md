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
from sandlock import Sandbox

sandbox = Sandbox(
    fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev"],
    fs_writable=["/tmp"],
)
result = sandbox.run(["echo", "hello"], timeout=10)
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

### Confine

Apply a `Sandbox`'s Landlock rules to the **current** process, in
place. No fork, no exec.

```python
from sandlock import Sandbox, confine

confine(Sandbox(
    fs_readable=["/usr", "/lib"],
    fs_writable=["/tmp"],
))
```

#### `sandlock.confine(sandbox) -> None`

Set `PR_SET_NO_NEW_PRIVS` and install the sandbox's Landlock ruleset
on the live process. The confinement is **irreversible**.

Only Landlock fields are honored (`fs_readable`, `fs_writable`,
`fs_denied`); IPC and signal scoping are always applied. Sandbox
config that requires a supervisor or a fresh child (seccomp, network,
resource limits, COW, env, `policy_fn`, etc.) is rejected rather than
silently ignored. Raises `ConfinementError` on failure.

### Sandbox

```python
sandlock.Sandbox(**kwargs)
```

Sandbox configuration and runtime handle. Holds both the policy (filesystem,
network, resource limits, etc.) and runtime state. Construct once, then call
`run()` (blocking) or `spawn()` + lifecycle methods, or use as a context manager.

All config fields are optional. Unset fields mean "no restriction" unless
noted otherwise. Runtime kwargs (`name`, `policy_fn`, `init_fn`, `work_fn`)
are set at construction time alongside config fields.

A single `Sandbox` instance holds at most one running process at a time.
For concurrent execution, create multiple instances.

**Runtime kwargs:**

- `name` -- sandbox name (also its virtual hostname inside the sandbox).
  Auto-generated as `sandbox-{pid}` when omitted.
- `policy_fn` -- optional callback for dynamic per-event policy decisions
  (see [Dynamic policy](#dynamic-policy)).
- `init_fn` / `work_fn` -- callbacks for COW fork mode (see [Fork](#fork)).

`Sandbox` is a context manager:

```python
with Sandbox(fs_readable=["/usr", "/lib"]) as sb:
    result = sb.run(["echo", "hello"])
```

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
| `net_allow` | `list[str]` | `[]` | Outbound endpoint rules. Bare `host:port` is TCP; protocol prefixes opt others in: `tcp://host:port`, `udp://host:port` (or `udp://*:*` for any UDP), `icmp://host` (or `icmp://*` for any ICMP echo via the kernel ping socket — gated by `net.ipv4.ping_group_range` on the host). Empty = deny all. Raw ICMP is not exposed. |
| `net_allow_bind` | `list[int \| str]` | `[]` | TCP ports the sandbox may bind (empty = deny all) |
| `port_remap` | `bool` | `False` | Transparent TCP port virtualization |

#### HTTP ACL

Enforce method + host + path rules on HTTP traffic via a transparent
MITM proxy. When `http_allow` is set, all non-matching HTTP requests are
denied by default. Block rules are checked first and take precedence.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `http_allow` | `list[str]` | `[]` | Allow rules in `"METHOD host/path"` format |
| `http_deny` | `list[str]` | `[]` | Block rules in `"METHOD host/path"` format |
| `http_ports` | `list[int]` | `[80]` | TCP ports to intercept (443 added when `http_ca` is set) |
| `http_ca` | `str \| None` | `None` | CA certificate for HTTPS MITM |
| `http_key` | `str \| None` | `None` | CA private key for HTTPS MITM |
| `http_inject_ca` | `list[str]` | `[]` | Trust bundle paths to splice the active MITM CA's public cert into at open time. Without `http_ca`, generates an ephemeral CA (key in memory only) and intercepts port 443. Requires an `http_allow` / `http_deny` rule |
| `http_ca_out` | `str \| None` | `None` | Writes the active CA's public certificate (PEM) to this path; never the private key. Requires an `http_allow` / `http_deny` rule |

Rule format: `"METHOD host/path"` where method and host can be `*` for
wildcard, and path supports trailing `*` for prefix matching. Paths are
normalized (percent-decoding, `..` resolution, `//` collapsing) before
matching to prevent bypasses.

```python
sandbox = Sandbox(
    fs_readable=["/usr", "/lib", "/etc"],
    http_allow=[
        "GET docs.python.org/*",
        "POST api.openai.com/v1/chat/completions",
    ],
    http_deny=["* */admin/*"],
)
result = sandbox.run(["python3", "agent.py"])
```

#### Chroot with mount mapping

Map host directories into a chroot — like Docker's `-v /host:/container`
but without kernel bind mounts or root privileges. Each sandbox gets its
own persistent workspace while sharing a read-only rootfs.

```python
sandbox = Sandbox(
    chroot="/opt/rootfs",
    fs_mount={"/work": "/tmp/sandbox-1/work"},
    fs_readable=["/usr", "/bin", "/lib", "/etc"],
    cwd="/work",
)
result = sandbox.run(["python3", "task.py"])
```

Combine with `workdir` + `max_disk` for quota-enforced writes:

```python
sandbox = Sandbox(
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
| `extra_deny_syscalls` | `list[str]` | `[]` | Extra syscall names to block in addition to Sandlock defaults |
| `extra_allow_syscalls` | `list[str]` | `[]` | Syscall groups to allow that are blocked by default (e.g. `"sysv_ipc"` to enable SysV shared memory, semaphores, and message queues) |

Sandlock always applies its default syscall blocklist.

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
| `uid` | `int \| None` | `None` | Map to given UID inside a user namespace (e.g. `0` for fake root). Set together with `gid` |
| `gid` | `int \| None` | `None` | Map to given GID inside the user namespace. Must be set together with `uid` (both or neither) |
| `no_coredump` | `bool` | `False` | Disable core dumps |

#### COW filesystem isolation

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `fs_storage` | `str \| None` | `None` | Storage directory for the seccomp COW upper layer / deltas |
| `max_disk` | `str \| None` | `None` | Disk quota for COW storage (e.g. `"1G"`) |
| `on_exit` | `BranchAction` | `COMMIT` | `COMMIT`, `ABORT`, or `KEEP` |
| `on_error` | `BranchAction` | `ABORT` | `COMMIT`, `ABORT`, or `KEEP` |

#### Protection opt-out

By default sandlock enforces every Landlock protection the host kernel
supports and refuses to start when a required protection is
unavailable. Two keyword arguments on `Sandbox` opt out of the strict
default on a per-protection basis:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `allow_degraded` | `list[Protection]` | `[]` | Enforce each listed protection where the host kernel supports it, silently skip it where it does not. |
| `disable` | `list[Protection]` | `[]` | Never enforce each listed protection, even on a kernel that supports it. |

```python
from sandlock import Sandbox, Protection

sb = Sandbox(
    fs_readable=["/data"],
    fs_writable=["/tmp"],
    allow_degraded=[Protection.SIGNAL_SCOPE, Protection.ABSTRACT_UNIX_SOCKET_SCOPE],
)
```

The two `allow_degraded` entries let the sandbox build on Linux kernels
below 6.12, where the v6 IPC scopes are unavailable; on a capable kernel
the scopes remain enforced. The protection policy is persisted with a
checkpoint, so a restored sandbox keeps the exact posture it was built
with. See the "Protection opt-out" section of
[`../docs/sandbox-reference.md`](../docs/sandbox-reference.md#protection-opt-out)
for the per-protection ABI floors and the full semantics.

#### `sandbox.run(cmd, timeout=None) -> Result`

Run a command, capturing stdout and stderr.

- `cmd` -- list of strings (command and arguments).
- `timeout` -- max execution time in seconds (float). `None` = no timeout.

```python
result = sandbox.run(["python3", "-c", "print(42)"], timeout=10.0)
```

#### `sandbox.spawn(cmd) -> None`

Spawn `cmd` without waiting. Use `pid`, `pause()`, `resume()`, `kill()`,
and `wait()` to manage the process lifecycle.

Raises `RuntimeError` if a process is already running.

Sugar for `create(cmd) + start()`; use those directly when you need the
fork-park-exec split (e.g. starting several sandboxes in lockstep, or
attaching external tracing to the parked PID before the child execs).

#### `sandbox.create(cmd) -> None`

Fork the sandboxed child and install policy. The child is parked between
policy install and `execve`; call `start()` to release it. `pid` is
available after this call but the child is not yet running user code.

Raises `RuntimeError` if a process is already running.

#### `sandbox.start() -> None`

Release a previously `create()`d child to `execve`.

Raises `RuntimeError` if no child has been created.

#### `sandbox.wait() -> Result`

Wait for the running process to finish and return its `Result`.

#### `sandbox.dry_run(cmd, timeout=None) -> DryRunResult`

Run a command in a temporary COW layer, then discard all writes.
Returns the list of filesystem changes that would have been made.

```python
result = sandbox.dry_run(["sh", "-c", "echo hi > /tmp/out.txt"])
for change in result.changes:
    print(change.kind, change.path)  # "A /tmp/out.txt"
```

#### `sandbox.run_interactive(cmd) -> int`

Run with inherited stdio (no capture). Returns the exit code.

#### `sandbox.name -> str | None`

The sandbox name.

#### `sandbox.pid -> int | None`

The child PID while running, `None` otherwise.

#### `sandbox.is_running -> bool`

`True` if a process is currently running in this sandbox.

#### `sandbox.ports() -> dict[int, int]`

Current port mappings `{virtual_port: real_port}` while running.
Only contains entries where port remapping occurred. Requires `port_remap=True`.

#### `sandbox.pause()` / `sandbox.resume()` / `sandbox.kill()`

Send SIGSTOP / SIGCONT / SIGKILL to the sandbox process group.
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
    sandbox_a.cmd(["echo", "hello"])
    | sandbox_b.cmd(["tr", "a-z", "A-Z"])
).run()
assert result.stdout == b"HELLO\n"
```

#### `sandbox.cmd(args) -> Stage`

Create a lazy `Stage` bound to this sandbox.

#### `pipeline.run(stdout=None, timeout=None) -> Result`

Run the pipeline. Each stage's stdout feeds the next stage's stdin.

### Gather

Fan multiple producers into one consumer via named pipes. Each
producer's stdout is delivered to the consumer under a label the
consumer reads from a `sandlock.inputs` dict. This is the structural
primitive behind the XOA pattern: producers and consumer are
independent sandboxes, and the consumer never executes producer code
inside its own LLM call.

```python
from sandlock import Sandbox

planner  = Sandbox(...)   # writes code
searcher = Sandbox(...)   # produces data
executor = Sandbox(...)   # consumes both

result = (
    searcher.cmd(["python3", "-c", "..."]).as_("data")
    + planner.cmd(["python3", "-c", "..."]).as_("code")
    | executor.cmd(["python3", "consume.py"])
).run()
```

Inside `consume.py`:

```python
from sandlock import inputs

code = inputs["code"]
data = inputs["data"]
exec(compile(code, "<planner>", "exec"), {"data": data})
```

#### `stage.as_(name) -> NamedStage`

Label a `Stage`'s stdout so the consumer can address it by name.

#### `named_stage + named_stage_or_gather -> Gather`

Combine two or more `NamedStage` values into a `Gather`. Repeated `+`
extends the gather:

```python
g = a.as_("x") + b.as_("y") + c.as_("z")
```

#### `gather | consumer_stage -> GatherPipeline`

Compose a `Gather` with a consumer `Stage` to form the runnable
pipeline.

#### `gather_pipeline.run(timeout=None) -> Result`

Run all producers in parallel; each producer's stdout is wired to a
pipe the consumer reads via `inputs[name]`. Returns the consumer's
`Result`.

#### `sandlock.inputs`

Lazy dict-like accessor available inside the consumer process. Reads
each producer's pipe on first access and caches the value.

```python
from sandlock import inputs

inputs["code"]        # str: the producer's full stdout, decoded as utf-8
"data" in inputs      # bool
list(inputs.keys())   # ["data", "code"]
```

The pipe fds are passed via the `_SANDLOCK_GATHER` env var
(`name:fd,name:fd,...`); the `inputs` object parses it on first
access. Users do not interact with the env var directly.

### Dynamic policy

Use `policy_fn` to make per-syscall decisions at runtime:

```python
from sandlock import Sandbox, SyscallEvent, PolicyContext

def my_policy(event: SyscallEvent, ctx: PolicyContext):
    if event.category == "network" and event.host == "evil.com":
        return True   # deny
    if event.category == "file" and "/secrets" in (event.path or ""):
        ctx.deny_path("/secrets")
        return True   # deny
    return False      # allow

sb = Sandbox(..., policy_fn=my_policy)
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
sb = Sandbox(
    fs_readable=[...],
    init_fn=lambda: load_model(),
    work_fn=lambda clone_id: process(clone_id),
)
clones = sb.fork(4)  # returns ForkResult with .pids
```

#### `sandbox.reduce(cmd, fork_result) -> Result`

Pipe combined clone output into a reducer command:

```python
result = sandbox.reduce(["python3", "sum.py"], clones)
```

### Checkpoint

Save and restore sandbox state:

```python
sb = Sandbox(...)
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

Load sandbox configuration from TOML files:
Profiles contain sandbox config only; pass the sandbox name at construction: `Sandbox(..., name=...)`.

```python
from sandlock import load_profile, list_profiles

sandbox = load_profile("web-scraper")
names = list_profiles()
```

### Exceptions

```
SandlockError (base)
  +-- SandboxError         invalid sandbox configuration
  +-- SandboxRuntimeError  sandbox lifecycle errors
        +-- ForkError          fork failed
        +-- ChildError         child exited abnormally
        +-- BranchError        COW branch operation failed
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
from sandlock import SandlockError, SandboxError, SandboxRuntimeError
```

### Enums

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

Register a local tool. `func` must be a top-level function in an import-safe
module: the worker imports that module by name and calls the function in a
fresh per-call sandbox. Module-level imports, helpers, constants, and state
are all fine; lambdas, methods, and nested functions are rejected. Guard any
module startup logic under `if __name__ == "__main__":`.

A tool that declares a parameter named `workspace` receives the sandbox's
workspace path automatically (injected at call time, hidden from the LLM
schema, and not overridable by the model). No env wiring needed.

```python
# tools.py  (an importable module)
import os

def read_file(path: str, *, workspace: str) -> str:
    with open(os.path.join(workspace, path)) as f:
        return f.read()
```

```python
import tools

mcp.add_tool("read_file", tools.read_file,
    description="Read a file from the workspace",
)
```

No capabilities = read-only, clean environment, no network. Grant
permissions explicitly:

| Capability | Example | Description |
|------------|---------|-------------|
| `fs_writable` | `["/tmp/agent"]` | Paths the tool can write to |
| `net_allow` | `["api.example.com:443", "udp://1.1.1.1:53"]` | Outbound endpoints. Bare `host:port` is TCP; `udp://...` / `icmp://...` schemes opt UDP / ICMP echo in. |
| `env` | `{"KEY": "val"}` | Environment variables to pass |
| `max_memory` | `"256M"` | Memory limit |

Any `Sandbox` field name is accepted as a capability key.

#### `await mcp.add_mcp_session(session)`

Discover tools from a remote MCP server. Capabilities are read from
`sandlock:*` keys in the tool's annotations or meta dict.

#### `await mcp.call_tool(name, arguments=None, *, timeout=None) -> str`

Call a tool by name. Local tools run in a per-call sandbox. MCP tools
are forwarded to their server session.

```python
result = await mcp.call_tool("read_file", {"path": "data.txt"})
```

#### `mcp.get_policy(tool_name) -> Sandbox`

Return the computed `Sandbox` for a registered tool.

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

#### `policy_for_tool(*, workspace, capabilities=None) -> Sandbox`

Build a deny-by-default `Sandbox` from explicit capabilities. Used
internally by `McpSandbox` but available for direct use.

#### `capabilities_from_mcp_tool(tool) -> dict`

Extract `sandlock:*` capabilities from an MCP tool's annotations/meta.

## License

Apache-2.0
