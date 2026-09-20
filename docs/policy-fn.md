# Dynamic Policy

A `policy_fn` callback inspects syscall events at runtime and adjusts
permissions on the fly. It complements the static Landlock and seccomp
rules; it does not replace them. This page documents the Python and Rust
callback shape, the event and context APIs, and the TOCTOU guarantees.

Events carry syscall name, category, PID, network destination (for
`connect`/`sendto`/`bind`), and `argv` (for `execve`). The callback
returns a verdict to allow, deny, or audit.

## Python

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
>   `fs_denied`), kernel-enforced and TOCTOU-immune. Use
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
- `ctx.restrict_network(ips)` / `ctx.grant_network(ips)`: network control
- `ctx.restrict_max_memory(bytes)` / `ctx.restrict_max_processes(n)`: resource limits
- `ctx.deny_path(path)` / `ctx.allow_path(path)`: dynamic filesystem restriction
- `ctx.restrict_pid_network(pid, ips)`: per-PID network override

**Held syscalls** (child blocked until callback returns): `execve`,
`connect`, `sendto`, `bind`, `openat`.

## Rust

```rust
use sandlock_core::Sandbox;
use sandlock_core::policy_fn::Verdict;

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

## Interaction with static rules

`policy_fn` only sees the syscalls the supervisor traps. Landlock rules
(`fs_readable`, `fs_writable`, `fs_denied`, TCP port rules) are evaluated
by the kernel first and never reach the callback, so a Landlock denial
cannot be overridden from `policy_fn`. Path-based decisions belong in
those static rules; use `ctx.deny_path()` for runtime additions.

Dynamic network restrictions are IP-only and resolve with legacy priority
(per-PID override > live policy > static allowlist); the static `net_deny`
layer is applied after the allow verdict and always wins, so a dynamic
override can never erase it.
