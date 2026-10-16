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
from sandlock import Sandbox, PolicyFn
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
    policy_fn=PolicyFn(on_event),
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
> - **`event.argv` is exposed and TOCTOU-safe.** `argv` is read without
>   stopping the sandbox, so other tasks keep running while an approval
>   is pending. After an allow, and before returning `Continue` for the
>   `execve`, the supervisor freezes every task in `ProcessIndex`,
>   including peer processes that may alias argv through shared memory,
>   re-reads `argv` and the path, and denies the `execve` with `EPERM`
>   unless they match what the callback judged. The freeze lasts until
>   the kernel has copied `argv`. With `policy_fn` active, fork-like
>   syscalls are traced for one ptrace creation event, so children are
>   registered in `ProcessIndex` before they can run user code. If the
>   freeze or creation tracking cannot be established (e.g., YAMA blocks
>   ptrace), the syscall is denied with `EPERM`; the safety invariant is
>   never silently relaxed.

**Context methods:**
- `ctx.restrict_network(ips)` / `ctx.grant_network(ips)`: network control
- `ctx.restrict_max_memory(bytes)` / `ctx.restrict_max_processes(n)`: resource limits
- `ctx.deny_path(path)` / `ctx.allow_path(path)`: dynamic filesystem restriction
- `ctx.restrict_pid_network(pid, ips)`: per-PID network override

**Held syscalls** (the calling task is blocked awaiting a verdict; the
rest of the sandbox keeps running): `execve`, `connect`, `sendto`,
`bind`, `openat`.

## Rust

```rust
use sandlock_core::Sandbox;
use sandlock_core::policy_fn::{PolicyFn, Verdict};

let mut dynamic = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib")
    .policy_fn(PolicyFn::new(|event, ctx| {
        if event.argv_contains("curl") {
            return Verdict::Deny;
        }
        if event.syscall == "execve" {
            ctx.restrict_network(&[]);
            ctx.deny_path("/etc/shadow");
        }
        Verdict::Allow
    }))
    .build()?;
let result = dynamic.run(&["python3", "agent.py"]).await?;
```

## Verdict timeout and shutdown

Each `PolicyFn` owns its callback and held-verdict timeout. The timeout defaults
to five seconds, including time queued behind another callback. Set
`PolicyFn(approve, verdict_timeout=120.0)` in Python or
`PolicyFn::new(approve).verdict_timeout(Some(Duration::from_secs(120)))` in Rust
to allow more time. Use `None` for the timeout in either API to wait without a
deadline. Zero denies immediately. Timeout expiry and closed verdict channels
deny the syscall with `EPERM`.

In Go, configure `PolicyFn: &sandlock.PolicyFn{Callback: approve,
VerdictTimeout: sandlock.NoTimeout}`. Its `VerdictTimeout` is a `time.Duration`:
zero uses the five-second default, positive values set a timeout, and negative
values disable it. Python and Go round positive fractional milliseconds up.

In C, pass the timeout in milliseconds alongside the callback:
`sandlock_sandbox_builder_policy_fn(builder, callback, timeout_ms, user_data,
user_data_drop)`. Negative values disable the timeout; zero denies immediately;
pass `5000` for the SDK default. There is no independent sandbox timeout setter.

Shutdown cancels outstanding verdict waits and discards queued events. A running
callback must cooperate: check `ctx.is_cancelled()` in Rust or Python,
`ctx.IsCancelled()` in Go, or `sandlock_ctx_is_cancelled(ctx)` in C between
bounded waits for user input. The context is valid only during its callback.
Shutdown joins that callback before releasing its data; it cannot forcibly
interrupt user code. A verdict timeout closes the verdict wait, but does not
interrupt a callback already running. Its eventual verdict is ignored.

## Deferred approval

A callback that returns its verdict holds the callback thread until it
decides, so later events queue behind a slow approval. A deferred callback
instead receives an approval handle for each held syscall, returns at once,
and answers later from any thread. The handle is absent for
observation-only events. Answering twice is an error; dropping or closing an
unanswered handle denies with `EPERM`, as does a callback that raises or
panics while holding one. The handle reports cancellation once shutdown or
the verdict timeout has decided, after which an answer is ignored.

A verdict decides only the event it answers: policy changed while an approval
was pending is not re-applied to that event.

```python
import queue
from sandlock import Sandbox, PolicyFn

pending = queue.Queue()

def on_event(event, ctx, approval):
    if approval is None:
        return
    if event.syscall != "execve":
        approval.allow()
        return
    pending.put((event, approval))   # a UI thread calls allow() or deny()

sandbox = Sandbox(policy_fn=PolicyFn(on_event, deferred=True, verdict_timeout=None))
```

| API | Deferred callback | Answer | Abandon | Cancelled |
|---|---|---|---|---|
| Python | `PolicyFn(cb, deferred=True)`, `cb(event, ctx, approval)` | `allow()`, `deny(errno=None)`, `resolve(verdict)` | `close()` | `cancelled` |
| Rust | `PolicyFn::deferred(\|event, ctx, approval\| ..)` | `allow()`, `deny()`, `resolve(Verdict)` | drop | `is_cancelled()` |
| Go | `PolicyFn{Deferred: cb}` | `Resolve(decision)` | `Close()` | `IsCancelled()` |
| C | `sandlock_sandbox_builder_policy_fn_deferred` | `sandlock_approval_resolve` | `sandlock_approval_free` | `sandlock_approval_is_cancelled` |

`resolve` takes the same verdict encoding as a synchronous callback's return
value.

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
