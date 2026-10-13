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

**Held syscalls** (child blocked awaiting a verdict): `execve`,
`connect`, `sendto`, `bind`, `openat`.

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

Use `PolicyFn.deferred` when a decision needs user input or another service.
The callback receives an owned approval handle and returns promptly. The
supervisor continues processing other notifications while the requesting task
waits in its syscall. Existing synchronous callbacks remain supported.

```python
import queue
from sandlock import Sandbox, PolicyFn

approvals = queue.Queue()

def on_event(event, ctx, approval):
    if approval is None:
        return
    if event.syscall == "connect":
        approvals.put((event, approval))
    else:
        approval.allow()

sandbox = Sandbox(policy_fn=PolicyFn.deferred(on_event, verdict_timeout=120))
```

Your UI or another thread consumes `approvals` while the sandbox runs:

```python
event, approval = approvals.get()
approval.allow()
# Alternatively: approval.deny() or approval.deny(errno.EACCES).
```

`approval.allow()` and `approval.deny(errno=1)` accept one decision. They raise
`RuntimeError` if the request was already answered, timed out, or cancelled.
`approval.is_cancelled()` reports whether it can no longer accept a decision.
`approval.close()` releases the handle and denies an unanswered request; it is
safe to call repeatedly. Garbage collection also releases it, but use `close()`
for deterministic abandonment, especially when disabling the timeout.
Callback exceptions close unanswered handles even if they were retained.

Observation-only events receive `None`. Retain the event and approval as needed,
but the context remains valid only during its callback. The existing timeout
includes callback queue time. Shutdown cancels pending approvals without waiting
for applications to release their handles. Callbacks themselves must still
return promptly.

The supervisor bounds outstanding approvals and queued exec preparations to 64;
when full it rejects additional held requests with `EAGAIN`. Exec approval retains
the existing sandbox-wide argv freeze. The supervisor stays responsive, but
frozen sandbox tasks cannot make progress until that exec is decided. Overlapping
exec and process-creation preparations wait until the freeze is released.

In Rust, use the same ownership model:

```rust
use sandlock_core::policy_fn::{PolicyFn, Verdict};

let (tx, rx) = std::sync::mpsc::channel();
let policy = PolicyFn::deferred(move |event, _ctx, approval| {
    if let Some(approval) = approval {
        tx.send((event, approval)).unwrap();
    }
});
// In an application worker while the sandbox runs:
let (_event, mut approval) = rx.recv()?;
approval.resolve(Verdict::Allow)?;
```

Dropping an unanswered Rust handle denies. `resolve` returns `ApprovalClosed`
for a late or repeated decision.

In Go, set `PolicyFn.Deferred` instead of `PolicyFn.Callback`:

```go
approvals := make(chan *sandlock.Approval, 64)
policy := &sandlock.PolicyFn{
    Deferred: func(event sandlock.SyscallEvent, ctx *sandlock.PolicyContext, approval *sandlock.Approval) {
        if approval != nil {
            approvals <- approval
        }
    },
}
// In another goroutine:
approval := <-approvals
err := approval.Resolve(sandlock.Allow())
```

Exactly one callback field must be set. Use `Close()` to abandon an approval
and `IsCancelled()` to inspect it. `Resolve` releases the native handle even
when the decision arrives too late. Go finalization is only a fallback; always
resolve or close each received handle.

In C, register `sandlock_sandbox_builder_policy_fn_deferred`. Its callback
receives an owned `sandlock_approval_t *`, or NULL for observation events.
Use `sandlock_approval_resolve` with the existing integer verdict encoding,
`sandlock_approval_is_cancelled`, and `sandlock_approval_free`. Release each
handle exactly once, including after resolution or cancellation. Serialize
access to a handle; freeing it concurrently with resolution is invalid.

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
