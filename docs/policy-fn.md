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
from sandlock import Sandbox, PolicyFn, Allow, Audit, Deny
import errno

def on_event(event, ctx):
    # Block download tools by argv
    if event.syscall == "execve" and event.argv_contains("curl"):
        return Deny()

    # Deny connections to a specific IP
    if event.syscall == "connect" and event.host == "10.0.0.5":
        return Deny(errno.EACCES)

    # Lock down once the program has finished starting up
    if event.syscall == "execve":
        ctx.restrict(net_allow=[])         # block all network
        ctx.deny_path("/etc/shadow")       # dynamic fs deny

    # Audit every filesystem access (allow but flag)
    if event.category == "filesystem":
        return Audit()

    return Allow()

sandbox = Sandbox(
    fs_readable=["/usr", "/lib", "/etc"],
    net_allow=["api.example.com:443"],
    policy_fn=PolicyFn(on_event),
)
result = sandbox.run(["python3", "agent.py"])
```

**Verdicts:** `Allow()` (or `None`), `Deny()` (EPERM), `Deny(errno)`,
`Audit()` = allow + flag, `Grant(net_allow=[...])` = widen the network, then
allow (see [Approve network on demand](#approve-network-on-demand)). Any other
return value raises `TypeError` and denies.

**Event fields:** `syscall`, `category` (filesystem/network/process),
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
- `ctx.restrict(net_allow=specs)`: narrow the live network rules for good
- `ctx.restrict_max_memory(bytes)` / `ctx.restrict_max_processes(n)`: resource limits
- `ctx.deny_path(path)` / `ctx.allow_path(path)`: dynamic filesystem restriction
  (`deny_path` fails unless filesystem events are subscribed; see below)
- `ctx.restrict_pid(pid, net_allow=specs)`: narrow one process below the live rules

Runtime specs use `net_allow` syntax with IPs and CIDRs only; a hostname
raises `ValueError`. Widening the network is an answer to a held operation,
so it lives on the approval (see [Approve network on demand](#approve-network-on-demand)).

**Held syscalls** (the calling task is blocked awaiting a verdict; the
rest of the sandbox keeps running): `execve`, `connect`, `sendto`,
`bind`, `openat`.

## Rust

```rust
use sandlock_core::Sandbox;
use sandlock_core::policy_fn::{Permissions, PolicyFn, Verdict};

let mut dynamic = Sandbox::builder()
    .fs_read("/usr").fs_read("/lib")
    .policy_fn(PolicyFn::new(|event, ctx| {
        if event.argv_contains("curl") {
            return Verdict::Deny;
        }
        if event.syscall == "execve" {
            ctx.restrict(&Permissions::new().net_allow_none()).expect("literal rules");
            ctx.deny_path("/etc/shadow").expect("filesystem events are subscribed");
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
`sandlock_sandbox_builder_policy_fn(builder, callback, timeout_ms, events,
user_data, user_data_drop)`. Negative values disable the timeout; zero denies immediately;
pass `5000` for the SDK default. There is no independent sandbox timeout setter.

Shutdown cancels outstanding verdict waits and discards queued events. A running
callback must cooperate: check `ctx.is_cancelled()` in Rust or Python,
`ctx.IsCancelled()` in Go, or `sandlock_ctx_is_cancelled(ctx)` in C between
bounded waits for user input. The context is valid only during its callback.
Shutdown joins that callback before releasing its data; it cannot forcibly
interrupt user code. A verdict timeout closes the verdict wait, but does not
interrupt a callback already running. Its eventual verdict is ignored.

## Event subscriptions

A callback receives every event category by default. Subscribing to fewer
categories also drops the interception that only those categories need: a
network-only callback leaves file syscalls untrapped and skips the ptrace
fork tracking and `execve` freeze that make `argv` safe to inspect.

```python
PolicyFn(on_net, events={"network"})
```

Rust uses `PolicyFn::new(on_net).events(&[SyscallCategory::Network])`, Go sets
`PolicyFn.Events: []sandlock.SyscallCategory{sandlock.CategoryNetwork}`, and C
passes `SANDLOCK_EVENT_NETWORK` as the `events` mask (`SANDLOCK_EVENT_ALL` keeps
every category).

| Category | Syscalls | Subscribing adds |
|----------|----------|------------------|
| `filesystem` | `open`, `openat`, `openat2`, `mkdir(at)`, `mknod(at)`, `unlink(at)`, `rmdir`, `symlink(at)`, `link(at)`, `rename(at)`, `renameat2`, `truncate` | traps on these path syscalls, plus those `ctx.deny_path()` gates |
| `network` | `connect`, `sendto`, `sendmsg`, `sendmmsg`, `bind` | traps on these syscalls |
| `process` | `execve`, `execveat`, `clone`, `clone3`, `fork`, `vfork` | `execve` traps, ptrace fork tracking, and the `execve` freeze |

Process creation syscalls are always trapped for process accounting, so
subscribing to `process` adds no traps for them; it delivers their events and
tracks each new child with ptrace.

Unsubscribed syscalls remain governed by the static policy. Network supervision
stays on for any callback, so `ctx.restrict()` works from every
category. `ctx.deny_path()` needs filesystem events because only they keep path
syscalls trapped; without them it fails (Python raises `RuntimeError`, Go
returns `ErrFilesystemEventsRequired`, C returns `-1`) rather than silently not
denying.

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

`resolve` takes the same verdicts a synchronous callback returns; in C that
is the integer encoding `0` allow, `-1` deny, `-2` audit, positive errno.

## Approve network on demand

A sandbox can start with no network and open it when a person says yes.
`net_allow` is what the sandbox may reach at launch; `PolicyFn.approvable`
is the most an approval may ever add on top. A connect or send to a
destination inside `approvable` but not yet allowed is held for the callback.
Answering with a `Grant` widens the live rules for good and then lets the held
operation through; it is a verdict like any other, so a synchronous callback
returns it and a deferred one resolves its approval with it.

```python
import errno
from sandlock import Sandbox, PolicyFn, Permissions, Allow, Deny, Grant

def on_event(event, ctx):
    if event.syscall != "connect":
        return Allow()
    if ask_human(f"{event.host}:{event.port}?"):
        return Grant(net_allow=["*:*"])   # widen for good, then allow this one
    return Deny(errno.ECONNREFUSED)

sandbox = Sandbox(
    net_deny=["169.254.169.254"],
    policy_fn=PolicyFn(
        on_event,
        events={"network"},
        verdict_timeout=None,
        approvable=Permissions(net_allow=["*:*"]),
    ),
)

# a deferred callback answers the same way, from any thread
approval.resolve(Grant(net_allow=["*:*"]))
```

Each destination falls in one class:

| Class | Rule | Outcome |
|---|---|---|
| denied | matches `net_deny` | refused; no grant can open it |
| allowed | inside the live rules (`net_allow` plus grants) | runs, still reported to a network callback |
| held | inside `approvable`, outside the live rules | waits for the verdict; a plain allow lets this one through without granting |
| rejected | outside `approvable` | refused with `ECONNREFUSED`; the callback still sees it but cannot grant it |

A grant outside `approvable`, or after `ctx.restrict()` narrowed it, denies the
operation and changes nothing. A returned grant is logged; resolving an
approval with one also reports it (Python raises `PermissionError`, Go returns
`ErrNotApprovable`, Rust `try_resolve` returns `PolicyFnError::NotApprovable`,
C returns `-EPERM`). A held
operation that times out or is closed is refused with `ECONNREFUSED`. As in
`net_allow`, `*:*` covers TCP and UDP but not ICMP; add `icmp://*` to approve
pings. A `policy_fn` with neither `net_allow` nor `approvable` reaches no
network. Approvable rules need a callback subscribed to network events, since
only it can answer a held operation; building fails otherwise.

| API | Approvable rules | Grant verdict |
|---|---|---|
| Python | `PolicyFn(cb, approvable=Permissions(net_allow=[...]))` | `Grant(net_allow=[...])` |
| Rust | `PolicyFn::new(cb).approvable(Permissions::new().net_allow(..))` | `Verdict::Grant(permissions)` |
| Go | `PolicyFn{Approvable: &sandlock.Permissions{NetAllow: ...}}` | `sandlock.Grant(sandlock.Permissions{...})` |
| C | `sandlock_sandbox_builder_approvable_net_allow` | `sandlock_approval_grant_net_allow` (deferred callbacks) |

## Interaction with static rules

`policy_fn` only sees the syscalls the supervisor traps. Landlock rules
(`fs_readable`, `fs_writable`, `fs_denied`, TCP port rules) are evaluated
by the kernel first and never reach the callback, so a Landlock denial
cannot be overridden from `policy_fn`. Path-based decisions belong in
those static rules; use `ctx.deny_path()` for runtime additions.

Runtime network rules are IP-only. A per-PID override narrows the live
rules for that process; the static `net_deny` layer is applied after the
allow verdict and always wins, so no grant or override can erase it.
