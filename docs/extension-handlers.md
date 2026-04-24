# `ExtraHandler`: user-supplied seccomp-notification handlers

`sandlock-core` routes every intercepted syscall through a chain-of-responsibility
table where builtin handlers (`chroot`, `cow`, `procfs`, `network`, `port_remap`,
resource accounting) register for the syscall numbers they care about. Within
each chain, handlers run in registration order; the first
non-[`NotifAction::Continue`](../crates/sandlock-core/src/seccomp/notif.rs)
result wins.

`ExtraHandler` is the public extension point that lets downstream crates append
their own handler functions to the chain after all builtins. It is the
supported alternative to forking the crate or duplicating
[`notif::supervisor`](../crates/sandlock-core/src/seccomp/notif.rs) — one
[`SECCOMP_FILTER_FLAG_NEW_LISTENER`](https://man7.org/linux/man-pages/man2/seccomp.2.html)
per process means one supervisor, so user code that needs to intercept extra
syscalls in the same sandbox as the builtins must run inside the same dispatch
loop.

## API

A handler is an async closure bound to a syscall number:

```rust
use sandlock_core::seccomp::dispatch::{ExtraHandler, HandlerFn};
use sandlock_core::seccomp::notif::NotifAction;
use sandlock_core::{Policy, Sandbox};

let policy = Policy::builder().fs_read("/usr").fs_write("/tmp").build()?;

let handler: HandlerFn = Box::new(|notif, _ctx, _fd| {
    Box::pin(async move {
        // inspect notif.data.args, perform side effects, return action
        NotifAction::Continue
    })
});

Sandbox::run_with_extra_handlers(
    &policy,
    &["python3", "-c", "print(42)"],
    vec![ExtraHandler::new(libc::SYS_openat, handler)],
).await?;
```

[`Sandbox::run`](../crates/sandlock-core/src/sandbox.rs) is preserved and
delegates to `run_with_extra_handlers` with an empty `Vec`, so callers that do
not need extras observe no API change.

## Semantics

### Ordering

For each intercepted syscall:

1. Builtin handlers registered inside
   [`build_dispatch_table`](../crates/sandlock-core/src/seccomp/dispatch.rs)
   run first, in their internal registration order.
2. `extra_handlers` run afterwards, in `Vec` order.
3. Multiple extras on the same syscall run in insertion order.

The chain stops as soon as a handler returns a non-`NotifAction::Continue`
result; subsequent handlers in the chain are not invoked. This contract is
enforced structurally — `build_dispatch_table` registers builtins into an empty
table *before* iterating `extra_handlers`, and the chain evaluator
short-circuits on the first non-`Continue`.

The contract is exercised at two layers:

- Unit, in [`seccomp::dispatch::extra_handler_tests`](../crates/sandlock-core/src/seccomp/dispatch.rs):
  `dispatch_walks_chain_in_registration_order`,
  `dispatch_runs_builtin_before_extra`,
  `dispatch_stops_at_first_non_continue` drive the actual `dispatch()` walker
  against a minimal `SupervisorCtx`.
- End-to-end, in [`tests/integration/test_extra_handlers.rs`](../crates/sandlock-core/tests/integration/test_extra_handlers.rs):
  `extra_handler_runs_after_builtin_returns_continue`,
  `builtin_non_continue_blocks_extra`,
  `chain_of_extras_runs_in_insertion_order` drive a live Landlock+seccomp
  sandbox.

### Return values

`HandlerFn` returns [`NotifAction`](../crates/sandlock-core/src/seccomp/notif.rs):

| Variant | Effect |
|---|---|
| `Continue` | Fall through to the next handler in the chain; if last, the kernel resumes the syscall (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`). |
| `Errno(e)` | Return `-e` to the guest; the kernel does not run the syscall. |
| `ReturnValue(val)` | Return `val` to the guest; the kernel does not run the syscall (useful for faking `write` and similar). |
| `InjectFd { srcfd, targetfd }` | Inject `srcfd` into the guest at slot `targetfd`, then continue. |
| `Kill { sig, pgid }` | Send `sig` to the guest's process group. |

### Continue-site safety

The supervisor processes notifications sequentially in a single tokio task, so
the response sent for one notification gates the kernel resumption of the
trapped syscall. A handler must not hold any
[`SupervisorCtx`](../crates/sandlock-core/src/seccomp/ctx.rs) internal lock
(`tokio::sync::Mutex`/`RwLock`) across an `.await` point: if the guard is alive
when control returns to the supervisor loop, the next notification that needs
the same lock parks, the response for the current notification is not sent, and
the child stays trapped in the syscall. Acquire, mutate, drop — `await` only
after the guard is out of scope. See [issue #27][i27] for the underlying
contract that this convention extends to user handlers.

[i27]: https://github.com/multikernel/sandlock/issues/27

## Security boundary

Extras run after builtins. By the time a user handler observes a notification,
builtins have already normalised paths (chroot), validated access (Landlock
pre-checks at the BPF/notif layer), and short-circuited any call that conflicts
with the policy.

Extras cannot:

- Remove a builtin handler.
- Reorder a builtin handler to run after the extra.
- Skip a builtin's `Errno`/`ReturnValue`/`Kill` response.

Extras can:

- Observe every syscall sandlock intercepts via `SECCOMP_RET_USER_NOTIF` —
  builtins for that syscall must have returned `Continue` for the extra to
  see it.
- Fake results (`ReturnValue`, `Errno`) — but only after the builtins for the
  same syscall returned `Continue`, so they cannot subvert confinement.

### BPF coverage

`run_with_extra_handlers` collects the syscall numbers declared by the supplied
`Vec<ExtraHandler>` and merges them into the cBPF notification list installed
in the child before `execve`. Without this step the kernel never raises
`SECCOMP_RET_USER_NOTIF` for a syscall that no builtin intercepts, and the user
handler silently never fires. The merge is dedup-aware: an `openat` registered
both by a builtin and an extra produces a single JEQ in the assembled program.

### Deny-list bypass guard

The cBPF program emits notif JEQs *before* deny JEQs, so a syscall present in
both lists hits `SECCOMP_RET_USER_NOTIF` first. An extra registered on a
syscall in
[`DEFAULT_DENY_SYSCALLS`](../crates/sandlock-core/src/sys/structs.rs) — or in
`policy.deny_syscalls` — would convert a kernel-deny into a user-supervised
path; a handler returning `NotifAction::Continue` would become
`SECCOMP_USER_NOTIF_FLAG_CONTINUE` and the kernel would actually run the
syscall, silently bypassing deny.

`run_with_extra_handlers` rejects this configuration at registration time
(before fork) and returns `SandboxError::Child` naming the offending syscall.
The check is implemented in
[`validate_extras_against_policy`](../crates/sandlock-core/src/seccomp/dispatch.rs)
and covers both the default-deny branch (`DEFAULT_DENY_SYSCALLS`) and the
user-specified branch (`policy.deny_syscalls`); both branches are unit-tested
(`validate_extras_rejects_user_specified_deny`,
`extra_handler_on_default_deny_syscall_is_rejected`,
`extra_handler_on_user_specified_deny_is_rejected`).

In allowlist mode (`policy.allow_syscalls = Some(_)`) the resolved deny list is
empty and the guard is a no-op — but so is the BPF deny block, and confinement
comes entirely from the kernel-enforced allowlist, so there is no overlap to
bypass.

## Panics

`DispatchTable::dispatch` does not wrap handler calls in `catch_unwind`. A
panic inside a user handler propagates up the `tokio::spawn` task that drives
the supervisor, leading to task failure and the child being killed by
sandlock's watchdog.

To tolerate bugs in downstream handlers, wrap each one with
[`futures::FutureExt::catch_unwind`][catch] (the synchronous
`std::panic::catch_unwind` does not apply to async futures):

```rust
use futures::future::FutureExt as _;
use std::panic::AssertUnwindSafe;

let safe: HandlerFn = Box::new(|notif, ctx, fd| {
    Box::pin(async move {
        AssertUnwindSafe(actual_handler(notif, ctx, fd))
            .catch_unwind()
            .await
            .unwrap_or(NotifAction::Continue) // fail-open on panic
    })
});
```

[catch]: https://docs.rs/futures/latest/futures/future/trait.FutureExt.html#method.catch_unwind

## Use cases

### VFS engine: real-time uploads to object storage

A deployment that streams guest-generated artefacts to object storage as the
process runs (rather than collecting them after exit) needs interceptors on
`openat(O_CREAT)`, `write`, and `close` to translate filesystem operations
into multipart-upload calls. Those interceptors must live inside the same
supervisor task as sandlock's builtins — `SECCOMP_FILTER_FLAG_NEW_LISTENER`
allows only one listener per process, so a second supervisor cannot run
alongside.

```rust
let extras = vec![
    ExtraHandler::new(libc::SYS_openat, s3_open_handler),
    ExtraHandler::new(libc::SYS_write,  s3_write_handler),
    ExtraHandler::new(libc::SYS_close,  s3_close_handler),
];
Sandbox::run_with_extra_handlers(&policy, &cmd, extras).await?;
```

Each handler observes the post-builtin view: by the time `s3_open_handler`
runs, the `openat` arguments are already chroot-normalised, so the path the
handler inspects can be trusted against the configured policy.

### Deterministic audit trail for compliance

Regulated environments (CIS, GDPR data-residency) require a guaranteed audit
log of every file read/write the user code performs, tamper-proof against the
guest. Python wrappers (`wrapt`, import hooks) are easy for the guest to
circumvent through `ctypes` or raw syscalls; eBPF file tracing requires
`CAP_BPF`, which is often unavailable in managed Kubernetes.

An `ExtraHandler` on `SYS_openat`/`SYS_write`/`SYS_unlinkat` captures the call
before the kernel acts on it. The guest cannot bypass it without bypassing
seccomp itself, which sandlock blocks at the BPF level.

A minimal runnable example lives in
[`examples/openat_audit.rs`](../crates/sandlock-core/examples/openat_audit.rs).

## Limitations

- **No builtin override.** Security-critical handlers (`chroot`, `cow`) always
  run first. To change builtin behaviour, modify sandlock directly.
- **No before-builtin priority.** An audit handler that wants to observe calls
  rejected by builtins is a coherent use case, but it requires a
  `HandlerPriority` enum that has not been added; the current API only supports
  appending to the chain.
- **No declarative `Policy` extension.** Adding handlers is a runtime action,
  not a serialisable part of the policy. `Policy` remains a pure data struct.

## Backwards compatibility

`Sandbox::run(policy, cmd)` is preserved and delegates to
`Sandbox::run_with_extra_handlers(policy, cmd, Vec::new())`. Existing unit and
integration tests pass without modification; downstream callers that do not
need extras need no change.

## Downstream usage

A typical downstream crate exports a builder:

```rust
pub fn build_vfs_handlers(
    config: VfsConfig,
) -> Vec<sandlock_core::seccomp::dispatch::ExtraHandler> { /* ... */ }
```

which the supervisor binary passes straight into `run_with_extra_handlers`. The
crate links against `sandlock-core` as an ordinary dependency — no fork, no
`[patch.crates-io]`, no duplication of `notif::supervisor`.
