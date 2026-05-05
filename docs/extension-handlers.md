# `Handler`: user-supplied seccomp-notification handlers

`sandlock-core` routes every intercepted syscall through a chain-of-responsibility
table where builtin handlers (`chroot`, `cow`, `procfs`, `network`, `port_remap`,
resource accounting) register for the syscall numbers they care about. Within
each chain, handlers run in registration order; the first
non-[`NotifAction::Continue`](../crates/sandlock-core/src/seccomp/notif.rs)
result wins.

`Handler` is the public extension trait that lets downstream crates append their
own handlers to the chain after all builtins. It is the supported alternative to
forking the crate or duplicating
[`notif::supervisor`](../crates/sandlock-core/src/seccomp/notif.rs) — one
[`SECCOMP_FILTER_FLAG_NEW_LISTENER`](https://man7.org/linux/man-pages/man2/seccomp.2.html)
per process means one supervisor task, so user code that needs to intercept extra
syscalls in the same sandbox as the builtins must run inside the same dispatch
loop.

## API

### `Handler` trait

The `Handler` trait has a single async method `handle(&self, cx: &HandlerCtx<'_>) -> NotifAction`.
State lives on the struct's fields — no `Arc::clone` ladders, no `Box::pin` ceremony at call site.

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use sandlock_core::{Handler, HandlerCtx, Policy, Sandbox};
use sandlock_core::seccomp::notif::NotifAction;
use async_trait::async_trait;

struct OpenAudit { count: AtomicU64 }

#[async_trait]
impl Handler for OpenAudit {
    async fn handle(&self, cx: &HandlerCtx<'_>) -> NotifAction {
        let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        eprintln!("[audit #{n}] pid={} openat", cx.notif.pid);
        NotifAction::Continue
    }
}

let policy = Policy::builder().fs_read("/usr").fs_write("/tmp").build()?;
Sandbox::run_with_extra_handlers(
    &policy,
    &["python3", "-c", "print(42)"],
    [(libc::SYS_openat, OpenAudit { count: AtomicU64::new(0) })],
)
.await?;
```

`HandlerCtx<'_>` is borrowed for the dispatch call (cannot outlive it — its `&Arc<SupervisorCtx>`
ref carries supervisor state for the next notification).

### Closures via blanket impl

For trivial single-shot handlers, closures work via the blanket `impl<F, Fut> Handler for F`:

```rust
let audit = |cx: &HandlerCtx<'_>| async move {
    eprintln!("openat from pid {}", cx.notif.pid);
    NotifAction::Continue
};

Sandbox::run_with_extra_handlers(&policy, &cmd, [(libc::SYS_openat, audit)]).await?;
```

Use closures for prototyping or trivial state; switch to a struct as soon as the handler grows
non-trivial captures.

### `Syscall::checked` newtype

`Syscall::checked(nr)` validates against the architecture's known syscall set and rejects negatives:

```rust
use sandlock_core::{Syscall, SyscallError};

assert!(Syscall::checked(libc::SYS_openat).is_ok());
assert!(matches!(Syscall::checked(-5), Err(SyscallError::Negative(-5))));
assert!(matches!(Syscall::checked(99_999), Err(SyscallError::UnknownForArch(99_999))));
```

`run_with_extra_handlers` accepts an `IntoIterator<Item = (S, H)>` where `S: TryInto<Syscall, Error = SyscallError>`,
so callers can pass raw `i64`/`u32` syscall numbers and they are validated up-front:

```rust
Sandbox::run_with_extra_handlers(&policy, &cmd, [(libc::SYS_openat, openat_h)]).await?;
```

Without `Syscall::checked`, passing `-5` as a syscall number would compile but never fire — the
cBPF filter cannot emit a JEQ for an arch-unknown number.

### Entry points

There are two entry points; both spawn the sandbox, wait for it to exit, and return the result:

| name | stdio |
| --- | --- |
| `Sandbox::run_with_extra_handlers(policy, cmd, handlers)` | captured (returned in `RunResult`) |
| `Sandbox::run_interactive_with_extra_handlers(policy, cmd, handlers)` | inherited from the parent |

Both have the same generic shape:

```rust
pub async fn run_with_extra_handlers<I, S, H>(
    policy: &Policy,
    cmd: &[&str],
    extra_handlers: I,
) -> Result<RunResult, SandlockError>
where
    I: IntoIterator<Item = (S, H)>,
    S: TryInto<Syscall, Error = SyscallError>,
    H: Handler;
```

Multiple handlers — passed in one array literal:

```rust
Sandbox::run_with_extra_handlers(
    &policy,
    &cmd,
    [
        (libc::SYS_openat, openat_handler),
        (libc::SYS_close,  close_handler),
        (libc::SYS_mmap,   mmap_deny),
    ],
)
.await?;
```

When the iterator mixes handlers of different opaque types (e.g. several different closures, or
a closure plus a struct), `H` can no longer be inferred to a single concrete type.  Wrap the
handlers in a small adapter struct in your own crate, or use `Box<dyn Handler>` after defining a
local `impl Handler for Box<dyn Handler>` shim — sandlock-core does not ship a built-in erasure
to keep the public surface minimal.

Errors at registration time, before fork:

- `SyscallError::Negative` / `SyscallError::UnknownForArch` from `Syscall::checked` (wrapped in
  `HandlerError::InvalidSyscall`, then in `SandlockError::Handler`).
- `HandlerError::OnDenySyscall` if any registered syscall is in `policy.deny_syscalls` or
  `DEFAULT_DENY_SYSCALLS` (see [Security boundary](#security-boundary)).

### Interactive mode

For REPL-like workflows (a sandboxed shell, a long-running supervised process whose stdin/stdout
should be inherited from the host), use `run_interactive_with_extra_handlers`. The handler API
is identical:

```rust
Sandbox::run_interactive_with_extra_handlers(
    &policy,
    &["bash"],
    [(libc::SYS_openat, audit_handler)],
)
.await?;  // host stdin/stdout inherited
```

`run_interactive_with_extra_handlers` does not capture stdout/stderr — the child sees the parent's
terminal directly.

### Reading syscall arguments

The kernel passes most syscall arguments by pointer (paths in `openat`, buffers in `write`/`writev`,
`struct stat` slot in `newfstatat`, …). To read those out of guest memory inside a handler, use the
TOCTOU-safe helpers in [`crate::seccomp::notif`](../crates/sandlock-core/src/seccomp/notif.rs):

| Helper | Purpose |
|---|---|
| [`read_child_cstr`](../crates/sandlock-core/src/seccomp/notif.rs) | NUL-terminated string (paths). Page-aware, never crosses unmapped boundaries. |
| [`read_child_mem`](../crates/sandlock-core/src/seccomp/notif.rs) | Fixed-length byte buffer. |
| [`write_child_mem`](../crates/sandlock-core/src/seccomp/notif.rs) | Synthesise return data into the guest (e.g. fake `getdents64` listings, synthesised `stat` buffers). |

All three bracket the syscall with `id_valid` checks before and after `process_vm_readv` /
`process_vm_writev`, so they will not race with the kernel aborting or releasing the trapped
syscall while the supervisor is reading guest memory.

Example: an `openat` handler that reads the path argument and rejects access to a denylist
of suffixes:

```rust
use sandlock_core::seccomp::dispatch::{Handler, HandlerCtx};
use sandlock_core::seccomp::notif::{read_child_cstr, NotifAction};
use async_trait::async_trait;

struct ExtensionDenyHandler { denied_suffixes: Vec<String> }

#[async_trait]
impl Handler for ExtensionDenyHandler {
    async fn handle(&self, cx: &HandlerCtx<'_>) -> NotifAction {
        // openat(2): args[1] is `const char *pathname`.  4096 = PATH_MAX.
        let path = match read_child_cstr(cx.notif_fd, cx.notif.id, cx.notif.pid,
                                          cx.notif.data.args[1], 4096) {
            Some(p) => p,
            // Couldn't read path (rare: NULL pointer, kernel released the
            // notification mid-read, etc.).  Pass through and let the kernel
            // handle the syscall — usually it will fail with EFAULT itself.
            None => return NotifAction::Continue,
        };

        if self.denied_suffixes.iter().any(|s| path.ends_with(s)) {
            return NotifAction::Errno(libc::EACCES);
        }
        NotifAction::Continue
    }
}
```

Synthesising data INTO the guest follows the same pattern with `write_child_mem`. For example, a
`getdents64` handler that returns an empty directory listing:

```rust
async fn handle(&self, cx: &HandlerCtx<'_>) -> NotifAction {
    // args[1] is `struct linux_dirent64 *dirp` — write zero bytes (empty
    // listing) and return 0 (no entries) to the guest.
    let buf_addr = cx.notif.data.args[1];
    if let Err(_e) = write_child_mem(cx.notif_fd, cx.notif.id, cx.notif.pid, buf_addr, &[]) {
        return NotifAction::Errno(libc::EFAULT);
    }
    NotifAction::ReturnValue(0)
}
```

### State patterns

Common confusion: when a handler holds mutable state, what kind of synchronisation is needed?
`Handler::handle` takes `&self`, so anything mutated must be in an interior-mutability container.
Pick by access pattern:

| Pattern | Use when | Example |
|---|---|---|
| `AtomicU64` / `AtomicUsize` | Counter or single value, lock-free. | Audit call count. |
| `parking_lot::Mutex<T>` (or `std::sync::Mutex`) | Short critical section, never crosses `.await`. | Append to a `Vec<Event>` log buffer. |
| `tokio::sync::RwLock<T>` | Read-heavy, value rebuilt occasionally. | A small in-memory virtual file table refreshed on changes. |
| `dashmap::DashMap<K, V>` | High-fanout per-key concurrent access. | Per-pid open-file table indexed by `(pid, fd)`. |

⚠️ **Continue-site safety** (see [Semantics → Continue-site safety](#continue-site-safety)) applies
to async locks: never hold a `tokio::sync::Mutex`/`RwLock` guard across an `.await` inside a
handler, or the next notification will park behind it and the trapped syscall will never resume.
Use sync `parking_lot::Mutex` for short critical sections instead — it cannot deadlock the
supervisor loop because it cannot be held across `.await`.

```rust
use std::sync::atomic::{AtomicU64, Ordering};

struct CallStats {
    openat: AtomicU64,
    close:  AtomicU64,
}

#[async_trait]
impl Handler for CallStats {
    async fn handle(&self, cx: &HandlerCtx<'_>) -> NotifAction {
        match cx.notif.data.nr as i64 {
            n if n == libc::SYS_openat => self.openat.fetch_add(1, Ordering::Relaxed),
            n if n == libc::SYS_close  => self.close.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
        NotifAction::Continue
    }
}
```

For one handler instance shared across multiple syscall registrations, write a thin wrapper:

```rust
struct DispatchCallStats(std::sync::Arc<CallStats>);

#[async_trait]
impl Handler for DispatchCallStats {
    async fn handle(&self, cx: &HandlerCtx<'_>) -> NotifAction {
        self.0.handle(cx).await
    }
}

let stats = std::sync::Arc::new(CallStats {
    openat: AtomicU64::new(0),
    close:  AtomicU64::new(0),
});

Sandbox::run_with_extra_handlers(
    &policy,
    &cmd,
    [
        (libc::SYS_openat, DispatchCallStats(std::sync::Arc::clone(&stats))),
        (libc::SYS_close,  DispatchCallStats(std::sync::Arc::clone(&stats))),
    ],
)
.await?;

println!("openat: {}, close: {}",
    stats.openat.load(Ordering::Relaxed),
    stats.close.load(Ordering::Relaxed));
```

## Semantics

### Ordering

For each intercepted syscall:

1. Builtin handlers registered inside
   [`build_dispatch_table`](../crates/sandlock-core/src/seccomp/dispatch.rs)
   run first, in their internal registration order.
2. Handlers passed to `run_with_extra_handlers` run afterwards, in iterator order.
3. Multiple iterator entries on the same syscall run in insertion order.

The chain stops as soon as a handler returns a non-`NotifAction::Continue` result; subsequent
handlers in the chain are not invoked. This contract is enforced structurally —
`build_dispatch_table` registers builtins into an empty table *before* iterating user-supplied
handlers, and the chain evaluator short-circuits on the first non-`Continue`.

The contract is exercised at two layers:

- Unit, in [`seccomp::dispatch::extra_handler_tests`](../crates/sandlock-core/src/seccomp/dispatch.rs):
  `dispatch_walks_chain_in_registration_order`,
  `dispatch_runs_builtin_before_extra`,
  `dispatch_stops_at_first_non_continue` drive `dispatch()` walker against a minimal `SupervisorCtx`.
- End-to-end, in [`tests/integration/test_extra_handlers.rs`](../crates/sandlock-core/tests/integration/test_extra_handlers.rs):
  `run_with_extra_handlers_preserves_insertion_order_in_sandbox_chain`,
  `builtin_non_continue_blocks_extra`,
  `extra_handler_runs_after_builtin_returns_continue` drive a live Landlock+seccomp sandbox.

### Return values

`Handler::handle` returns [`NotifAction`](../crates/sandlock-core/src/seccomp/notif.rs):

| Variant | Effect |
|---|---|
| `Continue` | Fall through to the next handler in the chain; if last, the kernel resumes the syscall (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`). |
| `Errno(e)` | Return `-e` to the guest; the kernel does not run the syscall. |
| `ReturnValue(val)` | Return `val` to the guest; the kernel does not run the syscall (useful for synthesising `read`/`fstat`/`getdents64`/...). |
| `InjectFd { srcfd, targetfd }` | Inject `srcfd` into the guest at slot `targetfd`, then continue. |
| `InjectFdSendTracked { srcfd, newfd_flags, on_success }` | Inject `srcfd`; `on_success` callback runs synchronously when the kernel returns the slot, so downstream tracking cannot race with the guest seeing the new fd. |
| `Kill { sig, pgid }` | Send `sig` to the guest's process group. |

### Continue-site safety

The supervisor processes notifications sequentially in a single tokio task, so the response sent
for one notification gates the kernel resumption of the trapped syscall. A handler must not hold
any [`SupervisorCtx`](../crates/sandlock-core/src/seccomp/ctx.rs) internal lock
(`tokio::sync::Mutex`/`RwLock`) across an `.await` point: if the guard is alive when control
returns to the supervisor loop, the next notification that needs the same lock parks, the response
for the current notification is not sent, and the child stays trapped in the syscall. Acquire,
mutate, drop — `await` only after the guard is out of scope.

The trait shape does not change this contract — `&self` in `Handler::handle` gives access to your
own struct fields, but `cx.sup` is a borrowed `&Arc<SupervisorCtx>` and its locks have the same
constraint as before. See [issue #27][i27] for the underlying contract.

[i27]: https://github.com/multikernel/sandlock/issues/27

## Security boundary

User handlers run after builtins. By the time a user handler observes a notification, builtins
have already normalised paths (chroot), validated access (Landlock pre-checks at the BPF/notif
layer), and short-circuited any call that conflicts with the policy.

User handlers cannot:

- Remove a builtin handler.
- Reorder a builtin handler to run after the user handler.
- Skip a builtin's `Errno`/`ReturnValue`/`Kill` response.

User handlers can:

- Observe every syscall sandlock intercepts via `SECCOMP_RET_USER_NOTIF` — builtins for that
  syscall must have returned `Continue` for the user handler to see it.
- Fake results (`ReturnValue`, `Errno`) — but only after the builtins for the same syscall
  returned `Continue`, so they cannot subvert confinement.
- Inject fds (`InjectFd`/`InjectFdSendTracked`) — useful for materialising virtual file content
  via `memfd` without ever touching the host filesystem.

### BPF coverage

`run_with_extra_handlers` collects the syscall numbers declared by the user-supplied handlers and merges them
into the cBPF notification list installed in the child before `execve`. Without this step the
kernel never raises `SECCOMP_RET_USER_NOTIF` for a syscall that no builtin intercepts, and the
user handler silently never fires. The merge is dedup-aware: an `openat` registered both by a
builtin and a user handler produces a single JEQ in the assembled program.

Validation runs at registration time (before fork). If `Syscall::checked` fails, `run_with_extra_handlers`
returns the error without enqueueing the handler.

### Deny-list bypass guard

The cBPF program emits notif JEQs *before* deny JEQs, so a syscall present in both lists hits
`SECCOMP_RET_USER_NOTIF` first. A handler registered on a syscall in
[`DEFAULT_DENY_SYSCALLS`](../crates/sandlock-core/src/sys/structs.rs) — or in
`policy.deny_syscalls` — would convert a kernel-deny into a user-supervised path; a handler
returning `NotifAction::Continue` would become `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and the kernel
would actually run the syscall, silently bypassing deny.

`run_with_extra_handlers` rejects this configuration at registration time and returns
`HandlerError::OnDenySyscall { syscall_nr }`. The check is implemented in
[`validate_handler_syscalls_against_policy`](../crates/sandlock-core/src/seccomp/dispatch.rs)
and covers both the default-deny branch (`DEFAULT_DENY_SYSCALLS`) and the user-specified branch
(`policy.deny_syscalls`); both branches are tested
(`validate_extras_rejects_user_specified_deny`,
`extra_handler_on_default_deny_syscall_is_rejected`,
`run_with_extra_handlers_rejects_handler_on_default_deny_syscall`,
`run_with_extra_handlers_rejects_negative_syscall`,
`run_with_extra_handlers_rejects_arch_unknown_syscall`).

In allowlist mode (`policy.allow_syscalls = Some(_)`) the resolved deny list is empty and the
guard is a no-op — but so is the BPF deny block, and confinement comes entirely from the
kernel-enforced allowlist, so there is no overlap to bypass.

## Panics

`DispatchTable::dispatch` does not wrap handler calls in `catch_unwind`. A panic inside a user
handler propagates up the `tokio::spawn` task that drives the supervisor, leading to task failure
and the child being killed by sandlock's watchdog.

To tolerate bugs in downstream handlers, wrap each one with
[`futures::FutureExt::catch_unwind`][catch] (the synchronous `std::panic::catch_unwind` does not
apply to async futures):

```rust
use async_trait::async_trait;
use futures::future::FutureExt as _;
use std::panic::AssertUnwindSafe;

struct PanicSafe<H: Handler>(H);

#[async_trait]
impl<H: Handler> Handler for PanicSafe<H> {
    async fn handle(&self, cx: &HandlerCtx<'_>) -> NotifAction {
        AssertUnwindSafe(self.0.handle(cx))
            .catch_unwind()
            .await
            .unwrap_or(NotifAction::Continue) // fail-open on panic
    }
}

Sandbox::run_with_extra_handlers(
    &policy,
    &cmd,
    [(libc::SYS_openat, PanicSafe(actual_handler))],
)
.await?;
```

[catch]: https://docs.rs/futures/latest/futures/future/trait.FutureExt.html#method.catch_unwind

## Use cases

### VFS engine: real-time uploads to object storage

A deployment that streams guest-generated artefacts to object storage as the process runs (rather
than collecting them after exit) needs interceptors on `openat(O_CREAT)`, `write`, and `close` to
translate filesystem operations into multipart-upload calls. Those interceptors must live inside
the same supervisor task as sandlock's builtins — `SECCOMP_FILTER_FLAG_NEW_LISTENER` allows only
one listener per process.

A small adapter enum lets the iterator's `H` parameter stay homogeneous when the underlying
struct types differ:

```rust
enum S3Handler {
    Open(S3OpenHandler),
    Close(S3CloseHandler),
    MmapDeny(MmapDenyManaged),
}

#[async_trait]
impl Handler for S3Handler {
    async fn handle(&self, cx: &HandlerCtx<'_>) -> NotifAction {
        match self {
            S3Handler::Open(h)     => h.handle(cx).await,
            S3Handler::Close(h)    => h.handle(cx).await,
            S3Handler::MmapDeny(h) => h.handle(cx).await,
        }
    }
}

Sandbox::run_with_extra_handlers(
    &policy,
    &cmd,
    [
        (libc::SYS_openat, S3Handler::Open(S3OpenHandler::new(&cfg)?)),
        (libc::SYS_close,  S3Handler::Close(S3CloseHandler::new(&cfg)?)),
        (libc::SYS_mmap,   S3Handler::MmapDeny(MmapDenyManaged::new(&open_files))),
    ],
)
.await?;
```

Each handler observes the post-builtin view: by the time `S3OpenHandler::handle` runs, the
`openat` arguments are already chroot-normalised, so the path the handler inspects can be trusted
against the configured policy.

### Synthetic file content via `InjectFdSendTracked`

A read-only virtual file (e.g. `/etc/hostname`, an in-memory configuration generated per-call)
can be exposed by intercepting `openat` and injecting a sealed `memfd` containing the content.
The kernel returns the new fd slot to the guest, the handler's `on_success` callback runs
synchronously to register the fd in the handler's bookkeeping, and the guest reads the content
via the `memfd` — no host filesystem touched.

### Deterministic audit trail for compliance

Regulated environments (CIS, GDPR data-residency) require a guaranteed audit log of every file
read/write the user code performs, tamper-proof against the guest. Python wrappers (`wrapt`,
import hooks) are easy for the guest to circumvent through `ctypes` or raw syscalls; eBPF file
tracing requires `CAP_BPF`, which is often unavailable in managed Kubernetes.

A `Handler` on `SYS_openat`/`SYS_write`/`SYS_unlinkat` captures the call before the kernel acts
on it. The guest cannot bypass it without bypassing seccomp itself, which sandlock blocks at the
BPF level.

A minimal runnable example lives in
[`examples/openat_audit.rs`](../crates/sandlock-core/examples/openat_audit.rs).

## Limitations

- **No builtin override.** Security-critical handlers (`chroot`, `cow`) always run first. To
  change builtin behaviour, modify sandlock directly.
- **No before-builtin priority.** An audit handler that wants to observe calls rejected by
  builtins is a coherent use case, but it requires a `HandlerPriority` enum that has not been
  added; the current API only supports appending to the chain.
- **No declarative `Policy` extension.** Adding handlers is a runtime action, not a serialisable
  part of the policy. `Policy` remains a pure data struct.

## Downstream usage

A typical downstream crate exports a struct per handler kind:

```rust
pub struct OpenatHandler {
    pub virtual_tree: Arc<RwLock<MyTree>>,
    pub workspace: PathBuf,
    /* ... */
}

#[async_trait]
impl Handler for OpenatHandler {
    async fn handle(&self, cx: &HandlerCtx<'_>) -> NotifAction {
        /* read path arg via sandlock_core::seccomp::notif::read_child_cstr,
           consult self.virtual_tree, return NotifAction::InjectFdSendTracked
           / Errno / ... */
    }
}
```

The host binary instantiates the handlers and passes them as one
`IntoIterator<Item = (Syscall, Handler)>`.  When the handler types differ
(common in a real downstream), wrap them in a small adapter enum on the
crate side so the iterator's `H` parameter stays homogeneous (see the
"VFS engine" use-case above for an example), then call:

```rust
Sandbox::run_with_extra_handlers(
    &policy,
    &cmd,
    [
        (libc::SYS_openat,     DownstreamHandler::Openat(OpenatHandler   { virtual_tree, workspace })),
        (libc::SYS_close,      DownstreamHandler::Close (CloseHandler    { virtual_tree, oft, store })),
        (libc::SYS_getdents64, DownstreamHandler::DirRead(DirReadHandler { virtual_tree, oft })),
    ],
)
.await?;
```

The crate links against `sandlock-core` as an ordinary dependency — no fork, no
`[patch.crates-io]`, no duplication of `notif::supervisor`.
