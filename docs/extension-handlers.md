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

The `Handler` trait has a single method that returns a boxed future, kept dyn-compatible so the
supervisor can store user handlers as `Vec<Arc<dyn Handler>>`. State lives on the struct's
fields — no `Arc::clone` ladders, no closure ceremony at the call site.

```rust
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use sandlock_core::{Handler, HandlerCtx, Policy, Sandbox};
use sandlock_core::seccomp::notif::NotifAction;

struct OpenAudit { count: AtomicU64 }

impl Handler for OpenAudit {
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> Pin<Box<dyn Future<Output = NotifAction> + Send + 'a>> {
        Box::pin(async move {
            let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
            eprintln!("[audit #{n}] pid={} openat", cx.notif.pid);
            NotifAction::Continue
        })
    }
}

let policy = Policy::builder().fs_read("/usr").fs_write("/tmp").build()?;
Sandbox::run_with_handlers(
    &policy,
    None,
    &["python3", "-c", "print(42)"],
    [(libc::SYS_openat, OpenAudit { count: AtomicU64::new(0) })],
)
.await?;
```

`HandlerCtx` is passed by reference for the dispatch call.  It exposes only the kernel
notification (`notif`) and the supervisor's seccomp listener fd (`notif_fd`); supervisor-internal
state is intentionally not part of this contract — handler state lives on the implementor.

### Closures via blanket impl

For trivial single-shot handlers, closures work via the blanket `impl<F, Fut> Handler for F`:

```rust
let audit = |cx: &HandlerCtx| async move {
    eprintln!("openat from pid {}", cx.notif.pid);
    NotifAction::Continue
};

Sandbox::run_with_handlers(&policy, None, &cmd, [(libc::SYS_openat, audit)]).await?;
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

`run_with_handlers` accepts an `IntoIterator<Item = (S, H)>` where `S: TryInto<Syscall, Error = SyscallError>`,
so callers can pass raw `i64`/`u32` syscall numbers and they are validated up-front:

```rust
Sandbox::run_with_handlers(&policy, None, &cmd, [(libc::SYS_openat, openat_h)]).await?;
```

Without `Syscall::checked`, passing `-5` as a syscall number would compile but never fire — the
cBPF filter cannot emit a JEQ for an arch-unknown number.

### Entry points

There are two entry points; both spawn the sandbox, wait for it to exit, and return the result:

| name | stdio |
| --- | --- |
| `Sandbox::run_with_handlers(policy, name, cmd, handlers)` | captured (returned in `RunResult`) |
| `Sandbox::run_interactive_with_handlers(policy, name, cmd, handlers)` | inherited from the parent |

`name: Option<&str>` is the sandbox instance name (also exposed as the virtual hostname when set);
pass `None` when no name is needed.

Both have the same generic shape:

```rust
pub async fn run_with_handlers<I, S, H>(
    policy: &Policy,
    name: Option<&str>,
    cmd: &[&str],
    handlers: I,
) -> Result<RunResult, SandlockError>
where
    I: IntoIterator<Item = (S, H)>,
    S: TryInto<Syscall, Error = SyscallError>,
    H: Handler;
```

Multiple handlers — passed in one array literal:

```rust
Sandbox::run_with_handlers(
    &policy,
    None,
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
a closure plus a struct), erase them via `Box<dyn Handler>` (or `Arc<dyn Handler>`) — both
implement `Handler` themselves, so `H` resolves to a single type:

```rust
let openat_h: Box<dyn Handler> = Box::new(my_openat_handler);
let close_h:  Box<dyn Handler> = Box::new(MyCloseStruct { ... });

Sandbox::run_with_handlers(
    &policy,
    None,
    &cmd,
    [(libc::SYS_openat, openat_h), (libc::SYS_close, close_h)],
)
.await?;
```

Errors at registration time, before fork:

- `SyscallError::Negative` / `SyscallError::UnknownForArch` from `Syscall::checked` (wrapped in
  `HandlerError::InvalidSyscall`, then in `SandlockError::Handler`).
- `HandlerError::OnDenySyscall` if any registered syscall is in Sandlock's default syscall
  blocklist or the policy's `extra_deny_syscalls` list (see [Security boundary](#security-boundary)).

### Interactive mode

For REPL-like workflows (a sandboxed shell, a long-running supervised process whose stdin/stdout
should be inherited from the host), use `run_interactive_with_handlers`. The handler API
is identical:

```rust
Sandbox::run_interactive_with_handlers(
    &policy,
    None,
    &["bash"],
    [(libc::SYS_openat, audit_handler)],
)
.await?;  // host stdin/stdout inherited
```

`run_interactive_with_handlers` does not capture stdout/stderr — the child sees the parent's
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
use std::future::Future;
use std::pin::Pin;
use sandlock_core::{Handler, HandlerCtx};
use sandlock_core::seccomp::notif::{read_child_cstr, NotifAction};

struct ExtensionDenyHandler { denied_suffixes: Vec<String> }

impl Handler for ExtensionDenyHandler {
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> Pin<Box<dyn Future<Output = NotifAction> + Send + 'a>> {
        Box::pin(async move {
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
        })
    }
}
```

Synthesising data INTO the guest follows the same pattern with `write_child_mem`. For example, a
`getdents64` handler that returns an empty directory listing:

```rust
fn handle<'a>(
    &'a self,
    cx: &'a HandlerCtx,
) -> Pin<Box<dyn Future<Output = NotifAction> + Send + 'a>> {
    Box::pin(async move {
        // args[1] is `struct linux_dirent64 *dirp` — write zero bytes (empty
        // listing) and return 0 (no entries) to the guest.
        let buf_addr = cx.notif.data.args[1];
        if let Err(_e) = write_child_mem(cx.notif_fd, cx.notif.id, cx.notif.pid, buf_addr, &[]) {
            return NotifAction::Errno(libc::EFAULT);
        }
        NotifAction::ReturnValue(0)
    })
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
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};

struct CallStats {
    openat: AtomicU64,
    close:  AtomicU64,
}

impl Handler for CallStats {
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> Pin<Box<dyn Future<Output = NotifAction> + Send + 'a>> {
        Box::pin(async move {
            match cx.notif.data.nr as i64 {
                n if n == libc::SYS_openat => self.openat.fetch_add(1, Ordering::Relaxed),
                n if n == libc::SYS_close  => self.close.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
            NotifAction::Continue
        })
    }
}
```

For one handler instance shared across multiple syscall registrations, write a thin wrapper:

```rust
struct DispatchCallStats(std::sync::Arc<CallStats>);

impl Handler for DispatchCallStats {
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> Pin<Box<dyn Future<Output = NotifAction> + Send + 'a>> {
        self.0.handle(cx)
    }
}

let stats = std::sync::Arc::new(CallStats {
    openat: AtomicU64::new(0),
    close:  AtomicU64::new(0),
});

Sandbox::run_with_handlers(
    &policy,
    None,
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
2. Handlers passed to `run_with_handlers` run afterwards, in iterator order.
3. Multiple iterator entries on the same syscall run in insertion order.

The chain stops as soon as a handler returns a non-`NotifAction::Continue` result; subsequent
handlers in the chain are not invoked. This contract is enforced structurally —
`build_dispatch_table` registers builtins into an empty table *before* iterating user-supplied
handlers, and the chain evaluator short-circuits on the first non-`Continue`.

The contract is exercised at two layers:

- Unit, in [`seccomp::dispatch::handler_tests`](../crates/sandlock-core/src/seccomp/dispatch.rs):
  `dispatch_walks_chain_in_registration_order`,
  `dispatch_runs_builtin_before_extra`,
  `dispatch_stops_at_first_non_continue` drive `dispatch()` walker against a minimal `SupervisorCtx`.
- End-to-end, in [`tests/integration/test_handlers.rs`](../crates/sandlock-core/tests/integration/test_handlers.rs):
  `run_with_handlers_preserves_insertion_order_in_sandbox_chain`,
  `builtin_non_continue_blocks_extra`,
  `handler_runs_after_builtin_returns_continue` drive a live Landlock+seccomp sandbox.

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
| `Defer(Deferred)` | Run the carried future off the supervisor loop; its terminal action is sent later, keyed by `notif.id`. Non-`Continue`, so it ends the chain. See [Deferred handlers](#deferred-handlers). |

`InjectFd`/`InjectFdSend`/`InjectFdSendTracked` carry a file descriptor. To synthesise *content*
(rather than inject an fd you already hold), construct the action with
[`NotifAction::inject_bytes`](#injecting-synthetic-content-inject_bytes); it builds the sealed
`memfd` and produces an `InjectFdSend` for you.

### Injecting synthetic content (`inject_bytes`)

When a handler hands the guest synthetic file content (a secret, a generated config, a fetched
object) as the result of an `open`/`openat`, use
[`NotifAction::inject_bytes`](../crates/sandlock-core/src/seccomp/notif.rs) instead of building a
`memfd` by hand. It creates an in-memory file populated with the bytes, rewinds it, seals it
read-only, and returns an `InjectFdSend` action carrying that fd:

```rust
use sandlock_core::seccomp::notif::NotifAction;

// Inside a handler: serve the bytes as the openat result fd.
return NotifAction::inject_bytes(b"INJECTED CONTENT\n");
```

`inject_bytes` owns the fd end to end: the supervisor creates, populates, seals, and (on dispatch)
closes it, so the caller never touches a raw fd and there is no "when do I close this" question. On
an allocation failure it collapses to `Errno(EIO)`, which is why it returns a `NotifAction`
directly rather than a `Result`.

The two defaults both suit the dominant case (synthetic, often sensitive, read-only content):

- **Sealed read-only.** The fd carries `F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK`,
  so the guest cannot modify or resize the content it is handed. Sealing is best-effort: on a
  kernel without sealing support the fd is still injected but unsealed, bounded only by the rest
  of the policy.
- **`O_CLOEXEC` on the child-side fd**, so the content does not leak into programs the guest later
  `execve`s (see the note below).

When you are impersonating a real file and want byte-for-byte the semantics the guest asked for (a
writable fd, or the guest's own `O_CLOEXEC` choice), drop to the lower-level primitive
[`content_memfd(content, seal)`](../crates/sandlock-core/src/seccomp/notif.rs), which returns an
`OwnedFd` you pass to `NotifAction::InjectFdSend { srcfd, newfd_flags }` yourself:

```rust
use sandlock_core::seccomp::notif::{content_memfd, NotifAction};

// Writable injected fd, mirroring the guest's own O_CLOEXEC request.
let fd = match content_memfd(&bytes, /* seal */ false) {
    Ok(fd) => fd,
    Err(_) => return NotifAction::Errno(libc::EIO),
};
let cloexec = (cx.notif.data.args[2] as i32 & libc::O_CLOEXEC) != 0; // openat flags
NotifAction::InjectFdSend {
    srcfd: fd,
    newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
}
```

> **Why `O_CLOEXEC` by default.** `newfd_flags` sets the close-on-exec bit on the *child-side* fd
> (distinct from the supervisor's own `MFD_CLOEXEC` copy of the memfd). Without it, a subprocess
> the guest `execve`s inherits an open fd to the injected content and can read it without ever
> opening the file. For secret injection that is a silent leak, so `inject_bytes` closes the fd
> across `exec`; handlers that virtualize a real file and need to honor the guest's request opt out
> via `content_memfd` (or, over the C ABI, the documented flags).

### Continue-site safety

Today's supervisor processes notifications sequentially in a single tokio task, so the response
sent for one notification gates the kernel resumption of the trapped syscall. Treat this as an
implementation detail, not a contract — the public API makes no promise that a future
dispatcher will not parallelise. The `Handler` trait already requires `Send + Sync`, and the C
ABI requires `ud` to be thread-safe (see [C ABI → Thread safety](#thread-safety)) for exactly
this reason. Sandlock-internal locks (`tokio::sync::Mutex`/`RwLock`) live on the supervisor;
user handlers do not have access to them through `HandlerCtx`, so the contract here is local to
handler-owned state on `&self`: a `tokio::sync::Mutex<T>` or `RwLock<T>` field on your handler
must not be held across an `.await` point. If the guard is alive when control returns to the
supervisor loop, the next notification that needs the same lock parks, the response for the
current notification is not sent, and the child stays trapped in the syscall. Acquire, mutate,
drop, and `await` only after the guard is out of scope. For work that is genuinely slow (a network
round-trip, a blocking syscall) rather than a short critical section, do not block the loop at
all: return [`NotifAction::Defer`](#deferred-handlers) and let the supervisor run it off-loop.

See [issue #27][i27] for the underlying supervisor-loop contract that this convention extends to
user handlers.

[i27]: https://github.com/multikernel/sandlock/issues/27

### Deferred handlers

Continue-site safety exists because the supervisor processes notifications sequentially: a handler
that blocks (a network round-trip, a blocking syscall, a slow lock) stalls every other trapped
syscall until it returns. `NotifAction::Defer` is the escape hatch. A handler that returns `Defer`
hands the supervisor an owned, `'static` future; the supervisor moves it onto a worker task, lets
the notification loop proceed immediately, and sends the response (keyed by `notif.id`) when the
future resolves. The trapped child stays parked in the syscall until then, so `notif.id` stays
valid and the child-memory helpers keep working inside the deferred future.

```rust
use std::future::Future;
use std::pin::Pin;
use sandlock_core::{Handler, HandlerCtx};
use sandlock_core::seccomp::notif::{read_child_cstr, NotifAction};

fn handle<'a>(
    &'a self,
    cx: &'a HandlerCtx,
) -> Pin<Box<dyn Future<Output = NotifAction> + Send + 'a>> {
    // Copy out what the deferred future needs: `notif` is `Copy`, `notif_fd`
    // is a `RawFd`, and `Arc` state is cloned. Never borrow `&self`/`cx`:
    // the deferred future is `'static` and outlives this call.
    let (fd, id, pid) = (cx.notif_fd, cx.notif.id, cx.notif.pid);
    let key = read_child_cstr(fd, id, pid, cx.notif.data.args[1], 4096);
    let backend = self.backend.clone();
    Box::pin(async move {
        let Some(key) = key else { return NotifAction::Continue };
        NotifAction::defer(async move {
            // Runs on a worker, off the supervisor loop. The child is still
            // parked, so child-memory helpers and `id` are valid here.
            match backend.get(&key).await {
                Ok(_data) => NotifAction::ReturnValue(0), // e.g. inject a memfd of `_data`
                Err(_) => NotifAction::Errno(libc::EIO),
            }
        })
    })
}
```

The deferred future must be `Send + 'static`: `Send` so the supervisor can move it onto a worker,
and `'static` so it can outlive the borrowed `HandlerCtx`. It does **not** need to be `Sync` (the
supervisor moves it, never shares it by reference). Capture owned data only: copy `notif` (it is
`Copy`), clone an `Arc` for shared state, and never borrow `&self`/`cx`.

Contract:

- **Terminal decision.** `Defer` is non-`Continue`, so it short-circuits the handler chain exactly
  like `Errno`/`ReturnValue`: later handlers on the same syscall do not run. A deferring handler
  decides the outcome.
- **No deferral on freeze/fork syscalls.** Deferral is refused (with `EPERM`) on
  `execve`/`execveat` and fork-creating syscalls, because moving the response off-loop would skip
  the argv-safety freeze (see [issue #27][i27]) and process creation-tracking that those paths
  require before `Continue`.
- **Bounded fan-out.** At most `DEFER_MAX_INFLIGHT` deferred futures run concurrently; beyond that,
  further deferrals fail fast with `EAGAIN` rather than queuing. The cap also bounds the resources
  workers hold (memfds, sockets).
- **No nesting.** A deferred future that itself resolves to `Defer` is a bug; the supervisor
  collapses it to `EIO` so the child is never left wedged.
- **Stale id.** If the child exits mid-defer, the eventual `send_response` is a no-op and the
  child-memory helpers fail safe (they are `id_valid`-bracketed), matching the inline path's
  "child may have exited" tolerance.

Do not defer trivial fast handlers: the worker hop adds latency. Defer only when the work would
otherwise block the loop.

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
- Inject fds (`inject_bytes`, `InjectFd`, `InjectFdSendTracked`) to materialise virtual file
  content via `memfd` without ever touching the host filesystem.

### BPF coverage

`run_with_handlers` collects the syscall numbers declared by the user-supplied handlers and merges them
into the cBPF notification list installed in the child before `execve`. Without this step the
kernel never raises `SECCOMP_RET_USER_NOTIF` for a syscall that no builtin intercepts, and the
user handler silently never fires. The merge is dedup-aware: an `openat` registered both by a
builtin and a user handler produces a single JEQ in the assembled program.

Validation runs at registration time (before fork). If `Syscall::checked` fails, `run_with_handlers`
returns the error without enqueueing the handler.

### Blocklist Bypass Guard

The cBPF program emits notif JEQs *before* deny JEQs, so a syscall present in both lists
hits `SECCOMP_RET_USER_NOTIF` first. A handler registered on a syscall in
[`DEFAULT_BLOCKLIST_SYSCALLS`](../crates/sandlock-core/src/sys/structs.rs) — or in the policy's
`extra_deny_syscalls` list — would convert a kernel-deny into a user-supervised
path; a handler returning `NotifAction::Continue` would become
`SECCOMP_USER_NOTIF_FLAG_CONTINUE` and the kernel would actually run the syscall, silently
bypassing deny.

`run_with_handlers` rejects this configuration at registration time and returns
`HandlerError::OnDenySyscall { syscall_nr }`. The check is implemented in
[`validate_handler_syscalls_against_policy`](../crates/sandlock-core/src/seccomp/dispatch.rs)
and covers both the default blocklist (`DEFAULT_BLOCKLIST_SYSCALLS`) and the
user-specified extras (`extra_deny_syscalls`); both branches are tested
(`validate_extras_rejects_user_specified_blocklist`,
`handler_on_default_blocklist_syscall_is_rejected`,
`run_with_handlers_rejects_handler_on_default_blocklist_syscall`,
`run_with_handlers_rejects_negative_syscall`,
`run_with_handlers_rejects_arch_unknown_syscall`).

Sandlock always installs its default syscall blocklist, so this guard is always active.

## Panics

`DispatchTable::dispatch` does not wrap handler calls in `catch_unwind`. A panic inside a user
handler propagates up the `tokio::spawn` task that drives the supervisor, leading to task failure
and the child being killed by sandlock's watchdog.

To tolerate bugs in downstream handlers, wrap each one with
[`futures::FutureExt::catch_unwind`][catch] (the synchronous `std::panic::catch_unwind` does not
apply to async futures):

```rust
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use futures::future::FutureExt as _;

struct PanicSafe<H: Handler>(H);

impl<H: Handler> Handler for PanicSafe<H> {
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> Pin<Box<dyn Future<Output = NotifAction> + Send + 'a>> {
        Box::pin(async move {
            AssertUnwindSafe(self.0.handle(cx))
                .catch_unwind()
                .await
                .unwrap_or(NotifAction::Continue) // fail-open on panic
        })
    }
}

Sandbox::run_with_handlers(
    &policy,
    None,
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

Because the multipart-upload calls are slow network operations, return
[`NotifAction::Defer`](#deferred-handlers) from those handlers so the uploads run off the
notification loop. Otherwise each upload blocks the single supervisor task and stalls every other
trapped syscall for the duration of the round-trip.

Wrap each handler in `Box<dyn Handler>` so the iterator's `H` parameter is uniform across
heterogeneous handler types:

```rust
Sandbox::run_with_handlers(
    &policy,
    None,
    &cmd,
    [
        (libc::SYS_openat, Box::new(S3OpenHandler::new(&cfg)?)  as Box<dyn Handler>),
        (libc::SYS_close,  Box::new(S3CloseHandler::new(&cfg)?) as Box<dyn Handler>),
        (libc::SYS_mmap,   Box::new(MmapDenyManaged::new(&open_files)) as Box<dyn Handler>),
    ],
)
.await?;
```

Each handler observes the post-builtin view: by the time `S3OpenHandler::handle` runs, the
`openat` arguments are already chroot-normalised, so the path the handler inspects can be trusted
against the configured policy.

### Synthetic file content via `InjectFdSendTracked`

For the common read-only case,
[`NotifAction::inject_bytes`](#injecting-synthetic-content-inject_bytes) is the one-liner: it
builds the sealed `memfd` and returns the inject action for you. Reach for `InjectFdSendTracked`
only when you must know the exact fd number the kernel assigned in the child (for example to key
per-fd bookkeeping); its `on_success` callback delivers that number without racing the guest.

A read-only virtual file (e.g. `/etc/hostname`, an in-memory configuration generated per-call)
can be exposed by intercepting `openat` and injecting a sealed `memfd` containing the content.
The kernel returns the new fd slot to the guest, the handler's `on_success` callback runs
synchronously to register the fd in the handler's bookkeeping, and the guest reads the content
via the `memfd` (no host filesystem touched).

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

impl Handler for OpenatHandler {
    fn handle<'a>(
        &'a self,
        cx: &'a HandlerCtx,
    ) -> Pin<Box<dyn Future<Output = NotifAction> + Send + 'a>> {
        Box::pin(async move {
            /* read path arg via sandlock_core::seccomp::notif::read_child_cstr,
               consult self.virtual_tree, return NotifAction::InjectFdSendTracked
               / Errno / ... */
        })
    }
}
```

The host binary instantiates the handlers and passes them as one
`IntoIterator<Item = (Syscall, Handler)>`.  When the handler types differ
(common in a real downstream), erase them via `Box<dyn Handler>` so the
iterator's `H` parameter stays homogeneous:

```rust
Sandbox::run_with_handlers(
    &policy,
    None,
    &cmd,
    [
        (libc::SYS_openat,     Box::new(OpenatHandler  { virtual_tree, workspace })   as Box<dyn Handler>),
        (libc::SYS_close,      Box::new(CloseHandler   { virtual_tree, oft, store }) as Box<dyn Handler>),
        (libc::SYS_getdents64, Box::new(DirReadHandler { virtual_tree, oft })        as Box<dyn Handler>),
    ],
)
.await?;
```

For a single concrete handler type the bare struct works without the `Box::new` wrapper.

The crate links against `sandlock-core` as an ordinary dependency — no fork, no
`[patch.crates-io]`, no duplication of `notif::supervisor`.

## C ABI

The same handler model is available to non-Rust callers via the
`sandlock-ffi` cdylib (header: `crates/sandlock-ffi/include/sandlock.h`).

### Lifetimes

| Object                         | Allocated by                           | Freed by                                    |
|--------------------------------|----------------------------------------|---------------------------------------------|
| `sandlock_handler_t*`          | `sandlock_handler_new`                 | `sandlock_handler_free` (if never registered) <br>or the supervisor (after a successful `sandlock_run_with_handlers`) |
| `sandlock_action_out_t`        | Rust adapter (stack), pointer to C     | Adapter (stack-scoped to one callback)      |
| `sandlock_mem_handle_t*`       | Rust adapter (stack)                   | Adapter (do not retain past callback return) |
| `sandlock_notif_data_t`        | Rust adapter (stack), pointer to C     | Adapter (do not retain past callback return) |

### Callback contract

A C handler must:

1. Return `0` exactly when it has called one — and only one — of the
   `sandlock_action_set_*` setters on `out`.
2. Return non-zero on any internal error. The supervisor then applies
   the handler's `on_exception` policy (default: `SANDLOCK_EXCEPTION_KILL`).
3. Not retain `notif`, `mem`, or `out` past the return statement.
4. May panic from inside a Rust-side handler exposed through the
   C ABI — the supervisor catches the unwind via `catch_unwind` and
   applies the configured exception policy. Pure-C callers cannot
   panic (C has no unwinding); this clause is for Rust handlers
   plugged into the C ABI surface.

### Thread safety

The supervisor MAY invoke a C handler callback from multiple worker
threads concurrently across different notifications. Today's dispatch
loop is largely serial, but the public C ABI makes no concurrency
guarantee — a future dispatcher could parallelise without an ABI
break. Consequently the caller MUST ensure their `ud` pointer is
thread-safe: either immutable, or guarded by their own synchronization
primitives (atomics, mutex, etc.). Rust offers no synchronization for
an opaque `void*`; the responsibility is on the C side.

### Injecting content (`sandlock_action_set_inject_bytes`)

The C counterpart of
[`NotifAction::inject_bytes`](#injecting-synthetic-content-inject_bytes) is:

```c
void sandlock_action_set_inject_bytes(sandlock_action_out_t *out,
                                      const uint8_t *data, size_t len,
                                      uint32_t flags);
```

The supervisor copies `data` during the call (so it need not outlive the
call), builds the backing in-memory file, and owns the resulting fd.
Unlike `sandlock_action_set_inject_fd_send`, the caller passes no fd and
frees nothing. On an allocation failure the action becomes `Errno(EIO)`,
so the one-setter callback contract still holds.

`flags` is a bitmask whose zero value is the safe default (sealed
read-only, child-side fd `O_CLOEXEC`), matching `inject_bytes`:

| `flags` | effect |
|---|---|
| `0` | sealed read-only, `O_CLOEXEC` (recommended) |
| `SANDLOCK_INJECT_WRITABLE` | leave the memfd writable (do not seal) |
| `SANDLOCK_INJECT_NO_CLOEXEC` | clear `O_CLOEXEC` on the child-side fd |

`data` may be `NULL` when `len == 0`, which injects an empty file. The
pure-C check in `crates/sandlock-ffi/tests/c/handler_smoke.c` exercises
both the sealed default and the `SANDLOCK_INJECT_WRITABLE` variant.

### Minimal example

See `crates/sandlock-ffi/tests/c/handler_smoke.c` for the canonical
end-to-end example.

## Python wrapper

See [`python-handlers.md`](python-handlers.md) — the dedicated page is the
single source of truth for the Python wrapper.
