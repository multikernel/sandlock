# Extension: user-supplied syscall handlers

> Available since 0.7 (branch `feature/extra-handlers`).

## 1. What this is

`sandlock-core` routes every intercepted syscall through a
[chain-of-responsibility table](../crates/sandlock-core/src/seccomp/dispatch.rs)
where builtin handlers (`chroot`, `cow`, `procfs`, `network`, `port_remap`,
resource accounting) each register for the specific syscall numbers they
care about.  A call walks the chain in registration order; the first
non-[`NotifAction::Continue`](../crates/sandlock-core/src/seccomp/notif.rs)
result wins.

This patch exposes a **public extension point**:

```rust
Sandbox::run_with_extra_handlers(policy, cmd, Vec<ExtraHandler>)
```

Downstream crates register their own `HandlerFn` instances that are
appended to each syscall's chain **after** all builtins.  No builtin is
modified, disabled, or reordered.

## 2. Why it is needed

Two concrete use cases motivate this API.

### 2.1 VFS engine: real-time uploads to object storage

A deployment that collects guest-generated artifacts to object storage
typically does so *after* the sandboxed process exits — the whole tree is
walked and uploaded in a blocking post-step.  For large outputs this
doubles end-to-end latency: the guest's own write time plus a serial
upload while the request hangs.

Streaming uploads remove the post-step:

- `openat(O_CREAT)` on a tracked path → allocate a virtual node + S3
  Multipart Upload session.
- Every `write(fd, buf, n)` where `fd` is mapped to that node → chunked
  Multipart `UploadPart`, track offset, return `n` synchronously to
  the guest.
- `close(fd)` → `CompleteMultipartUpload`.

These three interceptors must live in the same supervisor task as
sandlock's chroot normalizer and COW tracker — one `SECCOMP_FILTER_FLAG_NEW_LISTENER`
per process means one listener, so we cannot run a second supervisor
alongside sandlock's.

With `run_with_extra_handlers`:

```rust
let extras = vec![
    ExtraHandler::new(libc::SYS_openat, s3_open_handler),
    ExtraHandler::new(libc::SYS_write,  s3_write_handler),
    ExtraHandler::new(libc::SYS_close,  s3_close_handler),
];
Sandbox::run_with_extra_handlers(&policy, &cmd, extras).await?;
```

Each handler sees the post-builtin view (e.g. `openat` arguments are
already chroot-normalized by sandlock's handler), so we can trust the
path string we inspect.

### 2.2 Deterministic audit trail for compliance

Regulated environments (CIS, GDPR data residency) require a guaranteed
audit log of every file read/write the user code performs, tamper-proof
against the guest.  Traditional approaches:

- Python wrapping (`wrapt`, import hooks) — easy for the guest to
  circumvent via `ctypes` / raw syscalls.
- eBPF file tracing — requires `CAP_BPF`, often unavailable in managed
  Kubernetes.

An `ExtraHandler` sitting on `SYS_openat` / `SYS_write` / `SYS_unlinkat`
captures the call before the kernel acts on it.  The guest cannot
bypass it without bypassing seccomp itself (which sandlock blocks).

The included example [`openat_audit.rs`](../crates/sandlock-core/examples/openat_audit.rs)
shows a minimal audit handler.

## 3. Semantics

### 3.0 BPF filter coverage

`Sandbox::run_with_extra_handlers` collects the syscall numbers declared
by the supplied `Vec<ExtraHandler>` and merges them into the cBPF
notification list installed in the child *before* `execve`.  Without this
step the kernel would never raise `SECCOMP_USER_NOTIF` for a syscall
that has no builtin handler — the dispatch table would receive nothing
and the user handler would silently never fire.  The merge is dedup-aware
(`SYS_openat` registered both by a builtin and by an extra produces a
single JEQ in the assembled program).

### 3.0.1 Default-deny bypass guard

The cBPF program emits `notif` JEQs *before* `deny` JEQs, so a syscall
present in both lists hits `SECCOMP_RET_USER_NOTIF` first.  An extra
registered on a syscall in
[`DEFAULT_DENY_SYSCALLS`](../crates/sandlock-core/src/sys/structs.rs)
(or in `policy.deny_syscalls`) would therefore convert a kernel-deny
into a user-supervised path; a handler returning
`NotifAction::Continue` becomes `SECCOMP_USER_NOTIF_FLAG_CONTINUE` and
the kernel actually runs the syscall — silently bypassing deny.

`Sandbox::run_with_extra_handlers` rejects this configuration at
registration time and returns `SandboxError::Child` naming the offending
syscall.  This is the API-level enforcement of the security boundary
described in §3.3.

### 3.1 Ordering

For each syscall:

1. All builtin handlers registered inside
   [`build_dispatch_table`](../crates/sandlock-core/src/seccomp/dispatch.rs)
   run first, in the order they are registered.
2. All `extra_handlers` run afterwards, in the order they appear in the
   `Vec<ExtraHandler>` argument.
3. If the same syscall number appears multiple times in
   `extra_handlers`, those handlers run in insertion order.

This is the same contract as existing `DispatchTable::register` —
`ExtraHandler` is just a declarative sugar for "call `register` at the
end of `build_dispatch_table`".

### 3.2 What a handler can return

`HandlerFn` returns [`NotifAction`](../crates/sandlock-core/src/seccomp/notif.rs),
same as builtin handlers:

| Variant | Effect |
|---|---|
| `Continue` | fall through to the next handler in the chain; if last, the kernel resumes the syscall (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`) |
| `Errno(e)` | return `-e` to the guest, do not run the syscall |
| `ReturnValue(val)` | return `val` to the guest, do not run the syscall (useful for faking `write`) |
| `InjectFd { srcfd, targetfd }` | inject `srcfd` into the guest at `targetfd`, then continue |
| `Kill { sig, pgid }` | signal the guest's process group |

### 3.3 Security boundary

User handlers **cannot**:

- Remove a builtin handler.
- Reorder a builtin handler to run after them.
- Skip a builtin handler if it returned non-Continue.

This is enforced structurally: `build_dispatch_table` registers builtins
into an empty table *before* iterating `extra_handlers`, and the chain
evaluator stops at the first non-Continue.

User handlers **can**:

- Observe every syscall invocation that sandlock intercepts via seccomp
  user-notification.  (They do not see syscalls that seccomp allows
  unconditionally without notification.)
- Fake results (`ReturnValue`, `Errno`) — but only after builtins
  returned `Continue`, so they cannot subvert confinement.

### 3.4 Panics

`DispatchTable::dispatch` does not wrap handler calls in `catch_unwind`.
A panic inside a user handler propagates up the `tokio::spawn` task that
drives the supervisor, which leads to task failure and the child being
killed by sandlock's watchdog.

If you want to tolerate bugs in downstream handlers, wrap them yourself:

```rust
let safe: HandlerFn = Box::new(|notif, ctx, fd| {
    Box::pin(async move {
        match std::panic::AssertUnwindSafe(actual_handler(notif, ctx, fd))
            .catch_unwind()
            .await
        {
            Ok(action) => action,
            Err(_) => NotifAction::Continue, // fail-open
        }
    })
});
```

## 4. Non-goals

- **Overriding builtins.**  Security-critical handlers (`chroot`, `cow`)
  must always run.  If you need different behaviour, patch sandlock.
- **`Before`-priority user handlers.**  Use case (audit that sees
  denied-by-builtin calls) is real but orthogonal — will be added via
  a separate `HandlerPriority` enum if demand emerges.
- **Declarative `Policy` extension.**  Adding handlers is a runtime
  action, not a serializable part of the policy.  Keep `Policy` a pure
  data struct.

## 5. Usage

See [`examples/openat_audit.rs`](../crates/sandlock-core/examples/openat_audit.rs)
for a runnable example.

Quick sketch:

```rust
use sandlock_core::{Policy, Sandbox};
use sandlock_core::seccomp::dispatch::{ExtraHandler, HandlerFn};
use sandlock_core::seccomp::notif::NotifAction;

let policy = Policy::builder().fs_read("/usr").fs_write("/tmp").build()?;

let h: HandlerFn = Box::new(|notif, _ctx, _fd| {
    Box::pin(async move {
        // inspect notif.data.args, etc.
        NotifAction::Continue
    })
});

let result = Sandbox::run_with_extra_handlers(
    &policy,
    &["python3", "-c", "print(42)"],
    vec![ExtraHandler::new(libc::SYS_openat, h)],
).await?;
```

## 6. Backwards compatibility

None of the existing API changes signature.  `Sandbox::run(policy, cmd)`
still exists and now delegates to
`Sandbox::run_with_extra_handlers(policy, cmd, Vec::new())`.  All 211
unit tests and the unaffected integration tests keep passing.

## 7. Downstream sketch

A typical VFS-engine downstream crate would export something like:

```rust
pub fn build_vfs_handlers(
    config: VfsConfig,
) -> Vec<sandlock_core::seccomp::dispatch::ExtraHandler> { /* ... */ }
```

which the supervisor binary passes straight into `run_with_extra_handlers`.
No fork of sandlock, no `[patch.crates-io]`, no duplication of
`notif::supervisor` — one dependency declaration in `Cargo.toml` is all
it takes.
