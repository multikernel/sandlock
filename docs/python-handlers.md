# Python handlers

The `sandlock.handler` Python wrapper layers a pythonic API over the C ABI
exposed by `sandlock-ffi`. This page is the single source of truth for the
Python wrapper; for the underlying C/Rust contract see
[`extension-handlers.md`](extension-handlers.md).

## Quick start

```python
import sandlock
from sandlock.presets import AuditPathsHandler, COMMON_PATH_SYSCALLS

audit = AuditPathsHandler(callback=lambda path, _ctx: print(f"open {path}"))
sb = sandlock.Sandbox(fs_readable=["/usr", "/etc", "/lib", "/bin"])
sb.run_with_handlers(
    cmd=["/usr/bin/cat", "/etc/hostname"],
    handlers=[(s, audit) for s in COMMON_PATH_SYSCALLS],
)
```

## Core types

- `Handler` — base class. Subclass and override `handle(ctx) -> NotifAction`.
  Set the class attribute `on_exception` (default `ExceptionPolicy.KILL`) to
  choose what the supervisor does when the handler errors.
- `HandlerCtx` — frozen dataclass with the notification fields (`id`, `pid`,
  `flags`, `syscall_nr`, `arch`, `instruction_pointer`, `args`) plus
  child-memory accessors.
- `NotifAction` — frozen value-object. Construct via factory classmethods:
  `continue_()`, `errno(value)`, `returns(value)`, `hold()`,
  `kill(sig, pgid)`, `inject_fd_send(srcfd, newfd_flags)`.
- `ExceptionPolicy` — IntEnum: `KILL` (default), `DENY_EPERM`, `CONTINUE`,
  `DENY_EIO`.

## HandlerCtx accessors

### `read_cstr(addr, max_len) -> str | None`

Read a NUL-terminated string from the child at `addr`. Returns the decoded
string on success, `None` on failure (invalid address, race, or no live
mem handle).

### `read(addr, length) -> bytes | None`

Read `length` raw bytes. Returns the bytes on success, `None` on failure.

### `write(addr, data) -> bool`

Write `data` into the child memory at `addr`. Returns `True` on success.

### `read_path(arg=None, max_len=4096) -> str | None`

Resolve a path-bearing syscall argument to a Python string. With
`arg=None` (default), the path-argument index is inferred from
`ctx.syscall_nr` via a name-keyed table. Multi-path syscalls
(`renameat2`, `rename`, `linkat`, `link`, `symlinkat`, `symlink`) and
unknown syscalls raise `ValueError` — pass `arg=` explicitly in those
cases.

Known single-path syscalls (auto-inferred):

| Syscall                                                                                          | path arg |
|---|---|
| `openat`, `unlinkat`, `mkdirat`, `newfstatat`, `statx`, `faccessat`, `readlinkat`, `execveat`    | 1 |
| `open`, `unlink`, `mkdir`, `rmdir`, `stat`, `lstat`, `access`, `readlink`, `execve`              | 0 |

Multi-path syscalls — call twice with explicit `arg=`:

```python
def handle(self, ctx):
    # renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
    src = ctx.read_path(arg=1)
    dst = ctx.read_path(arg=3)
    return NotifAction.continue_()
```

A live `HandlerCtx` returns the decoded string; a stale or absent mem
handle returns `None`.

## Preset handlers

Imported from `sandlock.presets`. The preset classes are deliberately
NOT re-exported from the root `sandlock` package — root surface stays
minimal; callers reach for presets when they want them. (The core
handler types — `Handler`, `NotifAction`, `HandlerCtx`,
`ExceptionPolicy` — *are* re-exported at the root.)

### `COMMON_PATH_SYSCALLS`

The set of modern path-bearing syscalls a generic file-operation handler
is typically registered against:

```python
COMMON_PATH_SYSCALLS = [
    "openat", "unlinkat", "newfstatat", "statx", "faccessat",
    "readlinkat", "mkdirat", "execveat", "execve",
]
```

Used with a list comprehension to register one handler on all of them:

```python
handlers = [(s, my_handler) for s in COMMON_PATH_SYSCALLS]
```

### `AuditPathsHandler(callback, max_len=4096)`

- `on_exception=CONTINUE` — audit must never block.
- Calls `callback(path, ctx)` on every intercepted syscall (including
  when `path is None`, so the caller sees "couldn't read").
- Returns `NotifAction.continue_()`.

### `PathDenyHandler(deny: list[str], errno=errno.EPERM, max_len=4096)`

- `on_exception=KILL` — security handler, fail-closed.
- `deny` is a `list[str]` of `fnmatch` patterns; passing a single string
  raises `TypeError` (the API is uniform).
- If `path` matches any pattern, returns `NotifAction.errno(errno)`;
  otherwise returns `NotifAction.continue_()`.
- **`path is None` → `continue_()`.** A deny-list does not claim
  "everything else is allowed", so when the path cannot be classified we
  defer to Landlock and other handlers in the chain.

### `PathAllowHandler(allow: list[str], errno=errno.EACCES, max_len=4096)`

- `on_exception=KILL` — security handler, fail-closed.
- `allow` is a `list[str]` of `fnmatch` patterns; passing a single string
  raises `TypeError`.
- If `path` matches any pattern, returns `NotifAction.continue_()`;
  otherwise returns `NotifAction.errno(errno)`.
- **`path is None` → `errno(errno)`.** An allow-list claims "everything
  except the listed paths is denied", so failing to verify means failing
  closed.

### `LogSyscallsHandler(logger=None)`

- `on_exception=CONTINUE` — observational.
- Logs one line per intercepted syscall:
  `syscall=N pid=P args=(a0, a1, a2, a3, a4, a5)`.
- Default `logger` is `logging.getLogger("sandlock.audit").info`. Any
  `Callable[[str], None]` works (e.g. `list.append` in tests).
- If `logger` raises, the exception is absorbed by `on_exception=CONTINUE`
  — the child proceeds but the log line is silently lost.

## Recipes

### Audit every common path syscall

```python
audit = AuditPathsHandler(callback=lambda path, _ctx: print(path))
sb.run_with_handlers(cmd, [(s, audit) for s in COMMON_PATH_SYSCALLS])
```

### Deny a directory tree

```python
deny = PathDenyHandler(deny=["/etc/*", "/var/lib/*"])
sb.run_with_handlers(cmd, [(s, deny) for s in COMMON_PATH_SYSCALLS])
```

### Allow-list paths (fail-closed)

```python
allow = PathAllowHandler(allow=["/tmp/sandbox/*", "/usr/lib/*"])
sb.run_with_handlers(cmd, [(s, allow) for s in COMMON_PATH_SYSCALLS])
```

Anything not under those prefixes returns `EACCES`. Any syscall whose
path the handler cannot read also returns `EACCES` (fail-closed).

### Synthesise a return value

```python
from sandlock.handler import Handler, NotifAction, ExceptionPolicy

class FakePid(Handler):
    on_exception = ExceptionPolicy.KILL

    def handle(self, ctx):
        return NotifAction.returns(777)

sb.run_with_handlers(cmd, [("getpid", FakePid())])
```

### Kill the child from a handler

```python
import signal
from sandlock.handler import Handler, NotifAction

class KillOnEtc(Handler):
    def handle(self, ctx):
        path = ctx.read_path()
        if path and path.startswith("/etc/"):
            return NotifAction.kill(signal.SIGKILL, pgid=0)
        return NotifAction.continue_()
```

**Caveat:** `ctx.read_path()` without an explicit `arg=` raises
`ValueError` for syscalls not in the known path table (see the
`read_path` accessor section). Under the default
`on_exception=KILL` policy that `ValueError` becomes a kill signal
to the child. Either register the handler only against syscalls in
`COMMON_PATH_SYSCALLS`, pass `arg=` explicitly, or set
`on_exception=ExceptionPolicy.CONTINUE` on your handler.

### Combine multiple handlers on one syscall

Register multiple handlers on the same syscall — the supervisor calls
them in registration order, stopping at the first non-`Continue` action:

```python
sb.run_with_handlers(cmd, [
    ("openat", audit),
    ("openat", deny),
])
```

On syscalls that already carry built-in handlers (`openat` for chroot
path normalization, COW write redirection, procfs virtualization;
`clone`/`fork`/`execve` for resource accounting; and others), user
handlers are appended **after** all builtins — see
`build_dispatch_table` in
`crates/sandlock-core/src/seccomp/dispatch.rs`. Dispatch short-circuits
on the first non-`Continue` action, so a user handler only fires if
every built-in for that syscall first returned `Continue`. Built-ins
cannot be overridden or removed; this is the security boundary. When
testing security-critical user handlers (e.g. `PathDenyHandler` on
`openat`), exercise them against the actual built-in set on your
syscall list rather than against an empty dispatch table.

## Threading & safety contract

- **GIL contention.** Each handler dispatch holds the GIL for the
  duration of `handle()`. The supervisor may dispatch handler
  callbacks concurrently across different notifications, so design
  `handle()` to be fast (sub-millisecond) and to protect any mutable
  handler state with your own synchronization. High-frequency
  interception (e.g. per-`SYS_openat` audit on a busy workload) will
  serialize on the GIL and can stall the supervisor.

- **Interpreter finalization.** If `Py_FinalizeEx` runs while the
  sandbox is still alive (e.g. the main thread exits with handlers
  still registered), the trampoline checks `Py_IsInitialized()` and
  returns an error, routing the notification through the handler's
  `on_exception` policy. Do not rely on this for clean shutdown — wait
  for the run to finish before tearing down the interpreter.

- **Native crashes inside `handle()`.** A segfault inside a Python
  handler is not recoverable: the supervisor task hangs and the
  trapped child is held indefinitely. Write defensive handlers; this
  is a user responsibility.

- **Tokio runtime reentrancy.** The C ABI's `sandlock_run_with_handlers`
  builds and drives its own Tokio runtime internally. Do not call
  `Sandbox.run_with_handlers` from a thread that already runs a Tokio
  runtime — the FFI will panic, and the panic surfaces as a Python
  exception. Pure-Python use (the common case) is unaffected.

## Ownership rules

- **Handler instances** must outlive the run. The Sandbox holds a
  strong reference for the duration of the run; the reference is
  released when the run completes (success or failure).

- **File descriptors** passed via `NotifAction.inject_fd_send(srcfd)`
  transfer ownership to the supervisor on dispatch. The Python caller
  must NOT close `srcfd` afterwards, regardless of whether the action
  was actually dispatched — the supervisor handles cleanup on all
  paths.

## C ABI

The Python wrapper sits on the C ABI declared in
`crates/sandlock-ffi/include/sandlock.h`. For the C ABI contract,
exception policies at the supervisor level, and ownership across the
boundary see the C/Rust sections of
[`extension-handlers.md`](extension-handlers.md).
