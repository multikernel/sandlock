# Architecture

Sandlock is implemented in Rust. The crates and SDKs layer as follows:

```
       ┌─────────────┐      ┌─────────────┐
       │  Python SDK │      │   Go SDK    │
       │   (ctypes)  │      │    (cgo)    │
       └──────┬──────┘      └──────┬──────┘
              │  FFI               │  FFI
              └─────────┬──────────┘
                        ▼
┌──────────────┐    ┌──────────────────────────────┐
│ sandlock CLI │───>│       libsandlock_ffi.so      │
└──────────────┘    └───────────────┬──────────────┘
                                    │
┌──────────────┐                    │
│ sandlock-oci │────────────┐       │
│ (OCI runtime)│            │       │
└──────────────┘            ▼       ▼
                    ┌──────────────────────────────┐
                    │         sandlock-core         │
                    │  Landlock · seccomp · COW ·   │
                    │  pipeline · policy_fn · vDSO  │
                    └──────────────────────────────┘
```

- **sandlock-core**: Rust library (Landlock, seccomp, supervisor, COW, pipeline)
- **sandlock-cli**: Rust CLI binary (`sandlock run ...`)
- **sandlock-oci**: OCI runtime shim for containerd, CRI-O, and Kubernetes (namespace-less)
- **sandlock-ffi**: C ABI shared library (`libsandlock_ffi.so`)
- **Python SDK**: ctypes bindings to the FFI library
- **Go SDK**: cgo bindings to the FFI library

## Confinement sequence

Sandlock applies confinement in sequence after `fork()`:

```
Parent                              Child
  │  fork()                           │
  │──────────────────────────────────>│
  │                                   ├─ 1. setpgid(0,0)
  │                                   ├─ 2. Optional: chdir(cwd)
  │                                   ├─ 3. NO_NEW_PRIVS
  │                                   ├─ 4. Landlock (fs + net + IPC)
  │                                   ├─ 5. seccomp filter (deny + notif)
  │                                   │     └─ send notif fd ──> Parent
  │  receive notif fd                 ├─ 6. Wait for "ready" signal
  │  start supervisor (tokio)         ├─ 7. Close fds 3+
  │  optional: vDSO patching          └─ 8. exec(cmd)
  │  optional: policy_fn thread
  │  optional: CPU throttle task
```

## Seccomp Supervisor

The async notification supervisor (tokio) handles intercepted syscalls:

| Syscall | Handler |
|---|---|
| `clone/fork/vfork` | Process count enforcement (only with `max_processes` or `policy_fn`; otherwise left to the kernel) |
| `mmap/munmap/brk/mremap/mprotect` | Memory limit tracking |
| `connect/sendto/sendmsg` | IP allowlist + on-behalf execution + HTTP ACL redirect |
| `bind` | On-behalf bind + port remapping |
| `openat` | /proc virtualization, COW interception |
| `unlinkat/mkdirat/renameat2` | COW write interception |
| `execve/execveat` | policy_fn hold + vDSO re-patching |
| `getrandom` | Deterministic PRNG injection |
| `clock_nanosleep/timer_settime` | Timer adjustment for frozen time |
| `getdents64` | PID filtering, COW directory merging |
| `getsockname` | Port remap translation |

## Custom Handlers

Downstream Rust crates can append their own seccomp-notification
handlers to the supervisor chain alongside the builtins, registering
for any syscall they care about via the `Handler` trait and
`Sandbox::run_with_handlers`. The builtin chain runs first, so
user handlers cannot subvert confinement; the registration step also
rejects handlers on syscalls in the default blocklist or
`extra_deny_syscalls`. See
[`extension-handlers.md`](extension-handlers.md) for the
full API, ordering semantics, and state patterns, and
[`python-handlers.md`](python-handlers.md) for the Python wrapper.

## COW Filesystem

Copy-on-write filesystem isolation via seccomp notification: when
`workdir` is set, sandlock intercepts filesystem syscalls and stages
writes in an upper directory; reads resolve upper-then-lower. No mount
namespace, no user namespace, no root. Committed on exit, aborted on
error. Only regular files, directories, and symlinks are staged: a FIFO,
socket, or device node is a kernel object, so opens and metadata changes
on one go to the kernel under the Landlock policy and are never reverted.

**Dry-run mode**: `--dry-run` runs the command, inspects the COW layer
for changes (added/modified/deleted files), prints a summary, then
aborts, leaving the workdir completely untouched. Useful for previewing
what a command would do before committing.
