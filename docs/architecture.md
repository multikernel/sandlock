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
| `clone/fork/vfork` | Process count enforcement |
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

## Control discovery

Sandbox names are reserved in a per-user System V semaphore registry in the
current IPC namespace. Claims use `SEM_UNDO`, so an ordinary fork cannot retain
its parent's reservation. A completed or dropped sandbox releases its claim;
process exit, including `SIGKILL`, releases it in the kernel. Each new claim uses
a random abstract Unix socket address. An inherited descriptor for an earlier
instance therefore cannot prevent reuse of the sandbox name.

The registry grows in segments of 4,096 names, with no compiled-in total
sandbox limit. Each segment has one set of 8,196 semaphores and one shared-memory
segment for names, 128-bit instance tokens, and index links. Each sandbox uses
two semaphores: supervisor ownership and the child's PID stamp. A shared root
directory has 65,536 hash buckets, so name lookup and reservation scan only the
matching bucket rather than every sandbox. The bucket count does not limit the
number of names; collisions form chains across segments.

A root transaction lock serializes metadata access, name reservation, and child
instance-token checks. A small insertion journal lets the next process finish
or discard an index update interrupted by a crash. Each segment's metadata
header identifies its root and ordinal before its semaphore set is used, so an
IPC key collision fails without modifying another segment's reservations.

The registry uses no filesystem paths, helper processes, dedicated threads, or
io_uring. Its versioned IPC objects persist and reuse inactive entries within
each hash bucket. Allocated storage therefore tracks historical demand per
bucket, not just the current live count. Host semaphore, shared-memory, and
memory limits bound growth. Resource exhaustion and registry transaction errors
fail sandbox creation; transaction waits are bounded to two seconds. SEM_UNDO
releases both ownership and transaction locks after a process exits.

The registry is accessible only to its owning UID. Processes with that same UID
are trusted, as with the control socket. The child publishes its process-group
identity in a dedicated semaphore before confinement; `GETPID` returns its
kernel-recorded PID. This replaces the
process-group socket. A single abstract request socket remains for control
requests, and clients authenticate its supervisor with `SO_PEERCRED`. Control
clients and supervisors must share the IPC namespace used for discovery and the
network namespace containing their abstract sockets. This protocol does not
discover sandboxes started by older versions using name-based socket addresses.

Sandlock does not create an IPC namespace. The default seccomp policy denies
semaphore and shared-memory syscalls, including in unsupervised mode.
Knowing the registry ID does not let a confined workload read, modify, or remove
it. Metadata is attached only during registry operations, marked
`MADV_DONTFORK` under the sandbox fork lock, and detached before confinement.
This also protects in-process entrypoints that do not exec. The child PID stamp
creates no undo adjustment, and ordinary forks do not
inherit the supervisor's undo adjustments. Explicitly allowing `sysv_ipc` restores
same-UID access to the registry and therefore requires trusting the workload.
A nested sandbox that cannot access the registry can execute without control
introspection, with a diagnostic. A host explicitly using `CLONE_SYSVSEM` can
share undo state and delay automatic cleanup until the last sharer exits. Explicit sandbox cleanup
still releases the claim.

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
