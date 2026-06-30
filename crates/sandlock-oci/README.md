# sandlock-oci

An OCI runtime shim for the [sandlock](https://github.com/multikernel/sandlock)
sandbox. It implements the OCI Runtime Specification command interface so that
container runtimes (containerd, CRI-O, Kubernetes) can use sandlock as a
drop-in low-level runtime, with no kernel namespaces and no cgroups.

Where `runc` builds containers from namespaces, cgroups, and `pivot_root`,
`sandlock-oci` confines the workload with **Landlock** (filesystem, network,
and IPC), **seccomp-bpf** (syscall filtering), and **seccomp user
notification** (resource limits, IP enforcement, and `/proc` virtualization).
The result is a namespace-less container that runs unprivileged.

## How it fits in

`sandlock-oci` is a thin OCI-compatible front end over `sandlock-core`. It
parses an OCI bundle, translates `config.json` into a sandlock policy, and
drives the sandbox lifecycle on behalf of a higher-level runtime.

```
  containerd / CRI-O / kubelet
            │  (OCI runtime calls)
            ▼
      sandlock-oci  ──fork──>  supervisor daemon
            │                       │
            │                       ▼
            │                  sandlock-init  (confined PID 1 in the sandbox)
            │                       │  fork + execve
            │                       ▼
            │                   workload  (+ any exec'd siblings)
            ▼
      sandlock-core
   Landlock · seccomp · seccomp-notify · COW
```

Each call from the runtime maps to one `sandlock-oci` subcommand. A long-lived
supervisor daemon owns the sandbox between calls, and an in-sandbox
`sandlock-init` acts as PID 1 so the workload and every `exec`'d process share
one sandbox and one seccomp supervisor.

## Lifecycle

```
create <id> -b <bundle>   spawn the supervisor, build the sandbox, park the
                          child before execve, and save state
start  <id>               release the parked child so it execve's the workload
state  <id>               print state.json, reconciled against liveness
kill   <id> <signal>      forward a signal to the workload (or its group with -a)
delete <id>               shut the supervisor down and remove the state dir
exec   <id> <cmd>         run a sibling process in the same sandbox
list                      list all sandboxes managed by sandlock-oci
checkpoint <id>           snapshot a running sandbox to an image directory
restore <id>              recreate and resume a sandbox from a checkpoint image
check                     report kernel Landlock support
```

The `create` then `start` split matches the OCI two-phase model: `create`
forks the child and installs the full policy (Landlock, seccomp-notify,
resource limits, and the network ACL) with the child parked just before
execve, and `start` releases it. The supervisor reports the child PID back to
the caller over a pipe, so there is no sleep or race in the handshake.

## OCI spec translation

`config.json` is mapped to a sandlock policy by intent rather than by
replaying Linux container primitives:

| OCI field | sandlock mapping |
|---|---|
| `root.path` | chroot target for the sandbox |
| `root.readonly` | grants the rootfs read-only instead of read-write |
| `mounts` (bind) | `fs_mount` with read-only or read-write from options |
| `mounts` (tmpfs) | host-backed scratch dir, isolated and cleaned on delete |
| `mounts` (proc) | host `/proc` mounted read-only, virtualized by seccomp |
| `mounts` (sysfs) | host `/sys` mounted read-only |
| `process.cwd` | working directory |
| `process.env` | environment (started clean, then populated from the spec) |
| `process.user` | run-as uid/gid, with a user namespace only if needed |
| `linux.resources.memory.limit` | `max_memory` |
| `linux.resources.pids.limit` | `max_processes` |
| `linux.resources.cpu.quota/period` | sub-core `max_cpu` throttle |
| `linux.resources.cpu.cpus` | CPU affinity via `sched_setaffinity` |
| `linux.namespaces` | ignored by design |

Supported OCI spec versions are 1.0.x, 1.1.x, and 1.2.x. Bundles declaring any
other version are rejected at `create` rather than silently mis-mapped.

Mount types with no safe namespace-less equivalent (`devpts`, `mqueue`,
`cgroup`, `cgroup2`) are skipped. Port binding is remapped so in-container
servers can `bind()` without colliding on host ports.

## runc compatibility

The CLI accepts the global and per-command flags that containerd and CRI-O
pass to `runc`, so it can be wired in as a drop-in replacement. Flags that do
not apply to a namespace-less, cgroup-less runtime are accepted and ignored:
`--systemd-cgroup`, `--rootless`, `--no-pivot`, `--no-new-keyring`, and the
`--debug` flag. Fatal errors are appended to the `--log` file in text or JSON
form so the containerd shim can surface the real failure reason.

The supervisor daemon exits with the workload's status (re-raising the killing
signal where applicable), so a reaping shim sees a wait-status that mirrors the
workload, the same as it would from `runc`.

## Usage

Point a runtime at the `sandlock-oci` binary as its OCI runtime, or drive it
directly against a bundle:

```sh
sandlock-oci create mycontainer -b /path/to/bundle
sandlock-oci start  mycontainer
sandlock-oci state  mycontainer
sandlock-oci exec   mycontainer sh -c 'echo hello'
sandlock-oci kill   mycontainer SIGTERM
sandlock-oci delete mycontainer
```

State lives under `$XDG_RUNTIME_DIR/sandlock-oci` for unprivileged users and
`/run/sandlock-oci` for root, overridable with the global `--root` flag.

## Requirements

- Linux 6.12 or newer (Landlock ABI v6)
- A built `sandlock-core` (this crate depends on it directly)

Run `sandlock-oci check` to confirm the running kernel supports Landlock.

## Limitations

- The workload and all `exec`'d processes share one sandbox and one seccomp
  supervisor, via the in-sandbox `sandlock-init` PID 1.
- `exec` is non-TTY only. `-t` and `--console-socket` are accepted for runc
  compatibility but ignored, as there is no PTY support yet.

## License

Apache-2.0. See the repository root for details.
