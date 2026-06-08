# sandlock Go SDK

Go bindings for [sandlock](https://github.com/multikernel/sandlock), a
lightweight Linux process sandbox built on Landlock, seccomp-bpf, and seccomp
user notification. No root, no Docker, no namespaces.

The bindings bind the sandlock C ABI (`libsandlock_ffi`) via cgo, mirroring the
Python SDK's `Sandbox` surface. **Linux only**; the runtime requires Linux
6.12+ (Landlock ABI v6).

```go
import sandlock "github.com/multikernel/sandlock/go"
```

## Building

cgo links against `libsandlock_ffi`, produced by the Rust workspace. The
default link flags resolve the library relative to this package
(`../target/release`), so build from a checkout of the sandlock repository:

```bash
cargo build --release            # writes target/release/libsandlock_ffi.so
cd go && go test ./...
```

To use the SDK from another module, point cgo at an installed library, e.g.:

```bash
CGO_LDFLAGS="-L/usr/local/lib -Wl,-rpath,/usr/local/lib" go build
```

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"

	sandlock "github.com/multikernel/sandlock/go"
)

func main() {
	sb := &sandlock.Sandbox{
		FSReadable: []string{"/usr", "/lib", "/lib64", "/bin", "/etc"},
		FSWritable: []string{"/tmp"},
	}
	res, err := sb.Run(context.Background(), "echo", "hello")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("exit=%d: %s", res.ExitCode, res.Stdout) // exit=0: hello
}
```

## API

### Sandbox

`Sandbox` is a plain configuration struct; every field is optional and an unset
field means "no restriction" unless noted. sandlock's default syscall blocklist
is always applied. A `Sandbox` carries no runtime state, so it is safe to reuse
and share across goroutines — `Run`, `RunInteractive`, and `DryRun` build a
fresh native policy on each call.

| Group | Fields |
|---|---|
| Filesystem | `FSReadable`, `FSWritable`, `FSDenied`, `Workdir`, `Cwd`, `Chroot`, `FSMount` |
| Network | `NetAllow`, `NetDeny`, `NetAllowBind`, `NetDenyBind`, `PortRemap` |
| HTTP ACL | `HTTPAllow`, `HTTPDeny`, `HTTPPorts`, `HTTPCAFile`, `HTTPKeyFile` |
| Resources | `MaxMemory`, `MaxDisk`, `MaxProcesses`, `MaxCPU`, `MaxOpenFiles`, `CPUCores`, `NumCPUs`, `GPUDevices` |
| Syscalls | `ExtraAllowSyscalls`, `ExtraDenySyscalls` |
| Determinism | `RandomSeed`, `TimeStart`, `NoRandomizeMemory`, `NoHugePages`, `DeterministicDirs` |
| Environment | `CleanEnv`, `Env` |
| Misc | `UID`, `NoCoredump`, `Name` |
| COW branch | `FSStorage`, `OnExit`, `OnError` |
| Dynamic policy | `PolicyFn` |

`NetAllow` entries follow sandlock's rule grammar: bare `host:port` is TCP
(`"api.openai.com:443"`, `"github.com:22,443"`, `":53"`); a target may be a
host, IP, or CIDR (`"10.0.0.0/8:443"`, `"[2606:4700::/32]:443"`); scheme
prefixes opt other protocols in (`"udp://1.1.1.1:53"`, `"udp://*"`,
`"icmp://host"`, `"icmp://*"`). `NetDeny` is the inverse (default-allow
denylist, IP/CIDR targets only, mutually exclusive with `NetAllow`).
`NetAllowBind` entries are comma-separated single ports or inclusive ranges
(`"8080"`, `"3000-3010"`, `"8080,9000-9005"`). `NetDenyBind` is the inverse
(default-allow bind, deny these TCP ports; same syntax, mutually exclusive
with `NetAllowBind`).

### Execution

```go
func (s *Sandbox) Run(ctx context.Context, cmd ...string) (*Result, error)
func (s *Sandbox) RunInteractive(ctx context.Context, cmd ...string) (int, error)
func (s *Sandbox) DryRun(ctx context.Context, cmd ...string) (*DryRunResult, error)
func (s *Sandbox) Spawn(cmd ...string) (*Process, error)
```

- **Run** captures stdout/stderr and waits. A `ctx` deadline kills the process
  and returns a result with `ExitCode == -1`. `ctx` cancellation without a
  deadline does not preempt a running child.
- **RunInteractive** inherits the caller's stdio and returns the exit code.
- **DryRun** runs against a temporary copy-on-write layer, reports the
  filesystem `Changes` it would have made, and discards them. Requires
  `Workdir`.
- **Spawn** starts a process without waiting, returning a `*Process`.

### Dynamic policy callbacks

```go
type PolicyFunc func(event SyscallEvent, ctx *PolicyContext) PolicyDecision

func Allow() PolicyDecision
func Deny() PolicyDecision
func Audit() PolicyDecision
func DenyWith(errnoValue int) PolicyDecision

func (e SyscallEvent) ArgvContains(sub string) bool

func (ctx *PolicyContext) RestrictNetwork(ips []string) error
func (ctx *PolicyContext) GrantNetwork(ips []string) error
func (ctx *PolicyContext) RestrictMaxMemory(bytes uint64)
func (ctx *PolicyContext) RestrictMaxProcesses(n uint32)
func (ctx *PolicyContext) RestrictPIDNetwork(pid uint32, ips []string) error
func (ctx *PolicyContext) DenyPath(path string) error
func (ctx *PolicyContext) AllowPath(path string) error
```

`PolicyFn` receives dynamic syscall events from sandlock's policy-fn worker
thread. Path strings are deliberately absent; use Landlock fields for static
path policy and `DenyPath`/`AllowPath` for the dynamic path-deny hook. `Argv`
is populated for `execve`/`execveat` events.

```go
sb := &sandlock.Sandbox{
    FSReadable: []string{"/usr", "/lib", "/lib64", "/bin", "/etc"},
    PolicyFn: func(event sandlock.SyscallEvent, ctx *sandlock.PolicyContext) sandlock.PolicyDecision {
        if event.Syscall == "execve" && event.ArgvContains("curl") {
            return sandlock.Deny()
        }
        return sandlock.Allow()
    },
}
```

### Process lifecycle

```go
func (p *Process) Pid() int
func (p *Process) Wait() (*Result, error)
func (p *Process) Pause() error           // SIGSTOP to the process group
func (p *Process) Resume() error          // SIGCONT
func (p *Process) Kill() error            // SIGKILL
func (p *Process) Ports() (map[int]int, error) // virtual→real, with PortRemap
func (p *Process) Close() error           // release the handle (kills if running)
```

### Confine the current process

```go
func Confine(s *Sandbox) error
```

Applies the sandbox's Landlock filesystem rules to the **current** process, in
place and irreversibly — no fork, no exec. Only filesystem fields are honored;
configuration that needs a supervisor or a fresh child (seccomp, network,
resource limits, environment, ...) is rejected rather than silently ignored.
This is something the `sandlock` CLI cannot do.

### Platform

```go
func LandlockABIVersion() int        // kernel's Landlock ABI, or -1
func MinLandlockABI() int            // minimum this build requires
func SyscallNr(name string) (int, error)
```

## Status

This SDK covers the static policy surface, dynamic `policy_fn` callbacks, and
in-process `Confine`. The following sandlock features are not yet bound and are
tracked as follow-ups: custom seccomp handlers, pipelines, gather (fan-in), COW
`fork`/`reduce`, and `checkpoint`/restore.

## License

Apache-2.0
