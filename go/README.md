# sandlock Go SDK

Go bindings for [sandlock](https://github.com/multikernel/sandlock), a
lightweight Linux process sandbox built on Landlock, seccomp-bpf, and seccomp
user notification. No root, no Docker, no namespaces.

The bindings bind the sandlock C ABI (`libsandlock_ffi`) via cgo, mirroring the
Python SDK's `Sandbox` surface. **Linux only**; by default the runtime requires
Linux 6.12+ (Landlock ABI v6), but the `AllowDegraded` / `Disable` fields let a
sandbox run on older kernels by degrading or disabling the v6-only protections.

```go
import sandlock "github.com/multikernel/sandlock/go"
```

## Building

cgo links against `libsandlock_ffi`, produced by the Rust workspace. There are
two build modes.

### Released mode (default): installed library via pkg-config

The default build resolves the library and header through `pkg-config`, so the
SDK is usable from another module once the native side is installed. From a
checkout of the sandlock repository:

```bash
sudo make install-go-lib         # installs libsandlock_ffi.so, sandlock.h, sandlock.pc
go get github.com/multikernel/sandlock/go
```

`make install-go-lib` honors `PREFIX` (default `/usr/local`) and `DESTDIR`. For
a non-standard prefix, point pkg-config at it:

```bash
make install-go-lib PREFIX=$HOME/.local
export PKG_CONFIG_PATH=$HOME/.local/lib/pkgconfig
```

The installed `sandlock.pc` bakes an rpath to its `libdir`, so binaries find the
shared library at runtime without `LD_LIBRARY_PATH`.

### In-tree mode: build against this checkout (`-tags sandlock_repo`)

For development without installing, build with `-tags sandlock_repo`, which
points cgo at this checkout's `target/release`:

```bash
cargo build --release -p sandlock-ffi    # writes target/release/libsandlock_ffi.so
cd go && go build -tags sandlock_repo ./...
# run the test suite the same way:
go test -tags sandlock_repo ./...
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
and share across goroutines: `Run` and `RunInteractive` build a fresh native
policy on each call.

| Group | Fields |
|---|---|
| Filesystem | `FSReadable`, `FSWritable`, `FSDenied`, `Workdir`, `Cwd`, `Chroot`, `FSMount`, `FSMountRO`, `Image` |
| Network | `NetAllow`, `NetDeny`, `NetAllowBind`, `NetDenyBind`, `PortRemap` |
| HTTP ACL | `HTTPAllow`, `HTTPDeny`, `HTTPPorts`, `HTTPCAFile`, `HTTPKeyFile` |
| Resources | `MaxMemory`, `MaxDisk`, `MaxProcesses`, `MaxCPU`, `MaxOpenFiles`, `CPUCores`, `NumCPUs`, `GPUDevices` |
| Syscalls | `ExtraAllowSyscalls`, `ExtraDenySyscalls` |
| Determinism | `RandomSeed`, `TimeStart`, `NoRandomizeMemory`, `NoHugePages`, `DeterministicDirs` |
| Environment | `CleanEnv`, `Env` |
| Misc | `UID`, `GID`, `NoCoredump`, `Name` |
| COW branch | `FSStorage`, `OnExit`, `OnError` |
| Dynamic policy | `PolicyFn` |

`NetAllow` entries follow sandlock's rule grammar: bare `host:port` is TCP
(`"api.openai.com:443"`, `"github.com:22,443"`, `":53"`); a target may be a
host, IP, or CIDR (`"10.0.0.0/8:443"`, `"[2606:4700::/32]:443"`); scheme
prefixes opt other protocols in (`"udp://1.1.1.1:53"`, `"udp://*"`,
`"icmp://host"`, `"icmp://*"`). `NetDeny` is the inverse (default-allow
denylist, IP/CIDR targets only); when both are set, denied destinations win.
`NetAllowBind` entries are comma-separated single ports or inclusive ranges
(`"8080"`, `"3000-3010"`, `"8080,9000-9005"`); only `"*"` means any port (a
listed `"0"` authorizes only `bind(0)`). `NetDenyBind` is the inverse
(default-allow bind, deny these TCP ports; same syntax); when both are set,
denied ports win.

### Execution

```go
func (s *Sandbox) Run(ctx context.Context, cmd ...string) (*Result, error)
func (s *Sandbox) RunInteractive(ctx context.Context, cmd ...string) (int, error)
func (s *Sandbox) Spawn(cmd ...string) (*Process, error)
func (s *Sandbox) Popen(stdio Stdio, cmd ...string) (*Process, error)
```

- **Run** captures stdout/stderr and waits. A `ctx` deadline kills the process
  and returns a result with `ExitCode == -1`. `ctx` cancellation without a
  deadline does not preempt a running child.
- **RunInteractive** inherits the caller's stdio and returns the exit code.
- Every `Result` from a sandbox with `Workdir` carries `Changes`, the files and
  directories the run added, modified, or deleted in its COW branch. Each
  `Change` holds the `Before` and `After` entries (kind, mode, size, digest,
  link target); `Kind()` derives A, M, or D from which sides exist, and
  `Renames` pairs moved files by digest. A dry run is a run with
  `OnExit: BranchActionAbort`.
- **Spawn** starts a process without waiting, returning a `*Process`.
- **Popen** is the streaming counterpart of Spawn: each stream set to
  `StdioPiped` is handed back on the `*Process` as an `*os.File`
  (`Stdin`/`Stdout`/`Stderr`) you read/write while the child runs. The zero
  `Stdio` inherits all three (identical to Spawn). Close a piped `Stdin` before
  `Wait` (or let `Wait` close it for you) so a reader child sees EOF; drain a
  piped `Stdout`/`Stderr` while waiting, or `Kill` from another goroutine to
  interrupt a blocked `Wait`. `Wait` returns the main process's `ExitStatus`
  and leaves its background jobs supervised; `Shutdown` ends the session and
  returns a `Result`. A Popen'd process sends piped output to the
  `Stdout`/`Stderr` fields (inherited/null streams go to the parent fd or
  `/dev/null`), so (unlike `Run`) `Result.Stdout`/`Result.Stderr` are always
  empty.

```go
p, _ := sb.Popen(sandlock.Stdio{Stdin: sandlock.StdioPiped, Stdout: sandlock.StdioPiped}, "cat")
defer p.Close()
p.Stdin.Write([]byte("hi\n"))
p.Stdin.Close()                 // EOF so cat exits
out, _ := io.ReadAll(p.Stdout)  // "hi\n"
st, _ := p.Wait()               // main's ExitStatus
res, _ := p.Shutdown()          // ends the session
```

### Container images

```go
func PullImage(reference, cacheDir string) (*Image, error)
```

`PullImage` fetches and unpacks a container image without a Docker daemon or
root, and returns it as plain data. Setting `Sandbox.Image` runs inside it:
the image's rootfs becomes the chroot, read access to `/` inside it is
granted, and its `Env` and `WorkingDir` fill only what `Env` and `Cwd` leave
unset.

Like a container's writable layer, every write lands in a copy-on-write
branch that is discarded when the run ends, so the cached image never
changes. To keep output, mount a host directory with `FSMount` and grant it
in `FSWritable`; setting `Workdir`, or an `OnExit`/`OnError` other than
`BranchActionAbort`, is rejected. The cache belongs to the invoking user, so
it is only as protected as that user's other files.

| Reference | Source |
|---|---|
| `docker://python:3.12`, `docker://ghcr.io/org/img@sha256:...` | registry (Docker Hub by default) |
| `oci:<dir>[:tag]` | OCI image layout directory |
| `oci-archive:<file>[:tag]` | tar of an OCI image layout |
| `docker-daemon:<ref>`, `docker-daemon:sha256:<id>` | local Docker daemon (Docker 25+) |

References use skopeo's transport syntax (containers-transports(5)): the
transport prefix is required, and a tag together with a digest is rejected.
Registry credentials come from `docker login`'s `~/.docker/config.json` (or
`$DOCKER_CONFIG`); credential helpers are not run. Every blob is verified
against its digest, and each image is unpacked once into `cacheDir`, or
`$XDG_CACHE_HOME/sandlock/images` when `cacheDir` is empty. A cached image
named by digest starts without network access.

```go
img, err := sandlock.PullImage("docker://python:3.12-slim", "")
if err != nil {
	log.Fatal(err)
}
sb := &sandlock.Sandbox{Image: img, MaxMemory: "512M"}
res, _ := sb.Run(ctx, "python3", "-c", "print('hello')")
// Or the image's own command: sb.Run(ctx, img.Config.DefaultCmd()...)
```

### Profiles

TOML profiles are parsed by sandlock's own parser, the one the CLI uses, so a
profile means the same thing to both. Named profiles live in
`~/.config/sandlock/profiles` (`ProfileDir()`).

```go
sb, err := sandlock.LoadProfile("build")        // or LoadProfileFile(path), ParseProfile(text)
names, err := sandlock.ListProfiles()
```

A profile field the Go `Sandbox` cannot express (such as `[config].http_inject_ca`)
is an error rather than silently dropped.

### Dynamic policy callbacks

`PolicyFn.VerdictTimeout` sets the held-verdict wait as a `time.Duration`. Zero uses
five seconds, and `sandlock.NoTimeout` disables the timeout. Approval callbacks
must check `ctx.IsCancelled()` between bounded waits and return on shutdown.
See [verdict timeout and shutdown](../docs/policy-fn.md#verdict-timeout-and-shutdown).
Set `PolicyFn.Deferred` instead of `Callback` to receive an `*Approval` for each
held syscall and `Resolve` it later from any goroutine; see
[deferred approval](../docs/policy-fn.md#deferred-approval).

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

`PolicyFn.Callback` receives dynamic syscall events from sandlock's policy-fn worker
thread. Path strings are deliberately absent; use Landlock fields for static
path policy and `DenyPath`/`AllowPath` for the dynamic path-deny hook. `Argv`
is populated for `execve`/`execveat` events.

```go
sb := &sandlock.Sandbox{
	FSReadable: []string{"/usr", "/lib", "/lib64", "/bin", "/etc"},
	PolicyFn: &sandlock.PolicyFn{
		Callback: func(event sandlock.SyscallEvent, ctx *sandlock.PolicyContext) sandlock.PolicyDecision {
			if event.Syscall == "execve" && event.ArgvContains("curl") {
				return sandlock.Deny()
			}
			return sandlock.Allow()
		},
	},
}
```

### Process lifecycle

```go
func (p *Process) Pid() int
func (p *Process) Wait() (*ExitStatus, error)   // main exited; background jobs keep running
func (p *Process) WaitTimeout(d time.Duration) (*ExitStatus, error) // ErrTimeout leaves the session
func (p *Process) Shutdown() (*Result, error)   // kill what is left, reap it, collect the result
func (p *Process) ProcessGroups() ([]int, error) // groups that still have members
func (p *Process) Pause() error           // SIGSTOP to every process group
func (p *Process) Resume() error          // SIGCONT
func (p *Process) Kill() error            // SIGKILL
func (p *Process) Ports() (map[int]int, error) // virtual→real, with PortRemap
func (p *Process) Close() error           // release the handle (ends the session), close piped streams

// Kill, Pause and Resume work while another goroutine is blocked in Wait.

// BranchActionDefer only: after Shutdown, the change set stays on the Process.
func (p *Process) Pending() bool          // exited under Defer and undecided
func (p *Process) UpperDir() string       // new bytes of added/modified files, laid out like Workdir
func (p *Process) Commit() error          // merge into Workdir (blocks up to 5s on a contended workdir)
func (p *Process) Abort() error           // discard

// Popen only: caller-owned pipe ends, non-nil per stream wired StdioPiped.
p.Stdin  // *os.File
p.Stdout // *os.File
p.Stderr // *os.File
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
