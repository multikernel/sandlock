// Package sandlock provides Go bindings for sandlock, a lightweight Linux
// process sandbox built on Landlock, seccomp-bpf, and seccomp user
// notification. It binds the sandlock C ABI (libsandlock_ffi) via cgo and
// mirrors the Python SDK's Sandbox surface.
//
// The bindings are Linux-only. By default the runtime requires Linux 6.12+
// (Landlock ABI v6); use the AllowDegraded or Disable fields to run on older
// kernels by degrading or disabling the v6-only protections. See the project
// README for the full kernel feature matrix.
//
// # Building
//
// cgo links against libsandlock_ffi, which is produced by the Rust workspace:
//
//	cargo build --release        # writes target/release/libsandlock_ffi.so
//	cd go && go test ./...
//
// The default cgo link flags resolve the library relative to this package
// (../target/release). Build from a checkout of the sandlock repository, or
// adjust the link flags for an installed library.
//
// # Quick start
//
//	sb := &sandlock.Sandbox{
//	    FSReadable: []string{"/usr", "/lib", "/lib64", "/bin", "/etc"},
//	    FSWritable: []string{"/tmp"},
//	}
//	res, err := sb.Run(context.Background(), "echo", "hello")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("%d: %s", res.ExitCode, res.Stdout)
package sandlock

import (
	"strings"
	"unsafe"
)

// Ptr returns a pointer to v. The Sandbox fields whose "unset" state is not
// expressible in the value itself are pointers, and Go has no address-of for
// a literal, so this is the spelling for setting one:
//
//	sb := &sandlock.Sandbox{MaxCPU: sandlock.Ptr[uint8](50)}
func Ptr[T any](v T) *T { return &v }

// BranchAction is the action taken on a copy-on-write working-directory
// branch when the sandbox exits. The values are the stable ABI discriminants
// shared with the C/Rust core, and are passed through unchanged: a value
// outside this set is rejected by the core, naming the number the caller
// wrote. The Sandbox fields are pointers, so "leave it to sandlock's own
// default" is nil rather than a sentinel member of this type.
type BranchAction uint8

const (
	// BranchActionCommit merges the branch's writes into the parent on exit.
	BranchActionCommit BranchAction = 0
	// BranchActionAbort discards all of the branch's writes on exit.
	BranchActionAbort BranchAction = 1
	// BranchActionKeep leaves the branch in place for the caller to handle.
	BranchActionKeep BranchAction = 2
)

// SyscallCategory is the high-level category of an intercepted syscall event.
type SyscallCategory uint8

const (
	// CategoryFile covers filesystem operations such as openat and unlinkat.
	CategoryFile SyscallCategory = iota
	// CategoryNetwork covers network operations such as connect and bind.
	CategoryNetwork
	// CategoryProcess covers process lifecycle operations such as execve.
	CategoryProcess
	// CategoryMemory covers memory-management operations such as mmap.
	CategoryMemory
)

// String returns the category name used by the Python SDK.
func (c SyscallCategory) String() string {
	switch c {
	case CategoryFile:
		return "file"
	case CategoryNetwork:
		return "network"
	case CategoryProcess:
		return "process"
	case CategoryMemory:
		return "memory"
	default:
		return "unknown"
	}
}

// SyscallEvent is a policy_fn event delivered by the sandbox supervisor.
//
// Path strings are intentionally absent. Path-based access control belongs in
// Landlock rules (FSReadable, FSWritable, FSDenied). Argv is populated only for
// execve/execveat events, where sandlock freezes sibling tasks before exposing
// it to the policy callback.
type SyscallEvent struct {
	Syscall   string
	Category  SyscallCategory
	PID       uint32
	ParentPID uint32
	Host      string
	Port      uint16
	Denied    bool
	Argv      []string
}

// ArgvContains reports whether any argv element contains sub.
func (e SyscallEvent) ArgvContains(sub string) bool {
	for _, arg := range e.Argv {
		if strings.Contains(arg, sub) {
			return true
		}
	}
	return false
}

// PolicyDecision is the result returned by a PolicyFunc.
type PolicyDecision int32

const (
	// DecisionAllow allows the syscall.
	DecisionAllow PolicyDecision = 0
	// DecisionDeny denies the syscall with EPERM.
	DecisionDeny PolicyDecision = -1
	// DecisionAudit allows the syscall and flags it for audit.
	DecisionAudit PolicyDecision = -2
)

// Allow returns a decision that allows the syscall.
func Allow() PolicyDecision { return DecisionAllow }

// Deny returns a decision that denies the syscall with EPERM.
func Deny() PolicyDecision { return DecisionDeny }

// Audit returns a decision that allows the syscall and flags it for audit.
func Audit() PolicyDecision { return DecisionAudit }

// DenyWith returns a decision that denies the syscall with errnoValue.
func DenyWith(errnoValue int) PolicyDecision {
	if errnoValue <= 0 {
		return DecisionDeny
	}
	return PolicyDecision(errnoValue)
}

// PolicyContext lets a PolicyFunc adjust selected live policy state.
//
// A PolicyContext is valid only during the PolicyFunc call that received it.
// Do not retain it after the callback returns.
type PolicyContext struct {
	ptr unsafe.Pointer
}

// PolicyFunc is a dynamic policy callback invoked from sandlock's policy-fn
// worker thread. Callbacks may be invoked concurrently with other sandbox
// activity, so captured state should be synchronized when mutated.
type PolicyFunc func(event SyscallEvent, ctx *PolicyContext) PolicyDecision

// Protection identifies a single Landlock protection whose enforcement
// posture can be opted out of via the Sandbox AllowDegraded / Disable fields.
// The values match the sandlock C ABI discriminants.
type Protection uint32

const (
	ProtectionFSRefer                 Protection = 0 // file reparenting (Landlock ABI v2)
	ProtectionFSTruncate              Protection = 1 // truncate(2) (ABI v3)
	ProtectionNetTCP                  Protection = 2 // TCP bind/connect (ABI v4)
	ProtectionFSIoctlDev              Protection = 3 // device ioctl(2) (ABI v5)
	ProtectionSignalScope             Protection = 4 // signal scoping (ABI v6)
	ProtectionAbstractUnixSocketScope Protection = 5 // abstract UNIX socket scoping (ABI v6)
)

// RunAs is the identity the sandboxed process runs as, applied through a
// single-entry user-namespace map. Both ids are always present because that is
// what the core models: an unprivileged user namespace can map exactly one uid
// and one gid, so "a uid without a gid" is not a state it can represent, and
// this type does not let a caller spell it. The ids are uint32 for the same
// reason: that is the width the kernel and the C ABI carry, so a value outside
// it cannot be silently truncated on the way down.
type RunAs struct {
	UID uint32
	GID uint32
}

// Sandbox holds the policy configuration for confining a process. Every field
// is optional; an unset field means "no restriction" unless documented
// otherwise. sandlock's default syscall blocklist is always applied.
//
// A Sandbox value carries no runtime state: Run, RunInteractive, and DryRun
// build a fresh native policy on each call, so a single Sandbox may be reused
// and shared across goroutines. Use Spawn for explicit process lifecycle
// control, which returns an independent *Process handle.
type Sandbox struct {
	// Filesystem (Landlock).
	FSReadable []string // paths the sandbox may read (and execute)
	FSWritable []string // paths the sandbox may write
	FSDenied   []string // paths explicitly denied

	Workdir string // copy-on-write root; enables COW protection of this tree
	Cwd     string // child working directory (chdir target)
	Chroot  string // path to chroot into before applying confinement

	// FSMount maps virtual paths inside the chroot to host directories,
	// like a bind mount without kernel mounts or root.
	FSMount map[string]string

	// Protection opt-out (Landlock per-protection posture).
	//
	// By default every protection is enforced strictly, which requires the
	// host kernel to support it (the highest floor is ABI v6); on an older
	// kernel a strict protection it cannot satisfy makes the build fail.
	// AllowDegraded marks protections to enforce where the host supports them
	// and silently skip otherwise; Disable turns them off entirely. Together
	// they let a sandbox run on a kernel below the default v6 floor.
	//
	// A protection listed in both fields is disabled: Disable is applied
	// last and takes precedence.
	AllowDegraded []Protection
	Disable       []Protection

	// Network.
	//
	// NetAllow entries are outbound endpoint rules. The bare form is TCP
	// ("api.openai.com:443", "github.com:22,443", ":53"); a target may be a
	// host, IP, or CIDR ("10.0.0.0/8:443", "[2606:4700::/32]:443"), and
	// scheme prefixes opt other protocols in ("tcp://", "udp://host:port",
	// "udp://*", "icmp://host", "icmp://*"). Empty denies all outbound.
	NetAllow []string
	// NetDeny is the inverse of NetAllow: default-allow networking, block
	// these targets. Same grammar as NetAllow except targets must be a
	// literal IP/CIDR or "*" (no hostnames; use HTTPDeny for domains).
	// Mutually exclusive with NetAllow.
	NetDeny []string
	// NetAllowBind lists TCP ports the sandbox may bind/listen on
	// (default-deny). Each entry is a comma-separated list of single ports
	// or inclusive "lo-hi" ranges ("8080", "3000-3010", "8080,9000-9005").
	// The "*" wildcard allows binding any port and cannot be mixed with
	// port entries.
	// Mutually exclusive with NetDenyBind.
	NetAllowBind []string
	// NetDenyBind is the inverse of NetAllowBind: default-allow binding,
	// deny these TCP ports (same port syntax). Mutually exclusive with
	// NetAllowBind.
	NetDenyBind []string
	PortRemap   bool // transparent per-sandbox TCP port virtualization

	// HTTP ACL (method + host + path rules via a transparent proxy).
	HTTPAllow   []string // allow rules, "METHOD host/path"
	HTTPDeny    []string // deny rules, checked before allow rules
	HTTPPorts   []uint16 // ports to intercept (defaults to 80, plus 443 with a CA)
	HTTPCAFile  string   // PEM CA certificate for HTTPS MITM
	HTTPKeyFile string   // PEM CA private key (required with HTTPCAFile)

	// Resource limits.
	//
	// MaxMemory and MaxDisk are byte-size strings parsed by sandlock itself,
	// with the grammar it accepts everywhere else: a decimal integer and an
	// optional K/M/G suffix (case-insensitive), a bare number being a count of
	// bytes. Fractions and a T suffix are not part of it; a value outside the
	// grammar is reported by the core when the sandbox is built.
	//
	// The numeric caps are pointers because zero is a value the core has an
	// opinion about (it rejects a cap of zero processes, CPU percent,
	// descriptors, or processors), so it must not double as "unset". Use Ptr
	// to set one.
	// An empty MaxMemory is the only spelling of "unlimited": "0" is refused,
	// because zero is what the supervisor already carries for "no ceiling",
	// and setting the field at all is what installs the memory handler. An
	// empty CPUCores is refused for the same reason in reverse: it is an
	// affinity mask with no bits, not "every core", which is what leaving the
	// field nil already means. MaxDisk is the exception: zero is its
	// documented spelling of "unlimited".
	MaxMemory    string   // e.g. "512M"; empty = unlimited, "0" is refused
	MaxDisk      string   // disk quota for COW storage, e.g. "1G"; "0" = unlimited
	MaxProcesses *uint32  // peak concurrent process cap; nil = sandlock default
	MaxCPU       *uint8   // CPU throttle, percent of one core (1-100); nil = unset
	MaxOpenFiles *uint32  // RLIMIT_NOFILE soft+hard in the child, clamped to sandlock's own limits; nil = inherit
	CPUCores     []uint32 // cores to pin to via sched_setaffinity; nil = unset, empty is refused
	NumCPUs      *uint32  // synthetic /proc/cpuinfo processor count; nil = unset
	// GPUDevices lists the GPU device indices to expose. nil means none; an
	// empty (non-nil) slice means every GPU present on the host.
	GPUDevices []uint32

	// Syscall filtering (on top of sandlock's default blocklist).
	ExtraAllowSyscalls []string // syscall groups to allow, e.g. "sysv_ipc"
	ExtraDenySyscalls  []string // extra syscall names to block

	// Determinism.
	RandomSeed *uint64 // seed getrandom() deterministically
	// TimeStart is the virtual clock start as an RFC3339 timestamp
	// ("2026-01-01T00:00:00Z"), parsed by sandlock itself with the same
	// grammar as a profile's [determinism].time_start. Empty = unset.
	TimeStart         string
	NoRandomizeMemory bool // disable ASLR
	NoHugePages       bool // disable transparent huge pages
	DeterministicDirs bool // sort readdir() entries

	// Environment.
	CleanEnv bool              // start from a minimal environment
	Env      map[string]string // variables to set/override in the child

	// Misc.
	User       *RunAs // identity inside a user namespace; nil = unset
	NoCoredump bool   // disable core dumps and restrict /proc/pid access

	// Copy-on-write branch handling.
	FSStorage string        // storage directory for COW deltas
	OnExit    *BranchAction // branch action on normal exit; nil = sandlock's default
	OnError   *BranchAction // branch action on error exit; nil = sandlock's default

	// Name is the sandbox name and its virtual hostname inside the sandbox.
	// nil auto-generates "sandbox-{pid}"; any other value is passed to
	// sandlock verbatim, including the empty string, which it rejects.
	Name *string

	// PolicyFn receives dynamic syscall events and may return an allow/deny
	// decision or modify live policy through the supplied context.
	PolicyFn PolicyFunc
}

// ExitReason is why a sandboxed process terminated. It mirrors the C
// sandlock_exit_reason enum. Linux bottoms both a timeout and an OOM kill out in
// SIGKILL, so there is no distinct OOM reason: a timeout sandlock enforced is
// ReasonTimeout, any other kill is ReasonKilled.
type ExitReason uint32

const (
	// ReasonExited: exited normally with a code (Result.ExitCode).
	ReasonExited ExitReason = 0
	// ReasonSignaled: terminated by a signal (Result.Signal).
	ReasonSignaled ExitReason = 1
	// ReasonKilled: killed with no recoverable signal number.
	ReasonKilled ExitReason = 2
	// ReasonTimeout: killed by sandlock because it exceeded its timeout.
	ReasonTimeout ExitReason = 3
)

// Result is the outcome of a captured run.
type Result struct {
	ExitCode int        // process exit code, or -1 if terminated abnormally
	Reason   ExitReason // why the process terminated (exit / signal / kill / timeout)
	Signal   int        // signal number for a ReasonSignaled result, else -1
	Success  bool       // true when the process exited 0
	Stdout   []byte     // captured standard output
	Stderr   []byte     // captured standard error
}

// StdioMode selects how one of a Popen'd process's standard streams is wired.
// The values are the stable ABI discriminants shared with the C/Rust core.
type StdioMode uint32

const (
	// StdioInherit shares the parent's fd (the child writes to the same
	// terminal/file). It is the zero value, so an unset stream inherits.
	StdioInherit StdioMode = 0
	// StdioPiped connects the stream to a pipe; Popen hands the caller the
	// owning end as an *os.File on the returned Process.
	StdioPiped StdioMode = 1
	// StdioNull connects the stream to /dev/null.
	StdioNull StdioMode = 2
)

// Stdio selects the wiring of a Popen'd process's three standard streams. The
// zero value wires all three as StdioInherit, matching Spawn.
type Stdio struct {
	Stdin  StdioMode
	Stdout StdioMode
	Stderr StdioMode
}

// ChangeKind classifies a filesystem change observed during a dry run.
type ChangeKind byte

const (
	ChangeAdded    ChangeKind = 'A'
	ChangeModified ChangeKind = 'M'
	ChangeDeleted  ChangeKind = 'D'
)

// Change is a single filesystem change detected by DryRun.
type Change struct {
	Kind ChangeKind // 'A' added, 'M' modified, 'D' deleted
	Path string     // path relative to the working directory
}

// DryRunResult is the outcome of a dry run: a normal Result plus the list of
// filesystem changes the command would have made, all of which are discarded.
type DryRunResult struct {
	Result
	Changes []Change
}
