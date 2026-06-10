// Package sandlock provides Go bindings for sandlock, a lightweight Linux
// process sandbox built on Landlock, seccomp-bpf, and seccomp user
// notification. It binds the sandlock C ABI (libsandlock_ffi) via cgo and
// mirrors the Python SDK's Sandbox surface.
//
// The bindings are Linux-only. The runtime requires Linux 6.12+ (Landlock
// ABI v6); see the project README for the full kernel feature matrix.
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

// BranchAction is the action taken on a copy-on-write working-directory
// branch when the sandbox exits. The zero value, BranchActionDefault, leaves
// the choice to sandlock's own defaults (commit on success, abort on error).
type BranchAction uint8

const (
	// BranchActionDefault defers to sandlock's built-in default.
	BranchActionDefault BranchAction = iota
	// BranchActionCommit merges the branch's writes into the parent on exit.
	BranchActionCommit
	// BranchActionAbort discards all of the branch's writes on exit.
	BranchActionAbort
	// BranchActionKeep leaves the branch in place for the caller to handle.
	BranchActionKeep
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
	HTTPPorts   []int    // ports to intercept (defaults to 80, plus 443 with a CA)
	HTTPCAFile  string   // PEM CA certificate for HTTPS MITM
	HTTPKeyFile string   // PEM CA private key (required with HTTPCAFile)

	// Resource limits.
	MaxMemory    string   // e.g. "512M"; empty = unlimited
	MaxDisk      string   // disk quota for COW storage, e.g. "1G"
	MaxProcesses uint32   // lifetime fork cap; 0 = sandlock default
	MaxCPU       uint8    // CPU throttle, percent of one core (1-100); 0 = unset
	MaxOpenFiles uint32   // RLIMIT_NOFILE; 0 = inherit system default
	CPUCores     []uint32 // cores to pin to via sched_setaffinity
	NumCPUs      uint32   // synthetic /proc/cpuinfo processor count; 0 = unset
	GPUDevices   []uint32 // GPU device indices to expose; nil = none

	// Syscall filtering (on top of sandlock's default blocklist).
	ExtraAllowSyscalls []string // syscall groups to allow, e.g. "sysv_ipc"
	ExtraDenySyscalls  []string // extra syscall names to block

	// Determinism.
	RandomSeed        *uint64 // seed getrandom() deterministically
	TimeStart         string  // virtual clock start: RFC3339 or unix seconds
	NoRandomizeMemory bool    // disable ASLR
	NoHugePages       bool    // disable transparent huge pages
	DeterministicDirs bool    // sort readdir() entries

	// Environment.
	CleanEnv bool              // start from a minimal environment
	Env      map[string]string // variables to set/override in the child

	// Misc.
	UID        *int // map to this UID inside a user namespace; nil = unset
	GID        *int // map to this GID inside the user namespace; must be set together with UID
	NoCoredump bool // disable core dumps and restrict /proc/pid access

	// Copy-on-write branch handling.
	FSStorage string       // storage directory for COW deltas
	OnExit    BranchAction // branch action on normal exit
	OnError   BranchAction // branch action on error exit

	// Name is the sandbox name and its virtual hostname inside the sandbox.
	// Empty auto-generates "sandbox-{pid}".
	Name string

	// PolicyFn receives dynamic syscall events and may return an allow/deny
	// decision or modify live policy through the supplied context.
	PolicyFn PolicyFunc
}

// Result is the outcome of a captured run.
type Result struct {
	ExitCode int    // process exit code, or -1 if terminated abnormally
	Success  bool   // true when the process exited 0
	Stdout   []byte // captured standard output
	Stderr   []byte // captured standard error
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
