//go:build linux

package sandlock

/*
// Build flags (include path plus link flags) are supplied by build-tagged
// companion files: cgo_pkgconfig.go by default (resolves the installed library
// via pkg-config) and cgo_repo.go under `-tags sandlock_repo` (resolves the
// library from this checkout's target/release without installing).
//
// The C declarations come from the cbindgen-generated header, so the cgo
// prototypes stay in lock-step with crates/sandlock-ffi automatically.
#include <stdlib.h>
#include "sandlock.h"

extern int32_t goPolicyCallback(sandlock_event_t *event, sandlock_ctx_t *ctx, void *user_data);
extern void goPolicyDrop(void *user_data);
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/multikernel/sandlock/go/internal/policy"
)

// hasNUL reports whether s contains an interior NUL byte, which cannot survive
// the conversion to a C string.
func hasNUL(s string) bool { return strings.IndexByte(s, 0) >= 0 }

func cbool(v bool) C.bool { return C.bool(v) }

var (
	nextPolicyCallbackID atomic.Uint64
	policyCallbacks      sync.Map // uint64 -> PolicyFunc
)

func registerPolicyCallback(fn PolicyFunc) unsafe.Pointer {
	id := nextPolicyCallbackID.Add(1)
	userData := C.malloc(C.size_t(unsafe.Sizeof(C.uint64_t(0))))
	if userData == nil {
		panic("sandlock: failed to allocate policy callback handle")
	}
	*(*C.uint64_t)(userData) = C.uint64_t(id)
	policyCallbacks.Store(id, fn)
	return userData
}

func unregisterPolicyCallback(userData unsafe.Pointer) {
	if userData == nil {
		return
	}
	policyCallbacks.Delete(uint64(*(*C.uint64_t)(userData)))
	C.free(userData)
}

func policyCallbackID(userData unsafe.Pointer) uint64 {
	if userData == nil {
		return 0
	}
	return uint64(*(*C.uint64_t)(userData))
}

func policyEventFromC(ev *C.sandlock_event_t) SyscallEvent {
	if ev == nil {
		return SyscallEvent{}
	}
	out := SyscallEvent{
		Syscall:   C.GoString(ev.syscall),
		Category:  SyscallCategory(ev.category),
		PID:       uint32(ev.pid),
		ParentPID: uint32(ev.parent_pid),
		Port:      uint16(ev.port),
		Denied:    bool(ev.denied),
	}
	if ev.host != nil {
		out.Host = C.GoString(ev.host)
	}
	if ev.argv != nil && ev.argc > 0 {
		args := unsafe.Slice((**C.char)(unsafe.Pointer(ev.argv)), int(ev.argc))
		out.Argv = make([]string, 0, len(args))
		for _, arg := range args {
			if arg != nil {
				out.Argv = append(out.Argv, C.GoString(arg))
			}
		}
	}
	return out
}

//export goPolicyCallback
func goPolicyCallback(event *C.sandlock_event_t, ctx *C.sandlock_ctx_t, userData unsafe.Pointer) (ret C.int32_t) {
	ret = C.int32_t(DecisionDeny)
	defer func() {
		if recover() != nil {
			ret = C.int32_t(DecisionDeny)
		}
	}()

	fn, ok := policyCallbacks.Load(policyCallbackID(userData))
	if !ok {
		return C.int32_t(DecisionDeny)
	}
	decision := fn.(PolicyFunc)(policyEventFromC(event), &PolicyContext{
		ptr: unsafe.Pointer(ctx),
	})
	return C.int32_t(decision)
}

//export goPolicyDrop
func goPolicyDrop(userData unsafe.Pointer) {
	unregisterPolicyCallback(userData)
}

// validateStrings rejects any configuration string carrying a NUL byte before
// a builder is allocated. The FFI has no builder-free entry point, so a failure
// partway through building would leak the builder; validating up front keeps
// buildPolicy infallible with respect to string conversion.
func (s *Sandbox) validateStrings() error {
	groups := [][]string{
		s.FSReadable, s.FSWritable, s.FSDenied,
		s.NetAllow, s.NetDeny, s.NetAllowBind, s.NetDenyBind,
		s.HTTPAllow, s.HTTPDeny,
		s.ExtraAllowSyscalls, s.ExtraDenySyscalls,
		{s.Workdir, s.Cwd, s.Chroot, s.FSStorage, s.MaxMemory, s.MaxDisk,
			s.TimeStart, s.HTTPCAFile, s.HTTPKeyFile, s.Name},
	}
	for _, g := range groups {
		for _, v := range g {
			if hasNUL(v) {
				return ErrInvalidString
			}
		}
	}
	for k, v := range s.FSMount {
		if hasNUL(k) || hasNUL(v) {
			return ErrInvalidString
		}
	}
	for k, v := range s.Env {
		if hasNUL(k) || hasNUL(v) {
			return ErrInvalidString
		}
	}
	return nil
}

// buildPolicy translates the Sandbox configuration into a native policy handle.
// The returned pointer must be released with C.sandlock_sandbox_free.
func (s *Sandbox) buildPolicy() (*C.sandlock_sandbox_t, error) {
	if err := s.validateStrings(); err != nil {
		return nil, err
	}

	b := C.sandlock_sandbox_builder_new()

	// str calls a one-string builder setter, freeing the C string afterward.
	str := func(fn func(*C.sandlock_builder_t, *C.char) *C.sandlock_builder_t, val string) {
		c := C.CString(val)
		b = fn(b, c)
		C.free(unsafe.Pointer(c))
	}

	for _, p := range s.FSReadable {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_fs_read(b, c)
		}, p)
	}
	for _, p := range s.FSWritable {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_fs_write(b, c)
		}, p)
	}
	for _, p := range s.FSDenied {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_fs_deny(b, c)
		}, p)
	}
	if s.Workdir != "" {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_workdir(b, c)
		}, s.Workdir)
	}
	if s.Cwd != "" {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_cwd(b, c)
		}, s.Cwd)
	}
	if s.Chroot != "" {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_chroot(b, c)
		}, s.Chroot)
	}
	for vp, hp := range s.FSMount {
		cv, ch := C.CString(vp), C.CString(hp)
		b = C.sandlock_sandbox_builder_fs_mount(b, cv, ch)
		C.free(unsafe.Pointer(cv))
		C.free(unsafe.Pointer(ch))
	}

	// Network.
	for _, spec := range s.NetAllow {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_net_allow(b, c)
		}, spec)
	}
	for _, spec := range s.NetDeny {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_net_deny(b, c)
		}, spec)
	}
	if len(s.NetAllowBind) > 0 {
		ports, err := policy.ParsePorts(s.NetAllowBind)
		if err != nil {
			freeBuilderViaBuild(b)
			return nil, err
		}
		for _, p := range ports {
			b = C.sandlock_sandbox_builder_net_allow_bind_port(b, C.uint16_t(p))
		}
	}
	if len(s.NetDenyBind) > 0 {
		ports, err := policy.ParsePorts(s.NetDenyBind)
		if err != nil {
			freeBuilderViaBuild(b)
			return nil, err
		}
		for _, p := range ports {
			b = C.sandlock_sandbox_builder_net_deny_bind_port(b, C.uint16_t(p))
		}
	}
	if s.PortRemap {
		b = C.sandlock_sandbox_builder_port_remap(b, cbool(true))
	}

	// HTTP ACL.
	for _, r := range s.HTTPAllow {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_http_allow(b, c)
		}, r)
	}
	for _, r := range s.HTTPDeny {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_http_deny(b, c)
		}, r)
	}
	for _, p := range s.HTTPPorts {
		b = C.sandlock_sandbox_builder_http_port(b, C.uint16_t(p))
	}
	if s.HTTPCAFile != "" {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_http_ca(b, c)
		}, s.HTTPCAFile)
	}
	if s.HTTPKeyFile != "" {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_http_key(b, c)
		}, s.HTTPKeyFile)
	}

	// Resource limits.
	if s.MaxMemory != "" {
		v, err := policy.ParseMemory(s.MaxMemory)
		if err != nil {
			freeBuilderViaBuild(b)
			return nil, err
		}
		b = C.sandlock_sandbox_builder_max_memory(b, C.uint64_t(v))
	}
	if s.MaxDisk != "" {
		v, err := policy.ParseMemory(s.MaxDisk)
		if err != nil {
			freeBuilderViaBuild(b)
			return nil, err
		}
		b = C.sandlock_sandbox_builder_max_disk(b, C.uint64_t(v))
	}
	if s.MaxProcesses > 0 {
		b = C.sandlock_sandbox_builder_max_processes(b, C.uint32_t(s.MaxProcesses))
	}
	if s.MaxCPU > 0 {
		b = C.sandlock_sandbox_builder_max_cpu(b, C.uint8_t(s.MaxCPU))
	}
	if s.MaxOpenFiles > 0 {
		b = C.sandlock_sandbox_builder_max_open_files(b, C.uint(s.MaxOpenFiles))
	}
	if s.NumCPUs > 0 {
		b = C.sandlock_sandbox_builder_num_cpus(b, C.uint32_t(s.NumCPUs))
	}
	if len(s.CPUCores) > 0 {
		b = C.sandlock_sandbox_builder_cpu_cores(b, (*C.uint32_t)(unsafe.Pointer(&s.CPUCores[0])), C.uint32_t(len(s.CPUCores)))
	}
	if s.GPUDevices != nil {
		var ptr *C.uint32_t
		if len(s.GPUDevices) > 0 {
			ptr = (*C.uint32_t)(unsafe.Pointer(&s.GPUDevices[0]))
		}
		b = C.sandlock_sandbox_builder_gpu_devices(b, ptr, C.uint32_t(len(s.GPUDevices)))
	}

	// Syscall filtering.
	if len(s.ExtraDenySyscalls) > 0 {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_extra_deny_syscalls(b, c)
		}, strings.Join(s.ExtraDenySyscalls, ","))
	}
	if len(s.ExtraAllowSyscalls) > 0 {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_extra_allow_syscalls(b, c)
		}, strings.Join(s.ExtraAllowSyscalls, ","))
	}

	// Determinism.
	if s.RandomSeed != nil {
		b = C.sandlock_sandbox_builder_random_seed(b, C.uint64_t(*s.RandomSeed))
	}
	if s.TimeStart != "" {
		secs, err := policy.ParseTimeStart(s.TimeStart)
		if err != nil {
			freeBuilderViaBuild(b)
			return nil, err
		}
		b = C.sandlock_sandbox_builder_time_start(b, C.uint64_t(secs))
	}
	if s.NoRandomizeMemory {
		b = C.sandlock_sandbox_builder_no_randomize_memory(b, cbool(true))
	}
	if s.NoHugePages {
		b = C.sandlock_sandbox_builder_no_huge_pages(b, cbool(true))
	}
	if s.DeterministicDirs {
		b = C.sandlock_sandbox_builder_deterministic_dirs(b, cbool(true))
	}

	// Environment.
	if s.CleanEnv {
		b = C.sandlock_sandbox_builder_clean_env(b, cbool(true))
	}
	for k, v := range s.Env {
		ck, cv := C.CString(k), C.CString(v)
		b = C.sandlock_sandbox_builder_env_var(b, ck, cv)
		C.free(unsafe.Pointer(ck))
		C.free(unsafe.Pointer(cv))
	}

	// Misc.
	if s.UID != nil || s.GID != nil {
		if s.UID == nil || s.GID == nil {
			freeBuilderViaBuild(b)
			return nil, fmt.Errorf("UID and GID must both be set (or both unset)")
		}
		b = C.sandlock_sandbox_builder_user(b, C.uint32_t(*s.UID), C.uint32_t(*s.GID))
	}
	if s.NoCoredump {
		b = C.sandlock_sandbox_builder_no_coredump(b, cbool(true))
	}

	// Copy-on-write branch handling.
	if s.FSStorage != "" {
		str(func(b *C.sandlock_builder_t, c *C.char) *C.sandlock_builder_t {
			return C.sandlock_sandbox_builder_fs_storage(b, c)
		}, s.FSStorage)
	}
	if s.OnExit != BranchActionDefault {
		b = C.sandlock_sandbox_builder_on_exit(b, C.uint8_t(s.OnExit-1))
	}
	if s.OnError != BranchActionDefault {
		b = C.sandlock_sandbox_builder_on_error(b, C.uint8_t(s.OnError-1))
	}
	if s.PolicyFn != nil {
		b = C.sandlock_sandbox_builder_policy_fn(
			b,
			(C.sandlock_policy_fn_t)(C.goPolicyCallback),
			registerPolicyCallback(s.PolicyFn),
			(*[0]byte)(C.goPolicyDrop),
		)
	}

	var errCode C.int
	var errMsg *C.char
	policyPtr := C.sandlock_sandbox_build(b, &errCode, &errMsg)
	if policyPtr == nil {
		msg := "sandlock: failed to build sandbox policy"
		if errMsg != nil {
			msg = "sandlock: " + C.GoString(errMsg)
			C.sandlock_string_free(errMsg)
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return policyPtr, nil
}

// freeBuilderViaBuild consumes a builder that will not be used, so it is not
// leaked. The FFI exposes no builder-free entry point; build() is the only
// consumer, so we build and immediately free the resulting policy (or discard
// a build error). Reached only on the rare numeric-parse error paths after the
// builder already exists.
func freeBuilderViaBuild(b *C.sandlock_builder_t) {
	var errCode C.int
	var errMsg *C.char
	p := C.sandlock_sandbox_build(b, &errCode, &errMsg)
	if errMsg != nil {
		C.sandlock_string_free(errMsg)
	}
	if p != nil {
		C.sandlock_sandbox_free(p)
	}
}

// cArgv converts a command into a C argv array. Each element and the array
// itself live in Go memory; the elements are C strings that the caller must
// free with freeArgv. Returns an error if any argument carries a NUL byte.
func cArgv(args []string) ([]*C.char, error) {
	out := make([]*C.char, len(args))
	for i, a := range args {
		if hasNUL(a) {
			for j := 0; j < i; j++ {
				C.free(unsafe.Pointer(out[j]))
			}
			return nil, ErrInvalidString
		}
		out[i] = C.CString(a)
	}
	return out, nil
}

func freeArgv(argv []*C.char) {
	for _, p := range argv {
		C.free(unsafe.Pointer(p))
	}
}

func cStringArray(vals []string) ([]*C.char, error) {
	out := make([]*C.char, len(vals))
	for i, v := range vals {
		if hasNUL(v) {
			for j := 0; j < i; j++ {
				C.free(unsafe.Pointer(out[j]))
			}
			return nil, ErrInvalidString
		}
		out[i] = C.CString(v)
	}
	return out, nil
}

func cStringArrayPtr(vals []*C.char) (**C.char, C.uint32_t) {
	if len(vals) == 0 {
		return nil, 0
	}
	return (**C.char)(unsafe.Pointer(&vals[0])), C.uint32_t(len(vals))
}

func (c *PolicyContext) cptr() *C.sandlock_ctx_t {
	if c == nil || c.ptr == nil {
		return nil
	}
	return (*C.sandlock_ctx_t)(c.ptr)
}

// RestrictNetwork permanently restricts the live network policy to ips.
func (c *PolicyContext) RestrictNetwork(ips []string) error {
	cips, err := cStringArray(ips)
	if err != nil {
		return err
	}
	defer freeArgv(cips)
	ptr, n := cStringArrayPtr(cips)
	C.sandlock_ctx_restrict_network(c.cptr(), ptr, n)
	return nil
}

// GrantNetwork grants ips within the sandbox's immutable network ceiling.
func (c *PolicyContext) GrantNetwork(ips []string) error {
	cips, err := cStringArray(ips)
	if err != nil {
		return err
	}
	defer freeArgv(cips)
	ptr, n := cStringArrayPtr(cips)
	C.sandlock_ctx_grant_network(c.cptr(), ptr, n)
	return nil
}

// RestrictMaxMemory permanently restricts the live max-memory policy.
func (c *PolicyContext) RestrictMaxMemory(bytes uint64) {
	C.sandlock_ctx_restrict_max_memory(c.cptr(), C.uint64_t(bytes))
}

// RestrictMaxProcesses permanently restricts the live max-processes policy.
func (c *PolicyContext) RestrictMaxProcesses(n uint32) {
	C.sandlock_ctx_restrict_max_processes(c.cptr(), C.uint32_t(n))
}

// RestrictPIDNetwork restricts network access for a specific process.
func (c *PolicyContext) RestrictPIDNetwork(pid uint32, ips []string) error {
	cips, err := cStringArray(ips)
	if err != nil {
		return err
	}
	defer freeArgv(cips)
	ptr, n := cStringArrayPtr(cips)
	C.sandlock_ctx_restrict_pid_network(c.cptr(), C.uint32_t(pid), ptr, n)
	return nil
}

// DenyPath dynamically denies access to path for mediated openat checks.
func (c *PolicyContext) DenyPath(path string) error {
	if hasNUL(path) {
		return ErrInvalidString
	}
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	C.sandlock_ctx_deny_path(c.cptr(), cp)
	return nil
}

// AllowPath removes a dynamic path denial previously added by DenyPath.
func (c *PolicyContext) AllowPath(path string) error {
	if hasNUL(path) {
		return ErrInvalidString
	}
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	C.sandlock_ctx_allow_path(c.cptr(), cp)
	return nil
}

// argvPtr returns the pointer/count pair for an argv slice.
func argvPtr(argv []*C.char) (**C.char, C.uint) {
	if len(argv) == 0 {
		return nil, 0
	}
	return (**C.char)(unsafe.Pointer(&argv[0])), C.uint(len(argv))
}

// cName converts the sandbox name to a C string, returning nil for the empty
// name (which tells the FFI to auto-generate one).
func (s *Sandbox) cName() *C.char {
	if s.Name == "" {
		return nil
	}
	return C.CString(s.Name)
}

func freeName(c *C.char) {
	if c != nil {
		C.free(unsafe.Pointer(c))
	}
}

// timeoutMs derives an FFI wait timeout from a context. A zero return means
// "no timeout"; a context with a deadline maps to the remaining milliseconds
// (at least 1, so an already-expired deadline does not become "no timeout").
func timeoutMs(ctx context.Context) C.uint64_t {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	d := time.Until(deadline)
	if d <= 0 {
		return 1
	}
	ms := d.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return C.uint64_t(ms)
}

func readResult(r *C.sandlock_result_t) *Result {
	res := &Result{
		ExitCode: int(C.sandlock_result_exit_code(r)),
		Success:  bool(C.sandlock_result_success(r)),
	}
	res.Stdout = readBytes(r, true)
	res.Stderr = readBytes(r, false)
	return res
}

func readBytes(r *C.sandlock_result_t, stdout bool) []byte {
	var n C.uintptr_t
	var p *C.uint8_t
	if stdout {
		p = C.sandlock_result_stdout_bytes(r, &n)
	} else {
		p = C.sandlock_result_stderr_bytes(r, &n)
	}
	if p == nil || n == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n))
}

// Run executes cmd in the sandbox, capturing stdout and stderr, and waits for
// it to finish. If ctx carries a deadline, the process is killed and a result
// with ExitCode -1 is returned once it elapses. ctx cancellation without a
// deadline does not preempt an already-running child.
func (s *Sandbox) Run(ctx context.Context, cmd ...string) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(cmd) == 0 {
		return nil, fmt.Errorf("sandlock: empty command")
	}
	policyPtr, err := s.buildPolicy()
	if err != nil {
		return nil, err
	}
	defer C.sandlock_sandbox_free(policyPtr)

	argv, err := cArgv(cmd)
	if err != nil {
		return nil, err
	}
	defer freeArgv(argv)
	ap, ac := argvPtr(argv)
	name := s.cName()
	defer freeName(name)

	h := C.sandlock_create_for_run(policyPtr, name, ap, ac)
	if h == nil {
		return nil, fmt.Errorf("sandlock: failed to create sandbox")
	}
	if C.sandlock_start(h) != 0 {
		C.sandlock_handle_free(h)
		return nil, fmt.Errorf("sandlock: failed to start sandbox")
	}
	r := C.sandlock_handle_wait_timeout(h, timeoutMs(ctx))
	C.sandlock_handle_free(h)
	if r == nil {
		return nil, fmt.Errorf("sandlock: wait failed")
	}
	res := readResult(r)
	C.sandlock_result_free(r)
	return res, nil
}

// RunInteractive executes cmd with the calling process's stdio inherited (no
// capture) and returns the exit code. The context is honored only as a
// pre-run cancellation check; interactive runs are not interrupted by a
// deadline.
func (s *Sandbox) RunInteractive(ctx context.Context, cmd ...string) (int, error) {
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	if len(cmd) == 0 {
		return -1, fmt.Errorf("sandlock: empty command")
	}
	policyPtr, err := s.buildPolicy()
	if err != nil {
		return -1, err
	}
	defer C.sandlock_sandbox_free(policyPtr)

	argv, err := cArgv(cmd)
	if err != nil {
		return -1, err
	}
	defer freeArgv(argv)
	ap, ac := argvPtr(argv)
	name := s.cName()
	defer freeName(name)

	code := int(C.sandlock_run_interactive(policyPtr, name, ap, ac))
	return code, nil
}

// DryRun executes cmd against a temporary copy-on-write layer, collects the
// filesystem changes it would have made, then discards them. It requires
// Workdir to be set.
func (s *Sandbox) DryRun(ctx context.Context, cmd ...string) (*DryRunResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(cmd) == 0 {
		return nil, fmt.Errorf("sandlock: empty command")
	}
	policyPtr, err := s.buildPolicy()
	if err != nil {
		return nil, err
	}
	defer C.sandlock_sandbox_free(policyPtr)

	argv, err := cArgv(cmd)
	if err != nil {
		return nil, err
	}
	defer freeArgv(argv)
	ap, ac := argvPtr(argv)
	name := s.cName()
	defer freeName(name)

	r := C.sandlock_dry_run(policyPtr, name, ap, ac)
	if r == nil {
		return nil, fmt.Errorf("sandlock: dry run failed (Workdir is required; check that readable paths exist)")
	}
	defer C.sandlock_dry_run_result_free(r)

	out := &DryRunResult{Result: Result{
		ExitCode: int(C.sandlock_dry_run_result_exit_code(r)),
		Success:  bool(C.sandlock_dry_run_result_success(r)),
	}}
	var n C.uintptr_t
	if p := C.sandlock_dry_run_result_stdout_bytes(r, &n); p != nil && n > 0 {
		out.Stdout = C.GoBytes(unsafe.Pointer(p), C.int(n))
	}
	if p := C.sandlock_dry_run_result_stderr_bytes(r, &n); p != nil && n > 0 {
		out.Stderr = C.GoBytes(unsafe.Pointer(p), C.int(n))
	}
	count := int(C.sandlock_dry_run_result_changes_len(r))
	for i := 0; i < count; i++ {
		kind := byte(C.sandlock_dry_run_result_change_kind(r, C.uintptr_t(i)))
		var path string
		if pc := C.sandlock_dry_run_result_change_path(r, C.uintptr_t(i)); pc != nil {
			path = C.GoString(pc)
			C.sandlock_string_free(pc)
		}
		out.Changes = append(out.Changes, Change{Kind: ChangeKind(kind), Path: path})
	}
	return out, nil
}

// Confine applies the Sandbox's Landlock filesystem rules to the current
// process, in place and irreversibly. Only filesystem fields are honored;
// configuration that requires a supervisor or a fresh child (seccomp,
// network, resource limits, environment, etc.) is rejected by the core rather
// than silently ignored.
func Confine(s *Sandbox) error {
	policyPtr, err := s.buildPolicy()
	if err != nil {
		return err
	}
	defer C.sandlock_sandbox_free(policyPtr)
	if C.sandlock_confine(policyPtr) != 0 {
		return fmt.Errorf("sandlock: confine failed")
	}
	return nil
}

// LandlockABIVersion returns the Landlock ABI version supported by the running
// kernel, or -1 if Landlock is unavailable.
func LandlockABIVersion() int { return int(C.sandlock_landlock_abi_version()) }

// MinLandlockABI returns the minimum Landlock ABI version this build requires.
func MinLandlockABI() int { return int(C.sandlock_min_landlock_abi()) }

// SyscallNr resolves a syscall name (e.g. "openat") to its kernel syscall
// number for the host architecture. It returns an error for names sandlock
// cannot resolve (syscalls outside the set it filters or supervises).
func SyscallNr(name string) (int, error) {
	if hasNUL(name) {
		return -1, ErrInvalidString
	}
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	nr := int64(C.sandlock_syscall_nr(c))
	if nr < 0 {
		return -1, fmt.Errorf("sandlock: unknown syscall %q", name)
	}
	return int(nr), nil
}

// Process is a live sandboxed process started by Spawn. It supports PID
// inspection, pause/resume/kill via the process group, and Wait. A Process
// holds at most one running command; create separate Spawns for concurrency.
//
// The underlying FFI handle is not safe for concurrent access, so all handle
// operations are serialized. Pause/Resume/Kill act on the OS process group by
// PID and touch no handle state, so they remain usable while Wait blocks on
// the handle — that is how Kill interrupts a blocked Wait. Ports, by contrast,
// reads the handle and is reported as empty while a Wait is in flight.
type Process struct {
	mu      sync.Mutex
	h       *C.sandlock_handle_t
	pid     int
	waiting bool // a Wait owns the handle; other handle ops must defer to it
}

// Spawn forks the sandboxed child, installs the policy, and releases it to
// exec cmd without waiting. Use the returned Process to manage its lifecycle.
func (s *Sandbox) Spawn(cmd ...string) (*Process, error) {
	if len(cmd) == 0 {
		return nil, fmt.Errorf("sandlock: empty command")
	}
	policyPtr, err := s.buildPolicy()
	if err != nil {
		return nil, err
	}
	defer C.sandlock_sandbox_free(policyPtr)

	argv, err := cArgv(cmd)
	if err != nil {
		return nil, err
	}
	defer freeArgv(argv)
	ap, ac := argvPtr(argv)
	name := s.cName()
	defer freeName(name)

	h := C.sandlock_create(policyPtr, name, ap, ac)
	if h == nil {
		return nil, fmt.Errorf("sandlock: failed to create sandbox")
	}
	if C.sandlock_start(h) != 0 {
		C.sandlock_handle_free(h)
		return nil, fmt.Errorf("sandlock: failed to start sandbox")
	}
	p := &Process{h: h, pid: int(C.sandlock_handle_pid(h))}
	// Last-resort cleanup if the caller drops the Process without Wait/Close:
	// kill the child and release the handle so neither is leaked. Wait and
	// Close clear this once they have done the cleanup themselves.
	runtime.SetFinalizer(p, (*Process).finalize)
	return p, nil
}

// finalize is the SetFinalizer cleanup for a Process abandoned without
// Wait/Close. It can only run once the Process is unreachable, which implies
// no Wait is in flight (a blocked Wait keeps the Process reachable), so the
// handle is not concurrently borrowed and is safe to free here.
func (p *Process) finalize() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h == nil {
		return
	}
	if p.pid > 0 {
		_ = syscall.Kill(-p.pid, syscall.SIGKILL)
	}
	C.sandlock_handle_free(p.h)
	p.h = nil
}

// Pid returns the child process ID, or 0 if it is not available.
func (p *Process) Pid() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pid
}

// Wait blocks until the process exits, returns its captured Result, and
// releases the handle. After Wait the Process is no longer running.
//
// The blocking native wait runs without holding the mutex so that Kill (and
// Pause/Resume), which signal the process group by PID, can run concurrently
// and interrupt it. The waiting flag reserves exclusive use of the handle for
// the duration, so no other handle operation aliases it.
func (p *Process) Wait() (*Result, error) {
	p.mu.Lock()
	if p.h == nil || p.waiting {
		p.mu.Unlock()
		return nil, ErrNotRunning
	}
	h := p.h
	p.waiting = true
	p.mu.Unlock()

	r := C.sandlock_handle_wait(h)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.waiting = false
	C.sandlock_handle_free(h)
	p.h = nil
	runtime.SetFinalizer(p, nil)
	if r == nil {
		return nil, fmt.Errorf("sandlock: wait failed")
	}
	res := readResult(r)
	C.sandlock_result_free(r)
	return res, nil
}

func (p *Process) signal(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h == nil || p.pid <= 0 {
		return ErrNotRunning
	}
	// The sandbox child leads its own process group; signal the whole group.
	return syscall.Kill(-p.pid, sig)
}

// Pause sends SIGSTOP to the sandbox process group.
func (p *Process) Pause() error { return p.signal(syscall.SIGSTOP) }

// Resume sends SIGCONT to the sandbox process group.
func (p *Process) Resume() error { return p.signal(syscall.SIGCONT) }

// Kill sends SIGKILL to the sandbox process group.
func (p *Process) Kill() error {
	err := p.signal(syscall.SIGKILL)
	if err == syscall.ESRCH {
		return nil
	}
	return err
}

// Ports returns the current virtual-to-real TCP port mappings while the
// process is running. It is non-empty only when PortRemap is enabled and at
// least one port has been remapped.
func (p *Process) Ports() (map[int]int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// While a Wait holds the handle, reading port mappings would alias it;
	// report empty rather than touch the handle concurrently.
	if p.h == nil || p.waiting {
		return map[int]int{}, nil
	}
	c := C.sandlock_handle_port_mappings(p.h)
	if c == nil {
		return map[int]int{}, nil
	}
	raw := C.GoString(c)
	C.sandlock_string_free(c)

	var m map[string]int
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("sandlock: parsing port mappings: %w", err)
	}
	out := make(map[int]int, len(m))
	for k, v := range m {
		var vp int
		if _, err := fmt.Sscanf(k, "%d", &vp); err == nil {
			out[vp] = v
		}
	}
	return out, nil
}

// Close releases the process handle, killing the process if it is still
// running. It is safe to call multiple times.
func (p *Process) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h == nil {
		return nil
	}
	if p.waiting {
		// A Wait owns the handle and will free it; just kill the process
		// group by PID to unblock that Wait, without touching the handle.
		if p.pid > 0 {
			_ = syscall.Kill(-p.pid, syscall.SIGKILL)
		}
		return nil
	}
	C.sandlock_handle_free(p.h)
	p.h = nil
	runtime.SetFinalizer(p, nil)
	return nil
}
