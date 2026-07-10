//go:build linux

package sandlock_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	sandlock "github.com/multikernel/sandlock/go"
)

// rootfs is a minimal read-only set covering a typical dynamic binary,
// filtered to paths that actually exist on the host. sandlock errors on a
// readable path that does not exist, and the set differs across architectures
// (for example /lib64 is absent on arm64), so this is computed at startup.
var rootfs = existingPaths(
	"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev",
)

func existingPaths(candidates ...string) []string {
	var out []string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// requireLandlock skips a test when the running kernel cannot satisfy
// sandlock's minimum Landlock ABI, so the suite stays green on older CI images.
func requireLandlock(t *testing.T) {
	t.Helper()
	have, want := sandlock.LandlockABIVersion(), sandlock.MinLandlockABI()
	if have < want {
		t.Skipf("kernel Landlock ABI v%d < required v%d", have, want)
	}
}

func TestLandlockABI(t *testing.T) {
	t.Logf("Landlock ABI: have v%d, require v%d", sandlock.LandlockABIVersion(), sandlock.MinLandlockABI())
	if sandlock.MinLandlockABI() < 1 {
		t.Fatalf("MinLandlockABI() = %d, want >= 1", sandlock.MinLandlockABI())
	}
}

func TestRunEcho(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	res, err := sb.Run(context.Background(), "echo", "hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Success || res.ExitCode != 0 {
		t.Fatalf("expected success, got exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := string(res.Stdout); got != "hello\n" {
		t.Fatalf("stdout = %q, want %q", got, "hello\n")
	}
}

func TestRunExitCode(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	res, err := sb.Run(context.Background(), "sh", "-c", "exit 3")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Success {
		t.Fatalf("expected failure")
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", res.ExitCode)
	}
}

// TestExitReason pins the #131 terminating-reason surface across the four
// ExitStatus variants. SIGKILL folds into ReasonKilled in core (no signal
// number), distinct from a catchable signal (ReasonSignaled + number); a context
// deadline enforced by sandlock is ReasonTimeout.
func TestExitReason(t *testing.T) {
	requireLandlock(t)

	t.Run("exited", func(t *testing.T) {
		sb := &sandlock.Sandbox{FSReadable: rootfs}
		res, err := sb.Run(context.Background(), "sh", "-c", "exit 7")
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Reason != sandlock.ReasonExited || res.ExitCode != 7 || res.Signal != -1 {
			t.Fatalf("got reason=%d exit=%d signal=%d, want Exited/7/-1", res.Reason, res.ExitCode, res.Signal)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		sb := &sandlock.Sandbox{FSReadable: rootfs}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		res, err := sb.Run(ctx, "sleep", "60")
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Reason != sandlock.ReasonTimeout || res.Success {
			t.Fatalf("got reason=%d success=%v, want ReasonTimeout / not success", res.Reason, res.Success)
		}
	})

	t.Run("signaled", func(t *testing.T) {
		sb := &sandlock.Sandbox{FSReadable: rootfs}
		res, err := sb.Run(context.Background(), "sh", "-c", "kill -TERM $$")
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Reason != sandlock.ReasonSignaled || res.Signal != 15 {
			t.Fatalf("got reason=%d signal=%d, want ReasonSignaled/15", res.Reason, res.Signal)
		}
	})

	t.Run("killed", func(t *testing.T) {
		sb := &sandlock.Sandbox{FSReadable: rootfs}
		res, err := sb.Run(context.Background(), "sh", "-c", "kill -KILL $$")
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Reason != sandlock.ReasonKilled || res.Signal != -1 {
			t.Fatalf("got reason=%d signal=%d, want ReasonKilled/-1", res.Reason, res.Signal)
		}
	})
}

func TestRunEmptyCommand(t *testing.T) {
	sb := &sandlock.Sandbox{}
	if _, err := sb.Run(context.Background()); err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestRunNULRejected(t *testing.T) {
	sb := &sandlock.Sandbox{}
	if _, err := sb.Run(context.Background(), "echo", "a\x00b"); err != sandlock.ErrInvalidString {
		t.Fatalf("err = %v, want ErrInvalidString", err)
	}
}

func TestSyscallEventArgvContains(t *testing.T) {
	ev := sandlock.SyscallEvent{Argv: []string{"python3", "-c", "print(1)"}}
	if !ev.ArgvContains("python") {
		t.Fatal("ArgvContains did not find substring")
	}
	if ev.ArgvContains("ruby") {
		t.Fatal("ArgvContains found absent substring")
	}
}

func TestPolicyDecisionValues(t *testing.T) {
	if sandlock.Allow() != sandlock.DecisionAllow {
		t.Fatal("Allow did not return DecisionAllow")
	}
	if sandlock.Deny() != sandlock.DecisionDeny {
		t.Fatal("Deny did not return DecisionDeny")
	}
	if sandlock.Audit() != sandlock.DecisionAudit {
		t.Fatal("Audit did not return DecisionAudit")
	}
	if got := sandlock.DenyWith(13); got == sandlock.DecisionAllow {
		t.Fatal("DenyWith returned allow for positive errno")
	}
	if got := sandlock.DenyWith(0); got != sandlock.DecisionDeny {
		t.Fatalf("DenyWith(0) = %d, want deny", got)
	}
}

func TestPolicyFnDenyByArgv(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{
		FSReadable: rootfs,
		PolicyFn: func(event sandlock.SyscallEvent, ctx *sandlock.PolicyContext) sandlock.PolicyDecision {
			if event.Syscall == "execve" && event.ArgvContains("sandlock-go-deny-token") {
				return sandlock.Deny()
			}
			return sandlock.Allow()
		},
	}
	res, err := sb.Run(context.Background(), "sh", "-c", "echo sandlock-go-deny-token")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Success {
		t.Fatalf("expected policy_fn to deny execve, got success stdout=%q", res.Stdout)
	}
}

func TestPolicyFnReceivesExecveArgv(t *testing.T) {
	requireLandlock(t)
	seen := make(chan []string, 1)
	sb := &sandlock.Sandbox{
		FSReadable: rootfs,
		PolicyFn: func(event sandlock.SyscallEvent, ctx *sandlock.PolicyContext) sandlock.PolicyDecision {
			if event.Syscall == "execve" && len(event.Argv) > 0 {
				select {
				case seen <- append([]string(nil), event.Argv...):
				default:
				}
			}
			return sandlock.Allow()
		},
	}
	res, err := sb.Run(context.Background(), "echo", "policy-fn-ok")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	select {
	case argv := <-seen:
		if len(argv) == 0 {
			t.Fatal("empty argv")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("policy_fn did not receive execve argv")
	}
}

func TestDryRun(t *testing.T) {
	requireLandlock(t)
	dir := t.TempDir()
	sb := &sandlock.Sandbox{
		FSReadable: rootfs,
		FSWritable: []string{dir},
		Workdir:    dir,
	}
	res, err := sb.DryRun(context.Background(), "sh", "-c", "echo hi > "+dir+"/out.txt")
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if !res.Success {
		t.Fatalf("dry run failed: exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	// The write is discarded; the file must not exist on the host afterward.
	if _, statErr := os.Stat(dir + "/out.txt"); statErr == nil {
		t.Fatalf("dry run leaked a write to the host")
	}
	t.Logf("changes: %+v", res.Changes)
}

func TestProcessKillInterruptsWait(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Spawn("sleep", "60")
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	defer p.Close()

	done := make(chan error, 1)
	go func() {
		_, werr := p.Wait()
		done <- werr
	}()

	// Wait is now blocked in the native wait. Kill must acquire the mutex and
	// signal the process group even though Wait is in flight; if Wait still
	// held the mutex across the blocking call, this would block until timeout.
	if err := p.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	select {
	case <-done:
		// Wait returned promptly after the kill, as intended.
	case <-time.After(5 * time.Second):
		t.Fatal("Kill did not interrupt a blocked Wait within 5s")
	}
}

// --- streaming-stdio popen (RFC #67), mirrors the FFI/Python popen suites ---

func TestPopenStreamsStdout(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Popen(sandlock.Stdio{Stdout: sandlock.StdioPiped}, "echo", "go-hi")
	if err != nil {
		t.Fatalf("Popen: %v", err)
	}
	defer p.Close()
	if p.Stdin != nil || p.Stderr != nil {
		t.Fatalf("inherited streams must be nil (stdin=%v stderr=%v)", p.Stdin, p.Stderr)
	}
	if p.Stdout == nil {
		t.Fatal("piped stdout must be non-nil")
	}
	out, err := io.ReadAll(p.Stdout)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if string(out) != "go-hi\n" {
		t.Fatalf("stdout = %q, want %q", out, "go-hi\n")
	}
	res, err := p.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if !res.Success || res.ExitCode != 0 {
		t.Fatalf("want success exit 0, got success=%v exit=%d", res.Success, res.ExitCode)
	}
}

func TestPopenStdinStdoutRoundtrip(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Popen(sandlock.Stdio{Stdin: sandlock.StdioPiped, Stdout: sandlock.StdioPiped}, "cat")
	if err != nil {
		t.Fatalf("Popen: %v", err)
	}
	defer p.Close()
	if _, err := p.Stdin.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	p.Stdin.Close() // EOF so cat exits
	out, err := io.ReadAll(p.Stdout)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if string(out) != "ping\n" {
		t.Fatalf("roundtrip = %q, want %q", out, "ping\n")
	}
	if res, _ := p.Wait(); !res.Success {
		t.Fatalf("cat should succeed, got %+v", res)
	}
}

func TestPopenWaitClosesUnclosedStdin(t *testing.T) {
	// cat reads stdin to EOF. If the caller pipes stdin but never closes it,
	// Wait must close it to deliver EOF — else cat blocks forever and Wait hangs.
	// Run under a watchdog so a regression surfaces as a failure, not a hung job.
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Popen(sandlock.Stdio{Stdin: sandlock.StdioPiped, Stdout: sandlock.StdioPiped}, "cat")
	if err != nil {
		t.Fatalf("Popen: %v", err)
	}
	defer p.Close()
	if _, err := p.Stdin.Write([]byte("data\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	// Deliberately do NOT close stdin — Wait is responsible for the EOF. Drain
	// stdout concurrently so a full pipe can never be the reason cat blocks.
	go io.ReadAll(p.Stdout)

	done := make(chan *sandlock.Result, 1)
	go func() {
		res, _ := p.Wait()
		done <- res
	}()
	select {
	case res := <-done:
		if res == nil || !res.Success {
			t.Fatalf("wait result not success: %+v", res)
		}
	case <-time.After(10 * time.Second):
		p.Kill()
		t.Fatal("Wait did not close unclosed piped stdin → cat blocked forever")
	}
}

func TestPopenStdoutAndStderrBothPiped(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Popen(
		sandlock.Stdio{Stdout: sandlock.StdioPiped, Stderr: sandlock.StdioPiped},
		"sh", "-c", "echo out; echo err 1>&2",
	)
	if err != nil {
		t.Fatalf("Popen: %v", err)
	}
	defer p.Close()
	out, _ := io.ReadAll(p.Stdout)
	errb, _ := io.ReadAll(p.Stderr)
	if string(out) != "out\n" {
		t.Fatalf("stdout = %q, want %q", out, "out\n")
	}
	if string(errb) != "err\n" {
		t.Fatalf("stderr = %q, want %q", errb, "err\n")
	}
	if res, _ := p.Wait(); !res.Success {
		t.Fatalf("want success, got %+v", res)
	}
}

func TestPopenNullStdoutNoStream(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Popen(sandlock.Stdio{Stdout: sandlock.StdioNull}, "echo", "discarded")
	if err != nil {
		t.Fatalf("Popen: %v", err)
	}
	defer p.Close()
	if p.Stdout != nil {
		t.Fatal("null stdout must yield no caller stream")
	}
	if res, _ := p.Wait(); res.ExitCode != 0 {
		t.Fatalf("want exit 0, got %d", res.ExitCode)
	}
}

func TestPopenZeroStdioInheritsAllLikeSpawn(t *testing.T) {
	// The zero Stdio value must wire all three streams as StdioInherit (the ABI
	// default StdioInherit == 0), identical to Spawn: no caller stream is handed
	// back and the child runs to success. Pins the zero-value contract the type
	// doc, the Popen doc, and the README all state but nothing exercised.
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Popen(sandlock.Stdio{}, "true")
	if err != nil {
		t.Fatalf("Popen: %v", err)
	}
	defer p.Close()
	if p.Stdin != nil || p.Stdout != nil || p.Stderr != nil {
		t.Fatalf("zero Stdio must inherit all three; got streams stdin=%v stdout=%v stderr=%v",
			p.Stdin != nil, p.Stdout != nil, p.Stderr != nil)
	}
	res, err := p.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if !res.Success || res.ExitCode != 0 {
		t.Fatalf("want success exit 0, got success=%v exit=%d", res.Success, res.ExitCode)
	}
}

func TestPopenKillAfterWaitIsNil(t *testing.T) {
	// Kill on an already-reaped Process must be nil (not ErrNotRunning), matching
	// the FFI (returns 0) and Python (no-op): a "Kill from another goroutine"
	// firing just as Wait reaps the child must not surface a spurious error.
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Popen(sandlock.Stdio{}, "true")
	if err != nil {
		t.Fatalf("Popen: %v", err)
	}
	if _, err := p.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if err := p.Kill(); err != nil {
		t.Fatalf("Kill after Wait must return nil, got %v", err)
	}
}

func TestPopenInvalidStdioMode(t *testing.T) {
	// An out-of-range discriminant is rejected before the child is spawned, so
	// this needs no Landlock.
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	if _, err := sb.Popen(sandlock.Stdio{Stdout: sandlock.StdioMode(99)}, "echo", "x"); err == nil {
		t.Fatal("an out-of-range StdioMode must be rejected")
	}
}

func TestPopenKillInterruptsWait(t *testing.T) {
	// A piped stdout we never drain would block Wait on a child that never exits;
	// Kill from another goroutine must interrupt it (the Go escape hatch that
	// makes a wait-timeout unnecessary here).
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Popen(sandlock.Stdio{Stdout: sandlock.StdioPiped}, "sleep", "60")
	if err != nil {
		t.Fatalf("Popen: %v", err)
	}
	defer p.Close()
	done := make(chan error, 1)
	go func() {
		_, werr := p.Wait()
		done <- werr
	}()
	if err := p.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Kill did not interrupt a blocked Wait within 5s")
	}
}

func TestPopenCloseClosesStreamsAndReaps(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Popen(sandlock.Stdio{Stdout: sandlock.StdioPiped}, "sleep", "60")
	if err != nil {
		t.Fatalf("Popen: %v", err)
	}
	stdout := p.Stdout
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close must close the piped stream: a further read fails on the closed fd.
	if _, err := stdout.Read(make([]byte, 1)); err == nil {
		t.Fatal("Close must close the piped stdout stream")
	}
	// Close is idempotent.
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// procDead reports whether pid names no live process: its /proc entry is gone
// (reaped) or its state is zombie/dead. Robust to the reap-vs-zombie race a
// plain kill(pid, 0) would be sensitive to.
func procDead(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true // no /proc entry → reaped
	}
	// "pid (comm) STATE ..." — comm may contain spaces/parens, so the state is
	// the character two positions after the final ')'.
	s := string(data)
	j := strings.LastIndexByte(s, ')')
	if j < 0 || j+2 >= len(s) {
		return true
	}
	switch s[j+2] {
	case 'Z', 'X', 'x': // zombie / dead
		return true
	}
	return false
}

func TestPopenFinalizerReapsAbandonedProcess(t *testing.T) {
	// A Process dropped without Wait/Close must not leak: the finalizer kills the
	// child's process group and frees the handle. Capture the pid in a scope that
	// drops the Process, then force GC and confirm the child is gone.
	requireLandlock(t)
	pid := func() int {
		sb := &sandlock.Sandbox{FSReadable: rootfs}
		p, err := sb.Popen(sandlock.Stdio{Stdout: sandlock.StdioPiped}, "sleep", "60")
		if err != nil {
			t.Fatalf("Popen: %v", err)
		}
		return p.Pid() // p becomes unreachable when this closure returns
	}()
	if pid <= 0 {
		t.Fatalf("no pid, got %d", pid)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		runtime.GC()
		if procDead(pid) {
			return // finalizer reaped the abandoned child
		}
		if time.Now().After(deadline) {
			t.Fatalf("abandoned Popen child (pid %d) was not reaped by the finalizer", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPopenCloseAfterWaitClosesLeftoverStream(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Popen(sandlock.Stdio{Stdout: sandlock.StdioPiped}, "echo", "leftover")
	if err != nil {
		t.Fatalf("Popen: %v", err)
	}
	stdout := p.Stdout

	// Wait without draining first (small output fits the pipe buffer); the stream
	// stays open so the caller can still read the buffered output afterward.
	if res, _ := p.Wait(); !res.Success {
		t.Fatalf("want success, got %+v", res)
	}
	got, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatalf("read after wait: %v", err)
	}
	if string(got) != "leftover\n" {
		t.Fatalf("post-wait read = %q, want %q", got, "leftover\n")
	}

	// Close after Wait must still release the leftover piped stream.
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := stdout.Read(make([]byte, 1)); err == nil {
		t.Fatal("Close after Wait must close the leftover piped stream")
	}
}

func TestSyscallNr(t *testing.T) {
	nr, err := sandlock.SyscallNr("openat")
	if err != nil {
		t.Fatalf("SyscallNr(openat): %v", err)
	}
	if nr < 0 {
		t.Fatalf("SyscallNr(openat) = %d, want >= 0", nr)
	}
	if _, err := sandlock.SyscallNr("definitely_not_a_real_syscall"); err == nil {
		t.Fatal("expected error for unknown syscall")
	}
}

func TestConfineRejectsSupervisorConfig(t *testing.T) {
	// Confine only honors Landlock fields; a field requiring a supervisor
	// must be rejected rather than silently ignored. Asserting the rejection
	// avoids irreversibly confining the test process.
	err := sandlock.Confine(&sandlock.Sandbox{
		FSReadable: rootfs,
		MaxMemory:  "256M",
	})
	if err == nil {
		t.Fatal("expected Confine to reject supervisor-only config")
	}
	if !strings.Contains(err.Error(), "confine") {
		t.Logf("Confine rejected with: %v", err)
	}
}

func TestProtectionMinABI(t *testing.T) {
	// Also pins the Protection discriminants: a wrong value would resolve to a
	// different protection (or 0 for unknown) and fail these expectations.
	cases := []struct {
		p    sandlock.Protection
		want int
	}{
		{sandlock.ProtectionFSRefer, 2},
		{sandlock.ProtectionFSTruncate, 3},
		{sandlock.ProtectionNetTCP, 4},
		{sandlock.ProtectionFSIoctlDev, 5},
		{sandlock.ProtectionSignalScope, 6},
		{sandlock.ProtectionAbstractUnixSocketScope, 6},
	}
	for _, c := range cases {
		if got := sandlock.ProtectionMinABI(c.p); got != c.want {
			t.Errorf("ProtectionMinABI(%d) = %d, want %d", c.p, got, c.want)
		}
	}
}

// TestRunDegradedBelowV6 exercises the Protection opt-out end to end: a
// fully-degradable policy must build and confine on any Landlock-capable
// kernel, degrading the protections the host cannot provide instead of failing
// the build the way the default strict posture does below ABI v6. It runs on
// the low-ABI CI image where the strict suite is skipped.
func TestRunDegradedBelowV6(t *testing.T) {
	if sandlock.LandlockABIVersion() < 1 {
		t.Skip("Landlock unavailable on this host")
	}
	// Negative control: below the v6 floor the default strict policy must fail
	// to build, so the degraded run's success is attributable to the opt-out
	// rather than to the protections being satisfiable on this host anyway.
	// On a v6+ host strict would succeed, so the contrast only applies below v6.
	if sandlock.LandlockABIVersion() < 6 {
		strict := &sandlock.Sandbox{FSReadable: rootfs}
		if _, err := strict.Run(context.Background(), "echo", "ok"); err == nil {
			t.Fatalf("default strict policy unexpectedly succeeded on Landlock ABI v%d (< v6); the degraded assertion would prove nothing", sandlock.LandlockABIVersion())
		}
	}
	sb := &sandlock.Sandbox{
		FSReadable: rootfs,
		AllowDegraded: []sandlock.Protection{
			sandlock.ProtectionFSRefer,
			sandlock.ProtectionFSTruncate,
			sandlock.ProtectionNetTCP,
			sandlock.ProtectionFSIoctlDev,
			sandlock.ProtectionSignalScope,
			sandlock.ProtectionAbstractUnixSocketScope,
		},
	}
	res, err := sb.Run(context.Background(), "echo", "ok")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Success || strings.TrimSpace(string(res.Stdout)) != "ok" {
		t.Fatalf("degraded run failed: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}
