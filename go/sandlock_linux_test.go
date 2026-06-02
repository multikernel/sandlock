//go:build linux

package sandlock_test

import (
	"context"
	"os"
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
