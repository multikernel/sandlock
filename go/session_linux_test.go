//go:build linux

package sandlock_test

import (
	"context"
	"fmt"
	"github.com/multikernel/sandlock/go"
	"runtime"
	"testing"
	"time"
)

func TestSessionWaitRetainsBackgroundJobs(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Spawn("sh", "-c", "sleep 60 & echo retained; exit 7")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	status, err := p.Wait()
	if err != nil || status.ExitCode != 7 {
		t.Fatalf("wait: %+v, %v", status, err)
	}
	again, err := p.Wait()
	if err != nil || *again != *status {
		t.Fatalf("repeat wait: %+v, %v", again, err)
	}
	groups, err := p.ProcessGroups()
	if err != nil || len(groups) == 0 {
		t.Fatalf("groups: %v, %v", groups, err)
	}
	result, err := p.Shutdown()
	if err != nil || result.ExitCode != 7 || string(result.Stdout) != "retained\n" {
		t.Fatalf("shutdown: %+v, %v", result, err)
	}
}

func TestSessionCloseInterruptsWait(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	p, err := sb.Spawn("sleep", "60")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := p.Wait(); done <- err }()
	time.Sleep(100 * time.Millisecond)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not release wait")
	}
}

func TestSessionRunTimeoutStillCleansUp(t *testing.T) {
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result, err := sb.Run(ctx, "sleep", "60")
	if err != nil || result.Reason != sandlock.ReasonTimeout || result.Success {
		t.Fatalf("run: %+v, %v", result, err)
	}
}

func TestSessionFinalizerCleansJobsAfterMainExit(t *testing.T) {
	requireLandlock(t)
	child := func() int {
		sb := &sandlock.Sandbox{FSReadable: rootfs}
		p, err := sb.Popen(sandlock.Stdio{Stdout: sandlock.StdioPiped}, "sh", "-c", "sleep 60 & echo $!")
		if err != nil {
			t.Fatal(err)
		}
		var pid int
		if _, err := fmt.Fscanln(p.Stdout, &pid); err != nil {
			t.Fatal(err)
		}
		if status, err := p.Wait(); err != nil || !status.Success {
			t.Fatalf("wait: %+v, %v", status, err)
		}
		return pid
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !procDead(child) {
		runtime.GC()
		if time.Now().After(deadline) {
			t.Fatal("finalizer left background job alive")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
