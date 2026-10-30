//go:build linux

package sandlock_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	sandlock "github.com/multikernel/sandlock/go"
)

func TestRegistrationIsPerSandbox(t *testing.T) {
	requireLandlock(t)
	name := fmt.Sprintf("go-unregistered-%d", os.Getpid())
	holder := &sandlock.Sandbox{FSReadable: rootfs, Name: name, DisableRegistration: true}
	p, err := holder.Spawn("sleep", "30")
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	defer p.Close()
	defer p.Kill()

	registered := &sandlock.Sandbox{FSReadable: rootfs, Name: name}
	r, err := registered.Spawn("sleep", "30")
	if err != nil {
		t.Fatalf("registered Spawn: %v", err)
	}
	defer r.Close()
	defer r.Kill()

	sb := &sandlock.Sandbox{FSReadable: rootfs, Name: name, DisableRegistration: true}
	res, err := sb.Run(context.Background(), "true")
	if err != nil {
		t.Fatalf("Run with a reused name: %v", err)
	}
	if !res.Success {
		t.Fatalf("Run failed: exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	duplicate, err := registered.Spawn("true")
	if err == nil {
		defer duplicate.Close()
		defer duplicate.Kill()
		t.Fatal("registered Spawn accepted a duplicate name")
	}
}
