//go:build linux

package sandlock_test

import (
	"io"
	"log/slog"
	"testing"

	sandlock "github.com/multikernel/sandlock/go"
)

func TestSetLoggerInstallsAndRemoves(t *testing.T) {
	l := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := sandlock.SetLogger(l); err != nil {
		t.Fatalf("SetLogger: %v", err)
	}
	if err := sandlock.SetLogger(nil); err != nil {
		t.Fatalf("SetLogger(nil): %v", err)
	}
}
