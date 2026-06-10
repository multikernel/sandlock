// Command basic demonstrates running a command under a sandlock sandbox with a
// read-only root filesystem and a single writable directory.
//
// Build the FFI library first, then run from a sandlock checkout:
//
//	cargo build --release
//	go run ./go/examples/basic
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	sandlock "github.com/multikernel/sandlock/go"
)

func main() {
	if v, min := sandlock.LandlockABIVersion(), sandlock.MinLandlockABI(); v < min {
		log.Fatalf("kernel Landlock ABI v%d < required v%d", v, min)
	}

	sb := &sandlock.Sandbox{
		FSReadable: []string{"/usr", "/lib", "/lib64", "/bin", "/etc"},
		FSWritable: []string{"/tmp"},
		MaxMemory:  "256M",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := sb.Run(ctx, "sh", "-c", "echo hello from $(uname -s); ls /tmp >/dev/null")
	if err != nil {
		log.Fatalf("run: %v", err)
	}

	fmt.Printf("exit=%d success=%v\n", res.ExitCode, res.Success)
	os.Stdout.Write(res.Stdout)
	if len(res.Stderr) > 0 {
		fmt.Fprintf(os.Stderr, "stderr: %s", res.Stderr)
	}
}
