//go:build linux

package sandlock_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sandlock "github.com/multikernel/sandlock/go"
)

// helperRootfs builds a chroot whose only binary is the static rootfs-helper,
// reachable as /bin/cat and /bin/write.
func helperRootfs(t *testing.T) string {
	t.Helper()
	helper := rootfsHelper(t)
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	must(t, os.MkdirAll(bin, 0o755))
	must(t, os.WriteFile(filepath.Join(bin, "rootfs-helper"), helper, 0o755))
	for _, name := range []string{"cat", "write"} {
		must(t, os.Symlink("rootfs-helper", filepath.Join(bin, name)))
	}
	return root
}

func TestFSMountROReadsButRefusesWrites(t *testing.T) {
	requireLandlock(t)
	root := helperRootfs(t)
	host := t.TempDir()
	file := filepath.Join(host, "file.txt")
	must(t, os.WriteFile(file, []byte("original"), 0o644))

	sb := &sandlock.Sandbox{
		Chroot:     root,
		FSReadable: []string{"/bin"},
		FSMountRO:  map[string]string{"/work": host},
	}
	res, err := sb.Run(context.Background(), "/bin/cat", "/work/file.txt")
	if err != nil || res.ExitCode != 0 || string(res.Stdout) != "original" {
		t.Fatalf("read: err=%v res=%+v", err, res)
	}
	res, err = sb.Run(context.Background(), "/bin/write", "/work/file.txt", "HACKED")
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "Permission denied") {
		t.Fatalf("write through a read-only mount was not refused: %+v", res)
	}
	if got, _ := os.ReadFile(file); string(got) != "original" {
		t.Fatalf("host file changed to %q", got)
	}
}

func TestFSMountROConflictRejected(t *testing.T) {
	sb := &sandlock.Sandbox{
		FSMount:   map[string]string{"/work": "/a"},
		FSMountRO: map[string]string{"/work": "/b"},
	}
	_, err := sb.Run(context.Background(), "/bin/true")
	if err == nil || !strings.Contains(err.Error(), "mounted more than once") {
		t.Fatalf("got %v, want a repeated mount error", err)
	}
}
