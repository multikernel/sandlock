//go:build linux

package sandlock_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sandlock "github.com/multikernel/sandlock/go"
)

// writeHelperImage writes an OCI image layout holding the repository's
// static rootfs-helper, with a config that sets Env and a WorkingDir the
// layer does not contain.
func writeHelperImage(t *testing.T, dir string) {
	t.Helper()
	helper := rootfsHelper(t)

	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	for _, d := range []string{"usr/", "usr/bin/", "proc/", "dev/", "tmp/"} {
		must(t, tw.WriteHeader(&tar.Header{Name: d, Typeflag: tar.TypeDir, Mode: 0o755}))
	}
	must(t, tw.WriteHeader(&tar.Header{Name: "usr/bin/rootfs-helper", Mode: 0o755, Size: int64(len(helper))}))
	_, err := tw.Write(helper)
	must(t, err)
	must(t, tw.Close())

	blobs := filepath.Join(dir, "blobs", "sha256")
	must(t, os.MkdirAll(blobs, 0o755))
	blob := func(mediaType string, data []byte) map[string]any {
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		must(t, os.WriteFile(filepath.Join(blobs, h), data, 0o644))
		return map[string]any{"mediaType": mediaType, "digest": "sha256:" + h, "size": len(data)}
	}
	config, _ := json.Marshal(map[string]any{"config": map[string]any{
		"Env":        []string{"PATH=/usr/bin", "GREETING=from-image"},
		"WorkingDir": "/work/here",
		"Cmd":        []string{"rootfs-helper", "pwd"},
	}})
	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"config":        blob("application/vnd.oci.image.config.v1+json", config),
		"layers":        []any{blob("application/vnd.oci.image.layer.v1.tar", layer.Bytes())},
	})
	index, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"manifests":     []any{blob("application/vnd.oci.image.manifest.v1+json", manifest)},
	})
	must(t, os.WriteFile(filepath.Join(dir, "index.json"), index, 0o644))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// rootfsHelper reads the static rootfs-helper that sandlock-core's build.rs
// compiles into its OUT_DIR.
func rootfsHelper(t *testing.T) []byte {
	t.Helper()
	var found []string
	for _, pattern := range []string{
		"../target/*/build/sandlock-core-*/out/rootfs-helper",
		"../target/*/*/build/sandlock-core-*/out/rootfs-helper",
	} {
		m, _ := filepath.Glob(pattern)
		found = append(found, m...)
	}
	var newest string
	var newestTime time.Time
	for _, p := range found {
		if fi, err := os.Stat(p); err == nil && fi.ModTime().After(newestTime) {
			newest, newestTime = p, fi.ModTime()
		}
	}
	if newest == "" {
		t.Skip("rootfs-helper not built (sandlock-core's build.rs compiles it)")
	}
	helper, err := os.ReadFile(newest)
	must(t, err)
	return helper
}

func TestPullImageAndRunInIt(t *testing.T) {
	requireLandlock(t)
	layout := t.TempDir()
	writeHelperImage(t, layout)

	img, err := sandlock.PullImage("oci:"+layout, t.TempDir())
	if err != nil {
		t.Fatalf("PullImage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(img.Rootfs, "usr/bin/rootfs-helper")); err != nil {
		t.Fatalf("rootfs lacks the layer's file: %v", err)
	}
	if got := strings.Join(img.Config.DefaultCmd(), " "); got != "rootfs-helper pwd" {
		t.Fatalf("DefaultCmd = %q", got)
	}
	if img.Config.WorkingDir != "/work/here" {
		t.Fatalf("WorkingDir = %q", img.Config.WorkingDir)
	}

	sb := &sandlock.Sandbox{Image: img}
	res, err := sb.Run(context.Background(), img.Config.DefaultCmd()...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Success || strings.TrimSpace(string(res.Stdout)) != "/work/here" {
		t.Fatalf("pwd in image: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}

	// An explicit Cwd wins over the image's WorkingDir.
	sb = &sandlock.Sandbox{Image: img, Cwd: "/tmp"}
	res, err = sb.Run(context.Background(), "rootfs-helper", "pwd")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.TrimSpace(string(res.Stdout)) != "/tmp" {
		t.Fatalf("Cwd override: stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

func TestImageWritesAreDiscarded(t *testing.T) {
	requireLandlock(t)
	layout := t.TempDir()
	writeHelperImage(t, layout)
	img, err := sandlock.PullImage("oci:"+layout, t.TempDir())
	if err != nil {
		t.Fatalf("PullImage: %v", err)
	}

	sb := &sandlock.Sandbox{Image: img, FSWritable: []string{"/tmp"}}
	res, err := sb.Run(context.Background(), "rootfs-helper", "write", "/tmp/f", "x")
	if err != nil || !res.Success {
		t.Fatalf("write in image: err=%v res=%+v", err, res)
	}
	if _, err := os.Stat(filepath.Join(img.Rootfs, "tmp/f")); !os.IsNotExist(err) {
		t.Fatalf("a run changed the cached image: %v", err)
	}

	sb = &sandlock.Sandbox{Image: img, OnExit: sandlock.BranchActionCommit}
	if _, err := sb.Run(context.Background(), "rootfs-helper", "pwd"); err == nil || !strings.Contains(err.Error(), "on_exit must be abort") {
		t.Fatalf("OnExit commit with an image: err=%v", err)
	}
}

func TestPullImageReportsFailure(t *testing.T) {
	_, err := sandlock.PullImage("oci:/nonexistent/layout", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "not an OCI image layout") {
		t.Fatalf("err = %v", err)
	}
}

func TestImageConfigDefaultCmdFallsBackToShell(t *testing.T) {
	if got := (sandlock.ImageConfig{}).DefaultCmd(); len(got) != 1 || got[0] != "/bin/sh" {
		t.Fatalf("DefaultCmd = %q", got)
	}
}
