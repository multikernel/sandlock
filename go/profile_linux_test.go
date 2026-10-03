//go:build linux

package sandlock_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sandlock "github.com/multikernel/sandlock/go"
)

func TestParseProfileMapsFields(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	sb, err := sandlock.ParseProfile(`
[filesystem]
read = ["/usr", "${HOME}/src"]
mount = ["/w:/a:b:ro", "/v:/c"]
on_exit = "abort"
on_error = "keep"

[program]
uid = 1000
gid = 1000
env = { CC = "gcc" }

[network]
allow_bind = [8080, "9000-9001"]

[limits]
memory = "64M"
cpu = 50
`)
	if err != nil {
		t.Fatal(err)
	}
	uid := 1000
	want := &sandlock.Sandbox{
		FSReadable:   []string{"/usr", "/home/alice/src"},
		FSMount:      map[string]string{"/v": "/c"},
		FSMountRO:    map[string]string{"/w": "/a:b"},
		OnExit:       sandlock.BranchActionAbort,
		OnError:      sandlock.BranchActionKeep,
		UID:          &uid,
		GID:          &uid,
		Env:          map[string]string{"CC": "gcc"},
		NetAllowBind: []string{"8080", "9000-9001"},
		MaxMemory:    "64M",
		MaxCPU:       50,
	}
	if !reflect.DeepEqual(sb, want) {
		t.Fatalf("got  %+v\nwant %+v", sb, want)
	}
}

func TestParseProfileReportsCoreErrors(t *testing.T) {
	for toml, want := range map[string]string{
		"[program]\nuid = 1000\n": "gid must both be set",
		"[bogus]\n":               "unknown field `bogus`",
		"[filesystem]\nmount = [\"/w:/a\", \"/w:/b:ro\"]\n": "mounted more than once",
		"[filesystem]\non_exit = \"maybe\"\n":               "[filesystem].on_exit",
		"[network]\nallow_bind = [8080, \"*\"]\n":           "wildcard",
	} {
		if _, err := sandlock.ParseProfile(toml); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error containing %q", toml, err, want)
		}
	}
}

func TestParseProfileRefusesFieldsGoCannotExpress(t *testing.T) {
	_, err := sandlock.ParseProfile("[config]\nhttp_inject_ca = [\"/etc/ssl/ca.pem\"]\n[http]\nallow = [\"GET example.com/*\"]\n")
	if err == nil || !strings.Contains(err.Error(), "http_inject_ca") {
		t.Fatalf("got %v, want the unsupported field named", err)
	}
}

func TestProfileDirAndListing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "elsewhere"))
	dir := filepath.Join(home, ".config", "sandlock", "profiles")
	if got, err := sandlock.ProfileDir(); err != nil || got != dir {
		t.Fatalf("ProfileDir() = %q, %v, want %q", got, err, dir)
	}
	if names, err := sandlock.ListProfiles(); err != nil || names != nil {
		t.Fatalf("missing dir: got %v, %v", names, err)
	}
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "dev.toml"), []byte("[filesystem]\nmount = [\"/w:/h:ro\"]\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "build.toml"), []byte(""), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte(""), 0o644))

	names, err := sandlock.ListProfiles()
	if err != nil || !reflect.DeepEqual(names, []string{"build", "dev"}) {
		t.Fatalf("ListProfiles() = %v, %v", names, err)
	}
	sb, err := sandlock.LoadProfile("dev")
	if err != nil || !reflect.DeepEqual(sb.FSMountRO, map[string]string{"/w": "/h"}) {
		t.Fatalf("LoadProfile(dev) = %+v, %v", sb, err)
	}
	if _, err := sandlock.LoadProfile("absent"); err == nil || !strings.Contains(err.Error(), "profile not found") {
		t.Fatalf("LoadProfile(absent) = %v", err)
	}
}

func TestLoadProfileFileErrorNamesThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.toml")
	must(t, os.WriteFile(path, []byte("[typo]\n"), 0o644))
	if _, err := sandlock.LoadProfileFile(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("got %v, want the path named", err)
	}
}

// Issue #174 from Go: a ':ro' entry mounts the directory it names, read-only,
// never a sibling literally named '<host>:ro'.
func TestProfileReadOnlyMountIsEnforced(t *testing.T) {
	requireLandlock(t)
	root := helperRootfs(t)
	base := t.TempDir()
	host := filepath.Join(base, "hostdata")
	decoy := host + ":ro"
	must(t, os.MkdirAll(host, 0o755))
	must(t, os.MkdirAll(decoy, 0o755))
	must(t, os.WriteFile(filepath.Join(host, "file.txt"), []byte("original"), 0o644))
	must(t, os.WriteFile(filepath.Join(decoy, "file.txt"), []byte("decoy"), 0o644))

	sb, err := sandlock.ParseProfile(fmt.Sprintf(
		"[filesystem]\nchroot = %q\nread = [\"/bin\"]\nmount = [\"/work:%s:ro\"]\n", root, host))
	if err != nil {
		t.Fatal(err)
	}
	res, err := sb.Run(context.Background(), "/bin/cat", "/work/file.txt")
	if err != nil || string(res.Stdout) != "original" {
		t.Fatalf("read: err=%v res=%+v", err, res)
	}
	res, err = sb.Run(context.Background(), "/bin/write", "/work/file.txt", "HACKED")
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("write through a read-only profile mount succeeded: %+v", res)
	}
	for path, want := range map[string]string{
		filepath.Join(host, "file.txt"):  "original",
		filepath.Join(decoy, "file.txt"): "decoy",
	} {
		if got, _ := os.ReadFile(path); string(got) != want {
			t.Fatalf("%s = %q, want %q", path, got, want)
		}
	}
}

func TestExplicitReadWrite(t *testing.T) {
	sb, err := sandlock.ParseProfile("[filesystem]\nread_write = [\"/tmp\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sb.FSReadable, []string{"/tmp"}) || !reflect.DeepEqual(sb.FSWritable, []string{"/tmp"}) {
		t.Fatalf("read_write did not grant both: %+v", sb)
	}
}

func TestExplicitReadWriteSDK(t *testing.T) {
	dir := t.TempDir()
	sb := &sandlock.Sandbox{FSReadable: rootfs, FSReadWrite: []string{dir}}
	result, err := sb.Run(context.Background(), "sh", "-c", `printf rw > "$1/out"; cat "$1/out"`, "sh", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success || string(result.Stdout) != "rw" {
		t.Fatalf("read/write SDK: %+v", result)
	}
}
