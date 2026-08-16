//go:build linux

package sandlock_test

import (
	"context"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	sandlock "github.com/multikernel/sandlock/go"
)

// The binding forwards configuration values to sandlock and translates its
// verdict; it does not parse or filter them itself. These tests pin that from
// the outside: each one asserts on sandlock's own error text, which the Go SDK
// has no way to produce on its own. They are also the regression guard for the
// grammar the SDK used to carry, so every case here is one the deleted
// go/internal/policy accepted, truncated, or swallowed.
//
// None of them needs Landlock: the policy is rejected while it is being built,
// before any child is forked.

// buildErr runs sb far enough to build the native policy and returns the error.
// The command never executes in these tests; the build fails first.
func buildErr(t *testing.T, sb *sandlock.Sandbox) string {
	t.Helper()
	_, err := sb.Run(context.Background(), "true")
	if err == nil {
		t.Fatal("expected the configuration to be rejected, got no error")
	}
	return err.Error()
}

func TestByteSizeGrammarIsTheCores(t *testing.T) {
	// The deleted SDK parser took a float and a T suffix and converted with
	// uint64(), so it accepted all three of these: "1.5G" and "2T" built a
	// sandbox sandlock would have refused, and "0.5K" silently became 512.
	cases := []struct {
		size string
		want string
	}{
		{"1.5G", "invalid byte size: 1.5G"},
		{"0.5K", "invalid byte size: 0.5K"},
		{"2T", "unknown byte size suffix: T"},
		{"", "empty byte size string"},
	}
	for _, c := range cases {
		t.Run("MaxMemory/"+c.size, func(t *testing.T) {
			// An empty MaxMemory means "unset" and is not forwarded at all, so
			// the empty-string verdict is exercised through a lone space.
			size := c.size
			if size == "" {
				size = " "
			}
			got := buildErr(t, &sandlock.Sandbox{MaxMemory: size})
			if !strings.Contains(got, c.want) {
				t.Fatalf("error = %q, want it to contain sandlock's own %q", got, c.want)
			}
		})
		t.Run("MaxDisk/"+c.size, func(t *testing.T) {
			size := c.size
			if size == "" {
				size = " "
			}
			got := buildErr(t, &sandlock.Sandbox{MaxDisk: size})
			if !strings.Contains(got, c.want) {
				t.Fatalf("error = %q, want it to contain sandlock's own %q", got, c.want)
			}
		})
	}
}

func TestByteSizeGrammarAcceptsWhatTheCoreAccepts(t *testing.T) {
	// A bare byte count is part of sandlock's grammar, so it must reach the
	// core unchanged rather than being rejected on the way.
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs, MaxMemory: "268435456", MaxDisk: "1G"}
	res, err := sb.Run(context.Background(), "true")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Success {
		t.Fatalf("want success, got exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
}

func TestTimeStartGrammarIsTheCores(t *testing.T) {
	// The deleted SDK parser resolved a bare number of seconds itself and
	// clamped negatives. sandlock parses RFC3339 only, so a plain epoch count
	// is now refused with sandlock's own wording instead of silently working.
	for _, spec := range []string{"1700000000", "1700000000.5", "not-a-time"} {
		t.Run(spec, func(t *testing.T) {
			got := buildErr(t, &sandlock.Sandbox{TimeStart: spec})
			if !strings.Contains(got, "time_start") {
				t.Fatalf("error = %q, want it to name time_start", got)
			}
		})
	}
}

func TestTimeStartCarriesWhatTheOldEpochCountCouldNot(t *testing.T) {
	// Sub-second precision and a pre-1970 instant both survive the trip now
	// that the ABI takes the timestamp as a string: the u64 epoch count the
	// SDK used to compute could express neither (it truncated the fraction and
	// the SDK refused the negative outright).
	//
	// Each case reads the guest's own clock rather than only asserting that
	// the run succeeded: the parse landing in the policy is not the same
	// claim as the guest running at the requested instant, and the pre-1970
	// case used to satisfy the first while failing the second (the offset
	// collapsed to the epoch, so `date` printed 1970-01-01T00:00:00Z).
	requireLandlock(t)
	for _, tc := range []struct{ spec, want string }{
		{"2026-01-01T00:00:00.5Z", "2026-01-01T00:00:00"},
		{"1969-07-20T20:17:00Z", "1969-07-20T20:17:00"},
		// 03:00 east of UTC, so the same instant reads three hours earlier in UTC.
		{"2026-01-01T00:00:00+03:00", "2025-12-31T21:00:00"},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			sb := &sandlock.Sandbox{FSReadable: rootfs, TimeStart: tc.spec}
			res, err := sb.Run(context.Background(), "/usr/bin/date", "-u", "+%Y-%m-%dT%H:%M:%S")
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !res.Success {
				t.Fatalf("want success, got exit=%d stderr=%q", res.ExitCode, res.Stderr)
			}
			raw := strings.TrimSpace(string(res.Stdout))
			got, err := time.Parse("2006-01-02T15:04:05", raw)
			if err != nil {
				t.Fatalf("guest printed %q, which is not a timestamp: %v", raw, err)
			}
			want, err := time.Parse("2006-01-02T15:04:05", tc.want)
			if err != nil {
				t.Fatalf("bad want %q: %v", tc.want, err)
			}
			// The guest clock ticks at real speed from the requested start, so
			// it has advanced by however long the sandbox took to come up.
			if d := got.Sub(want); d < 0 || d > 30*time.Second {
				t.Fatalf("guest clock = %q, want %q plus the startup delay (off by %s)", raw, tc.want, d)
			}
		})
	}
}

func TestZeroCapsReachTheCore(t *testing.T) {
	// Each of these was filtered by a `> 0` guard in the binding, so the
	// caller's explicit zero was dropped and the field silently took its
	// default. Now the zero travels and sandlock names the setting.
	cases := []struct {
		name string
		sb   *sandlock.Sandbox
		want string
	}{
		{"MaxCPU", &sandlock.Sandbox{MaxCPU: sandlock.Ptr[uint8](0)}, "max_cpu must be 1-100, got 0"},
		{"MaxProcesses", &sandlock.Sandbox{MaxProcesses: sandlock.Ptr[uint32](0)}, "max_processes must be greater than 0"},
		{"MaxOpenFiles", &sandlock.Sandbox{MaxOpenFiles: sandlock.Ptr[uint32](0)}, "max_open_files must be greater than 0"},
		{"NumCPUs", &sandlock.Sandbox{NumCPUs: sandlock.Ptr[uint32](0)}, "num_cpus must be greater than 0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildErr(t, c.sb)
			if !strings.Contains(got, c.want) {
				t.Fatalf("error = %q, want it to contain sandlock's own %q", got, c.want)
			}
		})
	}
}

func TestMaxCPUOutOfRangeKeepsTheCoresWording(t *testing.T) {
	got := buildErr(t, &sandlock.Sandbox{MaxCPU: sandlock.Ptr[uint8](200)})
	if !strings.Contains(got, "max_cpu must be 1-100, got 200") {
		t.Fatalf("error = %q, want sandlock's own out-of-range message", got)
	}
}

func TestBranchActionDiscriminantsAreTheABIs(t *testing.T) {
	// The binding used to prepend its own Default sentinel and send
	// action-1, so a value sandlock rejects came back naming a different
	// number, and 3 was a valid "keep". Both properties are pinned here: the
	// error quotes the number the caller wrote, and 3 is no longer a value.
	bad := sandlock.Ptr(sandlock.BranchAction(3))
	cases := []struct {
		field  string
		sb     *sandlock.Sandbox
		setter string
	}{
		{"OnExit", &sandlock.Sandbox{OnExit: bad}, "on_exit"},
		{"OnError", &sandlock.Sandbox{OnError: bad}, "on_error"},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			got := buildErr(t, c.sb)
			want := c.setter + ": unrecognized branch action 3"
			if !strings.Contains(got, want) {
				t.Fatalf("error = %q, want it to contain %q", got, want)
			}
		})
	}
}

func TestBranchActionCommitIsForwarded(t *testing.T) {
	// Commit is discriminant 0, which the old sentinel numbering made
	// indistinguishable from "unset" and dropped. It must reach sandlock now.
	requireLandlock(t)
	dir := t.TempDir()
	sb := &sandlock.Sandbox{
		FSReadable: rootfs,
		FSWritable: []string{dir},
		Workdir:    dir,
		OnExit:     sandlock.Ptr(sandlock.BranchActionCommit),
		OnError:    sandlock.Ptr(sandlock.BranchActionAbort),
	}
	res, err := sb.Run(context.Background(), "true")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Success {
		t.Fatalf("want success, got exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
}

func TestExplicitEmptyNameIsNotAutoGenerated(t *testing.T) {
	// The binding used to turn an empty Name into the NULL that asks sandlock
	// to invent one, so a caller whose name came from an empty variable got a
	// random sandbox instead of a diagnosis. nil is now the only spelling of
	// "auto-generate"; a name the caller set is forwarded as written, and
	// sandlock refuses the empty one.
	requireLandlock(t)
	sb := &sandlock.Sandbox{FSReadable: rootfs, Name: sandlock.Ptr("")}
	if _, err := sb.Run(context.Background(), "true"); err == nil {
		t.Fatal("an explicitly empty Name must be refused, not auto-generated")
	}

	// A nil Name still auto-generates, and a real one is still accepted.
	for _, name := range []*string{nil, sandlock.Ptr("go-sdk-named")} {
		sb := &sandlock.Sandbox{FSReadable: rootfs, Name: name}
		res, err := sb.Run(context.Background(), "true")
		if err != nil {
			t.Fatalf("Run(name=%v): %v", name, err)
		}
		if !res.Success {
			t.Fatalf("want success, got exit=%d stderr=%q", res.ExitCode, res.Stderr)
		}
	}
}

func TestZeroIsNotUnsetForTheStringSizedCaps(t *testing.T) {
	// MaxMemory is a string, so it never met the numeric `> 0` filter that
	// used to guard the caps above; the deleted SDK parser turned "0" into a
	// uint64 zero and the filter then dropped it, which is why this case
	// needs its own test now that the string travels.
	//
	// Zero is what the supervisor carries internally for "no ceiling", but
	// the memory handler is installed on the field being set at all, so an
	// explicit zero used to install a handler enforcing a ceiling of zero:
	// the guest was SIGKILLed on the loader's first anonymous mmap, with no
	// exit status and nothing naming the setting.
	got := buildErr(t, &sandlock.Sandbox{FSReadable: rootfs, MaxMemory: "0"})
	if !strings.Contains(got, "max_memory must be greater than 0") {
		t.Fatalf("error = %q, want sandlock's own verdict on a zero ceiling", got)
	}

	// MaxDisk is deliberately not the same knob: zero is its documented
	// spelling of "unlimited", so it must still build. A binding that
	// generalised the rule would take a working policy away.
	requireLandlock(t)
	res, err := (&sandlock.Sandbox{FSReadable: rootfs, MaxDisk: "0"}).Run(context.Background(), "true")
	if err != nil {
		t.Fatalf("a zero disk quota means unlimited and must be accepted: %v", err)
	}
	if !res.Success {
		t.Fatalf("want success, got exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
}

func TestAnEmptyCoreSetIsNotAnUnsetOne(t *testing.T) {
	// CPUCores moved from a `len(...) > 0` guard to `!= nil`, so an empty
	// non-nil slice now reaches sandlock instead of being dropped by the
	// binding. It asks for an affinity mask with no bits, which the kernel
	// refuses; the child setup used to skip the call for it, so the pinning
	// the caller asked for silently did not happen.
	got := buildErr(t, &sandlock.Sandbox{FSReadable: rootfs, CPUCores: []uint32{}})
	if !strings.Contains(got, "cpu_cores must name at least one core") {
		t.Fatalf("error = %q, want sandlock's own verdict on an empty core set", got)
	}

	// GPUDevices shares the shape and not the rule: an empty list there is
	// the spelling of "every GPU present", so it must still build.
	requireLandlock(t)
	res, err := (&sandlock.Sandbox{FSReadable: rootfs, GPUDevices: []uint32{}}).Run(context.Background(), "true")
	if err != nil {
		t.Fatalf("an empty GPU list means every GPU and must be accepted: %v", err)
	}
	if !res.Success {
		t.Fatalf("want success, got exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
}

func TestAnUnsetCapIsNeverSent(t *testing.T) {
	// The other half of TestZeroCapsReachTheCore: a nil pointer must reach
	// no setter at all, so the guest sees the host's own value rather than
	// anything this binding chose. Both knobs here are readable from inside
	// the sandbox, so the assertion is on what the child actually got, not
	// on the build succeeding.
	requireLandlock(t)

	read := func(t *testing.T, sb *sandlock.Sandbox, script string) string {
		t.Helper()
		sb.FSReadable = rootfs
		res, err := sb.Run(context.Background(), "sh", "-c", script)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !res.Success {
			t.Fatalf("want success, got exit=%d stderr=%q", res.ExitCode, res.Stderr)
		}
		return strings.TrimSpace(string(res.Stdout))
	}

	hostCPUs := strconv.Itoa(runtime.NumCPU())
	if got := read(t, &sandlock.Sandbox{}, "nproc"); got != hostCPUs {
		t.Fatalf("an unset NumCPUs must leave the host count visible: nproc = %q, want %q", got, hostCPUs)
	}
	if got := read(t, &sandlock.Sandbox{NumCPUs: sandlock.Ptr[uint32](2)}, "nproc"); got != "2" {
		t.Fatalf("a set NumCPUs must reach sandlock: nproc = %q, want \"2\"", got)
	}

	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	hostNoFile := strconv.FormatUint(lim.Cur, 10)
	if got := read(t, &sandlock.Sandbox{}, "ulimit -n"); got != hostNoFile {
		t.Fatalf("an unset MaxOpenFiles must inherit the host limit: ulimit -n = %q, want %q", got, hostNoFile)
	}
	if got := read(t, &sandlock.Sandbox{MaxOpenFiles: sandlock.Ptr[uint32](32)}, "ulimit -n"); got != "32" {
		t.Fatalf("a set MaxOpenFiles must reach sandlock: ulimit -n = %q, want \"32\"", got)
	}
}

func TestOnlyAUIDIsNotAStateThisBindingCanSpell(t *testing.T) {
	// The binding used to carry UID and GID as two separate *int fields and
	// answer "UID and GID must both be set" itself. RunAs carries the pair
	// the core's own Option<RunAs> carries, so the half-set state is gone
	// from the type rather than from a check: this compiles only because
	// both ids are required, and stops compiling if either becomes optional.
	requireLandlock(t)
	var _ = sandlock.RunAs{UID: 1000, GID: 1000}

	f, ok := reflect.TypeOf(sandlock.Sandbox{}).FieldByName("User")
	if !ok {
		t.Fatal("Sandbox.User is gone; the identity must still be one field")
	}
	if f.Type.Kind() != reflect.Pointer || f.Type.Elem() != reflect.TypeOf(sandlock.RunAs{}) {
		t.Fatalf("Sandbox.User is %s, want *sandlock.RunAs: one pointer is the whole \"unset\"", f.Type)
	}
	for _, name := range []string{"UID", "GID"} {
		id, ok := f.Type.Elem().FieldByName(name)
		if !ok {
			t.Fatalf("RunAs.%s is gone", name)
		}
		if id.Type.Kind() == reflect.Pointer {
			t.Fatalf("RunAs.%s is %s: an optional id puts the half-set state back", name, id.Type)
		}
	}
	if _, ok := reflect.TypeOf(sandlock.Sandbox{}).FieldByName("UID"); ok {
		t.Fatal("Sandbox.UID is back; the pair must be the only spelling")
	}

	// And the pair itself still works end to end. An unprivileged user
	// namespace can map only the id that created it, so the pair under test
	// is this process's own: a hardcoded 1000 passes on a host whose user is
	// 1000 and fails to create the sandbox anywhere else.
	uid, gid := uint32(syscall.Getuid()), uint32(syscall.Getgid())
	sb := &sandlock.Sandbox{FSReadable: rootfs, User: &sandlock.RunAs{UID: uid, GID: gid}}
	res, err := sb.Run(context.Background(), "sh", "-c", "id -u; id -g")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantUID, wantGID := strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10)
	if got := strings.Fields(string(res.Stdout)); len(got) != 2 || got[0] != wantUID || got[1] != wantGID {
		t.Fatalf("id inside the sandbox = %q, want uid %s and gid %s", res.Stdout, wantUID, wantGID)
	}
}

func TestAnUnknownProtectionIsRefusedNotDropped(t *testing.T) {
	// `Protection` is a plain uint32 with six named values, so a number with
	// no variant is expressible and reaches the C ABI. The setter used to
	// drop it and the build used to succeed, which told a caller built
	// against a newer header nothing at all when an older library did not
	// recognise the protection it asked to relax: the caller believed it had
	// opted out and the protection stayed strict.
	for _, tc := range []struct {
		name string
		sb   *sandlock.Sandbox
		want string
	}{
		{"allow_degraded", &sandlock.Sandbox{AllowDegraded: []sandlock.Protection{42}}, "allow_degraded: unrecognized protection 42"},
		{"disable", &sandlock.Sandbox{Disable: []sandlock.Protection{99}}, "disable: unrecognized protection 99"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildErr(t, tc.sb); !strings.Contains(got, tc.want) {
				t.Fatalf("error = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}
