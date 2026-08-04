//go:build linux

package sandlock_test

// The Go SDK's half of the four-surface parity proof.
//
// sandlock owns the byte-size and RFC 3339 grammars. Four surfaces reach them:
// a CLI flag, a profile key, the Python SDK and this one. Until the C ABI
// setters started taking strings, the last two parsed the value themselves,
// agreed with each other and both disagreed with the core, so 1.5G and 1T
// built sandboxes that no flag and no profile could have built.
//
// The corpus of values is not in this file. It is tests/grammar-corpus.json,
// shared with python/tests/test_setter_grammar_parity.py, which drives the
// other three surfaces over the same entries. A list of values pasted into
// each language would be the very failure being fixed here.
//
// Two things are compared, and neither of them is this file's own opinion:
//
//   - a rejected value has to come back with the core's sentence, and the
//     sentence is checked against what the CLI prints for the same text rather
//     than against a string typed here, so the two languages are compared
//     directly and not each to a copy of the expected answer;
//   - an accepted value has to produce the same live policy, read back over
//     `sandlock inspect`, which serializes the policy through one core routine
//     whichever surface configured it.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sandlock "github.com/multikernel/sandlock/go"
)

// ============================================================
// The corpus
// ============================================================

type corpusKnob struct {
	Flag    string            `json:"flag"`
	Profile []string          `json:"profile"`
	Setter  string            `json:"setter"`
	Python  string            `json:"python"`
	Go      string            `json:"go"`
	Labels  map[string]string `json:"labels"`
}

// label is the knob name a surface hands the core so the core can name it in a
// diagnosis. It is the one part of the sentence a surface supplies, so it is
// folded away before two surfaces are compared. An empty result means this
// grammar's message names no knob and the surfaces must match word for word.
func (k corpusKnob) label(surface string) string { return k.Labels[surface] }

type corpusAccepted struct {
	Knob string `json:"knob"`
	// Value is the text every surface is given, character for character.
	Value string `json:"value"`
	// Renders is how a live sandbox spells the value back, or nil when the
	// effective policy document cannot carry it at all.
	Renders *string `json:"renders"`
	// Live is absent (true) for a policy whose guest survives long enough to
	// be inspected.
	Live        *bool             `json:"live"`
	Unreachable map[string]string `json:"unreachable"`
}

func (c corpusAccepted) live() bool { return c.Live == nil || *c.Live }

type corpusRejected struct {
	Knob  string `json:"knob"`
	Value string `json:"value"`
	// Diagnosis is what the core's sentence must start with, once the
	// surface's envelope is peeled and the knob label is folded away.
	Diagnosis   string            `json:"diagnosis"`
	SDKOnly     bool              `json:"sdk_only"`
	Unreachable map[string]string `json:"unreachable"`
}

type grammarCorpus struct {
	Knobs    map[string]corpusKnob `json:"knobs"`
	Accepted []corpusAccepted      `json:"accepted"`
	Rejected []corpusRejected      `json:"rejected"`
}

const corpusPath = "../tests/grammar-corpus.json"

func corpusLoad(t *testing.T) grammarCorpus {
	t.Helper()
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("reading the shared corpus: %v", err)
	}
	var c grammarCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parsing %s: %v", corpusPath, err)
	}
	if len(c.Knobs) == 0 || len(c.Accepted) == 0 || len(c.Rejected) == 0 {
		t.Fatalf("%s is empty; the parity claim would be vacuous", corpusPath)
	}
	return c
}

func corpusKnobFor(t *testing.T, c grammarCorpus, name string) corpusKnob {
	t.Helper()
	k, ok := c.Knobs[name]
	if !ok {
		t.Fatalf("corpus entry names knob %q, which %s does not describe", name, corpusPath)
	}
	return k
}

// ============================================================
// Driving the Go SDK
// ============================================================

// corpusSandbox returns a Sandbox with one field set, chosen by the name the
// corpus records rather than by a switch written here: a field this SDK
// renamed or retyped has to fail loudly instead of quietly dropping out of the
// comparison.
func corpusSandbox(t *testing.T, knob corpusKnob, value string) *sandlock.Sandbox {
	t.Helper()
	sb := &sandlock.Sandbox{}
	f := reflect.ValueOf(sb).Elem().FieldByName(knob.Go)
	if !f.IsValid() {
		t.Fatalf("sandlock.Sandbox has no field %q; %s and the SDK disagree", knob.Go, corpusPath)
	}
	if f.Kind() != reflect.String {
		t.Fatalf("sandlock.Sandbox.%s is %s, not a string: the value would have to be parsed to get in, which is what this test exists to rule out", knob.Go, f.Kind())
	}
	f.SetString(value)
	return sb
}

// goEnvelope is what the SDK wraps around the core's diagnosis. Asserted
// literally before it is peeled: an envelope that changed is a binding that
// started reporting something other than the core's verdict.
const goEnvelope = "sandlock: invalid sandbox: "

// goRefusal offers a value to the SDK and returns the refusal, or "" if the
// policy was built. The command never runs: with no grants a built policy
// still produces a guest that cannot exec, and that is a result rather than a
// build error, which is what tells acceptance from refusal here.
func goRefusal(t *testing.T, knob corpusKnob, value string) string {
	t.Helper()
	sb := corpusSandbox(t, knob, value)
	_, err := sb.Run(context.Background(), "/bin/true")
	if err == nil {
		return ""
	}
	if !strings.HasPrefix(err.Error(), goEnvelope) {
		// Not a verdict on the value: something later went wrong, and
		// reporting it as a refusal would let a broken run stand in for a
		// grammar the SDK never actually reached.
		return ""
	}
	return err.Error()
}

var corpusNames atomic.Uint64

func corpusName(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, os.Getpid(), corpusNames.Add(1))
}

// ============================================================
// The CLI, as the surface to be compared against
// ============================================================

const cliEnvelope = "Error: invalid sandbox: "

// corpusFindCLI locates the sandlock binary built from this checkout. The Go build
// already resolves libsandlock_ffi.so out of ../target (see cgo_repo.go), so
// the CLI beside it is the same tree; SANDLOCK_CLI overrides that for a run
// against an installed build.
func corpusFindCLI(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SANDLOCK_CLI"); p != "" {
		return p
	}
	var best string
	var bestTime time.Time
	for _, profile := range []string{"debug", "release"} {
		p := filepath.Join("..", "target", profile, "sandlock")
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if best == "" || info.ModTime().After(bestTime) {
			best, bestTime = p, info.ModTime()
		}
	}
	if best == "" {
		t.Skip("no sandlock binary in ../target; build it or set SANDLOCK_CLI to compare the two surfaces")
	}
	return best
}

// cliRefusal offers a value to the flag and returns the refusal, or "".
func cliRefusal(t *testing.T, cli string, knob corpusKnob, value string) string {
	t.Helper()
	// The attached form, as one argument: a value that starts with "-" reads
	// as another flag when it stands on its own, and being turned away by the
	// argument parser is not the grammar's verdict on it.
	cmd := exec.Command(cli, "run", knob.Flag+"="+value, "--", "/bin/true")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run()
	head := strings.TrimSpace(strings.SplitN(stderr.String(), "\n\nCaused by:", 2)[0])
	if !strings.HasPrefix(head, "Error: ") {
		return ""
	}
	return head
}

// cliPolicy launches the same value through the flag and returns the effective
// policy of the sandbox it produced, so the two surfaces can be compared on
// what they built rather than on what either of them was told to build.
func cliPolicy(t *testing.T, cli string, knob corpusKnob, value string) map[string]any {
	t.Helper()
	name := corpusName("cli-parity")
	args := []string{"run", knob.Flag + "=" + value, "--name", name}
	for _, p := range rootfs {
		args = append(args, "--fs-read", p)
	}
	args = append(args, "--", corpusSleep, "30")

	cmd := exec.Command(cli, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the CLI: %v", err)
	}
	defer func() {
		// `sandlock kill` first: a supervisor asked to stop clears its control
		// directory, while one that is only signalled leaves it behind. Here
		// the supervisor is the `sandlock run` process, not this test binary,
		// so naming the sandbox is safe. The process is reaped either way, so
		// no guest outlives the test as an orphan.
		_ = exec.Command(cli, "kill", name).Run()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	return corpusInspect(t, cli, name)
}

// corpusInspect reads a live sandbox's effective policy through the control plane.
func corpusInspect(t *testing.T, cli, name string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		cmd := exec.Command(cli, "inspect", name)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err == nil {
			var doc map[string]any
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("`sandlock inspect %s` returned something other than JSON: %v", name, err)
			}
			return doc
		}
		last = strings.TrimSpace(stderr.String())
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("`sandlock inspect %s` never answered: %s", name, last)
	return nil
}

// corpusDocString reads one leaf out of an effective policy document.
func corpusDocString(doc map[string]any, path []string) *string {
	section, ok := doc[path[0]].(map[string]any)
	if !ok {
		return nil
	}
	s, ok := section[path[1]].(string)
	if !ok {
		return nil
	}
	return &s
}

// ============================================================
// Tests
// ============================================================

// TestCorpusMatchesThisSDK is the guard on everything below: every knob the
// corpus describes must still be a plain string field on Sandbox. Without it a
// renamed field would take its whole grammar out of the comparison silently.
func TestCorpusMatchesThisSDK(t *testing.T) {
	c := corpusLoad(t)
	for name, knob := range c.Knobs {
		t.Run(name, func(t *testing.T) {
			corpusSandbox(t, knob, "")
		})
	}
	for _, entry := range c.Accepted {
		corpusKnobFor(t, c, entry.Knob)
	}
	for _, entry := range c.Rejected {
		corpusKnobFor(t, c, entry.Knob)
	}
}

// TestARejectedValueIsRefusedWithTheCoresOwnSentence compares the two
// languages against each other rather than each against a copy of the answer.
// The corpus prefix pins the verdict, so a refusal for some unrelated reason
// cannot stand in for the grammar's; the CLI comparison pins the rest of the
// sentence, so a binding that reworded the diagnosis fails even where the
// prefix still matches.
func TestARejectedValueIsRefusedWithTheCoresOwnSentence(t *testing.T) {
	c := corpusLoad(t)
	cli := corpusFindCLI(t)
	for _, entry := range c.Rejected {
		t.Run(corpusTestID(entry.Knob, entry.Value), func(t *testing.T) {
			knob := corpusKnobFor(t, c, entry.Knob)
			if why, unreachable := entry.Unreachable["go"]; unreachable {
				// Announced, not silent: the reason is a claim about this SDK
				// and is pinned by TestAnEmptyStringIsThisSDKsSpellingOfUnset.
				t.Skip(why)
			}

			raw := goRefusal(t, knob, entry.Value)
			if raw == "" {
				t.Fatalf("the SDK accepted %q, which no other surface does", entry.Value)
			}
			got := corpusFold(strings.TrimPrefix(raw, goEnvelope), knob.label("go"))

			rawCLI := cliRefusal(t, cli, knob, entry.Value)
			if rawCLI == "" {
				t.Fatalf("the CLI accepted %q, so there is nothing to compare against", entry.Value)
			}
			if !strings.HasPrefix(rawCLI, cliEnvelope) {
				t.Fatalf("the CLI reported something other than the core's verdict: %q", rawCLI)
			}
			want := corpusFold(strings.TrimPrefix(rawCLI, cliEnvelope), knob.label("flag"))

			if got != want {
				t.Fatalf("the two surfaces disagree on %q:\n  Go SDK: %q\n  CLI:    %q", entry.Value, got, want)
			}
			if !strings.HasPrefix(got, entry.Diagnosis) {
				t.Fatalf("expected the grammar's verdict %q, got %q", entry.Diagnosis, got)
			}
			if entry.SDKOnly {
				// Narrative only, and the reason this entry is in the corpus:
				// the deleted go/internal/policy parser took this value.
				t.Logf("%q used to be accepted by the SDK's own parser", entry.Value)
			}
		})
	}
}

// TestAnAcceptedValueMeansTheSameThroughTheSDKAsThroughTheFlag launches the
// same text twice and compares the policy, not the text: a setter that ignored
// its argument, or a binding that rounded the value on the way, shows up as
// two different documents.
func TestAnAcceptedValueMeansTheSameThroughTheSDKAsThroughTheFlag(t *testing.T) {
	requireLandlock(t)
	c := corpusLoad(t)
	cli := corpusFindCLI(t)
	for _, entry := range c.Accepted {
		if !entry.live() {
			continue
		}
		t.Run(corpusTestID(entry.Knob, entry.Value), func(t *testing.T) {
			knob := corpusKnobFor(t, c, entry.Knob)
			if why, unreachable := entry.Unreachable["go"]; unreachable {
				t.Skip(why)
			}

			sb := corpusSandbox(t, knob, entry.Value)
			sb.FSReadable = rootfs
			name := corpusName("go-parity")
			sb.Name = sandlock.Ptr(name)

			proc, err := sb.Spawn(corpusSleep, "30")
			if err != nil {
				t.Fatalf("the SDK refused %q, which the corpus says every surface takes: %v", entry.Value, err)
			}
			// Close kills the guest and releases the handle. `sandlock kill`
			// is deliberately not used: for a CLI-launched sandbox the
			// supervisor is the `sandlock run` process, but for an
			// SDK-launched one it is this test binary.
			defer proc.Close()

			fromSDK := corpusInspect(t, cli, name)
			got := corpusDocString(fromSDK, knob.Profile)
			// Pin the value first. Without this the two documents could agree
			// by both dropping it, which is what a setter that ignored its
			// argument would look like.
			if !corpusSameString(got, entry.Renders) {
				t.Fatalf("the SDK resolved %q to %s, expected %s", entry.Value, corpusShow(got), corpusShow(entry.Renders))
			}

			// Then compare the whole policy against the one the flag produces
			// from the same text. The document is serialized by one core
			// routine whichever surface configured the sandbox, so this
			// compares the policy rather than the words that asked for it, and
			// it covers the fields the corpus does not name.
			fromFlag := cliPolicy(t, cli, knob, entry.Value)
			if !reflect.DeepEqual(fromSDK, fromFlag) {
				t.Fatalf("the SDK and the flag built different policies from %q:\n  SDK:  %s\n  flag: %s",
					entry.Value, corpusJSON(fromSDK), corpusJSON(fromFlag))
			}
		})
	}
}

// TestAnAcceptedValueWhoseGuestCannotRunIsStillTaken keeps the values whose
// policy no guest survives inside the comparison. The document check above
// needs a sandbox that stays up long enough to answer `sandlock inspect`,
// which a one-byte memory ceiling never does; what is left to compare is the
// verdict, and no surface may refuse a value the others take.
func TestAnAcceptedValueWhoseGuestCannotRunIsStillTaken(t *testing.T) {
	c := corpusLoad(t)
	for _, entry := range c.Accepted {
		if entry.live() {
			continue
		}
		t.Run(corpusTestID(entry.Knob, entry.Value), func(t *testing.T) {
			knob := corpusKnobFor(t, c, entry.Knob)
			if why, unreachable := entry.Unreachable["go"]; unreachable {
				t.Skip(why)
			}
			if refusal := goRefusal(t, knob, entry.Value); refusal != "" {
				t.Fatalf("the SDK refused %q, which no other surface does: %s", entry.Value, refusal)
			}
		})
	}
}

// TestAnEmptyStringIsThisSDKsSpellingOfUnset pins the one excuse the corpus
// grants this SDK. A Go struct field of type string has no value left over for
// "not configured", so an empty MaxMemory means the knob was never set and
// never reaches the core, which is why those corpus entries are skipped above.
// That is a claim about the binding, so it is tested rather than assumed: a
// blank value, which the core does have an opinion about, still travels.
func TestAnEmptyStringIsThisSDKsSpellingOfUnset(t *testing.T) {
	requireLandlock(t)
	c := corpusLoad(t)

	excused := map[string]bool{}
	for _, entry := range c.Rejected {
		if _, ok := entry.Unreachable["go"]; ok {
			excused[entry.Knob] = true
		}
	}
	if len(excused) == 0 {
		t.Fatal("the corpus excuses this SDK nowhere, so this test guards nothing; delete it or the excuse")
	}

	for knobName := range excused {
		knob := corpusKnobFor(t, c, knobName)
		t.Run(knobName, func(t *testing.T) {
			// Empty: the knob is not configured, so the sandbox is the same
			// one an untouched field produces and it runs.
			sb := corpusSandbox(t, knob, "")
			sb.FSReadable = rootfs
			res, err := sb.Run(context.Background(), "/bin/true")
			if err != nil {
				t.Fatalf("an empty %s must mean \"unset\", not an empty value handed to the core: %v", knob.Go, err)
			}
			if !res.Success {
				t.Fatalf("want success, got exit=%d stderr=%q", res.ExitCode, res.Stderr)
			}

			// Blank: a value the caller did set, and one the core refuses.
			// Nothing between here and the core may trim it into the case
			// above, which is what "unset" would have to become to leak.
			if refusal := goRefusal(t, knob, " "); refusal == "" {
				t.Fatalf("a blank %s must reach the core and be refused there", knob.Go)
			}
		})
	}
}

// ============================================================
// Small helpers
// ============================================================

// corpusSleep keeps a guest alive long enough to be inspected.
var corpusSleep = corpusFirstExisting("/bin/sleep", "/usr/bin/sleep")

func corpusFirstExisting(candidates ...string) string {
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/bin/sleep"
}

// corpusFold removes the knob name a surface supplied, so what is compared
// afterwards is the core's own sentence.
func corpusFold(sentence, label string) string {
	if label == "" {
		return sentence
	}
	return strings.Replace(sentence, label, "<knob>", 1)
}

// corpusTestID turns a corpus value into a subtest name `go test -run` can
// select.
// Spaces become underscores rather than disappearing: whitespace is part of
// what is being tested, and two entries differing only in it must not collapse.
func corpusTestID(knob, value string) string {
	if value == "" {
		return knob + "/empty"
	}
	return knob + "/" + strings.ReplaceAll(value, " ", "_")
}

func corpusSameString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// corpusJSON renders a policy document for a failure message.
func corpusJSON(doc map[string]any) string {
	out, err := json.Marshal(doc)
	if err != nil {
		return fmt.Sprintf("%v", doc)
	}
	return string(out)
}

func corpusShow(s *string) string {
	if s == nil {
		return "nothing"
	}
	return fmt.Sprintf("%q", *s)
}
