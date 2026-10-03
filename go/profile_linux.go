//go:build linux

package sandlock

/*
#include <stdlib.h>
#include "sandlock.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"
)

// resolvedProfile mirrors the JSON from sandlock_profile_resolve. Unknown keys
// are an error: a profile field this SDK cannot express must not be dropped.
type resolvedProfile struct {
	HTTPCA             string            `json:"http_ca"`
	HTTPKey            string            `json:"http_key"`
	FSStorage          string            `json:"fs_storage"`
	Workdir            string            `json:"workdir"`
	RandomSeed         *uint64           `json:"random_seed"`
	TimeStart          string            `json:"time_start"`
	DeterministicDirs  bool              `json:"deterministic_dirs"`
	NoRandomizeMemory  bool              `json:"no_randomize_memory"`
	Env                map[string]string `json:"env"`
	Cwd                string            `json:"cwd"`
	UID                *int              `json:"uid"`
	GID                *int              `json:"gid"`
	CleanEnv           bool              `json:"clean_env"`
	NoCoredump         bool              `json:"no_coredump"`
	NoHugePages        bool              `json:"no_huge_pages"`
	FSReadable         []string          `json:"fs_readable"`
	FSWritable         []string          `json:"fs_writable"`
	FSDenied           []string          `json:"fs_denied"`
	Chroot             string            `json:"chroot"`
	FSMount            map[string]string `json:"fs_mount"`
	FSMountRO          map[string]string `json:"fs_mount_ro"`
	OnExit             string            `json:"on_exit"`
	OnError            string            `json:"on_error"`
	NetAllowBind       []any             `json:"net_allow_bind"`
	NetDenyBind        []any             `json:"net_deny_bind"`
	NetAllow           []string          `json:"net_allow"`
	NetDeny            []string          `json:"net_deny"`
	PortRemap          bool              `json:"port_remap"`
	HTTPPorts          []uint16          `json:"http_ports"`
	HTTPAllow          []string          `json:"http_allow"`
	HTTPDeny           []string          `json:"http_deny"`
	ExtraAllowSyscalls []string          `json:"extra_allow_syscalls"`
	ExtraDenySyscalls  []string          `json:"extra_deny_syscalls"`
	MaxMemory          string            `json:"max_memory"`
	MaxProcesses       uint32            `json:"max_processes"`
	MaxOpenFiles       uint32            `json:"max_open_files"`
	MaxCPU             uint8             `json:"max_cpu"`
	MaxDisk            string            `json:"max_disk"`
	GPUDevices         []uint32          `json:"gpu_devices"`
	CPUCores           []uint32          `json:"cpu_cores"`
	NumCPUs            uint32            `json:"num_cpus"`
}

// ParseProfile builds a Sandbox from profile TOML using sandlock's own
// parser, the one the CLI uses, so a profile means the same thing to both.
func ParseProfile(toml string) (*Sandbox, error) {
	if hasNUL(toml) {
		return nil, ErrInvalidString
	}
	cToml := C.CString(toml)
	defer C.free(unsafe.Pointer(cToml))
	var errMsg *C.char
	out := C.sandlock_profile_resolve(cToml, &errMsg)
	if out == nil {
		msg := "invalid profile"
		if errMsg != nil {
			msg = C.GoString(errMsg)
			C.sandlock_string_free(errMsg)
		}
		return nil, fmt.Errorf("sandlock: %s", msg)
	}
	defer C.sandlock_string_free(out)

	dec := json.NewDecoder(strings.NewReader(C.GoString(out)))
	dec.DisallowUnknownFields()
	// Bind specs mix ports and range strings; UseNumber keeps ports textual.
	dec.UseNumber()
	var r resolvedProfile
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("sandlock: profile not supported by the Go SDK: %w", err)
	}
	onExit, err := parseBranchAction(r.OnExit)
	if err != nil {
		return nil, err
	}
	onError, err := parseBranchAction(r.OnError)
	if err != nil {
		return nil, err
	}
	return &Sandbox{
		FSReadable: r.FSReadable, FSWritable: r.FSWritable, FSDenied: r.FSDenied,
		Workdir: r.Workdir, Cwd: r.Cwd, Chroot: r.Chroot,
		FSMount: r.FSMount, FSMountRO: r.FSMountRO,
		NetAllow: r.NetAllow, NetDeny: r.NetDeny,
		NetAllowBind: bindSpecs(r.NetAllowBind), NetDenyBind: bindSpecs(r.NetDenyBind),
		PortRemap: r.PortRemap,
		HTTPAllow: r.HTTPAllow, HTTPDeny: r.HTTPDeny, HTTPPorts: r.HTTPPorts,
		HTTPCAFile: r.HTTPCA, HTTPKeyFile: r.HTTPKey,
		MaxMemory: r.MaxMemory, MaxDisk: r.MaxDisk, MaxProcesses: r.MaxProcesses,
		MaxCPU: r.MaxCPU, MaxOpenFiles: r.MaxOpenFiles, CPUCores: r.CPUCores,
		NumCPUs: r.NumCPUs, GPUDevices: r.GPUDevices,
		ExtraAllowSyscalls: r.ExtraAllowSyscalls, ExtraDenySyscalls: r.ExtraDenySyscalls,
		RandomSeed: r.RandomSeed, TimeStart: r.TimeStart,
		NoRandomizeMemory: r.NoRandomizeMemory, NoHugePages: r.NoHugePages,
		DeterministicDirs: r.DeterministicDirs,
		CleanEnv:          r.CleanEnv, Env: r.Env,
		UID: r.UID, GID: r.GID, NoCoredump: r.NoCoredump,
		FSStorage: r.FSStorage, OnExit: onExit, OnError: onError,
	}, nil
}

// LoadProfileFile reads and parses the profile at path.
func LoadProfileFile(path string) (*Sandbox, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sandlock: %w", err)
	}
	sb, err := ParseProfile(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return sb, nil
}

// LoadProfile loads the named profile from ProfileDir.
func LoadProfile(name string) (*Sandbox, error) {
	dir, err := ProfileDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name+".toml")
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("sandlock: profile not found: %s", path)
	}
	return LoadProfileFile(path)
}

// ProfileDir returns ~/.config/sandlock/profiles, resolved as the CLI
// resolves it; it fails when there is no usable home directory.
func ProfileDir() (string, error) {
	var errMsg *C.char
	p := C.sandlock_profile_dir(&errMsg)
	if p == nil {
		msg := "no profile directory"
		if errMsg != nil {
			msg = C.GoString(errMsg)
			C.sandlock_string_free(errMsg)
		}
		return "", fmt.Errorf("sandlock: %s", msg)
	}
	defer C.sandlock_string_free(p)
	return C.GoString(p), nil
}

// ListProfiles returns the sorted names of the profiles in ProfileDir.
func ListProfiles() ([]string, error) {
	dir, err := ProfileDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sandlock: %w", err)
	}
	var names []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".toml"); ok && e.Type().IsRegular() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func parseBranchAction(s string) (BranchAction, error) {
	switch s {
	case "":
		return BranchActionDefault, nil
	case "commit":
		return BranchActionCommit, nil
	case "abort":
		return BranchActionAbort, nil
	case "keep":
		return BranchActionKeep, nil
	case "defer":
		return BranchActionDefer, nil
	}
	return 0, fmt.Errorf("sandlock: unknown branch action %q", s)
}

func bindSpecs(specs []any) []string {
	if specs == nil {
		return nil
	}
	out := make([]string, len(specs))
	for i, s := range specs {
		out[i] = fmt.Sprint(s)
	}
	return out
}
