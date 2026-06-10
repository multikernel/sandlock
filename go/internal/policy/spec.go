// Package policy holds pure, platform-independent parsing helpers shared by
// the sandlock Go SDK. It deliberately has no cgo dependency so the logic can
// be unit-tested on any OS, separate from the Linux-only FFI bindings.
package policy

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	sizeRe = regexp.MustCompile(`^\s*(\d+(?:\.\d+)?)\s*([KMGTkmgt])?\s*$`)
	portRe = regexp.MustCompile(`^(\d+)(?:-(\d+))?$`)
)

var sizeUnits = map[byte]uint64{
	'K': 1 << 10,
	'M': 1 << 20,
	'G': 1 << 30,
	'T': 1 << 40,
}

// ParseMemory parses a human-friendly size string into bytes. It accepts a
// plain integer (bytes) or a value suffixed with K, M, G, or T (case
// insensitive), e.g. "512M", "1G", "100K". Mirrors the Python SDK's
// parse_memory_size so the two SDKs agree byte-for-byte.
func ParseMemory(s string) (uint64, error) {
	m := sizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid memory size: %q", s)
	}
	value, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory size: %q", s)
	}
	if m[2] != "" {
		unit := sizeUnits[strings.ToUpper(m[2])[0]]
		value *= float64(unit)
	}
	return uint64(value), nil
}

// ParsePorts expands a list of port specs into a sorted, de-duplicated list of
// individual port numbers. Each spec is a comma-separated list of single ports
// ("80") or inclusive ranges ("8000-9000"), e.g. "8080,9000-9005" (matching
// the CLI's --net-allow-bind grammar). Values must fall in [0, 65535].
func ParsePorts(specs []string) ([]uint16, error) {
	set := map[uint16]struct{}{}
	for _, spec := range specs {
		for _, part := range strings.Split(spec, ",") {
			m := portRe.FindStringSubmatch(strings.TrimSpace(part))
			if m == nil {
				return nil, fmt.Errorf("invalid port spec: %q", part)
			}
			lo, err := strconv.Atoi(m[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port spec: %q", part)
			}
			hi := lo
			if m[2] != "" {
				hi, err = strconv.Atoi(m[2])
				if err != nil {
					return nil, fmt.Errorf("invalid port spec: %q", part)
				}
			}
			if lo > hi || lo < 0 || hi > 65535 {
				return nil, fmt.Errorf("invalid port range: %q", part)
			}
			for p := lo; p <= hi; p++ {
				set[uint16(p)] = struct{}{}
			}
		}
	}
	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

// ParseTimeStart resolves a time-virtualization start point to whole seconds
// since the Unix epoch. It accepts an RFC 3339 / ISO 8601 timestamp
// (e.g. "2000-01-01T00:00:00Z") or a plain integer/float number of seconds.
func ParseTimeStart(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f < 0 {
			return 0, fmt.Errorf("invalid time_start: %q", s)
		}
		return uint64(f), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, fmt.Errorf("invalid time_start: %q (want RFC3339 or unix seconds)", s)
	}
	return uint64(t.Unix()), nil
}
