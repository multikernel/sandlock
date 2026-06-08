package policy

import (
	"reflect"
	"testing"
)

func TestParseMemory(t *testing.T) {
	cases := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{"1024", 1024, false},
		{"512M", 512 << 20, false},
		{"1G", 1 << 30, false},
		{"100K", 100 << 10, false},
		{"2T", 2 << 40, false},
		{"1g", 1 << 30, false},
		{" 256M ", 256 << 20, false},
		{"1.5G", uint64(1.5 * float64(1<<30)), false},
		{"", 0, true},
		{"abc", 0, true},
		{"10X", 0, true},
	}
	for _, c := range cases {
		got, err := ParseMemory(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseMemory(%q): expected error, got %d", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMemory(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseMemory(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in      []string
		want    []uint16
		wantErr bool
	}{
		{[]string{"80"}, []uint16{80}, false},
		{[]string{"8000-8002"}, []uint16{8000, 8001, 8002}, false},
		{[]string{"443", "80", "443"}, []uint16{80, 443}, false},
		{[]string{"3000-3001", "3001-3002"}, []uint16{3000, 3001, 3002}, false},
		{[]string{"8080,9090"}, []uint16{8080, 9090}, false},
		{[]string{"8080,9000-9002", "443"}, []uint16{443, 8080, 9000, 9001, 9002}, false},
		{nil, []uint16{}, false},
		{[]string{"70000"}, nil, true},
		{[]string{"10-5"}, nil, true},
		{[]string{"x"}, nil, true},
		{[]string{"8080,"}, nil, true},
	}
	for _, c := range cases {
		got, err := ParsePorts(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParsePorts(%v): expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePorts(%v): unexpected error: %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParsePorts(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseTimeStart(t *testing.T) {
	cases := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{"0", 0, false},
		{"946684800", 946684800, false},
		{"2000-01-01T00:00:00Z", 946684800, false},
		{"", 0, true},
		{"not-a-time", 0, true},
		{"-5", 0, true},
	}
	for _, c := range cases {
		got, err := ParseTimeStart(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseTimeStart(%q): expected error, got %d", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTimeStart(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseTimeStart(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
