package policy

import (
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
