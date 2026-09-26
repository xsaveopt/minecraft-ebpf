package main

import (
	"strings"
	"testing"
)

func TestHealthExitsOneWhenTheMapIsNotPinned(t *testing.T) {
	for _, extra := range [][]string{nil, {"--all"}} {
		args := append([]string{"health", "--pin-path", missingPinPath}, extra...)
		res := runCLI(t, args...)
		if res.code != 1 {
			t.Errorf("%v: exit code %d, want 1", args, res.code)
		}
		if !strings.HasPrefix(res.stderr, "open health:") {
			t.Errorf("%v: stderr = %q, want an open health error", args, res.stderr)
		}
		if res.stdout != "" {
			t.Errorf("%v: stdout = %q, want no table header before the map opens", args, res.stdout)
		}
	}
}

func TestStatsExitsOneWhenTheMapIsNotPinned(t *testing.T) {
	for _, extra := range [][]string{nil, {"--json"}} {
		args := append([]string{"stats", "--pin-path", missingPinPath}, extra...)
		res := runCLI(t, args...)
		if res.code != 1 {
			t.Errorf("%v: exit code %d, want 1", args, res.code)
		}
		if !strings.HasPrefix(res.stderr, "stats:") {
			t.Errorf("%v: stderr = %q, want a stats error", args, res.stderr)
		}
		if res.stdout != "" {
			t.Errorf("%v: stdout = %q, want nothing", args, res.stdout)
		}
	}
}

func TestStatsRejectsAMalformedWatchInterval(t *testing.T) {
	res := runCLI(t, "stats", "--watch", "often")
	if res.code != 2 {
		t.Errorf("exit code %d, want 2", res.code)
	}
	if !strings.Contains(res.stderr, "invalid value") || !strings.Contains(res.stderr, "-watch") {
		t.Errorf("stderr does not reject -watch:\n%s", res.stderr)
	}
}
