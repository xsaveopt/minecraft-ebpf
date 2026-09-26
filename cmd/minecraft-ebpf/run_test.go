package main

import (
	"strings"
	"testing"
)

func TestRunDeclaresEveryDaemonFlagWithItsDefault(t *testing.T) {
	res := runCLI(t, "run", "-h")
	if res.code != 0 {
		t.Fatalf("exit code %d, want 0; stderr:\n%s", res.code, res.stderr)
	}
	want := map[string]string{
		"iface":               `"eth0"`,
		"port":                "25565",
		"ttl":                 "10m0s",
		"metrics-addr":        `":9464"`,
		"cgroup":              `"/sys/fs/cgroup"`,
		"pin-path":            `"/sys/fs/bpf/minecraft"`,
		"status-per-min":      "60",
		"status-burst":        "20",
		"login-per-min":       "20",
		"login-burst":         "8",
		"tcp-global-rate":     "5000",
		"tcp-global-burst":    "15000",
		"tcp-max-open-per-ip": "8",
		"conn-pps":            "300",
		"conn-burst":          "600",
		"conn-bps":            "524288",
		"conn-byte-burst":     "1048576",
		"conn-new-rate":       "10",
		"conn-new-burst":      "20",
		"health-window":       "1m0s",
		"health-threshold":    "100",
		"health-blacklist":    "5m0s",
		"map-size-interval":   "30s",
	}
	blocks := strings.Split(res.stderr, "\n  -")
	found := make(map[string]string, len(blocks))
	for _, b := range blocks[1:] {
		name, _, _ := strings.Cut(b, " ")
		name, _, _ = strings.Cut(name, "\n")
		found[name] = b
	}
	if len(found) != len(want) {
		t.Errorf("run declares %d flags, want %d:\n%s", len(found), len(want), res.stderr)
	}
	for name, def := range want {
		block, ok := found[name]
		if !ok {
			t.Errorf("run does not declare -%s", name)
			continue
		}
		if !strings.Contains(block, "(default "+def+")") {
			t.Errorf("-%s does not default to %s:\n%s", name, def, block)
		}
	}
}

func TestRunRejectsUnknownFlagsBeforeTouchingTheKernel(t *testing.T) {
	res := runCLI(t, "run", "--bogus")
	if res.code != 2 {
		t.Errorf("exit code %d, want 2", res.code)
	}
	if !strings.Contains(res.stderr, "flag provided but not defined: -bogus") {
		t.Errorf("stderr does not name the bad flag:\n%s", res.stderr)
	}
	for _, s := range []string{"rlimit:", "load:"} {
		if strings.Contains(res.stderr, s) {
			t.Errorf("run reached %s despite a bad flag:\n%s", s, res.stderr)
		}
	}
}

func TestRunRejectsMalformedFlagValues(t *testing.T) {
	cases := map[string][]string{
		"port":          {"--port", "http"},
		"ttl":           {"--ttl", "forever"},
		"conn-pps":      {"--conn-pps", "-1"},
		"health-window": {"--health-window", "60"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			res := runCLI(t, append([]string{"run"}, args...)...)
			if res.code != 2 {
				t.Errorf("exit code %d, want 2", res.code)
			}
			if !strings.Contains(res.stderr, "invalid value") || !strings.Contains(res.stderr, "-"+name) {
				t.Errorf("stderr does not reject -%s:\n%s", name, res.stderr)
			}
		})
	}
}
