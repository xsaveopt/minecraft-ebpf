package main

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/xsaveopt/minecraft-ebpf/internal/metrics"
)

func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	done := make(chan struct{})
	var outBuf, errBuf []byte
	go func() {
		outBuf, _ = io.ReadAll(outR)
		errBuf, _ = io.ReadAll(errR)
		close(done)
	}()
	fn()
	_ = outW.Close()
	_ = errW.Close()
	<-done
	os.Stdout, os.Stderr = origOut, origErr
	return string(outBuf), string(errBuf)
}

func TestParseIPv4Key(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    [4]byte
		wantErr string
	}{
		{name: "dotted quad", in: "10.0.0.1", want: [4]byte{10, 0, 0, 1}},
		{name: "broadcast", in: "255.255.255.255", want: [4]byte{255, 255, 255, 255}},
		{name: "ipv4 in ipv6 form", in: "::ffff:10.0.0.1", want: [4]byte{10, 0, 0, 1}},
		{name: "empty", in: "", wantErr: "invalid IP"},
		{name: "not an ip", in: "banana", wantErr: "invalid IP"},
		{name: "ipv6", in: "2001:db8::1", wantErr: "not an IPv4 address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIPv4Key(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClearReportsAnUnreachablePinPathAsAnError(t *testing.T) {
	path := filepath.Join(missingPinPath, "tcp_whitelist")
	if _, err := clearMap(path); err == nil {
		t.Error("clearMap on a missing pin returned no error")
	}
	if _, err := clearMapKey(path, [4]byte{10, 0, 0, 1}); err == nil {
		t.Error("clearMapKey on a missing pin returned no error")
	}
}

func TestInfoCountersReportMinusOneWhenNothingIsPinned(t *testing.T) {
	if n := mapEntryCount(missingPinPath, "tcp_whitelist"); n != -1 {
		t.Errorf("mapEntryCount = %d, want -1", n)
	}
	if n := blacklistedNow(missingPinPath); n != -1 {
		t.Errorf("blacklistedNow = %d, want -1", n)
	}
}

func TestInspectPrintsAnOpenErrorForEveryMapItCannotReach(t *testing.T) {
	key := [4]byte{10, 0, 0, 1}
	stdout, _ := captureOutput(t, func() {
		inspectTimestamp(missingPinPath, "tcp_whitelist", key, 0)
		inspectCount(missingPinPath, "tcp_open_count", key)
		inspectRatelimit(missingPinPath, "login_ratelimit", key, 0)
		inspectConnLimit(missingPinPath, "conn_ratelimit", key, 0)
		inspectHealth(missingPinPath, "health", key, 0)
		inspectDropHistory(missingPinPath, "ip_drop_history", key, 0)
	})

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 6 {
		t.Fatalf("got %d lines, want 6:\n%s", len(lines), stdout)
	}
	for _, name := range []string{
		"tcp_whitelist", "tcp_open_count", "login_ratelimit",
		"conn_ratelimit", "health", "ip_drop_history",
	} {
		if !strings.Contains(stdout, name) {
			t.Errorf("output does not mention %s:\n%s", name, stdout)
		}
	}
	for _, line := range lines {
		if !strings.Contains(line, "(open:") {
			t.Errorf("line %q does not report the open failure", line)
		}
	}
}

func TestInspectLinePadsTheLabelColumn(t *testing.T) {
	stdout, _ := captureOutput(t, func() {
		inspectLine("health", "anomalies=1")
	})
	want := "  health" + strings.Repeat(" ", inspectLabelWidth-len("health")) + " anomalies=1\n"
	if stdout != want {
		t.Fatalf("got %q, want %q", stdout, want)
	}
}

func TestDumpReportsAnUnreachablePinPathOnStderr(t *testing.T) {
	stdout, stderr := captureOutput(t, func() {
		dumpTimestampMap(missingPinPath, "tcp_whitelist")
		dumpCountMap(missingPinPath, "tcp_open_count")
		dumpRatelimitMap(missingPinPath, "login_ratelimit")
		dumpHealthMap(missingPinPath, "health")
		dumpDropHistoryMap(missingPinPath, "ip_drop_history")
	})
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing when no map can be opened", stdout)
	}
	for _, name := range []string{
		"tcp_whitelist", "tcp_open_count", "login_ratelimit", "health", "ip_drop_history",
	} {
		if !strings.Contains(stderr, "open "+name+":") {
			t.Errorf("stderr does not report %s:\n%s", name, stderr)
		}
	}
}

func TestTopRejectsUnknownMapsAndReasons(t *testing.T) {
	if _, err := topFromMap(missingPinPath, "banana", 10, ""); err == nil ||
		!strings.Contains(err.Error(), "unknown map: banana") {
		t.Errorf("err = %v, want unknown map", err)
	}
	if _, err := topFromMap(missingPinPath, "drop-history", 10, "banana"); err == nil ||
		!strings.Contains(err.Error(), "unknown reason: banana") {
		t.Errorf("err = %v, want unknown reason", err)
	}
	for _, reason := range dropReasonNames {
		if _, err := topFromMap(missingPinPath, "drop-history", 10, reason); err == nil ||
			strings.Contains(err.Error(), "unknown reason") {
			t.Errorf("reason %s was rejected: %v", reason, err)
		}
	}
}

func TestTopKnowsOnlyRealPinnedMaps(t *testing.T) {
	pinned := map[string]bool{
		"tcp_whitelist": true, "tcp_established": true, "tcp_syn_seen": true,
		"tcp_open_count": true, "status_ratelimit": true, "login_ratelimit": true,
		"syn_ratelimit": true, "conn_ratelimit": true, "health": true,
		"ip_drop_history": true, "tcp_global_ratelimit": true, "stats": true,
	}
	kinds := map[string]bool{
		"timestamp": true, "count": true, "ratelimit": true,
		"conn-limit": true, "health": true, "drop-reasons": true,
	}
	for name, mt := range topMapKinds {
		if !pinned[mt.pinned] {
			t.Errorf("top map %s points at %q, which is not a pinned map", name, mt.pinned)
		}
		if !kinds[mt.kind] {
			t.Errorf("top map %s has kind %q, which topFromMap does not decode", name, mt.kind)
		}
	}
	for _, name := range perIPMaps {
		if !pinned[name] {
			t.Errorf("info lists %q, which is not a pinned map", name)
		}
	}
}

func TestStatLabelsMatchTheCollectorSlots(t *testing.T) {
	if len(statLabels) != metrics.StatMax {
		t.Fatalf("statLabels has %d entries, collector expects %d", len(statLabels), metrics.StatMax)
	}
	want := map[int]string{
		metrics.StatPassTCP:                "pass_tcp",
		metrics.StatTCPEstablishedInserts:  "tcp_established_inserts",
		metrics.StatTCPL7Promoted:          "tcp_l7_promoted",
		metrics.StatTCPL7MatchNoEst:        "tcp_l7_match_no_est",
		metrics.StatTCPHandshakeStatusSeen: "tcp_handshake_status_seen",
		metrics.StatTCPHandshakeLoginSeen:  "tcp_handshake_login_seen",
		metrics.StatDropTCPNoSyn:           "drop_tcp_no_syn",
		metrics.StatDropTCPTooManyOpen:     "drop_tcp_too_many_open",
		metrics.StatDropTCPGlobalRatelimit: "drop_tcp_global_ratelimit",
		metrics.StatDropStatusRatelimit:    "drop_status_ratelimit",
		metrics.StatDropLoginRatelimit:     "drop_login_ratelimit",
		metrics.StatDropMalformedHandshake: "drop_malformed_handshake",
		metrics.StatDropTCPUnhealthy:       "drop_tcp_unhealthy",
		metrics.StatDropTCPBadFlags:        "drop_tcp_bad_flags",
		metrics.StatDropConnRatelimit:      "drop_conn_ratelimit",
		metrics.StatDropTCPConnRate:        "drop_tcp_conn_rate",
	}
	if len(want) != metrics.StatMax {
		t.Fatalf("this test pins %d slots, collector has %d", len(want), metrics.StatMax)
	}
	for slot, label := range want {
		if statLabels[slot] != label {
			t.Errorf("slot %d is %q, want %q", slot, statLabels[slot], label)
		}
	}
}

func TestDropReasonNamesMatchTheDatapathEnum(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "bpf", "shared", "maps.h"))
	if err != nil {
		t.Fatalf("read maps.h: %v", err)
	}
	re := regexp.MustCompile(`DROP_REASON_([A-Z0-9_]+)\s*=\s*(\d+)`)
	matches := re.FindAllStringSubmatch(string(raw), -1)
	if len(matches) != len(dropReasonNames) {
		t.Fatalf("maps.h declares %d drop reasons, Go names %d", len(matches), len(dropReasonNames))
	}
	for _, m := range matches {
		idx, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("parse index %q: %v", m[2], err)
		}
		if idx < 0 || idx >= len(dropReasonNames) {
			t.Fatalf("DROP_REASON_%s has index %d, outside the Go name table", m[1], idx)
		}
		if got, want := dropReasonNames[idx], strings.ToLower(m[1]); got != want {
			t.Errorf("slot %d is named %q in Go and %q in maps.h", idx, got, want)
		}
	}
}
