package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	hotIP  = "192.0.2.7"
	coldIP = "198.51.100.8"
	idleIP = "203.0.113.9"
)

func pinnedDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("pinning BPF maps needs root")
	}
	_ = rlimit.RemoveMemlock()
	dir := t.TempDir()
	if err := unix.Mount("bpf", dir, "bpf", 0, ""); err != nil {
		t.Skipf("cannot mount bpffs: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	return dir
}

func pinMap(t *testing.T, dir, name string, spec *ebpf.MapSpec) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("kernel refused to create map %s: %v", name, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := m.Pin(filepath.Join(dir, name)); err != nil {
		t.Fatalf("pin %s: %v", name, err)
	}
	return m
}

func pinIPMap(t *testing.T, dir, name string, valueSize uint32) *ebpf.Map {
	t.Helper()
	return pinMap(t, dir, name, &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  valueSize,
		MaxEntries: 64,
	})
}

func putIP(t *testing.T, m *ebpf.Map, ip string, value any) {
	t.Helper()
	key := mustIPKey(t, ip)
	if err := m.Put(&key, value); err != nil {
		t.Fatalf("put %s: %v", ip, err)
	}
}

func pinStats(t *testing.T, dir string, totals map[int]uint64) *ebpf.Map {
	t.Helper()
	m := pinMap(t, dir, "stats", &ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: uint32(len(statLabels)),
	})
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible cpus: %v", err)
	}
	for slot, total := range totals {
		vals := make([]uint64, ncpu)
		vals[0] = total
		if ncpu > 1 && total > 1 {
			vals[0] = total - 1
			vals[ncpu-1] = 1
		}
		k := uint32(slot)
		if err := m.Put(&k, vals); err != nil {
			t.Fatalf("put stat %d: %v", slot, err)
		}
	}
	return m
}

type fixture struct {
	dir string
	now uint64
}

func pinEveryMap(t *testing.T) fixture {
	t.Helper()
	dir := pinnedDir(t)
	now := bootTimeNS()
	const sec = uint64(1_000_000_000)

	wl := pinIPMap(t, dir, "tcp_whitelist", 8)
	putIP(t, wl, hotIP, now-5*sec)
	putIP(t, wl, coldIP, now-90*sec)

	est := pinIPMap(t, dir, "tcp_established", 8)
	putIP(t, est, hotIP, now-30*sec)

	pinIPMap(t, dir, "tcp_syn_seen", 8)

	open := pinIPMap(t, dir, "tcp_open_count", 8)
	putIP(t, open, hotIP, uint64(3))
	putIP(t, open, coldIP, uint64(7))
	putIP(t, open, idleIP, uint64(1))

	status := pinIPMap(t, dir, "status_ratelimit", 16)
	putIP(t, status, hotIP, fakeRatelimit{Tokens: 2, LastRefillNS: now - 4*sec})
	putIP(t, status, coldIP, fakeRatelimit{Tokens: 10, LastRefillNS: now})

	pinIPMap(t, dir, "login_ratelimit", 16)
	pinIPMap(t, dir, "syn_ratelimit", 16)

	conn := pinIPMap(t, dir, "conn_ratelimit", 32)
	putIP(t, conn, hotIP, fakeConnLimit{PktTokens: 1, PktLastNS: now, ByteTokens: 512, ByteLastNS: now})
	putIP(t, conn, coldIP, fakeConnLimit{PktTokens: 9, PktLastNS: now, ByteTokens: 4096, ByteLastNS: now})

	health := pinIPMap(t, dir, "health", 24)
	putIP(t, health, hotIP, fakeHealth{Anomalies: 9, WindowStartNS: now - 20*sec, BlacklistUntilNS: now + 120*sec})
	putIP(t, health, coldIP, fakeHealth{Anomalies: 3, WindowStartNS: now - 20*sec, BlacklistUntilNS: now - sec})

	drops := pinIPMap(t, dir, "ip_drop_history", 96)
	var hot, cold fakeDropHistory
	hot.FirstDropNS, hot.LastDropNS = now-60*sec, now-sec
	hot.Counts[0] = 5
	cold.FirstDropNS, cold.LastDropNS = now-60*sec, now-sec
	cold.Counts[3] = 2
	cold.Counts[4] = 1
	putIP(t, drops, hotIP, hot)
	putIP(t, drops, coldIP, cold)

	pinStats(t, dir, map[int]uint64{0: 100, 6: 4, 9: 3, 13: 2, 3: 50})
	return fixture{dir: dir, now: now}
}

func topIPs(rows []topRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.IP
	}
	return out
}

func sameIPs(got, want []string) bool {
	return strings.Join(got, ",") == strings.Join(want, ",")
}

func TestTopRanksEachMapKind(t *testing.T) {
	f := pinEveryMap(t)

	cases := []struct {
		which  string
		n      int
		reason string
		want   []string
	}{
		{"open-count", 2, "", []string{coldIP, hotIP}},
		{"open-count", 0, "", []string{coldIP, hotIP, idleIP}},
		{"whitelist", 10, "", []string{hotIP, coldIP}},
		{"status-ratelimit", 10, "", []string{hotIP, coldIP}},
		{"conn-ratelimit", 10, "", []string{hotIP, coldIP}},
		{"health", 10, "", []string{hotIP, coldIP}},
		{"drop-history", 10, "", []string{hotIP, coldIP}},
		{"drop-history", 10, "login_ratelimit", []string{coldIP, hotIP}},
		{"login-ratelimit", 10, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.which+"/"+tc.reason, func(t *testing.T) {
			rows, err := topFromMap(f.dir, tc.which, tc.n, tc.reason)
			if err != nil {
				t.Fatalf("top: %v", err)
			}
			if got := topIPs(rows); !sameIPs(got, tc.want) {
				t.Fatalf("ranked %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTopDecodesTheValuesOfEachMapKind(t *testing.T) {
	f := pinEveryMap(t)

	rows, err := topFromMap(f.dir, "open-count", 1, "")
	if err != nil {
		t.Fatalf("top: %v", err)
	}
	if rows[0].Count != 7 || rows[0].Display != "count=7" {
		t.Errorf("open-count row %+v, want count 7", rows[0])
	}

	rows, err = topFromMap(f.dir, "whitelist", 1, "")
	if err != nil {
		t.Fatalf("top: %v", err)
	}
	if rows[0].AgeSeconds < 5 || rows[0].AgeSeconds > 6 || !strings.HasPrefix(rows[0].Display, "age=5s") {
		t.Errorf("whitelist row %+v, want an age of five seconds", rows[0])
	}

	rows, err = topFromMap(f.dir, "health", 0, "")
	if err != nil {
		t.Fatalf("top: %v", err)
	}
	if !rows[0].Blacklisted || rows[0].Anomalies != 9 || !strings.Contains(rows[0].Display, "BLACKLISTED unblock_in=") {
		t.Errorf("blacklisted health row %+v", rows[0])
	}
	if rows[1].Blacklisted || strings.Contains(rows[1].Display, "BLACKLISTED") {
		t.Errorf("health row with an expired ban reported as blacklisted: %+v", rows[1])
	}

	rows, err = topFromMap(f.dir, "conn-ratelimit", 1, "")
	if err != nil {
		t.Fatalf("top: %v", err)
	}
	if rows[0].Tokens != 1 || !strings.Contains(rows[0].Display, "byte_tokens=512") {
		t.Errorf("conn-ratelimit row %+v", rows[0])
	}

	rows, err = topFromMap(f.dir, "drop-history", 0, "")
	if err != nil {
		t.Fatalf("top: %v", err)
	}
	cold := rows[1]
	if cold.Total != 3 || cold.ByReason["status_ratelimit"] != 2 || cold.ByReason["login_ratelimit"] != 1 || len(cold.ByReason) != 2 {
		t.Errorf("drop-history row %+v, want total 3 split across status and login", cold)
	}
	if cold.Display != "total=3 status_ratelimit=2,login_ratelimit=1" {
		t.Errorf("drop-history display %q", cold.Display)
	}
}

func TestTopCommandPrintsRowsOrEmpty(t *testing.T) {
	f := pinEveryMap(t)

	res := runCLI(t, "top", "--pin-path", f.dir, "--map", "open-count", "-n", "1")
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	if fields := strings.Fields(res.stdout); len(fields) != 2 || fields[0] != coldIP || fields[1] != "count=7" {
		t.Errorf("stdout = %q, want the single hottest row", res.stdout)
	}

	res = runCLI(t, "top", "--pin-path", f.dir, "--map", "syn-ratelimit")
	if res.code != 0 || strings.TrimSpace(res.stdout) != "(empty)" {
		t.Errorf("empty map printed %q (exit %d), want (empty)", res.stdout, res.code)
	}
}

func dataLines(out string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		rows = append(rows, strings.Fields(line))
	}
	return rows
}

func rowFor(rows [][]string, ip string) []string {
	for _, r := range rows {
		if len(r) > 0 && r[0] == ip {
			return r
		}
	}
	return nil
}

func TestDumpPrintsEveryEntryOfEachMap(t *testing.T) {
	f := pinEveryMap(t)

	stdout, stderr := captureOutput(t, func() { dumpCountMap(f.dir, "tcp_open_count") })
	rows := dataLines(stdout)
	if stderr != "" || strings.Join(rows[0], " ") != "IP OPEN" || len(rows) != 4 {
		t.Fatalf("count dump:\n%s\nstderr: %s", stdout, stderr)
	}
	if r := rowFor(rows, coldIP); len(r) != 2 || r[1] != "7" {
		t.Errorf("count row %v, want 7", r)
	}

	stdout, _ = captureOutput(t, func() { dumpTimestampMap(f.dir, "tcp_whitelist") })
	if r := rowFor(dataLines(stdout), coldIP); len(r) != 2 || r[1] != "1m30s" {
		t.Errorf("timestamp row %v, want an age of 1m30s", r)
	}

	stdout, _ = captureOutput(t, func() { dumpRatelimitMap(f.dir, "status_ratelimit") })
	if r := rowFor(dataLines(stdout), hotIP); len(r) != 3 || r[1] != "2" || !strings.HasPrefix(r[2], "4") {
		t.Errorf("ratelimit row %v, want 2 tokens refilled about 4s ago", r)
	}

	stdout, _ = captureOutput(t, func() { dumpHealthMap(f.dir, "health") })
	rows = dataLines(stdout)
	if r := rowFor(rows, hotIP); len(r) != 5 || r[1] != "9" || r[3] != "in" {
		t.Errorf("blacklisted health row %v", r)
	}
	if r := rowFor(rows, coldIP); len(r) != 4 || r[1] != "3" || r[3] != "-" {
		t.Errorf("expired health row %v, want no blacklist", r)
	}

	stdout, _ = captureOutput(t, func() { dumpDropHistoryMap(f.dir, "ip_drop_history") })
	if r := rowFor(dataLines(stdout), coldIP); len(r) != 5 || r[1] != "1m0s" || r[3] != "3" || r[4] != "status_ratelimit=2,login_ratelimit=1" {
		t.Errorf("drop history row %v", r)
	}
}

func TestDumpAllPrintsASectionPerMap(t *testing.T) {
	f := pinEveryMap(t)
	res := runCLI(t, "dump", "--pin-path", f.dir, "--map", "all")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("exit %d, stderr %q", res.code, res.stderr)
	}
	for _, name := range []string{
		"tcp_established", "tcp_syn_seen", "tcp_open_count", "tcp_whitelist",
		"status_ratelimit", "login_ratelimit", "health", "ip_drop_history",
	} {
		if !strings.Contains(res.stdout, "== "+name+" ==") {
			t.Errorf("dump all has no %s section", name)
		}
	}
}

func TestInspectShowsEveryMapForOneAddress(t *testing.T) {
	f := pinEveryMap(t)
	res := runCLI(t, "inspect", "--pin-path", f.dir, hotIP)
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	lines := strings.Split(strings.TrimSpace(res.stdout), "\n")
	if lines[0] != "IP "+hotIP {
		t.Fatalf("first line %q", lines[0])
	}
	want := map[string]string{
		"tcp_whitelist":    "age=5s",
		"tcp_established":  "age=30s",
		"tcp_syn_seen":     "-",
		"tcp_open_count":   "count=3",
		"status_ratelimit": "tokens=2 refill_age=4s",
		"login_ratelimit":  "-",
		"syn_ratelimit":    "-",
		"conn_ratelimit":   "pkt_tokens=1 byte_tokens=512",
		"health":           "anomalies=9 window_age=20s BLACKLISTED unblock_in=",
		"ip_drop_history":  "first=1m0s last=1s total=5 tcp_no_syn=5",
	}
	if len(lines) != 1+len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), 1+len(want), res.stdout)
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), fields[0]))
		w, ok := want[fields[0]]
		if !ok {
			t.Errorf("unexpected line %q", line)
			continue
		}
		if !strings.HasPrefix(body, w) {
			t.Errorf("%s: %q, want it to start with %q", fields[0], body, w)
		}
	}
}

func TestInspectReportsAnExpiredBanAsNotBlacklisted(t *testing.T) {
	f := pinEveryMap(t)
	stdout, _ := captureOutput(t, func() {
		inspectHealth(f.dir, "health", mustIPKey(t, coldIP), f.now)
	})
	if !strings.Contains(stdout, "anomalies=3") || !strings.HasSuffix(strings.TrimSpace(stdout), "blacklisted=no") {
		t.Errorf("inspect health = %q, want anomalies=3 and blacklisted=no", stdout)
	}
}

func TestHealthListsOnlyBannedIPsUnlessAllIsGiven(t *testing.T) {
	f := pinEveryMap(t)

	res := runCLI(t, "health", "--pin-path", f.dir)
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	rows := dataLines(res.stdout)
	if strings.Join(rows[0], " ") != "IP ANOMALIES WINDOW_AGE BLACKLIST" || len(rows) != 2 {
		t.Fatalf("health output:\n%s", res.stdout)
	}
	if r := rowFor(rows, hotIP); len(r) != 5 || r[1] != "9" || r[2] != "20s" || r[3] != "in" {
		t.Errorf("banned row %v", r)
	}

	res = runCLI(t, "health", "--pin-path", f.dir, "--all")
	rows = dataLines(res.stdout)
	if len(rows) != 3 {
		t.Fatalf("health --all output:\n%s", res.stdout)
	}
	if r := rowFor(rows, coldIP); len(r) != 4 || r[1] != "3" || r[3] != "-" {
		t.Errorf("unbanned row %v", r)
	}
}

func TestInfoSummarisesCountersAndMapPopulations(t *testing.T) {
	f := pinEveryMap(t)
	res := runCLI(t, "info", "--pin-path", f.dir)
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "  tcp: 100 pass / 9 drop\n") {
		t.Errorf("counter line missing or wrong, want 100 pass and 4+3+2 drops:\n%s", res.stdout)
	}
	want := map[string]string{
		"tcp_whitelist":    "2",
		"tcp_established":  "1",
		"tcp_syn_seen":     "0",
		"tcp_open_count":   "3",
		"status_ratelimit": "2",
		"login_ratelimit":  "0",
		"health":           "2",
		"ip_drop_history":  "2",
	}
	rows := dataLines(res.stdout)
	for name, n := range want {
		r := rowFor(rows, name)
		if len(r) != 2 || r[1] != n {
			t.Errorf("%s population %v, want %s", name, r, n)
		}
	}
	if !strings.Contains(res.stdout, "health (blacklisted)") || !strings.HasSuffix(strings.TrimSpace(res.stdout), " 1") {
		t.Errorf("blacklisted count missing or not 1:\n%s", res.stdout)
	}
}

func TestInfoMarksUnpinnedMapsAsClosed(t *testing.T) {
	dir := pinnedDir(t)
	wl := pinIPMap(t, dir, "tcp_whitelist", 8)
	putIP(t, wl, hotIP, uint64(1))

	res := runCLI(t, "info", "--pin-path", dir)
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	rows := dataLines(res.stdout)
	if r := rowFor(rows, "tcp_whitelist"); len(r) != 2 || r[1] != "1" {
		t.Errorf("tcp_whitelist population %v, want 1", r)
	}
	if r := rowFor(rows, "health"); len(r) != 2 || r[1] != "(closed)" {
		t.Errorf("health population %v, want (closed)", r)
	}
	if strings.Contains(res.stdout, "tcp:") || strings.Contains(res.stdout, "blacklisted") {
		t.Errorf("info printed counters for maps that are not pinned:\n%s", res.stdout)
	}
}

func TestStatsSumsPerCPUCountersInTextAndJSON(t *testing.T) {
	f := pinEveryMap(t)

	res := runCLI(t, "stats", "--pin-path", f.dir)
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	rows := dataLines(res.stdout)
	if len(rows) != len(statLabels) {
		t.Fatalf("got %d lines, want %d", len(rows), len(statLabels))
	}
	for i, lbl := range statLabels {
		if rows[i][0] != lbl {
			t.Errorf("line %d is %q, want %q", i, rows[i][0], lbl)
		}
	}
	for lbl, want := range map[string]string{"pass_tcp": "100", "drop_tcp_no_syn": "4", "tcp_l7_match_no_est": "50", "drop_status_ratelimit": "3", "tcp_l7_promoted": "0"} {
		if r := rowFor(rows, lbl); len(r) != 2 || r[1] != want {
			t.Errorf("%s = %v, want %s", lbl, r, want)
		}
	}

	res = runCLI(t, "stats", "--pin-path", f.dir, "--json")
	var got map[string]uint64
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("decode %q: %v", res.stdout, err)
	}
	if len(got) != len(statLabels) || got["pass_tcp"] != 100 || got["drop_tcp_bad_flags"] != 2 {
		t.Errorf("json stats %v", got)
	}
}

func TestClearMapKeyReportsAMissingKeyAsNotPresent(t *testing.T) {
	dir := pinnedDir(t)
	wl := pinIPMap(t, dir, "tcp_whitelist", 8)
	putIP(t, wl, hotIP, uint64(1))
	path := filepath.Join(dir, "tcp_whitelist")

	n, err := clearMapKey(path, mustIPKey(t, coldIP))
	if err != nil || n != 0 {
		t.Fatalf("clearing an absent key = (%d, %v), want (0, nil)", n, err)
	}
	n, err = clearMapKey(path, mustIPKey(t, hotIP))
	if err != nil || n != 1 {
		t.Fatalf("clearing a present key = (%d, %v), want (1, nil)", n, err)
	}
	if count := mapEntryCount(dir, "tcp_whitelist"); count != 0 {
		t.Errorf("%d entries left after removing the only key", count)
	}
}

func TestClearMapWipesEveryEntryAndCountsThem(t *testing.T) {
	f := pinEveryMap(t)
	n, err := clearMap(filepath.Join(f.dir, "tcp_open_count"))
	if err != nil || n != 3 {
		t.Fatalf("clearMap = (%d, %v), want (3, nil)", n, err)
	}
	if count := mapEntryCount(f.dir, "tcp_open_count"); count != 0 {
		t.Errorf("%d entries left after clearing", count)
	}
}

func TestClearCommandReportsEachTarget(t *testing.T) {
	f := pinEveryMap(t)

	res := runCLI(t, "clear", "--pin-path", f.dir, "--map", "whitelist", "--ip", idleIP)
	if res.code != 0 || strings.TrimSpace(res.stdout) != "tcp_whitelist: "+idleIP+" not present" {
		t.Errorf("clear of an absent IP printed %q (exit %d)", res.stdout, res.code)
	}
	res = runCLI(t, "clear", "--pin-path", f.dir, "--map", "whitelist", "--ip", hotIP)
	if res.code != 0 || strings.TrimSpace(res.stdout) != "tcp_whitelist: removed "+hotIP {
		t.Errorf("clear of a present IP printed %q (exit %d)", res.stdout, res.code)
	}

	res = runCLI(t, "clear", "--pin-path", f.dir, "--map", "all")
	if res.code != 0 {
		t.Fatalf("exit %d: %s", res.code, res.stderr)
	}
	for _, line := range []string{
		"tcp_whitelist: cleared 1 entries",
		"tcp_open_count: cleared 3 entries",
		"health: cleared 2 entries",
		"syn_ratelimit: cleared 0 entries",
	} {
		if !strings.Contains(res.stdout, line+"\n") {
			t.Errorf("clear all output lacks %q:\n%s", line, res.stdout)
		}
	}
	for _, name := range []string{"tcp_whitelist", "tcp_open_count", "health", "ip_drop_history"} {
		if n := mapEntryCount(f.dir, name); n != 0 {
			t.Errorf("%s still has %d entries after clear all", name, n)
		}
	}
}

func TestClearCommandRejectsABadIPAndAnUnknownMap(t *testing.T) {
	if res := runCLI(t, "clear", "--map", "whitelist", "--ip", "2001:db8::1"); res.code != 2 || !strings.Contains(res.stderr, "not an IPv4 address") {
		t.Errorf("ipv6 clear: exit %d, stderr %q", res.code, res.stderr)
	}
	if res := runCLI(t, "clear", "--map", "banana"); res.code != 2 || !strings.Contains(res.stderr, "unknown map: banana") {
		t.Errorf("unknown map clear: exit %d, stderr %q", res.code, res.stderr)
	}
}
