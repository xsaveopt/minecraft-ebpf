package metrics

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type healthValue struct {
	Anomalies        uint32
	Pad              uint32
	WindowStartNS    uint64
	BlacklistUntilNS uint64
}

func newIPMap(t *testing.T, valueSize uint32) *ebpf.Map {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("creating BPF maps needs root")
	}
	_ = rlimit.RemoveMemlock()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  valueSize,
		MaxEntries: 64,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("kernel refused to create a map: %v", err)
		}
		t.Fatalf("create map: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func fillTimestamps(t *testing.T, m *ebpf.Map, keys ...[4]byte) {
	t.Helper()
	for i, k := range keys {
		v := uint64(i + 1)
		if err := m.Put(&k, &v); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
}

var (
	ipA = [4]byte{192, 0, 2, 1}
	ipB = [4]byte{192, 0, 2, 2}
	ipC = [4]byte{198, 51, 100, 3}
	ipD = [4]byte{203, 0, 113, 4}
)

func healthMapWithOneBan(t *testing.T) *ebpf.Map {
	t.Helper()
	m := newIPMap(t, 24)
	now := bootTimeNS()
	for k, v := range map[[4]byte]healthValue{
		ipA: {Anomalies: 50, WindowStartNS: now, BlacklistUntilNS: now + 600_000_000_000},
		ipB: {Anomalies: 50, WindowStartNS: now, BlacklistUntilNS: now - 1_000_000_000},
		ipC: {Anomalies: 1, WindowStartNS: now},
	} {
		if err := m.Put(&k, &v); err != nil {
			t.Fatalf("put health: %v", err)
		}
	}
	return m
}

func TestCountKeysAndCountHealthReportMinusOneForAMissingMap(t *testing.T) {
	if n := countKeys(nil); n != -1 {
		t.Errorf("countKeys(nil) = %d, want -1", n)
	}
	if total, bl := countHealth(nil); total != -1 || bl != -1 {
		t.Errorf("countHealth(nil) = (%d, %d), want (-1, -1)", total, bl)
	}
}

func TestCountKeysCountsEveryEntry(t *testing.T) {
	m := newIPMap(t, 16)
	if n := countKeys(m); n != 0 {
		t.Errorf("empty map counted %d", n)
	}
	for i, k := range [][4]byte{ipA, ipB, ipC} {
		v := [2]uint64{uint64(i), 0}
		if err := m.Put(&k, &v); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	if n := countKeys(m); n != 3 {
		t.Errorf("countKeys = %d, want 3", n)
	}
}

func TestCountHealthCountsOnlyActiveBansAsBlacklisted(t *testing.T) {
	m := healthMapWithOneBan(t)
	total, bl := countHealth(m)
	if total != 3 || bl != 1 {
		t.Errorf("countHealth = (%d, %d), want (3, 1)", total, bl)
	}
}

func TestRefreshSizesFeedsTheMapEntryGauges(t *testing.T) {
	wl := newIPMap(t, 8)
	fillTimestamps(t, wl, ipA, ipB)
	est := newIPMap(t, 8)
	fillTimestamps(t, est, ipA, ipB, ipC)
	syn := newIPMap(t, 8)
	fillTimestamps(t, syn, ipD)
	open := newIPMap(t, 8)
	fillTimestamps(t, open, ipA)
	drops := newIPMap(t, 96)
	health := healthMapWithOneBan(t)

	c := NewCollector(Maps{
		Whitelist:   wl,
		Established: est,
		SynSeen:     syn,
		OpenCount:   open,
		Health:      health,
		DropHistory: drops,
	}, "eth0", 25565, "v1.2.3", func() bool { return true }, func() bool { return true })
	c.stats = &fakeStats{totals: allSlots()}
	c.refreshSizes()

	got := gather(t, c)
	want := map[string]float64{
		`minecraft_map_entries{map=tcp_whitelist}`:   2,
		`minecraft_map_entries{map=tcp_established}`: 3,
		`minecraft_map_entries{map=tcp_syn_seen}`:    1,
		`minecraft_map_entries{map=tcp_open_count}`:  1,
		`minecraft_map_entries{map=health}`:          3,
		`minecraft_map_entries{map=ip_drop_history}`: 0,
		`minecraft_health_blacklisted_ips`:           1,
	}
	for key, value := range want {
		v, ok := got[key]
		if !ok || v != value {
			t.Errorf("%s = %v (present %v), want %v", key, v, ok, value)
		}
	}
	for _, name := range []string{"status_ratelimit", "login_ratelimit", "syn_ratelimit", "conn_ratelimit"} {
		if _, ok := got[`minecraft_map_entries{map=`+name+`}`]; ok {
			t.Errorf("unloaded map %s was reported", name)
		}
	}
}

func TestBlacklistGaugeIsNeverNegativeWhenTheHealthMapIsMissing(t *testing.T) {
	c := newTestCollector(t, &fakeStats{totals: allSlots()})
	c.refreshSizes()
	got := gather(t, c)
	if v, ok := got["minecraft_health_blacklisted_ips"]; ok && v < 0 {
		t.Errorf("minecraft_health_blacklisted_ips = %v; with no health map the IP count is unknown, "+
			"so it should be omitted like the map size gauges rather than exported as a negative count", v)
	}
}
