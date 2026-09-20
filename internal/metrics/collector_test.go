package metrics

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

type fakeStats struct {
	totals  map[uint32]uint64
	lookups int
}

func (f *fakeStats) Lookup(key, valueOut any) error {
	f.lookups++
	k, ok := key.(*uint32)
	if !ok {
		return fmt.Errorf("fake stats: unsupported key type %T", key)
	}
	out, ok := valueOut.(*[]uint64)
	if !ok {
		return fmt.Errorf("fake stats: unsupported value type %T", valueOut)
	}
	total, ok := f.totals[*k]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	n := len(*out)
	if n == 0 {
		return nil
	}
	per := total / uint64(n)
	for i := range *out {
		(*out)[i] = per
	}
	(*out)[0] += total - per*uint64(n)
	return nil
}

func newTestCollector(t *testing.T, stats *fakeStats) *Collector {
	t.Helper()
	c := NewCollector(Maps{}, "eth0", 25565, "v1.2.3",
		func() bool { return true },
		func() bool { return false },
	)
	c.stats = stats
	return c
}

func gather(t *testing.T, c *Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := make(map[string]float64)
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			labels := make([]string, 0, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				labels = append(labels, lp.GetName()+"="+lp.GetValue())
			}
			sort.Strings(labels)
			key := mf.GetName()
			if len(labels) > 0 {
				key += "{" + strings.Join(labels, ",") + "}"
			}
			switch {
			case m.GetCounter() != nil:
				out[key] = m.GetCounter().GetValue()
			case m.GetGauge() != nil:
				out[key] = m.GetGauge().GetValue()
			default:
				t.Fatalf("metric %s is neither a counter nor a gauge", key)
			}
		}
	}
	return out
}

func allSlots() map[uint32]uint64 {
	totals := make(map[uint32]uint64, StatMax)
	for slot := uint32(0); slot < StatMax; slot++ {
		totals[slot] = uint64(slot+1) * 1000
	}
	return totals
}

func TestCollectorNamesAndValuesEveryPacketVerdict(t *testing.T) {
	c := newTestCollector(t, &fakeStats{totals: allSlots()})
	got := gather(t, c)

	want := map[string]float64{
		`minecraft_xdp_packets_total{proto=tcp,reason=,verdict=pass}`:                    1000,
		`minecraft_xdp_packets_total{proto=tcp,reason=no_syn,verdict=drop}`:              7000,
		`minecraft_xdp_packets_total{proto=tcp,reason=too_many_open,verdict=drop}`:       8000,
		`minecraft_xdp_packets_total{proto=tcp,reason=global_ratelimit,verdict=drop}`:    9000,
		`minecraft_xdp_packets_total{proto=tcp,reason=status_ratelimit,verdict=drop}`:    10000,
		`minecraft_xdp_packets_total{proto=tcp,reason=login_ratelimit,verdict=drop}`:     11000,
		`minecraft_xdp_packets_total{proto=tcp,reason=malformed_handshake,verdict=drop}`: 12000,
		`minecraft_xdp_packets_total{proto=tcp,reason=unhealthy,verdict=drop}`:           13000,
		`minecraft_xdp_packets_total{proto=tcp,reason=bad_flags,verdict=drop}`:           14000,
		`minecraft_xdp_packets_total{proto=tcp,reason=conn_ratelimit,verdict=drop}`:      15000,
		`minecraft_xdp_packets_total{proto=tcp,reason=conn_rate,verdict=drop}`:           16000,
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %v, want %v", key, got[key], value)
		}
	}

	series := 0
	for key := range got {
		if strings.HasPrefix(key, "minecraft_xdp_packets_total{") {
			series++
		}
	}
	if series != len(want) {
		t.Errorf("packets_total has %d series, want %d", series, len(want))
	}
}

func TestCollectorSumsPerCPUValuesForTheStandaloneCounters(t *testing.T) {
	c := newTestCollector(t, &fakeStats{totals: allSlots()})
	got := gather(t, c)

	want := map[string]float64{
		"minecraft_tcp_established_inserts_total":     2000,
		"minecraft_tcp_l7_promoted_total":             3000,
		"minecraft_tcp_l7_match_no_established_total": 4000,
		"minecraft_tcp_handshake_status_seen_total":   5000,
		"minecraft_tcp_handshake_login_seen_total":    6000,
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s = %v, want %v", name, got[name], value)
		}
	}
}

func TestCollectorReadsAMissingStatSlotAsZero(t *testing.T) {
	totals := allSlots()
	delete(totals, StatDropLoginRatelimit)
	stats := &fakeStats{totals: totals}

	got := gather(t, newTestCollector(t, stats))

	key := `minecraft_xdp_packets_total{proto=tcp,reason=login_ratelimit,verdict=drop}`
	if got[key] != 0 {
		t.Errorf("%s = %v, want 0 when the slot cannot be read", key, got[key])
	}
	if stats.lookups != StatMax {
		t.Errorf("collector made %d lookups, want one per slot (%d)", stats.lookups, StatMax)
	}
}

func TestCollectorReportsMapSizesAndSkipsUnloadedMaps(t *testing.T) {
	c := newTestCollector(t, &fakeStats{totals: allSlots()})
	c.sizes.whitelist.Store(11)
	c.sizes.established.Store(12)
	c.sizes.synSeen.Store(13)
	c.sizes.openCount.Store(14)
	c.sizes.statusRL.Store(15)
	c.sizes.loginRL.Store(16)
	c.sizes.synRL.Store(17)
	c.sizes.connRL.Store(18)
	c.sizes.health.Store(19)
	c.sizes.dropHistory.Store(-1)
	c.sizes.blacklisted.Store(4)

	got := gather(t, c)

	want := map[string]float64{
		`minecraft_map_entries{map=tcp_whitelist}`:    11,
		`minecraft_map_entries{map=tcp_established}`:  12,
		`minecraft_map_entries{map=tcp_syn_seen}`:     13,
		`minecraft_map_entries{map=tcp_open_count}`:   14,
		`minecraft_map_entries{map=status_ratelimit}`: 15,
		`minecraft_map_entries{map=login_ratelimit}`:  16,
		`minecraft_map_entries{map=syn_ratelimit}`:    17,
		`minecraft_map_entries{map=conn_ratelimit}`:   18,
		`minecraft_map_entries{map=health}`:           19,
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %v, want %v", key, got[key], value)
		}
	}
	if _, ok := got[`minecraft_map_entries{map=ip_drop_history}`]; ok {
		t.Error("an unloaded map was reported as a size instead of being omitted")
	}
	if got["minecraft_health_blacklisted_ips"] != 4 {
		t.Errorf("minecraft_health_blacklisted_ips = %v, want 4", got["minecraft_health_blacklisted_ips"])
	}
}

func TestCollectorReportsBuildInfoAndAttachmentState(t *testing.T) {
	c := newTestCollector(t, &fakeStats{totals: allSlots()})
	got := gather(t, c)

	buildInfo := `minecraft_build_info{iface=eth0,port=25565,version=v1.2.3}`
	if got[buildInfo] != 1 {
		t.Errorf("%s = %v, want 1", buildInfo, got[buildInfo])
	}
	if got[`minecraft_attached{program=xdp}`] != 1 {
		t.Errorf("xdp attachment = %v, want 1", got[`minecraft_attached{program=xdp}`])
	}
	if got[`minecraft_attached{program=sockops}`] != 0 {
		t.Errorf("sockops attachment = %v, want 0", got[`minecraft_attached{program=sockops}`])
	}
}

func TestCollectorDescribesEveryMetricItEmits(t *testing.T) {
	c := newTestCollector(t, &fakeStats{totals: allSlots()})

	described := make(chan *prometheus.Desc, 32)
	c.Describe(described)
	close(described)

	names := make(map[string]bool)
	for d := range described {
		names[d.String()] = true
	}
	if len(names) != 10 {
		t.Fatalf("Describe sent %d distinct descriptors, want 10", len(names))
	}

	collected := make(chan prometheus.Metric, 64)
	c.Collect(collected)
	close(collected)
	for m := range collected {
		if !names[m.Desc().String()] {
			t.Errorf("collected an undescribed metric: %s", m.Desc())
		}
	}
}
