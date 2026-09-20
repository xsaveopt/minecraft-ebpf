package loader

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

var xdpTunables = []string{
	"target_port",
	"whitelist_ttl_ns",
	"status_period_ns",
	"status_burst",
	"login_period_ns",
	"login_burst",
	"tcp_global_period_ns",
	"tcp_global_burst",
	"tcp_max_open_per_ip",
	"conn_pkt_period_ns",
	"conn_pkt_burst",
	"conn_byte_period_ns",
	"conn_byte_burst",
	"conn_new_period_ns",
	"conn_new_burst",
	"health_window_ns",
	"health_threshold",
	"health_blacklist_ns",
}

var pinnedMaps = []string{
	"tcp_established",
	"tcp_syn_seen",
	"tcp_whitelist",
	"status_ratelimit",
	"login_ratelimit",
	"tcp_global_ratelimit",
	"tcp_open_count",
	"conn_ratelimit",
	"syn_ratelimit",
	"health",
	"ip_drop_history",
	"stats",
}

func TestXDPSpecCarriesEveryTunableTheLoaderSets(t *testing.T) {
	spec, err := loadMinecraftXDP()
	if err != nil {
		t.Fatalf("load xdp spec: %v", err)
	}
	for _, name := range xdpTunables {
		if _, ok := spec.Variables[name]; !ok {
			t.Errorf("variable %s is missing from the compiled spec, so the loader would refuse to start", name)
		}
	}
}

func TestSockopsSpecCarriesTargetPort(t *testing.T) {
	spec, err := loadMinecraftSockops()
	if err != nil {
		t.Fatalf("load sockops spec: %v", err)
	}
	if _, ok := spec.Variables["target_port"]; !ok {
		t.Fatal("variable target_port is missing from the compiled sockops spec")
	}
}

func TestXDPSpecDeclaresEveryPinnedMap(t *testing.T) {
	spec, err := loadMinecraftXDP()
	if err != nil {
		t.Fatalf("load xdp spec: %v", err)
	}
	for _, name := range pinnedMaps {
		m, ok := spec.Maps[name]
		if !ok {
			t.Errorf("map %s is missing from the compiled spec", name)
			continue
		}
		if m.Pinning != ebpf.PinByName {
			t.Errorf("map %s has pinning %v, want PinByName so it survives a restart", name, m.Pinning)
		}
	}
}

func TestTunablesRoundTripThroughTheSpec(t *testing.T) {
	spec, err := loadMinecraftXDP()
	if err != nil {
		t.Fatalf("load xdp spec: %v", err)
	}

	if err := setVar(spec, "target_port", uint16(25566)); err != nil {
		t.Fatalf("set target_port: %v", err)
	}
	var port uint16
	if err := spec.Variables["target_port"].Get(&port); err != nil {
		t.Fatalf("get target_port: %v", err)
	}
	if port != 25566 {
		t.Errorf("target_port read back as %d, want 25566", port)
	}

	if err := setVar(spec, "login_period_ns", uint64(3_000_000_000)); err != nil {
		t.Fatalf("set login_period_ns: %v", err)
	}
	var period uint64
	if err := spec.Variables["login_period_ns"].Get(&period); err != nil {
		t.Fatalf("get login_period_ns: %v", err)
	}
	if period != 3_000_000_000 {
		t.Errorf("login_period_ns read back as %d, want 3000000000", period)
	}

	if err := setVar(spec, "health_threshold", uint32(20)); err != nil {
		t.Fatalf("set health_threshold: %v", err)
	}
	var threshold uint32
	if err := spec.Variables["health_threshold"].Get(&threshold); err != nil {
		t.Fatalf("get health_threshold: %v", err)
	}
	if threshold != 20 {
		t.Errorf("health_threshold read back as %d, want 20", threshold)
	}
}

func TestSetVarRefusesAnUnknownVariable(t *testing.T) {
	spec := &ebpf.CollectionSpec{Variables: map[string]*ebpf.VariableSpec{}}
	err := setVar(spec, "no_such_tunable", uint64(1))
	if err == nil {
		t.Fatal("setVar accepted an unknown variable, which would silently disable a limit")
	}
	if !strings.Contains(err.Error(), "no_such_tunable") {
		t.Errorf("error %q does not name the variable", err)
	}
}

func TestSetVarRejectsAMistypedValue(t *testing.T) {
	spec, err := loadMinecraftXDP()
	if err != nil {
		t.Fatalf("load xdp spec: %v", err)
	}
	if err := setVar(spec, "target_port", uint64(25565)); err == nil {
		t.Fatal("setVar accepted a 64-bit value for a 16-bit variable")
	}
}

func TestClosingAnUnloadedSetIsNotAnError(t *testing.T) {
	var l Loaded
	if err := l.Close(); err != nil {
		t.Fatalf("Close on an unloaded set: %v", err)
	}
}
