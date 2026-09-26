package loader

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func mountBPFFS(t *testing.T) string {
	t.Helper()
	requireBPFPrivileges(t)
	dir := t.TempDir()
	if err := unix.Mount("bpf", dir, "bpf", 0, ""); err != nil {
		t.Skipf("cannot mount bpffs: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	pin := filepath.Join(dir, "minecraft")
	if err := os.MkdirAll(pin, 0o755); err != nil {
		t.Fatalf("create pin dir: %v", err)
	}
	return pin
}

func loopbackIndex(t *testing.T) int {
	t.Helper()
	ifc, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface: %v", err)
	}
	return ifc.Index
}

func testOptions(pinPath string) Options {
	return Options{
		Iface:           "lo",
		Port:            testPort,
		TTL:             10 * time.Minute,
		CgroupPath:      cgroupRoot,
		PinPath:         pinPath,
		StatusPerMin:    60,
		StatusBurst:     20,
		LoginPerMin:     20,
		LoginBurst:      8,
		HealthWindow:    time.Minute,
		HealthThreshold: 100,
		HealthBlacklist: 5 * time.Minute,
	}
}

func loadForTest(t *testing.T, opts Options) *Loaded {
	t.Helper()
	l, err := Load(opts)
	if err != nil {
		skipIfKernelRefuses(t, err)
		t.Fatalf("load: %v", err)
	}
	return l
}

func TestLoadAttachesBothProgramsAndPinsEveryMap(t *testing.T) {
	pin := mountBPFFS(t)
	requireCgroup2(t)
	loopbackIndex(t)

	l := loadForTest(t, testOptions(pin))
	t.Cleanup(func() { _ = l.Close() })

	if l.XDPLink == nil || l.SockopsLink == nil {
		t.Fatalf("links xdp=%v sockops=%v, want both attached", l.XDPLink, l.SockopsLink)
	}
	if l.XDPMode != "native" && l.XDPMode != "generic" {
		t.Errorf("xdp mode %q, want native or generic", l.XDPMode)
	}
	for _, name := range pinnedMaps {
		if _, err := os.Stat(filepath.Join(pin, name)); err != nil {
			t.Errorf("map %s is not pinned: %v", name, err)
		}
	}
	for name, m := range map[string]*ebpf.Map{
		"tcp_established": l.TCPEstablished, "tcp_syn_seen": l.TCPSynSeen,
		"tcp_whitelist": l.TCPWhitelist, "status_ratelimit": l.StatusRatelimit,
		"login_ratelimit": l.LoginRatelimit, "tcp_global_ratelimit": l.TCPGlobalRatelimit,
		"tcp_open_count": l.TCPOpenCount, "conn_ratelimit": l.ConnRatelimit,
		"syn_ratelimit": l.SynRatelimit, "health": l.Health,
		"ip_drop_history": l.IPDropHistory, "stats": l.Stats,
	} {
		if m == nil {
			t.Errorf("Loaded.%s is nil", name)
		}
	}
}

func TestLoadedStateSurvivesARestartThroughThePins(t *testing.T) {
	pin := mountBPFFS(t)
	requireCgroup2(t)
	loopbackIndex(t)

	first := loadForTest(t, testOptions(pin))
	ip := [4]byte{192, 0, 2, 55}
	ts := uint64(123456789)
	if err := first.TCPWhitelist.Put(&ip, &ts); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second := loadForTest(t, testOptions(pin))
	t.Cleanup(func() { _ = second.Close() })
	var got uint64
	if err := second.TCPWhitelist.Lookup(&ip, &got); err != nil {
		t.Fatalf("whitelist entry lost across a restart: %v", err)
	}
	if got != ts {
		t.Errorf("whitelist entry read back as %d, want %d", got, ts)
	}
}

func TestCloseDetachesTheXDPProgram(t *testing.T) {
	pin := mountBPFFS(t)
	requireCgroup2(t)
	idx := loopbackIndex(t)

	l := loadForTest(t, testOptions(pin))
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	obj := loadTestXDP(t, nil)
	again, _, err := attachXDP(obj.MinecraftXdp, idx)
	if err != nil {
		t.Fatalf("attaching after Close failed, so the old program is still on the interface: %v", err)
	}
	_ = again.Close()
}

func TestLoadRejectsAnUnknownInterface(t *testing.T) {
	opts := testOptions(t.TempDir())
	opts.Iface = "nosuchif0"
	_, err := Load(opts)
	if err == nil {
		t.Fatal("Load accepted an interface that does not exist")
	}
	if !strings.Contains(err.Error(), "interface nosuchif0") {
		t.Errorf("error %q does not name the interface", err)
	}
}

func TestFailedSockopsAttachLeavesNoXDPProgramBehind(t *testing.T) {
	pin := mountBPFFS(t)
	idx := loopbackIndex(t)

	opts := testOptions(pin)
	opts.CgroupPath = t.TempDir()
	l, err := Load(opts)
	if err == nil {
		_ = l.Close()
		t.Fatal("Load succeeded with a cgroup path that is not a cgroup")
	}
	if !strings.Contains(err.Error(), "attach sockops to "+opts.CgroupPath) {
		t.Errorf("error %q does not name the cgroup path", err)
	}

	obj := loadTestXDP(t, nil)
	again, _, err := attachXDP(obj.MinecraftXdp, idx)
	if err != nil {
		t.Fatalf("attaching after a failed Load failed, so the XDP program leaked onto the interface: %v", err)
	}
	_ = again.Close()
}

func TestAttachXDPFallsBackToGenericModeOnLoopback(t *testing.T) {
	idx := loopbackIndex(t)
	obj := loadTestXDP(t, nil)
	l, mode, err := attachXDP(obj.MinecraftXdp, idx)
	if err != nil {
		skipIfKernelRefuses(t, err)
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = l.Close() }()
	if mode != "generic" {
		t.Errorf("mode %q, want generic on an interface without native XDP", mode)
	}
}

func TestAttachXDPReportsBothModesWhenNeitherWorks(t *testing.T) {
	obj := loadTestXDP(t, nil)
	_, _, err := attachXDP(obj.MinecraftXdp, 1<<30)
	if err == nil {
		t.Fatal("attach to a missing interface succeeded")
	}
	if !strings.Contains(err.Error(), "native:") || !strings.Contains(err.Error(), "generic:") {
		t.Errorf("error %q does not report both attach attempts", err)
	}
}

func readVar[T any](t *testing.T, v *ebpf.Variable) T {
	t.Helper()
	var out T
	if err := v.Get(&out); err != nil {
		t.Fatalf("get variable: %v", err)
	}
	return out
}

func TestLoadXDPConvertsRatesIntoRefillPeriods(t *testing.T) {
	pin := mountBPFFS(t)
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible cpus: %v", err)
	}

	opts := testOptions(pin)
	opts.Port = 25570
	opts.StatusPerMin = 30
	opts.StatusBurst = 5
	opts.LoginPerMin = 20
	opts.LoginBurst = 3
	opts.TCPGlobalPerSec = 1000 * uint64(ncpu)
	opts.TCPGlobalBurst = 3 * uint64(ncpu)
	opts.TCPMaxOpenPerIP = 8
	opts.ConnPPS = 250
	opts.ConnBurst = 600
	opts.ConnBPS = 1_000_000
	opts.ConnByteBurst = 2048
	opts.ConnNewPerSec = 10
	opts.ConnNewBurst = 20
	opts.HealthThreshold = 42

	obj, err := loadXDP(opts)
	if err != nil {
		skipIfKernelRefuses(t, err)
		t.Fatalf("loadXDP: %v", err)
	}
	t.Cleanup(func() { _ = obj.Close() })

	u64 := map[string]struct {
		v    *ebpf.Variable
		want uint64
	}{
		"whitelist_ttl_ns":     {obj.WhitelistTtlNs, 600_000_000_000},
		"status_period_ns":     {obj.StatusPeriodNs, 2_000_000_000},
		"status_burst":         {obj.StatusBurst, 5},
		"login_period_ns":      {obj.LoginPeriodNs, 3_000_000_000},
		"login_burst":          {obj.LoginBurst, 3},
		"tcp_global_period_ns": {obj.TcpGlobalPeriodNs, 1_000_000},
		"tcp_global_burst":     {obj.TcpGlobalBurst, 3},
		"tcp_max_open_per_ip":  {obj.TcpMaxOpenPerIp, 8},
		"conn_pkt_period_ns":   {obj.ConnPktPeriodNs, 4_000_000},
		"conn_pkt_burst":       {obj.ConnPktBurst, 600},
		"conn_byte_period_ns":  {obj.ConnBytePeriodNs, 1_000},
		"conn_byte_burst":      {obj.ConnByteBurst, 2048},
		"conn_new_period_ns":   {obj.ConnNewPeriodNs, 100_000_000},
		"conn_new_burst":       {obj.ConnNewBurst, 20},
		"health_window_ns":     {obj.HealthWindowNs, 60_000_000_000},
		"health_blacklist_ns":  {obj.HealthBlacklistNs, 300_000_000_000},
	}
	for name, c := range u64 {
		if got := readVar[uint64](t, c.v); got != c.want {
			t.Errorf("%s = %d, want %d", name, got, c.want)
		}
	}
	if got := readVar[uint16](t, obj.TargetPort); got != 25570 {
		t.Errorf("target_port = %d, want 25570", got)
	}
	if got := readVar[uint32](t, obj.HealthThreshold); got != 42 {
		t.Errorf("health_threshold = %d, want 42", got)
	}
}

func TestLoadXDPDisablesLimitsWithAZeroRateAndKeepsOneGlobalTokenPerCPU(t *testing.T) {
	pin := mountBPFFS(t)
	opts := testOptions(pin)
	opts.StatusPerMin = 0
	opts.LoginPerMin = 0
	opts.TCPGlobalPerSec = 1
	opts.TCPGlobalBurst = 1

	obj, err := loadXDP(opts)
	if err != nil {
		skipIfKernelRefuses(t, err)
		t.Fatalf("loadXDP: %v", err)
	}
	t.Cleanup(func() { _ = obj.Close() })

	for name, v := range map[string]*ebpf.Variable{
		"status_period_ns":    obj.StatusPeriodNs,
		"login_period_ns":     obj.LoginPeriodNs,
		"conn_pkt_period_ns":  obj.ConnPktPeriodNs,
		"conn_byte_period_ns": obj.ConnBytePeriodNs,
		"conn_new_period_ns":  obj.ConnNewPeriodNs,
	} {
		if got := readVar[uint64](t, v); got != 0 {
			t.Errorf("%s = %d, want 0 for a zero rate", name, got)
		}
	}
	if got := readVar[uint64](t, obj.TcpGlobalPeriodNs); got != 1_000_000_000 {
		t.Errorf("tcp_global_period_ns = %d, want one second when the rate is below one per CPU", got)
	}
	if got := readVar[uint64](t, obj.TcpGlobalBurst); got != 1 {
		t.Errorf("tcp_global_burst = %d, want 1 when the burst is below one per CPU", got)
	}
}
