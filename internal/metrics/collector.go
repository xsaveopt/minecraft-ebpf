package metrics

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

func bootTimeNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

const (
	StatPassTCP                = 0
	StatTCPEstablishedInserts  = 1
	StatTCPL7Promoted          = 2
	StatTCPL7MatchNoEst        = 3
	StatTCPHandshakeStatusSeen = 4
	StatTCPHandshakeLoginSeen  = 5
	StatDropTCPNoSyn           = 6
	StatDropTCPTooManyOpen     = 7
	StatDropTCPGlobalRatelimit = 8
	StatDropStatusRatelimit    = 9
	StatDropLoginRatelimit     = 10
	StatDropMalformedHandshake = 11
	StatDropTCPUnhealthy       = 12
	StatDropTCPBadFlags        = 13
	StatDropConnRatelimit      = 14
	StatDropTCPConnRate        = 15
	StatMax                    = 16
)

type MapSizes struct {
	whitelist   atomic.Int64
	established atomic.Int64
	synSeen     atomic.Int64
	openCount   atomic.Int64
	statusRL    atomic.Int64
	loginRL     atomic.Int64
	synRL       atomic.Int64
	connRL      atomic.Int64
	health      atomic.Int64
	dropHistory atomic.Int64
	blacklisted atomic.Int64
}

type Collector struct {
	stats          *ebpf.Map
	whitelistMap   *ebpf.Map
	establishedMap *ebpf.Map
	synSeenMap     *ebpf.Map
	openCountMap   *ebpf.Map
	statusRLMap    *ebpf.Map
	loginRLMap     *ebpf.Map
	synRLMap       *ebpf.Map
	connRLMap      *ebpf.Map
	healthMap      *ebpf.Map
	dropHistoryMap *ebpf.Map

	sizes MapSizes

	packets     *prometheus.Desc
	inserts     *prometheus.Desc
	promoted    *prometheus.Desc
	noEst       *prometheus.Desc
	statusSeen  *prometheus.Desc
	loginSeen   *prometheus.Desc
	mapSize     *prometheus.Desc
	blacklisted *prometheus.Desc
	buildInfo   *prometheus.Desc
	attached    *prometheus.Desc

	iface           string
	port            uint16
	version         string
	xdpAttached     func() bool
	sockopsAttached func() bool
}

type Maps struct {
	Stats       *ebpf.Map
	Whitelist   *ebpf.Map
	Established *ebpf.Map
	SynSeen     *ebpf.Map
	OpenCount   *ebpf.Map
	StatusRL    *ebpf.Map
	LoginRL     *ebpf.Map
	SynRL       *ebpf.Map
	ConnRL      *ebpf.Map
	Health      *ebpf.Map
	DropHistory *ebpf.Map
}

func NewCollector(
	maps Maps,
	iface string, port uint16, version string,
	xdpAttached, sockopsAttached func() bool,
) *Collector {
	return &Collector{
		stats:          maps.Stats,
		whitelistMap:   maps.Whitelist,
		establishedMap: maps.Established,
		synSeenMap:     maps.SynSeen,
		openCountMap:   maps.OpenCount,
		statusRLMap:    maps.StatusRL,
		loginRLMap:     maps.LoginRL,
		synRLMap:       maps.SynRL,
		connRLMap:      maps.ConnRL,
		healthMap:      maps.Health,
		dropHistoryMap: maps.DropHistory,
		packets: prometheus.NewDesc(
			"minecraft_xdp_packets_total",
			"Packets observed by the Minecraft XDP filter.",
			[]string{"verdict", "proto", "reason"}, nil,
		),
		inserts: prometheus.NewDesc(
			"minecraft_tcp_established_inserts_total",
			"TCP connections promoted to tcp_established by sockops (3WHS completed on port).",
			nil, nil,
		),
		promoted: prometheus.NewDesc(
			"minecraft_tcp_l7_promoted_total",
			"IPs promoted to tcp_whitelist after a Login handshake + TCP established confirmation.",
			nil, nil,
		),
		noEst: prometheus.NewDesc(
			"minecraft_tcp_l7_match_no_established_total",
			"Login handshake matched on a TCP segment but tcp_established missing (spoofed or racy).",
			nil, nil,
		),
		statusSeen: prometheus.NewDesc(
			"minecraft_tcp_handshake_status_seen_total",
			"Status handshakes (next_state=1) and legacy 0xFE pings seen (regardless of verdict).",
			nil, nil,
		),
		loginSeen: prometheus.NewDesc(
			"minecraft_tcp_handshake_login_seen_total",
			"Login/Transfer handshakes (next_state=2/3) seen (regardless of verdict).",
			nil, nil,
		),
		mapSize: prometheus.NewDesc(
			"minecraft_map_entries",
			"Number of entries in each pinned IP-keyed map (refreshed by background ticker, default every 30s).",
			[]string{"map"}, nil,
		),
		blacklisted: prometheus.NewDesc(
			"minecraft_health_blacklisted_ips",
			"IPs currently in the health blacklist (blacklist_until_ns > now).",
			nil, nil,
		),
		buildInfo: prometheus.NewDesc(
			"minecraft_build_info",
			"Build and runtime configuration.",
			[]string{"version", "iface", "port"}, nil,
		),
		attached: prometheus.NewDesc(
			"minecraft_attached",
			"Program attachment state (1=attached, 0=not).",
			[]string{"program"}, nil,
		),
		iface:           iface,
		port:            port,
		version:         version,
		xdpAttached:     xdpAttached,
		sockopsAttached: sockopsAttached,
	}
}

func (c *Collector) StartSizeTicker(ctx context.Context, interval time.Duration) {
	go func() {
		c.refreshSizes()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.refreshSizes()
			}
		}
	}()
}

func (c *Collector) refreshSizes() {
	c.sizes.whitelist.Store(countKeys(c.whitelistMap))
	c.sizes.established.Store(countKeys(c.establishedMap))
	c.sizes.synSeen.Store(countKeys(c.synSeenMap))
	c.sizes.openCount.Store(countKeys(c.openCountMap))
	c.sizes.statusRL.Store(countKeys(c.statusRLMap))
	c.sizes.loginRL.Store(countKeys(c.loginRLMap))
	c.sizes.synRL.Store(countKeys(c.synRLMap))
	c.sizes.connRL.Store(countKeys(c.connRLMap))
	c.sizes.dropHistory.Store(countKeys(c.dropHistoryMap))
	total, blacklisted := countHealth(c.healthMap)
	c.sizes.health.Store(total)
	c.sizes.blacklisted.Store(blacklisted)
}

func countKeys(m *ebpf.Map) int64 {
	if m == nil {
		return -1
	}
	var n int64
	var key [4]byte
	valBuf := make([]byte, m.ValueSize())
	iter := m.Iterate()
	for iter.Next(&key, &valBuf) {
		n++
	}
	return n
}

func countHealth(m *ebpf.Map) (total, blacklisted int64) {
	if m == nil {
		return -1, -1
	}
	now := bootTimeNS()
	var key [4]byte
	var val struct {
		Anomalies        uint32
		_                uint32
		WindowStartNS    uint64
		BlacklistUntilNS uint64
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		total++
		if val.BlacklistUntilNS > now {
			blacklisted++
		}
	}
	return
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packets
	ch <- c.inserts
	ch <- c.promoted
	ch <- c.noEst
	ch <- c.statusSeen
	ch <- c.loginSeen
	ch <- c.mapSize
	ch <- c.blacklisted
	ch <- c.buildInfo
	ch <- c.attached
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ncpu, err := ebpf.PossibleCPU()
	if err != nil || ncpu <= 0 {
		ncpu = 1
	}
	perCPU := make([]uint64, ncpu)
	sums := make([]uint64, StatMax)
	for slot := uint32(0); slot < StatMax; slot++ {
		if err := c.stats.Lookup(&slot, &perCPU); err != nil {
			continue
		}
		var s uint64
		for _, v := range perCPU {
			s += v
		}
		sums[slot] = s
	}

	emit := func(slot int, verdict, proto, reason string) {
		ch <- prometheus.MustNewConstMetric(
			c.packets, prometheus.CounterValue, float64(sums[slot]),
			verdict, proto, reason,
		)
	}
	emit(StatPassTCP, "pass", "tcp", "")
	emit(StatDropTCPNoSyn, "drop", "tcp", "no_syn")
	emit(StatDropTCPTooManyOpen, "drop", "tcp", "too_many_open")
	emit(StatDropTCPGlobalRatelimit, "drop", "tcp", "global_ratelimit")
	emit(StatDropStatusRatelimit, "drop", "tcp", "status_ratelimit")
	emit(StatDropLoginRatelimit, "drop", "tcp", "login_ratelimit")
	emit(StatDropMalformedHandshake, "drop", "tcp", "malformed_handshake")
	emit(StatDropTCPUnhealthy, "drop", "tcp", "unhealthy")
	emit(StatDropTCPBadFlags, "drop", "tcp", "bad_flags")
	emit(StatDropConnRatelimit, "drop", "tcp", "conn_ratelimit")
	emit(StatDropTCPConnRate, "drop", "tcp", "conn_rate")

	ch <- prometheus.MustNewConstMetric(c.inserts, prometheus.CounterValue, float64(sums[StatTCPEstablishedInserts]))
	ch <- prometheus.MustNewConstMetric(c.promoted, prometheus.CounterValue, float64(sums[StatTCPL7Promoted]))
	ch <- prometheus.MustNewConstMetric(c.noEst, prometheus.CounterValue, float64(sums[StatTCPL7MatchNoEst]))
	ch <- prometheus.MustNewConstMetric(c.statusSeen, prometheus.CounterValue, float64(sums[StatTCPHandshakeStatusSeen]))
	ch <- prometheus.MustNewConstMetric(c.loginSeen, prometheus.CounterValue, float64(sums[StatTCPHandshakeLoginSeen]))

	mapSize := func(name string, v int64) {
		if v < 0 {
			return
		}
		ch <- prometheus.MustNewConstMetric(c.mapSize, prometheus.GaugeValue, float64(v), name)
	}
	mapSize("tcp_whitelist", c.sizes.whitelist.Load())
	mapSize("tcp_established", c.sizes.established.Load())
	mapSize("tcp_syn_seen", c.sizes.synSeen.Load())
	mapSize("tcp_open_count", c.sizes.openCount.Load())
	mapSize("status_ratelimit", c.sizes.statusRL.Load())
	mapSize("login_ratelimit", c.sizes.loginRL.Load())
	mapSize("syn_ratelimit", c.sizes.synRL.Load())
	mapSize("conn_ratelimit", c.sizes.connRL.Load())
	mapSize("health", c.sizes.health.Load())
	mapSize("ip_drop_history", c.sizes.dropHistory.Load())

	ch <- prometheus.MustNewConstMetric(c.blacklisted, prometheus.GaugeValue, float64(c.sizes.blacklisted.Load()))
	ch <- prometheus.MustNewConstMetric(
		c.buildInfo, prometheus.GaugeValue, 1,
		c.version, c.iface, fmt.Sprintf("%d", c.port),
	)
	ch <- prometheus.MustNewConstMetric(c.attached, prometheus.GaugeValue, boolToF(c.xdpAttached()), "xdp")
	ch <- prometheus.MustNewConstMetric(c.attached, prometheus.GaugeValue, boolToF(c.sockopsAttached()), "sockops")
}

func boolToF(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
