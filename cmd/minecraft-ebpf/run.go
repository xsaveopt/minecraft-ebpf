package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/xsaveopt/minecraft-ebpf/internal/loader"
	"github.com/xsaveopt/minecraft-ebpf/internal/metrics"
)

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	iface := fs.String("iface", "eth0", "network interface to attach XDP to")
	port := fs.Uint("port", 25565, "Minecraft Java server port (TCP)")
	ttl := fs.Duration("ttl", 10*time.Minute, "whitelist TTL")
	metricsAddr := fs.String("metrics-addr", ":9464", "prometheus metrics listen address")
	cgroup := fs.String("cgroup", "/sys/fs/cgroup", "cgroup v2 path for sockops attach")
	pinPath := fs.String("pin-path", "/sys/fs/bpf/minecraft", "bpf map pin directory")
	statusRate := fs.Uint64("status-per-min", 60, "per-IP Status/ping handshake refill rate (per minute)")
	statusBurst := fs.Uint64("status-burst", 20, "per-IP Status/ping handshake burst capacity")
	loginRate := fs.Uint64("login-per-min", 20, "per-IP Login/Transfer handshake refill rate (per minute)")
	loginBurst := fs.Uint64("login-burst", 8, "per-IP Login/Transfer handshake burst capacity")
	tcpGlobalRate := fs.Uint64("tcp-global-rate", 5000, "global circuit-breaker on aggregate new-connection SYNs/sec to target port (0 disables)")
	tcpGlobalBurst := fs.Uint64("tcp-global-burst", 15000, "global circuit-breaker burst capacity (SYNs)")
	tcpMaxOpenPerIP := fs.Uint64("tcp-max-open-per-ip", 8, "drop new SYNs from any IP that already holds this many open TCP sockets to the target port (0 disables)")
	connPPS := fs.Uint64("conn-pps", 300, "per-IP packets/sec cap on established+whitelisted connections (0 disables)")
	connBurst := fs.Uint64("conn-burst", 600, "per-IP established/whitelisted packet burst capacity")
	connBPS := fs.Uint64("conn-bps", 524288, "per-IP bytes/sec cap on established+whitelisted connections (0 disables)")
	connByteBurst := fs.Uint64("conn-byte-burst", 1048576, "per-IP established/whitelisted byte burst capacity")
	connNewRate := fs.Uint64("conn-new-rate", 10, "per-IP new-connection (SYN) rate/sec to the target port (0 disables)")
	connNewBurst := fs.Uint64("conn-new-burst", 20, "per-IP new-connection burst capacity")
	healthWindow := fs.Duration("health-window", 60*time.Second, "anomaly counting window per IP")
	healthThreshold := fs.Uint("health-threshold", 100, "anomalies (malformed handshakes) per window before blacklisting an IP")
	healthBlacklist := fs.Duration("health-blacklist", 5*time.Minute, "how long an unhealthy IP stays blacklisted")
	sizeInterval := fs.Duration("map-size-interval", 30*time.Second, "how often to refresh map-size Prometheus gauges")
	_ = fs.Parse(args)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	l, err := loader.Load(loader.Options{
		Iface:           *iface,
		Port:            uint16(*port),
		TTL:             *ttl,
		CgroupPath:      *cgroup,
		PinPath:         *pinPath,
		StatusPerMin:    *statusRate,
		StatusBurst:     *statusBurst,
		LoginPerMin:     *loginRate,
		LoginBurst:      *loginBurst,
		TCPGlobalPerSec: *tcpGlobalRate,
		TCPGlobalBurst:  *tcpGlobalBurst,
		TCPMaxOpenPerIP: *tcpMaxOpenPerIP,
		ConnPPS:         *connPPS,
		ConnBurst:       *connBurst,
		ConnBPS:         *connBPS,
		ConnByteBurst:   *connByteBurst,
		ConnNewPerSec:   *connNewRate,
		ConnNewBurst:    *connNewBurst,
		HealthWindow:    *healthWindow,
		HealthThreshold: uint32(*healthThreshold),
		HealthBlacklist: *healthBlacklist,
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("load: verifier rejected program:\n%+v", verr)
		}
		log.Fatalf("load: %v", err)
	}
	defer l.Close()

	log.Printf("xdp: %s mode on %s", l.XDPMode, *iface)
	log.Printf("sockops: attached to %s", *cgroup)
	log.Printf("pin path: %s", *pinPath)
	log.Printf("port: %d, ttl: %s", *port, *ttl)
	log.Printf("status ratelimit: %d/min burst %d", *statusRate, *statusBurst)
	log.Printf("login ratelimit: %d/min burst %d", *loginRate, *loginBurst)
	if *tcpGlobalRate > 0 {
		log.Printf("tcp global circuit-breaker: %d SYNs/s aggregate, burst %d (split per-CPU internally)", *tcpGlobalRate, *tcpGlobalBurst)
	} else {
		log.Printf("tcp global circuit-breaker: DISABLED")
	}
	if *tcpMaxOpenPerIP > 0 {
		log.Printf("tcp per-IP open-conn cap: %d sockets/IP", *tcpMaxOpenPerIP)
	} else {
		log.Printf("tcp per-IP open-conn cap: DISABLED")
	}
	if *connPPS > 0 || *connBPS > 0 {
		log.Printf("per-IP established/whitelisted cap: %d pps burst %d, %d B/s burst %d", *connPPS, *connBurst, *connBPS, *connByteBurst)
	} else {
		log.Printf("per-IP established/whitelisted cap: DISABLED")
	}
	if *connNewRate > 0 {
		log.Printf("per-IP new-connection rate: %d/s burst %d", *connNewRate, *connNewBurst)
	} else {
		log.Printf("per-IP new-connection rate: DISABLED")
	}
	log.Printf("health: %d anomalies / %s → blacklist for %s", *healthThreshold, *healthWindow, *healthBlacklist)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := prometheus.NewRegistry()
	collector := metrics.NewCollector(
		metrics.Maps{
			Stats:       l.Stats,
			Whitelist:   l.TCPWhitelist,
			Established: l.TCPEstablished,
			SynSeen:     l.TCPSynSeen,
			OpenCount:   l.TCPOpenCount,
			StatusRL:    l.StatusRatelimit,
			LoginRL:     l.LoginRatelimit,
			SynRL:       l.SynRatelimit,
			ConnRL:      l.ConnRatelimit,
			Health:      l.Health,
			DropHistory: l.IPDropHistory,
		},
		*iface, uint16(*port), version,
		func() bool { return l.XDPLink != nil },
		func() bool { return l.SockopsLink != nil },
	)
	collector.StartSizeTicker(ctx, *sizeInterval)
	reg.MustRegister(collector)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	registerAPI(mux, apiCfg{
		Loaded:  l,
		Version: version,
		Iface:   *iface,
		Port:    uint16(*port),
		PinPath: *pinPath,
		Limits: apiLimits{
			StatusPerMin:    *statusRate,
			StatusBurst:     *statusBurst,
			LoginPerMin:     *loginRate,
			LoginBurst:      *loginBurst,
			TCPGlobalPerSec: *tcpGlobalRate,
			TCPGlobalBurst:  *tcpGlobalBurst,
			TCPMaxOpenPerIP: *tcpMaxOpenPerIP,
			ConnPPS:         *connPPS,
			ConnBurst:       *connBurst,
			ConnBPS:         *connBPS,
			ConnByteBurst:   *connByteBurst,
			ConnNewPerSec:   *connNewRate,
			ConnNewBurst:    *connNewBurst,
			WhitelistTTL:    *ttl,
			HealthWindow:    *healthWindow,
			HealthThreshold: uint32(*healthThreshold),
			HealthBlacklist: *healthBlacklist,
		},
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("minecraft-ebpf " + version + "\n" +
			"  /metrics                     prometheus counters\n" +
			"  /api/info                    daemon overview (limits + maps + counters)\n" +
			"  /api/stats                   counter values (JSON)\n" +
			"  /api/top?map=...&n=...       hottest IPs in a per-IP map\n" +
			"  /api/health[?all=1]          blacklisted IPs (with ?all=1: all anomaly entries)\n" +
			"  /api/whitelist               IPs in tcp_whitelist\n" +
			"  /api/blacklist               IPs currently blacklisted\n" +
			"  /api/established             IPs in tcp_established\n" +
			"  /api/syn-seen                IPs in tcp_syn_seen\n" +
			"  /api/open-count              open TCP socket count per IP\n" +
			"  /api/drop-history            per-IP cumulative drops by reason\n" +
			"  /api/ip/<addr>               aggregate state for one IPv4 across all maps\n" +
			"  /api/state                   index of the above\n"))
	})

	srv := &http.Server{Addr: *metricsAddr, Handler: mux}
	go func() {
		log.Printf("metrics: http://%s/metrics (map-size refresh every %s)", *metricsAddr, *sizeInterval)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
}
