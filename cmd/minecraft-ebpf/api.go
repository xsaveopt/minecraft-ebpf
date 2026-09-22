package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/xsaveopt/minecraft-ebpf/internal/loader"
)

type timestampEntry struct {
	IP         string `json:"ip"`
	AgeSeconds int64  `json:"age_seconds"`
}

type blacklistEntry struct {
	IP                        string `json:"ip"`
	Anomalies                 uint32 `json:"anomalies"`
	WindowAgeSeconds          int64  `json:"window_age_seconds"`
	BlacklistRemainingSeconds int64  `json:"blacklist_remaining_seconds"`
}

type countEntry struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

var dropReasonNames = [10]string{
	"tcp_no_syn",
	"tcp_too_many_open",
	"tcp_global_ratelimit",
	"status_ratelimit",
	"login_ratelimit",
	"malformed_handshake",
	"unhealthy",
	"tcp_bad_flags",
	"conn_ratelimit",
	"tcp_conn_rate",
}

type ipDropHistoryValue struct {
	FirstDropNS uint64
	LastDropNS  uint64
	Counts      [10]uint64
}

type dropHistoryEntry struct {
	IP                  string            `json:"ip"`
	FirstDropAgeSeconds int64             `json:"first_drop_age_seconds"`
	LastDropAgeSeconds  int64             `json:"last_drop_age_seconds"`
	Total               uint64            `json:"total"`
	ByReason            map[string]uint64 `json:"by_reason"`
}

type mapIterator interface {
	Next(keyOut, valueOut any) bool
}

type mapReader interface {
	Lookup(key, valueOut any) error
	Iterate() mapIterator
	ValueSize() uint32
}

type ebpfMapReader struct {
	m *ebpf.Map
}

func (r ebpfMapReader) Lookup(key, valueOut any) error {
	return r.m.Lookup(key, valueOut)
}

func (r ebpfMapReader) Iterate() mapIterator {
	return r.m.Iterate()
}

func (r ebpfMapReader) ValueSize() uint32 {
	return r.m.ValueSize()
}

func wrapMap(m *ebpf.Map) mapReader {
	if m == nil {
		return nil
	}
	return ebpfMapReader{m: m}
}

func bootNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

func ipv4Str(key [4]byte) string {
	return net.IPv4(key[0], key[1], key[2], key[3]).String()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func handleTimestampMap(m mapReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []timestampEntry{}
		if m != nil {
			now := bootNS()
			var key [4]byte
			var val uint64
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				age := int64(now) - int64(val)
				if age < 0 {
					age = 0
				}
				out = append(out, timestampEntry{
					IP:         ipv4Str(key),
					AgeSeconds: age / 1_000_000_000,
				})
			}
		}
		writeJSON(w, out)
	}
}

func handleCountMap(m mapReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []countEntry{}
		if m != nil {
			var key [4]byte
			var val uint64
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				out = append(out, countEntry{IP: ipv4Str(key), Count: val})
			}
		}
		writeJSON(w, out)
	}
}

func handleBlacklist(m mapReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []blacklistEntry{}
		if m != nil {
			now := bootNS()
			var key [4]byte
			var val struct {
				Anomalies        uint32
				_                uint32
				WindowStartNS    uint64
				BlacklistUntilNS uint64
			}
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				if val.BlacklistUntilNS <= now {
					continue
				}
				out = append(out, blacklistEntry{
					IP:                        ipv4Str(key),
					Anomalies:                 val.Anomalies,
					WindowAgeSeconds:          int64(now-val.WindowStartNS) / 1_000_000_000,
					BlacklistRemainingSeconds: int64(val.BlacklistUntilNS-now) / 1_000_000_000,
				})
			}
		}
		writeJSON(w, out)
	}
}

func handleIPLookup(l *loader.Loaded) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := strings.TrimPrefix(r.URL.Path, "/api/ip/")
		if addr == "" {
			http.Error(w, "missing IP: GET /api/ip/<addr>", http.StatusBadRequest)
			return
		}
		parsed := net.ParseIP(addr)
		if parsed == nil {
			http.Error(w, "invalid IP: "+addr, http.StatusBadRequest)
			return
		}
		v4 := parsed.To4()
		if v4 == nil {
			http.Error(w, "IPv4 only: "+addr, http.StatusBadRequest)
			return
		}
		var key [4]byte
		copy(key[:], v4)

		now := bootNS()
		out := map[string]any{
			"ip":               addr,
			"tcp_whitelist":    lookupTimestamp(wrapMap(l.TCPWhitelist), key, now),
			"tcp_established":  lookupTimestamp(wrapMap(l.TCPEstablished), key, now),
			"tcp_syn_seen":     lookupTimestamp(wrapMap(l.TCPSynSeen), key, now),
			"tcp_open_count":   lookupCount(wrapMap(l.TCPOpenCount), key),
			"status_ratelimit": lookupRatelimit(wrapMap(l.StatusRatelimit), key, now),
			"login_ratelimit":  lookupRatelimit(wrapMap(l.LoginRatelimit), key, now),
			"syn_ratelimit":    lookupRatelimit(wrapMap(l.SynRatelimit), key, now),
			"conn_ratelimit":   lookupConnLimit(wrapMap(l.ConnRatelimit), key, now),
			"health":           lookupHealth(wrapMap(l.Health), key, now),
			"drop_history":     lookupDropHistory(wrapMap(l.IPDropHistory), key, now),
		}
		writeJSON(w, out)
	}
}

func lookupTimestamp(m mapReader, key [4]byte, now uint64) any {
	if m == nil {
		return nil
	}
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	age := int64(now) - int64(val)
	if age < 0 {
		age = 0
	}
	return map[string]any{"age_seconds": age / 1_000_000_000}
}

func lookupCount(m mapReader, key [4]byte) any {
	if m == nil {
		return nil
	}
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	return map[string]any{"count": val}
}

func lookupRatelimit(m mapReader, key [4]byte, now uint64) any {
	if m == nil {
		return nil
	}
	var val struct {
		Tokens       uint64
		LastRefillNS uint64
	}
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	age := int64(now) - int64(val.LastRefillNS)
	if age < 0 {
		age = 0
	}
	return map[string]any{
		"tokens":                  val.Tokens,
		"last_refill_age_seconds": age / 1_000_000_000,
	}
}

func lookupConnLimit(m mapReader, key [4]byte, now uint64) any {
	if m == nil {
		return nil
	}
	var val struct {
		PktTokens  uint64
		PktLastNS  uint64
		ByteTokens uint64
		ByteLastNS uint64
	}
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	age := int64(now) - int64(val.PktLastNS)
	if age < 0 {
		age = 0
	}
	return map[string]any{
		"pkt_tokens":              val.PktTokens,
		"byte_tokens":             val.ByteTokens,
		"last_refill_age_seconds": age / 1_000_000_000,
	}
}

func lookupDropHistory(m mapReader, key [4]byte, now uint64) any {
	if m == nil {
		return nil
	}
	var val ipDropHistoryValue
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	first := int64(now) - int64(val.FirstDropNS)
	if first < 0 {
		first = 0
	}
	last := int64(now) - int64(val.LastDropNS)
	if last < 0 {
		last = 0
	}
	var total uint64
	by := make(map[string]uint64)
	for i, c := range val.Counts {
		if c == 0 {
			continue
		}
		total += c
		by[dropReasonNames[i]] = c
	}
	return map[string]any{
		"first_drop_age_seconds": first / 1_000_000_000,
		"last_drop_age_seconds":  last / 1_000_000_000,
		"total":                  total,
		"by_reason":              by,
	}
}

func lookupHealth(m mapReader, key [4]byte, now uint64) any {
	if m == nil {
		return nil
	}
	var val struct {
		Anomalies        uint32
		_                uint32
		WindowStartNS    uint64
		BlacklistUntilNS uint64
	}
	if err := m.Lookup(&key, &val); err != nil {
		return nil
	}
	wAge := int64(now) - int64(val.WindowStartNS)
	if wAge < 0 {
		wAge = 0
	}
	out := map[string]any{
		"anomalies":          val.Anomalies,
		"window_age_seconds": wAge / 1_000_000_000,
		"blacklisted":        val.BlacklistUntilNS > now,
	}
	if val.BlacklistUntilNS > now {
		out["blacklist_remaining_seconds"] = int64(val.BlacklistUntilNS-now) / 1_000_000_000
	}
	return out
}

type apiCfg struct {
	Loaded  *loader.Loaded
	Version string
	Iface   string
	Port    uint16
	PinPath string
	Limits  apiLimits
}

type apiLimits struct {
	StatusPerMin    uint64        `json:"status_per_min"`
	StatusBurst     uint64        `json:"status_burst"`
	LoginPerMin     uint64        `json:"login_per_min"`
	LoginBurst      uint64        `json:"login_burst"`
	TCPGlobalPerSec uint64        `json:"tcp_global_per_sec"`
	TCPGlobalBurst  uint64        `json:"tcp_global_burst"`
	TCPMaxOpenPerIP uint64        `json:"tcp_max_open_per_ip"`
	ConnPPS         uint64        `json:"conn_pps"`
	ConnBurst       uint64        `json:"conn_burst"`
	ConnBPS         uint64        `json:"conn_bps"`
	ConnByteBurst   uint64        `json:"conn_byte_burst"`
	ConnNewPerSec   uint64        `json:"conn_new_per_sec"`
	ConnNewBurst    uint64        `json:"conn_new_burst"`
	WhitelistTTL    time.Duration `json:"whitelist_ttl_ns"`
	HealthWindow    time.Duration `json:"health_window_ns"`
	HealthThreshold uint32        `json:"health_threshold"`
	HealthBlacklist time.Duration `json:"health_blacklist_ns"`
}

func handleInfo(cfg apiCfg) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{
			"version":  cfg.Version,
			"iface":    cfg.Iface,
			"port":     cfg.Port,
			"pin_path": cfg.PinPath,
			"xdp_mode": cfg.Loaded.XDPMode,
			"attached": map[string]bool{
				"xdp":     cfg.Loaded.XDPLink != nil,
				"sockops": cfg.Loaded.SockopsLink != nil,
			},
			"limits":   cfg.Limits,
			"maps":     mapPopulations(cfg.Loaded),
			"counters": readCounters(cfg.Loaded),
		}
		writeJSON(w, out)
	}
}

func handleStats(l *loader.Loaded) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, readCounters(l))
	}
}

func handleTop(cfg apiCfg) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		which := r.URL.Query().Get("map")
		if which == "" {
			http.Error(w, "missing ?map=...", http.StatusBadRequest)
			return
		}
		n := 10
		if s := r.URL.Query().Get("n"); s != "" {
			_, _ = fmt.Sscanf(s, "%d", &n)
		}
		reason := r.URL.Query().Get("reason")
		rows, err := topFromMap(cfg.PinPath, which, n, reason)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, rows)
	}
}

func handleDropHistory(m mapReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []dropHistoryEntry{}
		if m != nil {
			now := bootNS()
			var key [4]byte
			var val ipDropHistoryValue
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				first := int64(now) - int64(val.FirstDropNS)
				if first < 0 {
					first = 0
				}
				last := int64(now) - int64(val.LastDropNS)
				if last < 0 {
					last = 0
				}
				var total uint64
				by := make(map[string]uint64)
				for i, c := range val.Counts {
					if c == 0 {
						continue
					}
					total += c
					by[dropReasonNames[i]] = c
				}
				out = append(out, dropHistoryEntry{
					IP:                  ipv4Str(key),
					FirstDropAgeSeconds: first / 1_000_000_000,
					LastDropAgeSeconds:  last / 1_000_000_000,
					Total:               total,
					ByReason:            by,
				})
			}
		}
		writeJSON(w, out)
	}
}

func handleHealth(m mapReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all := r.URL.Query().Get("all") == "1"
		out := []map[string]any{}
		if m != nil {
			now := bootNS()
			var key [4]byte
			var val struct {
				Anomalies        uint32
				_                uint32
				WindowStartNS    uint64
				BlacklistUntilNS uint64
			}
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				blacklisted := val.BlacklistUntilNS > now
				if !all && !blacklisted {
					continue
				}
				wAge := int64(now) - int64(val.WindowStartNS)
				if wAge < 0 {
					wAge = 0
				}
				entry := map[string]any{
					"ip":                 ipv4Str(key),
					"anomalies":          val.Anomalies,
					"window_age_seconds": wAge / 1_000_000_000,
					"blacklisted":        blacklisted,
				}
				if blacklisted {
					entry["blacklist_remaining_seconds"] = int64(val.BlacklistUntilNS-now) / 1_000_000_000
				}
				out = append(out, entry)
			}
		}
		writeJSON(w, out)
	}
}

func handleHealthz(xdpAttached, sockopsAttached func() bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if !xdpAttached() || !sockopsAttached() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("degraded"))
			return
		}
		_, _ = w.Write([]byte("up"))
	}
}

func mapPopulations(l *loader.Loaded) map[string]int64 {
	count := func(m mapReader) int64 {
		if m == nil {
			return -1
		}
		var n int64
		var key [4]byte
		val := make([]byte, m.ValueSize())
		iter := m.Iterate()
		for iter.Next(&key, &val) {
			n++
		}
		return n
	}
	return map[string]int64{
		"tcp_whitelist":    count(wrapMap(l.TCPWhitelist)),
		"tcp_established":  count(wrapMap(l.TCPEstablished)),
		"tcp_syn_seen":     count(wrapMap(l.TCPSynSeen)),
		"tcp_open_count":   count(wrapMap(l.TCPOpenCount)),
		"status_ratelimit": count(wrapMap(l.StatusRatelimit)),
		"login_ratelimit":  count(wrapMap(l.LoginRatelimit)),
		"syn_ratelimit":    count(wrapMap(l.SynRatelimit)),
		"conn_ratelimit":   count(wrapMap(l.ConnRatelimit)),
		"health":           count(wrapMap(l.Health)),
		"ip_drop_history":  count(wrapMap(l.IPDropHistory)),
	}
}

func readCounters(l *loader.Loaded) map[string]uint64 {
	if l.Stats == nil {
		return nil
	}
	vals, err := readStatsMap(l.Stats)
	if err != nil {
		return nil
	}
	out := make(map[string]uint64, len(statLabels))
	for i, lbl := range statLabels {
		out[lbl] = vals[i]
	}
	return out
}

func registerAPI(mux *http.ServeMux, cfg apiCfg) {
	l := cfg.Loaded
	mux.HandleFunc("/health", handleHealthz(
		func() bool { return l.XDPLink != nil },
		func() bool { return l.SockopsLink != nil },
	))
	mux.HandleFunc("/api/info", handleInfo(cfg))
	mux.HandleFunc("/api/stats", handleStats(l))
	mux.HandleFunc("/api/top", handleTop(cfg))
	mux.HandleFunc("/api/health", handleHealth(wrapMap(l.Health)))
	mux.HandleFunc("/api/whitelist", handleTimestampMap(wrapMap(l.TCPWhitelist)))
	mux.HandleFunc("/api/established", handleTimestampMap(wrapMap(l.TCPEstablished)))
	mux.HandleFunc("/api/syn-seen", handleTimestampMap(wrapMap(l.TCPSynSeen)))
	mux.HandleFunc("/api/open-count", handleCountMap(wrapMap(l.TCPOpenCount)))
	mux.HandleFunc("/api/blacklist", handleBlacklist(wrapMap(l.Health)))
	mux.HandleFunc("/api/drop-history", handleDropHistory(wrapMap(l.IPDropHistory)))
	mux.HandleFunc("/api/ip/", handleIPLookup(l))
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []string{
			"/api/info",
			"/api/stats",
			"/api/top?map=<name>&n=<N>",
			"/api/health",
			"/api/whitelist",
			"/api/blacklist",
			"/api/established",
			"/api/syn-seen",
			"/api/open-count",
			"/api/drop-history",
			"/api/ip/<addr>",
		})
	})
}
