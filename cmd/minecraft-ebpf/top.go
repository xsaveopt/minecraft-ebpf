package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

type topRow struct {
	IP          string            `json:"ip"`
	Sort        int64             `json:"-"`
	Display     string            `json:"-"`
	Tokens      uint64            `json:"tokens,omitempty"`
	Count       uint64            `json:"count,omitempty"`
	AgeSeconds  int64             `json:"age_seconds,omitempty"`
	Anomalies   uint32            `json:"anomalies,omitempty"`
	Blacklisted bool              `json:"blacklisted,omitempty"`
	Total       uint64            `json:"total,omitempty"`
	ByReason    map[string]uint64 `json:"by_reason,omitempty"`
}

var topMapKinds = map[string]struct {
	pinned string
	kind   string
}{
	"whitelist":        {"tcp_whitelist", "timestamp"},
	"established":      {"tcp_established", "timestamp"},
	"syn-seen":         {"tcp_syn_seen", "timestamp"},
	"open-count":       {"tcp_open_count", "count"},
	"status-ratelimit": {"status_ratelimit", "ratelimit"},
	"login-ratelimit":  {"login_ratelimit", "ratelimit"},
	"syn-ratelimit":    {"syn_ratelimit", "ratelimit"},
	"conn-ratelimit":   {"conn_ratelimit", "conn-limit"},
	"health":           {"health", "health"},
	"drop-history":     {"ip_drop_history", "drop-reasons"},
}

func topFromMap(pinPath, which string, n int, reason string) ([]topRow, error) {
	mt, ok := topMapKinds[which]
	if !ok {
		return nil, fmt.Errorf("unknown map: %s", which)
	}
	reasonIdx := -1
	if reason != "" {
		for i, name := range dropReasonNames {
			if name == reason {
				reasonIdx = i
				break
			}
		}
		if reasonIdx < 0 {
			return nil, fmt.Errorf("unknown reason: %s", reason)
		}
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, mt.pinned), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = m.Close() }()

	now := bootTimeNS()
	var rows []topRow
	var key [4]byte

	switch mt.kind {
	case "timestamp":
		var v uint64
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			age := int64(now) - int64(v)
			if age < 0 {
				age = 0
			}
			ageS := age / 1_000_000_000
			rows = append(rows, topRow{
				IP:         ipv4Str(key),
				Sort:       -ageS,
				AgeSeconds: ageS,
				Display:    fmt.Sprintf("age=%s", time.Duration(age).Truncate(time.Second)),
			})
		}
	case "count":
		var v uint64
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			rows = append(rows, topRow{
				IP:      ipv4Str(key),
				Sort:    int64(v),
				Count:   v,
				Display: fmt.Sprintf("count=%d", v),
			})
		}
	case "ratelimit":
		var v struct {
			Tokens       uint64
			LastRefillNS uint64
		}
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			age := int64(now) - int64(v.LastRefillNS)
			if age < 0 {
				age = 0
			}
			rows = append(rows, topRow{
				IP:         ipv4Str(key),
				Sort:       -int64(v.Tokens),
				Tokens:     v.Tokens,
				AgeSeconds: age / 1_000_000_000,
				Display: fmt.Sprintf("tokens=%d refill_age=%s",
					v.Tokens, time.Duration(age).Truncate(time.Second)),
			})
		}
	case "health":
		var v struct {
			Anomalies        uint32
			_                uint32
			WindowStartNS    uint64
			BlacklistUntilNS uint64
		}
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			wAge := int64(now) - int64(v.WindowStartNS)
			if wAge < 0 {
				wAge = 0
			}
			tag := ""
			if v.BlacklistUntilNS > now {
				rem := time.Duration(int64(v.BlacklistUntilNS) - int64(now))
				tag = fmt.Sprintf(" BLACKLISTED unblock_in=%s", rem.Truncate(time.Second))
			}
			rows = append(rows, topRow{
				IP:          ipv4Str(key),
				Sort:        int64(v.Anomalies),
				Anomalies:   v.Anomalies,
				Blacklisted: v.BlacklistUntilNS > now,
				AgeSeconds:  wAge / 1_000_000_000,
				Display: fmt.Sprintf("anomalies=%d window_age=%s%s",
					v.Anomalies, time.Duration(wAge).Truncate(time.Second), tag),
			})
		}
	case "conn-limit":
		var v struct {
			PktTokens  uint64
			PktLastNS  uint64
			ByteTokens uint64
			ByteLastNS uint64
		}
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			age := int64(now) - int64(v.PktLastNS)
			if age < 0 {
				age = 0
			}
			rows = append(rows, topRow{
				IP:         ipv4Str(key),
				Sort:       -int64(v.PktTokens),
				Tokens:     v.PktTokens,
				AgeSeconds: age / 1_000_000_000,
				Display: fmt.Sprintf("pkt_tokens=%d byte_tokens=%d refill_age=%s",
					v.PktTokens, v.ByteTokens, time.Duration(age).Truncate(time.Second)),
			})
		}
	case "drop-reasons":
		var v struct {
			FirstDropNS uint64
			LastDropNS  uint64
			Counts      [10]uint64
		}
		iter := m.Iterate()
		for iter.Next(&key, &v) {
			var total uint64
			by := make(map[string]uint64)
			for i, c := range v.Counts {
				if c == 0 {
					continue
				}
				total += c
				by[dropReasonNames[i]] = c
			}
			sortKey := int64(total)
			if reasonIdx >= 0 {
				sortKey = int64(v.Counts[reasonIdx])
			}
			parts := make([]string, 0, len(by))
			for _, name := range dropReasonNames {
				if c, ok := by[name]; ok {
					parts = append(parts, fmt.Sprintf("%s=%d", name, c))
				}
			}
			rows = append(rows, topRow{
				IP:       ipv4Str(key),
				Sort:     sortKey,
				Total:    total,
				ByReason: by,
				Display:  fmt.Sprintf("total=%d %s", total, strings.Join(parts, ",")),
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].Sort > rows[j].Sort })
	if n > 0 && len(rows) > n {
		rows = rows[:n]
	}
	return rows, nil
}

func cmdTop(args []string) {
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	pinPath := fs.String("pin-path", "/sys/fs/bpf/minecraft", "bpf map pin directory")
	which := fs.String("map", "open-count", "which map: whitelist | established | syn-seen | open-count | status-ratelimit | login-ratelimit | syn-ratelimit | conn-ratelimit | health | drop-history")
	n := fs.Int("n", 10, "max entries to print (0 for all)")
	reason := fs.String("reason", "", "for --map drop-history: rank by this reason instead of total drops (e.g. login_ratelimit)")
	_ = fs.Parse(args)

	rows, err := topFromMap(*pinPath, *which, *n, *reason)
	if err != nil {
		fmt.Fprintln(os.Stderr, "top:", err)
		os.Exit(1)
	}
	if len(rows) == 0 {
		fmt.Println("(empty)")
		return
	}
	for _, r := range rows {
		fmt.Printf("%-16s %s\n", r.IP, r.Display)
	}
}
