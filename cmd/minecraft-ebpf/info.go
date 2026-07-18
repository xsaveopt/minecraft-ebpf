package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
)

var perIPMaps = []string{
	"tcp_whitelist",
	"tcp_established",
	"tcp_syn_seen",
	"tcp_open_count",
	"status_ratelimit",
	"login_ratelimit",
	"health",
	"ip_drop_history",
}

func mapEntryCount(pinPath, name string) int64 {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
	if err != nil {
		return -1
	}
	defer func() { _ = m.Close() }()
	var n int64
	var key [4]byte
	val := make([]byte, m.ValueSize())
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		n++
	}
	return n
}

func blacklistedNow(pinPath string) int64 {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, "health"), nil)
	if err != nil {
		return -1
	}
	defer func() { _ = m.Close() }()
	now := bootTimeNS()
	var n int64
	var key [4]byte
	var val struct {
		Anomalies        uint32
		_                uint32
		WindowStartNS    uint64
		BlacklistUntilNS uint64
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.BlacklistUntilNS > now {
			n++
		}
	}
	return n
}

func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	pinPath := fs.String("pin-path", "/sys/fs/bpf/minecraft", "bpf map pin directory")
	_ = fs.Parse(args)

	fmt.Printf("minecraft-ebpf %s\n", version)
	fmt.Printf("  pin path: %s\n", *pinPath)

	if _, err := os.Stat(*pinPath); err != nil {
		fmt.Fprintln(os.Stderr, "  (no pinned maps — daemon not running?)")
		os.Exit(1)
	}

	stats, err := ebpf.LoadPinnedMap(filepath.Join(*pinPath, "stats"), nil)
	if err == nil {
		defer func() { _ = stats.Close() }()
		if vals, _ := readStatsMap(stats); vals != nil {
			byLabel := map[string]uint64{}
			for i, lbl := range statLabels {
				byLabel[lbl] = vals[i]
			}
			passTCP := byLabel["pass_tcp"]
			var dropTCP uint64
			for lbl, v := range byLabel {
				if strings.HasPrefix(lbl, "drop_") {
					dropTCP += v
				}
			}
			fmt.Printf("  tcp: %d pass / %d drop\n", passTCP, dropTCP)
		}
	}

	fmt.Println("  map populations:")
	for _, name := range perIPMaps {
		n := mapEntryCount(*pinPath, name)
		if n < 0 {
			fmt.Printf("    %-22s (closed)\n", name)
		} else {
			fmt.Printf("    %-22s %d\n", name, n)
		}
	}
	if bl := blacklistedNow(*pinPath); bl >= 0 {
		fmt.Printf("    %-22s %d\n", "health (blacklisted)", bl)
	}
}
