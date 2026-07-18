package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
)

func cmdHealth(args []string) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	pinPath := fs.String("pin-path", "/sys/fs/bpf/minecraft", "bpf map pin directory")
	all := fs.Bool("all", false, "include IPs that have anomalies but aren't blacklisted")
	_ = fs.Parse(args)

	m, err := ebpf.LoadPinnedMap(filepath.Join(*pinPath, "health"), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open health:", err)
		os.Exit(1)
	}
	defer func() { _ = m.Close() }()

	now := bootTimeNS()
	fmt.Printf("%-16s %-10s %-12s %s\n", "IP", "ANOMALIES", "WINDOW_AGE", "BLACKLIST")

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
		if !*all && !blacklisted {
			continue
		}
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		wAge := time.Duration(int64(now) - int64(val.WindowStartNS))
		if wAge < 0 {
			wAge = 0
		}
		bl := "-"
		if blacklisted {
			rem := time.Duration(int64(val.BlacklistUntilNS) - int64(now))
			bl = "in " + rem.Truncate(time.Second).String()
		}
		fmt.Printf("%-16s %-10d %-12s %s\n",
			ip.String(), val.Anomalies, wAge.Truncate(time.Second), bl)
	}
}
