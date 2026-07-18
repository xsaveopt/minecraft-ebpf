package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func cmdDump(args []string) {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	pinPath := fs.String("pin-path", "/sys/fs/bpf/minecraft", "bpf map pin directory")
	which := fs.String("map", "whitelist", "which map to dump: whitelist | established | syn-seen | open-count | status-ratelimit | login-ratelimit | health | drop-history | all")
	_ = fs.Parse(args)

	switch *which {
	case "whitelist":
		dumpTimestampMap(*pinPath, "tcp_whitelist")
	case "established":
		dumpTimestampMap(*pinPath, "tcp_established")
	case "syn-seen":
		dumpTimestampMap(*pinPath, "tcp_syn_seen")
	case "open-count":
		dumpCountMap(*pinPath, "tcp_open_count")
	case "status-ratelimit":
		dumpRatelimitMap(*pinPath, "status_ratelimit")
	case "login-ratelimit":
		dumpRatelimitMap(*pinPath, "login_ratelimit")
	case "health":
		dumpHealthMap(*pinPath, "health")
	case "drop-history":
		dumpDropHistoryMap(*pinPath, "ip_drop_history")
	case "all":
		fmt.Println("== tcp_established ==")
		dumpTimestampMap(*pinPath, "tcp_established")
		fmt.Println("\n== tcp_syn_seen ==")
		dumpTimestampMap(*pinPath, "tcp_syn_seen")
		fmt.Println("\n== tcp_open_count ==")
		dumpCountMap(*pinPath, "tcp_open_count")
		fmt.Println("\n== tcp_whitelist ==")
		dumpTimestampMap(*pinPath, "tcp_whitelist")
		fmt.Println("\n== status_ratelimit ==")
		dumpRatelimitMap(*pinPath, "status_ratelimit")
		fmt.Println("\n== login_ratelimit ==")
		dumpRatelimitMap(*pinPath, "login_ratelimit")
		fmt.Println("\n== health ==")
		dumpHealthMap(*pinPath, "health")
		fmt.Println("\n== ip_drop_history ==")
		dumpDropHistoryMap(*pinPath, "ip_drop_history")
	default:
		fmt.Fprintln(os.Stderr, "unknown map:", *which)
		os.Exit(2)
	}
}

func dumpTimestampMap(pinPath, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer func() { _ = m.Close() }()

	now := bootTimeNS()
	fmt.Printf("%-16s %-12s\n", "IP", "AGE")
	var key [4]byte
	var val uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		age := time.Duration(int64(now) - int64(val))
		if age < 0 {
			age = 0
		}
		fmt.Printf("%-16s %-12s\n", ip.String(), age.Truncate(time.Second))
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}

func dumpCountMap(pinPath, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer func() { _ = m.Close() }()

	fmt.Printf("%-16s %-10s\n", "IP", "OPEN")
	var key [4]byte
	var val uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		fmt.Printf("%-16s %-10d\n", ip.String(), val)
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}

func dumpRatelimitMap(pinPath, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer func() { _ = m.Close() }()

	now := bootTimeNS()
	fmt.Printf("%-16s %-10s %-12s\n", "IP", "TOKENS", "LAST_REFILL")
	var key [4]byte
	var val struct {
		Tokens       uint64
		LastRefillNS uint64
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		age := time.Duration(int64(now) - int64(val.LastRefillNS))
		if age < 0 {
			age = 0
		}
		fmt.Printf("%-16s %-10d %-12s\n", ip.String(), val.Tokens, age.Truncate(time.Millisecond))
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}

func dumpHealthMap(pinPath, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer func() { _ = m.Close() }()

	now := bootTimeNS()
	fmt.Printf("%-16s %-10s %-12s %-12s\n", "IP", "ANOMALIES", "WINDOW_AGE", "BLACKLIST")
	var key [4]byte
	var val struct {
		Anomalies        uint32
		_                uint32
		WindowStartNS    uint64
		BlacklistUntilNS uint64
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		windowAge := time.Duration(int64(now) - int64(val.WindowStartNS))
		if windowAge < 0 {
			windowAge = 0
		}
		bl := "-"
		if val.BlacklistUntilNS > now {
			remaining := time.Duration(int64(val.BlacklistUntilNS) - int64(now))
			bl = "in " + remaining.Truncate(time.Second).String()
		}
		fmt.Printf("%-16s %-10d %-12s %-12s\n",
			ip.String(), val.Anomalies,
			windowAge.Truncate(time.Second), bl)
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}

func dumpDropHistoryMap(pinPath, name string) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open", name+":", err)
		return
	}
	defer func() { _ = m.Close() }()

	now := bootTimeNS()
	fmt.Printf("%-16s %-12s %-12s %-10s %s\n", "IP", "FIRST_AGE", "LAST_AGE", "TOTAL", "BY_REASON")
	var key [4]byte
	var val struct {
		FirstDropNS uint64
		LastDropNS  uint64
		Counts      [10]uint64
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := net.IPv4(key[0], key[1], key[2], key[3])
		first := time.Duration(int64(now) - int64(val.FirstDropNS))
		if first < 0 {
			first = 0
		}
		last := time.Duration(int64(now) - int64(val.LastDropNS))
		if last < 0 {
			last = 0
		}
		var total uint64
		var parts []string
		for i, c := range val.Counts {
			if c == 0 {
				continue
			}
			total += c
			parts = append(parts, fmt.Sprintf("%s=%d", dropReasonNames[i], c))
		}
		fmt.Printf("%-16s %-12s %-12s %-10d %s\n",
			ip.String(),
			first.Truncate(time.Second),
			last.Truncate(time.Second),
			total,
			strings.Join(parts, ","))
	}
	if err := iter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iter:", err)
	}
}

func bootTimeNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}
