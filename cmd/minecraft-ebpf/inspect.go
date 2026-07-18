package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

func cmdInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	pinPath := fs.String("pin-path", "/sys/fs/bpf/minecraft", "bpf map pin directory")
	watch := fs.Duration("watch", 0, "repeat every N (e.g. 1s); 0 = run once")
	_ = fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: minecraft-ebpf inspect <ipv4> [--watch 1s]")
		os.Exit(2)
	}
	addr := fs.Arg(0)
	parsed := net.ParseIP(addr)
	if parsed == nil {
		fmt.Fprintln(os.Stderr, "invalid IP:", addr)
		os.Exit(2)
	}
	v4 := parsed.To4()
	if v4 == nil {
		fmt.Fprintln(os.Stderr, "IPv4 only:", addr)
		os.Exit(2)
	}
	var key [4]byte
	copy(key[:], v4)

	dump := func() {
		now := bootTimeNS()
		fmt.Printf("IP %s\n", addr)
		inspectTimestamp(*pinPath, "tcp_whitelist", key, now)
		inspectTimestamp(*pinPath, "tcp_established", key, now)
		inspectTimestamp(*pinPath, "tcp_syn_seen", key, now)
		inspectCount(*pinPath, "tcp_open_count", key)
		inspectRatelimit(*pinPath, "status_ratelimit", key, now)
		inspectRatelimit(*pinPath, "login_ratelimit", key, now)
		inspectRatelimit(*pinPath, "syn_ratelimit", key, now)
		inspectConnLimit(*pinPath, "conn_ratelimit", key, now)
		inspectHealth(*pinPath, "health", key, now)
		inspectDropHistory(*pinPath, "ip_drop_history", key, now)
	}

	if *watch == 0 {
		dump()
		return
	}
	for {
		fmt.Print("\x1b[H\x1b[2J")
		fmt.Printf("# minecraft-ebpf inspect — %s (refresh %s)\n", time.Now().Format(time.TimeOnly), *watch)
		dump()
		time.Sleep(*watch)
	}
}

const inspectLabelWidth = 22

func inspectLine(name, body string) {
	fmt.Printf("  %-*s %s\n", inspectLabelWidth, name, body)
}

func openPinned(pinPath, name string) (*ebpf.Map, bool) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, name), nil)
	if err != nil {
		inspectLine(name, fmt.Sprintf("(open: %v)", err))
		return nil, false
	}
	return m, true
}

func inspectTimestamp(pinPath, name string, key [4]byte, now uint64) {
	m, ok := openPinned(pinPath, name)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return
	}
	age := time.Duration(int64(now) - int64(val))
	if age < 0 {
		age = 0
	}
	inspectLine(name, fmt.Sprintf("age=%s", age.Truncate(time.Second)))
}

func inspectCount(pinPath, name string, key [4]byte) {
	m, ok := openPinned(pinPath, name)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()
	var val uint64
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return
	}
	inspectLine(name, fmt.Sprintf("count=%d", val))
}

func inspectConnLimit(pinPath, name string, key [4]byte, now uint64) {
	m, ok := openPinned(pinPath, name)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()
	var val struct {
		PktTokens  uint64
		PktLastNS  uint64
		ByteTokens uint64
		ByteLastNS uint64
	}
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return
	}
	age := time.Duration(int64(now) - int64(val.PktLastNS))
	if age < 0 {
		age = 0
	}
	inspectLine(name, fmt.Sprintf("pkt_tokens=%d byte_tokens=%d refill_age=%s",
		val.PktTokens, val.ByteTokens, age.Truncate(time.Second)))
}

func inspectRatelimit(pinPath, name string, key [4]byte, now uint64) {
	m, ok := openPinned(pinPath, name)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()
	var val struct {
		Tokens       uint64
		LastRefillNS uint64
	}
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return
	}
	age := time.Duration(int64(now) - int64(val.LastRefillNS))
	if age < 0 {
		age = 0
	}
	inspectLine(name, fmt.Sprintf("tokens=%d refill_age=%s",
		val.Tokens, age.Truncate(time.Second)))
}

func inspectHealth(pinPath, name string, key [4]byte, now uint64) {
	m, ok := openPinned(pinPath, name)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()
	var val struct {
		Anomalies        uint32
		_                uint32
		WindowStartNS    uint64
		BlacklistUntilNS uint64
	}
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return
	}
	wAge := time.Duration(int64(now) - int64(val.WindowStartNS))
	if wAge < 0 {
		wAge = 0
	}
	body := fmt.Sprintf("anomalies=%d window_age=%s",
		val.Anomalies, wAge.Truncate(time.Second))
	if val.BlacklistUntilNS > now {
		remaining := time.Duration(int64(val.BlacklistUntilNS) - int64(now))
		body += fmt.Sprintf(" BLACKLISTED unblock_in=%s",
			remaining.Truncate(time.Second))
	} else {
		body += " blacklisted=no"
	}
	inspectLine(name, body)
}

func inspectDropHistory(pinPath, name string, key [4]byte, now uint64) {
	m, ok := openPinned(pinPath, name)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()
	var val struct {
		FirstDropNS uint64
		LastDropNS  uint64
		Counts      [10]uint64
	}
	if err := m.Lookup(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			inspectLine(name, "-")
		} else {
			inspectLine(name, fmt.Sprintf("(lookup: %v)", err))
		}
		return
	}
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
	body := fmt.Sprintf("first=%s last=%s total=%d",
		first.Truncate(time.Second), last.Truncate(time.Second), total)
	if len(parts) > 0 {
		body += " " + strings.Join(parts, ",")
	}
	inspectLine(name, body)
}
