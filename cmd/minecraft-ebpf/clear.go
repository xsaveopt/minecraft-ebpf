package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

func cmdClear(args []string) {
	fs := flag.NewFlagSet("clear", flag.ExitOnError)
	pinPath := fs.String("pin-path", "/sys/fs/bpf/minecraft", "bpf map pin directory")
	which := fs.String("map", "whitelist", "which map to clear: whitelist | established | syn-seen | open-count | status-ratelimit | login-ratelimit | syn-ratelimit | conn-ratelimit | health | drop-history | all")
	ipFlag := fs.String("ip", "", "if set, only clear this single IPv4 from the target map(s) instead of wiping every entry")
	_ = fs.Parse(args)

	targets := []string{}
	switch *which {
	case "whitelist":
		targets = []string{"tcp_whitelist"}
	case "established":
		targets = []string{"tcp_established"}
	case "syn-seen":
		targets = []string{"tcp_syn_seen"}
	case "open-count":
		targets = []string{"tcp_open_count"}
	case "status-ratelimit":
		targets = []string{"status_ratelimit"}
	case "login-ratelimit":
		targets = []string{"login_ratelimit"}
	case "syn-ratelimit":
		targets = []string{"syn_ratelimit"}
	case "conn-ratelimit":
		targets = []string{"conn_ratelimit"}
	case "health":
		targets = []string{"health"}
	case "drop-history":
		targets = []string{"ip_drop_history"}
	case "all":
		targets = []string{"tcp_whitelist", "tcp_established", "tcp_syn_seen", "tcp_open_count", "status_ratelimit", "login_ratelimit", "syn_ratelimit", "conn_ratelimit", "health", "ip_drop_history"}
	default:
		fmt.Fprintln(os.Stderr, "unknown map:", *which)
		os.Exit(2)
	}

	if *ipFlag != "" {
		key, err := parseIPv4Key(*ipFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, name := range targets {
			n, err := clearMapKey(filepath.Join(*pinPath, name), key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
				continue
			}
			if n == 1 {
				fmt.Printf("%s: removed %s\n", name, *ipFlag)
			} else {
				fmt.Printf("%s: %s not present\n", name, *ipFlag)
			}
		}
		return
	}

	for _, name := range targets {
		n, err := clearMap(filepath.Join(*pinPath, name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			continue
		}
		fmt.Printf("%s: cleared %d entries\n", name, n)
	}
}

func parseIPv4Key(s string) ([4]byte, error) {
	var key [4]byte
	parsed := net.ParseIP(s)
	if parsed == nil {
		return key, fmt.Errorf("invalid IP: %q", s)
	}
	v4 := parsed.To4()
	if v4 == nil {
		return key, fmt.Errorf("not an IPv4 address: %q", s)
	}
	copy(key[:], v4)
	return key, nil
}

func clearMapKey(path string, key [4]byte) (int, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return 0, err
	}
	defer m.Close()

	if err := m.Delete(&key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, nil
		}
		return 0, err
	}
	return 1, nil
}

func clearMap(path string) (int, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return 0, err
	}
	defer m.Close()

	keys, err := collectKeys(m)
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		_ = m.Delete(&k)
	}
	return len(keys), nil
}

func collectKeys(m *ebpf.Map) ([][4]byte, error) {
	var key [4]byte
	valBuf := make([]byte, m.ValueSize())
	var keys [][4]byte
	iter := m.Iterate()
	for iter.Next(&key, &valBuf) {
		keys = append(keys, key)
	}
	return keys, iter.Err()
}
