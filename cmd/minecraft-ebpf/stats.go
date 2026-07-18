package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
)

var statLabels = []string{
	"pass_tcp",
	"tcp_established_inserts",
	"tcp_l7_promoted",
	"tcp_l7_match_no_est",
	"tcp_handshake_status_seen",
	"tcp_handshake_login_seen",
	"drop_tcp_no_syn",
	"drop_tcp_too_many_open",
	"drop_tcp_global_ratelimit",
	"drop_status_ratelimit",
	"drop_login_ratelimit",
	"drop_malformed_handshake",
	"drop_tcp_unhealthy",
	"drop_tcp_bad_flags",
	"drop_conn_ratelimit",
	"drop_tcp_conn_rate",
}

func readStatsMap(m *ebpf.Map) ([]uint64, error) {
	ncpu, err := ebpf.PossibleCPU()
	if err != nil || ncpu <= 0 {
		ncpu = 1
	}
	perCPU := make([]uint64, ncpu)
	out := make([]uint64, len(statLabels))
	for i := range statLabels {
		k := uint32(i)
		if err := m.Lookup(&k, &perCPU); err != nil {
			return nil, fmt.Errorf("slot %d: %w", i, err)
		}
		var s uint64
		for _, v := range perCPU {
			s += v
		}
		out[i] = s
	}
	return out, nil
}

func cmdStats(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	pinPath := fs.String("pin-path", "/sys/fs/bpf/minecraft", "bpf map pin directory")
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	watch := fs.Duration("watch", 0, "repeat every N (e.g. 1s); 0 = run once")
	_ = fs.Parse(args)

	dump := func() error {
		m, err := ebpf.LoadPinnedMap(filepath.Join(*pinPath, "stats"), nil)
		if err != nil {
			return err
		}
		defer func() { _ = m.Close() }()
		vals, err := readStatsMap(m)
		if err != nil {
			return err
		}
		if *asJSON {
			obj := make(map[string]uint64, len(statLabels))
			for i, lbl := range statLabels {
				obj[lbl] = vals[i]
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(obj)
		}
		for i, lbl := range statLabels {
			fmt.Printf("%-32s %d\n", lbl, vals[i])
		}
		return nil
	}

	if *watch == 0 {
		if err := dump(); err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
			os.Exit(1)
		}
		return
	}

	for {
		fmt.Print("\x1b[H\x1b[2J")
		fmt.Printf("# minecraft-ebpf stats — %s (refresh %s)\n", time.Now().Format(time.TimeOnly), *watch)
		if err := dump(); err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
		}
		time.Sleep(*watch)
	}
}
