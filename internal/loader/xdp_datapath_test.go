package loader

import (
	"testing"

	"github.com/cilium/ebpf"
)

var (
	peerA = [4]byte{192, 0, 2, 10}
	peerB = [4]byte{192, 0, 2, 20}
	peerC = [4]byte{198, 51, 100, 30}
	peerD = [4]byte{198, 51, 100, 40}
)

const farFuturePeriod = uint64(1) << 40

func TestXDPIgnoresTrafficThatIsNotForTheTargetPort(t *testing.T) {
	obj := loadTestXDP(t, nil)

	expectVerdict(t, obj, tcpPacket(peerA, 80, 0, nil), xdpPass)

	nonIP := tcpPacket(peerA, testPort, 0, nil)
	nonIP[12], nonIP[13] = 0x86, 0xDD
	expectVerdict(t, obj, nonIP, xdpPass)

	udp := tcpPacket(peerA, testPort, 0, nil)
	udp[14+9] = 17
	expectVerdict(t, obj, udp, xdpPass)

	if got := statTotal(t, obj.Stats, statDropTCPBadFlags); got != 0 {
		t.Fatalf("drop_tcp_bad_flags = %d for traffic that is not for the target port", got)
	}
}

func TestBogusTCPFlagCombinationsAreDropped(t *testing.T) {
	cases := []struct {
		name  string
		flags byte
	}{
		{"null scan", 0},
		{"syn fin", tcpSYN | tcpFIN},
		{"syn rst", tcpSYN | tcpRST},
		{"fin rst", tcpFIN | tcpRST},
		{"xmas without ack", tcpFIN | tcpPSH | tcpURG},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj := loadTestXDP(t, nil)
			putTimestamp(t, obj.TcpEstablished, peerA, bootNow(t))
			expectVerdict(t, obj, tcpPacket(peerA, testPort, tc.flags, nil), xdpDrop)
			if got := statTotal(t, obj.Stats, statDropTCPBadFlags); got != 1 {
				t.Errorf("drop_tcp_bad_flags = %d, want 1", got)
			}
			h := lookupValue[minecraftXDPIpDropHistory](t, obj.IpDropHistory, peerA)
			if h.Counts[reasonTCPBadFlags] != 1 {
				t.Errorf("drop history counts %v, want one tcp_bad_flags drop", h.Counts)
			}
		})
	}
}

func TestLegitimateTCPFlagCombinationsAreNotBogus(t *testing.T) {
	cases := []struct {
		name  string
		flags byte
	}{
		{"syn", tcpSYN},
		{"ack", tcpACK},
		{"psh ack", tcpPSH | tcpACK},
		{"fin ack", tcpFIN | tcpACK},
		{"rst", tcpRST},
		{"rst ack", tcpRST | tcpACK},
		{"urg ack", tcpURG | tcpACK},
		{"fin psh urg ack", tcpFIN | tcpPSH | tcpURG | tcpACK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj := loadTestXDP(t, nil)
			putTimestamp(t, obj.TcpEstablished, peerA, bootNow(t))
			expectVerdict(t, obj, tcpPacket(peerA, testPort, tc.flags, nil), xdpPass)
			if got := statTotal(t, obj.Stats, statDropTCPBadFlags); got != 0 {
				t.Errorf("drop_tcp_bad_flags = %d, want 0", got)
			}
		})
	}
}

func TestNonSYNFromAnUnknownSourceIsDropped(t *testing.T) {
	obj := loadTestXDP(t, nil)
	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpDrop)
	if got := statTotal(t, obj.Stats, statDropTCPNoSyn); got != 1 {
		t.Errorf("drop_tcp_no_syn = %d, want 1", got)
	}
	if got := statTotal(t, obj.Stats, statPassTCP); got != 0 {
		t.Errorf("pass_tcp = %d, want 0", got)
	}
}

func TestNonSYNPassesOnceTheSourceSentASYNOrIsEstablished(t *testing.T) {
	obj := loadTestXDP(t, nil)
	putTimestamp(t, obj.TcpSynSeen, peerA, bootNow(t))
	putTimestamp(t, obj.TcpEstablished, peerB, bootNow(t))

	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpPass)
	expectVerdict(t, obj, tcpPacket(peerB, testPort, tcpACK, nil), xdpPass)
	if got := statTotal(t, obj.Stats, statDropTCPNoSyn); got != 0 {
		t.Errorf("drop_tcp_no_syn = %d, want 0", got)
	}
}

func TestSYNMarksTheSourceAsSeen(t *testing.T) {
	obj := loadTestXDP(t, nil)
	before := bootNow(t)
	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpSYN, nil), xdpPass)
	seen := lookupValue[uint64](t, obj.TcpSynSeen, peerA)
	if seen < before || seen > bootNow(t) {
		t.Errorf("tcp_syn_seen timestamp %d is outside the run window starting %d", seen, before)
	}
	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpPass)
	if got := statTotal(t, obj.Stats, statPassTCP); got != 2 {
		t.Errorf("pass_tcp = %d, want 2", got)
	}
}

func TestSYNOverTheOpenConnectionCapIsDropped(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{"tcp_max_open_per_ip": uint64(2)})
	putValue(t, obj.TcpOpenCount, peerA, uint64(2))
	putValue(t, obj.TcpOpenCount, peerB, uint64(1))

	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpSYN, nil), xdpDrop)
	expectVerdict(t, obj, tcpPacket(peerB, testPort, tcpSYN, nil), xdpPass)

	if got := statTotal(t, obj.Stats, statDropTCPTooManyOpen); got != 1 {
		t.Errorf("drop_tcp_too_many_open = %d, want 1", got)
	}
	h := lookupValue[minecraftXDPIpDropHistory](t, obj.IpDropHistory, peerA)
	if h.Counts[reasonTCPTooManyOpen] != 1 {
		t.Errorf("drop history counts %v, want one tcp_too_many_open drop", h.Counts)
	}
	if hasKey(t, obj.TcpSynSeen, peerA) {
		t.Error("a SYN dropped for the open-connection cap still marked the source as seen")
	}
}

func TestPerIPNewConnectionRateDropsSYNsBeyondTheBurst(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{
		"conn_new_period_ns": farFuturePeriod,
		"conn_new_burst":     uint64(2),
	})
	syn := tcpPacket(peerA, testPort, tcpSYN, nil)
	expectVerdict(t, obj, syn, xdpPass)
	expectVerdict(t, obj, syn, xdpPass)
	expectVerdict(t, obj, syn, xdpDrop)
	expectVerdict(t, obj, tcpPacket(peerB, testPort, tcpSYN, nil), xdpPass)

	if got := statTotal(t, obj.Stats, statDropTCPConnRate); got != 1 {
		t.Errorf("drop_tcp_conn_rate = %d, want 1", got)
	}
	h := lookupValue[minecraftXDPIpDropHistory](t, obj.IpDropHistory, peerA)
	if h.Counts[reasonTCPConnRate] != 1 {
		t.Errorf("drop history counts %v, want one tcp_conn_rate drop", h.Counts)
	}
}

func setGlobalBucket(t *testing.T, obj *minecraftXDPObjects, tokens, last uint64) {
	t.Helper()
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible cpus: %v", err)
	}
	vals := make([]minecraftXDPRatelimit, ncpu)
	for i := range vals {
		vals[i] = minecraftXDPRatelimit{Tokens: tokens, LastRefillNs: last}
	}
	zero := uint32(0)
	if err := obj.TcpGlobalRatelimit.Put(&zero, vals); err != nil {
		t.Fatalf("put global bucket: %v", err)
	}
}

func TestGlobalSYNCircuitBreaker(t *testing.T) {
	vars := map[string]any{
		"tcp_global_period_ns": farFuturePeriod,
		"tcp_global_burst":     uint64(4),
	}

	t.Run("empty bucket drops", func(t *testing.T) {
		obj := loadTestXDP(t, vars)
		setGlobalBucket(t, obj, 0, bootNow(t))
		expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpSYN, nil), xdpDrop)
		if got := statTotal(t, obj.Stats, statDropTCPGlobalRatelimit); got != 1 {
			t.Errorf("drop_tcp_global_ratelimit = %d, want 1", got)
		}
		h := lookupValue[minecraftXDPIpDropHistory](t, obj.IpDropHistory, peerA)
		if h.Counts[reasonTCPGlobalRatelimit] != 1 {
			t.Errorf("drop history counts %v, want one tcp_global_ratelimit drop", h.Counts)
		}
	})

	t.Run("bucket with tokens passes", func(t *testing.T) {
		obj := loadTestXDP(t, vars)
		setGlobalBucket(t, obj, 1, bootNow(t))
		expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpSYN, nil), xdpPass)
	})

	t.Run("disabled breaker ignores the bucket", func(t *testing.T) {
		obj := loadTestXDP(t, nil)
		setGlobalBucket(t, obj, 0, bootNow(t))
		expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpSYN, nil), xdpPass)
	})
}

func TestWhitelistedSourceSkipsTheSYNCheckAndRefreshesItsTimestamp(t *testing.T) {
	obj := loadTestXDP(t, nil)
	stale := bootNow(t) - 10_000_000_000
	putTimestamp(t, obj.TcpWhitelist, peerA, stale)

	before := bootNow(t)
	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpPass)
	if got := lookupValue[uint64](t, obj.TcpWhitelist, peerA); got < before {
		t.Errorf("whitelist timestamp %d was not refreshed to at least %d", got, before)
	}
	if got := statTotal(t, obj.Stats, statPassTCP); got != 1 {
		t.Errorf("pass_tcp = %d, want 1", got)
	}
}

func TestWhitelistEntryPastItsTTLIsEvicted(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{"whitelist_ttl_ns": uint64(600_000_000_000)})
	putTimestamp(t, obj.TcpWhitelist, peerA, bootNow(t)-601_000_000_000)

	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpDrop)
	if hasKey(t, obj.TcpWhitelist, peerA) {
		t.Error("an expired whitelist entry was not evicted")
	}
	if got := statTotal(t, obj.Stats, statDropTCPNoSyn); got != 1 {
		t.Errorf("drop_tcp_no_syn = %d, want 1 once the expired entry falls through", got)
	}
}

func TestWhitelistTTLOfZeroNeverExpires(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{"whitelist_ttl_ns": uint64(0)})
	putTimestamp(t, obj.TcpWhitelist, peerA, 1)
	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpPass)
	if !hasKey(t, obj.TcpWhitelist, peerA) {
		t.Error("whitelist entry was evicted although the TTL is disabled")
	}
}

func TestWhitelistedSYNStillRespectsTheOpenConnectionCap(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{"tcp_max_open_per_ip": uint64(1)})
	putTimestamp(t, obj.TcpWhitelist, peerA, bootNow(t))
	putValue(t, obj.TcpOpenCount, peerA, uint64(1))

	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpSYN, nil), xdpDrop)
	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpPass)
	if got := statTotal(t, obj.Stats, statDropTCPTooManyOpen); got != 1 {
		t.Errorf("drop_tcp_too_many_open = %d, want 1", got)
	}
}

func firstSegment(t *testing.T, obj *minecraftXDPObjects, src [4]byte, established bool, payload []byte) uint32 {
	t.Helper()
	now := bootNow(t)
	putTimestamp(t, obj.TcpSynSeen, src, now)
	if established {
		putTimestamp(t, obj.TcpEstablished, src, now)
	}
	if err := obj.TcpFirstData.Delete(&src); err != nil && !isNotExist(err) {
		t.Fatalf("delete first data: %v", err)
	}
	return runXDP(t, obj, tcpPacket(src, testPort, tcpPSH|tcpACK, payload))
}

func TestHandshakeClassificationOnAFirstSegment(t *testing.T) {
	overrun := append([]byte{0x03, 0x00, 0xFD, 0x05}, handshake(2)...)
	trailing := append(handshake(2), 0x00, 0x00)
	trailing[0] = byte(len(trailing) - 1)

	cases := []struct {
		name    string
		payload []byte
		verdict uint32
		slot    int
	}{
		{"status", handshake(1), xdpPass, statTCPHandshakeStatusSeen},
		{"login", handshake(2), xdpPass, statTCPHandshakeLoginSeen},
		{"transfer", handshake(3), xdpPass, statTCPHandshakeLoginSeen},
		{"legacy ping", []byte{0xFE, 0x01}, xdpPass, statTCPHandshakeStatusSeen},
		{"unknown next state", handshake(7), xdpDrop, statDropMalformedHandshake},
		{"declared length below three", []byte{0x02, 0x00, 0x01}, xdpPass, -1},
		{"truncated frame", handshake(2)[:8], xdpPass, -1},
		{"fields overrun the declared length", overrun, xdpPass, -1},
		{"trailing bytes after next state", trailing, xdpPass, -1},
		{"not a handshake packet id", append([]byte{0x03, 0x01}, 0x00, 0x00), xdpPass, -1},
	}
	watched := []uint32{statTCPHandshakeStatusSeen, statTCPHandshakeLoginSeen, statDropMalformedHandshake}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj := loadTestXDP(t, nil)
			if got := firstSegment(t, obj, peerA, false, tc.payload); got != tc.verdict {
				t.Fatalf("verdict %s, want %s", verdictName(got), verdictName(tc.verdict))
			}
			for _, slot := range watched {
				want := uint64(0)
				if int(slot) == tc.slot {
					want = 1
				}
				if got := statTotal(t, obj.Stats, slot); got != want {
					t.Errorf("stat slot %d = %d, want %d", slot, got, want)
				}
			}
		})
	}
}

func TestAnUnestablishedSourceNeverDrivesPerIPAccounting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"status", handshake(1)},
		{"login", handshake(2)},
		{"malformed", handshake(7)},
		{"mid stream", midStreamPlay()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := loadTestXDP(t, nil)
			firstSegment(t, obj, peerA, false, tc.payload)
			for name, m := range map[string]*ebpf.Map{
				"status_ratelimit": obj.StatusRatelimit,
				"login_ratelimit":  obj.LoginRatelimit,
				"conn_ratelimit":   obj.ConnRatelimit,
				"health":           obj.Health,
				"ip_drop_history":  obj.IpDropHistory,
				"tcp_whitelist":    obj.TcpWhitelist,
			} {
				if hasKey(t, m, peerA) {
					t.Errorf("a source with no tcp_established entry wrote %s; a spoofed packet would charge the victim", name)
				}
			}
		})
	}
}

func TestSpoofedHandshakesAreCountedAsUnestablished(t *testing.T) {
	obj := loadTestXDP(t, nil)
	firstSegment(t, obj, peerA, false, handshake(1))
	firstSegment(t, obj, peerB, false, handshake(2))
	if got := statTotal(t, obj.Stats, statTCPL7MatchNoEst); got != 2 {
		t.Errorf("tcp_l7_match_no_est = %d, want 2", got)
	}
	if got := statTotal(t, obj.Stats, statTCPL7Promoted); got != 0 {
		t.Errorf("tcp_l7_promoted = %d, want 0", got)
	}
}

func TestEstablishedHandshakesMeterAgainstTheirBucketAndLoginPromotes(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{
		"status_burst": uint64(20),
		"login_burst":  uint64(8),
	})
	if got := firstSegment(t, obj, peerA, true, handshake(1)); got != xdpPass {
		t.Fatalf("status verdict %s", verdictName(got))
	}
	if got := lookupValue[minecraftXDPRatelimit](t, obj.StatusRatelimit, peerA); got.Tokens != 19 {
		t.Errorf("status bucket holds %d tokens, want 19", got.Tokens)
	}
	if hasKey(t, obj.TcpWhitelist, peerA) {
		t.Error("a status handshake promoted the source to the whitelist")
	}
	if !hasKey(t, obj.TcpFirstData, peerA) {
		t.Error("the first data segment of an established source was not recorded")
	}

	if got := firstSegment(t, obj, peerB, true, handshake(2)); got != xdpPass {
		t.Fatalf("login verdict %s", verdictName(got))
	}
	if got := lookupValue[minecraftXDPRatelimit](t, obj.LoginRatelimit, peerB); got.Tokens != 7 {
		t.Errorf("login bucket holds %d tokens, want 7", got.Tokens)
	}
	if !hasKey(t, obj.TcpWhitelist, peerB) {
		t.Error("a login handshake from an established source was not promoted to the whitelist")
	}
	if got := statTotal(t, obj.Stats, statTCPL7Promoted); got != 1 {
		t.Errorf("tcp_l7_promoted = %d, want 1", got)
	}
}

func TestAnEstablishedPlayerIsNeverDroppedForPayloadThatLooksMalformed(t *testing.T) {
	obj := loadTestXDP(t, nil)
	if got := firstSegment(t, obj, peerA, true, handshake(7)); got != xdpPass {
		t.Fatalf("first segment verdict %s, want XDP_PASS", verdictName(got))
	}
	if got := statTotal(t, obj.Stats, statDropMalformedHandshake); got != 0 {
		t.Errorf("drop_malformed_handshake = %d, want 0", got)
	}
}

func TestLaterSegmentsOfAnEstablishedConnectionAreNotClassified(t *testing.T) {
	obj := loadTestXDP(t, nil)
	now := bootNow(t)
	putTimestamp(t, obj.TcpEstablished, peerA, now)
	putTimestamp(t, obj.TcpFirstData, peerA, now)
	putValue(t, obj.TcpOpenCount, peerA, uint64(1))

	for _, payload := range [][]byte{midStreamPlay(), handshake(1), handshake(7)} {
		expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpPSH|tcpACK, payload), xdpPass)
	}
	for _, slot := range []uint32{statTCPHandshakeStatusSeen, statTCPHandshakeLoginSeen, statDropMalformedHandshake} {
		if got := statTotal(t, obj.Stats, slot); got != 0 {
			t.Errorf("stat slot %d = %d for mid-stream bytes, want 0", slot, got)
		}
	}
}

func TestAHandshakeOnASecondConcurrentConnectionIsStillMetered(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{
		"login_period_ns": farFuturePeriod,
		"login_burst":     uint64(1),
	})
	now := bootNow(t)
	putTimestamp(t, obj.TcpSynSeen, peerA, now)
	putTimestamp(t, obj.TcpEstablished, peerA, now)
	putTimestamp(t, obj.TcpFirstData, peerA, now)
	putValue(t, obj.TcpOpenCount, peerA, uint64(2))
	putValue(t, obj.LoginRatelimit, peerA, &minecraftXDPRatelimit{Tokens: 0, LastRefillNs: now})

	got := runXDP(t, obj, tcpPacket(peerA, testPort, tcpPSH|tcpACK, handshake(2)))
	if got != xdpDrop {
		t.Errorf("a login handshake on a second open connection got %s with the login bucket empty; "+
			"tcp_first_data is keyed by source IP, so once any connection from that IP has sent data every later "+
			"connection skips handshake classification and bypasses the login and status rate limits", verdictName(got))
	}
	if n := statTotal(t, obj.Stats, statTCPHandshakeLoginSeen); n != 1 {
		t.Errorf("tcp_handshake_login_seen = %d, want 1", n)
	}
}

func TestStatusRateLimitDropsBeyondTheBurst(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{
		"status_period_ns": farFuturePeriod,
		"status_burst":     uint64(2),
	})
	want := []uint32{xdpPass, xdpPass, xdpDrop}
	for i, w := range want {
		if got := firstSegment(t, obj, peerA, true, handshake(1)); got != w {
			t.Fatalf("status handshake %d: verdict %s, want %s", i+1, verdictName(got), verdictName(w))
		}
	}
	if got := statTotal(t, obj.Stats, statDropStatusRatelimit); got != 1 {
		t.Errorf("drop_status_ratelimit = %d, want 1", got)
	}
	h := lookupValue[minecraftXDPIpDropHistory](t, obj.IpDropHistory, peerA)
	if h.Counts[reasonStatusRatelimit] != 1 {
		t.Errorf("drop history counts %v, want one status_ratelimit drop", h.Counts)
	}
}

func TestLoginRateLimitDropsBeyondTheBurstWithoutPromoting(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{
		"login_period_ns": farFuturePeriod,
		"login_burst":     uint64(1),
	})
	if got := firstSegment(t, obj, peerA, true, handshake(2)); got != xdpPass {
		t.Fatalf("first login verdict %s", verdictName(got))
	}
	if err := obj.TcpWhitelist.Delete(&peerA); err != nil {
		t.Fatalf("delete whitelist: %v", err)
	}
	if got := firstSegment(t, obj, peerA, true, handshake(2)); got != xdpDrop {
		t.Fatalf("second login verdict %s, want XDP_DROP", verdictName(got))
	}
	if hasKey(t, obj.TcpWhitelist, peerA) {
		t.Error("a rate-limited login still promoted the source")
	}
	h := lookupValue[minecraftXDPIpDropHistory](t, obj.IpDropHistory, peerA)
	if h.Counts[reasonLoginRatelimit] != 1 {
		t.Errorf("drop history counts %v, want one login_ratelimit drop", h.Counts)
	}
	if got := statTotal(t, obj.Stats, statDropLoginRatelimit); got != 1 {
		t.Errorf("drop_login_ratelimit = %d, want 1", got)
	}
}

func TestRateLimitBucketRefillsByWholePeriodsAndCapsAtTheBurst(t *testing.T) {
	const period = uint64(1_000_000_000)
	obj := loadTestXDP(t, map[string]any{
		"status_period_ns": period,
		"status_burst":     uint64(3),
	})

	last := bootNow(t) - 2*period - period/2
	putValue(t, obj.StatusRatelimit, peerA, &minecraftXDPRatelimit{Tokens: 0, LastRefillNs: last})
	if got := firstSegment(t, obj, peerA, true, handshake(1)); got != xdpPass {
		t.Fatalf("verdict %s after two periods of refill", verdictName(got))
	}
	b := lookupValue[minecraftXDPRatelimit](t, obj.StatusRatelimit, peerA)
	if b.Tokens != 1 {
		t.Errorf("tokens = %d, want 1 after refilling two and spending one", b.Tokens)
	}
	if b.LastRefillNs != last+2*period {
		t.Errorf("last refill advanced to %d, want %d so the partial period carries over", b.LastRefillNs, last+2*period)
	}

	putValue(t, obj.StatusRatelimit, peerB, &minecraftXDPRatelimit{Tokens: 0, LastRefillNs: bootNow(t) - 100*period})
	firstSegment(t, obj, peerB, true, handshake(1))
	if got := lookupValue[minecraftXDPRatelimit](t, obj.StatusRatelimit, peerB); got.Tokens != 2 {
		t.Errorf("tokens = %d, want 2 when a long idle refill is capped at the burst of 3", got.Tokens)
	}
}

func TestConnPacketRateLimitDropsAWhitelistedFloodAndRecordsAnAnomaly(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{
		"conn_pkt_period_ns": farFuturePeriod,
		"conn_pkt_burst":     uint64(2),
	})
	putTimestamp(t, obj.TcpWhitelist, peerA, bootNow(t))
	pkt := tcpPacket(peerA, testPort, tcpACK, nil)
	expectVerdict(t, obj, pkt, xdpPass)
	expectVerdict(t, obj, pkt, xdpPass)
	expectVerdict(t, obj, pkt, xdpDrop)

	if got := statTotal(t, obj.Stats, statDropConnRatelimit); got != 1 {
		t.Errorf("drop_conn_ratelimit = %d, want 1", got)
	}
	h := lookupValue[minecraftXDPIpHealth](t, obj.Health, peerA)
	if h.Anomalies != 1 {
		t.Errorf("anomalies = %d, want 1", h.Anomalies)
	}
	d := lookupValue[minecraftXDPIpDropHistory](t, obj.IpDropHistory, peerA)
	if d.Counts[reasonConnRatelimit] != 1 {
		t.Errorf("drop history counts %v, want one conn_ratelimit drop", d.Counts)
	}
}

func TestConnByteRateLimitChargesTheIPTotalLength(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{
		"conn_byte_period_ns": farFuturePeriod,
		"conn_byte_burst":     uint64(110),
	})
	putTimestamp(t, obj.TcpWhitelist, peerA, bootNow(t))
	pkt := tcpPacket(peerA, testPort, tcpPSH|tcpACK, make([]byte, 30))

	expectVerdict(t, obj, pkt, xdpPass)
	if got := lookupValue[minecraftXDPConnLimit](t, obj.ConnRatelimit, peerA); got.ByteTokens != 40 {
		t.Errorf("byte tokens = %d, want 40 after a 70 byte packet against a 110 byte burst", got.ByteTokens)
	}
	expectVerdict(t, obj, pkt, xdpDrop)
	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpPass)
}

func TestConnPacketBucketRefillsByWholePeriods(t *testing.T) {
	const period = uint64(1_000_000_000)
	obj := loadTestXDP(t, map[string]any{
		"conn_pkt_period_ns": period,
		"conn_pkt_burst":     uint64(2),
	})
	putTimestamp(t, obj.TcpWhitelist, peerA, bootNow(t))
	last := bootNow(t) - period - period/2
	putValue(t, obj.ConnRatelimit, peerA, &minecraftXDPConnLimit{PktTokens: 0, PktLastNs: last})

	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpPass)
	got := lookupValue[minecraftXDPConnLimit](t, obj.ConnRatelimit, peerA)
	if got.PktTokens != 0 {
		t.Errorf("pkt tokens = %d, want 0 after refilling one and spending one", got.PktTokens)
	}
	if got.PktLastNs != last+period {
		t.Errorf("pkt last = %d, want %d", got.PktLastNs, last+period)
	}
}

func TestConnRateLimitAppliesToEstablishedTrafficThatIsNotWhitelisted(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{
		"conn_pkt_period_ns": farFuturePeriod,
		"conn_pkt_burst":     uint64(1),
	})
	now := bootNow(t)
	putTimestamp(t, obj.TcpEstablished, peerA, now)
	putTimestamp(t, obj.TcpFirstData, peerA, now)
	pkt := tcpPacket(peerA, testPort, tcpPSH|tcpACK, midStreamPlay())

	expectVerdict(t, obj, pkt, xdpPass)
	expectVerdict(t, obj, pkt, xdpDrop)
	if h := lookupValue[minecraftXDPIpHealth](t, obj.Health, peerA); h.Anomalies != 1 {
		t.Errorf("anomalies = %d, want 1", h.Anomalies)
	}
}

func TestRepeatedConnRateLimitHitsBlacklistTheSourceAndEvictItsWhitelistEntry(t *testing.T) {
	obj := loadTestXDP(t, map[string]any{
		"conn_pkt_period_ns":  farFuturePeriod,
		"conn_pkt_burst":      uint64(1),
		"health_threshold":    uint32(2),
		"health_window_ns":    uint64(60_000_000_000),
		"health_blacklist_ns": uint64(300_000_000_000),
	})
	putTimestamp(t, obj.TcpWhitelist, peerA, bootNow(t))
	pkt := tcpPacket(peerA, testPort, tcpACK, nil)

	expectVerdict(t, obj, pkt, xdpPass)
	expectVerdict(t, obj, pkt, xdpDrop)
	if !hasKey(t, obj.TcpWhitelist, peerA) {
		t.Fatal("whitelist entry evicted before the health threshold was reached")
	}
	before := bootNow(t)
	expectVerdict(t, obj, pkt, xdpDrop)
	after := bootNow(t)
	if hasKey(t, obj.TcpWhitelist, peerA) {
		t.Error("a source that crossed the health threshold kept its whitelist entry")
	}
	h := lookupValue[minecraftXDPIpHealth](t, obj.Health, peerA)
	if h.BlacklistUntilNs < before+300_000_000_000 || h.BlacklistUntilNs > after+300_000_000_000 {
		t.Errorf("blacklist until %d, want now plus the 300s blacklist", h.BlacklistUntilNs)
	}

	expectVerdict(t, obj, pkt, xdpDrop)
	if got := statTotal(t, obj.Stats, statDropTCPUnhealthy); got != 1 {
		t.Errorf("drop_tcp_unhealthy = %d, want 1", got)
	}
	d := lookupValue[minecraftXDPIpDropHistory](t, obj.IpDropHistory, peerA)
	if d.Counts[reasonUnhealthy] != 1 || d.Counts[reasonConnRatelimit] != 2 {
		t.Errorf("drop history counts %v, want two conn_ratelimit and one unhealthy", d.Counts)
	}
}

func TestBlacklistOnlyHoldsUntilItExpires(t *testing.T) {
	obj := loadTestXDP(t, nil)
	now := bootNow(t)
	putTimestamp(t, obj.TcpEstablished, peerA, now)
	putTimestamp(t, obj.TcpEstablished, peerB, now)
	putValue(t, obj.Health, peerA, &minecraftXDPIpHealth{Anomalies: 50, WindowStartNs: now, BlacklistUntilNs: now + 60_000_000_000})
	putValue(t, obj.Health, peerB, &minecraftXDPIpHealth{Anomalies: 50, WindowStartNs: now, BlacklistUntilNs: now - 1_000_000_000})

	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpDrop)
	expectVerdict(t, obj, tcpPacket(peerB, testPort, tcpACK, nil), xdpPass)
}

func TestHealthAnomalyWindowResetsOnceItElapses(t *testing.T) {
	const window = uint64(10_000_000_000)
	vars := map[string]any{
		"conn_pkt_period_ns": farFuturePeriod,
		"conn_pkt_burst":     uint64(1),
		"health_threshold":   uint32(3),
		"health_window_ns":   window,
	}
	obj := loadTestXDP(t, vars)
	now := bootNow(t)
	for _, ip := range [][4]byte{peerC, peerD} {
		putTimestamp(t, obj.TcpWhitelist, ip, now)
		putValue(t, obj.ConnRatelimit, ip, &minecraftXDPConnLimit{PktTokens: 0, PktLastNs: now})
	}
	putValue(t, obj.Health, peerC, &minecraftXDPIpHealth{Anomalies: 2, WindowStartNs: now - window - 1_000_000_000})
	putValue(t, obj.Health, peerD, &minecraftXDPIpHealth{Anomalies: 2, WindowStartNs: now})

	before := bootNow(t)
	expectVerdict(t, obj, tcpPacket(peerC, testPort, tcpACK, nil), xdpDrop)
	expectVerdict(t, obj, tcpPacket(peerD, testPort, tcpACK, nil), xdpDrop)

	c := lookupValue[minecraftXDPIpHealth](t, obj.Health, peerC)
	if c.Anomalies != 1 || c.WindowStartNs < before || c.BlacklistUntilNs != 0 {
		t.Errorf("stale window gave %+v, want a fresh window with one anomaly and no blacklist", c)
	}
	d := lookupValue[minecraftXDPIpHealth](t, obj.Health, peerD)
	if d.Anomalies != 3 || d.BlacklistUntilNs <= before {
		t.Errorf("open window gave %+v, want three anomalies and a blacklist", d)
	}
}

func TestDropHistoryKeepsTheFirstDropAndCountsPerReason(t *testing.T) {
	obj := loadTestXDP(t, nil)
	bogus := tcpPacket(peerA, testPort, tcpSYN|tcpFIN, nil)

	before := bootNow(t)
	expectVerdict(t, obj, bogus, xdpDrop)
	first := lookupValue[minecraftXDPIpDropHistory](t, obj.IpDropHistory, peerA)
	if first.FirstDropNs < before || first.FirstDropNs != first.LastDropNs {
		t.Fatalf("first drop recorded as %+v, want first == last == now", first)
	}

	expectVerdict(t, obj, bogus, xdpDrop)
	expectVerdict(t, obj, tcpPacket(peerA, testPort, tcpACK, nil), xdpDrop)
	got := lookupValue[minecraftXDPIpDropHistory](t, obj.IpDropHistory, peerA)
	if got.FirstDropNs != first.FirstDropNs {
		t.Errorf("first drop moved from %d to %d", first.FirstDropNs, got.FirstDropNs)
	}
	if got.LastDropNs < first.LastDropNs {
		t.Errorf("last drop went backwards from %d to %d", first.LastDropNs, got.LastDropNs)
	}
	want := [10]uint64{}
	want[reasonTCPBadFlags] = 2
	want[reasonTCPNoSyn] = 1
	if got.Counts != want {
		t.Errorf("counts %v, want %v", got.Counts, want)
	}
	if hasKey(t, obj.IpDropHistory, peerB) {
		t.Error("drop history has an entry for a source that never sent anything")
	}
}
