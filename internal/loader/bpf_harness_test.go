package loader

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
	tcpURG = 0x20

	xdpDrop = 1
	xdpPass = 2

	testPort = 25565
)

const (
	statPassTCP                = 0
	statTCPEstablishedInserts  = 1
	statTCPL7Promoted          = 2
	statTCPL7MatchNoEst        = 3
	statTCPHandshakeStatusSeen = 4
	statTCPHandshakeLoginSeen  = 5
	statDropTCPNoSyn           = 6
	statDropTCPTooManyOpen     = 7
	statDropTCPGlobalRatelimit = 8
	statDropStatusRatelimit    = 9
	statDropLoginRatelimit     = 10
	statDropMalformedHandshake = 11
	statDropTCPUnhealthy       = 12
	statDropTCPBadFlags        = 13
	statDropConnRatelimit      = 14
	statDropTCPConnRate        = 15
)

const (
	reasonTCPNoSyn           = 0
	reasonTCPTooManyOpen     = 1
	reasonTCPGlobalRatelimit = 2
	reasonStatusRatelimit    = 3
	reasonLoginRatelimit     = 4
	reasonUnhealthy          = 6
	reasonTCPBadFlags        = 7
	reasonConnRatelimit      = 8
	reasonTCPConnRate        = 9
)

var serverAddr = [4]byte{203, 0, 113, 1}

func requireBPFPrivileges(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs needs root")
	}
	_ = rlimit.RemoveMemlock()
}

func skipIfKernelRefuses(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("kernel refused the BPF operation: %v", err)
	}
}

func loadTestXDP(t *testing.T, vars map[string]any) *minecraftXDPObjects {
	t.Helper()
	requireBPFPrivileges(t)
	spec, err := loadMinecraftXDP()
	if err != nil {
		t.Fatalf("load xdp spec: %v", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	for name, v := range vars {
		if err := setVar(spec, name, v); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}
	obj := &minecraftXDPObjects{}
	if err := spec.LoadAndAssign(obj, nil); err != nil {
		skipIfKernelRefuses(t, err)
		t.Fatalf("load xdp objects: %v", err)
	}
	t.Cleanup(func() { _ = obj.Close() })
	return obj
}

func bootNow(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatalf("clock_gettime: %v", err)
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

func tcpPacket(src [4]byte, dport uint16, flags byte, payload []byte) []byte {
	b := make([]byte, 14+20+20+len(payload))
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(40+len(payload)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src[:])
	copy(ip[16:20], serverAddr[:])
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = 0x50
	tcp[13] = flags
	copy(tcp[20:], payload)
	return b
}

func runXDP(t *testing.T, obj *minecraftXDPObjects, pkt []byte) uint32 {
	t.Helper()
	ret, err := obj.MinecraftXdp.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		skipIfKernelRefuses(t, err)
		t.Fatalf("run xdp: %v", err)
	}
	return ret
}

func verdictName(v uint32) string {
	switch v {
	case xdpDrop:
		return "XDP_DROP"
	case xdpPass:
		return "XDP_PASS"
	}
	return "unexpected verdict"
}

func expectVerdict(t *testing.T, obj *minecraftXDPObjects, pkt []byte, want uint32) {
	t.Helper()
	if got := runXDP(t, obj, pkt); got != want {
		t.Fatalf("verdict %s, want %s", verdictName(got), verdictName(want))
	}
}

func statTotal(t *testing.T, m *ebpf.Map, slot uint32) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := m.Lookup(&slot, &perCPU); err != nil {
		t.Fatalf("lookup stat %d: %v", slot, err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

func putTimestamp(t *testing.T, m *ebpf.Map, ip [4]byte, ns uint64) {
	t.Helper()
	if err := m.Put(&ip, &ns); err != nil {
		t.Fatalf("put %v: %v", ip, err)
	}
}

func putValue(t *testing.T, m *ebpf.Map, ip [4]byte, v any) {
	t.Helper()
	if err := m.Put(&ip, v); err != nil {
		t.Fatalf("put %v: %v", ip, err)
	}
}

func hasKey(t *testing.T, m *ebpf.Map, ip [4]byte) bool {
	t.Helper()
	buf := make([]byte, m.ValueSize())
	err := m.Lookup(&ip, &buf)
	if err == nil {
		return true
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false
	}
	t.Fatalf("lookup %v: %v", ip, err)
	return false
}

func isNotExist(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist)
}

func lookupValue[T any](t *testing.T, m *ebpf.Map, ip [4]byte) T {
	t.Helper()
	var v T
	if err := m.Lookup(&ip, &v); err != nil {
		t.Fatalf("lookup %v: %v", ip, err)
	}
	return v
}

func handshake(nextState byte) []byte {
	body := []byte{0x00, 0xFD, 0x05, 0x0B}
	body = append(body, "example.net"...)
	body = append(body, 0x63, 0xDD, nextState)
	return append([]byte{byte(len(body))}, body...)
}

func midStreamPlay() []byte {
	payload := make([]byte, 23)
	payload[0] = 22
	payload[1] = 0x00
	payload[2] = 0x1E
	payload[3] = 0x10
	for i := 4; i < 22; i++ {
		payload[i] = byte('a' + (i % 26))
	}
	payload[22] = 0x00
	return payload
}
