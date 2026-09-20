package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeRatelimit struct {
	Tokens       uint64
	LastRefillNS uint64
}

type fakeHealth struct {
	Anomalies        uint32
	Pad              uint32
	WindowStartNS    uint64
	BlacklistUntilNS uint64
}

type fakeConnLimit struct {
	PktTokens  uint64
	PktLastNS  uint64
	ByteTokens uint64
	ByteLastNS uint64
}

type fakeDropHistory struct {
	FirstDropNS uint64
	LastDropNS  uint64
	Counts      [10]uint64
}

type fakeEntry struct {
	key [4]byte
	val []byte
}

type fakeMap struct {
	valueSize uint32
	entries   []fakeEntry
}

func newFakeMap(valueSize uint32) *fakeMap {
	return &fakeMap{valueSize: valueSize}
}

func (f *fakeMap) ValueSize() uint32 {
	return f.valueSize
}

func (f *fakeMap) put(t *testing.T, ip string, value any) *fakeMap {
	t.Helper()
	raw := encodeMapValue(t, value)
	if uint32(len(raw)) != f.valueSize {
		t.Fatalf("value for %s encodes to %d bytes, map value size is %d", ip, len(raw), f.valueSize)
	}
	f.entries = append(f.entries, fakeEntry{key: mustIPKey(t, ip), val: raw})
	return f
}

func (f *fakeMap) Lookup(key, valueOut any) error {
	k, ok := key.(*[4]byte)
	if !ok {
		return fmt.Errorf("fake map: unsupported key type %T", key)
	}
	for _, e := range f.entries {
		if e.key == *k {
			return decodeMapValue(e.val, valueOut)
		}
	}
	return ebpf.ErrKeyNotExist
}

func (f *fakeMap) Iterate() mapIterator {
	return &fakeIterator{m: f}
}

type fakeIterator struct {
	m   *fakeMap
	pos int
}

func (it *fakeIterator) Next(keyOut, valueOut any) bool {
	if it.pos >= len(it.m.entries) {
		return false
	}
	e := it.m.entries[it.pos]
	it.pos++
	k, ok := keyOut.(*[4]byte)
	if !ok {
		return false
	}
	*k = e.key
	return decodeMapValue(e.val, valueOut) == nil
}

func encodeMapValue(t *testing.T, value any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, value); err != nil {
		t.Fatalf("encode %T: %v", value, err)
	}
	return buf.Bytes()
}

func decodeMapValue(raw []byte, out any) error {
	if p, ok := out.(*[]byte); ok {
		if len(*p) != len(raw) {
			*p = make([]byte, len(raw))
		}
		copy(*p, raw)
		return nil
	}
	return binary.Read(bytes.NewReader(raw), binary.NativeEndian, out)
}

func mustIPKey(t *testing.T, ip string) [4]byte {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("unparseable IP: %s", ip)
	}
	v4 := parsed.To4()
	if v4 == nil {
		t.Fatalf("not an IPv4 address: %s", ip)
	}
	var key [4]byte
	copy(key[:], v4)
	return key
}

func TestFakeMapRoundTripsEveryMapValueLayout(t *testing.T) {
	cases := []struct {
		name  string
		size  uint32
		value any
	}{
		{"timestamp", 8, uint64(1234567890)},
		{"ratelimit", 16, fakeRatelimit{Tokens: 7, LastRefillNS: 99}},
		{"health", 24, fakeHealth{Anomalies: 3, Pad: 0xDEADBEEF, WindowStartNS: 11, BlacklistUntilNS: 22}},
		{"conn_limit", 32, fakeConnLimit{PktTokens: 1, PktLastNS: 2, ByteTokens: 3, ByteLastNS: 4}},
		{"drop_history", 96, fakeDropHistory{FirstDropNS: 5, LastDropNS: 6, Counts: [10]uint64{1, 2, 3}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newFakeMap(tc.size)
			m.put(t, "10.0.0.1", tc.value)
			key := mustIPKey(t, "10.0.0.1")
			raw := make([]byte, m.ValueSize())
			if err := m.Lookup(&key, &raw); err != nil {
				t.Fatalf("lookup: %v", err)
			}
			if uint32(len(raw)) != tc.size {
				t.Fatalf("read back %d bytes, want %d", len(raw), tc.size)
			}
			missing := mustIPKey(t, "10.0.0.2")
			if err := m.Lookup(&missing, &raw); err == nil {
				t.Fatal("lookup of an absent key returned no error")
			}
		})
	}
}

func TestFakeHealthPaddingIsSkippedByTheAPIDecoder(t *testing.T) {
	m := newFakeMap(24)
	m.put(t, "10.0.0.1", fakeHealth{Anomalies: 41, Pad: 0xFFFFFFFF, WindowStartNS: 7, BlacklistUntilNS: 8})
	key := mustIPKey(t, "10.0.0.1")
	var val struct {
		Anomalies        uint32
		_                uint32
		WindowStartNS    uint64
		BlacklistUntilNS uint64
	}
	if err := m.Lookup(&key, &val); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if val.Anomalies != 41 || val.WindowStartNS != 7 || val.BlacklistUntilNS != 8 {
		t.Fatalf("decoded %+v, want anomalies=41 window=7 blacklist=8", val)
	}
}
