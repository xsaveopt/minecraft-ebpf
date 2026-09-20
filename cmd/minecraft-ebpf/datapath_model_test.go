package main

import (
	"testing"
)

type hsClass int

const (
	hsNone hsClass = iota
	hsStatus
	hsLogin
	hsMalformed
)

func (c hsClass) String() string {
	switch c {
	case hsNone:
		return "HS_NONE"
	case hsStatus:
		return "HS_STATUS"
	case hsLogin:
		return "HS_LOGIN"
	case hsMalformed:
		return "HS_MALFORMED"
	}
	return "unknown"
}

const (
	mcHandshakePacketID = 0x00
	mcNextStateStatus   = 1
	mcNextStateLogin    = 2
	mcNextStateTransfer = 3
	mcLegacyPingByte    = 0xFE
	mcAddrMax           = 255
	mcHandshakeMaxLen   = 1024
)

type packetReader struct {
	payload []byte
	maxRead int
}

func newPacketReader(payload []byte) *packetReader {
	return &packetReader{payload: payload, maxRead: -1}
}

func (p *packetReader) loadByte(off uint32) (byte, bool) {
	if int(off) >= len(p.payload) {
		return 0, false
	}
	if int(off) > p.maxRead {
		p.maxRead = int(off)
	}
	return p.payload[off], true
}

func (p *packetReader) loadVarint(off, avail uint32) (uint32, uint32) {
	var value uint32
	for i := uint32(0); i < 5; i++ {
		if i >= avail {
			return 0, 0
		}
		c, ok := p.loadByte(off + i)
		if !ok {
			return 0, 0
		}
		value |= uint32(c&0x7F) << (7 * i)
		if c&0x80 == 0 {
			return value, i + 1
		}
	}
	return 0, 0
}

func classifyHandshake(p *packetReader, payloadLen uint32) hsClass {
	if payloadLen < 1 {
		return hsNone
	}
	first, ok := p.loadByte(0)
	if !ok {
		return hsNone
	}
	if first == mcLegacyPingByte {
		return hsStatus
	}

	var off uint32
	pktLen, k := p.loadVarint(off, payloadLen-off)
	if k == 0 {
		return hsNone
	}
	if pktLen < 3 || pktLen > mcHandshakeMaxLen {
		return hsNone
	}
	off += k

	if payloadLen-off < pktLen {
		return hsNone
	}
	limit := off + pktLen

	id, ok := p.loadByte(off)
	if !ok {
		return hsNone
	}
	if id != mcHandshakePacketID {
		return hsNone
	}
	off++

	if off >= limit {
		return hsNone
	}
	_, k = p.loadVarint(off, limit-off)
	if k == 0 {
		return hsNone
	}
	off += k

	if off >= limit {
		return hsNone
	}
	addrLen, k := p.loadVarint(off, limit-off)
	if k == 0 {
		return hsNone
	}
	if addrLen > mcAddrMax {
		return hsNone
	}
	off += k

	nsOff := off + addrLen + 2
	if nsOff >= limit {
		return hsNone
	}
	nextState, k := p.loadVarint(nsOff, limit-nsOff)
	if k == 0 {
		return hsNone
	}
	if nsOff+k != limit {
		return hsNone
	}
	if nextState == mcNextStateStatus {
		return hsStatus
	}
	if nextState == mcNextStateLogin || nextState == mcNextStateTransfer {
		return hsLogin
	}
	return hsMalformed
}

type verdict struct {
	pass       bool
	dropReason string
	anomaly    bool
	tokenTaken string
	class      hsClass
}

func datapathVerdict(payload []byte, established bool) verdict {
	p := newPacketReader(payload)
	hs := classifyHandshake(p, uint32(len(payload)))
	if established && hs == hsMalformed {
		hs = hsNone
	}
	v := verdict{pass: true, class: hs}

	switch hs {
	case hsNone:
		if established {
			v.tokenTaken = "conn_ratelimit"
		}
		return v
	case hsMalformed:
		v.pass = false
		return v
	case hsStatus:
		if !established {
			return v
		}
		v.tokenTaken = "status_ratelimit"
		return v
	case hsLogin:
		if !established {
			return v
		}
		v.tokenTaken = "login_ratelimit"
		return v
	}
	return v
}

func handshakePayload(nextState byte) []byte {
	body := []byte{
		mcHandshakePacketID,
		0xFD, 0x05,
		0x09,
		'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0x63, 0xDD,
		nextState,
	}
	return append([]byte{byte(len(body))}, body...)
}

func midStreamPlayPayload() []byte {
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

func TestHandshakeClassifierRecognisesTheRealHandshakes(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		want    hsClass
	}{
		{"status", handshakePayload(mcNextStateStatus), hsStatus},
		{"login", handshakePayload(mcNextStateLogin), hsLogin},
		{"transfer", handshakePayload(mcNextStateTransfer), hsLogin},
		{"unknown next state", handshakePayload(7), hsMalformed},
		{"legacy ping", []byte{mcLegacyPingByte, 0x01}, hsStatus},
		{"empty", nil, hsNone},
		{"declared length below three", []byte{0x02, 0x00, 0x01}, hsNone},
		{"truncated frame", handshakePayload(mcNextStateLogin)[:8], hsNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyHandshake(newPacketReader(tc.payload), uint32(len(tc.payload)))
			if got != tc.want {
				t.Fatalf("classified as %s, want %s", got, tc.want)
			}
		})
	}
}

func TestHandshakeWalkStaysInsideTheDeclaredPacketLength(t *testing.T) {
	payload := append([]byte{0x03, mcHandshakePacketID, 0xFD, 0x05}, handshakePayload(mcNextStateLogin)...)
	p := newPacketReader(payload)

	got := classifyHandshake(p, uint32(len(payload)))
	if got != hsNone {
		t.Fatalf("classified as %s, want %s: fields that overrun the declared length are not a handshake", got, hsNone)
	}
	limit := 1 + 3
	if p.maxRead >= limit {
		t.Fatalf("read byte %d, outside the declared packet length %d", p.maxRead, limit)
	}
}

func TestHandshakeFieldsMustExactlyFillTheDeclaredLength(t *testing.T) {
	payload := append(handshakePayload(mcNextStateLogin), 0x00, 0x00)
	payload[0] = byte(len(payload) - 1)

	if got := classifyHandshake(newPacketReader(payload), uint32(len(payload))); got != hsNone {
		t.Fatalf("classified as %s, want %s: trailing bytes mean the fields do not fill the frame", got, hsNone)
	}
}

func TestAnEstablishedPlayerMidStreamIsNeverDropped(t *testing.T) {
	payload := midStreamPlayPayload()
	got := datapathVerdict(payload, true)
	if !got.pass {
		t.Fatalf("a mid-stream Play packet from an established player was dropped as %s (classified %s, anomaly=%v); "+
			"the datapath has no notion of a first data segment, so any later packet whose bytes happen to walk "+
			"like a handshake frame is dropped and counted against the player",
			got.dropReason, got.class, got.anomaly)
	}
}

func TestAnUnestablishedSourceNeverDrivesPerIPAccounting(t *testing.T) {
	payload := midStreamPlayPayload()
	got := datapathVerdict(payload, false)
	if got.anomaly {
		t.Errorf("a packet from a source with no tcp_established entry recorded a health anomaly")
	}
	if got.dropReason != "" {
		t.Errorf("a packet from a source with no tcp_established entry recorded drop %q against that IP; "+
			"the source is unverified, so a spoofed packet pollutes the victim's drop history",
			got.dropReason)
	}
}

func TestSpoofedHandshakesTakeNoTokensFromTheVictim(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"status", handshakePayload(mcNextStateStatus)},
		{"login", handshakePayload(mcNextStateLogin)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := datapathVerdict(tc.payload, false)
			if got.tokenTaken != "" {
				t.Fatalf("took a token from %s for a source with no tcp_established entry", got.tokenTaken)
			}
			if !got.pass {
				t.Fatalf("dropped an unverified source's handshake as %s", got.dropReason)
			}
		})
	}
}

func TestEstablishedHandshakesStillMeterAgainstTheirBucket(t *testing.T) {
	if got := datapathVerdict(handshakePayload(mcNextStateStatus), true); got.tokenTaken != "status_ratelimit" {
		t.Errorf("status handshake took %q, want status_ratelimit", got.tokenTaken)
	}
	if got := datapathVerdict(handshakePayload(mcNextStateLogin), true); got.tokenTaken != "login_ratelimit" {
		t.Errorf("login handshake took %q, want login_ratelimit", got.tokenTaken)
	}
}
