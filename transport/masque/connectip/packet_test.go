package connectip

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/sagernet/quic-go"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// lx: SPEC 120 §2.6 — the ICMP "packet too big" reply names quic-go's actual
// datagram budget minus the context-id byte, floored at the IPv6 minimum.
func TestICMPAdvertisedMTU(t *testing.T) {
	t.Parallel()
	cases := []struct {
		budget int64
		want   int
	}{
		{1310, 1309},
		{1281, 1280},
		{1205, 1280}, // below the floor: never advertise under 1280
		{0, 1280},
		{1452, 1451},
	}
	for _, tc := range cases {
		if got := icmpAdvertisedMTU(tc.budget); got != tc.want {
			t.Errorf("icmpAdvertisedMTU(%d) = %d, want %d", tc.budget, got, tc.want)
		}
	}
}

// tooLargeStream is an Http3Stream whose SendDatagram always reports the
// given budget; the capsule side blocks until Close so the Conn stays open.
type tooLargeStream struct {
	budget    int64
	closeOnce sync.Once
	closed    chan struct{}
}

func newTooLargeStream(budget int64) *tooLargeStream {
	return &tooLargeStream{budget: budget, closed: make(chan struct{})}
}

func (s *tooLargeStream) Read([]byte) (int, error) {
	<-s.closed
	return 0, context.Canceled
}

func (s *tooLargeStream) Write(b []byte) (int, error) { return len(b), nil }

func (s *tooLargeStream) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *tooLargeStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-s.closed:
		return nil, context.Canceled
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *tooLargeStream) SendDatagram([]byte) error {
	return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: s.budget}
}

func (s *tooLargeStream) CancelRead(quic.StreamErrorCode) {}

func ipv6Packet(size int) []byte {
	b := make([]byte, size)
	b[0] = 6 << 4
	binary.BigEndian.PutUint16(b[4:6], uint16(size-ipv6.HeaderLen))
	b[6] = 17 // UDP
	b[7] = 64
	b[8+15] = 1  // src ::1
	b[24+15] = 2 // dst ::2
	return b
}

func ipv4Packet(size int) []byte {
	b := make([]byte, size)
	b[0] = 4<<4 | ipv4.HeaderLen>>2
	binary.BigEndian.PutUint16(b[2:4], uint16(size))
	b[8] = 64
	b[9] = 17 // UDP
	copy(b[12:16], []byte{10, 0, 0, 1})
	copy(b[16:20], []byte{10, 0, 0, 2})
	return b
}

// WritePacket through a Conn: the reply carries the advertised MTU, for both
// families, and quotes the packet with the original hop limit / TTL.
func TestWritePacketTooBigAdvertisesBudget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		budget int64
		want   int
	}{
		{"budget 1310", 1310, 1309},
		{"budget 1205 floors at 1280", 1205, 1280},
	}
	for _, tc := range cases {
		t.Run(tc.name+" ipv6", func(t *testing.T) {
			conn := NewProxiedConn(newTooLargeStream(tc.budget))
			defer conn.Close()
			reply, err := conn.WritePacket(ipv6Packet(1280))
			if err != nil {
				t.Fatalf("WritePacket: %v", err)
			}
			if len(reply) < ipv6.HeaderLen+8 || reply[0]>>4 != 6 || reply[6] != ipProtoICMPv6 {
				t.Fatalf("not an ICMPv6 reply: % x", reply[:min(len(reply), 48)])
			}
			msg, err := icmp.ParseMessage(ipProtoICMPv6, reply[ipv6.HeaderLen:])
			if err != nil {
				t.Fatalf("parse ICMPv6: %v", err)
			}
			if msg.Type != ipv6.ICMPTypePacketTooBig {
				t.Fatalf("type = %v, want PacketTooBig", msg.Type)
			}
			body := msg.Body.(*icmp.PacketTooBig)
			if body.MTU != tc.want {
				t.Fatalf("MTU = %d, want %d", body.MTU, tc.want)
			}
			if body.Data[7] != 64 {
				t.Fatalf("quoted hop limit = %d, want the original 64", body.Data[7])
			}
		})
		t.Run(tc.name+" ipv4", func(t *testing.T) {
			conn := NewProxiedConn(newTooLargeStream(tc.budget))
			defer conn.Close()
			reply, err := conn.WritePacket(ipv4Packet(1280))
			if err != nil {
				t.Fatalf("WritePacket: %v", err)
			}
			if len(reply) < ipv4.HeaderLen+8 || reply[0]>>4 != 4 || reply[9] != ipProtoICMP {
				t.Fatalf("not an ICMPv4 reply: % x", reply[:min(len(reply), 28)])
			}
			msg := reply[ipv4.HeaderLen:]
			if msg[0] != byte(ipv4.ICMPTypeDestinationUnreachable) || msg[1] != 4 {
				t.Fatalf("type/code = %d/%d, want 3/4", msg[0], msg[1])
			}
			// RFC 1191: next-hop MTU in the low 16 bits of the unused field.
			if got := int(binary.BigEndian.Uint16(msg[6:8])); got != tc.want {
				t.Fatalf("MTU = %d, want %d", got, tc.want)
			}
			if msg[8+8] != 64 {
				t.Fatalf("quoted TTL = %d, want the original 64", msg[8+8])
			}
		})
	}
}

func TestIPv4Checksum(t *testing.T) {
	t.Parallel()
	// A well-formed IPv4 header (from RFC examples): checksum field zeroed.
	header := [20]byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	got := calculateIPv4Checksum(header[:])
	if got != 0xb861 {
		t.Fatalf("checksum = %#x, want 0xb861", got)
	}
}

// TestIPv4ChecksumWithOptions covers a header carrying an IPv4 option (IHL=6, so
// 24 bytes): the checksum must fold in the option word, not just the first 20
// bytes (SPEC 022 #6). Expected value is the ones-complement sum over all 24
// bytes with the checksum field zeroed.
func TestIPv4ChecksumWithOptions(t *testing.T) {
	t.Parallel()
	header := []byte{
		0x46, 0x00, 0x00, 0x77, 0x00, 0x00, 0x40, 0x00, // IHL=6 (0x46)
		0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
		0x94, 0x04, 0x00, 0x00, // option: Router Alert (type 0x94, len 4)
	}
	// Independent reference sum over the 24 bytes, checksum field (10-11) zeroed.
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	want := ^uint16(sum)
	if got := calculateIPv4Checksum(header); got != want {
		t.Fatalf("checksum over IHL=6 header = %#x, want %#x", got, want)
	}
	// The 20-byte-only sum would differ, proving the option word is now covered.
	if want == calculateIPv4Checksum(header[:20]) {
		t.Fatal("option word did not change the checksum — coverage not exercised")
	}
}
