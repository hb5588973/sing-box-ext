/* SPDX-License-Identifier: MIT
 *
 * Regression test for the AWG transport-padding (uapi "s4") out-of-bounds
 * crash: RoutineSequentialSender shifts elem.packet right by
 * device.paddings.transport bytes inside elem.buffer to prepend a random
 * padding prefix, but the injection paths (InputPacket/InputPackets)
 * allocated elem.buffer tightly, without headroom for that shift:
 *
 *   panic: runtime error: index out of range [123] with length 76
 *   device.(*Peer).RoutineSequentialSender
 *
 * (payload 28 bytes -> allocLength 76, sealed packet 64, s4=60 -> 63+60=123).
 *
 * The tests spin up two real Devices wired together through an in-memory
 * conn.Bind (Go channels) and an in-memory tun.Device, configure s4=60 on
 * both sides, and pass a small IPv4 packet end to end via both outbound
 * paths: Device.InputPacket (the crashing path) and the regular tun read
 * loop (in-place shift path).
 */

package device

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"

	"golang.org/x/net/ipv4"
)

const testTransportPadding = 60 // uapi s4, matches the on-device crash

// ---------------------------------------------------------------------------
// In-memory conn.Bind over Go channels (minimal bindtest.ChannelBind clone).
// ---------------------------------------------------------------------------

type chanEndpoint uint16

func (e chanEndpoint) ClearSrc()           {}
func (e chanEndpoint) SrcToString() string { return "" }
func (e chanEndpoint) DstToString() string { return fmt.Sprintf("127.0.0.1:%d", uint16(e)) }
func (e chanEndpoint) DstToBytes() []byte  { return []byte{byte(e), byte(e >> 8)} }
func (e chanEndpoint) DstIP() netip.Addr   { return netip.AddrFrom4([4]byte{127, 0, 0, 1}) }
func (e chanEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type chanBind struct {
	rx, tx chan []byte
	source chanEndpoint // "port" this bind listens on
	target chanEndpoint // endpoint of the opposite bind

	mu          sync.Mutex
	closeSignal chan struct{} // recreated on every Open (BindUpdate closes+reopens)

	// tap, if set, sees a copy of every datagram this bind sends (wire-format
	// assertions in the AWG tests). Set before Up; called on the sender's
	// goroutine.
	tap func(pkt []byte)
}

// newChanBindPair returns two Binds whose Send/Receive are cross-wired.
func newChanBindPair() (*chanBind, *chanBind) {
	aToB := make(chan []byte, 1024)
	bToA := make(chan []byte, 1024)
	a := &chanBind{rx: bToA, tx: aToB, source: 1, target: 2}
	b := &chanBind{rx: aToB, tx: bToA, source: 2, target: 1}
	return a, b
}

func (b *chanBind) currentCloseSignal() chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closeSignal
}

func (b *chanBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	b.closeSignal = make(chan struct{})
	closeSignal := b.closeSignal
	b.mu.Unlock()
	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-closeSignal:
			// Must be net.ErrClosed: RoutineReceiveIncoming treats anything
			// else as a transient error and death-spirals before exiting.
			return 0, net.ErrClosed
		case pkt, ok := <-b.rx:
			if !ok {
				return 0, net.ErrClosed
			}
			sizes[0] = copy(packets[0], pkt)
			eps[0] = b.target
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{fn}, uint16(b.source), nil
}

func (b *chanBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closeSignal != nil {
		select {
		case <-b.closeSignal:
		default:
			close(b.closeSignal)
		}
	}
	return nil
}

func (b *chanBind) SetMark(mark uint32) error { return nil }

func (b *chanBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	closeSignal := b.currentCloseSignal()
	if closeSignal == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])
		if b.tap != nil {
			b.tap(pkt)
		}
		select {
		case <-closeSignal:
			return net.ErrClosed
		case b.tx <- pkt:
		}
	}
	return nil
}

func (b *chanBind) ParseEndpoint(s string) (conn.Endpoint, error) { return b.target, nil }

func (b *chanBind) BatchSize() int { return 1 }

func (b *chanBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {}

// ---------------------------------------------------------------------------
// In-memory tun.Device over Go channels (minimal tuntest.ChannelTUN clone).
// ---------------------------------------------------------------------------

type chanTun struct {
	toDevice   chan []byte // packets the device Reads (outbound plaintext)
	fromDevice chan []byte // packets the device Writes (inbound plaintext)
	events     chan tun.Event
	closed     chan struct{}
	closeOnce  sync.Once
}

func newChanTun() *chanTun {
	return &chanTun{
		toDevice:   make(chan []byte, 1024),
		fromDevice: make(chan []byte, 1024),
		events:     make(chan tun.Event, 4),
		closed:     make(chan struct{}),
	}
}

func (t *chanTun) File() *os.File { return nil }

func (t *chanTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt, ok := <-t.toDevice:
		if !ok {
			return 0, os.ErrClosed
		}
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	}
}

func (t *chanTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])
		select {
		case <-t.closed:
			return 0, os.ErrClosed
		case t.fromDevice <- pkt:
		}
	}
	return len(bufs), nil
}

func (t *chanTun) MTU() (int, error)        { return DefaultMTU, nil }
func (t *chanTun) Name() (string, error)    { return "chantun", nil }
func (t *chanTun) Events() <-chan tun.Event { return t.events }
func (t *chanTun) BatchSize() int           { return 1 }

func (t *chanTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// ---------------------------------------------------------------------------
// Test scaffolding.
// ---------------------------------------------------------------------------

var (
	testIPA = netip.AddrFrom4([4]byte{10, 0, 0, 1})
	testIPB = netip.AddrFrom4([4]byte{10, 0, 0, 2})
)

// buildIPv4Packet builds a minimal, routable IPv4/UDP packet whose header
// fields satisfy the receive-side validation in RoutineSequentialReceiver
// (version, total-length field, allowed source address).
func buildIPv4Packet(src, dst netip.Addr, payloadLen int) []byte {
	total := ipv4.HeaderLen + payloadLen
	pkt := make([]byte, total)
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[IPv4offsetTotalLength:IPv4offsetTotalLength+2], uint16(total))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // protocol: UDP
	copy(pkt[IPv4offsetSrc:], src.AsSlice())
	copy(pkt[IPv4offsetDst:], dst.AsSlice())
	for i := ipv4.HeaderLen; i < total; i++ {
		pkt[i] = byte(i) // deterministic payload
	}
	return pkt
}

type paddedPair struct {
	devA, devB *Device
	tunA, tunB *chanTun
}

// newPaddedDevicePair builds two Up()'d devices peered with each other over
// the channel bind, both configured with s4 (transport padding) enabled.
func newPaddedDevicePair(t *testing.T) *paddedPair {
	t.Helper()

	skA, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey A: %v", err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey B: %v", err)
	}
	pkA := skA.publicKey()
	pkB := skB.publicKey()

	bindA, bindB := newChanBindPair()
	tunA := newChanTun()
	tunB := newChanTun()

	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "devA: "), 1)
	devB := NewDevice(context.Background(), tunB, bindB, NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)

	cfgA := fmt.Sprintf(
		"private_key=%s\ns4=%d\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n",
		hex.EncodeToString(skA[:]), testTransportPadding, hex.EncodeToString(pkB[:]), testIPB)
	cfgB := fmt.Sprintf(
		"private_key=%s\ns4=%d\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n",
		hex.EncodeToString(skB[:]), testTransportPadding, hex.EncodeToString(pkA[:]), testIPA)

	if err := devA.IpcSet(cfgA); err != nil {
		t.Fatalf("IpcSet A: %v", err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		t.Fatalf("IpcSet B: %v", err)
	}
	if devA.paddings.transport.Load() != testTransportPadding {
		t.Fatalf("s4 not applied: paddings.transport = %d", devA.paddings.transport.Load())
	}

	if err := devA.Up(); err != nil {
		t.Fatalf("Up A: %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("Up B: %v", err)
	}

	return &paddedPair{devA: devA, devB: devB, tunA: tunA, tunB: tunB}
}

// awaitPacket waits for want to arrive on the receiving tun, periodically
// re-sending via resend (injection has no delivery guarantee before the
// handshake completes).
func awaitPacket(t *testing.T, from *chanTun, want []byte, resend func()) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	retry := time.NewTicker(1 * time.Second)
	defer retry.Stop()
	for {
		select {
		case got := <-from.fromDevice:
			if bytes.Equal(got, want) {
				return
			}
			t.Logf("ignoring unexpected packet, len=%d", len(got))
		case <-retry.C:
			resend()
		case <-deadline:
			t.Fatal("timed out waiting for packet on peer tun")
		}
	}
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

// TestTransportPaddingInputPacket exercises the exact crash path: an injected
// packet (Device.InputPacket) whose buffer was allocated by payload size.
// With s4=60 and a 28-byte IPv4 packet the pre-fix buffer was 76 bytes and
// the padding shift indexed [123] -> index out of range.
func TestTransportPaddingInputPacket(t *testing.T) {
	pair := newPaddedDevicePair(t)

	// 20-byte header + 8-byte payload = 28 bytes, the on-device crash size.
	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	dst := testIPB.AsSlice()

	send := func() { pair.devA.InputPacket(dst, [][]byte{pkt}) }
	send()
	awaitPacket(t, pair.tunB, pkt, send)
}

// TestTransportPaddingInputPackets covers the batched injection path
// (Device.InputPackets), which had the same tight allocation.
func TestTransportPaddingInputPackets(t *testing.T) {
	pair := newPaddedDevicePair(t)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	refs := []*InputPacketRef{{
		Destination:  testIPB.AsSlice(),
		PacketSlices: [][]byte{pkt[:12], pkt[12:]}, // multi-slice on purpose
	}}

	send := func() {
		if unmatched := pair.devA.InputPackets(refs); len(unmatched) != 0 {
			t.Fatalf("InputPackets returned %d unmatched refs", len(unmatched))
		}
	}
	send()
	awaitPacket(t, pair.tunB, pkt, send)
}

// TestTransportPaddingTunPath covers the regular outbound path (tun read
// loop), whose MaxMessageSize buffers take the in-place shift branch.
func TestTransportPaddingTunPath(t *testing.T) {
	pair := newPaddedDevicePair(t)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)

	send := func() { pair.tunA.toDevice <- pkt }
	send()
	awaitPacket(t, pair.tunB, pkt, send)
}
