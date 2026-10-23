/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 112 — every datagram the device hands to conn.Bind.Send carries
 * MessageEncapsulatingTransportSize bytes of free headroom, and offset says
 * so. Tailscale's magicsock writes a Geneve header there and rejects any other
 * offset on the direct UDP path; the AWG graft once zeroed the headroom and
 * broke it. The bind below scribbles over the headroom the way magicsock does,
 * so a datagram that leaked into it would corrupt the tunnel.
 */

package device

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/sagernet/wireguard-go/conn"
)

type headroomBind struct {
	*chanBind
	mu      sync.Mutex
	offsets map[int]int
}

func (b *headroomBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.mu.Lock()
	b.offsets[offset] += len(bufs)
	b.mu.Unlock()
	for _, buf := range bufs {
		if len(buf) <= offset {
			return fmt.Errorf("buffer of %d bytes has no datagram past offset %d", len(buf), offset)
		}
		for i := range buf[:offset] {
			buf[i] = 0xff
		}
	}
	return b.chanBind.Send(bufs, ep, offset)
}

func (b *headroomBind) snapshot() map[int]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[int]int, len(b.offsets))
	for k, v := range b.offsets {
		out[k] = v
	}
	return out
}

func newHeadroomDevicePair(t *testing.T, deviceLines string) (*paddedPair, *headroomBind, *headroomBind) {
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

	chanA, chanB := newChanBindPair()
	bindA := &headroomBind{chanBind: chanA, offsets: make(map[int]int)}
	bindB := &headroomBind{chanBind: chanB, offsets: make(map[int]int)}
	tunA := newChanTun()
	tunB := newChanTun()

	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "devA: "), 1)
	devB := NewDevice(context.Background(), tunB, bindB, NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)

	cfgA := "private_key=" + hex.EncodeToString(skA[:]) + "\n" + deviceLines +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n",
			hex.EncodeToString(pkB[:]), testIPB)
	cfgB := "private_key=" + hex.EncodeToString(skB[:]) + "\n" + deviceLines +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n",
			hex.EncodeToString(pkA[:]), testIPA)
	if err := devA.IpcSet(cfgA); err != nil {
		t.Fatalf("IpcSet A: %v", err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		t.Fatalf("IpcSet B: %v", err)
	}
	if err := devA.Up(); err != nil {
		t.Fatalf("Up A: %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("Up B: %v", err)
	}
	return &paddedPair{devA: devA, devB: devB, tunA: tunA, tunB: tunB}, bindA, bindB
}

func testSendHeadroom(t *testing.T, deviceLines string) {
	pair, bindA, bindB := newHeadroomDevicePair(t, deviceLines)

	ping := buildIPv4Packet(testIPA, testIPB, 64)
	send := func() { pair.tunA.toDevice <- ping }
	send()
	awaitPacket(t, pair.tunB, ping, send)

	pong := buildIPv4Packet(testIPB, testIPA, 64)
	sendBack := func() { pair.tunB.toDevice <- pong }
	sendBack()
	awaitPacket(t, pair.tunA, pong, sendBack)

	for name, bind := range map[string]*headroomBind{"A": bindA, "B": bindB} {
		offsets := bind.snapshot()
		if len(offsets) != 1 || offsets[MessageEncapsulatingTransportSize] == 0 {
			t.Errorf("bind %s: Send offsets %v, want only %d", name, offsets, MessageEncapsulatingTransportSize)
		}
	}
}

func TestSendHeadroomWireGuard(t *testing.T) {
	if MessageEncapsulatingTransportSize != 8 {
		t.Fatalf("MessageEncapsulatingTransportSize = %d, magicsock requires 8", MessageEncapsulatingTransportSize)
	}
	testSendHeadroom(t, "")
}

func TestSendHeadroomAWG2(t *testing.T) {
	testSendHeadroom(t, "jc=3\njmin=10\njmax=50\ns1=15\ns2=18\ns3=20\ns4=23\n"+
		"h1=1000-2000\nh2=3000-4000\nh3=5000-6000\nh4=7000-8000\n"+
		"i1=<b 0xf6a1><r 16>\ni3=<r 8>\n")
}

func TestSendHeadroomAWG3(t *testing.T) {
	testSendHeadroom(t, awg3DeviceLines(newHeaderKey(t)))
}
