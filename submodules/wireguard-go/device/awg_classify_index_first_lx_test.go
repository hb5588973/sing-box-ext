/* SPDX-License-Identifier: MIT
 *
 * sing-box-lx SPEC 081 — transport-first classification by receiver index.
 *
 * The reference amneziawg-go receiver classifies a datagram by trying the
 * handshake kinds first (init / response / cookie, each by "size matches
 * S_k + size_k" and "type word in H_k") and transport last. A data datagram
 * whose size coincides with S1 + 148 is therefore tried as an initiation by
 * the 4 ciphertext bytes at offset S1 — random bytes — and with a wide H1
 * range they match: the packet is truncated, fails MAC1 and is dropped. With
 * AWG 3.1 random_trailers every data datagram longer than S1 + 148 is tried
 * the same way. The loss is on our receive side (downlink); the fix checks
 * the transport candidate first when its unmasked receiver index resolves to
 * one of our live keypairs — a 32-bit value a foreign datagram cannot carry
 * by accident.
 *
 * The test pins the exact-size case with a deterministic collision: s1 = 44,
 * s4 = 0, h1 = 5..2^32-1 (everything but the WireGuard types), a 160-byte IP
 * packet -> data datagram of exactly 44 + 148 = 192 bytes. Without the fix the
 * packet never arrives (RED); with it, it does (GREEN).
 */

package device

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

const (
	indexFirstS1         = 44
	indexFirstPayloadLen = 140                                  // 20-byte IPv4 header + 140 = 160 = 10 x 16, so no alignment pad
	indexFirstDatagram   = indexFirstS1 + MessageInitiationSize // 192
)

// newWideH1DevicePair brings up two peered devices with s1=44, s4=0 and an
// h1 range that claims any random type word; tapA records A's datagrams.
func newWideH1DevicePair(t *testing.T, tapA *wireTap) *paddedPair {
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
	if tapA != nil {
		bindA.tap = tapA.record
	}
	tunA := newChanTun()
	tunB := newChanTun()

	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "devA: "), 1)
	devB := NewDevice(context.Background(), tunB, bindB, NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)

	obf := fmt.Sprintf("s1=%d\ns2=0\ns3=0\ns4=0\nh1=5-4294967295\nh2=2\nh3=3\nh4=4\n", indexFirstS1)
	cfgA := "private_key=" + hex.EncodeToString(skA[:]) + "\n" + obf +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n", hex.EncodeToString(pkB[:]), testIPB)
	cfgB := "private_key=" + hex.EncodeToString(skB[:]) + "\n" + obf +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n", hex.EncodeToString(pkA[:]), testIPA)

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
	return &paddedPair{devA: devA, devB: devB, tunA: tunA, tunB: tunB}
}

func TestAWGDataPacketOfInitSizeNotClaimedByWideH1(t *testing.T) {
	tap := &wireTap{}
	pair := newWideH1DevicePair(t, tap)

	// establish the session with a packet of a harmless size (64-byte datagram)
	small := buildIPv4Packet(testIPA, testIPB, 8)
	sendSmall := func() { pair.tunA.toDevice <- append([]byte(nil), small...) }
	sendSmall()
	awaitPacket(t, pair.tunB, small, sendSmall)

	// the collision: a data datagram of exactly s1 + 148 bytes
	big := buildIPv4Packet(testIPA, testIPB, indexFirstPayloadLen)
	sendBig := func() { pair.tunA.toDevice <- append([]byte(nil), big...) }
	sendBig()
	awaitPacket(t, pair.tunB, big, sendBig)

	// the premise: A really put a 192-byte transport datagram on the wire
	// (s4 = 0 and no header key, so the type word is in the clear at offset 0)
	seen := false
	for _, dg := range tap.snapshot() {
		if len(dg) == indexFirstDatagram && binary.LittleEndian.Uint32(dg[:4]) == MessageTransportType {
			seen = true
			break
		}
	}
	if !seen {
		t.Fatalf("no %d-byte transport datagram on the wire: the test no longer exercises the size collision", indexFirstDatagram)
	}

	// and the responder's direction, same trap on A's receiver
	back := buildIPv4Packet(testIPB, testIPA, indexFirstPayloadLen)
	sendBack := func() { pair.tunB.toDevice <- append([]byte(nil), back...) }
	sendBack()
	awaitPacket(t, pair.tunA, back, sendBack)
}
