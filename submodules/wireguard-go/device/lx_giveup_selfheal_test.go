/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 041 — behavioural red/green test for the handshake give-up
 * self-heal. Field failure mode (WARP/AWG after device sleep): the per-flow
 * path state of the socket's 5-tuple dies (expired NAT mapping / poisoned DPI
 * flow entry), every packet sent from the old socket vanishes, and upstream
 * wireguard-go retries into that dead socket forever — only a manual
 * reconnect (new socket, new ephemeral port) heals the peer.
 *
 * The test models the dead 5-tuple with a bind whose FIRST socket generation
 * silently swallows every send; any socket opened after a rebind delivers
 * normally. It then drives the peer into the give-up branch of
 * expiredRetransmitHandshake and expects traffic to flow end to end without
 * any reconnect:
 *
 *   - pre-fix (base): give-up only flushes staged packets, the bind is never
 *     reopened, every retry keeps dying in the first generation -> timeout;
 *   - post-fix: give-up rebinds the socket and re-initiates -> tunnel comes
 *     up and the packet arrives.
 *
 * This file deliberately uses NO post-fix API, so it compiles and runs RED on
 * the pre-fix base commit. Reuses the chanBind/chanTun harness from
 * transport_padding_test.go.
 */

package device

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
)

// gateBind wraps chanBind: it records every Open (the port argument the
// device asked for) and silently swallows sends while the socket generation
// is at most dropOpens — modelling a dead 5-tuple whose packets vanish on the
// path without any local error.
type gateBind struct {
	*chanBind
	mu        sync.Mutex
	openPorts []uint16
	opens     int
	dropOpens int // swallow sends while opens <= dropOpens
}

func (b *gateBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.chanBind.Open(port)
	b.mu.Lock()
	b.opens++
	b.openPorts = append(b.openPorts, port)
	b.mu.Unlock()
	return fns, actual, err
}

func (b *gateBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.mu.Lock()
	drop := b.opens <= b.dropOpens
	b.mu.Unlock()
	if drop {
		return nil // the dead 5-tuple: no local error, the packet just vanishes
	}
	return b.chanBind.Send(bufs, ep, offset)
}

func (b *gateBind) openCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.opens
}

func (b *gateBind) portsSnapshot() []uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]uint16(nil), b.openPorts...)
}

type giveUpPair struct {
	devA, devB *Device
	tunA, tunB *chanTun
	bindA      *gateBind
	pkB        NoisePublicKey
}

// newGiveUpPair builds two Up()'d peered devices; devA sits on a gateBind
// whose first socket generation optionally blackholes all sends.
func newGiveUpPair(t *testing.T, dropFirstOpen bool) *giveUpPair {
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

	rawA, rawB := newChanBindPair()
	bindA := &gateBind{chanBind: rawA}
	if dropFirstOpen {
		bindA.dropOpens = 1
	}
	tunA := newChanTun()
	tunB := newChanTun()

	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "devA: "), 1)
	devB := NewDevice(context.Background(), tunB, rawB, NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)

	cfgA := fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n",
		hex.EncodeToString(skA[:]), hex.EncodeToString(pkB[:]), testIPB)
	cfgB := fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n",
		hex.EncodeToString(skB[:]), hex.EncodeToString(pkA[:]), testIPA)

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

	return &giveUpPair{devA: devA, devB: devB, tunA: tunA, tunB: tunB, bindA: bindA, pkB: pkB}
}

// triggerGiveUp drives dev's peer into the give-up branch of
// expiredRetransmitHandshake exactly the way 90s of unanswered retries would:
// attempts past the limit, last initiation older than RekeyTimeout.
func triggerGiveUp(t *testing.T, dev *Device, pk NoisePublicKey) {
	t.Helper()
	dev.peers.RLock()
	peer := dev.peers.keyMap[pk]
	dev.peers.RUnlock()
	if peer == nil {
		t.Fatal("peer not found")
	}
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-2 * RekeyTimeout)
	peer.handshake.mutex.Unlock()
	peer.timers.handshakeAttempts.Store(MaxTimerHandshakes + 1)
	expiredRetransmitHandshake(peer)
}

// TestHandshakeGiveUpSelfHeal: dead first socket, give-up fires — the tunnel
// must come up and deliver traffic without any reconnect.
func TestHandshakeGiveUpSelfHeal(t *testing.T) {
	pair := newGiveUpPair(t, true)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	send := func() { pair.tunA.toDevice <- pkt }

	// Traffic demand: stages the packet and sends the first (blackholed)
	// initiation, exactly the state a real give-up cycle ends in.
	send()
	triggerGiveUp(t, pair.devA, pair.pkB)
	awaitPacket(t, pair.tunB, pkt, send)
}
