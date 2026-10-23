/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 041 v2 — behavioural red/green test for the EARLY give-up rebind.
 * Field failure mode (the v1 field leftover, dump 2026-08-01): the v1 give-up
 * rebind heals a dead 5-tuple, but only at ~90s after the first demand — while
 * the user pings within the first 5-35s after device wake and sees every node
 * in ERR. The early trigger fires from the retry branch once >=3 initiations
 * went unanswered AND the session is provably dead (no live keypair, or last
 * handshake older than RejectAfterTime), shrinking the ERR window to ~15-20s.
 *
 * The test reuses the v1 harness (gateBind: first socket generation blackholes
 * every send) and drives the peer to the 3rd retry expiry — the state a real
 * ~15s of unanswered retries ends in. Post-fix the retry branch rebinds and
 * the tunnel comes up; pre-fix (v1 base) the retry keeps dying in the first
 * socket generation and only the ~90s give-up would heal, so the packet never
 * arrives within the test window.
 *
 * This file deliberately uses NO post-fix API, so it compiles and runs RED on
 * the v1 base commit.
 */

package device

import (
	"testing"
	"time"
)

// TestEarlyRebindSelfHeal: dead first socket, cold session (no keypair yet),
// 3rd retry expiry fires — the tunnel must come up and deliver traffic without
// waiting out the full 90s give-up cycle.
func TestEarlyRebindSelfHeal(t *testing.T) {
	pair := newGiveUpPair(t, true)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	send := func() { pair.tunA.toDevice <- pkt }

	// Traffic demand: stages the packet and sends the first (blackholed)
	// initiation.
	send()

	pair.devA.peers.RLock()
	peer := pair.devA.peers.keyMap[pair.pkB]
	pair.devA.peers.RUnlock()
	if peer == nil {
		t.Fatal("peer not found")
	}

	// Simulate reaching the 3rd retry expiry (~15s in the field): two retries
	// already counted, the last initiation older than the retransmit timeout.
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-2 * RekeyTimeout)
	peer.handshake.mutex.Unlock()
	peer.timers.handshakeAttempts.Store(2)
	expiredRetransmitHandshake(peer)

	awaitPacket(t, pair.tunB, pkt, send)
}
