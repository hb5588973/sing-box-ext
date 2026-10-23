/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 041 — passive self-heal for a dead per-flow path (an expired NAT
 * mapping or a poisoned DPI flow entry that pins every retry to the same dead
 * 5-tuple until a manual reconnect). One mechanism — reopen the bind (fresh
 * ephemeral port when allowed) and immediately re-initiate — with three
 * triggers sharing one debounce window:
 *
 *   giveup — the handshake retry cycle exhausted (~90s of unanswered
 *            initiations under traffic demand); safety net, covers every path;
 *   early  — >=3 unanswered initiations against a provably dead session
 *            (see sessionProvablyDead): no point waiting out the rest of the
 *            cycle, rebind at ~15s instead of ~90s;
 *   nudge  — the consumer reports "device woke up" via
 *            Device.RebindIfSessionStale (wired through sing-box libbox);
 *            heals without waiting for traffic demand at all.
 *
 * Zero cost while healthy: no timers, no goroutines — triggers 1-2 live in
 * the existing retry cycle, trigger 3 is paid by the caller. The state lives
 * in Device.giveUpRebind (device.go); enabled defaults to true in NewDevice,
 * sing-box decides freshPort from whether the user pinned listen_port.
 */

package device

import "time"

// earlyGiveUpMinAttempts is the number of unanswered initiations (retry timer
// expiries) after which a provably dead session is rebound early instead of
// waiting out the full RekeyAttemptTime cycle: ~15s at RekeyTimeout=5s.
const earlyGiveUpMinAttempts = 3

// SetGiveUpRebind configures the self-heal (see the giveUpRebind field
// comment in device.go). freshPort must be false when the user pinned an
// explicit listen_port: the pinned port is preserved, at the cost of the
// rebind not changing the 5-tuple.
func (device *Device) SetGiveUpRebind(enabled, freshPort bool) {
	device.giveUpRebind.enabled.Store(enabled)
	device.giveUpRebind.freshPort.Store(freshPort)
}

// handleHandshakeGiveUp is invoked from the give-up branch of
// expiredRetransmitHandshake: ~90s of initiations went unanswered, so the
// current socket's 5-tuple is proven dead.
func (device *Device) handleHandshakeGiveUp(peer *Peer) {
	device.selfHealRebind("giveup", peer)
}

// maybeEarlyGiveUpRebind is invoked from the RETRY branch of
// expiredRetransmitHandshake. Once enough initiations went unanswered AND the
// session is provably dead there is nothing left to protect — rebind now, at
// ~15s instead of ~90s. The retry cycle itself continues untouched: this only
// moves the socket under it. A live session with transient packet loss fails
// sessionProvablyDead and keeps byte-for-byte upstream behaviour; the shared
// debounce means this also suppresses the giveup rebind of the same series.
func (device *Device) maybeEarlyGiveUpRebind(peer *Peer) {
	if peer.timers.handshakeAttempts.Load() < earlyGiveUpMinAttempts {
		return
	}
	if !device.sessionProvablyDead(peer) {
		return
	}
	device.selfHealRebind("early", peer)
}

// sessionProvablyDead reports whether the peer's session is beyond saving: no
// live keypair, or the last successful handshake is older than
// RejectAfterTime (the keys are invalid after that, so a rebind loses
// nothing). The stale predicate shared by the early and nudge triggers.
func (device *Device) sessionProvablyDead(peer *Peer) bool {
	if peer.keypairs.Current() == nil {
		return true
	}
	return time.Since(time.Unix(0, peer.lastHandshakeNano.Load())) > device.keychainExpireTime()
}

// RebindIfSessionStale is the wake-nudge entry (trigger 3): the consumer
// observed a device wake-up and asks for an immediate heal instead of waiting
// for traffic demand to walk the retry cycle. If any running peer's session
// is provably dead the bind is reopened once (shared debounce) and every such
// peer re-initiates immediately; a healthy device is a no-op. Returns whether
// a rebind was actually scheduled. Never blocks on the rebind itself — the
// heavy part runs in a goroutine (see selfHealRebind). On a down or closed
// device it is a no-op, so callers racing idle-suspend or Close are safe.
func (device *Device) RebindIfSessionStale() bool {
	if !device.giveUpRebind.enabled.Load() || !device.isUp() {
		return false
	}
	var stale []*Peer
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		if peer.isRunning.Load() && device.sessionProvablyDead(peer) {
			stale = append(stale, peer)
		}
	}
	device.peers.RUnlock()
	if len(stale) == 0 {
		return false
	}
	return device.selfHealRebind("nudge", stale...)
}

// selfHealRebind is the shared action behind all three triggers. Runs the
// heavy part in a goroutine so a timer callback (or a nudge caller) never
// blocks on BindUpdate's worker drain. Debounced to one rebind per
// RekeyAttemptTime per device across ALL triggers (CAS on `last` settles
// concurrent multi-peer races): an early rebind at ~15s suppresses the giveup
// rebind of the same failed series at ~90s. On a down or closed device
// BindUpdate does not reopen the socket, so a rebind racing idle-suspend
// (SPEC 020) or Close degrades to a no-op.
func (device *Device) selfHealRebind(trigger string, peers ...*Peer) bool {
	if !device.giveUpRebind.enabled.Load() {
		return false
	}
	if device.isClosed() {
		return false
	}
	now := time.Now().Unix()
	last := device.giveUpRebind.last.Load()
	if now-last < int64(RekeyAttemptTime/time.Second) {
		return false
	}
	if !device.giveUpRebind.last.CompareAndSwap(last, now) {
		return false
	}
	fresh := device.giveUpRebind.freshPort.Load()
	go func() {
		if fresh {
			device.net.Lock()
			device.net.port = 0
			device.net.Unlock()
		}
		if err := device.BindUpdate(); err != nil {
			device.log.Errorf("%v - Failed self-heal rebind (trigger=%s): %v", peers[0], trigger, err)
			return
		}
		device.log.Verbosef("%v - Rebound socket for self-heal (trigger=%s, fresh port=%v)", peers[0], trigger, fresh)
		for _, peer := range peers {
			peer.SendHandshakeInitiation(false)
		}
	}()
	return true
}
