/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * This is based heavily on timers.c from the kernel implementation.
 */

package device

import (
	"sync"
	"time"
	_ "unsafe"
)

//go:linkname fastrandn runtime.fastrandn
func fastrandn(n uint32) uint32

// A Timer manages time-based aspects of the WireGuard protocol.
// Timer roughly copies the interface of the Linux kernel's struct timer_list.
type Timer struct {
	*time.Timer
	modifyingLock sync.RWMutex
	runningLock   sync.Mutex
	isPending     bool
}

func (peer *Peer) NewTimer(expirationFunction func(*Peer)) *Timer {
	timer := &Timer{}
	timer.Timer = time.AfterFunc(time.Hour, func() {
		timer.runningLock.Lock()
		defer timer.runningLock.Unlock()

		timer.modifyingLock.Lock()
		if !timer.isPending {
			timer.modifyingLock.Unlock()
			return
		}
		timer.isPending = false
		timer.modifyingLock.Unlock()

		if pauseManager := peer.device.pauseManager; pauseManager != nil {
			pauseManager.WaitActive()
		}
		expirationFunction(peer)
	})
	timer.Stop()
	return timer
}

func (timer *Timer) Mod(d time.Duration) {
	timer.modifyingLock.Lock()
	timer.isPending = true
	timer.Reset(d)
	timer.modifyingLock.Unlock()
}

func (timer *Timer) Del() {
	timer.modifyingLock.Lock()
	timer.isPending = false
	timer.Stop()
	timer.modifyingLock.Unlock()
}

func (timer *Timer) DelSync() {
	timer.Del()
	timer.runningLock.Lock()
	timer.Del()
	timer.runningLock.Unlock()
}

func (timer *Timer) IsPending() bool {
	timer.modifyingLock.RLock()
	defer timer.modifyingLock.RUnlock()
	return timer.isPending
}

func (peer *Peer) timersActive() bool {
	return peer.isRunning.Load() && peer.device != nil && peer.device.isUp()
}

func expiredRetransmitHandshake(peer *Peer) {
	// lx: AWG 3.x max_handshake_attempts — the pick for this handshake cycle
	// (timersStart / SendHandshakeInitiation); the WireGuard constant when the
	// cycle predates the pick.
	maxAttempts := peer.timers.maxHandshakeAttempts.Load()
	if maxAttempts == 0 {
		maxAttempts = peer.device.maxHandshakeAttempts()
	}

	if peer.timers.handshakeAttempts.Load() > maxAttempts {
		peer.device.log.Verbosef("%s - Handshake did not complete after %d attempts, giving up", peer, maxAttempts+2)

		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}

		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		peer.FlushStagedPackets()

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if peer.timersActive() && !peer.timers.zeroKeyMaterial.IsPending() {
			peer.timers.zeroKeyMaterial.Mod(peer.device.keychainExpireTime() * 3)
		}
		peer.noteSessionHandshakeStopped()

		/* lx: SPEC 041 — the exhausted cycle just proved the current socket's
		 * 5-tuple dead (90s of initiations, zero replies). Rebind once and
		 * re-initiate, so a stale NAT mapping / poisoned DPI flow entry cannot
		 * pin this peer to a dead socket until a manual reconnect. Runs after
		 * the session-state notification so a consumer sees "handshake stopped"
		 * before the socket is recreated. */
		peer.device.handleHandshakeGiveUp(peer)
	} else {
		peer.timers.handshakeAttempts.Add(1)
		peer.device.log.Verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", peer, int(peer.device.rekeyMinTimeout().Seconds()), peer.timers.handshakeAttempts.Load()+1)

		/* lx: SPEC 041 v2 — early self-heal: >=3 unanswered initiations against
		 * a provably dead session (no live keypair, or last handshake older
		 * than RejectAfterTime) prove the 5-tuple dead without waiting out the
		 * full cycle. Rebind now (debounced with the give-up trigger below);
		 * the retry cycle itself continues untouched. */
		peer.device.maybeEarlyGiveUpRebind(peer)

		/* We clear the endpoint address src address, in case this is the cause of trouble. */
		peer.markEndpointSrcForClearing()

		peer.SendHandshakeInitiation(true)
	}
}

func expiredSendKeepalive(peer *Peer) {
	peer.SendKeepalive()
	if peer.timers.needAnotherKeepalive.Load() {
		peer.timers.needAnotherKeepalive.Store(false)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Mod(peer.sendKeepaliveTimeout())
		}
	}
}

func expiredNewHandshake(peer *Peer) {
	peer.device.log.Verbosef("%s - Retrying handshake because we stopped hearing back after %d seconds", peer, int(peer.newHandshakeTimeout().Seconds()))
	/* We clear the endpoint address src address, in case this is the cause of trouble. */
	peer.markEndpointSrcForClearing()
	peer.SendHandshakeInitiation(false)
}

func expiredZeroKeyMaterial(peer *Peer) {
	peer.device.log.Verbosef("%s - Removing all keys, since we haven't received a new one in %d seconds", peer, int((peer.device.keychainExpireTime() * 3).Seconds()))
	peer.ZeroAndFlushAll()
	if peer.deleteOnIdle {
		peer.device.log.Verbosef("%s - Removing idle lazy peer", peer)
		// Remove the peer from the device in a new goroutine as we're currently
		// holding timer locks which RemovePeer also needs. This is TOCTOU, but
		// acceptable since the worst case is we remove the peer and the lazy
		// peerfunc created it again after. We might lose some packets.
		go peer.device.RemovePeer(peer.handshake.remoteStatic)
	}
}

func expiredSession(peer *Peer) {
	peer.sessionState.Lock()
	defer peer.sessionState.Unlock()
	if peer.sessionState.sessionExpires.IsZero() || time.Now().Before(peer.sessionState.sessionExpires) {
		return
	}
	peer.device.log.Verbosef("%s - Session expired after %d seconds", peer, int(peer.device.keychainExpireTime().Seconds()))
	peer.noteSessionStateLocked(PeerSessionExpired)
}

func expiredPersistentKeepalive(peer *Peer) {
	if !peer.persistentKeepaliveInterval.Load().IsZero() {
		peer.SendKeepalive()
	}
}

/* Should be called after an authenticated data packet is sent. */
func (peer *Peer) timersDataSent() {
	if peer.timersActive() && !peer.timers.newHandshake.IsPending() {
		peer.timers.newHandshake.Mod(peer.newHandshakeTimeout() + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after an authenticated data packet is received. */
func (peer *Peer) timersDataReceived() {
	if peer.timersActive() {
		if !peer.timers.sendKeepalive.IsPending() {
			peer.timers.sendKeepalive.Mod(peer.sendKeepaliveTimeout())
		} else {
			peer.timers.needAnotherKeepalive.Store(true)
		}
	}
}

/* Should be called after any type of authenticated packet is sent -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketSent() {
	if peer.timersActive() {
		peer.timers.sendKeepalive.Del()
	}
}

/* Should be called after any type of authenticated packet is received -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketReceived() {
	if peer.timersActive() {
		peer.timers.newHandshake.Del()
	}
}

/* Should be called after a handshake initiation message is sent. */
func (peer *Peer) timersHandshakeInitiated() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Mod(peer.retransmitHandshakeTimeout() + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
	peer.noteSessionHandshakeStarted()
}

/* Should be called after a handshake response message is received and processed or when getting key confirmation via the first data message. */
func (peer *Peer) timersHandshakeComplete() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Del()
	}
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.maxHandshakeAttempts.Store(peer.device.maxHandshakeAttempts())
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.lastHandshakeNano.Store(time.Now().UnixNano())
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
func (peer *Peer) timersSessionDerived() {
	if peer.timersActive() {
		expire := peer.device.keychainExpireTime()
		peer.sessionState.Lock()
		peer.sessionState.sessionExpires = time.Now().Add(expire)
		peer.noteSessionStateLocked(PeerSessionEstablished)
		peer.sessionState.Unlock()
		peer.timers.sessionExpired.Mod(expire)
		peer.timers.zeroKeyMaterial.Mod(expire * 3)
	} else {
		peer.noteSessionState(PeerSessionEstablished)
	}
}

/* Should be called before a packet with authentication -- keepalive, data, or handshake -- is sent, or after one is received. */
func (peer *Peer) timersAnyAuthenticatedPacketTraversal() {
	keepalive := peer.persistentKeepaliveInterval.Load()
	if !keepalive.IsZero() && peer.timersActive() {
		peer.timers.persistentKeepalive.Mod(time.Duration(keepalive.PickOne()) * time.Second)
	}
}

func (peer *Peer) timersInit() {
	peer.timers.retransmitHandshake = peer.NewTimer(expiredRetransmitHandshake)
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)
	peer.timers.sessionExpired = peer.NewTimer(expiredSession)
	peer.timers.zeroKeyMaterial = peer.NewTimer(expiredZeroKeyMaterial)
	peer.timers.persistentKeepalive = peer.NewTimer(expiredPersistentKeepalive)
}

func (peer *Peer) timersStart() {
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.maxHandshakeAttempts.Store(peer.device.maxHandshakeAttempts())
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.timers.needAnotherKeepalive.Store(false)
}

func (peer *Peer) timersStop() {
	peer.timers.retransmitHandshake.DelSync()
	peer.timers.sendKeepalive.DelSync()
	peer.timers.newHandshake.DelSync()
	peer.timers.sessionExpired.DelSync()
	peer.timers.zeroKeyMaterial.DelSync()
	peer.timers.persistentKeepalive.DelSync()
}

// lx:begin awg3 (AmneziaWG 3.x timings — ported from amneziawg-go v3 device/timers.go)
//
// Each WireGuard timing constant gets a device-level uapi override
// (rekey_after_time, rekey_timeout, reject_after_time, keepalive_timeout,
// max_handshake_attempts), each an inclusive "min-max" range in seconds /
// attempts. Unset (zero) ranges fall back to the constants, so a plain
// WireGuard device is unchanged. Where a derived timeout combines several
// ranges, the bound that keeps the protocol safe is used (e.g. the widest
// keepalive timeout before declaring the peer silent, the narrowest before a
// pre-emptive rekey).

func (peer *Peer) retransmitHandshakeTimeout() time.Duration {
	timeout := RekeyTimeout

	if t := peer.device.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		timeout = time.Duration(t.PickOne()) * time.Second
	}

	return timeout
}

func (peer *Peer) sendKeepaliveTimeout() time.Duration {
	timeout := KeepaliveTimeout

	if t := peer.device.timings.keepaliveTimeoutSec.Load(); !t.IsZero() {
		timeout = time.Duration(t.PickOne()) * time.Second
	}

	return timeout
}

func (peer *Peer) newHandshakeTimeout() time.Duration {
	keepaliveTimeout := KeepaliveTimeout
	rekeyTimeout := RekeyTimeout

	if t := peer.device.timings.keepaliveTimeoutSec.Load(); !t.IsZero() {
		keepaliveTimeout = time.Duration(t.Hi()) * time.Second
	}
	if t := peer.device.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		rekeyTimeout = time.Duration(t.PickOne()) * time.Second
	}

	return keepaliveTimeout + rekeyTimeout
}

func (device *Device) keyRefreshTimeoutSending() time.Duration {
	rekeyAfterTime := RekeyAfterTime

	if t := device.timings.rekeyAfterTimeSec.Load(); !t.IsZero() {
		rekeyAfterTime = time.Duration(t.PickOne()) * time.Second
	}

	return rekeyAfterTime
}

func (device *Device) keyRefreshTimeoutReceiving() time.Duration {
	rejectAfterTime := RejectAfterTime
	keepaliveTimeout := KeepaliveTimeout
	rekeyTimeout := RekeyTimeout

	if t := device.timings.rejectAfterTimeSec.Load(); !t.IsZero() {
		rejectAfterTime = time.Duration(t.PickOne()) * time.Second
	}
	if t := device.timings.keepaliveTimeoutSec.Load(); !t.IsZero() {
		keepaliveTimeout = time.Duration(t.Lo()) * time.Second
	}
	if t := device.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		rekeyTimeout = time.Duration(t.Lo()) * time.Second
	}

	return max(0, rejectAfterTime-keepaliveTimeout-rekeyTimeout)
}

// keychainExpireTime is the effective RejectAfterTime: the upper bound of
// reject_after_time, so a keypair is never rejected before the peer would.
func (device *Device) keychainExpireTime() time.Duration {
	rejectAfterTime := RejectAfterTime

	if t := device.timings.rejectAfterTimeSec.Load(); !t.IsZero() {
		rejectAfterTime = time.Duration(t.Hi()) * time.Second
	}

	return rejectAfterTime
}

// rekeyMinTimeout is the effective RekeyTimeout floor: the lower bound of
// rekey_timeout, the minimum spacing between two handshake initiations.
func (device *Device) rekeyMinTimeout() time.Duration {
	rekeyTimeout := RekeyTimeout

	if t := device.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		rekeyTimeout = time.Duration(t.Lo()) * time.Second
	}

	return rekeyTimeout
}

func (device *Device) maxHandshakeAttempts() uint32 {
	res := uint32(MaxTimerHandshakes)

	if t := device.timings.maxHandshakeAttempts.Load(); !t.IsZero() {
		res = t.PickOne()
	}

	return res
}

// lx:end awg3
