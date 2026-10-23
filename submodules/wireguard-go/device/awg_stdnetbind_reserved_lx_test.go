/* SPDX-License-Identifier: MIT
 *
 * lx: e2e regression for the reserved-clear vs AWG magic-header collision,
 * exercised over the StdNetBind path (no detour) with real loopback UDP.
 *
 * Bug model. On receive, StdNetBind.receiveIP unconditionally zeroed bytes
 * 1-3 of every datagram >3 bytes (the Cloudflare WARP "reserved" field).
 * AmneziaWG reads its magic header as LittleEndian.Uint32(packet[padding:]),
 * where padding is s1/s2 (handshake) or s4 (transport). With small padding
 * (0..3) the 4-byte magic overlaps bytes 1-3, so the unconditional clear
 * corrupts it: the value falls outside the ranged h1-h4 window, the packet is
 * classified MessageUnknownType and dropped. WARP was never configured on
 * these binds (no SetReservedForEndpoint), so the clear was pure collateral.
 *
 * The fix gates the clear behind StdNetBind.hasReserved(): bytes 1-3 are only
 * zeroed when a non-zero reserved value is actually set for some endpoint.
 * With no reserved value the magic survives and the handshake completes.
 *
 * This test provokes the worst case: padding = 0 (no s1/s2/s4 at all), so the
 * h1 initiation magic sits in bytes [0..3] and its high bytes (1-3) are the
 * ones the clear would destroy. The h1-h4 ranges are chosen entirely above
 * 0x10000000, so after zeroing bytes 1-3 the surviving value is <= 255 and can
 * never land back inside any range -> guaranteed drop on the buggy tree.
 *
 * GREEN on the fixed tree. To see RED, temporarily restore the unconditional
 * clear in conn/bind_std.go receiveIP:
 *     if msg.N > 3 {
 *         common.ClearArray(bufs[i][1:4])
 *     }
 * and the handshake times out (init magic zeroed in bytes 1-3).
 */

package device

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
)

// magic header ranges kept entirely above 0x10000000 (268435456). Any value
// the sender picks therefore has a non-zero byte among positions 1-3; zeroing
// those bytes collapses the value to <= 0xFF, which is below every range start,
// so a corrupted magic can never validate. Distinct windows per message type.
const (
	lxH1Lo, lxH1Hi = 268500000, 268600000 // init
	lxH2Lo, lxH2Hi = 300000000, 300100000 // response
	lxH3Lo, lxH3Hi = 400000000, 400100000 // cookie
	lxH4Lo, lxH4Hi = 500000000, 500100000 // transport
)

// lxReadListenPort parses listen_port=<n> out of a device's IpcGet dump.
func lxReadListenPort(t *testing.T, dev *Device) uint16 {
	t.Helper()
	dump, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(dump))
	for scanner.Scan() {
		line := scanner.Text()
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			p, err := strconv.Atoi(v)
			if err != nil {
				t.Fatalf("parse listen_port %q: %v", v, err)
			}
			return uint16(p)
		}
	}
	t.Fatalf("listen_port not found in dump:\n%s", dump)
	return 0
}

// newStdNetPaddedPair builds two Up()'d Devices peered over real loopback UDP
// (NewStdNetBind), configured with ranged h1-h4 + junk and *no* s1/s2/s4
// (padding = 0). Endpoints are wired after Up, once the ephemeral ports are
// known. No reserved value is ever set, so hasReserved() is false.
func newStdNetPaddedPair(t *testing.T) (devA, devB *Device, tunA, tunB *chanTun) {
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

	tunA = newChanTun()
	tunB = newChanTun()

	devA = NewDevice(context.Background(), tunA, conn.NewStdNetBind(nil), NewLogger(LogLevelError, "devA: "), 1)
	devB = NewDevice(context.Background(), tunB, conn.NewStdNetBind(nil), NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)

	// obfuscation shared by both ends. Ranged magic headers, junk packets,
	// and deliberately no s1/s2/s4 so padding stays 0 for every message type.
	obf := fmt.Sprintf(
		"jc=3\njmin=8\njmax=16\n"+
			"h1=%d-%d\nh2=%d-%d\nh3=%d-%d\nh4=%d-%d\n",
		lxH1Lo, lxH1Hi, lxH2Lo, lxH2Hi, lxH3Lo, lxH3Hi, lxH4Lo, lxH4Hi)

	// Bring both up on an ephemeral port (listen_port=0), no endpoint yet.
	cfgA := fmt.Sprintf("private_key=%s\nlisten_port=0\n%sreplace_peers=true\npublic_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(skA[:]), obf, hex.EncodeToString(pkB[:]), testIPB)
	cfgB := fmt.Sprintf("private_key=%s\nlisten_port=0\n%sreplace_peers=true\npublic_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(skB[:]), obf, hex.EncodeToString(pkA[:]), testIPA)

	if err := devA.IpcSet(cfgA); err != nil {
		t.Fatalf("IpcSet A: %v", err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		t.Fatalf("IpcSet B: %v", err)
	}
	if devA.paddings.init.Load() != 0 || devA.paddings.response.Load() != 0 || devA.paddings.transport.Load() != 0 {
		t.Fatalf("padding must be 0 for this test: init=%d resp=%d transport=%d",
			devA.paddings.init.Load(), devA.paddings.response.Load(), devA.paddings.transport.Load())
	}

	if err := devA.Up(); err != nil {
		t.Fatalf("Up A: %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("Up B: %v", err)
	}

	portA := lxReadListenPort(t, devA)
	portB := lxReadListenPort(t, devB)
	if portA == 0 || portB == 0 {
		t.Fatalf("ephemeral ports not assigned: A=%d B=%d", portA, portB)
	}

	// Now that ports are known, point each peer at the other over loopback.
	if err := devA.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=127.0.0.1:%d\n",
		hex.EncodeToString(pkB[:]), portB)); err != nil {
		t.Fatalf("set endpoint A->B: %v", err)
	}
	if err := devB.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=127.0.0.1:%d\n",
		hex.EncodeToString(pkA[:]), portA)); err != nil {
		t.Fatalf("set endpoint B->A: %v", err)
	}

	return devA, devB, tunA, tunB
}

// TestStdNetBindReservedClearVsMagic_ZeroPadding drives a real handshake and a
// data packet A->B over loopback UDP through StdNetBind, with padding=0 so the
// h1 magic overlaps the reserved bytes 1-3. It passes only when receive does
// not blindly clear those bytes (the fix).
func TestStdNetBindReservedClearVsMagic_ZeroPadding(t *testing.T) {
	devA, _, tunA, tunB := newStdNetPaddedPair(t)
	_ = devA

	pkt := buildIPv4Packet(testIPA, testIPB, 8)

	// Re-inject periodically: the first packet triggers the handshake and may
	// be dropped until keys are established.
	send := func() { tunA.toDevice <- pkt }
	send()

	deadline := time.After(15 * time.Second)
	retry := time.NewTicker(500 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case got := <-tunB.fromDevice:
			if bytes.Equal(got, pkt) {
				return // delivered end to end: magic survived, handshake ok
			}
			t.Logf("ignoring unexpected packet len=%d", len(got))
		case <-retry.C:
			send()
		case <-deadline:
			t.Fatal("timed out waiting for packet on peer tun " +
				"(handshake never completed: reserved-clear likely corrupted the h1 magic)")
		}
	}
}
