/* SPDX-License-Identifier: MIT
 *
 * lx: unit coverage for the StdNetBind.hasReserved() gate that guards the
 * receive-side reserved-clear. receiveIP zeroes bytes 1-3 (Cloudflare WARP
 * "reserved") only when a non-zero reserved value is set for some endpoint;
 * otherwise an AmneziaWG magic header landing in bytes 1-3 (small s1/s2/s4
 * padding) would be corrupted and the packet dropped. This test pins the gate
 * itself; the end-to-end handshake proof lives in the device package.
 */

package conn

import (
	"net/netip"
	"testing"
)

func stdNetBindForTest(t *testing.T) *StdNetBind {
	t.Helper()
	b, ok := NewStdNetBind(nil).(*StdNetBind)
	if !ok {
		t.Fatalf("NewStdNetBind did not return *StdNetBind")
	}
	return b
}

func TestStdNetBindHasReserved(t *testing.T) {
	b := stdNetBindForTest(t)
	if b.hasReserved() {
		t.Fatal("fresh bind must report no reserved value")
	}

	ep := netip.MustParseAddrPort("127.0.0.1:51820")

	// An all-zero reserved value is indistinguishable from "unset" and must
	// not arm the clear.
	b.SetReservedForEndpoint(ep, [3]byte{0, 0, 0})
	if b.hasReserved() {
		t.Fatal("all-zero reserved must not count as reserved")
	}

	// Any non-zero byte (WARP anycast tag) arms the clear.
	b.SetReservedForEndpoint(ep, [3]byte{0, 0, 1})
	if !b.hasReserved() {
		t.Fatal("non-zero reserved (byte 3) must count as reserved")
	}

	// A second endpoint's non-zero value must also be seen.
	b2 := stdNetBindForTest(t)
	ep2 := netip.MustParseAddrPort("192.0.2.1:2408")
	b2.SetReservedForEndpoint(ep, [3]byte{0, 0, 0})
	b2.SetReservedForEndpoint(ep2, [3]byte{0xAB, 0, 0})
	if !b2.hasReserved() {
		t.Fatal("non-zero reserved on any endpoint must count as reserved")
	}
}
