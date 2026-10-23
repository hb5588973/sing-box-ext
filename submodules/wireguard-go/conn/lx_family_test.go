/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 069 — Open must survive a per-family bind failure by keeping the
 * sibling family's socket. The injected error is EAFNOSUPPORT because that
 * value is family-unavailable on every platform; the Windows-only values
 * (WSAEINVAL, WSAEADDRNOTAVAIL) are covered by lx_family_windows_test.go.
 */

package conn

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// failFamilyControl returns an external control that rejects the given
// network with the given error, standing in for the interface-bind control
// sing-box wires into StdNetBind.
func failFamilyControl(failNetwork string, failErr error) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		if network == failNetwork {
			return failErr
		}
		return nil
	}
}

func TestOpenKeepsV4WhenV6FamilyUnavailable(t *testing.T) {
	bind := NewStdNetBind(failFamilyControl("udp6", syscall.EAFNOSUPPORT)).(*StdNetBind)
	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open must degrade to v4, got error: %v", err)
	}
	defer bind.Close()
	if port == 0 {
		t.Fatal("Open returned port 0")
	}
	if len(fns) == 0 {
		t.Fatal("Open returned no receive funcs")
	}
	if bind.ipv4 == nil {
		t.Fatal("v4 socket missing after v6 degradation")
	}
	if bind.ipv6 != nil {
		t.Fatal("v6 socket unexpectedly open")
	}

	// The failed family stays explicitly unavailable on the send path —
	// this is the exact client-visible symptom the degradation replaces.
	err = bind.Send([][]byte{make([]byte, 32)}, &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("[2001:db8::1]:2000")}, 0)
	if !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("v6 send: want EAFNOSUPPORT, got %v", err)
	}

	// The surviving family actually carries packets.
	sink, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()
	payload := make([]byte, 32)
	err = bind.Send([][]byte{payload}, &StdNetEndpoint{AddrPort: sink.LocalAddr().(*net.UDPAddr).AddrPort()}, 0)
	if err != nil {
		t.Fatalf("v4 send: %v", err)
	}
	sink.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, _, err := sink.ReadFrom(buf)
	if err != nil {
		t.Fatalf("v4 receive: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("v4 receive: want %d bytes, got %d", len(payload), n)
	}
}

func TestOpenKeepsV6WhenV4FamilyUnavailable(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		t.Skipf("environment without IPv6: %v", err)
	}
	probe.Close()

	bind := NewStdNetBind(failFamilyControl("udp4", syscall.EAFNOSUPPORT)).(*StdNetBind)
	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open must degrade to v6, got error: %v", err)
	}
	defer bind.Close()
	if port == 0 {
		t.Fatal("Open returned port 0")
	}
	if len(fns) == 0 {
		t.Fatal("Open returned no receive funcs")
	}
	if bind.ipv6 == nil {
		t.Fatal("v6 socket missing after v4 degradation")
	}
	if bind.ipv4 != nil {
		t.Fatal("v4 socket unexpectedly open")
	}
}

func TestOpenFailsWhenBothFamiliesUnavailable(t *testing.T) {
	control := func(network, address string, c syscall.RawConn) error {
		return syscall.EAFNOSUPPORT
	}
	bind := NewStdNetBind(control).(*StdNetBind)
	_, _, err := bind.Open(0)
	if !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("want EAFNOSUPPORT when both families fail, got %v", err)
	}
}
