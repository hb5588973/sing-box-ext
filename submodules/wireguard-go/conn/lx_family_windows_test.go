/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 069 — Windows predicate unit + the field scenario end to end:
 * a WSAEINVAL from the v6 interface-bind control (default adapter with the
 * IPv6 protocol unchecked) must degrade Open to v4, not kill the bind.
 */

package conn

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestBindFamilyUnavailableWindows(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"EAFNOSUPPORT", syscall.EAFNOSUPPORT, true},
		{"WSAEINVAL", windows.WSAEINVAL, true},
		{"WSAEADDRNOTAVAIL", windows.WSAEADDRNOTAVAIL, true},
		{"wrapped WSAEINVAL", &net.OpError{Op: "listen", Err: os.NewSyscallError("setsockopt", windows.WSAEINVAL)}, true},
		{"WSAECONNREFUSED", windows.WSAECONNREFUSED, false},
		{"EADDRINUSE", syscall.EADDRINUSE, false},
	}
	for _, c := range cases {
		if got := bindFamilyUnavailable(c.err); got != c.want {
			t.Errorf("%s: want %v, got %v", c.name, c.want, got)
		}
	}
}

// TestOpenKeepsV4OnWSAEINVAL reproduces the field failure (SPEC 069): the
// external control fails the udp6 socket with WSAEINVAL, as
// setsockopt(IPV6_UNICAST_IF) does when the default adapter is absent from
// the v6 stack. Red on the pre-fix base: Open returned the error and closed
// the already-open v4 socket.
func TestOpenKeepsV4OnWSAEINVAL(t *testing.T) {
	bind := NewStdNetBind(failFamilyControl("udp6", windows.WSAEINVAL)).(*StdNetBind)
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
	err = bind.Send([][]byte{make([]byte, 32)}, &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("[2001:db8::1]:2000")}, 0)
	if !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("v6 send: want EAFNOSUPPORT, got %v", err)
	}
}
