//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 069 — the non-Windows predicate must stay bit-for-bit upstream:
 * EINVAL and friends must NOT be treated as family-unavailable there.
 */

package conn

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestBindFamilyUnavailableDefault(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"EAFNOSUPPORT", syscall.EAFNOSUPPORT, true},
		{"wrapped EAFNOSUPPORT", &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EAFNOSUPPORT)}, true},
		{"EINVAL", syscall.EINVAL, false},
		{"EADDRNOTAVAIL", syscall.EADDRNOTAVAIL, false},
		{"EADDRINUSE", syscall.EADDRINUSE, false},
	}
	for _, c := range cases {
		if got := bindFamilyUnavailable(c.err); got != c.want {
			t.Errorf("%s: want %v, got %v", c.name, c.want, got)
		}
	}
}

// TestOpenStillFailsOnEINVAL pins the non-Windows contract: an EINVAL from
// the v6 path is a real error, not a degradation trigger, and must fail the
// whole Open exactly like upstream.
func TestOpenStillFailsOnEINVAL(t *testing.T) {
	bind := NewStdNetBind(failFamilyControl("udp6", syscall.EINVAL)).(*StdNetBind)
	_, _, err := bind.Open(0)
	if err == nil {
		bind.Close()
		t.Fatal("Open must fail on EINVAL on non-Windows platforms")
	}
	if bind.ipv4 != nil || bind.ipv6 != nil {
		t.Fatal("failed Open must not leave sockets behind")
	}
}
