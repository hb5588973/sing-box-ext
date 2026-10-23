/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 069 — Windows predicate for "this address family is unavailable".
 *
 * The external control wired in by sing-box binds every listener to the
 * default interface; for the v6 socket that is
 * setsockopt(IPV6_UNICAST_IF, ifIndex). When the default adapter has the
 * IPv6 protocol unchecked (absent from the v6 stack — a common state on
 * corporate/"optimized" machines), that setsockopt fails with WSAEINVAL,
 * and a fully disabled v6 stack yields WSAEADDRNOTAVAIL/WSAEAFNOSUPPORT on
 * the bind itself. All of these mean the same thing for our purposes: no
 * usable IPv6 on this host right now — degrade to IPv4, exactly like the
 * EAFNOSUPPORT case upstream already tolerates.
 *
 * sing's own bind_windows.go swallows a bind6 failure for the ""-wildcard
 * listener address ("workaround for windows disable interface ipv6") but
 * returns it for "[::]" — the form wireguard-go's listenNet uses — which is
 * how the error reaches Open at all.
 */

package conn

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// bindFamilyUnavailable reports whether err from listenNet means the address
// family cannot be used on this host, so Open should keep the sibling
// family's socket instead of failing outright.
func bindFamilyUnavailable(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, windows.WSAEINVAL) ||
		errors.Is(err, windows.WSAEADDRNOTAVAIL)
}
