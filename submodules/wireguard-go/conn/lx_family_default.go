//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 069 — see lx_family_windows.go for the Windows-specific cases.
 * On every other platform upstream behaviour is preserved bit-for-bit:
 * only EAFNOSUPPORT means "this address family is unavailable".
 */

package conn

import (
	"errors"
	"syscall"
)

// bindFamilyUnavailable reports whether err from listenNet means the address
// family cannot be used on this host, so Open should keep the sibling
// family's socket instead of failing outright.
func bindFamilyUnavailable(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT)
}
