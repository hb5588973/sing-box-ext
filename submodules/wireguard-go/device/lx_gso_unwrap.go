/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 101 — one unwrap of conn.ErrUDPGSODisabled for every send path.
 */

package device

import (
	"errors"

	"github.com/sagernet/wireguard-go/conn"
)

// unwrapGSODisabled strips conn.ErrUDPGSODisabled from a bind send error.
// StdNetBind returns it after the kernel rejected UDP GSO: offload is turned
// off for the address family and the same batch is resent without it, so the
// wrapper signals "offload disabled", and RetryErr is the error of the resend
// (nil when the resend went through). The wrapper is logged at Verbose and
// only RetryErr is returned; any other error passes through unchanged.
//
// lx: SPEC 101
func unwrapGSODisabled(log *Logger, err error) error {
	var errGSO conn.ErrUDPGSODisabled
	if errors.As(err, &errGSO) {
		log.Verbosef("%v", err)
		return errGSO.RetryErr
	}
	return err
}
