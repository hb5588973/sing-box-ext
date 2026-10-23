/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoisePresharedKey [NoisePresharedKeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

func (key NoisePrivateKey) IsZero() bool {
	var zero NoisePrivateKey
	return key.Equals(zero)
}

func (key NoisePrivateKey) Equals(tar NoisePrivateKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoisePrivateKey) FromHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	key.clamp()
	return
}

func (key *NoisePrivateKey) FromMaybeZeroHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	if key.IsZero() {
		return
	}
	key.clamp()
	return
}

func (key *NoisePublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoisePublicKey) IsZero() bool {
	var zero NoisePublicKey
	return key.Equals(zero)
}

func (key NoisePublicKey) Equals(tar NoisePublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoisePresharedKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

// lx:begin awg3 (AmneziaWG 3.x — ported from amneziawg-go v3 device/noise-types.go)

const (
	// HeaderCipherKeySize is the size of the AWG 3.x header-protection key
	// (uapi header_protection_key, `awg genkey` output).
	HeaderCipherKeySize = 32
	// HeaderCipherNonceSize is the ChaCha20 nonce taken from the first bytes of
	// every datagram — the S1–S4 random padding — which is why the uapi requires
	// each of S1–S4 to be at least this long whenever the key is set.
	HeaderCipherNonceSize = 12
)

// HeaderCipherKey is the AWG 3.x header-protection key. A zero key means
// header protection is off.
type HeaderCipherKey [HeaderCipherKeySize]byte

func (key HeaderCipherKey) IsZero() bool {
	var zero HeaderCipherKey
	return key.Equals(zero)
}

func (key HeaderCipherKey) Equals(tar HeaderCipherKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *HeaderCipherKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

// UintRange is an inclusive [lo, hi] uint32 range packed into one uint64
// (hi in the upper half) so it can be stored atomically. It replaces the
// AWG 2.0 magicHeader for H1–H4 and carries every AWG 3.x ranged parameter
// (content padding addition, timings, persistent keepalive). The zero value
// means "unset".
type UintRange uint64

func (r *UintRange) FromUint32(lo, hi uint32) {
	*r = UintRange(uint64(hi)<<32 | uint64(lo))
}

// FromString parses "N" (lo == hi) or "N-M" (N <= M), both uint32.
func (r *UintRange) FromString(str string) error {
	parts := strings.Split(str, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return errors.New("wrong format")
	}

	lo, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return err
	}

	hi := lo
	if len(parts) > 1 {
		hi, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return err
		}
	}

	if hi < lo {
		return errors.New("wrong range specified")
	}

	r.FromUint32(uint32(lo), uint32(hi))
	return nil
}

func (r UintRange) Contains(num uint32) bool {
	lo, hi := uint32(r), uint32(r>>32)
	return lo <= num && num <= hi
}

func (r UintRange) IsZero() bool {
	return r == 0
}

// PickOne returns a uniformly random value in [lo, hi].
func (r UintRange) PickOne() uint32 {
	lo, hi := uint32(r), uint32(r>>32)
	if lo == hi {
		return lo
	}
	// Widen before the arithmetic: hi-lo+1 wraps to 0 in uint32 for the full
	// 0..2^32-1 range, and fastrandn(0) would then always yield lo (the
	// SPEC 025 guard carried over from magicHeader.Generate).
	span := uint64(hi) - uint64(lo) + 1
	if span > math.MaxUint32 {
		return rand.Uint32()
	}
	return lo + fastrandn(uint32(span))
}

func (r UintRange) ToString() string {
	lo, hi := uint32(r), uint32(r>>32)

	if lo == hi {
		return fmt.Sprintf("%d", lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

func (r UintRange) Overlap(right UintRange) bool {
	lLo, lHi := uint32(r), uint32(r>>32)
	rLo, rHi := uint32(right), uint32(right>>32)

	return lLo <= rHi && rLo <= lHi
}

func (r UintRange) Lo() uint32 {
	return uint32(r)
}

func (r UintRange) Hi() uint32 {
	return uint32(r >> 32)
}

// AtomicUintRange is a UintRange readable and writable without locks — the
// obfuscation parameters are read on every packet and rewritten by IpcSet.
type AtomicUintRange struct {
	v atomic.Uint64
}

func (a *AtomicUintRange) Load() UintRange {
	return UintRange(a.v.Load())
}

func (a *AtomicUintRange) Store(r UintRange) {
	a.v.Store(uint64(r))
}

func (a *AtomicUintRange) Swap(r UintRange) UintRange {
	return UintRange(a.v.Swap(uint64(r)))
}

// lx:end awg3
