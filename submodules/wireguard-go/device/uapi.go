/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/ipc"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) Unwrap() error {
	return s.err
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// IpcGetOperation implements the WireGuard configuration protocol "get" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcGetOperation(w io.Writer) error {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}
	keyf := func(prefix string, key *[32]byte) {
		buf.Grow(len(key)*2 + 2 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		const hex = "0123456789abcdef"
		for i := 0; i < len(key); i++ {
			buf.WriteByte(hex[key[i]>>4])
			buf.WriteByte(hex[key[i]&0xf])
		}
		buf.WriteByte('\n')
	}

	func() {
		// lock required resources

		device.net.RLock()
		defer device.net.RUnlock()

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		device.peers.RLock()
		defer device.peers.RUnlock()

		// serialize device related values

		if !device.staticIdentity.privateKey.IsZero() {
			keyf("private_key", (*[32]byte)(&device.staticIdentity.privateKey))
		}

		if device.net.port != 0 {
			sendf("listen_port=%d", device.net.port)
		}

		if device.net.fwmark != 0 {
			sendf("fwmark=%d", device.net.fwmark)
		}

		// lx: AmneziaWG obfuscation parameters (unset ones are omitted, so a
		// plain WireGuard device reports exactly what upstream would).

		if count := device.junk.count.Load(); count != 0 {
			sendf("jc=%d", count)
		}

		if junkMin := device.junk.min.Load(); junkMin != 0 {
			sendf("jmin=%d", junkMin)
		}

		if junkMax := device.junk.max.Load(); junkMax != 0 {
			sendf("jmax=%d", junkMax)
		}

		if padding := device.paddings.init.Load(); padding != 0 {
			sendf("s1=%d", padding)
		}

		if padding := device.paddings.response.Load(); padding != 0 {
			sendf("s2=%d", padding)
		}

		if padding := device.paddings.cookie.Load(); padding != 0 {
			sendf("s3=%d", padding)
		}

		if padding := device.paddings.transport.Load(); padding != 0 {
			sendf("s4=%d", padding)
		}

		if header := device.headers.init.Load(); !header.IsZero() {
			sendf("h1=%s", header.ToString())
		}

		if header := device.headers.response.Load(); !header.IsZero() {
			sendf("h2=%s", header.ToString())
		}

		if header := device.headers.cookie.Load(); !header.IsZero() {
			sendf("h3=%s", header.ToString())
		}

		if header := device.headers.transport.Load(); !header.IsZero() {
			sendf("h4=%s", header.ToString())
		}

		for i, ipacket := range device.ipackets {
			if ipacket != nil {
				sendf("i%d=%s", i+1, ipacket.Spec)
			}
		}

		// lx: AmneziaWG 3.x

		if key := device.headerProtection.key.Load(); key != nil {
			keyf("header_protection_key", (*[32]byte)(key))
		}

		if addition := device.contentPaddingAddition.Load(); !addition.IsZero() {
			sendf("content_padding_addition=%s", addition.ToString())
		}

		if timing := device.timings.rekeyAfterTimeSec.Load(); !timing.IsZero() {
			sendf("rekey_after_time=%s", timing.ToString())
		}
		if timing := device.timings.rekeyTimeoutSec.Load(); !timing.IsZero() {
			sendf("rekey_timeout=%s", timing.ToString())
		}
		if timing := device.timings.rejectAfterTimeSec.Load(); !timing.IsZero() {
			sendf("reject_after_time=%s", timing.ToString())
		}
		if timing := device.timings.keepaliveTimeoutSec.Load(); !timing.IsZero() {
			sendf("keepalive_timeout=%s", timing.ToString())
		}
		if attempts := device.timings.maxHandshakeAttempts.Load(); !attempts.IsZero() {
			sendf("max_handshake_attempts=%s", attempts.ToString())
		}
		if device.randomTrailers.Load() {
			sendf("random_trailers=1")
		}
		if device.disableCookies.Load() {
			sendf("disable_cookies=1")
		}

		for _, peer := range device.peers.keyMap {
			// Serialize peer state.
			peer.handshake.mutex.RLock()
			keyf("public_key", (*[32]byte)(&peer.handshake.remoteStatic))
			keyf("preshared_key", (*[32]byte)(&peer.handshake.presharedKey))
			peer.handshake.mutex.RUnlock()
			sendf("protocol_version=1")
			peer.endpoint.Lock()
			if peer.endpoint.val != nil {
				sendf("endpoint=%s", peer.endpoint.val.DstToString())
			}
			peer.endpoint.Unlock()

			nano := peer.lastHandshakeNano.Load()
			secs := nano / time.Second.Nanoseconds()
			nano %= time.Second.Nanoseconds()

			sendf("last_handshake_time_sec=%d", secs)
			sendf("last_handshake_time_nsec=%d", nano)
			sendf("tx_bytes=%d", peer.txBytes.Load())
			sendf("rx_bytes=%d", peer.rxBytes.Load())
			// lx: AWG 3.x — a range prints as "min-max", a single value / off as
			// the plain number WireGuard always printed.
			sendf("persistent_keepalive_interval=%s", peer.persistentKeepaliveInterval.Load().ToString())

			device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
				sendf("allowed_ip=%s", prefix.String())
				return true
			})
		}
	}()

	// send lines (does not require resource locks)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output: %w", err)
	}

	return nil
}

// IpcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcSetOperation(r io.Reader) (err error) {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			device.log.Errorf("%v", err)
		}
	}()

	ipcDev := new(ipcSetDevice)
	ipcDev.fromDevice(device)
	peer := new(ipcSetPeer)
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			err := ipcDev.mergeWithDevice(device)
			if err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to merge with device: %w", err)
			}
			peer.handlePostConfig()
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(
				ipc.IpcErrorProtocol,
				"failed to parse line %q",
				line,
			)
		}

		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			peer.handlePostConfig()
			// Load/create the peer we are now configuring.
			err := device.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = device.handleDeviceLine(ipcDev, key, value)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	err = ipcDev.mergeWithDevice(device)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to merge with device: %w", err)
	}
	peer.handlePostConfig()

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

func (device *Device) handleDeviceLine(ipcDev *ipcSetDevice, key, value string) error {
	switch key {
	case "private_key":
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
		device.log.Verbosef("UAPI: Updating private key")
		device.SetPrivateKey(sk)

	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
		}

		// update port and rebind
		device.log.Verbosef("UAPI: Updating listen port")

		device.net.Lock()
		device.net.port = uint16(port)
		device.net.Unlock()

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set listen_port: %w", err)
		}

	case "fwmark":
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark: %w", err)
		}

		device.log.Verbosef("UAPI: Updating fwmark")
		if err := device.BindSetMark(uint32(mark)); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to update fwmark: %w", err)
		}

	case "replace_peers":
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set replace_peers, invalid value: %v",
				value,
			)
		}
		device.log.Verbosef("UAPI: Removing all peers")
		device.RemoveAllPeers()

	// lx: AmneziaWG obfuscation keys (amneziawg-go uapi). S1–S4 and H1–H4 are
	// staged in ipcDev and applied together by mergeWithDevice, which checks
	// the cross-field invariants (non-overlapping headers, padding long
	// enough for header protection).

	case "jc":
		jc, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jc: %w", err)
		}
		device.log.Verbosef("UAPI: Updating junk count")
		device.junk.count.Store(uint32(jc))

	case "jmin":
		jmin, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jmin: %w", err)
		}
		device.log.Verbosef("UAPI: Updating junk min")
		device.junk.min.Store(uint32(jmin))

	case "jmax":
		jmax, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jmax: %w", err)
		}
		device.log.Verbosef("UAPI: Updating junk max")
		device.junk.max.Store(uint32(jmax))

	case "s1":
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s1: %w", err)
		}
		ipcDev.paddings.init = uint32(padding)

	case "s2":
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s2: %w", err)
		}
		ipcDev.paddings.response = uint32(padding)

	case "s3":
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s3: %w", err)
		}
		ipcDev.paddings.cookie = uint32(padding)

	case "s4":
		padding, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s4: %w", err)
		}
		ipcDev.paddings.transport = uint32(padding)

	case "h1":
		var header UintRange
		if err := header.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H1: %w", err)
		}
		ipcDev.headers.init = header

	case "h2":
		var header UintRange
		if err := header.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H2: %w", err)
		}
		ipcDev.headers.response = header

	case "h3":
		var header UintRange
		if err := header.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H3: %w", err)
		}
		ipcDev.headers.cookie = header

	case "h4":
		var header UintRange
		if err := header.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H4: %w", err)
		}
		ipcDev.headers.transport = header

	case "i1":
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I1: %w", err)
		}
		device.ipackets[0] = chain

	case "i2":
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I2: %w", err)
		}
		device.ipackets[1] = chain

	case "i3":
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I3: %w", err)
		}
		device.ipackets[2] = chain

	case "i4":
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I4: %w", err)
		}
		device.ipackets[3] = chain

	case "i5":
		chain, err := newObfChain(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I5: %w", err)
		}
		device.ipackets[4] = chain

	// lx: AmneziaWG 3.x keys (amneziawg-go v3 uapi).

	case "header_protection_key":
		var key HeaderCipherKey
		err := key.FromHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set header_protection_key: %w", err)
		}
		ipcDev.headerProtectionKey = key

	case "content_padding_addition":
		var addition UintRange
		if err := addition.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse content_padding_addition: %w", err)
		}
		device.log.Verbosef("UAPI: Updating content padding addition")
		device.contentPaddingAddition.Store(addition)

	case "rekey_after_time":
		var timing UintRange
		if err := timing.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse rekey_after_time: %w", err)
		}
		device.log.Verbosef("UAPI: Updating rekey after time")
		device.timings.rekeyAfterTimeSec.Store(timing)

	case "rekey_timeout":
		var timing UintRange
		if err := timing.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse rekey_timeout: %w", err)
		}
		device.log.Verbosef("UAPI: Updating rekey timeout")
		device.timings.rekeyTimeoutSec.Store(timing)

	case "reject_after_time":
		var timing UintRange
		if err := timing.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse reject_after_time: %w", err)
		}
		device.log.Verbosef("UAPI: Updating reject after time")
		device.timings.rejectAfterTimeSec.Store(timing)

	case "keepalive_timeout":
		var timing UintRange
		if err := timing.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse keepalive_timeout: %w", err)
		}
		device.log.Verbosef("UAPI: Updating keepalive timeout")
		device.timings.keepaliveTimeoutSec.Store(timing)

	case "max_handshake_attempts":
		var attempts UintRange
		if err := attempts.FromString(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse max_handshake_attempts: %w", err)
		}
		device.log.Verbosef("UAPI: Updating max handshake attempts")
		device.timings.maxHandshakeAttempts.Store(attempts)

	case "random_trailers":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse random_trailers: %w", err)
		}
		device.log.Verbosef("UAPI: Updating random trailers")
		device.randomTrailers.Store(val)

	case "disable_cookies":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse disable_cookies: %w", err)
		}
		device.log.Verbosef("UAPI: Updating disable cookies")
		device.disableCookies.Store(val)

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*Peer        // Peer is the current peer being operated on
	dummy   bool // dummy reports whether this peer is a temporary, placeholder peer
	created bool // new reports whether this is a newly created peer
	pkaOn   bool // pkaOn reports whether the peer had the persistent keepalive turn on
}

func (peer *ipcSetPeer) handlePostConfig() {
	if peer.Peer == nil || peer.dummy {
		return
	}
	if peer.created {
		peer.endpoint.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	if peer.device.isUp() {
		peer.Start()
		if peer.pkaOn {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
}

func (device *Device) handlePublicKeyLine(
	peer *ipcSetPeer,
	value string,
) error {
	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}

	// Ignore peer with the same public key as this device.
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
	}

	peer.created = peer.Peer == nil
	if peer.created {
		peer.Peer, err = device.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer: %w", err)
		}
		device.log.Verbosef("%v - UAPI: Created", peer.Peer)
	}
	return nil
}

func (device *Device) handlePeerLine(
	peer *ipcSetPeer,
	key, value string,
) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set update only, invalid value: %v",
				value,
			)
		}
		if peer.created && !peer.dummy {
			device.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !peer.dummy {
			device.log.Verbosef("%v - UAPI: Removing", peer.Peer)
			device.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true

	case "preshared_key":
		device.log.Verbosef("%v - UAPI: Updating preshared key", peer.Peer)

		peer.handshake.mutex.Lock()
		err := peer.handshake.presharedKey.FromHex(value)
		peer.handshake.mutex.Unlock()

		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}

	case "endpoint":
		device.log.Verbosef("%v - UAPI: Updating endpoint", peer.Peer)
		endpoint, err := device.net.bind.ParseEndpoint(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v: %w", value, err)
		}
		peer.endpoint.Lock()
		defer peer.endpoint.Unlock()
		peer.endpoint.val = endpoint

	case "persistent_keepalive_interval":
		device.log.Verbosef("%v - UAPI: Updating persistent keepalive interval", peer.Peer)

		// lx: AWG 3.x — "N" (WireGuard) or an inclusive "min-max" range of
		// seconds; the interval is re-picked from the range at every arming.
		var keepalive UintRange
		if err := keepalive.FromString(value); err != nil {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to set persistent keepalive interval: %w",
				err,
			)
		}
		if keepalive.Hi() > 65535 {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set persistent keepalive interval: value out of range")
		}

		old := peer.persistentKeepaliveInterval.Swap(keepalive)

		// Send immediate keepalive if we're turning it on and before it wasn't on.
		peer.pkaOn = old.IsZero() && !keepalive.IsZero()

	case "replace_allowed_ips":
		device.log.Verbosef("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(
				ipc.IpcErrorInvalid,
				"failed to replace allowedips, invalid value: %v",
				value,
			)
		}
		if peer.dummy {
			return nil
		}
		device.allowedips.RemoveByPeer(peer.Peer)

	case "allowed_ip":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		device.log.Verbosef("%v - UAPI: %s allowedip", peer.Peer, verb)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
		}
		if peer.dummy {
			return nil
		}
		if add {
			device.allowedips.Insert(prefix, peer.Peer)
		} else {
			device.allowedips.Remove(prefix, peer.Peer)
		}

	case "protocol_version":
		if value != "1" {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI peer key: %v", key)
	}

	return nil
}

func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(strings.NewReader(uapiConf))
}

func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(buffered.Reader)
		case "get=1\n":
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(
					ipc.IpcErrorInvalid,
					"trailing character in UAPI get: %q",
					nextByte,
				)
				break
			}
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errorf("invalid UAPI operation: %v", op)
			return
		}

		// write status
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
		}
		if status != nil {
			device.log.Errorf("%v", status)
			fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		buffered.Flush()
	}
}

// lx:begin awg3 (AmneziaWG — staged device parameters, ported from amneziawg-go v3)

// ipcSetDevice stages the AmneziaWG parameters whose validity depends on each
// other — magic headers (must not overlap) and paddings (must be long enough
// for the header-protection nonce when a key is set) — for one IpcSet, seeded
// from the device so a partial update is checked against the values that stay.
type ipcSetDevice struct {
	headers struct {
		init      UintRange
		response  UintRange
		cookie    UintRange
		transport UintRange
	}
	paddings struct {
		init      uint32
		response  uint32
		cookie    uint32
		transport uint32
	}
	headerProtectionKey HeaderCipherKey
}

func (d *ipcSetDevice) fromDevice(device *Device) {
	d.headers.init = device.headers.init.Load()
	d.headers.response = device.headers.response.Load()
	d.headers.cookie = device.headers.cookie.Load()
	d.headers.transport = device.headers.transport.Load()

	d.paddings.init = device.paddings.init.Load()
	d.paddings.response = device.paddings.response.Load()
	d.paddings.cookie = device.paddings.cookie.Load()
	d.paddings.transport = device.paddings.transport.Load()

	if key := device.headerProtection.key.Load(); key != nil {
		d.headerProtectionKey = *key
	}
}

func (d *ipcSetDevice) mergeWithDevice(device *Device) error {
	headers := []UintRange{d.headers.init, d.headers.response, d.headers.cookie, d.headers.transport}
	for i := 0; i < len(headers); i++ {
		for j := i + 1; j < len(headers); j++ {
			if headers[i].Overlap(headers[j]) {
				return errors.New("headers must not overlap")
			}
		}
	}

	if !d.headerProtectionKey.IsZero() {
		paddings := []uint32{d.paddings.init, d.paddings.response, d.paddings.cookie, d.paddings.transport}
		for i, padding := range paddings {
			if padding < HeaderCipherNonceSize {
				return fmt.Errorf("s%d must be at least %d bytes to use header_protection_key (it carries the header cipher nonce)", i+1, HeaderCipherNonceSize)
			}
		}
	}

	device.log.Verbosef("UAPI: Updating h1-h4 magic headers")
	device.headers.init.Store(d.headers.init)
	device.headers.response.Store(d.headers.response)
	device.headers.cookie.Store(d.headers.cookie)
	device.headers.transport.Store(d.headers.transport)

	device.log.Verbosef("UAPI: Updating s1-s4 paddings")
	device.paddings.init.Store(d.paddings.init)
	device.paddings.response.Store(d.paddings.response)
	device.paddings.cookie.Store(d.paddings.cookie)
	device.paddings.transport.Store(d.paddings.transport)

	device.log.Verbosef("UAPI: Updating header protection key")
	if d.headerProtectionKey.IsZero() {
		device.headerProtection.key.Store(nil)
	} else {
		key := d.headerProtectionKey
		device.headerProtection.key.Store(&key)
	}

	return nil
}

// lx:end awg3
