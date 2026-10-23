/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type QueueHandshakeElement struct {
	msgType  uint32
	packet   []byte
	endpoint conn.Endpoint
	buffer   *[MaxMessageSize]byte
}

type QueueInboundElement struct {
	buffer   *[MaxMessageSize]byte
	packet   []byte
	counter  uint64
	keypair  *Keypair
	endpoint conn.Endpoint
	// lx: AmneziaWG — the transport padding (s4) this datagram arrived with;
	// packet is buffer[padding:...], the padding is left in place.
	padding uint32
}

type QueueInboundElementsContainer struct {
	// filling is a one-shot barrier signaling decryption→receive
	// handoff. RoutineReceiveIncoming calls Add(1) before sending the
	// container down the decryption and inbound queues; RoutineDecryption
	// calls Done after decrypting; RoutineSequentialReceiver calls Wait
	// before reading the decrypted packets.
	filling sync.WaitGroup
	elems   []*QueueInboundElement
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.endpoint = nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > peer.device.keyRefreshTimeoutReceiving() {
		peer.timers.sentLastMinuteHandshake.Store(true)
		peer.SendHandshakeInitiation(false)
	}
}

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (device *Device) RoutineReceiveIncoming(
	maxBatchSize int,
	recv conn.ReceiveFunc,
) {
	recvName := recv.PrettyName()
	defer func() {
		device.log.Verbosef("Routine: receive incoming %s - stopped", recvName)
		device.queue.decryption.wg.Done()
		device.queue.handshake.wg.Done()
		device.net.stopping.Done()
	}()

	device.log.Verbosef("Routine: receive incoming %s - started", recvName)

	// receive datagrams until conn is closed

	var (
		bufsArrs    = make([]*[MaxMessageSize]byte, maxBatchSize)
		bufs        = make([][]byte, maxBatchSize)
		err         error
		sizes       = make([]int, maxBatchSize)
		count       int
		endpoints   = make([]conn.Endpoint, maxBatchSize)
		deathSpiral int
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize)
		// lx: keystream bytes 0..8 of the header cipher — enough to unmask the
		// type word and the receiver index (SPEC 081) before classification.
		headerHashBuf [8]byte
	)

	for i := range bufsArrs {
		bufsArrs[i] = device.GetMessageBuffer()
		bufs[i] = bufsArrs[i][:]
	}

	defer func() {
		for i := 0; i < maxBatchSize; i++ {
			if bufsArrs[i] != nil {
				device.PutMessageBuffer(bufsArrs[i])
			}
		}
	}()

	for {
		count, err = recv(bufs, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			device.log.Verbosef("Failed to receive %s packet: %v", recvName, err)
			if errors.Is(err, conn.ErrRebindRequired) {
				device.scheduleBindUpdate()
				return
			}
			if neterr, ok := err.(net.Error); ok && !neterr.Temporary() {
				return
			}
			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		deathSpiral = 0

		// handle each packet in the batch
		for i, size := range sizes[:count] {
			if size < MinMessageSize {
				continue
			}

			// check size of packet
			packet := bufsArrs[i][:size]

			// lx: AmneziaWG 3.x header protection — the keystream for this
			// datagram is salted with its first 12 bytes (the S1–S4 padding);
			// its first 8 bytes unmask the type word and the receiver index
			// wherever they sit.
			cip, err := device.HeaderProtectionCipher(packet)
			if err != nil {
				device.log.Errorf("Failed to initialize header cipher: %v", err)
				continue
			}

			headerHash := headerHashBuf[:]
			clear(headerHash)
			if cip != nil {
				cip.XORKeyStream(headerHash, headerHash)
			}

			// lx: SPEC 081 — a datagram that carries one of our live receiver
			// indices behind a transport type word is a data packet, whatever
			// its size; only then fall back to the reference order, which lets a
			// handshake kind claim a data datagram by its (random) type word.
			var msgSize int
			var msgType, padding uint32
			entry, transportPadding, byIndex := device.classifyTransportByIndex(packet, headerHash)
			if byIndex {
				msgSize, msgType, padding = MessageTransportSize, MessageTransportType, transportPadding
			} else {
				// get message padding and type based on information from S1-S4 and H1-H4
				msgSize, msgType, padding = device.DeterminePacketTypeAndPadding(packet, headerHash[:4])
			}
			if msgType == MessageUnknownType {
				device.log.Verbosef("Received message with unknown type")
				continue
			}

			// strip the padding (left in place in the buffer) and, for the
			// fixed-size handshake messages, the AWG 3.x random trailer
			packet = packet[padding:]
			if msgType != MessageTransportType {
				packet = packet[:msgSize]
			}

			// unmask the first 8 bytes (type + sender/receiver index) with the
			// keystream already drawn; the cipher continues from byte 8 below
			if cip != nil {
				applyHash(packet[:8], packet[:8], headerHash)
			}

			switch msgType {

			// check if transport

			case MessageTransportType:

				// check size

				if len(packet) < MessageTransportSize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[8:MessageTransportHeaderSize], packet[8:MessageTransportHeaderSize])
				}

				// lookup key pair

				value := entry
				if !byIndex {
					receiver := binary.LittleEndian.Uint32(
						packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
					)
					value = device.indexTable.Lookup(receiver)
				}
				keypair := value.keypair
				if keypair == nil {
					continue
				}

				// check keypair expiry

				if keypair.created.Add(device.keychainExpireTime()).Before(time.Now()) {
					continue
				}

				// create work element
				peer := value.peer
				elem := device.GetInboundElement()
				elem.packet = packet
				elem.buffer = bufsArrs[i]
				elem.keypair = keypair
				elem.endpoint = endpoints[i]
				elem.counter = 0
				elem.padding = padding

				elemsForPeer, ok := elemsByPeer[peer]
				if !ok {
					elemsForPeer = device.GetInboundElementsContainer()
					elemsByPeer[peer] = elemsForPeer
				}
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
				continue

			// otherwise it is a fixed size & handshake related packet

			case MessageInitiationType:
				if len(packet) != MessageInitiationSize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[8:MessageInitiationSize], packet[8:MessageInitiationSize])
				}

			case MessageResponseType:
				if len(packet) != MessageResponseSize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[8:MessageResponseSize], packet[8:MessageResponseSize])
				}

			case MessageCookieReplyType:
				if len(packet) != MessageCookieReplySize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[8:MessageCookieReplySize], packet[8:MessageCookieReplySize])
				}

			default:
				device.log.Verbosef("Received message with unknown type")
				continue
			}

			select {
			case device.queue.handshake.c <- QueueHandshakeElement{
				msgType:  msgType,
				buffer:   bufsArrs[i],
				packet:   packet,
				endpoint: endpoints[i],
			}:
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
			default:
			}
		}
		for peer, elemsContainer := range elemsByPeer {
			if peer.isRunning.Load() {
				elemsContainer.filling.Add(1)
				peer.queue.inbound.c <- elemsContainer
				device.queue.decryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					device.PutMessageBuffer(elem.buffer)
					device.PutInboundElement(elem)
				}
				device.PutInboundElementsContainer(elemsContainer)
			}
			delete(elemsByPeer, peer)
		}
	}
}

func (device *Device) RoutineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: decryption worker %d - stopped", id)
	device.log.Verbosef("Routine: decryption worker %d - started", id)

	for elemsContainer := range device.queue.decryption.c {
		for _, elem := range elemsContainer.elems {
			// split message into fields
			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer
			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)
			elem.packet, err = elem.keypair.receive.Open(
				content[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				elem.packet = nil
			}
		}
		elemsContainer.filling.Done()
	}
}

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake(id int) {
	defer func() {
		device.log.Verbosef("Routine: handshake worker %d - stopped", id)
		device.queue.encryption.wg.Done()
	}()
	device.log.Verbosef("Routine: handshake worker %d - started", id)

	for elem := range device.queue.handshake.c {
		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			err := reply.unmarshal(elem.packet)
			if err != nil {
				device.log.Verbosef("Failed to decode cookie reply")
				goto skip
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Load() {
				device.log.Verbosef(
					"Receiving cookie response from %s",
					elem.endpoint.DstToString(),
				)
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					device.log.Verbosef(
						"Could not decrypt invalid cookie response",
					)
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(elem.packet) {
				device.log.Verbosef("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			// lx: AmneziaWG 3.x disable_cookies — never answer with a cookie
			// reply, and skip the under-load mac2/ratelimit gate that would
			// demand one (upstream b5928ef).
			if !device.disableCookies.Load() && device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(elem.packet, elem.endpoint.DstToBytes()) {
					device.SendHandshakeCookie(&elem)
					goto skip
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			device.log.Errorf("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:
			// unmarshal
			var msg MessageInitiation
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode initiation message")
				goto skip
			}

			// have to reassign msgType for ranged msgType to work
			msg.Type = elem.msgType

			peer := device.ConsumeMessageInitiation(&msg, elem.endpoint)
			if peer == nil {
				device.log.Verbosef("Received invalid initiation message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake initiation", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			peer.SendHandshakeResponse()

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode response message")
				goto skip
			}

			// have to reassign msgType for ranged msgType to work
			msg.Type = elem.msgType

			// consume response

			peer := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid response message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake response", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()
			if err != nil {
				device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendPriorityMessage()
			peer.SendKeepalive()
		}
	skip:
		device.PutMessageBuffer(elem.buffer)
	}
}

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	device := peer.device
	defer func() {
		device.log.Verbosef("%v - Routine: sequential receiver - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential receiver - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)

	for elemsContainer := range peer.queue.inbound.c {
		if elemsContainer == nil {
			return
		}
		peer.processInboundContainer(elemsContainer, bufs[:0])
	}
}

// processInboundContainer waits for the decryption routine to finish
// filling elemsContainer, then writes the valid packets to the TUN
// device and returns the container to the pool.
//
// scratch is a length-0 slice used to assemble the per-packet buffers
// passed to tun.device.Write; its backing array is reused across calls.
func (peer *Peer) processInboundContainer(elemsContainer *QueueInboundElementsContainer, scratch [][]byte) {
	// Invariants from RoutineSequentialReceiver; all should be unreachable.
	if len(scratch) != 0 || cap(scratch) == 0 {
		panic(fmt.Sprintf("processInboundContainer: scratch must be empty with non-zero cap; got len=%d cap=%d",
			len(scratch), cap(scratch)))
	}
	if cap(scratch) < len(elemsContainer.elems) {
		panic(fmt.Sprintf("processInboundContainer: scratch cap %d < elems %d",
			cap(scratch), len(elemsContainer.elems)))
	}

	device := peer.device
	defer device.PutInboundElementsContainer(elemsContainer)

	// Wait for RoutineDecryption to finish filling the container. After
	// Wait returns we have happens-before with that goroutine and are the
	// sole owner of the container until Put hands it back to the pool.
	elemsContainer.filling.Wait()
	elems := elemsContainer.elems

	validTailPacket := -1
	dataPacketReceived := false
	rxBytesLen := uint64(0)
	for i, elem := range elems {
		if elem.packet == nil {
			// decryption failed
			continue
		}

		if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
			continue
		}

		validTailPacket = i
		if peer.ReceivedWithKeypair(elem.keypair) {
			peer.SetEndpointFromPacket(elem.endpoint)
			peer.timersHandshakeComplete()
			peer.SendPriorityMessage()
			peer.SendStagedPackets()
		}
		if ep, ok := elem.endpoint.(conn.PeerAwareEndpoint); ok {
			ep.FromPeer(peer.handshake.remoteStatic)
		}
		rxBytesLen += uint64(len(elem.packet) + MinMessageSize)

		// lx: AmneziaWG 3.x — a datagram the peer got through to us is a
		// size this path carries; widen the UDP window accordingly.
		peer.noteUDPWindow(elem.padding + MessageTransportSize + uint32(len(elem.packet)))

		// lx: AmneziaWG 3.x — a keepalive may carry content padding / a
		// trailer, all zeros; an IP packet never starts with a zero byte
		// (version nibble), so a leading zero is a padded keepalive.
		if len(elem.packet) == 0 || elem.packet[0] == 0 {
			device.log.Verbosef("%v - Receiving keepalive packet", peer)
			continue
		}
		dataPacketReceived = true

		switch elem.packet[0] >> 4 {
		case 4:
			if len(elem.packet) < ipv4.HeaderLen {
				continue
			}
			field := elem.packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
			length := binary.BigEndian.Uint16(field)
			if int(length) > len(elem.packet) || int(length) < ipv4.HeaderLen {
				continue
			}
			elem.packet = elem.packet[:length]
			src := elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
			srcAddr, _ := netip.AddrFromSlice(src)
			if !peer.AllowedPeerSourceIP(srcAddr) {
				device.log.Verbosef("IPv4 packet with disallowed source address from %v", peer)
				continue
			}

		case 6:
			if len(elem.packet) < ipv6.HeaderLen {
				continue
			}
			field := elem.packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
			length := binary.BigEndian.Uint16(field)
			length += ipv6.HeaderLen
			if int(length) > len(elem.packet) {
				continue
			}
			elem.packet = elem.packet[:length]
			src := elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
			srcAddr, _ := netip.AddrFromSlice(src)
			if !peer.AllowedPeerSourceIP(srcAddr) {
				device.log.Verbosef("IPv6 packet with disallowed source address from %v", peer)
				continue
			}

		default:
			device.log.Verbosef("Packet with invalid IP version from %v", peer)
			continue
		}

		// the plaintext sits behind the (untouched) padding and the header
		start := int(elem.padding)
		scratch = append(scratch, elem.buffer[start:start+MessageTransportOffsetContent+len(elem.packet)])
	}

	peer.rxBytes.Add(rxBytesLen)
	if validTailPacket >= 0 {
		peer.SetEndpointFromPacket(elems[validTailPacket].endpoint)
		peer.keepKeyFreshReceiving()
		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketReceived()
	}
	if dataPacketReceived {
		peer.timersDataReceived()
	}
	if len(scratch) > 0 {
		_, err := device.tun.device.Write(scratch, MessageTransportOffsetContent)
		if err != nil && !device.isClosed() {
			device.log.Errorf("Failed to write packets to TUN device: %v", err)
		}
	}
	for _, elem := range elems {
		device.PutMessageBuffer(elem.buffer)
		device.PutInboundElement(elem)
	}
}

// lx:begin awg3 (AmneziaWG — ported from amneziawg-go v3 device/receive.go)

func applyHash(dst, src, hash []byte) {
	for i := range len(dst) {
		dst[i] = src[i] ^ hash[i]
	}
}

// classifyTransportByIndex is the lx transport-first candidate (SPEC 081). A
// data packet always carries one of our live receiver indices — a 32-bit value
// a foreign datagram cannot hold by accident — so a datagram whose unmasked
// type word is in H4 and whose unmasked receiver index resolves to a live
// keypair is a transport message, whatever its size. The reference order
// (DeterminePacketTypeAndPadding) tries the handshake kinds first, by size and
// type word alone, and with a wide H range claims real data packets: every one
// of exactly S1+148 / S2+92 / S3+64 bytes (AWG2), and under random_trailers
// every one longer than that (AWG 3.1). headerHash is the header-cipher
// keystream for bytes 0..8 (zeros when header protection is off). Returns the
// index-table entry, the transport padding and whether it matched; on a miss
// the caller falls back to the reference order, so nothing it accepted before
// is refused now.
func (device *Device) classifyTransportByIndex(packet []byte, headerHash []byte) (IndexTableEntry, uint32, bool) {
	padding := device.paddings.transport.Load()
	if len(packet) < int(padding)+MessageTransportSize {
		return IndexTableEntry{}, 0, false
	}
	var header [8]byte
	applyHash(header[:], packet[padding:padding+8], headerHash[:8])
	if !device.headers.transport.Load().Contains(binary.LittleEndian.Uint32(header[:4])) {
		return IndexTableEntry{}, 0, false
	}
	entry := device.indexTable.Lookup(binary.LittleEndian.Uint32(header[4:8]))
	if entry.keypair == nil {
		return IndexTableEntry{}, 0, false
	}
	return entry, padding, true
}

// DeterminePacketTypeAndPadding classifies a datagram by the AmneziaWG
// parameters in the reference (amneziawg-go) order: for each message kind, the
// type word is read at that kind's padding offset (S1–S4), unmasked with
// typeHash (the AWG 3.x header protection keystream, all zeros when off) and
// matched against the kind's magic range (H1–H4). Fixed-size messages must
// match their size exactly, or — with random_trailers — exceed it (the trailer
// is discarded by the caller). Returns the message size (without
// padding/trailer), its canonical type and the padding length;
// MessageUnknownType when nothing matched. Runs after classifyTransportByIndex
// missed (SPEC 081).
func (device *Device) DeterminePacketTypeAndPadding(packet []byte, typeHash []byte) (int, uint32, uint32) {
	var headerBytes [4]byte
	var padding uint32
	var header UintRange
	var expectedSize int

	size := len(packet)
	randomTrailers := device.randomTrailers.Load()

	padding = device.paddings.init.Load()
	header = device.headers.init.Load()
	expectedSize = int(padding) + MessageInitiationSize

	if size == expectedSize || randomTrailers && size > expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageInitiationSize, MessageInitiationType, padding
		}
	}

	padding = device.paddings.response.Load()
	header = device.headers.response.Load()
	expectedSize = int(padding) + MessageResponseSize

	if size == expectedSize || randomTrailers && size > expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageResponseSize, MessageResponseType, padding
		}
	}

	padding = device.paddings.cookie.Load()
	header = device.headers.cookie.Load()
	expectedSize = int(padding) + MessageCookieReplySize

	if size == expectedSize || randomTrailers && size > expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageCookieReplySize, MessageCookieReplyType, padding
		}
	}

	padding = device.paddings.transport.Load()
	header = device.headers.transport.Load()
	expectedSize = int(padding) + MessageTransportSize

	if size >= expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageTransportSize, MessageTransportType, padding
		}
	}

	return 0, MessageUnknownType, 0
}

// lx:end awg3
