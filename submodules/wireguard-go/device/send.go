/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QueueOutboundElement struct {
	buffer []byte // sing-allocated buffer holding the packet data
	// packet is always a slice of "buffer". The starting offset in buffer
	// is either:
	//  a) plaintextOffset() = MessageEncapsulatingTransportSize+padding+MessageTransportHeaderSize (plaintext)
	//  b) 0 (post-encryption)
	packet  []byte
	nonce   uint64   // nonce for encryption
	keypair *Keypair // keypair for encryption
	peer    *Peer    // related peer
	// lx: AmneziaWG — the transport padding (uapi s4) this element carries in
	// front of its transport header. Captured when the element is created so
	// the element stays self-consistent if the device is reconfigured while it
	// is in flight. Its first 12 bytes double as the AWG 3.x header-protection
	// nonce.
	padding uint32
	// lx: AmneziaWG 3.x — with content padding / random trailers a keepalive
	// is no longer the only 32-byte transport message, so it is flagged.
	isKeepalive bool
}

type QueueOutboundElementsContainer struct {
	// filling is a one-shot barrier signaling encryption→send handoff.
	// SendStagedPackets calls Add(1) before sending the container down
	// the encryption and outbound queues; RoutineEncryption calls Done
	// after encrypting; RoutineSequentialSender calls Wait before
	// reading the encrypted packets.
	filling sync.WaitGroup
	elems   []*QueueOutboundElement
}

func (device *Device) NewOutboundElement() *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetOutboundBuffer(MaxMessageSize)
	elem.nonce = 0
	elem.padding = device.paddings.transport.Load()
	elem.isKeepalive = false
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// plaintextOffset is where this element's plaintext starts in buffer: behind
// the (sagernet) encapsulation headroom, the AWG transport padding and the
// transport header, all of which RoutineEncryption fills in place.
func (elem *QueueOutboundElement) plaintextOffset() int {
	return MessageEncapsulatingTransportSize + int(elem.padding) + MessageTransportHeaderSize
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *Peer) SendKeepalive() {
	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.device.NewOutboundElement()
		elem.isKeepalive = true
		offset := elem.plaintextOffset()
		elem.packet = elem.buffer[offset:offset]
		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)
		select {
		case peer.queue.staged <- elemsContainer:
			peer.stagedPackets.Add(1)
			peer.device.log.Verbosef("%v - Sending keepalive packet", peer)
		default:
			peer.device.PutOutboundBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}
	peer.SendStagedPackets()
}

// SendPriorityMessage invokes the [PeerPriorityMessageFunc] callback if one is
// set, and queues the returned message for encryption and transmission if the
// current keypair is valid.
func (peer *Peer) SendPriorityMessage() {
	f := peer.device.priorityMsgFn.Load()
	if f == nil {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || time.Since(keypair.created) >= peer.device.keychainExpireTime() {
		// SendStagedPackets initializes a handshake when the keypair is invalid,
		// but we explicitly avoid that here. A priority message is only intended
		// to flow around symmetric session establishment, but it should never
		// trigger a new session. Reaching this branch due to nonce exhaustion
		// or keypair expiration is highly unlikely considering where
		// SendPriorityMessage is called (at current keypair establishment).
		return
	}

	// get plaintext message to send
	msg := (*f)(peer.handshake.remoteStatic)
	if len(msg) == 0 {
		return
	}
	if len(msg) > MaxPriorityMessageContentSize {
		peer.device.log.Verbosef("%v - Failed to queue priority message due to size", peer)
		return
	}

	// get pooled elements
	elem := peer.device.NewOutboundElement()
	elemsContainer := peer.device.GetOutboundElementsContainer()
	elemsContainer.elems = append(elemsContainer.elems, elem)
	packetQueued := false
	defer func() {
		if !packetQueued {
			peer.device.PutOutboundBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}()

	// initialize outbound element
	offset := elem.plaintextOffset()
	n := copy(elem.buffer[offset:], msg)
	elem.packet = elem.buffer[offset : offset+n]
	elem.peer = peer
	elem.nonce = keypair.sendNonce.Add(1) - 1
	if elem.nonce >= RejectAfterMessages {
		keypair.sendNonce.Store(RejectAfterMessages)
		return
	}
	elem.keypair = keypair

	// add to parallel and sequential queue
	if peer.isRunning.Load() {
		elemsContainer.filling.Add(1)
		peer.queuedOutboundPackets.Add(1)
		peer.queue.outbound.c <- elemsContainer
		peer.device.queue.encryption.c <- elemsContainer
		packetQueued = true
	}
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
		peer.timers.maxHandshakeAttempts.Store(peer.device.maxHandshakeAttempts())
	}

	timeout := peer.device.rekeyMinTimeout()

	peer.handshake.mutex.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < timeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < timeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake initiation", peer)

	candidates := peer.resolveEndpoints()

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create initiation message: %v", peer, err)
		return err
	}

	var sendBuffer [][]byte

	// lx: AmneziaWG — per-handshake decoys (sing-box-lx SPEC 009), then the
	// static CPS decoys (i1..i5), then Jc junk datagrams precede the initiation.
	if f := peer.device.decoyPackets.Load(); f != nil {
		for _, decoy := range (*f)() {
			if len(decoy) == 0 {
				continue
			}
			buf := make([]byte, MessageEncapsulatingTransportSize+len(decoy))
			copy(buf[MessageEncapsulatingTransportSize:], decoy)
			sendBuffer = append(sendBuffer, buf)
		}
	}
	for _, ipacket := range peer.device.ipackets {
		if ipacket != nil {
			buf := make([]byte, MessageEncapsulatingTransportSize+ipacket.ObfuscatedLen(0))
			ipacket.Obfuscate(buf[MessageEncapsulatingTransportSize:], nil)
			sendBuffer = append(sendBuffer, buf)
		}
	}

	sendBuffer = append(sendBuffer, peer.device.JunkPackets()...)

	// lx: AmneziaWG datagram layout: [S1 random padding][initiation][random
	// trailer]. The padding's first 12 bytes are the header-protection nonce.
	padding := int(peer.device.paddings.init.Load())
	trailerLen := max(peer.randomTrailer(padding+MessageInitiationSize), 0)

	sendBuf := make([]byte, MessageEncapsulatingTransportSize+padding+MessageInitiationSize+trailerLen)
	buf := sendBuf[MessageEncapsulatingTransportSize:]

	crypt := buf[:padding]
	rand.Read(crypt)

	packet := buf[padding : padding+MessageInitiationSize]
	if err := msg.marshal(packet); err != nil {
		peer.device.log.Errorf("%v - Failed to marshal initiation message: %v", peer, err)
		return err
	}
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	cip, err := peer.device.HeaderProtectionCipher(crypt)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to protect initiation message: %v", peer, err)
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	rand.Read(buf[padding+MessageInitiationSize:])

	sendBuffer = append(sendBuffer, sendBuf)

	if len(candidates) > 0 {
		err = peer.sendHandshakeBuffers(sendBuffer, candidates)
	} else {
		err = peer.SendBuffers(sendBuffer)
	}
	err = unwrapGSODisabled(peer.device.log, err) // lx: SPEC 101
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake response", peer)

	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create response message: %v", peer, err)
		return err
	}

	// lx: AmneziaWG datagram layout: [S2 random padding][response][random trailer].
	padding := int(peer.device.paddings.response.Load())
	trailerLen := max(peer.randomTrailer(padding+MessageResponseSize), 0)

	sendBuf := make([]byte, MessageEncapsulatingTransportSize+padding+MessageResponseSize+trailerLen)
	buf := sendBuf[MessageEncapsulatingTransportSize:]

	crypt := buf[:padding]
	rand.Read(crypt)

	packet := buf[padding : padding+MessageResponseSize]
	if err := response.marshal(packet); err != nil {
		peer.device.log.Errorf("%v - Failed to marshal response message: %v", peer, err)
		return err
	}
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	cip, err := peer.device.HeaderProtectionCipher(crypt)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to protect response message: %v", peer, err)
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	rand.Read(buf[padding+MessageResponseSize:])

	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{sendBuf})
	err = unwrapGSODisabled(peer.device.log, err) // lx: SPEC 101
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
	}
	return err
}

func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	device.log.Verbosef("Sending cookie response for denied handshake message for %v", initiatingElem.endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	msgType := device.headers.cookie.Load().PickOne()

	reply, err := device.cookieChecker.CreateReply(
		initiatingElem.packet,
		sender,
		initiatingElem.endpoint.DstToBytes(),
		msgType,
	)
	if err != nil {
		device.log.Errorf("Failed to create cookie reply: %v", err)
		return err
	}

	// lx: AmneziaWG datagram layout: [S3 random padding][cookie reply][random trailer].
	padding := int(device.paddings.cookie.Load())
	trailerLen := max(device.randomTrailer(padding+MessageCookieReplySize), 0)

	sendBuf := make([]byte, MessageEncapsulatingTransportSize+padding+MessageCookieReplySize+trailerLen)
	buf := sendBuf[MessageEncapsulatingTransportSize:]

	crypt := buf[:padding]
	rand.Read(crypt)

	packet := buf[padding : padding+MessageCookieReplySize]
	if err := reply.marshal(packet); err != nil {
		device.log.Errorf("Failed to marshal cookie reply: %v", err)
		return err
	}

	cip, err := device.HeaderProtectionCipher(crypt)
	if err != nil {
		device.log.Errorf("Failed to protect cookie reply: %v", err)
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	rand.Read(buf[padding+MessageCookieReplySize:])

	// TODO: allocation could be avoided
	device.net.bind.Send([][]byte{sendBuf}, initiatingElem.endpoint, MessageEncapsulatingTransportSize)
	return nil
}

func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := keypair.sendNonce.Load()
	if nonce > RekeyAfterMessages || (keypair.isInitiator && time.Since(keypair.created) > peer.device.keyRefreshTimeoutSending()) {
		peer.SendHandshakeInitiation(false)
	}
}

func (device *Device) RoutineReadFromTUN() {
	defer func() {
		device.log.Verbosef("Routine: TUN reader - stopped")
		device.state.stopping.Done()
		device.queue.encryption.wg.Done()
	}()

	device.log.Verbosef("Routine: TUN reader - started")

	var (
		batchSize   = device.BatchSize()
		readErr     error
		elems       = make([]*QueueOutboundElement, batchSize)
		bufs        = make([][]byte, batchSize)
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize)
		count       = 0
		sizes       = make([]int, batchSize)
	)

	for i := range elems {
		elems[i] = device.NewOutboundElement()
		bufs[i] = elems[i].buffer[:]
	}

	defer func() {
		for _, elem := range elems {
			if elem != nil {
				device.PutOutboundBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
		}
	}()

	for {
		// lx: AmneziaWG — read behind the transport padding (s4) as well as the
		// header, so RoutineEncryption can build the whole datagram in place.
		padding := device.paddings.transport.Load()
		offset := MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize

		// read packets
		count, readErr = device.tun.device.Read(bufs, sizes, offset)
		for i := 0; i < count; i++ {
			if sizes[i] < 1 {
				continue
			}

			elem := elems[i]
			elem.padding = padding
			elem.isKeepalive = false
			elem.packet = bufs[i][offset : offset+sizes[i]]

			// lookup peer
			var peer *Peer
			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				src := netip.AddrFrom4([4]byte(elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]))
				dst := netip.AddrFrom4([4]byte(elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]))
				peer = device.allowedips.LookupFromPacket(src, dst, elem.packet)

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				src := netip.AddrFrom16([16]byte(elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]))
				dst := netip.AddrFrom16([16]byte(elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]))
				peer = device.allowedips.LookupFromPacket(src, dst, elem.packet)

			default:
				device.log.Verbosef("Received packet with unknown IP version")
			}

			if peer == nil {
				continue
			}
			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				elemsForPeer = device.GetOutboundElementsContainer()
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			elems[i] = device.NewOutboundElement()
			bufs[i] = elems[i].buffer[:]
		}

		for peer, elemsForPeer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.StagePackets(elemsForPeer)
				peer.SendStagedPackets()
			} else {
				for _, elem := range elemsForPeer.elems {
					device.PutOutboundBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}
			delete(elemsByPeer, peer)
		}

		if readErr != nil {
			if errors.Is(readErr, tun.ErrTooManySegments) {
				// TODO: record stat for this
				// This will happen if MSS is surprisingly small (< 576)
				// coincident with reasonably high throughput.
				device.log.Verbosef("Dropped some packets from multi-segment read: %v", readErr)
				continue
			}
			if !device.isClosed() {
				if !errors.Is(readErr, os.ErrClosed) {
					device.log.Errorf("Failed to read packet from TUN device: %v", readErr)
				}
				go device.Close()
			}
			return
		}
	}
}

const (
	maxStagedPackets         = 128
	maxQueuedOutboundPackets = 1024
)

type InputPacketRef struct {
	Destination  []byte
	PacketSlices [][]byte
}

func (device *Device) inputPacketPeer(destination []byte, packetSlices [][]byte) *Peer {
	var src, dst netip.Addr
	switch len(destination) {
	case net.IPv4len:
		dst = netip.AddrFrom4([4]byte(destination))
		var srcBytes [net.IPv4len]byte
		if !gatherPacketBytes(packetSlices, IPv4offsetSrc, srcBytes[:]) {
			return nil
		}
		src = netip.AddrFrom4(srcBytes)
	case net.IPv6len:
		dst = netip.AddrFrom16([16]byte(destination))
		var srcBytes [net.IPv6len]byte
		if !gatherPacketBytes(packetSlices, IPv6offsetSrc, srcBytes[:]) {
			return nil
		}
		src = netip.AddrFrom16(srcBytes)
	default:
		return nil
	}
	var ipPkt []byte
	if len(packetSlices) == 1 {
		ipPkt = packetSlices[0]
	}
	return device.allowedips.LookupFromPacket(src, dst, ipPkt)
}

func gatherPacketBytes(packetSlices [][]byte, offset int, destination []byte) bool {
	for _, packetSlice := range packetSlices {
		if offset >= len(packetSlice) {
			offset -= len(packetSlice)
			continue
		}
		n := copy(destination, packetSlice[offset:])
		destination = destination[n:]
		offset = 0
		if len(destination) == 0 {
			return true
		}
	}
	return false
}

// outboundLayout sizes an injected (InputPacket/InputPackets) element for a
// plaintext of totalLength bytes: the plaintext goes at offset — behind the AWG
// transport padding (s4) and the transport header, which RoutineEncryption
// fills in place — and the buffer keeps room for the bytes appended before
// sealing (see outboundTailroom) plus the AEAD tag. allocLength is 0 when the
// packet cannot fit a MaxMessageSize datagram.
func (device *Device) outboundLayout(totalLength int) (padding uint32, offset, allocLength int) {
	padding = device.paddings.transport.Load()
	offset = MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize
	base := offset + totalLength + chacha20poly1305.Overhead
	if base+PaddingMultiple > MaxMessageSize {
		return padding, offset, 0
	}
	allocLength = min(base+device.outboundTailroom(offset+totalLength), MaxMessageSize)
	return padding, offset, allocLength
}

// outboundTailroom is the headroom kept after the plaintext of a tightly
// allocated element for what RoutineEncryption appends before sealing: the
// WireGuard multiple-of-16 pad, or under AWG 3.x the content padding addition
// / random trailer. Both are clamped to the buffer when they would not fit, so
// this only decides how much of the obfuscation an injected packet can carry —
// never whether it is safe. datagramSize is the datagram without any addition.
func (device *Device) outboundTailroom(datagramSize int) int {
	room := PaddingMultiple
	if addition := device.contentPaddingAddition.Load(); !addition.IsZero() {
		room = max(room, int(min(addition.Hi(), MaxMessageSize)))
	} else if device.randomTrailers.Load() {
		room = max(room, DefaultUdpWindow-datagramSize)
	}
	return room
}

func (device *Device) newInputElement(packetSlices ...[]byte) *QueueOutboundElement {
	var totalLength int
	for _, packetSlice := range packetSlices {
		totalLength += len(packetSlice)
	}
	padding, offset, allocLength := device.outboundLayout(totalLength)
	if allocLength == 0 {
		return nil
	}
	elem := device.GetOutboundElement()
	elem.buffer = device.GetOutboundBuffer(allocLength)
	elem.nonce = 0
	elem.padding = padding
	elem.isKeepalive = false
	packet := elem.buffer[offset:]
	var n int
	for _, packetSlice := range packetSlices {
		n += copy(packet[n:], packetSlice)
	}
	elem.packet = packet[:n]
	return elem
}

func (device *Device) InputPacket(destination []byte, packetSlices [][]byte) {
	peer := device.inputPacketPeer(destination, packetSlices)
	if peer == nil {
		return
	}
	if peer.stagedPackets.Load() >= maxStagedPackets || peer.queuedOutboundPackets.Load() >= maxQueuedOutboundPackets {
		return
	}
	elem := device.newInputElement(packetSlices...)
	if elem == nil {
		return
	}
	elemsForPeer := device.GetOutboundElementsContainer()
	elemsForPeer.elems = append(elemsForPeer.elems, elem)
	peer.stageInputPackets(elemsForPeer)
	peer.SendStagedPackets()
}

// InputPackets injects whole IP packets without waiting: packets for a peer
// whose pipeline is full are dropped. Packets matching no peer are returned.
func (device *Device) InputPackets(packets []*InputPacketRef) []*InputPacketRef {
	var unmatched []*InputPacketRef
	elemsByPeer := make(map[*Peer][]*QueueOutboundElementsContainer)
	for _, packetRef := range packets {
		peer := device.inputPacketPeer(packetRef.Destination, packetRef.PacketSlices)
		if peer == nil {
			unmatched = append(unmatched, packetRef)
			continue
		}
		if peer.stagedPackets.Load() >= maxStagedPackets || peer.queuedOutboundPackets.Load() >= maxQueuedOutboundPackets {
			continue
		}
		elem := device.newInputElement(packetRef.PacketSlices...)
		if elem == nil {
			continue
		}
		containers := elemsByPeer[peer]
		if len(containers) == 0 || len(containers[len(containers)-1].elems) >= conn.IdealBatchSize {
			containers = append(containers, device.GetOutboundElementsContainer())
			elemsByPeer[peer] = containers
		}
		elemsForPeer := containers[len(containers)-1]
		elemsForPeer.elems = append(elemsForPeer.elems, elem)
	}
	for peer, containers := range elemsByPeer {
		for _, elemsForPeer := range containers {
			peer.stageInputPackets(elemsForPeer)
		}
		peer.SendStagedPackets()
	}
	return unmatched
}

// WritePackets injects whole IP packets routed to this peer, waiting while the
// peer's encryption and transmission pipeline is full. Packets are dropped if
// the peer stops or is still waiting for a handshake with a full staged queue.
func (peer *Peer) WritePackets(packets [][]byte) {
	device := peer.device
	for len(packets) > 0 {
		if !peer.waitOutboundSpace() {
			return
		}
		batch := packets[:min(len(packets), conn.IdealBatchSize)]
		packets = packets[len(batch):]
		if peer.stagedPackets.Load() >= maxStagedPackets {
			continue
		}
		elemsForPeer := device.GetOutboundElementsContainer()
		for _, packet := range batch {
			elem := device.newInputElement(packet)
			if elem != nil {
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
			}
		}
		peer.stageInputPackets(elemsForPeer)
		peer.SendStagedPackets()
	}
}

func (peer *Peer) stageInputPackets(elemsForPeer *QueueOutboundElementsContainer) {
	if len(elemsForPeer.elems) > 0 && peer.isRunning.Load() {
		peer.StagePackets(elemsForPeer)
		return
	}
	for _, elem := range elemsForPeer.elems {
		peer.device.PutOutboundBuffer(elem.buffer)
		peer.device.PutOutboundElement(elem)
	}
	peer.device.PutOutboundElementsContainer(elemsForPeer)
}

func (peer *Peer) StagePackets(elems *QueueOutboundElementsContainer) {
	peer.stagedPackets.Add(int32(len(elems.elems)))
	for {
		select {
		case peer.queue.staged <- elems:
			return
		default:
			peer.dropOldestStaged()
		}
	}
}

func (peer *Peer) dropOldestStaged() bool {
	select {
	case tooOld := <-peer.queue.staged:
		peer.stagedPackets.Add(-int32(len(tooOld.elems)))
		for _, elem := range tooOld.elems {
			peer.device.PutOutboundBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
		}
		peer.device.PutOutboundElementsContainer(tooOld)
		return true
	default:
		return false
	}
}

func (peer *Peer) waitOutboundSpace() bool {
	for {
		if !peer.isRunning.Load() {
			return false
		}
		if peer.queuedOutboundPackets.Load() < maxQueuedOutboundPackets {
			return true
		}
		peer.outboundSpace.Lock()
		if peer.outboundSpace.ready == nil {
			peer.outboundSpace.ready = make(chan struct{})
		}
		ready := peer.outboundSpace.ready
		peer.outboundSpace.Unlock()
		if !peer.isRunning.Load() {
			return false
		}
		if peer.queuedOutboundPackets.Load() < maxQueuedOutboundPackets {
			return true
		}
		<-ready
	}
}

func (peer *Peer) releaseOutboundPackets(count int) {
	remaining := peer.queuedOutboundPackets.Add(-int32(count))
	if remaining < maxQueuedOutboundPackets && remaining+int32(count) >= maxQueuedOutboundPackets {
		peer.wakeOutboundWaiters()
	}
}

func (peer *Peer) wakeOutboundWaiters() {
	peer.outboundSpace.Lock()
	if peer.outboundSpace.ready != nil {
		close(peer.outboundSpace.ready)
		peer.outboundSpace.ready = nil
	}
	peer.outboundSpace.Unlock()
}

func (peer *Peer) SendStagedPackets() {
top:
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		return
	}

	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || time.Since(keypair.created) >= peer.device.keychainExpireTime() {
		peer.SendHandshakeInitiation(false)
		return
	}

	for {
		var elemsContainerOOO *QueueOutboundElementsContainer
		select {
		case elemsContainer := <-peer.queue.staged:
			peer.stagedPackets.Add(-int32(len(elemsContainer.elems)))
			i := 0
			for _, elem := range elemsContainer.elems {
				elem.peer = peer
				elem.nonce = keypair.sendNonce.Add(1) - 1
				if elem.nonce >= RejectAfterMessages {
					keypair.sendNonce.Store(RejectAfterMessages)
					if elemsContainerOOO == nil {
						elemsContainerOOO = peer.device.GetOutboundElementsContainer()
					}
					elemsContainerOOO.elems = append(elemsContainerOOO.elems, elem)
					continue
				} else {
					elemsContainer.elems[i] = elem
					i++
				}

				elem.keypair = keypair
			}
			elemsContainer.elems = elemsContainer.elems[:i]

			if elemsContainerOOO != nil {
				peer.StagePackets(elemsContainerOOO) // XXX: Out of order, but we can't front-load go chans
			}

			if len(elemsContainer.elems) == 0 {
				peer.device.PutOutboundElementsContainer(elemsContainer)
				goto top
			}

			// add to parallel and sequential queue
			if peer.isRunning.Load() {
				elemsContainer.filling.Add(1)
				peer.queuedOutboundPackets.Add(int32(len(elemsContainer.elems)))
				peer.queue.outbound.c <- elemsContainer
				peer.device.queue.encryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					peer.device.PutOutboundBuffer(elem.buffer)
					peer.device.PutOutboundElement(elem)
				}
				peer.device.PutOutboundElementsContainer(elemsContainer)
			}

			if elemsContainerOOO != nil {
				goto top
			}
		default:
			return
		}
	}
}

func (peer *Peer) FlushStagedPackets() {
	for peer.dropOldestStaged() {
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

// lx:begin awg3 (AmneziaWG 3.x — ported from amneziawg-go v3 device/send.go)

// randomPaddingAddition picks the AWG 3.x content padding addition for a
// transport datagram of datagramSize bytes (padding + header + content + tag):
// a value from content_padding_addition, clamped so the datagram never grows
// past the peer's UDP window. -1 when the feature is off.
func (peer *Peer) randomPaddingAddition(datagramSize int) int {
	addition := peer.device.contentPaddingAddition.Load()
	if addition.IsZero() {
		return -1
	}

	udpWindow := int(peer.udpWindow.Load())
	if udpWindow < datagramSize {
		return 0
	}

	add := int(addition.PickOne())
	if space := udpWindow - datagramSize; add > space {
		add = space
	}
	return add
}

// randomTrailer picks the AWG 3.x random trailer length for a datagram sent
// without a peer context (cookie replies): up to DefaultUdpWindow. -1 when
// random_trailers is off.
func (device *Device) randomTrailer(datagramSize int) int {
	if !device.randomTrailers.Load() {
		return -1
	}

	if DefaultUdpWindow < datagramSize {
		return 0
	}
	return int(fastrandn(uint32(DefaultUdpWindow - datagramSize)))
}

// randomTrailer picks the AWG 3.x random trailer length for a datagram to this
// peer: up to the peer's UDP window. -1 when random_trailers is off.
func (peer *Peer) randomTrailer(datagramSize int) int {
	if !peer.device.randomTrailers.Load() {
		return -1
	}

	udpWindow := int(peer.udpWindow.Load())
	if udpWindow < datagramSize {
		return 0
	}
	return int(fastrandn(uint32(udpWindow - datagramSize)))
}

// lx:end awg3

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: encryption worker %d - stopped", id)
	device.log.Verbosef("Routine: encryption worker %d - started", id)

	for elemsContainer := range device.queue.encryption.c {
		for _, elem := range elemsContainer.elems {
			// lx: AmneziaWG datagram layout, built in place in elem.buffer:
			//   [encap headroom][s4 random padding][16-byte header][sealed content]
			// The device's current s4 is authoritative: an element produced
			// under another value — the TUN reader captures s4 before it blocks
			// in Read, so the batch in flight across an IpcSet (notably the very
			// first one after start) still carries the old layout — is relocated
			// to the current offset; the peer classifies by the current s4.
			padding := int(device.paddings.transport.Load())
			headerStart := MessageEncapsulatingTransportSize + padding
			offset := headerStart + MessageTransportHeaderSize
			if int(elem.padding) != padding || (len(elem.packet) > 0 && &elem.packet[0] != &elem.buffer[offset]) {
				if offset+len(elem.packet)+chacha20poly1305.Overhead > len(elem.buffer) {
					// an injected element allocated for a smaller s4 (reconfigured
					// while in flight) — nothing sensible fits, drop it
					device.log.Verbosef("%v - Packet dropped: no room to relocate under transport padding %d", elem.peer, padding)
					elem.packet = nil
					continue
				}
				n := copy(elem.buffer[offset:], elem.packet) // overlap-safe (memmove)
				elem.packet = elem.buffer[offset : offset+n]
				elem.padding = uint32(padding)
			}

			// The datagram this element becomes is a size this path carries.
			elem.peer.noteUDPWindow(uint32(padding + MessageTransportSize + len(elem.packet)))

			// fill the transport padding; its first 12 bytes are the AWG 3.x
			// header-protection nonce
			crypt := elem.buffer[MessageEncapsulatingTransportSize:headerStart]
			if len(crypt) > 0 {
				rand.Read(crypt)
			}

			// populate header fields
			header := elem.buffer[headerStart:offset]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, device.headers.transport.Load().PickOne())
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			// trailing plaintext bytes: the AWG 3.x content padding addition,
			// else a random trailer, else the WireGuard multiple-of-16 pad
			datagramSize := padding + MessageTransportSize + len(elem.packet)
			paddingSize := elem.peer.randomPaddingAddition(datagramSize)
			if paddingSize < 0 {
				paddingSize = elem.peer.randomTrailer(datagramSize)
			}
			if paddingSize < 0 {
				paddingSize = calculatePaddingSize(len(elem.packet), int(device.tun.mtu.Load()))
			}
			// never spill past the buffer: injected elements are allocated by
			// size (see outboundLayout), so the addition is clamped to fit
			if room := cap(elem.packet) - len(elem.packet) - chacha20poly1305.Overhead; paddingSize > room {
				paddingSize = max(room, 0)
			}
			oldLen := len(elem.packet)
			elem.packet = elem.packet[:oldLen+paddingSize]
			clear(elem.packet[oldLen:])

			// encrypt content and release to consumer

			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
			elem.packet = elem.keypair.send.Seal(
				elem.buffer[:offset],
				nonce[:],
				elem.packet,
				nil,
			)

			// AWG 3.x header protection: the 16-byte header is XORed with a
			// ChaCha20 keystream keyed by the header key and salted with the
			// padding, so type / receiver index / counter carry no structure.
			cip, err := device.HeaderProtectionCipher(crypt)
			if err != nil {
				device.log.Errorf("%v - Header protection failed, packet dropped: %v", elem.peer, err)
				elem.packet = nil
				continue
			}
			if cip != nil {
				cip.XORKeyStream(header, header)
			}
		}
		elemsContainer.filling.Done()
	}
}

func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	device := peer.device
	defer func() {
		defer device.log.Verbosef("%v - Routine: sequential sender - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential sender - started", peer)

	bufs := make([][]byte, 0, max(maxBatchSize, conn.IdealBatchSize))

	for elemsContainer := range peer.queue.outbound.c {
		if elemsContainer == nil {
			return
		}
		peer.processOutboundContainer(elemsContainer, bufs[:0])
	}
}

// processOutboundContainer waits for the encryption routine to finish
// filling elemsContainer, then sends the batch (or drops it, if the peer
// has been stopped) and returns the container to the pool.
//
// scratch is a length-0 slice used to assemble the per-packet buffers
// passed to SendBuffers; its backing array is reused across calls.
func (peer *Peer) processOutboundContainer(elemsContainer *QueueOutboundElementsContainer, scratch [][]byte) {
	// Invariants from RoutineSequentialSender; all should be unreachable.
	if len(scratch) != 0 || cap(scratch) == 0 {
		panic(fmt.Sprintf("processOutboundContainer: scratch must be empty with non-zero cap; got len=%d cap=%d",
			len(scratch), cap(scratch)))
	}
	if cap(scratch) < len(elemsContainer.elems) {
		panic(fmt.Sprintf("processOutboundContainer: scratch cap %d < elems %d",
			cap(scratch), len(elemsContainer.elems)))
	}

	device := peer.device
	defer device.PutOutboundElementsContainer(elemsContainer)

	// Wait for RoutineEncryption to finish filling the container. After
	// Wait returns we have happens-before with that goroutine and are the
	// sole owner of the container until Put hands it back to the pool.
	elemsContainer.filling.Wait()

	if !peer.isRunning.Load() {
		// peer has been stopped; return re-usable elems to the shared pool.
		// This is an optimization only. It is possible for the peer to be stopped
		// immediately after this check, in which case, elem will get processed.
		// The timers and SendBuffers code are resilient to a few stragglers.
		// TODO: rework peer shutdown order to ensure
		// that we never accidentally keep timers alive longer than necessary.
		peer.releaseOutboundPackets(len(elemsContainer.elems))
		for _, elem := range elemsContainer.elems {
			device.PutOutboundBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		return
	}

	dataSent := false
	for _, elem := range elemsContainer.elems {
		if elem.packet == nil {
			// dropped by RoutineEncryption (header protection failure)
			continue
		}
		if !elem.isKeepalive {
			dataSent = true
		}
		scratch = append(scratch, elem.packet)
	}

	var err error
	if len(scratch) > 0 {
		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		err = peer.SendBuffers(scratch)
		if dataSent {
			peer.timersDataSent()
		}
	}
	peer.releaseOutboundPackets(len(elemsContainer.elems))
	for _, elem := range elemsContainer.elems {
		device.PutOutboundBuffer(elem.buffer)
		device.PutOutboundElement(elem)
	}
	err = unwrapGSODisabled(device.log, err) // lx: SPEC 101
	if err != nil {
		device.log.Errorf("%v - Failed to send data packets: %v", peer, err)
		return
	}

	peer.keepKeyFreshSending()
}
