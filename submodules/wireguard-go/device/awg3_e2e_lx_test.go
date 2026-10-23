/* SPDX-License-Identifier: MIT
 *
 * AmneziaWG 3.x end-to-end (sing-box-lx SPEC 080): two Devices wired through
 * the in-memory channel bind, both configured with the full parameter set of
 * a live amnezia-awg2 export (protocol_version 3.1) — header protection,
 * content padding addition, random trailers, disabled cookies, ranged
 * timings and a ranged persistent keepalive — must handshake and pass
 * packets in both directions over every outbound path (tun read and
 * InputPacket injection). The wire is tapped to pin the datagram format:
 * S1/S4 padding in front, the type word masked by the header cipher keyed
 * with the padding's first 12 bytes, content padding growing data packets.
 *
 * The negative cases pin the guards: a header-key mismatch yields no
 * handshake (the protection is real, not cosmetic), and the uapi refuses a
 * header key with S1–S4 shorter than the 12-byte nonce, including when the
 * key was set by an earlier IpcSet.
 */

package device

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20"
)

// S1–S4 of the live AWG 3.1 export (all >= HeaderCipherNonceSize).
const (
	awg3S1 = 55
	awg3S2 = 42
	awg3S3 = 40
	awg3S4 = 12
)

// awg3DeviceLines renders the device-level AWG 3.1 parameters of the live
// export as uapi lines (H1–H4 stay at the WireGuard defaults: with header
// protection the type word is masked anyway).
func awg3DeviceLines(hpKey []byte) string {
	return fmt.Sprintf(
		"jc=4\njmin=10\njmax=50\ns1=%d\ns2=%d\ns3=%d\ns4=%d\nh1=1\nh2=2\nh3=3\nh4=4\n"+
			"header_protection_key=%s\ncontent_padding_addition=10-100\n"+
			"rekey_after_time=100-120\nrekey_timeout=3-7\nreject_after_time=150-180\n"+
			"keepalive_timeout=5-15\nmax_handshake_attempts=15-20\n"+
			"random_trailers=1\ndisable_cookies=1\n",
		awg3S1, awg3S2, awg3S3, awg3S4, hex.EncodeToString(hpKey))
}

func newHeaderKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, HeaderCipherKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

// wireTap records every datagram a chanBind sends.
type wireTap struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (w *wireTap) record(pkt []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pkts = append(w.pkts, append([]byte(nil), pkt...))
}

func (w *wireTap) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.pkts...)
}

// unmaskType undoes the header protection on the type word at offset: the
// keystream is ChaCha20(key, nonce = datagram[:12]) from byte 0, exactly what
// the sender applied.
func unmaskType(t *testing.T, key, pkt []byte, offset int) uint32 {
	t.Helper()
	cip, err := chacha20.NewUnauthenticatedCipher(key, pkt[:HeaderCipherNonceSize])
	if err != nil {
		t.Fatalf("chacha20: %v", err)
	}
	var ks [4]byte
	cip.XORKeyStream(ks[:], ks[:])
	var word [4]byte
	for i := range word {
		word[i] = pkt[offset+i] ^ ks[i]
	}
	return binary.LittleEndian.Uint32(word[:])
}

// newAWG3DevicePair brings up two peered devices with the AWG 3.1 parameter
// set; keyA/keyB are the header-protection keys of each side (normally the
// same), tapA (optional) sees A's outgoing datagrams.
func newAWG3DevicePair(t *testing.T, keyA, keyB []byte, tapA *wireTap) *paddedPair {
	t.Helper()

	skA, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey A: %v", err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey B: %v", err)
	}
	pkA := skA.publicKey()
	pkB := skB.publicKey()

	bindA, bindB := newChanBindPair()
	if tapA != nil {
		bindA.tap = tapA.record
	}
	tunA := newChanTun()
	tunB := newChanTun()

	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "devA: "), 1)
	devB := NewDevice(context.Background(), tunB, bindB, NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)

	cfgA := "private_key=" + hex.EncodeToString(skA[:]) + "\n" + awg3DeviceLines(keyA) +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\npersistent_keepalive_interval=25-35\n",
			hex.EncodeToString(pkB[:]), testIPB)
	cfgB := "private_key=" + hex.EncodeToString(skB[:]) + "\n" + awg3DeviceLines(keyB) +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n",
			hex.EncodeToString(pkA[:]), testIPA)

	if err := devA.IpcSet(cfgA); err != nil {
		t.Fatalf("IpcSet A: %v", err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		t.Fatalf("IpcSet B: %v", err)
	}

	if err := devA.Up(); err != nil {
		t.Fatalf("Up A: %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("Up B: %v", err)
	}

	return &paddedPair{devA: devA, devB: devB, tunA: tunA, tunB: tunB}
}

// awaitNoPacket asserts nothing reaches the tun within d.
func awaitNoPacket(t *testing.T, from *chanTun, d time.Duration) {
	t.Helper()
	select {
	case got := <-from.fromDevice:
		t.Fatalf("unexpected packet delivered, len=%d", len(got))
	case <-time.After(d):
	}
}

func TestAWG3EndToEnd(t *testing.T) {
	key := newHeaderKey(t)
	tap := &wireTap{}
	pair := newAWG3DevicePair(t, key, key, tap)

	// A -> B over the tun read path (in-place datagram layout).
	const payloadLen = 100
	pkt := buildIPv4Packet(testIPA, testIPB, payloadLen)
	sendTun := func() { pair.tunA.toDevice <- append([]byte(nil), pkt...) }
	sendTun()
	awaitPacket(t, pair.tunB, pkt, sendTun)

	// B -> A (the responder's transport path).
	pktBack := buildIPv4Packet(testIPB, testIPA, 40)
	sendBack := func() { pair.tunB.toDevice <- append([]byte(nil), pktBack...) }
	sendBack()
	awaitPacket(t, pair.tunA, pktBack, sendBack)

	// A -> B over the injection path (tightly allocated element).
	pktInject := buildIPv4Packet(testIPA, testIPB, 8)
	sendInject := func() { pair.devA.InputPacket(testIPB.AsSlice(), [][]byte{pktInject}) }
	sendInject()
	awaitPacket(t, pair.tunB, pktInject, sendInject)

	// Wire format.
	var sawInit, sawTransport, sawPaddedData bool
	const dataDatagram = awg3S4 + MessageTransportSize + 20 + payloadLen // exact size without addition
	for _, dg := range tap.snapshot() {
		if len(dg) >= awg3S1+MessageInitiationSize && unmaskType(t, key, dg, awg3S1) == MessageInitiationType {
			sawInit = true
			if raw := binary.LittleEndian.Uint32(dg[awg3S1:]); raw == MessageInitiationType {
				t.Errorf("initiation type word is in the clear on the wire")
			}
			continue
		}
		if len(dg) >= awg3S4+MessageTransportSize && unmaskType(t, key, dg, awg3S4) == MessageTransportType {
			sawTransport = true
			if raw := binary.LittleEndian.Uint32(dg[awg3S4:]); raw == MessageTransportType {
				t.Errorf("transport type word is in the clear on the wire")
			}
			// content_padding_addition=10-100 grows the 100-byte data packet's
			// datagram by 10..100 (the UDP window of 500 leaves room)
			if len(dg) > dataDatagram && len(dg) <= dataDatagram+100 {
				sawPaddedData = true
			}
			if len(dg) == dataDatagram {
				t.Errorf("data datagram sent without content padding addition (len %d)", len(dg))
			}
		}
	}
	if !sawInit {
		t.Errorf("no header-protected handshake initiation seen on the wire")
	}
	if !sawTransport {
		t.Errorf("no header-protected transport datagram seen on the wire")
	}
	if !sawPaddedData {
		t.Errorf("no content-padded data datagram seen on the wire")
	}
}

// A header-key mismatch must leave both sides unable to classify each
// other's datagrams: no handshake, nothing delivered.
func TestAWG3HeaderKeyMismatch(t *testing.T) {
	pair := newAWG3DevicePair(t, newHeaderKey(t), newHeaderKey(t), nil)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	pair.tunA.toDevice <- append([]byte(nil), pkt...)
	awaitNoPacket(t, pair.tunB, 3*time.Second)

	got, err := pair.devB.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(got, "last_handshake_time_sec=0\n") {
		t.Fatalf("handshake completed across a header-key mismatch:\n%s", got)
	}
}

// The uapi refuses a header key unless every S1–S4 can carry the 12-byte
// nonce — also when the key is already on the device and only a padding
// shrinks (the staged set is seeded from the device).
func TestAWG3UapiRejectsShortPaddingWithHeaderKey(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	bind, _ := newChanBindPair()
	dev := NewDevice(context.Background(), newChanTun(), bind, NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	keyHex := hex.EncodeToString(newHeaderKey(t))
	base := "private_key=" + hex.EncodeToString(sk[:]) + "\n"

	err = dev.IpcSet(base + "s1=55\ns2=42\ns3=40\ns4=8\nheader_protection_key=" + keyHex + "\n")
	if err == nil || !strings.Contains(err.Error(), "s4") {
		t.Fatalf("s4=8 with a header key accepted (err=%v)", err)
	}
	if dev.headerProtection.key.Load() != nil {
		t.Fatal("rejected IpcSet left the header key on the device")
	}

	if err := dev.IpcSet(base + "s1=55\ns2=42\ns3=40\ns4=12\nheader_protection_key=" + keyHex + "\n"); err != nil {
		t.Fatalf("valid AWG 3 set rejected: %v", err)
	}
	if dev.headerProtection.key.Load() == nil {
		t.Fatal("header key not applied")
	}

	// partial update: only s2 shrinks, the key stays -> refused
	err = dev.IpcSet("s2=4\n")
	if err == nil || !strings.Contains(err.Error(), "s2") {
		t.Fatalf("s2=4 next to an existing header key accepted (err=%v)", err)
	}
	if dev.paddings.response.Load() != 42 {
		t.Fatalf("rejected partial set changed s2 to %d", dev.paddings.response.Load())
	}

	// clearing the key lifts the constraint
	if err := dev.IpcSet("header_protection_key=" + strings.Repeat("00", HeaderCipherKeySize) + "\ns2=4\n"); err != nil {
		t.Fatalf("clearing the key with a short padding rejected: %v", err)
	}
	if dev.headerProtection.key.Load() != nil {
		t.Fatal("zero header key did not clear header protection")
	}
}

func TestUintRangeFromString(t *testing.T) {
	cases := []struct {
		spec    string
		lo, hi  uint32
		wantErr bool
	}{
		{"5", 5, 5, false},
		{"3-7", 3, 7, false},
		{"0", 0, 0, false},
		{"4294967295", 4294967295, 4294967295, false},
		{"0-4294967295", 0, 4294967295, false},
		{"7-3", 0, 0, true},
		{"", 0, 0, true},
		{"a", 0, 0, true},
		{"1-2-3", 0, 0, true},
		{"1-4294967296", 0, 0, true},
		{"-1", 0, 0, true},
	}
	for _, c := range cases {
		var r UintRange
		err := r.FromString(c.spec)
		if c.wantErr != (err != nil) {
			t.Errorf("FromString(%q): err = %v, wantErr = %v", c.spec, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if r.Lo() != c.lo || r.Hi() != c.hi {
			t.Errorf("FromString(%q) = [%d, %d], want [%d, %d]", c.spec, r.Lo(), r.Hi(), c.lo, c.hi)
		}
		if got := r.ToString(); got != c.spec && !(c.lo == c.hi && got == fmt.Sprint(c.lo)) {
			t.Errorf("ToString(%q) = %q", c.spec, got)
		}
		for i := 0; i < 16; i++ {
			if v := r.PickOne(); !r.Contains(v) {
				t.Errorf("PickOne(%q) = %d outside range", c.spec, v)
			}
		}
	}
}

// persistent_keepalive_interval accepts the AWG 3.x "min-max" form and keeps
// WireGuard's plain-number form; IpcGet reports it back verbatim.
func TestAWG3PersistentKeepaliveRange(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	peerSK, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	peerPK := peerSK.publicKey()
	bind, _ := newChanBindPair()
	dev := NewDevice(context.Background(), newChanTun(), bind, NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	set := func(value string) error {
		return dev.IpcSet("private_key=" + hex.EncodeToString(sk[:]) + "\npublic_key=" + hex.EncodeToString(peerPK[:]) +
			"\npersistent_keepalive_interval=" + value + "\n")
	}
	get := func() string {
		got, err := dev.IpcGet()
		if err != nil {
			t.Fatalf("IpcGet: %v", err)
		}
		return got
	}

	for _, value := range []string{"25-35", "25", "0"} {
		if err := set(value); err != nil {
			t.Fatalf("persistent_keepalive_interval=%s rejected: %v", value, err)
		}
		if got := get(); !strings.Contains(got, "persistent_keepalive_interval="+value+"\n") {
			t.Errorf("persistent_keepalive_interval=%s not reported:\n%s", value, got)
		}
	}
	for _, bad := range []string{"35-25", "70000", "x"} {
		if err := set(bad); err == nil {
			t.Errorf("persistent_keepalive_interval=%s accepted", bad)
		}
	}
}
