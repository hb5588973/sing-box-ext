/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 101 — guard for the handshake log on a UDP GSO fallback.
 *
 * StdNetBind answers a send the kernel rejected with GSO by disabling offload,
 * resending the batch without it and returning conn.ErrUDPGSODisabled whose
 * RetryErr is the error of the resend. The data path always unwrapped it; the
 * two handshake send paths logged the wrapper as ERROR even when the resend
 * went through (LxBox #95: "failed to send handshake initiation: disabled UDP
 * GSO on ..."). The test drives both handshake paths against a bind that
 * returns the wrapper and checks the device log:
 *
 *   - RetryErr == nil: the wrapper is logged at Verbose, nothing at ERROR,
 *     the method returns nil;
 *   - RetryErr == io.ErrClosedPipe: ERROR names the resend error only.
 *
 * It uses no post-fix API in the end-to-end cases, so they run RED on d3a0e26.
 * Reuses the chanBind harness from transport_padding_test.go.
 */

package device

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/wireguard-go/conn"
)

// gsoBind wraps chanBind and answers every Send with a fixed error.
type gsoBind struct {
	*chanBind
	err error
}

func (b *gsoBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	return b.err
}

// captureLog records every line the device logs, split by level.
type captureLog struct {
	mu      sync.Mutex
	verbose []string
	errs    []string
}

func (c *captureLog) logger() *Logger {
	return &Logger{
		Verbosef: func(format string, args ...any) {
			c.mu.Lock()
			c.verbose = append(c.verbose, fmt.Sprintf(format, args...))
			c.mu.Unlock()
		},
		Errorf: func(format string, args ...any) {
			c.mu.Lock()
			c.errs = append(c.errs, fmt.Sprintf(format, args...))
			c.mu.Unlock()
		},
	}
}

func (c *captureLog) snapshot() (verbose, errs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.verbose...), append([]string(nil), c.errs...)
}

func hasLine(lines []string, substr string) bool {
	for _, line := range lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

type gsoHandshakePair struct {
	devA, devB   *Device
	peerA, peerB *Peer // peerA: devB's key on devA; peerB: devA's key on devB
	log          *captureLog
}

// newGSOHandshakePair builds two peered devices that are never brought up
// (no timers, no routines; the response case brings devA up, see
// consumeInitiationFromB): devA sends through a gsoBind answering sendErr and
// logs into a captureLog; devB only produces an initiation for devA to answer.
func newGSOHandshakePair(t *testing.T, sendErr error) *gsoHandshakePair {
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

	rawA, rawB := newChanBindPair()
	log := &captureLog{}
	devA := NewDevice(context.Background(), newChanTun(), &gsoBind{chanBind: rawA, err: sendErr}, log.logger(), 1)
	devB := NewDevice(context.Background(), newChanTun(), rawB, NewLogger(LogLevelSilent, ""), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)

	cfgA := fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n",
		hex.EncodeToString(skA[:]), hex.EncodeToString(pkB[:]), testIPB)
	cfgB := fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n",
		hex.EncodeToString(skB[:]), hex.EncodeToString(pkA[:]), testIPA)
	if err := devA.IpcSet(cfgA); err != nil {
		t.Fatalf("IpcSet A: %v", err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		t.Fatalf("IpcSet B: %v", err)
	}

	peerA := devA.LookupPeer(pkB)
	peerB := devB.LookupPeer(pkA)
	if peerA == nil || peerB == nil {
		t.Fatal("peer lookup failed")
	}
	return &gsoHandshakePair{devA: devA, devB: devB, peerA: peerA, peerB: peerB, log: log}
}

// consumeInitiationFromB puts peerA into handshakeInitiationConsumed, the
// state SendHandshakeResponse needs. ConsumeMessageInitiation only answers a
// running peer, so devA is brought up here (devB stays down: nothing reaches
// devA's receive routine).
func (p *gsoHandshakePair) consumeInitiationFromB(t *testing.T) {
	t.Helper()
	if err := p.devA.Up(); err != nil {
		t.Fatalf("Up A: %v", err)
	}
	msg, err := p.devB.CreateMessageInitiation(p.peerB)
	if err != nil {
		t.Fatalf("CreateMessageInitiation: %v", err)
	}
	if got := p.devA.ConsumeMessageInitiation(msg, p.peerA.endpoint.val); got != p.peerA {
		t.Fatalf("ConsumeMessageInitiation returned %v, want %v", got, p.peerA)
	}
}

func TestLXHandshakeGSORetryLog(t *testing.T) {
	type sendPath struct {
		name    string
		failure string // the ERROR text of this path
		send    func(t *testing.T, p *gsoHandshakePair) error
	}
	paths := []sendPath{
		{
			name:    "initiation",
			failure: "Failed to send handshake initiation",
			send: func(t *testing.T, p *gsoHandshakePair) error {
				return p.peerA.SendHandshakeInitiation(true)
			},
		},
		{
			name:    "response",
			failure: "Failed to send handshake response",
			send: func(t *testing.T, p *gsoHandshakePair) error {
				p.consumeInitiationFromB(t)
				return p.peerA.SendHandshakeResponse()
			},
		},
	}
	const wrapperText = "disabled UDP GSO"

	for _, path := range paths {
		t.Run(path.name+"/retry-ok", func(t *testing.T) {
			p := newGSOHandshakePair(t, conn.ErrUDPGSODisabled{RetryErr: nil})
			if err := path.send(t, p); err != nil {
				t.Errorf("send returned %v, want nil (the resend went through)", err)
			}
			verbose, errs := p.log.snapshot()
			if !hasLine(verbose, wrapperText) {
				t.Errorf("no Verbose line with %q; verbose=%q", wrapperText, verbose)
			}
			if len(errs) != 0 {
				t.Errorf("successful resend logged at ERROR: %q", errs)
			}
		})
		t.Run(path.name+"/retry-failed", func(t *testing.T) {
			p := newGSOHandshakePair(t, conn.ErrUDPGSODisabled{RetryErr: io.ErrClosedPipe})
			if err := path.send(t, p); !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("send returned %v, want %v", err, io.ErrClosedPipe)
			}
			verbose, errs := p.log.snapshot()
			if !hasLine(verbose, wrapperText) {
				t.Errorf("no Verbose line with %q; verbose=%q", wrapperText, verbose)
			}
			if !hasLine(errs, path.failure) {
				t.Fatalf("no ERROR line with %q; errors=%q", path.failure, errs)
			}
			if !hasLine(errs, io.ErrClosedPipe.Error()) {
				t.Errorf("ERROR does not name the resend error %q: %q", io.ErrClosedPipe, errs)
			}
			if hasLine(errs, wrapperText) {
				t.Errorf("ERROR carries the GSO wrapper instead of the resend error: %q", errs)
			}
		})
	}
}

// TestLXUnwrapGSODisabled covers the helper the data path shares with the
// handshake paths.
func TestLXUnwrapGSODisabled(t *testing.T) {
	log := &captureLog{}
	logger := log.logger()
	plain := errors.New("plain send error")

	cases := []struct {
		name        string
		in, want    error
		wantVerbose bool
	}{
		{"nil", nil, nil, false},
		{"plain", plain, plain, false},
		{"gso-retry-ok", conn.ErrUDPGSODisabled{}, nil, true},
		{"gso-retry-failed", conn.ErrUDPGSODisabled{RetryErr: io.ErrClosedPipe}, io.ErrClosedPipe, true},
		{"gso-wrapped", fmt.Errorf("send: %w", conn.ErrUDPGSODisabled{RetryErr: io.ErrClosedPipe}), io.ErrClosedPipe, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, _ := log.snapshot()
			if got := unwrapGSODisabled(logger, tc.in); got != tc.want {
				t.Errorf("unwrapGSODisabled(%v) = %v, want %v", tc.in, got, tc.want)
			}
			after, errs := log.snapshot()
			if logged := len(after) > len(before); logged != tc.wantVerbose {
				t.Errorf("Verbose logged = %v, want %v", logged, tc.wantVerbose)
			}
			if len(errs) != 0 {
				t.Errorf("helper logged at ERROR: %q", errs)
			}
		})
	}
}
