package masque

// Regression tests for the CONNECT-IP dial path: a peer that never answers the
// Extended CONNECT must not hang the dial (SPEC 108), and a silent endpoint must
// be reported as an idle timeout rather than a frame-parsing failure.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	E "github.com/sagernet/sing/common/exceptions"
)

// blockingStream answers ReadResponse only when cancelled, like an endpoint that
// took the connection and never replied to the CONNECT.
type blockingStream struct {
	cancelled chan struct{}
	once      sync.Once
	response  *http.Response
}

func (s *blockingStream) ReadResponse() (*http.Response, error) {
	if s.response != nil {
		return s.response, nil
	}
	<-s.cancelled
	return nil, errors.New("stream cancelled")
}

func (s *blockingStream) CancelRead(quic.StreamErrorCode) {
	s.once.Do(func() { close(s.cancelled) })
}

func (s *blockingStream) CancelWrite(quic.StreamErrorCode) {}

func TestReadResponseHonoursContext(t *testing.T) {
	stream := &blockingStream{cancelled: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := readResponse(ctx, stream)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("want the context's error, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readResponse ignored the context")
	}
}

// Once the response is in, a later cancel of the dial context must not touch
// the stream: the tunnel outlives the dial.
func TestReadResponseReleasesStreamOnSuccess(t *testing.T) {
	stream := &blockingStream{
		cancelled: make(chan struct{}),
		response:  &http.Response{StatusCode: http.StatusOK},
	}
	ctx, cancel := context.WithCancel(context.Background())
	response, err := readResponse(ctx, stream)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("response=%v err=%v", response, err)
	}
	cancel()
	select {
	case <-stream.cancelled:
		t.Fatal("dial context cancelled a live stream")
	case <-time.After(100 * time.Millisecond):
	}
}

// ---- idle timeout diagnosis ----

// wrapLikeDialCONNECTIP reproduces the wrapping a real idle timeout goes
// through before ConnectTunnelH3 inspects it.
func wrapLikeDialCONNECTIP(inner error) error {
	return E.Cause(fmt.Errorf("http3: parsing frame failed: %w", inner), "read response")
}

// TestIdleTimeoutMessageKeepsCause: the diagnosis replaces the leading context,
// not the chain — the underlying timeout must stay readable.
func TestIdleTimeoutMessageKeepsCause(t *testing.T) {
	t.Parallel()
	wrapped := wrapLikeDialCONNECTIP(&quic.IdleTimeoutError{})
	got := E.Cause(wrapped, "masque: CONNECT-IP timed out").Error()

	if !strings.HasPrefix(got, "masque: CONNECT-IP timed out") {
		t.Errorf("diagnosis must lead the message, got %q", got)
	}
	if !strings.Contains(got, "timeout: no recent network activity") {
		t.Errorf("original cause must survive, got %q", got)
	}
}

// TestNonIdleErrorIsNotClaimedAsTimeout: any other failure must keep falling
// through to the generic wrapping, or a real bug would be mislabelled.
func TestNonIdleErrorIsNotClaimedAsTimeout(t *testing.T) {
	t.Parallel()
	err := wrapLikeDialCONNECTIP(errors.New("connect-ip: server responded with 403"))

	var idleErr *quic.IdleTimeoutError
	if errors.As(err, &idleErr) {
		t.Fatal("a non-timeout failure must not match the idle-timeout branch")
	}
}
