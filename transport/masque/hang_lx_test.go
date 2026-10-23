package masque

// lx: SPEC 108 — a CONNECT-IP dial must not hang on a peer that took the
// connection and never answered the Extended CONNECT request.

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
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
