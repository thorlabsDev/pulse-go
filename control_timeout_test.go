package pulseclient

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type scriptedControlConnection struct {
	quic.Connection
	stream quic.Stream
}

func (c *scriptedControlConnection) OpenStreamSync(context.Context) (quic.Stream, error) {
	return c.stream, nil
}

type scriptedControlStream struct {
	quic.Stream
	response *bytes.Reader
}

func (s *scriptedControlStream) Read(dst []byte) (int, error) {
	return s.response.Read(dst)
}

func (s *scriptedControlStream) Write(src []byte) (int, error)    { return len(src), nil }
func (s *scriptedControlStream) Close() error                     { return nil }
func (s *scriptedControlStream) SetWriteDeadline(time.Time) error { return nil }
func (s *scriptedControlStream) SetReadDeadline(time.Time) error  { return nil }

type deadlineBlockingConnection struct {
	quic.Connection
	deadline time.Time
}

func (c *deadlineBlockingConnection) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("control stream context has no deadline")
	}
	c.deadline = deadline
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestAckTimeoutBoundsControlStreamOpening(t *testing.T) {
	const timeout = 30 * time.Millisecond
	conn := &deadlineBlockingConnection{}
	started := time.Now()
	_, err := controlRoundTrip(
		context.Background(),
		conn,
		"token",
		Accounts("account"),
		false,
		nil,
		true,
		timeout,
	)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if conn.deadline.IsZero() {
		t.Fatal("OpenStreamSync did not receive a bounded context")
	}
	if elapsed < timeout/2 || elapsed > time.Second {
		t.Fatalf("control stream open elapsed = %v, want approximately %v and definitely bounded", elapsed, timeout)
	}
}

func TestInitialControlRoundTripRejectsSuccessWithoutVersion(t *testing.T) {
	var framed bytes.Buffer
	writeAckFramed(&framed, `{"type":"ack","ok":true}`)
	stream := &scriptedControlStream{response: bytes.NewReader(framed.Bytes())}
	client := &Client{
		conn:       &scriptedControlConnection{stream: stream},
		token:      "token",
		ackTimeout: time.Second,
	}

	_, err := client.sendControl(context.Background(), Accounts("account"), false, nil)
	if !errors.Is(err, ErrMissingNegotiatedVersion) {
		t.Fatalf("err = %v, want ErrMissingNegotiatedVersion", err)
	}
}
