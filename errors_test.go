package pulseclient

import (
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestCloseCodeRetryClassification(t *testing.T) {
	tests := []struct {
		code      ApplicationCloseCode
		want      RetryClass
		retryable bool
		needsCred bool
	}{
		{CloseNormal, RetryNormal, false, false},
		{CloseInvalidControl, RetryNever, false, false},
		{CloseUnauthenticated, RetryAfterCredentialChange, false, true},
		{CloseQuotaExceeded, RetryTransient, true, false},
		{CloseUnsupportedVersion, RetryNever, false, false},
		{CloseTierNotEntitled, RetryNever, false, false},
		{99, RetryUnknown, false, false},
	}
	for _, tt := range tests {
		info := CloseInfo{Code: tt.code, Retry: ClassifyCloseCode(tt.code)}
		if info.Retry != tt.want || info.Retryable() != tt.retryable || info.NeedsCredentialChange() != tt.needsCred {
			t.Fatalf("code %d: info=%+v retryable=%v needsCred=%v", tt.code, info, info.Retryable(), info.NeedsCredentialChange())
		}
	}
}

func TestApplicationCloseMapsToTypedTerminalError(t *testing.T) {
	appErr := &quic.ApplicationError{
		Remote:       true,
		ErrorCode:    quic.ApplicationErrorCode(CloseQuotaExceeded),
		ErrorMessage: "tier at capacity",
	}
	err := wrapConnectionError("receive datagram", appErr)

	var terminal *TerminalError
	if !errors.As(err, &terminal) {
		t.Fatalf("err = %v (%T), want *TerminalError", err, err)
	}
	if terminal.Code != CloseQuotaExceeded || terminal.Reason != "tier at capacity" || !terminal.Remote || terminal.Retry != RetryTransient {
		t.Fatalf("terminal = %+v", terminal.CloseInfo)
	}
	if !errors.Is(err, appErr) {
		t.Fatal("TerminalError must retain the underlying quic.ApplicationError")
	}
	info, ok := CloseInfoFromError(err)
	if !ok || info != terminal.CloseInfo {
		t.Fatalf("CloseInfoFromError = %+v, %v", info, ok)
	}
}

func TestTerminalErrorsAreNotCollapsedBySubscriptionReaders(t *testing.T) {
	appErr := &quic.ApplicationError{
		Remote:       true,
		ErrorCode:    quic.ApplicationErrorCode(CloseTierNotEntitled),
		ErrorMessage: "tier cannot use this filter",
	}
	reader := errorReader{err: appErr}

	var hb heartbeatState
	if _, err := nextFrame(reader, &hb); !isTerminalCode(err, CloseTierNotEntitled) {
		t.Fatalf("nextFrame err = %v, want typed code 5", err)
	} else if errors.Is(err, ErrBadFrame) {
		t.Fatal("application close exactly at a frame boundary is not a truncated frame")
	}
	if err := verifyPreamble(reader); !isTerminalCode(err, CloseTierNotEntitled) {
		t.Fatalf("verifyPreamble err = %v, want typed code 5", err)
	}
	if _, err := readAck(reader); !isTerminalCode(err, CloseTierNotEntitled) {
		t.Fatalf("readAck err = %v, want typed code 5", err)
	}
}

func TestPartialFrameApplicationClosePreservesMalformedAndCloseSignals(t *testing.T) {
	appErr := &quic.ApplicationError{
		Remote:       true,
		ErrorCode:    quic.ApplicationErrorCode(CloseUnauthenticated),
		ErrorMessage: "token revoked",
	}
	var bodyPrefix [4]byte
	binary.BigEndian.PutUint32(bodyPrefix[:], 4)

	tests := []struct {
		name string
		data []byte
	}{
		{name: "partial length prefix", data: []byte{0, 0}},
		{name: "partial frame body", data: append(bodyPrefix[:], 1, 2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &bytesThenErrorReader{data: append([]byte(nil), tt.data...), err: appErr}
			var heartbeat heartbeatState
			_, err := nextFrame(reader, &heartbeat)
			if !errors.Is(err, ErrBadFrame) {
				t.Fatalf("err = %v, want ErrBadFrame", err)
			}
			if !isTerminalCode(err, CloseUnauthenticated) {
				t.Fatalf("err = %v, want typed close code 2", err)
			}
		})
	}
}

func TestPartialPreambleApplicationClosePreservesBothSignals(t *testing.T) {
	appErr := &quic.ApplicationError{
		Remote:       true,
		ErrorCode:    quic.ApplicationErrorCode(CloseUnsupportedVersion),
		ErrorMessage: "unsupported version",
	}
	reader := &bytesThenErrorReader{data: []byte("PLS"), err: appErr}
	err := verifyPreamble(reader)
	if !errors.Is(err, ErrBadPreamble) {
		t.Fatalf("err = %v, want ErrBadPreamble", err)
	}
	if !isTerminalCode(err, CloseUnsupportedVersion) {
		t.Fatalf("err = %v, want typed close code 4", err)
	}
}

func TestSigFirstDrainPreservesTerminalClose(t *testing.T) {
	appErr := &quic.ApplicationError{
		Remote:       true,
		ErrorCode:    quic.ApplicationErrorCode(CloseUnauthenticated),
		ErrorMessage: "token revoked",
	}
	sub := newSigFirstSub(1, func() ([]byte, error) { return nil, appErr })
	_, err := sub.Next(testContext(t))
	if !isTerminalCode(err, CloseUnauthenticated) {
		t.Fatalf("Next err = %v, want typed code 2", err)
	}
	if errors.Is(err, io.EOF) {
		t.Fatal("application close must not be collapsed to io.EOF")
	}
}

func TestStructuredVersionErrorAckMapsToTerminalError(t *testing.T) {
	code := CloseUnsupportedVersion
	_, err := checkInitialAck(&Ack{
		Type:   "error",
		Code:   &code,
		Reason: "unsupported protocol version",
	})
	if !isTerminalCode(err, CloseUnsupportedVersion) {
		t.Fatalf("checkAck err = %v, want typed code 4", err)
	}
	info, _ := CloseInfoFromError(err)
	if !info.Remote || info.Retry != RetryNever {
		t.Fatalf("info = %+v", info)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type bytesThenErrorReader struct {
	data []byte
	err  error
}

func (r *bytesThenErrorReader) Read(dst []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(dst, r.data)
	r.data = r.data[n:]
	return n, nil
}

func isTerminalCode(err error, code ApplicationCloseCode) bool {
	info, ok := CloseInfoFromError(err)
	return ok && info.Code == code
}
