package pulseclient

import (
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"
)

// ApplicationCloseCode is a Pulse QUIC application close code.
type ApplicationCloseCode uint64

const (
	CloseNormal             ApplicationCloseCode = 0
	CloseInvalidControl     ApplicationCloseCode = 1
	CloseUnauthenticated    ApplicationCloseCode = 2
	CloseQuotaExceeded      ApplicationCloseCode = 3
	CloseUnsupportedVersion ApplicationCloseCode = 4
	CloseTierNotEntitled    ApplicationCloseCode = 5
)

// RetryClass describes what must change before reconnecting after a terminal
// Pulse error.
type RetryClass uint8

const (
	// RetryUnknown means the server used an application close code this SDK
	// doesn't recognize. Callers should fail closed instead of looping.
	RetryUnknown RetryClass = iota
	// RetryNormal means the peer closed normally. Reconnect only when the
	// application intends to continue consuming the feed.
	RetryNormal
	// RetryNever means an unchanged reconnect cannot succeed. It covers invalid
	// control messages, unsupported protocol versions, and tier entitlement.
	RetryNever
	// RetryAfterCredentialChange means the token must be supplied, replaced, or
	// re-authorized before reconnecting.
	RetryAfterCredentialChange
	// RetryTransient means the same request may be retried with bounded backoff.
	RetryTransient
)

func (r RetryClass) String() string {
	switch r {
	case RetryNormal:
		return "normal"
	case RetryNever:
		return "never"
	case RetryAfterCredentialChange:
		return "after-credential-change"
	case RetryTransient:
		return "transient"
	default:
		return "unknown"
	}
}

// CloseInfo is the structured information carried by a QUIC application
// close. Retry is derived from Code, not from the human-readable Reason.
type CloseInfo struct {
	Code   ApplicationCloseCode
	Reason string
	Remote bool
	Retry  RetryClass
}

// Retryable reports whether an unchanged request may be retried. It is true
// only for transient quota exhaustion (code 3). Code 2 requires a credential
// correction first; codes 1, 4, and 5 must not be retried unchanged.
func (c CloseInfo) Retryable() bool { return c.Retry == RetryTransient }

// NeedsCredentialChange reports whether reconnecting requires a corrected or
// newly-authorized token.
func (c CloseInfo) NeedsCredentialChange() bool {
	return c.Retry == RetryAfterCredentialChange
}

// TerminalError is returned when a Pulse QUIC connection ends with an
// application close. It is never collapsed to io.EOF. Use errors.As to access
// CloseInfo and make a reconnect decision.
type TerminalError struct {
	CloseInfo
	cause error
}

func (e *TerminalError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("pulseclient: connection closed with application code %d (retry=%s)", e.Code, e.Retry)
	}
	return fmt.Sprintf("pulseclient: connection closed with application code %d: %s (retry=%s)", e.Code, e.Reason, e.Retry)
}

func (e *TerminalError) Unwrap() error { return e.cause }

// CloseInfoFromError returns Pulse close information from err, including when
// the terminal error has been wrapped with operation context.
func CloseInfoFromError(err error) (CloseInfo, bool) {
	var terminal *TerminalError
	if !errors.As(err, &terminal) {
		return CloseInfo{}, false
	}
	return terminal.CloseInfo, true
}

// ClassifyCloseCode returns the reconnect policy for a Pulse application
// close code. Unknown codes fail closed and return RetryUnknown.
func ClassifyCloseCode(code ApplicationCloseCode) RetryClass {
	switch code {
	case CloseNormal:
		return RetryNormal
	case CloseInvalidControl, CloseUnsupportedVersion, CloseTierNotEntitled:
		return RetryNever
	case CloseUnauthenticated:
		return RetryAfterCredentialChange
	case CloseQuotaExceeded:
		return RetryTransient
	default:
		return RetryUnknown
	}
}

func mapTerminalError(err error) error {
	if err == nil {
		return nil
	}
	var terminal *TerminalError
	if errors.As(err, &terminal) {
		return err
	}
	var appErr *quic.ApplicationError
	if !errors.As(err, &appErr) {
		return err
	}
	code := ApplicationCloseCode(appErr.ErrorCode)
	return &TerminalError{
		CloseInfo: CloseInfo{
			Code:   code,
			Reason: appErr.ErrorMessage,
			Remote: appErr.Remote,
			Retry:  ClassifyCloseCode(code),
		},
		cause: appErr,
	}
}

func wrapConnectionError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("pulseclient: %s: %w", operation, mapTerminalError(err))
}
