package pulseclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// writeAckFramed writes one length-delimited ack envelope (u32 BE length +
// JSON body) to buf — the same framing readAck expects.
func writeAckFramed(buf *bytes.Buffer, json string) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(json)))
	buf.Write(l[:])
	buf.WriteString(json)
}

func intPtr(v int) *int { return &v }

// ---- readAck: framing and canonical control-envelope shapes --------------

func TestReadAckParsesTheFirstMessageSuccessEnvelopeWithVersion(t *testing.T) {
	var buf bytes.Buffer
	writeAckFramed(&buf, `{"type": "ack", "ok": true, "v": 2}`)

	ack, err := readAck(&buf)
	if err != nil {
		t.Fatalf("readAck: %v", err)
	}
	if !ack.OK {
		t.Fatal("expected ok=true")
	}
	if ack.V == nil || *ack.V != 2 {
		t.Fatalf("V = %v, want 2", ack.V)
	}
}

func TestReadAckParsesARejectionEnvelopeWithReason(t *testing.T) {
	var buf bytes.Buffer
	writeAckFramed(&buf, `{"type":"ack","ok":false,"reason":"invalid control message"}`)

	ack, err := readAck(&buf)
	if err != nil {
		t.Fatalf("readAck: %v", err)
	}
	if ack.OK {
		t.Fatal("expected ok=false")
	}
	if ack.Reason != "invalid control message" {
		t.Fatalf("Reason = %q, want %q", ack.Reason, "invalid control message")
	}
}

func TestReadAckParsesAnUpdateSuccessEnvelopeWithoutVersion(t *testing.T) {
	var buf bytes.Buffer
	writeAckFramed(&buf, `{"type":"ack","ok":true}`)

	ack, err := readAck(&buf)
	if err != nil {
		t.Fatalf("readAck: %v", err)
	}
	if !ack.OK {
		t.Fatal("expected ok=true")
	}
	if ack.V != nil {
		t.Fatalf("V = %v, want nil (update acks carry no version)", *ack.V)
	}
}

func TestReadAckRejectsAnOversizedLengthPrefix(t *testing.T) {
	var buf bytes.Buffer
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], maxAckBytes+1)
	buf.Write(l[:])
	if _, err := readAck(&buf); err != ErrBadFrame {
		t.Fatalf("err = %v, want ErrBadFrame", err)
	}
}

func TestReadAckRejectsATruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], 20) // declares 20 bytes, supplies fewer
	buf.Write(l[:])
	buf.WriteString(`{"ok":true`)
	if _, err := readAck(&buf); err == nil {
		t.Fatal("expected an error for a truncated ack body")
	}
}

func TestReadAckRejectsAnUnknownEnvelopeType(t *testing.T) {
	var buf bytes.Buffer
	writeAckFramed(&buf, `{"type":"future","ok":true}`)
	if _, err := readAck(&buf); err != ErrBadFrame {
		t.Fatalf("err = %v, want ErrBadFrame", err)
	}
}

func TestReadAckRejectsAMissingEnvelopeType(t *testing.T) {
	var buf bytes.Buffer
	writeAckFramed(&buf, `{"ok":true,"v":2}`)
	if _, err := readAck(&buf); err != ErrBadFrame {
		t.Fatalf("err = %v, want ErrBadFrame", err)
	}
}

func TestCheckAckRejectsAnErrorEnvelopeWithoutACode(t *testing.T) {
	if _, err := checkAckEnvelope(&Ack{Type: "error", Reason: "missing code"}); err != ErrBadFrame {
		t.Fatalf("err = %v, want ErrBadFrame", err)
	}
}

// ---- checkAck: rejection surfaces the reason, success does not ------------

func TestCheckAckSurfacesARejectionWithItsReason(t *testing.T) {
	_, err := checkAckEnvelope(&Ack{Type: "ack", OK: false, Reason: "bad token"})
	if err == nil {
		t.Fatal("expected an error for ok=false")
	}
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("err = %v (%T), want *RejectedError", err, err)
	}
	if rej.Reason != "bad token" {
		t.Fatalf("Reason = %q, want %q", rej.Reason, "bad token")
	}
}

func TestCheckAckSucceedsOnAnOKAckAndDoesNotError(t *testing.T) {
	ack, err := checkInitialAck(&Ack{Type: "ack", OK: true, V: intPtr(WireVersion)})
	if err != nil {
		t.Fatalf("checkAck: %v", err)
	}
	if ack == nil || !ack.OK {
		t.Fatalf("ack = %+v, want ok=true", ack)
	}
}

func TestCheckAckSucceedsOnAnUpdateAckWithNoVersion(t *testing.T) {
	if _, err := checkUpdateAck(&Ack{Type: "ack", OK: true}); err != nil {
		t.Fatalf("checkUpdateAck: %v", err)
	}
}

func TestInitialAckRequiresANegotiatedVersion(t *testing.T) {
	_, err := checkInitialAck(&Ack{Type: "ack", OK: true})
	if !errors.Is(err, ErrMissingNegotiatedVersion) {
		t.Fatalf("err = %v, want ErrMissingNegotiatedVersion", err)
	}
}

func TestUpdateAckAcceptsMatchingVersionAndRejectsConflict(t *testing.T) {
	if _, err := checkUpdateAck(&Ack{Type: "ack", OK: true, V: intPtr(WireVersion)}); err != nil {
		t.Fatalf("matching update version: %v", err)
	}
	_, err := checkUpdateAck(&Ack{Type: "ack", OK: true, V: intPtr(WireVersion + 1)})
	var mismatch *VersionMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want VersionMismatchError", err)
	}
}

func TestSuccessfulAckRequiresAckEnvelopeType(t *testing.T) {
	if _, err := checkInitialAck(&Ack{OK: true, V: intPtr(WireVersion)}); !errors.Is(err, ErrBadFrame) {
		t.Fatalf("initial err = %v, want ErrBadFrame", err)
	}
	if _, err := checkUpdateAck(&Ack{OK: true}); !errors.Is(err, ErrBadFrame) {
		t.Fatalf("update err = %v, want ErrBadFrame", err)
	}
}

func TestAckEnvelopeRejectsAnApplicationCode(t *testing.T) {
	code := CloseUnsupportedVersion
	if _, err := checkInitialAck(&Ack{Type: "ack", OK: true, Code: &code, V: intPtr(WireVersion)}); !errors.Is(err, ErrBadFrame) {
		t.Fatalf("err = %v, want ErrBadFrame", err)
	}
}

func TestCheckAckSurfacesAVersionMismatchOnTheFirstAck(t *testing.T) {
	_, err := checkInitialAck(&Ack{Type: "ack", OK: true, V: intPtr(1)})
	if err == nil {
		t.Fatal("expected an error for a negotiated version this SDK does not speak")
	}
	var vm *VersionMismatchError
	if !errors.As(err, &vm) {
		t.Fatalf("err = %v (%T), want *VersionMismatchError", err, err)
	}
	if vm.Negotiated != 1 {
		t.Fatalf("Negotiated = %d, want 1", vm.Negotiated)
	}
}
