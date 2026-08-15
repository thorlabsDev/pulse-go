package pulseclient

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// writeFramed writes one length-delimited frame (u32 BE length + body) to buf.
func writeFramed(buf *bytes.Buffer, body []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(body)))
	buf.Write(l[:])
	buf.Write(body)
}

func TestNextFrameSkipsUnknownAndFoldsHeartbeatWithoutSurfacingIt(t *testing.T) {
	var buf bytes.Buffer

	// Frame 1: an unknown message type (99) — must be skipped, not error.
	writeFramed(&buf, []byte{99, 0})

	// Frame 2: a heartbeat — must update *hb, not be returned.
	var hbFrame []byte
	hbFrame = append(hbFrame, MsgHeartbeat, 0)
	var ts, seq [8]byte
	binary.LittleEndian.PutUint64(ts[:], 123)
	binary.LittleEndian.PutUint64(seq[:], 7)
	hbFrame = appendTLV(hbFrame, TLVServerTsMs, ts[:])
	hbFrame = appendTLV(hbFrame, TLVHighestSeq, seq[:])
	writeFramed(&buf, hbFrame)

	// Frame 3: a real (bare) tx frame — what nextFrame must finally return.
	txFrame := append([]byte{MsgTx, 0}, validV1Body(t)...)
	writeFramed(&buf, txFrame)

	var hb heartbeatState
	got, err := nextFrame(&buf, &hb)
	if err != nil {
		t.Fatalf("nextFrame: %v", err)
	}
	if got == nil {
		t.Fatal("expected a FullTxV2, got nil")
	}
	if got.Tx.Slot != sampleTx(false).Slot {
		t.Fatalf("wrong tx returned: %+v", got.Tx)
	}
	if !hb.ok || hb.serverTsMs != 123 || hb.highestSeq != 7 {
		t.Fatalf("heartbeat must be captured via *hb, not returned as an item: %+v", hb)
	}
}

func TestNextFrameReturnsEOFAtACleanEndOfStream(t *testing.T) {
	var hb heartbeatState
	got, err := nextFrame(bytes.NewReader(nil), &hb)
	if err != io.EOF {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if got != nil {
		t.Fatalf("got = %v, want nil", got)
	}
}

func TestNextFrameRejectsATruncatedLengthPrefix(t *testing.T) {
	var hb heartbeatState
	// Two bytes of a four-byte length prefix, then EOF: a real boundary was
	// never reached, so this must be a loud error, not a clean end.
	_, err := nextFrame(bytes.NewReader([]byte{0, 0}), &hb)
	if err != ErrBadFrame {
		t.Fatalf("err = %v, want ErrBadFrame", err)
	}
}

func TestNextFrameRejectsATruncatedBody(t *testing.T) {
	var hb heartbeatState
	var buf bytes.Buffer
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], 10) // declares 10 bytes, supplies fewer
	buf.Write(l[:])
	buf.Write([]byte{1, 2, 3})
	if _, err := nextFrame(&buf, &hb); err != ErrBadFrame {
		t.Fatalf("err = %v, want ErrBadFrame", err)
	}
}

// ---- preamble: loud failure, never a silent skip --------------------------

func TestVerifyPreambleAcceptsTheRealPreamble(t *testing.T) {
	if err := verifyPreamble(bytes.NewReader([]byte(Preamble))); err != nil {
		t.Fatalf("verifyPreamble: %v", err)
	}
}

func TestVerifyPreambleRejectsAMismatchedHeaderLoudly(t *testing.T) {
	err := verifyPreamble(bytes.NewReader([]byte("XXXXXX")))
	if err != ErrBadPreamble {
		t.Fatalf("err = %v, want ErrBadPreamble", err)
	}
}

func TestVerifyPreambleRejectsAShortStreamLoudly(t *testing.T) {
	err := verifyPreamble(bytes.NewReader(nil))
	if err != ErrBadPreamble {
		t.Fatalf("err = %v, want ErrBadPreamble", err)
	}
}
