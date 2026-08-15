package pulseclient

import (
	"encoding/binary"
	"testing"
)

// validV1Body returns a valid, minimal encoded v1 tx body (no TLV trailer),
// suitable as the positional prefix of a v2 MsgTx frame body.
func validV1Body(t *testing.T) []byte {
	t.Helper()
	return EncodeFullTx(sampleTx(false))
}

// appendTLV appends one `u8 type | u16 LE len | value` record to buf.
func appendTLV(buf []byte, typ uint8, value []byte) []byte {
	buf = append(buf, typ)
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], uint16(len(value)))
	buf = append(buf, l[:]...)
	buf = append(buf, value...)
	return buf
}

func TestPreambleIsSixBytesNonZeroFirst(t *testing.T) {
	if len(Preamble) != 6 {
		t.Fatalf("want 6, got %d", len(Preamble))
	}
	if Preamble[0] == 0x00 {
		t.Fatal("first byte must be non-zero: a v1 stream always starts 0x00")
	}
}

func TestPreambleMatchesDocumentedBytes(t *testing.T) {
	want := "PLS2\x02\x00"
	if Preamble != want {
		t.Fatalf("Preamble = %v, want %v", Preamble, want)
	}
}

func TestDatagramMinimumLengthNotExact(t *testing.T) {
	buf := make([]byte, DGSigFirstMin+8) // 8 trailing bytes
	buf[0] = DGSigFirst
	binary.LittleEndian.PutUint64(buf[1:9], 42)
	binary.LittleEndian.PutUint64(buf[9:17], 7)
	d, err := DecodeDatagram(buf)
	if err != nil {
		t.Fatalf("trailing bytes must be ignored: %v", err)
	}
	sf, ok := d.(SigFirst)
	if !ok || sf.Slot != 42 || sf.Seq != 7 {
		t.Fatalf("bad decode: %+v", d)
	}
}

func TestDatagramBelowMinimumIsRejected(t *testing.T) {
	buf := make([]byte, DGSigFirstMin)
	buf[0] = DGSigFirst
	if _, err := DecodeDatagram(buf[:DGSigFirstMin-1]); err == nil {
		t.Fatal("expected error for a sig-first datagram one byte short of the minimum")
	}

	hb := make([]byte, DGHeartbeatMin)
	hb[0] = DGHeartbeat
	if _, err := DecodeDatagram(hb[:DGHeartbeatMin-1]); err == nil {
		t.Fatal("expected error for a heartbeat datagram one byte short of the minimum")
	}

	if _, err := DecodeDatagram(nil); err == nil {
		t.Fatal("expected error for an empty datagram")
	}
}

func TestDatagramHeartbeatMinimumLengthNotExact(t *testing.T) {
	buf := make([]byte, DGHeartbeatMin+3)
	buf[0] = DGHeartbeat
	binary.LittleEndian.PutUint64(buf[1:9], 123)
	binary.LittleEndian.PutUint64(buf[9:17], 456)
	d, err := DecodeDatagram(buf)
	if err != nil {
		t.Fatalf("trailing bytes must be ignored: %v", err)
	}
	hb, ok := d.(DatagramHeartbeat)
	if !ok || hb.ServerTsMs != 123 || hb.HighestSeq != 456 {
		t.Fatalf("bad decode: %+v", d)
	}
}

func TestDatagramUnknownTypeIsSkippedNotAnError(t *testing.T) {
	d, err := DecodeDatagram([]byte{200, 1, 2, 3})
	if err != nil {
		t.Fatalf("unknown datagram type must not error: %v", err)
	}
	u, ok := d.(UnknownDatagram)
	if !ok || u.Type != 200 {
		t.Fatalf("bad decode: %+v", d)
	}
}

func TestUnknownTLVIsSkippedDuplicateIsRejected(t *testing.T) {
	// unknown type 200 must be skipped
	frame := append([]byte{MsgTx, 0}, validV1Body(t)...)
	frame = appendTLV(frame, 200, []byte{1, 2, 3})
	if _, err := DecodeFrame(frame); err != nil {
		t.Fatalf("unknown TLV must be skipped: %v", err)
	}
	// duplicate must be rejected
	dup := append([]byte{MsgTx, 0}, validV1Body(t)...)
	dup = appendTLV(dup, TLVLoadedWritable, make([]byte, 32))
	dup = appendTLV(dup, TLVLoadedWritable, make([]byte, 32))
	if _, err := DecodeFrame(dup); err == nil {
		t.Fatal("duplicate TLV type must be rejected")
	}
}

func TestDecodeFrameTxRoundTripsEnrichment(t *testing.T) {
	frame := append([]byte{MsgTx, FlagAltIncomplete}, validV1Body(t)...)
	w := [][32]byte{{0x11}, {0x22}}
	r := [][32]byte{{0x33}}
	var wf, rf []byte
	for _, a := range w {
		wf = append(wf, a[:]...)
	}
	for _, a := range r {
		rf = append(rf, a[:]...)
	}
	frame = appendTLV(frame, TLVLoadedWritable, wf)
	frame = appendTLV(frame, TLVLoadedReadonly, rf)

	f, err := DecodeFrame(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	v2, ok := f.(FullTxV2)
	if !ok {
		t.Fatalf("expected FullTxV2, got %T", f)
	}
	if !v2.AltIncomplete {
		t.Fatal("expected alt_incomplete flag set")
	}
	if len(v2.LoadedWritable) != 2 || v2.LoadedWritable[0] != w[0] || v2.LoadedWritable[1] != w[1] {
		t.Fatalf("loaded_writable mismatch: %+v", v2.LoadedWritable)
	}
	if len(v2.LoadedReadonly) != 1 || v2.LoadedReadonly[0] != r[0] {
		t.Fatalf("loaded_readonly mismatch: %+v", v2.LoadedReadonly)
	}
}

func TestDecodeFrameTxBareHasNoEnrichment(t *testing.T) {
	frame := append([]byte{MsgTx, 0}, validV1Body(t)...)
	f, err := DecodeFrame(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	v2, ok := f.(FullTxV2)
	if !ok {
		t.Fatalf("expected FullTxV2, got %T", f)
	}
	if v2.AltIncomplete {
		t.Fatal("no flag set, expected alt_incomplete=false")
	}
	if len(v2.LoadedWritable) != 0 || len(v2.LoadedReadonly) != 0 {
		t.Fatalf("expected no enrichment: %+v", v2)
	}
}

func TestDecodeFrameUnknownMsgTypeIsSkippedNotAnError(t *testing.T) {
	frame := []byte{99, 0}
	f, err := DecodeFrame(frame)
	if err != nil {
		t.Fatalf("unknown msg_type must not error: %v", err)
	}
	u, ok := f.(UnknownFrame)
	if !ok || u.Type != 99 {
		t.Fatalf("expected UnknownFrame(99), got %+v", f)
	}
}

func TestDecodeFrameHeartbeatRoundTrips(t *testing.T) {
	var b []byte
	b = append(b, MsgHeartbeat, 0)
	var ts, seq [8]byte
	binary.LittleEndian.PutUint64(ts[:], 1_700_000_000_123)
	binary.LittleEndian.PutUint64(seq[:], 4242)
	b = appendTLV(b, TLVServerTsMs, ts[:])
	b = appendTLV(b, TLVHighestSeq, seq[:])

	f, err := DecodeFrame(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	hb, ok := f.(FrameHeartbeat)
	if !ok {
		t.Fatalf("expected FrameHeartbeat, got %T", f)
	}
	if hb.ServerTsMs != 1_700_000_000_123 || hb.HighestSeq != 4242 {
		t.Fatalf("bad heartbeat decode: %+v", hb)
	}
}

func TestDecodeFrameHeartbeatRejectsAnyNonZeroFlags(t *testing.T) {
	for _, flags := range []uint8{FlagAltIncomplete, 0x02, 0xFF} {
		var b []byte
		b = append(b, MsgHeartbeat, flags)
		var ts [8]byte
		b = appendTLV(b, TLVServerTsMs, ts[:])
		if _, err := DecodeFrame(b); err == nil {
			t.Fatalf("flags=%#x: expected error, heartbeat reserves all 8 bits", flags)
		}
	}
}

func TestDecodeFrameTxRejectsReservedFlagBits(t *testing.T) {
	frame := append([]byte{MsgTx, 0x02}, validV1Body(t)...) // bit 1 reserved
	if _, err := DecodeFrame(frame); err == nil {
		t.Fatal("expected error for reserved flag bit on MsgTx")
	}
}

func TestDecodeFrameTooShortIsRejected(t *testing.T) {
	if _, err := DecodeFrame(nil); err == nil {
		t.Fatal("expected error for empty frame")
	}
	if _, err := DecodeFrame([]byte{MsgTx}); err == nil {
		t.Fatal("expected error for a frame missing the flags byte")
	}
}

func TestDecodeFrameLoadedAddressTLVNonMultipleOf32IsRejected(t *testing.T) {
	frame := append([]byte{MsgTx, 0}, validV1Body(t)...)
	frame = appendTLV(frame, TLVLoadedWritable, make([]byte, 33))
	if _, err := DecodeFrame(frame); err == nil {
		t.Fatal("expected error for a loaded-address TLV whose length is not a multiple of 32")
	}
}
