package pulseclient

import (
	"encoding/binary"
	"errors"
)

// ErrBadFrame is returned when a full-tx body, v2 frame, or v2 datagram does
// not match the documented layout (truncated, oversized, or malformed).
var ErrBadFrame = errors.New("pulseclient: malformed full-tx frame")

// Instruction is a compiled instruction within a transaction.
type Instruction struct {
	ProgramIDIndex uint32
	Accounts       []byte
	Data           []byte
}

// AddressTableLookup is a v0 address-table lookup.
type AddressTableLookup struct {
	AccountKey      [32]byte
	WritableIndexes []byte
	ReadonlyIndexes []byte
}

// FullTx is a fully-decoded transaction (the full-tx tier payload).
type FullTx struct {
	Slot                       uint64
	Versioned                  bool
	NumRequiredSignatures      uint32
	NumReadonlySignedAccounts  uint32
	NumReadonlyUnsignedAccount uint32
	RecentBlockhash            [32]byte
	Signatures                 [][64]byte
	AccountKeys                [][32]byte
	Instructions               []Instruction
	AddressTableLookups        []AddressTableLookup
}

// MaxFullTxBody is the 64 KiB cap applied after a v2 frame's message-type and
// flags bytes. For a v2 transaction this includes the positional transaction
// payload and its complete TLV trailer; DecodeFullTx applies the same cap to a
// standalone positional body.
const MaxFullTxBody = 1 << 16

// DecodeFullTx decodes a full-tx body. It is strict: bounds-checked, rejects
// truncation and trailing garbage, and never panics.
func DecodeFullTx(b []byte) (*FullTx, error) {
	ft, consumed, err := decodeFullTxPrefix(b)
	if err != nil {
		return nil, err
	}
	if consumed != len(b) {
		return nil, ErrBadFrame // exact consumption
	}
	return ft, nil
}

// decodeFullTxPrefix decodes a FullTx body from the front of b and returns
// the cursor offset just past it, without requiring b to be fully consumed.
// This lets a v2 frame decode the positional body and then treat whatever
// follows as a TLV trailer. DecodeFullTx wraps this and enforces exact
// consumption for the plain positional case.
func decodeFullTxPrefix(b []byte) (*FullTx, int, error) {
	if len(b) > MaxFullTxBody {
		return nil, 0, ErrBadFrame
	}
	d := &decoder{b: b}
	ft := &FullTx{}
	var err error
	if ft.Slot, err = d.u64(); err != nil {
		return nil, 0, err
	}
	var x uint8
	if x, err = d.u8(); err != nil {
		return nil, 0, err
	}
	ft.NumRequiredSignatures = uint32(x)
	if x, err = d.u8(); err != nil {
		return nil, 0, err
	}
	ft.NumReadonlySignedAccounts = uint32(x)
	if x, err = d.u8(); err != nil {
		return nil, 0, err
	}
	ft.NumReadonlyUnsignedAccount = uint32(x)
	if x, err = d.u8(); err != nil {
		return nil, 0, err
	}
	ft.Versioned = x != 0
	bh, err := d.take(32)
	if err != nil {
		return nil, 0, err
	}
	copy(ft.RecentBlockhash[:], bh)

	n, err := d.count(64)
	if err != nil {
		return nil, 0, err
	}
	ft.Signatures = make([][64]byte, n)
	for i := 0; i < n; i++ {
		s, err := d.take(64)
		if err != nil {
			return nil, 0, err
		}
		copy(ft.Signatures[i][:], s)
	}

	n, err = d.count(32)
	if err != nil {
		return nil, 0, err
	}
	ft.AccountKeys = make([][32]byte, n)
	for i := 0; i < n; i++ {
		k, err := d.take(32)
		if err != nil {
			return nil, 0, err
		}
		copy(ft.AccountKeys[i][:], k)
	}

	n, err = d.count(5) // min instruction = progIdx(1)+accLen(2)+dataLen(2)
	if err != nil {
		return nil, 0, err
	}
	ft.Instructions = make([]Instruction, n)
	for i := 0; i < n; i++ {
		pid, err := d.u8()
		if err != nil {
			return nil, 0, err
		}
		al, err := d.u16()
		if err != nil {
			return nil, 0, err
		}
		acc, err := d.take(al)
		if err != nil {
			return nil, 0, err
		}
		dl, err := d.u16()
		if err != nil {
			return nil, 0, err
		}
		dat, err := d.take(dl)
		if err != nil {
			return nil, 0, err
		}
		ft.Instructions[i] = Instruction{
			ProgramIDIndex: uint32(pid),
			Accounts:       append([]byte(nil), acc...),
			Data:           append([]byte(nil), dat...),
		}
	}

	n, err = d.count(36) // min ATL = key(32)+wLen(2)+rLen(2)
	if err != nil {
		return nil, 0, err
	}
	ft.AddressTableLookups = make([]AddressTableLookup, n)
	for i := 0; i < n; i++ {
		key, err := d.take(32)
		if err != nil {
			return nil, 0, err
		}
		wl, err := d.u16()
		if err != nil {
			return nil, 0, err
		}
		w, err := d.take(wl)
		if err != nil {
			return nil, 0, err
		}
		rl, err := d.u16()
		if err != nil {
			return nil, 0, err
		}
		r, err := d.take(rl)
		if err != nil {
			return nil, 0, err
		}
		var atl AddressTableLookup
		copy(atl.AccountKey[:], key)
		atl.WritableIndexes = append([]byte(nil), w...)
		atl.ReadonlyIndexes = append([]byte(nil), r...)
		ft.AddressTableLookups[i] = atl
	}

	return ft, d.off, nil
}

type decoder struct {
	b   []byte
	off int
}

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || d.off+n > len(d.b) {
		return nil, ErrBadFrame
	}
	s := d.b[d.off : d.off+n]
	d.off += n
	return s, nil
}

func (d *decoder) u8() (uint8, error) {
	s, err := d.take(1)
	if err != nil {
		return 0, err
	}
	return s[0], nil
}

func (d *decoder) u16() (int, error) {
	s, err := d.take(2)
	if err != nil {
		return 0, err
	}
	return int(binary.LittleEndian.Uint16(s)), nil
}

func (d *decoder) u64() (uint64, error) {
	s, err := d.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(s), nil
}

// count reads a u16 length and rejects it before allocating if that many
// elements of at least minElem bytes cannot fit in the remaining frame.
func (d *decoder) count(minElem int) (int, error) {
	n, err := d.u16()
	if err != nil {
		return 0, err
	}
	if minElem == 0 || n > (len(d.b)-d.off)/minElem {
		return 0, ErrBadFrame
	}
	return n, nil
}

// EncodeFullTx is the inverse of DecodeFullTx for the Pulse wire-v2 positional
// transaction layout.
func EncodeFullTx(ft *FullTx) []byte {
	var b []byte
	var u8b [1]byte
	put8 := func(v uint64) {
		var t [8]byte
		binary.LittleEndian.PutUint64(t[:], v)
		b = append(b, t[:]...)
	}
	put16 := func(v int) {
		var t [2]byte
		binary.LittleEndian.PutUint16(t[:], uint16(v))
		b = append(b, t[:]...)
	}
	putByte := func(v byte) { u8b[0] = v; b = append(b, u8b[0]) }

	put8(ft.Slot)
	putByte(byte(ft.NumRequiredSignatures))
	putByte(byte(ft.NumReadonlySignedAccounts))
	putByte(byte(ft.NumReadonlyUnsignedAccount))
	if ft.Versioned {
		putByte(1)
	} else {
		putByte(0)
	}
	b = append(b, ft.RecentBlockhash[:]...)
	put16(len(ft.Signatures))
	for i := range ft.Signatures {
		b = append(b, ft.Signatures[i][:]...)
	}
	put16(len(ft.AccountKeys))
	for i := range ft.AccountKeys {
		b = append(b, ft.AccountKeys[i][:]...)
	}
	put16(len(ft.Instructions))
	for i := range ft.Instructions {
		putByte(byte(ft.Instructions[i].ProgramIDIndex))
		put16(len(ft.Instructions[i].Accounts))
		b = append(b, ft.Instructions[i].Accounts...)
		put16(len(ft.Instructions[i].Data))
		b = append(b, ft.Instructions[i].Data...)
	}
	put16(len(ft.AddressTableLookups))
	for i := range ft.AddressTableLookups {
		b = append(b, ft.AddressTableLookups[i].AccountKey[:]...)
		put16(len(ft.AddressTableLookups[i].WritableIndexes))
		b = append(b, ft.AddressTableLookups[i].WritableIndexes...)
		put16(len(ft.AddressTableLookups[i].ReadonlyIndexes))
		b = append(b, ft.AddressTableLookups[i].ReadonlyIndexes...)
	}
	return b
}

// ---- wire v2: stream preamble, frame message types, TLV trailer -----------

// WireVersion is the wire protocol version carried by the stream preamble.
const WireVersion = 2

// Preamble is the immutable six-byte value written once at the head of every
// full-tx unidirectional stream, before any frame: "PLS2", the version, then
// a reserved flags byte. A v1 stream's first byte is always 0x00 (the high
// byte of a u32 big-endian length prefix on a frame capped at 64 KiB), so the
// non-zero magic is unambiguous. A client can identify a non-v1 server from
// the first byte.
const Preamble = "PLS2\x02\x00"

// Frame message types.
const (
	MsgTx        uint8 = 1
	MsgHeartbeat uint8 = 2
	// MsgShed is assigned to shed notices, which wire v2 does not emit.
	MsgShed uint8 = 3
)

// FlagAltIncomplete: the ALT address set on this MsgTx frame may be
// incomplete. Not a TLV-presence bitmap — a per-frame boolean.
const FlagAltIncomplete uint8 = 0x01

// TLV trailer types.
const (
	TLVLoadedWritable uint8 = 1
	TLVLoadedReadonly uint8 = 2
	TLVServerTsMs     uint8 = 3
	TLVHighestSeq     uint8 = 4
)

type tlvEntry struct {
	typ   uint8
	value []byte
}

// parseTLVs parses a TLV trailer to the end of src: `u8 type | u16 LE len |
// value` records. Unknown types are returned to the caller so new fields
// remain additive. Duplicate types are rejected.
func parseTLVs(src []byte) ([]tlvEntry, error) {
	var out []tlvEntry
	off := 0
	for off < len(src) {
		if off+3 > len(src) {
			return nil, ErrBadFrame
		}
		t := src[off]
		l := int(binary.LittleEndian.Uint16(src[off+1 : off+3]))
		start := off + 3
		end := start + l
		if end > len(src) {
			return nil, ErrBadFrame
		}
		for _, e := range out {
			if e.typ == t {
				return nil, ErrBadFrame
			}
		}
		out = append(out, tlvEntry{typ: t, value: src[start:end]})
		off = end
	}
	return out, nil
}

func flatten32(addrs [][32]byte) []byte {
	b := make([]byte, 0, len(addrs)*32)
	for _, a := range addrs {
		b = append(b, a[:]...)
	}
	return b
}

func unflatten32(src []byte) ([][32]byte, error) {
	if len(src)%32 != 0 {
		return nil, ErrBadFrame
	}
	out := make([][32]byte, len(src)/32)
	for i := range out {
		copy(out[i][:], src[i*32:(i+1)*32])
	}
	return out, nil
}

// Frame is a decoded v2 stream frame: exactly one of FullTxV2, FrameHeartbeat,
// or UnknownFrame.
type Frame interface{ isFrame() }

// FullTxV2 is a decoded v2 transaction frame: the v1 body plus its v2
// additions.
type FullTxV2 struct {
	Tx             FullTx
	AltIncomplete  bool
	LoadedWritable [][32]byte
	LoadedReadonly [][32]byte
}

func (FullTxV2) isFrame() {}

// FrameHeartbeat is a decoded v2 heartbeat frame (full-tx tier).
type FrameHeartbeat struct {
	ServerTsMs uint64
	HighestSeq uint64
}

func (FrameHeartbeat) isFrame() {}

// UnknownFrame carries the message type of a frame this decoder does not
// recognize, so a caller can skip it deliberately rather than erroring — that
// is what keeps a future wire addition from breaking this client.
type UnknownFrame struct{ Type uint8 }

func (UnknownFrame) isFrame() {}

// EncodeFrameTx encodes a v2 transaction frame: msg_type | flags | v1 body |
// TLV trailer. The v1 body is reused byte-for-byte; only the framing around
// it is new. Pass nil/empty slices for a non-enriched subscriber — the
// trailer is then empty and the frame costs two bytes more than v1.
func EncodeFrameTx(ft *FullTx, altIncomplete bool, loadedWritable, loadedReadonly [][32]byte) []byte {
	body := EncodeFullTx(ft)
	b := make([]byte, 0, len(body)+2+64)
	b = append(b, MsgTx)
	if altIncomplete {
		b = append(b, FlagAltIncomplete)
	} else {
		b = append(b, 0)
	}
	b = append(b, body...)
	if len(loadedWritable) > 0 {
		b = putTLV(b, TLVLoadedWritable, flatten32(loadedWritable))
	}
	if len(loadedReadonly) > 0 {
		b = putTLV(b, TLVLoadedReadonly, flatten32(loadedReadonly))
	}
	return b
}

func putTLV(buf []byte, t uint8, value []byte) []byte {
	buf = append(buf, t)
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], uint16(len(value)))
	buf = append(buf, l[:]...)
	buf = append(buf, value...)
	return buf
}

// DecodeFrame decodes one v2 frame (the caller has already stripped the u32
// big-endian length prefix). Bounds-checked; never panics. A msg_type this
// decoder does not recognize is returned as UnknownFrame rather than an
// error — that is a deliberate skip, not a failure.
func DecodeFrame(src []byte) (Frame, error) {
	if len(src) < 2 {
		return nil, ErrBadFrame
	}
	msgType := src[0]
	flags := src[1]
	rest := src[2:]

	switch msgType {
	case MsgTx:
		if flags & ^FlagAltIncomplete != 0 {
			return nil, ErrBadFrame // reserved bits must be zero
		}
		// The v1 body is self-delimiting: decode it, then treat whatever
		// follows as the TLV trailer.
		tx, consumed, err := decodeFullTxPrefix(rest)
		if err != nil {
			return nil, err
		}
		if consumed > len(rest) {
			return nil, ErrBadFrame
		}
		tlvs, err := parseTLVs(rest[consumed:])
		if err != nil {
			return nil, err
		}
		v2 := FullTxV2{
			Tx:            *tx,
			AltIncomplete: flags&FlagAltIncomplete != 0,
		}
		for _, e := range tlvs {
			switch e.typ {
			case TLVLoadedWritable:
				addrs, err := unflatten32(e.value)
				if err != nil {
					return nil, err
				}
				v2.LoadedWritable = addrs
			case TLVLoadedReadonly:
				addrs, err := unflatten32(e.value)
				if err != nil {
					return nil, err
				}
				v2.LoadedReadonly = addrs
			default:
				// unknown TLV: skip, do not error
			}
		}
		return v2, nil
	case MsgHeartbeat:
		// alt_incomplete (bit 0) is a tx-frame-only concept, so unlike MsgTx
		// there is no bit this message type defines: all 8 bits are reserved
		// here and MUST be zero. Do not reuse the MsgTx `^FlagAltIncomplete`
		// mask — that would silently accept bit 0 on a frame kind where it
		// has no meaning.
		if flags != 0 {
			return nil, ErrBadFrame
		}
		tlvs, err := parseTLVs(rest)
		if err != nil {
			return nil, err
		}
		var hb FrameHeartbeat
		for _, e := range tlvs {
			switch e.typ {
			case TLVServerTsMs:
				if len(e.value) != 8 {
					return nil, ErrBadFrame
				}
				hb.ServerTsMs = binary.LittleEndian.Uint64(e.value)
			case TLVHighestSeq:
				if len(e.value) != 8 {
					return nil, ErrBadFrame
				}
				hb.HighestSeq = binary.LittleEndian.Uint64(e.value)
			default:
				// unknown TLV: skip, do not error
			}
		}
		return hb, nil
	default:
		return UnknownFrame{Type: msgType}, nil
	}
}

// ---- typed datagrams -------------------------------------------------------

// Datagram types.
const (
	DGSigFirst  uint8 = 1
	DGHeartbeat uint8 = 2
)

// Minimum datagram lengths, by type. Each type declares a MINIMUM length, not
// an exact one: a known type that is long enough parses and trailing bytes
// are ignored, which is what lets a later wire version add a field without
// breaking this decoder.
const (
	// DGSigFirstMin is `u8 type | u64 slot | u64 seq | 64B signature`.
	DGSigFirstMin = 1 + 8 + 8 + 64
	// DGHeartbeatMin is `u8 type | u64 server_ts_ms | u64 highest_seq`.
	DGHeartbeatMin = 1 + 8 + 8
)

// Datagram is a decoded v2 QUIC datagram: exactly one of SigFirst,
// DatagramHeartbeat, or UnknownDatagram.
type Datagram interface{ isDatagram() }

// SigFirst is one sig-first datagram delivery.
type SigFirst struct {
	Slot      uint64
	Seq       uint64
	Signature [64]byte
}

func (SigFirst) isDatagram() {}

// DatagramHeartbeat is a decoded v2 heartbeat datagram (sig-first tier).
type DatagramHeartbeat struct {
	ServerTsMs uint64
	HighestSeq uint64
}

func (DatagramHeartbeat) isDatagram() {}

// UnknownDatagram carries the type tag of a datagram this decoder does not
// recognize, so a caller can skip it deliberately rather than erroring.
type UnknownDatagram struct{ Type uint8 }

func (UnknownDatagram) isDatagram() {}

// EncodeDGSigFirst encodes a sig-first datagram into buf, which must be
// exactly DGSigFirstMin bytes.
func EncodeDGSigFirst(buf []byte, slot, seq uint64, sig *[64]byte) {
	buf[0] = DGSigFirst
	binary.LittleEndian.PutUint64(buf[1:9], slot)
	binary.LittleEndian.PutUint64(buf[9:17], seq)
	copy(buf[17:81], sig[:])
}

// EncodeDGHeartbeat encodes a heartbeat datagram into buf, which must be
// exactly DGHeartbeatMin bytes.
func EncodeDGHeartbeat(buf []byte, serverTsMs, highestSeq uint64) {
	buf[0] = DGHeartbeat
	binary.LittleEndian.PutUint64(buf[1:9], serverTsMs)
	binary.LittleEndian.PutUint64(buf[9:17], highestSeq)
}

// DecodeDatagram decodes a datagram by its type tag.
//
// Each type declares a MINIMUM length, not an exact one: a known type that is
// long enough parses, and trailing bytes are ignored. A type this decoder
// does not recognize is returned as UnknownDatagram rather than an error —
// that is a deliberate skip. A known type that is too short to parse, or an
// empty datagram, is rejected as ErrBadFrame: that is the one case a caller
// must treat as "not decodable", not "a future field I don't understand yet".
func DecodeDatagram(src []byte) (Datagram, error) {
	if len(src) == 0 {
		return nil, ErrBadFrame
	}
	switch src[0] {
	case DGSigFirst:
		if len(src) < DGSigFirstMin {
			return nil, ErrBadFrame
		}
		var sf SigFirst
		sf.Slot = binary.LittleEndian.Uint64(src[1:9])
		sf.Seq = binary.LittleEndian.Uint64(src[9:17])
		copy(sf.Signature[:], src[17:81])
		return sf, nil
	case DGHeartbeat:
		if len(src) < DGHeartbeatMin {
			return nil, ErrBadFrame
		}
		return DatagramHeartbeat{
			ServerTsMs: binary.LittleEndian.Uint64(src[1:9]),
			HighestSeq: binary.LittleEndian.Uint64(src[9:17]),
		}, nil
	default:
		return UnknownDatagram{Type: src[0]}, nil
	}
}
