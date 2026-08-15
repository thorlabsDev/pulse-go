package pulseclient

import "encoding/binary"

// Fields a client can compute from a decoded transaction.
//
// These are deliberately NOT on the wire. FeePayer is AccountKeys[0],
// ProgramIDs resolve each instruction's ProgramIDIndex, the static writable
// set falls out of the three header counts, and the ComputeBudget
// instruction data is already carried verbatim. Shipping them as TLVs would
// spend wire bytes and hot-path encode time to save a caller a few lines.

// computeBudgetProgramID is kept private so callers cannot mutate a package
// invariant and change ComputeUnitPrice / ComputeUnitLimit behavior globally.
var computeBudgetProgramID = [32]byte{
	3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231,
	188, 140, 229, 187, 197, 247, 18, 107, 44, 67, 155, 58, 64, 0, 0, 0,
}

// ComputeBudgetProgramID returns the 32-byte program ID for
// ComputeBudget111111111111111111111111111111. It returns a value copy, so
// callers cannot mutate the package's derived-field matching invariant.
func ComputeBudgetProgramID() [32]byte { return computeBudgetProgramID }

// FeePayer is always the first account key. ok is false for a transaction
// with no account keys.
func FeePayer(tx *FullTx) (feePayer [32]byte, ok bool) {
	if len(tx.AccountKeys) == 0 {
		return feePayer, false
	}
	return tx.AccountKeys[0], true
}

// ProgramIDs returns every program the transaction invokes, in first-use
// order, deduplicated. Solana forbids an ALT-sourced program id, so this is
// complete without any lookup-table resolution.
func ProgramIDs(tx *FullTx) [][32]byte {
	var out [][32]byte
	seen := make(map[[32]byte]bool, len(tx.Instructions))
	for _, ix := range tx.Instructions {
		idx := int(ix.ProgramIDIndex)
		if idx < 0 || idx >= len(tx.AccountKeys) {
			continue
		}
		k := tx.AccountKeys[idx]
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// StaticWritableAccounts returns writable accounts drawn from the STATIC key
// array only. ALT-loaded writables arrive separately in the frame's
// LoadedWritable TLV.
func StaticWritableAccounts(tx *FullTx) [][32]byte {
	n := len(tx.AccountKeys)
	nrs := int(tx.NumRequiredSignatures)
	nrsa := int(tx.NumReadonlySignedAccounts)
	nrua := int(tx.NumReadonlyUnsignedAccount)

	var out [][32]byte
	signedWritableEnd := minInt(satSubInt(nrs, nrsa), n)
	for i := 0; i < signedWritableEnd; i++ {
		out = append(out, tx.AccountKeys[i])
	}
	unsignedStart := minInt(nrs, n)
	unsignedEnd := satSubInt(n, nrua)
	for i := unsignedStart; i < unsignedEnd; i++ {
		out = append(out, tx.AccountKeys[i])
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// satSubInt is a saturating (floor-at-zero) subtraction: a and b are always
// non-negative header-derived counts here, but a naive a-b could go negative
// and corrupt a slice bound.
func satSubInt(a, b int) int {
	if a < b {
		return 0
	}
	return a - b
}

func computeBudgetIx(tx *FullTx, discriminator byte) (data []byte, ok bool) {
	for _, ix := range tx.Instructions {
		idx := int(ix.ProgramIDIndex)
		if idx < 0 || idx >= len(tx.AccountKeys) {
			continue
		}
		if tx.AccountKeys[idx] != computeBudgetProgramID {
			continue
		}
		if len(ix.Data) > 0 && ix.Data[0] == discriminator {
			return ix.Data[1:], true
		}
	}
	return nil, false
}

// ComputeUnitPrice returns micro-lamports per compute unit from
// SetComputeUnitPrice (discriminator 3). ok is false when the transaction set
// no price — NOT zero.
func ComputeUnitPrice(tx *FullTx) (price uint64, ok bool) {
	d, found := computeBudgetIx(tx, 3)
	if !found || len(d) < 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(d[:8]), true
}

// ComputeUnitLimit returns the explicit SetComputeUnitLimit (discriminator 2)
// only. ok is false when the transaction set no limit; no implicit
// per-instruction default is applied.
func ComputeUnitLimit(tx *FullTx) (limit uint32, ok bool) {
	d, found := computeBudgetIx(tx, 2)
	if !found || len(d) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(d[:4]), true
}
