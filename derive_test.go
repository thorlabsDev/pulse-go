package pulseclient

import "testing"

func txWith(keys [][32]byte, ixs []Instruction, nrs, nrsa, nrua uint32) *FullTx {
	return &FullTx{
		Slot:                       1,
		Versioned:                  false,
		NumRequiredSignatures:      nrs,
		NumReadonlySignedAccounts:  nrsa,
		NumReadonlyUnsignedAccount: nrua,
		Signatures:                 [][64]byte{{}},
		AccountKeys:                keys,
		Instructions:               ixs,
	}
}

func TestFeePayerIsTheFirstAccountKey(t *testing.T) {
	tx := txWith([][32]byte{{0xA1}, {0xB2}}, nil, 1, 0, 0)
	fp, ok := FeePayer(tx)
	if !ok || fp != tx.AccountKeys[0] {
		t.Fatalf("FeePayer = %v, %v; want %v, true", fp, ok, tx.AccountKeys[0])
	}
	empty := txWith(nil, nil, 0, 0, 0)
	if _, ok := FeePayer(empty); ok {
		t.Fatal("expected ok=false for a transaction with no account keys")
	}
}

func TestProgramIDsResolveAndDedupInOrder(t *testing.T) {
	tx := txWith(
		[][32]byte{{0xA1}, {0xB2}, {0xC3}},
		[]Instruction{
			{ProgramIDIndex: 2},
			{ProgramIDIndex: 1},
			{ProgramIDIndex: 2},
		},
		1, 0, 0,
	)
	got := ProgramIDs(tx)
	want := [][32]byte{{0xC3}, {0xB2}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ProgramIDs = %v, want %v", got, want)
	}
}

func TestProgramIDIndexOutOfRangeIsSkippedNotPanicking(t *testing.T) {
	tx := txWith([][32]byte{{0xA1}}, []Instruction{{ProgramIDIndex: 9}}, 1, 0, 0)
	if got := ProgramIDs(tx); len(got) != 0 {
		t.Fatalf("ProgramIDs = %v, want empty", got)
	}
}

func TestStaticWritableFollowsTheHeaderCounts(t *testing.T) {
	// 4 keys, 2 signers of which 1 readonly, 1 readonly unsigned.
	// writable signers  = [0, nrs-nrsa) = [0,1) -> key 0
	// writable unsigned = [nrs, len-nrua) = [2,3) -> key 2
	tx := txWith([][32]byte{{0}, {1}, {2}, {3}}, nil, 2, 1, 1)
	got := StaticWritableAccounts(tx)
	want := [][32]byte{{0}, {2}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("StaticWritableAccounts = %v, want %v", got, want)
	}
}

func TestStaticWritableAccountsNeverPanicsOnHostileHeaderCounts(t *testing.T) {
	// nrsa > nrs and nrua > len(keys): saturating arithmetic must keep every
	// range non-negative and in-bounds rather than panicking.
	tx := txWith([][32]byte{{0}, {1}}, nil, 1, 5, 9)
	got := StaticWritableAccounts(tx)
	if len(got) != 0 {
		t.Fatalf("StaticWritableAccounts = %v, want empty (no panic)", got)
	}
}

func computeBudgetIxData(discriminator byte, data []byte) Instruction {
	return Instruction{ProgramIDIndex: 1, Data: append([]byte{discriminator}, data...)}
}

func TestComputeBudgetPriceAndLimitAreParsed(t *testing.T) {
	le64 := func(v uint64) []byte {
		b := make([]byte, 8)
		for i := 0; i < 8; i++ {
			b[i] = byte(v >> (8 * i))
		}
		return b
	}
	le32 := func(v uint32) []byte {
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			b[i] = byte(v >> (8 * i))
		}
		return b
	}
	tx := txWith(
		[][32]byte{{0xA1}, ComputeBudgetProgramID()},
		[]Instruction{
			computeBudgetIxData(3, le64(7_500)),
			computeBudgetIxData(2, le32(200_000)),
		},
		1, 0, 0,
	)
	p, ok := ComputeUnitPrice(tx)
	if !ok || p != 7_500 {
		t.Fatalf("ComputeUnitPrice = %d, %v; want 7500, true", p, ok)
	}
	l, ok := ComputeUnitLimit(tx)
	if !ok || l != 200_000 {
		t.Fatalf("ComputeUnitLimit = %d, %v; want 200000, true", l, ok)
	}
}

func TestComputeBudgetAbsentReturnsNotOkNotADefault(t *testing.T) {
	// No implicit 200k default — absent must be distinguishable from zero.
	tx := txWith([][32]byte{{0xA1}}, nil, 1, 0, 0)
	if _, ok := ComputeUnitPrice(tx); ok {
		t.Fatal("expected ok=false when no ComputeBudget instruction is present")
	}
	if _, ok := ComputeUnitLimit(tx); ok {
		t.Fatal("expected ok=false when no ComputeBudget instruction is present")
	}
}

func TestTruncatedComputeBudgetDataIsIgnored(t *testing.T) {
	tx := txWith(
		[][32]byte{{0xA1}, ComputeBudgetProgramID()},
		[]Instruction{{ProgramIDIndex: 1, Data: []byte{3, 1, 2}}}, // discriminator 3 but only 2 bytes follow
		1, 0, 0,
	)
	if _, ok := ComputeUnitPrice(tx); ok {
		t.Fatal("expected ok=false for truncated instruction data")
	}
}

func TestComputeBudgetProgramIDShape(t *testing.T) {
	programID := ComputeBudgetProgramID()
	if programID[0] != 0x03 {
		t.Fatalf("ComputeBudgetProgramID()[0] = %#x, want 0x03", programID[0])
	}
}

func TestComputeBudgetProgramIDReturnsAValueCopy(t *testing.T) {
	mutated := ComputeBudgetProgramID()
	mutated[0] = 0xff
	if got := ComputeBudgetProgramID(); got[0] != 0x03 {
		t.Fatalf("caller mutation changed package invariant: %#x", got[0])
	}
}
