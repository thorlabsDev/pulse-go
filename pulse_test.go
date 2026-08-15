package pulseclient

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func sampleTx(versioned bool) *FullTx {
	ft := &FullTx{
		Slot:                  7,
		Versioned:             versioned,
		NumRequiredSignatures: 1,
		RecentBlockhash:       [32]byte{},
		Signatures:            [][64]byte{{7, 7, 7}},
		AccountKeys:           [][32]byte{{0xA1}},
		Instructions: []Instruction{{
			ProgramIDIndex: 1,
			Accounts:       []byte{0},
			Data:           []byte{0xDE, 0xAD, 0xBE},
		}},
	}
	for i := range ft.RecentBlockhash {
		ft.RecentBlockhash[i] = 0xCC
	}
	if versioned {
		atl := AddressTableLookup{WritableIndexes: []byte{5}, ReadonlyIndexes: []byte{7}}
		for i := range atl.AccountKey {
			atl.AccountKey[i] = 0xEE
		}
		ft.AddressTableLookups = []AddressTableLookup{atl}
	}
	return ft
}

func TestFullTxRoundTrip(t *testing.T) {
	for _, versioned := range []bool{false, true} {
		ft := sampleTx(versioned)
		body := EncodeFullTx(ft)
		got, err := DecodeFullTx(body)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Slot != ft.Slot || got.Versioned != ft.Versioned ||
			len(got.Signatures) != 1 || got.Signatures[0] != ft.Signatures[0] ||
			len(got.AccountKeys) != 1 || got.AccountKeys[0] != ft.AccountKeys[0] ||
			len(got.Instructions) != 1 || got.Instructions[0].ProgramIDIndex != 1 ||
			!bytes.Equal(got.Instructions[0].Data, []byte{0xDE, 0xAD, 0xBE}) {
			t.Fatalf("round-trip mismatch (versioned=%v): %+v", versioned, got)
		}
		if versioned && (len(got.AddressTableLookups) != 1 ||
			!bytes.Equal(got.AddressTableLookups[0].WritableIndexes, []byte{5})) {
			t.Fatalf("ATL mismatch: %+v", got.AddressTableLookups)
		}
	}
}

// TestVectorMatchesDocumentedLayout decodes a hand-built body that follows the
// documented byte layout exactly, cross-checking the decoder against the
// canonical wire-v2 specification.
func TestVectorMatchesDocumentedLayout(t *testing.T) {
	var b []byte
	u16 := func(v int) []byte { x := make([]byte, 2); binary.LittleEndian.PutUint16(x, uint16(v)); return x }
	slot := make([]byte, 8)
	binary.LittleEndian.PutUint64(slot, 42)
	b = append(b, slot...)                           // slot
	b = append(b, 1, 0, 0, 0)                        // numReqSigs, roSigned, roUnsigned, versioned=0
	b = append(b, bytes.Repeat([]byte{0xCC}, 32)...) // recent blockhash
	b = append(b, u16(1)...)                         // 1 signature
	b = append(b, bytes.Repeat([]byte{0x11}, 64)...)
	b = append(b, u16(1)...) // 1 account key
	b = append(b, bytes.Repeat([]byte{0xA1}, 32)...)
	b = append(b, u16(0)...) // 0 instructions
	b = append(b, u16(0)...) // 0 ATLs

	ft, err := DecodeFullTx(b)
	if err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	if ft.Slot != 42 || len(ft.Signatures) != 1 || ft.Signatures[0][0] != 0x11 ||
		len(ft.AccountKeys) != 1 || ft.AccountKeys[0][0] != 0xA1 || ft.Versioned {
		t.Fatalf("vector decode wrong: %+v", ft)
	}
}

func TestRejectsTruncatedAndTrailing(t *testing.T) {
	body := EncodeFullTx(sampleTx(true))
	if _, err := DecodeFullTx(body[:len(body)-3]); err == nil {
		t.Fatal("expected error on truncated body")
	}
	if _, err := DecodeFullTx(append(body, 0x00)); err == nil {
		t.Fatal("expected error on trailing garbage")
	}
}

func TestControlDeclaresWireV2(t *testing.T) {
	body, err := json.Marshal(control{Filter: AllNonVoteTxs(), Full: false, V: WireVersion, Fields: []string{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"v":2`) {
		t.Fatalf(`expected "v":2 in %s`, body)
	}
}

func TestControlFieldsOptsIntoEnrichment(t *testing.T) {
	body, err := json.Marshal(control{Filter: AllNonVoteTxs(), Full: true, V: WireVersion, Fields: []string{"alt"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"fields":["alt"]`) {
		t.Fatalf(`expected "fields":["alt"] in %s`, body)
	}
}

func TestControlFieldsIsAnEmptyArrayNotNullWhenUnset(t *testing.T) {
	// sendControl normalizes a nil fields slice to []string{} before marshaling
	// so the wire always carries a JSON array, never a bare `null`, where the
	// server expects a list.
	body, err := json.Marshal(control{Filter: AllNonVoteTxs(), Full: false, V: WireVersion, Fields: []string{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"fields":[]`) {
		t.Fatalf(`expected "fields":[] (not null) in %s`, body)
	}
}

func TestControlTokenOmittedWhenEmpty(t *testing.T) {
	body, err := json.Marshal(control{Filter: AllNonVoteTxs(), Full: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "token") {
		t.Fatalf("empty token must be omitted: %s", body)
	}
}

func TestControlTokenIncludedWhenSet(t *testing.T) {
	body, err := json.Marshal(control{Filter: AllNonVoteTxs(), Token: "rpc_test", Full: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"token":"rpc_test"`) {
		t.Fatalf("token missing: %s", body)
	}
}

func TestControlVoteOmittedWhenUnset(t *testing.T) {
	body, err := json.Marshal(control{Filter: AllNonVoteTxs(), Full: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "vote") {
		t.Fatalf("unset vote must be omitted: %s", body)
	}
}

func TestControlVoteIncludedWhenSet(t *testing.T) {
	for _, want := range []bool{true, false} {
		body, err := json.Marshal(control{Filter: AllNonVoteTxs().WithVote(want), Full: false})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		exp := fmt.Sprintf(`"vote":%v`, want)
		if !strings.Contains(string(body), exp) {
			t.Fatalf("want %s in %s", exp, body)
		}
	}
}

func TestControlPreservesTheCompleteFilterPredicate(t *testing.T) {
	vote := true
	f := Filter{
		AccountInclude:  []string{"include-account", "program-id"},
		AccountExclude:  []string{"exclude-account"},
		AccountRequired: []string{"required-account"},
		Vote:            &vote,
	}
	body, err := json.Marshal(control{Filter: f, Token: "token", Full: true, V: WireVersion, Fields: []string{"alt"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"account_include", "account_exclude", "account_required"} {
		values, ok := got[field].([]any)
		if !ok || len(values) == 0 {
			t.Fatalf("%s missing from control: %s", field, body)
		}
	}
	if got["vote"] != true || got["token"] != "token" || got["full"] != true || got["v"] != float64(WireVersion) {
		t.Fatalf("control fields changed: %s", body)
	}
}

func TestAccountsCopiesTheCallerSlice(t *testing.T) {
	keys := []string{"account-a", "program-b"}
	filter := Accounts(keys...)
	keys[0] = "mutated"
	if filter.AccountInclude[0] != "account-a" {
		t.Fatalf("Accounts retained caller storage: %+v", filter.AccountInclude)
	}
}
