package pulseclient

import (
	"sync/atomic"
	"testing"
)

// Direct unit tests of noteItemSeq / noteHeartbeatSeq — the watermark and
// sentinel logic that backs SigFirstSub.Gaps(). Exercised again end-to-end via
// the drain loop in sigqueue_test.go, but pinned here at the smallest scope so
// a regression in the arithmetic itself, independent of datagram decoding, is
// caught directly.

func TestNoteItemSeqCountsMissedNumbersBetweenConsecutiveItems(t *testing.T) {
	var lastSeq uint64
	var haveLast bool
	var gaps atomic.Uint64

	noteItemSeq(&lastSeq, &haveLast, &gaps, 0)
	if gaps.Load() != 0 {
		t.Fatalf("first item establishes the baseline: gaps=%d, want 0", gaps.Load())
	}
	noteItemSeq(&lastSeq, &haveLast, &gaps, 3) // missed 1 and 2
	if gaps.Load() != 2 {
		t.Fatalf("gaps=%d, want 2", gaps.Load())
	}
	if lastSeq != 3 {
		t.Fatalf("lastSeq=%d, want 3", lastSeq)
	}
}

func TestNoteItemSeqOutOfOrderNeverUnderflows(t *testing.T) {
	lastSeq := uint64(10)
	haveLast := true
	var gaps atomic.Uint64

	noteItemSeq(&lastSeq, &haveLast, &gaps, 3)
	if gaps.Load() != 0 {
		t.Fatalf("no underflow, no bogus gap: gaps=%d, want 0", gaps.Load())
	}
	if lastSeq != 10 {
		t.Fatalf("watermark must not regress on reorder: lastSeq=%d, want 10", lastSeq)
	}
	noteItemSeq(&lastSeq, &haveLast, &gaps, 11)
	if gaps.Load() != 0 {
		t.Fatalf("seq 11 directly follows the watermark of 10: gaps=%d, want 0", gaps.Load())
	}
	if lastSeq != 11 {
		t.Fatalf("lastSeq=%d, want 11", lastSeq)
	}
}

func TestNoteItemSeqSentinelSeqDoesNotOverflowTheGapAddition(t *testing.T) {
	// A corrupt or hostile datagram could carry seq == NoSeqAssigned. The +1
	// computed against the PREVIOUS watermark must not overflow-wrap into a
	// bogus small number that fabricates a gap.
	lastSeq := NoSeqAssigned
	haveLast := true
	var gaps atomic.Uint64

	noteItemSeq(&lastSeq, &haveLast, &gaps, NoSeqAssigned)
	if gaps.Load() != 0 {
		t.Fatalf("gaps=%d, want 0", gaps.Load())
	}
	if lastSeq != NoSeqAssigned {
		t.Fatalf("lastSeq=%d, want NoSeqAssigned", lastSeq)
	}
}

func TestNoteHeartbeatSeqSentinelIsNeverAGap(t *testing.T) {
	// THE required property: NoSeqAssigned must never be treated as a real
	// value. A naive highestSeq-last here would compute an astronomical,
	// nonsensical gap.
	lastSeq := uint64(5)
	haveLast := true
	var gaps atomic.Uint64

	noteHeartbeatSeq(&lastSeq, &haveLast, &gaps, NoSeqAssigned)
	if gaps.Load() != 0 {
		t.Fatalf("gaps=%d, want 0", gaps.Load())
	}
	if lastSeq != 5 {
		t.Fatalf("the sentinel must not overwrite a real baseline either: lastSeq=%d, want 5", lastSeq)
	}
}

func TestNoteHeartbeatSeqRevealsTrailingLoss(t *testing.T) {
	// The case item-to-item comparison can never see: datagrams dropped AFTER
	// the last one actually received, with nothing since to reveal the hole.
	lastSeq := uint64(2)
	haveLast := true
	var gaps atomic.Uint64

	noteHeartbeatSeq(&lastSeq, &haveLast, &gaps, 7)
	if gaps.Load() != 5 {
		t.Fatalf("gaps=%d, want 5", gaps.Load())
	}
	if lastSeq != 7 {
		t.Fatalf("lastSeq=%d, want 7", lastSeq)
	}
}

func TestNoteHeartbeatSeqFirstObservationEstablishesABaselineNotAGap(t *testing.T) {
	// No prior item to compare against: no evidence anything was actually
	// lost, so don't allege a number we can't justify.
	var lastSeq uint64
	var haveLast bool
	var gaps atomic.Uint64

	noteHeartbeatSeq(&lastSeq, &haveLast, &gaps, 9)
	if gaps.Load() != 0 {
		t.Fatalf("gaps=%d, want 0", gaps.Load())
	}
	if lastSeq != 9 || !haveLast {
		t.Fatalf("lastSeq=%d haveLast=%v, want 9 true", lastSeq, haveLast)
	}
}
