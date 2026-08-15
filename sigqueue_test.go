package pulseclient

import (
	"context"
	"io"
	"testing"
)

// sigDatagram builds a valid v2 sig-first datagram for (slot, seq).
func sigDatagram(slot, seq uint64) []byte {
	dg := make([]byte, DGSigFirstMin)
	var sig [64]byte
	sig[0] = byte(slot) // make the signature distinguishable
	EncodeDGSigFirst(dg, slot, seq, &sig)
	return dg
}

// scriptedRecv returns a recv func yielding each datagram in order then io.EOF,
// plus a channel closed once every datagram has been handed over. Because drain
// only calls recv again after pushing the previous datagram, that close proves
// all pushes are done — which is what makes the eviction assertions
// deterministic instead of a race with the consumer.
func scriptedRecv(dgs ...[]byte) (func() ([]byte, error), <-chan struct{}) {
	fed := make(chan struct{})
	i := 0
	return func() ([]byte, error) {
		if i >= len(dgs) {
			select {
			case <-fed:
			default:
				close(fed)
			}
			return nil, io.EOF
		}
		dg := dgs[i]
		i++
		return dg, nil
	}, fed
}

// drain reads until EOF and returns the slots that survived the queue.
func drainSlots(t *testing.T, s *SigFirstSub) []uint64 {
	t.Helper()
	var got []uint64
	for {
		item, err := s.Next(context.Background())
		if err == io.EOF {
			return got
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		got = append(got, item.Slot)
	}
}

// A stalled consumer must lose the OLDEST signatures, not the newest — a stale
// signature is worth less than the one that just arrived — and must be able to
// see how many it lost.
func TestSigFirstEvictsOldestWhenConsumerStalls(t *testing.T) {
	var dgs [][]byte
	for slot := uint64(0); slot < 10; slot++ {
		dgs = append(dgs, sigDatagram(slot, slot))
	}
	recv, fed := scriptedRecv(dgs...)
	s := newSigFirstSub(4, recv)
	<-fed // every datagram is in (or already evicted from) the queue

	got := drainSlots(t, s)

	want := []uint64{6, 7, 8, 9}
	if len(got) != len(want) {
		t.Fatalf("survived %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("survived %v, want %v", got, want)
		}
	}
	if d := s.Dropped(); d != 6 {
		t.Fatalf("Dropped() = %d, want 6", d)
	}
}

// Nothing is dropped, and nothing is counted, when the consumer keeps up.
func TestSigFirstDropsNothingWhenConsumerKeepsUp(t *testing.T) {
	recv, fed := scriptedRecv(sigDatagram(1, 0), sigDatagram(2, 1))
	s := newSigFirstSub(4, recv)
	<-fed

	if got := drainSlots(t, s); len(got) != 2 {
		t.Fatalf("survived %v, want both slots", got)
	}
	if d := s.Dropped(); d != 0 {
		t.Fatalf("Dropped() = %d, want 0", d)
	}
	if g := s.Gaps(); g != 0 {
		t.Fatalf("Gaps() = %d, want 0", g)
	}
}

// A malformed datagram (too short for its declared type) is skipped rather
// than surfaced or fatal.
func TestSigFirstSkipsMalformedDatagram(t *testing.T) {
	recv, fed := scriptedRecv([]byte{DGSigFirst, 1, 2, 3}, sigDatagram(42, 0))
	s := newSigFirstSub(4, recv)
	<-fed

	got := drainSlots(t, s)
	if len(got) != 1 || got[0] != 42 {
		t.Fatalf("survived %v, want [42]", got)
	}
}

// An unrecognized datagram type is skipped rather than surfaced or fatal —
// that is what keeps a future wire addition from breaking this client.
func TestSigFirstSkipsUnknownDatagramType(t *testing.T) {
	recv, fed := scriptedRecv([]byte{200, 1, 2, 3}, sigDatagram(42, 0))
	s := newSigFirstSub(4, recv)
	<-fed

	got := drainSlots(t, s)
	if len(got) != 1 || got[0] != 42 {
		t.Fatalf("survived %v, want [42]", got)
	}
}

// A heartbeat datagram is never forwarded as an item, but does fold into the
// gap counter.
func TestSigFirstHeartbeatIsNeverForwardedButUpdatesGaps(t *testing.T) {
	hb := make([]byte, DGHeartbeatMin)
	EncodeDGHeartbeat(hb, 123, 5)
	recv, fed := scriptedRecv(sigDatagram(1, 1), hb)
	s := newSigFirstSub(4, recv)
	<-fed

	got := drainSlots(t, s)
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("survived %v, want [1] (heartbeat must not be forwarded as an item)", got)
	}
	// seq 1 establishes the baseline (no prior item), heartbeat highest_seq=5
	// then reveals trailing loss of 4 (seqs 2,3,4,5 never arrived as items).
	if g := s.Gaps(); g != 4 {
		t.Fatalf("Gaps() = %d, want 4", g)
	}
}

// NoSeqAssigned must never be treated as a real, enormous sequence number.
func TestSigFirstHeartbeatSentinelNeverFabricatesAGap(t *testing.T) {
	hb := make([]byte, DGHeartbeatMin)
	EncodeDGHeartbeat(hb, 123, NoSeqAssigned)
	recv, fed := scriptedRecv(sigDatagram(1, 5), hb)
	s := newSigFirstSub(4, recv)
	<-fed

	drainSlots(t, s)
	if g := s.Gaps(); g != 0 {
		t.Fatalf("Gaps() = %d, want 0 (sentinel must never contribute)", g)
	}
}

// QUIC datagrams are unordered by definition, so a late arrival must not drag
// the watermark backwards and double-charge the next in-order item.
func TestSigFirstGapWatermarkStaysMonotonicUnderReordering(t *testing.T) {
	// seqs 0,2,1,3 arrive in that wire order — zero actual loss. One
	// provisional gap on the 0->2 jump is unavoidable with a scalar
	// watermark, but it must never be double-charged when 3 arrives.
	recv, fed := scriptedRecv(
		sigDatagram(100, 0),
		sigDatagram(100, 2),
		sigDatagram(100, 1),
		sigDatagram(100, 3),
	)
	s := newSigFirstSub(4, recv)
	<-fed

	drainSlots(t, s)
	if g := s.Gaps(); g != 1 {
		t.Fatalf("Gaps() = %d, want 1 (one provisional gap, never double-charged)", g)
	}
}

// Next must honor its context instead of blocking forever on an idle stream.
func TestSigFirstNextRespectsContext(t *testing.T) {
	// A recv that never returns: the connection is open but silent.
	s := newSigFirstSub(4, func() ([]byte, error) { select {} })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Next(ctx); err != context.Canceled {
		t.Fatalf("Next err = %v, want context.Canceled", err)
	}
}
