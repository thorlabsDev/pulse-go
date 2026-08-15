package pulseclient

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientAllowsExactlyOneInitialSubscriptionClaim(t *testing.T) {
	client := &Client{}
	if err := client.claimSubscription(); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := client.claimSubscription(); !errors.Is(err, ErrAlreadySubscribed) {
		t.Fatalf("second claim err = %v, want ErrAlreadySubscribed", err)
	}
}

func TestSubscriptionClaimIsConcurrencySafe(t *testing.T) {
	client := &Client{}
	var successes atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if client.claimSubscription() == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful claims = %d, want 1", successes.Load())
	}
}

func TestBothSubscribeAPIsRejectASecondInitialSubscriptionBeforeIO(t *testing.T) {
	client := &Client{}
	if err := client.claimSubscription(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SubscribeSigFirst(context.Background(), Accounts("account")); !errors.Is(err, ErrAlreadySubscribed) {
		t.Fatalf("SubscribeSigFirst err = %v, want ErrAlreadySubscribed", err)
	}
	if _, err := client.SubscribeFull(context.Background(), Accounts("account")); !errors.Is(err, ErrAlreadySubscribed) {
		t.Fatalf("SubscribeFull err = %v, want ErrAlreadySubscribed", err)
	}
}

func TestSigFirstQueueStatsExposeBoundedBackpressure(t *testing.T) {
	recv, fed := scriptedRecv(sigDatagram(1, 0), sigDatagram(2, 1), sigDatagram(3, 2))
	sub := newSigFirstSub(2, recv)
	<-fed

	stats := sub.QueueStats()
	if stats.Capacity != 2 || stats.Queued != 2 || stats.Dropped != 1 {
		t.Fatalf("QueueStats = %+v, want capacity=2 queued=2 dropped=1", stats)
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}
