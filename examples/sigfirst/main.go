// Subscribe to the sig-first tier and print (slot, signature) as they arrive.
//
//	PULSE_ADDR='<HOST:PORT_FROM_DASHBOARD>' PULSE_TOKEN='<TOKEN_FROM_SAME_LOCATION>' PULSE_ACCOUNT='<ACCOUNT_OR_PROGRAM_PUBKEY>' go run ./examples/sigfirst
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/mr-tron/base58"
	pulseclient "github.com/thorlabsDev/pulse-go"
)

func main() {
	addr := os.Getenv("PULSE_ADDR")
	if addr == "" {
		log.Fatal("PULSE_ADDR is required (host:port)")
	}
	token := os.Getenv("PULSE_TOKEN")
	if token == "" {
		log.Fatal("PULSE_TOKEN is required")
	}
	account := os.Getenv("PULSE_ACCOUNT")
	if account == "" {
		log.Fatal("PULSE_ACCOUNT is required (an account or program id)")
	}
	ctx := context.Background()

	c, err := pulseclient.Connect(ctx, addr, pulseclient.WithToken(token))
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	fmt.Printf("connected to %s; subscribing sig-first for %s…\n", addr, account)

	// Unset/false selects matching non-votes. true switches this subscription
	// to matching vote transactions only; use two Clients to receive both.
	flt := pulseclient.Accounts(account)
	if v, ok := os.LookupEnv("PULSE_VOTE"); ok {
		isVote, err := strconv.ParseBool(v)
		if err != nil {
			log.Fatalf("PULSE_VOTE must be true or false: %v", err)
		}
		flt = flt.WithVote(isVote)
	}

	sub, err := c.SubscribeSigFirst(ctx, flt)
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < 20; n++ {
		item, err := sub.Next(ctx)
		if err != nil {
			if closeInfo, ok := pulseclient.CloseInfoFromError(err); ok {
				log.Fatalf("feed closed: code=%d reason=%q retry=%s", closeInfo.Code, closeInfo.Reason, closeInfo.Retry)
			}
			log.Fatal(err)
		}
		fmt.Printf("slot %12d  seq %8d  %s\n", item.Slot, item.Seq, base58.Encode(item.Signature[:]))
	}
	stats := sub.QueueStats()
	fmt.Printf("queue=%d/%d dropped=%d gaps=%d\n", stats.Queued, stats.Capacity, stats.Dropped, sub.Gaps())
}
