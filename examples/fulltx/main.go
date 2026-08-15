// Subscribe to the ordered full-tx tier and print decoded transactions.
//
//	PULSE_ADDR='<HOST:PORT_FROM_DASHBOARD>' PULSE_TOKEN='<TOKEN_FROM_SAME_LOCATION>' PULSE_ACCOUNT='<ACCOUNT_OR_PROGRAM_PUBKEY>' go run ./examples/fulltx
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
	fmt.Printf("connected to %s; subscribing full-tx for %s…\n", addr, account)

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

	sub, err := c.SubscribeFull(ctx, flt, "alt")
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < 20; n++ {
		frame, err := sub.Next()
		if err != nil {
			if closeInfo, ok := pulseclient.CloseInfoFromError(err); ok {
				log.Fatalf("feed closed: code=%d reason=%q retry=%s", closeInfo.Code, closeInfo.Reason, closeInfo.Retry)
			}
			log.Fatal(err)
		}
		tx := frame.Tx
		sig := ""
		if len(tx.Signatures) > 0 {
			sig = base58.Encode(tx.Signatures[0][:])
		}
		fmt.Printf("slot %12d  v0=%v  sigs=%d keys=%d ix=%d atl=%d  alt_incomplete=%v loaded_w=%d loaded_r=%d  %s\n",
			tx.Slot, tx.Versioned, len(tx.Signatures), len(tx.AccountKeys),
			len(tx.Instructions), len(tx.AddressTableLookups),
			frame.AltIncomplete, len(frame.LoadedWritable), len(frame.LoadedReadonly), sig)
	}
	if ts, seq, ok := sub.Heartbeat(); ok {
		fmt.Printf("last heartbeat: server_ts_ms=%d highest_seq=%d\n", ts, seq)
	}
}
