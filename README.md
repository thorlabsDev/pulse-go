# Pulse Go SDK

Go client for the Pulse wire-v2 Solana transaction feed over QUIC. The module
path is `github.com/thorlabsDev/pulse-go`; the Go package name is
`pulseclient`.

```sh
go get github.com/thorlabsDev/pulse-go@latest
```

## Quick start

Production connections require a TLS-valid target, a token, and a deliberate
account or program filter. The examples do not default to localhost or the
unfiltered non-vote feed.

```sh
export PULSE_ADDR='<HOST:PORT_FROM_DASHBOARD>'
export PULSE_TOKEN='<TOKEN_FROM_SAME_LOCATION>'
export PULSE_ACCOUNT='<ACCOUNT_OR_PROGRAM_PUBKEY>'

go run ./examples/sigfirst
# or: go run ./examples/fulltx
```

Copy the target and token together from the same dashboard location.

The same flow in application code, with
`github.com/mr-tron/base58` imported for Solana signature text:

```go
ctx := context.Background()

client, err := pulseclient.Connect(
    ctx,
    os.Getenv("PULSE_ADDR"),
    pulseclient.WithToken(os.Getenv("PULSE_TOKEN")),
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

filter := pulseclient.Accounts(os.Getenv("PULSE_ACCOUNT"))
sub, err := client.SubscribeSigFirst(ctx, filter)
if err != nil {
    log.Fatal(err)
}

for {
    item, err := sub.Next(ctx)
    if err != nil {
        if closeInfo, ok := pulseclient.CloseInfoFromError(err); ok {
            log.Fatalf("feed closed: code=%d reason=%q retry=%s",
                closeInfo.Code, closeInfo.Reason, closeInfo.Retry)
        }
        log.Fatal(err)
    }
    fmt.Println(item.Slot, item.Seq, base58.Encode(item.Signature[:]))
}
```

## TLS and authentication

`Connect` uses TLS 1.3, ALPN `pulse`, the target hostname for SNI/certificate
verification, and the system root store. The bearer token is sent in the first
control message only after the TLS handshake succeeds.

Available connection options:

- `WithToken(token)` authenticates the first control message.
- `WithRootCAs(pool)` uses an explicit CA pool (for a private CA, for example).
- `WithServerName(name)` overrides certificate hostname/SNI when dialing an IP.
- `WithSPKIPinSHA256(pin)` adds a 32-byte leaf-SPKI SHA-256 pin on top of normal
  chain and hostname verification.
- `WithAckTimeout` and `WithPreambleTimeout` customize bounded protocol waits.
- `WithSigQueueCapacity` sizes the bounded sig-first handoff queue.
- `WithInsecureTLSForLocalDevelopment()` is the only way to disable certificate
  verification. It is accepted only for literal `localhost`, `127.0.0.0/8`, or
  `::1` targets and rejected before dialing anything else. Never use it with a
  production token.

`ConnectWithToken` remains available as a compatibility convenience:

```go
client, err := pulseclient.ConnectWithToken(ctx, target, token)
```

QUIC is UDP. TCP port forwarding such as `ssh -L` does not carry Pulse traffic.

## Subscription lifecycle

One `Client` owns one QUIC connection and accepts exactly one initial
`SubscribeSigFirst` or `SubscribeFull` call. A second initial subscription
returns `ErrAlreadySubscribed`; create another `Client` for another feed or
tier. Change the active filter with the subscription's `UpdateFilter` method.

Filters support `AccountInclude`, `AccountExclude`, `AccountRequired`, and
the Yellowstone-compatible vote predicate. `Accounts(keys...)` builds an
include filter, and `AllNonVoteTxs()` requests the unfiltered non-vote feed.
An omitted `Vote` or `WithVote(false)` selects non-votes; `WithVote(true)`
selects votes only. It does not add votes to non-votes. Receiving both requires
two Clients/subscriptions merged by the application.

## Delivery semantics

### Sig-first

`SubscribeSigFirst` receives unordered QUIC datagrams containing slot,
per-connection sequence, and signature. The SDK drains them into a bounded
queue and evicts the oldest local item when the consumer falls behind.
`QueueStats()` reports capacity, current depth, and cumulative local drops.
`Gaps()` is a provisional sequence-gap signal and can over-report when
datagrams arrive out of order.

### Full transaction

`SubscribeFull` verifies the stream's six-byte wire-v2 preamble before it
returns. `Next()` yields decoded `FullTxV2` frames in QUIC stream order. Pass
`"alt"` to `SubscribeFull` to request loaded-address enrichment.

Stream ordering is not an end-to-end lossless guarantee. A server-side
subscriber queue can discard a transaction before it is written to the QUIC
stream, and wire v2 does not put a sequence number on every full-tx frame.

## Terminal errors and reconnects

QUIC application closes are returned as `*pulseclient.TerminalError`, not
collapsed to `io.EOF`. `CloseInfoFromError` works through wrapped errors.

| Code | Meaning | Retry class |
|---:|---|---|
| 0 | Normal close | `RetryNormal` |
| 1 | Invalid control message | `RetryNever` |
| 2 | Missing, invalid, or revoked token | `RetryAfterCredentialChange` |
| 3 | Current quota/capacity exhausted | `RetryTransient` |
| 4 | Unsupported wire version | `RetryNever` |
| 5 | Tier/filter not entitled | `RetryNever` |

Only code 3 is retryable unchanged, and it should use bounded backoff. Code 2
requires credential correction. Do not reconnect-loop on codes 1, 4, or 5.

## Compatibility

This release speaks Pulse wire v2 only and requires Go 1.22 or newer. See
[COMPATIBILITY.md](COMPATIBILITY.md) for the wire/package compatibility policy
and [CHANGELOG.md](CHANGELOG.md) for release-facing changes.
