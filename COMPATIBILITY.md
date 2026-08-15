# Compatibility

## Supported versions

- Go: 1.22 and newer.
- Pulse wire protocol: v2 only.
- QUIC application protocol: ALPN `pulse` over TLS 1.3.

The SDK package version and Pulse wire version are independent. A future Go
module release does not imply a new wire version. The initial control message
always declares wire v2, and the first acknowledgement must negotiate v2.
The full-tx stream additionally begins with the `PLS2 02 00` wire preamble.

## API stability

Stable releases follow semantic versioning. Additive options, decoded fields,
and support for unknown forward-compatible frame/datagram types may ship in a
minor release. Removing or changing exported Go API requires a major release.

Unknown frame and datagram message types are skipped so that an additive wire
extension does not break an older client. Malformed known messages, reserved
flag use, duplicate TLVs, oversized frames, a bad preamble, and a negotiated
version other than v2 return an error.

## Connection behavior

One QUIC connection carries one initial feed subscription. Filter updates stay
on that connection; another feed or tier requires another connection.

An omitted/false vote predicate selects non-vote transactions and true selects
vote transactions only. No single subscription delivers both categories.

The sig-first tier is unordered and may lose datagrams. The full-tx tier is
ordered after bytes enter its QUIC stream, but that does not guarantee that an
upstream server queue delivered every matching transaction to the stream.

## Migrating pre-release clients

Pre-release copies used the unresolved module path `pulseclient` and disabled
TLS verification by default. Replace the import path with:

```go
import pulseclient "github.com/thorlabsDev/pulse-go"
```

`Connect` now verifies system roots and the target hostname. Local self-signed
testing must opt in explicitly with
`WithInsecureTLSForLocalDevelopment()` or, preferably, trust the development
CA with `WithRootCAs`. The insecure option is restricted to literal loopback
targets (`localhost`, `127.0.0.0/8`, and `::1`) and fails before dialing any
other hostname or address.

`ConnectWithToken(ctx, target, token)` remains source compatible. New code can
use `Connect(ctx, target, WithToken(token))` so TLS, timeouts, pinning, and
queue capacity are configured in one place.

QUIC application closes now surface as `*TerminalError`; code that previously
treated every terminal condition as `io.EOF` must apply the retry class.

The misleading pre-release `AllTxs` helper was replaced by
`AllNonVoteTxs`, reflecting the server's default non-vote predicate.
