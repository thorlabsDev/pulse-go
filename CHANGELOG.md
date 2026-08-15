# Changelog

All notable changes to the standalone Pulse Go SDK are documented here. The
project follows semantic versioning; the Go package version is independent of
Pulse wire version.

## 0.1.1 - 2026-08-16

- Clarifies public error documentation without changing the Go API or wire
  format.
- Keeps automated dependency updates compatible with the supported Go 1.22
  baseline.

## 0.1.0 - 2026-08-16

### Added

- Resolvable module path `github.com/thorlabsDev/pulse-go` with package name
  `pulseclient`.
- Secure connection options for custom roots, hostname/SNI override, and an
  additional leaf-SPKI SHA-256 pin.
- Explicit `WithInsecureTLSForLocalDevelopment` escape hatch for local
  self-signed servers, enforced to literal loopback targets before dialing.
- Typed `TerminalError` / `CloseInfo` with Pulse close code, reason, remote
  marker, and retry classification.
- Configurable bounded acknowledgement, preamble, and sig-first queue limits.
- Sig-first `QueueStats` backpressure metrics.
- Standalone examples requiring target, token, and a non-empty account/program
  filter.

### Changed

- TLS certificate and hostname verification are enabled by default.
- `AllTxs` is replaced by `AllNonVoteTxs` to reflect the default non-vote
  predicate; `WithVote(true)` is documented as vote-only.
- Sig-first subscribe/filter-update APIs no longer accept unused enrichment
  fields.
- The exported stream `Preamble` is now an immutable string constant.
- `ComputeBudgetProgramID` is now a value-returning function rather than a
  mutable exported array.
- quic-go is upgraded to v0.49.1, which includes the fix for GO-2025-4017.
- Initial acknowledgements must explicitly prove wire-v2 negotiation; update
  acknowledgements are validated separately and cannot renegotiate version.
- The acknowledgement timeout now covers control-stream opening, writing, and
  reading as one bounded operation.
- A QUIC application close during a partial frame preserves both
  `ErrBadFrame` and typed close information.
- A `Client` accepts only one initial subscription per QUIC connection.
- QUIC application closes are no longer collapsed to `io.EOF`.
- Documentation no longer describes the full-tx feed as end-to-end reliable;
  QUIC stream ordering begins only after a frame enters the stream.

### Compatibility

- Wire v2 and control-token behavior are unchanged.
- `Connect(ctx, target)` and `ConnectWithToken(ctx, target, token)` remain
  source compatible, but now require a certificate trusted for the target.
