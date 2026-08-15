// Package pulseclient connects to the Pulse wire-v2 Solana transaction feed
// over QUIC.
//
// A Client owns one QUIC connection and permits exactly one initial feed
// subscription. Create another Client for another feed or tier; use the
// subscription's UpdateFilter method to change the active filter in place.
// The default vote predicate delivers non-vote transactions; true selects
// vote transactions only. Receiving both requires two connections.
//
// Connect verifies the endpoint certificate with the target hostname and the
// system trust store by default. Private certificate authorities can use WithRootCAs,
// WithServerName, or an additional WithSPKIPinSHA256 constraint. The only way
// to disable verification is the explicitly named
// WithInsecureTLSForLocalDevelopment option, which is enforced to literal
// loopback targets before dialing.
//
// SubscribeSigFirst receives unordered QUIC datagrams. Its bounded local queue
// evicts the oldest item when a caller falls behind; QueueStats and Gaps expose
// pressure and provisional wire loss. SubscribeFull receives ordered frames on
// one QUIC stream. Ordered transport does not imply end-to-end losslessness:
// an upstream server queue can discard a transaction before it reaches that
// stream.
//
// QUIC application closes are returned as *TerminalError, preserving the
// application code and reason. CloseInfo.Retry provides the reconnect policy;
// callers must not treat every terminal error as retryable.
package pulseclient
