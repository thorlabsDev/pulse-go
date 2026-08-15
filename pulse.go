package pulseclient

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// ErrBadPreamble is returned when the full-tx stream's opening bytes were not
// Preamble — the strongest signal available that this client is not actually
// talking to a wire v2 server (or the stream was corrupted in transit).
// Deliberately its own error: never folded into ErrBadFrame, and never
// silently skipped — the preamble is the one place a client confirms it is
// speaking the protocol it thinks it is.
var ErrBadPreamble = errors.New("pulseclient: bad stream preamble: this server is not speaking pulse wire v2")

// maxFullTxFrame is the allocation-safety ceiling applied to the outer frame
// length before its message type is known. It allows MaxFullTxBody, two
// maximally-sized TLV records, and the message-type/flags header. The decoded
// transaction path separately applies the tighter MaxFullTxBody limit to its
// complete positional-payload-plus-TLV remainder.
const maxFullTxFrame = MaxFullTxBody + 2*(65535+3) + 2

// Filter is the account/vote predicate model the server applies. With no
// account predicates, the zero value subscribes to every non-vote transaction.
type Filter struct {
	AccountInclude  []string `json:"account_include,omitempty"`
	AccountExclude  []string `json:"account_exclude,omitempty"`
	AccountRequired []string `json:"account_required,omitempty"`
	// Vote is the Yellowstone-compatible vote predicate. nil and *false select
	// non-vote transactions; *true selects vote transactions only. The
	// predicate ANDs with the account ones, so e.g.
	// account_include=[Vote111…] with Vote=*false yields the empty set.
	Vote *bool `json:"vote,omitempty"`
}

// AllNonVoteTxs returns a filter matching every non-vote transaction. Pulse's
// omitted vote predicate defaults to false, so a single subscription never
// means both vote and non-vote transactions.
func AllNonVoteTxs() Filter { return Filter{} }

// Accounts returns a filter matching transactions that touch any of the given
// base58 pubkeys / program ids. With the default vote predicate, only matching
// non-vote transactions are delivered.
func Accounts(keys ...string) Filter {
	return Filter{AccountInclude: append([]string(nil), keys...)}
}

// WithVote sets the Yellowstone-compatible vote predicate. true restricts the
// subscription to vote transactions only; false restricts it to non-vote
// transactions only. An omitted predicate also defaults to non-votes. To
// receive both categories, use two Clients and merge their subscriptions.
// It returns a copy, so it composes with Accounts.
func (f Filter) WithVote(isVote bool) Filter {
	f.Vote = &isVote
	return f
}

// control is the JSON control message sent on a bi-directional stream. V
// always declares wire v2 (this SDK speaks no other version); Full selects
// the tier and is only honored on the connection's FIRST control message;
// Fields opts into per-frame enrichment groups (currently just "alt") and is
// only meaningful on the full-tx tier — the sig-first tier carries no
// enrichment under any subscription, so the server simply ignores it there.
type control struct {
	Filter
	Token  string   `json:"token,omitempty"`
	Full   bool     `json:"full"`
	V      int      `json:"v"`
	Fields []string `json:"fields"`
}

// MarshalJSON keeps the three account arrays and fields explicit on the wire,
// including when they are empty. That canonical shape is shared by every SDK
// and avoids nil slices becoming JSON null while still leaving vote absent when
// the caller wants the server default.
func (c control) MarshalJSON() ([]byte, error) {
	type wireControl struct {
		Token           string   `json:"token,omitempty"`
		AccountInclude  []string `json:"account_include"`
		AccountExclude  []string `json:"account_exclude"`
		AccountRequired []string `json:"account_required"`
		Vote            *bool    `json:"vote,omitempty"`
		Full            bool     `json:"full"`
		V               int      `json:"v"`
		Fields          []string `json:"fields"`
	}
	nonNil := func(values []string) []string {
		if values == nil {
			return []string{}
		}
		return values
	}
	return json.Marshal(wireControl{
		Token:           c.Token,
		AccountInclude:  nonNil(c.AccountInclude),
		AccountExclude:  nonNil(c.AccountExclude),
		AccountRequired: nonNil(c.AccountRequired),
		Vote:            c.Vote,
		Full:            c.Full,
		V:               c.V,
		Fields:          nonNil(c.Fields),
	})
}

// Client is a connected Pulse client. A QUIC connection can carry exactly one
// initial feed subscription; call UpdateFilter on that subscription for later
// changes, or create another Client for another feed.
type Client struct {
	conn              quic.Connection
	token             string
	ackTimeout        time.Duration
	preambleTimeout   time.Duration
	sigQueueCapacity  int
	subscriptionTaken atomic.Bool
}

// Connect dials a Pulse server over QUIC with ALPN "pulse". By default it
// verifies the server certificate against the target hostname and system root
// store. Use WithRootCAs, WithServerName, or WithSPKIPinSHA256 for private
// certificate authorities or additional pinning. Verification can only be disabled with the explicitly named
// WithInsecureTLSForLocalDevelopment option.
func Connect(ctx context.Context, addr string, options ...Option) (*Client, error) {
	cfg, err := applyOptions(options)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := newTLSConfig(addr, cfg)
	if err != nil {
		return nil, err
	}
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return nil, wrapConnectionError("dial "+addr, err)
	}
	return &Client{
		conn:             conn,
		token:            cfg.token,
		ackTimeout:       cfg.ackTimeout,
		preambleTimeout:  cfg.preambleTimeout,
		sigQueueCapacity: cfg.sigQueueCapacity,
	}, nil
}

// ConnectWithToken is the token-oriented form of Connect. Additional options
// configure TLS and protocol bounds. New code may prefer
// Connect(ctx, addr, WithToken(token), ...).
func ConnectWithToken(ctx context.Context, addr string, token string, options ...Option) (*Client, error) {
	all := make([]Option, 0, len(options)+1)
	all = append(all, WithToken(token))
	all = append(all, options...)
	return Connect(ctx, addr, all...)
}

// Close tears down the connection.
func (c *Client) Close() error {
	return c.conn.CloseWithError(0, "")
}

// ErrAlreadySubscribed is returned when a Client is used for a second initial
// subscription. Pulse selects one feed and tier from the first control message;
// later control messages are filter updates, not new subscriptions.
var ErrAlreadySubscribed = errors.New("pulseclient: this connection already has an initial subscription")

func (c *Client) claimSubscription() error {
	if !c.subscriptionTaken.CompareAndSwap(false, true) {
		return ErrAlreadySubscribed
	}
	return nil
}

// Ack is a parsed `{"type":"ack","ok":bool,...}` control-channel envelope —
// the server's answer to any control message (first or update).
type Ack struct {
	Type   string                `json:"type,omitempty"`
	OK     bool                  `json:"ok"`
	Reason string                `json:"reason,omitempty"`
	Code   *ApplicationCloseCode `json:"code,omitempty"`
	// V is required on the FIRST control message's ack: the wire
	// version the server actually negotiated
	// (min(client's declared v, the server's max)). Updates normally omit it;
	// when present it must match the established wire version.
	V *int `json:"v,omitempty"`
}

// RejectedError is returned when the server answers a control message with
// `{"ok":false,...}`. It carries the server's stated Reason so a caller
// learns *why* a subscribe or UpdateFilter call was refused, rather than
// getting no error and simply receiving nothing forever.
type RejectedError struct{ Reason string }

func (e *RejectedError) Error() string {
	return fmt.Sprintf("pulseclient: control message rejected: %s", e.Reason)
}

// VersionMismatchError is returned when the server's first-control-message
// ack names a negotiated wire version this SDK does not speak. In practice
// the server closes the connection outright (code 4) rather than acking
// success with a version it can't actually serve, so this is a defensive
// backstop, not the primary version-mismatch signal.
type VersionMismatchError struct{ Negotiated int }

func (e *VersionMismatchError) Error() string {
	return fmt.Sprintf("pulseclient: server negotiated wire v%d, this SDK speaks only wire v%d", e.Negotiated, WireVersion)
}

// ErrMissingNegotiatedVersion is returned when the initial success ack omits
// v. Sig-first datagrams carry no per-message version marker, so accepting such
// an ack would start decoding without proof that the server selected wire v2.
var ErrMissingNegotiatedVersion = errors.New("pulseclient: initial acknowledgement omitted the negotiated wire version")

// maxAckBytes bounds a control-ack envelope's length prefix: acks are a few
// dozen bytes of JSON, so this is generous headroom against a corrupted
// length rather than a realistic ack size.
const maxAckBytes = 16 * 1024

// AckTimeout bounds the complete control round-trip: opening the stream,
// writing the message, and waiting for the server's acknowledgement.
//
// Without it, a peer that accepts the control stream and then neither writes
// nor closes leaves Subscribe* blocked forever: the connection itself is
// healthy, so no connection-level error is ever raised to release the read.
// The server acks as soon as admission completes, so ten seconds is headroom
// for a slow link rather than an expected admission delay.
const AckTimeout = 10 * time.Second

// PreambleTimeout bounds the wait for the full-tx stream and its six-byte
// wire-v2 preamble. A peer that acknowledges the subscription but never opens
// or writes the stream must not leave SubscribeFull blocked forever.
const PreambleTimeout = 10 * time.Second

// sendControl writes one control message on a fresh stream and reads back the
// server's ack. v is always negotiated to WireVersion; fields carries the
// enrichment groups to opt into (e.g. ["alt"]) and is always sent as a JSON
// array — nil is normalized to empty so the wire never carries a bare `null`
// where the server expects a list. A `{"ok":false,...}` ack is surfaced as
// *RejectedError, never silently treated as success — a bad filter or a bad
// token must not look like "subscribed, but nothing is arriving yet".
func (c *Client) sendControl(ctx context.Context, f Filter, full bool, fields []string) (*Ack, error) {
	return controlRoundTrip(ctx, c.conn, c.token, f, full, fields, true, c.ackTimeout)
}

// controlRoundTrip writes one control message (same JSON shape as
// Client.sendControl) and reads back the server's ack envelope on the same
// stream. Shared by the initial subscribe (Client.sendControl) and every
// later UpdateFilter call, which is why token is a parameter rather than
// always c.token: an update never re-sends the token (the first message is
// what admits the connection; updates ride the already-admitted connection).
func controlRoundTrip(ctx context.Context, conn quic.Connection, token string, f Filter, full bool, fields []string, initial bool, timeout time.Duration) (*Ack, error) {
	deadline := boundedDeadline(ctx, timeout)
	roundTripCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	if fields == nil {
		fields = []string{}
	}
	body, err := json.Marshal(control{Filter: f, Token: token, Full: full, V: WireVersion, Fields: fields})
	if err != nil {
		return nil, err
	}
	s, err := conn.OpenStreamSync(roundTripCtx)
	if err != nil {
		return nil, wrapConnectionError("open control stream", err)
	}
	if err := s.SetWriteDeadline(deadline); err != nil {
		return nil, wrapConnectionError("set control write deadline", err)
	}
	if _, err := s.Write(body); err != nil {
		return nil, wrapConnectionError("write control", err)
	}
	// Close the write side; the server reads one JSON value without needing
	// FIN, and the read side stays open for the ack that follows.
	if err := s.Close(); err != nil {
		return nil, wrapConnectionError("close control stream write side", err)
	}
	// Bound the ack read (see AckTimeout): a peer that accepts the stream and
	// then never writes and never closes would otherwise block here forever
	// on a connection that is, at the QUIC layer, perfectly healthy.
	if err := s.SetReadDeadline(deadline); err != nil {
		return nil, wrapConnectionError("set ack read deadline", err)
	}
	ack, err := readAck(s)
	if err != nil {
		return nil, wrapConnectionError("read control acknowledgement", err)
	}
	if initial {
		return checkInitialAck(ack)
	}
	return checkUpdateAck(ack)
}

func boundedDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

// checkAckEnvelope validates and interprets the envelope shared by initial and
// update acknowledgements. Version negotiation is deliberately handled by the
// two phase-specific validators below.
func checkAckEnvelope(ack *Ack) (*Ack, error) {
	// Unsupported-version admission writes a structured error envelope before
	// closing with the same application code. Surface that envelope as the same
	// typed terminal error even when it wins the stream-read/connection-close
	// race and is observed first.
	if ack.Type == "error" && ack.Code != nil {
		return nil, &TerminalError{CloseInfo: CloseInfo{
			Code:   *ack.Code,
			Reason: ack.Reason,
			Remote: true,
			Retry:  ClassifyCloseCode(*ack.Code),
		}}
	}
	if ack.Type == "error" {
		return nil, ErrBadFrame
	}
	if ack.Type != "ack" {
		return nil, ErrBadFrame
	}
	if ack.Code != nil {
		return nil, ErrBadFrame
	}
	if !ack.OK {
		return nil, &RejectedError{Reason: ack.Reason}
	}
	return ack, nil
}

// checkInitialAck requires positive proof that the server selected wire v2.
// This ack is sig-first's only negotiation marker; datagrams have no preamble.
func checkInitialAck(ack *Ack) (*Ack, error) {
	ack, err := checkAckEnvelope(ack)
	if err != nil {
		return nil, err
	}
	if ack.V == nil {
		return nil, ErrMissingNegotiatedVersion
	}
	if *ack.V != WireVersion {
		return nil, &VersionMismatchError{Negotiated: *ack.V}
	}
	return ack, nil
}

// checkUpdateAck validates a post-negotiation filter-update ack. Updates do
// not renegotiate the wire version. They normally omit v; an additive v field
// is accepted only when it matches the established dialect.
func checkUpdateAck(ack *Ack) (*Ack, error) {
	ack, err := checkAckEnvelope(ack)
	if err != nil {
		return nil, err
	}
	if ack.V != nil && *ack.V != WireVersion {
		return nil, &VersionMismatchError{Negotiated: *ack.V}
	}
	return ack, nil
}

// readAck reads one length-delimited ack envelope: the same u32 big-endian
// length prefix as a full-tx frame body, then the JSON.
func readAck(r io.Reader) (*Ack, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, mapTerminalError(err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxAckBytes {
		return nil, ErrBadFrame
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, mapTerminalError(err)
	}
	var ack Ack
	if err := json.Unmarshal(body, &ack); err != nil {
		return nil, ErrBadFrame
	}
	if ack.Type != "ack" && ack.Type != "error" {
		return nil, ErrBadFrame
	}
	return &ack, nil
}

// SigQueueLen is the depth of the SDK's internal sig-first handoff queue.
//
// It exists because quic-go holds only 128 datagrams of its own and silently
// drops new arrivals once that fills. The SDK therefore drains quic-go
// continuously into this queue instead of leaving datagrams there until the
// caller happens to call Next.
const SigQueueLen = 4096

// NoSeqAssigned is the wire sentinel for a heartbeat's HighestSeq meaning
// "nothing has been assigned to this subscriber yet". 0 is a real,
// already-assigned sequence number (the FIRST delivery on any connection is
// seq == 0), so 0 cannot double as "none" — conflating the two would tell a
// client it already missed transaction 0 the instant it connected.
const NoSeqAssigned uint64 = ^uint64(0)

// SigFirstItem is one sig-first delivery: the transaction's slot, this
// subscriber's per-connection sequence number (see SigFirstSub.Gaps), and its
// signature.
type SigFirstItem struct {
	Slot      uint64
	Seq       uint64
	Signature [64]byte
}

// SigFirstSub is a live sig-first subscription.
//
// A goroutine drains the connection into a bounded queue as fast as the network
// delivers, so a slow Next loop costs you the OLDEST items (counted by
// Dropped) rather than silently losing whatever arrives while you work.
type SigFirstSub struct {
	// conn is nil for the test-only newSigFirstSub construction (no real
	// connection to update against); non-nil whenever this came from
	// Client.SubscribeSigFirst.
	conn          quic.Connection
	ch            chan SigFirstItem
	queueCapacity int
	ackTimeout    time.Duration
	dropped       atomic.Uint64
	gaps          atomic.Uint64
	err           error // set before ch closes; read only after ch is drained
}

// SubscribeSigFirst selects the sig-first DATAGRAM tier. This tier has no
// enrichment fields; use SubscribeFull when loaded-address enrichment is
// required.
func (c *Client) SubscribeSigFirst(ctx context.Context, f Filter) (*SigFirstSub, error) {
	if err := c.claimSubscription(); err != nil {
		return nil, err
	}
	if _, err := c.sendControl(ctx, f, false, nil); err != nil {
		return nil, err
	}
	conn := c.conn
	// The drain outlives ctx (which scopes the subscribe call, not the
	// subscription); it ends when the connection does.
	sub := newSigFirstSub(c.sigQueueCapacity, func() ([]byte, error) {
		return conn.ReceiveDatagram(context.Background())
	})
	sub.conn = conn
	sub.ackTimeout = c.ackTimeout
	return sub, nil
}

func newSigFirstSub(queueLen int, recv func() ([]byte, error)) *SigFirstSub {
	s := &SigFirstSub{
		ch:            make(chan SigFirstItem, queueLen),
		queueCapacity: queueLen,
		ackTimeout:    AckTimeout,
	}
	go s.drain(recv)
	return s
}

// UpdateFilter updates the active sig-first filter live (opens a fresh control
// stream) and returns the server's parsed ack, or a
// *RejectedError if the server refused it. The tier cannot change after the
// first control message — this always sends full=false and no token, which
// the server accepts unconditionally on any control message but the first.
func (s *SigFirstSub) UpdateFilter(ctx context.Context, f Filter) (*Ack, error) {
	if s.conn == nil {
		// Test-only construction: no real connection to update against.
		return &Ack{OK: true}, nil
	}
	return controlRoundTrip(ctx, s.conn, "", f, false, nil, false, s.ackTimeout)
}

func (s *SigFirstSub) drain(recv func() ([]byte, error)) {
	defer close(s.ch)
	var lastSeq uint64
	var haveLast bool
	for {
		dg, err := recv()
		if err != nil {
			if err == io.EOF {
				s.err = io.EOF
			} else {
				s.err = mapTerminalError(err)
			}
			return
		}
		d, err := DecodeDatagram(dg)
		if err != nil {
			continue // corrupt bytes, or a known type too short: skip, never fatal
		}
		switch v := d.(type) {
		case SigFirst:
			noteItemSeq(&lastSeq, &haveLast, &s.gaps, v.Seq)
			s.push(SigFirstItem{Slot: v.Slot, Seq: v.Seq, Signature: v.Signature})
		case DatagramHeartbeat:
			noteHeartbeatSeq(&lastSeq, &haveLast, &s.gaps, v.HighestSeq)
		case UnknownDatagram:
			// unrecognized type: skip, never an error — that is what keeps a
			// future datagram type from breaking this client.
		}
	}
}

func (s *SigFirstSub) push(it SigFirstItem) {
	select {
	case s.ch <- it:
	default:
		// Full: evict the oldest, because a stale item is worth less than
		// the one that just arrived. This is the only producer, so the
		// retry cannot fail.
		select {
		case <-s.ch:
			s.dropped.Add(1)
		default:
		}
		select {
		case s.ch <- it:
		default:
			s.dropped.Add(1)
		}
	}
}

// noteItemSeq folds one sig-first item's own Seq into the running
// (last-seen, gap-count) state. A gap is exactly the count of sequence
// numbers skipped between the previous (highest-seen) item this subscriber
// saw and this one.
//
// QUIC DATAGRAMs are explicitly unordered, so out-of-order arrival is
// expected traffic, not a pathology — the watermark (*lastSeq) MUST be
// monotonic (max(last, seq)), never just overwritten with whatever arrived
// most recently. An unconditional overwrite would let a reordered item drag
// the watermark backwards, and the very next in-order item would then be
// charged again for a range that was never actually missing — inflating
// Gaps(), this tier's only loss signal, on a stream that lost nothing.
func noteItemSeq(lastSeq *uint64, haveLast *bool, gaps *atomic.Uint64, seq uint64) {
	if *haveLast {
		last := *lastSeq
		// satAdd1(last), not last+1: a corrupt or hostile datagram could
		// carry seq == NoSeqAssigned (u64 max) as a real item seq — nothing
		// on this path has reason to reject that value (the sentinel is only
		// reserved on the heartbeat side) — and an unguarded +1 would
		// overflow-wrap in a way that could fabricate a gap.
		gaps.Add(satSubU64(seq, satAdd1U64(last)))
		if seq > last {
			*lastSeq = seq
		}
	} else {
		*lastSeq = seq
		*haveLast = true
	}
}

// noteHeartbeatSeq folds a heartbeat's HighestSeq into the running
// (last-seen, gap-count) state. This is what reveals TRAILING loss —
// datagrams dropped after the last item this subscriber actually received,
// which item-to-item comparison alone can never see (there is no next item
// to reveal the hole).
//
// NoSeqAssigned MUST be treated as "no information yet", never as a real,
// enormous sequence number: a naive highestSeq-last on the sentinel would
// report an absurd multi-quintillion gap instead of the true answer, which is
// "nothing assigned yet, so don't guess".
func noteHeartbeatSeq(lastSeq *uint64, haveLast *bool, gaps *atomic.Uint64, highestSeq uint64) {
	if highestSeq == NoSeqAssigned {
		return
	}
	if *haveLast {
		if highestSeq > *lastSeq {
			gaps.Add(highestSeq - *lastSeq)
			*lastSeq = highestSeq
		}
		// else: heartbeat is stale/equal to what item traffic already told
		// us — nothing new to fold in.
	} else {
		// First observation ever, with no item to compare against: establish
		// a baseline rather than alleging a gap we have no evidence for.
		*lastSeq = highestSeq
		*haveLast = true
	}
}

func satAdd1U64(x uint64) uint64 {
	if x == NoSeqAssigned {
		return x
	}
	return x + 1
}

func satSubU64(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// Dropped reports how many items were evicted because the caller's Next loop
// fell behind. Export it: it is the only signal that this is happening, and
// no kernel or NIC counter will show it.
func (s *SigFirstSub) Dropped() uint64 { return s.dropped.Load() }

// Queued reports the current depth of the handoff queue. Sustained depth near
// SigQueueLen means the consumer is about to start losing items.
func (s *SigFirstSub) Queued() int { return len(s.ch) }

// QueueStats is a point-in-time snapshot of the bounded sig-first handoff
// queue. Dropped is cumulative for the subscription.
type QueueStats struct {
	Capacity int
	Queued   int
	Dropped  uint64
}

// QueueStats returns the queue capacity, current depth, and cumulative number
// of evicted items. Sustained depth near Capacity is a backpressure warning.
func (s *SigFirstSub) QueueStats() QueueStats {
	return QueueStats{
		Capacity: s.queueCapacity,
		Queued:   len(s.ch),
		Dropped:  s.dropped.Load(),
	}
}

// Gaps is a provisional loss indicator: item-to-item Seq gaps plus trailing
// loss revealed by a heartbeat's HighestSeq. NoSeqAssigned on the wire never
// contributes to this counter.
//
// It can OVER-report under reordering. QUIC DATAGRAMs are unordered by
// definition, so a scalar high-watermark cannot distinguish "this seq is
// late" from "this seq is lost" at the moment a later one arrives out of
// order — it charges one provisional gap on that jump, and never reverses
// the charge if the late item shows up afterward. A perfectly lossless but
// reordered stream can therefore report Gaps() > 0. Treat this as "loss
// happened, or reordering did" rather than an exact count of sequence numbers
// that never arrived on the wire at all.
func (s *SigFirstSub) Gaps() uint64 { return s.gaps.Load() }

// Next blocks for the next SigFirstItem. A clean datagram source end returns
// io.EOF; a QUIC application close returns *TerminalError with its code and
// reason; ctx.Err() is returned if ctx ends first.
//
// Do the work for each item elsewhere. This call should be a drain loop:
// every microsecond spent between two Next calls is queue depth.
func (s *SigFirstSub) Next(ctx context.Context) (SigFirstItem, error) {
	select {
	case it, ok := <-s.ch:
		if !ok {
			return SigFirstItem{}, s.err
		}
		return it, nil
	case <-ctx.Done():
		return SigFirstItem{}, ctx.Err()
	}
}

// FullSub is a live full-tx subscription.
type FullSub struct {
	conn       quic.Connection
	rs         quic.ReceiveStream
	ackTimeout time.Duration
	heartbeat  atomic.Pointer[heartbeatState]
}

// heartbeatState is the most recent heartbeat observed on a FullSub's stream.
type heartbeatState struct {
	serverTsMs uint64
	highestSeq uint64
	ok         bool
}

// SubscribeFull selects the ordered full-tx stream. fields requests enrichment
// groups (currently just "alt", which adds each frame's ALT-loaded addresses).
// Ordered QUIC delivery does not guarantee that an upstream server queue never
// discards a transaction before it is written to this stream.
//
// The stream's 6-byte preamble is read and verified here, before the
// subscription is ever returned to the caller — a mismatch is a loud
// ErrBadPreamble, never a silent skip.
func (c *Client) SubscribeFull(ctx context.Context, f Filter, fields ...string) (*FullSub, error) {
	if err := c.claimSubscription(); err != nil {
		return nil, err
	}
	if _, err := c.sendControl(ctx, f, true, fields); err != nil {
		return nil, err
	}
	deadline := boundedDeadline(ctx, c.preambleTimeout)
	waitCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	rs, err := c.conn.AcceptUniStream(waitCtx)
	if err != nil {
		return nil, wrapConnectionError("accept full-tx stream", err)
	}
	if err := rs.SetReadDeadline(deadline); err != nil {
		return nil, wrapConnectionError("set full-tx preamble deadline", err)
	}
	if err := verifyPreamble(rs); err != nil {
		return nil, err
	}
	if err := rs.SetReadDeadline(time.Time{}); err != nil {
		return nil, wrapConnectionError("clear full-tx preamble deadline", err)
	}
	return &FullSub{conn: c.conn, rs: rs, ackTimeout: c.ackTimeout}, nil
}

// UpdateFilter updates the active filter/enrichment fields live (opens a
// fresh control stream) and returns the server's parsed ack, or a
// *RejectedError if the server refused it. The tier cannot change after the
// first control message — this always sends full=false and no token, which
// the server accepts unconditionally on any control message but the first.
func (s *FullSub) UpdateFilter(ctx context.Context, f Filter, fields ...string) (*Ack, error) {
	return controlRoundTrip(ctx, s.conn, "", f, false, fields, false, s.ackTimeout)
}

// verifyPreamble reads exactly Preamble's length from r and rejects anything
// else — including a short read at EOF — as ErrBadPreamble.
func verifyPreamble(r io.Reader) error {
	var buf [6]byte
	read, err := io.ReadFull(r, buf[:])
	if err != nil {
		mapped := mapTerminalError(err)
		var terminal *TerminalError
		if errors.As(mapped, &terminal) {
			if read != 0 {
				return errors.Join(ErrBadPreamble, terminal)
			}
			return terminal
		}
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("pulseclient: read stream preamble: %w", err)
		}
		return ErrBadPreamble
	}
	if string(buf[:]) != Preamble {
		return ErrBadPreamble
	}
	return nil
}

// Next awaits the next transaction frame. UnknownFrame message types are
// skipped transparently — a client must never error on a message kind it
// does not recognize — and FrameHeartbeat frames update FullSub.Heartbeat
// instead of being returned. Only a *FullTxV2 is ever handed back here. It
// returns io.EOF at a clean end of stream. A QUIC application close is
// returned as *TerminalError with its code and reason.
func (s *FullSub) Next() (*FullTxV2, error) {
	return nextFrameWithHeartbeat(s.rs, func(heartbeat heartbeatState) {
		s.heartbeat.Store(&heartbeat)
	})
}

// Heartbeat returns the most recent heartbeat observed on this stream:
// (serverTsMs, highestSeq). highestSeq == NoSeqAssigned means the server has
// not assigned this subscriber a transaction yet. ok is false when no
// heartbeat has arrived at all yet (a busy stream can go a long time without
// one — the server resets its heartbeat timer on every real send).
//
// Unlike SigFirstSub.Gaps, the full-tx wire carries no per-frame sequence
// number, so this SDK cannot compute a numeric gap count for this tier —
// highestSeq is the raw signal a caller can compare against its own
// received-frame count if it wants that.
func (s *FullSub) Heartbeat() (serverTsMs, highestSeq uint64, ok bool) {
	heartbeat := s.heartbeat.Load()
	if heartbeat == nil {
		return 0, 0, false
	}
	return heartbeat.serverTsMs, heartbeat.highestSeq, heartbeat.ok
}

// nextFrame reads and decodes the next Frame from r, transparently skipping
// UnknownFrame and folding FrameHeartbeat into *hb until a FullTxV2 arrives or
// the stream ends cleanly. Generic over the reader (rather than tied to
// quic.ReceiveStream) so this framing logic is unit-testable against an
// in-memory pipe instead of requiring a live QUIC stream.
func nextFrame(r io.Reader, hb *heartbeatState) (*FullTxV2, error) {
	return nextFrameWithHeartbeat(r, func(heartbeat heartbeatState) {
		*hb = heartbeat
	})
}

func nextFrameWithHeartbeat(r io.Reader, observeHeartbeat func(heartbeatState)) (*FullTxV2, error) {
	for {
		// Each frame is a u32 big-endian length prefix followed by the body.
		var hdr [4]byte
		read, err := io.ReadFull(r, hdr[:])
		if err != nil {
			mapped := mapTerminalError(err)
			var terminal *TerminalError
			if errors.As(mapped, &terminal) {
				if read != 0 {
					return nil, errors.Join(ErrBadFrame, terminal)
				}
				return nil, terminal
			}
			if err == io.EOF {
				return nil, io.EOF
			}
			return nil, ErrBadFrame // a partial length prefix is a truncated frame
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n > maxFullTxFrame {
			return nil, fmt.Errorf("full-tx frame too large: %d", n)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			mapped := mapTerminalError(err)
			var terminal *TerminalError
			if errors.As(mapped, &terminal) {
				return nil, errors.Join(ErrBadFrame, terminal)
			}
			return nil, ErrBadFrame
		}
		frame, err := DecodeFrame(body)
		if err != nil {
			return nil, err
		}
		switch f := frame.(type) {
		case UnknownFrame:
			continue
		case FrameHeartbeat:
			observeHeartbeat(heartbeatState{serverTsMs: f.ServerTsMs, highestSeq: f.HighestSeq, ok: true})
			continue
		case FullTxV2:
			return &f, nil
		default:
			continue
		}
	}
}
