package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"azugo.io/core"

	crypto "github.com/gmb-eudi/go-eudi-crypto"
	"github.com/gmb-lib/go-platform-kit/observability"
	"github.com/gmb-lib/go-platform-kit/propagation"

	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"

	"github.com/dativa-lv/eudi-api-management/internal/api"
	"github.com/dativa-lv/eudi-api-management/internal/keyspace"
	"github.com/dativa-lv/eudi-api-management/internal/obs"
	"github.com/dativa-lv/eudi-api-management/internal/results"
	"github.com/dativa-lv/eudi-api-management/internal/sessiondb"
)

// MetricWebhookDeliveryTotal counts webhook delivery outcomes
// ({outcome="delivered"|"failed"}) and is the signal an operator alerts on
// when a delivery fails terminally. Label values come from a closed set:
// never a session id, never anything derived from wallet input.
//
// This re-exports obs.MetricWebhookDeliveryTotal (the single source of the
// metric name) under this package's own name so the call sites below and
// their tests require no changes.
const MetricWebhookDeliveryTotal = obs.MetricWebhookDeliveryTotal

// Doer is the outbound seam for webhook POSTs. A background consumer has no
// inbound request to carry, so it cannot use the request-scoped outbound HTTP
// client the request handlers use; instead production wires an
// observability-instrumented *http.Client (which already satisfies this
// interface via its own Do method), and tests inject a recording fake or
// http.DefaultClient against an httptest server.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Deliverer builds and signs one webhook POST — either from a handoff
// Envelope (decrypting result_jwe) or from an already-built payload (the
// Sweeper's expired-session path, which never reaches the handoff queue) —
// and treats any 2xx response as delivered. Bodies carry claim values and
// are never logged.
type Deliverer struct {
	doer    Doer
	keys    crypto.KeyProvider
	timeout time.Duration
}

// NewDeliverer builds a Deliverer over doer (in production, an
// observability.InstrumentHTTPClient-wrapped *http.Client).
func NewDeliverer(doer Doer, keys crypto.KeyProvider, timeout time.Duration) *Deliverer {
	return &Deliverer{doer: doer, keys: keys, timeout: timeout}
}

// ErrPermanentPayload marks a payload-decode failure that predates any
// delivery attempt — a corrupt/undecryptable result_jwe or malformed result
// JSON. Retrying changes nothing about a payload that will never decode,
// unlike a transient transport (POST) failure — so processOne routes an error
// wrapping this sentinel straight to the terminal path instead of the Retrier:
// fail closed, with no silent indefinite retry against an unwinnable payload.
var ErrPermanentPayload = errors.New("webhook: permanent payload error")

// Deliver decrypts env.ResultJWE (always encrypted, whatever the pipeline
// outcome — verified or failed; an already-expired session never reaches the
// handoff queue in the first place), builds the api.WebhookPayload, signs it,
// and POSTs it to env.WebhookURL. A decrypt/unmarshal failure in buildPayload
// returns an error wrapping ErrPermanentPayload; a transport (POST) failure in
// send does not — processOne distinguishes the two.
func (d *Deliverer) Deliver(ctx context.Context, env *handoffwire.Envelope) error {
	payload, err := d.buildPayload(ctx, env)
	if err != nil {
		return err
	}
	return d.send(ctx, env.WebhookURL, env.CorrelationID, payload)
}

// DeliverPayload signs and POSTs an already-built payload — the Sweeper's
// path: an expired session was never enqueued, so there is no
// Envelope/ResultJWE to decrypt.
func (d *Deliverer) DeliverPayload(ctx context.Context, webhookURL, correlationID string, payload *api.WebhookPayload) error {
	return d.send(ctx, webhookURL, correlationID, payload)
}

// buildPayload decrypts env.ResultJWE with the operator handoff-enc key and
// maps the plaintext Result onto the wire DTO: State mirrors the pipeline
// outcome (verified|failed — never "expired", the Sweeper's exclusive
// state); a verified outcome carries Result (claim values); either outcome
// carries Report/Failure when the pipeline attached one.
func (d *Deliverer) buildPayload(ctx context.Context, env *handoffwire.Envelope) (*api.WebhookPayload, error) {
	plain, _, err := crypto.DecryptJWE(ctx, d.keys, handoffwire.KeyHandoffEnc, []byte(env.ResultJWE))
	if err != nil {
		// Permanent: a corrupt/wrong-key result_jwe will never decrypt on
		// retry. go-eudi-crypto decrypt errors are safe/static (never echo
		// plaintext), so wrapping err here is fine.
		return nil, fmt.Errorf("webhook: decrypt result_jwe: %w: %w", ErrPermanentPayload, err)
	}

	var res handoffwire.Result
	unmarshalErr := json.Unmarshal(plain, &res)
	zero(plain) // the plaintext buffer's job ends here; zero it so it does not linger
	if unmarshalErr != nil {
		// Permanent: malformed JSON will never parse on retry either.
		return nil, fmt.Errorf("webhook: malformed result: %w: %w", ErrPermanentPayload, unmarshalErr)
	}

	payload := &api.WebhookPayload{SessionID: env.SessionID, State: res.Outcome}

	if res.Report != nil {
		repJSON, err := json.Marshal(res.Report)
		if err != nil {
			return nil, fmt.Errorf("webhook: re-marshal embedded report: %w", err)
		}
		report, failure, err := results.MapReport(repJSON)
		if err != nil {
			return nil, err
		}
		payload.Report = report
		payload.Failure = failure
	}

	if res.Outcome == "verified" {
		payload.Result = mapResultCredentials(&res)
	}

	return payload, nil
}

// mapResultCredentials projects a decrypted handoffwire.Result's Credentials
// onto the API DTO — mirrors internal/results.Fetch's own (unexported)
// mapResult; duplicated in miniature here rather than exported from results
// solely for this package, since the two call sites otherwise share nothing.
func mapResultCredentials(res *handoffwire.Result) *api.VerificationResult {
	out := &api.VerificationResult{Credentials: make([]api.ResultCredential, 0, len(res.Credentials))}
	for _, c := range res.Credentials {
		out.Credentials = append(out.Credentials, api.ResultCredential{
			QueryID:      c.QueryCredentialID,
			Format:       c.Format,
			DoctypeOrVCT: c.DoctypeOrVCT,
			Claims:       c.Claims,
		})
	}
	return out
}

// send marshals payload, signs it (RFC 7515 App. F detached JWS), and POSTs
// it with X-Payload-Signature + X-Correlation-ID. Any 2xx response is
// delivered; the response body is drained (for connection reuse) but never
// inspected or logged.
func (d *Deliverer) send(ctx context.Context, webhookURL, correlationID string, payload *api.WebhookPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: marshal payload: %w", err)
	}

	sig, err := SignDetached(ctx, d.keys, body)
	if err != nil {
		return fmt.Errorf("webhook: sign payload: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Payload-Signature", sig)
	if correlationID != "" {
		req.Header.Set(propagation.HeaderCorrelationID, correlationID)
	}

	resp, err := d.doer.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: post: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body) // never inspect/log the body; drain for connection reuse
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: non-2xx response: %d", resp.StatusCode)
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// decodeEnvelope parses raw payload bytes into an Envelope — the one place in
// this package where bytes crossing the eudi-verifier-core/eudi-api-management service
// boundary are decoded, and the target of FuzzDecodeEnvelope. Never panics on
// malformed input.
func decodeEnvelope(raw []byte) (*handoffwire.Envelope, error) {
	var env handoffwire.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("webhook: malformed envelope: %w", err)
	}
	return &env, nil
}

// Consumer drains vc:handoff:queue (RPOP) and the Retrier's due-retry set,
// delivering each session's result via Deliverer and rescheduling failures
// through Retrier until its ExpiresAt/max-attempts bound: retries live inside
// the result TTL — never longer, and never a DB fallback for the payload.
type Consumer struct {
	log       *zap.Logger
	rdb       redis.UniversalClient
	db        sessiondb.Store
	deliverer *Deliverer
	retrier   *Retrier
	poll      time.Duration
	now       func() time.Time
	prefix    keyspace.Prefix

	ticker   *time.Ticker
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewConsumer builds the queue-draining core.Tasker (wired via a.AddTask in
// app.go). prefix is the deployment key prefix (see keyspace) under which the
// producer wrote the queue and payloads; it must equal the producer's.
func NewConsumer(log *zap.Logger, rdb redis.UniversalClient, prefix keyspace.Prefix, db sessiondb.Store, d *Deliverer, r *Retrier, poll time.Duration, now func() time.Time) core.Tasker {
	if now == nil {
		now = time.Now
	}
	return &Consumer{log: log, rdb: rdb, prefix: prefix, db: db, deliverer: d, retrier: r, poll: poll, now: now}
}

// Name implements core.Tasker.
func (c *Consumer) Name() string { return "webhook-consumer" }

// Start implements core.Tasker: runs one cycle immediately, then on every
// poll tick.
func (c *Consumer) Start(ctx context.Context) error {
	c.stopCh = make(chan struct{})
	c.ticker = time.NewTicker(c.poll)
	go func() {
		c.runOnce(ctx)
		for {
			select {
			case <-c.stopCh:
				return
			case <-c.ticker.C:
				c.runOnce(ctx)
			}
		}
	}()
	return nil
}

// Stop implements core.Tasker. Safe to call more than once.
func (c *Consumer) Stop() {
	c.stopOnce.Do(func() {
		if c.ticker != nil {
			c.ticker.Stop()
		}
		close(c.stopCh)
	})
}

// runOnce drains the queue, then re-attempts anything the Retrier marks due.
func (c *Consumer) runOnce(ctx context.Context) {
	for {
		id, err := c.rdb.RPop(ctx, c.prefix.Key(handoffwire.QueueKey)).Result()
		if errors.Is(err, redis.Nil) {
			break
		}
		if err != nil {
			c.log.Error("webhook: queue drain failed", zap.Error(err))
			break
		}
		c.processOne(ctx, id)
	}

	due, err := c.retrier.Due(ctx, c.now())
	if err != nil {
		c.log.Error("webhook: retry due query failed", zap.Error(err))
		return
	}
	for _, id := range due {
		c.processOne(ctx, id)
	}
}

// processOne delivers one session's result. It is only ever called with an
// id already popped off its source (the queue's RPOP, or the retry ZSET's
// ZRem-claim in runOnce) — so any early return here must account for that id
// no longer existing anywhere else. Payload missing at pop (session expired
// before the consumer got to it) is an IMMEDIATE terminal failure — fail
// closed, never a silent drop; a malformed envelope is the same. A TRANSIENT
// (non-redis.Nil) error reading the payload is different: the id is real, so
// it is re-enqueued for a later cycle rather than lost or marked terminal.
// Otherwise it marks "delivering", attempts delivery, and on failure either
// routes straight to terminal (a permanent payload error, ErrPermanentPayload)
// or asks the Retrier to schedule the next attempt — Schedule's own
// ErrExhausted/ErrExpired is terminal too.
func (c *Consumer) processOne(ctx context.Context, id string) {
	raw, err := c.rdb.Get(ctx, c.prefix.Key(fmt.Sprintf(handoffwire.PayloadKeyFmt, id))).Bytes()
	if errors.Is(err, redis.Nil) {
		c.terminal(ctx, id)
		return
	}
	if err != nil {
		// Transient infra error, not a missing key: the RPOP/ZRem-claim that
		// preceded this call already removed id from its source, so it must
		// go back onto the queue or it is lost forever (never rescheduled,
		// never terminal). Not a delivery attempt — no failure metric, no
		// state change. No session id in the log; this call site has no
		// envelope/correlation id to log instead.
		c.log.Warn("webhook: read payload failed transiently, re-enqueueing", zap.Error(err))
		if perr := c.rdb.LPush(ctx, c.prefix.Key(handoffwire.QueueKey), id).Err(); perr != nil {
			c.log.Error("webhook: re-enqueue after transient payload read failure failed", zap.Error(perr))
		}
		return
	}

	env, err := decodeEnvelope(raw)
	if err != nil {
		c.log.Error("webhook: malformed envelope", zap.Error(err))
		c.terminal(ctx, id)
		return
	}

	// Poll-only session: no webhook registered, so there is nothing to deliver
	// and this is not a failure — no webhook_state transition, no alert. The
	// encrypted result stays in Valkey for the client to poll until its TTL
	// elapses. eudi-verifier-core does not enqueue a webhook-less session for
	// delivery, so this is a defensive guard against one ever reaching the
	// queue (e.g. across a version skew).
	if env.WebhookURL == "" {
		return
	}

	if err := c.db.SetWebhookState(ctx, id, "delivering", ""); err != nil {
		c.log.Error("webhook: set delivering state failed", zap.Error(err))
	}

	// Captured in the func's outer scope (not `if deliverErr := ...; ...`)
	// because the ErrPermanentPayload check below needs it in the failure
	// branch too — an if-statement's short variable declaration would fall
	// out of scope at its closing brace.
	deliverErr := c.deliverer.Deliver(ctx, env)
	if deliverErr == nil {
		if err := c.db.SetWebhookState(ctx, id, "delivered", ""); err != nil {
			c.log.Error("webhook: set delivered state failed", zap.Error(err))
		}
		observability.IncCounter(MetricWebhookDeliveryTotal, map[string]string{"outcome": "delivered"})
		return
	}

	if errors.Is(deliverErr, ErrPermanentPayload) {
		// An undecryptable/malformed result_jwe will never succeed on retry —
		// route straight to terminal, exactly like the
		// missing-payload/malformed-envelope paths above, rather than burning
		// retry attempts against an unwinnable payload.
		c.log.Error("webhook: permanent payload error", zap.Error(deliverErr))
		c.terminal(ctx, id)
		return
	}

	attempt, aerr := c.retrier.attempts(ctx, id)
	if aerr != nil {
		c.log.Error("webhook: read attempt counter failed", zap.Error(aerr))
	}
	if err := c.retrier.Schedule(ctx, id, attempt, env.ExpiresAt); err != nil {
		// ErrExhausted or ErrExpired: retries live inside the result TTL,
		// never a DB fallback — terminal.
		c.terminal(ctx, id)
		return
	}
}

// terminal marks id's webhook delivery as failed and increments the alert
// metric — the ONLY two effects of a terminal failure (no payload deletion:
// the Valkey TTL is the sole purge mechanism).
func (c *Consumer) terminal(ctx context.Context, id string) {
	if err := c.db.SetWebhookState(ctx, id, "failed", "err:webhook:deliveryFailed"); err != nil {
		c.log.Error("webhook: set failed state failed", zap.Error(err))
	}
	observability.IncCounter(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"})
}
