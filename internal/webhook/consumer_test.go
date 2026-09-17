package webhook

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	crypto "github.com/gmb-eudi/go-eudi-crypto"

	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"

	"github.com/dativa-lv/eudi-api-management/internal/api"
	"github.com/dativa-lv/eudi-api-management/internal/sessiondb"
)

// testKeys builds an in-memory KeyProvider carrying BOTH operator keys
// (crypto.NewStaticProvider — no filesystem, no import cycle back to the
// eudiapimanagement package that wires this package into app.go) and returns the
// handoff-enc key's public half for seeding encrypted envelopes.
func testKeys(t *testing.T) (crypto.KeyProvider, *ecdsa.PublicKey) {
	t.Helper()
	sign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	enc, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{
		handoffwire.KeyWebhookSigning: sign,
		handoffwire.KeyHandoffEnc:     enc,
	})
	return kp, &enc.PublicKey
}

// seedEnvelope encrypts result exactly as eudi-verifier-core does when it writes
// the handoff queue (crypto.EncryptJWE(pub, nil, plain)) and pushes id onto
// vc:handoff:queue with the envelope at vc:handoff:payload:{id} — the Valkey
// key and queue contract, LPUSH id / GET-by-key on the RPOP side.
func seedEnvelope(ctx context.Context, t *testing.T, rdb redis.UniversalClient, encPub *ecdsa.PublicKey, env handoffwire.Envelope, result handoffwire.Result, ttl time.Duration) {
	t.Helper()
	plain, err := json.Marshal(result)
	qt.Assert(t, qt.IsNil(err))
	jwe, err := crypto.EncryptJWE(encPub, nil, plain)
	qt.Assert(t, qt.IsNil(err))
	env.ResultJWE = string(jwe)
	envJSON, err := json.Marshal(env)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(rdb.Set(ctx, fmt.Sprintf(handoffwire.PayloadKeyFmt, env.SessionID), envJSON, ttl).Err()))
	qt.Assert(t, qt.IsNil(rdb.LPush(ctx, handoffwire.QueueKey, env.SessionID).Err()))
}

// recordingReceiver is an httptest webhook receiver that captures every
// request's body/headers and replies with the status the test configures.
type recordingReceiver struct {
	srv    *httptest.Server
	status int

	mu    sync.Mutex
	calls []recordedCall
}

type recordedCall struct {
	body          []byte
	signature     string
	correlationID string
}

func newRecordingReceiver(t *testing.T, status int) *recordingReceiver {
	t.Helper()
	rr := &recordingReceiver{status: status}
	rr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rr.mu.Lock()
		rr.calls = append(rr.calls, recordedCall{
			body:          body,
			signature:     r.Header.Get("X-Payload-Signature"),
			correlationID: r.Header.Get("X-Correlation-ID"),
		})
		rr.mu.Unlock()
		w.WriteHeader(rr.status)
	}))
	t.Cleanup(rr.srv.Close)
	return rr
}

func (rr *recordingReceiver) callCount() int {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return len(rr.calls)
}

func (rr *recordingReceiver) last() recordedCall {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return rr.calls[len(rr.calls)-1]
}

// verifySignature reattaches the detached JWS to the exact body bytes the
// receiver captured and verifies it against the signing key's public half —
// the same check a client performs against the published JWKS, applied here to
// a delivered webhook rather than a bare SignDetached call.
func verifySignature(t *testing.T, keys crypto.KeyProvider, call recordedCall) {
	t.Helper()
	parts := strings.Split(call.signature, ".")
	qt.Assert(t, qt.Equals(len(parts), 3))
	pub, err := keys.Public(context.Background(), handoffwire.KeyWebhookSigning)
	qt.Assert(t, qt.IsNil(err))
	payload := base64.RawURLEncoding.EncodeToString(call.body)
	_, _, err = crypto.VerifyJWS([]byte(parts[0]+"."+payload+"."+parts[2]), pub)
	qt.Assert(t, qt.IsNil(err))
}

// newTestConsumer builds a Consumer wired to rdb/db/keys with a real
// (instrumented-free) http.Client doer, ready for direct runOnce calls —
// tests never Start() the ticker, so the fake clock stays authoritative.
func newTestConsumer(rdb redis.UniversalClient, db sessiondb.Store, keys crypto.KeyProvider, retryBase time.Duration, maxAttempts int, now func() time.Time) (*Consumer, *Retrier) {
	deliverer := NewDeliverer(http.DefaultClient, keys, 5*time.Second)
	retrier := NewRetrier(rdb, retryBase, maxAttempts, now)
	c := NewConsumer(zap.NewNop(), rdb, "", db, deliverer, retrier, time.Second, now).(*Consumer)
	return c, retrier
}

func metricValue(name string, labels map[string]string) uint64 {
	full := name
	if len(labels) > 0 {
		full += "{"
		first := true
		for k, v := range labels {
			if !first {
				full += ","
			}
			first = false
			full += k + "=" + strconv.Quote(v)
		}
		full += "}"
	}
	return metrics.GetOrCreateCounter(full).Get()
}

// TestConsumer_HappyPath_DeliversAndKeepsPayloadForPolling covers the happy
// path: a verified envelope is popped, decrypted, signed, POSTed;
// SetWebhookState transitions to delivered; and the payload key is
// deliberately NOT deleted (polling stays available inside the TTL).
func TestConsumer_HappyPath_DeliversAndKeepsPayloadForPolling(t *testing.T) {
	ctx := context.Background()
	rdb, mr := testRedis(t)
	keys, encPub := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()

	clientID := "client-1"
	db.Seed(sessiondb.Session{ID: "sess-happy", ClientID: clientID, Status: "verified", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})

	receiver := newRecordingReceiver(t, http.StatusOK)
	seedEnvelope(ctx, t, rdb, encPub, handoffwire.Envelope{
		Version: 1, SessionID: "sess-happy", ClientID: clientID, CorrelationID: "corr-happy", WebhookURL: receiver.srv.URL,
		EnqueuedAt: now, ExpiresAt: now.Add(time.Hour),
	}, handoffwire.Result{
		SessionID: "sess-happy", Outcome: "verified",
		Report: &handoffwire.Report{SessionID: "sess-happy", Outcome: "verified", Checks: []handoffwire.CheckResult{{Check: "parse", Outcome: "pass"}}, Policy: map[string]bool{}},
		Credentials: []handoffwire.ResultCredential{{
			QueryCredentialID: "cred1", Format: "mso_mdoc", DoctypeOrVCT: "org.iso.18013.5.1.mDL",
			Claims: map[string]any{"given_name": "CANARY-ALICE"},
		}},
	}, time.Hour)

	c, _ := newTestConsumer(rdb, db, keys, 30*time.Second, 8, func() time.Time { return now })
	c.runOnce(ctx)

	qt.Assert(t, qt.Equals(receiver.callCount(), 1))
	call := receiver.last()
	verifySignature(t, keys, call)
	qt.Check(t, qt.Equals(call.correlationID, "corr-happy"))

	var got api.WebhookPayload
	qt.Assert(t, qt.IsNil(json.Unmarshal(call.body, &got)))
	qt.Check(t, qt.Equals(got.SessionID, "sess-happy"))
	qt.Check(t, qt.Equals(got.State, "verified"))
	qt.Assert(t, qt.IsNotNil(got.Result))
	qt.Assert(t, qt.Equals(len(got.Result.Credentials), 1))
	qt.Check(t, qt.DeepEquals(got.Result.Credentials[0].Claims, map[string]any{"given_name": "CANARY-ALICE"}))
	qt.Assert(t, qt.IsNotNil(got.Report))
	qt.Check(t, qt.Equals(len(got.Report.Checks), 1))

	s, err := db.GetForClient(ctx, clientID, "sess-happy")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(s.WebhookState, "delivered"))

	// A successful delivery does NOT delete the payload — polling stays
	// available within the TTL. Only the Valkey TTL purges it.
	qt.Check(t, qt.IsTrue(mr.Exists(fmt.Sprintf(handoffwire.PayloadKeyFmt, "sess-happy"))))

	// Purge canary: once the TTL elapses, the payload key itself — not a
	// substring grep against ciphertext — must be gone from the ENTIRE
	// keyspace.
	mr.FastForward(25 * time.Hour)
	for _, key := range mr.Keys() {
		val, _ := mr.Get(key)
		qt.Check(t, qt.IsFalse(strings.Contains(val, "CANARY-ALICE")), qt.Commentf("key %q still carries the canary claim value after TTL", key))
	}
	qt.Check(t, qt.IsFalse(mr.Exists(fmt.Sprintf(handoffwire.PayloadKeyFmt, "sess-happy"))))
}

// TestConsumer_PollOnlyEnvelope_SkipsDeliveryNoFailure: a webhook-less
// (poll-only) envelope that somehow reaches the queue is skipped — no delivery
// attempt, no webhook_state transition, no failure alert — and its payload is
// left in place for polling. (eudi-verifier-core does not enqueue such a session for
// delivery; this guards against version skew.)
func TestConsumer_PollOnlyEnvelope_SkipsDeliveryNoFailure(t *testing.T) {
	ctx := context.Background()
	rdb, mr := testRedis(t)
	keys, encPub := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()

	clientID := "client-poll"
	db.Seed(sessiondb.Session{ID: "sess-poll", ClientID: clientID, Status: "verified", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})

	failedBefore := metricValue(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"})

	seedEnvelope(ctx, t, rdb, encPub, handoffwire.Envelope{
		Version: 1, SessionID: "sess-poll", ClientID: clientID, CorrelationID: "corr-poll", WebhookURL: "", // poll-only
		EnqueuedAt: now, ExpiresAt: now.Add(time.Hour),
	}, handoffwire.Result{SessionID: "sess-poll", Outcome: "verified"}, time.Hour)

	c, _ := newTestConsumer(rdb, db, keys, 30*time.Second, 8, func() time.Time { return now })
	c.runOnce(ctx)

	// Skipped, not failed: the seeded 'pending' webhook_state is untouched…
	s, err := db.GetForClient(ctx, clientID, "sess-poll")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(s.WebhookState, "pending"))
	// …and no failure alert fired.
	qt.Check(t, qt.Equals(metricValue(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"}), failedBefore))

	// The payload stays for polling.
	qt.Check(t, qt.IsTrue(mr.Exists(fmt.Sprintf(handoffwire.PayloadKeyFmt, "sess-poll"))))
}

// TestConsumer_ReceiverFails_SchedulesRetryAndStaysDelivering: a non-2xx
// response schedules a retry via the Retrier and leaves the session in
// "delivering" (not reset to pending, not yet terminal).
func TestConsumer_ReceiverFails_SchedulesRetryAndStaysDelivering(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	keys, encPub := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	clientID := "client-2"
	db.Seed(sessiondb.Session{ID: "sess-500", ClientID: clientID, Status: "verified", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})

	receiver := newRecordingReceiver(t, http.StatusInternalServerError)
	seedEnvelope(ctx, t, rdb, encPub, handoffwire.Envelope{
		Version: 1, SessionID: "sess-500", ClientID: clientID, CorrelationID: "corr-500", WebhookURL: receiver.srv.URL,
		EnqueuedAt: now, ExpiresAt: now.Add(time.Hour),
	}, handoffwire.Result{SessionID: "sess-500", Outcome: "verified"}, time.Hour)

	c, retrier := newTestConsumer(rdb, db, keys, 30*time.Second, 8, func() time.Time { return now })
	c.runOnce(ctx)

	qt.Assert(t, qt.Equals(receiver.callCount(), 1))

	s, err := db.GetForClient(ctx, clientID, "sess-500")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(s.WebhookState, "delivering"))

	n, aerr := retrier.attempts(ctx, "sess-500")
	qt.Assert(t, qt.IsNil(aerr))
	qt.Check(t, qt.Equals(n, 1))
	score, serr := rdb.ZScore(ctx, retryZSetKey, "sess-500").Result()
	qt.Assert(t, qt.IsNil(serr))
	qt.Check(t, qt.Equals(score, float64(now.Add(30*time.Second).Unix())))
}

// TestConsumer_RetryPastExpiry_TerminalFailureWithAlert: repeated failures
// that would push the next attempt past env.ExpiresAt end in a terminal
// failure — err:webhook:deliveryFailed plus an increment of the alert metric.
func TestConsumer_RetryPastExpiry_TerminalFailureWithAlert(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	keys, encPub := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	clientID := "client-3"
	db.Seed(sessiondb.Session{ID: "sess-exhaust", ClientID: clientID, Status: "verified", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})

	receiver := newRecordingReceiver(t, http.StatusInternalServerError)
	// ExpiresAt is short enough that the SECOND failure's next attempt
	// (base×2^1=60s after a first attempt at now+30s => now+90s) falls past
	// it, forcing ErrExpired on that second Schedule call.
	expiresAt := now.Add(40 * time.Second)
	seedEnvelope(ctx, t, rdb, encPub, handoffwire.Envelope{
		Version: 1, SessionID: "sess-exhaust", ClientID: clientID, CorrelationID: "corr-exhaust", WebhookURL: receiver.srv.URL,
		EnqueuedAt: now, ExpiresAt: expiresAt,
	}, handoffwire.Result{SessionID: "sess-exhaust", Outcome: "verified"}, time.Hour)

	before := metricValue(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"})

	clock := now
	c, _ := newTestConsumer(rdb, db, keys, 30*time.Second, 8, func() time.Time { return clock })
	c.runOnce(ctx) // 1st failure: attempt=0, schedules retry at now+30s

	s, err := db.GetForClient(ctx, clientID, "sess-exhaust")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(s.WebhookState, "delivering"))

	clock = now.Add(30 * time.Second)
	c.runOnce(ctx) // due retry fires: 2nd failure, attempt=1 => next=+90s > expiresAt(+40s) => terminal

	qt.Assert(t, qt.Equals(receiver.callCount(), 2))
	s, err = db.GetForClient(ctx, clientID, "sess-exhaust")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(s.WebhookState, "failed"))
	qt.Check(t, qt.Equals(db.LastWebhookErrCode("sess-exhaust"), "err:webhook:deliveryFailed"))

	after := metricValue(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"})
	qt.Check(t, qt.Equals(after-before, uint64(1)))
}

// TestConsumer_PayloadMissingAtPop_ImmediateTerminalFailure: the queue held
// an id whose payload key is already gone (session expired before the
// consumer got to it) — this is a terminal failure with no delivery attempt.
func TestConsumer_PayloadMissingAtPop_ImmediateTerminalFailure(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	keys, _ := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	clientID := "client-4"
	db.Seed(sessiondb.Session{ID: "sess-gone", ClientID: clientID, Status: "verified", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})

	// Queue the id WITHOUT ever writing vc:handoff:payload:sess-gone.
	qt.Assert(t, qt.IsNil(rdb.LPush(ctx, handoffwire.QueueKey, "sess-gone").Err()))

	before := metricValue(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"})
	c, _ := newTestConsumer(rdb, db, keys, 30*time.Second, 8, func() time.Time { return now })
	c.runOnce(ctx)

	s, err := db.GetForClient(ctx, clientID, "sess-gone")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(s.WebhookState, "failed"))
	qt.Check(t, qt.Equals(db.LastWebhookErrCode("sess-gone"), "err:webhook:deliveryFailed"))

	after := metricValue(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"})
	qt.Check(t, qt.Equals(after-before, uint64(1)))
}

// flakyGetOnceClient wraps a real redis.UniversalClient and forces exactly
// one GET error for a chosen key — the seam
// TestConsumer_TransientPayloadReadError_ReEnqueuesWithoutTerminal uses to
// simulate a transient infra error on the payload read (as opposed to a
// genuinely-missing key, which is redis.Nil) without killing the whole
// connection. Every other command — including a later GET for the same key —
// passes through to the embedded client untouched.
type flakyGetOnceClient struct {
	redis.UniversalClient
	failKey string

	mu    sync.Mutex
	fired bool
}

func (f *flakyGetOnceClient) Get(ctx context.Context, key string) *redis.StringCmd {
	f.mu.Lock()
	shouldFail := !f.fired && key == f.failKey
	if shouldFail {
		f.fired = true
	}
	f.mu.Unlock()
	if shouldFail {
		cmd := redis.NewStringCmd(ctx, "get", key)
		cmd.SetErr(errors.New("forced transient redis error"))
		return cmd
	}
	return f.UniversalClient.Get(ctx, key)
}

// TestConsumer_TransientPayloadReadError_ReEnqueuesWithoutTerminal is a
// regression guard: processOne is only ever called with an id already popped
// off its source (the queue's RPOP, or the retry ZSET's ZRem-claim) — so a
// transient (non-redis.Nil) error on the payload GET that follows must NOT
// silently drop the id. It must go back onto vc:handoff:queue for a later
// cycle to retry, and must NOT be treated as a delivery attempt or terminal
// failure (state stays whatever it already was; no failure-metric bump).
func TestConsumer_TransientPayloadReadError_ReEnqueuesWithoutTerminal(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	keys, _ := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	clientID := "client-flaky"
	db.Seed(sessiondb.Session{ID: "sess-flaky", ClientID: clientID, Status: "verified", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})

	// The payload key genuinely exists (so a correctly-behaving retry would
	// succeed) — only the FIRST GET on it is forced to fail transiently.
	payloadKey := fmt.Sprintf(handoffwire.PayloadKeyFmt, "sess-flaky")
	qt.Assert(t, qt.IsNil(rdb.Set(ctx, payloadKey, "irrelevant-because-get-fails-first", time.Hour).Err()))
	flaky := &flakyGetOnceClient{UniversalClient: rdb, failKey: payloadKey}

	before := metricValue(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"})
	c, _ := newTestConsumer(flaky, db, keys, 30*time.Second, 8, func() time.Time { return now })

	// processOne's contract starts AFTER the id is already popped off its
	// source — call it directly (mirroring what runOnce does per-id) so the
	// re-enqueue is observed in isolation, rather than immediately re-drained
	// by runOnce's own drain-to-Nil loop within the same cycle.
	c.processOne(ctx, "sess-flaky")

	remaining, err := rdb.LRange(ctx, handoffwire.QueueKey, 0, -1).Result()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(remaining, []string{"sess-flaky"}), qt.Commentf("a transient GET error must re-enqueue the id, not drop it"))

	s, err := db.GetForClient(ctx, clientID, "sess-flaky")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(s.WebhookState, "pending"), qt.Commentf("a re-enqueued id must not be marked terminal"))

	after := metricValue(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"})
	qt.Check(t, qt.Equals(after-before, uint64(0)), qt.Commentf("a transient GET error must not count as a delivery attempt/failure"))
}

// TestConsumer_CorruptResultJWE_ImmediateTerminalNoRetry is a regression
// guard: an undecryptable/malformed result_jwe must fail IMMEDIATELY (no retry
// scheduled), exactly like the missing-payload/malformed-envelope terminal
// paths, rather than being routed to the Retrier as if it were a transient
// transport failure. Contrast with
// TestConsumer_ReceiverFails_SchedulesRetryAndStaysDelivering (a POST
// transport failure), which MUST still schedule a retry.
func TestConsumer_CorruptResultJWE_ImmediateTerminalNoRetry(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	keys, _ := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	clientID := "client-corrupt"
	db.Seed(sessiondb.Session{ID: "sess-corrupt", ClientID: clientID, Status: "verified", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})

	// Encrypt result_jwe to a key OTHER than the one wired into `keys` for
	// KeyHandoffEnc, so buildPayload's crypto.DecryptJWE call fails — a
	// structurally valid JWE that is genuinely undecryptable, exercising the
	// permanent-payload path rather than a transport failure.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	plain, err := json.Marshal(handoffwire.Result{SessionID: "sess-corrupt", Outcome: "verified"})
	qt.Assert(t, qt.IsNil(err))
	jwe, err := crypto.EncryptJWE(&wrongKey.PublicKey, nil, plain)
	qt.Assert(t, qt.IsNil(err))

	receiver := newRecordingReceiver(t, http.StatusOK) // must NEVER be called
	env := handoffwire.Envelope{
		Version: 1, SessionID: "sess-corrupt", ClientID: clientID, CorrelationID: "corr-corrupt", WebhookURL: receiver.srv.URL,
		EnqueuedAt: now, ExpiresAt: now.Add(time.Hour), ResultJWE: string(jwe),
	}
	envJSON, err := json.Marshal(env)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(rdb.Set(ctx, fmt.Sprintf(handoffwire.PayloadKeyFmt, "sess-corrupt"), envJSON, time.Hour).Err()))
	qt.Assert(t, qt.IsNil(rdb.LPush(ctx, handoffwire.QueueKey, "sess-corrupt").Err()))

	before := metricValue(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"})
	c, _ := newTestConsumer(rdb, db, keys, 30*time.Second, 8, func() time.Time { return now })
	c.runOnce(ctx)

	qt.Check(t, qt.Equals(receiver.callCount(), 0), qt.Commentf("a permanent payload error must never reach the webhook POST"))

	s, gerr := db.GetForClient(ctx, clientID, "sess-corrupt")
	qt.Assert(t, qt.IsNil(gerr))
	qt.Check(t, qt.Equals(s.WebhookState, "failed"))
	qt.Check(t, qt.Equals(db.LastWebhookErrCode("sess-corrupt"), "err:webhook:deliveryFailed"))

	after := metricValue(MetricWebhookDeliveryTotal, map[string]string{"outcome": "failed"})
	qt.Check(t, qt.Equals(after-before, uint64(1)))

	_, zerr := rdb.ZScore(ctx, retryZSetKey, "sess-corrupt").Result()
	qt.Check(t, qt.ErrorIs(zerr, redis.Nil), qt.Commentf("a permanent payload error must not schedule a retry"))
}

// TestConsumer_FailedOutcome_NoResultButReportAndFailure: a "failed" pipeline
// outcome still decrypts (result_jwe is always encrypted, verified or not)
// but the built payload carries the report/failure — never a Result (no
// credentials on a failed verification).
func TestConsumer_FailedOutcome_NoResultButReportAndFailure(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	keys, encPub := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	clientID := "client-5"
	db.Seed(sessiondb.Session{ID: "sess-failed", ClientID: clientID, Status: "failed", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})

	receiver := newRecordingReceiver(t, http.StatusOK)
	seedEnvelope(ctx, t, rdb, encPub, handoffwire.Envelope{
		Version: 1, SessionID: "sess-failed", ClientID: clientID, CorrelationID: "corr-failed", WebhookURL: receiver.srv.URL,
		EnqueuedAt: now, ExpiresAt: now.Add(time.Hour),
	}, handoffwire.Result{
		SessionID: "sess-failed", Outcome: "failed",
		Report: &handoffwire.Report{SessionID: "sess-failed", Outcome: "failed", FailCode: "err:oid4vp:device-binding-failed", Policy: map[string]bool{}},
	}, time.Hour)

	c, _ := newTestConsumer(rdb, db, keys, 30*time.Second, 8, func() time.Time { return now })
	c.runOnce(ctx)

	qt.Assert(t, qt.Equals(receiver.callCount(), 1))
	var got api.WebhookPayload
	qt.Assert(t, qt.IsNil(json.Unmarshal(receiver.last().body, &got)))
	qt.Check(t, qt.Equals(got.State, "failed"))
	qt.Check(t, qt.IsNil(got.Result))
	qt.Assert(t, qt.IsNotNil(got.Failure))
	qt.Check(t, qt.Equals(got.Failure.Code, "err:oid4vp:device-binding-failed"))
}

// TestConsumer_StartRunsTickerLoopAndStopHalts exercises the actual
// core.Tasker wiring (Name/Start/Stop) rather than calling runOnce directly:
// Start must run an immediate first cycle (so a freshly-deployed pod does not
// wait a full poll interval to drain a backlog) and keep ticking until Stop,
// which must be safe to call more than once.
func TestConsumer_StartRunsTickerLoopAndStopHalts(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	keys, encPub := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	clientID := "client-start"
	db.Seed(sessiondb.Session{ID: "sess-start", ClientID: clientID, Status: "verified", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})

	receiver := newRecordingReceiver(t, http.StatusOK)
	seedEnvelope(ctx, t, rdb, encPub, handoffwire.Envelope{
		Version: 1, SessionID: "sess-start", ClientID: clientID, CorrelationID: "corr-start", WebhookURL: receiver.srv.URL,
		EnqueuedAt: now, ExpiresAt: now.Add(time.Hour),
	}, handoffwire.Result{SessionID: "sess-start", Outcome: "verified"}, time.Hour)

	deliverer := NewDeliverer(http.DefaultClient, keys, 5*time.Second)
	retrier := NewRetrier(rdb, 30*time.Second, 8, time.Now)
	tasker := NewConsumer(zap.NewNop(), rdb, "", db, deliverer, retrier, 10*time.Millisecond, time.Now)
	qt.Check(t, qt.Equals(tasker.Name(), "webhook-consumer"))
	qt.Assert(t, qt.IsNil(tasker.Start(ctx)))
	t.Cleanup(tasker.Stop)

	deadline := time.Now().Add(2 * time.Second)
	for receiver.callCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	qt.Assert(t, qt.Equals(receiver.callCount(), 1))

	tasker.Stop()
	tasker.Stop() // safe to call more than once
}
