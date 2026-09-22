package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"

	crypto "github.com/gmb-eudi/go-eudi-crypto"

	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"

	mgmt "github.com/digimaks/eudi-api-management"
	"github.com/digimaks/eudi-api-management/internal/api"
	"github.com/digimaks/eudi-api-management/internal/sessiondb"
)

// TestCorrelation_CreateBodyToHandoffToWebhook is the correlation-trace test:
// one correlation id must survive across create -> wallet -> pipeline ->
// webhook. This proves the create-body -> envelope -> webhook-header half plus
// the wiring.
//
// createSession MINTS a fresh ULID and sends it in the internal eudi-verifier-core
// request BODY as the `correlation_id` field. That is the session's stable
// through-line identity, which eudi-verifier-core stores in Postgres and threads
// into the handoff envelope. The outbound X-Correlation-ID HTTP header carries
// a per-hop request-trace id instead — a DIFFERENT concern. So this test
// asserts on the BODY field, not the header, at the create hop, and proves the
// id survives into the handoff envelope and out the webhook's own
// X-Correlation-ID header (the webhook consumer carries the envelope's
// CorrelationID on that hop).
//
// Only the create-body -> envelope -> webhook-header half is provable here
// (there is no live eudi-verifier-core pipeline in this unit-test binary); the full
// four-hop LIVE proof, through a real eudi-verifier-core session/pipeline run, is
// covered by end-to-end integration testing.
func TestCorrelation_CreateBodyToHandoffToWebhook(t *testing.T) {
	// A short poll interval so the app's already-wired webhook consumer
	// (registered as a background task and started automatically by
	// newSessionsApp's ta.Start(t) — TestApp.Start starts every registered
	// Tasker) reaches its next cycle quickly instead of waiting the 1s
	// production default. Set BEFORE booting the app so the config env-binding
	// picks it up at load time.
	t.Setenv("HANDOFF_POLL_INTERVAL", "20ms")

	ta, app := newSessionsApp(t)

	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	stub := stubCreated(t)
	stub.attach(app)

	// Step 1: POST /sessions through the real router with the internal
	// eudi-verifier-core API stubbed. Capture the internal request BODY and
	// extract its correlation_id — the session's stable through-line id.
	status, _ := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))

	var sent struct {
		CorrelationID string `json:"correlation_id"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(stub.lastBody, &sent)))
	u := sent.CorrelationID
	_, err := ulid.ParseStrict(u)
	qt.Assert(t, qt.IsNil(err), qt.Commentf("correlation_id %q is not a valid ULID", u))

	// Step 2: seed a handoff envelope carrying correlation_id: u — exactly as
	// eudi-verifier-core round-trips the session row's stored correlation_id value
	// into the envelope it enqueues — and enqueue it for the consumer to drain.
	const sessionID = "corr-trace-session"
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: sessionID, ClientID: clientID, CorrelationID: u, Status: "verified",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	})

	received := make(chan string, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case received <- r.Header.Get("X-Correlation-ID"):
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	seedHandoffEnvelopeWithCorrelation(t, app, sessionID, u, receiver.URL, now)

	// Step 3: let the already-running webhook consumer (started by
	// ta.Start(t), see comment above) drain the queue and deliver — assert
	// the receiver got the SAME id u on its X-Correlation-ID header.
	select {
	case got := <-received:
		qt.Check(t, qt.Equals(got, u), qt.Commentf("webhook X-Correlation-ID must equal the session's create-time correlation_id"))
	case <-time.After(3 * time.Second):
		t.Fatal("webhook receiver never got a request within the deadline")
	}
}

// seedHandoffEnvelopeWithCorrelation writes an encrypted handoff envelope
// carrying correlationID and pushes sessionID onto the handoff queue. Unlike
// the read-path seed helpers, it (a) sets CorrelationID/WebhookURL and (b) also
// LPushes the queue key, so the consumer actually drains it (the GET-polling
// helpers deliberately never enqueue). Kept local to this test to avoid
// changing the shared helper's signature and its existing call sites.
func seedHandoffEnvelopeWithCorrelation(t testing.TB, app *mgmt.App, sessionID, correlationID, webhookURL string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	plain, err := json.Marshal(handoffwire.Result{SessionID: sessionID, Outcome: "verified"})
	qt.Assert(t, qt.IsNil(err))
	pub, err := app.Keys().Public(ctx, handoffwire.KeyHandoffEnc)
	qt.Assert(t, qt.IsNil(err))
	jwe, err := crypto.EncryptJWE(pub, nil, plain)
	qt.Assert(t, qt.IsNil(err))
	env := handoffwire.Envelope{
		Version: 1, SessionID: sessionID, CorrelationID: correlationID, WebhookURL: webhookURL,
		ResultJWE: string(jwe), EnqueuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	envJSON, err := json.Marshal(env)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(app.Valkey().Set(ctx, fmt.Sprintf(handoffwire.PayloadKeyFmt, sessionID), envJSON, time.Hour).Err()))
	qt.Assert(t, qt.IsNil(app.Valkey().LPush(ctx, handoffwire.QueueKey, sessionID).Err()))
}
