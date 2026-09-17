package sessiondb

import (
	"encoding/json"
	"testing"
	"time"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/go-quicktest/qt"
)

// session:not_cancellable only maps to 409 once the "not-cancellable" reason
// is registered (app.go, at service startup). This test binary never runs
// app.go's init (sessiondb can't import the eudiapimanagement package:
// eudiapimanagement imports sessiondb, not the reverse), so mirror that one
// RegisterReason call here — keep it in sync with app.go.
func init() {
	pkerrors.RegisterReason("notCancellable", pkerrors.ReasonSpec{Status: 409, Title: "Session not cancellable"})
}

func TestParseEnvelopeSuccess(t *testing.T) {
	data, code, err := parseEnvelope([]byte(`{"result":"success","data":{"id":"01J"}}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(code, ""))
	qt.Assert(t, qt.Equals(string(data), `{"id":"01J"}`))
}

func TestParseEnvelopeError(t *testing.T) {
	_, code, err := parseEnvelope([]byte(`{"result":"error","code":"session:not_found","message":"unknown session"}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(code, "session:not_found"))
}

func TestParseEnvelopeGarbage(t *testing.T) {
	_, _, err := parseEnvelope([]byte(`not json`))
	qt.Assert(t, qt.IsNotNil(err))
}

// resultError bridges the DB house-style code (session:<reason>) onto the
// error taxonomy so FromResultCode maps status correctly: not_found is a
// builtin reason (-> 404); not_cancellable is registered by app.go as
// "not-cancellable" (-> 409) — FromResultCode normalizes "_"/"-" so
// session:not_cancellable matches it.
func TestResultErrorHTTPStatus(t *testing.T) {
	type statusCoder interface{ StatusCode() int }

	nf, ok := resultError("session:not_found").(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(nf.StatusCode(), 404))

	nc, ok := resultError("session:not_cancellable").(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(nc.StatusCode(), 409))

	inv, ok := resultError("session:invalid").(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.IsTrue(inv.StatusCode() >= 400 && inv.StatusCode() < 500))

	qt.Assert(t, qt.IsNil(resultError("")))
}

func statusCode(t *testing.T, err error) int {
	t.Helper()
	type statusCoder interface{ StatusCode() int }
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	return sc.StatusCode()
}

// Ownership isolation: a session owned by client-a is invisible to
// client-b — session:not_found (404), the same code as an unknown id (no
// existence leak).
func TestFakeGetForClientOwnershipIsolation(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	f.Seed(Session{ID: "s1", ClientID: "client-a", CorrelationID: "corr-1", Flow: "cross_device",
		Status: "pending", WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(time.Hour)})

	got, err := f.GetForClient(ctx, "client-a", "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.CorrelationID, "corr-1"))

	_, err = f.GetForClient(ctx, "client-b", "s1")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.Equals(statusCode(t, err), 404))

	_, err = f.GetForClient(ctx, "client-a", "no-such-session")
	qt.Assert(t, qt.Equals(statusCode(t, err), 404))
}

// Lazy expiry: a pending session past its expires_at flips to 'expired' on
// read, without needing the sweeper to have run yet.
func TestFakeLazyExpiry(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	f.Seed(Session{ID: "s-exp", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(-time.Hour)})
	f.Seed(Session{ID: "s-live", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(time.Hour)})

	got, err := f.GetForClient(ctx, "client-a", "s-exp")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.Status, "expired"))

	got, err = f.GetForClient(ctx, "client-a", "s-live")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.Status, "pending"))
}

// Cancel transition matrix: pending -> cancelled succeeds; a second cancel
// (now terminal) is rejected with session:not_cancellable, not not_found.
func TestFakeCancelTransitionMatrix(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	f.Seed(Session{ID: "s1", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(time.Hour)})

	// cross-client cancel -> not_found, before any write
	err := f.Cancel(ctx, "client-b", "s1")
	qt.Assert(t, qt.Equals(statusCode(t, err), 404))
	got, _ := f.GetForClient(ctx, "client-a", "s1")
	qt.Assert(t, qt.Equals(got.Status, "pending")) // unaffected by the rejected cross-client attempt

	qt.Assert(t, qt.IsNil(f.Cancel(ctx, "client-a", "s1")))
	got, err = f.GetForClient(ctx, "client-a", "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.Status, "cancelled"))

	err = f.Cancel(ctx, "client-a", "s1")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.Equals(statusCode(t, err), 409))
}

// Regression: a session STILL in the row as 'pending' (not yet swept) but
// already past its expires_at must NOT be cancellable — Cancel lazily expires
// it first (fail-closed: it ends 'expired', never 'cancelled'), then the
// cancellable check sees the terminal state and returns
// session:not_cancellable (409). This keeps the fake in lockstep with the SQL
// cancel_session, which performs the same lazy-expiry UPDATE.
func TestFakeCancelPendingPastExpiryIsNotCancellable(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	f.Seed(Session{ID: "s-stale-pending", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(-time.Minute)})

	err := f.Cancel(ctx, "client-a", "s-stale-pending")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.Equals(statusCode(t, err), 409)) // not_cancellable, not a spurious success

	// and it ended 'expired', not 'cancelled'
	got, gerr := f.GetForClient(ctx, "client-a", "s-stale-pending")
	qt.Assert(t, qt.IsNil(gerr))
	qt.Assert(t, qt.Equals(got.Status, "expired"))
}

// wallet_engaged is also a cancellable state; verified/failed/expired are not.
func TestFakeCancelFromWalletEngagedAndTerminalStates(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	f.Seed(Session{ID: "s-we", ClientID: "client-a", Status: "wallet_engaged",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(time.Hour)})
	qt.Assert(t, qt.IsNil(f.Cancel(ctx, "client-a", "s-we")))

	for _, terminal := range []string{"verified", "failed", "expired"} {
		id := "s-" + terminal
		f.Seed(Session{ID: id, ClientID: "client-a", Status: terminal,
			WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(time.Hour)})
		err := f.Cancel(ctx, "client-a", id)
		qt.Assert(t, qt.IsNotNil(err), qt.Commentf("status=%s should not be cancellable", terminal))
		qt.Assert(t, qt.Equals(statusCode(t, err), 409))
	}
}

// GetReportForClient: ownership check, then "no report yet" is success (nil,
// nil), not an error; once a report is seeded it comes back.
func TestFakeGetReportForClientNilWhenAbsent(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	f.Seed(Session{ID: "s1", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(time.Hour)})

	_, err := f.GetReportForClient(ctx, "client-b", "s1")
	qt.Assert(t, qt.Equals(statusCode(t, err), 404))

	rep, err := f.GetReportForClient(ctx, "client-a", "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(rep))

	f.SeedReport("s1", json.RawMessage(`{"outcome":"verified"}`))
	rep, err = f.GetReportForClient(ctx, "client-a", "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(rep), `{"outcome":"verified"}`))
}

func TestFakeMarkCodeRedeemedOwnershipAndIdempotent(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	f.Seed(Session{ID: "s1", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(time.Hour)})

	err := f.MarkCodeRedeemed(ctx, "client-b", "s1")
	qt.Assert(t, qt.Equals(statusCode(t, err), 404))

	qt.Assert(t, qt.IsNil(f.MarkCodeRedeemed(ctx, "client-a", "s1")))
	got, err := f.GetForClient(ctx, "client-a", "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(got.CodeRedeemedAt))
	first := *got.CodeRedeemedAt

	// idempotent: a second call keeps the first timestamp
	qt.Assert(t, qt.IsNil(f.MarkCodeRedeemed(ctx, "client-a", "s1")))
	got, err = f.GetForClient(ctx, "client-a", "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.CodeRedeemedAt.Equal(first), true))
}

func TestFakeSetWebhookStateValidation(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	f.Seed(Session{ID: "s1", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(time.Hour)})

	qt.Assert(t, qt.IsNil(f.SetWebhookState(ctx, "s1", "delivering", "")))
	got, err := f.GetForClient(ctx, "client-a", "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.WebhookState, "delivering"))

	err = f.SetWebhookState(ctx, "s1", "not-a-state", "")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.IsTrue(statusCode(t, err) >= 400 && statusCode(t, err) < 500))

	err = f.SetWebhookState(ctx, "no-such-session", "pending", "")
	qt.Assert(t, qt.Equals(statusCode(t, err), 404))
}

func TestFakeExpireDue(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	f.Seed(Session{ID: "s-due-1", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", CorrelationID: "corr-1", ExpiresAt: time.Now().Add(-time.Minute)})
	f.Seed(Session{ID: "s-due-2", ClientID: "client-b", Status: "wallet_engaged",
		WebhookURL: "https://b.example/hook", CorrelationID: "corr-2", ExpiresAt: time.Now().Add(-time.Minute)})
	f.Seed(Session{ID: "s-not-due", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(time.Hour)})
	f.Seed(Session{ID: "s-already-terminal", ClientID: "client-a", Status: "verified",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(-time.Hour)})

	batch, err := f.ExpireDue(ctx, 100)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(batch, 2))
	ids := map[string]bool{}
	for _, e := range batch {
		ids[e.ID] = true
	}
	qt.Assert(t, qt.IsTrue(ids["s-due-1"]))
	qt.Assert(t, qt.IsTrue(ids["s-due-2"]))

	// swept sessions are now 'expired' and won't be swept again
	got, err := f.GetForClient(ctx, "client-a", "s-due-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.Status, "expired"))
	batch2, err := f.ExpireDue(ctx, 100)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(batch2, 0))

	// limit is honored
	f.Seed(Session{ID: "s-due-3", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(-time.Minute)})
	f.Seed(Session{ID: "s-due-4", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(-time.Minute)})
	limited, err := f.ExpireDue(ctx, 1)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(limited, 1))
}
