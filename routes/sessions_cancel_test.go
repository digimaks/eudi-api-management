package routes

import (
	"context"
	"net/http"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/digimaks/eudi-api-management/internal/sessiondb"
)

// deleteSessionReq issues DELETE /api/v1/sessions/{sessionId}.
func deleteSessionReq(t testing.TB, ta *azugo.TestApp, apiKey, sessionID string) (int, []byte) {
	t.Helper()
	tc := ta.TestClient()
	resp, err := tc.Delete("/api/v1/sessions/"+sessionID, tc.WithHeader(apiKeyHeader, apiKey))
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	body, _ := resp.BodyUncompressed()
	body = append([]byte(nil), body...)
	fasthttp.ReleaseResponse(resp)
	return status, body
}

// TestCancelSession_Pending_NoContentAndInternalDeleteHit: a pending session
// cancels (204), transitions to "cancelled", and the wallet-facing internal
// session is best-effort killed via eudi-verifier-core's internal API — the stub
// records the hit.
func TestCancelSession_Pending_NoContentAndInternalDeleteHit(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-cancel-pending", ClientID: clientID, Flow: "cross_device", Status: "pending",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})

	deleteHits := 0
	stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) {
		deleteHits++
		w.WriteHeader(http.StatusNoContent)
	})
	stub.attach(app)

	status, body := deleteSessionReq(t, ta, apiKey, "sess-cancel-pending")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNoContent), qt.Commentf("body: %s", body))
	qt.Check(t, qt.Equals(deleteHits, 1))

	row, err := app.Sessions().GetForClient(context.Background(), clientID, "sess-cancel-pending")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(row.Status, "cancelled"))
}

// TestCancelSession_WalletEngaged_NoContent.
func TestCancelSession_WalletEngaged_NoContent(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-cancel-we", ClientID: clientID, Flow: "cross_device", Status: "wallet_engaged",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})
	stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) { w.WriteHeader(http.StatusNoContent) })
	stub.attach(app)

	status, body := deleteSessionReq(t, ta, apiKey, "sess-cancel-we")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNoContent), qt.Commentf("body: %s", body))

	row, err := app.Sessions().GetForClient(context.Background(), clientID, "sess-cancel-we")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(row.Status, "cancelled"))
}

// TestCancelSession_Verified_NotCancellable: a terminal state can't be
// cancelled (409, err:session:not_cancellable).
func TestCancelSession_Verified_NotCancellable(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-cancel-verified", ClientID: clientID, Flow: "cross_device", Status: "verified",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})

	status, body := deleteSessionReq(t, ta, apiKey, "sess-cancel-verified")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusConflict), qt.Commentf("body: %s", body))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:session:not_cancellable"))
}

// TestCancelSession_AlreadyCancelled_NotCancellable: repeating cancel on a
// terminal (cancelled) session is also 409, not a silent 204.
func TestCancelSession_AlreadyCancelled_NotCancellable(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-cancel-twice", ClientID: clientID, Flow: "cross_device", Status: "cancelled",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})

	status, body := deleteSessionReq(t, ta, apiKey, "sess-cancel-twice")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusConflict), qt.Commentf("body: %s", body))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:session:not_cancellable"))
}

// TestCancelSession_OtherClient_NotFound: cross-client cancel is 404, no
// existence leak — same acceptance as GET.
func TestCancelSession_OtherClient_NotFound(t *testing.T) {
	ta, app := newSessionsApp(t)
	ownerID, _ := seedSessionClient(t, app, nil, "https://owner.example/webhook")
	_, otherKey := seedSessionClient(t, app, nil, "https://other.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-cancel-owned", ClientID: ownerID, Flow: "cross_device", Status: "pending",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})

	status, _ := deleteSessionReq(t, ta, otherKey, "sess-cancel-owned")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
}

// TestCancelSession_InternalDeleteFailure_CancelStillCommitted: cancel
// ordering — the DB transition commits FIRST; a failing best-effort internal
// delete does not undo it (the Valkey OID4VP session TTLs out on its own).
func TestCancelSession_InternalDeleteFailure_CancelStillCommitted(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-cancel-internalfail", ClientID: clientID, Flow: "cross_device", Status: "pending",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})
	stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) { w.WriteHeader(http.StatusServiceUnavailable) })
	stub.attach(app)

	status, body := deleteSessionReq(t, ta, apiKey, "sess-cancel-internalfail")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNoContent), qt.Commentf("body: %s", body))

	row, err := app.Sessions().GetForClient(context.Background(), clientID, "sess-cancel-internalfail")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(row.Status, "cancelled"))
}
