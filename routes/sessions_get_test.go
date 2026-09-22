package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	crypto "github.com/gmb-eudi/go-eudi-crypto"

	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"

	mgmt "github.com/digimaks/eudi-api-management"
	"github.com/digimaks/eudi-api-management/internal/api"
	"github.com/digimaks/eudi-api-management/internal/sessiondb"
)

// fakeSessions type-asserts the app's session store to the in-memory fake so
// tests can seed rows/reports directly — same seam shape seedSessionClient
// uses for registrydb.
func fakeSessions(t testing.TB, app *mgmt.App) *sessiondb.Fake {
	t.Helper()
	f, ok := app.Sessions().(*sessiondb.Fake)
	qt.Assert(t, qt.IsTrue(ok))
	return f
}

// seedHandoffPayload encrypts result exactly as eudi-verifier-core's handoff
// queue does (crypto.EncryptJWE(pub, nil, plain), nil protected header) and
// writes the envelope under vc:handoff:payload:{sessionID} in the app's own
// Valkey/keys, TTL-bounded to match the Valkey key and queue contract.
func seedHandoffPayload(t testing.TB, app *mgmt.App, sessionID string, result handoffwire.Result, ttl time.Duration) {
	t.Helper()
	ctx := context.Background()
	plain, err := json.Marshal(result)
	qt.Assert(t, qt.IsNil(err))
	pub, err := app.Keys().Public(ctx, handoffwire.KeyHandoffEnc)
	qt.Assert(t, qt.IsNil(err))
	jwe, err := crypto.EncryptJWE(pub, nil, plain)
	qt.Assert(t, qt.IsNil(err))
	env := handoffwire.Envelope{
		Version: 1, SessionID: sessionID, ResultJWE: string(jwe),
		EnqueuedAt: time.Now(), ExpiresAt: time.Now().Add(ttl),
	}
	envJSON, err := json.Marshal(env)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(app.Valkey().Set(ctx, fmt.Sprintf(handoffwire.PayloadKeyFmt, sessionID), envJSON, ttl).Err()))
}

// seedRespCode writes vc:respcode:{code} -> sessionID (the [OID4VP §8.2] index
// a same-device redirect handler, not implemented here, would write in
// production) so GET's GETDEL redemption has something to consume.
func seedRespCode(t testing.TB, app *mgmt.App, code, sessionID string, ttl time.Duration) {
	t.Helper()
	qt.Assert(t, qt.IsNil(app.Valkey().Set(context.Background(), fmt.Sprintf(handoffwire.RespCodeKeyFmt, code), sessionID, ttl).Err()))
}

// getSessionReq issues GET /api/v1/sessions/{sessionId}[?responseCode=...].
func getSessionReq(t testing.TB, ta *azugo.TestApp, apiKey, sessionID, responseCode string) (int, []byte) {
	t.Helper()
	tc := ta.TestClient()
	opts := []azugo.TestClientOption{tc.WithHeader(apiKeyHeader, apiKey)}
	if responseCode != "" {
		opts = append(opts, tc.WithQuery(map[string]any{"responseCode": responseCode}))
	}
	resp, err := tc.Get("/api/v1/sessions/"+sessionID, opts...)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	body, _ := resp.BodyUncompressed()
	body = append([]byte(nil), body...)
	fasthttp.ReleaseResponse(resp)
	return status, body
}

// assertPayloadKeyGone is the forward-and-delete canary: the claim value only
// ever exists inside the JWE-wrapped envelope stored under
// vc:handoff:payload:{sessionID} (see seedHandoffPayload), so grepping other
// Valkey values for the plaintext claim proves nothing — the envelope key
// itself is the thing that must disappear once its TTL elapses. Asserting the
// key is gone is what actually proves the purge.
func assertPayloadKeyGone(t testing.TB, app *mgmt.App, sessionID string) {
	t.Helper()
	key := fmt.Sprintf(handoffwire.PayloadKeyFmt, sessionID)
	qt.Check(t, qt.IsFalse(app.TestMiniredis().Exists(key)), qt.Commentf("payload key %q still present after TTL", key))
}

// decodeSession decodes a GET response body as api.Session.
func decodeSession(t testing.TB, body []byte) api.Session {
	t.Helper()
	var s api.Session
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &s)))
	return s
}

func mdlReportJSON(t testing.TB, outcome, failCode string) json.RawMessage {
	t.Helper()
	rep := handoffwire.Report{
		SessionID: "irrelevant-for-report-json",
		Outcome:   outcome,
		FailCode:  failCode,
		Checks:    []handoffwire.CheckResult{{Check: "parse", Outcome: "pass", SpecRef: "OID4VP §8"}},
		Policy:    map[string]bool{},
	}
	b, err := json.Marshal(rep)
	qt.Assert(t, qt.IsNil(err))
	return b
}

// TestGetSession_Pending: no report/result yet, state reflects the row.
func TestGetSession_Pending(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-pending", ClientID: clientID, Flow: "cross_device", Status: "pending",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})

	status, body := getSessionReq(t, ta, apiKey, "sess-pending", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("body: %s", body))
	got := decodeSession(t, body)
	qt.Check(t, qt.Equals(got.State, "pending"))
	qt.Check(t, qt.IsNil(got.Report))
	qt.Check(t, qt.IsNil(got.Result))
	qt.Check(t, qt.IsNil(got.Failure))
}

// TestGetSession_WalletEngaged: still no result.
func TestGetSession_WalletEngaged(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-we", ClientID: clientID, Flow: "cross_device", Status: "wallet_engaged",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})

	status, body := getSessionReq(t, ta, apiKey, "sess-we", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("body: %s", body))
	got := decodeSession(t, body)
	qt.Check(t, qt.Equals(got.State, "wallet_engaged"))
	qt.Check(t, qt.IsNil(got.Result))
}

// TestGetSession_VerifiedCrossDevice_PayloadLive: report + result (claims
// present) — cross_device never needs a response_code.
func TestGetSession_VerifiedCrossDevice_PayloadLive(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-cd", ClientID: clientID, Flow: "cross_device", Status: "verified",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})
	fakeSessions(t, app).SeedReport("sess-cd", mdlReportJSON(t, "verified", ""))
	seedHandoffPayload(t, app, "sess-cd", handoffwire.Result{
		SessionID: "sess-cd", Outcome: "verified",
		Credentials: []handoffwire.ResultCredential{{
			QueryCredentialID: "cred1", Format: "mso_mdoc", DoctypeOrVCT: "org.iso.18013.5.1.mDL",
			Claims: map[string]any{"given_name": "Alice"},
		}},
	}, time.Hour)

	status, body := getSessionReq(t, ta, apiKey, "sess-cd", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("body: %s", body))
	got := decodeSession(t, body)
	qt.Check(t, qt.Equals(got.State, "verified"))
	qt.Assert(t, qt.IsNotNil(got.Report))
	qt.Check(t, qt.Equals(len(got.Report.Checks), 1))
	qt.Assert(t, qt.IsNotNil(got.Result))
	qt.Assert(t, qt.Equals(len(got.Result.Credentials), 1))
	qt.Check(t, qt.DeepEquals(got.Result.Credentials[0].Claims, map[string]any{"given_name": "Alice"}))
}

// TestGetSession_VerifiedPayloadTTLdOut: report survives, result is GONE —
// forward-and-delete; canary asserts the vc:handoff:payload:{id} envelope key
// itself no longer exists in miniredis after its TTL elapses.
func TestGetSession_VerifiedPayloadTTLdOut(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-ttl", ClientID: clientID, Flow: "cross_device", Status: "verified",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})
	fakeSessions(t, app).SeedReport("sess-ttl", mdlReportJSON(t, "verified", ""))
	seedHandoffPayload(t, app, "sess-ttl", handoffwire.Result{
		SessionID: "sess-ttl", Outcome: "verified",
		Credentials: []handoffwire.ResultCredential{{
			QueryCredentialID: "cred1", Format: "mso_mdoc", DoctypeOrVCT: "org.iso.18013.5.1.mDL",
			Claims: map[string]any{"given_name": "AliceTTLCanary"},
		}},
	}, time.Second)

	app.TestMiniredis().FastForward(2 * time.Second)

	status, body := getSessionReq(t, ta, apiKey, "sess-ttl", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("body: %s", body))
	got := decodeSession(t, body)
	qt.Check(t, qt.Equals(got.State, "verified"))
	qt.Assert(t, qt.IsNotNil(got.Report))
	qt.Check(t, qt.IsNil(got.Result))
	assertPayloadKeyGone(t, app, "sess-ttl")
}

// TestGetSession_VerifiedSameDevice_NoResponseCodeYet: result withheld,
// problem-free — the same 200 shape as "not yet redeemed".
func TestGetSession_VerifiedSameDevice_NoResponseCodeYet(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, []string{"https://client.example"}, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-sd-nocode", ClientID: clientID, Flow: "same_device", Status: "verified",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})
	fakeSessions(t, app).SeedReport("sess-sd-nocode", mdlReportJSON(t, "verified", ""))
	seedHandoffPayload(t, app, "sess-sd-nocode", handoffwire.Result{
		SessionID: "sess-sd-nocode", Outcome: "verified",
		Credentials: []handoffwire.ResultCredential{{QueryCredentialID: "cred1", Format: "mso_mdoc", Claims: map[string]any{"given_name": "Bob"}}},
	}, time.Hour)

	status, body := getSessionReq(t, ta, apiKey, "sess-sd-nocode", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("body: %s", body))
	got := decodeSession(t, body)
	qt.Check(t, qt.Equals(got.State, "verified"))
	qt.Assert(t, qt.IsNotNil(got.Report))
	qt.Check(t, qt.IsNil(got.Result))
}

// TestGetSession_VerifiedSameDevice_CorrectCode_ThenStickySecondPoll: the
// [OID4VP §8.2] redemption core. First poll with the right code releases the
// result, consumes vc:respcode:{code} (GETDEL), and sets code_redeemed_at; a
// SECOND poll with NO code still returns the result (sticky, once per
// session — ARF AS-RP-51-011).
func TestGetSession_VerifiedSameDevice_CorrectCode_ThenStickySecondPoll(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, []string{"https://client.example"}, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-sd-ok", ClientID: clientID, Flow: "same_device", Status: "verified",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})
	fakeSessions(t, app).SeedReport("sess-sd-ok", mdlReportJSON(t, "verified", ""))
	seedHandoffPayload(t, app, "sess-sd-ok", handoffwire.Result{
		SessionID: "sess-sd-ok", Outcome: "verified",
		Credentials: []handoffwire.ResultCredential{{QueryCredentialID: "cred1", Format: "mso_mdoc", Claims: map[string]any{"given_name": "Carol"}}},
	}, time.Hour)
	seedRespCode(t, app, "the-right-code", "sess-sd-ok", 10*time.Minute)

	status, body := getSessionReq(t, ta, apiKey, "sess-sd-ok", "the-right-code")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("body: %s", body))
	got := decodeSession(t, body)
	qt.Assert(t, qt.IsNotNil(got.Result))
	qt.Check(t, qt.DeepEquals(got.Result.Credentials[0].Claims, map[string]any{"given_name": "Carol"}))

	// The response_code index is consumed (GETDEL) — gone from Valkey.
	_, err := app.TestMiniredis().Get(fmt.Sprintf(handoffwire.RespCodeKeyFmt, "the-right-code"))
	qt.Assert(t, qt.IsNotNil(err))

	// code_redeemed_at is now set on the DB-side row.
	row, err := app.Sessions().GetForClient(context.Background(), clientID, "sess-sd-ok")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(row.CodeRedeemedAt))

	// Second poll, WITHOUT any responseCode: still gets the result (sticky).
	status2, body2 := getSessionReq(t, ta, apiKey, "sess-sd-ok", "")
	qt.Assert(t, qt.Equals(status2, fasthttp.StatusOK), qt.Commentf("body: %s", body2))
	got2 := decodeSession(t, body2)
	qt.Assert(t, qt.IsNotNil(got2.Result))
	qt.Check(t, qt.DeepEquals(got2.Result.Credentials[0].Claims, map[string]any{"given_name": "Carol"}))
}

// TestGetSession_VerifiedSameDevice_WrongCode_ResultWithheld: a wrong code
// (never indexed) withholds the result with the SAME 200 shape as "no code
// yet" — no oracle about why.
func TestGetSession_VerifiedSameDevice_WrongCode_ResultWithheld(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, []string{"https://client.example"}, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-sd-wrong", ClientID: clientID, Flow: "same_device", Status: "verified",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})
	fakeSessions(t, app).SeedReport("sess-sd-wrong", mdlReportJSON(t, "verified", ""))
	seedHandoffPayload(t, app, "sess-sd-wrong", handoffwire.Result{
		SessionID: "sess-sd-wrong", Outcome: "verified",
		Credentials: []handoffwire.ResultCredential{{QueryCredentialID: "cred1", Format: "mso_mdoc", Claims: map[string]any{"given_name": "Dave"}}},
	}, time.Hour)
	// A code that indexes to a DIFFERENT session (replay from elsewhere).
	seedRespCode(t, app, "someone-elses-code", "some-other-session", 10*time.Minute)

	status, body := getSessionReq(t, ta, apiKey, "sess-sd-wrong", "someone-elses-code")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("body: %s", body))
	got := decodeSession(t, body)
	qt.Check(t, qt.IsNil(got.Result))

	// A never-indexed code (pure guess) behaves identically.
	status2, body2 := getSessionReq(t, ta, apiKey, "sess-sd-wrong", "never-existed")
	qt.Assert(t, qt.Equals(status2, fasthttp.StatusOK), qt.Commentf("body: %s", body2))
	got2 := decodeSession(t, body2)
	qt.Check(t, qt.IsNil(got2.Result))
}

// TestGetSession_Failed: report + failure code, no result.
func TestGetSession_Failed(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-failed", ClientID: clientID, Flow: "cross_device", Status: "failed",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})
	fakeSessions(t, app).SeedReport("sess-failed", mdlReportJSON(t, "failed", "err:oid4vp:device-binding-failed"))

	status, body := getSessionReq(t, ta, apiKey, "sess-failed", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("body: %s", body))
	got := decodeSession(t, body)
	qt.Check(t, qt.Equals(got.State, "failed"))
	qt.Assert(t, qt.IsNotNil(got.Report))
	qt.Assert(t, qt.IsNotNil(got.Failure))
	qt.Check(t, qt.Equals(got.Failure.Code, "err:oid4vp:device-binding-failed"))
	qt.Check(t, qt.IsNil(got.Result))
}

// TestGetSession_PendingPastExpiry_LazyExpired: the lazy expiry transition
// fires on read and PERSISTS — a subsequent direct store read also sees
// "expired".
func TestGetSession_PendingPastExpiry_LazyExpired(t *testing.T) {
	ta, app := newSessionsApp(t)
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")
	past := time.Now().Add(-time.Hour)
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-expired", ClientID: clientID, Flow: "cross_device", Status: "pending",
		CreatedAt: past, UpdatedAt: past, ExpiresAt: past.Add(time.Minute),
	})

	status, body := getSessionReq(t, ta, apiKey, "sess-expired", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("body: %s", body))
	got := decodeSession(t, body)
	qt.Check(t, qt.Equals(got.State, "expired"))

	row, err := app.Sessions().GetForClient(context.Background(), clientID, "sess-expired")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(row.Status, "expired"))
}

// TestGetSession_OtherClient_NotFound: cross-client access is 404, not 403
// (no existence leak). Asserts the domain-specific err:session:not_found
// (underscore -- the raw reason the session store raises), not the generic
// err:request:notFound: the app registers the domain reason to override the
// framework's builtin not-found at init.
func TestGetSession_OtherClient_NotFound(t *testing.T) {
	ta, app := newSessionsApp(t)
	ownerID, _ := seedSessionClient(t, app, nil, "https://owner.example/webhook")
	_, otherKey := seedSessionClient(t, app, nil, "https://other.example/webhook")
	now := time.Now()
	fakeSessions(t, app).Seed(sessiondb.Session{
		ID: "sess-owned", ClientID: ownerID, Flow: "cross_device", Status: "pending",
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	})

	status, body := getSessionReq(t, ta, otherKey, "sess-owned", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:session:not_found"))
}

// TestGetSession_UnknownID_NotFound. Same domain-specific code as
// TestGetSession_OtherClient_NotFound above (no oracle distinguishing
// "unknown id" from "cross-client id").
func TestGetSession_UnknownID_NotFound(t *testing.T) {
	ta, app := newSessionsApp(t)
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook")

	status, body := getSessionReq(t, ta, apiKey, "does-not-exist", "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:session:not_found"))
}
