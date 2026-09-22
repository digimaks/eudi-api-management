package vcclient

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	"github.com/gmb-lib/go-platform-kit/correlation"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
)

// newTestApp returns a running azugo test app. vcclient's do() unconditionally
// reads correlation.ID(ctx) (ctx.UserValue), and *azugo.TestApp.MockContext
// builds a *Context with a nil underlying *fasthttp.RequestCtx (it passes nil
// to acquireCtx) — UserValue/SetUserValue panic on that context (no nil
// guard, unlike Value/Deadline/Err). A genuinely served request (Start +
// TestClient, mirroring azugo core's own http_client_test.go) gives every
// call a real fasthttp.RequestCtx underneath, so this exercises the same path
// production traffic does.
func newTestApp(t *testing.T) *azugo.TestApp {
	t.Helper()
	a := azugo.NewTestApp()
	a.Start(t)
	t.Cleanup(a.Stop)
	return a
}

func testRegistration(t *testing.T) rpcert.RegistrationRef {
	t.Helper()
	ref, err := rpcert.NewRegistrationRef("Acme RP", "acme-client", "https://registry.example/api", "iu-1")
	qt.Assert(t, qt.IsNil(err))
	return ref
}

// probeCreate registers a throwaway route that runs fn(ctx) against a real
// served request and always responds 200 — the route's own response is
// irrelevant; the test asserts on whatever fn captured by closure.
func probeCreate(t *testing.T, a *azugo.TestApp, fn func(ctx *azugo.Context)) {
	t.Helper()
	a.Get("/probe", func(ctx *azugo.Context) {
		fn(ctx)
		ctx.StatusCode(http.StatusOK)
	})
	resp, err := a.TestClient().Get("/probe")
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
}

func TestCreateSession_Success(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := CreateResponse{
			SessionID:   "sess-1",
			ExpiresAt:   time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
			RequestURI:  "https://verifier.example/wallet/sess-1/request.jwt",
			ResponseURI: "https://verifier.example/wallet/sess-1/response",
		}
		resp.Invocation.WalletURL = "https://wallet.example/invoke?request_uri=..."
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := New(srv.URL, "test-internal-token")
	app := newTestApp(t)

	var got *CreateResponse
	var callErr error
	probeCreate(t, app, func(ctx *azugo.Context) {
		got, callErr = c.CreateSession(ctx, &CreateRequest{
			ClientID:      "client-1",
			CorrelationID: "01TESTCORRELATION",
			Flow:          "cross_device",
			DCQLQuery:     json.RawMessage(`{"credentials":[]}`),
			WebhookURL:    "https://client.example/webhook",
			Registration:  testRegistration(t),
			TTLSeconds:    300,
		})
	})

	qt.Assert(t, qt.IsNil(callErr))
	qt.Assert(t, qt.IsNotNil(got))
	qt.Check(t, qt.Equals(got.SessionID, "sess-1"))
	qt.Check(t, qt.Equals(got.Invocation.WalletURL, "https://wallet.example/invoke?request_uri=..."))

	qt.Check(t, qt.Equals(gotMethod, http.MethodPost))
	qt.Check(t, qt.Equals(gotPath, "/internal/v1/sessions"))
	qt.Check(t, qt.Equals(gotAuth, "Bearer test-internal-token"))
	qt.Check(t, qt.StringContains(gotBody, `"client_id":"client-1"`))
	qt.Check(t, qt.StringContains(gotBody, `"correlation_id":"01TESTCORRELATION"`))
	qt.Check(t, qt.StringContains(gotBody, `"flow":"cross_device"`))
}

func TestCreateSession_RelaysDownstreamProblem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(pkerrors.Problem{
			Title:  "Service unavailable",
			Status: http.StatusServiceUnavailable,
			Code:   "err:revocation:unavailable",
			Source: "eudi-verifier-core",
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "test-internal-token")
	app := newTestApp(t)

	var callErr error
	probeCreate(t, app, func(ctx *azugo.Context) {
		_, callErr = c.CreateSession(ctx, &CreateRequest{ClientID: "client-1", Registration: testRegistration(t)})
	})

	qt.Assert(t, qt.IsNotNil(callErr))
	var p *pkerrors.Problem
	ok := errors.As(callErr, &p)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(p.Status, http.StatusServiceUnavailable))
	qt.Check(t, qt.Equals(p.Code, "err:revocation:unavailable"))
}

func TestCreateSession_NonConformingBodyRelaysUniformUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c := New(srv.URL, "test-internal-token")
	app := newTestApp(t)

	var callErr error
	probeCreate(t, app, func(ctx *azugo.Context) {
		_, callErr = c.CreateSession(ctx, &CreateRequest{ClientID: "client-1", Registration: testRegistration(t)})
	})

	qt.Assert(t, qt.IsNotNil(callErr))
	var p *pkerrors.Problem
	ok := errors.As(callErr, &p)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(p.StatusCode(), http.StatusBadGateway))
	qt.Check(t, qt.Equals(p.Code, "err:upstream:unavailable"))
	qt.Check(t, qt.Equals(p.Title, "Verifier engine unavailable"))
	qt.Check(t, qt.StringContains(p.Detail, "answered 500 without a problem body"))
	qt.Check(t, qt.Equals(p.Public().Detail, ""), qt.Commentf("the cause is for the log, never the caller"))
}

// TestCreateSession_Undecodable2xxIsEngineUnavailable: a 201 whose body does
// not decode into CreateResponse (here expires_at as an epoch integer rather
// than RFC 3339) is the engine answering unusably — the same 502 as a
// non-problem error body, with the cause kept for the log, never a bare decode
// error.
func TestCreateSession_Undecodable2xxIsEngineUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"session_id":"sess-1","expires_at":1720000000}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "test-internal-token")
	app := newTestApp(t)

	var callErr error
	probeCreate(t, app, func(ctx *azugo.Context) {
		_, callErr = c.CreateSession(ctx, &CreateRequest{ClientID: "client-1", Registration: testRegistration(t)})
	})

	qt.Assert(t, qt.IsNotNil(callErr))
	var p *pkerrors.Problem
	qt.Assert(t, qt.IsTrue(errors.As(callErr, &p)))
	qt.Check(t, qt.Equals(p.StatusCode(), http.StatusBadGateway))
	qt.Check(t, qt.Equals(p.Code, "err:upstream:unavailable"))
	qt.Check(t, qt.Equals(p.Title, "Verifier engine unavailable"))
	qt.Check(t, qt.StringContains(p.Detail, "undecodable 2xx"))
	qt.Check(t, qt.Equals(p.Public().Detail, ""))
}

func TestCreateSession_TransportFailureRelaysUniformUnavailable(t *testing.T) {
	// Nothing listens here — a connection failure, not a non-2xx response.
	c := New("http://127.0.0.1:1", "test-internal-token")
	app := newTestApp(t)

	var callErr error
	probeCreate(t, app, func(ctx *azugo.Context) {
		_, callErr = c.CreateSession(ctx, &CreateRequest{ClientID: "client-1", Registration: testRegistration(t)})
	})

	qt.Assert(t, qt.IsNotNil(callErr))
	var p *pkerrors.Problem
	ok := errors.As(callErr, &p)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(p.StatusCode(), http.StatusBadGateway))
	qt.Check(t, qt.Equals(p.Title, "Verifier engine unavailable"))
	qt.Check(t, qt.StringContains(p.Detail, "did not answer"))
	qt.Check(t, qt.Equals(p.Public().Detail, ""))
}

func TestCreateSession_ForwardsBoundCorrelationID(t *testing.T) {
	var gotCID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCID = r.Header.Get("X-Correlation-ID")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(CreateResponse{SessionID: "sess-1"})
	}))
	defer srv.Close()

	c := New(srv.URL, "test-internal-token")
	app := azugo.NewTestApp()
	app.Use(correlation.Middleware()) // binds ctx's own inbound correlation id (or adopts one), same as production
	app.Start(t)
	t.Cleanup(app.Stop)

	var callErr error
	app.Get("/probe", func(ctx *azugo.Context) {
		_, callErr = c.CreateSession(ctx, &CreateRequest{ClientID: "client-1", Registration: testRegistration(t)})
		ctx.StatusCode(http.StatusOK)
	})

	tc := app.TestClient()
	resp, err := tc.Get("/probe", tc.WithHeader("X-Correlation-ID", "01BOUNDCID"))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.IsNil(callErr))
	// The inbound request's OWN correlation id (bound by the middleware —
	// outbound calls keep the thread) rides the downstream request header.
	// This is intentionally NOT the freshly-minted session correlation_id
	// (that travels in the JSON body only) — the two are different concerns:
	// hop-to-hop log correlation vs. the session's own identity.
	qt.Check(t, qt.Equals(gotCID, "01BOUNDCID"))
}

func TestDeleteSession_Success(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL, "test-internal-token")
	app := newTestApp(t)

	var callErr error
	probeCreate(t, app, func(ctx *azugo.Context) {
		callErr = c.DeleteSession(ctx, "sess-1")
	})

	qt.Assert(t, qt.IsNil(callErr))
	qt.Check(t, qt.Equals(gotMethod, http.MethodDelete))
	qt.Check(t, qt.Equals(gotPath, "/internal/v1/sessions/sess-1"))
}
