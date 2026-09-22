package routes

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/VictoriaMetrics/metrics"
	"github.com/go-quicktest/qt"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"

	mgmt "github.com/digimaks/eudi-api-management"
	"github.com/digimaks/eudi-api-management/internal/api"
	"github.com/digimaks/eudi-api-management/internal/obs"
	"github.com/digimaks/eudi-api-management/internal/registrydb"
	"github.com/digimaks/eudi-api-management/internal/vcclient"
)

// mdocNS is the mdoc namespace used by every fixture query/registration below
// (mdoc claim paths are exactly [namespace, element], OID4VP Annex B.2.3).
const mdocNS = "org.iso.18013.5.1"

// mdocDCQLQuery builds the api.Presentation.DCQLQuery map (inline-query
// shape) for a single mso_mdoc credential requesting one claim per element.
func mdocDCQLQuery(doctype string, elements ...string) map[string]any {
	claims := make([]any, 0, len(elements))
	for _, e := range elements {
		claims = append(claims, map[string]any{"path": []any{mdocNS, e}})
	}
	return map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "cred1",
				"format": "mso_mdoc",
				"meta":   map[string]any{"doctype_value": doctype},
				"claims": claims,
			},
		},
	}
}

// mdocIntendedUseRow builds the registrydb fixture matching a
// mdocDCQLQuery(doctype, elements...) query — i.e. what a registrar would
// have on file for a client allowed to request exactly those claims.
func mdocIntendedUseRow(intendedUseID, doctype string, elements ...string) registrydb.IntendedUse {
	claims := make([][]any, 0, len(elements))
	for _, e := range elements {
		claims = append(claims, []any{mdocNS, e})
	}
	return registrydb.IntendedUse{
		IntendedUseID: intendedUseID,
		Credentials: []registrydb.RegisteredCredentialJSON{
			{Format: "mso_mdoc", DoctypesOrVCTs: []string{doctype}, Claims: claims},
		},
	}
}

// newSessionsApp boots the full router (health + auth-gated /api/v1,
// including POST /sessions) against the fake registry — no network to
// Postgres/Valkey. Tests point app.SetVC at their own httptest stub before
// issuing requests.
func newSessionsApp(t *testing.T) (*azugo.TestApp, *mgmt.App) {
	t.Helper()
	app := mgmt.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)
	return ta, app
}

// vcStub is a minimal recording stub standing in for eudi-verifier-core's
// internal API — respond controls what it sends back; lastBody captures the
// most recent request body (for asserting the wire contract byte-for-byte).
type vcStub struct {
	srv      *httptest.Server
	lastBody []byte
	respond  func(w http.ResponseWriter, body []byte)
}

func newVCStub(t testing.TB, respond func(w http.ResponseWriter, body []byte)) *vcStub {
	t.Helper()
	s := &vcStub{respond: respond}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.lastBody = append([]byte(nil), b...)
		s.respond(w, s.lastBody)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *vcStub) attach(app *mgmt.App) {
	app.SetVC(vcclient.New(s.srv.URL, app.Config().InternalAPIToken))
}

// stubCreated responds 201 with a fixed CreateResponse — the "happy path"
// stub every positive-outcome test starts from.
func stubCreated(t testing.TB) *vcStub {
	t.Helper()
	return newVCStub(t, func(w http.ResponseWriter, _ []byte) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := vcclient.CreateResponse{
			SessionID: "01SESSIONFAKEXXXXXXXXXXXXX",
			ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
		}
		resp.Invocation.WalletURL = "https://wallet.example/invoke?request_uri=stub"
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// seedSessionClient creates a client + one or more intended uses ready to
// create sessions against, and returns (clientID, presentable API key).
func seedSessionClient(t testing.TB, app *mgmt.App, allowedOrigins []string, defaultWebhook string, ius ...registrydb.IntendedUse) (string, string) {
	t.Helper()
	c := &registrydb.Client{
		Name:             "Test Client",
		RegistryURI:      "https://registrar.test/api",
		ClientIdentifier: "test-client-001",
		DefaultWebhook:   defaultWebhook,
		AllowedOrigins:   allowedOrigins,
	}
	clientID, err := app.Registry().CreateClient(context.Background(), c)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(app.Registry().SetIntendedUses(context.Background(), clientID, ius)))
	displayKey, _, _, _ := mintAndStoreKey(t, app, clientID)
	return clientID, displayKey
}

func postSession(t testing.TB, ta *azugo.TestApp, apiKey string, req api.SessionRequest) (int, []byte) {
	t.Helper()
	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/v1/sessions", req, tc.WithHeader(apiKeyHeader, apiKey))
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	body, _ := resp.BodyUncompressed()
	body = append([]byte(nil), body...)
	fasthttp.ReleaseResponse(resp)
	return status, body
}

func TestCreateSession_TemplateBased_InScope_SingleIntendedUse(t *testing.T) {
	ta, app := newSessionsApp(t)

	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	tpl := &registrydb.Template{
		Name:          "PID identification",
		IntendedUseID: "iu-1",
		DCQLQuery:     json.RawMessage(mustJSON(t, mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"))),
	}
	_, err := app.Registry().CreateTemplate(context.Background(), clientID, tpl)
	qt.Assert(t, qt.IsNil(err))

	stub := stubCreated(t)
	stub.attach(app)

	// request omits flow -> api.FlowToDB defaults to cross_device, so
	// IncSessionCreated must label the series with that same default, not an
	// empty string.
	before := metrics.GetOrCreateCounter(`management_api_sessions_created_total{flow="cross_device"}`).Get()

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{TemplateID: tpl.ID},
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated), qt.Commentf("body: %s", body))

	var got api.SessionCreated
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &got)))
	qt.Check(t, qt.Equals(got.State, "pending"))
	qt.Check(t, qt.Equals(got.WalletURL, "https://wallet.example/invoke?request_uri=stub"))

	after := metrics.GetOrCreateCounter(`management_api_sessions_created_total{flow="cross_device"}`).Get()
	qt.Check(t, qt.Equals(after-before, uint64(1)))
	qt.Check(t, qt.Equals(obs.MetricSessionsCreatedTotal, "management_api_sessions_created_total"))

	// the session's own correlation id is minted in the handler and sent in
	// the internal request body as a valid ULID.
	var sent struct {
		CorrelationID string `json:"correlation_id"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(stub.lastBody, &sent)))
	_, parseErr := ulid.ParseStrict(sent.CorrelationID)
	qt.Check(t, qt.IsNil(parseErr), qt.Commentf("correlation_id %q is not a valid ULID", sent.CorrelationID))
}

func TestCreateSession_InlineDCQL_InScope(t *testing.T) {
	ta, app := newSessionsApp(t)

	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	stub := stubCreated(t)
	stub.attach(app)

	status, _ := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))
}

func TestCreateSession_BothTemplateAndDCQL(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	status, _ := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{
			TemplateID: "some-template",
			DCQLQuery:  mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
		},
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusBadRequest))
}

func TestCreateSession_NeitherTemplateNorDCQL(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	status, _ := postSession(t, ta, apiKey, api.SessionRequest{})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusBadRequest))
}

func TestCreateSession_MultipleIntendedUses_NoIntendedUseId(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu1 := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	iu2 := mdocIntendedUseRow("iu-2", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu1, iu2)

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
	p := decodeProblem(t, body)
	qt.Check(t, qt.StringContains(p.Detail, "ARF TS5"))
}

func TestCreateSession_UnknownIntendedUseId(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	status, _ := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation:  api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
		IntendedUseID: "does-not-exist",
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
}

func TestCreateSession_IntendedUseRevoked(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	iu.RevokedAt = "2026-01-01"
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:registrar:intendedUseRevoked"))
}

func TestCreateSession_ScopeExceeded(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	before := metrics.GetOrCreateCounter(obs.MetricScopeDenialsTotal).Get()

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		// requests document_number, which is NOT registered above.
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name", "document_number")},
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	p := decodeProblem(t, body)
	qt.Check(t, qt.Equals(p.Code, "err:client:scopeExceeded"))
	qt.Check(t, qt.StringContains(p.Detail, "document_number"))

	// createSession's scope-error branch increments the shared denial counter
	// (routes/sessions.go) — the same series createTemplate's own scope-error
	// branch increments (TestCreateTemplate_OutOfScope_Forbidden).
	after := metrics.GetOrCreateCounter(obs.MetricScopeDenialsTotal).Get()
	qt.Check(t, qt.Equals(after-before, uint64(1)))
}

func TestCreateSession_SameDeviceRedirectURI_UnregisteredOrigin(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, []string{"https://allowed.example"}, "https://client.example/webhook", iu)

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
		Flow:         "same_device",
		RedirectURI:  "https://not-allowed.example/callback",
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:client:originNotRegistered"))
}

func TestCreateSession_WebhookOverride_UnregisteredOrigin(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, []string{"https://allowed.example"}, "https://client.example/webhook", iu)

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
		WebhookURL:   "https://not-allowed.example/hook",
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:client:originNotRegistered"))
}

func TestCreateSession_TTLBelowMinimum(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	status, _ := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
		TTLSeconds:   30,
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusBadRequest))
}

func TestCreateSession_InternalAPI503Relayed(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"title":  "Session engine unavailable",
			"status": http.StatusServiceUnavailable,
			"code":   "err:oid4vp:unavailable",
		})
	})
	stub.attach(app)

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusServiceUnavailable), qt.Commentf("body: %s", body))
	p := decodeProblem(t, body)
	qt.Check(t, qt.Equals(p.Code, "err:oid4vp:unavailable"))
	qt.Check(t, qt.Equals(p.Status, fasthttp.StatusServiceUnavailable))
}

// dcapiResponseURI is the opaque token-routed endpoint the engine returns —
// deliberately unrelated to the session id, so a test that accidentally
// derived one from the other would show up here.
const dcapiResponseURI = "https://verifier.example/wallet/Zt7xQe1r/response"

func TestCreateSession_FlowDCAPI(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	// The browser-mediated flow requires a registered origin — see
	// TestCreateSession_FlowDCAPIWithoutOriginsRejected for the other half.
	_, apiKey := seedSessionClient(t, app, []string{"https://client.example"}, "https://client.example/webhook", iu)

	stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := vcclient.CreateResponse{
			SessionID:   "sess-dcapi",
			ExpiresAt:   time.Now().Add(5 * time.Minute).UTC(),
			ResponseURI: dcapiResponseURI,
		}
		resp.Invocation.WalletURL = "https://wallet.example/invoke"
		resp.Invocation.DCAPIRequest = json.RawMessage(`{"foo":"bar"}`)
		_ = json.NewEncoder(w).Encode(resp)
	})
	stub.attach(app)

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
		Flow:         "dc_api",
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated), qt.Commentf("body: %s", body))

	var got api.SessionCreated
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &got)))
	qt.Check(t, qt.DeepEquals(got.DCAPIRequest, map[string]any{"foo": "bar"}))
	// Without this the caller has the request but nowhere to post the
	// browser's answer, which is the whole reason the field exists.
	qt.Check(t, qt.Equals(got.DCAPIResponseURI, dcapiResponseURI))

	var sent struct {
		Flow            string   `json:"flow"`
		ExpectedOrigins []string `json:"expected_origins"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(stub.lastBody, &sent)))
	qt.Check(t, qt.Equals(sent.Flow, "dcapi"))
	qt.Check(t, qt.DeepEquals(sent.ExpectedOrigins, []string{"https://client.example"}))
}

// TestCreateSession_ResponseURIOmittedForRedirectFlows: the engine returns a
// response endpoint for every flow, but for the redirect-based ones the wallet
// posts there, not the caller. Publishing it would invite a caller to post to
// an endpoint that is not theirs to call.
func TestCreateSession_ResponseURIOmittedForRedirectFlows(t *testing.T) {
	for _, flow := range []string{"", "cross_device", "same_device"} {
		t.Run("flow="+flow, func(t *testing.T) {
			ta, app := newSessionsApp(t)
			iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
			_, apiKey := seedSessionClient(t, app, []string{"https://client.example"}, "https://client.example/webhook", iu)

			stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				resp := vcclient.CreateResponse{
					SessionID:   "sess-redirect",
					ExpiresAt:   time.Now().Add(5 * time.Minute).UTC(),
					ResponseURI: dcapiResponseURI,
				}
				resp.Invocation.WalletURL = "https://wallet.example/invoke"
				_ = json.NewEncoder(w).Encode(resp)
			})
			stub.attach(app)

			req := api.SessionRequest{
				Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
				Flow:         flow,
			}
			if flow == "same_device" {
				req.RedirectURI = "https://client.example/return"
			}
			status, body := postSession(t, ta, apiKey, req)
			qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated), qt.Commentf("body: %s", body))

			var got api.SessionCreated
			qt.Assert(t, qt.IsNil(json.Unmarshal(body, &got)))
			qt.Check(t, qt.Equals(got.DCAPIResponseURI, ""))
		})
	}
}

// TestCreateSession_FlowDCAPIWithoutOriginsRejected: a client with no
// registered origins cannot use the browser-mediated flow. Reported as the
// client-configuration problem it is — an integrator must not be told the
// verifier failed when their registration is simply incomplete. The engine is
// never reached, so it cannot answer with an unclassified fault.
func TestCreateSession_FlowDCAPIWithoutOriginsRejected(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	var engineCalled bool
	stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) {
		engineCalled = true
		w.WriteHeader(http.StatusCreated)
	})
	stub.attach(app)

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
		Flow:         "dc_api",
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("body: %s", body))
	p := decodeProblem(t, body)
	qt.Check(t, qt.Equals(p.Code, "err:client:originNotRegistered"))
	qt.Check(t, qt.IsFalse(engineCalled))
}

// TestCreateSession_OriginsSentToEngineOnlyForDCAPI: the registered origin list
// is the browser flow's, and the engine refuses it on the redirect flows. This
// client has origins — as any client must to use the browser flow, and as
// same_device must to have a redirectUri accepted — and creating a redirect-flow
// session with them was answered 422 for months, which is the whole bug.
func TestCreateSession_OriginsSentToEngineOnlyForDCAPI(t *testing.T) {
	for _, flow := range []string{"cross_device", "same_device"} {
		t.Run("flow="+flow, func(t *testing.T) {
			ta, app := newSessionsApp(t)
			iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
			_, apiKey := seedSessionClient(t, app, []string{"https://client.example"}, "https://client.example/webhook", iu)

			stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				resp := vcclient.CreateResponse{
					SessionID: "sess-redirect",
					ExpiresAt: time.Now().Add(5 * time.Minute).UTC(),
				}
				resp.Invocation.WalletURL = "https://wallet.example/invoke"
				_ = json.NewEncoder(w).Encode(resp)
			})
			stub.attach(app)

			req := api.SessionRequest{
				Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
				Flow:         flow,
			}
			if flow == "same_device" {
				req.RedirectURI = "https://client.example/return"
			}
			status, body := postSession(t, ta, apiKey, req)
			qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated), qt.Commentf("body: %s", body))

			var sent struct {
				Flow            string   `json:"flow"`
				ExpectedOrigins []string `json:"expected_origins"`
			}
			qt.Assert(t, qt.IsNil(json.Unmarshal(stub.lastBody, &sent)))
			qt.Check(t, qt.Equals(sent.Flow, flow))
			qt.Check(t, qt.Equals(len(sent.ExpectedOrigins), 0),
				qt.Commentf("origins are DCAPI-only; the engine refuses them on %s", flow))
		})
	}
}

// TestCreateSession_SameDeviceRequiresRedirectURI: without it the engine has no
// return target and answered with an unclassified fault — a 500 for a field the
// caller simply omitted. The engine must not be reached at all.
func TestCreateSession_SameDeviceRequiresRedirectURI(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, []string{"https://client.example"}, "https://client.example/webhook", iu)

	var engineCalled bool
	stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) {
		engineCalled = true
		w.WriteHeader(http.StatusCreated)
	})
	stub.attach(app)

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
		Flow:         "same_device",
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusBadRequest), qt.Commentf("body: %s", body))
	qt.Check(t, qt.IsFalse(engineCalled))
	// The status alone leaves an integrator guessing which field is missing.
	// Asserted on the PUBLIC body, because that is the boundary where the
	// azugo.BadRequestError alternative silently loses its message.
	p := decodeProblem(t, body)
	qt.Check(t, qt.StringContains(p.Detail, "redirectUri"))
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	qt.Assert(t, qt.IsNil(err))
	return b
}

// TestCreateSession_FlowDCAPIUnusableOriginNamed: an origin that was stored but
// cannot match anything a browser asserts must be reported as the stored-
// configuration problem it is, naming the offending entry — not left to the
// engine, which refuses the request without being able to say which value is
// at fault or that the cause is registration rather than this request.
//
// Reachable through a direct write to the registry (the write API rejects these
// shapes), which is exactly when nobody is watching and the message has to
// carry the diagnosis itself.
func TestCreateSession_FlowDCAPIUnusableOriginNamed(t *testing.T) {
	for _, origin := range []string{"", "http://client.example", "https://client.example/app", "not-a-url"} {
		t.Run(origin, func(t *testing.T) {
			ta, app := newSessionsApp(t)
			iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
			_, apiKey := seedSessionClient(t, app,
				[]string{"https://client.example", origin}, "https://client.example/webhook", iu)

			var engineCalled bool
			stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) {
				engineCalled = true
				w.WriteHeader(http.StatusCreated)
			})
			stub.attach(app)

			status, body := postSession(t, ta, apiKey, api.SessionRequest{
				Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
				Flow:         "dc_api",
			})
			qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("body: %s", body))
			p := decodeProblem(t, body)
			qt.Check(t, qt.Equals(p.Code, "err:client:originNotRegistered"))
			qt.Check(t, qt.IsTrue(strings.Contains(p.Detail, "not usable")),
				qt.Commentf("detail must name the cause, got: %s", p.Detail))
			// The engine is never asked: the request dies on stored state.
			qt.Check(t, qt.IsFalse(engineCalled))
		})
	}
}

// A well-formed list still reaches the engine — the check above must not
// reject every browser-flow session.
func TestCreateSession_FlowDCAPIGoodOriginsReachEngine(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app,
		[]string{"https://client.example", "https://client.example:8443"}, "https://client.example/webhook", iu)

	var engineCalled bool
	stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) {
		engineCalled = true
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"session_id":"s1","request_uri":"https://v.test/wallet/s1/request.jwt","response_uri":"https://v.test/wallet/t1/response","expires_at":"2030-01-01T00:00:00Z","invocation":{}}`))
	})
	stub.attach(app)

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
		Flow:         "dc_api",
	})
	qt.Check(t, qt.IsTrue(engineCalled), qt.Commentf("status %d body: %s", status, body))
}

// seedClientWithRegistrarIdentity seeds a client whose registrar identity is
// exactly what the test says — including the empty pair a client carries when
// the identity was never recorded — and returns its API key.
func seedClientWithRegistrarIdentity(t testing.TB, app *mgmt.App, registryURI, clientIdentifier string, ius ...registrydb.IntendedUse) string {
	t.Helper()
	c := &registrydb.Client{Name: "Test Client", RegistryURI: registryURI, ClientIdentifier: clientIdentifier}
	clientID, err := app.Registry().CreateClient(context.Background(), c)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(app.Registry().SetIntendedUses(context.Background(), clientID, ius)))
	displayKey, _, _, _ := mintAndStoreKey(t, app, clientID)
	return displayKey
}

// TestCreateSession_RegistrarIdentityMissingRefusedBeforeEngine: a client whose
// registrar identity was never recorded (or recorded unusably) is refused with
// the code that names the gap and the step that closes it — and the engine is
// never called, so no session is minted for a request that could not carry its
// registration reference. Asserting the 422 alone would still pass if the
// refusal came from further downstream; the never-called stub pins the property
// that matters.
func TestCreateSession_RegistrarIdentityMissingRefusedBeforeEngine(t *testing.T) {
	cases := []struct {
		name, registryURI, clientIdentifier, wantFault string
	}{
		{"never recorded (both empty)", "", "", "client id"},
		{"identifier empty", "https://registrar.test/api", "", "client id"},
		{"registry URI empty", "", "test-client-001", "registry URI must be an absolute https URL"},
		{"registry URI not https", "http://registrar.test/api", "test-client-001", "registry URI must be an absolute https URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ta, app := newSessionsApp(t)
			iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
			apiKey := seedClientWithRegistrarIdentity(t, app, tc.registryURI, tc.clientIdentifier, iu)
			stub := stubCreated(t) // would answer 201 — must never be asked
			stub.attach(app)

			status, body := postSession(t, ta, apiKey, api.SessionRequest{
				Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
			})
			qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity), qt.Commentf("body: %s", body))
			p := decodeProblem(t, body)
			qt.Check(t, qt.Equals(p.Code, "err:client:registrarIdentityRequired"))
			qt.Check(t, qt.Equals(p.Title, "Client registrar identity required"))
			qt.Check(t, qt.StringContains(p.Detail, "PUT /api/clients/{id}/registrar-identity"))
			qt.Check(t, qt.StringContains(p.Detail, tc.wantFault))
			qt.Check(t, qt.IsNil(stub.lastBody), qt.Commentf("the engine must not be called for a client that cannot carry its registration reference"))
		})
	}
}

// TestCreateSession_FlowDCAPINonObjectRequestIsEngineUnavailable: the engine
// answered 201 with a dc_api_request that is valid JSON but not an object. The
// caller is told the engine answered unusably (502, titled for the engine), not
// that this service failed (500) — and the cause stays out of the public body.
func TestCreateSession_FlowDCAPINonObjectRequestIsEngineUnavailable(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, []string{"https://client.example"}, "https://client.example/webhook", iu)

	stub := newVCStub(t, func(w http.ResponseWriter, _ []byte) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := vcclient.CreateResponse{SessionID: "sess-dcapi", ExpiresAt: time.Now().Add(5 * time.Minute).UTC(), ResponseURI: dcapiResponseURI}
		resp.Invocation.WalletURL = "https://wallet.example/invoke"
		resp.Invocation.DCAPIRequest = json.RawMessage(`["not","an","object"]`)
		_ = json.NewEncoder(w).Encode(resp)
	})
	stub.attach(app)

	status, body := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
		Flow:         "dc_api",
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusBadGateway), qt.Commentf("body: %s", body))
	p := decodeProblem(t, body)
	qt.Check(t, qt.Equals(p.Code, "err:upstream:unavailable"))
	qt.Check(t, qt.Equals(p.Title, "Verifier engine unavailable"))
	qt.Check(t, qt.Equals(p.Detail, ""), qt.Commentf("the cause is for the log, not the caller"))
}
