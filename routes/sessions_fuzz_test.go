package routes

import (
	"context"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	mgmt "github.com/dativa-lv/eudi-api-management"
	"github.com/dativa-lv/eudi-api-management/internal/registrydb"
)

// FuzzCreateSessionBody drives the authed POST /api/v1/sessions handler with
// arbitrary JSON bodies — every parser of untrusted input needs a fuzz target
// and must not panic on malformed input. The handler parses/validates a
// client-controlled DCQL query and several other attacker-shaped fields
// before ever reaching a real intended use, so this is the untrusted-input
// boundary. A VALID API key is used so every input actually reaches the
// handler's body parsing (an invalid key would short-circuit at the auth
// middleware — a separate surface — and never exercise this parser at all).
//
// Any outcome is fine EXCEPT a panic or a non-problem+json error body. A 2xx
// is impossible by construction here: the seeded intended use covers exactly
// one credential/claim shape, and even a body that happened to match it
// perfectly would still fail at the internal-API call (TestApp's
// VERIFIER_INTERNAL_URL is deliberately unreachable) — so a 2xx observed here
// means some check upstream of that call was bypassed, which is itself worth
// failing loudly on.
func FuzzCreateSessionBody(f *testing.F) {
	f.Add([]byte(`{"presentation":{"dcqlQuery":{"credentials":[]}}}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"presentation":{"templateId":"x","dcqlQuery":{}}}`))
	f.Add([]byte(`{"presentation":{"dcqlQuery":{"credentials":[{"id":"a","format":"mso_mdoc","meta":{"doctype_value":"d"},"claims":[{"path":["a",null,1,"b"]}]}]}},"flow":"same_device","redirectUri":"not a url","webhookUrl":"://","ttlSeconds":-1,"intendedUseId":"` + string(make([]byte, 200)) + `"}`))
	f.Add([]byte(`{"presentation":{"dcqlQuery":{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":[1,2]},"claims":[{"path":[{}]}]}]}},"transactionData":[1,2,3]}`))

	app := mgmt.TestApp(f)
	qt.Assert(f, qt.IsNil(Init(app)))

	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	clientID, err := app.Registry().CreateClient(context.Background(), &registrydb.Client{
		Name:             "Fuzz Client",
		RegistryURI:      "https://registrar.test/api",
		ClientIdentifier: "fuzz-client",
		DefaultWebhook:   "https://client.example/webhook",
		AllowedOrigins:   []string{"https://client.example"},
	})
	qt.Assert(f, qt.IsNil(err))
	qt.Assert(f, qt.IsNil(app.Registry().SetIntendedUses(context.Background(), clientID, []registrydb.IntendedUse{iu})))
	apiKey, _, _, _ := mintAndStoreKey(f, app, clientID)

	ta := azugo.NewTestApp(app.App)
	ta.StartBenchmark() // *testing.F is not a *testing.T; StartBenchmark needs neither.
	f.Cleanup(ta.Stop)

	f.Fuzz(func(t *testing.T, body []byte) {
		tc := ta.TestClient()
		resp, err := tc.Call(fasthttp.MethodPost, "/api/v1/sessions", body,
			tc.WithHeader(apiKeyHeader, apiKey),
			tc.WithHeader(fasthttp.HeaderContentType, "application/json"))
		qt.Assert(t, qt.IsNil(err))
		defer fasthttp.ReleaseResponse(resp)

		status := resp.StatusCode()
		body2 := append([]byte(nil), resp.Body()...)
		if status/100 == 2 {
			t.Fatalf("unexpected 2xx (%d) for a fuzzed body against an unreachable internal API; body: %s", status, body2)
		}

		ct := string(resp.Header.ContentType())
		qt.Check(t, qt.StringContains(ct, "application/problem+json"),
			qt.Commentf("expected application/problem+json, got %q (status %d, body %q)", ct, status, body2))
	})
}
