package routes

import (
	"strconv"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	mgmt "github.com/dativa-lv/eudi-api-management"
	"github.com/dativa-lv/eudi-api-management/internal/api"
)

// newRateLimitedApp boots the app with small, test-tunable per-key/per-IP
// session-creation rate limits so bursting past them in tests is cheap, then
// registers the full router (Init) so POST /api/v1/sessions carries the real
// limiters. The window is fixed at one hour — long enough that no assertion
// below can ever straddle a window rollover, however slow the CI box.
func newRateLimitedApp(t *testing.T, perKey, perIP int) (*azugo.TestApp, *mgmt.App) {
	t.Helper()
	app := mgmt.TestApp(t)
	app.Config().SessionRateLimitPerKey = perKey
	app.Config().SessionRateLimitPerIP = perIP
	app.Config().SessionRateWindow = time.Hour
	qt.Assert(t, qt.IsNil(Init(app)))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	t.Cleanup(ta.Stop)
	return ta, app
}

// validSessionRequest is a session-create body that always passes
// authorization (single registered intended use, in-scope DCQL query) so
// every non-rate-limited call in this file reaches the VC stub and gets 201.
func validSessionRequest() api.SessionRequest {
	return api.SessionRequest{
		Presentation: api.Presentation{DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name")},
	}
}

// postSessionAs POSTs /api/v1/sessions with the given API key and, if ip is
// non-empty, an X-Real-IP header spoofing the client address — honored because
// azugo.NewTestApp sets Proxy.TrustAll, so RealIP always trusts the configured
// trusted headers (X-Real-IP first, per the proxy defaults). Returns status,
// body, and the raw Retry-After header value (empty if absent).
func postSessionAs(t testing.TB, ta *azugo.TestApp, apiKey, ip string, req api.SessionRequest) (int, []byte, string) {
	t.Helper()
	tc := ta.TestClient()
	opts := []azugo.TestClientOption{tc.WithHeader(apiKeyHeader, apiKey)}
	if ip != "" {
		opts = append(opts, tc.WithHeader("X-Real-IP", ip))
	}
	resp, err := tc.PostJSON("/api/v1/sessions", req, opts...)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	retryAfter := string(resp.Header.Peek("Retry-After"))
	body, _ := resp.BodyUncompressed()
	body = append([]byte(nil), body...)
	fasthttp.ReleaseResponse(resp)
	return status, body, retryAfter
}

// TestSessionRateLimit_PerKeyBurst_LastRequest429WithRetryAfter is the core
// acceptance: the (SessionRateLimitPerKey+1)th create from one client within
// the window is rejected with 429 and a Retry-After header. perIP is set far
// above the burst size so the IP dimension never interferes.
func TestSessionRateLimit_PerKeyBurst_LastRequest429WithRetryAfter(t *testing.T) {
	const perKey = 3
	ta, app := newRateLimitedApp(t, perKey, 1000)

	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)
	stubCreated(t).attach(app)

	req := validSessionRequest()
	for i := range perKey {
		status, body, _ := postSessionAs(t, ta, apiKey, "", req)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated), qt.Commentf("request %d body: %s", i+1, body))
	}

	status, body, retryAfter := postSessionAs(t, ta, apiKey, "", req)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusTooManyRequests), qt.Commentf("body: %s", body))
	qt.Assert(t, qt.IsTrue(retryAfter != ""), qt.Commentf("expected a Retry-After header on 429"))
	seconds, err := strconv.Atoi(retryAfter)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(seconds > 0))
}

// TestSessionRateLimit_PerKeyIsolation_DifferentKeyUnaffected proves the
// key-scoped limiter is keyed per client, not global: exhausting client A's
// budget must not affect client B.
func TestSessionRateLimit_PerKeyIsolation_DifferentKeyUnaffected(t *testing.T) {
	const perKey = 3
	ta, app := newRateLimitedApp(t, perKey, 1000)

	iuA := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, keyA := seedSessionClient(t, app, nil, "https://client.example/webhook", iuA)
	iuB := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, keyB := seedSessionClient(t, app, nil, "https://client.example/webhook", iuB)
	stubCreated(t).attach(app)

	req := validSessionRequest()
	for i := range perKey {
		status, body, _ := postSessionAs(t, ta, keyA, "", req)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated), qt.Commentf("A request %d body: %s", i+1, body))
	}
	statusA, _, _ := postSessionAs(t, ta, keyA, "", req)
	qt.Assert(t, qt.Equals(statusA, fasthttp.StatusTooManyRequests))

	// Client B, never having posted before, is unaffected by A's exhaustion.
	statusB, bodyB, _ := postSessionAs(t, ta, keyB, "", req)
	qt.Assert(t, qt.Equals(statusB, fasthttp.StatusCreated), qt.Commentf("body: %s", bodyB))
}

// TestSessionRateLimit_KeyDimension_CapsAcrossDifferentIPs proves the
// key-scoped limiter tracks the CLIENT ID, not the caller's address: the
// same key rotated across different source IPs still trips at
// SessionRateLimitPerKey+1. perIP is set high per-IP-share so the IP
// dimension (each IP only ever sees one request here) never trips first.
func TestSessionRateLimit_KeyDimension_CapsAcrossDifferentIPs(t *testing.T) {
	const perKey = 3
	ta, app := newRateLimitedApp(t, perKey, 1000)

	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)
	stubCreated(t).attach(app)

	req := validSessionRequest()
	ips := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}
	for i := range perKey {
		status, body, _ := postSessionAs(t, ta, apiKey, ips[i], req)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated), qt.Commentf("request %d (ip %s) body: %s", i+1, ips[i], body))
	}

	// The (perKey+1)th request, from yet another fresh IP, is STILL rejected
	// — proving the key dimension (not IP) is what capped it.
	status, body, _ := postSessionAs(t, ta, apiKey, ips[perKey], req)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusTooManyRequests), qt.Commentf("body: %s", body))
}

// TestSessionRateLimit_PerIPBurst_CapsAcrossManyKeys proves the IP-scoped
// limiter caps by source address regardless of which (valid, individually
// far-from-its-own-limit) client key is presented. perKey is set far above
// the burst size so the key dimension never interferes.
func TestSessionRateLimit_PerIPBurst_CapsAcrossManyKeys(t *testing.T) {
	const perIP = 3
	ta, app := newRateLimitedApp(t, 1000, perIP)
	stubCreated(t).attach(app)

	req := validSessionRequest()
	keys := make([]string, perIP+1)
	for i := range keys {
		iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
		_, key := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)
		keys[i] = key
	}

	// All requests share the same (default, unspoofed) source IP but use a
	// BRAND NEW client key each time.
	for i := range perIP {
		status, body, _ := postSessionAs(t, ta, keys[i], "", req)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated), qt.Commentf("request %d body: %s", i+1, body))
	}

	status, body, _ := postSessionAs(t, ta, keys[perIP], "", req)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusTooManyRequests), qt.Commentf("body: %s", body))
}

// TestSessionRateLimit_OtherRoutesUnlimited proves the two session-create
// limiters are scoped to POST /api/v1/sessions alone: GET /sessions/{id} and
// GET /templates must never see a 429, even after issuing far more requests
// than the (tiny) configured session-create limits would tolerate.
func TestSessionRateLimit_OtherRoutesUnlimited(t *testing.T) {
	const tinyLimit = 2
	ta, app := newRateLimitedApp(t, tinyLimit, tinyLimit)

	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook",
		mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name"))
	_ = clientID

	const burst = 10 // > tinyLimit
	tc := ta.TestClient()

	for i := 0; i < burst; i++ {
		resp, err := tc.Get("/api/v1/sessions/does-not-exist", tc.WithHeader(apiKeyHeader, apiKey))
		qt.Assert(t, qt.IsNil(err))
		status := resp.StatusCode()
		fasthttp.ReleaseResponse(resp)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound), qt.Commentf("GET /sessions/{id} request %d", i+1))
	}

	for i := 0; i < burst; i++ {
		resp, err := tc.Get("/api/v1/templates", tc.WithHeader(apiKeyHeader, apiKey))
		qt.Assert(t, qt.IsNil(err))
		status := resp.StatusCode()
		fasthttp.ReleaseResponse(resp)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("GET /templates request %d", i+1))
	}
}
