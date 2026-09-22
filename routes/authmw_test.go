package routes

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	mgmt "github.com/digimaks/eudi-api-management"
	"github.com/digimaks/eudi-api-management/internal/apikeys"
	"github.com/digimaks/eudi-api-management/internal/registrydb"
)

// testAppWithProbe boots the app, runs newRouter (health + the auth-gated
// /api/v1 group), and attaches a GET /api/v1/probe route to r.v1 — the same
// authenticated group the real resource routes bind to. The probe echoes back
// the client_id apiKeyAuth set, so tests can assert both status and identity.
func testAppWithProbe(t testing.TB) (*azugo.TestApp, *mgmt.App) {
	t.Helper()
	app := mgmt.TestApp(t)
	r := newRouter(app)
	r.v1.Get("/probe", func(ctx *azugo.Context) {
		clientID, _ := ctx.UserValue("client_id").(string)
		ctx.JSON(map[string]string{"client_id": clientID})
	})
	return azugo.NewTestApp(app.App), app
}

// seedClient inserts a client row with the given status ("" defaults to
// "active" — registrydb.Fake.CreateClient's own default) and returns its id.
func seedClient(t testing.TB, app *mgmt.App, status string) string {
	t.Helper()
	c := &registrydb.Client{
		Name:             "Test Client",
		RegistryURI:      "https://registrar.test",
		ClientIdentifier: "test-client-001",
		Status:           status,
	}
	id, err := app.Registry().CreateClient(context.Background(), c)
	qt.Assert(t, qt.IsNil(err))
	return id
}

// mintAndStoreKey mints a fresh key, persists its argon2id hash for
// clientID, and returns everything a test needs: the presentable displayKey,
// its prefix/secret parts, and the registry-assigned keyID (for revocation).
func mintAndStoreKey(t testing.TB, app *mgmt.App, clientID string) (displayKey, prefix, secret, keyID string) {
	t.Helper()
	displayKey, prefix, phcHash, err := apikeys.Mint(rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	_, secret, err = apikeys.Parse(displayKey)
	qt.Assert(t, qt.IsNil(err))
	keyID, err = app.Registry().CreateAPIKey(context.Background(), clientID, prefix, phcHash)
	qt.Assert(t, qt.IsNil(err))
	return displayKey, prefix, secret, keyID
}

// flipFirstChar returns a same-length string differing from s in its first
// character — used to build a "wrong secret, correct prefix" key.
func flipFirstChar(s string) string {
	alt := byte('A')
	if s[0] == 'A' {
		alt = 'B'
	}
	return string(alt) + s[1:]
}

// probe GETs /api/v1/probe with the given presented key (empty = header
// omitted entirely) and returns the status and raw body.
func probe(t testing.TB, app *azugo.TestApp, presented string) (int, []byte) {
	t.Helper()
	tc := app.TestClient()
	opts := []azugo.TestClientOption{}
	if presented != "" {
		opts = append(opts, tc.WithHeader(apiKeyHeader, presented))
	}
	resp, err := tc.Get("/api/v1/probe", opts...)
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	body, _ := resp.BodyUncompressed()
	body = append([]byte(nil), body...)
	fasthttp.ReleaseResponse(resp)
	return status, body
}

// problemWire is the subset of the RFC 9457 body compared for "uniform
// body" assertions. trace_id is deliberately excluded: it legitimately
// varies per request (the correlation id), so "byte-identical apart from
// instance/trace" is asserted on everything else.
type problemWire struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code"`
}

func decodeProblem(t testing.TB, body []byte) problemWire {
	t.Helper()
	var p problemWire
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &p)))
	return p
}

func TestAPIKeyAuthValidKeySucceedsAndSetsClientID(t *testing.T) {
	testApp, app := testAppWithProbe(t)
	testApp.Start(t)
	defer testApp.Stop()

	clientID := seedClient(t, app, "")
	displayKey, _, _, _ := mintAndStoreKey(t, app, clientID)

	status, body := probe(t, testApp, displayKey)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))

	var got struct {
		ClientID string `json:"client_id"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &got)))
	qt.Assert(t, qt.Equals(got.ClientID, clientID))
}

func TestAPIKeyAuthMissingHeaderUnauthorized(t *testing.T) {
	testApp, _ := testAppWithProbe(t)
	testApp.Start(t)
	defer testApp.Stop()

	status, _ := probe(t, testApp, "")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnauthorized))
}

func TestAPIKeyAuthMalformedKeyUnauthorized(t *testing.T) {
	testApp, _ := testAppWithProbe(t)
	testApp.Start(t)
	defer testApp.Stop()

	status, _ := probe(t, testApp, "not-even-the-right-shape")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnauthorized))
}

// TestAllUnauthorizedBodiesByteIdentical is the core no-oracle acceptance: an
// attacker must not be able to tell ANY of the five presented-key 401 causes
// apart — missing header, malformed key, unknown prefix, wrong secret on a
// known prefix, or a revoked key. All five render a byte-identical problem
// body (aside from the per-request trace_id, which decodeProblem excludes),
// not merely the same status+code.
func TestAllUnauthorizedBodiesByteIdentical(t *testing.T) {
	testApp, app := testAppWithProbe(t)
	testApp.Start(t)
	defer testApp.Stop()

	clientID := seedClient(t, app, "")
	displayKey, prefix, secret, keyID := mintAndStoreKey(t, app, clientID)

	wrongSecretKey := "vk_" + prefix + "_" + flipFirstChar(secret)

	// A freshly minted prefix that was never persisted via CreateAPIKey:
	// unknown to the store with overwhelming probability.
	_, unknownPrefix, _, err := apikeys.Mint(rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	unknownPrefixKey := "vk_" + unknownPrefix + "_" + secret

	// Sanity: the real key works before we revoke it, so the revoked-case 401
	// below is genuinely caused by revocation, not a broken fixture.
	statusValid, _ := probe(t, testApp, displayKey)
	qt.Assert(t, qt.Equals(statusValid, fasthttp.StatusOK))
	qt.Assert(t, qt.IsNil(app.Registry().RevokeAPIKey(context.Background(), clientID, keyID)))

	// All five presented-key 401 causes. "revoked" reuses displayKey (correct
	// secret) now that keyID is revoked; "wrong-secret" keeps the correct
	// prefix so it resolves the (now revoked) row but fails on the secret —
	// both must still land in the identical 401 bucket.
	cases := map[string]string{
		"missing-header": "",
		"malformed":      "vk_not_a_valid_shape",
		"unknown-prefix": unknownPrefixKey,
		"wrong-secret":   wrongSecretKey,
		"revoked":        displayKey,
	}
	bodies := map[string]problemWire{}
	for name, key := range cases {
		st, body := probe(t, testApp, key)
		qt.Assert(t, qt.Equals(st, fasthttp.StatusUnauthorized), qt.Commentf("case %q", name))
		bodies[name] = decodeProblem(t, body)
	}

	want := bodies["wrong-secret"]
	for name, got := range bodies {
		qt.Assert(t, qt.DeepEquals(got, want), qt.Commentf("case %q body differs", name))
	}
	qt.Assert(t, qt.Equals(want.Code, "err:client:unauthorized"))
	qt.Assert(t, qt.Equals(want.Status, fasthttp.StatusUnauthorized))
	qt.Assert(t, qt.Equals(want.Detail, "")) // never a per-branch detail (no leak)
}

func TestAPIKeyAuthRevokedKeyUnauthorized(t *testing.T) {
	testApp, app := testAppWithProbe(t)
	testApp.Start(t)
	defer testApp.Stop()

	clientID := seedClient(t, app, "")
	displayKey, _, _, keyID := mintAndStoreKey(t, app, clientID)

	statusBefore, _ := probe(t, testApp, displayKey)
	qt.Assert(t, qt.Equals(statusBefore, fasthttp.StatusOK))

	qt.Assert(t, qt.IsNil(app.Registry().RevokeAPIKey(context.Background(), clientID, keyID)))

	statusAfter, bodyAfter := probe(t, testApp, displayKey)
	qt.Assert(t, qt.Equals(statusAfter, fasthttp.StatusUnauthorized))
	qt.Assert(t, qt.Equals(decodeProblem(t, bodyAfter).Code, "err:client:unauthorized"))
}

func TestAPIKeyAuthSuspendedClientForbidden(t *testing.T) {
	testApp, app := testAppWithProbe(t)
	testApp.Start(t)
	defer testApp.Stop()

	clientID := seedClient(t, app, "suspended")
	displayKey, _, _, _ := mintAndStoreKey(t, app, clientID)

	status, body := probe(t, testApp, displayKey)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden))
	qt.Assert(t, qt.Equals(decodeProblem(t, body).Code, "err:client:notRegistered"))
}

// TestAPIKeyRotation is the rotation test: minting a new key B and revoking
// the old key A must take effect immediately (A -> 401, B -> 200), all within
// one test — proving revocation is never served stale by the verified-key
// cache (which only ever caches the argon2id verdict for a given keyID/secret
// pair, never the registry's revoked/active status).
func TestAPIKeyRotation(t *testing.T) {
	testApp, app := testAppWithProbe(t)
	testApp.Start(t)
	defer testApp.Stop()

	clientID := seedClient(t, app, "")
	keyA, _, _, keyIDA := mintAndStoreKey(t, app, clientID)

	statusA1, _ := probe(t, testApp, keyA)
	qt.Assert(t, qt.Equals(statusA1, fasthttp.StatusOK))

	keyB, _, _, _ := mintAndStoreKey(t, app, clientID)
	qt.Assert(t, qt.IsNil(app.Registry().RevokeAPIKey(context.Background(), clientID, keyIDA)))

	statusA2, _ := probe(t, testApp, keyA)
	qt.Assert(t, qt.Equals(statusA2, fasthttp.StatusUnauthorized))

	statusB, _ := probe(t, testApp, keyB)
	qt.Assert(t, qt.Equals(statusB, fasthttp.StatusOK))
}

// TestAPIKeyAuthCachedVerifyStillHonorsLiveRevocation exercises the same
// property as TestAPIKeyRotation but forces the FIRST probe to populate the
// verified-key cache (same key, two calls) before revoking, to make sure a
// warm cache entry doesn't shortcut the registry's revoked check.
func TestAPIKeyAuthCachedVerifyStillHonorsLiveRevocation(t *testing.T) {
	testApp, app := testAppWithProbe(t)
	testApp.Start(t)
	defer testApp.Stop()

	clientID := seedClient(t, app, "")
	displayKey, _, _, keyID := mintAndStoreKey(t, app, clientID)

	// Warm the cache: two identical successful verifies.
	for range 2 {
		status, _ := probe(t, testApp, displayKey)
		qt.Assert(t, qt.Equals(status, fasthttp.StatusOK))
	}

	qt.Assert(t, qt.IsNil(app.Registry().RevokeAPIKey(context.Background(), clientID, keyID)))

	status, _ := probe(t, testApp, displayKey)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnauthorized))
}
