package registrydb

import (
	"encoding/json"
	"testing"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/go-quicktest/qt"
)

// registry:intended_use_revoked only maps to 422 once the "intended-use-
// revoked" reason is registered (app.go, at service startup). This test
// binary never runs app.go's init (registrydb can't import the eudiapimanagement
// package: eudiapimanagement imports registrydb, not the reverse), so mirror
// that one RegisterReason call here — keep it in sync with app.go.
func init() {
	pkerrors.RegisterReason("intendedUseRevoked", pkerrors.ReasonSpec{Status: 422, Title: "Intended use revoked"})
}

func TestParseEnvelopeSuccess(t *testing.T) {
	data, code, err := parseEnvelope([]byte(`{"result":"success","data":{"id":"01J"}}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(code, ""))
	qt.Assert(t, qt.Equals(string(data), `{"id":"01J"}`))
}

func TestParseEnvelopeError(t *testing.T) {
	_, code, err := parseEnvelope([]byte(`{"result":"error","code":"registry:not_found","message":"unknown client"}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(code, "registry:not_found"))
}

func TestParseEnvelopeGarbage(t *testing.T) {
	_, _, err := parseEnvelope([]byte(`not json`))
	qt.Assert(t, qt.IsNotNil(err))
}

// resultError bridges the DB house-style code (registry:<reason>) onto the
// error taxonomy (err:registry:<reason>) so FromResultCode maps status
// correctly. not_found is a builtin reason (-> 404); intended_use_revoked is
// registered by app.go as "intended-use-revoked" (-> 422) — FromResultCode
// normalizes "_"/"-" so registry:intended_use_revoked matches it.
func TestResultErrorHTTPStatus(t *testing.T) {
	type statusCoder interface{ StatusCode() int }

	nf, ok := resultError("registry:not_found").(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(nf.StatusCode(), 404))

	rev, ok := resultError("registry:intended_use_revoked").(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(rev.StatusCode(), 422))

	inv, ok := resultError("registry:invalid").(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.IsTrue(inv.StatusCode() >= 400 && inv.StatusCode() < 500))

	qt.Assert(t, qt.IsNil(resultError("")))
}

func seedClientWithIntendedUse(t *testing.T, f *Fake, revokedAt string) (clientID string) {
	t.Helper()
	ctx := t.Context()
	c := &Client{Name: "Client", RegistryURI: "https://reg.example", ClientIdentifier: "sub", DefaultWebhook: "https://a.example/hook"}
	id, err := f.CreateClient(ctx, c)
	qt.Assert(t, qt.IsNil(err))
	err = f.SetIntendedUses(ctx, id, []IntendedUse{
		{IntendedUseID: "iu-1", Credentials: []RegisteredCredentialJSON{{Format: "mso_mdoc", AllClaims: true}}, RevokedAt: revokedAt},
	})
	qt.Assert(t, qt.IsNil(err))
	return id
}

// Ownership isolation: a template created for client A is invisible to
// client B (same code as an unknown id — no existence leak).
func TestFakeTemplateOwnershipIsolation(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	clientA := seedClientWithIntendedUse(t, f, "")
	clientB, err := f.CreateClient(ctx, &Client{Name: "B", RegistryURI: "https://reg.example/b", ClientIdentifier: "sub-b", DefaultWebhook: "https://b.example/hook"})
	qt.Assert(t, qt.IsNil(err))

	tpl := &Template{Name: "t1", IntendedUseID: "iu-1", DCQLQuery: json.RawMessage(`{"credentials":[]}`)}
	id, err := f.CreateTemplate(ctx, clientA, tpl)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, tpl.ID))

	// owner reads fine
	got, err := f.GetTemplate(ctx, clientA, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.Name, "t1"))

	// cross-client read -> registry:not_found (404), not a distinguishable 403
	_, err = f.GetTemplate(ctx, clientB, id)
	qt.Assert(t, qt.ErrorMatches(err, ".*not.found.*"))
	type statusCoder interface{ StatusCode() int }
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))

	// cross-client delete also rejected
	err = f.DeleteTemplate(ctx, clientB, id)
	qt.Assert(t, qt.ErrorMatches(err, ".*not.found.*"))

	// cross-client list sees nothing
	list, err := f.ListTemplates(ctx, clientB)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(list, 0))

	// owner list sees it
	list, err = f.ListTemplates(ctx, clientA)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(list, 1))
}

// create_template on a revoked intended use is rejected BEFORE any write
// with the dedicated code (-> 422 via app.go's registration), distinct from a
// wholly-unknown intended use (-> registry:not_found, 404).
func TestFakeCreateTemplateRevokedIntendedUseRejected(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	clientA := seedClientWithIntendedUse(t, f, "2026-01-01")

	_, err := f.CreateTemplate(ctx, clientA, &Template{Name: "t", IntendedUseID: "iu-1", DCQLQuery: json.RawMessage(`{}`)})
	qt.Assert(t, qt.IsNotNil(err))
	type statusCoder interface{ StatusCode() int }
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 422))

	_, err = f.CreateTemplate(ctx, clientA, &Template{Name: "t2", IntendedUseID: "no-such-iu", DCQLQuery: json.RawMessage(`{}`)})
	qt.Assert(t, qt.IsNotNil(err))
	sc, ok = err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))
}

// GetWRPRCForIntendedUse distinguishes two absent cases: an OWNED intended
// use with no current WRPRC -> (nil, nil) success (graceful fallback); an
// intended use not owned by / unknown to the caller -> registry:not_found
// (404, no existence leak). When a WRPRC has been seeded for an owned
// intended use it is returned verbatim.
func TestFakeGetWRPRCForIntendedUseNilWhenAbsent(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	clientA := seedClientWithIntendedUse(t, f, "") // owns "iu-1"

	// owned but no WRPRC row yet -> nil success, not an error
	raw, err := f.GetWRPRCForIntendedUse(ctx, clientA, "iu-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(raw))

	// seeded WRPRC for the owned intended use -> returned verbatim
	f.SeedWRPRC(clientA, "iu-1", []byte("fake-signed-wrprc-bytes"))
	raw, err = f.GetWRPRCForIntendedUse(ctx, clientA, "iu-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(raw), "fake-signed-wrprc-bytes"))
}

// Regression: an intended-use-id the caller does NOT own must be
// registry:not_found (404), NOT the same empty-success as an
// owned-but-no-WRPRC intended use — no existence leak, and the two cases stay
// distinguishable.
func TestFakeGetWRPRCForUnownedIntendedUseIsNotFound(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	clientA := seedClientWithIntendedUse(t, f, "") // owns "iu-1"
	clientB, err := f.CreateClient(ctx, &Client{Name: "B", RegistryURI: "https://reg.example/b", ClientIdentifier: "sub-b", DefaultWebhook: "https://b.example/hook"})
	qt.Assert(t, qt.IsNil(err))

	// client B does not own "iu-1" -> not_found (404), even though a WRPRC
	// row keyed (clientB, "iu-1") is nonexistent either way.
	_, err = f.GetWRPRCForIntendedUse(ctx, clientB, "iu-1")
	qt.Assert(t, qt.IsNotNil(err))
	type statusCoder interface{ StatusCode() int }
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))

	// a wholly-unknown intended-use-id for a real client is also not_found
	_, err = f.GetWRPRCForIntendedUse(ctx, clientA, "no-such-iu")
	qt.Assert(t, qt.IsNotNil(err))
	sc, ok = err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))
}

func TestFakeAPIKeyLifecycle(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	clientA, err := f.CreateClient(ctx, &Client{Name: "A", RegistryURI: "https://reg.example/a", ClientIdentifier: "sub-a", DefaultWebhook: "https://a.example/hook"})
	qt.Assert(t, qt.IsNil(err))
	clientB, err := f.CreateClient(ctx, &Client{Name: "B", RegistryURI: "https://reg.example/b", ClientIdentifier: "sub-b", DefaultWebhook: "https://b.example/hook"})
	qt.Assert(t, qt.IsNil(err))

	keyID, err := f.CreateAPIKey(ctx, clientA, "pfx_1", "$argon2id$fake")
	qt.Assert(t, qt.IsNil(err))

	rec, err := f.GetClientByKeyPrefix(ctx, "pfx_1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(rec.ClientID, clientA))
	qt.Assert(t, qt.Equals(rec.Status, "active"))
	qt.Assert(t, qt.IsFalse(rec.Revoked))

	_, err = f.GetClientByKeyPrefix(ctx, "no-such-prefix")
	qt.Assert(t, qt.ErrorMatches(err, ".*not.found.*"))

	// cross-client revoke rejected
	err = f.RevokeAPIKey(ctx, clientB, keyID)
	qt.Assert(t, qt.ErrorMatches(err, ".*not.found.*"))

	// owner revoke succeeds and is reflected on lookup
	err = f.RevokeAPIKey(ctx, clientA, keyID)
	qt.Assert(t, qt.IsNil(err))
	rec, err = f.GetClientByKeyPrefix(ctx, "pfx_1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(rec.Revoked))
}

func TestFakeGetClientNotFound(t *testing.T) {
	f := NewFake()
	_, err := f.GetClient(t.Context(), "no-such-client")
	qt.Assert(t, qt.ErrorMatches(err, ".*not.found.*"))
}

func TestFakeGetIntendedUseCrossClientNotFound(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	clientA := seedClientWithIntendedUse(t, f, "")

	iu, err := f.GetIntendedUse(ctx, clientA, "iu-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(iu.IntendedUseID, "iu-1"))

	_, err = f.GetIntendedUse(ctx, "some-other-client", "iu-1")
	qt.Assert(t, qt.ErrorMatches(err, ".*not.found.*"))
}
