package routes

import (
	"context"
	"encoding/json"
	"testing"

	"azugo.io/azugo"
	"github.com/VictoriaMetrics/metrics"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/dativa-lv/eudi-api-management/internal/api"
	"github.com/dativa-lv/eudi-api-management/internal/obs"
	"github.com/dativa-lv/eudi-api-management/internal/registrydb"
)

// postTemplate issues POST /api/v1/templates.
func postTemplate(t testing.TB, ta *azugo.TestApp, apiKey string, req api.TemplateNew) (int, []byte) {
	t.Helper()
	tc := ta.TestClient()
	resp, err := tc.PostJSON("/api/v1/templates", req, tc.WithHeader(apiKeyHeader, apiKey))
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	body, _ := resp.BodyUncompressed()
	body = append([]byte(nil), body...)
	fasthttp.ReleaseResponse(resp)
	return status, body
}

// getTemplateReq issues GET /api/v1/templates/{templateId}.
func getTemplateReq(t testing.TB, ta *azugo.TestApp, apiKey, templateID string) (int, []byte) {
	t.Helper()
	tc := ta.TestClient()
	resp, err := tc.Get("/api/v1/templates/"+templateID, tc.WithHeader(apiKeyHeader, apiKey))
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	body, _ := resp.BodyUncompressed()
	body = append([]byte(nil), body...)
	fasthttp.ReleaseResponse(resp)
	return status, body
}

// listTemplatesReq issues GET /api/v1/templates.
func listTemplatesReq(t testing.TB, ta *azugo.TestApp, apiKey string) (int, []byte) {
	t.Helper()
	tc := ta.TestClient()
	resp, err := tc.Get("/api/v1/templates", tc.WithHeader(apiKeyHeader, apiKey))
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	body, _ := resp.BodyUncompressed()
	body = append([]byte(nil), body...)
	fasthttp.ReleaseResponse(resp)
	return status, body
}

// deleteTemplateReq issues DELETE /api/v1/templates/{templateId}.
func deleteTemplateReq(t testing.TB, ta *azugo.TestApp, apiKey, templateID string) (int, []byte) {
	t.Helper()
	tc := ta.TestClient()
	resp, err := tc.Delete("/api/v1/templates/"+templateID, tc.WithHeader(apiKeyHeader, apiKey))
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	body, _ := resp.BodyUncompressed()
	body = append([]byte(nil), body...)
	fasthttp.ReleaseResponse(resp)
	return status, body
}

func decodeTemplate(t testing.TB, body []byte) api.Template {
	t.Helper()
	var tpl api.Template
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &tpl)))
	return tpl
}

func decodeTemplateList(t testing.TB, body []byte) []api.Template {
	t.Helper()
	var tpls []api.Template
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &tpls)))
	return tpls
}

func TestCreateTemplate_InScope_Created(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	status, body := postTemplate(t, ta, apiKey, api.TemplateNew{
		Name:          "PID identification",
		IntendedUseID: "iu-1",
		DCQLQuery:     mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated), qt.Commentf("body: %s", body))

	got := decodeTemplate(t, body)
	qt.Check(t, qt.IsTrue(got.TemplateID != ""))
	qt.Check(t, qt.IsFalse(got.CreatedAt.IsZero()))
	qt.Check(t, qt.Equals(got.Name, "PID identification"))
	qt.Check(t, qt.Equals(got.IntendedUseID, "iu-1"))
}

// TestCreateTemplate_OutOfScope_Forbidden: write-time scope enforcement — a
// template requesting a claim outside the registered intended use is rejected
// at CREATE time, not deferred to session creation.
func TestCreateTemplate_OutOfScope_Forbidden(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	before := metrics.GetOrCreateCounter(obs.MetricScopeDenialsTotal).Get()

	status, body := postTemplate(t, ta, apiKey, api.TemplateNew{
		Name:          "Over-broad",
		IntendedUseID: "iu-1",
		// requests document_number, which is NOT registered above.
		DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name", "document_number"),
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusForbidden), qt.Commentf("body: %s", body))
	p := decodeProblem(t, body)
	qt.Check(t, qt.Equals(p.Code, "err:client:scopeExceeded"))
	qt.Check(t, qt.StringContains(p.Detail, "document_number"))

	// createTemplate's scope-error branch increments the shared denial counter.
	after := metrics.GetOrCreateCounter(obs.MetricScopeDenialsTotal).Get()
	qt.Check(t, qt.Equals(after-before, uint64(1)))
}

func TestCreateTemplate_IntendedUseRevoked(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	iu.RevokedAt = "2026-01-01"
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	status, body := postTemplate(t, ta, apiKey, api.TemplateNew{
		Name:          "PID identification",
		IntendedUseID: "iu-1",
		DCQLQuery:     mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity), qt.Commentf("body: %s", body))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:registrar:intendedUseRevoked"))
}

func TestCreateTemplate_MissingRequiredField(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	status, _ := postTemplate(t, ta, apiKey, api.TemplateNew{
		// Name omitted.
		IntendedUseID: "iu-1",
		DCQLQuery:     mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusBadRequest))
}

// TestCreateTemplate_UnknownIntendedUse_NotFound: resolving intendedUseId
// happens before the scope check — an unregistered id is a 404, not a 403
// (no existence leak, but also not silently treated as in-scope).
func TestCreateTemplate_UnknownIntendedUse_NotFound(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	status, _ := postTemplate(t, ta, apiKey, api.TemplateNew{
		Name:          "PID identification",
		IntendedUseID: "does-not-exist",
		DCQLQuery:     mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
}

// TestListTemplates_OwnOnly: cross-client isolation — client A's list never
// includes client B's templates.
func TestListTemplates_OwnOnly(t *testing.T) {
	ta, app := newSessionsApp(t)
	iuA := mdocIntendedUseRow("iu-a", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKeyA := seedSessionClient(t, app, nil, "https://a.example/webhook", iuA)
	iuB := mdocIntendedUseRow("iu-b", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKeyB := seedSessionClient(t, app, nil, "https://b.example/webhook", iuB)

	statusA, bodyA := postTemplate(t, ta, apiKeyA, api.TemplateNew{
		Name: "A's template", IntendedUseID: "iu-a",
		DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	qt.Assert(t, qt.Equals(statusA, fasthttp.StatusCreated), qt.Commentf("body: %s", bodyA))

	statusB, bodyB := postTemplate(t, ta, apiKeyB, api.TemplateNew{
		Name: "B's template", IntendedUseID: "iu-b",
		DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	qt.Assert(t, qt.Equals(statusB, fasthttp.StatusCreated), qt.Commentf("body: %s", bodyB))

	status, body := listTemplatesReq(t, ta, apiKeyA)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusOK), qt.Commentf("body: %s", body))
	got := decodeTemplateList(t, body)
	qt.Assert(t, qt.HasLen(got, 1))
	qt.Check(t, qt.Equals(got[0].Name, "A's template"))
}

// TestGetTemplate_Foreign_NotFound: another client's template id reads as 404,
// not 403 (no existence leak, same acceptance as sessions), rendering the
// specific err:template:notFound code, not the generic err:request:notFound a
// raw registry error would produce.
func TestGetTemplate_Foreign_NotFound(t *testing.T) {
	ta, app := newSessionsApp(t)
	iuA := mdocIntendedUseRow("iu-a", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKeyA := seedSessionClient(t, app, nil, "https://a.example/webhook", iuA)
	iuB := mdocIntendedUseRow("iu-b", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKeyB := seedSessionClient(t, app, nil, "https://b.example/webhook", iuB)

	_, bodyA := postTemplate(t, ta, apiKeyA, api.TemplateNew{
		Name: "A's template", IntendedUseID: "iu-a",
		DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	tplA := decodeTemplate(t, bodyA)

	status, body := getTemplateReq(t, ta, apiKeyB, tplA.TemplateID)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:template:notFound"))
}

// TestGetTemplate_Unknown_NotFound: a template id that was never created (not
// merely owned by another client) reads as the SAME err:template:notFound 404
// as the foreign case below — no oracle distinguishing "exists but not yours"
// from "never existed".
func TestGetTemplate_Unknown_NotFound(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	status, body := getTemplateReq(t, ta, apiKey, "does-not-exist")
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:template:notFound"))
}

// TestGetTemplate_ForeignAndUnknown_SameCode: explicit no-oracle check — the
// foreign-template and wholly-unknown-template responses must be identical
// on the wire (same code), not merely both 404s that could otherwise be
// distinguished by a different code/detail.
func TestGetTemplate_ForeignAndUnknown_SameCode(t *testing.T) {
	ta, app := newSessionsApp(t)
	iuA := mdocIntendedUseRow("iu-a", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKeyA := seedSessionClient(t, app, nil, "https://a.example/webhook", iuA)
	iuB := mdocIntendedUseRow("iu-b", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKeyB := seedSessionClient(t, app, nil, "https://b.example/webhook", iuB)

	_, bodyA := postTemplate(t, ta, apiKeyA, api.TemplateNew{
		Name: "A's template", IntendedUseID: "iu-a",
		DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	tplA := decodeTemplate(t, bodyA)

	statusForeign, bodyForeign := getTemplateReq(t, ta, apiKeyB, tplA.TemplateID)
	statusUnknown, bodyUnknown := getTemplateReq(t, ta, apiKeyB, "does-not-exist")

	qt.Assert(t, qt.Equals(statusForeign, fasthttp.StatusNotFound))
	qt.Assert(t, qt.Equals(statusUnknown, fasthttp.StatusNotFound))
	qt.Check(t, qt.Equals(decodeProblem(t, bodyForeign).Code, decodeProblem(t, bodyUnknown).Code))
	qt.Check(t, qt.Equals(decodeProblem(t, bodyForeign).Code, "err:template:notFound"))
}

// TestDeleteTemplate_ThenGet_NotFound: delete is a soft-delete — the template
// is immediately unreachable via GET.
func TestDeleteTemplate_ThenGet_NotFound(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	_, body := postTemplate(t, ta, apiKey, api.TemplateNew{
		Name: "To delete", IntendedUseID: "iu-1",
		DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	tpl := decodeTemplate(t, body)

	statusDel, bodyDel := deleteTemplateReq(t, ta, apiKey, tpl.TemplateID)
	qt.Assert(t, qt.Equals(statusDel, fasthttp.StatusNoContent), qt.Commentf("body: %s", bodyDel))

	statusGet, _ := getTemplateReq(t, ta, apiKey, tpl.TemplateID)
	qt.Assert(t, qt.Equals(statusGet, fasthttp.StatusNotFound))
}

// TestDeleteTemplate_Foreign_NotFound: deleting another client's template is
// 404, not 403/204 — no existence leak, and the row must survive untouched.
func TestDeleteTemplate_Foreign_NotFound(t *testing.T) {
	ta, app := newSessionsApp(t)
	iuA := mdocIntendedUseRow("iu-a", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKeyA := seedSessionClient(t, app, nil, "https://a.example/webhook", iuA)
	iuB := mdocIntendedUseRow("iu-b", "org.iso.18013.5.1.mDL", "given_name")
	_, apiKeyB := seedSessionClient(t, app, nil, "https://b.example/webhook", iuB)

	_, bodyA := postTemplate(t, ta, apiKeyA, api.TemplateNew{
		Name: "A's template", IntendedUseID: "iu-a",
		DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	tplA := decodeTemplate(t, bodyA)

	status, body := deleteTemplateReq(t, ta, apiKeyB, tplA.TemplateID)
	qt.Assert(t, qt.Equals(status, fasthttp.StatusNotFound))
	qt.Check(t, qt.Equals(decodeProblem(t, body).Code, "err:template:notFound"))

	// The row survived — the owner can still fetch it.
	statusOwner, _ := getTemplateReq(t, ta, apiKeyA, tplA.TemplateID)
	qt.Assert(t, qt.Equals(statusOwner, fasthttp.StatusOK))
}

// TestTemplateCreate_ThenIntendedUseRevoked_SessionCreateFails is the
// end-to-end acceptance: a template that was valid (in scope, non-revoked
// intended use) at CREATE time must still fail session creation once its
// intended use is revoked afterwards — revocation is re-checked live, never
// cached at template-creation time.
func TestTemplateCreate_ThenIntendedUseRevoked_SessionCreateFails(t *testing.T) {
	ta, app := newSessionsApp(t)
	iu := mdocIntendedUseRow("iu-1", "org.iso.18013.5.1.mDL", "given_name")
	clientID, apiKey := seedSessionClient(t, app, nil, "https://client.example/webhook", iu)

	_, body := postTemplate(t, ta, apiKey, api.TemplateNew{
		Name: "PID identification", IntendedUseID: "iu-1",
		DCQLQuery: mdocDCQLQuery("org.iso.18013.5.1.mDL", "given_name"),
	})
	tpl := decodeTemplate(t, body)
	qt.Assert(t, qt.IsTrue(tpl.TemplateID != ""))

	// Revoke the intended use AFTER template creation: SetIntendedUses
	// replaces the client's full intended-use set (registrydb.Fake semantics)
	// with the same iu-1 id now carrying a RevokedAt date.
	revoked := iu
	revoked.RevokedAt = "2026-01-01"
	qt.Assert(t, qt.IsNil(app.Registry().SetIntendedUses(context.Background(), clientID, []registrydb.IntendedUse{revoked})))

	status, sbody := postSession(t, ta, apiKey, api.SessionRequest{
		Presentation: api.Presentation{TemplateID: tpl.TemplateID},
	})
	qt.Assert(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity), qt.Commentf("body: %s", sbody))
	qt.Check(t, qt.Equals(decodeProblem(t, sbody).Code, "err:registrar:intendedUseRevoked"))
}
