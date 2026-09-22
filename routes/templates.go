package routes

import (
	"encoding/json"
	"errors"
	"strings"

	"azugo.io/azugo"
	dcql "github.com/gmb-eudi/go-dcql"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/valyala/fasthttp"

	"github.com/digimaks/eudi-api-management/internal/api"
	"github.com/digimaks/eudi-api-management/internal/obs"
	"github.com/digimaks/eudi-api-management/internal/registrydb"
	"github.com/digimaks/eudi-api-management/internal/scope"
)

// createTemplate is POST /api/v1/templates: it validates the template's DCQL
// query against the client's registered intended use at CREATE time —
// write-time scope enforcement, so a stored template can never outrun what the
// client is registered for. The ordering mirrors createSession: resolve and
// revocation-check the target intended use (ARF TS5 intendedUseId) BEFORE the
// scope check, and only persist once both pass.
func (r *router) createTemplate(ctx *azugo.Context) {
	var req api.TemplateNew
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)
		return
	}

	// Required fields: name, dcqlQuery, intendedUseId. description is optional.
	if req.Name == "" || req.IntendedUseID == "" || len(req.DCQLQuery) == 0 {
		ctx.Error(azugo.BadRequestError{Description: "name, intendedUseId, and dcqlQuery are required"})
		return
	}

	clientID, _ := ctx.UserValue("client_id").(string)

	// ARF TS5 intendedUseId semantics: resolve + revocation re-check before any
	// scope validation or write — a template can never be created against a
	// revoked intended use.
	iu, err := r.Registry().GetIntendedUse(ctx, clientID, req.IntendedUseID)
	if err != nil {
		ctx.Error(err) // unknown/foreign intended use -> 404, no existence leak
		return
	}
	if iu.RevokedAt != "" {
		ctx.Error(pkerrors.NewProblem("err:registrar:intendedUseRevoked"))
		return
	}

	rawQuery, err := json.Marshal(req.DCQLQuery)
	if err != nil {
		ctx.Error(azugo.BadRequestError{Description: "invalid dcqlQuery", Err: err})
		return
	}

	// Write-time scope enforcement ([OID4VP §6] / [OID4VP §7] parse/validate, then
	// registered-scope check) — never a claim value in any error path.
	if _, err := scope.CheckWithinScope(rawQuery, []registrydb.IntendedUse{*iu}, req.IntendedUseID); err != nil {
		var scopeErr *scope.ScopeError
		switch {
		case errors.As(err, &scopeErr):
			obs.IncScopeDenial()
			ctx.Error(pkerrors.NewProblem("err:client:scopeExceeded",
				pkerrors.WithPublicDetail(strings.Join(scopeErr.Offending, "; "))))
			return
		case errors.Is(err, dcql.ErrParse), errors.Is(err, dcql.ErrInvalid):
			ctx.Error(azugo.BadRequestError{Description: "invalid dcqlQuery", Err: err})
			return
		default:
			ctx.Error(err)
			return
		}
	}

	tpl := &registrydb.Template{
		Name:          req.Name,
		Description:   req.Description,
		IntendedUseID: req.IntendedUseID,
		DCQLQuery:     rawQuery,
	}
	// CreateTemplate re-validates existence/non-revocation of the intended use
	// INSIDE the procedure/fake too (defense in depth) and fills
	// tpl.ID/tpl.CreatedAt on success.
	if _, err := r.Registry().CreateTemplate(ctx, clientID, tpl); err != nil {
		ctx.Error(err)
		return
	}

	out := api.Template{TemplateNew: req, TemplateID: tpl.ID, CreatedAt: tpl.CreatedAt}
	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(out)
}

// listTemplates is GET /api/v1/templates: the client's own templates only
// (registrydb.ListTemplates scopes by clientID for cross-client isolation).
func (r *router) listTemplates(ctx *azugo.Context) {
	clientID, _ := ctx.UserValue("client_id").(string)

	tpls, err := r.Registry().ListTemplates(ctx, clientID)
	if err != nil {
		ctx.Error(err)
		return
	}

	out := make([]api.Template, 0, len(tpls))
	for i := range tpls {
		o, err := templateToAPI(tpls[i])
		if err != nil {
			ctx.Error(err)
			return
		}
		out = append(out, o)
	}
	ctx.JSON(out)
}

// getTemplate is GET /api/v1/templates/{templateId}: another client's or an
// unknown template both translate the store's not-found outcome to the same
// err:template:notFound (404) — no existence leak. Without this translation
// the raw registrydb not-found error would render as the generic
// err:request:notFound instead.
func (r *router) getTemplate(ctx *azugo.Context) {
	clientID, _ := ctx.UserValue("client_id").(string)
	templateID := ctx.Params.String("templateId")

	tpl, err := r.Registry().GetTemplate(ctx, clientID, templateID)
	if err != nil {
		if isNotFoundError(err) {
			// foreign/unknown -> err:template:notFound, no existence leak
			ctx.Error(pkerrors.NewProblem("err:template:notFound"))
			return
		}
		ctx.Error(err)
		return
	}

	out, err := templateToAPI(*tpl)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(out)
}

// deleteTemplate is DELETE /api/v1/templates/{templateId}: soft-delete scoped
// to clientID; another client's or an already-deleted template both fail
// err:template:notFound (no existence leak, same as getTemplate).
func (r *router) deleteTemplate(ctx *azugo.Context) {
	clientID, _ := ctx.UserValue("client_id").(string)
	templateID := ctx.Params.String("templateId")

	if err := r.Registry().DeleteTemplate(ctx, clientID, templateID); err != nil {
		if isNotFoundError(err) {
			// foreign/unknown -> err:template:notFound, no existence leak
			ctx.Error(pkerrors.NewProblem("err:template:notFound"))
			return
		}
		ctx.Error(err)
		return
	}

	ctx.StatusCode(fasthttp.StatusNoContent)
}

// templateToAPI projects a registrydb.Template row onto the wire DTO,
// decoding its stored DCQLQuery (json.RawMessage) back into the
// map[string]any shape api.TemplateNew declares.
func templateToAPI(t registrydb.Template) (api.Template, error) {
	var q map[string]any
	if len(t.DCQLQuery) > 0 {
		if err := json.Unmarshal(t.DCQLQuery, &q); err != nil {
			return api.Template{}, err
		}
	}
	return api.Template{
		TemplateNew: api.TemplateNew{
			Name:          t.Name,
			Description:   t.Description,
			IntendedUseID: t.IntendedUseID,
			DCQLQuery:     q,
		},
		TemplateID: t.ID,
		CreatedAt:  t.CreatedAt,
	}, nil
}
