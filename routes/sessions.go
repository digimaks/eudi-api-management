package routes

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"azugo.io/azugo"
	dcql "github.com/gmb-eudi/go-dcql"
	rpcert "github.com/gmb-eudi/go-eudi-rpcert"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/oklog/ulid/v2"
	"github.com/redis/go-redis/v9"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"

	"github.com/dativa-lv/eudi-api-management/internal/api"
	"github.com/dativa-lv/eudi-api-management/internal/obs"
	"github.com/dativa-lv/eudi-api-management/internal/registrydb"
	"github.com/dativa-lv/eudi-api-management/internal/results"
	"github.com/dativa-lv/eudi-api-management/internal/scope"
	"github.com/dativa-lv/eudi-api-management/internal/vcclient"
)

// createSession handles POST /api/v1/sessions: it authorizes the request
// (DCQL scope, intended-use resolution/revocation, pre-registered origins)
// and, only once authorized, calls eudi-verifier-core's internal API to mint the
// OID4VP session. It never writes the session row directly — eudi-verifier-core's
// internal API is the sole writer, and this service's database role has no
// grant to create sessions.
func (r *router) createSession(ctx *azugo.Context) {
	var req api.SessionRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)
		return
	}

	hasTemplate := req.Presentation.TemplateID != ""
	hasInline := len(req.Presentation.DCQLQuery) > 0
	if hasTemplate == hasInline { // both set or neither set
		ctx.Error(azugo.BadRequestError{Description: "presentation must set exactly one of templateId or dcqlQuery"})
		return
	}

	dbFlow, err := api.FlowToDB(req.Flow)
	if err != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "flow", Tag: "oneof=same_device cross_device dc_api", Err: err})
		return
	}

	// ttlSeconds: minimum 60, maximum 3600, default 300. 0 (omitted) is
	// resolved to the configured default below, AFTER this bounds check — an
	// explicit out-of-range value is the caller's error; omission is not.
	if req.TTLSeconds != 0 && (req.TTLSeconds < 60 || req.TTLSeconds > 3600) {
		ctx.Error(azugo.BadRequestError{Description: "ttlSeconds must be between 60 and 3600"})
		return
	}

	clientID, _ := ctx.UserValue("client_id").(string)
	client, err := r.Registry().GetClient(ctx, clientID)
	if err != nil {
		ctx.Error(err)
		return
	}

	// Resolve the presentation: a template pins its own registered intended
	// use (ARF TS5) at create time — the request's intendedUseId is irrelevant
	// for a template and is ignored; an inline dcqlQuery instead resolves the
	// target intended use from the request/registry below.
	var rawQuery json.RawMessage
	targetIUID := req.IntendedUseID
	if hasTemplate {
		tpl, err := r.Registry().GetTemplate(ctx, clientID, req.Presentation.TemplateID)
		if err != nil {
			ctx.Error(err)
			return
		}
		rawQuery = tpl.DCQLQuery
		targetIUID = tpl.IntendedUseID
	} else {
		rawQuery, err = json.Marshal(req.Presentation.DCQLQuery)
		if err != nil {
			ctx.Error(azugo.BadRequestError{Description: "invalid dcqlQuery", Err: err})
			return
		}
		if targetIUID == "" {
			// ARF TS5 intendedUseId semantics: required once the client has
			// more than one registered intended use.
			ius, err := r.Registry().ListIntendedUses(ctx, clientID)
			if err != nil {
				ctx.Error(err)
				return
			}
			if len(ius) != 1 {
				ctx.Error(pkerrors.NewProblem("err:client:intendedUseRequired",
					pkerrors.WithPublicDetail("intendedUseId is required when the client has more than one registered intended use (ARF TS5)")))
				return
			}
			targetIUID = ius[0].IntendedUseID
		}
	}

	// ARF TS5 intendedUseId semantics: resolve + revocation re-check — a
	// template valid at creation whose intended use was later revoked must
	// fail create, not just future creates from scratch.
	iu, err := r.Registry().GetIntendedUse(ctx, clientID, targetIUID)
	if err != nil {
		ctx.Error(err) // registry:not_found -> 404, no existence leak
		return
	}
	if iu.RevokedAt != "" {
		ctx.Error(pkerrors.NewProblem("err:registrar:intendedUseRevoked"))
		return
	}

	// [OID4VP §6] dcql_query (parsed/validated here; the scope check enforces
	// the registered scope — never an attribute value in any error path).
	if _, err := scope.CheckWithinScope(rawQuery, []registrydb.IntendedUse{*iu}, targetIUID); err != nil {
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

	// The browser-mediated flow cannot work for a client with no registered
	// origins: the verifier engine requires a non-empty expected-origins list
	// for it, and the browser's calling origin is checked against that list
	// before the response is decrypted. Caught HERE rather than left to the
	// engine because only this service knows WHY the list is empty — the
	// client's registration has none — and that is the thing the operator has
	// to change. Reported as the client-configuration error it is, so an
	// integrator is never told the verifier is broken when their registration
	// is simply incomplete.
	if dbFlow == "dcapi" && len(client.AllowedOrigins) == 0 {
		ctx.Error(pkerrors.NewProblem("err:client:originNotRegistered",
			pkerrors.WithPublicDetail("client has no allowed origins registered; the dc_api flow requires at least one")))
		return
	}
	// A registered origin that is not a bare web origin cannot match the one a
	// browser asserts, so the engine refuses the whole request — correctly, but
	// with nothing that says WHICH entry is wrong or that the cause is stored
	// configuration rather than this request. Named here for the same reason
	// the empty list is: only this service can see the client's stored list,
	// and that list is the thing someone has to fix. The offending value is
	// echoed because an operator repairing a registration needs to know which
	// entry to remove, and it is a value they registered themselves.
	if dbFlow == "dcapi" {
		for _, o := range client.AllowedOrigins {
			if !isWebOrigin(o) {
				ctx.Error(pkerrors.NewProblem("err:client:originNotRegistered",
					pkerrors.WithPublicDetail(fmt.Sprintf(
						"client has a registered origin that is not usable: %q must be https://host[:port] with no path, query, fragment or userinfo", o))))
				return
			}
		}
	}

	// same_device sends the person back to the caller's page when the wallet is
	// done, so that target is not optional for it — the engine requires it and
	// there is nothing sensible to default it to. Named here, in the caller's
	// own vocabulary, rather than left to come back from the engine as an
	// unclassified fault.
	//
	// Carried as a Problem with a PUBLIC detail rather than the
	// azugo.BadRequestError used above: that type's Description reaches the log
	// and nothing else, so an integrator would read a bare "Bad request" and
	// still not know which field is missing. Same code the boundary already
	// renders for this class — a detail is added, no new code is minted.
	if dbFlow == "same_device" && req.RedirectURI == "" {
		ctx.Error(pkerrors.NewProblem("err:request:invalid",
			pkerrors.WithPublicDetail("redirectUri is required for the same_device flow — it is the page the wallet returns the person to")))
		return
	}

	// redirectUri/webhookUrl origins must be pre-registered for the client; a
	// webhookUrl override replaces (not adds to) the client's default webhook.
	if req.RedirectURI != "" && !originAllowed(req.RedirectURI, client.AllowedOrigins) {
		ctx.Error(pkerrors.NewProblem("err:client:originNotRegistered"))
		return
	}
	webhookURL := client.DefaultWebhook
	if req.WebhookURL != "" {
		if !originAllowed(req.WebhookURL, client.AllowedOrigins) {
			ctx.Error(pkerrors.NewProblem("err:client:originNotRegistered"))
			return
		}
		webhookURL = req.WebhookURL
	}

	// A WRPRC is optional per Member State — absence is the graceful
	// registrar-reference-only fallback, never an error. Only a bool ever
	// reaches the logs — never the WRPRC bytes.
	wrprc, err := r.Registry().GetWRPRCForIntendedUse(ctx, clientID, targetIUID)
	if err != nil {
		ctx.Error(err)
		return
	}
	_ = ctx.AddLogFields(zap.Bool("wrprc_present", wrprc != nil))

	// The registration reference rides in every request the wallet receives —
	// the client's display name, its registrar-assigned identifier, the
	// registrar's URL and the intended use — so the wallet can look the relying
	// party up. Every input comes from the client's STORED registration; nothing
	// in this request can complete it. So a failure here is the same class as
	// the origin checks above: a gap in the client's configuration, named with
	// the step that closes it, never a server fault. The validator's own wording
	// says which field is unusable and never echoes a value.
	reg, err := rpcert.NewRegistrationRef(client.Name, client.ClientIdentifier, client.RegistryURI, targetIUID)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:client:registrarIdentityRequired",
			pkerrors.WithPublicDetail("the client has no usable registrar identity ("+registrationRefFault(err)+
				"); record it on the registration API with PUT /api/clients/{id}/registrar-identity, then retry")))
		return
	}

	ttl := req.TTLSeconds
	if ttl == 0 {
		ttl = int(r.Config().SessionDefaultTTL / time.Second)
	}

	// Origins go to the engine for the browser-mediated flow ONLY. They are the
	// list a DC API response's calling origin is checked against; the redirect
	// flows have no calling origin, so the engine refuses them there rather
	// than hold a restriction that is not in force.
	//
	// Keyed on the flow, never on the list being non-empty: this one registered
	// list also gates the client's redirectUri and webhookUrl targets, so its
	// contents say nothing about which flow is being created. Sending it
	// unconditionally is what made a client that registered an origin — which
	// the browser flow requires, and which same_device needs for its
	// redirectUri — unable to create a redirect-flow session at all.
	var expectedOrigins []string
	if dbFlow == "dcapi" {
		expectedOrigins = client.AllowedOrigins
	}

	// The session's own correlation id is minted HERE, not adopted from this
	// request's inbound X-Correlation-ID. That inbound header keeps riding the
	// HTTP hop-to-hop for log/trace correlation across this call — a different
	// concern from the session's own stable identity, which eudi-verifier-core
	// stores in Postgres.
	correlationID := ulid.Make().String()

	created, err := r.VC().CreateSession(ctx, &vcclient.CreateRequest{
		ClientID:        clientID,
		CorrelationID:   correlationID,
		Flow:            dbFlow,
		DCQLQuery:       rawQuery,
		Policy:          client.Policy,
		WebhookURL:      webhookURL,
		RedirectURI:     req.RedirectURI,
		Registration:    reg,
		WRPRC:           wrprc,
		ExpectedOrigins: expectedOrigins,
		TTLSeconds:      ttl,
	})
	if err != nil {
		ctx.Error(err) // already a well-formed problem; relayed intact
		return
	}

	out := api.SessionCreated{
		SessionID: created.SessionID,
		State:     "pending",
		WalletURL: created.Invocation.WalletURL,
		QRPayload: created.Invocation.QRPayload,
		ExpiresAt: created.ExpiresAt,
	}
	if len(created.Invocation.DCAPIRequest) > 0 {
		var dcAPI map[string]any
		if err := json.Unmarshal(created.Invocation.DCAPIRequest, &dcAPI); err != nil {
			// Well-formed JSON that is not an object: the engine answered, but
			// not with a request the browser can be handed. The session exists
			// upstream and will expire on its own; the caller is told the engine
			// answered unusably — the same class as an undecodable body.
			ctx.Error(vcclient.Unavailable("dc_api_request in the engine's response is not a JSON object", err))
			return
		}
		out.DCAPIRequest = dcAPI
	}
	// The engine returns a response endpoint for every flow, but only the
	// browser-mediated one needs the caller to know it — see
	// api.SessionCreated.DCAPIResponseURI. Keyed on the flow rather than on
	// the request member's presence, so the two fields cannot drift apart.
	if dbFlow == "dcapi" {
		out.DCAPIResponseURI = created.ResponseURI
	}

	// Increment only once the internal create actually succeeded (201) — flow
	// is api.FlowFromDB(dbFlow), the closed API-facing enum value
	// (same_device|cross_device|dc_api), never free text from req.Flow.
	obs.IncSessionCreated(api.FlowFromDB(dbFlow))

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(out)
}

// terminalSessionStates are the states after which a session never changes
// again — used to populate Session.completedAt. There is no dedicated
// "completed_at" column in the session schema; UpdatedAt is the timestamp of
// the transition INTO one of these states, so it is the best available proxy.
var terminalSessionStates = map[string]bool{"verified": true, "failed": true, "expired": true, "cancelled": true}

// getSession handles GET /api/v1/sessions/{sessionId}: poll for session
// state, the value-free report, and — once released — the claim-bearing
// result.
func (r *router) getSession(ctx *azugo.Context) {
	clientID, _ := ctx.UserValue("client_id").(string)
	sessionID := ctx.Params.String("sessionId")

	sess, err := r.Sessions().GetForClient(ctx, clientID, sessionID)
	if err != nil {
		ctx.Error(err) // wrong client / unknown id -> 404, no existence leak
		return
	}

	out := api.Session{
		SessionID: sess.ID,
		State:     sess.Status,
		CreatedAt: sess.CreatedAt,
	}
	if terminalSessionStates[sess.Status] {
		completedAt := sess.UpdatedAt
		out.CompletedAt = &completedAt
	}

	rawReport, err := r.Sessions().GetReportForClient(ctx, clientID, sessionID)
	if err != nil {
		ctx.Error(err)
		return
	}
	report, failure, err := results.MapReport(rawReport)
	if err != nil {
		ctx.Error(err)
		return
	}
	out.Report = report
	out.Failure = failure

	// [OID4VP §8.2] response_code: a same_device session gates `result` on a
	// successful, single-use redemption of the code from the wallet's
	// same-device redirect. Redemption is sticky — CodeRedeemedAt, once set,
	// releases the result on every later poll with no code at all — so we
	// only attempt it while not yet redeemed, and only for same_device
	// (responseCode is ignored for other flows: a cross_device/dc_api session
	// must never even touch the response_code index, so it can't accidentally
	// consume a code meant for a different same_device session).
	redeemed := sess.CodeRedeemedAt != nil
	if sess.Flow == "same_device" && !redeemed {
		if code := ctx.Query.StringOptional("responseCode"); code != nil && *code != "" {
			owner, err := r.Valkey().GetDel(ctx, r.KeyPrefix().Key(fmt.Sprintf(handoffwire.RespCodeKeyFmt, *code))).Result()
			switch {
			case err == nil && owner == sess.ID:
				if err := r.Sessions().MarkCodeRedeemed(ctx, clientID, sessionID); err != nil {
					ctx.Error(err)
					return
				}
				redeemed = true
			case err != nil && !errors.Is(err, redis.Nil):
				ctx.Error(err)
				return
			default:
				// Missing (redis.Nil), or a code that indexes a DIFFERENT
				// session (replay from elsewhere): release nothing, and
				// react identically either way — no oracle about which
				// (ARF AS-RP-51-011).
			}
		}
	}

	// `result` (claim VALUES) is released ONLY when verified AND (not
	// same_device OR redeemed). Forward-and-delete: once the Valkey payload
	// key TTLs out, results.Fetch returns a nil result — the report above
	// still stands on its own from Postgres.
	if sess.Status == "verified" && (sess.Flow != "same_device" || redeemed) {
		result, _, _, err := results.Fetch(ctx, r.Valkey(), r.KeyPrefix(), r.Keys(), sessionID)
		if err != nil {
			ctx.Error(err) // corrupt/undecryptable payload: fail closed, never an empty success
			return
		}
		out.Result = result
	}

	ctx.JSON(out)
}

// cancelSession handles DELETE /api/v1/sessions/{sessionId}: cancel a
// pending/wallet_engaged session.
//
// Ordering is deliberate: the cancel transition matrix runs FIRST and is
// authoritative/durable (pending/wallet_engaged -> cancelled; any terminal
// state -> err:session:not_cancellable 409; wrong client/unknown -> 404).
// Only once that commits do we best-effort kill the wallet-facing OID4VP
// session via eudi-verifier-core's internal API — a failure there is logged as a
// WARNING but never undoes the cancel: the Valkey OID4VP session simply TTLs
// out on its own, so the outcome fails closed either way (a cancelled
// session's engine-side state can no longer be advanced by a wallet
// regardless of whether this best-effort delete succeeded).
func (r *router) cancelSession(ctx *azugo.Context) {
	clientID, _ := ctx.UserValue("client_id").(string)
	sessionID := ctx.Params.String("sessionId")

	if err := r.Sessions().Cancel(ctx, clientID, sessionID); err != nil {
		ctx.Error(err) // cancel transition matrix: not_found (404) / not-cancellable (409)
		return
	}

	if err := r.VC().DeleteSession(ctx, sessionID); err != nil {
		// Never put a session id in a log field — the correlation id already
		// rides ctx.Log() via the correlation middleware, so no identifier
		// needs adding here.
		ctx.Log().Warn("cancelSession: best-effort internal session delete failed; cancel already committed", zap.Error(err))
	}

	ctx.StatusCode(fasthttp.StatusNoContent)
}

// isWebOrigin reports whether raw is a bare web origin — https, a host, and
// nothing else. This is the shape the browser-mediated flow compares literally
// against the origin a browser asserts, so anything else registered for a
// client can never match and is worth naming rather than letting the engine
// refuse the request without saying which entry is at fault.
//
// Deliberately a re-statement of the same rule eudi-api-registration enforces when
// an origin is written, rather than a shared helper: the two services do not
// share a module, and a check that silently drifts is worse than one restated
// where it is used.
func isWebOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != "" && u.Path == "" &&
		u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// originAllowed reports whether rawURL's origin (scheme://host, including
// any port) exactly matches one of allowed. A malformed or schemeless/hostless
// URL is never allowed — fail closed.
func originAllowed(rawURL string, allowed []string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	origin := u.Scheme + "://" + u.Host
	for _, a := range allowed {
		if strings.EqualFold(a, origin) {
			return true
		}
	}
	return false
}

// registrationRefFault reduces a registration-reference validation error to
// the clause that names the unusable field ("client id", "registry URI must be
// an absolute https URL"), dropping the validator's fixed prefix. The wording is
// the validator's own, so it cannot drift from what was rejected, and it names
// a field, never a value. If the prefix ever changes the message is merely
// longer, not wrong.
func registrationRefFault(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 && errors.Is(err, rpcert.ErrRegistrationRef) {
		return msg[i+2:]
	}
	return msg
}
