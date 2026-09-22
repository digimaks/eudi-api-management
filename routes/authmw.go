package routes

import (
	"errors"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"github.com/digimaks/eudi-api-management/internal/apikeys"
	"github.com/digimaks/eudi-api-management/internal/registrydb"
)

// apiKeyHeader is the HTTP header carrying the presented API key.
const apiKeyHeader = "X-API-Key" // #nosec G101 -- a header NAME, not a credential value

// unauthorized builds the single uniform 401 problem body that every failing
// branch of apiKeyAuth returns. "unauthorized" is a built-in error-taxonomy
// reason, so it always renders the same {code, title, status}: missing header,
// malformed key, unknown prefix, wrong secret, and revoked key are all
// indistinguishable on the wire (no authentication oracle). No Detail is ever
// set — a per-branch detail string would itself be the leak this exists to
// prevent. A fresh Problem is built per call so trace_id still varies per
// request; only {type, title, status, detail, code, trace_id} survive to the
// public error boundary.
func unauthorized() error { return pkerrors.NewProblem("err:client:unauthorized") }

// isNotFoundError reports whether err is the registry "not found" outcome (an
// unknown key prefix, or — defensively — any other not-found this store might
// return), as opposed to a genuine infrastructure error (DB unreachable,
// malformed envelope). The two are handled differently below: an unknown
// prefix folds into the uniform 401 bucket, while a real infrastructure
// failure is a 500. Suppressing the "which key is valid" oracle is not the
// same as disguising the service being down.
//
// The match is by STATUS CODE, not by a concrete not-found error type. When a
// domain-specific not-found reason is registered service-wide, the store's
// not-found error can be delivered as a registered problem rather than the
// built-in not-found type; a type assertion against that concrete type would
// then silently stop matching, leaking a raw 404 on an unknown key prefix
// instead of folding into the uniform 401 (a no-oracle regression). Both
// shapes implement corehttp.ResponseStatusCode, so matching on status is
// correct for either and stays robust as new problem reasons are registered.
func isNotFoundError(err error) bool {
	var sc corehttp.ResponseStatusCode
	return errors.As(err, &sc) && sc.StatusCode() == fasthttp.StatusNotFound
}

// apiKeyAuth resolves the X-API-Key header to a client identity, fail-closed:
//
//	missing/malformed/unknown/wrong-secret  → 401 (uniform body, no oracle)
//	revoked key                             → 401 (same body)
//	client not active                       → 403 err:client:notRegistered
//
// On success it sets ctx.SetUserValue("client_id", …) and adds a client_id log
// field — an identifier, safe to log; the key and secret never are.
//
// No early-exit timing oracle: Verify is called EXACTLY ONCE per request,
// unconditionally, before any success/failure branching. For a malformed key
// or an unknown prefix it is called against apikeys.DummyPHC() with the raw
// presented value standing in for the secret, so it still runs the full
// argon2id derive. Verify caches ONLY successful verdicts, so EVERY failing
// path — wrong secret on a known prefix, unknown prefix, malformed — always
// pays the full derive cost and returns the same (false-shaped) result; only a
// legitimate client with the correct secret ever hits the fast cache path.
// That is what keeps "wrong secret against a real key", "unknown prefix", and
// "malformed key" mutually timing-indistinguishable. The one path that skips
// the derive is a genuine registry infrastructure error (not attacker-
// influenced by which key was presented), which fails closed as a distinct 500
// rather than joining the 401 bucket.
func (r *router) apiKeyAuth(next azugo.RequestHandler) azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		presented := ctx.Header.Get(apiKeyHeader)
		prefix, secret, parseErr := apikeys.Parse(presented)

		keyID, phcHash, known := apikeys.DummyKeyID, apikeys.DummyPHC(), false
		var rec *registrydb.APIKeyRecord

		if parseErr != nil {
			// No secret to check against a real hash — verify the raw
			// presented value against the dummy hash instead of skipping the
			// derive entirely (see doc comment above).
			secret = presented
		} else {
			var lookupErr error
			rec, lookupErr = r.Registry().GetClientByKeyPrefix(ctx, prefix)
			switch {
			case lookupErr == nil:
				keyID, phcHash, known = rec.KeyID, rec.SecretHash, true
			case isNotFoundError(lookupErr):
				// Unknown prefix: fall through with the dummy pair and the
				// real (well-formed but unmatched) secret.
			default:
				ctx.Error(lookupErr) // registry/infra failure, not a security branch
				return
			}
		}

		ok, verifyErr := r.apiKeys.Verify(keyID, phcHash, secret)
		if verifyErr != nil || !ok || !known {
			ctx.Error(unauthorized())
			return
		}
		if rec.Revoked {
			ctx.Error(unauthorized())
			return
		}
		if rec.Status != "active" {
			ctx.Error(pkerrors.NewProblem("err:client:notRegistered"))
			return
		}

		ctx.SetUserValue("client_id", rec.ClientID)
		_ = ctx.AddLogFields(zap.String("client_id", rec.ClientID))
		next(ctx)
	}
}
