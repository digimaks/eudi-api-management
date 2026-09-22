package routes

import (
	"azugo.io/azugo"
	"azugo.io/azugo/config"
	"azugo.io/azugo/middleware"

	mgmt "github.com/digimaks/eudi-api-management"
)

// Rate-limit namespaces for the two POST /api/v1/sessions dimensions.
// middleware.RateLimit namespaces its counters in the cache backend by this
// name (default "global") — the key-scoped and IP-scoped limiters below MUST
// use DISTINCT names, or they would share one counter and neither dimension
// would be enforced independently.
const (
	rateLimitNameSessionKey = "session-key"
	rateLimitNameSessionIP  = "session-ip"
)

// sessionKeyRateLimitConfig builds the fixed-window config.RateLimit for the
// per-client-id dimension of POST /api/v1/sessions. Limit and window are read
// from configuration, never hardcoded.
func sessionKeyRateLimitConfig(cfg *mgmt.Configuration) *config.RateLimit {
	return &config.RateLimit{
		Enabled:  true,
		Strategy: "fixed-window",
		Limit:    cfg.SessionRateLimitPerKey,
		Window:   cfg.SessionRateWindow,
	}
}

// sessionIPRateLimitConfig builds the fixed-window config.RateLimit for the
// per-client-IP dimension of POST /api/v1/sessions.
func sessionIPRateLimitConfig(cfg *mgmt.Configuration) *config.RateLimit {
	return &config.RateLimit{
		Enabled:  true,
		Strategy: "fixed-window",
		Limit:    cfg.SessionRateLimitPerIP,
		Window:   cfg.SessionRateWindow,
	}
}

// sessionKeyRateLimit rate-limits POST /api/v1/sessions by the authenticated
// client id. apiKeyAuth sets "client_id" via ctx.SetUserValue on success, so
// this middleware MUST run AFTER apiKeyAuth in the chain — it is nested inside
// the r.v1 group, which already carries apiKeyAuth before this sub-group is
// created.
func sessionKeyRateLimit(cfg *mgmt.Configuration) azugo.RequestHandlerFunc {
	return middleware.RateLimit(sessionKeyRateLimitConfig(cfg),
		middleware.RateLimitName(rateLimitNameSessionKey),
		middleware.RateLimitKeyGenerator(func(ctx *azugo.Context) (string, error) {
			clientID, _ := ctx.UserValue("client_id").(string)
			return "key:" + clientID, nil
		}),
	)
}

// sessionIPRateLimit rate-limits POST /api/v1/sessions by client IP
// (proxy-aware — azugo's RealIP middleware, wired by server.New, resolves
// ctx.IP() from X-Real-IP/X-Forwarded-For behind a trusted proxy).
func sessionIPRateLimit(cfg *mgmt.Configuration) azugo.RequestHandlerFunc {
	return middleware.RateLimit(sessionIPRateLimitConfig(cfg),
		middleware.RateLimitName(rateLimitNameSessionIP),
		middleware.RateLimitKeyGenerator(func(ctx *azugo.Context) (string, error) {
			return "ip:" + ctx.IP().String(), nil
		}),
	)
}
