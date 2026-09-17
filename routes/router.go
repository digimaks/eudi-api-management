// Package routes registers eudi-api-management's HTTP routes: health/readiness, the
// API-key auth boundary, and the client-facing /api/v1 surface.
package routes

import (
	"time"

	"azugo.io/azugo"

	mgmt "github.com/dativa-lv/eudi-api-management"
	"github.com/dativa-lv/eudi-api-management/internal/apikeys"
)

type router struct {
	*mgmt.App

	apiKeys *apikeys.Verifier // argon2id verify + verified-key cache

	// v1 is the /api/v1 group, auth-gated by apiKeyAuth. Every resource route
	// binds onto THIS group, not a fresh a.Group("/api/v1") — azugo's Group()
	// returns a new middleware chain per call, so re-deriving the group would
	// silently bypass auth.
	v1 azugo.Router
}

// newRouter builds the router and registers the always-on production surface:
// health/readiness and the /api/v1 group behind the API-key middleware. It is
// split out from Init so tests can attach a probe route to the same
// authenticated group the resource routes use, without duplicating this
// wiring.
func newRouter(a *mgmt.App) *router {
	r := &router{App: a, apiKeys: apikeys.NewVerifier(time.Now)}

	a.Get("/healthz", r.healthz)
	a.Get("/readyz", r.readyz)

	r.v1 = a.Group("/api/v1")
	r.v1.Use(r.apiKeyAuth)

	// POST /sessions (session creation only) carries two stacked rate limiters
	// — per authenticated client id and per client IP — that no other route
	// under /api/v1 has. Bound to a dedicated sub-group holding ONLY this route
	// so GET/DELETE sessions and the template routes stay unlimited. The
	// sub-group inherits r.v1's already-registered apiKeyAuth middleware
	// (RouteGroup.Group copies the parent's middleware chain), so the client id
	// is set before the key-scoped limiter reads it.
	sessionCreate := r.v1.Group("/sessions")
	sessionCreate.Use(sessionKeyRateLimit(a.Config()), sessionIPRateLimit(a.Config()))
	sessionCreate.Post("", r.createSession)

	r.v1.Get("/sessions/{sessionId}", r.getSession)
	r.v1.Delete("/sessions/{sessionId}", r.cancelSession)

	r.v1.Get("/templates", r.listTemplates)
	r.v1.Post("/templates", r.createTemplate)
	r.v1.Get("/templates/{templateId}", r.getTemplate)
	r.v1.Delete("/templates/{templateId}", r.deleteTemplate)

	return r
}

// Init registers the public surface. All business routes live under /api/v1
// and are bound behind the API-key middleware via router.v1.
func Init(a *mgmt.App) error {
	newRouter(a)
	return nil
}
