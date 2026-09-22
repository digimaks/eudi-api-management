package routes

import (
	"context"
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// healthz is liveness only — no dependency probing (that is /readyz). Tiny
// body, and it skips the access log.
func (r *router) healthz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	ctx.JSON(map[string]string{"status": "ok"})
}

// readyz fails closed: Postgres ping + Valkey ping. (eudi-verifier-core internal
// API reachability is intentionally NOT a readiness dependency — sessions
// degrade per-request with a 503 problem; polling/webhooks keep working.)
func (r *router) readyz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	probe, cancel := context.WithTimeout(ctx.Context(), 2*time.Second)
	defer cancel()

	degraded := map[string]string{}
	if err := r.DB().Ping(probe); err != nil {
		degraded["postgres"] = "unreachable"
	}
	if err := r.Valkey().Ping(probe).Err(); err != nil {
		degraded["valkey"] = "unreachable"
	}
	if len(degraded) > 0 {
		ctx.StatusCode(fasthttp.StatusServiceUnavailable)
		ctx.JSON(map[string]any{"status": "degraded", "components": degraded})
		return
	}
	ctx.JSON(map[string]string{"status": "ok"})
}
