// Package obs is eudi-api-management's observability delta: the metric NAME
// constants + thin helper funcs for the service's own counters, mirroring
// eudi-verifier-core's metrics idiom. Every label value here comes from a CLOSED
// set — the API flow enum (same_device|cross_device|dc_api) or the webhook
// delivery outcome enum (delivered|failed) — never a session id, a client id,
// a claim path/value, or anything else derived from wallet/client input.
package obs

import (
	"github.com/gmb-lib/go-platform-kit/observability"
)

const (
	// MetricSessionsCreatedTotal counts successful (201) POST /sessions,
	// labeled by the API flow value actually used (routes.createSession
	// calls IncSessionCreated with api.FlowFromDB(dbFlow), which normalizes
	// the DB enum back onto eudi-api-management.yaml's
	// same_device|cross_device|dc_api).
	MetricSessionsCreatedTotal = "management_api_sessions_created_total"

	// MetricScopeDenialsTotal counts requests rejected for scope-exceeded
	// (the *scope.ScopeError branch) in BOTH routes.createSession and
	// routes.createTemplate. No labels — cardinality-free by construction;
	// never a claim path/value (see internal/scope's own doc comment on why
	// ScopeError.Offending is safe to log but is still never placed in a
	// metric label).
	MetricScopeDenialsTotal = "management_api_scope_denials_total"

	// MetricWebhookDeliveryTotal counts webhook delivery outcomes
	// ({outcome="delivered"|"failed"}) — the "terminal failure => alert"
	// signal. This constant is the SINGLE SOURCE of the metric name (do not
	// duplicate the string literal); it is defined here rather than in
	// internal/webhook/consumer.go (which actually calls
	// observability.IncCounter for it) purely so every eudi-api-management metric
	// name is discoverable from one file. consumer.go re-exports this value
	// under its own MetricWebhookDeliveryTotal name so the existing call sites
	// and tests require no changes.
	MetricWebhookDeliveryTotal = "management_api_webhook_delivery_total"
)

// IncSessionCreated increments MetricSessionsCreatedTotal for one
// successfully created session, labeled by flow. Called only from
// routes.createSession's success path (after eudi-verifier-core's internal
// CreateSession call returns 201) — flow is always one of the three
// api.SessionRequest.Flow wire values by construction (the caller derives it
// via api.FlowFromDB(dbFlow), and dbFlow was already validated by
// api.FlowToDB earlier in the handler), never free text from the request.
func IncSessionCreated(flow string) {
	observability.IncCounter(MetricSessionsCreatedTotal, map[string]string{"flow": flow})
}

// IncScopeDenial increments MetricScopeDenialsTotal. No labels — never a
// claim path/value or any other request-derived data.
func IncScopeDenial() {
	observability.IncCounter(MetricScopeDenialsTotal, nil)
}
