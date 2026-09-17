package eudiapimanagement

import (
	"testing"

	"github.com/go-quicktest/qt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/gmb-lib/go-platform-kit/observability"
)

// redactedLogger boots the eudi-api-management TestApp, swaps its logger for an
// observer sink, and re-applies observability.EnableRedaction against that
// sink core, so the assertion below sees exactly what a production sink would
// receive.
func redactedLogger(t *testing.T, policy *observability.RedactionPolicy) (*zap.Logger, *observer.ObservedLogs) {
	t.Helper()

	app := TestApp(t)

	core, logs := observer.New(zapcore.DebugLevel)
	qt.Assert(t, qt.IsNil(app.ReplaceLogger(zap.New(core))))
	observability.EnableRedaction(app.App, policy)

	return app.Log(), logs
}

// TestClaimValueNeverReachesSink is the ARF AS-RP-01-002 canary: every field this
// service's handoff/webhook/polling paths might one day log by mistake must
// never survive to the sink. Covers the drop keys specific to this service
// (claims via "claim" substring, credentials, result, result_jwe, vp_token)
// plus the credential-PII set shared with eudi-verifier-core.
func TestClaimValueNeverReachesSink(t *testing.T) {
	lg, logs := redactedLogger(t, RedactionPolicy())

	const canary = "CANARY-CLAIM-VALUE-77f1"
	lg.Info("webhook delivery attempt",
		zap.String("claims", canary),           // DROPPED ("claim" substring)
		zap.String("credentials", canary),      // DROPPED
		zap.String("result", canary),           // DROPPED
		zap.String("result_jwe", canary),       // DROPPED
		zap.String("vp_token", canary),         // DROPPED
		zap.String("disclosure_salt", canary),  // DROPPED (salts)
		zap.String("kb_jwt_payload", canary),   // DROPPED
		zap.String("device_signature", canary), // DROPPED
		zap.String("portrait", canary),         // DROPPED
		zap.String("biometric_template", canary),
		zap.String("document_number", canary),
		zap.String("documentNumber", canary),  // camelCase, no separator normalization
		zap.String("given_name", canary),      // MASKED (fleet default), not asserted here
		zap.String("check", "device_binding"), // kept — outcome identifiers are fine
		// Deliberately NOT "session_id": the fleet default already drops any
		// key containing "session". Use correlation_id instead.
		zap.String("correlation_id", "01JZX0S"),
	)

	qt.Assert(t, qt.Equals(logs.Len(), 1))
	entry := logs.All()[0]
	for _, f := range entry.Context {
		qt.Assert(t, qt.Not(qt.Equals(f.String, canary)),
			qt.Commentf("field %q leaked the claim value", f.Key))
	}

	found := map[string]string{}
	for _, f := range entry.Context {
		found[f.Key] = f.String
	}
	qt.Assert(t, qt.Equals(found["check"], "device_binding"))
	qt.Assert(t, qt.Equals(found["correlation_id"], "01JZX0S"))
}

// TestSessionIDFieldIsDroppedByFleetDefault documents a fleet-default gotcha: a
// literal "session_id" field is dropped by the kit's own DropKeys (substring
// "session"), not by this service's extension.
func TestSessionIDFieldIsDroppedByFleetDefault(t *testing.T) {
	lg, logs := redactedLogger(t, RedactionPolicy())

	lg.Info("session lookup", zap.String("session_id", "01JZX0S"))

	qt.Assert(t, qt.Equals(logs.Len(), 1))
	for _, f := range logs.All()[0].Context {
		qt.Assert(t, qt.Not(qt.Equals(f.Key, "session_id")),
			qt.Commentf("session_id is expected to be dropped by the fleet default policy"))
	}
}

// TestFleetDefaultsRetained: the fleet defaults must survive extension (add,
// never weaken) — RedactionPolicy() is a strict superset.
func TestFleetDefaultsRetained(t *testing.T) {
	p := RedactionPolicy()
	def := observability.DefaultRedactionPolicy()
	for _, k := range def.DropKeys {
		qt.Check(t, qt.SliceContains(p.DropKeys, k), qt.Commentf("missing fleet default drop key %q", k))
	}
	for _, k := range def.MaskKeys {
		qt.Check(t, qt.SliceContains(p.MaskKeys, k), qt.Commentf("missing fleet default mask key %q", k))
	}
}

// TestRedactionPolicyHasExpectedDropKeys pins the literal drop set so a future
// refactor that accidentally drops one of these entries fails a test, not just
// a canary log line.
func TestRedactionPolicyHasExpectedDropKeys(t *testing.T) {
	p := RedactionPolicy()
	for _, k := range []string{
		"claim", "disclosure", "salt", "vp_token", "kb_jwt", "device_signature",
		"deviceauth", "portrait", "biometric", "document_number", "documentnumber",
		"credentials", "result", "result_jwe",
	} {
		qt.Check(t, qt.SliceContains(p.DropKeys, k), qt.Commentf("expected drop key %q missing", k))
	}
}
