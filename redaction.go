package eudiapimanagement

import "github.com/gmb-lib/go-platform-kit/observability"

// RedactionPolicy extends the fleet default for the one service besides
// eudi-verifier-core that handles verified attribute VALUES in memory (webhook and
// polling paths, from the decrypted handoff result envelope). Claim values
// must never reach logs, traces, or error messages (ARF AS-RP-01-002). It carries
// eudi-verifier-core's full credential-PII drop set (so the same attribute fields
// are redacted wherever they surface) PLUS this service's handoff
// result-envelope keys. It is additive-only over
// observability.DefaultRedactionPolicy: add, never weaken. Extend this list
// BEFORE logging any new struct.
//
// Matching is case-insensitive SUBSTRING on top-level field keys, with NO
// separator normalization — so "claim" catches "claims"/"claim_value" but a
// camelCase "documentNumber" needs its own "documentnumber" entry. Matching is
// top-level-key only: NEVER log a nested map/struct of claims via
// zap.Any/zap.Reflect — the redacting core cannot see inside it, so sensitive
// keys within would bypass this policy entirely. Log individual scalar fields
// instead.
//
// Gotcha (shared with eudi-verifier-core): the fleet default already drops the
// substring "session", so a literal "session_id" log field is silently
// dropped. Identify a session in logs via "correlation_id" instead (bound
// automatically by go-platform-kit/correlation's middleware).
func RedactionPolicy() *observability.RedactionPolicy {
	p := observability.DefaultRedactionPolicy()
	p.DropKeys = append(p.DropKeys,
		// credential attribute values — the same set eudi-verifier-core redacts
		"claim",            // disclosed claim values (claims, claim_value, claim_values)
		"disclosure",       // disclosure content + salts (disclosure_salt, disclosures)
		"salt",             // disclosure salts logged standalone
		"vp_token",         // raw vp_token content
		"kb_jwt",           // KB-JWT payloads (kb_jwt_payload, kb_jwt)
		"device_signature", // mdoc device signatures
		"deviceauth",       // mdoc DeviceAuth structures
		"portrait",         // portrait images (PII bytes)
		"biometric",        // biometric templates
		"document_number",  // document numbers
		"documentnumber",   // camelCase documentNumber (no separator normalization)
		// eudi-api-management handoff result envelope (decrypted verification result)
		"credentials", // result.credentials[] — claim-bearing
		"result",      // pipeline.Result / decrypted result plaintext
		"result_jwe",  // encrypted handoff payload
	)
	return p
}
