// Package webhook is eudi-api-management's webhook delivery subsystem: a background
// queue consumer (forward-and-delete: retries live inside the result TTL, and
// the Valkey TTL is the sole purge), detached-JWS signing, fake-clock-testable
// backoff bounded by the result TTL, and an expiry sweeper. eudi-verifier-core is
// the SOLE WRITER of the handoff queue (vc:handoff:queue /
// vc:handoff:payload:{id}, handoffwire); this package is the sole
// reader/consumer.
package webhook

import (
	"context"
	"fmt"
	"strings"

	crypto "github.com/gmb-eudi/go-eudi-crypto"

	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"
)

// SignDetached signs body with the operator webhook-signing key and returns
// the X-Payload-Signature value: a detached compact JWS per RFC 7515
// Appendix F — "<protectedB64>..<sigB64>".
//
// This detached-JWS signer is intentionally duplicated in the
// registration-portal service, whose ARF TS7 DeletionRequestEvent
// notification is signed with the exact same mechanism. The two services are
// separate Go modules with no shared importable location today, so the two
// copies must be kept in sync: mirror any change here in the other, and vice
// versa. The portal's copy parameterizes the key id rather than importing
// handoffwire; the mechanism is otherwise identical.
//
// crypto.SignJWS produces the normal compact "h.p.s" form (the signing input
// is ASCII(h) || "." || BASE64URL(body), so the signature already covers the
// body); the payload segment is then removed so the wire form carries the
// body only once (in the response body itself, not duplicated
// base64url-encoded in a header) — a receiver reattaches its own copy of the
// body before verifying.
//
// alg is derived by go-eudi-crypto from the signing key's curve (ES256 for the
// operator's P-256 key; ECCG policy) — never a caller literal: SignJWS rejects
// a caller-supplied alg/crit header outright. kid pins
// handoffwire.KeyWebhookSigning, the id clients resolve from eudi-verifier-core's
// /.well-known/verifier-jwks.json.
func SignDetached(ctx context.Context, keys crypto.KeyProvider, body []byte) (string, error) {
	compact, err := crypto.SignJWS(ctx, keys, handoffwire.KeyWebhookSigning,
		map[string]any{"kid": handoffwire.KeyWebhookSigning}, body)
	if err != nil {
		return "", fmt.Errorf("webhook: sign detached: %w", err)
	}

	header, _, sig, ok := splitCompactJWS(string(compact))
	if !ok {
		return "", fmt.Errorf("webhook: sign detached: unexpected JWS shape")
	}
	return header + ".." + sig, nil
}

// splitCompactJWS splits a compact JWS "header.payload.signature" into its
// three segments.
func splitCompactJWS(token string) (header, payload, sig string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
