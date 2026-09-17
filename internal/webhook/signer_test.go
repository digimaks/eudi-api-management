package webhook

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"

	crypto "github.com/gmb-eudi/go-eudi-crypto"

	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"
)

// testSigningKeys builds an in-memory KeyProvider carrying only the
// webhook-signing key (crypto.NewStaticProvider — no filesystem, no cycle
// back to the eudiapimanagement package that will wire this package in app.go).
func testSigningKeys(t *testing.T) (crypto.KeyProvider, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	kp := crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{handoffwire.KeyWebhookSigning: key})
	return kp, key
}

// reattach turns the RFC 7515 Appendix F detached form "h..s" back into a
// verifiable compact JWS "h.<payload>.s" — VerifyJWS only accepts compact
// serialization, so the test supplies the payload segment the wire form
// deliberately omits (the receiver does the same: it holds the exact body
// bytes and re-attaches them before verifying).
func reattach(t *testing.T, detached string, body []byte) []byte {
	t.Helper()
	parts := strings.Split(detached, ".")
	qt.Assert(t, qt.Equals(len(parts), 3), qt.Commentf("detached JWS must have 3 dot-separated segments, got %q", detached))
	qt.Assert(t, qt.Equals(parts[1], ""), qt.Commentf("payload segment must be empty in the detached form"))
	payload := base64.RawURLEncoding.EncodeToString(body)
	return []byte(parts[0] + "." + payload + "." + parts[2])
}

// TestSignDetached_VerifiesAgainstPublicHalf checks that a delivered
// signature verifies against the public half published as JWKS. The public
// half is read exactly as routes/jwks.go publishes it (KeyProvider.Public);
// this test verifies the detached JWS carries a header (kid + library-chosen
// alg) and a signature that VerifyJWS accepts once the payload segment is
// reattached.
func TestSignDetached_VerifiesAgainstPublicHalf(t *testing.T) {
	ctx := context.Background()
	keys, _ := testSigningKeys(t)
	body := []byte(`{"sessionId":"sess-1","state":"verified"}`)

	detached, err := SignDetached(ctx, keys, body)
	qt.Assert(t, qt.IsNil(err))

	pub, err := keys.Public(ctx, handoffwire.KeyWebhookSigning)
	qt.Assert(t, qt.IsNil(err))

	payload, hdr, err := crypto.VerifyJWS(reattach(t, detached, body), pub)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(payload, body))
	qt.Check(t, qt.Equals(hdr["kid"], handoffwire.KeyWebhookSigning))
	qt.Check(t, qt.Equals(hdr["alg"], "ES256")) // library-chosen for a P-256 key (ECCG policy) — never a caller literal
}

// TestSignDetached_PayloadSegmentIsEmpty pins the RFC 7515 Appendix F wire
// shape byte-for-byte: "h..s" — the payload segment between the two dots is
// always empty (removed), never re-derived by the caller.
func TestSignDetached_PayloadSegmentIsEmpty(t *testing.T) {
	ctx := context.Background()
	keys, _ := testSigningKeys(t)

	detached, err := SignDetached(ctx, keys, []byte("body"))
	qt.Assert(t, qt.IsNil(err))
	parts := strings.Split(detached, ".")
	qt.Assert(t, qt.Equals(len(parts), 3))
	qt.Check(t, qt.Equals(parts[1], ""))
	qt.Check(t, qt.IsTrue(len(parts[0]) > 0))
	qt.Check(t, qt.IsTrue(len(parts[2]) > 0))
}

// TestSignDetached_TamperedBodyFailsVerification: the signature covers
// BASE64URL(body) as part of the JWS signing input, so re-attaching a
// DIFFERENT body than the one actually signed must fail verification — this
// is what lets a receiver detect a body tampered with in transit.
func TestSignDetached_TamperedBodyFailsVerification(t *testing.T) {
	ctx := context.Background()
	keys, _ := testSigningKeys(t)
	body := []byte(`{"sessionId":"sess-1","state":"verified"}`)

	detached, err := SignDetached(ctx, keys, body)
	qt.Assert(t, qt.IsNil(err))

	pub, err := keys.Public(ctx, handoffwire.KeyWebhookSigning)
	qt.Assert(t, qt.IsNil(err))

	tampered := append(append([]byte{}, body...), 'X')
	_, _, err = crypto.VerifyJWS(reattach(t, detached, tampered), pub)
	qt.Assert(t, qt.IsNotNil(err))
}
