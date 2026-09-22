package results

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"

	crypto "github.com/gmb-eudi/go-eudi-crypto"

	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"
)

// testKeys builds an in-memory KeyProvider carrying only the handoff-enc key
// (crypto.NewStaticProvider — no filesystem). NOTE: this package must not
// import the parent eudiapimanagement package from a test file even indirectly:
// eudiapimanagement imports internal/webhook, which imports this package for
// MapReport, so a results_test.go -> eudiapimanagement import would be a cycle in
// the results package's own test build. Same in-memory key technique
// internal/webhook's tests use.
func testKeys(t *testing.T) crypto.KeyProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	return crypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{handoffwire.KeyHandoffEnc: key})
}

func testRedis(t *testing.T) redis.UniversalClient {
	t.Helper()
	mr := miniredis.RunT(t)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// seedEnvelope encrypts result exactly as eudi-verifier-core's handoff producer
// does (crypto.EncryptJWE(pub, nil, plain) — nil protected header) and writes
// the resulting Envelope under vc:handoff:payload:{sessionID}.
func seedEnvelope(ctx context.Context, t *testing.T, rdb redis.UniversalClient, keys crypto.KeyProvider, sessionID string, result handoffwire.Result) {
	t.Helper()
	plain, err := json.Marshal(result)
	qt.Assert(t, qt.IsNil(err))
	pub, err := keys.Public(ctx, handoffwire.KeyHandoffEnc)
	qt.Assert(t, qt.IsNil(err))
	jwe, err := crypto.EncryptJWE(pub, nil, plain)
	qt.Assert(t, qt.IsNil(err))
	setEnvelope(ctx, t, rdb, sessionID, handoffwire.Envelope{
		Version: 1, SessionID: sessionID, ResultJWE: string(jwe),
		EnqueuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
}

func setEnvelope(ctx context.Context, t *testing.T, rdb redis.UniversalClient, sessionID string, env handoffwire.Envelope) {
	t.Helper()
	envJSON, err := json.Marshal(env)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(rdb.Set(ctx, fmt.Sprintf(handoffwire.PayloadKeyFmt, sessionID), envJSON, time.Hour).Err()))
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	qt.Assert(t, qt.IsNil(err))
	return b
}

// TestFetch_DecryptsAndMapsCredentialsAndReport is the happy path: an
// envelope whose result_jwe decrypts to a Result carrying both claim VALUES
// (Credentials) and the value-free embedded Report.
func TestFetch_DecryptsAndMapsCredentialsAndReport(t *testing.T) {
	ctx := context.Background()
	rdb := testRedis(t)
	keys := testKeys(t)

	result := handoffwire.Result{
		SessionID: "sess-1",
		Outcome:   "verified",
		Report: &handoffwire.Report{
			SessionID: "sess-1",
			Outcome:   "verified",
			Checks:    []handoffwire.CheckResult{{Check: "parse", Outcome: "pass", SpecRef: "OID4VP §8"}},
			Policy:    map[string]bool{},
		},
		Credentials: []handoffwire.ResultCredential{
			{
				QueryCredentialID: "cred1",
				Format:            "mso_mdoc",
				DoctypeOrVCT:      "org.iso.18013.5.1.mDL",
				Claims:            map[string]any{"given_name": "Alice"},
			},
		},
	}
	seedEnvelope(ctx, t, rdb, keys, "sess-1", result)

	res, report, failure, err := Fetch(ctx, rdb, "", keys, "sess-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(res))
	qt.Assert(t, qt.Equals(len(res.Credentials), 1))
	qt.Check(t, qt.Equals(res.Credentials[0].QueryID, "cred1"))
	qt.Check(t, qt.Equals(res.Credentials[0].Format, "mso_mdoc"))
	qt.Check(t, qt.DeepEquals(res.Credentials[0].Claims, map[string]any{"given_name": "Alice"}))
	qt.Assert(t, qt.IsNotNil(report))
	qt.Assert(t, qt.Equals(len(report.Checks), 1))
	qt.Check(t, qt.Equals(report.Checks[0].Check, "parse"))
	qt.Check(t, qt.Equals(report.Checks[0].Outcome, "pass"))
	qt.Check(t, qt.IsNil(failure))
}

// TestFetch_MissingKey_AllNil is the forward-and-delete case: once the Valkey
// payload TTLs out, Fetch returns four nils (success, not error) — the report
// survives independently in Postgres (GetReportForClient), and this is the
// "result is gone" signal the GET handler relies on.
func TestFetch_MissingKey_AllNil(t *testing.T) {
	ctx := context.Background()
	rdb := testRedis(t)
	keys := testKeys(t)

	res, report, failure, err := Fetch(ctx, rdb, "", keys, "does-not-exist")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(res))
	qt.Check(t, qt.IsNil(report))
	qt.Check(t, qt.IsNil(failure))
}

// TestFetch_CorruptJWE_FailsClosed: a payload whose result_jwe cannot be
// decrypted must be an ERROR, never an empty success — a corrupt/undecryptable
// ciphertext must not silently look like "no result yet"/"TTL'd out".
func TestFetch_CorruptJWE_FailsClosed(t *testing.T) {
	ctx := context.Background()
	rdb := testRedis(t)
	keys := testKeys(t)

	setEnvelope(ctx, t, rdb, "sess-2", handoffwire.Envelope{
		Version: 1, SessionID: "sess-2", ResultJWE: "not-a-valid-jwe",
	})

	res, report, failure, err := Fetch(ctx, rdb, "", keys, "sess-2")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsNil(res))
	qt.Check(t, qt.IsNil(report))
	qt.Check(t, qt.IsNil(failure))
}

// TestFetch_MalformedEnvelopeJSON_FailsClosed: the stored value at the
// payload key is not even a JSON envelope — also an error, not empty success.
func TestFetch_MalformedEnvelopeJSON_FailsClosed(t *testing.T) {
	ctx := context.Background()
	rdb := testRedis(t)
	keys := testKeys(t)

	qt.Assert(t, qt.IsNil(rdb.Set(ctx, fmt.Sprintf(handoffwire.PayloadKeyFmt, "sess-3"), []byte("{not json"), time.Hour).Err()))

	_, _, _, err := Fetch(ctx, rdb, "", keys, "sess-3")
	qt.Assert(t, qt.IsNotNil(err))
}

// TestMapReport_OutcomeMapping is the table test pinning: "skipped" ->
// "skipped_by_policy" (YAML enum), fail_code -> Failure{Code}, and every
// CheckResult field carried through (Check comes from the "name" wire tag,
// not "check" — handoffwire's documented trap; CredentialRef has no source
// in CheckResult and must stay empty, never invented).
func TestMapReport_OutcomeMapping(t *testing.T) {
	raw := mustJSON(t, handoffwire.Report{
		SessionID: "sess-4",
		Outcome:   "failed",
		FailCode:  "err:oid4vp:device-binding-failed",
		Checks: []handoffwire.CheckResult{
			{Check: "parse", Outcome: "pass", SpecRef: "OID4VP §8"},
			{Check: "device_binding", Outcome: "fail", Code: "err:oid4vp:device-binding-failed", SpecRef: "ARF §6.6.3.7"},
			{Check: "revocation", Outcome: "skipped", Code: "policy:revocation-disabled"},
		},
		Policy: map[string]bool{"revocation_check": false},
	})

	report, failure, err := MapReport(raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(report))
	qt.Assert(t, qt.Equals(len(report.Checks), 3))

	qt.Check(t, qt.Equals(report.Checks[0].Check, "parse"))
	qt.Check(t, qt.Equals(report.Checks[0].Outcome, "pass"))
	qt.Check(t, qt.Equals(report.Checks[0].CredentialRef, ""))

	qt.Check(t, qt.Equals(report.Checks[1].Check, "device_binding"))
	qt.Check(t, qt.Equals(report.Checks[1].Outcome, "fail"))
	qt.Check(t, qt.Equals(report.Checks[1].Code, "err:oid4vp:device-binding-failed"))
	qt.Check(t, qt.Equals(report.Checks[1].SpecRef, "ARF §6.6.3.7"))

	qt.Check(t, qt.Equals(report.Checks[2].Check, "revocation"))
	qt.Check(t, qt.Equals(report.Checks[2].Outcome, "skipped_by_policy"))

	qt.Assert(t, qt.IsNotNil(failure))
	qt.Check(t, qt.Equals(failure.Code, "err:oid4vp:device-binding-failed"))
}

// TestMapReport_VerifiedHasNoFailure: a verified report (empty fail_code)
// must not synthesize a Failure.
func TestMapReport_VerifiedHasNoFailure(t *testing.T) {
	raw := mustJSON(t, handoffwire.Report{
		SessionID: "sess-5",
		Outcome:   "verified",
		Checks:    []handoffwire.CheckResult{{Check: "parse", Outcome: "pass"}},
		Policy:    map[string]bool{},
	})

	report, failure, err := MapReport(raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(failure))
	qt.Assert(t, qt.IsNotNil(report))
	qt.Check(t, qt.Equals(report.Checks[0].Outcome, "pass"))
}

// TestMapReport_EmptyRaw mirrors sessiondb.GetReportForClient's "no report
// yet" contract: (nil, nil) is success, not an error.
func TestMapReport_EmptyRaw(t *testing.T) {
	report, failure, err := MapReport(nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(report))
	qt.Check(t, qt.IsNil(failure))
}

// TestMapReport_Malformed_FailsClosed: not valid JSON is an error, never an
// empty/success report.
func TestMapReport_Malformed_FailsClosed(t *testing.T) {
	_, _, err := MapReport(json.RawMessage(`{not json`))
	qt.Assert(t, qt.IsNotNil(err))
}
