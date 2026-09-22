// Package results is the forward-and-delete reader: it loads the Valkey
// handoff payload eudi-verifier-core enqueued (vc:handoff:payload:{id},
// handoffwire.PayloadKeyFmt), decrypts the result_jwe with the operator
// handoff-enc key, and maps the plaintext Result (claim VALUES) and Report
// (claim NAMES only) onto the eudi-api-management wire DTOs. It never persists a
// claim value — the decrypted buffer is zeroed before this package returns;
// the caller's response body is the only place the values ever land again.
package results

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"

	crypto "github.com/gmb-eudi/go-eudi-crypto"

	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"

	"github.com/digimaks/eudi-api-management/internal/api"
	"github.com/digimaks/eudi-api-management/internal/keyspace"
)

// Fetch loads vc:handoff:payload:{sessionID}, decrypts its result_jwe with
// the operator handoff-enc key (KeyHandoffEnc), and maps the plaintext to the
// API DTOs.
//
// Returns (nil, nil, nil, nil) — success, not an error — when the payload key
// is gone: the Valkey TTL is the forward-and-delete purge, so "key absent"
// means the result window elapsed and only the (separately, durably stored in
// Postgres) report remains. Any other failure — a malformed envelope, an
// undecryptable/corrupt JWE — is returned as an error: failing closed forbids
// ever turning a corrupt ciphertext into an empty success, which would be
// indistinguishable from "nothing to see here".
//
// prefix is the deployment key prefix (see keyspace) the producer wrote the
// payload under.
func Fetch(ctx context.Context, rdb redis.UniversalClient, prefix keyspace.Prefix, keys crypto.KeyProvider, sessionID string) (*api.VerificationResult, *api.VerificationReport, *api.Failure, error) {
	raw, err := rdb.Get(ctx, prefix.Key(fmt.Sprintf(handoffwire.PayloadKeyFmt, sessionID))).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil, nil, nil // TTL elapsed — not an error
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("results: read payload: %w", err)
	}

	var env handoffwire.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, nil, fmt.Errorf("results: malformed envelope: %w", err)
	}

	plain, _, err := crypto.DecryptJWE(ctx, keys, handoffwire.KeyHandoffEnc, []byte(env.ResultJWE))
	if err != nil {
		// Fail closed: a corrupt/undecryptable JWE is an error, never an
		// empty success.
		return nil, nil, nil, fmt.Errorf("results: decrypt result_jwe: %w", err)
	}

	var res handoffwire.Result
	unmarshalErr := json.Unmarshal(plain, &res)
	zero(plain) // the plaintext buffer's job ends here
	if unmarshalErr != nil {
		return nil, nil, nil, fmt.Errorf("results: malformed result: %w", unmarshalErr)
	}

	result := mapResult(&res)

	var report *api.VerificationReport
	var failure *api.Failure
	if res.Report != nil {
		repJSON, err := json.Marshal(res.Report)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("results: re-marshal embedded report: %w", err)
		}
		report, failure, err = MapReport(repJSON)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	return result, report, failure, nil
}

// mapResult projects a decrypted handoffwire.Result's Credentials (the sole
// value-bearing type in the handoff contract) onto the API DTO.
func mapResult(res *handoffwire.Result) *api.VerificationResult {
	out := &api.VerificationResult{Credentials: make([]api.ResultCredential, 0, len(res.Credentials))}
	for _, c := range res.Credentials {
		out.Credentials = append(out.Credentials, api.ResultCredential{
			QueryID:      c.QueryCredentialID,
			Format:       c.Format,
			DoctypeOrVCT: c.DoctypeOrVCT,
			Claims:       c.Claims,
		})
	}
	return out
}

// MapReport converts a pipeline Report JSON document — the Postgres jsonb
// session.get_report_for_client returns, or a decrypted handoff payload's
// embedded report; handoffwire.Report is the canonical decode target for
// both — into the API's VerificationReport + Failure shape.
//
// (nil, nil, nil) is returned for an empty/absent raw document: the session
// legitimately has no report yet (still pending/wallet_engaged), matching
// sessiondb.GetReportForClient's own "no report yet" contract (success, not
// error). A malformed document (present but not decodable) is an error —
// fail closed, never a silently empty report.
//
// Outcome mapping: a check's "skipped" outcome becomes "skipped_by_policy"
// (eudi-api-management.yaml VerificationReport.checks[].outcome enum). fail_code
// becomes Failure{Code}; a verified report (empty fail_code) yields a nil
// Failure. CheckResult has no source field for ReportCheck.CredentialRef, so
// it is always left empty (omitempty) — never invented.
func MapReport(raw json.RawMessage) (*api.VerificationReport, *api.Failure, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}

	var rep handoffwire.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, nil, fmt.Errorf("results: malformed report: %w", err)
	}

	out := &api.VerificationReport{Checks: make([]api.ReportCheck, 0, len(rep.Checks))}
	for _, c := range rep.Checks {
		outcome := c.Outcome
		if outcome == "skipped" {
			outcome = "skipped_by_policy"
		}
		out.Checks = append(out.Checks, api.ReportCheck{
			Check:   c.Check, // handoffwire.CheckResult.Check has wire tag "name", not "check"
			Outcome: outcome,
			Code:    c.Code,
			SpecRef: c.SpecRef,
			// CredentialRef intentionally left empty: no source field on
			// handoffwire.CheckResult.
		})
	}

	var failure *api.Failure
	if rep.FailCode != "" {
		failure = &api.Failure{Code: rep.FailCode}
	}

	return out, failure, nil
}

// zero overwrites b in place so the decrypted plaintext does not linger in
// memory beyond its one use — claim values live only in the returned DTO,
// which the handler serializes and drops.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
