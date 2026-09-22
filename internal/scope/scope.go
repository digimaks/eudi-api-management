// Package scope enforces that a session's (or template's) DCQL query may only
// request credentials/claims the client's registered intended use actually
// covers. It is the boundary where err:client:scopeExceeded is decided; the
// offense strings it returns carry credential positions and claim PATHS only
// — never claim values.
package scope

import (
	"encoding/json"
	"fmt"

	dcql "github.com/gmb-eudi/go-dcql"

	"github.com/digimaks/eudi-api-management/internal/registrydb"
)

// ScopeError reports that a validated DCQL query requests credentials or
// claims outside the target intended use's registered scope. Offending is
// go-dcql's own offense list (dcql.Query.WithinScope): each entry names a
// credential position/id and, for a claim violation, the claim's JSON path —
// never a value.
//
//nolint:revive // stutter is intentional — the ScopeError name is part of this package's public API
type ScopeError struct {
	Offending []string
}

// Error implements error. It never includes claim values — Offending is the
// full detail, safe to log or place in a problem detail.
func (e *ScopeError) Error() string {
	return fmt.Sprintf("scope: %d credential/claim(s) outside registered intended use", len(e.Offending))
}

// CheckWithinScope parses and validates rawQuery ([OID4VP §6] / [OID4VP §7]), converts the
// registrydb projection of the intended use identified by intendedUseID into
// go-dcql's RegisteredCredential shape, and checks the query is within that
// scope (both create-time and write-time enforcement).
//
// Callers resolve and revocation-check the target intended use BEFORE calling
// this (eudi-api-management.yaml POST /sessions; ARF TS5 intendedUseId semantics) —
// CheckWithinScope only matches intendedUseID against ius to build the
// registered-credential set; it does not re-check RevokedAt.
//
// Error cases (never a claim value in any of them):
//   - rawQuery fails to parse: wraps dcql.ErrParse.
//   - rawQuery parses but fails [OID4VP §6] / [OID4VP §7] semantic validation: wraps
//     dcql.ErrInvalid (errors.Is matches — each violation is a
//     *dcql.ValidationError).
//   - the query is syntactically/semantically valid but requests
//     credentials/claims outside the registered intended use: *ScopeError.
//
// On success it returns the parsed, validated *dcql.Query so the caller can
// forward rawQuery/q on to vcclient without re-parsing.
func CheckWithinScope(rawQuery []byte, ius []registrydb.IntendedUse, intendedUseID string) (*dcql.Query, error) {
	q, err := dcql.Parse(rawQuery)
	if err != nil {
		return nil, err
	}
	if err := q.Validate(); err != nil {
		return nil, err
	}

	registered, err := registeredCredentials(ius, intendedUseID)
	if err != nil {
		return nil, err
	}

	if ok, offenses := q.WithinScope(registered); !ok {
		return nil, &ScopeError{Offending: offenses}
	}

	return q, nil
}

// registeredCredentials finds the intended use matching intendedUseID within
// ius and converts its registrydb.RegisteredCredentialJSON projection into
// go-dcql's RegisteredCredential shape (dcql.WithinScope's input type).
func registeredCredentials(ius []registrydb.IntendedUse, intendedUseID string) ([]dcql.RegisteredCredential, error) {
	for i := range ius {
		if ius[i].IntendedUseID != intendedUseID {
			continue
		}

		creds := ius[i].Credentials
		out := make([]dcql.RegisteredCredential, 0, len(creds))
		for _, c := range creds {
			claims, err := toClaimPaths(c.Claims)
			if err != nil {
				return nil, err
			}
			out = append(out, dcql.RegisteredCredential{
				Format:         c.Format,
				DoctypesOrVCTs: c.DoctypesOrVCTs,
				AllClaims:      c.AllClaims,
				Claims:         claims,
			})
		}
		return out, nil
	}

	return nil, fmt.Errorf("scope: intended use %q not among the %d provided", intendedUseID, len(ius))
}

// toClaimPaths converts the registry's JSON claim-path projection — each
// inner []any is one [OID4VP §7] claims path pointer in its JSON array form
// (registrydb.RegisteredCredentialJSON doc comment: string | number | null)
// — into go-dcql's typed dcql.ClaimPath via dcql.NewPath/Key/Index/Wildcard.
// A JSON string is a key; a JSON number (float64 — the encoding/json default
// for a map[string]any/[]any target, or json.Number when a decoder used
// UseNumber) is a non-negative array index; a JSON null is a wildcard.
func toClaimPaths(raw [][]any) ([]dcql.ClaimPath, error) {
	out := make([]dcql.ClaimPath, 0, len(raw))
	for i, path := range raw {
		elems := make([]dcql.PathElement, 0, len(path))
		for j, e := range path {
			elem, err := toPathElement(e)
			if err != nil {
				return nil, fmt.Errorf("scope: claims[%d][%d]: %w", i, j, err)
			}
			elems = append(elems, elem)
		}
		out = append(out, dcql.NewPath(elems...))
	}
	return out, nil
}

func toPathElement(e any) (dcql.PathElement, error) {
	switch v := e.(type) {
	case nil:
		return dcql.Wildcard(), nil
	case string:
		return dcql.Key(v), nil
	case float64:
		if v < 0 {
			return dcql.PathElement{}, fmt.Errorf("negative array index %v", v)
		}
		return dcql.Index(int(v)), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil || n < 0 {
			return dcql.PathElement{}, fmt.Errorf("array index must be a non-negative integer, got %v", v)
		}
		return dcql.Index(int(n)), nil
	default:
		return dcql.PathElement{}, fmt.Errorf("unsupported path element type %T", v)
	}
}
