// Package sessiondb is a CLIENT-SCOPED view of the session schema. It calls
// the SECURITY DEFINER procedures via the JSONB envelope — it never touches
// session tables directly, and it is never granted EXECUTE on
// session.create_session or session.save_report (those stay
// eudi-verifier-core-only).
package sessiondb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type envelope struct {
	Result  string          `json:"result"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// resultError maps a DB envelope result code onto the HTTP error taxonomy.
// Procedures emit codes in `<domain>:<reason>` form, but FromResultCode keys
// off the `err:<domain>:<reason>` taxonomy — it needs the `err:` prefix and
// three segments to map `:not_found` → 404 (else 4xx/5xx). Bridge the two
// here so `session:not_found` surfaces as err:session:not_found (404) rather
// than an opaque 500. An empty code is not an error.
func resultError(code string) error {
	if code == "" {
		return nil
	}
	return pkerrors.FromResultCode("err:" + code)
}

func parseEnvelope(b []byte) (json.RawMessage, string, error) {
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, "", fmt.Errorf("sessiondb: malformed envelope: %w", err)
	}
	switch e.Result {
	case "success":
		return e.Data, "", nil
	case "error":
		return nil, e.Code, nil
	default:
		return nil, "", fmt.Errorf("sessiondb: unknown envelope result %q", e.Result)
	}
}

// call invokes one procedure. proc MUST be one of the fixed constants below —
// never caller input (no SQL injection surface).
func call(ctx context.Context, pool *pgxpool.Pool, proc string, in any) (json.RawMessage, error) {
	pi, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("sessiondb: marshal pi_data: %w", err)
	}
	var out []byte
	err = pool.QueryRow(ctx, "call "+proc+"($1, $2)", pi, nil).Scan(&out)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "P0001" {
			// A raised P0001 exception carries the structured envelope as its message.
			_, code, perr := parseEnvelope([]byte(pgErr.Message))
			if perr != nil {
				return nil, perr
			}
			return nil, resultError(code)
		}
		return nil, fmt.Errorf("sessiondb: %s: %w", proc, err)
	}
	data, code, err := parseEnvelope(out)
	if err != nil {
		return nil, err
	}
	if code != "" {
		return nil, resultError(code) // :not_found → 404, else 4xx/5xx
	}
	return data, nil
}
