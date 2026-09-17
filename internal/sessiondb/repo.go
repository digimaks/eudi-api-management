package sessiondb

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Fixed procedure names (see call() in db.go).
const (
	procGetSessionForClient = "session.get_session_for_client"
	procCancelSession       = "session.cancel_session"
	procGetReportForClient  = "session.get_report_for_client"
	procMarkCodeRedeemed    = "session.mark_code_redeemed"
	procSetWebhookState     = "session.set_webhook_state"
	procExpireDueSessions   = "session.expire_due_sessions"
)

// Session is a session-metadata row as projected by
// session.get_session_for_client. Structure and identifiers only — never
// verified attribute values.
type Session struct {
	ID             string     `json:"id"`
	ClientID       string     `json:"client_id"`
	CorrelationID  string     `json:"correlation_id"`
	Flow           string     `json:"flow"`   // DB enum: same_device|cross_device|dcapi
	Status         string     `json:"status"` // incl. lazy 'expired' (see get_session_for_client)
	WebhookURL     string     `json:"webhook_url"`
	RedirectURI    string     `json:"redirect_uri,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CodeRedeemedAt *time.Time `json:"code_redeemed_at,omitempty"`
	WebhookState   string     `json:"webhook_state"` // pending|delivering|delivered|failed
}

// ExpiredSession is one row of the session.expire_due_sessions sweeper batch
// (the sweeper consumes this to fire terminal-failure webhooks/alerts).
type ExpiredSession struct {
	ID            string `json:"id"`
	ClientID      string `json:"client_id"`
	WebhookURL    string `json:"webhook_url"`
	CorrelationID string `json:"correlation_id"`
}

// Store is the seam unit tests fake (fake.go) and production backs with PG
// (below). Every client-scoped method enforces isolation on the procedure
// side — cross-client access returns session:not_found (404), never a
// distinguishable 403 (no existence leak). SetWebhookState is intentionally
// NOT client-scoped: it is the internal webhook-consumer path, not
// client-facing.
type Store interface {
	GetForClient(ctx context.Context, clientID, sessionID string) (*Session, error)
	Cancel(ctx context.Context, clientID, sessionID string) error // transition matrix inside the procedure
	GetReportForClient(ctx context.Context, clientID, sessionID string) (json.RawMessage, error)
	MarkCodeRedeemed(ctx context.Context, clientID, sessionID string) error
	SetWebhookState(ctx context.Context, sessionID, state, errCode string) error // consumer-side (no client scoping: internal)
	ExpireDue(ctx context.Context, limit int) ([]ExpiredSession, error)          // sweeper
}

// PG is the production Store: it calls the session-schema client-scoped
// procedures through the pgx pool (never raw table SQL).
type PG struct{ pool *pgxpool.Pool }

// NewPG returns a PG-backed Store over pool.
func NewPG(pool *pgxpool.Pool) *PG { return &PG{pool: pool} }

// GetForClient returns the session via session.get_session_for_client
// (err:session:not_found → 404 when absent or owned by another client). A
// pending/wallet_engaged session past its expires_at is lazily flipped to
// 'expired' by the procedure before this call returns.
func (p *PG) GetForClient(ctx context.Context, clientID, sessionID string) (*Session, error) {
	data, err := call(ctx, p.pool, procGetSessionForClient, map[string]string{"id": sessionID, "client_id": clientID})
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Cancel drives the transition matrix inside session.cancel_session:
// pending/wallet_engaged -> cancelled; wrong client/unknown id ->
// session:not_found (404); any terminal state -> session:not_cancellable
// (409, via app.go's "not-cancellable" reason registration).
func (p *PG) Cancel(ctx context.Context, clientID, sessionID string) error {
	_, err := call(ctx, p.pool, procCancelSession, map[string]string{"id": sessionID, "client_id": clientID})
	return err
}

// GetReportForClient returns the newest verification report via
// session.get_report_for_client. Returns (nil, nil) — success, not an error —
// when the session legitimately has no report yet (e.g. still pending).
func (p *PG) GetReportForClient(ctx context.Context, clientID, sessionID string) (json.RawMessage, error) {
	data, err := call(ctx, p.pool, procGetReportForClient, map[string]string{"id": sessionID, "client_id": clientID})
	if err != nil {
		return nil, err
	}
	var out struct {
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.Report, nil
}

// MarkCodeRedeemed sets code_redeemed_at (idempotent, first write wins) via
// session.mark_code_redeemed, ownership-checked.
func (p *PG) MarkCodeRedeemed(ctx context.Context, clientID, sessionID string) error {
	_, err := call(ctx, p.pool, procMarkCodeRedeemed, map[string]string{"id": sessionID, "client_id": clientID})
	return err
}

// SetWebhookState updates the webhook delivery state via
// session.set_webhook_state. NOT client-scoped — the webhook consumer is the
// only caller. errCode is optional; when empty it is omitted from the call so
// the procedure clears any previously stored webhook_error (a transition to a
// non-error state has no error to keep).
func (p *PG) SetWebhookState(ctx context.Context, sessionID, state, errCode string) error {
	in := map[string]string{"id": sessionID, "state": state}
	if errCode != "" {
		in["error_code"] = errCode
	}
	_, err := call(ctx, p.pool, procSetWebhookState, in)
	return err
}

// ExpireDue returns up to limit newly-expired sessions via
// session.expire_due_sessions — the sweeper's input.
func (p *PG) ExpireDue(ctx context.Context, limit int) ([]ExpiredSession, error) {
	data, err := call(ctx, p.pool, procExpireDueSessions, map[string]int{"limit": limit})
	if err != nil {
		return nil, err
	}
	var out struct {
		Sessions []ExpiredSession `json:"sessions"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.Sessions, nil
}
