package sessiondb

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

var validWebhookStates = map[string]bool{"pending": true, "delivering": true, "delivered": true, "failed": true}

// Fake is the in-memory Store for unit tests. It mirrors the client-scoped
// procedures' semantics: ownership isolation (wrong client_id ->
// session:not_found, no existence leak), the cancel transition matrix, lazy
// expiry on read, and "no report yet" as success-with-nil.
type Fake struct {
	mu          sync.Mutex
	sessions    map[string]*Session
	reports     map[string]json.RawMessage
	now         func() time.Time
	lastErrCode map[string]string // sessionID -> errCode from the most recent SetWebhookState call
}

// NewFake returns an empty in-memory Store, using time.Now as its clock.
func NewFake() *Fake {
	return &Fake{sessions: map[string]*Session{}, reports: map[string]json.RawMessage{}, now: time.Now, lastErrCode: map[string]string{}}
}

// SetClock overrides the fake's time source — test-only seam for
// deterministic lazy-expiry/sweeper assertions (inject a clock into anything
// validating validity windows).
func (f *Fake) SetClock(now func() time.Time) { f.now = now }

// Seed inserts a session row directly — test-only seam, NOT part of Store.
// Production sessions are created by eudi-verifier-core via
// session.create_session; this package's Store only reads/updates its
// client-scoped view (it is never granted EXECUTE on create_session).
func (f *Fake) Seed(s Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := s
	if cp.WebhookState == "" {
		cp.WebhookState = "pending"
	}
	f.sessions[s.ID] = &cp
}

// SeedReport stores a report for sessionID — test-only seam, NOT part of
// Store (production reports are written by eudi-verifier-core's session.save_report).
func (f *Fake) SeedReport(sessionID string, report json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports[sessionID] = append(json.RawMessage(nil), report...)
}

func (f *Fake) lazilyExpireLocked(s *Session) {
	if (s.Status == "pending" || s.Status == "wallet_engaged") && !s.ExpiresAt.IsZero() && !s.ExpiresAt.After(f.now()) {
		s.Status = "expired"
		s.UpdatedAt = f.now()
	}
}

// GetForClient returns a copy of the session scoped to clientID, lazily
// expiring it first when due, or session:not_found (404) when absent/owned
// by another client.
func (f *Fake) GetForClient(_ context.Context, clientID, sessionID string) (*Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[sessionID]
	if !ok || s.ClientID != clientID {
		return nil, resultError("session:not_found")
	}
	f.lazilyExpireLocked(s)
	cp := *s
	return &cp, nil
}

// Cancel mirrors session.cancel_session's transition matrix: only
// pending/wallet_engaged -> cancelled; wrong client/unknown id ->
// session:not_found; any terminal state -> session:not_cancellable.
func (f *Fake) Cancel(_ context.Context, clientID, sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[sessionID]
	if !ok || s.ClientID != clientID {
		return resultError("session:not_found")
	}
	f.lazilyExpireLocked(s)
	if s.Status != "pending" && s.Status != "wallet_engaged" {
		return resultError("session:not_cancellable")
	}
	s.Status = "cancelled"
	s.UpdatedAt = f.now()
	return nil
}

// GetReportForClient returns the stored report, or (nil, nil) — success, not
// an error — when the session legitimately has none yet.
func (f *Fake) GetReportForClient(_ context.Context, clientID, sessionID string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[sessionID]
	if !ok || s.ClientID != clientID {
		return nil, resultError("session:not_found")
	}
	r, ok := f.reports[sessionID]
	if !ok {
		return nil, nil
	}
	return append(json.RawMessage(nil), r...), nil
}

// MarkCodeRedeemed sets CodeRedeemedAt idempotently (first write wins),
// ownership-checked.
func (f *Fake) MarkCodeRedeemed(_ context.Context, clientID, sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[sessionID]
	if !ok || s.ClientID != clientID {
		return resultError("session:not_found")
	}
	if s.CodeRedeemedAt == nil {
		now := f.now()
		s.CodeRedeemedAt = &now
	}
	return nil
}

// SetWebhookState mirrors session.set_webhook_state: NOT client-scoped,
// validates state against the CHECK set before writing. errCode is recorded
// (not discarded) so tests can assert which terminal error code was threaded
// through — e.g. err:webhook:deliveryFailed — via LastWebhookErrCode, not
// just the state string.
func (f *Fake) SetWebhookState(_ context.Context, sessionID, state, errCode string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !validWebhookStates[state] {
		return resultError("session:invalid")
	}
	s, ok := f.sessions[sessionID]
	if !ok {
		return resultError("session:not_found")
	}
	s.WebhookState = state
	f.lastErrCode[sessionID] = errCode
	return nil
}

// LastWebhookErrCode returns the errCode argument from the most recent
// SetWebhookState call for sessionID ("" if never called, or if the last
// call passed no code — e.g. the "delivering" transition). Test-only seam,
// NOT part of Store.
func (f *Fake) LastWebhookErrCode(sessionID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastErrCode[sessionID]
}

// ExpireDue mirrors session.expire_due_sessions: flips due
// pending/wallet_engaged sessions to 'expired' and returns up to limit of
// them, in a stable (id-sorted) order for deterministic test assertions.
func (f *Fake) ExpireDue(_ context.Context, limit int) ([]ExpiredSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	ids := make([]string, 0, len(f.sessions))
	for id := range f.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := []ExpiredSession{}
	now := f.now()
	for _, id := range ids {
		if len(out) >= limit {
			break
		}
		s := f.sessions[id]
		if (s.Status == "pending" || s.Status == "wallet_engaged") && !s.ExpiresAt.IsZero() && !s.ExpiresAt.After(now) {
			s.Status = "expired"
			s.UpdatedAt = now
			out = append(out, ExpiredSession{
				ID: s.ID, ClientID: s.ClientID, WebhookURL: s.WebhookURL, CorrelationID: s.CorrelationID,
			})
		}
	}
	return out, nil
}
