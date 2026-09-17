package webhook

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"azugo.io/core"

	"github.com/dativa-lv/eudi-api-management/internal/api"
	"github.com/dativa-lv/eudi-api-management/internal/results"
	"github.com/dativa-lv/eudi-api-management/internal/sessiondb"
)

// Sweeper polls sessiondb.Store.ExpireDue and delivers a signed
// {state:"expired"} WebhookPayload for each newly-expired session — the
// WebhookPayload state enum includes "expired", and this is the ONLY code
// path that ever produces it: a session that never completes has no handoff
// envelope, so nothing else notifies the client.
type Sweeper struct {
	log       *zap.Logger
	db        sessiondb.Store
	deliverer *Deliverer
	limit     int
	interval  time.Duration

	ticker   *time.Ticker
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewSweeper builds the expiry-notification core.Tasker (wired via a.AddTask
// in app.go). Production runs this on a 30s interval.
func NewSweeper(log *zap.Logger, db sessiondb.Store, d *Deliverer, limit int, interval time.Duration) core.Tasker {
	return &Sweeper{log: log, db: db, deliverer: d, limit: limit, interval: interval}
}

// Name implements core.Tasker.
func (s *Sweeper) Name() string { return "webhook-sweeper" }

// Start implements core.Tasker: runs one cycle immediately, then on every
// tick — same ticker-task shape as Consumer.Start.
func (s *Sweeper) Start(ctx context.Context) error {
	s.stopCh = make(chan struct{})
	s.ticker = time.NewTicker(s.interval)
	go func() {
		s.runOnce(ctx)
		for {
			select {
			case <-s.stopCh:
				return
			case <-s.ticker.C:
				s.runOnce(ctx)
			}
		}
	}()
	return nil
}

// Stop implements core.Tasker. Safe to call more than once.
func (s *Sweeper) Stop() {
	s.stopOnce.Do(func() {
		if s.ticker != nil {
			s.ticker.Stop()
		}
		close(s.stopCh)
	})
}

func (s *Sweeper) runOnce(ctx context.Context) {
	expired, err := s.db.ExpireDue(ctx, s.limit)
	if err != nil {
		s.log.Error("webhook: expire-due sweep failed", zap.Error(err))
		return
	}
	for _, exp := range expired {
		s.notify(ctx, exp)
	}
}

// notify delivers the expired-session payload. Best-effort: a session already
// terminal (expired) has no further webhook_state to transition, and retrying
// beyond the (already-elapsed) result TTL is not allowed, so a delivery
// failure here is logged, not retried.
func (s *Sweeper) notify(ctx context.Context, exp sessiondb.ExpiredSession) {
	// Poll-only session (no webhook registered): nothing to notify on expiry.
	// The client learns of the timeout by polling GET /sessions/{id}.
	if exp.WebhookURL == "" {
		return
	}

	payload := &api.WebhookPayload{SessionID: exp.ID, State: "expired"}

	raw, err := s.db.GetReportForClient(ctx, exp.ClientID, exp.ID)
	if err != nil {
		s.log.Error("webhook: read report for expired session failed", zap.Error(err))
	} else if len(raw) > 0 {
		report, failure, merr := results.MapReport(raw)
		if merr != nil {
			s.log.Error("webhook: malformed report for expired session", zap.Error(merr))
		} else {
			payload.Report = report
			payload.Failure = failure
		}
	}

	if err := s.deliverer.DeliverPayload(ctx, exp.WebhookURL, exp.CorrelationID, payload); err != nil {
		s.log.Error("webhook: expired-session notification failed", zap.Error(err))
	}
}
