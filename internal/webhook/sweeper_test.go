package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"go.uber.org/zap"

	"github.com/gmb-eudi/go-verifier-helpers/handoffwire"

	"github.com/digimaks/eudi-api-management/internal/api"
	"github.com/digimaks/eudi-api-management/internal/sessiondb"
)

// TestSweeper_ExpiredPendingSession_DeliversExpiredState seeds an expired
// pending session in the fake sessiondb, then checks the sweeper marks it
// expired and the receiver gets a signed {state:"expired"} payload — the ONLY
// way a client learns a session expired without ever completing.
func TestSweeper_ExpiredPendingSession_DeliversExpiredState(t *testing.T) {
	ctx := context.Background()
	keys, _ := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	db.SetClock(func() time.Time { return now })

	clientID := "client-sweep"
	receiver := newRecordingReceiver(t, http.StatusOK)
	db.Seed(sessiondb.Session{
		ID: "sess-expired", ClientID: clientID, Status: "pending",
		WebhookURL: receiver.srv.URL, CorrelationID: "corr-expired",
		CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute), // already due
	})

	deliverer := NewDeliverer(http.DefaultClient, keys, 5*time.Second)
	s := NewSweeper(zap.NewNop(), db, deliverer, 100, time.Second).(*Sweeper)
	s.runOnce(ctx)

	qt.Assert(t, qt.Equals(receiver.callCount(), 1))
	call := receiver.last()
	verifySignature(t, keys, call)
	qt.Check(t, qt.Equals(call.correlationID, "corr-expired"))

	var got api.WebhookPayload
	qt.Assert(t, qt.IsNil(json.Unmarshal(call.body, &got)))
	qt.Check(t, qt.Equals(got.SessionID, "sess-expired"))
	qt.Check(t, qt.Equals(got.State, "expired"))
	qt.Check(t, qt.IsNil(got.Result))

	// ExpireDue itself flips the row to 'expired' — confirms the sweeper
	// consumed the SAME batch the DB procedure/fake produced, not a stale one.
	row, err := db.GetForClient(ctx, clientID, "sess-expired")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(row.Status, "expired"))
}

// TestSweeper_ExpiredSessionWithReport_IncludesReport: when a report already
// exists for the expired session (e.g. verification finished but the
// webhook queue never got to deliver it before the row aged out), the
// sweeper attaches it to the expired notification.
func TestSweeper_ExpiredSessionWithReport_IncludesReport(t *testing.T) {
	ctx := context.Background()
	keys, _ := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	db.SetClock(func() time.Time { return now })

	clientID := "client-sweep2"
	receiver := newRecordingReceiver(t, http.StatusOK)
	db.Seed(sessiondb.Session{
		ID: "sess-expired-rep", ClientID: clientID, Status: "wallet_engaged",
		WebhookURL: receiver.srv.URL, CorrelationID: "corr-expired-rep",
		CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute),
	})
	rep := handoffwire.Report{SessionID: "sess-expired-rep", Outcome: "failed", FailCode: "err:webhook:deliveryFailed", Policy: map[string]bool{}}
	repJSON, err := json.Marshal(rep)
	qt.Assert(t, qt.IsNil(err))
	db.SeedReport("sess-expired-rep", repJSON)

	deliverer := NewDeliverer(http.DefaultClient, keys, 5*time.Second)
	s := NewSweeper(zap.NewNop(), db, deliverer, 100, time.Second).(*Sweeper)
	s.runOnce(ctx)

	qt.Assert(t, qt.Equals(receiver.callCount(), 1))
	var got api.WebhookPayload
	qt.Assert(t, qt.IsNil(json.Unmarshal(receiver.last().body, &got)))
	qt.Check(t, qt.Equals(got.State, "expired"))
	qt.Assert(t, qt.IsNotNil(got.Report))
}

// TestSweeper_NoExpiredSessions_NoDelivery: the common case — nothing due —
// must not call the webhook receiver at all.
func TestSweeper_NoExpiredSessions_NoDelivery(t *testing.T) {
	ctx := context.Background()
	keys, _ := testKeys(t)
	db := sessiondb.NewFake()
	receiver := newRecordingReceiver(t, http.StatusOK)
	deliverer := NewDeliverer(http.DefaultClient, keys, 5*time.Second)
	s := NewSweeper(zap.NewNop(), db, deliverer, 100, time.Second).(*Sweeper)
	s.runOnce(ctx)
	qt.Check(t, qt.Equals(receiver.callCount(), 0))
}

// TestSweeper_StartRunsTickerLoopAndStopHalts exercises the actual
// core.Tasker wiring (Name/Start/Stop): Start runs an immediate first cycle,
// and Stop is safe to call more than once.
func TestSweeper_StartRunsTickerLoopAndStopHalts(t *testing.T) {
	ctx := context.Background()
	keys, _ := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	db.SetClock(func() time.Time { return now })

	clientID := "client-sweep-start"
	receiver := newRecordingReceiver(t, http.StatusOK)
	db.Seed(sessiondb.Session{
		ID: "sess-expired-start", ClientID: clientID, Status: "pending",
		WebhookURL: receiver.srv.URL, CorrelationID: "corr-expired-start",
		CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute),
	})

	deliverer := NewDeliverer(http.DefaultClient, keys, 5*time.Second)
	tasker := NewSweeper(zap.NewNop(), db, deliverer, 100, 10*time.Millisecond)
	qt.Check(t, qt.Equals(tasker.Name(), "webhook-sweeper"))
	qt.Assert(t, qt.IsNil(tasker.Start(ctx)))
	t.Cleanup(tasker.Stop)

	deadline := time.Now().Add(2 * time.Second)
	for receiver.callCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	qt.Assert(t, qt.Equals(receiver.callCount(), 1))

	tasker.Stop()
	tasker.Stop() // safe to call more than once
}

// TestSweeper_PollOnlyExpiredSession_NoDelivery: a poll-only session (no
// webhook) that expires is still transitioned to 'expired' by ExpireDue, but
// the sweeper makes no delivery attempt — there is no webhook to notify; the
// client learns of the timeout by polling.
func TestSweeper_PollOnlyExpiredSession_NoDelivery(t *testing.T) {
	ctx := context.Background()
	keys, _ := testKeys(t)
	db := sessiondb.NewFake()
	now := time.Now()
	db.SetClock(func() time.Time { return now })

	clientID := "client-poll-sweep"
	receiver := newRecordingReceiver(t, http.StatusOK) // must never be called
	db.Seed(sessiondb.Session{
		ID: "sess-poll-expired", ClientID: clientID, Status: "pending",
		WebhookURL: "", CorrelationID: "corr-poll-expired", // poll-only: no webhook
		CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute),
	})

	deliverer := NewDeliverer(http.DefaultClient, keys, 5*time.Second)
	s := NewSweeper(zap.NewNop(), db, deliverer, 100, time.Second).(*Sweeper)
	s.runOnce(ctx)

	// No webhook ⇒ no delivery attempt…
	qt.Check(t, qt.Equals(receiver.callCount(), 0))

	// …but the row is still flipped to 'expired' so a poller sees the timeout.
	row, err := db.GetForClient(ctx, clientID, "sess-poll-expired")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(row.Status, "expired"))
}
