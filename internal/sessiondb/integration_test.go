package sessiondb_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/digimaks/eudi-api-management/internal/sessiondb"

	"github.com/go-quicktest/qt"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testStore requires the compose dev stack with migrations applied
// (util -> registry -> session). It connects as management_public, the SAME
// EXECUTE-only role production uses. Session ROWS are seeded via the owner
// connection below because session.create_session is eudi-verifier-core-only
// (management_public has no EXECUTE on it) — this integration test proves
// that boundary too.
func testStore(t *testing.T) sessiondb.Store {
	t.Helper()
	dsn := os.Getenv("MGMT_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set MGMT_TEST_PG_DSN (compose dev stack) for integration run")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(pool.Close)
	return sessiondb.NewPG(pool)
}

// seedSession creates a session row using a connection allowed to call
// session.create_session (verifier_core_public, or the owner) —
// MGMT_TEST_SEED_PG_DSN — the same procedure eudi-verifier-core calls in
// production. Skips (not fails) when unset, since a bare management_public
// DSN can't seed rows for this test to exercise (it has no EXECUTE on
// create_session, by design).
func seedSession(t *testing.T, id, clientID string, expiresAt time.Time) {
	t.Helper()
	seedDSN := os.Getenv("MGMT_TEST_SEED_PG_DSN")
	if seedDSN == "" {
		t.Skip("set MGMT_TEST_SEED_PG_DSN (e.g. verifier_core_public's DSN) to seed sessions for this integration run")
	}
	pool, err := pgxpool.New(context.Background(), seedDSN)
	qt.Assert(t, qt.IsNil(err))
	defer pool.Close()

	var out []byte
	pi := []byte(`{"id":"` + id + `","client_id":"` + clientID + `","correlation_id":"corr-` + id +
		`","flow":"cross_device","webhook_url":"https://a.example/hook","expires_at":"` +
		expiresAt.UTC().Format(time.RFC3339) + `"}`)
	err = pool.QueryRow(context.Background(), "call session.create_session($1, $2)", pi, nil).Scan(&out)
	qt.Assert(t, qt.IsNil(err))
}

// newID returns a session id unique per run so the integration tests are
// re-runnable against a persistent DB (session.id is the PK — a fixed id
// would collide with a prior run's row on the second create_session).
func newID(label string) string {
	return label + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func TestGetForClientRoundtripAndLazyExpiry(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	clientA := newID("client-int-a")
	pendingID := newID("intpending")
	seedSession(t, pendingID, clientA, time.Now().Add(time.Hour))

	s, err := store.GetForClient(ctx, clientA, pendingID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(s.Status, "pending"))
	qt.Assert(t, qt.Equals(s.ClientID, clientA))
	qt.Assert(t, qt.IsFalse(s.ExpiresAt.IsZero()))
	qt.Assert(t, qt.IsFalse(s.CreatedAt.IsZero()))
	qt.Assert(t, qt.IsNil(s.CodeRedeemedAt))

	// cross-client -> 404
	_, err = store.GetForClient(ctx, newID("client-int-b"), pendingID)
	qt.Assert(t, qt.IsNotNil(err))
	type statusCoder interface{ StatusCode() int }
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))

	// lazy expiry
	expiredID := newID("intexpired")
	seedSession(t, expiredID, clientA, time.Now().Add(-time.Hour))
	s, err = store.GetForClient(ctx, clientA, expiredID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(s.Status, "expired"))
}

func TestCancelTransitionMatrixIntegration(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	clientA := newID("client-int-a")
	id := newID("intcancel")
	seedSession(t, id, clientA, time.Now().Add(time.Hour))

	qt.Assert(t, qt.IsNil(store.Cancel(ctx, clientA, id)))
	err := store.Cancel(ctx, clientA, id)
	qt.Assert(t, qt.IsNotNil(err))
	type statusCoder interface{ StatusCode() int }
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 409))

	// Regression: a pending session already past its expires_at is lazily
	// expired by Cancel and ends 'expired', not 'cancelled' ->
	// not_cancellable (409).
	staleID := newID("intstalepending")
	seedSession(t, staleID, clientA, time.Now().Add(-time.Minute))
	err = store.Cancel(ctx, clientA, staleID)
	qt.Assert(t, qt.IsNotNil(err))
	sc, ok = err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 409))
	got, gerr := store.GetForClient(ctx, clientA, staleID)
	qt.Assert(t, qt.IsNil(gerr))
	qt.Assert(t, qt.Equals(got.Status, "expired"))
}

func TestGetReportForClientEmptyWhenAbsent(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	clientA := newID("client-int-a")
	id := newID("intreport")
	seedSession(t, id, clientA, time.Now().Add(time.Hour))

	rep, err := store.GetReportForClient(ctx, clientA, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(rep))
}

// Role-leak coverage for this package's schema surface: management_public has
// no table access, and no EXECUTE on eudi-verifier-core's
// create_session/save_report.
func TestRoleLeakSessionTableAndProcedureAccessFails(t *testing.T) {
	dsn := os.Getenv("MGMT_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set MGMT_TEST_PG_DSN (compose dev stack) for integration run")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(pool.Close)

	_, err = pool.Exec(context.Background(), "select * from session.session limit 1")
	qt.Assert(t, qt.ErrorMatches(err, ".*permission denied.*"))

	var out []byte
	err = pool.QueryRow(context.Background(), "call session.create_session($1, $2)", []byte(`{}`), nil).Scan(&out)
	qt.Assert(t, qt.ErrorMatches(err, ".*permission denied.*"))
}
