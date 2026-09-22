package sessiondb

import (
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

// TestParseEnvelopeUnknownResult covers parseEnvelope's default branch
// (db.go) — fail-closed on a malformed envelope whose "result" is neither
// "success" nor "error". Cheap pure-function coverage — no Postgres involved.
func TestParseEnvelopeUnknownResult(t *testing.T) {
	_, _, err := parseEnvelope([]byte(`{"result":"weird"}`))
	qt.Assert(t, qt.IsNotNil(err))
}

// TestFakeSetClockOverridesLazyExpiry covers SetClock (fake.go, previously
// 0% within this package — only ever called cross-package from
// internal/webhook's sweeper/consumer tests, which don't count toward
// sessiondb's own coverage). Proves the injected clock, not time.Now, drives
// lazy expiry.
func TestFakeSetClockOverridesLazyExpiry(t *testing.T) {
	f := NewFake()
	ctx := t.Context()

	fixed := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	f.SetClock(func() time.Time { return fixed })

	// Seeded relative to the FAKE clock, not wall time: expired one tick
	// after "now", but the fake clock is frozen at `fixed` for the whole
	// test — so this session is already past its expiry the instant it's
	// read, deterministically, regardless of real wall-clock time.
	f.Seed(Session{ID: "s1", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: fixed.Add(-time.Second)})

	got, err := f.GetForClient(ctx, "client-a", "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.Status, "expired"))
	qt.Assert(t, qt.IsTrue(got.UpdatedAt.Equal(fixed)))
}

// TestFakeLastWebhookErrCode covers LastWebhookErrCode (fake.go, previously
// 0% within this package for the same cross-package reason as SetClock —
// internal/webhook's consumer tests are the only callers today).
func TestFakeLastWebhookErrCode(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	f.Seed(Session{ID: "s1", ClientID: "client-a", Status: "pending",
		WebhookURL: "https://a.example/hook", ExpiresAt: time.Now().Add(time.Hour)})

	// never called yet -> ""
	qt.Assert(t, qt.Equals(f.LastWebhookErrCode("s1"), ""))

	qt.Assert(t, qt.IsNil(f.SetWebhookState(ctx, "s1", "failed", "err:webhook:deliveryFailed")))
	qt.Assert(t, qt.Equals(f.LastWebhookErrCode("s1"), "err:webhook:deliveryFailed"))

	// a later transition with no code clears it (not stale from the last call)
	qt.Assert(t, qt.IsNil(f.SetWebhookState(ctx, "s1", "delivering", "")))
	qt.Assert(t, qt.Equals(f.LastWebhookErrCode("s1"), ""))
}
