package webhook

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"
)

// testRedis boots an in-process miniredis and returns a go-redis client over
// it (no network in unit tests) plus the miniredis handle for direct
// keyspace assertions.
func testRedis(t *testing.T) (redis.UniversalClient, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, mr
}

// fakeClock is a manually-advanced clock for deterministic backoff
// assertions — a clock is injected into anything validating validity windows.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// dueScore reads back the ZSET score Schedule persisted for sessionID.
func dueScore(t *testing.T, rdb redis.UniversalClient, sessionID string) float64 {
	t.Helper()
	score, err := rdb.ZScore(context.Background(), retryZSetKey, sessionID).Result()
	qt.Assert(t, qt.IsNil(err))
	return score
}

// TestSchedule_BackoffDoublesFromBase verifies the retry schedule with a fake
// clock: 4 consecutive failures on the same session, driven with attempt=0..3
// (0-indexed: the FIRST failure passes attempt=0), must land at cumulative
// offsets t+30s, t+90s, t+210s, t+450s from a base of 30s doubling per attempt
// (base×2^attempt).
func TestSchedule_BackoffDoublesFromBase(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	base := clock.t
	expiresAt := base.Add(24 * time.Hour)

	r := NewRetrier(rdb, 30*time.Second, 100, clock.Now)

	qt.Assert(t, qt.IsNil(r.Schedule(ctx, "sess-1", 0, expiresAt)))
	qt.Check(t, qt.Equals(dueScore(t, rdb, "sess-1"), float64(base.Add(30*time.Second).Unix())))
	clock.Advance(30 * time.Second)

	qt.Assert(t, qt.IsNil(r.Schedule(ctx, "sess-1", 1, expiresAt)))
	qt.Check(t, qt.Equals(dueScore(t, rdb, "sess-1"), float64(base.Add(90*time.Second).Unix())))
	clock.Advance(60 * time.Second)

	qt.Assert(t, qt.IsNil(r.Schedule(ctx, "sess-1", 2, expiresAt)))
	qt.Check(t, qt.Equals(dueScore(t, rdb, "sess-1"), float64(base.Add(210*time.Second).Unix())))
	clock.Advance(120 * time.Second)

	qt.Assert(t, qt.IsNil(r.Schedule(ctx, "sess-1", 3, expiresAt)))
	qt.Check(t, qt.Equals(dueScore(t, rdb, "sess-1"), float64(base.Add(450*time.Second).Unix())))
}

// TestSchedule_PastExpiryReturnsErrExpired: an attempt whose next-attempt
// time would fall past env.ExpiresAt is not scheduled (retries live inside the
// result TTL) — the caller marks the session terminally failed.
func TestSchedule_PastExpiryReturnsErrExpired(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	now := time.Unix(1_700_000_000, 0)
	r := NewRetrier(rdb, 30*time.Second, 100, func() time.Time { return now })
	expiresAt := now.Add(20 * time.Second) // shorter than the 30s base delay

	err := r.Schedule(ctx, "sess-2", 0, expiresAt)
	qt.Assert(t, qt.ErrorIs(err, ErrExpired))

	_, zerr := rdb.ZScore(ctx, retryZSetKey, "sess-2").Result()
	qt.Assert(t, qt.ErrorIs(zerr, redis.Nil), qt.Commentf("a rejected schedule must not leave retry state behind"))
}

// TestSchedule_AttemptsExhaustedReturnsErrExhausted: attempt reaching
// maxAttempts is terminal independently of the TTL clamp.
func TestSchedule_AttemptsExhaustedReturnsErrExhausted(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	now := time.Unix(1_700_000_000, 0)
	r := NewRetrier(rdb, 30*time.Second, 3, func() time.Time { return now })
	expiresAt := now.Add(24 * time.Hour)

	err := r.Schedule(ctx, "sess-3", 3, expiresAt) // attempt == maxAttempts
	qt.Assert(t, qt.ErrorIs(err, ErrExhausted))
}

// TestDue_OnlyReturnsRipeMembers: a member scheduled in the future must not
// be returned before its score elapses.
func TestDue_OnlyReturnsRipeMembers(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	now := time.Unix(1_700_000_000, 0)
	r := NewRetrier(rdb, 30*time.Second, 100, func() time.Time { return now })

	qt.Assert(t, qt.IsNil(r.Schedule(ctx, "sess-future", 0, now.Add(time.Hour))))

	due, err := r.Due(ctx, now)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(due, 0))

	due, err = r.Due(ctx, now.Add(31*time.Second))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(due, []string{"sess-future"}))
}

// TestDue_ConcurrentClaimsExactlyOneWinner is the multi-replica-safety check:
// two concurrent Due callers racing on the same ripe id must claim it exactly
// once between them — the loser's ZRem returns 0.
func TestDue_ConcurrentClaimsExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	now := time.Unix(1_700_000_000, 0)
	r := NewRetrier(rdb, 30*time.Second, 100, func() time.Time { return now })
	qt.Assert(t, qt.IsNil(r.Schedule(ctx, "sess-race", 0, now.Add(time.Hour))))

	due := now.Add(31 * time.Second)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		claimed []string
	)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids, err := r.Due(ctx, due)
			qt.Check(t, qt.IsNil(err))
			mu.Lock()
			claimed = append(claimed, ids...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	qt.Assert(t, qt.HasLen(claimed, 1), qt.Commentf("exactly one of the two concurrent Due() callers must claim sess-race, got %v", claimed))
	qt.Check(t, qt.Equals(claimed[0], "sess-race"))
}

// TestAttempts_DefaultsToZero: a session never scheduled has an implicit
// attempt count of 0 (the very first delivery try, before any retry).
func TestAttempts_DefaultsToZero(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	r := NewRetrier(rdb, 30*time.Second, 100, time.Now)

	n, err := r.attempts(ctx, "never-scheduled")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(n, 0))
}

// TestAttempts_PersistedAcrossSchedule: Schedule persists attempt+1 so the
// next failure's caller (a different poll cycle, possibly a different
// replica) reads back the correct exponent.
func TestAttempts_PersistedAcrossSchedule(t *testing.T) {
	ctx := context.Background()
	rdb, _ := testRedis(t)
	now := time.Unix(1_700_000_000, 0)
	r := NewRetrier(rdb, 30*time.Second, 100, func() time.Time { return now })

	qt.Assert(t, qt.IsNil(r.Schedule(ctx, "sess-4", 0, now.Add(time.Hour))))
	n, err := r.attempts(ctx, "sess-4")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(n, 1))

	qt.Assert(t, qt.IsNil(r.Schedule(ctx, "sess-4", 1, now.Add(time.Hour))))
	n, err = r.attempts(ctx, "sess-4")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(n, 2))
}
