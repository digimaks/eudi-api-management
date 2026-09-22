package webhook

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/digimaks/eudi-api-management/internal/keyspace"
)

// Valkey keys owned by this package (Consumer and Retrier are the only
// readers/writers, both here — distinct from the cross-service handoff key
// and queue contract, which lives in handoffwire).
const (
	// retryZSetKey is the due-retry schedule: member=sessionID,
	// score=next-attempt unix time.
	retryZSetKey = "mgmt:webhook:retry"
	// attemptsKeyFmt is the per-session attempt counter, TTL-bounded by the
	// time remaining until the envelope's ExpiresAt (never outlives the
	// result TTL it belongs to).
	attemptsKeyFmt = "mgmt:webhook:attempts:%s"
)

// ErrExpired and ErrExhausted are both terminal: Schedule refuses to persist
// a next attempt, so the caller (Consumer) marks the session failed
// (err:webhook:deliveryFailed) rather than retrying further. Retries live
// inside the result TTL — never longer, and never a DB fallback for the
// payload.
var (
	// ErrExpired: the computed next-attempt time would fall past
	// env.ExpiresAt.
	ErrExpired = errors.New("webhook: next retry would fall past the result TTL")
	// ErrExhausted: attempt has already reached maxAttempts.
	ErrExhausted = errors.New("webhook: retry attempts exhausted")
)

// Retrier owns the due-retry ZSET (due-claim via ZRem-returns-1 —
// multi-replica safe) and the per-session attempt counter.
type Retrier struct {
	rdb         redis.UniversalClient
	base        time.Duration
	maxAttempts int
	now         func() time.Time
	prefix      keyspace.Prefix
}

// NewRetrier builds a Retrier. base is the first backoff delay, doubled per
// attempt (base×2^attempt); maxAttempts bounds the attempt count
// independently of the env.ExpiresAt clamp; now is the injected clock, which
// keeps the backoff schedule testable with a fake clock.
func NewRetrier(rdb redis.UniversalClient, base time.Duration, maxAttempts int, now func() time.Time) *Retrier {
	if now == nil {
		now = time.Now
	}
	return &Retrier{rdb: rdb, base: base, maxAttempts: maxAttempts, now: now}
}

// WithKeyPrefix sets the deployment key prefix (see keyspace) applied to the
// retry schedule and attempt counters, and returns the Retrier for chaining.
func (r *Retrier) WithKeyPrefix(p keyspace.Prefix) *Retrier {
	r.prefix = p
	return r
}

func (r *Retrier) attemptsKey(sessionID string) string {
	return r.prefix.Key(fmt.Sprintf(attemptsKeyFmt, sessionID))
}

func (r *Retrier) zsetKey() string { return r.prefix.Key(retryZSetKey) }

// Schedule computes the next-attempt time for the attempt-th failure
// (0-indexed: the FIRST failure on a session calls Schedule with attempt=0)
// as base×2^attempt after now. It persists that time to the due-retry ZSET
// and records attempt+1 in the attempts counter so a later failure — on this
// replica or another, in this poll cycle or a later one — reads back the
// correct exponent for ITS Schedule call.
//
// Returns ErrExhausted when attempt has already reached maxAttempts, or
// ErrExpired when the computed next-attempt time would fall past expiresAt.
// In either terminal case nothing is written — the caller marks the session
// failed instead of leaving stale retry state behind.
func (r *Retrier) Schedule(ctx context.Context, sessionID string, attempt int, expiresAt time.Time) error {
	if attempt >= r.maxAttempts {
		return ErrExhausted
	}

	now := r.now()
	delay := r.base * time.Duration(int64(1)<<uint(attempt)) //nolint:gosec // attempt is bounded by maxAttempts, never large enough to overflow the shift
	next := now.Add(delay)
	if next.After(expiresAt) {
		return ErrExpired
	}
	ttl := expiresAt.Sub(now)
	if ttl <= 0 {
		return ErrExpired
	}

	if err := r.rdb.Set(ctx, r.attemptsKey(sessionID), attempt+1, ttl).Err(); err != nil {
		return fmt.Errorf("webhook: persist attempt counter: %w", err)
	}
	if err := r.rdb.ZAdd(ctx, r.zsetKey(), redis.Z{Score: float64(next.Unix()), Member: sessionID}).Err(); err != nil {
		return fmt.Errorf("webhook: schedule retry: %w", err)
	}
	return nil
}

// Due returns the sessionIDs whose scheduled retry time is <= now, claiming
// each via ZRem so that of any two concurrent callers racing on the same id,
// exactly one wins: ZRem returns 1 for the winner and 0 for the loser
// (multi-replica safe — no distributed lock needed).
func (r *Retrier) Due(ctx context.Context, now time.Time) ([]string, error) {
	ids, err := r.rdb.ZRangeByScore(ctx, r.zsetKey(), &redis.ZRangeBy{
		Min: "-inf",
		Max: strconv.FormatInt(now.Unix(), 10),
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("webhook: query due retries: %w", err)
	}

	claimed := make([]string, 0, len(ids))
	for _, id := range ids {
		n, err := r.rdb.ZRem(ctx, r.zsetKey(), id).Result()
		if err != nil {
			return nil, fmt.Errorf("webhook: claim due retry: %w", err)
		}
		if n == 1 {
			claimed = append(claimed, id)
		}
	}
	return claimed, nil
}

// attempts returns the persisted attempt count for sessionID, or 0 if it has
// never been scheduled (the very first delivery try, before any failure).
func (r *Retrier) attempts(ctx context.Context, sessionID string) (int, error) {
	n, err := r.rdb.Get(ctx, r.attemptsKey(sessionID)).Int()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("webhook: read attempt counter: %w", err)
	}
	return n, nil
}
