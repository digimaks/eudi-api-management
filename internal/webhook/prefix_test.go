package webhook

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"

	"github.com/digimaks/eudi-api-management/internal/keyspace"
)

// The retry schedule and attempt counters land under the prefix and nowhere
// else; Due reads the prefixed schedule back.
func TestRetrierKeyPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	r := NewRetrier(rdb, 30*time.Second, 5, func() time.Time { return now }).WithKeyPrefix(keyspace.New("verifierdev"))

	qt.Assert(t, qt.IsNil(r.Schedule(context.Background(), "s1", 0, now.Add(time.Hour))))
	qt.Assert(t, qt.IsTrue(mr.Exists("verifierdev:mgmt:webhook:retry")))
	qt.Assert(t, qt.IsTrue(mr.Exists("verifierdev:mgmt:webhook:attempts:s1")))
	qt.Assert(t, qt.IsFalse(mr.Exists("mgmt:webhook:retry")))
	qt.Assert(t, qt.IsFalse(mr.Exists("mgmt:webhook:attempts:s1")))

	due, err := r.Due(context.Background(), now.Add(time.Minute))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(due, []string{"s1"}))
}

// The consumer drains the prefixed queue (what a prefixed producer writes) and
// re-enqueues under the same prefix; an unprefixed queue is not its business.
func TestConsumerDrainsPrefixedQueue(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	_, err := mr.Push("verifierdev:vc:handoff:queue", "s1")
	qt.Assert(t, qt.IsNil(err))
	_, err = mr.Push("vc:handoff:queue", "other")
	qt.Assert(t, qt.IsNil(err))

	c := &Consumer{rdb: rdb, prefix: keyspace.New("verifierdev")}
	id, err := c.rdb.RPop(context.Background(), c.prefix.Key("vc:handoff:queue")).Result()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, "s1"))
	qt.Assert(t, qt.IsFalse(mr.Exists("verifierdev:vc:handoff:queue")))
	qt.Assert(t, qt.IsTrue(mr.Exists("vc:handoff:queue")))
}
