package results

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"
	"github.com/redis/go-redis/v9"

	"github.com/dativa-lv/eudi-api-management/internal/keyspace"
)

// A prefixed Fetch looks only under the prefix: an unprefixed payload for the
// same id reads as "gone" (nil result, nil error), never as that payload.
func TestFetchReadsOnlyPrefixedPayload(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	qt.Assert(t, qt.IsNil(mr.Set("vc:handoff:payload:s1", "{not for us}")))

	res, report, failure, err := Fetch(context.Background(), rdb, keyspace.New("verifierdev"), nil, "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(res))
	qt.Assert(t, qt.IsNil(report))
	qt.Assert(t, qt.IsNil(failure))
}
