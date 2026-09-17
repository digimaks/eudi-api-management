package registrydb

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// TestParseEnvelopeUnknownResult covers parseEnvelope's default branch
// (db.go) — an envelope whose "result" field is neither "success" nor
// "error" is malformed and must error, not silently succeed with no data
// (fail-closed). Cheap pure-function coverage — no Postgres involved.
func TestParseEnvelopeUnknownResult(t *testing.T) {
	_, _, err := parseEnvelope([]byte(`{"result":"weird"}`))
	qt.Assert(t, qt.IsNotNil(err))
}

// TestFakeGetClientFoundReturnsCopy covers the found branch of GetClient
// (fake.go) — every existing repo_test.go call site only exercises the
// not-found path. Also asserts the return is an independent copy (mutating
// it must not corrupt the Fake's internal state).
func TestFakeGetClientFoundReturnsCopy(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	id, err := f.CreateClient(ctx, &Client{Name: "A", RegistryURI: "https://reg.example/a", ClientIdentifier: "sub-a", DefaultWebhook: "https://a.example/hook"})
	qt.Assert(t, qt.IsNil(err))

	got, err := f.GetClient(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.Name, "A"))

	got.Name = "mutated"
	again, err := f.GetClient(ctx, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(again.Name, "A"))
}

// TestFakeDeleteTemplateOwnerSucceeds covers the success branch of
// DeleteTemplate (fake.go) — existing repo_test.go coverage only exercises
// the cross-client rejection. A second delete of the now-soft-deleted
// template must also fail not_found (idempotent-failure, not a crash).
func TestFakeDeleteTemplateOwnerSucceeds(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	clientA := seedClientWithIntendedUse(t, f, "")
	id, err := f.CreateTemplate(ctx, clientA, &Template{Name: "t", IntendedUseID: "iu-1"})
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(f.DeleteTemplate(ctx, clientA, id)))

	_, err = f.GetTemplate(ctx, clientA, id)
	qt.Assert(t, qt.IsNotNil(err))

	err = f.DeleteTemplate(ctx, clientA, id)
	qt.Assert(t, qt.IsNotNil(err))
}

// TestFakeCreateAPIKeyDuplicatePrefixRejected covers CreateAPIKey's
// unique-prefix-violation branch (fake.go) — existing repo_test.go coverage
// only exercises the success path.
func TestFakeCreateAPIKeyDuplicatePrefixRejected(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	clientA, err := f.CreateClient(ctx, &Client{Name: "A", RegistryURI: "https://reg.example/a", ClientIdentifier: "sub-a", DefaultWebhook: "https://a.example/hook"})
	qt.Assert(t, qt.IsNil(err))

	_, err = f.CreateAPIKey(ctx, clientA, "pfx_dup", "$argon2id$fake1")
	qt.Assert(t, qt.IsNil(err))

	_, err = f.CreateAPIKey(ctx, clientA, "pfx_dup", "$argon2id$fake2")
	qt.Assert(t, qt.IsNotNil(err))
}

// TestFakeListIntendedUses covers ListIntendedUses (fake.go, previously
// 0% — only ever exercised indirectly via SetIntendedUses in other tests,
// never actually read back through ListIntendedUses itself).
func TestFakeListIntendedUses(t *testing.T) {
	f := NewFake()
	ctx := t.Context()
	clientA := seedClientWithIntendedUse(t, f, "")

	out, err := f.ListIntendedUses(ctx, clientA)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(out, 1))
	qt.Assert(t, qt.Equals(out[0].IntendedUseID, "iu-1"))

	// unknown client -> empty slice, not an error (list read, not a
	// single-resource lookup — no existence leak concern here either way).
	out, err = f.ListIntendedUses(ctx, "no-such-client")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(out, 0))
}
