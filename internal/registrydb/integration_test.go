package registrydb_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dativa-lv/eudi-api-management/internal/registrydb"

	"github.com/go-quicktest/qt"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testStore requires the compose dev stack with migrations applied
// (util -> registry -> session). It connects as management_public, the SAME
// EXECUTE-only role production uses — never the owner.
func testStore(t *testing.T) registrydb.Store {
	t.Helper()
	dsn := os.Getenv("MGMT_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set MGMT_TEST_PG_DSN (compose dev stack) for integration run")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(pool.Close)
	return registrydb.NewPG(pool)
}

func uniqueName(t *testing.T, label string) string {
	t.Helper()
	return fmt.Sprintf("%s-%s-%d", t.Name(), label, time.Now().UnixNano())
}

func TestProcedureRoundtripAndOwnershipIsolation(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	clientA := &registrydb.Client{
		Name: uniqueName(t, "client-a"), RegistryURI: "https://reg.example/a",
		ClientIdentifier: uniqueName(t, "sub-a"), DefaultWebhook: "https://a.example/hook",
	}
	_, err := store.CreateClient(ctx, clientA)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(clientA.ID), 26)) // ULID

	clientB := &registrydb.Client{
		Name: uniqueName(t, "client-b"), RegistryURI: "https://reg.example/b",
		ClientIdentifier: uniqueName(t, "sub-b"), DefaultWebhook: "https://b.example/hook",
	}
	_, err = store.CreateClient(ctx, clientB)
	qt.Assert(t, qt.IsNil(err))

	got, err := store.GetClient(ctx, clientA.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got.Name, clientA.Name))

	err = store.SetIntendedUses(ctx, clientA.ID, []registrydb.IntendedUse{
		{IntendedUseID: "iu-active", Credentials: []registrydb.RegisteredCredentialJSON{
			{Format: "mso_mdoc", DoctypesOrVCTs: []string{"eu.europa.ec.eudi.pid.1"}, AllClaims: true},
		}},
		{IntendedUseID: "iu-revoked", RevokedAt: "2026-01-01"},
	})
	qt.Assert(t, qt.IsNil(err))

	ius, err := store.ListIntendedUses(ctx, clientA.ID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(ius, 2))

	tpl := &registrydb.Template{Name: "tmpl-1", IntendedUseID: "iu-active", DCQLQuery: json.RawMessage(`{"credentials":[]}`)}
	id, err := store.CreateTemplate(ctx, clientA.ID, tpl)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, tpl.ID))

	// cross-client template access -> 404 (registry:not_found, no existence leak)
	_, err = store.GetTemplate(ctx, clientB.ID, id)
	qt.Assert(t, qt.IsNotNil(err))
	type statusCoder interface{ StatusCode() int }
	sc, ok := err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))

	// own-client read succeeds
	got2, err := store.GetTemplate(ctx, clientA.ID, id)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got2.Name, "tmpl-1"))

	// revoked intended use -> 422 at create time (before any write)
	_, err = store.CreateTemplate(ctx, clientA.ID, &registrydb.Template{
		Name: "tmpl-revoked", IntendedUseID: "iu-revoked", DCQLQuery: json.RawMessage(`{}`),
	})
	qt.Assert(t, qt.IsNotNil(err))
	sc, ok = err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 422))

	// WRPRC absent -> nil, nil (graceful fallback, not an error)
	raw, err := store.GetWRPRCForIntendedUse(ctx, clientA.ID, "iu-active")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(raw))

	// delete then re-get -> not_found
	qt.Assert(t, qt.IsNil(store.DeleteTemplate(ctx, clientA.ID, id)))
	_, err = store.GetTemplate(ctx, clientA.ID, id)
	sc, ok = err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))

	// api key lifecycle + cross-client revoke rejection
	prefix := uniqueName(t, "pfx")
	keyID, err := store.CreateAPIKey(ctx, clientA.ID, prefix, "$argon2id$fake")
	qt.Assert(t, qt.IsNil(err))
	rec, err := store.GetClientByKeyPrefix(ctx, prefix)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(rec.ClientID, clientA.ID))

	err = store.RevokeAPIKey(ctx, clientB.ID, keyID)
	sc, ok = err.(statusCoder)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(sc.StatusCode(), 404))
	qt.Assert(t, qt.IsNil(store.RevokeAPIKey(ctx, clientA.ID, keyID)))
}

func TestUnknownClientNotFound(t *testing.T) {
	store := testStore(t)
	_, err := store.GetClient(context.Background(), "01JZXNOSUCHCLIENT00000000")
	qt.Assert(t, qt.IsNotNil(err))
}

// Role-leak test: management_public has NO table access.
func TestRoleLeakDirectTableAccessFails(t *testing.T) {
	dsn := os.Getenv("MGMT_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set MGMT_TEST_PG_DSN (compose dev stack) for integration run")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(pool.Close)

	_, err = pool.Exec(context.Background(), "select * from registry.client limit 1")
	qt.Assert(t, qt.ErrorMatches(err, ".*permission denied.*"))
	_, err = pool.Exec(context.Background(),
		"insert into registry.client (name, registry_uri, client_identifier, default_webhook_url) values ('x','x','x','x')")
	qt.Assert(t, qt.ErrorMatches(err, ".*permission denied.*"))
	_, err = pool.Exec(context.Background(), "select * from session.session limit 1")
	qt.Assert(t, qt.ErrorMatches(err, ".*permission denied.*"))
}
