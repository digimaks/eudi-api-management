//go:build testhelpers

package eudiapimanagement

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-quicktest/qt"

	"github.com/dativa-lv/eudi-api-management/internal/registrydb"
	"github.com/dativa-lv/eudi-api-management/internal/sessiondb"
)

// WriteTestKey writes a fresh P-256 PKCS#8 PEM.
func WriteTestKey(tb testing.TB, dir, name string) string {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(tb, qt.IsNil(err))
	der, err := x509.MarshalPKCS8PrivateKey(key)
	qt.Assert(tb, qt.IsNil(err))
	path := filepath.Join(dir, name)
	qt.Assert(tb, qt.IsNil(os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)))
	return path
}

// TestApp boots the app against in-process miniredis + generated keys.
// POSTGRES_DSN points at an unreachable port; unit tests install the fake
// stores so they never dial Postgres.
func TestApp(tb testing.TB) *App {
	tb.Helper()

	mr := miniredis.RunT(tb)
	dir := tb.TempDir()

	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("SERVICE_NAME", "eudi-api-management")
	tb.Setenv("METRICS_ENABLED", "false")
	tb.Setenv("POSTGRES_DSN", "postgres://management_public:x@127.0.0.1:1/verifier")
	tb.Setenv("VALKEY_URL", "redis://"+mr.Addr())
	tb.Setenv("VERIFIER_INTERNAL_URL", "http://127.0.0.1:1")
	tb.Setenv("INTERNAL_API_TOKEN", "test-internal-token")
	tb.Setenv("HANDOFF_ENC_KEY_FILE", WriteTestKey(tb, dir, "handoff.pem"))
	tb.Setenv("WEBHOOK_SIGNING_KEY_FILE", WriteTestKey(tb, dir, "webhook.pem"))

	app, err := New(nil, "0.0.0-test")
	qt.Assert(tb, qt.IsNil(err))
	app.testRedis = mr
	app.SetRegistry(registrydb.NewFake()) // unit tests never dial Postgres
	app.SetSessions(sessiondb.NewFake())  // unit tests never dial Postgres
	tb.Cleanup(func() { app.db.Close(); _ = app.valkey.Close() })
	return app
}

// TestMiniredis exposes the backing miniredis for canary greps (e.g. purge
// tests).
func (a *App) TestMiniredis() *miniredis.Miniredis {
	mr, _ := a.testRedis.(*miniredis.Miniredis)
	return mr
}
