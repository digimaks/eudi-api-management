package eudiapimanagement

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/digimaks/eudi-api-management/internal/registrydb"
	"github.com/digimaks/eudi-api-management/internal/sessiondb"
)

// TestAppAccessors boots TestApp (New + init) and asserts every accessor that
// New/init is supposed to have populated is non-nil. It exercises app.go
// in-package, which was previously covered only through cross-package tests.
func TestAppAccessors(t *testing.T) {
	app := TestApp(t)

	qt.Assert(t, qt.IsNotNil(app.Config()))
	qt.Assert(t, qt.IsNotNil(app.DB()))
	qt.Assert(t, qt.IsNotNil(app.Valkey()))
	qt.Assert(t, qt.IsNotNil(app.Keys()))
	qt.Assert(t, qt.IsNotNil(app.Registry()))
	qt.Assert(t, qt.IsNotNil(app.Sessions()))
	qt.Assert(t, qt.IsNotNil(app.VC()))
	qt.Assert(t, qt.IsNotNil(app.TestMiniredis()))
}

// TestAppConfigPanicsWhenNotLoaded exercises Config()'s fail-closed panic
// branch: a handler calling Config() before New() has completed (or on a
// zero-value App) is a programming bug, not a runtime condition to recover
// from silently.
func TestAppConfigPanicsWhenNotLoaded(t *testing.T) {
	defer func() {
		r := recover()
		qt.Assert(t, qt.IsNotNil(r))
	}()

	a := &App{}
	a.Config()
}

// TestAppRegistryAndSessionsSeams verifies the test-only Set* seams (which let
// unit tests avoid dialing Postgres) round-trip correctly through the
// accessors.
func TestAppRegistryAndSessionsSeams(t *testing.T) {
	app := TestApp(t)

	reg := registrydb.NewFake()
	app.SetRegistry(reg)
	qt.Assert(t, qt.Equals[registrydb.Store](app.Registry(), reg))

	sess := sessiondb.NewFake()
	app.SetSessions(sess)
	qt.Assert(t, qt.Equals[sessiondb.Store](app.Sessions(), sess))
}
