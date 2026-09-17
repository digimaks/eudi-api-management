package keyspace_test

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/dativa-lv/eudi-api-management/internal/keyspace"
)

func TestNewNormalizes(t *testing.T) {
	qt.Assert(t, qt.Equals(keyspace.New(""), keyspace.Prefix("")))
	qt.Assert(t, qt.Equals(keyspace.New("  "), keyspace.Prefix("")))
	qt.Assert(t, qt.Equals(keyspace.New("verifierdev"), keyspace.Prefix("verifierdev:")))
	qt.Assert(t, qt.Equals(keyspace.New("verifierdev:"), keyspace.Prefix("verifierdev:")))
}

func TestKey(t *testing.T) {
	qt.Assert(t, qt.Equals(keyspace.New("").Key("vc:handoff:queue"), "vc:handoff:queue"))
	qt.Assert(t, qt.Equals(keyspace.New("verifierdev").Key("vc:handoff:queue"), "verifierdev:vc:handoff:queue"))
}
