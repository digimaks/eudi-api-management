package apikeys_test

import (
	"testing"

	"github.com/digimaks/eudi-api-management/internal/apikeys"
)

// FuzzParseAPIKey is the fuzz target for Parse, the one function in this
// package that runs directly over attacker-controlled input (the X-API-Key
// header). It must never panic, regardless of input — a malformed key is
// always ErrFormat, never a crash.
func FuzzParseAPIKey(f *testing.F) {
	f.Add("vk_01HXAMPLE_c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0")
	f.Add("")
	f.Add("vk__")
	f.Add("vk_AAAAAAAA_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // well-formed shape
	f.Add("vk")
	f.Add("_")
	f.Add("vk_" + "\x00\x00\x00\x00\x00\x00\x00\x00" + "_secret")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _, _ = apikeys.Parse(s) // must never panic
	})
}
