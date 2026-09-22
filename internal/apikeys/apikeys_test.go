package apikeys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"golang.org/x/crypto/argon2"
)

// mintKey mints a fresh key and immediately round-trips it through Parse,
// asserting the prefixes agree — every other test builds on top of this
// (TestMintParseRoundTrip is this same round trip, made explicit).
func mintKey(t *testing.T) (prefix, secret, phcHash string) {
	t.Helper()
	displayKey, mintedPrefix, phcHash, err := Mint(rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	gotPrefix, gotSecret, err := Parse(displayKey)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(gotPrefix, mintedPrefix))
	return mintedPrefix, gotSecret, phcHash
}

func TestMintParseRoundTrip(t *testing.T) {
	prefix, secret, phcHash := mintKey(t)
	qt.Assert(t, qt.HasLen(prefix, prefixLen))
	qt.Assert(t, qt.HasLen(secret, secretLen))
	qt.Assert(t, qt.IsTrue(strings.HasPrefix(phcHash, "$argon2id$v=19$m=19456,t=2,p=1$")))
}

func TestVerifyTrueOnCorrectSecret(t *testing.T) {
	_, secret, phcHash := mintKey(t)

	v := NewVerifier(time.Now)
	ok, err := v.Verify("k1", phcHash, secret)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(ok))
}

func TestVerifyFalseOnSameLengthWrongSecret(t *testing.T) {
	_, secret, phcHash := mintKey(t)
	wrong := flipFirstChar(secret)
	qt.Assert(t, qt.HasLen(wrong, len(secret)))
	qt.Assert(t, qt.IsTrue(wrong != secret))

	v := NewVerifier(time.Now)
	ok, err := v.Verify("k1", phcHash, wrong)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(ok))
}

func flipFirstChar(s string) string {
	alt := byte('A')
	if s[0] == 'A' {
		alt = 'B'
	}
	return string(alt) + s[1:]
}

// TestPHCParamsEncodedAndDecodedExactly is the PHC round-trip: the fixed
// shape ($argon2id$v=19$m=19456,t=2,p=1$<salt>$<tag>) is what Mint writes and
// what decodePHC reads back, byte for byte.
func TestPHCParamsEncodedAndDecodedExactly(t *testing.T) {
	_, _, phcHash := mintKey(t)

	re := regexp.MustCompile(`^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)
	qt.Assert(t, qt.IsTrue(re.MatchString(phcHash)), qt.Commentf("phcHash = %q", phcHash))

	p, err := decodePHC(phcHash)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(p.memory, uint32(argonMemoryKiB)))
	qt.Assert(t, qt.Equals(p.time, uint32(argonTime)))
	qt.Assert(t, qt.Equals(p.threads, uint8(argonThreads)))
	qt.Assert(t, qt.HasLen(p.salt, saltLen))
	qt.Assert(t, qt.HasLen(p.tag, tagLen))
}

// TestVerifyUsesPHCsOwnParams proves Verify re-derives with the params
// ENCODED IN THE PHC STRING, not the package's own minting constants: this
// hash uses deliberately different m/t/p, and it still verifies.
func TestVerifyUsesPHCsOwnParams(t *testing.T) {
	const customMemory, customTime, customThreads = 8, 1, 1
	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	qt.Assert(t, qt.IsNil(err))

	secret := "custom-params-secret-000000000A" // #nosec G101 -- test fixture value, not a real credential
	tag := argon2.IDKey([]byte(secret), salt, customTime, customMemory, customThreads, tagLen)
	customPHC := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		customMemory, customTime, customThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(tag))

	v := NewVerifier(time.Now)
	ok, err := v.Verify("k1", customPHC, secret)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(ok))
}

func TestVerifyRejectsMalformedPHC(t *testing.T) {
	v := NewVerifier(time.Now)
	ok, err := v.Verify("k1", "not-a-phc-string", "whatever")
	qt.Assert(t, qt.IsFalse(ok))
	qt.Assert(t, qt.IsNotNil(err))
}

// countingDerive wraps a deriveFn with a call counter, used below to prove
// the verified-key cache actually skips argon2 on a hit rather than merely
// returning the same answer twice by coincidence.
func countingDerive(wrapped deriveFn) (deriveFn, *int) {
	calls := 0
	return func(secret, salt []byte, ti, mem uint32, th uint8, kl uint32) []byte {
		calls++
		return wrapped(secret, salt, ti, mem, th, kl)
	}, &calls
}

func TestCacheSkipsArgon2OnHit(t *testing.T) {
	_, secret, phcHash := mintKey(t)

	v := NewVerifier(time.Now)
	var calls *int
	v.derive, calls = countingDerive(v.derive)

	ok1, err := v.Verify("k1", phcHash, secret)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(ok1))
	qt.Assert(t, qt.Equals(*calls, 1))

	ok2, err := v.Verify("k1", phcHash, secret) // identical (keyID, secret): cache hit
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(*calls, 1)) // unchanged -- argon2 was NOT invoked again
	qt.Assert(t, qt.Equals(ok1, ok2))
}

// TestCacheHitMatchesColdVerdictOnFailure proves a wrong secret verifies
// false both times -- negatives are never cached, so the second call is
// another cold verify, not a served-from-cache "true". A cache that ever
// returned "true" on a hit would pass TestCacheSkipsArgon2OnHit's call-count
// check while being a security hole; this guards the verdict directly.
func TestCacheHitMatchesColdVerdictOnFailure(t *testing.T) {
	_, secret, phcHash := mintKey(t)
	wrong := flipFirstChar(secret)

	v := NewVerifier(time.Now)
	ok1, err := v.Verify("k1", phcHash, wrong)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(ok1))

	ok2, err := v.Verify("k1", phcHash, wrong) // cold verify again (negatives not cached)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(ok2))
}

// TestCacheRotationFallsThroughOnSecretChange: a cached entry for keyID
// belongs to one specific secret. Presenting a DIFFERENT secret for the same
// keyID (e.g. the client rotated locally, or an attacker is guessing) must
// fall through to a fresh cold verify against the CURRENT phcHash, never
// serve the old cached verdict for the new secret.
func TestCacheRotationFallsThroughOnSecretChange(t *testing.T) {
	_, secretA, phcHashA := mintKey(t)
	_, secretB, phcHashB := mintKey(t)

	v := NewVerifier(time.Now)
	okA, err := v.Verify("k1", phcHashA, secretA)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(okA))

	// Same cache slot ("k1"), different secret/hash entirely -- must verify
	// against the new hash, not reuse A's cached success entry.
	okB, err := v.Verify("k1", phcHashB, secretB)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(okB))

	// And A's own secret against A's own hash still verifies correctly after
	// the slot was overwritten by B's cache entry (cold verify, cache miss).
	okA2, err := v.Verify("k1", phcHashA, secretA)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(okA2))
}

// TestCacheCapEvictsOldest exercises cacheCap (1024) eviction. It swaps in a
// cheap stub derive so the test doesn't pay a real argon2id cost cacheCap+1
// times (that would take tens of seconds); eviction is a pure cache-mechanics
// property, independent of the real KDF.
func TestCacheCapEvictsOldest(t *testing.T) {
	v := NewVerifier(time.Now)
	var calls *int
	v.derive, calls = countingDerive(func(_, _ []byte, _, _ uint32, _ uint8, kl uint32) []byte {
		return make([]byte, kl) // cheap stand-in; verdict correctness isn't under test here
	})
	phcHash := encodePHC(make([]byte, saltLen), make([]byte, tagLen))

	for i := range cacheCap + 1 {
		keyID := fmt.Sprintf("key-%d", i)
		_, err := v.Verify(keyID, phcHash, "secret")
		qt.Assert(t, qt.IsNil(err))
	}
	qt.Assert(t, qt.Equals(len(v.cache), cacheCap))

	callsBefore := *calls
	_, err := v.Verify("key-0", phcHash, "secret") // key-0 was the first evicted
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(*calls > callsBefore)) // re-derived: not served from cache
}

// TestNoEarlyExit is the core no-oracle property: "wrong secret against a
// real key's hash" and "any secret against the dummy hash" (the auth
// middleware's stand-in for an unknown prefix) must be indistinguishable in
// both return shape and derive cost -- neither may short-circuit before
// reaching the constant-time compare.
func TestNoEarlyExit(t *testing.T) {
	_, _, realPHC := mintKey(t)

	v := NewVerifier(time.Now)
	var calls *int
	v.derive, calls = countingDerive(v.derive)

	okA, errA := v.Verify("real-key", realPHC, "definitely-the-wrong-secret-000")
	okB, errB := v.Verify(DummyKeyID+"-test", DummyPHC(), "attackers-guess-at-a-secret-000")

	qt.Assert(t, qt.IsFalse(okA))
	qt.Assert(t, qt.IsFalse(okB))
	qt.Assert(t, qt.IsNil(errA))
	qt.Assert(t, qt.IsNil(errB))
	qt.Assert(t, qt.Equals(*calls, 2)) // both derived -- neither short-circuited
}

// TestWarmCacheNoTimingOracle is the regression guard for the no-negative-
// cache rule (stop caching negative verdicts). Setup mirrors the attack: a
// real key's cache slot is WARMED by a legitimate correct verify, and the
// shared dummy slot is primed by one unknown-prefix attempt. Then it measures
// the derive cost of the SECOND attempt on each failing path — a REPEATED
// wrong-secret guess on the (warm) known-prefix slot, and a REPEATED
// unknown-prefix guess on the dummy slot. Both must STILL pay a full argon2
// derive: negatives are never cached, so neither path is ever served fast.
//
// This FAILS against the old cache-negatives implementation — there, the
// first wrong-secret verify overwrote the known-prefix slot with a cached
// NEGATIVE, so the repeated guess hit that slot and skipped the derive
// (knownWrong == 0), while a differently-populated dummy slot re-derived —
// the exact prefix-existence timing oracle. It PASSES once only successes are
// cached (both repeats derive → knownWrong == unknown == 1).
func TestWarmCacheNoTimingOracle(t *testing.T) {
	_, secret, realPHC := mintKey(t)
	wrong := flipFirstChar(secret)

	v := NewVerifier(time.Now)
	var calls *int
	v.derive, calls = countingDerive(v.derive)

	// Warm the real key's dedicated cache slot with a correct verify.
	ok, err := v.Verify("real-key", realPHC, secret)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(ok))

	// Prime both failing paths once (this is where the OLD code cached the
	// negatives that produced the oracle).
	_, err = v.Verify("real-key", realPHC, wrong) // known prefix, wrong secret
	qt.Assert(t, qt.IsNil(err))
	_, err = v.Verify(DummyKeyID, DummyPHC(), "unknown-prefix-guess-00000000000") // #nosec G101 -- test fixture, not a credential
	qt.Assert(t, qt.IsNil(err))

	// Measure the SECOND identical attempt on each path.
	before := *calls
	okKnown, err := v.Verify("real-key", realPHC, wrong)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(okKnown))
	knownWrong := *calls - before

	before = *calls
	okUnknown, err := v.Verify(DummyKeyID, DummyPHC(), "unknown-prefix-guess-00000000000") // #nosec G101 -- test fixture, not a credential
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(okUnknown))
	unknown := *calls - before

	qt.Assert(t, qt.Equals(knownWrong, 1))       // known-prefix wrong-secret repeat still derives
	qt.Assert(t, qt.Equals(unknown, 1))          // unknown-prefix repeat still derives
	qt.Assert(t, qt.Equals(knownWrong, unknown)) // no warm-cache timing oracle
}

func TestParseRejectsMalformed(t *testing.T) {
	prefix, secret, _ := mintKey(t)

	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"double underscore only", "vk__"},
		{"wrong scheme", "xx_" + prefix + "_" + secret},
		{"short prefix", "vk_" + prefix[:7] + "_" + secret},
		{"long prefix", "vk_" + prefix + "X_" + secret},
		{"prefix has excluded crockford char", "vk_AAAAAAAI_" + secret}, // 'I' excluded
		{"lowercase prefix", "vk_" + strings.ToLower(prefix) + "_" + secret},
		{"short secret", "vk_" + prefix + "_" + secret[:31]},
		{"secret has invalid char", "vk_" + prefix + "_" + secret[:31] + "!"},
		{"no underscores at all", "vksomethingwithnounderscoresatall"},
		{"only scheme", "vk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse(tt.input)
			qt.Assert(t, qt.ErrorIs(err, ErrFormat))
		})
	}

	// Sanity: the well-formed shape actually parses, so the malformed cases
	// above aren't vacuously true.
	gotPrefix, gotSecret, err := Parse("vk_" + prefix + "_" + secret)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(gotPrefix, prefix))
	qt.Assert(t, qt.Equals(gotSecret, secret))
}
